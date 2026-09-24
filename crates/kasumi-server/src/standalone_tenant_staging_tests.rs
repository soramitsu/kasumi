use super::*;
use std::{future::Future, task::Poll};

fn run_large_staging_fixture<F, Fut>(name: &'static str, make: F) -> Result<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + 'static,
{
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(async move {
                    let _serial = crate::standalone::ownership_tests::drain_serial()
                        .lock()
                        .await;
                    let outcome =
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            Box::pin(make())
                        })) {
                            Ok(mut fixture) => {
                                // Catch each poll, then drop the future so its
                                // pause guard runs before joining retained owners.
                                let outcome = std::future::poll_fn(|cx| {
                                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                        || fixture.as_mut().poll(cx),
                                    )) {
                                        Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
                                        Ok(Poll::Pending) => Poll::Pending,
                                        Err(payload) => Poll::Ready(Err(payload)),
                                    }
                                })
                                .await;
                                drop(fixture);
                                outcome
                            }
                            Err(payload) => Err(payload),
                        };
                    // The process-wide startup registry must join its tasks
                    // before this test's Tokio runtime can cancel them.
                    let drained =
                        crate::startup_owner::drain(crate::startup_owner::Kind::LocalOperator)
                            .await;
                    match outcome {
                        Err(payload) => {
                            if let Err(drain) = drained {
                                eprintln!(
                                    "LocalOperator drain failed after fixture panic: {drain:#}"
                                );
                            }
                            std::panic::resume_unwind(payload)
                        }
                        Ok(outcome) => match (outcome, drained) {
                            (Err(error), Err(drain)) => {
                                let summary = format!(
                                    "{error:#}; LocalOperator drain also failed: {drain:#}"
                                );
                                Err(error.context(summary))
                            }
                            (Err(error), Ok(())) => Err(error),
                            (Ok(()), Err(drain)) => Err(drain),
                            (Ok(()), Ok(())) => Ok(()),
                        },
                    }
                }))
        })?
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

#[derive(Default)]
struct Pause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail: bool,
}
struct ReleasePauseOnDrop(Arc<Pause>);
impl Drop for ReleasePauseOnDrop {
    fn drop(&mut self) {
        // An early Result error must not strand the retained startup owner
        // while the enclosing fixture joins it on the same Tokio runtime.
        self.0.release.notify_one();
    }
}
type Pauses = std::sync::Mutex<std::collections::BTreeMap<(Uuid, &'static str), Arc<Pause>>>;
fn pauses() -> &'static Pauses {
    static PAUSES: std::sync::OnceLock<Pauses> = std::sync::OnceLock::new();
    PAUSES.get_or_init(Default::default)
}
pub(super) async fn checkpoint(node: Uuid, phase: &'static str) -> Result<()> {
    let pause = pauses().lock().unwrap().remove(&(node, phase));
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
        ensure!(!pause.fail, "injected staging phase failure");
    }
    Ok(())
}
fn request(config: &RuntimeConfig) -> StageTenantRequest {
    StageTenantRequest {
        operation_id: Uuid::new_v4(),
        tenant: "tenant-b".into(),
        incarnation: Uuid::new_v4(),
        initial_policy: config.tenants[0].initial_policy.clone(),
        initial_limits: config.tenants[0].initial_limits.clone(),
    }
}
async fn entered(pause: &Pause) {
    tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified())
        .await
        .unwrap();
}

#[test]
fn cancelled_staging_retains_exclusive_owner_until_configuration_and_workers_finish() -> Result<()>
{
    run_large_staging_fixture(
        "standalone cancelled tenant staging fixture",
        cancelled_staging_impl,
    )
}

async fn cancelled_staging_impl() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("installed"),
        "tenant-a",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert((config.database_id, "files-ready"), pause.clone());
    let _release_pause = ReleasePauseOnDrop(pause.clone());
    let mut staged = Box::pin(stage_tenant_with_storage(
        &installed.configuration,
        request.clone(),
        storage.clone(),
    ));
    std::future::poll_fn(|cx| {
        assert!(staged.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    entered(&pause).await;
    drop(staged);
    assert!(
        claim(
            &config,
            &crate::persistent_disk::open(&config.persistent_disk, &storage).unwrap()
        )
        .is_err()
    );
    assert!(
        RuntimeConfig::load(&installed.configuration)?
            .tenants
            .iter()
            .all(|entry| entry.tenant != request.tenant)
    );
    pause.release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::startup_owner::drain(crate::startup_owner::Kind::LocalOperator),
    )
    .await??;
    assert_eq!(
        tenant_stage_status_with_storage(
            &installed.configuration,
            request.operation_id,
            storage.clone()
        )
        .await?
        .state,
        "completed"
    );
    let updated = RuntimeConfig::load(&installed.configuration)?;
    assert!(
        updated
            .tenants
            .iter()
            .any(|entry| entry.tenant == request.tenant)
    );
    let mut owner = OperatorState::open(&updated, storage.clone()).await?;
    let checked = (|| {
        assert!(
            crate::node_enrollment::tenant_record(owner.audit.store(), &request.tenant)?.is_none()
        );
        assert!(!kasumi_store::CustodyStore::catalog_installed(
            &owner.node,
            &request.tenant
        )?);
        Ok(())
    })();
    owner.finish(checked).await
}

#[test]
fn staging_replay_resolves_lost_configuration_outcome_without_replacing_keys() -> Result<()> {
    run_large_staging_fixture("standalone staging replay fixture", staging_replay_impl)
}

async fn staging_replay_impl() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("installed"),
        "tenant-a",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause {
        fail: true,
        ..Default::default()
    });
    pauses().lock().unwrap().insert(
        (config.database_id, "configuration-published"),
        pause.clone(),
    );
    let _release_pause = ReleasePauseOnDrop(pause.clone());
    let configuration = installed.configuration.clone();
    let invocation = request.clone();
    let worker_storage = storage.clone();
    let worker = tokio::spawn(async move {
        stage_tenant_with_storage(&configuration, invocation, worker_storage).await
    });
    entered(&pause).await;
    pause.release.notify_one();
    assert!(worker.await?.is_err());
    let updated = RuntimeConfig::load(&installed.configuration)?;
    let keys = installation_root(&updated)?
        .join("operator")
        .join(format!("tenant-stage-{}", request.operation_id));
    let before = private_files::read(&keys.join("application.json"), MAX_KEYRING)?;
    assert_eq!(
        tenant_stage_status_with_storage(
            &installed.configuration,
            request.operation_id,
            storage.clone()
        )
        .await?
        .state,
        "files_ready"
    );
    assert_eq!(
        stage_tenant_with_storage(&installed.configuration, request.clone(), storage.clone())
            .await?
            .state,
        "completed"
    );
    assert_eq!(
        private_files::read(&keys.join("application.json"), MAX_KEYRING)?.as_slice(),
        before.as_slice()
    );
    let mut conflicting = request;
    conflicting.initial_limits.max_documents -= 1;
    assert!(
        stage_tenant_with_storage(&installed.configuration, conflicting, storage.clone())
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn interrupted_key_creation_never_adopts_files_or_reuses_its_dispatch() -> Result<()> {
    run_large_staging_fixture(
        "standalone interrupted key creation fixture",
        interrupted_key_creation_impl,
    )
}

async fn interrupted_key_creation_impl() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("installed"),
        "tenant-a",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause {
        fail: true,
        ..Default::default()
    });
    pauses()
        .lock()
        .unwrap()
        .insert((config.database_id, "files-ready"), pause.clone());
    let _release_pause = ReleasePauseOnDrop(pause.clone());
    let configuration = installed.configuration.clone();
    let invocation = request.clone();
    let worker_storage = storage.clone();
    let worker = tokio::spawn(async move {
        stage_tenant_with_storage(&configuration, invocation, worker_storage).await
    });
    entered(&pause).await;
    pause.release.notify_one();
    assert!(worker.await?.is_err());
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let receipt = (|| {
        let mut record = load(&owner, request.operation_id)?.unwrap();
        // Model a crash after private files exist but before their receipt commits.
        record.outcome = Outcome::Dispatched;
        save(&owner, &record)?;
        Ok(record)
    })();
    let record = owner.finish(receipt).await?;
    drop(owner);
    let before = private_files::read(&record.directory.join("application.json"), MAX_KEYRING)?;
    assert!(
        stage_tenant_with_storage(&installed.configuration, request.clone(), storage.clone())
            .await
            .is_err()
    );
    assert_eq!(
        tenant_stage_status_with_storage(
            &installed.configuration,
            request.operation_id,
            storage.clone()
        )
        .await?
        .state,
        "failed"
    );
    assert_eq!(
        private_files::read(&record.directory.join("application.json"), MAX_KEYRING)?.as_slice(),
        before.as_slice()
    );
    assert_eq!(
        digest(&private_files::read(&installed.configuration, 2 << 20)?),
        record.before_sha256
    );
    let fresh = StageTenantRequest {
        operation_id: Uuid::new_v4(),
        ..request
    };
    assert_eq!(
        stage_tenant_with_storage(&installed.configuration, fresh, storage.clone())
            .await?
            .state,
        "completed"
    );
    assert_eq!(
        private_files::read(&record.directory.join("application.json"), MAX_KEYRING)?.as_slice(),
        before.as_slice()
    );
    Ok(())
}

#[test]
fn early_result_error_releases_local_operator_before_runtime_drop() -> Result<()> {
    // Keep the physical installation alive until the fixture thread has joined
    // its retained owner. The async body exits before that same-runtime drain.
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let installation = directory.path().join("installed");
    let error = run_large_staging_fixture("standalone early staging error fixture", move || {
        early_result_error_impl(installation)
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "injected pre-release fixture failure");
    drop(directory);
    Ok(())
}

async fn early_result_error_impl(installation: std::path::PathBuf) -> Result<()> {
    let (installed, storage) =
        crate::runtime_storage_fixtures::initialize_standalone(&installation, "tenant-a").await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert((config.database_id, "files-ready"), pause.clone());
    let _release_pause = ReleasePauseOnDrop(pause.clone());
    let mut staged = Box::pin(stage_tenant_with_storage(
        &installed.configuration,
        request,
        storage,
    ));
    std::future::poll_fn(|cx| {
        assert!(staged.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    entered(&pause).await;
    drop(staged);
    anyhow::bail!("injected pre-release fixture failure")
}

#[test]
fn early_panic_releases_local_operator_before_runtime_drop() -> Result<()> {
    // A caught panic drops the async body's locals before the wrapper drains.
    // Keep the real installation rooted on this test thread through that join.
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let installation = directory.path().join("installed");
    let panic = std::panic::catch_unwind(|| {
        run_large_staging_fixture("standalone early staging panic fixture", move || {
            early_panic_impl(installation)
        })
    })
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&'static str>().copied(),
        Some("injected pre-release fixture panic")
    );
    // Starting another operation in the same process exposes a cancelled
    // registry handle if the panicking fixture skipped its drain.
    let result = run_large_staging_fixture("standalone post-panic operator fixture", || async {
        operator::run(async { Ok(()) }).await
    });
    drop(directory);
    result
}

async fn early_panic_impl(installation: std::path::PathBuf) -> Result<()> {
    let (installed, storage) =
        crate::runtime_storage_fixtures::initialize_standalone(&installation, "tenant-a").await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert((config.database_id, "files-ready"), pause.clone());
    let _release_pause = ReleasePauseOnDrop(pause.clone());
    let mut staged = Box::pin(stage_tenant_with_storage(
        &installed.configuration,
        request,
        storage,
    ));
    std::future::poll_fn(|cx| {
        assert!(staged.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    entered(&pause).await;
    drop(staged);
    std::panic::panic_any("injected pre-release fixture panic")
}
