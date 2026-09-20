use super::*;
use std::{future::Future, task::Poll};

#[derive(Default)]
struct Pause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail: bool,
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

#[tokio::test]
async fn cancelled_staging_retains_exclusive_owner_until_configuration_and_workers_finish()
-> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let installed = initialize(&directory.path().join("installed"), "tenant-a").await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = request(&config);
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert((config.database_id, "files-ready"), pause.clone());
    let mut staged = Box::pin(stage_tenant(&installed.configuration, request.clone()));
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
            &crate::persistent_disk::open(&config.persistent_disk).unwrap()
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
        tenant_stage_status(&installed.configuration, request.operation_id)
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
    let mut owner = OperatorState::open(&updated).await?;
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

#[tokio::test]
async fn staging_replay_resolves_lost_configuration_outcome_without_replacing_keys() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let installed = initialize(&directory.path().join("installed"), "tenant-a").await?;
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
    let configuration = installed.configuration.clone();
    let invocation = request.clone();
    let worker = tokio::spawn(async move { stage_tenant(&configuration, invocation).await });
    entered(&pause).await;
    pause.release.notify_one();
    assert!(worker.await?.is_err());
    let updated = RuntimeConfig::load(&installed.configuration)?;
    let keys = installation_root(&updated)?
        .join("operator")
        .join(format!("tenant-stage-{}", request.operation_id));
    let before = private_files::read(&keys.join("application.json"), MAX_KEYRING)?;
    assert_eq!(
        tenant_stage_status(&installed.configuration, request.operation_id)
            .await?
            .state,
        "files_ready"
    );
    assert_eq!(
        stage_tenant(&installed.configuration, request.clone())
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
        stage_tenant(&installed.configuration, conflicting)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn interrupted_key_creation_never_adopts_files_or_reuses_its_dispatch() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let installed = initialize(&directory.path().join("installed"), "tenant-a").await?;
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
    let configuration = installed.configuration.clone();
    let invocation = request.clone();
    let worker = tokio::spawn(async move { stage_tenant(&configuration, invocation).await });
    entered(&pause).await;
    pause.release.notify_one();
    assert!(worker.await?.is_err());
    let mut owner = OperatorState::open(&config).await?;
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
        stage_tenant(&installed.configuration, request.clone())
            .await
            .is_err()
    );
    assert_eq!(
        tenant_stage_status(&installed.configuration, request.operation_id)
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
        stage_tenant(&installed.configuration, fresh).await?.state,
        "completed"
    );
    assert_eq!(
        private_files::read(&record.directory.join("application.json"), MAX_KEYRING)?.as_slice(),
        before.as_slice()
    );
    Ok(())
}
