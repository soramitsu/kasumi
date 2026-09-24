use super::*;
use std::{future::Future, task::Poll};
#[derive(Default)]
struct Pause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
fn pauses() -> &'static std::sync::Mutex<BTreeMap<Uuid, Arc<Pause>>> {
    static PAUSES: std::sync::OnceLock<std::sync::Mutex<BTreeMap<Uuid, Arc<Pause>>>> =
        std::sync::OnceLock::new();
    PAUSES.get_or_init(Default::default)
}
pub(super) async fn pause_ready(id: Uuid) {
    let pause = pauses().lock().unwrap().remove(&id);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
}
async fn approve_fixture(
    manager: &Arc<Administration>,
    context: &RequestContext,
    tenant: &str,
) -> Result<()> {
    let released = crate::api::mutation_release(
        manager
            .execute_for_test(
                context.clone(),
                ManagementCommand::ApproveTenant {
                    tenant: tenant.into(),
                },
            )
            .await,
    );
    match released {
        Ok(_) => {}
        Err(error) if error.code == kasumi_types::ErrorCode::UnknownOutcome => {}
        Err(error) => return Err(error.into()),
    }
    ensure!(
        manager.approved_enrollment(tenant)?.digest()?
            == manager.enrollment_proposal(tenant)?.digest()?,
        "fixture approval did not commit the exact configured proposal"
    );
    Ok(())
}
async fn dormant_resident() -> (
    tempfile::TempDir,
    crate::runtime::NodeRuntime,
    Arc<Administration>,
    RequestContext,
) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (installation, storage) = Box::pin(crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("installed"),
        "tenant-a",
    ))
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = listeners[0].local_addr().unwrap();
    config.native.listen = listeners[1].local_addr().unwrap();
    config.admin.listen = listeners[2].local_addr().unwrap();
    drop(listeners);
    let runtime = Box::pin(crate::runtime::NodeRuntime::open_using_storage(
        config,
        crate::runtime::file_secret,
        storage.clone(),
    ))
    .await
    .unwrap();
    let manager = runtime.administration_for_enrollment_test();
    let context = crate::runtime::configured_control_context(&manager.config.control).unwrap();
    let plane = ControlPlane::new(manager.control.clone()).unwrap();
    let mut current = plane.topology(&context).await.unwrap().unwrap();
    current.topology.tenants.remove("tenant-a");
    plane
        .replace_topology(
            context.clone(),
            current.topology,
            Precondition::Version(current.version),
            "test-dormant-resident".into(),
        )
        .await
        .unwrap();
    approve_fixture(&manager, &context, "tenant-a")
        .await
        .unwrap();
    (directory, runtime, manager, context)
}

#[tokio::test]
async fn cancelled_preparation_of_borrowed_resident_preserves_its_original_storage_owner() {
    let (_directory, mut runtime, manager, context) = dormant_resident().await;
    let before = manager.configured("tenant-a").unwrap();
    let original = before.store.get("engine.bootstrap", b"manifest").unwrap();
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert(manager.config.database_id, pause.clone());
    let invocation = manager
        .prepare(
            context,
            ManagementCommand::PrepareTenant {
                tenant: "tenant-a".into(),
            },
        )
        .unwrap();
    let mut waiting = Box::pin(invocation.execute());
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified())
        .await
        .unwrap();
    drop(waiting);
    pause.release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::startup_owner::drain(crate::startup_owner::Kind::TenantEnrollment),
    )
    .await
    .unwrap()
    .unwrap();
    before.store.check_access().unwrap();
    assert!(Arc::ptr_eq(
        &before.database,
        &manager.configured("tenant-a").unwrap().database
    ));
    assert_eq!(
        before.store.get("engine.bootstrap", b"manifest").unwrap(),
        original
    );
    assert!(invocation.prepared_selection.lock().unwrap().is_none());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn closure_before_actual_enrollment_handoff_rejects_publication_and_preserves_borrowed_owner()
{
    let (_directory, mut runtime, manager, context) = dormant_resident().await;
    let before = manager.configured("tenant-a").unwrap();
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert(manager.config.database_id, pause.clone());
    let invocation = manager
        .prepare(
            context,
            ManagementCommand::PrepareTenant {
                tenant: "tenant-a".into(),
            },
        )
        .unwrap();
    let mut waiting = Box::pin(invocation.execute());
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified())
        .await
        .unwrap();
    // The shutdown admission transition takes exactly the handoff's mutex.
    *manager.enrollment_closed.lock().unwrap() = true;
    pause.release.notify_one();
    assert!(waiting.await.is_err());
    crate::startup_owner::drain(crate::startup_owner::Kind::TenantEnrollment)
        .await
        .unwrap();
    before.store.check_access().unwrap();
    assert!(Arc::ptr_eq(
        &before.database,
        &manager.configured("tenant-a").unwrap().database
    ));
    assert!(invocation.prepared_selection.lock().unwrap().is_none());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn abandoned_fresh_standalone_preparation_drains_without_publication_and_retries_existing_state()
-> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = Box::pin(crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("installed"),
        "tenant-a",
    ))
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let request = crate::standalone::StageTenantRequest {
        operation_id: Uuid::new_v4(),
        tenant: "tenant-b".into(),
        incarnation: Uuid::new_v4(),
        initial_policy: config.tenants[0].initial_policy.clone(),
        initial_limits: config.tenants[0].initial_limits.clone(),
    };
    Box::pin(crate::standalone::stage_tenant_with_storage(
        &installed.configuration,
        request.clone(),
        storage.clone(),
    ))
    .await?;
    let mut config = RuntimeConfig::load(&installed.configuration)?;
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = listeners[0].local_addr()?;
    config.native.listen = listeners[1].local_addr()?;
    config.admin.listen = listeners[2].local_addr()?;
    drop(listeners);
    let mut runtime = Box::pin(crate::runtime::NodeRuntime::open_using_storage(
        config,
        crate::runtime::file_secret,
        storage.clone(),
    ))
    .await?;
    let manager = runtime.administration_for_enrollment_test();
    let original = manager.configured("tenant-a")?;
    let original_bytes = original.store.get("engine.bootstrap", b"manifest")?;
    let context = crate::runtime::configured_control_context(&manager.config.control)?;
    approve_fixture(&manager, &context, &request.tenant).await?;
    let pause = Arc::new(Pause::default());
    pauses()
        .lock()
        .unwrap()
        .insert(manager.config.database_id, pause.clone());
    let invocation = manager.prepare(
        context.clone(),
        ManagementCommand::PrepareTenant {
            tenant: request.tenant.clone(),
        },
    )?;
    let mut waiting = Box::pin(invocation.execute());
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified()).await?;
    drop(waiting);
    pause.release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::startup_owner::drain(crate::startup_owner::Kind::TenantEnrollment),
    )
    .await??;
    assert!(manager.configured(&request.tenant).is_err());
    assert!(invocation.prepared_selection.lock().unwrap().is_none());
    let record = node_enrollment::tenant_record(manager.audit.store(), &request.tenant)?.unwrap();
    assert_eq!(record.stage, Stage::Prepared);
    assert_eq!(record.incarnation, request.incarnation);
    original.store.check_access()?;
    assert_eq!(
        original.store.get("engine.bootstrap", b"manifest")?,
        original_bytes
    );
    manager
        .execute_for_test(
            context,
            ManagementCommand::PrepareTenant {
                tenant: request.tenant.clone(),
            },
        )
        .await?;
    let installed = manager.configured(&request.tenant)?;
    assert_eq!(
        Some(crate::runtime::persisted_bootstrap_fingerprint(
            &installed.store
        )?),
        record.bootstrap_sha256
    );
    assert_eq!(
        installed.database.engine().generation()?.state.incarnation,
        request.incarnation.to_string()
    );
    assert!(
        runtime
            .registry()
            .database(&RequestContext {
                tenant: request.tenant,
                ..invocation.context.clone()
            })
            .is_err()
    );
    drop(installed);
    drop(original);
    drop(invocation);
    runtime.shutdown().await?;
    Ok(())
}
