use super::*;
use crate::{
    runtime::NodeRuntime,
    standalone::{ClientProfile, initialize},
};
use kasumi_types::*;
use std::collections::BTreeSet;

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}
async fn backup(root: &Path) -> (PathBuf, LocalRecoveryStart, ClientProfile) {
    let installed = initialize(&root.join("kasumi"), "tenant-a").await.unwrap();
    let mut config = RuntimeConfig::load(&installed.configuration).unwrap();
    let mut profile = ClientProfile::load(&installed.tenant_profile).unwrap();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = listeners[0].local_addr().unwrap();
    config.native.listen = listeners[1].local_addr().unwrap();
    config.admin.listen = listeners[2].local_addr().unwrap();
    config.mcp.protocol = crate::mcp::McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))
    .unwrap();
    profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
    profile.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
    profile.admin_endpoint = format!("https://localhost:{}", config.admin.listen.port());
    private_files::replace(
        &installed.configuration,
        &serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    private_files::replace(
        &installed.tenant_profile,
        &serde_json::to_vec_pretty(&profile).unwrap(),
    )
    .unwrap();
    crate::standalone::configure_test_topology(&config).await;
    drop(listeners);
    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context()).is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    registry
        .database(&context())
        .unwrap()
        .administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut data = kasumi_client::KasumiClient::connect(&profile.connection(false).unwrap())
        .await
        .unwrap();
    data.mutate(
        &profile.bearer().unwrap(),
        &MutationBatch {
            idempotency_key: Uuid::new_v4().to_string(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "first".into(),
                body: serde_json::json!({"value":"retained encrypted backup"}),
                expected: Precondition::Absent,
            }],
        },
    )
    .await
    .unwrap();
    let mut admin = kasumi_client::KasumiAdminClient::connect(&profile.connection(true).unwrap())
        .await
        .unwrap();
    let checkpoint = admin
        .create_backup_checkpoint(
            &profile.bearer().unwrap(),
            &CreateBackupCheckpoint {
                session_id: uuid::Uuid::new_v4(),
                destination: "local".into(),
            },
        )
        .await
        .unwrap()
        .checkpoint()
        .clone();
    let verified = admin
        .verify_backup_checkpoint(
            &profile.bearer().unwrap(),
            &VerifyBackupCheckpoint {
                destination: "local".into(),
                backup_id: checkpoint.backup_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(verified.checkpoint(), &checkpoint);
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    drop(data);
    drop(admin);
    drop(registry);
    let configured = &config.tenants[0];
    let crate::serving_runtime::TenantServingConfig::Standalone { installation_id } =
        configured.serving
    else {
        panic!()
    };
    let incarnation = Uuid::parse_str(configured.incarnation.as_ref().unwrap()).unwrap();
    (
        installed.configuration,
        LocalRecoveryStart {
            operation_id: Uuid::new_v4(),
            tenant: "tenant-a".into(),
            expected_active_incarnation: incarnation,
            target_incarnation: Uuid::new_v4(),
            checkpoint,
            source_purpose: StoragePurpose::Standalone {
                installation_id,
                tenant: "tenant-a".into(),
                incarnation,
            },
            source_keys: configured.keys.clone(),
            source_principal: "administrator".into(),
            destination: "local".into(),
            phase_timeout_ms: 60_000,
        },
        profile,
    )
}

#[tokio::test]
async fn local_recovery_resumes_each_phase_and_fences_old_resources_after_activation() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, old_profile) = backup(root.path()).await;
    let started = start(&configuration, request.clone()).await.unwrap();
    assert_eq!(started.phase, LocalRecoveryPhase::Materialize);
    assert_eq!(
        start(&configuration, request.clone())
            .await
            .unwrap()
            .phase_id,
        started.phase_id
    );
    let mut conflicting = request.clone();
    conflicting.target_incarnation = Uuid::new_v4();
    assert!(start(&configuration, conflicting).await.is_err());
    let config = RuntimeConfig::load(&configuration).unwrap();
    assert!(NodeRuntime::open(config.clone()).await.is_err());
    for expected in [
        LocalRecoveryPhase::Complete,
        LocalRecoveryPhase::Activate,
        LocalRecoveryPhase::Publish,
    ] {
        let operator = Operator::open(&configuration).await.unwrap();
        let mut journal = record(operator.store(), request.operation_id).unwrap();
        let old_phase = journal.status.phase_id;
        operator.step(&mut journal).await.unwrap();
        assert_eq!(journal.status.phase, expected);
        assert!(
            operator
                .store()
                .get(PHASES, old_phase.as_bytes())
                .unwrap()
                .is_some()
        );
        operator.audit.shutdown().await;
        drop(operator);
        assert_eq!(
            status(&configuration, request.operation_id)
                .await
                .unwrap()
                .phase,
            expected
        );
    }
    assert!(stop(&configuration, request.operation_id).await.is_err());
    assert!(NodeRuntime::open(config.clone()).await.is_err());
    let completed = resume(&configuration, request.operation_id).await.unwrap();
    assert_eq!(completed.phase, LocalRecoveryPhase::Finished);
    assert_eq!(completed.fencing_scope, "exclusive_local_installation");
    assert_eq!(
        resume(&configuration, request.operation_id)
            .await
            .unwrap()
            .phase,
        LocalRecoveryPhase::Finished
    );
    let profile = ClientProfile::load(completed.client_profile.as_ref().unwrap()).unwrap();
    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context()).is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut client = kasumi_client::KasumiClient::connect(&profile.connection(false).unwrap())
        .await
        .unwrap();
    let read = ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "first".into(),
        }],
        queries: vec![],
    };
    let snapshot_resources = kasumi_client::ClientResources::new(16 << 20, 8).unwrap();
    let snapshot_options = |duration| kasumi_client::SnapshotReadOptions {
        resources: snapshot_resources.clone(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 64 << 10,
            max_json_bytes: 64 << 10,
            max_decoded_bytes: 2 << 20,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + duration,
        expected_incarnation: request.target_incarnation,
    };
    let result = client
        .read_snapshot(
            &profile.bearer().unwrap(),
            &read,
            &snapshot_options(std::time::Duration::from_secs(4)),
        )
        .await
        .unwrap();
    assert_eq!(result.incarnation, request.target_incarnation.to_string());
    assert_eq!(
        result.documents[0].document.as_ref().unwrap().body,
        serde_json::json!({"value":"retained encrypted backup"})
    );
    assert!(
        client
            .read_snapshot(
                &old_profile.bearer().unwrap(),
                &read,
                &snapshot_options(std::time::Duration::from_secs(4))
            )
            .await
            .is_err()
    );
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    drop(client);
    drop(registry);
    crate::standalone::rotate_wrapping_keys(&configuration)
        .await
        .unwrap();
    let recovered = crate::standalone::recover_administrator(
        &configuration,
        &root.path().join("recovered-admin"),
    )
    .await
    .unwrap();
    assert!(
        recovered
            .iter()
            .map(|path| ClientProfile::load(path).unwrap())
            .any(|profile| profile.resource
                == CredentialResource::Database {
                    incarnation: request.target_incarnation
                })
    );
    // Committed activation cannot recreate absent target storage from an empty
    // path, even with the original source database still present.
    let target = directory(&config, request.target_incarnation)
        .unwrap()
        .join("node.redb");
    std::fs::rename(&target, target.with_extension("missing")).unwrap();
    assert!(NodeRuntime::open(config).await.is_err());
    assert!(!target.exists());
}

#[tokio::test]
async fn local_stop_persists_identity_before_cleanup_and_rejects_unrelated_files() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    operator.step(&mut journal).await.unwrap();
    let target = journal.target_directory.clone();
    // Verified materialization can stage an archive before its bootstrap
    // commits. Ownership comes from this generation's journal, not the
    // historical source identity inside the ciphertext.
    let mut builder = kasumi_store::AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
    assert!(builder.push(0, b"historical source record").unwrap());
    let segment = operator.store().encrypt_audit_segment(builder).unwrap();
    let cache = operator.observed_archives(&journal).unwrap();
    cache.publish_blocking(&segment).unwrap();
    cache.publish_blocking(&segment).unwrap();
    let shared =
        kasumi_store::FilesystemAuditArchive::open(root.path().join("shared-archives")).unwrap();
    shared.publish_blocking(&segment).unwrap();
    let cache_directory = target.join("tenant-audit-archives");
    let archive = cache_directory.join(format!("{}.audit", segment.reference.object.object_id));
    drop(cache);
    operator.audit.shutdown().await;
    drop(operator);
    let unrelated = target.join("unrelated.txt");
    private_files::create(&unrelated, b"must remain").unwrap();
    assert!(stop(&configuration, request.operation_id).await.is_err());
    assert_eq!(
        status(&configuration, request.operation_id)
            .await
            .unwrap()
            .phase,
        LocalRecoveryPhase::Stopping
    );
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"must remain");
    std::fs::remove_file(unrelated).unwrap();
    let database = target.join("node.redb");
    let preserved = root.path().join("preserved-node.redb");
    std::fs::rename(&database, &preserved).unwrap();
    private_files::create(&database, b"unrelated replacement inode").unwrap();
    assert!(resume(&configuration, request.operation_id).await.is_err());
    assert_eq!(
        std::fs::read(&database).unwrap(),
        b"unrelated replacement inode"
    );
    std::fs::remove_file(&database).unwrap();
    std::fs::rename(preserved, &database).unwrap();
    let original_cache = root.path().join("preserved-cache");
    std::fs::rename(&cache_directory, &original_cache).unwrap();
    private_files::create_directory(&cache_directory).unwrap();
    let unrelated_archive = cache_directory.join("unrelated.txt");
    private_files::create(&unrelated_archive, b"must remain").unwrap();
    assert!(resume(&configuration, request.operation_id).await.is_err());
    assert_eq!(std::fs::read(&unrelated_archive).unwrap(), b"must remain");
    std::fs::remove_file(&unrelated_archive).unwrap();
    std::fs::remove_dir(&cache_directory).unwrap();
    std::fs::rename(original_cache, &cache_directory).unwrap();
    let original_archive = root.path().join("preserved.audit");
    std::fs::rename(&archive, &original_archive).unwrap();
    private_files::create(&archive, &segment.ciphertext).unwrap();
    assert!(resume(&configuration, request.operation_id).await.is_err());
    assert_eq!(std::fs::read(&archive).unwrap(), segment.ciphertext);
    std::fs::remove_file(&archive).unwrap();
    std::fs::rename(original_archive, &archive).unwrap();
    let stopped = resume(&configuration, request.operation_id).await.unwrap();
    assert_eq!(stopped.phase, LocalRecoveryPhase::Stopped);
    assert!(stopped.cleanup_evidence.is_some());
    assert!(!target.exists());
    assert_eq!(
        shared.read_blocking(&segment.reference.object).unwrap(),
        segment.ciphertext
    );
    let operator = Operator::open(&configuration).await.unwrap();
    let ownership_key = [
        request.operation_id.as_bytes().as_slice(),
        segment.reference.object.object_id.as_bytes().as_slice(),
    ]
    .concat();
    assert!(
        operator
            .store()
            .get("standalone-recovery-archive-objects", &ownership_key)
            .unwrap()
            .is_some()
    );
    operator.audit.shutdown().await;
    drop(operator);
    assert_eq!(
        stop(&configuration, request.operation_id)
            .await
            .unwrap()
            .phase,
        LocalRecoveryPhase::Stopped
    );
    let mut reused = request.clone();
    reused.operation_id = Uuid::new_v4();
    assert!(start(&configuration, reused.clone()).await.is_err());
    let mut config = RuntimeConfig::load(&configuration).unwrap();
    let KeyProviderSettings::File { path: application } = &config.tenants[0].keys else {
        panic!()
    };
    let alias = application.with_file_name("application-alias.json");
    private_files::create(&alias, &private_files::read(application, 2 << 20).unwrap()).unwrap();
    config.tenants[0].keys = KeyProviderSettings::File {
        path: alias.clone(),
    };
    reused.source_keys = KeyProviderSettings::File { path: alias };
    let alias_configuration = configuration.with_file_name("alias.json");
    private_files::create(&alias_configuration, &serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(start(&alias_configuration, reused.clone()).await.is_err());
    assert!(!target.exists());
    let saved_path = config.database_path.clone();
    config.database_path = config.database_path.with_file_name("replacement.redb");
    private_files::replace(&alias_configuration, &serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(start(&alias_configuration, reused).await.is_err());
    assert!(!config.database_path.exists());
    config.database_path = saved_path;
    assert!(config.database_path.exists());
    let mut runtime = NodeRuntime::open(config).await.unwrap();
    runtime.shutdown().await.unwrap();
}

#[derive(Default)]
struct OpenPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
fn open_pauses() -> &'static std::sync::Mutex<std::collections::BTreeMap<PathBuf, Arc<OpenPause>>> {
    static PAUSES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<PathBuf, Arc<OpenPause>>>,
    > = std::sync::OnceLock::new();
    PAUSES.get_or_init(Default::default)
}
pub(super) async fn pause_open(path: &Path) {
    let pause = open_pauses().lock().unwrap().remove(path);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
}

async fn create_catalogs(operator: &Operator, journal: &mut Journal) {
    let node = operator.prepare_database_file(journal).unwrap().unwrap();
    let tenant = &operator.config.tenants[0];
    let source = Arc::new(crate::runtime::file_secret);
    let stores = kasumi_store::TenantStorageSet::initialize_catalogs(
        node.clone(),
        journal.status.request.tenant.clone(),
        tenant.keys.provider(source.clone()).unwrap(),
        tenant.custody_keys.provider(source).unwrap(),
        kasumi_store::StorageAccess::standalone(
            journal.installation_id,
            &journal.status.request.tenant,
            journal.status.request.target_incarnation,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    node.drain_initializers().await.unwrap();
}

#[tokio::test]
async fn cancelled_local_operator_retains_exclusive_installation_until_joined_drain() {
    use std::{future::Future, task::Poll};
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let pause = Arc::new(OpenPause::default());
    open_pauses()
        .lock()
        .unwrap()
        .insert(configuration.clone(), pause.clone());
    let mut waiting = Box::pin(status(&configuration, request.operation_id));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    drop(waiting);
    assert!(Operator::open(&configuration).await.is_err());
    let mut drain = Box::pin(drain_operations());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(Operator::open(&configuration).await.is_err());
    pause.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), drain_operations())
        .await
        .unwrap()
        .unwrap();
    let mut operator = Operator::open(&configuration).await.unwrap();
    assert_eq!(
        record(operator.store(), request.operation_id)
            .unwrap()
            .status
            .phase,
        LocalRecoveryPhase::Materialize
    );
    crate::startup_owner::finish(&mut operator).await.unwrap();
}

#[tokio::test]
async fn local_creation_replay_never_creates_or_adopts_an_absent_or_empty_file() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let mut operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    operator.prepare_directory(&journal).unwrap();
    operator.prepare_archives(&mut journal).unwrap();
    operator
        .prepare_stage(&mut journal, TargetPreparation::CreationDispatched)
        .unwrap();
    let path = journal.target_directory.join("node.redb");
    assert!(
        operator
            .target(&mut journal, TargetOpen::Materialize)
            .await
            .is_err()
    );
    assert!(!path.exists());
    private_files::create(&path, b"").unwrap();
    assert!(
        operator
            .target(&mut journal, TargetOpen::Materialize)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    crate::startup_owner::finish(&mut operator).await.unwrap();
    drop(operator);
    assert!(stop(&configuration, request.operation_id).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    // This unrecognized inode is deliberately operator-owned test input. Recovery
    // refuses it; removing it here permits cleanup of the otherwise empty target.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        resume(&configuration, request.operation_id)
            .await
            .unwrap()
            .phase,
        LocalRecoveryPhase::Stopped
    );
}

#[tokio::test]
async fn local_lost_file_binding_cleanup_requires_the_original_node_identity() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let mut operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    operator.prepare_directory(&journal).unwrap();
    operator.prepare_archives(&mut journal).unwrap();
    operator
        .prepare_stage(&mut journal, TargetPreparation::CreationDispatched)
        .unwrap();
    let path = journal.target_directory.join("node.redb");
    let node = kasumi_store::NodeStore::create_new(
        &path,
        local_node_id(&journal).unwrap(),
        operator.store().scratch_disk().clone(),
    )
    .unwrap();
    drop(node);
    assert!(journal.database_file.is_none());
    assert!(
        operator
            .target(&mut journal, TargetOpen::Materialize)
            .await
            .is_err()
    );
    crate::startup_owner::finish(&mut operator).await.unwrap();
    drop(operator);
    let preserved = root.path().join("original-node.redb");
    std::fs::rename(&path, &preserved).unwrap();
    let other = kasumi_store::NodeStore::create_new(
        &path,
        Uuid::new_v4(),
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    drop(other);
    let bytes = std::fs::read(&path).unwrap();
    assert!(stop(&configuration, request.operation_id).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&preserved, &path).unwrap();
    let stopped = resume(&configuration, request.operation_id).await.unwrap();
    assert_eq!(stopped.phase, LocalRecoveryPhase::Stopped);
    assert!(stopped.cleanup_evidence.is_some());
    assert!(!path.exists());
}

#[tokio::test]
async fn local_catalog_replay_resolves_complete_catalogs_without_reinitialization() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let mut operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    create_catalogs(&operator, &mut journal).await;
    assert_eq!(
        journal.target_preparation,
        TargetPreparation::CreationDispatched
    );
    crate::startup_owner::finish(&mut operator).await.unwrap();
    drop(operator);
    let mut operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    operator.step(&mut journal).await.unwrap();
    assert_eq!(journal.status.phase, LocalRecoveryPhase::Complete);
    assert_eq!(
        journal.target_preparation,
        TargetPreparation::MaterializationDispatched
    );
    crate::startup_owner::finish(&mut operator).await.unwrap();
    drop(operator);
    assert_eq!(
        stop(&configuration, request.operation_id)
            .await
            .unwrap()
            .phase,
        LocalRecoveryPhase::Stopped
    );
}

#[tokio::test]
async fn local_incomplete_catalogs_or_dispatched_restore_never_restart_creation() {
    for dispatched in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (configuration, request, _) = backup(root.path()).await;
        start(&configuration, request.clone()).await.unwrap();
        let mut operator = Operator::open(&configuration).await.unwrap();
        let mut journal = record(operator.store(), request.operation_id).unwrap();
        if dispatched {
            create_catalogs(&operator, &mut journal).await;
            operator
                .prepare_stage(&mut journal, TargetPreparation::CatalogsReady)
                .unwrap();
            operator
                .prepare_stage(&mut journal, TargetPreparation::MaterializationDispatched)
                .unwrap();
        } else {
            drop(
                operator
                    .prepare_database_file(&mut journal)
                    .unwrap()
                    .unwrap(),
            );
        }
        let path = journal.target_directory.join("node.redb");
        let before = std::fs::read(&path).unwrap();
        let stage = journal.target_preparation;
        assert!(
            operator
                .target(&mut journal, TargetOpen::Materialize)
                .await
                .is_err()
        );
        assert_eq!(journal.target_preparation, stage);
        assert_eq!(
            record(operator.store(), request.operation_id)
                .unwrap()
                .target_preparation,
            stage
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        crate::startup_owner::finish(&mut operator).await.unwrap();
        drop(operator);
        assert!(resume(&configuration, request.operation_id).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            stop(&configuration, request.operation_id)
                .await
                .unwrap()
                .phase,
            LocalRecoveryPhase::Stopped
        );
    }
}

#[tokio::test]
async fn activated_local_recovery_never_recreates_missing_control_topology() {
    let root = tempfile::tempdir().unwrap();
    let (configuration, request, _) = backup(root.path()).await;
    start(&configuration, request.clone()).await.unwrap();
    let mut operator = Operator::open(&configuration).await.unwrap();
    let mut journal = record(operator.store(), request.operation_id).unwrap();
    for expected in [
        LocalRecoveryPhase::Complete,
        LocalRecoveryPhase::Activate,
        LocalRecoveryPhase::Publish,
    ] {
        operator.step(&mut journal).await.unwrap();
        assert_eq!(journal.status.phase, expected);
    }
    let original_phase = journal.status.phase_id;
    let activation = active_generation(&operator.config, operator.store(), &request.tenant)
        .unwrap()
        .unwrap();
    let control = crate::standalone::operator_control(
        &operator.config,
        operator.node.clone(),
        operator.audit.clone(),
    )
    .await
    .unwrap();
    let context = crate::standalone::offline_context(&control).unwrap();
    let plane = kasumi_engine::control::ControlPlane::new(control.clone()).unwrap();
    let topology = plane.topology(&context).await.unwrap().unwrap();
    control
        .mutate(
            context.clone(),
            MutationBatch {
                idempotency_key: Uuid::new_v4().to_string(),
                read_set: vec![],
                operations: vec![Mutation::Delete {
                    collection: "topology".into(),
                    id: "current".into(),
                    expected: Precondition::Version(topology.version),
                }],
            },
        )
        .await
        .unwrap();
    assert!(plane.topology(&context).await.unwrap().is_none());
    drop(plane);
    control.shutdown().await.unwrap();
    drop(control);
    let failure = operator.step(&mut journal).await.unwrap_err();
    assert!(format!("{failure:#}").contains("installed standalone Control topology is missing"));
    let retained = record(operator.store(), request.operation_id).unwrap();
    assert_eq!(retained.status.phase, LocalRecoveryPhase::Publish);
    assert_eq!(retained.status.phase_id, original_phase);
    assert!(retained.publication.is_none());
    let current = active_generation(&operator.config, operator.store(), &request.tenant)
        .unwrap()
        .unwrap();
    assert_eq!(current.operation_id, activation.operation_id);
    assert_eq!(current.incarnation, activation.incarnation);
    let control = crate::standalone::operator_control(
        &operator.config,
        operator.node.clone(),
        operator.audit.clone(),
    )
    .await
    .unwrap();
    let context = crate::standalone::offline_context(&control).unwrap();
    let plane = kasumi_engine::control::ControlPlane::new(control.clone()).unwrap();
    assert!(plane.topology(&context).await.unwrap().is_none());
    drop(plane);
    control.shutdown().await.unwrap();
    drop(control);
    crate::startup_owner::finish(&mut operator).await.unwrap();
    drop(operator);
    assert!(stop(&configuration, request.operation_id).await.is_err());
}
