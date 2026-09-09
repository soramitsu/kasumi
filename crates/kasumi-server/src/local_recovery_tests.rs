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
