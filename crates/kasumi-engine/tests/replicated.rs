mod common;

use kasumi_engine::{
    Database, ReplicaPlacement, ReplicatedBootstrap, initialize_replicated, open_local,
    open_replicated,
};
use kasumi_raft::{Config, InProcessRouter};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

fn context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "replicated-test".into(),
    }
}
fn bootstrap() -> ReplicatedBootstrap {
    ReplicatedBootstrap {
        incarnation: uuid::Uuid::new_v4().to_string(),
        initial_policy: Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context().scopes,
            }],
            strict_read_audit: false,
        },
        initial_limits: Limits::default(),
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    ReplicaPlacement {
                        address: format!("node-{id}"),
                        failure_domain: format!("zone-{id}"),
                    },
                )
            })
            .collect(),
    }
}
async fn store(path: &std::path::Path) -> (Arc<TenantStore>, Arc<kasumi_engine::SecurityAudit>) {
    let node = NodeStore::open(path).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([43; 32])),
    )
    .await
    .unwrap();
    (store, audit)
}
async fn shutdown_nodes(
    nodes: &mut BTreeMap<u64, Arc<Database>>,
    audits: &mut BTreeMap<u64, Arc<kasumi_engine::SecurityAudit>>,
    router: &InProcessRouter,
    group: &str,
) {
    for (&id, db) in nodes.iter() {
        router.unregister(group, id);
        db.shutdown().await.unwrap();
    }
    nodes.clear();
    for audit in audits.values() {
        audit.shutdown().await;
    }
    audits.clear();
}
async fn leader(nodes: &BTreeMap<u64, Arc<Database>>, exclude: Option<u64>) -> u64 {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for (&id, db) in nodes {
                if Some(id) != exclude
                    && db.raft_group().raft().metrics().borrow().current_leader == Some(id)
                    && matches!(
                        tokio::time::timeout(
                            Duration::from_millis(200),
                            db.raft_group().linearizable_barrier()
                        )
                        .await,
                        Ok(Ok(_))
                    )
                {
                    return id;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
fn batch() -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: "receipt-after-failover".into(),
        operations: ["a", "b"]
            .into_iter()
            .map(|id| Mutation::Put {
                collection: "documents".into(),
                id: id.into(),
                body: json!({"exact":9007199254740993_u64}),
                expected: Precondition::Absent,
            })
            .collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_service_preserves_batches_receipts_and_cursor_fences_across_partition_and_restart()
 {
    let root = tempfile::tempdir().unwrap();
    let bootstrap = bootstrap();
    let group = format!("tenant-a/{}", bootstrap.incarnation);
    let router = Arc::new(InProcessRouter::default());
    let mut nodes = BTreeMap::new();
    let mut audits = BTreeMap::new();
    for id in 1..=3 {
        let (node_store, audit) = store(&root.path().join(format!("{id}.redb"))).await;
        audits.insert(id, audit.clone());
        let db = open_replicated(
            id,
            kasumi_store::test_utils::with_custody(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            Config {
                election_timeout_min: 200,
                election_timeout_max: 400,
                heartbeat_interval: 50,
                ..Config::default()
            },
            audit,
        )
        .await
        .unwrap();
        router.register(group.clone(), id, db.raft_group().raft().clone());
        nodes.insert(id, db);
    }
    initialize_replicated(&nodes[&1], &bootstrap).await.unwrap();
    let first = leader(&nodes, None).await;
    nodes[&first]
        .administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                name: "documents".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let receipt = nodes[&first].mutate(context(), batch()).await.unwrap();
    let mut query: QueryRequest =
        serde_json::from_value(json!({"collection":"documents", "allow_scan":true, "limit":1}))
            .unwrap();
    let first_page = nodes[&first]
        .query(&context(), query.clone())
        .await
        .unwrap();
    query.cursor = first_page.cursor;
    assert!(query.cursor.is_some());
    let chunks: Vec<_> = (0..2)
        .map(|chunk| StagedChunk {
            read_set: vec![],
            operations: (chunk * 150..(chunk + 1) * 150)
                .map(|n| Mutation::Put {
                    collection: "documents".into(),
                    id: format!("staged{n:04}"),
                    body: json!({"exact":9007199254740993_u64}),
                    expected: Precondition::Absent,
                })
                .collect(),
        })
        .collect();
    let manifest = StagedManifest::from_chunks(&chunks).unwrap();
    let staged = StagedTransactionRef {
        transaction_id: "across-leaders".into(),
        manifest_digest: staged_digest(&manifest).unwrap().0,
    };
    nodes[&first]
        .begin_staged_transaction(
            context(),
            BeginStagedTransaction {
                transaction_id: staged.transaction_id.clone(),
                manifest,
                ttl_ms: 60_000,
            },
        )
        .await
        .unwrap();
    nodes[&first]
        .append_staged_chunk(
            context(),
            AppendStagedChunk {
                transaction: staged.clone(),
                index: 0,
                chunk: chunks[0].clone(),
            },
        )
        .await
        .unwrap();
    let lease = nodes[&first]
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let lease_page = ReadSnapshotPage {
        lease_id: lease.lease_id,
        documents: vec![DocumentKey {
            collection: "documents".into(),
            id: "a".into(),
        }],
    };
    router.isolate(&group, first, true);
    assert!(!matches!(
        tokio::time::timeout(
            Duration::from_millis(600),
            nodes[&first].get(&context(), "documents", "a")
        )
        .await,
        Ok(Ok(_))
    ));
    assert!(!matches!(
        tokio::time::timeout(
            Duration::from_millis(600),
            nodes[&first].read_snapshot_page(&context(), lease_page.clone())
        )
        .await,
        Ok(Ok(_))
    ));
    let second = leader(&nodes, Some(first)).await;
    let status = nodes[&second]
        .staged_transaction_status(&context(), &staged)
        .await
        .unwrap();
    assert_eq!(status.received_chunks, vec![0]);
    assert_eq!(
        nodes[&second]
            .engine()
            .generation()
            .unwrap()
            .state
            .document_count,
        2
    );
    nodes[&second]
        .append_staged_chunk(
            context(),
            AppendStagedChunk {
                transaction: staged.clone(),
                index: 1,
                chunk: chunks[1].clone(),
            },
        )
        .await
        .unwrap();
    let staged_receipt = nodes[&second]
        .finalize_staged_transaction(context(), staged.clone())
        .await
        .unwrap();
    assert_eq!(
        nodes[&second]
            .engine()
            .generation()
            .unwrap()
            .state
            .document_count,
        302
    );
    assert!(
        nodes[&second]
            .read_snapshot_page(&context(), lease_page.clone())
            .await
            .is_err()
    );
    assert_eq!(
        nodes[&second].mutate(context(), batch()).await.unwrap(),
        receipt
    );
    assert_eq!(
        nodes[&second]
            .query(&context(), query.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        nodes[&second]
            .get(&context(), "documents", "b")
            .await
            .unwrap()
            .body["exact"]
            .to_string(),
        "9007199254740993"
    );
    router.isolate(&group, first, false);
    // A historical page cannot resume on the former leader even after it rejoins.
    assert!(nodes[&first].query(&context(), query).await.is_err());
    assert!(
        nodes[&first]
            .read_snapshot_page(&context(), lease_page)
            .await
            .is_err()
    );
    shutdown_nodes(&mut nodes, &mut audits, &router, &group).await;
    nodes.clear();
    for id in 1..=3 {
        let (node_store, audit) = store(&root.path().join(format!("{id}.redb"))).await;
        audits.insert(id, audit.clone());
        let db = open_replicated(
            id,
            kasumi_store::test_utils::with_custody(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            Config::default(),
            audit,
        )
        .await
        .unwrap();
        router.register(group.clone(), id, db.raft_group().raft().clone());
        nodes.insert(id, db);
    }
    let recovered = leader(&nodes, None).await;
    assert_eq!(
        nodes[&recovered]
            .finalize_staged_transaction(context(), staged)
            .await
            .unwrap(),
        staged_receipt
    );
    assert_eq!(
        nodes[&recovered]
            .get(&context(), "documents", "staged0299")
            .await
            .unwrap()
            .version,
        staged_receipt.revision
    );
    assert_eq!(
        nodes[&recovered].mutate(context(), batch()).await.unwrap(),
        receipt
    );
    assert_eq!(
        nodes[&recovered]
            .get(&context(), "documents", "a")
            .await
            .unwrap()
            .version,
        receipt.revision
    );
    shutdown_nodes(&mut nodes, &mut audits, &router, &group).await;
}

#[tokio::test]
async fn deployment_modes_and_live_store_ownership_cannot_be_overridden() {
    let root = tempfile::tempdir().unwrap();
    let (store, audit) = store(&root.path().join("local.redb")).await;
    let bootstrap = bootstrap();
    let db = open_local(
        kasumi_store::test_utils::with_custody(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        bootstrap.initial_policy.clone(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert!(
        open_local(
            kasumi_store::test_utils::with_custody(
                store.clone(),
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
            )
            .await
            .unwrap(),
            bootstrap.initial_policy.clone(),
            Limits::default(),
            audit.clone(),
        )
        .await
        .is_err()
    );
    db.raft_group().shutdown().await.unwrap();
    audit.drain().await;
    assert!(db.collections(&context()).await.is_err());
    assert!(
        open_replicated(
            1,
            kasumi_store::test_utils::with_custody(
                store.clone(),
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
            )
            .await
            .unwrap(),
            &bootstrap,
            Arc::new(InProcessRouter::default()),
            Config::default(),
            audit.clone(),
        )
        .await
        .is_err()
    );
    let reopened = open_local(
        kasumi_store::test_utils::with_custody(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        Policy::default(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.engine().generation().unwrap().state.policy.grants[0].principal,
        "owner"
    );
    reopened.shutdown().await.unwrap();
    audit.shutdown().await;
    let mut invalid = bootstrap;
    invalid.voters.get_mut(&2).unwrap().failure_domain = "zone-1".into();
    assert!(invalid.validate().is_err());
    invalid.voters.remove(&2);
    assert!(invalid.validate().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_restore_has_identical_genesis_and_requires_quorum_audit_before_activation() {
    use kasumi_engine::{ReplicaRestoreConfig, prepare_replicated_restore};
    let root = tempfile::tempdir().unwrap();
    let initial = bootstrap();
    let (source_store, source_audit) = store(&root.path().join("source.redb")).await;
    let source = open_local(
        kasumi_store::test_utils::with_custody(
            source_store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        initial.initial_policy.clone(),
        Limits::default(),
        source_audit.clone(),
    )
    .await
    .unwrap();
    source
        .administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::ArchivableHistory,
                write_mode: kasumi_types::CollectionWriteMode::AppendOnly,
                name: "documents".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let receipt = source.mutate(context(), batch()).await.unwrap();
    let backups = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(root.path().join("backups"), 16 << 20)
            .unwrap(),
    );
    let cold_path = root.path().join("cold");
    let cold =
        Arc::new(kasumi_store::FilesystemBackupDestination::new(&cold_path, 16 << 20).unwrap());
    source
        .install_archive_destination("cold".into(), cold)
        .unwrap();
    source
        .archive_history(
            context(),
            ArchiveHistory {
                archive_id: "replicated-period".into(),
                collection: "documents".into(),
                cutoff_revision: receipt.revision,
                destination: "cold".into(),
            },
        )
        .await
        .unwrap();
    let backup_id = source
        .backup(context(), backups.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    std::fs::remove_dir_all(cold_path).unwrap();
    let incarnation = uuid::Uuid::new_v4();
    let group = format!("tenant-a/{incarnation}");
    let router = Arc::new(InProcessRouter::default());
    let mut nodes = BTreeMap::new();
    let mut audits = BTreeMap::new();
    let mut hashes = BTreeSet::new();
    let mut restored_bootstrap = None;
    for id in 1..=3 {
        let (node_store, audit) = store(&root.path().join(format!("restored-{id}.redb"))).await;
        audits.insert(id, audit.clone());
        let restored = prepare_replicated_restore(
            &kasumi_engine::RestoreSource {
                timeout_ms: 300_000,
                destination_alias: "backup".into(),
                destination: backups.clone(),
                keys: Arc::new(LocalKeyProvider::new([43; 32])),
            },
            backup_id,
            kasumi_store::test_utils::with_custody(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            context(),
            ReplicaRestoreConfig {
                node_id: id,
                incarnation,
                voters: initial.voters.clone(),
                raft: Config::default(),
                admission: kasumi_engine::admission::NodeAdmission::new(Default::default())
                    .unwrap(),
            },
            router.clone(),
            audit,
        )
        .await
        .unwrap();
        assert!(
            restored
                .database
                .engine()
                .generation()
                .unwrap()
                .state
                .pending_restore
                .is_some()
        );
        hashes.insert(restored.bootstrap_sha256);
        restored_bootstrap = Some(restored.bootstrap);
        router.register(
            group.clone(),
            id,
            restored.database.raft_group().raft().clone(),
        );
        nodes.insert(id, restored.database);
    }
    assert_eq!(
        hashes.len(),
        1,
        "replicas must have identical restored genesis"
    );
    let restored_bootstrap = restored_bootstrap.unwrap();
    initialize_replicated(&nodes[&1], &restored_bootstrap)
        .await
        .unwrap();
    let active = leader(&nodes, None).await;
    assert_eq!(
        nodes[&active]
            .administer(context(), Operation::Suspend(false))
            .await
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    assert_eq!(
        nodes[&active]
            .get(&context(), "documents", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    nodes[&active].complete_restore(context()).await.unwrap();
    nodes[&active].complete_restore(context()).await.unwrap();
    nodes[&active]
        .administer(context(), Operation::Suspend(false))
        .await
        .unwrap();
    assert_eq!(
        nodes[&active]
            .get(&context(), "documents", "a")
            .await
            .unwrap()
            .version,
        receipt.revision
    );
    assert_eq!(
        nodes[&active].mutate(context(), batch()).await.unwrap(),
        receipt
    );
    shutdown_nodes(&mut nodes, &mut audits, &router, &group).await;
    nodes.clear();
    for id in 1..=3 {
        let (node_store, audit) = store(&root.path().join(format!("restored-{id}.redb"))).await;
        audits.insert(id, audit.clone());
        let db = open_replicated(
            id,
            kasumi_store::test_utils::with_custody(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &restored_bootstrap,
            router.clone(),
            Config::default(),
            audit,
        )
        .await
        .unwrap();
        db.install_archive_destination("backup".into(), backups.clone())
            .unwrap();
        router.register(group.clone(), id, db.raft_group().raft().clone());
        nodes.insert(id, db);
    }
    let active = leader(&nodes, None).await;
    assert!(
        nodes[&active]
            .engine()
            .generation()
            .unwrap()
            .state
            .pending_restore
            .is_none()
    );
    assert_eq!(
        nodes[&active]
            .get(&context(), "documents", "b")
            .await
            .unwrap()
            .version,
        receipt.revision
    );
    shutdown_nodes(&mut nodes, &mut audits, &router, &group).await;
    source.shutdown().await.unwrap();
    source_audit.shutdown().await;
}
