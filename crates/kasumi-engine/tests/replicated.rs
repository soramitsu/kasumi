use kasumi_engine::test_utils::{open_fixture, open_fixture_replicated};
mod common;

use kasumi_engine::{Database, ReplicaPlacement, ReplicatedBootstrap, initialize_replicated};
use kasumi_raft::{InProcessRouter, server_config};
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
        genesis: kasumi_engine::ReplicatedGenesis::Application,
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
fn replica_fixture(root: &std::path::Path, name: &str) -> common::PhysicalFixture {
    let directory = root.join(name);
    kasumi_store::private_files::create_directory(&directory).unwrap();
    common::PhysicalFixture::new(&directory.join("node.kv"), Default::default())
}
async fn store(
    physical: &common::PhysicalFixture,
    path: &std::path::Path,
    create: bool,
) -> (
    Arc<TenantStore>,
    Arc<kasumi_engine::SecurityAudit>,
    NodeStore,
) {
    let node = (if create {
        physical
            .storage
            .create_new(path, kasumi_store::test_utils::NODE_STORE_ID)
    } else {
        physical
            .storage
            .open_existing(path, kasumi_store::test_utils::NODE_STORE_ID)
    })
    .unwrap();
    let audit = if create {
        common::security_audit(node.clone(), physical.storage.admission.clone()).await
    } else {
        common::existing_security_audit(node.clone(), physical.storage.admission.clone()).await
    };
    let store = if create {
        TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
    } else {
        TenantStore::open_existing_fixture(
            node.clone(),
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
    }
    .unwrap();
    (store, audit, node)
}
async fn shutdown_nodes(
    nodes: &mut BTreeMap<u64, Arc<Database>>,
    audits: &mut BTreeMap<u64, Arc<kasumi_engine::SecurityAudit>>,
    node_owners: &mut BTreeMap<u64, NodeStore>,
    router: &InProcessRouter,
    group: &str,
) {
    for (&id, db) in nodes.iter() {
        router.unregister(group, id);
        db.shutdown().await.unwrap();
    }
    nodes.clear();
    for audit in audits.values() {
        audit.shutdown().await.unwrap();
    }
    audits.clear();
    for node in node_owners.values() {
        node.shutdown().await.unwrap();
    }
    node_owners.clear();
}
async fn leader(nodes: &BTreeMap<u64, Arc<Database>>, exclude: Option<u64>) -> u64 {
    let mut last_barriers = BTreeMap::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for (&id, db) in nodes {
                if Some(id) == exclude {
                    continue;
                }
                // A metrics borrow holds a read lock. Release it before the
                // barrier, which may need the Raft worker to publish metrics.
                let current_leader = db.raft_group().raft().metrics().borrow().current_leader;
                if current_leader == Some(id) {
                    // Keep the barrier's own deadline inside the overall
                    // election bound; a 200 ms probe would cancel before one
                    // production heartbeat round can complete.
                    match db.raft_group().linearizable_barrier().await {
                        Ok(_) => return id,
                        Err(error) => {
                            last_barriers.insert(id, format!("{error:#}"));
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|error| {
        let observations: Vec<_> = nodes
            .iter()
            .map(|(id, db)| (*id, db.raft_group().raft().metrics().borrow().clone()))
            .collect();
        panic!(
            "no quorum-backed leader excluding {exclude:?}: {error}; \
             last_barriers={last_barriers:?}; metrics={observations:?}"
        )
    })
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
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical: BTreeMap<_, _> = (1..=3)
        .map(|id| (id, replica_fixture(root.path(), &id.to_string())))
        .collect();
    let bootstrap = bootstrap();
    let group = format!("tenant-a/{}", bootstrap.incarnation);
    let router = Arc::new(InProcessRouter::default());
    let mut nodes = BTreeMap::new();
    let mut audits = BTreeMap::new();
    let mut node_owners = BTreeMap::new();
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(id.to_string()).join("node.kv"),
            true,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let db = open_fixture_replicated(
            id,
            kasumi_store::test_utils::initialize_custody_fixture(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            // These replicas use real durable storage, as the server does.
            server_config(),
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
    query.cursor = first_page.cursor.clone();
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
        scope: kasumi_types::StagedTransactionScope {
            tenant: context().tenant,
            principal: context().principal,
            incarnation: nodes[&first]
                .engine()
                .generation()
                .unwrap()
                .state
                .incarnation
                .clone(),
        },
        transaction_id: "across-leaders".into(),
        manifest_digest: staged_digest(&manifest).unwrap().0,
    };
    nodes[&first]
        .begin_staged_transaction(
            context(),
            BeginStagedTransaction {
                scope: staged.scope.clone(),
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
            .expect("document exists")
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
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
    nodes.clear();
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(id.to_string()).join("node.kv"),
            false,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let db = open_fixture_replicated(
            id,
            kasumi_store::test_utils::open_existing_custody_fixture(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            server_config(),
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
            .expect("document exists")
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
            .expect("document exists")
            .version,
        receipt.revision
    );
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
}

#[tokio::test]
async fn deployment_modes_and_live_store_ownership_cannot_be_overridden() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical = replica_fixture(root.path(), "local");
    let (store, audit, node_owner) =
        store(&physical, &root.path().join("local/node.kv"), true).await;
    let bootstrap = bootstrap();
    let db = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
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
        open_fixture(
            kasumi_store::test_utils::open_existing_custody_fixture(
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
        open_fixture_replicated(
            1,
            kasumi_store::test_utils::open_existing_custody_fixture(
                store.clone(),
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
            )
            .await
            .unwrap(),
            &bootstrap,
            Arc::new(InProcessRouter::default()),
            server_config(),
            audit.clone(),
        )
        .await
        .is_err()
    );
    let reopened = open_fixture(
        kasumi_store::test_utils::open_existing_custody_fixture(
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
    audit.shutdown().await.unwrap();
    node_owner.shutdown().await.unwrap();
    let mut invalid = bootstrap;
    invalid.voters.get_mut(&2).unwrap().failure_domain = "zone-1".into();
    assert!(invalid.validate().is_err());
    invalid.voters.remove(&2);
    assert!(invalid.validate().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_restore_has_identical_genesis_and_requires_quorum_audit_before_activation() {
    use kasumi_engine::{ReplicaRestoreConfig, prepare_replicated_restore};
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let initial = bootstrap();
    let source_physical = replica_fixture(root.path(), "source");
    let physical: BTreeMap<_, _> = (1..=3)
        .map(|id| (id, replica_fixture(root.path(), &format!("restored-{id}"))))
        .collect();
    let (source_store, source_audit, source_node) =
        store(&source_physical, &root.path().join("source/node.kv"), true).await;
    let source = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
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
        kasumi_store::FilesystemBackupDestination::new(
            root.path().join("source/backups"),
            16 << 20,
            source_physical.storage.persistent.clone(),
        )
        .unwrap(),
    );
    let cold_path = root.path().join("source/cold");
    let cold = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            &cold_path,
            16 << 20,
            source_physical.storage.persistent.clone(),
        )
        .unwrap(),
    );
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
    source.shutdown().await.unwrap();
    source_audit.shutdown().await.unwrap();
    source_node.shutdown().await.unwrap();
    drop(source);
    drop(source_audit);
    drop(source_node);
    drop(backups);
    source_physical.storage.persistent.pause().unwrap();
    std::fs::remove_dir_all(cold_path).unwrap();
    source_physical
        .storage
        .persistent
        .reconcile(&kasumi_store::CensusCancellation::default())
        .unwrap();
    let backups = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            root.path().join("source/backups"),
            16 << 20,
            source_physical.storage.persistent.clone(),
        )
        .unwrap(),
    );
    let incarnation = uuid::Uuid::new_v4();
    let group = format!("tenant-a/{incarnation}");
    let router = Arc::new(InProcessRouter::default());
    let mut nodes = BTreeMap::new();
    let mut audits = BTreeMap::new();
    let mut node_owners = BTreeMap::new();
    let mut hashes = BTreeSet::new();
    let mut restored_bootstrap = None;
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(format!("restored-{id}/node.kv")),
            true,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let restored = prepare_replicated_restore(
            &kasumi_engine::RestoreSource {
                timeout_ms: 300_000,
                destination_alias: "backup".into(),
                destination: backups.clone(),
                keys: Arc::new(LocalKeyProvider::new([43; 32])),
            },
            backup_id,
            kasumi_store::test_utils::initialize_custody_fixture(
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
                raft: server_config(),
                admission: audit.admission().clone(),
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
            .expect("document exists")
            .version,
        receipt.revision
    );
    assert_eq!(
        nodes[&active].mutate(context(), batch()).await.unwrap(),
        receipt
    );
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
    nodes.clear();
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(format!("restored-{id}/node.kv")),
            false,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let db = open_fixture_replicated(
            id,
            kasumi_store::test_utils::open_existing_custody_fixture(
                node_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &restored_bootstrap,
            router.clone(),
            server_config(),
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
            .expect("document exists")
            .version,
        receipt.revision
    );
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
}

/// Hold the first manifest after it is durably uploaded but before the caller
/// can submit its catalog publication. The next leader sees only the objects,
/// never the first node's local in-flight registry.
struct HeldArchiveManifest {
    inner: kasumi_store::FilesystemBackupDestination,
    puts: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl kasumi_store::BackupDestination for HeldArchiveManifest {
    fn namespace_binding(&self) -> anyhow::Result<BackupNamespaceBinding> {
        self.inner.namespace_binding()
    }
    async fn put(&self, id: uuid::Uuid, bytes: kasumi_store::BackupUpload) -> anyhow::Result<()> {
        let number = self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let result = self.inner.put(id, bytes).await;
        if number == 1 {
            assert!(result.is_ok(), "first manifest upload failed: {result:?}");
            self.entered.notify_one();
            self.release.notified().await;
        }
        result
    }
    async fn get(&self, id: uuid::Uuid, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        self.inner.get(id, max_bytes).await
    }
}

fn archive_object_bytes(path: &std::path::Path) -> BTreeMap<uuid::Uuid, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_str().unwrap();
            name.strip_suffix(".kasumi").map(|id| {
                (
                    uuid::Uuid::parse_str(id).unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_retry_after_leader_change_adopts_original_objects_and_survives_restart() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical: BTreeMap<_, _> = (1..=3)
        .map(|id| (id, replica_fixture(root.path(), &id.to_string())))
        .collect();
    let bootstrap = bootstrap();
    let group = format!("tenant-a/{}", bootstrap.incarnation);
    let router = Arc::new(InProcessRouter::default());
    let mut nodes = BTreeMap::new();
    let mut audits = BTreeMap::new();
    let mut node_owners = BTreeMap::new();
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(id.to_string()).join("node.kv"),
            true,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let db = open_fixture_replicated(
            id,
            kasumi_store::test_utils::initialize_custody_fixture(
                node_store,
                Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            server_config(),
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
                retention_class: CollectionRetentionClass::ArchivableHistory,
                write_mode: CollectionWriteMode::AppendOnly,
                name: "documents".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let cutoff = nodes[&first]
        .mutate(context(), batch())
        .await
        .unwrap()
        .revision;
    let cold_path = root.path().join("1/cold");
    let destination = Arc::new(HeldArchiveManifest {
        inner: kasumi_store::FilesystemBackupDestination::new(
            &cold_path,
            16 << 20,
            physical[&1].storage.persistent.clone(),
        )
        .unwrap(),
        puts: std::sync::atomic::AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    for node in nodes.values() {
        node.install_archive_destination("cold".into(), destination.clone())
            .unwrap();
    }
    let request = ArchiveHistory {
        archive_id: "failover-period".into(),
        collection: "documents".into(),
        cutoff_revision: cutoff,
        destination: "cold".into(),
    };
    let original = {
        let node = nodes[&first].clone();
        let request = request.clone();
        tokio::spawn(async move { node.archive_history(context(), request).await })
    };
    tokio::time::timeout(Duration::from_secs(300), destination.entered.notified())
        .await
        .expect("original never uploaded its manifest");
    let original_objects = archive_object_bytes(&cold_path);
    assert_eq!(original_objects.len(), 2);
    assert!(
        !nodes[&first]
            .engine()
            .generation()
            .unwrap()
            .state
            .history_archives
            .contains_key(&request.archive_id)
    );

    router.isolate(&group, first, true);
    let second = leader(&nodes, Some(first)).await;
    // The request remains the same despite an unrelated schema generation.
    // Schema fences belong to each publication proposal, not immutable bytes.
    let before_schema = nodes[&second]
        .engine()
        .generation()
        .unwrap()
        .state
        .schema_epoch;
    nodes[&second]
        .administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: CollectionRetentionClass::Operational,
                write_mode: CollectionWriteMode::Mutable,
                name: "unrelated".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    assert!(
        nodes[&second]
            .engine()
            .generation()
            .unwrap()
            .state
            .schema_epoch
            > before_schema
    );
    let receipt = nodes[&second]
        .archive_history(context(), request.clone())
        .await
        .unwrap();
    let archive = nodes[&second]
        .engine()
        .generation()
        .unwrap()
        .state
        .history_archives[&request.archive_id]
        .clone();
    let referenced: BTreeSet<_> = archive
        .manifest
        .chunks
        .iter()
        .map(|chunk| uuid::Uuid::parse_str(&chunk.object_id).unwrap())
        .chain([uuid::Uuid::parse_str(&archive.manifest_object_id).unwrap()])
        .collect();
    assert_eq!(referenced, original_objects.keys().copied().collect());
    assert_eq!(
        archive_object_bytes(&cold_path),
        original_objects,
        "retry must not overwrite or orphan objects"
    );
    assert_eq!(
        destination.puts.load(std::sync::atomic::Ordering::SeqCst),
        4
    );
    assert_eq!(receipt.revision, archive.published_revision);
    let mut different = request.clone();
    different.cutoff_revision -= 1;
    assert_eq!(
        nodes[&second]
            .archive_history(context(), different)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        destination.puts.load(std::sync::atomic::Ordering::SeqCst),
        4
    );

    // The old caller can be cancelled without damaging the winner's objects.
    original.abort();
    assert!(original.await.unwrap_err().is_cancelled());
    router.isolate(&group, first, false);
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
    for id in 1..=3 {
        let (node_store, audit, node_owner) = store(
            &physical[&id],
            &root.path().join(id.to_string()).join("node.kv"),
            false,
        )
        .await;
        audits.insert(id, audit.clone());
        node_owners.insert(id, node_owner);
        let db = open_fixture_replicated(
            id,
            kasumi_store::test_utils::open_existing_custody_fixture(
                node_store,
                Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            &bootstrap,
            router.clone(),
            server_config(),
            audit,
        )
        .await
        .unwrap();
        db.install_archive_destination("cold".into(), destination.clone())
            .unwrap();
        router.register(group.clone(), id, db.raft_group().raft().clone());
        nodes.insert(id, db);
    }
    let recovered = leader(&nodes, None).await;
    assert_eq!(
        nodes[&recovered]
            .archive_history(context(), request)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(
        nodes[&recovered]
            .get(&context(), "documents", "a")
            .await
            .unwrap()
            .unwrap()
            .version,
        cutoff
    );
    assert_eq!(archive_object_bytes(&cold_path), original_objects);
    assert_eq!(
        destination.puts.load(std::sync::atomic::Ordering::SeqCst),
        4
    );
    shutdown_nodes(&mut nodes, &mut audits, &mut node_owners, &router, &group).await;
}
