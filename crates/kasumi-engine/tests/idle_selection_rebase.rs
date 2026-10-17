//! A tenant's current Generation holds its application selection, a read pin
//! on the shared node root, and reclamation keeps every file a pinned root
//! names. A tenant that never applies again must not keep a root from before
//! the node's latest evacuation: its database worker moves the selection onto
//! the current root at the same applied boundary. Snapshot leases keep their
//! own Generation, and that root, until they expire.
//!
//! Two tenants share one node store. Reopening it rolls a fresh arena, so the
//! pages written before are older than the cutoffs of every cycle B's writes
//! then drive, each followed by a step the size of the node worker's.
mod common;

use kasumi_engine::{Database, SecurityAudit, admission::AdmissionConfig};
use kasumi_kv::{MaintenanceBudget, StorageCompactionPhase, StorageMaintenanceStatus};
use kasumi_store::{
    NodeStore, RegisteredNodeOpening, TenantStorageSet, TenantStore, test_utils::LocalKeyProvider,
};
use kasumi_types::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const NODE_WORKER_STEP: MaintenanceBudget = MaintenanceBudget {
    units: 512,
    mutations: 1,
};
const LEASE_TTL: Duration = Duration::from_secs(30);

fn context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "request".into(),
    }
}

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: false,
    }
}

type GroupFile = (&'static str, u64);

/// Segment and arena identifiers present in a node group directory.
fn group_files(group: &Path) -> BTreeSet<GroupFile> {
    let mut pending = vec![group.to_owned()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_str().unwrap();
            for (suffix, kind) in [(".kvseg", "segment"), (".kvdir", "arena")] {
                if let Some(id) = name.strip_suffix(suffix) {
                    files.insert((kind, u64::from_str_radix(id, 16).unwrap()));
                }
            }
        }
    }
    files
}

/// Everything below the newest segment and the newest arena: the files a
/// cycle beginning now may evacuate and reclaim.
fn candidates(files: &BTreeSet<GroupFile>) -> BTreeSet<GroupFile> {
    let newest = |kind| {
        files
            .iter()
            .filter(|(present, _)| *present == kind)
            .map(|(_, id)| *id)
            .max()
    };
    files
        .iter()
        .filter(|(kind, id)| Some(*id) < newest(*kind))
        .copied()
        .collect()
}

#[derive(Debug, PartialEq)]
struct TenantView {
    revision: u64,
    incarnation: String,
    policy_epoch: u64,
    schema_epoch: u64,
    document_count: u64,
    collections: Vec<String>,
    documents: Vec<Option<Value>>,
}

struct Tenant {
    name: &'static str,
    stores: Arc<TenantStorageSet>,
    database: Arc<Database>,
}
impl Tenant {
    async fn open(
        node: &NodeStore,
        name: &'static str,
        key: u8,
        audit: &Arc<SecurityAudit>,
        existing: bool,
    ) -> Self {
        let application = Arc::new(LocalKeyProvider::new([key; 32]));
        let custody = Arc::new(LocalKeyProvider::new([key ^ 0x5A; 32]));
        let stores = if existing {
            let store = TenantStore::open_existing_fixture(node.clone(), name.into(), application)
                .await
                .unwrap();
            kasumi_store::test_utils::open_existing_custody_fixture(store, custody)
                .await
                .unwrap()
        } else {
            let store =
                TenantStore::initialize_catalog_fixture(node.clone(), name.into(), application)
                    .await
                    .unwrap();
            kasumi_store::test_utils::initialize_custody_fixture(store, custody)
                .await
                .unwrap()
        };
        let database =
            kasumi_engine::open_local(stores.clone(), policy(), Limits::default(), audit.clone())
                .await
                .unwrap();
        Self {
            name,
            stores,
            database,
        }
    }

    async fn create_documents(&self) {
        self.database
            .administer(
                context(self.name),
                Operation::CreateCollection(CollectionDefinition {
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                    name: "docs".into(),
                    schema: json!({"type": "object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                }),
            )
            .await
            .unwrap();
    }

    async fn put(&self, id: &str, body: Value) -> WriteReceipt {
        self.database
            .mutate(
                context(self.name),
                MutationBatch {
                    read_set: Vec::new(),
                    idempotency_key: format!("{}-{}", self.name, uuid::Uuid::new_v4()),
                    operations: vec![Mutation::Put {
                        collection: "docs".into(),
                        id: id.into(),
                        body,
                        expected: Precondition::Any,
                    }],
                },
            )
            .await
            .unwrap()
    }

    async fn body(&self, id: &str) -> Option<Value> {
        self.database
            .get(&context(self.name), "docs", id)
            .await
            .unwrap()
            .map(|document| document.body.clone())
    }

    async fn leased(&self, lease: &SnapshotLease, id: &str) -> Result<(u64, Option<Value>)> {
        let page = self
            .database
            .read_snapshot_page(
                &context(self.name),
                ReadSnapshotPage {
                    lease_id: lease.lease_id.clone(),
                    documents: vec![DocumentKey {
                        collection: "docs".into(),
                        id: id.into(),
                    }],
                },
            )
            .await?;
        Ok((
            page.revision,
            page.documents[0]
                .document
                .as_ref()
                .map(|document| document.body.clone()),
        ))
    }

    async fn view(&self) -> TenantView {
        let (revision, incarnation, policy_epoch, schema_epoch, document_count, collections) = {
            let generation = self.database.engine().generation().unwrap();
            let state = &generation.state;
            (
                state.revision,
                state.incarnation.clone(),
                state.policy_epoch,
                state.schema_epoch,
                state.document_count,
                state.collections.keys().cloned().collect(),
            )
        };
        let mut documents = Vec::new();
        for id in ["a-0", "a-1", "a-2"] {
            documents.push(self.body(id).await);
        }
        TenantView {
            revision,
            incarnation,
            policy_epoch,
            schema_epoch,
            document_count,
            collections,
            documents,
        }
    }

    /// Identity of the published current Generation. The returned owner is
    /// dropped at once: retaining it would keep its selection's root pinned.
    fn generation(&self) -> usize {
        Arc::as_ptr(&self.database.engine().generation().unwrap()) as usize
    }

    /// Whether the worker publishes a successor without any apply. Its
    /// predecessor is still live during that publication, so the successor
    /// never reuses the observed allocation.
    async fn republished(&self, observed: usize) -> bool {
        for _ in 0..100 {
            if self.generation() != observed {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    async fn shutdown(self) {
        self.database.shutdown().await.unwrap();
        drop(self.database);
        self.stores.shutdown().await.unwrap();
    }
}

struct Fixture {
    physical: common::PhysicalFixture,
    group: PathBuf,
    audit_node: NodeStore,
    audit: Arc<SecurityAudit>,
    node: NodeStore,
    a: Tenant,
    b: Tenant,
    writes: u64,
    _directory: tempfile::TempDir,
}
impl Fixture {
    /// A writes three documents and B one. After the node reopens, A stays
    /// idle with the selection its startup took, and B's first write rolls a
    /// fresh arena. The security ledger lives on its own node.
    async fn open() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let group = directory.path().join("node.kv");
        let physical = common::PhysicalFixture::new(&group, AdmissionConfig::default());
        let audit_node = physical
            .storage
            .create_new(
                directory.path().join("audit.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let audit =
            common::security_audit(audit_node.clone(), physical.storage.admission.clone()).await;
        let node = physical
            .storage
            .create_new(&group, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let a = Tenant::open(&node, "tenant-a", 0x21, &audit, false).await;
        let b = Tenant::open(&node, "tenant-b", 0x42, &audit, false).await;
        for tenant in [&a, &b] {
            tenant.create_documents().await;
        }
        for i in 0..3 {
            a.put(&format!("a-{i}"), json!({"tenant": "a", "version": 1, "i": i}))
                .await;
        }
        b.put("b-0", json!({"write": 0})).await;
        a.shutdown().await;
        b.shutdown().await;
        node.shutdown().await.unwrap();
        drop(node);
        let node = physical
            .storage
            .open_existing(&group, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let a = Tenant::open(&node, "tenant-a", 0x21, &audit, true).await;
        let b = Tenant::open(&node, "tenant-b", 0x42, &audit, true).await;
        let mut fixture = Self {
            physical,
            group,
            audit_node,
            audit,
            node,
            a,
            b,
            writes: 0,
            _directory: directory,
        };
        fixture.write_b().await;
        fixture
    }

    async fn write_b(&mut self) {
        self.writes += 1;
        self.b
            .put(
                &format!("b-{}", self.writes % 8),
                json!({"write": self.writes}),
            )
            .await;
    }

    fn files(&self) -> BTreeSet<GroupFile> {
        group_files(&self.group)
    }

    /// Request one cycle and drive it to Idle as a serving node does: every
    /// B write runs the inline step, and a node-worker step follows it.
    async fn cycle(&mut self) -> StorageMaintenanceStatus {
        let start = self.node.storage_maintenance_status().unwrap();
        assert_eq!(start.phase, StorageCompactionPhase::Idle, "{start:?}");
        self.node.request_storage_compaction().unwrap();
        let opening = RegisteredNodeOpening::retained(
            self.physical.storage.persistent.memory().clone(),
            self.node.registered_opening_id().unwrap(),
        )
        .unwrap();
        for _ in 0..5_000 {
            self.write_b().await;
            opening.run_maintenance(NODE_WORKER_STEP).unwrap();
            let status = self.node.storage_maintenance_status().unwrap();
            if status.cycle > start.cycle && status.phase == StorageCompactionPhase::Idle {
                return status;
            }
        }
        panic!(
            "cycle after {start:?} did not finish: {:?}",
            self.node.storage_maintenance_status()
        );
    }

    async fn shutdown(self) {
        self.a.shutdown().await;
        self.b.shutdown().await;
        self.node.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.audit_node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_tenant_releases_the_files_an_evacuation_emptied() {
    let mut fixture = Fixture::open().await;
    let before = candidates(&fixture.files());
    assert!(
        before.iter().any(|(kind, _)| *kind == "arena"),
        "{before:?}"
    );
    let idle = fixture.a.generation();
    // Reclamation's first cohort may capture A's startup root before any
    // worker tick, so this cycle can still keep what that root names.
    let first = fixture.cycle().await;
    let rebased = fixture.a.republished(idle).await;
    let second = fixture.cycle().await;
    let kept: BTreeSet<_> = before.intersection(&fixture.files()).copied().collect();
    assert!(
        kept.is_empty(),
        "A's pre-cycle files survive: {kept:?}; rebased={rebased}; first={first:?}; second={second:?}"
    );
    assert_eq!(second.snapshot_retained_files, 0, "{second:?}");
    assert_eq!(second.garbage_files, 0, "{second:?}");
    assert!(rebased);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebased_selection_keeps_reads_revision_and_later_applies() {
    let mut fixture = Fixture::open().await;
    let before = fixture.a.view().await;
    assert_eq!(before.documents.iter().flatten().count(), 3, "{before:?}");
    let idle = fixture.a.generation();
    fixture.cycle().await;
    assert!(fixture.a.republished(idle).await);
    assert_eq!(fixture.a.view().await, before);
    // The rebased Generation is the predecessor of A's next apply.
    let receipt = fixture.a.put("a-3", json!({"tenant": "a", "i": 3})).await;
    assert_eq!(receipt.revision, before.revision + 1);
    assert_eq!(
        fixture.a.body("a-3").await,
        Some(json!({"tenant": "a", "i": 3}))
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_lease_keeps_its_generation_and_root_until_expiry() {
    let mut fixture = Fixture::open().await;
    let before = candidates(&fixture.files());
    let original = json!({"tenant": "a", "version": 1, "i": 0});
    let lease = fixture
        .a
        .database
        .open_snapshot_lease(
            &context("tenant-a"),
            OpenSnapshotLease {
                ttl_ms: LEASE_TTL.as_millis() as u64,
            },
        )
        .await
        .unwrap();
    let opened = Instant::now();
    let idle = fixture.a.generation();
    fixture.cycle().await;
    assert!(fixture.a.republished(idle).await);
    // The rebase changed nothing the lease refreshes against.
    assert_eq!(
        fixture.a.leased(&lease, "a-0").await.unwrap(),
        (lease.revision, Some(original.clone()))
    );
    // A's next apply moves its current Generation on; the lease keeps its own.
    let updated = json!({"tenant": "a", "version": 2, "i": 0});
    fixture.a.put("a-0", updated.clone()).await;
    assert_eq!(fixture.a.body("a-0").await, Some(updated));
    assert_eq!(
        fixture.a.leased(&lease, "a-0").await.unwrap(),
        (lease.revision, Some(original))
    );
    // That Generation still pins the root from before the first cycle.
    let held = fixture.cycle().await;
    assert!(opened.elapsed() < LEASE_TTL, "the lease expired too early");
    assert!(held.snapshot_retained_files > 0, "{held:?}");
    assert!(!before.is_disjoint(&fixture.files()), "{held:?}");
    // At expiry the database worker, ticking every second, drops the lease
    // and its old selection.
    tokio::time::sleep_until((opened + LEASE_TTL + Duration::from_secs(5)).into()).await;
    assert_eq!(
        fixture.a.leased(&lease, "a-0").await.unwrap_err().code,
        ErrorCode::CursorExpired
    );
    let released = fixture.cycle().await;
    assert_eq!(released.snapshot_retained_files, 0, "{released:?}");
    let kept: BTreeSet<_> = before.intersection(&fixture.files()).copied().collect();
    assert!(kept.is_empty(), "{kept:?}; {released:?}");
    fixture.shutdown().await;
}
