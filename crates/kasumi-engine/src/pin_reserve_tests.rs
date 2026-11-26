//! Forward progress under snapshot-pin pressure (Codex G02 ruling, 4.3).
//!
//! Tenants and the service audit share one node database and its snapshot
//! pin registry. Client holders (snapshot leases and cursors) keep their
//! selections alive across publications, and before the reserve nothing
//! bounded them: they could take every slot, after which a tenant's next
//! write, its successor capture, the service audit and a new tenant's
//! activation were refused. These tests use a 64-slot registry with the
//! production accounting, and assert each guarantee while the holders stay
//! alive.
use crate::admission::AdmissionConfig;
use crate::application_sources::completion::{CompletionCheckpoint, CompletionFault};
use crate::test_fixture_failure::FixtureResult;
use kasumi_store::{NodeStore, TenantReadView, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

/// A reduced effective registry: the production accounting on 64 slots.
const PINS: usize = 64;
/// Ordinary credits stop at 24, so 12 holders at two credits each.
const RESERVE: usize = 40;

fn context(tenant: &str, request: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: request.into(),
    }
}

fn put(tenant: &str, id: &str, version: u64) -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: format!("{tenant}-{id}-{version}"),
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"tenant": tenant, "id": id, "version": version}),
            expected: Precondition::Any,
        }],
    }
}

fn event(request: &str) -> SecurityEvent {
    SecurityEvent {
        kind: SecurityEventKind::AccessDenied,
        principal: Some("principal".into()),
        tenant: Some("tenant-a".into()),
        request_id: request.into(),
        outcome: SecurityOutcome::Denied,
    }
}

struct Fixture {
    node: NodeStore,
    audit: Arc<crate::SecurityAudit>,
    security: Arc<TenantStore>,
    storage: crate::test_utils::FixtureStorage,
    tenants: Vec<Arc<crate::Database>>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn open(reserve: usize) -> FixtureResult<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
        let storage = crate::test_utils::FixtureStorage::open(
            &persistent,
            &scratch,
            AdmissionConfig::default(),
        )?;
        let node = NodeStore::create_new(
            directory.path().join("persistent/pinned-node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            storage.persistent.clone(),
            storage.scratch.clone(),
            storage
                .persistent
                .native_storage_config()
                .with_directory_page_format(Default::default())
                .with_snapshot_pins(PINS),
        )?;
        node.reserve_snapshot_pins(reserve)
            .map_err(anyhow::Error::from)?;
        let security = TenantStore::initialize_catalog_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([0xA7; 32])),
        )
        .await?;
        let audit = crate::SecurityAudit::initialize(
            security.clone(),
            AuditRetentionBudget::default(),
            storage.admission.clone(),
        )?;
        let mut fixture = Self {
            node,
            audit,
            security,
            storage,
            tenants: Vec::new(),
            _directory: directory,
        };
        for tenant in ["tenant-a", "tenant-b"] {
            fixture.activate(tenant).await?;
        }
        Ok(fixture)
    }

    /// Open a tenant on the shared node: its first selection capture is the
    /// activation's pin.
    async fn activate(&mut self, tenant: &str) -> FixtureResult<Arc<crate::Database>> {
        let key = 0x10 + self.tenants.len() as u8;
        let store = TenantStore::initialize_catalog_fixture(
            self.node.clone(),
            tenant.into(),
            Arc::new(LocalKeyProvider::new([key; 32])),
        )
        .await?;
        let database = crate::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
                store,
                Arc::new(LocalKeyProvider::new([key ^ 0x5A; 32])),
            )
            .await?,
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: context(tenant, "grant").scopes,
                }],
                strict_read_audit: false,
            },
            Limits::default(),
            self.audit.clone(),
        )
        .await?;
        crate::test_utils::install_fixture_native_maintenance(&database, &self.storage.admission)?;
        database
            .administer(
                context(tenant, "schema"),
                Operation::CreateCollection(CollectionDefinition {
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                    name: "docs".into(),
                    schema: json!({"type": "object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                }),
            )
            .await?;
        self.tenants.push(database.clone());
        Ok(database)
    }

    async fn shutdown(self) {
        for database in self.tenants {
            database.shutdown().await.unwrap();
        }
        self.audit.shutdown().await.unwrap();
    }
}

async fn write(database: &crate::Database, tenant: &str, id: &str, version: u64) {
    database
        .mutate(
            context(tenant, &format!("{id}-{version}")),
            put(tenant, id, version),
        )
        .await
        .unwrap_or_else(|error| panic!("{tenant} write {id}/{version}: {error:?}"));
}

async fn body(database: &crate::Database, tenant: &str, id: &str) -> Option<serde_json::Value> {
    database
        .get(&context(tenant, "read"), "docs", id)
        .await
        .unwrap()
        .map(|document| document.body.clone())
}

/// Snapshot leases and cursors take ordinary credits before any effect and
/// are refused with `ResourceExhausted` at the registry less its reserve.
/// With those holders alive, each stranding a distinct predecessor, tenant
/// writes, the service audit and a new tenant's activation all complete.
#[tokio::test]
async fn client_holders_never_take_the_pins_writes_audit_and_activation_need() {
    let mut fixture = Fixture::open(RESERVE).await.unwrap();
    let names = ["tenant-a", "tenant-b"];
    let tenants = fixture.tenants.clone();
    for (database, tenant) in tenants.iter().zip(names) {
        for id in ["x", "y", "z"] {
            write(database, tenant, id, 0).await;
        }
    }
    // A cursor keeps its query's rows, and so their selection.
    let query: QueryRequest =
        serde_json::from_value(json!({"collection": "docs", "limit": 1})).unwrap();
    let page = tenants[0]
        .query(&context(names[0], "query"), query.clone())
        .await
        .unwrap();
    assert!(
        page.cursor.is_some(),
        "a one-row page of three keeps a cursor"
    );
    // Leases alternate between the tenants; each write after a lease makes
    // the leased generation historical, so every holder strands one.
    let mut leases = Vec::new();
    let mut version = 0;
    let refused = loop {
        let slot = leases.len() % names.len();
        match tenants[slot]
            .open_snapshot_lease(
                &context(names[slot], "lease"),
                OpenSnapshotLease { ttl_ms: 60_000 },
            )
            .await
        {
            Ok(lease) => leases.push((slot, lease)),
            Err(error) => break error,
        }
        version += 1;
        write(&tenants[slot], names[slot], "x", version).await;
        assert!(
            leases.len() <= PINS - RESERVE,
            "ordinary holders were never refused"
        );
    };
    assert_eq!(refused.code, ErrorCode::ResourceExhausted, "{refused:?}");
    assert!(refused.message.contains("snapshot pins"), "{refused:?}");
    // One cursor and eleven leases hold the 24 ordinary credits.
    assert_eq!(leases.len(), (PINS - RESERVE) / 2 - 1);
    let usage = fixture.node.snapshot_pin_use().unwrap();
    assert_eq!(
        (usage.ordinary, usage.reserve),
        ((PINS - RESERVE) as u64, RESERVE as u64)
    );
    // The next cursor is refused too, with no cursor created.
    let refused = tenants[1]
        .query(&context(names[1], "query"), query.clone())
        .await
        .err()
        .expect("cursor refused at the ordinary limit");
    assert_eq!(refused.code, ErrorCode::ResourceExhausted, "{refused:?}");
    // Every holder stays alive while critical work proceeds.
    for round in 1..=4 {
        for (database, tenant) in tenants.iter().zip(names) {
            write(database, tenant, "y", round).await;
        }
        fixture
            .audit
            .record_sync(event(&format!("audit-{round}")))
            .unwrap();
    }
    let activated = fixture.activate("tenant-c").await.unwrap();
    write(&activated, "tenant-c", "x", 1).await;
    assert_eq!(
        body(&activated, "tenant-c", "x").await,
        Some(json!({"tenant": "tenant-c", "id": "x", "version": 1}))
    );
    assert_eq!(
        body(&tenants[0], names[0], "y").await,
        Some(json!({"tenant": "tenant-a", "id": "y", "version": 4}))
    );
    let usage = fixture.node.snapshot_pin_use().unwrap();
    assert!(usage.held <= usage.limit && usage.ordinary == (PINS - RESERVE) as u64);
    // Released holders return their credits, and a lease opens again.
    for (slot, lease) in leases.drain(..) {
        tenants[slot]
            .close_snapshot_lease(&context(names[slot], "close"), &lease.lease_id)
            .await
            .unwrap();
    }
    drop(page);
    let lease = tenants[1]
        .open_snapshot_lease(
            &context(names[1], "again"),
            OpenSnapshotLease { ttl_ms: 60_000 },
        )
        .await
        .unwrap();
    tenants[1]
        .close_snapshot_lease(&context(names[1], "again"), &lease.lease_id)
        .await
        .unwrap();
    fixture.shutdown().await;
}

/// A committed write captures its successor selection after the commit. Its
/// pin slot was reserved with the queued read before the commit, so taking
/// every free slot between the durable commit and the capture cannot refuse
/// it: the write completes and is visible while those readers stay alive.
#[tokio::test]
async fn a_committed_write_captures_its_successor_with_every_free_pin_held() {
    let fixture = Fixture::open(0).await.unwrap();
    let database = fixture.tenants[0].clone();
    write(&database, "tenant-a", "before", 1).await;
    let holders: Arc<Mutex<Vec<TenantReadView>>> = Arc::default();
    let refusals = Arc::new(Mutex::new(0usize));
    {
        let (holders, refusals, store) =
            (holders.clone(), refusals.clone(), fixture.security.clone());
        database
            .engine()
            .application_sources_for_test()
            .expect("installed application sources")
            .arm_completion_fault_for_test(
                CompletionCheckpoint::Published,
                CompletionFault::Window(Box::new(move || {
                    let mut held = holders.lock().unwrap();
                    loop {
                        match store.read_view() {
                            Ok(view) => held.push(view),
                            Err(error) => {
                                assert!(
                                    kasumi_raft::capacity_refusal::refused(&error),
                                    "{error:#}"
                                );
                                *refusals.lock().unwrap() += 1;
                                break;
                            }
                        }
                        assert!(held.len() <= PINS);
                    }
                })),
            );
    }
    write(&database, "tenant-a", "after", 2).await;
    assert_eq!(
        *refusals.lock().unwrap(),
        1,
        "the window held every free slot"
    );
    let usage = fixture.node.snapshot_pin_use().unwrap();
    assert!(!holders.lock().unwrap().is_empty());
    assert!(usage.held + 3 >= usage.limit, "{usage:?}");
    assert_eq!(
        body(&database, "tenant-a", "after").await,
        Some(json!({"tenant": "tenant-a", "id": "after", "version": 2}))
    );
    holders.lock().unwrap().clear();
    write(&database, "tenant-a", "later", 3).await;
    fixture.shutdown().await;
}
