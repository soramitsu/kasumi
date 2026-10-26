//! The standalone writer's own storage work runs outside any committed apply:
//! the journal append before its entry commits, and the periodic snapshot
//! beside later appends. Native Resident traffic can hold every byte and ledger
//! slot, and RSS above the high-water mark refuses every new reservation, while
//! that work runs. A refusal may reject the one write whose entry never reached
//! the journal, or defer the snapshot while the journal keeps every entry, but
//! it must never close the tenant.
use crate::admission::{AdmissionConfig, MemorySource, NodeAdmission, Reservation};
use crate::test_fixture_failure::FixtureResult;
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

const TENANT: &str = "local-writer";
// RSS samples are compared with this high-water mark every 10 ms.
const HIGH_WATER: u64 = 1 << 30;
// Entries between periodic snapshots, instead of the installed 5000.
const INTERVAL: u64 = 4;

type Position = Option<openraft::LogId<u64>>;

fn context(request_id: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: TENANT.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: request_id.into(),
    }
}

fn put(key: &str, id: &str) -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: key.into(),
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"id": id, "key": key}),
            expected: Precondition::Any,
        }],
    }
}

/// Hold every remaining byte and ledger slot as native Resident traffic does.
fn exhaust_native(admission: &Arc<NodeAdmission>) -> Vec<Reservation> {
    let max = admission.policy().max_inflight_bytes.unwrap();
    let free = max - admission.snapshot().reserved_bytes;
    let mut held = vec![admission.reserve_resident(free).unwrap()];
    while let Ok(slot) = admission.reserve_resident(0) {
        held.push(slot);
    }
    assert!(admission.reserve_resident(0).is_err());
    held
}

struct Rss(AtomicU64);
impl MemorySource for Rss {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
impl Rss {
    /// Cross the high-water mark, or fall back below it, and wait on this
    /// blocking thread until admission has sampled the change.
    fn press(&self, admission: &NodeAdmission, pressured: bool) {
        self.0
            .store(if pressured { 2 * HIGH_WATER } else { 0 }, Ordering::SeqCst);
        for _ in 0..5000 {
            if admission.snapshot().pressured == pressured {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("RSS pressure {pressured} was not observed");
    }
}

struct Fixture {
    database: Arc<crate::Database>,
    audit: Arc<crate::SecurityAudit>,
    admission: Arc<NodeAdmission>,
    rss: Arc<Rss>,
    _storage: crate::test_utils::FixtureStorage,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn open() -> FixtureResult<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                max_inflight_bytes: Some(
                    2 * crate::test_utils::NATIVE_RAFT_HEADROOM_BYTES + (256 << 20),
                ),
                // The installed kasumid reserve for retained cache work.
                cache_work_reserve_bytes: Some(64 << 20),
                cache_work_reserve_slots: Some(64),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let rss = Arc::new(Rss(AtomicU64::new(0)));
        let admission = NodeAdmission::create(
            AdmissionConfig {
                sample_interval_ms: 10,
                max_sample_age_ms: 10,
                ..config
            },
            HIGH_WATER,
            rss.clone(),
            Arc::new(kasumi_clock::SystemLeaseClock),
        )?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent,
            &scratch,
            admission.clone(),
        )?;
        let node = storage.create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let audit = crate::SecurityAudit::initialize(
            TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                Arc::new(LocalKeyProvider::new([0xA7; 32])),
            )
            .await?,
            AuditRetentionBudget::default(),
            admission.clone(),
        )?;
        let store = TenantStore::initialize_catalog_fixture(
            node,
            TENANT.into(),
            Arc::new(LocalKeyProvider::new([97; 32])),
        )
        .await?;
        let database = crate::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
                store,
                Arc::new(LocalKeyProvider::new([98; 32])),
            )
            .await?,
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: context("owner").scopes,
                }],
                strict_read_audit: false,
            },
            Limits::default(),
            audit.clone(),
        )
        .await?;
        // Production standalone owners install the native maintenance escrow
        // and the ordinary-operation protection before serving.
        crate::test_utils::install_fixture_native_maintenance(&database, &admission)?;
        database
            .administer(
                context("schema"),
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
        Ok(Self {
            database,
            audit,
            admission,
            rss,
            _storage: storage,
            _directory: directory,
        })
    }

    fn group(&self) -> &kasumi_raft::RaftGroup {
        self.database.raft_group()
    }

    #[allow(
        clippy::result_large_err,
        reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
    )]
    fn document(&self, id: &str) -> FixtureResult<Option<serde_json::Value>> {
        Ok(
            self.database.engine().generation()?.state.collections["docs"]
                .documents
                .get(id)
                .map(|document| document.body.clone()),
        )
    }

    /// Write until one periodic snapshot task has run its build window and
    /// settled; returns the number of writes.
    async fn write_until_snapshot(&self, ran: &AtomicBool) -> FixtureResult<u64> {
        for number in 0..=INTERVAL {
            let key = format!("before-{number}");
            self.database.mutate(context(&key), put(&key, &key)).await?;
            self.group().fixture_local_snapshot_settled().await?;
            if ran.load(Ordering::SeqCst) {
                return Ok(number + 1);
            }
        }
        panic!("no periodic snapshot was scheduled within its interval");
    }

    /// The tenant serves, and the next periodic snapshot covers every entry
    /// the journal kept through the deferred one before purging it.
    async fn snapshots_after_deferral(
        &self,
        writes: u64,
        deferred: Position,
        retained: Position,
    ) -> FixtureResult<()> {
        assert_eq!(self.database.serving_failure_class(), None);
        assert!(deferred < retained, "the refused build published nothing");
        for number in 0..=INTERVAL {
            let key = format!("after-{number}");
            self.database.mutate(context(&key), put(&key, &key)).await?;
            self.group().fixture_local_snapshot_settled().await?;
            let metrics = self.group().metrics();
            if metrics.snapshot > deferred {
                assert!(metrics.snapshot >= retained);
                assert_eq!(metrics.purged, metrics.snapshot);
                for number in 0..writes {
                    let key = format!("before-{number}");
                    assert_eq!(self.document(&key)?, Some(json!({"id": key, "key": key})));
                }
                return Ok(());
            }
        }
        panic!("no snapshot was published after the deferred one");
    }

    async fn finish(self) -> FixtureResult<()> {
        assert_eq!(self.database.serving_failure_class(), None);
        self.database
            .mutate(context("finish"), put("finish", "finish"))
            .await?;
        assert_eq!(
            self.document("finish")?,
            Some(json!({"id": "finish", "key": "finish"}))
        );
        self.database.shutdown().await?;
        self.audit.shutdown().await?;
        Ok(())
    }
}

/// The write whose append was refused reached neither the journal nor the
/// engine; it is a definite rejection that its idempotency key can retry.
async fn refused_append_rejects_only_its_write(
    fixture: &Fixture,
    ran: &AtomicBool,
    release: impl FnOnce(),
) -> FixtureResult<()> {
    let journal = fixture.group().metrics().last_log_index;
    let revision = fixture.database.engine().generation()?.state.revision;
    let refused = fixture
        .database
        .mutate(context("refused"), put("refused", "refused"))
        .await;
    assert!(ran.load(Ordering::SeqCst), "the append window did not run");
    assert_eq!(
        refused.expect_err("append under exhausted capacity").code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(fixture.database.serving_failure_class(), None);
    assert_eq!(fixture.group().metrics().last_log_index, journal);
    assert_eq!(
        fixture.database.engine().generation()?.state.revision,
        revision
    );
    assert_eq!(fixture.document("refused")?, None);
    release();
    fixture
        .database
        .mutate(context("retried"), put("refused", "refused"))
        .await?;
    assert_eq!(
        fixture.database.engine().generation()?.state.revision,
        revision + 1
    );
    assert_eq!(
        fixture.document("refused")?,
        Some(json!({"id": "refused", "key": "refused"}))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn journal_append_refused_for_native_capacity_rejects_only_its_write() -> FixtureResult<()> {
    let fixture = Fixture::open().await?;
    let held = Arc::new(Mutex::new(Vec::new()));
    let ran = Arc::new(AtomicBool::new(false));
    let (window, flag, admission) = (held.clone(), ran.clone(), fixture.admission.clone());
    // The proposer admitted its write; native traffic then takes everything
    // immediately before the writer appends the entry to its journal.
    fixture
        .group()
        .fixture_local_before_apply(Box::new(move || {
            *window.lock().unwrap() = exhaust_native(&admission);
            flag.store(true, Ordering::SeqCst);
        }))?;
    refused_append_rejects_only_its_write(&fixture, &ran, || held.lock().unwrap().clear()).await?;
    fixture.finish().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn journal_append_refused_under_rss_pressure_rejects_only_its_write() -> FixtureResult<()> {
    let fixture = Fixture::open().await?;
    let ran = Arc::new(AtomicBool::new(false));
    let (flag, rss, admission) = (ran.clone(), fixture.rss.clone(), fixture.admission.clone());
    // The process crosses its RSS high-water mark after the write was
    // admitted and before its journal append.
    fixture
        .group()
        .fixture_local_before_apply(Box::new(move || {
            rss.press(&admission, true);
            flag.store(true, Ordering::SeqCst);
        }))?;
    let (rss, admission) = (fixture.rss.clone(), fixture.admission.clone());
    refused_append_rejects_only_its_write(&fixture, &ran, move || rss.press(&admission, false))
        .await?;
    fixture.finish().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn periodic_snapshot_refused_for_native_capacity_is_deferred() -> FixtureResult<()> {
    let fixture = Fixture::open().await?;
    fixture
        .group()
        .fixture_local_snapshot_interval(INTERVAL)
        .await?;
    let held = Arc::new(Mutex::new(Vec::new()));
    let ran = Arc::new(AtomicBool::new(false));
    let (window, flag, admission) = (held.clone(), ran.clone(), fixture.admission.clone());
    // Native traffic takes everything while the periodic snapshot builds,
    // concurrently with the writer's later appends.
    fixture
        .group()
        .fixture_local_before_snapshot(Box::new(move || {
            *window.lock().unwrap() = exhaust_native(&admission);
            flag.store(true, Ordering::SeqCst);
        }))?;
    let writes = fixture.write_until_snapshot(&ran).await?;
    let deferred = fixture.group().metrics();
    held.lock().unwrap().clear();
    fixture
        .snapshots_after_deferral(writes, deferred.snapshot, deferred.last_applied)
        .await?;
    fixture.finish().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn periodic_snapshot_refused_under_rss_pressure_is_deferred() -> FixtureResult<()> {
    let fixture = Fixture::open().await?;
    fixture
        .group()
        .fixture_local_snapshot_interval(INTERVAL)
        .await?;
    let ran = Arc::new(AtomicBool::new(false));
    let (flag, rss, admission) = (ran.clone(), fixture.rss.clone(), fixture.admission.clone());
    fixture
        .group()
        .fixture_local_before_snapshot(Box::new(move || {
            rss.press(&admission, true);
            flag.store(true, Ordering::SeqCst);
        }))?;
    let writes = fixture.write_until_snapshot(&ran).await?;
    let deferred = fixture.group().metrics();
    let (rss, admission) = (fixture.rss.clone(), fixture.admission.clone());
    tokio::task::spawn_blocking(move || rss.press(&admission, false)).await?;
    fixture
        .snapshots_after_deferral(writes, deferred.snapshot, deferred.last_applied)
        .await?;
    fixture.finish().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn snapshot_triggered_with_native_capacity_exhausted_is_deferred() -> FixtureResult<()> {
    let fixture = Fixture::open().await?;
    let before = fixture.group().metrics();
    // Native traffic already holds everything when the snapshot is triggered,
    // so its capture and its build are both refused.
    let held = exhaust_native(&fixture.admission);
    fixture.group().snapshot().await?;
    fixture.group().fixture_local_snapshot_settled().await?;
    assert_eq!(fixture.database.serving_failure_class(), None);
    assert_eq!(fixture.group().metrics().snapshot, before.snapshot);
    drop(held);
    fixture.group().snapshot().await?;
    fixture.group().fixture_local_snapshot_settled().await?;
    let built = fixture.group().metrics();
    assert!(built.snapshot > before.snapshot);
    assert_eq!(built.snapshot, built.last_applied);
    assert_eq!(built.purged, built.snapshot);
    fixture.finish().await
}
