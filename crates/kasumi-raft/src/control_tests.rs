use super::*;
use crate::{LogStore, RaftCommand, RetirementReplayState};
use anyhow::Result;
use kasumi_store::{
    NodeStore, TenantStorageSet,
    test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
};
use kasumi_types::*;
use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
use std::collections::BTreeSet;

const INCARNATION: &str = "f38b3bea-9d6e-4ecb-9eab-9c5e4cb412d6";
fn group() -> String {
    format!("tenant/{INCARNATION}")
}
fn id(index: u64) -> LogId<u64> {
    LogId::new(openraft::CommittedLeaderId::new(3, 1), index)
}

// This fixture is log metadata, not a verified full backup or successful source
// retirement. The engine's retirement integration exercises its actual producer.
fn seed() -> Result<(Command, RetirementLogSeed)> {
    let context = RequestContext {
        tenant: "tenant".into(),
        principal: "owner".into(),
        request_id: "retire-one".into(),
        scopes: BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::service_identity(),
    };
    let command = Command {
        context,
        timestamp_ms: 123,
        operation: Operation::RetireSource(PreparedRetirement {
            request: RetireSourceRequest {
                retirement_id: "retire-one".into(),
                expected_source_incarnation: INCARNATION.into(),
                target_incarnation: "feb9b646-a733-4315-8216-2c2c7f28b9c4".into(),
                checkpoint: FullBackupCheckpoint {
                    tenant: "tenant".into(),
                    source_incarnation: INCARNATION.into(),
                    revision: 0,
                    resident_sha256: "1".repeat(64),
                    backup_id: uuid::Uuid::new_v4(),
                    manifest_ciphertext_sha256: "2".repeat(64),
                    key_lineage_digest: "3".repeat(64),
                },
                destination: "installed".into(),
                not_after_ms: 1000,
            },
            verified_closure_digest: "4".repeat(64),
            observation: Some(RetirementObservation {
                revision: 0,
                closure_digest: "4".repeat(64),
            }),
        }),
    };
    let state = RetirementReplayState {
        tenant: "tenant".into(),
        incarnation: INCARNATION.into(),
        previous_revision: 0,
        revision_base: 0,
        policy_epoch: 1,
        administrators: BTreeSet::from(["owner".into()]),
        suspended: true,
        retired: false,
        pending_restore: false,
        existing_identity: None,
        retirement_count: 0,
        retirement_bytes: 0,
        max_retirements: 4096,
        audit_count: 0,
        max_audit_records: 1000,
        snapshot_bytes: 1024,
        max_snapshot_bytes: 1 << 20,
        staged_outcome_headroom: 0,
    };
    let seed = RetirementLogSeed::prepare(&command, state)?;
    Ok((command, seed))
}
fn retirement_entry() -> Result<Entry<TypeConfig>> {
    let (command, seed) = seed()?;
    Ok(Entry {
        log_id: id(1),
        payload: EntryPayload::Normal(RaftCommand::retirement(
            serde_json::to_vec(&command)?,
            seed,
        )?),
    })
}
fn ordinary(index: u64) -> Entry<TypeConfig> {
    Entry {
        log_id: id(index),
        payload: EntryPayload::Normal(RaftCommand::application(
            b"municipal-sensitive-payload".to_vec(),
        )),
    }
}
async fn fixture(
    disk: FaultBackend,
) -> Result<(
    Arc<TenantStorageSet>,
    Arc<LocalKeyProvider>,
    Arc<LocalKeyProvider>,
    LogStore,
)> {
    let node = NodeStore::open_with_backend(disk)?;
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let app = TenantStore::open_with_clock(
        node.clone(),
        "tenant".into(),
        app_provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let custody = TenantStore::open_with_clock(
        node,
        CustodyStore::catalog_name("tenant"),
        custody_provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let stores = TenantStorageSet::install(app, custody)?;
    if stores
        .custody()
        .store()
        .get(META, b"application_bootstrap_sha256")?
        .is_none()
    {
        stores.custody().store().write_batch(&[WriteOp::put(
            META,
            b"application_bootstrap_sha256",
            serde_json::to_vec(&"0".repeat(64))?,
        )])?;
    }
    let log = LogStore::open(stores.clone(), 1).await?;
    log.bind_group(group()).await?;
    Ok((stores, app_provider, custody_provider, log))
}

#[tokio::test]
async fn committed_seed_reopens_before_any_projection_without_application_key_access() -> Result<()>
{
    let disk = FaultBackend::new();
    let (stores, app_provider, custody_provider, mut log) = fixture(disk.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(
        view.retirement_seed(1)?.is_none(),
        "append is not commitment"
    );
    assert!(load::<AppliedPosition>(stores.custody().store(), META, b"applied")?.is_none());
    log.save_committed(Some(id(1))).await?;
    let original = view.retirement_seed(1)?.unwrap().seed().encoded()?;
    let crash = disk.crash();
    app_provider.revoke();
    assert!(stores.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    drop(view);
    drop(log);
    drop(stores);
    // No source state machine, application provider or payload decoder is opened.
    let control = CustodyStore::open(
        NodeStore::open_with_backend(crash)?,
        "tenant".into(),
        custody_provider,
    )
    .await?;
    let recovered = ControlLog::open(control.clone(), 1, group())?;
    assert_eq!(
        recovered.retirement_seed(1)?.unwrap().seed().encoded()?,
        original
    );
    assert_eq!(app_provider.probe_count(), probes);
    assert!(load::<AppliedPosition>(control.store(), META, b"applied")?.is_none());
    for (_, bytes) in control.store().scan(HEADERS)? {
        assert!(!String::from_utf8_lossy(&bytes).contains("municipal-sensitive-payload"));
    }
    control.store().shutdown().await;
    Ok(())
}

#[tokio::test]
async fn truncation_permanently_removes_uncommitted_seed_before_overwrite_and_restart() -> Result<()>
{
    let disk = FaultBackend::new();
    let (stores, _, provider, mut log) = fixture(disk.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    log.save_committed(Some(id(0))).await?;
    log.truncate(id(1)).await?;
    assert!(
        stores
            .custody()
            .store()
            .get(SEEDS, &1u64.to_be_bytes())?
            .is_none()
    );
    log.blocking_append([ordinary(1)]).await?;
    log.save_committed(Some(id(1))).await?;
    assert!(
        log.truncate(id(1)).await.is_err(),
        "committed source prefix cannot be truncated"
    );
    let crash = disk.crash();
    drop(log);
    drop(stores);
    let control = CustodyStore::open(
        NodeStore::open_with_backend(crash)?,
        "tenant".into(),
        provider,
    )
    .await?;
    assert!(
        ControlLog::open(control.clone(), 1, group())?
            .retirement_seed(1)?
            .is_none()
    );
    control.store().shutdown().await;
    Ok(())
}

#[tokio::test]
async fn interrupted_raft_append_never_persists_seed_without_matching_body_and_header() -> Result<()>
{
    let seed_disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(seed_disk.clone()).await?;
    log.blocking_append([ordinary(0)]).await?;
    log.save_committed(Some(id(0))).await?;
    let baseline = seed_disk.crash();
    drop(log);
    drop(stores);
    let mut failed = 0;
    let mut succeeded = 0;
    for failure in 0..40 {
        let disk = baseline.crash();
        let (stores, _, _, mut log) = fixture(disk.clone()).await?;
        disk.fail_after(failure);
        let appended = log.blocking_append([retirement_entry()?]).await;
        let crash = disk.crash();
        disk.disarm();
        drop(log);
        drop(stores);
        let (reopened, _, _, _) = fixture(crash).await?;
        let control = reopened.custody().store();
        let body = reopened
            .application()
            .get("raft.log", &1u64.to_be_bytes())?;
        let header = control.get(HEADERS, &1u64.to_be_bytes())?;
        let seed = control.get(SEEDS, &1u64.to_be_bytes())?;
        assert_eq!(body.is_some(), header.is_some());
        assert_eq!(body.is_some(), seed.is_some());
        assert!(
            ControlLog::open(reopened.custody().clone(), 1, group())?
                .retirement_seed(1)?
                .is_none()
        );
        if appended.is_ok() {
            succeeded += 1;
            assert!(body.is_some());
        } else {
            failed += 1;
        }
    }
    assert!(failed > 0 && succeeded > 0);
    Ok(())
}

#[tokio::test]
async fn substituted_seed_bootstrap_or_command_and_uncovered_commit_fail_closed() -> Result<()> {
    let (stores, _, _, mut log) = fixture(FaultBackend::new()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    assert!(log.save_committed(Some(id(9))).await.is_err());
    log.save_committed(Some(id(1))).await?;
    assert!(log.save_committed(Some(id(0))).await.is_err());
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(view.retirement_seed(1)?.is_some());
    let mut saved: RetainedSeed =
        load(stores.custody().store(), SEEDS, &1u64.to_be_bytes())?.unwrap();
    saved.bootstrap_sha256 = "f".repeat(64);
    stores.custody().store().write_batch(&[WriteOp::put(
        SEEDS,
        1u64.to_be_bytes(),
        serde_json::to_vec(&saved)?,
    )])?;
    assert!(view.retirement_seed(1).is_err());
    let (mut command, seed) = seed()?;
    command.operation = Operation::Suspend(false);
    assert!(RaftCommand::retirement(serde_json::to_vec(&command)?, seed.clone()).is_err());
    let mut value = serde_json::to_value(&seed)?;
    value["source"]["documents"] = serde_json::json!({"payload":"forbidden"});
    assert!(RetirementLogSeed::decode(&serde_json::to_vec(&value)?).is_err());
    assert!(ControlLog::open(stores.custody().clone(), 2, group()).is_err());
    Ok(())
}

#[tokio::test]
async fn ordinary_purge_deletes_bodies_and_nonretirement_overwrite_cannot_leave_a_seed()
-> Result<()> {
    let (stores, _, _, mut log) = fixture(FaultBackend::new()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    log.save_committed(Some(id(0))).await?;
    // Storage's own contract clears an overwritten uncommitted seed even if an
    // embedding omitted OpenRaft's normal preceding truncate call.
    log.blocking_append([ordinary(1)]).await?;
    log.save_committed(Some(id(1))).await?;
    assert!(
        stores
            .custody()
            .store()
            .get(SEEDS, &1u64.to_be_bytes())?
            .is_none()
    );
    log.purge(id(1)).await?;
    assert!(
        stores
            .application()
            .get("raft.log", &1u64.to_be_bytes())?
            .is_none()
    );
    assert!(
        ControlLog::open(stores.custody().clone(), 1, group())?
            .retirement_seed(1)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn accepted_boundary_and_exact_applied_position_publish_atomically_before_retained_purge()
-> Result<()> {
    let seed_disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(seed_disk.clone()).await?;
    let entry = retirement_entry()?;
    let EntryPayload::Normal(command) = &entry.payload else {
        unreachable!()
    };
    let seed = command.seed()?.unwrap();
    let context = AppliedEntryContext {
        log_id: id(1),
        previous: Some(id(0)),
        membership: StoredMembership::default(),
        command_sha256: seed.command_sha256().into(),
        retirement_seed: Some(seed.clone()),
    };
    let receipt = RetirementReceipt {
        tenant: "tenant".into(),
        principal: "owner".into(),
        retirement_id: seed.request().retirement_id.clone(),
        request_digest: seed.request().reference()?.request_digest,
        source_incarnation: INCARNATION.into(),
        target_incarnation: seed.request().target_incarnation.clone(),
        revision: 1,
        policy_epoch: 2,
        admitted_at_ms: 123,
        checkpoint: seed.request().checkpoint.clone(),
        closure_digest: "4".repeat(64),
    };
    log.blocking_append([ordinary(0), entry]).await?;
    log.save_committed(Some(id(1))).await?;
    let baseline = seed_disk.crash();
    drop(log);
    drop(stores);
    let mut successes = 0;
    for failure in 0..40 {
        let disk = baseline.crash();
        let (stores, _, _, _) = fixture(disk.clone()).await?;
        disk.fail_after(failure);
        let result = persist_applied(&stores, &context, Some(receipt.clone()));
        let crash = disk.crash();
        disk.disarm();
        drop(stores);
        let (reopened, _, _, mut log) = fixture(crash).await?;
        let applied: Option<AppliedPosition> = load(reopened.custody().store(), META, b"applied")?;
        let boundary = retired_boundary(reopened.custody())?;
        assert_eq!(
            applied.is_some(),
            boundary.is_some(),
            "torn source transition {failure}"
        );
        if let Some(boundary) = boundary {
            assert_eq!(applied.unwrap(), context.record());
            assert_eq!(boundary.receipt, receipt);
            log.purge(id(1)).await?;
            assert!(
                reopened
                    .application()
                    .get("raft.log", &1u64.to_be_bytes())?
                    .is_some()
            );
            assert!(
                ControlLog::open(reopened.custody().clone(), 1, group())?
                    .retirement_seed(1)?
                    .is_some()
            );
        }
        if result.is_ok() {
            successes += 1;
        }
    }
    assert!(successes > 0);
    Ok(())
}
