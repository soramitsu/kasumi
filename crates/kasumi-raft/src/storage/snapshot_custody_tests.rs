//! Storage-adapter metadata fixtures; actual source backup/retirement production
//! is separately exercised by the engine snapshot transfer test.
use super::*;
use crate::control::tests::{fixture, group, id, ordinary, retirement_entry};
use crate::control::{self, AppliedCursor, AppliedEntryContext, ControlLog, RetainedSeed, SEEDS};
use crate::{RetiredSnapshotState, StateMachineBackend};
use openraft::storage::RaftLogStorageExt;

async fn accepted_snapshot() -> Result<SnapshotEnvelope> {
    let (domains, _, _, mut log) = fixture(FaultBackend::new()).await?;
    let entry = retirement_entry()?;
    let command = match &entry.payload {
        EntryPayload::Normal(value) => value,
        _ => unreachable!(),
    };
    let seed = command.seed()?.unwrap();
    let receipt = kasumi_types::RetirementReceipt {
        tenant: seed.source().tenant.clone(),
        source_incarnation: seed.source().incarnation.clone(),
        target_incarnation: seed.request().target_incarnation.clone(),
        retirement_id: seed.request().retirement_id.clone(),
        principal: "owner".into(),
        admitted_at_ms: 123,
        request_digest: seed.request().reference()?.request_digest,
        checkpoint: seed.request().checkpoint.clone(),
        revision: 1,
        policy_epoch: 2,
        closure_digest: "4".repeat(64),
    };
    let context = AppliedEntryContext {
        log_id: id(1),
        previous: Some(id(0)),
        membership: StoredMembership::default(),
        command_sha256: seed.command_sha256().into(),
        retirement_seed: Some(seed.clone()),
    };
    log.blocking_append([ordinary(0), entry]).await?;
    log.save_committed(Some(id(1))).await?;
    control::persist_applied(&domains, &context, Some(receipt.clone()))?;
    let state = RetiredSnapshotState {
        revision_base: 0,
        revision: 1,
        policy_epoch: 2,
        administrators: std::collections::BTreeSet::from(["owner".into()]),
        request: seed.request().clone(),
        receipt,
    };
    let mut result = envelope(serde_json::to_vec(&state)?);
    result.meta.last_log_id = Some(id(1));
    result.retirement =
        crate::snapshot_custody::capture(domains.custody(), &result.meta, Some(state))?;
    Ok(result)
}
#[derive(Default)]
struct ClosedBackend(Mutex<Option<RetiredSnapshotState>>);
impl StateMachineBackend for ClosedBackend {
    fn close_application(&self) {
        *self.0.lock().unwrap() = None;
    }
    fn apply(&self, _: &AppliedEntryContext, _: &[u8]) -> Result<crate::AppliedResponse> {
        anyhow::bail!("metadata test cannot apply payload")
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        let retirement = self.0.lock().unwrap().clone();
        Ok(crate::CapturedSnapshot::new(
            retirement.clone(),
            move |writer| {
                serde_json::to_writer(writer, &retirement)?;
                Ok(())
            },
        ))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<RetiredSnapshotState>> {
        let mut captured = Vec::new();
        bytes.read_to_end(&mut captured)?;
        if captured == b"not-retired" {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&captured)?))
    }
    fn prepare_restore<'a>(
        &'a self,
        _context: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        let retirement = self.validate_snapshot(bytes)?;
        Ok(Box::new(PreparedFixtureRestore {
            retirement: retirement.clone(),
            commit: Box::new(move || {
                *self.0.lock().unwrap() = retirement;
                Ok(())
            }),
        }))
    }
}

#[tokio::test]
async fn same_position_reencoding_preserves_custody_and_reuses_verified_current_image() -> Result<()>
{
    let original = accepted_snapshot().await?;
    let (domains, _, _, _) = fixture(FaultBackend::new()).await?;
    let backend = Arc::new(ClosedBackend::default());
    let mut machine = StateMachine::open(domains.clone(), backend).await?;
    machine
        .install_snapshot(&original.meta, as_snapshot(&original, 1 << 20)?.snapshot)
        .await?;
    let state: RetiredSnapshotState = serde_json::from_reader(original.backend.reader())?;
    let mut reencoded = original.clone();
    reencoded.meta.snapshot_id = uuid::Uuid::new_v4().to_string();
    reencoded.backend = kasumi_store::SnapshotImage::from_bytes(
        &kasumi_store::ScratchDisk::fixture(),
        &serde_json::to_vec_pretty(&state)?,
    )?;
    assert_ne!(original.backend.sha256(), reencoded.backend.sha256());
    machine
        .install_snapshot(&reencoded.meta, as_snapshot(&reencoded, 1 << 20)?.snapshot)
        .await?;
    let persisted = load_snapshot(domains.application(), 1 << 20)?.unwrap();
    assert_eq!(persisted.backend.sha256(), reencoded.backend.sha256());
    validate_snapshot_coverage(&domains, &persisted, 1 << 20)?;
    // The backend captures compact JSON, while the current image uses pretty
    // JSON. Their exact image hashes differ but their closed state is identical.
    let mut builder = machine.get_snapshot_builder().await;
    let recaptured = builder.build_snapshot().await?;
    assert_eq!(recaptured.meta, reencoded.meta);
    let recaptured = {
        let image = recaptured.snapshot.into_image()?;
        SnapshotEnvelope::decode(image.disk(), &mut image.reader(), 64 << 20)?
    };
    assert_eq!(recaptured.backend.sha256(), reencoded.backend.sha256());
    assert!(
        ControlLog::open(domains.custody().clone(), 1, group())?
            .retirement_seed(1)?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn same_position_cannot_substitute_matching_backend_and_custody_policy() -> Result<()> {
    let original = accepted_snapshot().await?;
    for change_epoch in [false, true] {
        let (domains, _, _, _) = fixture(FaultBackend::new()).await?;
        let backend = Arc::new(ClosedBackend::default());
        let mut machine = StateMachine::open(domains.clone(), backend.clone()).await?;
        machine
            .install_snapshot(&original.meta, as_snapshot(&original, 1 << 20)?.snapshot)
            .await?;
        let mut changed = original.clone();
        changed.meta.snapshot_id = uuid::Uuid::new_v4().to_string();
        let mut state: RetiredSnapshotState = serde_json::from_reader(original.backend.reader())?;
        if change_epoch {
            state.policy_epoch += 1;
        } else {
            state.administrators.insert("substituted".into());
        }
        changed.backend = kasumi_store::SnapshotImage::from_bytes(
            &kasumi_store::ScratchDisk::fixture(),
            &serde_json::to_vec(&state)?,
        )?;
        let mut capsule = serde_json::to_value(changed.retirement.take().unwrap())?;
        capsule["state"] = serde_json::to_value(&state)?;
        changed.retirement = Some(serde_json::from_value(capsule)?);
        // Neither a newly captured image nor incoming matching metadata can
        // replace the custody identity already published at this exact position.
        *backend.0.lock().unwrap() = Some(state);
        assert!(
            machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .is_err()
        );
        // Reopen a healthy adapter so installation is rejected by its own
        // identity check, not the earlier builder's failure fence.
        drop(machine);
        let mut machine =
            StateMachine::open(domains.clone(), Arc::new(ClosedBackend::default())).await?;
        assert!(
            machine
                .install_snapshot(
                    &changed.meta,
                    crate::snapshot_codec::unvalidated_snapshot(&changed, &original, 1 << 20)?
                        .snapshot
                )
                .await
                .is_err()
        );
        let persisted = load_snapshot(domains.application(), 1 << 20)?.unwrap();
        assert_eq!(persisted.meta, original.meta);
        validate_snapshot_coverage(&domains, &persisted, 1 << 20)?;
    }
    Ok(())
}

#[tokio::test]
async fn retired_snapshot_installs_without_original_log_and_recovers_with_only_custody_key()
-> Result<()> {
    let snapshot = accepted_snapshot().await?;
    let disk = FaultBackend::new();
    let (domains, app_provider, custody_provider, mut log) = fixture(disk.clone()).await?;
    let backend = Arc::new(ClosedBackend::default());
    let mut machine = StateMachine::open(domains.clone(), backend.clone()).await?;
    machine
        .install_snapshot(&snapshot.meta, as_snapshot(&snapshot, 1 << 20)?.snapshot)
        .await?;
    assert_eq!(
        backend.0.lock().unwrap().as_ref().unwrap().administrators,
        std::collections::BTreeSet::from(["owner".into()])
    );
    assert!(
        log.get_log_state().await?.last_log_id.is_none(),
        "snapshot cannot fabricate physical log entries"
    );
    assert!(
        log.read_committed().await?.is_none(),
        "snapshot cannot rewrite raw log commit cursor"
    );
    assert!(domains.application().scan(LOG)?.is_empty());
    let view = ControlLog::open(domains.custody().clone(), 1, group())?;
    assert_eq!(view.committed()?, Some(id(1)));
    assert!(view.retirement_seed(1)?.is_some());
    assert!(matches!(
        control::load::<AppliedCursor>(domains.custody().store(), META, b"applied")?,
        Some(AppliedCursor::Snapshot { .. })
    ));
    // Crash before Raft purges the log prefix. Only metadata is reopened.
    let crash = disk.crash();
    app_provider.revoke();
    assert!(domains.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    drop(view);
    drop(log);
    drop(machine);
    drop(domains);
    let custody = kasumi_store::CustodyStore::open(
        NodeStore::open_with_backend(crash, kasumi_store::ScratchDisk::fixture())?,
        "tenant".into(),
        custody_provider,
    )
    .await?;
    let view = ControlLog::open(custody.clone(), 1, group())?;
    assert!(view.retirement_seed(1)?.is_some());
    assert_eq!(app_provider.probe_count(), probes);
    custody.store().shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn snapshot_rejects_missing_substituted_stale_and_payload_custody_before_publication()
-> Result<()> {
    let original = accepted_snapshot().await?;
    for case in 0..8 {
        let (domains, _, _, _) = fixture(FaultBackend::new()).await?;
        let mut machine =
            StateMachine::open(domains.clone(), Arc::new(ClosedBackend::default())).await?;
        let mut changed = original.clone();
        match case {
            0 => changed.retirement = None,
            1 => {
                changed.backend = kasumi_store::SnapshotImage::from_bytes(
                    &kasumi_store::ScratchDisk::fixture(),
                    b"not-retired",
                )?
            }
            2 | 3 => {
                let mut state: RetiredSnapshotState =
                    serde_json::from_reader(changed.backend.reader())?;
                if case == 2 {
                    state.policy_epoch += 1;
                } else {
                    state.administrators.insert("substituted".into());
                }
                changed.backend = kasumi_store::SnapshotImage::from_bytes(
                    &kasumi_store::ScratchDisk::fixture(),
                    &serde_json::to_vec(&state)?,
                )?;
            }
            4 => {
                let mut portable = serde_json::to_value(changed.retirement.take().unwrap())?;
                portable["bootstrap_sha256"] = serde_json::Value::String("f".repeat(64));
                changed.retirement = Some(serde_json::from_value(portable)?);
            }
            5 => {
                let mut portable = serde_json::to_value(changed.retirement.take().unwrap())?;
                portable["header"]["entry_sha256"] = serde_json::Value::String("f".repeat(64));
                changed.retirement = Some(serde_json::from_value(portable)?);
            }
            6 => {
                let mut portable = serde_json::to_value(changed.retirement.take().unwrap())?;
                portable["seed"] = serde_json::to_value(b"municipal-payload-command".to_vec())?;
                changed.retirement = Some(serde_json::from_value(portable)?);
            }
            7 => changed.meta.last_log_id = Some(id(0)),
            _ => unreachable!(),
        }
        assert!(
            machine
                .install_snapshot(
                    &changed.meta,
                    crate::snapshot_codec::unvalidated_snapshot(&changed, &original, 1 << 20)?
                        .snapshot
                )
                .await
                .is_err(),
            "accepted substituted case {case}"
        );
        assert!(load_manifest(domains.application(), b"current", 1 << 20)?.is_none());
        assert!(control::retired_boundary(domains.custody())?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn accepted_snapshot_supersedes_uncommitted_candidate_and_survives_late_truncation()
-> Result<()> {
    let accepted = accepted_snapshot().await?;
    let (domains, _, _, mut log) = fixture(FaultBackend::new()).await?;
    // UUID-backed checkpoint differs, so this is a conflicting candidate.
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    let mut machine =
        StateMachine::open(domains.clone(), Arc::new(ClosedBackend::default())).await?;
    machine
        .install_snapshot(&accepted.meta, as_snapshot(&accepted, 1 << 20)?.snapshot)
        .await?;
    let view = ControlLog::open(domains.custody().clone(), 1, group())?;
    let expected: RetiredSnapshotState = serde_json::from_reader(accepted.backend.reader())?;
    assert_eq!(
        view.retirement_seed(1)?.unwrap().seed().request(),
        &expected.request
    );
    // Physical suffix cleanup may follow committed snapshot installation. It
    // cannot delete the separately accepted seed or mint a new candidate.
    log.truncate(id(0)).await?;
    assert_eq!(
        view.retirement_seed(1)?.unwrap().seed().request(),
        &expected.request
    );
    assert!(log.blocking_append([ordinary(1)]).await.is_err());
    assert_eq!(
        view.retirement_seed(1)?.unwrap().seed().request(),
        &expected.request
    );
    Ok(())
}

#[tokio::test]
async fn nonretired_snapshot_discards_stale_candidate_coverage_without_retirement_projection()
-> Result<()> {
    let (domains, _, _, mut log) = fixture(FaultBackend::new()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    let mut value = envelope(b"not-retired".to_vec());
    value.meta.last_log_id = Some(id(3));
    let mut machine =
        StateMachine::open(domains.clone(), Arc::new(ClosedBackend::default())).await?;
    machine
        .install_snapshot(&value.meta, as_snapshot(&value, 1 << 20)?.snapshot)
        .await?;
    let view = ControlLog::open(domains.custody().clone(), 1, group())?;
    assert!(view.retirement_seed(1)?.is_none());
    assert!(control::retired_boundary(domains.custody())?.is_none());
    // Physical log repair beneath the snapshot remains legal. Neither a normal
    // overwrite nor a newly appended candidate can create accepted custody.
    log.blocking_append([ordinary(1)]).await?;
    log.blocking_append([retirement_entry()?]).await?;
    log.save_committed(Some(id(1))).await?;
    assert!(view.retirement_seed(1)?.is_none());
    assert!(control::retired_boundary(domains.custody())?.is_none());
    Ok(())
}

#[tokio::test]
async fn retired_snapshot_power_loss_never_tears_image_seed_boundary_or_applied_cursor()
-> Result<()> {
    let value = accepted_snapshot().await?;
    let bytes = value.encode(64 << 20)?.read_bounded(64 << 20)?;
    let seed = FaultBackend::new();
    let (initial, _, _, _) = fixture(seed.clone()).await?;
    let baseline = seed.crash();
    drop(initial);
    let measured_disk = baseline.crash();
    let (domains, _, _, _) = fixture(measured_disk.clone()).await?;
    let start = measured_disk.operations();
    persist_snapshot(&domains, &bytes, 1 << 20, &value)?;
    let operations = measured_disk.operations() - start;
    assert!(operations > 10);
    for failure in 0..=operations {
        let disk = baseline.crash();
        let (domains, _, _, _) = fixture(disk.clone()).await?;
        disk.fail_after(failure);
        let result = persist_snapshot(&domains, &bytes, 1 << 20, &value);
        let crash = disk.crash();
        disk.disarm();
        drop(domains);
        let (reopened, _, _, _) = fixture(crash).await?;
        cleanup_snapshots(reopened.application(), 1 << 20)?;
        let image = load_snapshot(reopened.application(), 1 << 20)?;
        let boundary = control::retired_boundary(reopened.custody())?;
        let applied: Option<AppliedCursor> =
            control::load(reopened.custody().store(), META, b"applied")?;
        let retained: Option<RetainedSeed> =
            control::load(reopened.custody().store(), SEEDS, &1u64.to_be_bytes())?;
        assert_eq!(
            image.is_some(),
            boundary.is_some(),
            "boundary torn at {failure}"
        );
        assert_eq!(
            image.is_some(),
            applied.is_some(),
            "cursor torn at {failure}"
        );
        assert_eq!(
            image.is_some(),
            retained.is_some(),
            "seed torn at {failure}"
        );
        if let Some(image) = image {
            validate_snapshot_coverage(&reopened, &image, 1 << 20)?;
            let view = ControlLog::open(reopened.custody().clone(), 1, group())?;
            assert!(view.retirement_seed(1)?.is_some());
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn equal_index_different_term_log_and_snapshot_coverage_is_rejected() -> Result<()> {
    let value = accepted_snapshot().await?;
    let (domains, _, _, _) = fixture(FaultBackend::new()).await?;
    persist_snapshot(
        &domains,
        &value.encode(64 << 20)?.read_bounded(64 << 20)?,
        1 << 20,
        &value,
    )?;
    let wrong = LogId::new(openraft::CommittedLeaderId::new(4, 1), 1);
    domains.custody().store().write_batch(&[WriteOp::put(
        META,
        b"committed",
        serde_json::to_vec(&Some(wrong))?,
    )])?;
    let view = ControlLog::open(domains.custody().clone(), 1, group())?;
    assert!(view.committed().is_err());
    assert!(view.retirement_seed(1).is_err());
    Ok(())
}

#[tokio::test]
async fn old_snapshot_capture_cannot_regress_newer_accepted_cursor() -> Result<()> {
    let (domains, _, _, mut log) = fixture(FaultBackend::new()).await?;
    let mut machine =
        StateMachine::open(domains.clone(), Arc::new(BytesBackend::default())).await?;
    let one = ordinary(1);
    log.blocking_append([one.clone()]).await?;
    log.save_committed(Some(id(1))).await?;
    machine.apply([one]).await?;
    let mut captured = machine.get_snapshot_builder().await;
    let two = ordinary(2);
    log.blocking_append([two.clone()]).await?;
    log.save_committed(Some(id(2))).await?;
    machine.apply([two]).await?;
    let before: AppliedCursor =
        control::load(domains.custody().store(), META, b"applied")?.unwrap();
    let snapshot = captured.build_snapshot().await?;
    assert_eq!(snapshot.meta.last_log_id, Some(id(1)));
    assert_eq!(
        control::load::<AppliedCursor>(domains.custody().store(), META, b"applied")?.unwrap(),
        before
    );
    assert_eq!(before.log_id(), Some(id(2)));
    Ok(())
}

#[tokio::test]
async fn published_retirement_projection_substitution_fails_closed_after_reopen() -> Result<()> {
    let value = accepted_snapshot().await?;
    let disk = FaultBackend::new();
    let (domains, _, _, _) = fixture(disk.clone()).await?;
    let mut machine =
        StateMachine::open(domains.clone(), Arc::new(ClosedBackend::default())).await?;
    let mut older_capture = machine.get_snapshot_builder().await;
    persist_snapshot(
        &domains,
        &value.encode(64 << 20)?.read_bounded(64 << 20)?,
        1 << 20,
        &value,
    )?;
    let mut projection: serde_json::Value = serde_json::from_slice(
        &domains
            .custody()
            .store()
            .get(META, b"snapshot_retirement")?
            .unwrap(),
    )?;
    projection["snapshot_sha256"] = serde_json::Value::String("0".repeat(64));
    domains.custody().store().write_batch(&[WriteOp::put(
        META,
        b"snapshot_retirement",
        serde_json::to_vec(&projection)?,
    )])?;
    assert!(
        older_capture.build_snapshot().await.is_err(),
        "cached newer snapshot cannot bypass custody validation"
    );
    let (reopened, _, _, _) = fixture(disk.crash()).await?;
    assert!(
        StateMachine::open(reopened.clone(), Arc::new(ClosedBackend::default()))
            .await
            .is_err()
    );
    assert!(
        ControlLog::open(reopened.custody().clone(), 1, group())?
            .retirement_seed(1)
            .is_err()
    );
    Ok(())
}
