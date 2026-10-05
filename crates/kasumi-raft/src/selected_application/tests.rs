use super::{fixture::*, *};
use kasumi_store::WriteOp;

#[tokio::test]
async fn selected_application_exact_old_entry_and_real_covered_replay_remain_distinct() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let first = entry(0);
    crate::control::prepare_applied(&fixture.stores, &first, None)?.publish(
        &fixture.stores,
        &[WriteOp::put("projection", b"current", b"first")],
    )?;
    let old = fixture.stores.read_view()?;
    assert!(old.registered_reader_id().is_some());
    let later = entry(1);
    crate::control::prepare_applied(&fixture.stores, &later, None)?.publish(
        &fixture.stores,
        &[WriteOp::put("projection", b"current", b"later")],
    )?;
    let before = fixture.memory.snapshot();
    let proof = fixture.select(
        &old,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Serving,
    )?;
    assert!(!proof.is_covered_reconstruction());
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == first.log_id)
    );
    let held = fixture.memory.snapshot();
    assert_eq!(held.proof_slots, before.proof_slots + 1);
    assert_eq!(
        held.proof_bytes,
        before.proof_bytes + 1024 + proof.retained_workspace_bytes()
    );
    assert!(
        held.proof_peak > held.proof_bytes * 64,
        "scratch peak was not released"
    );
    assert_eq!(held.retains, before.retains + 1);
    assert!(
        proof.retained_workspace_bytes() < 4096,
        "small metadata retained a worst-case decode allowance"
    );
    assert_eq!(
        old.application_get("projection", b"current", 64)?
            .as_deref(),
        Some(b"first".as_slice())
    );
    // This is the actual production CoveredReplay path: it replaces application
    // bytes while preserving the independently newer custody cursor.
    let prepared = crate::control::prepare_applied(&fixture.stores, &first, None)?;
    assert!(matches!(
        prepared,
        crate::control::PreparedApplied::CoveredReplay { .. }
    ));
    prepared.publish(
        &fixture.stores,
        &[WriteOp::put(
            "projection",
            b"current",
            b"reconstructed-first",
        )],
    )?;
    let selected = fixture.stores.read_view()?;
    assert_eq!(
        selected
            .application_get("projection", b"current", 64)?
            .as_deref(),
        Some(b"reconstructed-first".as_slice())
    );
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Entry(&first),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    let reconstructed = fixture.select(
        &selected,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Reconstructing,
    )?;
    assert!(reconstructed.is_covered_reconstruction());
    assert!(
        matches!(reconstructed.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == later.log_id)
    );
    drop(reconstructed);
    drop(proof);
    assert_eq!(fixture.memory.snapshot().proof_bytes, before.proof_bytes);
    old.close()?;
    selected.close()?;
    fixture.close().await
}

#[tokio::test]
async fn selected_application_checks_complete_entry_and_bootstrap_identity() -> Result<()> {
    let fixture = Fixture::new().await?;
    let genesis = fixture.stores.read_view()?;
    let initial = fixture.select(
        &genesis,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
    )?;
    assert_eq!(initial.bootstrap().digest, fixture.image.sha256());
    assert!(initial.applied().is_none());
    let wrong_image =
        SnapshotImage::from_bytes(fixture.image.disk(), b"different authenticated genesis")?;
    assert!(
        fixture
            .select(
                &genesis,
                ApplicationBoundaryRef::Bootstrap(&wrong_image),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    drop(initial);
    genesis.close()?;
    let actual = entry(0);
    crate::control::prepare_applied(&fixture.stores, &actual, None)?
        .publish(&fixture.stores, &[])?;
    let selected = fixture.stores.read_view()?;
    for field in 0..4 {
        let mut wrong = entry(0);
        match field {
            0 => wrong.log_id.leader_id.term += 1,
            1 => wrong.previous = Some(actual.log_id),
            2 => {
                wrong.membership = StoredMembership::new(
                    None,
                    openraft::Membership::new(
                        vec![std::collections::BTreeSet::from([9])],
                        std::collections::BTreeMap::from([(9, BasicNode::new("other"))]),
                    ),
                )
            }
            _ => wrong.command_sha256 = "f".repeat(64),
        }
        for mode in [
            ApplicationSelectionMode::Serving,
            ApplicationSelectionMode::Reconstructing,
        ] {
            assert!(
                fixture
                    .select(&selected, ApplicationBoundaryRef::Entry(&wrong), mode)
                    .is_err()
            );
        }
    }
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Bootstrap(&fixture.image),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    let replay = fixture.select(
        &selected,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
    )?;
    assert!(replay.is_covered_reconstruction());
    drop(replay);
    selected.close()?;
    fixture.close().await
}

#[tokio::test]
async fn selected_application_snapshot_uses_actual_manifest_and_snapshot_cursor() -> Result<()> {
    let fixture = Fixture::new().await?;
    let meta = SnapshotMeta {
        last_log_id: Some(entry(0).log_id),
        last_membership: StoredMembership::default(),
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    let snapshot = crate::storage::SnapshotEnvelope {
        version: 2,
        kind: SnapshotKind::Application,
        meta: meta.clone(),
        backend: fixture.image.clone(),
        retirement: None,
        first_membership: None,
        initialization_association: None,
    };
    let image = snapshot.encode(1 << 20)?;
    let manifest = SnapshotManifest {
        version: 1,
        sha256: image.sha256().into(),
        id: uuid::Uuid::new_v4().to_string(),
        bytes: image.len(),
        chunks: 1,
    };
    let coverage = SnapshotCoverage {
        kind: SnapshotKind::Application,
        manifest_id: manifest.id.clone(),
        snapshot_sha256: manifest.sha256.clone(),
        backend_sha256: fixture.image.sha256().into(),
        meta: meta.clone(),
    };
    let cursor = AppliedCursor::Snapshot {
        meta: meta.clone(),
        backend_sha256: coverage.backend_sha256.clone(),
        snapshot_sha256: coverage.snapshot_sha256.clone(),
    };
    fixture.stores.write_batch(
        &[WriteOp::put(
            "raft.snapshot",
            b"current",
            serde_json::to_vec(&manifest)?,
        )],
        &[
            WriteOp::put(
                META,
                b"snapshot_coverage",
                crate::storage::encode_snapshot_coverage(&coverage)?,
            ),
            WriteOp::put(META, b"applied", serde_json::to_vec(&cursor)?),
        ],
    )?;
    let selected = fixture.stores.read_view()?;
    let mut context = SnapshotRestoreContext {
        mode: crate::SnapshotRestoreMode::Reopen,
        backend_sha256: coverage.backend_sha256.clone(),
        meta,
    };
    let proof = fixture.select(
        &selected,
        ApplicationBoundaryRef::Snapshot(&context),
        ApplicationSelectionMode::Serving,
    )?;
    assert_eq!(proof.snapshot().unwrap().snapshot_sha256, image.sha256());
    assert!(matches!(
        proof.applied(),
        Some(SelectedAppliedRef::Snapshot { .. })
    ));
    drop(proof);
    // Snapshot coverage is never fabricated into Entry(command_sha256).
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Entry(&entry(0)),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    drop(fixture.select(
        &selected,
        ApplicationBoundaryRef::Entry(&entry(0)),
        ApplicationSelectionMode::Reconstructing,
    )?);
    context.backend_sha256 = "a".repeat(64);
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Snapshot(&context),
                ApplicationSelectionMode::Reconstructing
            )
            .is_err()
    );
    context.backend_sha256 = coverage.backend_sha256.clone();
    context.meta.snapshot_id = uuid::Uuid::new_v4().to_string();
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Snapshot(&context),
                ApplicationSelectionMode::Reconstructing
            )
            .is_err()
    );
    context.meta = coverage.meta.clone();
    // Atomically preserve snapshot records with a newer actual Entry cursor,
    // exactly the supported reconstruction relationship.
    fixture
        .stores
        .write_batch(&[], &[crate::control::applied_write(&entry(1))?])?;
    let newer = fixture.stores.read_view()?;
    assert!(
        fixture
            .select(
                &newer,
                ApplicationBoundaryRef::Snapshot(&context),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    let replay = fixture.select(
        &newer,
        ApplicationBoundaryRef::Snapshot(&context),
        ApplicationSelectionMode::Reconstructing,
    )?;
    assert!(replay.is_covered_reconstruction());
    drop(replay);
    // An independently changed current manifest must not satisfy old coverage.
    let mut broken = manifest;
    broken.sha256 = "b".repeat(64);
    fixture.stores.write_batch(
        &[WriteOp::put(
            "raft.snapshot",
            b"current",
            serde_json::to_vec(&broken)?,
        )],
        &[],
    )?;
    let inconsistent = fixture.stores.read_view()?;
    assert!(
        fixture
            .select(
                &inconsistent,
                ApplicationBoundaryRef::Snapshot(&context),
                ApplicationSelectionMode::Reconstructing
            )
            .is_err()
    );
    drop(fixture.select(
        &selected,
        ApplicationBoundaryRef::Snapshot(&context),
        ApplicationSelectionMode::Serving,
    )?);
    selected.close()?;
    newer.close()?;
    inconsistent.close()?;
    fixture.close().await
}

#[tokio::test]
async fn selected_application_denial_foreign_provider_and_retain_failure_keep_grant() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let view = fixture.stores.read_view()?;
    let id = view.registered_reader_id();
    let baseline = fixture.memory.snapshot();
    let denied = selected_application_at(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024),
    )
    .err()
    .expect("workspace denial");
    assert_eq!(
        denied.original_error().downcast_ref::<Denied>().unwrap().0,
        "selection fixture denied"
    );
    assert_eq!(fixture.memory.snapshot().proof_bytes, 1024);
    assert_eq!(fixture.memory.snapshot().proof_slots, 1);
    assert_eq!(view.registered_reader_id(), id);
    drop(denied);
    // A later read refusal retires unexposed partial metadata under the same
    // peak grant; it does not shrink the error owner or poison the view.
    let partial = selected_application_at(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1 << 20),
    )
    .err()
    .expect("applied read preclaim denial");
    assert_eq!(
        partial.original_error().downcast_ref::<Denied>().unwrap().0,
        "selection fixture denied"
    );
    let held = fixture.memory.snapshot();
    assert!(held.proof_bytes > 1024);
    assert_eq!(held.proof_bytes, held.proof_peak);
    assert_eq!(held.proof_slots, 1);
    assert_eq!(held.retains, baseline.retains);
    drop(partial);
    let foreign = Memory::new();
    let wrong = selected_application_at(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        foreign.workspace(128 << 20),
    )
    .err()
    .expect("foreign provider");
    assert_eq!(
        wrong.to_string(),
        "selected view and workspace memory owners differ"
    );
    assert_eq!(
        foreign.snapshot().proof_peak,
        0,
        "foreign provider allocated read workspace"
    );
    drop(wrong);
    assert_eq!(foreign.snapshot().slots, 0);
    let mut workspace = fixture.memory.workspace(128 << 20);
    workspace.reject_retain = true;
    let failure = selected_application_at(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        workspace,
    )
    .err()
    .expect("retain failure");
    assert_eq!(
        failure.original_error().downcast_ref::<Denied>().unwrap().0,
        "selection fixture retain denied"
    );
    let held = fixture.memory.snapshot();
    assert_eq!(held.proof_slots, 1);
    assert_eq!(held.proof_bytes, held.proof_peak);
    assert_eq!(held.retains, baseline.retains);
    drop(failure);
    assert_eq!(fixture.memory.snapshot().proof_bytes, baseline.proof_bytes);
    assert_eq!(fixture.memory.snapshot().proof_slots, baseline.proof_slots);
    // Refusal occurs outside native read state; the exact view remains usable.
    drop(fixture.select(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Serving,
    )?);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn selected_application_original_bounded_read_failure_retains_exact_reader() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.stores.write_batch(
        &[],
        &[WriteOp::put(
            META,
            b"applied",
            vec![b'x'; CONTROL_BYTES + 1],
        )],
    )?;
    let view = fixture.stores.read_view()?;
    let id = view.registered_reader_id().unwrap();
    let error = fixture
        .select(
            &view,
            ApplicationBoundaryRef::Entry(&entry(0)),
            ApplicationSelectionMode::Serving,
        )
        .err()
        .expect("bounded native read error");
    let original = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<kasumi_store::NodeScopedReadFailure>()
        .expect("original read owner remains accessible through canonical error chain");
    assert_eq!(original.reader_id(), id);
    assert!(matches!(
        original.report().read_failure(),
        kasumi_kv::TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    let close = view
        .close()
        .expect_err("failed body remains reported on close");
    assert_eq!(original.reader_id(), id);
    assert!(matches!(
        original.report().read_failure(),
        kasumi_kv::TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    let original_address = std::ptr::from_ref(original) as usize;
    let close = close
        .downcast::<kasumi_store::NodeScopedReadFailure>()
        .expect("explicit close owner");
    assert_eq!(
        original.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retained
    );
    assert_eq!(
        close.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(
        original.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(
        std::ptr::from_ref(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<kasumi_store::NodeScopedReadFailure>()
                .unwrap()
        ) as usize,
        original_address
    );
    // The canonical failure and its real workspace still own the original
    // error after its native registration stops pinning the database.
    assert_eq!(fixture.memory.snapshot().proof_slots, 1);
    drop(error);
    assert_eq!(fixture.memory.snapshot().proof_slots, 0);
    drop(close);
    fixture.close().await
}

#[tokio::test]
async fn selected_application_older_image_and_entry_replay_keep_newer_snapshot_identity()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let newer = install_snapshot(&fixture, 10)?;
    let exact = fixture.stores.read_view()?;
    drop(fixture.select(
        &exact,
        ApplicationBoundaryRef::Snapshot(&newer),
        ApplicationSelectionMode::Serving,
    )?);
    let older = install_snapshot(&fixture, 2)?;
    let selected = fixture.stores.read_view()?;
    assert!(
        fixture
            .select(
                &selected,
                ApplicationBoundaryRef::Snapshot(&older),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    let reconstructed = fixture.select(
        &selected,
        ApplicationBoundaryRef::Snapshot(&older),
        ApplicationSelectionMode::Reconstructing,
    )?;
    assert!(reconstructed.is_covered_reconstruction());
    assert_eq!(reconstructed.snapshot().unwrap().meta, &older.meta);
    assert!(
        matches!(reconstructed.applied(), Some(SelectedAppliedRef::Snapshot { meta, .. }) if meta == &newer.meta)
    );
    drop(reconstructed);
    let middle = entry(5);
    let replay = crate::control::prepare_applied(&fixture.stores, &middle, None)?;
    assert!(matches!(
        replay,
        crate::control::PreparedApplied::CoveredReplay { .. }
    ));
    replay.publish(
        &fixture.stores,
        &[WriteOp::put(
            "projection",
            b"current",
            b"reconstructed-entry-five",
        )],
    )?;
    let entry_view = fixture.stores.read_view()?;
    assert!(
        fixture
            .select(
                &entry_view,
                ApplicationBoundaryRef::Entry(&middle),
                ApplicationSelectionMode::Serving
            )
            .is_err()
    );
    let proof = fixture.select(
        &entry_view,
        ApplicationBoundaryRef::Entry(&middle),
        ApplicationSelectionMode::Reconstructing,
    )?;
    assert!(proof.is_covered_reconstruction());
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Snapshot { meta, .. }) if meta == &newer.meta)
    );
    assert_eq!(proof.snapshot().unwrap().meta, &older.meta);
    assert_eq!(
        entry_view
            .application_get("projection", b"current", 64)?
            .as_deref(),
        Some(b"reconstructed-entry-five".as_slice())
    );
    drop(proof);
    drop(fixture.select(
        &exact,
        ApplicationBoundaryRef::Snapshot(&newer),
        ApplicationSelectionMode::Serving,
    )?);
    exact.close()?;
    selected.close()?;
    entry_view.close()?;
    fixture.close().await
}
