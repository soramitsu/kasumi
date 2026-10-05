use super::*;
use crate::selected_application::fixture::{Denied, Fixture, entry, install_snapshot};
use kasumi_store::NodeDiskMemoryAdmission;
use openraft::{EntryPayload, Membership, storage::RaftLogStorageExt};
use std::collections::{BTreeMap, BTreeSet};

fn membership(large: bool) -> Membership<u64, BasicNode> {
    Membership::new(
        if large {
            vec![BTreeSet::from([1]), BTreeSet::from([1, u64::MAX])]
        } else {
            vec![BTreeSet::from([1])]
        },
        BTreeMap::from([(
            1,
            BasicNode::new(if large {
                "escaped\"\\\n\0日本".repeat(256)
            } else {
                "local".into()
            }),
        )]),
    )
}
fn context(entry: &crate::Entry<crate::TypeConfig>) -> Result<AppliedEntryContext> {
    let EntryPayload::Membership(membership) = &entry.payload else {
        unreachable!()
    };
    Ok(AppliedEntryContext {
        log_id: entry.log_id,
        previous: (entry.log_id.index != 0).then(|| self::entry(entry.log_id.index - 1).log_id),
        membership: StoredMembership::new(Some(entry.log_id), membership.clone()),
        command_sha256: crate::command::sha256(&crate::storage::encode_entry(entry)?),
        retirement_seed: None,
    })
}

#[tokio::test]
async fn constructor_covers_retained_uncommitted_membership_and_real_capture_without_new_grants()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let mut log = crate::LogStore::open(fixture.stores.clone(), 1).await?;
    let first = crate::Entry::<crate::TypeConfig> {
        initialization: None,
        log_id: entry(0).log_id,
        payload: EntryPayload::Membership(membership(false)),
    };
    let next = crate::Entry::<crate::TypeConfig> {
        initialization: None,
        log_id: entry(1).log_id,
        payload: EntryPayload::Membership(membership(true)),
    };
    let body = crate::Entry::<crate::TypeConfig> {
        initialization: None,
        log_id: entry(2).log_id,
        payload: EntryPayload::Normal(crate::RaftCommand::application(vec![7; 12345])),
    };
    let body_bytes = crate::storage::encode_entry(&body)?.len();
    log.blocking_append([first.clone(), next.clone(), body])
        .await?;
    let first = context(&first)?;
    let next = context(&next)?;
    crate::control::prepare_applied(&fixture.stores, &first, None)?
        .publish(&fixture.stores, &[])?;
    let before = fixture
        .stores
        .custody()
        .store()
        .get_bounded(META, b"applied", CONTROL_BYTES)?;
    let (envelope, mut points, workspace) = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )?;
    let (_, covered, covered_points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &first, None, &[])?;
    envelope.require_plan(&covered)?;
    drop(covered_points);
    let (pending, plan, planner_points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &next, None, &[])?;
    envelope.require_plan(&plan)?;
    let (header_bound, body_bound) = envelope.retained_lookup_bounds();
    assert!(header_bound > 1000);
    assert!(body_bound >= body_bytes);
    assert!(body_bound < body_bytes + 8192);
    assert_eq!(
        fixture
            .stores
            .custody()
            .store()
            .get_bounded(META, b"applied", CONTROL_BYTES)?,
        before
    );
    // This entry was already present during construction; no new append is
    // needed when the actor later learns that it has become committed.
    pending.publish(&fixture.stores, &[])?;
    drop(planner_points);
    let (new_current, current_points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    assert!(
        envelope.require_plan(&new_current).is_err(),
        "capacity is not exact replay authority"
    );
    let next_seed = envelope.with_publication_plan(&plan)?;
    next_seed.require_plan(&new_current)?;
    assert!(envelope.require_plan(&new_current).is_err());
    drop(next_seed);
    drop(current_points);
    let view = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let selected = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&next),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        workspace,
        &plan,
        &mut points,
    );
    fixture.memory.deny_installed(false);
    let selected = selected?;
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert!(
        matches!(selected.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == next.log_id)
    );
    drop((selected, points, plan, covered, new_current, envelope, log));
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn constructor_snapshot_seed_covers_exact_reconstruction_but_rejects_same_size_replacement()
-> Result<()> {
    let fixture = Fixture::new().await?;
    install_snapshot(&fixture, 4)?;
    let (envelope, points, workspace) = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )?;
    let (current, current_points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    envelope.require_plan(&current)?;
    let (_, covered, covered_points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &entry(0), None, &[])?;
    envelope.require_plan(&covered)?;
    drop((current_points, covered_points));
    let (_, advancing, advancing_points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &entry(5), None, &[])?;
    let next_seed = envelope.with_publication_plan(&advancing)?;
    assert_eq!(next_seed.peak_bytes(), envelope.peak_bytes());
    assert_eq!(next_seed.retained_bytes(), envelope.retained_bytes());
    assert_eq!(next_seed.point_bounds(), envelope.point_bounds());
    drop((next_seed, advancing, advancing_points));
    install_snapshot(&fixture, 4)?;
    let (substituted, substituted_points) =
        PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    assert_eq!(
        current
            .records
            .map(|record| record.map(|record| record.bytes)),
        substituted
            .records
            .map(|record| record.map(|record| record.bytes))
    );
    assert_eq!(
        envelope.require_plan(&substituted).unwrap_err().to_string(),
        "source reconstruction differs from producer seed"
    );
    drop((
        current,
        covered,
        substituted,
        points,
        substituted_points,
        workspace,
        envelope,
    ));
    fixture.close().await
}

#[tokio::test]
async fn constructor_preserves_actual_capacity_refusal_and_retires_reader_before_retry()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.memory.snapshot();
    let failure = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(1024),
    )
    .err()
    .context("constructor ignored actual metadata capacity refusal")?;
    assert!(failure.original_error().downcast_ref::<Denied>().is_some());
    assert_eq!(
        fixture.memory.snapshot().proof_slots,
        before.proof_slots + 1
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    drop(failure);
    assert_eq!(fixture.memory.snapshot().bytes, before.bytes);
    assert_eq!(fixture.memory.snapshot().slots, before.slots);
    let (envelope, points, workspace) = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )?;
    drop((envelope, points, workspace));
    fixture.close().await
}

#[tokio::test]
async fn constructor_rejects_foreign_workspace_and_noncanonical_or_disconnected_retained_headers()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let failure = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        foreign.memory.workspace(128 << 20),
    )
    .err()
    .context("foreign workspace accepted")?;
    assert!(
        failure
            .original_error()
            .to_string()
            .contains("memory owners differ")
    );
    drop(failure);
    foreign.close().await?;
    let mut log = crate::LogStore::open(fixture.stores.clone(), 1).await?;
    let headers = (0..3)
        .map(|index| crate::Entry::<crate::TypeConfig> {
            initialization: None,
            log_id: entry(index).log_id,
            payload: EntryPayload::Blank,
        })
        .collect::<Vec<_>>();
    log.blocking_append(headers).await?;
    let old = fixture
        .stores
        .custody()
        .store()
        .get_bounded(crate::control::HEADERS, &1u64.to_be_bytes(), HEADER_BYTES)?
        .unwrap();
    fixture.stores.write_batch(
        &[],
        &[WriteOp::Delete {
            namespace: crate::control::HEADERS.into(),
            key: 1u64.to_be_bytes().to_vec(),
        }],
    )?;
    let failure = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )
    .err()
    .context("retained hole accepted")?;
    assert_eq!(
        failure.original_error().to_string(),
        "raft log contains a hole"
    );
    drop(failure);
    let store = fixture.stores.custody().store();
    let noncanonical =
        kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(store, old.as_bytes(), b" ")?;
    kasumi_store::test_utils::FixtureWriteBatch::prepare(
        store,
        &[kasumi_store::test_utils::FixtureWrite::Put(
            crate::control::HEADERS,
            &1u64.to_be_bytes(),
            noncanonical.as_bytes(),
        )],
    )?
    .write_custody(&fixture.stores)?;
    let failure = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )
    .err()
    .context("noncanonical retained header accepted")?;
    assert_eq!(
        failure.original_error().to_string(),
        "noncanonical raft control record"
    );
    drop((failure, log));
    fixture.close().await
}

#[tokio::test]
async fn constructor_header_peak_refusal_preserves_current_dtos_and_durable_tail() -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut log = crate::LogStore::open(fixture.stores.clone(), 1).await?;
    let large = crate::Entry::<crate::TypeConfig> {
        initialization: None,
        log_id: entry(0).log_id,
        payload: EntryPayload::Membership(membership(true)),
    };
    log.blocking_append([large]).await?;
    let (current, mut points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    let budget = 1024 + current.peak_bytes();
    // The exact same real budget supports canonical current-root selection.
    let view = fixture.stores.read_view()?;
    let selected = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(budget),
        &current,
        &mut points,
    )?;
    drop((selected, points));
    view.close()?;
    let header_before = fixture.stores.custody().store().get_bounded(
        crate::control::HEADERS,
        &0u64.to_be_bytes(),
        HEADER_BYTES,
    )?;
    let before = fixture.memory.snapshot();
    let failure = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(budget),
    )
    .err()
    .context("retained membership bypassed actual header allocation refusal")?;
    assert!(failure.original_error().downcast_ref::<Denied>().is_some());
    assert_eq!(
        fixture.memory.snapshot().proof_slots,
        before.proof_slots + 1
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    drop(failure);
    assert_eq!(fixture.memory.snapshot().bytes, before.bytes);
    assert_eq!(fixture.memory.snapshot().slots, before.slots);
    assert_eq!(
        fixture.stores.custody().store().get_bounded(
            crate::control::HEADERS,
            &0u64.to_be_bytes(),
            HEADER_BYTES,
        )?,
        header_before
    );
    let (envelope, points, workspace) = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )?;
    drop((envelope, points, workspace, current, log));
    fixture.close().await
}

#[tokio::test]
async fn incoming_capacity_covers_each_intermediate_membership_without_adopting_replay_seed()
-> Result<()> {
    use crate::selected_application::allocation_tests::require_no_allocations;
    let fixture = Fixture::new().await?;
    let (original, points, workspace) = PreparedSourceCapacityEnvelope::for_constructor(
        &fixture.stores,
        &fixture.image,
        &RaftLimits::default(),
        fixture.memory.workspace(128 << 20),
    )?;
    drop((points, workspace));
    let incoming = [
        crate::Entry::<crate::TypeConfig> {
            initialization: None,
            log_id: entry(0).log_id,
            payload: EntryPayload::Membership(membership(true)),
        },
        crate::Entry::<crate::TypeConfig> {
            initialization: None,
            log_id: entry(1).log_id,
            payload: EntryPayload::Membership(membership(false)),
        },
    ];
    let empty = require_no_allocations(|| original.with_entries(&[]))?;
    assert_eq!(empty.point_bounds(), original.point_bounds());
    assert_eq!(empty.peak_bytes(), original.peak_bytes());
    assert_eq!(empty.retained_bytes(), original.retained_bytes());
    let last_only = require_no_allocations(|| original.with_entries(&incoming[1..]))?;
    let expanded = require_no_allocations(|| original.with_entries(&incoming))?;
    assert!(expanded.point_bounds().2 > last_only.point_bounds().2);
    assert_eq!(
        expanded.retained_lookup_bounds(),
        original.retained_lookup_bounds()
    );
    let (initial, initial_points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    original.require_plan(&initial)?;
    expanded.require_plan(&initial)?;
    drop(initial_points);
    let mut log = crate::LogStore::open(fixture.stores.clone(), 1).await?;
    log.blocking_append(incoming.clone()).await?;
    for (index, incoming) in incoming.iter().enumerate() {
        let context = context(incoming)?;
        let (prepared, plan, points) =
            crate::control::prepare_applied_and_selection(&fixture.stores, &context, None, &[])?;
        if index == 0 {
            assert!(original.require_plan(&plan).is_err());
            assert!(last_only.require_plan(&plan).is_err());
        }
        expanded.require_plan(&plan)?;
        prepared.publish(&fixture.stores, &[])?;
        drop(points);
        let (current, current_points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
        assert!(
            expanded.require_plan(&current).is_err(),
            "shape growth is not replay authority"
        );
        expanded
            .with_publication_plan(&plan)?
            .require_plan(&current)?;
        drop(current_points);
    }
    drop((original, expanded, last_only, empty, log));
    fixture.close().await
}
