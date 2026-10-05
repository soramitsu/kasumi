use super::*;
use crate::selected_application::allocation_tests::require_no_allocations;
use crate::selected_application::fixture::{Fixture, entry as entry_context, install_snapshot};
use openraft::storage::RaftLogStorageExt;
use std::collections::{BTreeMap, BTreeSet};

fn bootstrap(fixture: &Fixture) -> ApplicationBootstrapManifest {
    ApplicationBootstrapManifest {
        format: 2,
        bytes: fixture.image.len(),
        chunks: fixture
            .image
            .len()
            .div_ceil(kasumi_store::APPLICATION_BOOTSTRAP_CHUNK_BYTES as u64),
        digest: fixture.image.sha256().into(),
    }
}
fn members(large: bool) -> Membership<u64, BasicNode> {
    let address = if large {
        "quote\" slash\\ newline\n nul\0 日本語".repeat(80)
    } else {
        "local".into()
    };
    Membership::new(
        if large {
            vec![BTreeSet::from([1]), BTreeSet::from([1, u64::MAX])]
        } else {
            vec![BTreeSet::from([1])]
        },
        if large {
            BTreeMap::from([
                (1, BasicNode::new(&address)),
                (u64::MAX, BasicNode::new("other")),
            ])
        } else {
            BTreeMap::from([(1, BasicNode::new(&address))])
        },
    )
}

#[test]
fn streamed_shape_quote_matches_actual_canonical_wire_and_number_channels() -> Result<()> {
    for bytes in [
        br#"{"empty":[],"object":{},"false":false,"null":null}"#.as_slice(),
        br#"[0,18446744073709551615,-9223372036854775808,18446744073709551616,-9223372036854775809,1.25e50]"#,
        br#"{"escaped":"quote\" backslash\\ control\u0000 final\\","unicode":"\u65e5\u672c"}"#,
    ] {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let wire = serde_json::to_vec(&value)?;
        let (length, streamed, digest) = require_no_allocations(|| allocation::serialized_quote(&value))?;
        let existing = allocation::canonical_wire_quote(&wire)?;
        assert_eq!(length, wire.len());
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&wire)));
        assert_eq!((streamed.peak, streamed.retained), (existing.peak, existing.retained));
    }
    Ok(())
}

#[test]
fn borrowed_maximum_shape_matches_actual_cursor_schema_for_zero_single_and_joint_membership()
-> Result<()> {
    let maximum = LogId::new(CommittedLeaderId::new(u64::MAX, u64::MAX), u64::MAX);
    for membership in [Membership::default(), members(false), members(true)] {
        let actual = AppliedCursor::Entry(AppliedPosition {
            log_id: maximum,
            previous: Some(maximum),
            membership: StoredMembership::new(Some(maximum), membership.clone()),
            command_sha256: HASH_SHAPE.into(),
        });
        let shape = CursorShape::Entry(EntryShape {
            log_id: maximum,
            previous: Some(maximum),
            membership: MembershipShape {
                log_id: Some(maximum),
                membership: &membership,
            },
            command_sha256: HASH_SHAPE,
        });
        let actual = serde_json::to_vec(&actual)?;
        assert_eq!(serde_json::to_vec(&shape)?, actual);
        let (length, streamed, _) =
            require_no_allocations(|| allocation::serialized_quote(&shape))?;
        let wire = allocation::canonical_wire_quote(&actual)?;
        assert_eq!(length, actual.len());
        assert_eq!(
            (streamed.peak, streamed.retained),
            (wire.peak, wire.retained)
        );
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_envelope_covers_actual_current_and_advancing_plans_but_not_covered_or_snapshot()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let actual_bootstrap = bootstrap(&fixture);
    let membership = StoredMembership::default();
    let envelope = require_no_allocations(|| {
        PreparedOrdinarySourceEnvelope::for_membership(
            &fixture.stores,
            &actual_bootstrap,
            &membership,
        )
    })?;
    let (current, points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    envelope.require_plan(&current)?;
    drop(points);
    let position = entry_context(0);
    let (prepared, plan, points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &position, None, &[])?;
    envelope.require_plan(&plan)?;
    assert!(envelope.point_bounds().2 < CONTROL_BYTES);
    prepared.publish(&fixture.stores, &[])?;
    drop(points);
    let (current, points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    envelope.require_plan(&current)?;
    drop(points);
    let (_, covered, points) =
        crate::control::prepare_applied_and_selection(&fixture.stores, &position, None, &[])?;
    assert_eq!(
        envelope.require_plan(&covered).unwrap_err().to_string(),
        "ordinary source envelope excludes covered or snapshot reconstruction"
    );
    drop(points);
    install_snapshot(&fixture, 1)?;
    let (snapshot, points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    assert_eq!(
        envelope.require_plan(&snapshot).unwrap_err().to_string(),
        "ordinary source envelope excludes covered or snapshot reconstruction"
    );
    drop(points);
    drop((current, plan, covered, snapshot, envelope));
    fixture.close().await
}

#[tokio::test]
async fn membership_growth_requires_expanded_quote_before_actual_internal_entry_publication()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let mut log = crate::LogStore::open(fixture.stores.clone(), 1).await?;
    let mut envelope = PreparedOrdinarySourceEnvelope::for_membership(
        &fixture.stores,
        &bootstrap(&fixture),
        &StoredMembership::default(),
    )?;
    for index in 0..2 {
        let membership = members(index == 1);
        let entry = crate::Entry::<crate::TypeConfig> {
            initialization: None,
            log_id: entry_context(index).log_id,
            payload: openraft::EntryPayload::Membership(membership.clone()),
        };
        log.blocking_append([entry.clone()]).await?;
        let context = AppliedEntryContext {
            log_id: entry.log_id,
            previous: (index != 0).then(|| entry_context(index - 1).log_id),
            membership: StoredMembership::new(Some(entry.log_id), membership),
            command_sha256: crate::command::sha256(&crate::storage::encode_entry(&entry)?),
            retirement_seed: None,
        };
        let before =
            fixture
                .stores
                .custody()
                .store()
                .get_bounded(META, b"applied", CONTROL_BYTES)?;
        let (prepared, plan, points) =
            crate::control::prepare_applied_and_selection(&fixture.stores, &context, None, &[])?;
        // Scalar-width slack may already cover the first small membership.
        // Shape coverage is not exact-membership authority. The later actual
        // large joint membership must exceed the preceding owned envelope.
        if index == 1 {
            assert!(envelope.require_plan(&plan).is_err());
        }
        assert_eq!(
            fixture
                .stores
                .custody()
                .store()
                .get_bounded(META, b"applied", CONTROL_BYTES)?,
            before
        );
        let expanded = require_no_allocations(|| envelope.with_membership(&context.membership))?;
        require_no_allocations(|| expanded.require_plan(&plan))?;
        let independently_derived = PreparedOrdinarySourceEnvelope::for_membership(
            &fixture.stores,
            &bootstrap(&fixture),
            &context.membership,
        )?;
        let merged = require_no_allocations(|| envelope.merge(&independently_derived))?;
        assert_eq!(merged.peak_bytes(), expanded.peak_bytes());
        assert_eq!(merged.retained_bytes(), expanded.retained_bytes());
        assert_eq!(merged.point_bounds(), expanded.point_bounds());
        prepared.publish(&fixture.stores, &[])?;
        drop(points);
        let view = fixture.stores.read_view()?;
        let selected = fixture.select(
            &view,
            ApplicationBoundaryRef::Entry(&context),
            ApplicationSelectionMode::Serving,
        )?;
        assert!(selected.retained_workspace_bytes() <= expanded.retained_bytes());
        drop(selected);
        view.close()?;
        envelope = expanded;
    }
    drop(log);
    drop(envelope);
    fixture.close().await
}

#[tokio::test]
async fn ordinary_envelope_rejects_foreign_pair_and_changed_bootstrap_without_admission()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let membership = StoredMembership::default();
    let actual = bootstrap(&fixture);
    let envelope =
        PreparedOrdinarySourceEnvelope::for_membership(&fixture.stores, &actual, &membership)?;
    let other = PreparedOrdinarySourceEnvelope::for_membership(
        &foreign.stores,
        &bootstrap(&foreign),
        &membership,
    )?;
    let mut changed = bootstrap(&fixture);
    changed.digest = "f".repeat(64);
    let changed =
        PreparedOrdinarySourceEnvelope::for_membership(&fixture.stores, &changed, &membership)?;
    let (plan, points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    let before = fixture.memory.snapshot();
    assert!(envelope.require_stores(&foreign.stores).is_err());
    assert!(envelope.merge(&other).is_err());
    assert!(envelope.merge(&changed).is_err());
    assert!(other.require_plan(&plan).is_err());
    assert!(changed.require_plan(&plan).is_err());
    let after = fixture.memory.snapshot();
    assert_eq!(
        (
            after.bytes,
            after.peak_bytes,
            after.slots,
            after.proof_bytes,
            after.proof_slots,
            after.proof_peak,
            after.retains
        ),
        (
            before.bytes,
            before.peak_bytes,
            before.slots,
            before.proof_bytes,
            before.proof_slots,
            before.proof_peak,
            before.retains
        )
    );
    drop(points);
    drop((envelope, other, changed, plan));
    fixture.close().await?;
    foreign.close().await
}

#[tokio::test]
async fn ordinary_shape_preserves_the_existing_maximum_control_record_ceiling() -> Result<()> {
    let fixture = Fixture::new().await?;
    let maximum = LogId::new(CommittedLeaderId::new(u64::MAX, u64::MAX), u64::MAX);
    let membership_for = |address: String| {
        Membership::new(
            vec![BTreeSet::from([1])],
            BTreeMap::from([(1, BasicNode::new(address))]),
        )
    };
    let empty = membership_for(String::new());
    fn cursor(membership: &Membership<u64, BasicNode>) -> CursorShape<'_> {
        let maximum = LogId::new(CommittedLeaderId::new(u64::MAX, u64::MAX), u64::MAX);
        CursorShape::Entry(EntryShape {
            log_id: maximum,
            previous: Some(maximum),
            membership: MembershipShape {
                log_id: Some(maximum),
                membership,
            },
            command_sha256: HASH_SHAPE,
        })
    }
    let fixed = allocation::serialized_quote(&cursor(&empty))?.0;
    let membership = membership_for("x".repeat(CONTROL_BYTES - fixed));
    let (length, quote, _) =
        require_no_allocations(|| allocation::serialized_quote(&cursor(&membership)))?;
    assert_eq!(length, CONTROL_BYTES);
    let actual_bootstrap = bootstrap(&fixture);
    let stored = StoredMembership::new(Some(maximum), membership);
    let envelope = require_no_allocations(|| {
        PreparedOrdinarySourceEnvelope::for_membership(&fixture.stores, &actual_bootstrap, &stored)
    })?;
    assert_eq!(envelope.point_bounds().2, CONTROL_BYTES);
    assert!(envelope.peak_bytes() >= quote.peak);
    assert!(envelope.retained_bytes() >= quote.retained);
    drop(envelope);
    fixture.close().await
}
