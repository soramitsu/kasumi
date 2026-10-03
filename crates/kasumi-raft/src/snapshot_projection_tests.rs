//! Projection row bounds are independent of the snapshot transport header's
//! separate bound: the latter also carries first membership and initialization.
use super::*;
use crate::storage::SnapshotEnvelope;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn verify_boundary(
    store: &TenantStore,
    baseline: &SnapshotEnvelope,
) -> Result<SnapshotEnvelope> {
    let original = store
        .get_bounded(META, PROJECTION, MAX_PROJECTION_BYTES)?
        .context("published baseline projection absent")?;
    let first = baseline
        .first_membership
        .as_ref()
        .context("baseline first membership absent")?;
    let mut sized = baseline.clone();
    let later_id = crate::control::tests::id(2);
    ensure!(
        later_id > first.header.log_id && Some(later_id) > baseline.meta.last_log_id,
        "sizing membership must follow the immutable first fact and baseline"
    );
    let membership = |address: String| {
        openraft::StoredMembership::new(
            Some(later_id),
            openraft::Membership::new(
                vec![BTreeSet::from([1])],
                BTreeMap::from([(1, BasicNode::new(address))]),
            ),
        )
    };
    // This is a direct projection codec fixture, not a claimed snapshot
    // publication. A later membership preserves the exact first fact and its
    // association while providing a variable-length, canonical metadata field.
    sized.meta.last_log_id = Some(later_id);
    sized.meta.last_membership = membership(String::new());
    let mut projection = Projection {
        meta: sized.meta.clone(),
        snapshot_sha256: "0".repeat(64),
        retirement: sized.retirement.clone().context("retirement absent")?,
    };
    let address_len = MAX_PROJECTION_BYTES
        .checked_sub(encode_projection(&projection)?.len())
        .context("base projection exceeds record budget")?;
    projection.meta.last_membership = membership("x".repeat(address_len));
    sized.meta = projection.meta.clone();
    control::validate_snapshot_first_membership(&sized.meta, sized.first_membership.as_ref())?;
    crate::initialization_association::validate_snapshot(
        &sized.meta,
        sized.first_membership.as_ref(),
        sized.initialization_association.as_ref(),
    )?;
    projection.retirement.validate(&projection.meta)?;
    let bytes = encode_projection(&projection)?;
    assert_eq!(bytes.len(), MAX_PROJECTION_BYTES);
    store.write_batch(&[WriteOp::put(META, PROJECTION, bytes.clone())])?;
    assert!(load_projection(store)?.as_ref() == Some(&projection));

    let reordered = serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(&bytes)?)?;
    assert_eq!(reordered.len(), bytes.len());
    assert_ne!(reordered, bytes);
    store.write_batch(&[WriteOp::put(META, PROJECTION, reordered)])?;
    let error = load_projection(store)
        .err()
        .context("noncanonical row accepted")?;
    assert!(
        error
            .to_string()
            .contains("noncanonical snapshot retirement projection")
    );

    let mut alias = projection.clone();
    alias.meta.snapshot_id = uuid::Uuid::parse_str(&projection.meta.snapshot_id)?
        .simple()
        .to_string();
    let error = encode_projection(&alias).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid snapshot retirement projection identity")
    );
    store.write_batch(&[WriteOp::put(META, PROJECTION, serde_json::to_vec(&alias)?)])?;
    let error = load_projection(store)
        .err()
        .context("snapshot UUID alias accepted")?;
    assert!(
        error
            .to_string()
            .contains("invalid snapshot retirement projection identity")
    );

    projection.meta.last_membership = membership("x".repeat(address_len + 1));
    let oversized = serde_json::to_vec(&projection)?;
    assert_eq!(oversized.len(), MAX_PROJECTION_BYTES + 1);
    let error = encode_projection(&projection).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("snapshot retirement projection exceeds byte limit")
    );
    store.write_batch(&[WriteOp::put(META, PROJECTION, oversized)])?;
    assert!(
        load_projection(store).is_err(),
        "reader admitted an oversized canonical row"
    );

    // Restore the exact previously published row; the caller independently
    // validates the baseline's image/coverage before testing staging refusal.
    store.write_batch(&[WriteOp::put(META, PROJECTION, original.clone())])?;
    assert_eq!(
        encode_projection(&load_projection(store)?.unwrap())?,
        original
    );
    sized.meta = projection.meta;
    control::validate_snapshot_first_membership(&sized.meta, sized.first_membership.as_ref())?;
    crate::initialization_association::validate_snapshot(
        &sized.meta,
        sized.first_membership.as_ref(),
        sized.initialization_association.as_ref(),
    )?;
    Ok(sized)
}
