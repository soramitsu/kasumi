//! Real lane charges and actual Strong/Weak allocation tails. Native settlement
//! authority is exercised by the source-cohort integration tests separately.
use super::*;
use crate::admission::AdmissionConfig;

fn node() -> Result<Arc<NodeAdmission>> {
    Ok(NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            max_inflight_bytes: Some(64 << 20),
            max_reservations: 64,
            cache_work_reserve_bytes: Some(1 << 20),
            cache_work_reserve_slots: Some(2),
            ..Default::default()
        },
        1 << 30,
        0,
    )?)
}

#[test]
fn source_lane_waits_for_the_actual_last_weak_credit_tail() -> Result<()> {
    let node = node()?;
    let funding = LaneFunding::new(node.clone(), 64 << 10)?;
    let baseline = node.snapshot();
    let credit = SourceCredit::publication(&funding, 0)?;
    let payload = Strong::new(vec![0u8; 256], credit.clone());
    let tail = payload.downgrade();
    credit.prove_retirement();
    drop(payload);
    drop(credit);
    assert!(tail.upgrade().is_none());
    assert!(
        funding.assign(0).is_err(),
        "Weak backing still owns the actual lane credit"
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    drop(tail);
    let next = SourceCredit::publication(&funding, 0)?;
    next.prove_retirement();
    drop(next);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

#[test]
fn history_credit_uses_a_real_new_slot_before_lane_transfer_and_does_not_refill_on_refusal()
-> Result<()> {
    let node = node()?;
    let funding = LaneFunding::new(node.clone(), 64 << 10)?;
    let old = SourceCredit::publication(&funding, 0)?;
    let old_payload = Strong::new(vec![1u8; 256], old.clone());
    let old_tail = old_payload.downgrade();
    let mut pressure = Vec::new();
    while let Ok(grant) = node.reserve_resident(0) {
        pressure.push(grant);
    }
    let full = node.snapshot();
    assert!(old.prepare_history().is_err());
    assert!(!old.is_history());
    assert_eq!(node.snapshot().reserved_bytes, full.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, full.live_reservations);
    assert!(funding.assign(0).is_err());
    drop(pressure);
    let before = node.snapshot();
    assert!(old.prepare_history()?);
    assert_eq!(
        node.snapshot().reserved_bytes,
        before.reserved_bytes + (64 << 10)
    );
    assert_eq!(
        node.snapshot().live_reservations,
        before.live_reservations + 1
    );
    assert!(old.prepare_history()?); // Incomplete native exchange reuses the exact grant.
    assert_eq!(
        node.snapshot().live_reservations,
        before.live_reservations + 1
    );
    old.commit_history();
    assert!(old.is_history());
    assert!(!old.prepare_history()?);
    let next = SourceCredit::publication(&funding, 0)?;
    assert!(!next.is_history());
    assert_eq!(old_payload[0], 1);
    drop(old_payload);
    drop(old);
    assert_eq!(
        node.snapshot().live_reservations,
        before.live_reservations + 1
    );
    drop(old_tail);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    next.prove_retirement();
    drop(next);
    Ok(())
}

#[test]
fn source_lane_clean_history_cancel_restores_current_but_unknown_drop_does_not_free_it()
-> Result<()> {
    let node = node()?;
    let funding = LaneFunding::new(node.clone(), 64 << 10)?;
    let current = SourceCredit::publication(&funding, 0)?;
    let before = node.snapshot();
    assert!(current.prepare_history()?);
    assert!(current.abort_history().is_ok());
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    assert!(!current.is_history());
    assert!(funding.assign(0).is_err());
    drop(current); // No positive native retirement or committed history authority.
    assert!(funding.assign(0).is_err());
    assert!(
        funding.assign(1).is_err(),
        "unknown ownership seals the cohort"
    );
    Ok(())
}
