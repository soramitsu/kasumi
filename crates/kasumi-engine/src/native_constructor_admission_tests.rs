//! Real fixed-census constructor receiver with the production Engine governor.
use super::*;
use crate::admission::{AdmissionConfig, AdmissionSnapshot, ChargeOrigin, NodeAdmission};
use crate::audit_maintenance::NodeAuditMaintenance;
use kasumi_kv::TerminalObservation;
use kasumi_store::{NativeConstructorProbe, NodeDiskMemoryAdmission, StorageCensusDisposition};

fn admission() -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            max_inflight_bytes: Some(4 * NodeAuditMaintenance::WORKSPACE_BYTES),
            ..Default::default()
        },
        2 << 30,
        0,
    )
    .unwrap()
}

fn assert_charge_counters(before: &AdmissionSnapshot, after: &AdmissionSnapshot) {
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(
        after.resident_reserved_bytes,
        before.resident_reserved_bytes
    );
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, before.inflight_operations);
}

fn assert_constructor_charge(core: &MemoryCore, id: u64, bytes: u64) {
    let state = core.data.state.lock().unwrap();
    let charge = state
        .slots
        .iter()
        .find(|slot| slot.id == id)
        .and_then(|slot| slot.charge.as_ref())
        .expect("actual constructor reservation remains owned");
    assert_eq!(charge.bytes, bytes);
    assert!(charge.kind == ChargeKind::Resident);
    assert!(charge.origin == ChargeOrigin::OtherOrdinary);
    assert!(charge.cancellation.is_none());
}

#[test]
fn native_constructor_uses_actual_ordinary_origin_inside_audit_scope() {
    let node = admission();
    let core = node.memory().clone();
    let pool = NodeAuditMaintenance::install(&node).unwrap();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = core.clone();
    let before_prepare = core.snapshot();
    let workspace = 1234;
    let required = MemoryCore::required_installed_reservation_bytes(workspace).unwrap();
    let receiver = NativeConstructorProbe::prepare(provider, workspace).unwrap();
    let before = core.snapshot();
    let id = core.data.state.lock().unwrap().next;
    {
        let _scope = pool.enter_scope();
        assert!(NodeAuditMaintenance::current_for(&core).is_some());
        assert!(receiver.run());
    }
    receiver.with_report(|report| {
        assert!(matches!(
            report.provider(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_eq!(report.protocol(), None);
        assert_eq!(report.request_bytes(), workspace);
        assert!(report.has_lease());
        assert!(!report.capacity_refused());
    });
    let after = core.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes + required);
    assert_eq!(
        after.resident_reserved_bytes,
        before.resident_reserved_bytes + required
    );
    assert_eq!(after.live_reservations, before.live_reservations + 1);
    assert_eq!(after.inflight_operations, before.inflight_operations);
    assert_constructor_charge(&core, id, required);
    assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
    assert_charge_counters(&before_prepare, &core.snapshot());
}

#[test]
fn native_constructor_capacity_refusal_under_audit_scope_preserves_original_counters() {
    let node = admission();
    let core = node.memory().clone();
    let pool = NodeAuditMaintenance::install(&node).unwrap();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = core.clone();
    let before_prepare = core.snapshot();
    let receiver = NativeConstructorProbe::prepare(provider, 1234).unwrap();
    // Obtain the real census receiver before saturating ordinary resident
    // capacity, so the refusal belongs to the actual provider callback.
    let ordinary = node
        .reserve_resident(core.data.max_bytes - core.snapshot().reserved_bytes)
        .unwrap();
    let before = core.snapshot();
    let next = core.data.state.lock().unwrap().next;
    {
        let _scope = pool.enter_scope();
        assert!(NodeAuditMaintenance::current_for(&core).is_some());
        assert!(!receiver.run());
    }
    let original = receiver.with_report(|report| {
        let error = match report.provider() {
            TerminalObservation::Returned(Err(error)) => error,
            _ => panic!("actual constructor capacity refusal"),
        };
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(report.capacity_refused());
        assert!(!report.has_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        error as *const io::Error
    });
    assert!(!receiver.run());
    receiver.with_report(|report| match report.provider() {
        TerminalObservation::Returned(Err(error)) => {
            assert!(std::ptr::eq(error, original));
        }
        _ => panic!("original constructor refusal remains retained"),
    });
    assert_charge_counters(&before, &core.snapshot());
    assert_eq!(core.data.state.lock().unwrap().next, next);
    assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
    drop(ordinary);
    assert_charge_counters(&before_prepare, &core.snapshot());
}

#[test]
fn native_constructor_duplicate_entry_retains_exact_first_grant() {
    let node = admission();
    let core = node.memory().clone();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = core.clone();
    let before_prepare = core.snapshot();
    let workspace = 1234;
    let required = MemoryCore::required_installed_reservation_bytes(workspace).unwrap();
    let receiver = NativeConstructorProbe::prepare(provider, workspace).unwrap();
    let id = core.data.state.lock().unwrap().next;
    assert!(receiver.run());
    let bound = core.snapshot();
    let next = core.data.state.lock().unwrap().next;
    assert_constructor_charge(&core, id, required);
    assert!(!receiver.run_provider_again_for_test());
    assert_charge_counters(&bound, &core.snapshot());
    assert_eq!(core.data.state.lock().unwrap().next, next);
    assert_constructor_charge(&core, id, required);
    receiver.with_report(|report| {
        assert!(matches!(
            report.provider(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_eq!(report.request_bytes(), workspace);
        assert!(report.has_lease());
        assert!(!report.capacity_refused());
    });
    assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
    assert_charge_counters(&before_prepare, &core.snapshot());
}
