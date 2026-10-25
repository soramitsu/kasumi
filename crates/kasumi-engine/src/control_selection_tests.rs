use super::*;
use crate::{
    admission::{AdmissionConfig, NodeAdmission},
    document_pool::allocation_tests::measure_topology_input,
};
use serde_json::{Value, json};

fn node(payload: u64) -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(128 << 20),
            low_water_bytes: Some(96 << 20),
            max_inflight_bytes: Some(payload),
            max_inflight_operations: 4,
            max_reservations: 256,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            ..Default::default()
        })
        .unwrap(),
        128 << 20,
        0,
    )
    .unwrap()
}

fn topology() -> Document {
    Document {
        id: "current".into(),
        version: 9,
        body: json!({"nodes":{},"tenants":{}}),
    }
}

#[test]
fn control_document_small_rows_fit_a_tight_budget_and_hundred_retained_reads() {
    let document = topology();
    let admission = node(1 << 20);
    let before = admission.snapshot();
    let retained = PendingDocument::retained_bytes(&document).unwrap();
    assert!(retained < 10 << 10);
    let mut outputs = Vec::new();
    for _ in 0..100 {
        outputs.push(
            PendingDocument::copy(&admission, &document)
                .unwrap()
                .finish(&admission)
                .unwrap(),
        );
    }
    let held = admission.snapshot();
    assert_eq!(held.reserved_bytes - before.reserved_bytes, 100 * retained);
    assert_eq!(held.live_reservations - before.live_reservations, 100);
    assert_eq!(held.inflight_operations, before.inflight_operations);
    assert!(outputs.iter().all(|output| output.as_ref() == &document));
    drop(outputs);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
}

#[test]
fn control_document_compact_copy_does_not_retain_source_spare_capacity() {
    let mut id = String::with_capacity(1 << 20);
    id.push_str("current");
    let mut text = String::with_capacity(1 << 20);
    text.push_str("tiny");
    let document = Document {
        id,
        version: 7,
        body: Value::String(text),
    };
    let admission = node(8 << 10);
    let before = admission.snapshot();
    let output = PendingDocument::copy(&admission, &document)
        .unwrap()
        .finish(&admission)
        .unwrap();
    assert_eq!(output.as_ref(), &document);
    assert_ne!(output.id.as_ptr(), document.id.as_ptr());
    let (Value::String(actual), Value::String(source)) = (&output.body, &document.body) else {
        panic!("string fixture");
    };
    assert_ne!(actual.as_ptr(), source.as_ptr());
    assert!(actual.capacity() < source.capacity());
    assert!(output.id.capacity() < document.id.capacity());
    let held = admission.snapshot();
    let last = output.clone();
    assert_eq!(admission.snapshot().reserved_bytes, held.reserved_bytes);
    drop((document, output));
    assert_eq!(admission.snapshot().reserved_bytes, held.reserved_bytes);
    std::thread::spawn(move || {
        assert_eq!(last.body, "tiny");
        drop(last);
    })
    .join()
    .unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
}

#[test]
fn control_document_large_shape_is_quoted_before_copy_and_bounds_measured_allocations() {
    let document = Document {
        id: "large-enrollment".into(),
        version: 81,
        body: json!({
            "blob": "x".repeat(512 << 10),
            "entries": (0..128).map(|index| json!({"id":index,"values":[true,null,"value"]})).collect::<Vec<_>>()
        }),
    };
    let retained = PendingDocument::retained_bytes(&document).unwrap();
    let peak = retained + cancellation_bytes().unwrap();
    let admission = node(peak);
    let before = admission.snapshot();
    let (output, live, measured_peak, _) = measure_topology_input(|| {
        PendingDocument::copy(&admission, &document)
            .unwrap()
            .finish(&admission)
            .unwrap()
    });
    assert!(live > 0);
    assert!(live as u64 <= retained, "{live} > {retained}");
    assert!(measured_peak as u64 <= peak, "{measured_peak} > {peak}");
    assert_eq!(
        admission.snapshot().reserved_bytes - before.reserved_bytes,
        retained
    );
    assert_eq!(output.as_ref(), &document);
    drop(output);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);

    let denied = node(peak - 1);
    let before = denied.snapshot();
    let (error, _, denied_peak, _) =
        measure_topology_input(|| PendingDocument::copy(&denied, &document).err().unwrap());
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(
        denied_peak < 4096,
        "admission denial allocated {denied_peak}"
    );
    assert_eq!(denied.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        denied.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        denied.snapshot().inflight_operations,
        before.inflight_operations
    );
}

#[test]
fn control_document_cancelled_release_discards_copy_before_refunding_admission() {
    let document = topology();
    let admission = node(16 << 10);
    let before = admission.snapshot();
    let pending = PendingDocument::copy(&admission, &document).unwrap();
    assert!(pending.document.is_some());
    pending.cancellation.cancel();
    assert_eq!(
        pending.finish(&admission).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        admission.snapshot().inflight_operations,
        before.inflight_operations
    );
}

#[test]
fn control_document_charge_outlives_the_actual_body_deallocation() {
    let document = Document {
        id: "current".into(),
        version: 1,
        body: Value::String("x".repeat(4096)),
    };
    let admission = node(16 << 10);
    let before = admission.snapshot();
    let output = PendingDocument::copy(&admission, &document)
        .unwrap()
        .finish(&admission)
        .unwrap();
    let held = admission.snapshot();
    let address = output.body.as_str().unwrap().as_ptr() as usize;
    crate::document_pool::allocation_tests::check_topology_input_drop(
        address,
        move || drop(output),
        || {
            assert_eq!(admission.snapshot().reserved_bytes, held.reserved_bytes);
            assert_eq!(
                admission.snapshot().live_reservations,
                held.live_reservations
            );
        },
    );
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
}
