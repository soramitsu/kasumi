use super::*;
use crate::admission::AdmissionConfig;
use serde_json::json;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) const WORK_HEADROOM: u64 = 4096;

// payload_bytes is the usable source allowance. Required-work headroom remains
// separately free; no installed default or production limit is changed.
pub(super) fn node(payload_bytes: u64) -> Arc<NodeAdmission> {
    node_with_headroom(
        payload_bytes.checked_add(WORK_HEADROOM).unwrap(),
        4,
        WORK_HEADROOM,
    )
}

fn node_with_headroom(
    total_payload_bytes: u64,
    slots: usize,
    work_bytes: u64,
) -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            max_inflight_bytes: Some(total_payload_bytes),
            cache_work_reserve_bytes: Some(work_bytes),
            cache_work_reserve_slots: Some(1),
            max_inflight_operations: 2,
            max_reservations: slots,
            max_snapshot_startups: 1,
            max_startup_scopes: 1,
            ..Default::default()
        })
        .unwrap(),
        8 << 30,
        0,
    )
    .unwrap()
}

#[test]
fn document_pool_thousands_of_documents_share_one_resident_slot() {
    let node = node(8 << 20);
    let baseline = node.snapshot();
    let pool = DocumentPool::new(&node).unwrap();
    let control = DocumentPool::control_bytes().unwrap();
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    let body = json!({"value": 7});
    let mut expected = control;
    let mut documents = Vec::with_capacity(4096);
    for index in 0..4096 {
        let id = format!("row-{index}");
        let document = pool.clone_parts(&id, 1, &body).unwrap();
        expected += document.charged_bytes();
        documents.push(document);
    }
    let retained = node.snapshot();
    assert_eq!(retained.live_reservations, baseline.live_reservations + 1);
    assert_eq!(retained.inflight_operations, baseline.inflight_operations);
    assert_eq!(retained.reserved_bytes, baseline.reserved_bytes + expected);
    assert_eq!(pool.used(), expected);
    let alias = documents[2000].clone();
    assert!(std::ptr::eq(alias.as_ref(), documents[2000].as_ref()));
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    assert_eq!(serde_json::to_value(&alias).unwrap()["body"], body);
    let last = alias.charged_bytes();
    drop(documents);
    assert_eq!(pool.used(), control + last);
    drop(pool);
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control + last
    );
    std::thread::spawn(move || drop(alias)).join().unwrap();
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn document_pool_denial_and_overflow_preserve_existing_credit_and_source() {
    let source = Document {
        id: "a".into(),
        version: 4,
        body: json!({"kept": "x".repeat(1024)}),
    };
    let control = DocumentPool::control_bytes().unwrap();
    let quote = DocumentPool::document_bytes(&source.id, &source.body).unwrap();
    let node = node(control + quote);
    let baseline = node.snapshot();
    let pool = DocumentPool::new(&node).unwrap();
    let document = pool.clone_document(&source).unwrap();
    let retained = node.snapshot();
    let denied = pool.clone_document(&source).unwrap_err();
    assert!(matches!(denied, SourceAdmissionError::Provider(_)));
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        retained.live_reservations
    );
    assert_eq!(pool.used(), control + quote);
    assert!(matches!(
        pool.borrow(u64::MAX),
        Err(SourceAdmissionError::SizeOverflow)
    ));
    assert_eq!(pool.used(), control + quote);
    assert_eq!(document.as_ref(), &source);
    drop(document);
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control
    );
    let successor = pool.clone_document(&source).unwrap();
    assert_eq!(successor.as_ref(), &source);
    drop(successor);
    drop(pool);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[test]
fn document_pool_unwind_retires_private_document_and_unpublished_credit() {
    let node = node(2 << 20);
    let pool = DocumentPool::new(&node).unwrap();
    let baseline = node.snapshot();
    let body = json!({"private": [1, 2, 3], "exact": 12345678901234567890u64});
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _document = pool.clone_parts("unpublished", 1, &body).unwrap();
            panic!("failure after private document preparation");
        }))
        .is_err()
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(pool.used(), DocumentPool::control_bytes().unwrap());
    // The same guard also owns a denied/interrupted construction before its
    // payload has been installed, without needing an Arc or another grant.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _credit = pool.borrow(4096).unwrap();
            panic!("failure before document construction");
        }))
        .is_err()
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    let output = pool.clone_parts("after", 2, &body).unwrap();
    assert_eq!(output.body, body);
}

#[test]
fn document_pool_concurrent_growth_and_retirement_leave_exact_control() {
    let node = node(8 << 20);
    let baseline = node.snapshot();
    let pool = DocumentPool::new(&node).unwrap();
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                let body = json!([worker, "value"]);
                for index in 0..256 {
                    let document = pool.clone_parts("same", index, &body).unwrap();
                    let alias = document.clone();
                    drop(document);
                    assert_eq!(alias.body, body);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(pool.used(), DocumentPool::control_bytes().unwrap());
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + pool.used()
    );
    drop(pool);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[test]
fn document_pool_creation_preserves_work_and_protected_byte_floors() {
    let control = DocumentPool::control_bytes().unwrap();
    let protected_bytes = 2048;
    // Without a protected floor, the mandatory cache-work floor alone blocks
    // the final byte. An ordinary operation may use that work headroom.
    let node = node_with_headroom(control + WORK_HEADROOM - 1, 8, WORK_HEADROOM);
    let baseline = node.snapshot();
    assert!(matches!(
        DocumentPool::new(&node),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    let work = node.reserve(control, None).unwrap();
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);

    // Each floor is additive: removing only the protection makes this exact
    // one-byte-short acquisition admissible with cache-work still reserved.
    let node = node_with_headroom(
        control + WORK_HEADROOM + protected_bytes - 1,
        8,
        WORK_HEADROOM,
    );
    let protection = node.memory().protect_ordinary(protected_bytes, 1).unwrap();
    let baseline = node.snapshot();
    assert!(matches!(
        DocumentPool::new(&node),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    drop(protection);
    let pool = DocumentPool::new(&node).unwrap();
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control
    );
    drop(pool);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[test]
fn document_pool_growth_preserves_exact_work_and_protected_byte_floors() {
    let control = DocumentPool::control_bytes().unwrap();
    let body = json!({"body": [1, 2, 3]});
    let quote = DocumentPool::document_bytes("row", &body).unwrap();
    let protected_bytes = 2048;
    let node = node_with_headroom(
        control + quote + WORK_HEADROOM + protected_bytes,
        8,
        WORK_HEADROOM,
    );
    let baseline = node.snapshot();
    let protection = node.memory().protect_ordinary(protected_bytes, 1).unwrap();
    let pool = DocumentPool::new(&node).unwrap();
    let document = pool.clone_parts("row", 1, &body).unwrap();
    assert_eq!(pool.used(), control + quote);
    let retained = node.snapshot();
    assert!(matches!(
        pool.borrow(1),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        retained.live_reservations
    );
    // Source growth has not consumed either floor. Ordinary work can use its
    // complete share while the separately protected maintenance share remains.
    let work = node.reserve(WORK_HEADROOM, None).unwrap();
    assert!(node.reserve(1, None).is_err());
    let maintenance = node.reserve_resident(protected_bytes).unwrap();
    assert_eq!(
        node.snapshot().reserved_bytes,
        retained.reserved_bytes + WORK_HEADROOM + protected_bytes
    );
    assert!(matches!(
        pool.borrow(1),
        Err(SourceAdmissionError::Provider(_))
    ));
    drop(maintenance);
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    // Retiring the document restores only its own credit; the same aggregate
    // slot can then admit a successor under the unchanged floor policy.
    drop(document);
    let successor = pool.clone_parts("row", 2, &body).unwrap();
    assert_eq!(pool.used(), control + quote);
    drop(successor);
    drop(pool);
    drop(protection);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn document_pool_creation_and_growth_preserve_both_slot_floors() {
    // Two bookkeeping slots + one pool + one cache-work + one protected slot.
    let node = node_with_headroom(8 << 20, 5, WORK_HEADROOM);
    let baseline = node.snapshot();
    assert_eq!(baseline.live_reservations, 2);
    let protection = node.memory().protect_ordinary(1024, 1).unwrap();
    let blocker = node.reserve_resident(1).unwrap();
    assert!(matches!(
        DocumentPool::new(&node),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    drop(blocker);
    let pool = DocumentPool::new(&node).unwrap();
    let document = pool.clone_parts("row", 1, &Value::Null).unwrap();
    let retained = node.snapshot();
    assert_eq!(retained.live_reservations, baseline.live_reservations + 1);
    // Positive growth needs no new slot but must still preserve both floors.
    let credit = pool.borrow(1).unwrap();
    drop(credit);
    let work = node.reserve(1, None).unwrap();
    assert!(matches!(
        pool.borrow(1),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes + 1);
    assert_eq!(
        node.snapshot().live_reservations,
        retained.live_reservations + 1
    );
    assert!(
        node.reserve(1, None).is_err(),
        "ordinary work must preserve the protected slot"
    );
    let maintenance = node.reserve_resident(1).unwrap();
    assert_eq!(node.snapshot().live_reservations, 5);
    drop(maintenance);
    drop(work);
    let credit = pool.borrow(1).unwrap();
    drop(credit);
    // Removing only protection allows one more pool; cache-work still retains
    // its slot, so the next acquisition is denied without consuming a slot.
    drop(protection);
    let second = DocumentPool::new(&node).unwrap();
    assert!(matches!(
        DocumentPool::new(&node),
        Err(SourceAdmissionError::Provider(_))
    ));
    assert_eq!(node.snapshot().live_reservations, 4);
    drop(second);
    drop(document);
    drop(pool);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}
