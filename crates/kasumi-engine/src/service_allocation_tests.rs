//! Release future heap storage must be charged before constructing the future.
use super::{RELEASE_FUTURE_ALLOCATION_ALLOWANCE, admitted_release_future};
use crate::admission::{AdmissionConfig, AdmissionSnapshot, NodeAdmission};
use kasumi_types::{Error, ErrorCode, Result};
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

fn admission() -> Arc<NodeAdmission> {
    let config = AdmissionConfig {
        high_water_bytes: Some(16 << 20),
        low_water_bytes: Some(14 << 20),
        max_inflight_bytes: Some(8 << 20),
        ..AdmissionConfig::default()
    };
    NodeAdmission::with_fixed_memory(config, 32 << 20, 0).unwrap()
}

#[tokio::test]
async fn denied_release_future_never_constructs_boxed_work() {
    let node = admission();
    let baseline = node.snapshot();
    let cap = 8 << 20;
    let held = node
        .reserve_resident(cap - baseline.reserved_bytes)
        .unwrap();
    let invoked = Cell::new(false);
    let error = admitted_release_future(&node, || {
        invoked.set(true);
        std::future::ready(Ok::<(), Error>(()))
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(!invoked.get(), "denial must precede future construction");
    assert_eq!(node.snapshot().reserved_bytes, cap);
    drop(held);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

struct ChargeVisibleOnDrop {
    node: Arc<NodeAdmission>,
    before: AdmissionSnapshot,
    expected_charge: u64,
    dropped: Arc<AtomicBool>,
}

impl Future for ChargeVisibleOnDrop {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for ChargeVisibleOnDrop {
    fn drop(&mut self) {
        let active = self.node.snapshot();
        assert_eq!(
            active.resident_reserved_bytes,
            self.before.resident_reserved_bytes + self.expected_charge,
            "resident charge must remain held while the inner future is dropped"
        );
        assert_eq!(
            active.reserved_bytes,
            self.before.reserved_bytes + self.expected_charge
        );
        assert_eq!(active.live_reservations, self.before.live_reservations + 1);
        assert_eq!(active.inflight_operations, self.before.inflight_operations);
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn cancelled_release_retires_its_future_charge_after_inner_drop() {
    let node = admission();
    let before = node.snapshot();
    let dropped = Arc::new(AtomicBool::new(false));
    let expected = u64::try_from(std::mem::size_of::<ChargeVisibleOnDrop>()).unwrap()
        + RELEASE_FUTURE_ALLOCATION_ALLOWANCE;
    let mut operation = Box::pin(admitted_release_future(&node, || ChargeVisibleOnDrop {
        node: Arc::clone(&node),
        before: before.clone(),
        expected_charge: expected,
        dropped: Arc::clone(&dropped),
    }));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        operation.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert!(!dropped.load(Ordering::SeqCst));
    let active = node.snapshot();
    assert_eq!(active.reserved_bytes, before.reserved_bytes + expected);
    assert_eq!(
        active.resident_reserved_bytes,
        before.resident_reserved_bytes + expected
    );
    assert_eq!(active.live_reservations, before.live_reservations + 1);
    assert_eq!(active.inflight_operations, before.inflight_operations);
    drop(operation);
    assert!(
        dropped.load(Ordering::SeqCst),
        "inner future Drop must run on cancellation"
    );
    let after = node.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(
        after.resident_reserved_bytes,
        before.resident_reserved_bytes
    );
    assert_eq!(after.live_reservations, before.live_reservations);
}
