//! Output custody beyond a completed database operation. The retained provider
//! is immutable: the operation's cancellation token may already be cancelled.
use crate::admission::Reservation;
use serde::{Serialize, Serializer};
use std::{fmt, mem::size_of, ops::Deref, sync::Arc};

/// The shared charge's Arc backing, admitted before allocation. Payload and
/// inline owner storage have separate accounting. Match the query allocation
/// policy's power-of-two rounding plus 64 bytes of allocation metadata slack.
pub(crate) const OUTPUT_CHARGE_BYTES: u64 =
    ((size_of::<Reservation>() + 2 * size_of::<usize>()).next_power_of_two() + 64) as u64;

/// A database result together with the memory admission that keeps it alive.
/// Borrow it to inspect or serialize its payload. There is no uncharged owned
/// extraction or implicit owner clone; retaining the result retains its charge.
///
/// Serialization and protocol conversion may allocate another representation.
/// Adapters must separately admit those allocations before constructing them,
/// and keep this owner through the overlap and final transport handoff. This
/// owner preserves memory custody; it does not renew authorization or expiry.
pub struct AdmittedOutput<T> {
    // Declaration order is intentional, including during unwinding.
    payload: T,
    _charge: Arc<Reservation>,
}

impl<T> AdmittedOutput<T> {
    /// The shared charge must already include its Arc backing and the payload,
    /// and must have released the completed operation count. Construction is
    /// infallible so callers can transfer an already-admitted payload atomically.
    pub(crate) fn new(payload: T, charge: Arc<Reservation>) -> Self {
        Self {
            payload,
            _charge: charge,
        }
    }
}

impl<T> Deref for AdmittedOutput<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> AsRef<T> for AdmittedOutput<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

impl<T: fmt::Debug> fmt::Debug for AdmittedOutput<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AdmittedOutput")
            .field(&self.payload)
            .finish()
    }
}

impl<T: Serialize> Serialize for AdmittedOutput<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.payload.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionConfig, NodeAdmission};
    use kasumi_query::QueryCancellation;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn node() -> Arc<NodeAdmission> {
        NodeAdmission::with_fixed_memory(
            crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
                high_water_bytes: Some(64 << 20),
                low_water_bytes: Some(48 << 20),
                max_inflight_bytes: Some(4 << 20),
                max_inflight_operations: 4,
                max_reservations: 16,
                max_snapshot_startups: 2,
                max_startup_scopes: 2,
                ..Default::default()
            })
            .unwrap(),
            64 << 20,
            0,
        )
        .unwrap()
    }

    struct Payload {
        bytes: Vec<u8>,
        node: Arc<NodeAdmission>,
        baseline: u64,
        destroyed: Arc<AtomicBool>,
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            assert!(
                self.node.snapshot().reserved_bytes >= self.baseline + self.bytes.capacity() as u64
            );
            assert_eq!(self.node.snapshot().inflight_operations, 0);
            self.destroyed.store(true, Ordering::Release);
        }
    }

    fn output(node: &Arc<NodeAdmission>, destroyed: Arc<AtomicBool>) -> AdmittedOutput<Payload> {
        let baseline = node.snapshot().reserved_bytes;
        let cancellation = QueryCancellation::default();
        let mut reservation = node
            .reserve(4096 + OUTPUT_CHARGE_BYTES, Some(cancellation.clone()))
            .unwrap();
        let payload = Payload {
            bytes: vec![7; 4096],
            node: node.clone(),
            baseline,
            destroyed,
        };
        reservation.retain_workspace();
        // The immutable retained provider is still valid after worker completion.
        cancellation.cancel();
        AdmittedOutput::new(payload, Arc::new(reservation))
    }

    #[test]
    fn admitted_output_survives_completed_worker_and_cross_thread_handoff() {
        let node = node();
        let before = node.snapshot();
        let destroyed = Arc::new(AtomicBool::new(false));
        let output = output(&node, destroyed.clone());
        assert_eq!(node.snapshot().inflight_operations, 0);
        assert_eq!(
            node.snapshot().live_reservations,
            before.live_reservations + 1
        );
        assert!(!destroyed.load(Ordering::Acquire));
        // An embedded caller can hold the returned owner after all work permits
        // and the worker token have finished, then move it to another thread.
        std::thread::spawn(move || {
            assert_eq!(output.bytes.as_slice(), &[7; 4096]);
            drop(output);
        })
        .join()
        .unwrap();
        assert!(destroyed.load(Ordering::Acquire));
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    }

    #[test]
    fn admitted_output_unwind_destroys_payload_before_releasing_its_charge() {
        let node = node();
        let before = node.snapshot();
        let destroyed = Arc::new(AtomicBool::new(false));
        let output = output(&node, destroyed.clone());
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = output;
            panic!("injected embedded caller unwind");
        }));
        assert!(unwind.is_err());
        assert!(destroyed.load(Ordering::Acquire));
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    }
}
