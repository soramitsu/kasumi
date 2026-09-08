use crate::ClientError;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::time::Instant;

/// Aggregate SDK-accounted capacity. This is not a process RSS or allocator limit.
#[derive(Debug)]
pub struct ClientResources {
    maximum: u64,
    maximum_owners: usize,
    used: Mutex<ClientResourceUsage>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientResourceUsage {
    pub accounted_bytes: u64,
    pub live_owners: usize,
}
impl ClientResources {
    pub fn new(maximum: u64, maximum_owners: usize) -> Result<Arc<Self>, ClientError> {
        if maximum == 0 || maximum_owners == 0 {
            return Err(invalid("empty client resource budget"));
        }
        Ok(Arc::new(Self {
            maximum,
            maximum_owners,
            used: Mutex::new(ClientResourceUsage::default()),
        }))
    }
    pub fn usage(&self) -> ClientResourceUsage {
        *self.used.lock().unwrap()
    }
    fn reserve(self: &Arc<Self>, bytes: u64) -> Result<Arc<Reservation>, ClientError> {
        let mut used = self.used.lock().unwrap();
        let next = used
            .accounted_bytes
            .checked_add(bytes)
            .ok_or_else(exhausted)?;
        if next > self.maximum || used.live_owners >= self.maximum_owners {
            return Err(exhausted());
        }
        used.accounted_bytes = next;
        used.live_owners += 1;
        Ok(Arc::new(Reservation {
            resources: self.clone(),
            bytes,
        }))
    }
}
#[derive(Debug)]
pub(super) struct Reservation {
    resources: Arc<ClientResources>,
    pub bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut used = self.resources.used.lock().unwrap();
        used.accounted_bytes -= self.bytes;
        used.live_owners -= 1;
    }
}

/// Bounds accepted tokens and a conservative SDK capacity charge, not hard RSS.
/// No value is silently substituted when a limit is too small.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotDecodeLimits {
    pub max_request_bytes: usize,
    /// Entire protobuf message; the five-byte gRPC prefix is accounted separately.
    pub max_wire_bytes: usize,
    pub max_json_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_string_bytes: usize,
    pub max_number_bytes: usize,
    pub max_rows: usize,
    pub max_decoded_bytes: u64,
}
impl Default for SnapshotDecodeLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 8 << 20,
            max_wire_bytes: 16 << 20,
            max_json_bytes: 16 << 20,
            max_depth: 64,
            max_nodes: 262_144,
            max_string_bytes: 1 << 20,
            max_number_bytes: 4096,
            max_rows: 1000,
            max_decoded_bytes: 256 << 20,
        }
    }
}
impl SnapshotDecodeLimits {
    pub fn accounted_bytes(&self) -> Result<u64, ClientError> {
        if self.max_request_bytes == 0
            || self.max_wire_bytes == 0
            || self.max_wire_bytes > u32::MAX as usize
            || self.max_json_bytes == 0
            || self.max_json_bytes > self.max_wire_bytes
            || self.max_depth == 0
            || self.max_depth > 120
            || self.max_nodes == 0
            || self.max_rows == 0
            || self.max_string_bytes == 0
            || self.max_number_bytes == 0
            || self.max_decoded_bytes == 0
        {
            return Err(invalid("invalid snapshot decode limits"));
        }
        // Retain overlap for framing, request/envelope copies, token preflight,
        // serde scratch, metadata inspection and the final immutable DTO.
        (self.max_wire_bytes as u64)
            .checked_mul(4)
            .and_then(|v| v.checked_add((self.max_request_bytes as u64).checked_mul(4)?))
            .and_then(|v| v.checked_add(self.max_decoded_bytes))
            .and_then(|v| v.checked_add(256 << 10))
            .ok_or_else(exhausted)
    }
}
#[derive(Clone, Debug)]
pub struct SnapshotReadOptions {
    pub resources: Arc<ClientResources>,
    pub limits: SnapshotDecodeLimits,
    /// One original finite deadline, including routing, decoding and release.
    pub deadline: Instant,
    /// Caller-installed database identity; never inferred from unverified JWT text.
    pub expected_incarnation: uuid::Uuid,
}
impl SnapshotReadOptions {
    pub(crate) fn admit(&self) -> Result<Call, ClientError> {
        if self.expected_incarnation.is_nil() {
            return Err(invalid("nil expected snapshot incarnation"));
        }
        if Instant::now() >= self.deadline {
            return Err(deadline());
        }
        let reservation = self.resources.reserve(self.limits.accounted_bytes()?)?;
        Ok(Call {
            reservation,
            limits: self.limits,
            deadline: self.deadline,
            expected_incarnation: self.expected_incarnation,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }
}
#[derive(Clone)]
pub(crate) struct Call {
    pub(super) reservation: Arc<Reservation>,
    pub(super) limits: SnapshotDecodeLimits,
    pub(super) deadline: Instant,
    pub(super) expected_incarnation: uuid::Uuid,
    cancelled: Arc<AtomicBool>,
}
impl Call {
    pub(super) fn check(&self) -> Result<(), ClientError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(deadline())
        } else {
            Ok(())
        }
    }
    pub(super) fn waiter(&self) -> Waiter {
        Waiter {
            cancelled: self.cancelled.clone(),
            finished: false,
        }
    }
}
pub(super) struct Waiter {
    cancelled: Arc<AtomicBool>,
    pub finished: bool,
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.finished {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

/// Immutable response sharing one retained admission reservation. Borrowed data
/// can be copied by application code; those application allocations are outside
/// the SDK resource contract. There is deliberately no uncharged `into_inner`.
#[derive(Debug)]
pub struct AdmittedSnapshot<T>(Arc<Owned<T>>);
#[derive(Debug)]
struct Owned<T> {
    value: T,
    reservation: Arc<Reservation>,
}
impl<T> Clone for AdmittedSnapshot<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> std::ops::Deref for AdmittedSnapshot<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0.value
    }
}
impl<T> AdmittedSnapshot<T> {
    pub fn accounted_bytes(&self) -> u64 {
        self.0.reservation.bytes
    }
    pub(super) fn new(value: T, call: &Call) -> Self {
        Self(Arc::new(Owned {
            value,
            reservation: call.reservation.clone(),
        }))
    }
}
pub(super) fn invalid(message: &'static str) -> ClientError {
    ClientError::InvalidResponse(message)
}
pub(super) fn exhausted() -> ClientError {
    tonic::Status::resource_exhausted("snapshot client resource budget exceeded").into()
}
pub(super) fn deadline() -> ClientError {
    tonic::Status::deadline_exceeded("snapshot operation deadline elapsed").into()
}
