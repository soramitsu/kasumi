//! Constructor-owned requests only: no capacity, capture or provider authority.
use crate::{CoreError, core::AdmittedValue, snapshot_pins::SnapshotPins};

/// Native requests before the installed backend/provider adds its actual leases.
/// Backing and pin are per snapshot.
/// This value neither selects a root nor reserves any byte or snapshot slot.
pub struct ProtectedReadRequests;
impl ProtectedReadRequests {
    pub const fn snapshot_backing_request_bytes() -> u64 {
        crate::tables::snapshot_backing_request_bytes()
    }
    pub const fn pin_backing_request_bytes() -> u64 {
        SnapshotPins::pin_backing_request_bytes()
    }
    /// Native admission for both temporary table name allocations and its grant.
    /// The two type probes are sequential and their native output drops first.
    pub fn table_name_backing_bytes(name_bytes: usize) -> Result<u64, CoreError> {
        crate::tables::table_name_backing_bytes(name_bytes)
    }
}

/// Conservative native point-read requests. Each directory lookup retains
/// Bounds and PageBuffer together. Table and row lookups are sequential and
/// retire before AdmittedValue allocation. Directory and admitted value reads
/// fill their own output on optional retention refusal. Retained optional
/// caches are separate.
#[derive(Clone, Copy, Debug)]
pub struct PointReadRequests {
    output: u64,
}
impl PointReadRequests {
    pub fn new(max_value_bytes: usize) -> Result<Self, CoreError> {
        if max_value_bytes > crate::MAX_VALUE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "point quote exceeds native value limit",
            )));
        }
        Ok(Self {
            output: AdmittedValue::request_bytes(max_value_bytes)?,
        })
    }
    pub const fn bounds_request_bytes(&self) -> u64 {
        crate::directory::point_bounds_request_bytes()
    }
    pub const fn page_request_bytes(&self) -> u64 {
        crate::directory::point_page_request_bytes()
    }
    pub const fn output_request_bytes(&self) -> u64 {
        self.output
    }
}
