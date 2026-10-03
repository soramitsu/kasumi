//! Constructor-owned requests only: no capacity, capture or provider authority.
use crate::{CoreError, core::AdmittedValue, snapshot_pins::SnapshotPins};

/// Native requests before the installed backend/provider adds its actual leases.
/// Rights are installed once per source pool; backing and pin are per capture.
/// This value neither selects a root nor reserves any byte or snapshot slot.
pub struct ProtectedReadRequests;
impl ProtectedReadRequests {
    pub const fn snapshot_backing_request_bytes() -> u64 {
        crate::tables::snapshot_backing_request_bytes()
    }
    pub const fn pin_backing_request_bytes() -> u64 {
        SnapshotPins::pin_backing_request_bytes()
    }
    pub const fn rights_request_bytes() -> u64 {
        SnapshotPins::rights_request_bytes()
    }
    /// Plain heap envelope for the temporary table name, not an admission request.
    /// The two type probes are sequential and their native output drops first.
    pub fn table_name_backing_bytes(name_bytes: usize) -> Result<u64, CoreError> {
        crate::tables::table_name_backing_bytes(name_bytes)
    }
}

/// Conservative native point-read requests. Each directory lookup retains
/// Bounds and PageBuffer together. Table and row lookups are sequential and
/// retire before AdmittedValue allocation. Former temporary page/value
/// CachedBytes allowances remain in existing aggregate quotes; directory and
/// admitted value reads now fill their own output on optional retention refusal.
/// Retained optional caches are separate.
#[derive(Clone, Copy, Debug)]
pub struct PointReadRequests {
    output: u64,
    page_fallback: u64,
    value_fallback: u64,
}
impl PointReadRequests {
    pub fn new(max_value_bytes: usize) -> Result<Self, CoreError> {
        if max_value_bytes > crate::MAX_VALUE_BYTES {
            return Err(CoreError::InvalidInput(
                "point quote exceeds native value limit",
            ));
        }
        Ok(Self {
            output: AdmittedValue::request_bytes(max_value_bytes)?,
            page_fallback: crate::CachedBytes::charge_for_len(
                crate::directory::DIRECTORY_PAGE_BYTES,
            )
            .ok_or(CoreError::CapacityDenied)?,
            value_fallback: crate::CachedBytes::charge_for_len(max_value_bytes)
                .ok_or(CoreError::CapacityDenied)?,
        })
    }
    pub const fn bounds_request_bytes(&self) -> u64 {
        crate::directory::point_bounds_request_bytes()
    }
    pub const fn page_request_bytes(&self) -> u64 {
        crate::directory::point_page_request_bytes()
    }
    /// Conservative former page-workspace allowance. Production directory reads
    /// fill their admitted PageBuffer directly when optional retention refuses.
    /// Existing aggregate quotations retain this safe overestimate.
    pub const fn page_fallback_request_bytes(&self) -> u64 {
        self.page_fallback
    }
    /// Conservative former value-workspace allowance. The zero-copy cache.load
    /// path still needs this request; value_admitted no longer allocates it.
    /// Existing aggregate quotations may safely retain the overestimate.
    pub const fn value_fallback_request_bytes(&self) -> u64 {
        self.value_fallback
    }
    pub const fn output_request_bytes(&self) -> u64 {
        self.output
    }
}
