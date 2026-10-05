//! Kasumi's native append-only transactional key/value storage.
//!
//! The core owns the on-disk format and keeps values on the backend. The table
//! facade supplies typed handles; the retained facade supplies lifecycle reports.

pub mod cache;
pub mod core;
pub mod retained;
pub mod tables;

#[cfg(test)]
use crate as cache_types;
#[cfg(test)]
mod cache_test;

// Canonical segmented storage, immutable directories and bounded caches.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod arena;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod checked_group;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod checkpoint;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod directory;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod disk_state;
#[cfg_attr(not(test), allow(dead_code))]
pub mod group;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod page_cache;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod reclaim;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod root;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod segment;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod snapshot_pins;

mod source_read_requests;
pub use source_read_requests::{PointReadRequests, ProtectedReadRequests};

mod cache_admission;
pub use cache::{CacheConfig, CacheLoadError, CacheStats, CachedBytes, NativeCache};
pub use cache_admission::{CacheMemoryLease, CacheMemoryQuote, CacheMemoryReservation};
pub use core::{
    AdmissionError, AdmittedValue, BackendCloseEntry, BackendCloseOutcome,
    BackendNativeDisposition, CacheWarmup, CacheWarmupState, CacheWarmupStatus, CommittedPosition,
    Core, CoreError, CoreErrorCause, CoreErrorDisposition, CoreOpenCleanup, CoreOpenFailure,
    CorePanic, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_TABLE_BYTES, MAX_VALUE_BYTES,
    NativeDisposalReport, NativeOpenFailure, NativeOwnedDisposal, Operation, OwnerFailed,
    PreparedPointRead, ReadSnapshot, ResidentLease, StorageAdmission,
};
pub use group::{
    ExistingFileSpace, FileKind, FileSpaceRange, GroupFile, ROOT_FILE_NAME, SegmentGroupBackend,
    TransactionReserveError, TransactionSpacePlan,
};
pub use retained::*;
pub use root::{
    ROOT_SLOT_BYTES, RootSlot, TRANSACTION_SPACE_ROOTS_HEAP_BYTES, validate_transaction_space_roots,
};
pub use tables::*;

pub mod backends {
    pub use crate::group::InMemoryGroup;
}

mod native_backend;
mod native_owned_arc;
mod native_resident_lease;
mod native_sync;
mod resident_allocation;
pub use resident_allocation::ResidentAllocation;
