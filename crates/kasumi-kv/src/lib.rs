//! Kasumi's native append-only transactional key/value storage.
//!
//! The core owns the on-disk format and keeps values on the backend. The table
//! facade supplies typed handles; the retained facade supplies lifecycle reports.

/// A single-writer ordered byte database using compressed checkpoints and a durable log.
/// Enable the `compact` feature for the filesystem-backed indexing API.
#[cfg(all(unix, feature = "compact"))]
pub mod compact {
    pub use kasumi_frozen_run::{LIVE_CHECKPOINT_BYTES, LiveDb, LiveStats, WalOp};
}

pub mod cache;
pub mod core;
pub mod retained;
pub mod tables;

#[cfg(test)]
use crate as cache_types;
#[cfg(test)]
mod cache_test;

// Canonical segmented storage, immutable directories and bounded caches.
pub(crate) mod arena;
pub(crate) mod checked_group;
pub(crate) mod directory;
pub(crate) mod disk_state;
pub mod group;
pub(crate) mod page_cache;
pub(crate) mod reclaim;
pub(crate) mod root;
pub(crate) mod segment;
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
    CorePanic, DescendingCursor, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_TABLE_BYTES, MAX_VALUE_BYTES,
    NativeDisposalReport, NativeOpenFailure, NativeOwnedDisposal, Operation, OwnerFailed,
    PreparedPointRead, ReadSnapshot, ResidentLease, ScanDirection, StorageAdmission,
};
pub use disk_state::{
    MaintenanceBudget, MaintenanceDeferral, MaintenancePolicy, MaintenanceProgress,
    MaintenanceStep, StorageCompactionPhase, StorageMaintenanceStatus,
};
pub use group::{
    ExistingFileSpace, FileKind, FileSpaceRange, GroupFile, ROOT_FILE_NAME, SegmentGroupBackend,
    TransactionReserveError, TransactionSpacePlan,
};
pub use retained::*;
pub use root::{
    DirectoryPageFormat, ROOT_SLOT_BYTES, RootSlot, TRANSACTION_SPACE_ROOTS_HEAP_BYTES,
    validate_transaction_space_roots,
};
pub use segment::MAX_BATCH_OPERATIONS;
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
