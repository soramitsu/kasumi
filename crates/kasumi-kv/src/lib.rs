//! Kasumi's native append-only transactional key/value storage.
//!
//! The core owns the on-disk format and keeps values on the backend. The table
//! facade supplies typed handles; the retained facade supplies lifecycle reports.

pub mod core;
pub mod retained;
pub mod tables;

// Segmented-log format components. `Core` still owns the contiguous format
// until the segmented core replaces it, so only tests exercise them for now.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod checkpoint;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod group;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod root;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod segment;

pub use core::{
    AdmissionError, AdmittedValue, BackendCloseEntry, BackendCloseOutcome,
    BackendNativeDisposition, Core, CoreError, CoreOpenFailure, CorePanic, MAX_BATCH_BYTES,
    MAX_KEY_BYTES, MAX_TABLE_BYTES, MAX_VALUE_BYTES, Operation, OwnerFailed, ReadSnapshot,
    ResidentLease, StorageAdmission, StorageBackend,
};
pub use retained::*;
pub use tables::*;

pub mod backends {
    pub use crate::core::InMemoryBackend;
}
