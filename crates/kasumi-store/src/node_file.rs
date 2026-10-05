//! Canonical installed multi-file backend and physical owner test fixtures.
#[cfg(test)]
use crate::node_disk::FailedFileWitness;
pub(crate) use crate::node_disk::{FailedCloseReport, FailedFileTransfer};
pub(crate) mod segment_group;

#[cfg(test)]
include!("node_file/file_owner_fixture.rs");
#[cfg(test)]
#[path = "node_file/tests.rs"]
mod tests;
