//! Explicit fixture-only codecs for arithmetic and corruption tests. These are
//! not portable snapshots, storage capabilities, or production restore APIs.
use crate::TenantEngine;
pub use crate::bootstrap::fixtures::{
    open_fixture, open_fixture_replicated, open_fixture_with_incarnation,
};
use kasumi_store::SnapshotImage;
use kasumi_types::{Error, ErrorCode, Result, TenantState};

pub trait SnapshotFixture {
    fn fixture_snapshot(&self) -> Result<SnapshotImage>;
    fn fixture_restore(&self, candidate: &SnapshotImage) -> Result<()>;
}
impl SnapshotFixture for TenantEngine {
    fn fixture_snapshot(&self) -> Result<SnapshotImage> {
        self.logical_snapshot(&kasumi_store::ScratchDisk::fixture())
    }
    fn fixture_restore(&self, candidate: &SnapshotImage) -> Result<()> {
        self.restore_candidate(candidate)
    }
}
pub fn encode_snapshot_candidate(state: &TenantState, max_bytes: u64) -> Result<SnapshotImage> {
    SnapshotImage::capture(&kasumi_store::ScratchDisk::fixture(), max_bytes, |writer| {
        crate::snapshot_codec::write(state, writer)
    })
    .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
pub fn decode_snapshot_candidate(candidate: &SnapshotImage) -> Result<TenantState> {
    crate::snapshot_codec::read(&mut candidate.reader())
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
