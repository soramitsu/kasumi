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
pub trait SnapshotFixtureState {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()>;
}
impl SnapshotFixtureState for TenantState {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        let empty = crate::staged_terminal::View::empty(&self.tenant, &self.staged_terminal_head.origin_incarnation)?;
        crate::snapshot_codec::write(self, &empty, writer)
    }
}
impl SnapshotFixtureState for crate::Generation {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        crate::snapshot_codec::write(&self.state, &self.terminals, writer)
    }
}
#[derive(Clone)]
pub struct SnapshotCandidate(crate::snapshot_codec::Decoded);
impl std::ops::Deref for SnapshotCandidate {
    type Target = TenantState;
    fn deref(&self) -> &TenantState { &self.0.state }
}
impl std::ops::DerefMut for SnapshotCandidate {
    fn deref_mut(&mut self) -> &mut TenantState { &mut self.0.state }
}
impl SnapshotFixtureState for SnapshotCandidate {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        crate::snapshot_codec::write(&self.0.state, &self.0.terminals, writer)
    }
}
pub fn encode_snapshot_candidate(state: &impl SnapshotFixtureState, max_bytes: u64) -> Result<SnapshotImage> {
    SnapshotImage::capture(&kasumi_store::ScratchDisk::fixture(), max_bytes, |writer| state.write_fixture(writer))
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
pub fn decode_snapshot_candidate(candidate: &SnapshotImage) -> Result<SnapshotCandidate> {
    crate::snapshot_codec::read(candidate.disk(), &mut candidate.reader()).map(SnapshotCandidate)
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
