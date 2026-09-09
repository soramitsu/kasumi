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
        write_candidate(self, None, None, None, writer)
    }
}
impl SnapshotFixtureState for crate::Generation {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        crate::snapshot_codec::write(
            &self.state,
            &self.receipts,
            &self.terminals,
            &self.target_resolutions,
            writer,
        )
    }
}
#[derive(Clone)]
pub struct SnapshotCandidate(crate::snapshot_codec::Decoded);
impl std::ops::Deref for SnapshotCandidate {
    type Target = TenantState;
    fn deref(&self) -> &TenantState {
        &self.0.state
    }
}
impl std::ops::DerefMut for SnapshotCandidate {
    fn deref_mut(&mut self) -> &mut TenantState {
        &mut self.0.state
    }
}
impl SnapshotFixtureState for SnapshotCandidate {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        write_candidate(
            &self.0.state,
            Some(&self.0.receipts),
            Some(&self.0.terminals),
            Some(&self.0.target_resolutions),
            writer,
        )
    }
}
pub fn encode_snapshot_candidate(
    state: &impl SnapshotFixtureState,
    max_bytes: u64,
) -> Result<SnapshotImage> {
    SnapshotImage::capture(&kasumi_store::ScratchDisk::fixture(), max_bytes, |writer| {
        state.write_fixture(writer)
    })
    .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
pub fn decode_snapshot_candidate(candidate: &SnapshotImage) -> Result<SnapshotCandidate> {
    crate::snapshot_codec::read(candidate.disk(), &mut candidate.reader())
        .map(SnapshotCandidate)
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}

// Corruption fixtures must be able to encode intentionally inconsistent heads.
// This path is feature gated and never grants publication or a storage capability.
fn write_candidate(
    state: &TenantState,
    receipts: Option<&crate::mutation_receipt::View>,
    terminals: Option<&crate::staged_terminal::View>,
    target_resolutions: Option<&crate::target_resolution::View>,
    writer: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
    for kind in 0..21 {
        if kind == 5 {
            if let Some(receipts) = receipts {
                for row in receipts.records() {
                    encoder.record(crate::snapshot_codec::Record::Receipt(Box::new(row?)))?;
                }
            }
        }
        for record in crate::snapshot_codec::records(state, kind, None)? {
            encoder.record(record?)?;
        }
    }
    if let Some(terminals) = terminals {
        for row in terminals.records() {
            encoder.record(crate::snapshot_codec::Record::Terminal(Box::new(row?)))?;
        }
    }
    if let Some(target_resolutions) = target_resolutions {
        for row in target_resolutions.records() {
            encoder.record(crate::snapshot_codec::Record::TargetResolution(Box::new(
                row?,
            )))?;
        }
    }
    encoder.finish()
}
