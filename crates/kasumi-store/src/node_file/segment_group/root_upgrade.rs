//! One-time, offline, first-release upgrade of an installed group root file
//! from `KASUMI-KVROOT003` to `KASUMI-KVROOT005` in place, for
//! `kasumid maintenance upgrade-storage-root`. Delete it with that command once
//! the BPNG installation is upgraded.
//!
//! The file must be the exact installed root: the 4 KiB `KASUMI-NODE-SEG1`
//! envelope of this node identity, Prepared or Ready, followed by the two kv
//! slots, whose selected root must name the same group. Only kv slot bytes are
//! written, through the verified descriptor and on the same inode; the
//! envelope, the length and every data file stay as they are.
use super::{HEADER_BYTES, PREPARED, READY, ROOT_KIND, root_offset, validate_envelope};
use crate::NodeDiskFile;
use anyhow::{Context, Result, bail, ensure};
use kasumi_kv::ROOT_SLOT_BYTES;
pub use kasumi_kv::{ROOT_FILE_NAME, RootSlot, RootSlotUpgrade, RootUpgradePlan};
use uuid::Uuid;

/// Bytes of an installed group root file: the envelope and both kv slots.
pub const STORAGE_ROOT_FILE_BYTES: usize = HEADER_BYTES + 2 * ROOT_SLOT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootEnvelopeState {
    Prepared,
    Ready,
}

impl RootEnvelopeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Ready => "ready",
        }
    }
}

fn slot_range(slot: RootSlot) -> std::ops::Range<usize> {
    let start = root_offset(slot) as usize;
    start..start + ROOT_SLOT_BYTES
}

fn slot(image: &[u8; STORAGE_ROOT_FILE_BYTES], slot: RootSlot) -> &[u8; ROOT_SLOT_BYTES] {
    image[slot_range(slot)].try_into().expect("root slot range")
}

/// A validated root file image and its planned upgrade. Planning writes
/// nothing; `apply` performs the only writes.
pub struct StorageRootUpgrade {
    before: Box<[u8; STORAGE_ROOT_FILE_BYTES]>,
    after: Box<[u8; STORAGE_ROOT_FILE_BYTES]>,
    envelope: RootEnvelopeState,
    plan: RootUpgradePlan,
}

impl StorageRootUpgrade {
    /// Read and plan one installed root file of the node store `identity`.
    pub fn inspect(file: &NodeDiskFile, identity: Uuid) -> Result<Self> {
        Self::from_image(&read(file)?[..], identity)
    }

    /// Plan from a complete root file image, such as a saved copy.
    pub fn from_image(image: &[u8], identity: Uuid) -> Result<Self> {
        let before: Box<[u8; STORAGE_ROOT_FILE_BYTES]> = Box::new(
            image
                .try_into()
                .ok()
                .context("segment group root length is invalid")?,
        );
        let header: &[u8; HEADER_BYTES] = before[..HEADER_BYTES]
            .try_into()
            .expect("root envelope range");
        let envelope = match validate_envelope(header, identity, ROOT_KIND, 0)
            .context("segment group root envelope is invalid")?
        {
            PREPARED => RootEnvelopeState::Prepared,
            READY => RootEnvelopeState::Ready,
            _ => bail!("segment group root state is unsupported"),
        };
        let plan = RootUpgradePlan::new(slot(&before, RootSlot::A), slot(&before, RootSlot::B))?;
        if let Some(group) = plan.group_id() {
            ensure!(
                group == *identity.as_bytes(),
                "root slots name another group than the installed node identity"
            );
        }
        let mut after = before.clone();
        for root in [RootSlot::A, RootSlot::B] {
            after[slot_range(root)].copy_from_slice(plan.target(root));
        }
        Ok(Self {
            before,
            after,
            envelope,
            plan,
        })
    }

    pub fn plan(&self) -> &RootUpgradePlan {
        &self.plan
    }

    pub fn envelope(&self) -> RootEnvelopeState {
        self.envelope
    }

    pub fn before(&self) -> &[u8; STORAGE_ROOT_FILE_BYTES] {
        &self.before
    }

    pub fn after(&self) -> &[u8; STORAGE_ROOT_FILE_BYTES] {
        &self.after
    }

    /// `other` is this file at another point of the same upgrade: the same
    /// envelope, completing to the same slots and selection.
    pub fn same_upgrade(&self, other: &Self) -> bool {
        self.before[..HEADER_BYTES] == other.before[..HEADER_BYTES]
            && self.plan.same_upgrade(&other.plan)
    }

    /// Write every slot that differs from its target, the slot the selection
    /// does not read first, synchronizing the root after each write; then read
    /// the file back and verify it. Returns the slots written, in order. The
    /// file must still hold the inspected image.
    pub fn apply(&self, file: &NodeDiskFile) -> Result<Vec<RootSlot>> {
        ensure!(
            *read(file)? == *self.before,
            "segment group root changed after inspection"
        );
        let mut written = Vec::with_capacity(2);
        for root in self.plan.write_order() {
            if self.plan.needs_write(root) {
                file.write_all_at(self.plan.target(root), root_offset(root))?;
                file.sync_all()?;
                written.push(root);
            }
        }
        let image = read(file)?;
        ensure!(
            *image == *self.after,
            "segment group root differs from the upgrade after writing"
        );
        self.plan
            .verify(slot(&image, RootSlot::A), slot(&image, RootSlot::B))?;
        Ok(written)
    }
}

fn read(file: &NodeDiskFile) -> Result<Box<[u8; STORAGE_ROOT_FILE_BYTES]>> {
    ensure!(
        file.observed_len()? == STORAGE_ROOT_FILE_BYTES as u64,
        "segment group root length is invalid"
    );
    let mut image = Box::new([0; STORAGE_ROOT_FILE_BYTES]);
    file.read_exact_at(&mut image[..], 0)?;
    Ok(image)
}
