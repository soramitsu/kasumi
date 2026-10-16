//! One-time, offline, first-release upgrade of `KASUMI-KVROOT003` group root
//! slots to `KASUMI-KVROOT005`, in place.
//!
//! It exists only so the BPNG installation created before ROOT005 can run the
//! reclamation fix on its existing storage. Delete this module together with
//! `kasumid maintenance upgrade-storage-root` once that installation is
//! upgraded. Reopen never calls it: the runtime decoder still refuses ROOT003.
//!
//! ROOT005 is ROOT003 plus the compaction record at bytes 2384..4080, a region
//! a ROOT003 slot must hold as zero, and an all-zero record decodes as
//! `CompactionRecord::GENESIS`. A valid ROOT003 slot therefore becomes the same
//! superblock with the genesis record by rewriting its magic and its CRC-32C;
//! planning proves that the result is exactly what the current encoder writes
//! for the decoded superblock. A torn or damaged ROOT003 slot gets the new
//! magic and keeps its checksum, so it stays invalid. Unwritten slots and every
//! other image are left unchanged.
//!
//! The two magics differ only in byte 15, so an interrupted slot write leaves
//! byte 15 and the checksum each either old or new. Planning recognizes those
//! states and completes them, so a rerun resumes an interrupted upgrade from
//! the slots alone. Before any write, a plan requires the strict runtime
//! selection over the upgraded images to equal what a ROOT003 reader selects
//! from the original images, with the genesis compaction record; `verify`
//! repeats that check on the images read back.

use super::compaction::{COMPACTION_AT, CompactionRecord};
use super::{
    CHECKSUM_AT, ROOT_MAGIC, ROOT_SLOT_BYTES, RootSelection, RootSlot, SlotImage, Superblock,
    decode_slot, is_successor, select_root_images,
};
use crate::core::CoreError;
use crate::segment::{FORMAT_VERSION, crc32c, le_u32};

const ROOT003_MAGIC: [u8; 16] = *b"KASUMI-KVROOT003";
/// The only byte in which the ROOT003 and ROOT005 magics differ.
const MAGIC_VERSION_AT: usize = 15;
const _: () = {
    let mut at = 0;
    while at < 16 {
        assert!((at == MAGIC_VERSION_AT) == (ROOT003_MAGIC[at] != ROOT_MAGIC[at]));
        at += 1;
    }
};

fn corrupt(reason: &'static str) -> CoreError {
    CoreError::new(crate::CoreErrorCause::Corrupt(reason))
}

/// How the upgrade treats one root slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSlotUpgrade {
    /// All zero; left unchanged.
    Unwritten,
    /// A valid ROOT003 superblock, possibly behind an interrupted earlier
    /// write of this upgrade: rewritten as its ROOT005 encoding with the
    /// genesis compaction record.
    Upgraded,
    /// A torn or damaged ROOT003 image: only the magic changes, and the image
    /// stays invalid.
    InvalidRewritten,
    /// A ROOT005 image or an invalid image under another magic; unchanged.
    Unchanged,
}

impl RootSlotUpgrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unwritten => "unwritten",
            Self::Upgraded => "upgraded",
            Self::InvalidRewritten => "invalid_rewritten",
            Self::Unchanged => "unchanged",
        }
    }
}

struct SlotPlan {
    upgrade: RootSlotUpgrade,
    target: [u8; ROOT_SLOT_BYTES],
    /// The slot as a ROOT003 reader decodes the image the upgrade started from.
    original: SlotImage,
    /// The image is an earlier upgrade write of this slot, complete or not.
    interrupted: bool,
}

fn with_magic(bytes: &[u8; ROOT_SLOT_BYTES], magic: &[u8; 16]) -> [u8; ROOT_SLOT_BYTES] {
    let mut image = *bytes;
    image[..16].copy_from_slice(magic);
    image
}

fn seal(image: &mut [u8; ROOT_SLOT_BYTES]) {
    let checksum = crc32c(&image[..CHECKSUM_AT]);
    image[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
}

fn plan_slot(bytes: &[u8; ROOT_SLOT_BYTES]) -> Result<SlotPlan, CoreError> {
    let unchanged = |original, interrupted| SlotPlan {
        upgrade: RootSlotUpgrade::Unchanged,
        target: *bytes,
        original,
        interrupted,
    };
    if bytes.iter().all(|&byte| byte == 0) {
        return Ok(SlotPlan {
            upgrade: RootSlotUpgrade::Unwritten,
            ..unchanged(SlotImage::Unwritten, false)
        });
    }
    let root003 = bytes[..16] == ROOT003_MAGIC;
    if !root003 && bytes[..16] != ROOT_MAGIC {
        // Legacy and retired images keep the strict refusal both readers
        // share; any other image is invalid to both and stays as it is.
        return Ok(unchanged(decode_slot(bytes)?, false));
    }
    let stored = le_u32(&bytes[CHECKSUM_AT..]);
    let mut original = with_magic(bytes, &ROOT003_MAGIC);
    let mut target = with_magic(bytes, &ROOT_MAGIC);
    let old_checksum = crc32c(&original[..CHECKSUM_AT]);
    let new_checksum = crc32c(&target[..CHECKSUM_AT]);
    if stored == old_checksum || (root003 && stored == new_checksum) {
        // A valid ROOT003 slot, or one whose earlier upgrade write reached
        // only the magic or only the checksum.
        seal(&mut original);
        seal(&mut target);
        return Ok(SlotPlan {
            upgrade: RootSlotUpgrade::Upgraded,
            original: SlotImage::Valid(decode_root003(&original, &target)?),
            target,
            interrupted: original != *bytes,
        });
    }
    if root003 {
        // Torn or damaged: the stored checksum matches neither spelling, so
        // the rewritten image, and any torn mixture with it, stays invalid.
        return Ok(SlotPlan {
            upgrade: RootSlotUpgrade::InvalidRewritten,
            target,
            original: SlotImage::Invalid,
            interrupted: false,
        });
    }
    // A ROOT005 image: valid, or invalid like a completed rewrite of a torn
    // ROOT003 slot. Next to a slot that still needs work it can only be an
    // earlier write of this upgrade; `RootUpgradePlan::new` checks that.
    Ok(unchanged(decode_slot(bytes)?, true))
}

/// Decode a checksum-valid ROOT003 image as a ROOT003 reader does. Its layout
/// errors are hard refusals, as they are for that reader.
fn decode_root003(
    original: &[u8; ROOT_SLOT_BYTES],
    target: &[u8; ROOT_SLOT_BYTES],
) -> Result<Superblock, CoreError> {
    if le_u32(&original[16..20]) != FORMAT_VERSION {
        return Err(corrupt("ROOT003 slot has an unsupported version"));
    }
    if original[COMPACTION_AT..CHECKSUM_AT]
        .iter()
        .any(|&byte| byte != 0)
    {
        return Err(corrupt("ROOT003 slot has a nonzero compaction region"));
    }
    // Every remaining field has the same layout and checks in both formats.
    let SlotImage::Valid(superblock) = decode_slot(target)? else {
        return Err(corrupt("ROOT003 slot does not decode"));
    };
    if *superblock.compaction() != CompactionRecord::GENESIS {
        return Err(corrupt(
            "ROOT003 slot does not decode to the genesis record",
        ));
    }
    if superblock.encode()? != *target {
        return Err(corrupt(
            "ROOT003 slot is not the canonical encoding of its superblock",
        ));
    }
    Ok(superblock)
}

/// The mirrored-slot selection of the ROOT003 reader (`select_root_images` of
/// that build), over slots as it classifies them. It is kept apart from the
/// runtime selection so the reopen path is untouched; its successor check is
/// the current one, which adds only compaction rules the genesis record of
/// every ROOT003 superblock passes.
fn select_root003(a: SlotImage, b: SlotImage) -> Result<RootSelection, CoreError> {
    let selected = |superblock, slot, mirrored| {
        Ok(RootSelection::Selected {
            superblock,
            slot,
            mirrored,
        })
    };
    match (a, b) {
        (SlotImage::Valid(a), SlotImage::Valid(b)) => {
            if a.group_id != b.group_id {
                return Err(corrupt("root slots name different groups"));
            }
            if a.generation == b.generation {
                if a != b {
                    return Err(corrupt("root slots disagree at one generation"));
                }
                return selected(a, RootSlot::A, true);
            }
            let (newer, newer_slot, older) = if a.generation > b.generation {
                (a, RootSlot::A, b)
            } else {
                (b, RootSlot::B, a)
            };
            if newer.generation != older.generation + 1
                || RootSlot::for_generation(newer.generation) != newer_slot
            {
                return Err(corrupt("root slots are not adjacent publications"));
            }
            if !is_successor(&older, &newer) {
                return Err(corrupt("root slots are not successive publications"));
            }
            selected(newer, newer_slot, false)
        }
        (SlotImage::Valid(valid), SlotImage::Invalid) => selected(valid, RootSlot::A, false),
        (SlotImage::Invalid, SlotImage::Valid(valid)) => selected(valid, RootSlot::B, false),
        (SlotImage::Unwritten, SlotImage::Valid(valid)) if valid.generation == 1 => {
            selected(valid, RootSlot::B, false)
        }
        (SlotImage::Valid(_), SlotImage::Unwritten)
        | (SlotImage::Unwritten, SlotImage::Valid(_)) => {
            Err(corrupt("a published root slot was erased"))
        }
        (SlotImage::Unwritten, SlotImage::Unwritten | SlotImage::Invalid) => {
            Ok(RootSelection::Empty)
        }
        (SlotImage::Invalid, SlotImage::Invalid | SlotImage::Unwritten) => {
            Err(corrupt("no intact root slot"))
        }
    }
}

/// The upgrade of one root file's two slots, planned without any effect.
pub struct RootUpgradePlan {
    current: [[u8; ROOT_SLOT_BYTES]; 2],
    target: [[u8; ROOT_SLOT_BYTES]; 2],
    upgrades: [RootSlotUpgrade; 2],
    interrupted: bool,
    selection: RootSelection,
}

impl RootUpgradePlan {
    /// Plan from the slot images as read. Refuses, before any write, every
    /// pair a ROOT003 reader refuses, every ROOT003 slot it cannot prove, and
    /// any pair whose upgraded selection would differ.
    pub fn new(a: &[u8; ROOT_SLOT_BYTES], b: &[u8; ROOT_SLOT_BYTES]) -> Result<Self, CoreError> {
        let [plan_a, plan_b] = [plan_slot(a)?, plan_slot(b)?];
        let current = [*a, *b];
        let target = [plan_a.target, plan_b.target];
        let upgrades = [plan_a.upgrade, plan_b.upgrade];
        if target == current {
            // Nothing is ROOT003; the strict reader alone decides.
            return Ok(Self {
                current,
                target,
                upgrades,
                interrupted: false,
                selection: select_root_images(a, b)?,
            });
        }
        for plan in [&plan_a, &plan_b] {
            if let (RootSlotUpgrade::Unchanged, SlotImage::Valid(superblock)) =
                (plan.upgrade, &plan.original)
                && (*superblock.compaction() != CompactionRecord::GENESIS
                    || superblock.encode()? != plan.target)
            {
                return Err(corrupt(
                    "ROOT005 slot beside a ROOT003 slot is not an upgrade of it",
                ));
            }
        }
        let interrupted = plan_a.interrupted || plan_b.interrupted;
        let original = select_root003(plan_a.original, plan_b.original)?;
        let selection = select_root_images(&target[0], &target[1])?;
        if selection != original {
            return Err(corrupt("upgraded root slots select a different root"));
        }
        Ok(Self {
            current,
            target,
            upgrades,
            interrupted,
            selection,
        })
    }

    /// No slot needs a write: the pair is already ROOT005 (or unwritten).
    pub fn is_current(&self) -> bool {
        self.target == self.current
    }

    /// An earlier, interrupted run of this upgrade already wrote part of it.
    pub fn is_interrupted(&self) -> bool {
        self.interrupted
    }

    pub fn upgrade(&self, slot: RootSlot) -> RootSlotUpgrade {
        self.upgrades[slot.index()]
    }

    /// The image the slot holds once the upgrade completes.
    pub fn target(&self, slot: RootSlot) -> &[u8; ROOT_SLOT_BYTES] {
        &self.target[slot.index()]
    }

    /// The slot image planned from differs from its target.
    pub fn needs_write(&self, slot: RootSlot) -> bool {
        self.target[slot.index()] != self.current[slot.index()]
    }

    /// The order of slot writes: the slot the selection does not read first,
    /// then the selected slot, so the selected root stays intact until every
    /// other slot is written.
    pub fn write_order(&self) -> [RootSlot; 2] {
        match &self.selection {
            RootSelection::Selected { slot, .. } => [slot.other(), *slot],
            RootSelection::Empty => [RootSlot::A, RootSlot::B],
        }
    }

    /// The selected generation, or `None` for a group with no published root.
    pub fn generation(&self) -> Option<u64> {
        match &self.selection {
            RootSelection::Selected { superblock, .. } => Some(superblock.generation()),
            RootSelection::Empty => None,
        }
    }

    pub fn group_id(&self) -> Option<[u8; 16]> {
        match &self.selection {
            RootSelection::Selected { superblock, .. } => Some(*superblock.group_id()),
            RootSelection::Empty => None,
        }
    }

    /// The selected slot and whether both slots hold the selected root.
    pub fn selected(&self) -> Option<(RootSlot, bool)> {
        match &self.selection {
            RootSelection::Selected { slot, mirrored, .. } => Some((*slot, *mirrored)),
            RootSelection::Empty => None,
        }
    }

    /// Whether `other` completes to the same images and selection, as a plan
    /// of the same root file at another point of one upgrade does.
    pub fn same_upgrade(&self, other: &Self) -> bool {
        self.target == other.target && self.selection == other.selection
    }

    /// Check slot images read back after the writes: they must be the target
    /// images, and the strict runtime selection over them must be exactly the
    /// planned one.
    pub fn verify(
        &self,
        a: &[u8; ROOT_SLOT_BYTES],
        b: &[u8; ROOT_SLOT_BYTES],
    ) -> Result<(), CoreError> {
        if *a != self.target[0] || *b != self.target[1] {
            return Err(corrupt("root slots differ from the planned upgrade"));
        }
        if select_root_images(a, b)? != self.selection {
            return Err(corrupt("upgraded root slots select a different root"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "root_upgrade_tests.rs"]
mod tests;
