//! The ROOT003 upgrade checked against the ROOT003 codec of master 4b3b02f3.

use super::*;
use crate::cache::CacheConfig;
use crate::checkpoint::CheckpointRef;
use crate::core::{AdmissionError, Core, Operation, OwnerFailed, ResidentLease, StorageAdmission};
use crate::directory::{DirectoryPageRef, DirectoryRoot};
use crate::group::{GroupFile, InMemoryGroup, SegmentGroupBackend};
use crate::root::compaction::{COMPACTION_END, decode_compaction, encode_compaction};
use crate::root::{DirectoryCommit, Superblock};
use crate::segment::test_support::{GROUP, corrupt_reason};
use crate::segment::{LEGACY_MAGIC, LogPosition, ReplayStart, SEGMENT_HEADER_BYTES, SealedSegment};
use std::sync::Arc;

/// The ROOT003 slot codec and selection of master 4b3b02f3
/// (`git show 4b3b02f3:crates/kasumi-kv/src/root.rs`), ported verbatim except
/// that it builds the current `Superblock` with the genesis compaction record,
/// the only record a ROOT003 slot can carry, and uses the current invariant
/// check, which adds only compaction checks that the genesis record passes.
/// The directory codec it calls is byte-for-byte unchanged since master.
mod master {
    use crate::checkpoint::CheckpointRef;
    use crate::core::CoreError;
    use crate::group::{FileKind, GroupFile};
    use crate::root::directory::{decode_directory, directory_successor, encode_directory};
    use crate::root::{
        CompactionRecord, ROOT_SLOT_BYTES, RootSelection, RootSlot, SlotImage, Superblock,
    };
    use crate::segment::{FORMAT_VERSION, SealedSegment, crc32c, le_u32, le_u64, reject_legacy};

    pub(super) const ROOT_MAGIC: [u8; 16] = *b"KASUMI-KVROOT003";
    const MAX_GARBAGE: usize = 128;
    const CHECKPOINT_AT: usize = 72;
    const SEALED_AT: usize = 128;
    const GARBAGE_COUNT_AT: usize = 152;
    const GARBAGE_AT: usize = 160;
    const GARBAGE_ENTRY_BYTES: usize = 16;
    pub(super) const CHECKSUM_AT: usize = ROOT_SLOT_BYTES - 4;
    pub(super) const DIRECTORY_AT: usize = GARBAGE_AT + MAX_GARBAGE * GARBAGE_ENTRY_BYTES;
    pub(super) const DIRECTORY_END: usize = DIRECTORY_AT + 24 + 96 + 56;

    pub(super) fn encode(root: &Superblock) -> [u8; ROOT_SLOT_BYTES] {
        assert_eq!(root.compaction, CompactionRecord::GENESIS);
        assert_eq!(root.invariant_violation(), None);
        let mut bytes = [0u8; ROOT_SLOT_BYTES];
        bytes[..16].copy_from_slice(&ROOT_MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[24..40].copy_from_slice(&root.group_id);
        bytes[40..48].copy_from_slice(&root.generation.to_le_bytes());
        bytes[48..56].copy_from_slice(&root.next_segment_id.to_le_bytes());
        bytes[56..64].copy_from_slice(&root.last_segment_id.to_le_bytes());
        bytes[64..72].copy_from_slice(&root.next_checkpoint_id.to_le_bytes());
        if let Some(reference) = root.checkpoint {
            let at = CHECKPOINT_AT;
            bytes[at..at + 8].copy_from_slice(&reference.id.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&reference.len.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&reference.start_segment_id.to_le_bytes());
            bytes[at + 24..at + 56].copy_from_slice(&reference.sha256);
        }
        if let Some(sealed) = root.sealed {
            let at = SEALED_AT;
            bytes[at..at + 8].copy_from_slice(&sealed.segment_id.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&sealed.len.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&sealed.commit_seq.to_le_bytes());
        }
        bytes[GARBAGE_COUNT_AT..GARBAGE_COUNT_AT + 4]
            .copy_from_slice(&(root.garbage.len() as u32).to_le_bytes());
        for (index, file) in root.garbage.iter().enumerate() {
            let at = GARBAGE_AT + index * GARBAGE_ENTRY_BYTES;
            bytes[at] = file.kind.tag();
            bytes[at + 8..at + 16].copy_from_slice(&file.id.to_le_bytes());
        }
        encode_directory(root, &mut bytes[DIRECTORY_AT..DIRECTORY_END]);
        let checksum = crc32c(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }

    pub(super) fn decode_slot(bytes: &[u8; ROOT_SLOT_BYTES]) -> Result<SlotImage, CoreError> {
        reject_legacy(bytes)?;
        if bytes[..16] == *b"KASUMI-KVROOT001" || bytes[..16] == *b"KASUMI-KVROOT002" {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "retired root format is unsupported",
            )));
        }
        if bytes.iter().all(|&byte| byte == 0) {
            return Ok(SlotImage::Unwritten);
        }
        if bytes[..16] != ROOT_MAGIC
            || le_u32(&bytes[CHECKSUM_AT..]) != crc32c(&bytes[..CHECKSUM_AT])
        {
            return Ok(SlotImage::Invalid);
        }
        let layout = CoreError::new(crate::CoreErrorCause::Corrupt(
            "root slot has an unsupported layout",
        ));
        let garbage_count = le_u32(&bytes[GARBAGE_COUNT_AT..GARBAGE_COUNT_AT + 4]) as usize;
        if le_u32(&bytes[16..20]) != FORMAT_VERSION
            || bytes[20..24].iter().any(|&byte| byte != 0)
            || bytes[GARBAGE_COUNT_AT + 4..GARBAGE_AT]
                .iter()
                .any(|&byte| byte != 0)
            || garbage_count > MAX_GARBAGE
            || bytes[GARBAGE_AT + garbage_count * GARBAGE_ENTRY_BYTES..DIRECTORY_AT]
                .iter()
                .any(|&byte| byte != 0)
            || bytes[DIRECTORY_END..CHECKSUM_AT]
                .iter()
                .any(|&byte| byte != 0)
        {
            return Err(layout);
        }
        let checkpoint_id = le_u64(&bytes[CHECKPOINT_AT..CHECKPOINT_AT + 8]);
        let checkpoint = if checkpoint_id == 0 {
            if bytes[CHECKPOINT_AT + 8..SEALED_AT]
                .iter()
                .any(|&byte| byte != 0)
            {
                return Err(layout);
            }
            None
        } else {
            let at = CHECKPOINT_AT;
            Some(CheckpointRef {
                id: checkpoint_id,
                len: le_u64(&bytes[at + 8..at + 16]),
                start_segment_id: le_u64(&bytes[at + 16..at + 24]),
                sha256: bytes[at + 24..at + 56].try_into().expect("32 bytes"),
            })
        };
        let sealed_id = le_u64(&bytes[SEALED_AT..SEALED_AT + 8]);
        let sealed = if sealed_id == 0 {
            if bytes[SEALED_AT + 8..GARBAGE_COUNT_AT]
                .iter()
                .any(|&byte| byte != 0)
            {
                return Err(layout);
            }
            None
        } else {
            Some(SealedSegment {
                segment_id: sealed_id,
                len: le_u64(&bytes[SEALED_AT + 8..SEALED_AT + 16]),
                commit_seq: le_u64(&bytes[SEALED_AT + 16..SEALED_AT + 24]),
            })
        };
        let mut garbage = Vec::with_capacity(garbage_count);
        for index in 0..garbage_count {
            let at = GARBAGE_AT + index * GARBAGE_ENTRY_BYTES;
            let kind = FileKind::from_tag(bytes[at]).ok_or(CoreError::new(
                crate::CoreErrorCause::Corrupt("root garbage entry has an unknown kind"),
            ))?;
            if bytes[at + 1..at + 8].iter().any(|&byte| byte != 0) {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "root slot has an unsupported layout",
                )));
            }
            garbage.push(GroupFile {
                kind,
                id: le_u64(&bytes[at + 8..at + 16]),
            });
        }
        let (next_directory_id, last_directory_id, directory) = decode_directory(
            &bytes[DIRECTORY_AT..DIRECTORY_END],
            bytes[24..40].try_into().expect("16 bytes"),
        )?;
        let superblock = Superblock {
            generation: le_u64(&bytes[40..48]),
            group_id: bytes[24..40].try_into().expect("16 bytes"),
            next_segment_id: le_u64(&bytes[48..56]),
            last_segment_id: le_u64(&bytes[56..64]),
            sealed,
            next_checkpoint_id: le_u64(&bytes[64..72]),
            checkpoint,
            next_directory_id,
            last_directory_id,
            directory,
            garbage,
            compaction: CompactionRecord::GENESIS,
        };
        if let Some(reason) = superblock.invariant_violation() {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(reason)));
        }
        Ok(SlotImage::Valid(superblock))
    }

    pub(super) fn select_root_images(
        a: &[u8; ROOT_SLOT_BYTES],
        b: &[u8; ROOT_SLOT_BYTES],
    ) -> Result<RootSelection, CoreError> {
        let a = decode_slot(a)?;
        let b = decode_slot(b)?;
        let selected = |superblock: Superblock, slot, mirrored| {
            Ok(RootSelection::Selected {
                superblock,
                slot,
                mirrored,
            })
        };
        match (a, b) {
            (SlotImage::Valid(a), SlotImage::Valid(b)) => {
                if a.group_id != b.group_id {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "root slots name different groups",
                    )));
                }
                if a.generation == b.generation {
                    if a != b {
                        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                            "root slots disagree at one generation",
                        )));
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
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "root slots are not adjacent publications",
                    )));
                }
                if !is_successor(&older, &newer) {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "root slots are not successive publications",
                    )));
                }
                selected(newer, newer_slot, false)
            }
            (SlotImage::Valid(valid), SlotImage::Invalid) => selected(valid, RootSlot::A, false),
            (SlotImage::Invalid, SlotImage::Valid(valid)) => selected(valid, RootSlot::B, false),
            (SlotImage::Unwritten, SlotImage::Valid(valid)) if valid.generation == 1 => {
                selected(valid, RootSlot::B, false)
            }
            (SlotImage::Valid(_), SlotImage::Unwritten)
            | (SlotImage::Unwritten, SlotImage::Valid(_)) => Err(CoreError::new(
                crate::CoreErrorCause::Corrupt("a published root slot was erased"),
            )),
            (SlotImage::Unwritten, SlotImage::Unwritten | SlotImage::Invalid) => {
                Ok(RootSelection::Empty)
            }
            (SlotImage::Invalid, SlotImage::Invalid | SlotImage::Unwritten) => Err(CoreError::new(
                crate::CoreErrorCause::Corrupt("no intact root slot"),
            )),
        }
    }

    fn is_successor(previous: &Superblock, next: &Superblock) -> bool {
        let checkpoint_regressed = previous.checkpoint.is_some_and(|current| {
            next.checkpoint.is_none_or(|reference| {
                reference.id < current.id
                    || (reference.id == current.id && reference != current)
                    || reference.start_segment_id < current.start_segment_id
            })
        });
        previous.generation.checked_add(1) == Some(next.generation)
            && previous.group_id == next.group_id
            && next.next_segment_id >= previous.next_segment_id
            && next.last_segment_id >= previous.last_segment_id
            && next.next_checkpoint_id >= previous.next_checkpoint_id
            && next.next_directory_id >= previous.next_directory_id
            && next.last_directory_id >= previous.last_directory_id
            && directory_successor(previous.directory, next.directory)
            && !checkpoint_regressed
            && (next.next_segment_id != previous.next_segment_id || next.sealed == previous.sealed)
    }
}

type Slot = [u8; ROOT_SLOT_BYTES];

fn reseal(bytes: &mut Slot) {
    let checksum = crc32c(&bytes[..CHECKSUM_AT]);
    bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
}

fn sealing(root: &Superblock) -> Option<SealedSegment> {
    (root.last_segment_id != 0).then_some(SealedSegment {
        segment_id: root.last_segment_id,
        len: 4096,
        commit_seq: root.last_segment_id,
    })
}

fn commit(generation: u64, segment_id: u64, arena_id: u64) -> DirectoryCommit {
    DirectoryCommit {
        root: DirectoryRoot {
            group_id: GROUP,
            generation,
            page: Some(DirectoryPageRef {
                arena_id,
                page_index: generation,
                sha256: [generation as u8; 32],
            }),
            height: 2,
            entries: 9,
        },
        start: ReplayStart {
            position: LogPosition {
                segment_id,
                offset: SEGMENT_HEADER_BYTES + 1024 + generation * 256,
            },
            batch_seq: generation,
            chain: [generation as u8; 32],
        },
    }
}

/// Successive roots of a store-shaped group: segment and arena intents and
/// confirmations, then directory commits.
fn store_history() -> Vec<Superblock> {
    let mut roots = vec![Superblock::genesis(GROUP).initialized().unwrap()];
    for _ in 0..3 {
        let root = roots.last().unwrap().clone();
        let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
        roots.push(next.clone());
        roots.push(next.confirm_segment(id).unwrap());
        let root = roots.last().unwrap().clone();
        let (next, id) = root.reserve_directory().unwrap();
        roots.push(next.clone());
        roots.push(next.confirm_directory(id).unwrap());
    }
    for generation in 1..=3 {
        let next = roots
            .last()
            .unwrap()
            .install_directory(commit(generation, 3, 3))
            .unwrap();
        roots.push(next);
    }
    roots
}

/// Roots exercising every ROOT003 field for the codec comparison, including
/// the checkpoint and garbage records a directory store never holds.
fn codec_roots() -> Vec<Superblock> {
    let mut roots = store_history();
    let mut root = Superblock::genesis(GROUP).initialized().unwrap();
    for _ in 0..4 {
        let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
        root = next.confirm_segment(id).unwrap();
    }
    let (pending, _) = root.reserve_segment(sealing(&root)).unwrap();
    roots.push(pending);
    let (next, _) = root.reserve_checkpoint().unwrap();
    let (next, _) = next.reserve_checkpoint().unwrap();
    let reference = |id: u64, start_segment_id| CheckpointRef {
        id,
        len: 100 * id,
        start_segment_id,
        sha256: [id as u8; 32],
    };
    let next = next.install_checkpoint(reference(1, 2)).unwrap();
    roots.push(next.clone());
    let next = next.install_checkpoint(reference(2, 4)).unwrap();
    assert_eq!(next.garbage(), [GroupFile::checkpoint(1)]);
    roots.push(next);
    roots
}

/// The slot pair a master-era publication sequence leaves for `roots[at]`,
/// with its predecessor still in the other slot when `mirrored` is false.
fn pair(roots: &[Superblock], at: usize, mirrored: bool) -> (Slot, Slot) {
    let newer = master::encode(&roots[at]);
    let other = if mirrored {
        newer
    } else {
        master::encode(&roots[at - 1])
    };
    match RootSlot::for_generation(roots[at].generation) {
        RootSlot::A => (newer, other),
        RootSlot::B => (other, newer),
    }
}

/// A publication of `next` over `slot`, torn after `keep` bytes.
fn torn(old: &Slot, next: &Slot, keep: usize) -> Slot {
    let mut bytes = *old;
    bytes[..keep].copy_from_slice(&next[..keep]);
    bytes
}

fn image(pair: &(Slot, Slot), slot: RootSlot) -> &Slot {
    match slot {
        RootSlot::A => &pair.0,
        RootSlot::B => &pair.1,
    }
}

fn set(pair: &mut (Slot, Slot), slot: RootSlot, bytes: Slot) {
    match slot {
        RootSlot::A => pair.0 = bytes,
        RootSlot::B => pair.1 = bytes,
    }
}

/// Master-era slot pairs a ROOT003 build can open, by name.
fn scenarios() -> Vec<(&'static str, (Slot, Slot))> {
    let roots = store_history();
    let last = roots.len() - 1;
    let mut scenarios = vec![
        ("mirrored", pair(&roots, last, true)),
        (
            "mirrored at an odd generation",
            pair(&roots, last - 1, true),
        ),
        ("unmirrored, newer in A", {
            let at = (1..=last)
                .rev()
                .find(|&at| RootSlot::for_generation(roots[at].generation) == RootSlot::A)
                .unwrap();
            pair(&roots, at, false)
        }),
        ("unmirrored, newer in B", {
            let at = (1..=last)
                .rev()
                .find(|&at| RootSlot::for_generation(roots[at].generation) == RootSlot::B)
                .unwrap();
            pair(&roots, at, false)
        }),
        (
            "first publication only",
            ([0; ROOT_SLOT_BYTES], master::encode(&roots[0])),
        ),
        ("torn first publication", {
            let first = master::encode(&roots[0]);
            (
                [0; ROOT_SLOT_BYTES],
                torn(&[0; ROOT_SLOT_BYTES], &first, 100),
            )
        }),
        ("damaged magic beside the root", {
            let mut slots = pair(&roots, last, true);
            slots.1[..16].fill(0);
            slots
        }),
    ];
    // A torn publication of the next generation over its parity slot, from a
    // tear inside the generation field to one just before the checksum.
    let next = roots[last].install_directory(commit(9, 3, 3)).unwrap();
    let encoded = master::encode(&next);
    let parity = RootSlot::for_generation(next.generation);
    for keep in [44, 100, 2400, CHECKSUM_AT] {
        let mut slots = pair(&roots, last, true);
        let tear = torn(image(&slots, parity), &encoded, keep);
        set(&mut slots, parity, tear);
        scenarios.push((
            match keep {
                44 => "tear in the generation",
                100 => "tear in the counters",
                2400 => "tear in the compaction region",
                _ => "tear before the checksum",
            },
            slots,
        ));
    }
    scenarios
}

fn strict(pair: &(Slot, Slot)) -> Result<RootSelection, CoreError> {
    select_root_images(&pair.0, &pair.1)
}

/// The master-era selection with the genesis record, which is what the
/// upgraded slots must select.
fn expected(pair: &(Slot, Slot)) -> RootSelection {
    master::select_root_images(&pair.0, &pair.1).unwrap()
}

#[test]
fn genesis_compaction_record_is_the_all_zero_region() {
    let mut region = [0xa5u8; COMPACTION_END - COMPACTION_AT];
    encode_compaction(&CompactionRecord::GENESIS, &mut region);
    assert!(region.iter().all(|&byte| byte == 0));
    assert_eq!(
        decode_compaction(&[0; COMPACTION_END - COMPACTION_AT]).unwrap(),
        CompactionRecord::GENESIS
    );
    // The record starts where the ROOT003 zero region starts; ROOT005 keeps
    // the rest of that region zero, up to the checksum.
    assert_eq!(
        (COMPACTION_AT, COMPACTION_END, CHECKSUM_AT),
        (master::DIRECTORY_END, 4080, master::CHECKSUM_AT)
    );
    assert_eq!(master::DIRECTORY_END, super::super::DIRECTORY_END);
    assert_eq!(master::DIRECTORY_AT, super::super::DIRECTORY_AT);
}

#[test]
fn master_encoding_differs_from_root005_only_in_magic_byte_and_checksum() {
    for root in codec_roots() {
        let old = master::encode(&root);
        let new = root.encode().unwrap();
        let differing: Vec<usize> = (0..ROOT_SLOT_BYTES)
            .filter(|&at| old[at] != new[at])
            .collect();
        assert_eq!(differing[0], MAGIC_VERSION_AT, "{root:?}");
        assert!(
            differing[1..].iter().all(|&at| at >= CHECKSUM_AT),
            "{differing:?}"
        );
        assert_eq!(
            master::decode_slot(&old).unwrap(),
            SlotImage::Valid(root.clone())
        );
        // The strict runtime decoder still refuses every ROOT003 slot.
        assert_eq!(
            corrupt_reason(decode_slot(&old)),
            "retired root format is unsupported"
        );
        // The master reader treats a ROOT005 slot as torn.
        assert_eq!(master::decode_slot(&new).unwrap(), SlotImage::Invalid);
    }
}

#[test]
fn every_master_slot_pair_upgrades_to_the_same_selection() {
    let mut seen = Vec::new();
    for (name, slots) in scenarios() {
        let plan = RootUpgradePlan::new(&slots.0, &slots.1)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        for slot in [RootSlot::A, RootSlot::B] {
            if !seen.contains(&plan.upgrade(slot)) {
                seen.push(plan.upgrade(slot));
            }
        }
        assert!(!plan.is_current(), "{name}");
        assert!(!plan.is_interrupted(), "{name}");
        let target = (*plan.target(RootSlot::A), *plan.target(RootSlot::B));
        assert_eq!(strict(&target).unwrap(), expected(&slots), "{name}");
        plan.verify(&target.0, &target.1).unwrap();
        for slot in [RootSlot::A, RootSlot::B] {
            let before = image(&slots, slot);
            let after = image(&target, slot);
            let changed: Vec<usize> = (0..ROOT_SLOT_BYTES)
                .filter(|&at| before[at] != after[at])
                .collect();
            match plan.upgrade(slot) {
                RootSlotUpgrade::Upgraded => {
                    let SlotImage::Valid(superblock) = master::decode_slot(before).unwrap() else {
                        panic!("{name}: upgraded an invalid slot");
                    };
                    // Exactly the current encoder's bytes for the same root.
                    assert_eq!(*after, superblock.encode().unwrap(), "{name}");
                    assert_eq!(changed[0], MAGIC_VERSION_AT, "{name}");
                }
                RootSlotUpgrade::InvalidRewritten => {
                    assert_eq!(master::decode_slot(before).unwrap(), SlotImage::Invalid);
                    assert_eq!(decode_slot(after).unwrap(), SlotImage::Invalid, "{name}");
                    assert_eq!(changed, [MAGIC_VERSION_AT], "{name}");
                }
                RootSlotUpgrade::Unwritten | RootSlotUpgrade::Unchanged => {
                    assert!(changed.is_empty(), "{name}");
                    assert!(!plan.needs_write(slot));
                }
            }
        }
        // The slot the selection reads is written last.
        if let Some((selected, _)) = plan.selected() {
            assert_eq!(plan.write_order(), [selected.other(), selected], "{name}");
        }
        // A second plan of the upgraded slots has nothing to do.
        let again = RootUpgradePlan::new(&target.0, &target.1).unwrap();
        assert!(again.is_current(), "{name}");
        assert!(again.same_upgrade(&plan), "{name}");
    }
    assert_eq!(seen.len(), 4, "{seen:?}");
}

/// Byte 15 and the checksum each old or new, as a torn write of one slot
/// leaves them.
fn interruptions(before: &Slot, after: &Slot) -> Vec<Slot> {
    let mut states = Vec::new();
    for magic in [before, after] {
        for checksum in [before, after] {
            let mut state = *before;
            state[MAGIC_VERSION_AT] = magic[MAGIC_VERSION_AT];
            state[CHECKSUM_AT..].copy_from_slice(&checksum[CHECKSUM_AT..]);
            if !states.contains(&state) {
                states.push(state);
            }
        }
    }
    assert!(
        (0..ROOT_SLOT_BYTES)
            .filter(|&at| before[at] != after[at])
            .all(|at| at == MAGIC_VERSION_AT || at >= CHECKSUM_AT)
    );
    states
}

#[test]
fn every_interrupted_slot_write_resumes_to_the_same_upgrade() {
    for (name, slots) in scenarios() {
        let plan = RootUpgradePlan::new(&slots.0, &slots.1).unwrap();
        let original = expected(&slots);
        let [first, second] = plan.write_order();
        let mut state = slots;
        for (written, slot) in [(0, first), (1, second)] {
            for interrupted in interruptions(image(&slots, slot), plan.target(slot)) {
                let mut torn = state;
                set(&mut torn, slot, interrupted);
                let resumed = RootUpgradePlan::new(&torn.0, &torn.1)
                    .unwrap_or_else(|error| panic!("{name} slot {slot:?}: {error}"));
                assert!(resumed.same_upgrade(&plan), "{name} slot {slot:?}");
                if torn != slots && !resumed.is_current() {
                    assert!(resumed.is_interrupted(), "{name} slot {slot:?}");
                }
                if written == 0 {
                    // Until the selected slot is written, a master-era build
                    // still selects the original root from the same slot.
                    let RootSelection::Selected {
                        superblock, slot, ..
                    } = master::select_root_images(&torn.0, &torn.1).unwrap()
                    else {
                        assert_eq!(original, RootSelection::Empty, "{name}");
                        continue;
                    };
                    let RootSelection::Selected {
                        superblock: original_root,
                        slot: original_slot,
                        ..
                    } = &original
                    else {
                        unreachable!()
                    };
                    assert_eq!(
                        (&superblock, slot),
                        (original_root, *original_slot),
                        "{name}"
                    );
                } else if let (
                    Ok(RootSelection::Selected { superblock, .. }),
                    RootSelection::Selected {
                        superblock: original_root,
                        mirrored: true,
                        ..
                    },
                ) = (strict(&torn), &original)
                {
                    // A mirrored root never falls back to an older one.
                    assert_eq!(&superblock, original_root, "{name}");
                }
            }
            set(&mut state, slot, *plan.target(slot));
        }
        plan.verify(&state.0, &state.1).unwrap();
        assert_eq!(strict(&state).unwrap(), original, "{name}");
    }
}

#[test]
fn already_current_slots_are_left_alone_in_every_phase() {
    let roots = store_history();
    let root = roots.last().unwrap();
    let evacuating = root.begin_compaction().unwrap();
    for current in [root.clone(), evacuating] {
        let bytes = current.encode().unwrap();
        for slots in [(bytes, bytes), ([0; ROOT_SLOT_BYTES], bytes)] {
            if slots.0 != bytes && current.generation != 1 {
                assert!(RootUpgradePlan::new(&slots.0, &slots.1).is_err());
                continue;
            }
            let plan = RootUpgradePlan::new(&slots.0, &slots.1).unwrap();
            assert!(plan.is_current());
            assert_eq!(plan.generation(), Some(current.generation));
            assert!(!plan.needs_write(RootSlot::A) && !plan.needs_write(RootSlot::B));
            plan.verify(&slots.0, &slots.1).unwrap();
        }
    }
    let empty = RootUpgradePlan::new(&[0; ROOT_SLOT_BYTES], &[0; ROOT_SLOT_BYTES]).unwrap();
    assert!(empty.is_current());
    assert_eq!(empty.generation(), None);
}

#[test]
fn unprovable_or_unopenable_master_slots_are_refused_before_any_write() {
    let roots = store_history();
    let last = roots.len() - 1;
    let (a, b) = pair(&roots, last, true);
    let refuse = |a: &Slot, b: &Slot| match RootUpgradePlan::new(a, b) {
        Ok(_) => panic!("planned an unprovable pair"),
        Err(error) => error,
    };
    // A nonzero byte in the region ROOT003 keeps zero, under a valid checksum.
    for at in [COMPACTION_AT, 3000, COMPACTION_END, CHECKSUM_AT - 1] {
        let mut damaged = a;
        damaged[at] = 1;
        reseal(&mut damaged);
        assert_eq!(
            corrupt_reason(Err::<(), _>(refuse(&damaged, &b))),
            "ROOT003 slot has a nonzero compaction region"
        );
    }
    // Another record version under a valid checksum.
    let mut version = a;
    version[16..20].copy_from_slice(&3u32.to_le_bytes());
    reseal(&mut version);
    assert_eq!(
        corrupt_reason(Err::<(), _>(refuse(&version, &b))),
        "ROOT003 slot has an unsupported version"
    );
    // Retired and legacy images both readers refuse, and one that only the
    // current reader refuses.
    for magic in [
        *b"KASUMI-KVROOT001",
        *b"KASUMI-KVROOT002",
        *b"KASUMI-KVROOT004",
        LEGACY_MAGIC,
    ] {
        let mut retired = a;
        retired[..16].copy_from_slice(&magic);
        refuse(&retired, &b);
        refuse(&b, &retired);
    }
    // Pairs a master-era build cannot open either.
    let first = master::encode(&roots[0]);
    let mut torn_a = a;
    torn_a[100] ^= 1;
    let mut torn_b = b;
    torn_b[100] ^= 1;
    assert_eq!(
        corrupt_reason(Err::<(), _>(refuse(&torn_a, &torn_b))),
        "no intact root slot"
    );
    assert_eq!(
        corrupt_reason(Err::<(), _>(refuse(&[0; ROOT_SLOT_BYTES], &b))),
        "a published root slot was erased"
    );
    let mut foreign = Superblock::genesis([9; 16]).initialized().unwrap();
    foreign.generation = roots[last].generation;
    refuse(&master::encode(&foreign), &b);
    refuse(&first, &b);
    // A ROOT005 slot beside a ROOT003 slot must be this upgrade's own write.
    let progressed = roots[last].begin_compaction().unwrap();
    let mut beside = pair(&roots, last, true);
    set(
        &mut beside,
        RootSlot::for_generation(progressed.generation).other(),
        progressed.encode().unwrap(),
    );
    refuse(&beside.0, &beside.1);
}

#[derive(Default)]
struct Unlimited;
impl StorageAdmission for Unlimited {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for Unlimited {
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn release_cache(&self, _: u64, _: bool) {}
}

fn rows(core: &Core) -> Vec<(Vec<u8>, Vec<u8>)> {
    let view = core.snapshot().unwrap();
    let mut rows = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, value)) = core
        .next_admitted(&view, "rows", b"", after.as_deref(), 1024)
        .unwrap()
    {
        rows.push((key.as_bytes().to_vec(), value.as_bytes().to_vec()));
        after = Some(key.as_bytes().to_vec());
    }
    rows
}

fn root_slots(group: &InMemoryGroup) -> (Slot, Slot) {
    let mut a = [0; ROOT_SLOT_BYTES];
    let mut b = [0; ROOT_SLOT_BYTES];
    group.read_root(RootSlot::A, &mut a).unwrap();
    group.read_root(RootSlot::B, &mut b).unwrap();
    (a, b)
}

#[test]
fn master_store_upgraded_in_place_reads_the_same_rows_and_reclaims_old_files() {
    let group = InMemoryGroup::new();
    let admission = Arc::new(Unlimited);
    let core = Core::create_with_backend(
        group.clone(),
        admission.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    core.commit(&[Operation::create_table("rows")]).unwrap();
    for batch in 0..8u8 {
        let puts: Vec<_> = (0..32u8)
            .map(|index| Operation::put("rows", vec![batch, index], vec![batch ^ index; 64]))
            .collect();
        core.commit(&puts).unwrap();
    }
    // Dead values in the old files: overwrites and deletions.
    let overwrites: Vec<_> = (0..32u8)
        .map(|index| Operation::put("rows", vec![0, index], vec![0xee; 64]))
        .collect();
    core.commit(&overwrites).unwrap();
    core.commit(&[
        Operation::delete("rows", vec![1, 0]),
        Operation::delete("rows", vec![1, 1]),
    ])
    .unwrap();
    let written = rows(&core);
    assert_eq!(written.len(), 8 * 32 - 2);
    core.close().into_result().unwrap();
    drop(core);

    // A store this build never compacted holds what a master-era build
    // writes for the same commits; give its root the master-era encoding.
    let durable = group.crash();
    let current = root_slots(&durable);
    for slot in [RootSlot::A, RootSlot::B] {
        let SlotImage::Valid(superblock) = decode_slot(image(&current, slot)).unwrap() else {
            panic!("published store has an invalid slot");
        };
        assert_eq!(superblock.compaction, CompactionRecord::GENESIS);
        durable.with_durable_root(slot, |bytes| {
            bytes.copy_from_slice(&master::encode(&superblock));
        });
    }
    let master_slots = root_slots(&durable);
    let master_selection = expected(&master_slots);
    let files: Vec<_> = durable.entries().unwrap();
    assert!(
        matches!(
            Core::open_with_backend(durable.clone(), admission.clone(), GROUP, CacheConfig::default()),
            Err(failure) if failure.to_string().contains("retired root format is unsupported")
        ),
        "the strict reader opened a ROOT003 root"
    );
    // The refused open closed its backend; restart from the durable image.
    let durable = durable.crash();
    assert_eq!(root_slots(&durable), master_slots);

    let plan = RootUpgradePlan::new(&master_slots.0, &master_slots.1).unwrap();
    for slot in plan.write_order() {
        if plan.needs_write(slot) {
            let target = *plan.target(slot);
            durable.with_durable_root(slot, |bytes| bytes.copy_from_slice(&target));
        }
    }
    let upgraded = root_slots(&durable);
    plan.verify(&upgraded.0, &upgraded.1).unwrap();
    assert_eq!(strict(&upgraded).unwrap(), master_selection);
    assert!(
        RootUpgradePlan::new(&upgraded.0, &upgraded.1)
            .unwrap()
            .is_current()
    );
    // Only the root changed.
    assert_eq!(durable.entries().unwrap(), files);

    let core = Core::open_with_backend(
        durable.clone(),
        admission.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    assert_eq!(rows(&core), written);
    // The first write of this lifetime rolls a fresh arena, so every file
    // the master-era build wrote is older than the newest.
    core.commit(&[Operation::put(
        "rows",
        b"after".to_vec(),
        b"upgrade".to_vec(),
    )])
    .unwrap();
    let progress = core.complete_cycle_for_test().unwrap();
    assert!(progress.reclaimed_files >= 1, "{progress:?}");
    let status = core.maintenance_status().unwrap();
    assert_eq!(status.cycle, 1, "{status:?}");
    assert_eq!(status.phase, crate::StorageCompactionPhase::Idle);
    assert_eq!(status.garbage_files, 0);
    assert!(!durable.exists(GroupFile::directory(1)).unwrap());
    let mut expected_rows = written.clone();
    expected_rows.insert(
        expected_rows.partition_point(|(key, _)| key.as_slice() < b"after".as_slice()),
        (b"after".to_vec(), b"upgrade".to_vec()),
    );
    assert_eq!(rows(&core), expected_rows);
    core.close().into_result().unwrap();
    drop(core);
    let reopened =
        Core::open_with_backend(durable.crash(), admission, GROUP, CacheConfig::default()).unwrap();
    assert_eq!(rows(&reopened), expected_rows);
}
