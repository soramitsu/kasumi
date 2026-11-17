//! The packed deployed-format fixtures, shared by the tests that read them in
//! kasumi-kv, kasumi-store and kasumi-server through `#[path]`. README.md in
//! this directory says where the fixtures come from.
//!
//! `fixtures.kfx` is one stream holding every file of every fixture. The
//! copies share most of their bytes, and directory arenas repeat themselves,
//! so the stream is a sequence of literal runs and back references of any
//! distance; nothing else is needed and the tests take no new dependency.
#![allow(dead_code, reason = "each including test uses part of this module")]

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// The store first written by 12140939, stopped cleanly by it.
pub const FIRST_CLEAN: &str = "12140939-clean";
/// The same store killed while its root listed garbage and a write ran.
pub const FIRST_KILLED: &str = "12140939-killed";
/// The same store after cf9959f1, the build now deployed, served it.
pub const SECOND_CLEAN: &str = "cf9959f1-clean";
pub const FIXTURES: [&str; 3] = [FIRST_CLEAN, FIRST_KILLED, SECOND_CLEAN];

const STREAM_MAGIC: &[u8; 8] = b"KFXZ0001";
const FILE: u8 = 1;
const DIRECTORY: u8 = 2;
const MINIMUM_MATCH: usize = 24;
const TABLE_BITS: u32 = 22;

pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/deployed-format")
}

/// What the build that wrote `fixture` answered before it stopped.
pub fn manifest(fixture: &str) -> String {
    let path = directory().join(format!("{fixture}.manifest.json"));
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Every fixture file by `<fixture>/<path below the copy>`; a directory has
/// no bytes.
pub struct Fixtures {
    entries: BTreeMap<String, Option<Vec<u8>>>,
}

impl Fixtures {
    pub fn load() -> Self {
        let path = directory().join("fixtures.kfx");
        let packed = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        Self::decode(&unpack(&packed).expect("fixtures.kfx is damaged"))
            .expect("fixtures.kfx holds an unknown entry")
    }

    fn decode(mut raw: &[u8]) -> Option<Self> {
        let mut entries = BTreeMap::new();
        let mut take = |bytes: usize| {
            let (head, rest) = raw.split_at_checked(bytes)?;
            raw = rest;
            Some(head)
        };
        loop {
            let kind = take(1)?[0];
            if kind == 0 {
                return Some(Self { entries });
            }
            let name = u16::from_le_bytes(take(2)?.try_into().ok()?);
            let name = String::from_utf8(take(usize::from(name))?.to_vec()).ok()?;
            let body = match kind {
                FILE => {
                    let length = u64::from_le_bytes(take(8)?.try_into().ok()?);
                    Some(take(usize::try_from(length).ok()?)?.to_vec())
                }
                DIRECTORY => None,
                _ => return None,
            };
            entries.insert(name, body);
        }
    }

    /// A file's bytes, by its path below the copied installation.
    pub fn file(&self, fixture: &str, path: &str) -> &[u8] {
        self.entries
            .get(&format!("{fixture}/{path}"))
            .and_then(Option::as_deref)
            .unwrap_or_else(|| panic!("{fixture} has no file {path}"))
    }

    /// Paths of the files directly inside `directory` of a fixture.
    pub fn names(&self, fixture: &str, directory: &str) -> Vec<String> {
        let prefix = format!("{fixture}/{directory}/");
        self.entries
            .range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix))
            .filter(|(path, body)| body.is_some() && !path[prefix.len()..].contains('/'))
            .map(|(path, _)| path[prefix.len()..].to_owned())
            .collect()
    }

    /// Write the fixture's installation as owner-only files below `target`,
    /// which must not exist.
    pub fn extract(&self, fixture: &str, target: &Path) -> io::Result<()> {
        let prefix = format!("{fixture}/");
        let private = |path: &Path| fs::DirBuilder::new().mode(0o700).create(path);
        private(target)?;
        for (path, body) in self
            .entries
            .range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix))
        {
            let path = target.join(&path[prefix.len()..]);
            match body {
                None => private(&path)?,
                Some(bytes) => {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)?;
                    io::Write::write_all(&mut file, bytes)?;
                }
            }
        }
        Ok(())
    }
}

/// Pack the copies `scripts/deployed_format_fixture.py` wrote below `raw`
/// into `fixtures.kfx` and their manifests beside it.
pub fn pack(raw: &Path) -> io::Result<()> {
    let mut stream = Vec::new();
    for fixture in FIXTURES {
        let copy = raw.join(fixture);
        fs::copy(
            copy.join("manifest.json"),
            directory().join(format!("{fixture}.manifest.json")),
        )?;
        collect(&copy.join("installation"), fixture, &mut stream)?;
    }
    stream.push(0);
    let packed = compress(&stream);
    assert_eq!(unpack(&packed).as_deref(), Some(stream.as_slice()));
    fs::write(directory().join("fixtures.kfx"), packed)
}

fn collect(directory: &Path, name: &str, stream: &mut Vec<u8>) -> io::Result<()> {
    let mut entry = |kind: u8, name: &str| {
        stream.push(kind);
        stream.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(name.as_bytes());
    };
    entry(DIRECTORY, name);
    let mut children = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        let path = format!("{name}/{}", child.file_name().to_str().unwrap());
        if child.file_type()?.is_dir() {
            collect(&child.path(), &path, stream)?;
        } else {
            let bytes = fs::read(child.path())?;
            stream.push(FILE);
            stream.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
            stream.extend_from_slice(path.as_bytes());
            stream.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            stream.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

fn varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(packed: &mut &[u8]) -> Option<usize> {
    let mut value = 0usize;
    for shift in (0..usize::BITS).step_by(7) {
        let (&byte, rest) = packed.split_first()?;
        *packed = rest;
        value |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Greedy matching against the most recent earlier occurrence of each eight
/// bytes. A match is as long as it runs and may reach back any distance.
fn compress(raw: &[u8]) -> Vec<u8> {
    let mut out = STREAM_MAGIC.to_vec();
    out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    out.extend_from_slice(&Sha256::digest(raw));
    let mut table = vec![0u32; 1 << TABLE_BITS];
    let slot = |at: usize| {
        let word = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        (word.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - TABLE_BITS)) as usize
    };
    let (mut at, mut literals) = (0, 0);
    while at + 8 <= raw.len() {
        let key = slot(at);
        let candidate = table[key] as usize;
        table[key] = u32::try_from(at + 1).expect("fixtures stay below 4 GiB");
        let length = match candidate.checked_sub(1) {
            Some(earlier) => raw[earlier..]
                .iter()
                .zip(&raw[at..])
                .take_while(|(left, right)| left == right)
                .count(),
            None => 0,
        };
        if length < MINIMUM_MATCH {
            at += 1;
            continue;
        }
        varint(at - literals, &mut out);
        out.extend_from_slice(&raw[literals..at]);
        varint(length, &mut out);
        varint(at - (candidate - 1), &mut out);
        // Later copies of a long run match its start; index a few positions.
        for inside in (at + 1..at + length).step_by(64) {
            if inside + 8 <= raw.len() {
                table[slot(inside)] = (inside + 1) as u32;
            }
        }
        at += length;
        literals = at;
    }
    varint(raw.len() - literals, &mut out);
    out.extend_from_slice(&raw[literals..]);
    out
}

fn unpack(packed: &[u8]) -> Option<Vec<u8>> {
    let mut packed = packed.strip_prefix(STREAM_MAGIC)?;
    let (header, rest) = packed.split_at_checked(40)?;
    packed = rest;
    let length = usize::try_from(u64::from_le_bytes(header[..8].try_into().ok()?)).ok()?;
    let mut raw = Vec::with_capacity(length);
    while raw.len() < length {
        let literals = read_varint(&mut packed)?;
        let (run, rest) = packed.split_at_checked(literals)?;
        raw.extend_from_slice(run);
        packed = rest;
        if raw.len() == length {
            break;
        }
        let count = read_varint(&mut packed)?;
        let distance = read_varint(&mut packed)?;
        let from = raw.len().checked_sub(distance).filter(|_| distance > 0)?;
        if distance >= count {
            raw.extend_from_within(from..from + count);
        } else {
            // The run repeats its own last `distance` bytes.
            for index in 0..count {
                raw.push(raw[from + index]);
            }
        }
    }
    (raw.len() == length && packed.is_empty() && Sha256::digest(&raw)[..] == header[8..])
        .then_some(raw)
}

/// The pinned byte layouts of a deployed node group: the store's file envelope
/// and, below it, the native KV root slots, segments and Fixed directory
/// arenas. A check panics with the name of the file it refuses.
pub mod layout {
    use sha2::{Digest, Sha256};

    // The `KASUMI-NODE-SEG1` envelope in front of every file.
    pub const ENVELOPE_BYTES: usize = 4096;
    pub const ENVELOPE_MAGIC: &[u8; 16] = b"KASUMI-NODE-SEG1";
    pub const NODE_STORE_ID_AT: std::ops::Range<usize> = 16..32;
    pub const ROOT_KIND: u8 = 1;
    pub const SEGMENT_KIND: u8 = 2;
    pub const DIRECTORY_KIND: u8 = 4;
    pub const READY_STATE: u8 = 2;

    // The `KASUMI-KVROOT005` slot.
    pub const ROOT_FILE_NAME: &str = "root.kvroot";
    pub const ROOT_SLOT_BYTES: usize = 4096;
    pub const ROOT_MAGIC: &[u8; 16] = b"KASUMI-KVROOT005";
    pub const ROOT_FORMAT_VERSION: u32 = 4;
    pub const DIRECTORY_FORMAT_AT: std::ops::Range<usize> = 20..24;
    pub const FIXED_DIRECTORY_TAG: [u8; 4] = [0; 4];
    pub const GROUP_ID_AT: std::ops::Range<usize> = 24..40;
    pub const GENERATION_AT: usize = 40;
    pub const NEXT_SEGMENT_AT: usize = 48;
    pub const LAST_SEGMENT_AT: usize = 56;
    /// The retired checkpoint allocator: next identifier one, no reference.
    pub const RETIRED_CHECKPOINT_AT: std::ops::Range<usize> = 64..128;
    pub const SEALED_AT: usize = 128;
    pub const GARBAGE_COUNT_AT: usize = 152;
    pub const GARBAGE_AT: usize = 160;
    pub const GARBAGE_ENTRY_BYTES: usize = 16;
    pub const MAX_GARBAGE: usize = 128;
    pub const SEGMENT_GARBAGE_TAG: u8 = 1;
    pub const DIRECTORY_GARBAGE_TAG: u8 = 3;
    pub const DIRECTORY_COMMIT_AT: std::ops::Range<usize> = 2208..2384;
    pub const COMPACTION_AT: std::ops::Range<usize> = 2384..4080;
    pub const ROOT_CHECKSUM_AT: usize = ROOT_SLOT_BYTES - 4;

    // Data files, after their envelope.
    pub const SEGMENT_MAGIC: &[u8; 16] = b"KASUMI-KVSEG0004";
    pub const SEGMENT_FORMAT_VERSION: u32 = 4;
    pub const SEGMENT_HEADER_BYTES: usize = 64;
    pub const SEGMENT_BYTES: usize = 64 << 20;
    pub const RECORD_MAGIC: &[u8; 4] = b"KVSR";
    pub const ARENA_MAGIC: &[u8; 16] = b"KASUMI-KVARENA01";
    pub const ARENA_VERSION: u32 = 1;
    pub const ARENA_HEADER_BYTES: usize = 4096;
    pub const ARENA_BYTES: usize = 64 << 20;
    pub const DIRECTORY_PAGE_BYTES: usize = 16 << 10;
    pub const DIRECTORY_PAGE_MAGIC: &[u8; 16] = b"KASUMI-KVDIR0002";
    pub const DIRECTORY_PAGE_VERSION: u32 = 2;

    pub fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82f6_3b78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    pub fn le_u32(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    pub fn le_u64(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// `(kind, identifier)` of a canonical group file name; the root is
    /// `(ROOT_KIND, 0)`.
    pub fn file_identity(name: &str) -> Option<(u8, u64)> {
        if name == ROOT_FILE_NAME {
            return Some((ROOT_KIND, 0));
        }
        let (digits, kind) = match name.strip_suffix(".kvseg") {
            Some(digits) => (digits, SEGMENT_KIND),
            None => (name.strip_suffix(".kvdir")?, DIRECTORY_KIND),
        };
        let id = u64::from_str_radix(digits, 16).ok()?;
        (format!("{id:016x}") == digits && id != 0).then_some((kind, id))
    }

    /// The Ready envelope of the file named `name`: kind 1 root, 2 segment or
    /// 4 directory arena, the installed node store and the file identifier.
    pub fn check_envelope(name: &str, file: &[u8], node_store_id: &[u8]) {
        let (kind, id) =
            file_identity(name).unwrap_or_else(|| panic!("{name} is not a group file"));
        assert!(file.len() >= ENVELOPE_BYTES, "{name} has no envelope");
        let envelope = &file[..ENVELOPE_BYTES];
        assert_eq!(&envelope[..16], ENVELOPE_MAGIC, "{name}");
        assert_eq!(&envelope[NODE_STORE_ID_AT], node_store_id, "{name}");
        assert_eq!(envelope[32], kind, "{name} kind");
        assert_eq!(envelope[33], READY_STATE, "{name} state");
        assert_eq!(envelope[34..40], [0; 6], "{name}");
        assert_eq!(le_u64(envelope, 40), id, "{name} identifier");
        assert_eq!(
            envelope[48..80],
            Sha256::digest(&envelope[..48])[..],
            "{name}"
        );
        assert!(envelope[80..].iter().all(|byte| *byte == 0), "{name}");
    }

    /// One native root slot. Returns its garbage records as `(tag, file
    /// identifier)`: tag 1 names a segment and tag 3 a directory arena.
    pub fn check_root_slot(slot: &[u8], node_store_id: &[u8]) -> Vec<(u8, u64)> {
        assert_eq!(slot.len(), ROOT_SLOT_BYTES);
        assert_eq!(&slot[..16], ROOT_MAGIC);
        assert_eq!(le_u32(slot, 16), ROOT_FORMAT_VERSION);
        assert_eq!(slot[DIRECTORY_FORMAT_AT], FIXED_DIRECTORY_TAG);
        assert_eq!(&slot[GROUP_ID_AT], node_store_id);
        assert!(le_u64(slot, GENERATION_AT) > 0);
        let (next, last) = (le_u64(slot, NEXT_SEGMENT_AT), le_u64(slot, LAST_SEGMENT_AT));
        assert!(last >= 1 && (next == last + 1 || next == last + 2));
        let mut retired = [0u8; 64];
        retired[0] = 1;
        assert_eq!(slot[RETIRED_CHECKPOINT_AT], retired);
        if le_u64(slot, SEALED_AT) == 0 {
            assert!(
                slot[SEALED_AT..GARBAGE_COUNT_AT]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        let count = le_u32(slot, GARBAGE_COUNT_AT) as usize;
        assert!(count <= MAX_GARBAGE);
        assert_eq!(le_u32(slot, GARBAGE_COUNT_AT + 4), 0);
        let garbage = (0..count)
            .map(|index| {
                let entry =
                    &slot[GARBAGE_AT + index * GARBAGE_ENTRY_BYTES..][..GARBAGE_ENTRY_BYTES];
                assert!(
                    entry[0] == SEGMENT_GARBAGE_TAG || entry[0] == DIRECTORY_GARBAGE_TAG,
                    "garbage tag {}",
                    entry[0]
                );
                assert_eq!(entry[1..8], [0; 7]);
                let id = le_u64(entry, 8);
                assert_ne!(id, 0);
                (entry[0], id)
            })
            .collect();
        assert_eq!(
            GARBAGE_AT + MAX_GARBAGE * GARBAGE_ENTRY_BYTES,
            DIRECTORY_COMMIT_AT.start
        );
        assert!(
            slot[GARBAGE_AT + count * GARBAGE_ENTRY_BYTES..DIRECTORY_COMMIT_AT.start]
                .iter()
                .all(|byte| *byte == 0)
        );
        // A served store always has a selected directory commit.
        assert!(slot[DIRECTORY_COMMIT_AT].iter().any(|byte| *byte != 0));
        assert_eq!(DIRECTORY_COMMIT_AT.end, COMPACTION_AT.start);
        assert!(
            slot[COMPACTION_AT.end..ROOT_CHECKSUM_AT]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            le_u32(slot, ROOT_CHECKSUM_AT),
            crc32c(&slot[..ROOT_CHECKSUM_AT])
        );
        garbage
    }

    /// A whole root file: its envelope and both slots, which hold equal or
    /// adjacent generations. Returns each slot's garbage records.
    pub fn check_root_file(file: &[u8]) -> [Vec<(u8, u64)>; 2] {
        assert_eq!(file.len(), ENVELOPE_BYTES + 2 * ROOT_SLOT_BYTES);
        let id = &file[NODE_STORE_ID_AT];
        check_envelope(ROOT_FILE_NAME, file, id);
        let slots = [
            &file[ENVELOPE_BYTES..][..ROOT_SLOT_BYTES],
            &file[ENVELOPE_BYTES + ROOT_SLOT_BYTES..],
        ];
        let generations = slots.map(|slot| le_u64(slot, GENERATION_AT));
        assert!(generations[0].abs_diff(generations[1]) <= 1);
        slots.map(|slot| check_root_slot(slot, id))
    }

    /// A segment or Fixed directory arena below its envelope. Returns the
    /// number of 16 KiB directory pages it holds.
    pub fn check_data_file(name: &str, payload: &[u8], node_store_id: &[u8]) -> usize {
        let (kind, _) = file_identity(name).unwrap_or_else(|| panic!("{name} is not a group file"));
        if payload.is_empty() {
            // Created and not yet written: an interrupted roll leaves this.
            return 0;
        }
        if kind == SEGMENT_KIND {
            assert!(payload.len() <= SEGMENT_BYTES, "{name}");
            assert_eq!(&payload[..16], SEGMENT_MAGIC, "{name}");
            assert_eq!(le_u32(payload, 16), SEGMENT_FORMAT_VERSION, "{name}");
            if payload.len() > SEGMENT_HEADER_BYTES {
                assert_eq!(
                    &payload[SEGMENT_HEADER_BYTES..][..4],
                    RECORD_MAGIC,
                    "{name}"
                );
            }
            return 0;
        }
        assert!(payload.len() <= ARENA_BYTES, "{name}");
        let header = &payload[..ARENA_HEADER_BYTES];
        assert_eq!(&header[..16], ARENA_MAGIC, "{name}");
        assert_eq!(le_u32(header, 16), ARENA_VERSION, "{name}");
        assert_eq!(
            le_u32(header, ARENA_HEADER_BYTES - 4),
            crc32c(&header[..ARENA_HEADER_BYTES - 4]),
            "{name}"
        );
        // A Fixed arena is whole, uncompressed 16 KiB pages after its header.
        let pages = &payload[ARENA_HEADER_BYTES..];
        assert_eq!(pages.len() % DIRECTORY_PAGE_BYTES, 0, "{name}");
        for page in pages.chunks(DIRECTORY_PAGE_BYTES) {
            assert_eq!(&page[..16], DIRECTORY_PAGE_MAGIC, "{name}");
            assert_eq!(le_u32(page, 16), DIRECTORY_PAGE_VERSION, "{name}");
            assert_eq!(&page[20..36], node_store_id, "{name}");
        }
        pages.len() / DIRECTORY_PAGE_BYTES
    }
}
