//! Immutable, ordered disk directory pages.
//!
//! A directory root is a snapshot: readers never need an in-memory copy of
//! every key or a resident version chain. The streaming builder admits one
//! page per tree level and consumes sorted entries without collecting them.
//! Page references may be shared by later copy-on-write roots. This module
//! does not publish roots or reclaim pages: the segmented owner must bind the
//! root to its durable batch/chain, and retain every page/value reachable from
//! current and pinned roots before retiring an arena or segment.
//!
//! `DirectoryBackend` is the page-arena boundary. A backend may cache immutable
//! pages under the installed cache budget; it must keep the incarnation and
//! complete page reference in that cache identity. Writes are synchronized
//! before `finish` returns, but only the owner's durable root publication
//! makes those pages authoritative. Failed builds leave unreferenced pages.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::core::{CoreError, MAX_KEY_BYTES, MAX_TABLE_BYTES, ResidentLease, StorageAdmission};
use crate::segment::{ValueLocation, crc32c, le_u16, le_u32, le_u64};

pub(crate) const DIRECTORY_PAGE_BYTES: usize = 16 << 10;
const MAGIC: [u8; 16] = *b"KASUMI-KVDIR0001";
const FORMAT_VERSION: u32 = 1;
const HEADER_BYTES: usize = 64;
const KEY_HEADER_BYTES: usize = 5;
const VALUE_BYTES: usize = 32;
const MAX_ENCODED_KEY: usize = KEY_HEADER_BYTES + MAX_TABLE_BYTES + MAX_KEY_BYTES;
// A 16 KiB page holds at least three maximum-size entries. This depth
// exceeds the addressable page population even at minimum branching.
const MAX_HEIGHT: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryPageRef {
    pub(crate) arena_id: u64,
    pub(crate) page_index: u64,
    pub(crate) checksum: u32,
}

impl DirectoryPageRef {
    fn validate(self) -> Result<(), CoreError> {
        if self.arena_id == 0 || self.page_index == u64::MAX {
            return Err(CoreError::Corrupt("directory page reference is invalid"));
        }
        Ok(())
    }

    fn encode(self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.arena_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.page_index.to_le_bytes());
        out[16..20].copy_from_slice(&self.checksum.to_le_bytes());
        out[20..24].fill(0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes[20..24].iter().any(|&byte| byte != 0) {
            return Err(CoreError::Corrupt(
                "directory page reference is noncanonical",
            ));
        }
        let reference = Self {
            arena_id: le_u64(&bytes[..8]),
            page_index: le_u64(&bytes[8..16]),
            checksum: le_u32(&bytes[16..20]),
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Pages are append-only and identifiers must never be reused. An append
/// returns the checksum of exactly the supplied bytes. Synchronization must
/// cover every page previously appended, including its arena's durable name.
/// The owner, not this codec, performs growth admission and failure fencing.
pub(crate) trait DirectoryBackend: Send + Sync {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError>;
    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError>;
    fn sync_pages(&self) -> Result<(), CoreError>;
}

/// The owner persists all fields together with the corresponding log commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryRoot {
    pub(crate) group_id: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) page: Option<DirectoryPageRef>,
    pub(crate) height: u8,
    pub(crate) entries: u64,
}

impl DirectoryRoot {
    pub(crate) fn validate(self) -> Result<(), CoreError> {
        if self.generation == 0
            || (self.page.is_none() && (self.height != 0 || self.entries != 0))
            || (self.page.is_some()
                && (self.height == 0 || self.height as usize > MAX_HEIGHT || self.entries == 0))
        {
            return Err(CoreError::Corrupt("directory root is invalid"));
        }
        if let Some(page) = self.page {
            page.validate()?;
        }
        Ok(())
    }
}

/// Table entries sort before that table's rows. Table names and row keys are
/// ordered by their original bytes, independently of their encoded lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryKey<'a> {
    pub(crate) table: &'a str,
    pub(crate) row: Option<&'a [u8]>,
}

impl<'a> DirectoryKey<'a> {
    pub(crate) fn table(table: &'a str) -> Self {
        Self { table, row: None }
    }

    pub(crate) fn row(table: &'a str, key: &'a [u8]) -> Self {
        Self {
            table,
            row: Some(key),
        }
    }

    fn validate(self) -> Result<(), CoreError> {
        if self.table.is_empty()
            || self.table.len() > MAX_TABLE_BYTES
            || self.row.is_some_and(|key| key.len() > MAX_KEY_BYTES)
        {
            return Err(CoreError::InvalidInput(
                "directory key exceeds storage limits",
            ));
        }
        Ok(())
    }

    fn encoded_len(self) -> usize {
        KEY_HEADER_BYTES + self.table.len() + self.row.map_or(0, <[u8]>::len)
    }

    fn encode(self, out: &mut [u8]) {
        out[..2].copy_from_slice(&(self.table.len() as u16).to_le_bytes());
        out[2..4].copy_from_slice(&(self.row.map_or(0, <[u8]>::len) as u16).to_le_bytes());
        out[4] = u8::from(self.row.is_some());
        let end = KEY_HEADER_BYTES + self.table.len();
        out[KEY_HEADER_BYTES..end].copy_from_slice(self.table.as_bytes());
        if let Some(row) = self.row {
            out[end..end + row.len()].copy_from_slice(row);
        }
    }
}

impl Ord for DirectoryKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.table
            .as_bytes()
            .cmp(other.table.as_bytes())
            .then_with(|| self.row.cmp(&other.row))
    }
}

impl PartialOrd for DirectoryKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn decode_key(bytes: &[u8]) -> Result<(DirectoryKey<'_>, usize), CoreError> {
    if bytes.len() < KEY_HEADER_BYTES {
        return Err(CoreError::Corrupt("directory key header is truncated"));
    }
    let table_len = le_u16(&bytes[..2]) as usize;
    let key_len = le_u16(&bytes[2..4]) as usize;
    let end = KEY_HEADER_BYTES + table_len + key_len;
    if table_len == 0
        || table_len > MAX_TABLE_BYTES
        || key_len > MAX_KEY_BYTES
        || bytes[4] > 1
        || (bytes[4] == 0 && key_len != 0)
        || end > bytes.len()
    {
        return Err(CoreError::Corrupt("directory key is invalid"));
    }
    let table_end = KEY_HEADER_BYTES + table_len;
    let table = std::str::from_utf8(&bytes[KEY_HEADER_BYTES..table_end])
        .map_err(|_| CoreError::Corrupt("directory table name is not UTF-8"))?;
    Ok((
        DirectoryKey {
            table,
            row: (bytes[4] == 1).then_some(&bytes[table_end..end]),
        },
        end,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryValue {
    Table {
        birth_seq: u64,
    },
    Row {
        batch_seq: u64,
        value: ValueLocation,
    },
}

impl DirectoryValue {
    fn validate(self, key: DirectoryKey<'_>, generation: u64) -> Result<(), CoreError> {
        let seq = match (key.row, self) {
            (None, Self::Table { birth_seq }) => birth_seq,
            (Some(_), Self::Row { batch_seq, value }) => {
                value.validate()?;
                batch_seq
            }
            _ => return Err(CoreError::Corrupt("directory key and value kinds differ")),
        };
        if seq == 0 || seq > generation {
            return Err(CoreError::Corrupt("directory version exceeds its page"));
        }
        Ok(())
    }

    fn encode(self, out: &mut [u8]) {
        out.fill(0);
        match self {
            Self::Table { birth_seq } => out[..8].copy_from_slice(&birth_seq.to_le_bytes()),
            Self::Row { batch_seq, value } => {
                out[..8].copy_from_slice(&batch_seq.to_le_bytes());
                out[8..16].copy_from_slice(&value.segment_id.to_le_bytes());
                out[16..24].copy_from_slice(&value.offset.to_le_bytes());
                out[24..28].copy_from_slice(&value.len.to_le_bytes());
                out[28..32].copy_from_slice(&value.crc.to_le_bytes());
            }
        }
    }

    fn decode(key: DirectoryKey<'_>, bytes: &[u8], generation: u64) -> Result<Self, CoreError> {
        let value = if key.row.is_none() {
            if bytes[8..].iter().any(|&byte| byte != 0) {
                return Err(CoreError::Corrupt("directory table value is noncanonical"));
            }
            Self::Table {
                birth_seq: le_u64(&bytes[..8]),
            }
        } else {
            Self::Row {
                batch_seq: le_u64(&bytes[..8]),
                value: ValueLocation {
                    segment_id: le_u64(&bytes[8..16]),
                    offset: le_u64(&bytes[16..24]),
                    len: le_u32(&bytes[24..28]),
                    crc: le_u32(&bytes[28..32]),
                },
            }
        };
        value.validate(key, generation)?;
        Ok(value)
    }
}

fn reserve(
    admission: &Arc<dyn StorageAdmission>,
    bytes: usize,
) -> Result<Box<dyn ResidentLease>, CoreError> {
    admission
        .check_owner()
        .map_err(|_| CoreError::OwnerFailed)?;
    admission
        .reserve_workspace(bytes as u64)
        .map_err(Into::into)
}

struct PageBuffer {
    bytes: Vec<u8>,
    _lease: Box<dyn ResidentLease>,
}

impl PageBuffer {
    fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        let lease = reserve(
            admission,
            DIRECTORY_PAGE_BYTES + std::mem::size_of::<Self>(),
        )?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(DIRECTORY_PAGE_BYTES)
            .map_err(|_| CoreError::CapacityDenied)?;
        bytes.resize(DIRECTORY_PAGE_BYTES, 0);
        Ok(Self {
            bytes,
            _lease: lease,
        })
    }
}

struct PendingPage {
    buffer: PageBuffer,
    used: usize,
    count: u16,
    entries: u64,
}

impl PendingPage {
    fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        Ok(Self {
            buffer: PageBuffer::new(admission)?,
            used: HEADER_BYTES,
            count: 0,
            entries: 0,
        })
    }

    fn fits(&self, key_len: usize) -> bool {
        self.used + key_len + VALUE_BYTES <= DIRECTORY_PAGE_BYTES
    }

    fn append(
        &mut self,
        key: DirectoryKey<'_>,
        value: &[u8; VALUE_BYTES],
        entries: u64,
    ) -> Result<(), CoreError> {
        let total = self
            .entries
            .checked_add(entries)
            .ok_or(CoreError::InvalidInput("directory entry count overflow"))?;
        let key_end = self.used + key.encoded_len();
        key.encode(&mut self.buffer.bytes[self.used..key_end]);
        self.buffer.bytes[key_end..key_end + VALUE_BYTES].copy_from_slice(value);
        self.used = key_end + VALUE_BYTES;
        self.count += 1;
        self.entries = total;
        Ok(())
    }

    fn reset(&mut self) {
        self.buffer.bytes.fill(0);
        self.used = HEADER_BYTES;
        self.count = 0;
        self.entries = 0;
    }
}

struct Carry {
    key: [u8; MAX_ENCODED_KEY],
    key_len: usize,
    page: DirectoryPageRef,
    entries: u64,
}

/// A bounded streaming bulk loader. Input must be strictly increasing; a
/// refused input leaves the previous prefix intact. Any backend failure
/// poisons the builder; only a new unpublished build may follow it.
pub(crate) struct DirectoryBuilder<'a> {
    backend: &'a dyn DirectoryBackend,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    generation: u64,
    pages: [Option<PendingPage>; MAX_HEIGHT],
    last_key: [u8; MAX_ENCODED_KEY],
    last_key_len: usize,
    entries: u64,
    failed: bool,
    _lease: Box<dyn ResidentLease>,
}

impl<'a> DirectoryBuilder<'a> {
    pub(crate) fn new(
        backend: &'a dyn DirectoryBackend,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        generation: u64,
    ) -> Result<Self, CoreError> {
        if generation == 0 {
            return Err(CoreError::InvalidInput("directory generation is zero"));
        }
        let lease = reserve(
            &admission,
            std::mem::size_of::<Self>() + 2 * std::mem::size_of::<Carry>(),
        )?;
        Ok(Self {
            backend,
            admission,
            group_id,
            generation,
            pages: std::array::from_fn(|_| None),
            last_key: [0; MAX_ENCODED_KEY],
            last_key_len: 0,
            entries: 0,
            failed: false,
            _lease: lease,
        })
    }

    pub(crate) fn push(
        &mut self,
        key: DirectoryKey<'_>,
        value: DirectoryValue,
    ) -> Result<(), CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        key.validate()?;
        value
            .validate(key, self.generation)
            .map_err(|_| CoreError::InvalidInput("directory value is invalid"))?;
        if self.last_key_len != 0 && decode_key(&self.last_key[..self.last_key_len])?.0 >= key {
            return Err(CoreError::InvalidInput(
                "directory input is not strictly ordered",
            ));
        }
        let entries = self
            .entries
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("directory entry count overflow"))?;
        let result = self.push_validated(key, value);
        if result.is_err() {
            // A failed carry can have appended pages or changed pending
            // buffers. A second push must never publish that partial prefix.
            self.failed = true;
        } else {
            self.entries = entries;
            self.last_key_len = key.encoded_len();
            key.encode(&mut self.last_key[..self.last_key_len]);
        }
        result
    }

    fn ensure_level(&mut self, level: usize) -> Result<(), CoreError> {
        if level >= MAX_HEIGHT {
            return Err(CoreError::InvalidInput("directory exceeds maximum height"));
        }
        if self.pages[level].is_none() {
            self.pages[level] = Some(PendingPage::new(&self.admission)?);
        }
        Ok(())
    }

    fn push_validated(
        &mut self,
        key: DirectoryKey<'_>,
        value: DirectoryValue,
    ) -> Result<(), CoreError> {
        self.ensure_level(0)?;
        if !self.pages[0]
            .as_ref()
            .expect("leaf exists")
            .fits(key.encoded_len())
        {
            let carry = self.flush(0)?;
            self.insert_child(1, carry)?;
        }
        let mut encoded = [0; VALUE_BYTES];
        value.encode(&mut encoded);
        self.pages[0]
            .as_mut()
            .expect("leaf exists")
            .append(key, &encoded, 1)
    }

    fn insert_child(&mut self, mut level: usize, mut carry: Carry) -> Result<(), CoreError> {
        loop {
            self.ensure_level(level)?;
            let flushed = if self.pages[level]
                .as_ref()
                .expect("branch exists")
                .fits(carry.key_len)
            {
                None
            } else {
                Some(self.flush(level)?)
            };
            let mut value = [0; VALUE_BYTES];
            carry.page.encode(&mut value[..24]);
            value[24..].copy_from_slice(&carry.entries.to_le_bytes());
            self.pages[level].as_mut().expect("branch exists").append(
                decode_key(&carry.key[..carry.key_len])?.0,
                &value,
                carry.entries,
            )?;
            let Some(parent) = flushed else {
                return Ok(());
            };
            carry = parent;
            level += 1;
        }
    }

    fn flush(&mut self, level: usize) -> Result<Carry, CoreError> {
        let page = self.pages[level].as_mut().expect("flushed page exists");
        debug_assert!(page.count != 0);
        let bytes = &mut page.buffer.bytes;
        bytes[..16].copy_from_slice(&MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[20..36].copy_from_slice(&self.group_id);
        bytes[36..44].copy_from_slice(&self.generation.to_le_bytes());
        bytes[44] = level as u8;
        bytes[46..48].copy_from_slice(&page.count.to_le_bytes());
        bytes[48..52].copy_from_slice(&(page.used as u32).to_le_bytes());
        bytes[52..60].copy_from_slice(&page.entries.to_le_bytes());
        let key_len = decode_key(&bytes[HEADER_BYTES..page.used])?.1;
        let mut key = [0; MAX_ENCODED_KEY];
        key[..key_len].copy_from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + key_len]);
        let checksum = crc32c(bytes);
        let reference = self.backend.append_page(bytes)?;
        reference.validate()?;
        if reference.checksum != checksum {
            return Err(CoreError::Corrupt(
                "appended directory page checksum differs",
            ));
        }
        let carry = Carry {
            key,
            key_len,
            page: reference,
            entries: page.entries,
        };
        page.reset();
        Ok(carry)
    }

    /// Synchronizes every emitted page. The returned root remains private
    /// until the owner publishes it atomically with its log commit boundary.
    pub(crate) fn finish(mut self) -> Result<DirectoryRoot, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let (page, height) = loop {
            let Some(level) = self
                .pages
                .iter()
                .position(|page| page.as_ref().is_some_and(|page| page.count != 0))
            else {
                break (None, 0);
            };
            let higher = self.pages[level + 1..]
                .iter()
                .any(|page| page.as_ref().is_some_and(|page| page.count != 0));
            let carry = self.flush(level)?;
            if !higher {
                if carry.entries != self.entries {
                    return Err(CoreError::Corrupt("directory build entry count differs"));
                }
                break (Some(carry.page), (level + 1) as u8);
            }
            self.insert_child(level + 1, carry)?;
        };
        self.backend.sync_pages()?;
        Ok(DirectoryRoot {
            group_id: self.group_id,
            generation: self.generation,
            page,
            height,
            entries: self.entries,
        })
    }
}

#[derive(Clone, Copy)]
struct PageInfo {
    level: u8,
    count: usize,
    used: usize,
    entries: u64,
    generation: u64,
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    key: DirectoryKey<'a>,
    key_bytes: &'a [u8],
    value: &'a [u8],
}

fn page_entry(bytes: &[u8], at: usize, used: usize) -> Result<(Entry<'_>, usize), CoreError> {
    if at > used {
        return Err(CoreError::Corrupt("directory entry exceeds page"));
    }
    let (key, key_len) = decode_key(&bytes[at..used])?;
    let end = at + key_len + VALUE_BYTES;
    if end > used {
        return Err(CoreError::Corrupt("directory value exceeds page"));
    }
    Ok((
        Entry {
            key,
            key_bytes: &bytes[at..at + key_len],
            value: &bytes[at + key_len..end],
        },
        end,
    ))
}

fn validate_page(
    bytes: &[u8],
    root: DirectoryRoot,
    reference: DirectoryPageRef,
) -> Result<PageInfo, CoreError> {
    reference.validate()?;
    if bytes.len() != DIRECTORY_PAGE_BYTES || crc32c(bytes) != reference.checksum {
        return Err(CoreError::Corrupt("directory page checksum differs"));
    }
    if bytes[..16] != MAGIC
        || le_u32(&bytes[16..20]) != FORMAT_VERSION
        || bytes[20..36] != root.group_id
        || bytes[45] != 0
        || bytes[60..64].iter().any(|&byte| byte != 0)
    {
        return Err(CoreError::Corrupt("directory page header is invalid"));
    }
    let info = PageInfo {
        generation: le_u64(&bytes[36..44]),
        level: bytes[44],
        count: le_u16(&bytes[46..48]) as usize,
        used: le_u32(&bytes[48..52]) as usize,
        entries: le_u64(&bytes[52..60]),
    };
    if info.generation == 0
        || info.generation > root.generation
        || info.level as usize >= MAX_HEIGHT
        || info.count == 0
        || info.used < HEADER_BYTES
        || info.used > DIRECTORY_PAGE_BYTES
        || bytes[info.used..].iter().any(|&byte| byte != 0)
    {
        return Err(CoreError::Corrupt("directory page bounds are invalid"));
    }
    let mut at = HEADER_BYTES;
    let mut previous = None;
    let mut entries = 0u64;
    for _ in 0..info.count {
        let (entry, end) = page_entry(bytes, at, info.used)?;
        if previous.is_some_and(|previous| previous >= entry.key) {
            return Err(CoreError::Corrupt(
                "directory page keys are not strictly ordered",
            ));
        }
        previous = Some(entry.key);
        let count = if info.level == 0 {
            DirectoryValue::decode(entry.key, entry.value, info.generation)?;
            1
        } else {
            DirectoryPageRef::decode(&entry.value[..24])?;
            let count = le_u64(&entry.value[24..32]);
            if count == 0 {
                return Err(CoreError::Corrupt("directory child is empty"));
            }
            count
        };
        entries = entries
            .checked_add(count)
            .ok_or(CoreError::Corrupt("directory entry count overflows"))?;
        at = end;
    }
    if at != info.used || entries != info.entries {
        return Err(CoreError::Corrupt("directory page totals differ"));
    }
    Ok(info)
}

fn nth_entry(bytes: &[u8], info: PageInfo, index: usize) -> Result<Entry<'_>, CoreError> {
    if index >= info.count {
        return Err(CoreError::Corrupt("directory child index exceeds page"));
    }
    let mut at = HEADER_BYTES;
    for i in 0..info.count {
        let (entry, end) = page_entry(bytes, at, info.used)?;
        if i == index {
            return Ok(entry);
        }
        at = end;
    }
    unreachable!("validated page entry count")
}

struct Bounds {
    lower: [u8; MAX_ENCODED_KEY],
    lower_len: usize,
    upper: [u8; MAX_ENCODED_KEY],
    upper_len: usize,
    entries: u64,
    level: u8,
    generation: u64,
}

impl Bounds {
    fn root(root: DirectoryRoot) -> Self {
        Self {
            lower: [0; MAX_ENCODED_KEY],
            lower_len: 0,
            upper: [0; MAX_ENCODED_KEY],
            upper_len: 0,
            entries: root.entries,
            level: root.height - 1,
            generation: root.generation,
        }
    }

    fn child(
        &mut self,
        bytes: &[u8],
        info: PageInfo,
        index: usize,
    ) -> Result<DirectoryPageRef, CoreError> {
        let entry = nth_entry(bytes, info, index)?;
        self.lower_len = entry.key_bytes.len();
        self.lower[..self.lower_len].copy_from_slice(entry.key_bytes);
        // The last child retains its parent's upper limit. Earlier children
        // receive the next sibling's minimum instead.
        if index + 1 < info.count {
            let next = nth_entry(bytes, info, index + 1)?;
            self.upper_len = next.key_bytes.len();
            self.upper[..self.upper_len].copy_from_slice(next.key_bytes);
        }
        self.entries = le_u64(&entry.value[24..]);
        self.level = info.level - 1;
        self.generation = info.generation;
        DirectoryPageRef::decode(&entry.value[..24])
    }

    fn check(&self, bytes: &[u8], info: PageInfo) -> Result<(), CoreError> {
        if info.level != self.level
            || info.entries != self.entries
            || info.generation > self.generation
        {
            return Err(CoreError::Corrupt(
                "directory child shape differs from parent",
            ));
        }
        if self.lower_len != 0
            && nth_entry(bytes, info, 0)?.key != decode_key(&self.lower[..self.lower_len])?.0
        {
            return Err(CoreError::Corrupt(
                "directory child minimum differs from parent",
            ));
        }
        if self.upper_len != 0
            && nth_entry(bytes, info, info.count - 1)?.key
                >= decode_key(&self.upper[..self.upper_len])?.0
        {
            return Err(CoreError::Corrupt("directory child exceeds parent range"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AdmissionError, OwnerFailed};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

    const GROUP: [u8; 16] = [37; 16];

    #[derive(Default)]
    struct MemoryPages {
        pages: Mutex<Vec<Vec<u8>>>,
        reads: AtomicUsize,
        syncs: AtomicUsize,
        fail: AtomicBool,
    }

    impl DirectoryBackend for MemoryPages {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            self.reads.fetch_add(1, AtomicOrdering::Relaxed);
            let pages = self.pages.lock().unwrap();
            let page = pages
                .get(reference.page_index as usize)
                .ok_or(CoreError::Corrupt("test page is absent"))?;
            out.copy_from_slice(page);
            Ok(())
        }

        fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            if self.fail.load(AtomicOrdering::Relaxed) {
                return Err(CoreError::Io(std::io::Error::other(
                    "injected append failure",
                )));
            }
            let mut pages = self.pages.lock().unwrap();
            let reference = DirectoryPageRef {
                arena_id: 1,
                page_index: pages.len() as u64,
                checksum: crc32c(bytes),
            };
            pages.push(bytes.to_vec());
            Ok(reference)
        }

        fn sync_pages(&self) -> Result<(), CoreError> {
            self.syncs.fetch_add(1, AtomicOrdering::Relaxed);
            if self.fail.load(AtomicOrdering::Relaxed) {
                return Err(CoreError::Io(std::io::Error::other(
                    "injected sync failure",
                )));
            }
            Ok(())
        }
    }

    struct Accounting {
        limit: u64,
        used: AtomicU64,
        peak: AtomicU64,
        failed: AtomicBool,
    }

    #[derive(Clone)]
    struct Admission(Arc<Accounting>);

    struct Lease(Arc<Accounting>, u64);

    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.used.fetch_sub(self.1, AtomicOrdering::Relaxed);
        }
    }

    impl Admission {
        fn new(limit: u64) -> Arc<Self> {
            Arc::new(Self(Arc::new(Accounting {
                limit,
                used: AtomicU64::new(0),
                peak: AtomicU64::new(0),
                failed: AtomicBool::new(false),
            })))
        }
    }

    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            if self.0.failed.load(AtomicOrdering::Relaxed) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }
        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            let used = self.0.used.load(AtomicOrdering::Relaxed);
            let next = used
                .checked_add(bytes)
                .filter(|&next| next <= self.0.limit)
                .ok_or(AdmissionError::CapacityDenied)?;
            self.0.used.store(next, AtomicOrdering::Relaxed);
            self.0.peak.fetch_max(next, AtomicOrdering::Relaxed);
            Ok(Box::new(Lease(self.0.clone(), bytes)))
        }
        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            Ok(())
        }
        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            Ok(())
        }
        fn owner_failed(&self) {
            self.0.failed.store(true, AtomicOrdering::Relaxed);
        }
    }

    fn value(seq: u64, id: u64) -> DirectoryValue {
        DirectoryValue::Row {
            batch_seq: seq,
            value: ValueLocation {
                segment_id: id + 1,
                offset: 256,
                len: 8,
                crc: id as u32,
            },
        }
    }

    fn long_key(id: usize) -> [u8; MAX_KEY_BYTES] {
        let mut key = [0; MAX_KEY_BYTES];
        key[..8].copy_from_slice(&(id as u64).to_be_bytes());
        key
    }

    #[test]
    fn streaming_directory_exceeds_workspace_and_reopens_without_resident_keys() {
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 7).unwrap();
        builder
            .push(
                DirectoryKey::table("accounts"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        for id in 0..600 {
            builder
                .push(
                    DirectoryKey::row("accounts", &long_key(id)),
                    value(7, id as u64),
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        assert!(root.height >= 4);
        assert_eq!(root.entries, 601);
        assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        assert!(backend.pages.lock().unwrap().len() * DIRECTORY_PAGE_BYTES > 10 * (160 << 10));
        assert!(admission.0.peak.load(AtomicOrdering::Relaxed) <= 160 << 10);

        // Reopen is just the persisted root plus an empty bounded reader.
        let reader = DirectoryReader::new(&backend, admission.clone());
        for id in [0, 1, 117, 299, 598, 599] {
            let before = backend.reads.load(AtomicOrdering::Relaxed);
            assert_eq!(
                reader
                    .get(root, DirectoryKey::row("accounts", &long_key(id)))
                    .unwrap(),
                Some(value(7, id as u64))
            );
            assert_eq!(
                backend.reads.load(AtomicOrdering::Relaxed) - before,
                root.height as usize
            );
        }
        assert!(
            reader
                .get(root, DirectoryKey::row("accounts", &long_key(600)))
                .unwrap()
                .is_none()
        );
        let mut row = reader
            .next(root, DirectoryKey::table("accounts"), false)
            .unwrap()
            .unwrap();
        assert_eq!(row.value, DirectoryValue::Table { birth_seq: 1 });
        for id in 0..600 {
            let next = reader.next(root, row.key(), true).unwrap().unwrap();
            assert_eq!(next.key(), DirectoryKey::row("accounts", &long_key(id)));
            assert_eq!(next.value, value(7, id as u64));
            row = next;
        }
        assert!(reader.next(root, row.key(), true).unwrap().is_none());
        assert!(admission.0.used.load(AtomicOrdering::Relaxed) > 0);
        drop(row);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn ordered_successors_match_model_across_tables_and_missing_keys() {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 5).unwrap();
        let mut model = BTreeMap::new();
        for table in ["a", "aa", "b", "z"] {
            let value = DirectoryValue::Table { birth_seq: 1 };
            builder.push(DirectoryKey::table(table), value).unwrap();
            model.insert((table.to_owned(), None), value);
            for id in 0..400u64 {
                let key = (id * 3).to_be_bytes().to_vec();
                let value = self::value(5, id);
                builder.push(DirectoryKey::row(table, &key), value).unwrap();
                model.insert((table.to_owned(), Some(key)), value);
            }
        }
        let root = builder.finish().unwrap();
        assert!(root.height >= 2);
        let reader = DirectoryReader::new(&backend, admission);
        for table in ["\0", "a", "aa", "ab", "b", "y", "z", "zz"] {
            for key in [
                None,
                Some(Vec::new()),
                Some(0u64.to_be_bytes().to_vec()),
                Some(577u64.to_be_bytes().to_vec()),
                Some(1197u64.to_be_bytes().to_vec()),
                Some(vec![255; 12]),
            ] {
                for exclusive in [false, true] {
                    let bound = (table.to_owned(), key.clone());
                    let expected = model.iter().find(|(entry, _)| {
                        if exclusive {
                            *entry > &bound
                        } else {
                            *entry >= &bound
                        }
                    });
                    let result = reader
                        .next(
                            root,
                            DirectoryKey {
                                table,
                                row: key.as_deref(),
                            },
                            exclusive,
                        )
                        .unwrap();
                    assert_eq!(
                        result.as_ref().map(|entry| (
                            (
                                entry.key().table.to_owned(),
                                entry.key().row.map(<[u8]>::to_vec)
                            ),
                            entry.value
                        )),
                        expected.map(|(key, value)| (key.clone(), *value))
                    );
                }
            }
        }
    }

    #[test]
    fn immutable_roots_preserve_old_versions_and_incarnation_is_checked() {
        let backend = MemoryPages::default();
        let admission = Admission::new(128 << 10);
        let make = |seq| {
            let mut builder =
                DirectoryBuilder::new(&backend, admission.clone(), GROUP, seq).unwrap();
            builder
                .push(
                    DirectoryKey::table("t"),
                    DirectoryValue::Table { birth_seq: 1 },
                )
                .unwrap();
            builder
                .push(DirectoryKey::row("t", b"key"), value(seq, seq))
                .unwrap();
            builder.finish().unwrap()
        };
        let old = make(1);
        let new = make(2);
        let reader = DirectoryReader::new(&backend, admission);
        assert_eq!(
            reader.get(old, DirectoryKey::row("t", b"key")).unwrap(),
            Some(value(1, 1))
        );
        assert_eq!(
            reader.get(new, DirectoryKey::row("t", b"key")).unwrap(),
            Some(value(2, 2))
        );
        let substituted = DirectoryRoot {
            group_id: [9; 16],
            ..old
        };
        assert!(matches!(
            reader.get(substituted, DirectoryKey::row("t", b"key")),
            Err(CoreError::Corrupt(_))
        ));
        // A COW successor may keep an unchanged older page.
        let shared = DirectoryRoot {
            generation: 3,
            ..old
        };
        assert_eq!(
            reader.get(shared, DirectoryKey::row("t", b"key")).unwrap(),
            Some(value(1, 1))
        );
    }

    #[test]
    fn refused_input_does_not_change_prefix_and_backend_failure_poisons_builder() {
        let backend = MemoryPages::default();
        let admission = Admission::new(128 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        builder
            .push(
                DirectoryKey::table("t"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        assert!(matches!(
            builder.push(
                DirectoryKey::table("t"),
                DirectoryValue::Table { birth_seq: 1 }
            ),
            Err(CoreError::InvalidInput(_))
        ));
        for id in 0..3 {
            builder
                .push(DirectoryKey::row("t", &long_key(id)), value(1, id as u64))
                .unwrap();
        }
        backend.fail.store(true, AtomicOrdering::Relaxed);
        assert!(
            builder
                .push(DirectoryKey::row("t", &long_key(3)), value(1, 3))
                .is_err()
        );
        backend.fail.store(false, AtomicOrdering::Relaxed);
        assert!(matches!(
            builder.push(DirectoryKey::row("t", &long_key(4)), value(1, 4)),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(builder.finish(), Err(CoreError::OwnerFailed)));
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn empty_directory_and_owner_failure_are_checked_without_disk_reads() {
        let backend = MemoryPages::default();
        let admission = Admission::new(128 << 10);
        let root = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1)
            .unwrap()
            .finish()
            .unwrap();
        let reader = DirectoryReader::new(&backend, admission.clone());
        assert_eq!(root.entries, 0);
        assert!(
            reader
                .get(root, DirectoryKey::table("t"))
                .unwrap()
                .is_none()
        );
        assert!(
            reader
                .next(root, DirectoryKey::table("t"), false)
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), 0);
        admission.0.failed.store(true, AtomicOrdering::Relaxed);
        assert!(matches!(
            reader.get(root, DirectoryKey::table("t")),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            reader.next(root, DirectoryKey::table("t"), false),
            Err(CoreError::OwnerFailed)
        ));
    }

    #[test]
    fn page_corruption_and_noncanonical_encodings_fail_closed() {
        for corruption in 0..8 {
            let backend = MemoryPages::default();
            let admission = Admission::new(128 << 10);
            let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            builder
                .push(
                    DirectoryKey::table("t"),
                    DirectoryValue::Table { birth_seq: 1 },
                )
                .unwrap();
            builder
                .push(DirectoryKey::row("t", b"k"), value(1, 3))
                .unwrap();
            let mut root = builder.finish().unwrap();
            let mut pages = backend.pages.lock().unwrap();
            let page = &mut pages[root.page.unwrap().page_index as usize];
            match corruption {
                0 => page[0] ^= 1,
                1 => page[45] = 1,
                2 => page[36..44].copy_from_slice(&2u64.to_le_bytes()),
                3 => page[DIRECTORY_PAGE_BYTES - 1] = 1,
                4 => page[HEADER_BYTES + 4] = 2,
                5 => page[HEADER_BYTES + 6 + 8] = 1,
                6 => page[52..60].copy_from_slice(&3u64.to_le_bytes()),
                7 => page[44] = 1,
                _ => unreachable!(),
            }
            if corruption != 0 {
                root.page.as_mut().unwrap().checksum = crc32c(page);
            }
            drop(pages);
            let reader = DirectoryReader::new(&backend, admission);
            assert!(
                matches!(
                    reader.get(root, DirectoryKey::row("t", b"k")),
                    Err(CoreError::Corrupt(_))
                ),
                "corruption {corruption}"
            );
        }
    }
}

/// One admitted output key. Its bytes and overhead remain charged until the
/// caller releases the record; values are immutable physical references.
pub(crate) struct DirectoryRecord {
    key: Vec<u8>,
    pub(crate) value: DirectoryValue,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryRecord {
    pub(crate) fn key(&self) -> DirectoryKey<'_> {
        decode_key(&self.key)
            .expect("record copied a validated key")
            .0
    }
}

pub(crate) struct DirectoryReader<'a> {
    backend: &'a dyn DirectoryBackend,
    admission: Arc<dyn StorageAdmission>,
}

impl<'a> DirectoryReader<'a> {
    pub(crate) fn new(
        backend: &'a dyn DirectoryBackend,
        admission: Arc<dyn StorageAdmission>,
    ) -> Self {
        Self { backend, admission }
    }

    fn load(
        &self,
        buffer: &mut PageBuffer,
        root: DirectoryRoot,
        reference: DirectoryPageRef,
        bounds: &Bounds,
    ) -> Result<PageInfo, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.backend.read_page(reference, &mut buffer.bytes)?;
        let info = validate_page(&buffer.bytes, root, reference)?;
        bounds.check(&buffer.bytes, info)?;
        Ok(info)
    }

    pub(crate) fn get(
        &self,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
    ) -> Result<Option<DirectoryValue>, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        key.validate()?;
        let Some(mut reference) = root.page else {
            return Ok(None);
        };
        let _workspace = reserve(&self.admission, std::mem::size_of::<Bounds>())?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut bounds = Bounds::root(root);
        loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            let mut selected = None;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                match entry.key.cmp(&key) {
                    Ordering::Greater => break,
                    Ordering::Equal if info.level == 0 => {
                        return Ok(Some(DirectoryValue::decode(
                            entry.key,
                            entry.value,
                            info.generation,
                        )?));
                    }
                    _ => selected = Some(index),
                }
                at = end;
            }
            if info.level == 0 {
                return Ok(None);
            }
            let Some(index) = selected else {
                return Ok(None);
            };
            reference = bounds.child(&buffer.bytes, info, index)?;
        }
    }

    /// Find the first key >= `lower`, or > it when `exclusive`. Successor
    /// search uses a single page buffer and re-descends from the root at the
    /// first known next-subtree boundary, keeping workspace independent of
    /// both the dataset size and the number of preceding deleted keys.
    pub(crate) fn next(
        &self,
        root: DirectoryRoot,
        lower: DirectoryKey<'_>,
        exclusive: bool,
    ) -> Result<Option<DirectoryRecord>, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        lower.validate()?;
        let Some(root_page) = root.page else {
            return Ok(None);
        };
        let _workspace = reserve(
            &self.admission,
            std::mem::size_of::<Bounds>() + MAX_ENCODED_KEY,
        )?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut bounds = Bounds::root(root);
        let mut reference = root_page;
        let mut next_key = [0; MAX_ENCODED_KEY];
        let mut next_len = 0;
        loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            if info.level == 0 {
                let mut at = HEADER_BYTES;
                for _ in 0..info.count {
                    let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                    if entry.key > lower || (!exclusive && entry.key == lower) {
                        let lease = reserve(
                            &self.admission,
                            entry.key_bytes.len() + std::mem::size_of::<DirectoryRecord>(),
                        )?;
                        let mut key = Vec::new();
                        key.try_reserve_exact(entry.key_bytes.len())
                            .map_err(|_| CoreError::CapacityDenied)?;
                        key.extend_from_slice(entry.key_bytes);
                        let value =
                            DirectoryValue::decode(entry.key, entry.value, info.generation)?;
                        return Ok(Some(DirectoryRecord {
                            key,
                            value,
                            _lease: lease,
                        }));
                    }
                    at = end;
                }
                if next_len == 0 {
                    return Ok(None);
                }
                // A subtree to the right exists. Lookup its minimum from the
                // root, retaining all ancestor range validation. It must
                // lead to a leaf key strictly beyond the original lower.
                let target = decode_key(&next_key[..next_len])?.0;
                bounds = Bounds::root(root);
                reference = root_page;
                loop {
                    let info = self.load(&mut buffer, root, reference, &bounds)?;
                    if info.level == 0 {
                        break;
                    }
                    let mut selected = 0;
                    for index in 0..info.count {
                        if nth_entry(&buffer.bytes, info, index)?.key > target {
                            break;
                        }
                        selected = index;
                    }
                    reference = bounds.child(&buffer.bytes, info, selected)?;
                }
                // Reload and execute the leaf output path in the outer
                // loop. A valid separator equals the reached leaf minimum.
                next_len = 0;
                continue;
            }
            let mut selected = 0;
            for index in 0..info.count {
                if nth_entry(&buffer.bytes, info, index)?.key > lower {
                    break;
                }
                selected = index;
            }
            if selected + 1 < info.count {
                let next = nth_entry(&buffer.bytes, info, selected + 1)?;
                next_len = next.key_bytes.len();
                next_key[..next_len].copy_from_slice(next.key_bytes);
            }
            reference = bounds.child(&buffer.bytes, info, selected)?;
        }
    }
}
