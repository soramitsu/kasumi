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
use crate::segment::{ValueLocation, le_u16, le_u32, le_u64};
use sha2::{Digest, Sha256};

#[path = "directory_leaf.rs"]
mod leaf;
#[path = "directory_pack.rs"]
mod pack;
#[path = "directory_update.rs"]
mod update;
#[path = "directory_walk.rs"]
mod walk;
pub(crate) use leaf::{DirectoryLeaf, MAX_DIRECTORY_LEAF_RECORDS};
pub(crate) use pack::{DirectoryCursor, DirectoryPackPlan};
// The production Core cutover will consume this staged mutation boundary.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use update::{
    DirectoryEdit, DirectoryMutator, DirectoryWriteWorkspace, MAX_DIRECTORY_BATCH_EDITS,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use walk::{DirectoryWalkProgress, DirectoryWalker};

#[path = "directory_reachability.rs"]
mod reachability;

pub(crate) const DIRECTORY_PAGE_BYTES: usize = 16 << 10;
const MAGIC: [u8; 16] = *b"KASUMI-KVDIR0002";
const FORMAT_VERSION: u32 = 2;
const HEADER_BYTES: usize = 64;
const KEY_HEADER_BYTES: usize = 5;
const LEAF_VALUE_BYTES: usize = 32;
const PAGE_REF_BYTES: usize = 48;
const BRANCH_VALUE_BYTES: usize = PAGE_REF_BYTES + 8;
pub(crate) const DIRECTORY_ROOT_BYTES: usize = 96;

fn value_bytes(level: u8) -> usize {
    if level == 0 {
        LEAF_VALUE_BYTES
    } else {
        BRANCH_VALUE_BYTES
    }
}

pub(crate) fn page_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
const MAX_ENCODED_KEY: usize = KEY_HEADER_BYTES + MAX_TABLE_BYTES + MAX_KEY_BYTES;
// Match cache.rs's conservative allocation ledger. These allowances are in
// addition to Rust layouts and retained Vec capacities, not an RSS estimate.
// Custom admission owners must budget backing beyond LEASE_OWNER_ALLOWANCE.
const ALLOCATION_ALLOWANCE: usize = 64;
const LEASE_OWNER_ALLOWANCE: usize = 64;
const LEASE_ALLOWANCE: usize = LEASE_OWNER_ALLOWANCE + ALLOCATION_ALLOWANCE;
// A 16 KiB page holds at least three maximum-size entries. This depth
// exceeds the addressable page population even at minimum branching.
const MAX_HEIGHT: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryPageRef {
    pub(crate) arena_id: u64,
    pub(crate) page_index: u64,
    pub(crate) sha256: [u8; 32],
}

impl DirectoryPageRef {
    fn validate(self) -> Result<(), CoreError> {
        if self.arena_id == 0 || self.arena_id == u64::MAX || self.page_index == u64::MAX {
            return Err(CoreError::Corrupt("directory page reference is invalid"));
        }
        Ok(())
    }

    fn encode(self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.arena_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.page_index.to_le_bytes());
        out[16..PAGE_REF_BYTES].copy_from_slice(&self.sha256);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let reference = Self {
            arena_id: le_u64(&bytes[..8]),
            page_index: le_u64(&bytes[8..16]),
            sha256: bytes[16..PAGE_REF_BYTES]
                .try_into()
                .expect("32-byte digest"),
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Pages are append-only and identifiers must never be reused. An append
/// returns the SHA-256 digest of exactly the supplied bytes. Synchronization must
/// cover every page previously appended, including its arena's durable name.
/// The owner, not this codec, performs growth admission and failure fencing.
pub(crate) trait DirectoryBackend: Send + Sync {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError>;
    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError>;
    fn sync_pages(&self) -> Result<(), CoreError>;
}

impl<T: DirectoryBackend + ?Sized> DirectoryBackend for &T {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        (**self).read_page(reference, out)
    }
    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        (**self).append_page(bytes)
    }
    fn sync_pages(&self) -> Result<(), CoreError> {
        (**self).sync_pages()
    }
}

impl<T: DirectoryBackend + ?Sized> DirectoryBackend for Arc<T> {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        (**self).read_page(reference, out)
    }
    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        (**self).append_page(bytes)
    }
    fn sync_pages(&self) -> Result<(), CoreError> {
        (**self).sync_pages()
    }
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
    /// Canonical bytes shared by the durable commit and superblock codecs.
    /// The root digest transitively binds every reachable immutable page.
    pub(crate) fn encode(self) -> Result<[u8; DIRECTORY_ROOT_BYTES], CoreError> {
        self.validate()?;
        let mut bytes = [0; DIRECTORY_ROOT_BYTES];
        bytes[..16].copy_from_slice(&self.group_id);
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24] = self.height;
        bytes[25] = u8::from(self.page.is_some());
        bytes[32..40].copy_from_slice(&self.entries.to_le_bytes());
        if let Some(page) = self.page {
            page.encode(&mut bytes[40..88]);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8; DIRECTORY_ROOT_BYTES]) -> Result<Self, CoreError> {
        if bytes[25] > 1
            || bytes[26..32].iter().any(|&byte| byte != 0)
            || bytes[88..].iter().any(|&byte| byte != 0)
            || (bytes[25] == 0 && bytes[40..88].iter().any(|&byte| byte != 0))
        {
            return Err(CoreError::Corrupt("directory root is noncanonical"));
        }
        let root = Self {
            group_id: bytes[..16].try_into().expect("16-byte group"),
            generation: le_u64(&bytes[16..24]),
            height: bytes[24],
            entries: le_u64(&bytes[32..40]),
            page: if bytes[25] == 0 {
                None
            } else {
                Some(DirectoryPageRef::decode(&bytes[40..88])?)
            },
        };
        root.validate()?;
        Ok(root)
    }

    pub(crate) fn validate(self) -> Result<(), CoreError> {
        if (self.generation == 0 && self.page.is_some())
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
    // Every reservation returns an owned boxed lease, including scratch
    // reservations whose payload itself stays on the caller's stack.
    let bytes = bytes
        .checked_add(LEASE_ALLOWANCE)
        .ok_or(CoreError::CapacityDenied)?;
    admission
        .reserve_workspace(bytes as u64)
        .map_err(Into::into)
}

struct PageBuffer {
    bytes: Vec<u8>,
    _lease: Box<dyn ResidentLease>,
}

impl PageBuffer {
    const fn payload_request_bytes() -> usize {
        DIRECTORY_PAGE_BYTES + std::mem::size_of::<Self>() + ALLOCATION_ALLOWANCE
    }
    fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        let lease = reserve(admission, Self::payload_request_bytes())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(DIRECTORY_PAGE_BYTES)
            .map_err(|_| CoreError::CapacityDenied)?;
        if bytes.capacity() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::CapacityDenied);
        }
        bytes.resize(DIRECTORY_PAGE_BYTES, 0);
        Ok(Self {
            bytes,
            _lease: lease,
        })
    }
}

impl std::ops::Deref for PageBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::ops::DerefMut for PageBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl AsRef<[u8]> for PageBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl AsMut<[u8]> for PageBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

struct PendingPage<B = PageBuffer> {
    buffer: B,
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
}
impl<'a> PendingPage<&'a mut [u8]> {
    fn borrowed(buffer: &'a mut [u8]) -> Self {
        buffer.fill(0);
        Self {
            buffer,
            used: HEADER_BYTES,
            count: 0,
            entries: 0,
        }
    }
}
impl<B: AsRef<[u8]> + AsMut<[u8]>> PendingPage<B> {
    fn fits(&self, key_len: usize, value_len: usize) -> bool {
        self.used + key_len + value_len <= DIRECTORY_PAGE_BYTES
    }

    fn append(
        &mut self,
        key: DirectoryKey<'_>,
        value: &[u8],
        entries: u64,
    ) -> Result<(), CoreError> {
        let total = self
            .entries
            .checked_add(entries)
            .ok_or(CoreError::InvalidInput("directory entry count overflow"))?;
        let key_end = self.used + key.encoded_len();
        key.encode(&mut self.buffer.as_mut()[self.used..key_end]);
        self.buffer.as_mut()[key_end..key_end + value.len()].copy_from_slice(value);
        self.used = key_end + value.len();
        self.count += 1;
        self.entries = total;
        Ok(())
    }

    fn reset(&mut self) {
        self.buffer.as_mut().fill(0);
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
            .fits(key.encoded_len(), LEAF_VALUE_BYTES)
        {
            let carry = self.flush(0)?;
            self.insert_child(1, carry)?;
        }
        let mut encoded = [0; LEAF_VALUE_BYTES];
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
                .fits(carry.key_len, BRANCH_VALUE_BYTES)
            {
                None
            } else {
                Some(self.flush(level)?)
            };
            let mut value = [0; BRANCH_VALUE_BYTES];
            carry.page.encode(&mut value[..PAGE_REF_BYTES]);
            value[PAGE_REF_BYTES..].copy_from_slice(&carry.entries.to_le_bytes());
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
        let sha256 = page_digest(bytes);
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let reference = self.backend.append_page(bytes)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        reference.validate()?;
        if reference.sha256 != sha256 {
            return Err(CoreError::Corrupt("appended directory page digest differs"));
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
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(DirectoryRoot {
            group_id: self.group_id,
            generation: self.generation,
            page,
            height,
            entries: self.entries,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
std::thread_local! {
    static PARSED_ENTRIES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn page_entry(bytes: &[u8], at: usize, used: usize) -> Result<(Entry<'_>, usize), CoreError> {
    #[cfg(test)]
    PARSED_ENTRIES.with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current + 1));
        }
    });
    if at > used {
        return Err(CoreError::Corrupt("directory entry exceeds page"));
    }
    let (key, key_len) = decode_key(&bytes[at..used])?;
    let end = at + key_len + value_bytes(bytes[44]);
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
    if bytes.len() != DIRECTORY_PAGE_BYTES || page_digest(bytes) != reference.sha256 {
        return Err(CoreError::Corrupt("directory page digest differs"));
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
            DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES])?;
            let count = le_u64(&entry.value[PAGE_REF_BYTES..]);
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

pub(crate) const fn point_bounds_request_bytes() -> u64 {
    (std::mem::size_of::<Bounds>() + LEASE_ALLOWANCE) as u64
}
pub(crate) const fn point_page_request_bytes() -> u64 {
    (PageBuffer::payload_request_bytes() + LEASE_ALLOWANCE) as u64
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
        self.entries = le_u64(&entry.value[PAGE_REF_BYTES..]);
        self.level = info.level - 1;
        self.generation = info.generation;
        DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES])
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

#[derive(Clone, Copy)]
struct ReadFrame {
    reference: DirectoryPageRef,
    count: usize,
    next_child: usize,
}

/// Reusable point/proof/warming scratch admitted before an effectful operation.
/// It owns one page buffer and covers the maximum simultaneous fixed reader
/// temporaries. Reuse does not reserve or allocate; backend retention remains
/// the caller's choice. The exact admission owner cannot be substituted.
pub(crate) struct DirectoryReadWorkspace {
    // Page bytes and traversal shell share one actual constructor admission.
    // Field order retires the allocation before its exact lease.
    buffer: Vec<u8>,
    admission: Arc<dyn StorageAdmission>,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryReadWorkspace {
    const fn payload_request_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Bounds>()
            + std::mem::size_of::<[Option<ReadFrame>; MAX_HEIGHT]>()
            + 2 * std::mem::size_of::<PageInfo>()
            + 2 * std::mem::size_of::<Entry<'_>>()
            + DIRECTORY_PAGE_BYTES
            + ALLOCATION_ALLOWANCE
    }
    pub(crate) const fn request_bytes() -> u64 {
        (Self::payload_request_bytes() + LEASE_ALLOWANCE) as u64
    }
    pub(crate) fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        Self::for_enclosing_owner::<Self>(admission)
    }

    /// Admit the actual enclosing inline owner together with this workspace.
    /// The enclosing type keeps this field last, so the one lease outlives its
    /// other fields. This replaces only the inline shell charge; page capacity,
    /// simultaneous traversal temporaries and allocation allowance remain.
    pub(crate) fn for_enclosing_owner<T>(
        admission: &Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        let extra_shell = std::mem::size_of::<T>()
            .checked_sub(std::mem::size_of::<Self>())
            .ok_or(CoreError::InvalidInput(
                "enclosing directory owner is smaller than workspace",
            ))?;
        let bytes = Self::payload_request_bytes()
            .checked_add(extra_shell)
            .ok_or(CoreError::CapacityDenied)?;
        let lease = reserve(admission, bytes)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(DIRECTORY_PAGE_BYTES)
            .map_err(|_| CoreError::CapacityDenied)?;
        if buffer.capacity() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::CapacityDenied);
        }
        buffer.resize(DIRECTORY_PAGE_BYTES, 0);
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Self {
            buffer,
            admission: admission.clone(),
            _lease: lease,
        })
    }

    fn check(&self, admission: &Arc<dyn StorageAdmission>) -> Result<(), CoreError> {
        if !Arc::ptr_eq(&self.admission, admission) {
            return Err(CoreError::InvalidInput(
                "directory workspace belongs to another admission owner",
            ));
        }
        admission.check_owner().map_err(|_| CoreError::OwnerFailed)
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
        buffer: &mut [u8],
        root: DirectoryRoot,
        reference: DirectoryPageRef,
        bounds: &Bounds,
    ) -> Result<PageInfo, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.backend.read_page(reference, buffer)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let info = validate_page(buffer, root, reference)?;
        bounds.check(buffer, info)?;
        Ok(info)
    }

    /// Read selected pages created at or after `generation` through this
    /// backend, so a cached backend can retain the final published COW tree.
    /// Older child pages are validated once and their subtrees are skipped.
    /// Only pages reachable from `root` are read; earlier private mutations
    /// from the same batch are never admitted through their orphaned roots.
    ///
    /// One page buffer and a fixed path suffice. On sibling changes, ancestor
    /// bounds are reconstructed from the root rather than retaining a pair
    /// of maximum-size separator keys at every level. Fitting cached trees
    /// serve these ancestor rereads from memory. This does not publish roots
    /// or itself prove full residency; callers inspect uncached/eviction
    /// counters, including direct fallback after cache admission denial.
    pub(crate) fn warm_generation(
        &self,
        root: DirectoryRoot,
        generation: u64,
    ) -> Result<(), CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        if generation > root.generation {
            return Err(CoreError::InvalidInput(
                "warm generation exceeds directory root",
            ));
        }
        let Some(reference) = root.page else {
            return Ok(());
        };
        let _workspace = reserve(
            &self.admission,
            std::mem::size_of::<[Option<ReadFrame>; MAX_HEIGHT]>()
                + std::mem::size_of::<Bounds>()
                + std::mem::size_of::<PageInfo>(),
        )?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        self.warm_generation_in(root, generation, reference, &mut buffer)
    }

    /// As `warm_generation`, using previously admitted fixed scratch. This
    /// method makes no reservation or buffer allocation of its own.
    pub(crate) fn warm_generation_with_workspace(
        &self,
        root: DirectoryRoot,
        generation: u64,
        workspace: &mut DirectoryReadWorkspace,
    ) -> Result<(), CoreError> {
        workspace.check(&self.admission)?;
        root.validate()?;
        if generation > root.generation {
            return Err(CoreError::InvalidInput(
                "warm generation exceeds directory root",
            ));
        }
        let Some(reference) = root.page else {
            return Ok(());
        };
        self.warm_generation_in(root, generation, reference, &mut workspace.buffer)
    }

    fn warm_generation_in(
        &self,
        root: DirectoryRoot,
        generation: u64,
        mut reference: DirectoryPageRef,
        buffer: &mut [u8],
    ) -> Result<(), CoreError> {
        let mut frames = [None; MAX_HEIGHT];
        let mut depth = 0;
        let mut bounds = Bounds::root(root);
        loop {
            let info = self.load(buffer, root, reference, &bounds)?;
            if info.level != 0 && info.generation >= generation {
                frames[depth] = Some(ReadFrame {
                    reference,
                    count: info.count,
                    next_child: 1,
                });
                depth += 1;
                reference = bounds.child(buffer, info, 0)?;
                continue;
            }
            loop {
                if depth == 0 {
                    return Ok(());
                }
                let frame = frames[depth - 1].as_mut().expect("expanded ancestor");
                if frame.next_child == frame.count {
                    depth -= 1;
                    continue;
                }
                frame.next_child += 1;
                bounds = Bounds::root(root);
                for frame in frames[..depth].iter().flatten() {
                    let info = self.load(buffer, root, frame.reference, &bounds)?;
                    if info.count != frame.count {
                        return Err(CoreError::Corrupt("directory changed during cache warming"));
                    }
                    reference = bounds.child(buffer, info, frame.next_child - 1)?;
                }
                break;
            }
        }
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
        let Some(reference) = root.page else {
            return Ok(None);
        };
        let _workspace = reserve(&self.admission, std::mem::size_of::<Bounds>())?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        self.get_in(root, key, reference, &mut buffer)
    }

    /// As `get`, using previously admitted fixed scratch. The returned value
    /// is inline and does not borrow the reusable page buffer.
    pub(crate) fn get_with_workspace(
        &self,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
        workspace: &mut DirectoryReadWorkspace,
    ) -> Result<Option<DirectoryValue>, CoreError> {
        workspace.check(&self.admission)?;
        root.validate()?;
        key.validate()?;
        let Some(reference) = root.page else {
            return Ok(None);
        };
        self.get_in(root, key, reference, &mut workspace.buffer)
    }

    fn get_in(
        &self,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
        mut reference: DirectoryPageRef,
        buffer: &mut [u8],
    ) -> Result<Option<DirectoryValue>, CoreError> {
        let mut bounds = Bounds::root(root);
        loop {
            let info = self.load(buffer, root, reference, &bounds)?;
            let mut selected = None;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(buffer, at, info.used)?;
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
            reference = bounds.child(buffer, info, index)?;
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
                            entry.key_bytes.len()
                                + std::mem::size_of::<DirectoryRecord>()
                                + ALLOCATION_ALLOWANCE,
                        )?;
                        let mut key = Vec::new();
                        key.try_reserve_exact(entry.key_bytes.len())
                            .map_err(|_| CoreError::CapacityDenied)?;
                        if key.capacity() != entry.key_bytes.len() {
                            return Err(CoreError::CapacityDenied);
                        }
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
                    let mut at = HEADER_BYTES;
                    for index in 0..info.count {
                        let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                        if entry.key > target {
                            break;
                        }
                        selected = index;
                        at = end;
                    }
                    reference = bounds.child(&buffer.bytes, info, selected)?;
                }
                // Reload and execute the leaf output path in the outer
                // loop. A valid separator equals the reached leaf minimum.
                next_len = 0;
                continue;
            }
            let mut selected = 0;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                if entry.key > lower {
                    break;
                }
                selected = index;
                at = end;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AdmissionError, OwnerFailed};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

    mod leaves {
        use super::*;
        include!("directory_leaf_tests.rs");
    }
    mod packing {
        use super::*;
        include!("directory_pack_tests.rs");
    }

    mod reachability {
        include!("directory_reachability_tests.rs");
    }

    mod workspace {
        include!("directory_workspace_tests.rs");
    }

    mod batch {
        include!("directory_batch_tests.rs");
    }

    mod splitting {
        include!("directory_split_tests.rs");
    }

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
                sha256: page_digest(bytes),
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

        fn quote_cache_memory(
            &self,
            bytes: u64,
        ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
            crate::cache_test::quote::<Self>(bytes)
        }
        fn reserve_cache_memory(
            self: std::sync::Arc<Self>,
            bytes: u64,
        ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
            crate::cache_test::reserve(self, bytes)
        }
    }
    impl crate::cache_test::Provider for Admission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            let used = self
                .0
                .used
                .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |used| {
                    used.checked_add(bytes).filter(|next| *next <= self.0.limit)
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            self.0.peak.fetch_max(used + bytes, AtomicOrdering::Relaxed);
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
            self.0.used.fetch_sub(bytes, AtomicOrdering::AcqRel);
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
    fn canonical_root_codec_binds_the_complete_reference_and_shape() {
        let root = DirectoryRoot {
            group_id: GROUP,
            generation: 17,
            page: Some(DirectoryPageRef {
                arena_id: 9,
                page_index: 13,
                sha256: std::array::from_fn(|index| index as u8),
            }),
            height: 3,
            entries: 1200,
        };
        let encoded = root.encode().unwrap();
        assert_eq!(DirectoryRoot::decode(&encoded).unwrap(), root);
        assert_eq!(&encoded[56..88], &root.page.unwrap().sha256);
        for at in (26..32).chain(88..96) {
            let mut damaged = encoded;
            damaged[at] = 1;
            assert!(DirectoryRoot::decode(&damaged).is_err(), "reserved {at}");
        }
        for at in 56..88 {
            let mut different = encoded;
            different[at] ^= 1;
            assert_ne!(DirectoryRoot::decode(&different).unwrap(), root);
        }
        for (at, byte) in [(24, 0), (24, 49), (25, 2)] {
            let mut damaged = encoded;
            damaged[at] = byte;
            assert!(DirectoryRoot::decode(&damaged).is_err());
        }
        for range in [16..24, 32..40, 40..48] {
            let mut damaged = encoded;
            damaged[range].fill(0);
            assert!(DirectoryRoot::decode(&damaged).is_err());
        }
        for generation in [0, 17] {
            let empty = DirectoryRoot {
                generation,
                ..empty_root()
            };
            let encoded = empty.encode().unwrap();
            assert_eq!(DirectoryRoot::decode(&encoded).unwrap(), empty);
            for at in 40..88 {
                let mut damaged = encoded;
                damaged[at] = 1;
                assert!(DirectoryRoot::decode(&damaged).is_err(), "absent {at}");
            }
        }
    }

    // Solve a four-byte CRC patch so the corruption remains CRC32C-valid.
    // Both edited fields belong to a row value, leaving page canonicality
    // intact. The cryptographic parent reference must still reject it.
    fn restore_crc(bytes: &mut [u8], patch: usize, expected: u32) {
        use crate::segment::crc32c;
        let base = crc32c(bytes);
        let mut basis = [(0u32, 0u32); 32];
        for bit in 0..32 {
            bytes[patch + bit / 8] ^= 1 << (bit % 8);
            let mut delta = crc32c(bytes) ^ base;
            bytes[patch + bit / 8] ^= 1 << (bit % 8);
            let mut mask = 1u32 << bit;
            while delta != 0 {
                let pivot = 31 - delta.leading_zeros() as usize;
                if basis[pivot].0 == 0 {
                    basis[pivot] = (delta, mask);
                    break;
                }
                delta ^= basis[pivot].0;
                mask ^= basis[pivot].1;
            }
        }
        let mut delta = base ^ expected;
        let mut patch_mask = 0;
        while delta != 0 {
            let pivot = 31 - delta.leading_zeros() as usize;
            assert_ne!(basis[pivot].0, 0);
            delta ^= basis[pivot].0;
            patch_mask ^= basis[pivot].1;
        }
        for bit in 0..32 {
            if patch_mask & (1u32 << bit) != 0 {
                bytes[patch + bit / 8] ^= 1 << (bit % 8);
            }
        }
        assert_eq!(crc32c(bytes), expected);
    }

    #[test]
    fn parent_sha_rejects_canonical_child_substitution_with_the_same_crc() {
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        for id in 0..8 {
            builder
                .push(DirectoryKey::row("t", &long_key(id)), value(1, id as u64))
                .unwrap();
        }
        let root = builder.finish().unwrap();
        assert_eq!(root.height, 2);
        let mut pages = backend.pages.lock().unwrap();
        let root_page = &pages[root.page.unwrap().page_index as usize];
        let info = validate_page(root_page, root, root.page.unwrap()).unwrap();
        let child = DirectoryPageRef::decode(
            &nth_entry(root_page, info, 0).unwrap().value[..PAGE_REF_BYTES],
        )
        .unwrap();
        let page = &mut pages[child.page_index as usize];
        let old_crc = crate::segment::crc32c(page);
        let value_at = HEADER_BYTES + DirectoryKey::row("t", &long_key(0)).encoded_len();
        page[value_at + 16] ^= 1;
        restore_crc(page, value_at + 28, old_crc);
        let changed = DirectoryPageRef {
            sha256: page_digest(page),
            ..child
        };
        assert_ne!(changed.sha256, child.sha256);
        // The changed bytes are independently valid, but are not the child
        // named by this immutable parent or its selected durable root.
        validate_page(page, root, changed).unwrap();
        drop(pages);
        let reader = DirectoryReader::new(&backend, admission);
        assert!(matches!(
            reader.get(root, DirectoryKey::row("t", &long_key(0))),
            Err(CoreError::Corrupt("directory page digest differs"))
        ));
    }

    #[test]
    fn generation_warming_retains_final_split_pages_and_skips_private_orphans() {
        use crate::cache::CacheConfig;
        use crate::page_cache::CachedDirectoryBackend;
        use std::collections::BTreeSet;

        fn reachable(backend: &MemoryPages, root: DirectoryRoot) -> BTreeSet<u64> {
            let pages = backend.pages.lock().unwrap();
            let mut pending = root.page.into_iter().collect::<Vec<_>>();
            let mut reached = BTreeSet::new();
            while let Some(reference) = pending.pop() {
                assert!(reached.insert(reference.page_index));
                let page = &pages[reference.page_index as usize];
                let info = validate_page(page, root, reference).unwrap();
                if info.level != 0 {
                    for index in 0..info.count {
                        pending.push(
                            DirectoryPageRef::decode(
                                &nth_entry(page, info, index).unwrap().value[..PAGE_REF_BYTES],
                            )
                            .unwrap(),
                        );
                    }
                }
            }
            reached
        }

        let backend = MemoryPages::default();
        let admission = Admission::new(8 << 20);
        let cached = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 4 << 20,
            },
        );
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        for id in 0..90 {
            builder
                .push(DirectoryKey::row("t", &long_key(id)), value(1, id as u64))
                .unwrap();
        }
        let old = builder.finish().unwrap();
        let reader = DirectoryReader::new(&cached, admission.clone());
        reader.warm_generation(old, 0).unwrap();
        let mut expected = reachable(&backend, old);
        assert_eq!(cached.stats().unwrap().entries, expected.len());
        let before_private = backend.pages.lock().unwrap().len();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let private = mutator
            .set(
                old,
                2,
                DirectoryKey::row("t", &long_key(90)),
                Some(value(2, 90)),
            )
            .unwrap();
        let selected = mutator
            .set(
                private,
                2,
                DirectoryKey::row("t", &long_key(91)),
                Some(value(2, 91)),
            )
            .unwrap();
        let selected = mutator.finish(selected).unwrap();
        assert_eq!(cached.stats().unwrap().entries, expected.len());
        let selected_pages = reachable(&backend, selected);
        let final_new_pages = selected_pages
            .iter()
            .filter(|&&id| id as usize >= before_private)
            .count();
        let private_count = backend.pages.lock().unwrap().len() - before_private;
        assert!(
            final_new_pages < private_count,
            "intermediate COW paths are orphaned"
        );
        expected.extend(selected_pages);
        let reads = backend.reads.load(AtomicOrdering::Relaxed);
        reader.warm_generation(selected, 2).unwrap();
        assert_eq!(cached.stats().unwrap().entries, expected.len());
        assert_eq!(
            backend.reads.load(AtomicOrdering::Relaxed) - reads,
            final_new_pages
        );
        let reads = backend.reads.load(AtomicOrdering::Relaxed);
        reader.warm_generation(selected, 2).unwrap();
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
        assert_eq!(cached.stats().unwrap().uncached_loads, 0);
        assert_eq!(cached.stats().unwrap().evictions, 0);
    }

    #[test]
    fn walker_resumes_with_hard_work_limits_and_preserves_old_roots() {
        use std::collections::BTreeSet;
        fn pages(backend: &MemoryPages, root: DirectoryRoot) -> BTreeSet<(u64, u64, [u8; 32])> {
            let stored = backend.pages.lock().unwrap();
            let mut pending = root.page.into_iter().collect::<Vec<_>>();
            let mut found = BTreeSet::new();
            while let Some(reference) = pending.pop() {
                assert!(found.insert((reference.arena_id, reference.page_index, reference.sha256)));
                let bytes = &stored[reference.page_index as usize];
                let info = validate_page(bytes, root, reference).unwrap();
                if info.level != 0 {
                    for index in 0..info.count {
                        pending.push(
                            DirectoryPageRef::decode(
                                &nth_entry(bytes, info, index).unwrap().value[..PAGE_REF_BYTES],
                            )
                            .unwrap(),
                        );
                    }
                }
            }
            found
        }
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut small = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        small
            .push(
                DirectoryKey::table("small"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        let small = small.finish().unwrap();
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        builder
            .push(
                DirectoryKey::table("t"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        for index in 0..90 {
            builder
                .push(
                    DirectoryKey::row("t", &long_key(index)),
                    value(1, index as u64),
                )
                .unwrap();
        }
        let old = builder.finish().unwrap();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let current = mutator
            .set(old, 2, DirectoryKey::row("t", &long_key(17)), None)
            .unwrap();
        let current = mutator
            .set(
                current,
                2,
                DirectoryKey::row("t", &long_key(90)),
                Some(value(2, 90)),
            )
            .unwrap();
        let current = mutator.finish(current).unwrap();
        drop(mutator_workspace);
        let mut footprints = Vec::new();
        for root in [small, old, current] {
            for limit in [1, 7] {
                let mut walker = DirectoryWalker::new(root, admission.clone()).unwrap();
                assert_eq!(walker.root(), root);
                let footprint = admission.0.used.load(AtomicOrdering::Relaxed);
                footprints.push(footprint);
                let zero = walker
                    .step(
                        &backend,
                        0,
                        |_| panic!("zero-work page"),
                        |_| panic!("zero-work value"),
                    )
                    .unwrap();
                assert_eq!(zero, DirectoryWalkProgress::default());
                let mut reached = BTreeSet::new();
                let mut values = Vec::new();
                let mut total_work = 0;
                let mut total_entries = 0;
                loop {
                    let reads = backend.reads.load(AtomicOrdering::Relaxed);
                    let before = reached.len();
                    let progress = walker
                        .step(
                            &backend,
                            limit,
                            |page| {
                                assert!(reached.insert((
                                    page.arena_id,
                                    page.page_index,
                                    page.sha256
                                )));
                                Ok(())
                            },
                            |value| {
                                values.push(value.segment_id - 1);
                                Ok(())
                            },
                        )
                        .unwrap();
                    assert!(progress.work <= limit);
                    assert_eq!(progress.pages, reached.len() - before);
                    assert_eq!(
                        progress.work,
                        progress.entries + backend.reads.load(AtomicOrdering::Relaxed) - reads
                    );
                    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), footprint);
                    total_work += progress.work;
                    total_entries += progress.entries;
                    if progress.complete {
                        break;
                    }
                    assert!(progress.work > 0);
                }
                assert_eq!(reached, pages(&backend, root));
                let expected = (0..=90)
                    .filter(|&id| {
                        if root == small {
                            false
                        } else if root == old {
                            id < 90
                        } else {
                            id != 17
                        }
                    })
                    .collect::<Vec<_>>();
                assert_eq!(values, expected);
                assert_eq!(total_entries, root.entries as usize + reached.len() - 1);
                assert!(
                    total_work <= total_entries + 4 * reached.len(),
                    "parent restoration reread too much"
                );
                assert!(
                    walker
                        .step(
                            &backend,
                            3,
                            |_| panic!("complete page"),
                            |_| panic!("complete value")
                        )
                        .unwrap()
                        .complete
                );
                drop(walker);
                assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
            }
        }
        assert!(footprints.iter().all(|&bytes| bytes == footprints[0]));
    }

    #[test]
    fn walker_empty_table_only_and_cancellation_release_fixed_scratch() {
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut empty = DirectoryWalker::new(empty_root(), admission.clone()).unwrap();
        assert!(
            empty
                .step(
                    &backend,
                    0,
                    |_| panic!("empty page"),
                    |_| panic!("empty value")
                )
                .unwrap()
                .complete
        );
        drop(empty);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        builder
            .push(
                DirectoryKey::table("table-only"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        let root = builder.finish().unwrap();
        let mut walker = DirectoryWalker::new(root, admission.clone()).unwrap();
        let mut page_count = 0;
        let first = walker
            .step(
                &backend,
                1,
                |_| {
                    page_count += 1;
                    Ok(())
                },
                |_| panic!("table has no row"),
            )
            .unwrap();
        assert_eq!(first.work, 1);
        assert_eq!(page_count, 1);
        let next = walker
            .step(
                &backend,
                2,
                |_| panic!("page visited twice"),
                |_| panic!("table has no row"),
            )
            .unwrap();
        assert_eq!(next.entries, 1);
        assert!(next.complete);
        drop(walker);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        let denied = Admission::new(1);
        assert!(matches!(
            DirectoryWalker::new(root, denied.clone()),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);
        let mut cancelled = DirectoryWalker::new(root, admission.clone()).unwrap();
        cancelled.step(&backend, 1, |_| Ok(()), |_| Ok(())).unwrap();
        drop(cancelled);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn walker_operational_failures_poison_after_partial_callbacks() {
        struct Fault<'a> {
            backend: &'a MemoryPages,
            admission: Arc<Admission>,
            mode: usize,
            calls: AtomicUsize,
        }
        impl DirectoryBackend for Fault<'_> {
            fn read_page(
                &self,
                reference: DirectoryPageRef,
                out: &mut [u8],
            ) -> Result<(), CoreError> {
                let call = self.calls.fetch_add(1, AtomicOrdering::Relaxed);
                if call == 1 && self.mode == 0 {
                    return Err(CoreError::CapacityDenied);
                }
                self.backend.read_page(reference, out)?;
                if call == 1 && self.mode == 1 {
                    self.admission.0.failed.store(true, AtomicOrdering::Relaxed);
                }
                Ok(())
            }
            fn append_page(&self, _: &[u8]) -> Result<DirectoryPageRef, CoreError> {
                panic!("read-only walk")
            }
            fn sync_pages(&self) -> Result<(), CoreError> {
                panic!("read-only walk")
            }
        }
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        for index in 0..12 {
            builder
                .push(
                    DirectoryKey::row("t", &long_key(index)),
                    value(1, index as u64),
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        for mode in 0..4 {
            admission.0.failed.store(false, AtomicOrdering::Relaxed);
            let fault = Fault {
                backend: &backend,
                admission: admission.clone(),
                mode,
                calls: AtomicUsize::new(0),
            };
            let mut walker = DirectoryWalker::new(root, admission.clone()).unwrap();
            let mut pages = 0;
            let error = walker
                .step(
                    &fault,
                    1000,
                    |_| {
                        pages += 1;
                        if mode == 2 && pages == 2 {
                            Err(CoreError::CapacityDenied)
                        } else {
                            Ok(())
                        }
                    },
                    |_| {
                        if mode == 3 {
                            Err(CoreError::Corrupt("callback refused value"))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
            assert!(pages > 0);
            assert!(matches!(
                error,
                CoreError::CapacityDenied | CoreError::OwnerFailed | CoreError::Corrupt(_)
            ));
            assert!(matches!(
                walker.step(
                    &fault,
                    1,
                    |_| panic!("poisoned page"),
                    |_| panic!("poisoned value")
                ),
                Err(CoreError::OwnerFailed)
            ));
            drop(walker);
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
    }

    #[test]
    fn walker_rejects_digest_scope_parent_range_and_generation_corruption() {
        for corruption in 0..4 {
            let backend = MemoryPages::default();
            let admission = Admission::new(160 << 10);
            let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            for index in 0..12 {
                builder
                    .push(
                        DirectoryKey::row("t", &long_key(index)),
                        value(1, index as u64),
                    )
                    .unwrap();
            }
            let mut root = builder.finish().unwrap();
            let mut pages = backend.pages.lock().unwrap();
            let parent_index = root.page.unwrap().page_index as usize;
            match corruption {
                0 => pages[parent_index][0] ^= 1,
                1 => {
                    pages[parent_index][20] ^= 1;
                    root.page.as_mut().unwrap().sha256 = page_digest(&pages[parent_index]);
                }
                2 => {
                    pages[parent_index][HEADER_BYTES + KEY_HEADER_BYTES] = b'a';
                    root.page.as_mut().unwrap().sha256 = page_digest(&pages[parent_index]);
                }
                3 => {
                    let info =
                        validate_page(&pages[parent_index], root, root.page.unwrap()).unwrap();
                    let first = nth_entry(&pages[parent_index], info, 0).unwrap();
                    let child = DirectoryPageRef::decode(&first.value[..PAGE_REF_BYTES]).unwrap();
                    let digest_at = HEADER_BYTES + first.key_bytes.len() + 16;
                    pages[child.page_index as usize][36..44].copy_from_slice(&2u64.to_le_bytes());
                    let digest = page_digest(&pages[child.page_index as usize]);
                    pages[parent_index][digest_at..digest_at + 32].copy_from_slice(&digest);
                    root.page.as_mut().unwrap().sha256 = page_digest(&pages[parent_index]);
                    root.generation = 2;
                }
                _ => unreachable!(),
            }
            drop(pages);
            let mut walker = DirectoryWalker::new(root, admission.clone()).unwrap();
            assert!(
                matches!(
                    walker.step(&backend, 1000, |_| Ok(()), |_| Ok(())),
                    Err(CoreError::Corrupt(_))
                ),
                "corruption {corruption}"
            );
            drop(walker);
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
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
    fn successor_branch_work_is_linear_in_fanout_including_redescent() {
        const FANOUT: usize =
            (DIRECTORY_PAGE_BYTES - HEADER_BYTES) / (KEY_HEADER_BYTES + 1 + 8 + BRANCH_VALUE_BYTES);
        let backend = MemoryPages::default();
        let admission = Admission::new(128 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        for id in 0..FANOUT {
            let row = (id as u64).to_be_bytes();
            let key = DirectoryKey::row("t", &row);
            let mut leaf = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            leaf.push(key, value(1, id as u64)).unwrap();
            let root = leaf.finish().unwrap();
            let mut encoded = [0; MAX_ENCODED_KEY];
            key.encode(&mut encoded[..key.encoded_len()]);
            builder
                .insert_child(
                    1,
                    Carry {
                        key: encoded,
                        key_len: key.encoded_len(),
                        page: root.page.unwrap(),
                        entries: 1,
                    },
                )
                .unwrap();
        }
        builder.entries = FANOUT as u64;
        let root = builder.finish().unwrap();
        assert_eq!(root.height, 2);
        let reader = DirectoryReader::new(&backend, admission);
        for exclusive in [false, true] {
            PARSED_ENTRIES.with(|count| {
                count.set(Some(0));
                // Each leaf has only one key, so exclusive mode exhausts
                // it and exercises the second root-to-leaf descent.
                let id = FANOUT as u64 - 3;
                let result = reader
                    .next(root, DirectoryKey::row("t", &id.to_be_bytes()), exclusive)
                    .unwrap()
                    .unwrap();
                let work = count.replace(None).unwrap();
                assert_eq!(result.value, value(1, id + u64::from(exclusive)));
                assert!(
                    work <= 12 * FANOUT,
                    "parsed {work} entries at fanout {FANOUT}"
                );
            });
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
        let root = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 0)
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
    fn capacity_denial_precedes_page_allocation_and_outputs_remain_admitted() {
        let backend = MemoryPages::default();
        let admission = Admission::new(1);
        assert!(matches!(
            DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1),
            Err(CoreError::CapacityDenied)
        ));
        assert!(backend.pages.lock().unwrap().is_empty());
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);

        let mut builder =
            DirectoryBuilder::new(&backend, Admission::new(128 << 10), GROUP, 1).unwrap();
        builder
            .push(
                DirectoryKey::table("t"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        let root = builder.finish().unwrap();
        let reader = DirectoryReader::new(&backend, admission.clone());
        assert!(matches!(
            reader.get(root, DirectoryKey::table("t")),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);

        // The reader can hold its page and scratch, but cannot allocate an
        // output outside that same limit. All temporary charges unwind.
        let workspace = DIRECTORY_PAGE_BYTES
            + std::mem::size_of::<PageBuffer>()
            + ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE
            + std::mem::size_of::<Bounds>()
            + MAX_ENCODED_KEY
            + LEASE_ALLOWANCE;
        let admission = Admission::new(workspace as u64);
        let reader = DirectoryReader::new(&backend, admission.clone());
        assert!(matches!(
            reader.next(root, DirectoryKey::table("t"), false),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
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
                root.page.as_mut().unwrap().sha256 = page_digest(page);
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

    fn empty_root() -> DirectoryRoot {
        DirectoryRoot {
            group_id: GROUP,
            generation: 0,
            page: None,
            height: 0,
            entries: 0,
        }
    }

    type ModelKey = (String, Option<Vec<u8>>);

    fn model_key(key: &ModelKey) -> DirectoryKey<'_> {
        DirectoryKey {
            table: &key.0,
            row: key.1.as_deref(),
        }
    }

    fn assert_directory_model(
        backend: &dyn DirectoryBackend,
        admission: Arc<dyn StorageAdmission>,
        root: DirectoryRoot,
        model: &BTreeMap<ModelKey, DirectoryValue>,
    ) {
        let reader = DirectoryReader::new(backend, admission);
        assert_eq!(root.entries, model.len() as u64);
        let mut previous = ("a".to_owned(), None);
        let mut exclusive = false;
        for (expected_key, expected_value) in model {
            let record = reader
                .next(root, model_key(&previous), exclusive)
                .unwrap()
                .unwrap();
            assert_eq!(record.key(), model_key(expected_key));
            assert_eq!(&record.value, expected_value);
            assert_eq!(
                reader.get(root, model_key(expected_key)).unwrap(),
                Some(*expected_value)
            );
            previous = expected_key.clone();
            exclusive = true;
        }
        assert!(
            reader
                .next(root, model_key(&previous), exclusive)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cow_mutations_and_snapshots_match_ordered_model() {
        let backend = MemoryPages::default();
        let admission = Admission::new(192 << 10);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let mut root = empty_root();
        let mut model = BTreeMap::new();
        let mut snapshots = Vec::new();
        let mut random = 0x4931_a817_2d40_9c61u64;
        for step in 0..720 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let id = (random % 180) as usize;
            let table = match id % 4 {
                0 => "accounts".to_owned(),
                1 => "accounts-long".to_owned(),
                2 => "documents".to_owned(),
                _ => "z".repeat(MAX_TABLE_BYTES),
            };
            let bytes = long_key(id);
            let key = (
                table,
                if id.is_multiple_of(29) {
                    None
                } else {
                    Some(
                        bytes[..if id.is_multiple_of(5) {
                            MAX_KEY_BYTES
                        } else {
                            8 + id % 61
                        }]
                            .to_vec(),
                    )
                },
            );
            let generation = step as u64 / 3 + 1;
            let new_value = if random % 7 < 3 {
                None
            } else if key.1.is_none() {
                Some(DirectoryValue::Table {
                    birth_seq: generation,
                })
            } else {
                Some(value(generation, random % 1_000_000))
            };
            let before = backend.pages.lock().unwrap().len();
            let before_reads = backend.reads.load(AtomicOrdering::Relaxed);
            let previous_height = root.height;
            root = mutator
                .set(root, generation, model_key(&key), new_value)
                .unwrap();
            let appended = backend.pages.lock().unwrap().len() - before;
            assert!(appended <= 2 * usize::from(previous_height.max(1)) + 1);
            assert!(
                backend.reads.load(AtomicOrdering::Relaxed) - before_reads
                    <= 4 * usize::from(previous_height.max(1)) + 5
            );
            if let Some(value) = new_value {
                model.insert(key, value);
            } else {
                model.remove(&key);
            }
            if step % 120 == 119 {
                snapshots.push((root, model.clone()));
                assert_directory_model(&backend, admission.clone(), root, &model);
            }
        }
        assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(mutator.finish(root).unwrap(), root);
        assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), 1);
        for (snapshot, model) in snapshots {
            assert_directory_model(&backend, admission.clone(), snapshot, &model);
        }
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn cow_same_value_rewrite_copies_paths_preserving_versions_counts_and_old_roots() {
        let backend = MemoryPages::default();
        let admission = Admission::new(192 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 4).unwrap();
        let table = DirectoryValue::Table { birth_seq: 1 };
        builder.push(DirectoryKey::table("t"), table).unwrap();
        let mut model = BTreeMap::new();
        model.insert(("t".to_owned(), None), table);
        for id in 0..48 {
            let row = value(2, id as u64);
            builder
                .push(DirectoryKey::row("t", &long_key(id)), row)
                .unwrap();
            model.insert(("t".to_owned(), Some(long_key(id).to_vec())), row);
        }
        let old = builder.finish().unwrap();
        assert!(old.height > 1);
        let original_pages = backend.pages.lock().unwrap().clone();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();

        // Ordinary set retains its no-op behavior for an identical value.
        let key = long_key(24);
        let unchanged = mutator
            .set(old, 5, DirectoryKey::row("t", &key), Some(value(2, 24)))
            .unwrap();
        assert_eq!(unchanged.page, old.page);
        assert_eq!(unchanged.generation, 5);
        assert_eq!(backend.pages.lock().unwrap().len(), original_pages.len());

        let rewritten = mutator
            .rewrite(old, 5, DirectoryKey::row("t", &key), value(2, 24))
            .unwrap();
        assert_ne!(rewritten.page, old.page);
        assert_eq!(rewritten.generation, 5);
        assert_eq!(rewritten.height, old.height);
        assert_eq!(rewritten.entries, old.entries);
        assert_eq!(
            backend.pages.lock().unwrap().len() - original_pages.len(),
            usize::from(old.height)
        );
        let before_table = backend.pages.lock().unwrap().len();
        let rewritten_table = mutator
            .rewrite(rewritten, 5, DirectoryKey::table("t"), table)
            .unwrap();
        assert_ne!(rewritten_table.page, rewritten.page);
        assert_eq!(rewritten_table.entries, old.entries);
        assert_eq!(
            backend.pages.lock().unwrap().len() - before_table,
            usize::from(rewritten.height)
        );
        assert_eq!(
            backend.pages.lock().unwrap()[..original_pages.len()],
            original_pages
        );
        assert_eq!(mutator.finish(rewritten_table).unwrap(), rewritten_table);
        for root in [old, unchanged, rewritten, rewritten_table] {
            // Full ordered and point reads check every original row batch_seq
            // and the table birth_seq, not just the rewritten target value.
            assert_directory_model(&backend, admission.clone(), root, &model);
        }
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn cow_maximum_keys_split_remove_pages_and_shrink_root() {
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let mut root = empty_root();
        let table = "t".repeat(MAX_TABLE_BYTES);
        // Insertion alternates between new minimum and maximum keys so
        // separator replacement and both ends of splits are exercised.
        for step in 0..160 {
            let id = if step % 2 == 0 {
                79 - step / 2
            } else {
                80 + step / 2
            };
            root = mutator
                .set(
                    root,
                    1,
                    DirectoryKey::row(&table, &long_key(id)),
                    Some(value(1, id as u64)),
                )
                .unwrap();
        }
        assert!((4..=8).contains(&root.height));
        let snapshot = mutator.finish(root).unwrap();
        for step in 0..159 {
            let id = (step * 73) % 160;
            root = mutator
                .set(root, 2, DirectoryKey::row(&table, &long_key(id)), None)
                .unwrap();
            assert_eq!(root.entries, 159 - step as u64);
        }
        assert_eq!(root.height, 1);
        let survivor = (159 * 73) % 160;
        let reader = DirectoryReader::new(&backend, admission.clone());
        assert_eq!(
            reader
                .get(root, DirectoryKey::row(&table, &long_key(survivor)))
                .unwrap(),
            Some(value(1, survivor as u64))
        );
        root = mutator
            .set(
                root,
                2,
                DirectoryKey::row(&table, &long_key(survivor)),
                None,
            )
            .unwrap();
        assert_eq!(root.height, 0);
        assert_eq!(root.entries, 0);
        assert!(root.page.is_none());
        for id in 0..160 {
            assert_eq!(
                reader
                    .get(snapshot, DirectoryKey::row(&table, &long_key(id)))
                    .unwrap(),
                Some(value(1, id as u64))
            );
        }
        let reinserted = mutator
            .set(
                root,
                3,
                DirectoryKey::row(&table, &long_key(0)),
                Some(value(3, 1000)),
            )
            .unwrap();
        assert_eq!(reinserted.height, 1);
        assert_eq!(
            reader
                .get(reinserted, DirectoryKey::row(&table, &long_key(0)))
                .unwrap(),
            Some(value(3, 1000))
        );
    }

    #[test]
    fn cow_large_tree_mutation_keeps_fixed_workspace_and_path_sized_io() {
        let mut peaks = Vec::new();
        for population in [24, 3000] {
            let backend = MemoryPages::default();
            let mut builder =
                DirectoryBuilder::new(&backend, Admission::new(256 << 10), GROUP, 1).unwrap();
            for id in 0..population {
                builder
                    .push(DirectoryKey::row("t", &long_key(id)), value(1, id as u64))
                    .unwrap();
            }
            let old = builder.finish().unwrap();
            let admission = Admission::new(128 << 10);
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            let before = backend.pages.lock().unwrap().len();
            let reads = backend.reads.load(AtomicOrdering::Relaxed);
            let root = mutator
                .set(
                    old,
                    2,
                    DirectoryKey::row("t", &long_key(population / 2)),
                    Some(value(2, 9000)),
                )
                .unwrap();
            assert_eq!(
                backend.pages.lock().unwrap().len() - before,
                old.height as usize
            );
            assert!(
                backend.reads.load(AtomicOrdering::Relaxed) - reads <= 2 * old.height as usize + 1
            );
            if population == 3000 {
                assert!(before * DIRECTORY_PAGE_BYTES > 100 * (128 << 10));
            }
            assert_eq!(
                mutator
                    .get(old, DirectoryKey::row("t", &long_key(population / 2)))
                    .unwrap(),
                Some(value(1, (population / 2) as u64))
            );
            assert_eq!(
                mutator
                    .get(root, DirectoryKey::row("t", &long_key(population / 2)))
                    .unwrap(),
                Some(value(2, 9000))
            );
            peaks.push(admission.0.peak.load(AtomicOrdering::Relaxed));
            drop(mutator_workspace);
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
        assert_eq!(peaks[0], peaks[1]);
    }

    struct FailingPages {
        inner: MemoryPages,
        appends_remaining: AtomicUsize,
        fail_reads: AtomicBool,
        fail_sync: AtomicBool,
    }

    impl FailingPages {
        fn new() -> Self {
            Self {
                inner: MemoryPages::default(),
                appends_remaining: AtomicUsize::new(usize::MAX),
                fail_reads: AtomicBool::new(false),
                fail_sync: AtomicBool::new(false),
            }
        }
    }

    impl DirectoryBackend for FailingPages {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            if self.fail_reads.load(AtomicOrdering::Relaxed) {
                return Err(CoreError::Io(std::io::Error::other(
                    "injected read failure",
                )));
            }
            self.inner.read_page(reference, out)
        }
        fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            self.appends_remaining
                .fetch_update(
                    AtomicOrdering::Relaxed,
                    AtomicOrdering::Relaxed,
                    |remaining| remaining.checked_sub(1),
                )
                .map_err(|_| {
                    CoreError::Io(std::io::Error::other("injected late append failure"))
                })?;
            self.inner.append_page(bytes)
        }
        fn sync_pages(&self) -> Result<(), CoreError> {
            if self.fail_sync.load(AtomicOrdering::Relaxed) {
                return Err(CoreError::Io(std::io::Error::other(
                    "injected sync failure",
                )));
            }
            self.inner.sync_pages()
        }
    }

    #[test]
    fn cow_failed_appends_only_orphan_pages_and_poison_private_batch() {
        let backend = FailingPages::new();
        let admission = Admission::new(160 << 10);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        let table = "t".repeat(MAX_TABLE_BYTES);
        for id in 0..90 {
            builder
                .push(
                    DirectoryKey::row(&table, &long_key(id * 2 + 2)),
                    value(1, id as u64),
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        let mut failures_after_writes = 0;
        let mut successes = 0;
        for failure_after in 0..=2 * root.height as usize + 1 {
            let before = backend.inner.pages.lock().unwrap().len();
            backend
                .appends_remaining
                .store(failure_after, AtomicOrdering::Relaxed);
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            match mutator.set(
                root,
                2,
                DirectoryKey::row(&table, &long_key(1)),
                Some(value(2, 999)),
            ) {
                Ok(next) => {
                    assert_eq!(next.entries, root.entries + 1);
                    successes += 1;
                }
                Err(CoreError::Io(_)) => {
                    if backend.inner.pages.lock().unwrap().len() > before {
                        failures_after_writes += 1;
                    }
                    assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
                    assert!(matches!(
                        mutator.set(root, 3, DirectoryKey::table("t"), None),
                        Err(CoreError::OwnerFailed)
                    ));
                }
                Err(error) => panic!("unexpected error: {error:?}"),
            }
            drop(mutator_workspace);
            let reader = DirectoryReader::new(&backend, admission.clone());
            assert!(
                reader
                    .get(root, DirectoryKey::row(&table, &long_key(1)))
                    .unwrap()
                    .is_none()
            );
            for id in [0, 17, 89] {
                assert_eq!(
                    reader
                        .get(root, DirectoryKey::row(&table, &long_key(id * 2 + 2)))
                        .unwrap(),
                    Some(value(1, id as u64))
                );
            }
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
        assert!(failures_after_writes >= root.height as usize);
        assert!(successes > 0);
        backend
            .appends_remaining
            .store(usize::MAX, AtomicOrdering::Relaxed);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let next = mutator
            .set(
                root,
                2,
                DirectoryKey::row(&table, &long_key(1)),
                Some(value(2, 999)),
            )
            .unwrap();
        backend.fail_sync.store(true, AtomicOrdering::Relaxed);
        assert!(matches!(mutator.finish(next), Err(CoreError::Io(_))));
        backend.fail_sync.store(false, AtomicOrdering::Relaxed);
        assert!(matches!(mutator.finish(next), Err(CoreError::OwnerFailed)));
        drop(mutator_workspace);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        backend.fail_reads.store(true, AtomicOrdering::Relaxed);
        let before = backend.inner.pages.lock().unwrap().len();
        assert!(matches!(
            mutator.set(root, 2, DirectoryKey::row(&table, &long_key(1)), None),
            Err(CoreError::Io(_))
        ));
        assert_eq!(backend.inner.pages.lock().unwrap().len(), before);
        backend.fail_reads.store(false, AtomicOrdering::Relaxed);
        assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
    }

    #[test]
    fn cow_denial_and_invalid_input_do_not_append_or_corrupt_prior_root() {
        let backend = MemoryPages::default();
        let admission = Admission::new(160 << 10);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let root = mutator
            .set(
                empty_root(),
                2,
                DirectoryKey::table("t"),
                Some(DirectoryValue::Table { birth_seq: 1 }),
            )
            .unwrap();
        let before = backend.pages.lock().unwrap().len();
        for generation in [0, 1] {
            assert!(matches!(
                mutator.set(root, generation, DirectoryKey::table("t"), None),
                Err(CoreError::InvalidInput(_))
            ));
        }
        assert!(matches!(
            mutator.set(root, 3, DirectoryKey::row("t", b"k"), Some(value(4, 0))),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            mutator.set(root, 3, DirectoryKey::table("t"), Some(value(3, 0))),
            Err(CoreError::InvalidInput(_))
        ));
        let unchanged = mutator
            .set(root, 3, DirectoryKey::row("t", b"missing"), None)
            .unwrap();
        assert_eq!(unchanged.page, root.page);
        assert_eq!(unchanged.generation, 3);
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        let identical = mutator
            .set(
                root,
                3,
                DirectoryKey::table("t"),
                Some(DirectoryValue::Table { birth_seq: 1 }),
            )
            .unwrap();
        assert_eq!(identical.page, root.page);
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        drop(mutator_workspace);
        for limit in [1, 4096, 64 << 10, 96 << 10] {
            let bounded = Admission::new(limit);
            assert!(matches!(
                DirectoryWriteWorkspace::for_edits(bounded.clone()),
                Err(CoreError::CapacityDenied)
            ));
            assert_eq!(bounded.0.used.load(AtomicOrdering::Relaxed), 0);
            assert_eq!(backend.pages.lock().unwrap().len(), before);
        }
        let blocker = admission.reserve_workspace(64 << 10).unwrap();
        let reads = backend.reads.load(AtomicOrdering::Relaxed);
        assert!(matches!(
            DirectoryWriteWorkspace::for_edits(admission.clone()),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        admission.check_owner().unwrap();
        drop(blocker);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let retried = mutator
            .set(root, 3, DirectoryKey::row("t", b"k"), Some(value(3, 0)))
            .unwrap();
        assert_eq!(retried.entries, root.entries + 1);
        let reader = DirectoryReader::new(&backend, admission.clone());
        admission.0.failed.store(true, AtomicOrdering::Relaxed);
        assert!(matches!(
            mutator.set(root, 3, DirectoryKey::table("t"), None),
            Err(CoreError::OwnerFailed)
        ));
        admission.0.failed.store(false, AtomicOrdering::Relaxed);
        assert_eq!(
            reader.get(root, DirectoryKey::table("t")).unwrap(),
            Some(DirectoryValue::Table { birth_seq: 1 })
        );
    }

    #[test]
    fn cow_validates_inherited_incarnation_version_and_separator_bounds() {
        for corruption in 0..4 {
            let backend = MemoryPages::default();
            let admission = Admission::new(160 << 10);
            let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            for id in 1..40 {
                builder
                    .push(DirectoryKey::row("t", &long_key(id)), value(1, id as u64))
                    .unwrap();
            }
            let mut root = builder.finish().unwrap();
            let before = backend.pages.lock().unwrap().len();
            match corruption {
                0 => root.group_id = [99; 16],
                1 => {
                    let mut pages = backend.pages.lock().unwrap();
                    let page = &mut pages[root.page.unwrap().page_index as usize];
                    // The root separator no longer equals its child's min.
                    page[HEADER_BYTES + KEY_HEADER_BYTES + 1..HEADER_BYTES + KEY_HEADER_BYTES + 9]
                        .copy_from_slice(&0u64.to_be_bytes());
                    root.page.as_mut().unwrap().sha256 = page_digest(page);
                }
                2 => {
                    let mut pages = backend.pages.lock().unwrap();
                    let page = &mut pages[root.page.unwrap().page_index as usize];
                    page[36..44].copy_from_slice(&2u64.to_le_bytes());
                    root.page.as_mut().unwrap().sha256 = page_digest(page);
                }
                3 => root.entries += 1,
                _ => unreachable!(),
            }
            let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            assert!(
                matches!(
                    mutator.set(root, 3, DirectoryKey::row("t", &long_key(1)), None),
                    Err(CoreError::Corrupt(_))
                ),
                "corruption {corruption}"
            );
            assert_eq!(backend.pages.lock().unwrap().len(), before);
            assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
        }
    }

    struct OwnerFailingPages {
        inner: MemoryPages,
        admission: Arc<Admission>,
        operation: AtomicUsize,
    }

    impl DirectoryBackend for OwnerFailingPages {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            self.inner.read_page(reference, out)?;
            if self.operation.load(AtomicOrdering::Relaxed) == 1 {
                self.admission.owner_failed();
            }
            Ok(())
        }
        fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            let reference = self.inner.append_page(bytes)?;
            if self.operation.load(AtomicOrdering::Relaxed) == 2 {
                self.admission.owner_failed();
            }
            Ok(reference)
        }
        fn sync_pages(&self) -> Result<(), CoreError> {
            self.inner.sync_pages()?;
            if self.operation.load(AtomicOrdering::Relaxed) == 3 {
                self.admission.owner_failed();
            }
            Ok(())
        }
    }

    #[test]
    fn cow_owner_failure_during_backend_io_cannot_return_publishable_root() {
        for operation in 1..=3 {
            let admission = Admission::new(160 << 10);
            let backend = OwnerFailingPages {
                inner: MemoryPages::default(),
                admission: admission.clone(),
                operation: AtomicUsize::new(0),
            };
            let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            builder
                .push(DirectoryKey::row("t", b"k"), value(1, 1))
                .unwrap();
            let root = builder.finish().unwrap();
            backend.operation.store(operation, AtomicOrdering::Relaxed);
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            let result = mutator.set(root, 2, DirectoryKey::row("t", b"k"), Some(value(2, 2)));
            if operation == 3 {
                assert!(matches!(
                    mutator.finish(result.unwrap()),
                    Err(CoreError::OwnerFailed)
                ));
            } else {
                assert!(matches!(result, Err(CoreError::OwnerFailed)));
            }
            assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
            drop(mutator_workspace);
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
            let reader = DirectoryReader::new(&backend.inner, Admission::new(128 << 10));
            assert_eq!(
                reader.get(root, DirectoryKey::row("t", b"k")).unwrap(),
                Some(value(1, 1))
            );
        }
    }

    #[test]
    fn directory_reader_and_builder_check_owner_after_backend_io() {
        for operation in 1..=3 {
            let admission = Admission::new(128 << 10);
            let backend = OwnerFailingPages {
                inner: MemoryPages::default(),
                admission: admission.clone(),
                operation: AtomicUsize::new(0),
            };
            let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
            builder
                .push(DirectoryKey::row("t", b"k"), value(1, 1))
                .unwrap();
            if operation == 1 {
                let root = builder.finish().unwrap();
                backend.operation.store(operation, AtomicOrdering::Relaxed);
                let reader = DirectoryReader::new(&backend, admission.clone());
                assert!(matches!(
                    reader.get(root, DirectoryKey::row("t", b"k")),
                    Err(CoreError::OwnerFailed)
                ));
            } else {
                backend.operation.store(operation, AtomicOrdering::Relaxed);
                assert!(matches!(builder.finish(), Err(CoreError::OwnerFailed)));
            }
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
    }

    #[test]
    fn cow_arena_cache_composition_retains_snapshots_and_reopens_durable_pages() {
        use crate::arena::{DirectoryArenaBackend, DirectoryArenaRoll};
        use crate::cache::CacheConfig;
        use crate::group::InMemoryGroup;
        use crate::page_cache::CachedDirectoryBackend;
        use crate::root::{RootSelection, Superblock, publish_root, select_root};

        // The fixture publishes real allocation intents and confirmations.
        // Log-bound publication of data roots is tested by the root owner;
        // these two roots stand for its current and retained snapshot handles.
        struct Roll {
            group: InMemoryGroup,
            root: Mutex<Superblock>,
        }
        impl DirectoryArenaRoll for Roll {
            fn reserve(&self) -> Result<u64, CoreError> {
                let mut root = self.root.lock().unwrap();
                let (next, id) = root.reserve_directory()?;
                publish_root(&self.group, &root, &next)?;
                *root = next;
                Ok(id)
            }
            fn confirm(&self, id: u64) -> Result<(), CoreError> {
                let mut root = self.root.lock().unwrap();
                let next = root.confirm_directory(id)?;
                publish_root(&self.group, &root, &next)?;
                *root = next;
                Ok(())
            }
        }
        struct Counted<'a> {
            arena: &'a DirectoryArenaBackend,
            reads: AtomicUsize,
        }
        impl DirectoryBackend for Counted<'_> {
            fn read_page(
                &self,
                reference: DirectoryPageRef,
                out: &mut [u8],
            ) -> Result<(), CoreError> {
                self.reads.fetch_add(1, AtomicOrdering::Relaxed);
                self.arena.read_page(reference, out)
            }
            fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
                self.arena.append_page(bytes)
            }
            fn sync_pages(&self) -> Result<(), CoreError> {
                self.arena.sync_pages()
            }
        }

        let group = InMemoryGroup::new();
        let admission = Admission::new(2 << 20);
        let config = CacheConfig {
            byte_limit: 1 << 20,
        };
        let (old, current, old_model, current_model, pinned_page) = {
            let roll = Arc::new(Roll {
                group: group.clone(),
                root: Mutex::new(Superblock::genesis(GROUP)),
            });
            let arena =
                DirectoryArenaBackend::new(Arc::new(group.clone()), roll, admission.clone(), GROUP)
                    .unwrap();
            let counted = Counted {
                arena: &arena,
                reads: AtomicUsize::new(0),
            };
            let cached = CachedDirectoryBackend::new(&counted, admission.clone(), GROUP, config);
            let mut builder = DirectoryBuilder::new(&counted, admission.clone(), GROUP, 1).unwrap();
            let mut model = BTreeMap::new();
            model.insert(
                ("accounts".to_owned(), None),
                DirectoryValue::Table { birth_seq: 1 },
            );
            for id in 0..36 {
                model.insert(
                    ("accounts".to_owned(), Some(long_key(id).to_vec())),
                    value(1, id as u64),
                );
            }
            for (key, value) in &model {
                builder.push(model_key(key), *value).unwrap();
            }
            let old = builder.finish().unwrap();
            assert!(old.height >= 3);
            assert_eq!(cached.stats().unwrap().entries, 0);
            assert_directory_model(&cached, admission.clone(), old, &model);
            let old_model = model.clone();
            let pinned = cached.load_page(old.page.unwrap()).unwrap();
            let cache_before_mutation = cached.stats().unwrap();
            let physical_reads = counted.reads.load(AtomicOrdering::Relaxed);

            // Both committed and newly produced private roots are traversed
            // through the raw arena. Mutation must not change cache state.
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&counted, &mut mutator_workspace).unwrap();
            let replacement = ("accounts".to_owned(), Some(long_key(17).to_vec()));
            let mut current = mutator
                .set(old, 2, model_key(&replacement), Some(value(2, 777)))
                .unwrap();
            model.insert(replacement, value(2, 777));
            let deleted = ("accounts".to_owned(), Some(long_key(0).to_vec()));
            current = mutator.set(current, 2, model_key(&deleted), None).unwrap();
            model.remove(&deleted);
            let inserted = ("accounts".to_owned(), Some(long_key(40).to_vec()));
            current = mutator
                .set(current, 2, model_key(&inserted), Some(value(2, 40)))
                .unwrap();
            model.insert(inserted, value(2, 40));
            let current = mutator.finish(current).unwrap();
            drop(mutator_workspace);
            assert!(counted.reads.load(AtomicOrdering::Relaxed) > physical_reads);
            assert_eq!(cached.stats().unwrap(), cache_before_mutation);

            for pass in 0..2 {
                let before = counted.reads.load(AtomicOrdering::Relaxed);
                assert_directory_model(&cached, admission.clone(), old, &old_model);
                assert_directory_model(&cached, admission.clone(), current, &model);
                if pass == 1 {
                    assert_eq!(counted.reads.load(AtomicOrdering::Relaxed), before);
                }
            }
            assert_eq!(cached.stats().unwrap().evictions, 0);
            cached.clear().unwrap();
            assert_eq!(cached.stats().unwrap().pinned_bytes, pinned.charged_bytes());
            (old, current, old_model, model, pinned)
        };
        // Only the explicitly pinned old root page retains the first cache's
        // allocation owner. Reopen receives an independent, initially cold cache.
        assert!(admission.0.used.load(AtomicOrdering::Relaxed) > 0);
        let reopened_admission = Admission::new(2 << 20);
        {
            let crashed = group.crash();
            let RootSelection::Selected {
                superblock,
                mirrored: true,
                ..
            } = select_root(&crashed).unwrap()
            else {
                panic!("arena allocation superblock did not survive crash");
            };
            assert_eq!(superblock.pending_directory(), None);
            let roll = Arc::new(Roll {
                group: crashed.clone(),
                root: Mutex::new(superblock),
            });
            let arena = DirectoryArenaBackend::new(
                Arc::new(crashed),
                roll,
                reopened_admission.clone(),
                GROUP,
            )
            .unwrap();
            let counted = Counted {
                arena: &arena,
                reads: AtomicUsize::new(0),
            };
            let cached =
                CachedDirectoryBackend::new(&counted, reopened_admission.clone(), GROUP, config);
            assert_eq!(cached.stats().unwrap().entries, 0);
            for pass in 0..2 {
                let before = counted.reads.load(AtomicOrdering::Relaxed);
                assert_directory_model(&cached, reopened_admission.clone(), old, &old_model);
                assert_directory_model(
                    &cached,
                    reopened_admission.clone(),
                    current,
                    &current_model,
                );
                if pass == 0 {
                    assert!(counted.reads.load(AtomicOrdering::Relaxed) > before);
                } else {
                    assert_eq!(counted.reads.load(AtomicOrdering::Relaxed), before);
                }
            }
            assert_eq!(cached.stats().unwrap().evictions, 0);
        }
        drop(pinned_page);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(reopened_admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn transaction_page_bound_covers_real_descending_splits_and_missing_deletes() {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let mut root = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1)
            .unwrap()
            .finish()
            .unwrap();
        for batch in 0..8 {
            let bound = root.transaction_page_bound(16).unwrap();
            let before = backend.pages.lock().unwrap().len();
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            for offset in 0..16 {
                let key = long_key(200 - batch * 16 - offset);
                root = mutator
                    .set(
                        root,
                        2 + batch as u64,
                        DirectoryKey::row("t", &key),
                        Some(value(2 + batch as u64, offset as u64 + 1)),
                    )
                    .unwrap();
            }
            root = mutator.finish(root).unwrap();
            assert!((backend.pages.lock().unwrap().len() - before) as u64 <= bound);
            let before = backend.pages.lock().unwrap().len();
            let next = mutator
                .set(
                    root,
                    root.generation + 1,
                    DirectoryKey::row("t", b"never inserted"),
                    None,
                )
                .unwrap();
            assert_eq!(backend.pages.lock().unwrap().len(), before);
            assert_eq!(next.page, root.page);
            root = next;
        }
        assert_eq!(root.transaction_page_bound(0).unwrap(), 0);
        assert!(
            root.transaction_page_bound(crate::segment::MAX_BATCH_OPERATIONS + 1)
                .is_err()
        );
    }
}

// Transaction-space planning is qualified separately before production activation.
#[path = "directory_space.rs"]
mod space;
