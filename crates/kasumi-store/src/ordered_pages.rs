//! Immutable ordered pages above Store: the one copy-on-write B+tree format
//! for application descriptors, catalogs and metadata records.
//!
//! Pages are encrypted Store records in a caller-selected page space (a
//! namespace), addressed by random opaque IDs. Native KV sees point reads and
//! writes only; key order lives inside the encrypted pages. A parent reference
//! authenticates its child's exact bytes, level and aggregates, so a page is
//! accepted only under the root that names it. Unchanged subtrees are shared
//! between generations.
//!
//! A page space holds one live tree history at a time. An edit copies only the
//! pages on changed paths. A large edit commits its reclamation decision with
//! the new root. Earlier views keep reading their pinned native generation.
//! A bulk-built generation is staged into a fresh page space through
//! `NamespaceStage` and replaces a whole space by selection, after which the
//! replaced space is retired and reclaimed in bounded batches.
use super::*;

mod builder;
mod cache;
mod cursor;
mod edit_journal;
mod editor;
#[cfg(test)]
mod tests;

pub use builder::{BulkBuilder, RowSink, stage_tree};
pub use cache::{PageCache, PageCacheStats};
pub use cursor::{Direction, TreeReader};
pub use edit_journal::{EDIT_JOURNAL, recover_abandoned_edits, recover_abandoned_edits_in};
pub use editor::{Edit, EditWorkspace, TreeEdit, edit_tree, edit_tree_staged};

/// Plaintext bound of one page, header included.
pub const MAX_PAGE_BYTES: usize = 32 << 10;
pub const MAX_PAGE_ENTRIES: usize = 128;
/// Every logical key Kasumi stores is far smaller (names are at most 256
/// bytes); a longer key is refused rather than chunked.
pub const MAX_KEY_BYTES: usize = 1024;
/// Longer values move to immutable overflow chunks owned by their entry.
pub const MAX_INLINE_VALUE: usize = 2048;
pub const OVERFLOW_CHUNK_BYTES: usize = 64 << 10;
pub const MAX_VALUE_BYTES: usize = MAX_RECORD;
/// A rewritten page below this fill merges with a sibling, so deletions never
/// leave sparse paths behind.
const MIN_FILL_BYTES: usize = MAX_PAGE_BYTES / 4;
/// Fill above which a bulk build starts a new page. Full pages would split on
/// their first insertion.
const BULK_FILL_BYTES: usize = MAX_PAGE_BYTES * 3 / 4;
/// With the minimum fill a level holds at least seven children, so this
/// bounds every path far beyond any reachable entry count.
pub const MAX_HEIGHT: usize = 16;
const MAGIC: &[u8; 4] = b"KOP1";
const HEADER_BYTES: usize = 4 + 16 + 1 + 2;
const CHILD_BYTES: usize = 16 + 32 + 8 + 8;
const OVERFLOW_BYTES: usize = 16 + 8 + 32;
const PAGE_ROW: u8 = b'p';
const CHUNK_ROW: u8 = b'o';
/// Bound of one encoded entry: a page always holds at least ten.
const MAX_ENTRY_BYTES: usize = 2 + MAX_KEY_BYTES + 1 + 4 + MAX_INLINE_VALUE;
const _: () = assert!(HEADER_BYTES + 10 * MAX_ENTRY_BYTES <= MAX_PAGE_BYTES);
/// Resident cost of one decoded page beyond its bytes: the page and offset
/// allocations, the shared owner and its cache slot.
const PAGE_OVERHEAD: u64 = 256;

/// Random, never reused; the authenticating hash travels with every reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageId([u8; 16]);
impl PageId {
    fn fresh() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }
    fn row_key(&self) -> [u8; 17] {
        let mut key = [PAGE_ROW; 17];
        key[1..].copy_from_slice(&self.0);
        key
    }
}

/// A child reference: identity, exact plaintext hash, level and the subtree's
/// entry count and logical key+value bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRef {
    pub id: PageId,
    pub sha256: [u8; 32],
    pub level: u8,
    pub count: u64,
    pub bytes: u64,
}

/// One tree generation. The tree identity is written into every page, so a
/// page of another tree cannot be spliced in; generation identity is not,
/// because unchanged pages are shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRoot {
    pub tree: [u8; 16],
    pub root: Option<PageRef>,
}

pub const TREE_ROOT_BYTES: usize = 16 + 1 + 16 + 32 + 1 + 8 + 8;

impl TreeRoot {
    pub fn new_tree() -> Self {
        Self {
            tree: *Uuid::new_v4().as_bytes(),
            root: None,
        }
    }
    pub fn empty(tree: [u8; 16]) -> Self {
        Self { tree, root: None }
    }
    pub fn count(&self) -> u64 {
        self.root.map_or(0, |root| root.count)
    }
    pub fn bytes(&self) -> u64 {
        self.root.map_or(0, |root| root.bytes)
    }
    pub fn height(&self) -> usize {
        self.root.map_or(0, |root| usize::from(root.level) + 1)
    }
    pub fn encode(&self) -> [u8; TREE_ROOT_BYTES] {
        let mut out = [0; TREE_ROOT_BYTES];
        out[..16].copy_from_slice(&self.tree);
        if let Some(root) = &self.root {
            out[16] = 1;
            out[17..33].copy_from_slice(&root.id.0);
            out[33..65].copy_from_slice(&root.sha256);
            out[65] = root.level;
            out[66..74].copy_from_slice(&root.count.to_be_bytes());
            out[74..82].copy_from_slice(&root.bytes.to_be_bytes());
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == TREE_ROOT_BYTES, "tree root length differs");
        let tree: [u8; 16] = bytes[..16].try_into()?;
        let root = match bytes[16] {
            0 => {
                ensure!(
                    bytes[17..].iter().all(|byte| *byte == 0),
                    "empty tree root carries a reference"
                );
                None
            }
            1 => {
                let root = PageRef {
                    id: PageId(bytes[17..33].try_into()?),
                    sha256: bytes[33..65].try_into()?,
                    level: bytes[65],
                    count: u64::from_be_bytes(bytes[66..74].try_into()?),
                    bytes: u64::from_be_bytes(bytes[74..82].try_into()?),
                };
                ensure!(
                    usize::from(root.level) < MAX_HEIGHT && root.count > 0,
                    "invalid tree root reference"
                );
                Some(root)
            }
            _ => anyhow::bail!("invalid tree root tag"),
        };
        Ok(Self { tree, root })
    }
}

impl Serialize for TreeRoot {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.encode()))
    }
}
impl<'de> Deserialize<'de> for TreeRoot {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(&encoded).map_err(serde::de::Error::custom)?;
        let root = Self::decode(&bytes).map_err(serde::de::Error::custom)?;
        if hex::encode(root.encode()) != encoded {
            return Err(serde::de::Error::custom("noncanonical tree root"));
        }
        Ok(root)
    }
}

/// An overflow value: immutable 64 KiB chunks under one random identity,
/// owned by exactly one leaf entry and authenticated by length and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverflowRef {
    id: [u8; 16],
    len: u64,
    sha256: [u8; 32],
}
impl OverflowRef {
    fn chunks(&self) -> u32 {
        // Lengths are bounded by MAX_VALUE_BYTES when decoded or written.
        self.len.div_ceil(OVERFLOW_CHUNK_BYTES as u64) as u32
    }
    fn chunk_key(&self, chunk: u32) -> [u8; 21] {
        let mut key = [CHUNK_ROW; 21];
        key[1..17].copy_from_slice(&self.id);
        key[17..].copy_from_slice(&chunk.to_be_bytes());
        key
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ValueRef<'a> {
    Inline(&'a [u8]),
    Overflow(OverflowRef),
}
impl ValueRef<'_> {
    pub fn len(&self) -> u64 {
        match self {
            Self::Inline(bytes) => bytes.len() as u64,
            Self::Overflow(overflow) => overflow.len,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A row read through one pinned or current source.
pub enum PageRow {
    Stored(PlaintextValue),
    #[cfg(test)]
    Memory(Arc<[u8]>),
}
impl PageRow {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Stored(value) => value.as_bytes(),
            #[cfg(test)]
            Self::Memory(bytes) => bytes,
        }
    }
}

/// Where pages are read from: a pinned read view for readers, the current
/// store for an editor under its caller's publication gate.
pub trait PageSource {
    /// Rechecked for every page, including cache hits: cached plaintext is
    /// never authorization.
    fn check_access(&self) -> Result<()>;
    fn read_row(&self, space: &str, key: &[u8], max_bytes: usize) -> Result<Option<PageRow>>;
    fn memory(&self) -> Arc<dyn NodeDiskMemoryAdmission>;
    /// The encryption domain the page space belongs to; cache keys include it.
    fn domain(&self) -> &str;
}

impl PageSource for TenantReadView {
    fn check_access(&self) -> Result<()> {
        self.tenant_store().check_access()
    }
    fn read_row(&self, space: &str, key: &[u8], max_bytes: usize) -> Result<Option<PageRow>> {
        Ok(self.get(space, key, max_bytes)?.map(PageRow::Stored))
    }
    fn memory(&self) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.scratch_disk().memory().clone()
    }
    fn domain(&self) -> &str {
        self.tenant_store().tenant()
    }
}

impl PageSource for TenantStore {
    fn check_access(&self) -> Result<()> {
        TenantStore::check_access(self)
    }
    fn read_row(&self, space: &str, key: &[u8], max_bytes: usize) -> Result<Option<PageRow>> {
        Ok(self
            .get_bounded(space, key, max_bytes)?
            .map(PageRow::Stored))
    }
    fn memory(&self) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.scratch_disk().memory().clone()
    }
    fn domain(&self) -> &str {
        self.tenant()
    }
}

/// One authenticated decoded page: its exact bytes plus entry offsets.
pub(crate) struct Page {
    bytes: Box<[u8]>,
    offsets: Box<[u32]>,
    level: u8,
    count: u64,
    logical: u64,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .context("truncated ordered page")?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
}

impl Page {
    /// Accept `bytes` only as the exact page `expected` names in `tree`.
    fn decode(bytes: &[u8], tree: &[u8; 16], expected: &PageRef) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PAGE_BYTES,
            "ordered page exceeds its bound"
        );
        ensure!(
            <[u8; 32]>::from(Sha256::digest(bytes)) == expected.sha256,
            "ordered page hash differs from its reference"
        );
        let mut reader = Reader { bytes, offset: 0 };
        ensure!(reader.take(4)? == MAGIC, "unsupported ordered page format");
        ensure!(&reader.array::<16>()? == tree, "ordered page tree differs");
        let level = reader.u8()?;
        ensure!(
            level == expected.level && usize::from(level) < MAX_HEIGHT,
            "ordered page level differs"
        );
        let count = usize::from(reader.u16()?);
        ensure!(
            (1..=MAX_PAGE_ENTRIES).contains(&count),
            "ordered page entry count is out of bounds"
        );
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(count)?;
        let mut entries = 0u64;
        let mut logical = 0u64;
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            offsets.push(u32::try_from(reader.offset)?);
            let key_len = usize::from(reader.u16()?);
            ensure!(key_len <= MAX_KEY_BYTES, "ordered page key exceeds bound");
            let key = reader.take(key_len)?;
            ensure!(
                previous.is_none_or(|previous| previous < key),
                "ordered page keys are not strictly increasing"
            );
            previous = Some(key);
            if level == 0 {
                let value_len = match reader.u8()? {
                    0 => {
                        let len = reader.u32()? as usize;
                        ensure!(len <= MAX_INLINE_VALUE, "inline value exceeds bound");
                        reader.take(len)?;
                        len as u64
                    }
                    1 => {
                        let _id = reader.array::<16>()?;
                        let len = reader.u64()?;
                        let _sha256 = reader.array::<32>()?;
                        ensure!(
                            len > MAX_INLINE_VALUE as u64 && len <= MAX_VALUE_BYTES as u64,
                            "overflow value length is out of bounds"
                        );
                        len
                    }
                    _ => anyhow::bail!("invalid ordered value tag"),
                };
                entries = entries.checked_add(1).context("page count overflow")?;
                logical = logical
                    .checked_add(key_len as u64 + value_len)
                    .context("page bytes overflow")?;
            } else {
                let _id = reader.array::<16>()?;
                let _sha256 = reader.array::<32>()?;
                let child_count = reader.u64()?;
                let child_bytes = reader.u64()?;
                ensure!(child_count > 0, "ordered child subtree is empty");
                entries = entries
                    .checked_add(child_count)
                    .context("page count overflow")?;
                logical = logical
                    .checked_add(child_bytes)
                    .context("page bytes overflow")?;
            }
        }
        ensure!(
            reader.offset == bytes.len(),
            "ordered page has trailing bytes"
        );
        ensure!(
            entries == expected.count && logical == expected.bytes,
            "ordered page aggregates differ from its reference"
        );
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len())?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            bytes: owned.into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
            level,
            count: entries,
            logical,
        })
    }

    /// A cached page under another reference: its hash binds the bytes, tree
    /// and level, but the aggregates are this reference's claim.
    fn check_reference(&self, expected: &PageRef) -> Result<()> {
        ensure!(
            self.level == expected.level
                && self.count == expected.count
                && self.logical == expected.bytes,
            "ordered page aggregates differ from its reference"
        );
        Ok(())
    }

    fn len(&self) -> usize {
        self.offsets.len()
    }
    fn is_leaf(&self) -> bool {
        self.level == 0
    }
    fn entry_range(&self, index: usize) -> std::ops::Range<usize> {
        let start = self.offsets[index] as usize;
        let end = self
            .offsets
            .get(index + 1)
            .map_or(self.bytes.len(), |offset| *offset as usize);
        start..end
    }
    /// The exact encoded entry, copied unchanged into a rewritten page.
    fn entry_bytes(&self, index: usize) -> &[u8] {
        &self.bytes[self.entry_range(index)]
    }
    fn key(&self, index: usize) -> &[u8] {
        let start = self.offsets[index] as usize;
        let len = u16::from_be_bytes([self.bytes[start], self.bytes[start + 1]]) as usize;
        &self.bytes[start + 2..start + 2 + len]
    }
    fn payload(&self, index: usize) -> &[u8] {
        let range = self.entry_range(index);
        let start = range.start + 2 + self.key(index).len();
        &self.bytes[start..range.end]
    }
    fn value(&self, index: usize) -> ValueRef<'_> {
        debug_assert!(self.is_leaf());
        let payload = self.payload(index);
        match payload[0] {
            0 => ValueRef::Inline(&payload[5..]),
            _ => ValueRef::Overflow(OverflowRef {
                id: payload[1..17].try_into().expect("validated overflow id"),
                len: u64::from_be_bytes(payload[17..25].try_into().expect("validated length")),
                sha256: payload[25..57].try_into().expect("validated hash"),
            }),
        }
    }
    fn child(&self, index: usize) -> PageRef {
        debug_assert!(!self.is_leaf());
        let payload = self.payload(index);
        PageRef {
            id: PageId(payload[..16].try_into().expect("validated child id")),
            sha256: payload[16..48].try_into().expect("validated child hash"),
            level: self.level - 1,
            count: u64::from_be_bytes(payload[48..56].try_into().expect("validated count")),
            bytes: u64::from_be_bytes(payload[56..64].try_into().expect("validated bytes")),
        }
    }
    /// The child whose range holds `key`: the last separator not above it.
    fn child_index(&self, key: &[u8]) -> usize {
        let mut low = 0;
        let mut high = self.len();
        while high - low > 1 {
            let middle = (low + high) / 2;
            if self.key(middle) <= key {
                low = middle;
            } else {
                high = middle;
            }
        }
        low
    }
    /// The first index whose key is not below `key`.
    fn lower_bound(&self, key: &[u8]) -> usize {
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let middle = (low + high) / 2;
            if self.key(middle) < key {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
    /// A loaded child must start exactly at its separator and stay below the
    /// next one. Checked on every load, cached or not: a shared page can sit
    /// under different parents in different generations.
    fn check_bounds(&self, low: Option<&[u8]>, high: Option<&[u8]>) -> Result<()> {
        if let Some(low) = low {
            ensure!(self.key(0) == low, "ordered child separator differs");
        }
        if let Some(high) = high {
            ensure!(
                self.key(self.len() - 1) < high,
                "ordered child exceeds its parent range"
            );
        }
        Ok(())
    }
    fn charge(&self) -> u64 {
        self.bytes.len() as u64 + self.offsets.len() as u64 * 4 + PAGE_OVERHEAD
    }
}

/// Upper bound of what one traversal holds while descending: a row and its
/// decoded copy per level, plus one overflow chunk and its copy.
fn path_workspace(height: usize) -> u64 {
    let levels = height.max(1) as u64;
    levels * (2 * MAX_PAGE_BYTES as u64 + PAGE_OVERHEAD + 4 * MAX_PAGE_ENTRIES as u64)
        + 2 * OVERFLOW_CHUNK_BYTES as u64
        + (16 << 10)
}

fn encode_page(tree: &[u8; 16], level: u8, entries: &[&[u8]]) -> Vec<u8> {
    let len = HEADER_BYTES + entries.iter().map(|entry| entry.len()).sum::<usize>();
    let mut page = Vec::with_capacity(len);
    page.extend_from_slice(MAGIC);
    page.extend_from_slice(tree);
    page.push(level);
    page.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for entry in entries {
        page.extend_from_slice(entry);
    }
    page
}

fn encode_key(out: &mut Vec<u8>, key: &[u8]) -> Result<()> {
    ensure!(key.len() <= MAX_KEY_BYTES, "ordered key exceeds bound");
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key);
    Ok(())
}

fn encode_inline_entry(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    debug_assert!(value.len() <= MAX_INLINE_VALUE);
    let mut entry = Vec::with_capacity(2 + key.len() + 5 + value.len());
    encode_key(&mut entry, key)?;
    entry.push(0);
    entry.extend_from_slice(&(value.len() as u32).to_be_bytes());
    entry.extend_from_slice(value);
    Ok(entry)
}

fn encode_overflow_entry(key: &[u8], overflow: &OverflowRef) -> Result<Vec<u8>> {
    let mut entry = Vec::with_capacity(2 + key.len() + 1 + OVERFLOW_BYTES);
    encode_key(&mut entry, key)?;
    entry.push(1);
    entry.extend_from_slice(&overflow.id);
    entry.extend_from_slice(&overflow.len.to_be_bytes());
    entry.extend_from_slice(&overflow.sha256);
    Ok(entry)
}

fn encode_child_entry(key: &[u8], child: &PageRef) -> Result<Vec<u8>> {
    let mut entry = Vec::with_capacity(2 + key.len() + CHILD_BYTES);
    encode_key(&mut entry, key)?;
    entry.extend_from_slice(&child.id.0);
    entry.extend_from_slice(&child.sha256);
    entry.extend_from_slice(&child.count.to_be_bytes());
    entry.extend_from_slice(&child.bytes.to_be_bytes());
    Ok(entry)
}

/// The aggregates an encoded entry contributes to its page reference.
fn entry_aggregates(level: u8, entry: &[u8]) -> (u64, u64) {
    let key_len = u16::from_be_bytes([entry[0], entry[1]]) as usize;
    let payload = &entry[2 + key_len..];
    if level == 0 {
        let value_len = match payload[0] {
            0 => u32::from_be_bytes(payload[1..5].try_into().expect("inline length")) as u64,
            _ => u64::from_be_bytes(payload[17..25].try_into().expect("overflow length")),
        };
        (1, key_len as u64 + value_len)
    } else {
        (
            u64::from_be_bytes(payload[48..56].try_into().expect("child count")),
            u64::from_be_bytes(payload[56..64].try_into().expect("child bytes")),
        )
    }
}

fn entry_key(entry: &[u8]) -> &[u8] {
    let key_len = u16::from_be_bytes([entry[0], entry[1]]) as usize;
    &entry[2..2 + key_len]
}

const MAX_PAYLOAD_BYTES: usize = MAX_PAGE_BYTES - HEADER_BYTES;

/// Below a quarter of both page bounds. Pages of tiny entries fill by count,
/// so a byte threshold alone would call every one of them underfull.
fn underfull(bytes: usize, entries: usize) -> bool {
    bytes < MIN_FILL_BYTES && entries < MAX_PAGE_ENTRIES / 4
}

/// Split encoded entries into pages within both bounds: fill greedily to
/// `target` payload bytes, then rebalance the last two pages so that neither
/// is underfull. Returns each page's entry range.
fn pack(entries: &[Vec<u8>], target: usize) -> Vec<std::ops::Range<usize>> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (index, entry) in entries.iter().enumerate() {
        if index > start && (bytes + entry.len() > target || index - start == MAX_PAGE_ENTRIES) {
            ranges.push(start..index);
            start = index;
            bytes = 0;
        }
        bytes += entry.len();
    }
    ranges.push(start..entries.len());
    if ranges.len() >= 2 {
        let last = ranges.pop().expect("last page");
        let previous = ranges.pop().expect("previous page");
        let (left, right) = balance(entries, previous.start, last.end);
        ranges.push(left);
        ranges.push(right);
    }
    ranges
}

/// The split of `entries[start..end]` into two valid pages that leaves the
/// fewest underfull pages, then the most even bytes. The greedy split is
/// always valid; when the range cannot fit one page, a split with neither
/// page underfull exists (each bound is four times its minimum).
fn balance(
    entries: &[Vec<u8>],
    start: usize,
    end: usize,
) -> (std::ops::Range<usize>, std::ops::Range<usize>) {
    let total: usize = entries[start..end].iter().map(Vec::len).sum();
    let mut best: Option<((u8, usize), usize)> = None;
    let mut left = 0;
    for split in start + 1..end {
        left += entries[split - 1].len();
        let right = total - left;
        let (left_count, right_count) = (split - start, end - split);
        if left > MAX_PAYLOAD_BYTES
            || right > MAX_PAYLOAD_BYTES
            || left_count > MAX_PAGE_ENTRIES
            || right_count > MAX_PAGE_ENTRIES
        {
            continue;
        }
        let score = (
            u8::from(underfull(left, left_count)) + u8::from(underfull(right, right_count)),
            left.abs_diff(right),
        );
        if best.is_none_or(|(best, _)| score < best) {
            best = Some((score, split));
        }
    }
    let (_, split) = best.expect("greedy split is valid");
    (start..split, split..end)
}

/// Read and authenticate an overflow value through the same source.
fn visit_overflow(
    source: &dyn PageSource,
    space: &str,
    overflow: &OverflowRef,
    mut visit: impl FnMut(&[u8]),
) -> Result<()> {
    let mut remaining = usize::try_from(overflow.len)?;
    ensure!(remaining <= MAX_VALUE_BYTES, "overflow value exceeds bound");
    let mut digest = Sha256::new();
    for chunk in 0..overflow.chunks() {
        source.check_access()?;
        let expected = remaining.min(OVERFLOW_CHUNK_BYTES);
        let row = source
            .read_row(space, &overflow.chunk_key(chunk), OVERFLOW_CHUNK_BYTES)?
            .context("overflow chunk missing")?;
        let bytes = row.as_bytes();
        ensure!(bytes.len() == expected, "overflow chunk length differs");
        digest.update(bytes);
        visit(bytes);
        remaining -= expected;
    }
    ensure!(
        remaining == 0 && <[u8; 32]>::from(digest.finalize()) == overflow.sha256,
        "overflow value hash differs"
    );
    source.check_access()
}

/// Encode `value` for a leaf: inline, or as fresh overflow chunks emitted
/// through `emit` before the entry that owns them.
fn encode_value(
    key: &[u8],
    value: &[u8],
    mut emit: impl FnMut(Vec<u8>, Vec<u8>) -> Result<()>,
) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= MAX_VALUE_BYTES,
        "ordered value exceeds bound"
    );
    if value.len() <= MAX_INLINE_VALUE {
        return encode_inline_entry(key, value);
    }
    let overflow = OverflowRef {
        id: *Uuid::new_v4().as_bytes(),
        len: value.len() as u64,
        sha256: Sha256::digest(value).into(),
    };
    for (chunk, bytes) in value.chunks(OVERFLOW_CHUNK_BYTES).enumerate() {
        emit(overflow.chunk_key(chunk as u32).to_vec(), bytes.to_vec())?;
    }
    encode_overflow_entry(key, &overflow)
}
