use super::*;
use sha2::{Digest, Sha256};
use std::{fs::File, ops::Bound, path::Path, sync::Arc};

/// One directory entry. Its boundary keys stay in the authenticated directory
/// bytes that the reader retains, so opening a run allocates no key copies.
struct Block {
    offset: u64,
    digest: [u8; 32],
    packed: u32,
    raw: u32,
    /// Zero for a canonical block: a prefix-coded length is at least eight.
    prefix_len: u32,
    /// The stored bytes are a Zstandard frame instead of an LZ4 block.
    zstd: bool,
    /// Where the first key starts in the directory; the last key follows it.
    keys_at: u32,
    first_len: u16,
    last_len: u16,
}

impl Block {
    fn first<'a>(&self, directory: &'a [u8]) -> &'a [u8] {
        let at = self.keys_at as usize;
        &directory[at..at + self.first_len as usize]
    }

    fn last<'a>(&self, directory: &'a [u8]) -> &'a [u8] {
        let at = self.keys_at as usize + self.first_len as usize;
        &directory[at..at + self.last_len as usize]
    }
}

struct Decoded {
    id: usize,
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

#[cfg(test)]
std::thread_local! {
    pub(super) static ROW_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Decoded {
    fn row(&self, offset: u32) -> (&[u8], &[u8]) {
        #[cfg(test)]
        ROW_PROBES.with(|count| count.set(count.get() + 1));
        let record = &self.bytes[offset as usize..];
        let key_len = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
        let value_len = u32::from_le_bytes(record[2..6].try_into().unwrap()) as usize;
        let value_at = ROW_HEADER + key_len;
        (
            &record[ROW_HEADER..value_at],
            &record[value_at..value_at + value_len],
        )
    }

    fn load(file: &File, id: usize, block: &Block, directory: &[u8]) -> io::Result<Self> {
        let (raw, first, last) = (
            block.raw as usize,
            block.first(directory),
            block.last(directory),
        );
        let mut packed = vec![0; block.packed as usize];
        read_exact_at(file, &mut packed, block.offset)?;
        if <[u8; 32]>::from(Sha256::digest(&packed)) != block.digest {
            return Err(invalid("sorted-run block digest differs"));
        }
        let prefixed = block.prefix_len != 0;
        let stored_len = if prefixed {
            block.prefix_len as usize
        } else {
            raw
        };
        let mut bytes = if block.zstd {
            codec::zstd_expand(&packed, stored_len)?
        } else {
            let mut bytes = vec![0; stored_len];
            let size = lz4_flex::block::decompress_into(&packed, &mut bytes)
                .map_err(|_| invalid("invalid LZ4 block"))?;
            if size != stored_len {
                return Err(invalid("sorted-run decoded length differs"));
            }
            bytes
        };
        if prefixed {
            bytes = prefix::decode(&bytes, raw)?;
        }
        let mut input = bytes.as_slice();
        let max_rows = if raw > BLOCK_TARGET {
            1
        } else {
            raw / ROW_HEADER
        };
        let mut offsets = Vec::with_capacity(max_rows);
        let mut previous = None;
        while !input.is_empty() {
            offsets.push((bytes.len() - input.len()) as u32);
            let key_len = u16_from(&mut input)?;
            let value_len = u32_from(&mut input)?;
            if key_len > MAX_KEY || value_len > MAX_VALUE {
                return Err(invalid("sorted-run row exceeds limits"));
            }
            let key = take(&mut input, key_len)?;
            take(&mut input, value_len)?;
            if previous.map_or(key != first, |prior| key <= prior) {
                return Err(invalid("sorted-run keys or first boundary differ"));
            }
            previous = Some(key);
            if raw > BLOCK_TARGET && !input.is_empty() {
                return Err(invalid("oversized sorted-run block must contain one row"));
            }
        }
        if previous != Some(last) {
            return Err(invalid("sorted-run last boundary differs"));
        }
        // The worst-case row count sized the buffer; a cached block keeps only
        // the offsets of the rows it actually holds.
        offsets.shrink_to_fit();
        Ok(Self { id, bytes, offsets })
    }
}

/// A verified sparse index and a bounded, per-reader cache of decoded blocks.
/// Independent readers can open the same sealed file.
pub struct FrozenRun {
    file: Arc<File>,
    /// The authenticated directory. Block boundary keys borrow from it.
    directory: Vec<u8>,
    blocks: Vec<Block>,
    cache: [Option<Decoded>; 64],
    oversized: Option<Decoded>,
}

impl FrozenRun {
    /// Verify the directory against a digest supplied by the trusted owner.
    pub fn open(path: impl AsRef<Path>, expected_root: [u8; 32]) -> io::Result<Self> {
        Self::from_file(File::open(path)?, expected_root)
    }

    /// Verify an already opened regular file. The caller supplies its trusted
    /// expected digest independently of the file being opened.
    pub fn from_file(file: File, expected_root: [u8; 32]) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("missing sorted-run footer"));
        }
        Self::from_extent(Arc::new(file), 0, metadata.len(), expected_root)
    }

    /// Open a run embedded in a caller-validated extent of a larger file. The
    /// run shares that file's descriptor and reads only by absolute position.
    pub(super) fn from_extent(
        file: Arc<File>,
        start: u64,
        end: u64,
        expected_root: [u8; 32],
    ) -> io::Result<Self> {
        if end.checked_sub(start).is_none_or(|n| n < 16) {
            return Err(invalid("missing sorted-run footer"));
        }
        let mut footer = [0u8; 16];
        read_exact_at(&file, &mut footer, end - 16)?;
        let size = u64::from_le_bytes(footer[..8].try_into().unwrap());
        // Version 1 has canonical LZ4 blocks only, version 2 adds prefix
        // coding, and version 3 adds Zstandard as a per-block alternative.
        let (version, directory_magic) = match &footer[8..] {
            magic if magic == FOOTER_MAGIC_ZSTD => (3, DIRECTORY_MAGIC_ZSTD),
            magic if magic == FOOTER_MAGIC => (2, DIRECTORY_MAGIC),
            magic if magic == FOOTER_MAGIC_V1 => (1, DIRECTORY_MAGIC_V1),
            _ => return Err(invalid("invalid sorted-run footer")),
        };
        if size > MAX_DIRECTORY as u64 || size > end - start - 16 {
            return Err(invalid("invalid sorted-run footer"));
        }
        let payload_end = end - 16 - size;
        let mut directory = vec![0; size as usize];
        read_exact_at(&file, &mut directory, payload_end)?;
        if <[u8; 32]>::from(Sha256::digest(&directory)) != expected_root {
            return Err(invalid("sorted-run root digest differs"));
        }
        let mut input = directory.as_slice();
        if take(&mut input, 8)? != directory_magic {
            return Err(invalid("unknown sorted-run format"));
        }
        let count = u32_from(&mut input)?;
        if count > MAX_BLOCKS || count > input.len() / DIRECTORY_ENTRY_HEADER {
            return Err(invalid("invalid sorted-run block count"));
        }
        let mut blocks: Vec<Block> = Vec::with_capacity(count);
        let mut offset = start;
        for _ in 0..count {
            let tagged = u32_from(&mut input)? as u32;
            let raw = u32_from(&mut input)?;
            if !(ROW_HEADER..=MAX_RAW).contains(&raw) {
                return Err(invalid("invalid sorted-run expanded length"));
            }
            // Each flag exists only from the version that introduced it;
            // before that its bit is part of the stored length.
            let zstd = version == 3 && tagged & ZSTD_FLAG != 0;
            let tagged = if version == 3 {
                tagged & !ZSTD_FLAG
            } else {
                tagged
            };
            let (packed, prefix_len) = if version >= 2 && tagged & PREFIX_FLAG != 0 {
                let len = u32_from(&mut input)?;
                if raw > BLOCK_TARGET
                    || !(ROW_HEADER + 2..=prefix::max_encoded_len(raw)).contains(&len)
                {
                    return Err(invalid("invalid sorted-run prefix length"));
                }
                ((tagged & !PREFIX_FLAG) as usize, Some(len))
            } else {
                (tagged as usize, None)
            };
            let digest = take(&mut input, 32)?.try_into().unwrap();
            let first_len = u16_from(&mut input)?;
            let last_len = u16_from(&mut input)?;
            let stored_len = prefix_len.unwrap_or(raw);
            let packed_bound = if zstd {
                codec::zstd_bound(stored_len)
            } else {
                lz4_flex::block::get_maximum_output_size(stored_len)
            };
            if packed == 0 || packed > packed_bound || first_len > MAX_KEY || last_len > MAX_KEY {
                return Err(invalid("invalid sorted-run block lengths"));
            }
            let keys_at = directory.len() - input.len();
            let first = take(&mut input, first_len)?;
            let last = take(&mut input, last_len)?;
            if first > last
                || blocks
                    .last()
                    .is_some_and(|prior| prior.last(&directory) >= first)
            {
                return Err(invalid("unordered sorted-run block boundaries"));
            }
            // Every narrowed field was bounded above: the directory by
            // MAX_DIRECTORY, the lengths by MAX_RAW, its codec's compression
            // bound and MAX_KEY.
            blocks.push(Block {
                offset,
                digest,
                packed: packed as u32,
                raw: raw as u32,
                prefix_len: prefix_len.unwrap_or(0) as u32,
                zstd,
                keys_at: keys_at as u32,
                first_len: first_len as u16,
                last_len: last_len as u16,
            });
            offset = offset
                .checked_add(packed as u64)
                .filter(|&next| next <= payload_end)
                .ok_or_else(|| invalid("sorted-run extent differs"))?;
        }
        if !input.is_empty() || offset != payload_end {
            return Err(invalid("sorted-run extent differs"));
        }
        Ok(Self {
            file,
            directory,
            blocks,
            cache: std::array::from_fn(|_| None),
            oversized: None,
        })
    }

    #[cfg(unix)]
    /// Heap capacity retained by the authenticated index once decoded rows have been released.
    pub(super) fn index_heap_bytes(&self) -> usize {
        self.blocks.capacity() * size_of::<Block>() + self.directory.capacity()
    }

    #[cfg(unix)]
    pub(super) fn discard_decoded(&mut self) {
        self.cache.fill_with(|| None);
        self.oversized = None;
    }

    #[cfg(all(unix, test))]
    pub(super) fn has_decoded(&self) -> bool {
        self.oversized.is_some() || self.cache.iter().any(Option::is_some)
    }

    #[cfg(unix)]
    pub(crate) fn forget_oversized(&mut self) {
        self.oversized = None;
    }

    fn block(&mut self, id: usize) -> io::Result<&Decoded> {
        let block = &self.blocks[id];
        // An oversized single row cannot evict all the small lookup blocks or
        // multiply the cache bound by the maximum value size.
        let slot = if block.raw as usize > BLOCK_TARGET {
            &mut self.oversized
        } else {
            &mut self.cache[id % self.cache.len()]
        };
        if slot.as_ref().is_none_or(|decoded| decoded.id != id) {
            *slot = None;
            *slot = Some(Decoded::load(&self.file, id, block, &self.directory)?);
        }
        Ok(slot.as_ref().unwrap())
    }

    /// Read an exact binary key, including an empty key or value.
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        Ok(self.get_ref(key)?.map(<[u8]>::to_vec))
    }

    /// Borrow an exact value from its verified block until the next reader operation.
    pub fn get_ref(&mut self, key: &[u8]) -> io::Result<Option<&[u8]>> {
        let directory = self.directory.as_slice();
        let id = self
            .blocks
            .partition_point(|block| block.last(directory) < key);
        if self
            .blocks
            .get(id)
            .is_none_or(|block| block.first(directory) > key)
        {
            return Ok(None);
        }
        let block = self.block(id)?;
        let index = block
            .offsets
            .binary_search_by(|&offset| block.row(offset).0.cmp(key));
        Ok(index.ok().map(|i| block.row(block.offsets[i]).1))
    }

    /// Visit up to `limit` authenticated rows in ascending order. Empty or
    /// inverted bounds return zero. Earlier callbacks may precede an I/O error.
    pub fn visit_forward(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        visit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        self.visit(lower, upper, limit, false, visit)
    }

    /// Visit up to `limit` rows in descending order, using the same ascending
    /// lower and upper bounds as `visit_forward`.
    pub fn visit_reverse(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        visit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        self.visit(lower, upper, limit, true, visit)
    }

    fn visit(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        reverse: bool,
        mut visit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        let below = |key: &[u8]| match lower {
            Bound::Included(start) => key < start,
            Bound::Excluded(start) => key <= start,
            Bound::Unbounded => false,
        };
        let above = |key: &[u8]| match upper {
            Bound::Included(end) => key > end,
            Bound::Excluded(end) => key >= end,
            Bound::Unbounded => false,
        };
        if limit == 0 {
            return Ok(0);
        }
        let directory = self.directory.as_slice();
        let start = match lower {
            Bound::Unbounded => 0,
            _ => self.blocks.partition_point(|b| below(b.last(directory))),
        };
        let end = match upper {
            Bound::Unbounded => self.blocks.len(),
            _ => self.blocks.partition_point(|b| !above(b.first(directory))),
        };
        let mut seen = 0;
        for step in 0..end.saturating_sub(start) {
            if seen == limit {
                break;
            }
            let id = if reverse {
                end - 1 - step
            } else {
                start + step
            };
            let cut_lower = id == start && below(self.blocks[id].first(&self.directory));
            let cut_upper = id + 1 == end && above(self.blocks[id].last(&self.directory));
            let block = self.block(id)?;
            let lo = if cut_lower {
                block
                    .offsets
                    .partition_point(|&offset| below(block.row(offset).0))
            } else {
                0
            };
            let hi = if cut_upper {
                block
                    .offsets
                    .partition_point(|&offset| !above(block.row(offset).0))
            } else {
                block.offsets.len()
            };
            let take = hi.saturating_sub(lo).min(limit - seen);
            for index in 0..take {
                let i = if reverse { hi - 1 - index } else { lo + index };
                let (key, value) = block.row(block.offsets[i]);
                visit(key, value)?;
                seen += 1;
            }
        }
        Ok(seen)
    }
}

#[cfg(unix)]
#[path = "live_levels_cursor.rs"]
mod live_cursor;
#[cfg(unix)]
pub(super) use live_cursor::RunCursor;
