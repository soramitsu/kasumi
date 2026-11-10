use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    ops::Bound,
    path::Path,
};

struct Block {
    offset: u64,
    packed: usize,
    raw: usize,
    prefix_len: Option<usize>,
    digest: [u8; 32],
    first: Vec<u8>,
    last: Vec<u8>,
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

    fn load(file: &mut File, id: usize, block: &Block) -> io::Result<Self> {
        file.seek(SeekFrom::Start(block.offset))?;
        let mut packed = vec![0; block.packed];
        file.read_exact(&mut packed)?;
        if <[u8; 32]>::from(Sha256::digest(&packed)) != block.digest {
            return Err(invalid("sorted-run block digest differs"));
        }
        let lz4_len = block.prefix_len.unwrap_or(block.raw);
        let mut bytes = vec![0; lz4_len];
        let size = lz4_flex::block::decompress_into(&packed, &mut bytes)
            .map_err(|_| invalid("invalid LZ4 block"))?;
        if size != lz4_len {
            return Err(invalid("sorted-run decoded length differs"));
        }
        if block.prefix_len.is_some() {
            bytes = prefix::decode(&bytes, block.raw)?;
        }
        let mut input = bytes.as_slice();
        let max_rows = if block.raw > BLOCK_TARGET {
            1
        } else {
            block.raw / ROW_HEADER
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
            if previous.map_or(key != block.first, |prior| key <= prior) {
                return Err(invalid("sorted-run keys or first boundary differ"));
            }
            previous = Some(key);
            if block.raw > BLOCK_TARGET && !input.is_empty() {
                return Err(invalid("oversized sorted-run block must contain one row"));
            }
        }
        if previous != Some(block.last.as_slice()) {
            return Err(invalid("sorted-run last boundary differs"));
        }
        Ok(Self { id, bytes, offsets })
    }
}

/// A verified sparse index and a bounded, per-reader cache of decoded blocks.
/// Independent readers can open the same sealed file.
pub struct FrozenRun {
    file: File,
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
        Self::from_extent(file, 0, metadata.len(), expected_root)
    }

    /// Open a run embedded in a caller-validated extent of a larger file.
    pub(super) fn from_extent(
        mut file: File,
        start: u64,
        end: u64,
        expected_root: [u8; 32],
    ) -> io::Result<Self> {
        if end.checked_sub(start).is_none_or(|n| n < 16) {
            return Err(invalid("missing sorted-run footer"));
        }
        file.seek(SeekFrom::Start(end - 16))?;
        let mut footer = [0u8; 16];
        file.read_exact(&mut footer)?;
        let size = u64::from_le_bytes(footer[..8].try_into().unwrap());
        let v2 = &footer[8..] == FOOTER_MAGIC;
        if (!v2 && &footer[8..] != FOOTER_MAGIC_V1)
            || size > MAX_DIRECTORY as u64
            || size > end - start - 16
        {
            return Err(invalid("invalid sorted-run footer"));
        }
        let payload_end = end - 16 - size;
        file.seek(SeekFrom::Start(payload_end))?;
        let mut directory = vec![0; size as usize];
        file.read_exact(&mut directory)?;
        if <[u8; 32]>::from(Sha256::digest(&directory)) != expected_root {
            return Err(invalid("sorted-run root digest differs"));
        }
        let mut input = directory.as_slice();
        let directory_magic = if v2 {
            DIRECTORY_MAGIC
        } else {
            DIRECTORY_MAGIC_V1
        };
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
            let (packed, prefix_len) = if v2 && tagged & PREFIX_FLAG != 0 {
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
            if packed == 0
                || packed > lz4_flex::block::get_maximum_output_size(prefix_len.unwrap_or(raw))
                || first_len > MAX_KEY
                || last_len > MAX_KEY
            {
                return Err(invalid("invalid sorted-run block lengths"));
            }
            let first = take(&mut input, first_len)?;
            let last = take(&mut input, last_len)?;
            if first > last
                || blocks
                    .last()
                    .is_some_and(|prior| prior.last.as_slice() >= first)
            {
                return Err(invalid("unordered sorted-run block boundaries"));
            }
            blocks.push(Block {
                offset,
                packed,
                raw,
                prefix_len,
                digest,
                first: first.to_vec(),
                last: last.to_vec(),
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
            blocks,
            cache: std::array::from_fn(|_| None),
            oversized: None,
        })
    }

    #[cfg(unix)]
    /// Heap capacity retained by the authenticated index once decoded rows have been released.
    pub(super) fn index_heap_bytes(&self) -> usize {
        self.blocks.capacity() * size_of::<Block>()
            + self
                .blocks
                .iter()
                .map(|block| block.first.capacity() + block.last.capacity())
                .sum::<usize>()
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
        let slot = if block.raw > BLOCK_TARGET {
            &mut self.oversized
        } else {
            &mut self.cache[id % self.cache.len()]
        };
        if slot.as_ref().is_none_or(|decoded| decoded.id != id) {
            *slot = None;
            *slot = Some(Decoded::load(&mut self.file, id, block)?);
        }
        Ok(slot.as_ref().unwrap())
    }

    /// Read an exact binary key, including an empty key or value.
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        Ok(self.get_ref(key)?.map(<[u8]>::to_vec))
    }

    /// Borrow an exact value from its verified block until the next reader operation.
    pub fn get_ref(&mut self, key: &[u8]) -> io::Result<Option<&[u8]>> {
        let id = self
            .blocks
            .partition_point(|block| block.last.as_slice() < key);
        if self
            .blocks
            .get(id)
            .is_none_or(|block| block.first.as_slice() > key)
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
        let start = match lower {
            Bound::Unbounded => 0,
            _ => self.blocks.partition_point(|b| below(&b.last)),
        };
        let end = match upper {
            Bound::Unbounded => self.blocks.len(),
            _ => self.blocks.partition_point(|b| !above(&b.first)),
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
            let cut_lower = id == start && below(&self.blocks[id].first);
            let cut_upper = id + 1 == end && above(&self.blocks[id].last);
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
