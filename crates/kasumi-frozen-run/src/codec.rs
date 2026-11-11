//! Block compression. Every reader expands LZ4; Zstandard blocks appear only
//! in runs whose writer was asked for them.
use crate::{BLOCK_TARGET, invalid};
use std::{cell::RefCell, io};

/// How a writer compresses the blocks of a sorted run or live database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockCodec {
    /// LZ4 blocks. The default, readable by every version.
    #[default]
    Lz4,
    /// Each block keeps the smaller of its LZ4 and Zstandard forms. Files are
    /// smaller; writing takes about twice the CPU and expanding a block that
    /// is not cached about a third more. Readers from before this codec
    /// existed refuse these files.
    Zstd,
}

/// Level 7 is where 32 KiB blocks of indexer rows stop shrinking: on the
/// Stats fixture it is 12% smaller than level 3 and within 0.1% of level 9,
/// at about half of level 9's time.
const ZSTD_LEVEL: i32 = 7;

std::thread_local! {
    static COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> =
        const { RefCell::new(None) };
    static EXPANDER: RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        const { RefCell::new(None) };
}

/// One Zstandard frame of `raw`. Each thread keeps one compression context;
/// a context that compressed an oversized row is released, since it keeps
/// tables sized for that row.
pub(crate) fn zstd_compress(raw: &[u8]) -> io::Result<Vec<u8>> {
    COMPRESSOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        let compressor = match &mut *slot {
            Some(compressor) => compressor,
            None => slot.insert(zstd::bulk::Compressor::new(ZSTD_LEVEL)?),
        };
        let packed = compressor.compress(raw);
        if raw.len() > BLOCK_TARGET {
            *slot = None;
        }
        packed
    })
}

/// The first bytes of a frame in the current Zstandard format.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Expand an authenticated Zstandard block into exactly `len` bytes. A block
/// is one frame of the current format and nothing else: the library would
/// also take skippable and concatenated frames, and legacy formats when a
/// build enables them, so what a reader accepts must not depend on that. The
/// output buffer is allocated for `len`, so a frame that would expand
/// further fails instead of growing it. Each thread keeps one context.
pub(crate) fn zstd_expand(packed: &[u8], len: usize) -> io::Result<Vec<u8>> {
    if !packed.starts_with(&ZSTD_MAGIC)
        || zstd::zstd_safe::find_frame_compressed_size(packed).ok() != Some(packed.len())
    {
        return Err(invalid("invalid Zstandard block"));
    }
    EXPANDER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let expander = match &mut *slot {
            Some(expander) => expander,
            None => slot.insert(zstd::bulk::Decompressor::new()?),
        };
        let mut bytes = Vec::with_capacity(len);
        let written = expander
            .decompress_to_buffer(packed, &mut bytes)
            .map_err(|_| invalid("invalid Zstandard block"))?;
        if written != len {
            return Err(invalid("sorted-run decoded length differs"));
        }
        Ok(bytes)
    })
}

/// The largest Zstandard frame a writer can produce for `len` input bytes.
pub(crate) fn zstd_bound(len: usize) -> usize {
    zstd::zstd_safe::compress_bound(len)
}
