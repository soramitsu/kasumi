use super::*;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::Path};

/// Seal unique, strictly ascending binary rows. An empty run is valid.
/// Keys may be up to 4 KiB and values up to 32 MiB. The writer buffers one
/// block and its bounded sparse directory. Successful return means that the
/// file and its directory entry were synchronized. An existing destination
/// is never replaced. A directory-sync failure can leave the new file present.
pub fn seal<K, V>(
    path: impl AsRef<Path>,
    rows: impl IntoIterator<Item = (K, V)>,
) -> io::Result<[u8; 32]>
where
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    seal_with_codec(path, rows, BlockCodec::Lz4)
}

/// Seal as `seal` does, compressing blocks with `codec`. A run sealed with
/// `BlockCodec::Zstd` is smaller and needs a reader that knows that codec.
pub fn seal_with_codec<K, V>(
    path: impl AsRef<Path>,
    rows: impl IntoIterator<Item = (K, V)>,
    codec: BlockCodec,
) -> io::Result<[u8; 32]>
where
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let digest = write_rows(file.as_file_mut(), codec, |write| {
        for (key, value) in rows {
            write(key.as_ref(), value.as_ref())?;
        }
        Ok(())
    })?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(digest)
}

/// Write an ordered stream into a fresh empty file. The owner synchronizes
/// and publishes that file after all input reads and output writes succeed.
pub(super) fn write_rows(
    file: &mut File,
    codec: BlockCodec,
    rows: impl FnOnce(&mut dyn FnMut(&[u8], &[u8]) -> io::Result<()>) -> io::Result<()>,
) -> io::Result<[u8; 32]> {
    // An LZ4 run keeps the version 2 layout byte for byte.
    let (directory_magic, footer_magic) = match codec {
        BlockCodec::Lz4 => (DIRECTORY_MAGIC, FOOTER_MAGIC),
        BlockCodec::Zstd => (DIRECTORY_MAGIC_ZSTD, FOOTER_MAGIC_ZSTD),
    };
    let mut directory = Vec::from(directory_magic.as_slice());
    directory.extend(0u32.to_le_bytes());
    let mut blocks = 0u32;
    let mut raw = Vec::with_capacity(BLOCK_TARGET);
    let mut first = Vec::new();
    let mut last = Vec::new();
    let mut seen = false;
    rows(&mut |key, value| {
        if key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "row exceeds sorted-run limits",
            ));
        }
        if seen && key <= last.as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "keys must strictly increase",
            ));
        }
        let record_len = ROW_HEADER + key.len() + value.len();
        if !raw.is_empty() && raw.len() + record_len > BLOCK_TARGET {
            write_block(
                file,
                &mut directory,
                &mut blocks,
                &raw,
                &first,
                &last,
                codec,
            )?;
            raw.clear();
        }
        if raw.is_empty() {
            first.clear();
            first.extend_from_slice(key);
        }
        raw.extend((key.len() as u16).to_le_bytes());
        raw.extend((value.len() as u32).to_le_bytes());
        raw.extend_from_slice(key);
        raw.extend_from_slice(value);
        last.clear();
        last.extend_from_slice(key);
        seen = true;
        Ok(())
    })?;
    if !raw.is_empty() {
        write_block(
            file,
            &mut directory,
            &mut blocks,
            &raw,
            &first,
            &last,
            codec,
        )?;
    }
    directory[8..12].copy_from_slice(&blocks.to_le_bytes());
    let digest = Sha256::digest(&directory).into();
    file.write_all(&directory)?;
    file.write_all(&(directory.len() as u64).to_le_bytes())?;
    file.write_all(footer_magic)?;
    Ok(digest)
}

fn write_block(
    file: &mut impl Write,
    directory: &mut Vec<u8>,
    blocks: &mut u32,
    raw: &[u8],
    first: &[u8],
    last: &[u8],
    codec: BlockCodec,
) -> io::Result<()> {
    let metadata_end = directory.len() + DIRECTORY_ENTRY_HEADER + first.len() + last.len();
    if *blocks as usize >= MAX_BLOCKS || metadata_end > MAX_DIRECTORY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sorted-run directory limit exceeded",
        ));
    }
    // Canonical rows or prefix-coded rows: the smaller under LZ4, counting
    // the four directory bytes a prefix-coded block needs for its
    // intermediate length. A tie keeps canonical rows.
    let mut bytes = lz4_flex::block::compress(raw);
    let mut prefix_len = None;
    let mut zstd = false;
    let cost = |packed: &[u8], prefixed: bool| packed.len() + if prefixed { 4 } else { 0 };
    let prefixed = if first != last && metadata_end + 4 <= MAX_DIRECTORY {
        Some(prefix::encode(raw)?)
    } else {
        None
    };
    if let Some(encoded) = &prefixed {
        let candidate = lz4_flex::block::compress(encoded);
        if cost(&candidate, true) < cost(&bytes, false) {
            bytes = candidate;
            prefix_len = Some(encoded.len() as u32);
        }
    }
    if codec == BlockCodec::Zstd {
        // One Zstandard pass, over the form LZ4 just preferred: whether key
        // prefixes are worth coding depends on the rows, not on the codec,
        // and a pass over each form would double the cost of writing.
        let stored = match (&prefixed, prefix_len) {
            (Some(encoded), Some(_)) => encoded.as_slice(),
            _ => raw,
        };
        // A tie keeps LZ4, which expands faster.
        let candidate = codec::zstd_compress(stored)?;
        if candidate.len() < bytes.len() {
            bytes = candidate;
            zstd = true;
        }
    }
    file.write_all(&bytes)?;
    let mut tagged = bytes.len() as u32;
    if prefix_len.is_some() {
        tagged |= PREFIX_FLAG;
    }
    if zstd {
        tagged |= ZSTD_FLAG;
    }
    directory.extend(tagged.to_le_bytes());
    directory.extend((raw.len() as u32).to_le_bytes());
    if let Some(len) = prefix_len {
        directory.extend(len.to_le_bytes());
    }
    directory.extend(Sha256::digest(&bytes));
    directory.extend((first.len() as u16).to_le_bytes());
    directory.extend((last.len() as u16).to_le_bytes());
    directory.extend_from_slice(first);
    directory.extend_from_slice(last);
    *blocks += 1;
    Ok(())
}
