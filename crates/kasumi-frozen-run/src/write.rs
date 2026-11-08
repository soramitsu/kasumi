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
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let mut directory = Vec::from(DIRECTORY_MAGIC.as_slice());
    directory.extend(0u32.to_le_bytes());
    let mut blocks = 0u32;
    let mut raw = Vec::with_capacity(BLOCK_TARGET);
    let mut first = Vec::new();
    let mut last = Vec::new();
    let mut seen = false;
    for (key, value) in rows {
        let (key, value) = (key.as_ref(), value.as_ref());
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
            write_block(&mut file, &mut directory, &mut blocks, &raw, &first, &last)?;
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
    }
    if !raw.is_empty() {
        write_block(&mut file, &mut directory, &mut blocks, &raw, &first, &last)?;
    }
    directory[8..12].copy_from_slice(&blocks.to_le_bytes());
    let digest = Sha256::digest(&directory).into();
    file.write_all(&directory)?;
    file.write_all(&(directory.len() as u64).to_le_bytes())?;
    file.write_all(FOOTER_MAGIC)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(digest)
}

fn write_block(
    file: &mut impl Write,
    directory: &mut Vec<u8>,
    blocks: &mut u32,
    raw: &[u8],
    first: &[u8],
    last: &[u8],
) -> io::Result<()> {
    if *blocks as usize >= MAX_BLOCKS
        || directory.len() + DIRECTORY_ENTRY_HEADER + first.len() + last.len() > MAX_DIRECTORY
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sorted-run directory limit exceeded",
        ));
    }
    let bytes = lz4_flex::block::compress(raw);
    file.write_all(&bytes)?;
    directory.extend((bytes.len() as u32).to_le_bytes());
    directory.extend((raw.len() as u32).to_le_bytes());
    directory.extend(Sha256::digest(&bytes));
    directory.extend((first.len() as u16).to_le_bytes());
    directory.extend((last.len() as u16).to_le_bytes());
    directory.extend_from_slice(first);
    directory.extend_from_slice(last);
    *blocks += 1;
    Ok(())
}
