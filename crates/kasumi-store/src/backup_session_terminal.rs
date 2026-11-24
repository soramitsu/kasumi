//! Reserve the maximum terminal extent before publication. A v2 terminal keeps
//! the same inode while releasing its zero padding after the durable rename.
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

const FIXED_MAGIC: &[u8; 8] = b"KSMSES01";
const COMPACT_MAGIC: &[u8; 8] = b"KSMSES02";
pub(super) const HEADER_BYTES: usize = 72;
pub(super) const IO_CHUNK_BYTES: usize = 4096;
pub(super) const PAYLOAD_BYTES: usize =
    super::MAX_SESSION_RECORD_BYTES + crate::backup::HEADER_LIMIT + 84;
pub(super) const FILE_BYTES: usize = HEADER_BYTES + PAYLOAD_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Terminal {
    Intent,
    Outcome,
}
impl Terminal {
    const fn tag(self) -> u8 {
        match self {
            Self::Intent => 1,
            Self::Outcome => 2,
        }
    }
    pub(super) const fn published(self) -> &'static str {
        match self {
            Self::Intent => "intent.kasumi",
            Self::Outcome => "outcome.kasumi",
        }
    }
    pub(super) const fn reserve(self) -> &'static str {
        match self {
            Self::Intent => "intent.reserve",
            Self::Outcome => "outcome.reserve",
        }
    }
}

pub(super) fn header(
    session: Uuid,
    slot: Terminal,
    payload: &[u8],
) -> io::Result<[u8; HEADER_BYTES]> {
    if session.is_nil() || payload.is_empty() || payload.len() > PAYLOAD_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut result = [0; HEADER_BYTES];
    result[..8].copy_from_slice(COMPACT_MAGIC);
    result[8] = slot.tag();
    result[16..32].copy_from_slice(session.as_bytes());
    result[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    result[40..72].copy_from_slice(&Sha256::digest(payload));
    Ok(result)
}

fn parse_header(bytes: &[u8], session: Uuid, slot: Terminal, extent: u64) -> io::Result<usize> {
    if bytes.len() != HEADER_BYTES
        || session.is_nil()
        || (&bytes[..8] != FIXED_MAGIC && &bytes[..8] != COMPACT_MAGIC)
        || bytes[8] != slot.tag()
        || bytes[9..16] != [0; 7]
        || bytes[16..32] != *session.as_bytes()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("fixed header"),
    ))
    .map_err(|_| io::ErrorKind::InvalidData)?;
    if length == 0 || length > PAYLOAD_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // A crash after rename and before truncate leaves a complete padded v2.
    // Only v2 may also have the exact compact length.
    if extent != FILE_BYTES as u64
        && !(&bytes[..8] == COMPACT_MAGIC && extent == (HEADER_BYTES + length) as u64)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(length)
}

#[cfg(test)]
pub(super) fn decode(
    bytes: &[u8],
    session: Uuid,
    slot: Terminal,
    limit: usize,
) -> io::Result<&[u8]> {
    let header = bytes
        .get(..HEADER_BYTES)
        .ok_or(io::ErrorKind::InvalidData)?;
    let length = parse_header(header, session, slot, bytes.len() as u64)?;
    if length > limit {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let end = HEADER_BYTES
        .checked_add(length)
        .ok_or(io::ErrorKind::InvalidData)?;
    let payload = &bytes[HEADER_BYTES..end];
    if bytes[40..72] != Sha256::digest(payload)[..] || bytes[end..].iter().any(|&byte| byte != 0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
}

fn read_header(
    file: &crate::NodeDiskFile,
    session: Uuid,
    slot: Terminal,
) -> io::Result<([u8; HEADER_BYTES], usize, usize)> {
    let result = (|| {
        let extent = file.observed_len()?;
        let mut header = [0; HEADER_BYTES];
        file.read_exact_at(&mut header, 0)?;
        let length = parse_header(&header, session, slot, extent)?;
        Ok((header, length, extent as usize))
    })();
    result.inspect_err(|_| file.owner_failed())
}

/// Ordinary classification checks only the physical length and fixed header.
/// A full v2 left by an interrupted publication must authenticate the payload
/// and padding before that padding can be reclaimed by a subsequent writer.
pub(super) fn classify(
    file: &mut crate::NodeDiskFile,
    session: Uuid,
    slot: Terminal,
) -> io::Result<()> {
    let (header, length, extent) = read_header(file, session, slot)?;
    let end = HEADER_BYTES + length;
    if &header[..8] == FIXED_MAGIC || end == extent {
        return Ok(());
    }
    let mut buffer = [0; IO_CHUNK_BYTES];
    let mut digest = Sha256::new();
    let mut offset = HEADER_BYTES;
    let verify = (|| {
        while offset < extent {
            let count = buffer.len().min(extent - offset);
            file.read_exact_at(&mut buffer[..count], offset as u64)?;
            let payload = end.saturating_sub(offset).min(count);
            digest.update(&buffer[..payload]);
            if buffer[payload..count].iter().any(|&byte| byte != 0) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            offset += count;
        }
        if digest.finalize()[..] != header[40..72] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    })();
    verify.inspect_err(|_: &io::Error| file.owner_failed())?;
    file.shrink(end as u64)
}

/// The returned allocation is the exact original ciphertext length, bounded by
/// the caller before allocation. Canonical fixed padding uses the admitted
/// per-file scratch buffer; a small caller limit never allocates a full container.
pub(super) fn read(
    file: &crate::NodeDiskFile,
    session: Uuid,
    slot: Terminal,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let (header, length, extent) = read_header(file, session, slot)?;
    if length > limit {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let result = (|| {
        let mut payload = vec![0; length];
        file.read_exact_at(&mut payload, HEADER_BYTES as u64)?;
        if header[40..72] != Sha256::digest(&payload)[..] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut buffer = [0; IO_CHUNK_BYTES];
        let mut offset = HEADER_BYTES + length;
        while offset < extent {
            let count = buffer.len().min(extent - offset);
            file.read_exact_at(&mut buffer[..count], offset as u64)?;
            if buffer[..count].iter().any(|&byte| byte != 0) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            offset += count;
        }
        Ok(payload)
    })();
    result.inspect_err(|_| file.owner_failed())
}

/// The sole physical owner stays claimed for the whole write/sync/publish phase.
/// Keep the full durable length and canonical zero tail on every retry.
pub(super) fn write(
    file: &crate::NodeDiskFile,
    session: Uuid,
    slot: Terminal,
    payload: &[u8],
) -> io::Result<()> {
    let header = header(session, slot, payload)?;
    if file.observed_len()? != FILE_BYTES as u64 {
        file.owner_failed();
        return Err(io::ErrorKind::InvalidData.into());
    }
    // A fresh reserve is already zero. Materializing its padding can pin
    // the entire large COW extent to one live block even after truncate.
    // Repair only stale bytes from a previous attempt. Persist that tail
    // separately so the final payload can occupy its own short extent.
    let mut buffer = [0; IO_CHUNK_BYTES];
    let mut offset = HEADER_BYTES + payload.len();
    while offset < FILE_BYTES {
        let count = buffer.len().min(FILE_BYTES - offset);
        file.read_exact_at(&mut buffer[..count], offset as u64)?;
        if buffer[..count].iter().any(|&byte| byte != 0) {
            buffer[..count].fill(0);
            file.write_all_at(&buffer[..count], offset as u64)?;
        }
        offset += count;
    }
    file.sync_all()?;
    // The reserve stays private until the complete contents and header have
    // been synchronized and the original immutable rename publishes them.
    file.write_all_at(payload, HEADER_BYTES as u64)?;
    file.write_all_at(&header, 0)?;
    // The reserve's name is already durable; publication syncs the rename.
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(session: Uuid, slot: Terminal, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; FILE_BYTES];
        bytes[..HEADER_BYTES].copy_from_slice(&header(session, slot, payload).unwrap());
        bytes[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn fixed_terminal_roundtrip_preserves_exact_ciphertext_and_full_extent() {
        let session = Uuid::new_v4();
        for slot in [Terminal::Intent, Terminal::Outcome] {
            let payload = vec![0xa5; PAYLOAD_BYTES];
            let bytes = encoded(session, slot, &payload);
            assert_eq!(bytes.len(), FILE_BYTES);
            assert_eq!(
                decode(&bytes, session, slot, PAYLOAD_BYTES).unwrap(),
                payload
            );
            let short = encoded(session, slot, b"ciphertext");
            assert_eq!(short.len(), FILE_BYTES);
            assert_eq!(decode(&short, session, slot, 10).unwrap(), b"ciphertext");
            let compact_len = HEADER_BYTES + 10;
            assert_eq!(
                decode(&short[..compact_len], session, slot, 10).unwrap(),
                b"ciphertext"
            );
            assert!(decode(&short[..compact_len + 1], session, slot, 10).is_err());
            let mut legacy = short;
            legacy[..8].copy_from_slice(FIXED_MAGIC);
            assert_eq!(decode(&legacy, session, slot, 10).unwrap(), b"ciphertext");
            assert!(decode(&legacy[..compact_len], session, slot, 10).is_err());
        }
    }

    #[test]
    fn unknown_formats_legacy_bytes_and_every_noncanonical_field_reject() {
        let session = Uuid::new_v4();
        let bytes = encoded(session, Terminal::Intent, b"ciphertext");
        for offset in [
            0,
            7,
            8,
            9,
            15,
            16,
            31,
            32,
            39,
            40,
            71,
            HEADER_BYTES,
            FILE_BYTES - 1,
        ] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 0x80;
            assert!(decode(&corrupt, session, Terminal::Intent, PAYLOAD_BYTES).is_err());
        }
        assert!(decode(&bytes, Uuid::new_v4(), Terminal::Intent, PAYLOAD_BYTES).is_err());
        assert!(decode(&bytes, session, Terminal::Outcome, PAYLOAD_BYTES).is_err());
        assert!(decode(&bytes, session, Terminal::Intent, 9).is_err());
        assert!(
            decode(
                &bytes[..FILE_BYTES - 1],
                session,
                Terminal::Intent,
                PAYLOAD_BYTES
            )
            .is_err()
        );
        assert!(
            decode(
                b"old unframed ciphertext",
                session,
                Terminal::Intent,
                PAYLOAD_BYTES
            )
            .is_err()
        );
        assert!(
            decode(
                &vec![0; FILE_BYTES],
                session,
                Terminal::Intent,
                PAYLOAD_BYTES
            )
            .is_err()
        );
        assert!(header(Uuid::nil(), Terminal::Intent, b"ciphertext").is_err());
        assert!(header(session, Terminal::Intent, b"").is_err());
        assert!(header(session, Terminal::Intent, &vec![0; PAYLOAD_BYTES + 1]).is_err());
    }
}
