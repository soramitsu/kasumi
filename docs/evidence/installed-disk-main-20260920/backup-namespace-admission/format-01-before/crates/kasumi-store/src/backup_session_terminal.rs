//! Canonical fixed-extent filesystem terminal records. Reserve paths never
//! decode as published records; publication moves the original reserved inode.
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"KSMSES01";
pub(super) const HEADER_BYTES: usize = 72;
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
        match self { Self::Intent => 1, Self::Outcome => 2 }
    }
    pub(super) const fn published(self) -> &'static str {
        match self { Self::Intent => "intent.kasumi", Self::Outcome => "outcome.kasumi" }
    }
    pub(super) const fn reserve(self) -> &'static str {
        match self { Self::Intent => "intent.reserve", Self::Outcome => "outcome.reserve" }
    }
}

pub(super) fn header(session: Uuid, slot: Terminal, payload: &[u8]) -> io::Result<[u8; HEADER_BYTES]> {
    if session.is_nil() || payload.is_empty() || payload.len() > PAYLOAD_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut result = [0; HEADER_BYTES];
    result[..8].copy_from_slice(MAGIC);
    result[8] = slot.tag();
    result[16..32].copy_from_slice(session.as_bytes());
    result[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    result[40..72].copy_from_slice(&Sha256::digest(payload));
    Ok(result)
}

pub(super) fn decode(
    bytes: &[u8],
    session: Uuid,
    slot: Terminal,
    limit: usize,
) -> io::Result<&[u8]> {
    if bytes.len() != FILE_BYTES || session.is_nil() || &bytes[..8] != MAGIC
        || bytes[8] != slot.tag() || bytes[9..16] != [0; 7]
        || bytes[16..32] != *session.as_bytes() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().expect("fixed header")))
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if length == 0 || length > PAYLOAD_BYTES || length > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let end = HEADER_BYTES.checked_add(length).ok_or(io::ErrorKind::InvalidData)?;
    let payload = &bytes[HEADER_BYTES..end];
    if bytes[40..72] != Sha256::digest(payload)[..] || bytes[end..].iter().any(|&byte| byte != 0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
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
    // Write the header last. A reserve remains a reserve even if a write fails;
    // only a later successful immutable rename can expose a terminal record.
    file.write_all_at(payload, HEADER_BYTES as u64)?;
    let zero = [0; 8192];
    let mut offset = HEADER_BYTES + payload.len();
    while offset < FILE_BYTES {
        let length = zero.len().min(FILE_BYTES - offset);
        file.write_all_at(&zero[..length], offset as u64)?;
        offset += length;
    }
    file.write_all_at(&header, 0)?;
    file.sync_all_and_parent()
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
            assert_eq!(decode(&bytes, session, slot, PAYLOAD_BYTES).unwrap(), payload);
            let short = encoded(session, slot, b"ciphertext");
            assert_eq!(short.len(), FILE_BYTES);
            assert_eq!(decode(&short, session, slot, 10).unwrap(), b"ciphertext");
        }
    }

    #[test]
    fn unknown_formats_legacy_bytes_and_every_noncanonical_field_reject() {
        let session = Uuid::new_v4();
        let bytes = encoded(session, Terminal::Intent, b"ciphertext");
        for offset in [0, 7, 8, 9, 15, 16, 31, 32, 39, 40, 71, HEADER_BYTES, FILE_BYTES - 1] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 0x80;
            assert!(decode(&corrupt, session, Terminal::Intent, PAYLOAD_BYTES).is_err());
        }
        assert!(decode(&bytes, Uuid::new_v4(), Terminal::Intent, PAYLOAD_BYTES).is_err());
        assert!(decode(&bytes, session, Terminal::Outcome, PAYLOAD_BYTES).is_err());
        assert!(decode(&bytes, session, Terminal::Intent, 9).is_err());
        assert!(decode(&bytes[..FILE_BYTES - 1], session, Terminal::Intent, PAYLOAD_BYTES).is_err());
        assert!(decode(b"old unframed ciphertext", session, Terminal::Intent, PAYLOAD_BYTES).is_err());
        assert!(decode(&vec![0; FILE_BYTES], session, Terminal::Intent, PAYLOAD_BYTES).is_err());
        assert!(header(Uuid::nil(), Terminal::Intent, b"ciphertext").is_err());
        assert!(header(session, Terminal::Intent, b"").is_err());
        assert!(header(session, Terminal::Intent, &vec![0; PAYLOAD_BYTES + 1]).is_err());
    }
}
