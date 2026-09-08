//! Seekable scratch storage. Only independently authenticated ciphertext reaches
//! the temporary file; the random key dies with the final spool owner.
use crate::{SecretKey, decrypt, encrypt};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const BLOCK: usize = 64 << 10;
const SLOT: u64 = BLOCK as u64 + 40;

pub struct EncryptedSpool {
    file: std::fs::File,
    key: SecretKey,
    id: [u8; 16],
    length: u64,
    position: u64,
    limit: u64,
    cached_index: Option<u64>,
    cached: Zeroizing<Vec<u8>>,
    dirty: bool,
    append_digest: Option<Sha256>,
}

impl std::fmt::Debug for EncryptedSpool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSpool")
            .field("length", &self.length)
            .field("position", &self.position)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl EncryptedSpool {
    pub fn new(limit: u64) -> io::Result<Self> {
        // Unnamed temporary files have owner-only permissions and cannot be
        // reopened after a crash. No key or pathname is persisted.
        Ok(Self {
            file: tempfile::tempfile()?,
            key: SecretKey::random().map_err(io::Error::other)?,
            id: *uuid::Uuid::new_v4().as_bytes(),
            length: 0,
            position: 0,
            limit,
            cached_index: None,
            cached: Zeroizing::new(vec![0; BLOCK]),
            dirty: false,
            append_digest: Some(Sha256::new()),
        })
    }
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub(crate) fn resize(&mut self, length: u64) -> io::Result<()> {
        if length > self.limit {
            return Err(io::Error::other("spool resize exceeds budget"));
        }
        self.append_digest = None;
        let saved = self.position;
        if length > self.length {
            self.position = self.length;
            let zeroes = [0; BLOCK];
            while self.length < length {
                let count = (length - self.length).min(BLOCK as u64) as usize;
                self.write_all(&zeroes[..count])?;
            }
        } else if length < self.length {
            self.flush_block()?;
            self.cached_index = None;
            self.length = length;
            self.file
                .set_len(Self::offset(length.div_ceil(BLOCK as u64))?)?;
            if !length.is_multiple_of(BLOCK as u64) {
                self.block(length / BLOCK as u64)?;
                self.cached[(length % BLOCK as u64) as usize..].fill(0);
                self.dirty = true;
            }
        }
        self.position = saved.min(length);
        Ok(())
    }
    fn aad(&self, index: u64) -> [u8; 24] {
        let mut aad = [0; 24];
        aad[..16].copy_from_slice(&self.id);
        aad[16..].copy_from_slice(&index.to_be_bytes());
        aad
    }
    fn offset(index: u64) -> io::Result<u64> {
        index
            .checked_mul(SLOT)
            .ok_or_else(|| io::Error::other("spool offset overflow"))
    }
    fn flush_block(&mut self) -> io::Result<()> {
        if self.dirty {
            let index = self.cached_index.expect("dirty spool has a cached block");
            let ciphertext =
                encrypt(&self.key, &self.cached, &self.aad(index)).map_err(io::Error::other)?;
            self.file.seek(SeekFrom::Start(Self::offset(index)?))?;
            self.file.write_all(&ciphertext)?;
            self.dirty = false;
        }
        Ok(())
    }
    fn block(&mut self, index: u64) -> io::Result<()> {
        if self.cached_index == Some(index) {
            return Ok(());
        }
        self.flush_block()?;
        self.cached.fill(0);
        if index < self.length.div_ceil(BLOCK as u64) {
            let mut ciphertext = vec![0; SLOT as usize];
            self.file.seek(SeekFrom::Start(Self::offset(index)?))?;
            self.file.read_exact(&mut ciphertext)?;
            let plaintext = Zeroizing::new(
                decrypt(&self.key, &ciphertext, &self.aad(index)).map_err(io::Error::other)?,
            );
            if plaintext.len() != BLOCK {
                return Err(io::Error::other("invalid spool block"));
            }
            self.cached.copy_from_slice(&plaintext);
        }
        self.cached_index = Some(index);
        Ok(())
    }
}

impl Read for EncryptedSpool {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || bytes.is_empty() {
            return Ok(0);
        }
        let index = self.position / BLOCK as u64;
        self.block(index)?;
        let offset = (self.position % BLOCK as u64) as usize;
        let count = bytes
            .len()
            .min(BLOCK - offset)
            .min((self.length - self.position) as usize);
        bytes[..count].copy_from_slice(&self.cached[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}
impl Write for EncryptedSpool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self
            .position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            return Err(io::Error::other("spool byte budget exceeded"));
        }
        // Seeking is bounded to the existing stream: sparse holes cannot turn
        // one peer's tiny write into unbounded allocation or disk work.
        let index = self.position / BLOCK as u64;
        self.block(index)?;
        let offset = (self.position % BLOCK as u64) as usize;
        let count = bytes.len().min(BLOCK - offset);
        self.cached[offset..offset + count].copy_from_slice(&bytes[..count]);
        if self.position == self.length {
            if let Some(digest) = &mut self.append_digest {
                digest.update(&bytes[..count]);
            }
        } else {
            self.append_digest = None;
        }
        self.position += count as u64;
        self.length = self.length.max(self.position);
        self.dirty = true;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_block()
    }
}
impl Seek for EncryptedSpool {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::other("spool seek outside existing stream"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

/// An immutable, encrypted snapshot with cheap clones and independent readers.
/// Digest and length are computed only after the producer completes successfully.
#[derive(Clone, Debug)]
pub struct SnapshotImage {
    spool: Arc<Mutex<EncryptedSpool>>,
    length: u64,
    sha256: String,
}
impl PartialEq for SnapshotImage {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length && self.sha256 == other.sha256
    }
}
impl Eq for SnapshotImage {}
impl SnapshotImage {
    pub fn capture(
        limit: u64,
        write: impl FnOnce(&mut dyn Write) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let mut spool = EncryptedSpool::new(limit)?;
        write(&mut spool)?;
        Self::freeze(spool)
    }
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::capture(bytes.len() as u64, |writer| Ok(writer.write_all(bytes)?))
    }
    pub fn freeze(mut spool: EncryptedSpool) -> anyhow::Result<Self> {
        spool.flush()?;
        let digest = if let Some(digest) = spool.append_digest.take() {
            digest
        } else {
            spool.rewind()?;
            let mut digest = Sha256::new();
            let mut buffer = Zeroizing::new(vec![0; BLOCK]);
            loop {
                let count = spool.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            digest
        };
        let length = spool.len();
        Ok(Self {
            spool: Arc::new(Mutex::new(spool)),
            length,
            sha256: hex::encode(digest.finalize()),
        })
    }
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn reader(&self) -> SnapshotReader {
        SnapshotReader {
            image: self.clone(),
            position: 0,
        }
    }
    /// Use only for objects already bounded by a per-record budget.
    pub fn read_bounded(&self, limit: usize) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            self.length <= limit as u64,
            "snapshot exceeds record budget"
        );
        let mut bytes = Vec::with_capacity(usize::try_from(self.length)?);
        self.reader().read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

#[derive(Debug)]
pub struct SnapshotReader {
    image: SnapshotImage,
    position: u64,
}
impl Read for SnapshotReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut spool = self
            .image
            .spool
            .lock()
            .map_err(|_| io::Error::other("snapshot spool poisoned"))?;
        spool.seek(SeekFrom::Start(self.position))?;
        let count = spool.read(bytes)?;
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for SnapshotReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.image.length) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.image.length) {
            return Err(io::Error::other("snapshot seek outside stream"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_spool_seek_overwrite_and_bounds() {
        let mut spool = EncryptedSpool::new((BLOCK * 3) as u64).unwrap();
        let data: Vec<_> = (0..BLOCK * 2 + 31).map(|i| (i % 251) as u8).collect();
        spool.write_all(&data).unwrap();
        spool.seek(SeekFrom::Start(BLOCK as u64 - 5)).unwrap();
        spool.write_all(&[252; 20]).unwrap();
        let mut expected = data;
        expected[BLOCK - 5..BLOCK + 15].fill(252);
        spool.rewind().unwrap();
        let mut actual = Vec::new();
        spool.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(spool.seek(SeekFrom::End(1)).is_err());
        assert!(spool.write_all(&vec![0; BLOCK]).is_err());
        spool.flush().unwrap();
        spool.file.rewind().unwrap();
        let mut disk = Vec::new();
        spool.file.read_to_end(&mut disk).unwrap();
        assert!(!disk.windows(100).any(|window| window == &expected[..100]));
    }
    #[test]
    fn corrupted_or_reordered_blocks_fail_authentication() {
        let mut spool = EncryptedSpool::new((BLOCK * 3) as u64).unwrap();
        spool.write_all(&vec![7; BLOCK * 2]).unwrap();
        spool.flush().unwrap();
        spool.file.rewind().unwrap();
        let mut first = vec![0; SLOT as usize];
        spool.file.read_exact(&mut first).unwrap();
        spool.file.write_all(&first).unwrap();
        spool.rewind().unwrap();
        let mut data = vec![0; BLOCK];
        spool.read_exact(&mut data).unwrap();
        assert!(spool.read_exact(&mut data).is_err());
    }
}
