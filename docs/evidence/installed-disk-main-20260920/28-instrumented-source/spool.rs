//! Seekable scratch storage. Only independently authenticated ciphertext reaches
//! the temporary file; the random key dies with the final spool owner.
use crate::{ScratchDisk, SecretKey};
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const BLOCK: usize = 64 << 10;
const SLOT: u64 = BLOCK as u64 + 40;

pub struct EncryptedSpool {
    file: std::fs::File,
    // Field order closes the anonymous file before releasing its disk charge.
    charge: crate::scratch_disk::Charge,
    key: SecretKey,
    id: [u8; 16],
    length: u64,
    position: u64,
    limit: u64,
    cached_index: Option<u64>,
    cached: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
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
    pub fn new(disk: &Arc<ScratchDisk>, limit: u64) -> io::Result<Self> {
        if Self::offset(limit.div_ceil(BLOCK as u64))? > i64::MAX as u64 {
            return Err(io::Error::other(
                "spool limit exceeds supported file offsets",
            ));
        }
        let (file, charge) = disk.file()?;
        // Unnamed temporary files have owner-only permissions and cannot be
        // reopened after a crash. No key or pathname is persisted.
        Ok(Self {
            file,
            charge,
            key: SecretKey::random().map_err(io::Error::other)?,
            id: *uuid::Uuid::new_v4().as_bytes(),
            length: 0,
            position: 0,
            limit,
            cached_index: None,
            cached: Zeroizing::new(vec![0; BLOCK]),
            ciphertext: Zeroizing::new(vec![0; SLOT as usize]),
            dirty: false,
            append_digest: Some(Sha256::new()),
        })
    }
    pub fn disk(&self) -> &Arc<ScratchDisk> {
        self.charge.disk()
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

    pub(crate) fn check_owner(&self) -> io::Result<()> {
        self.charge.check_owner(&self.file)
    }

    pub(crate) fn owner_failed(&self) {
        self.charge.fail_owner();
    }

    pub(crate) fn reserve_growth(&mut self, current: u64, requested: u64) -> io::Result<()> {
        self.check_owner()?;
        if current != self.length || requested < current {
            self.owner_failed();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.reserve_length(requested)
    }

    fn reserve_length(&mut self, requested: u64) -> io::Result<()> {
        self.check_owner()?;
        if requested > self.limit {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        self.charge
            .grow(Self::offset(requested.div_ceil(BLOCK as u64))?)
    }

    pub(crate) fn settle_growth(&mut self, actual: u64) -> io::Result<()> {
        self.check_owner()?;
        if actual != self.length {
            self.owner_failed();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.flush_block()?;
        self.charge
            .shrink(&self.file, Self::offset(actual.div_ceil(BLOCK as u64))?)
    }

    pub(crate) fn sync_all(&mut self) -> io::Result<()> {
        self.check_owner()?;
        self.flush_block()?;
        self.file.sync_all().inspect_err(|_| self.owner_failed())
    }

    pub(crate) fn close(mut self) -> io::Result<()> {
        // The anonymous inode is physically released by the actual final file
        // close even when sync failed; field order releases its charge afterward.
        let result = self.sync_all();
        drop(self);
        result
    }

    pub(crate) fn resize(&mut self, length: u64) -> io::Result<()> {
        self.check_owner()?;
        // No cache flush, digest change, logical resize, or physical write occurs
        // until the complete ciphertext resize has been admitted atomically.
        self.reserve_length(length)?;
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
            let physical = Self::offset(length.div_ceil(BLOCK as u64))?;
            self.file
                .set_len(physical)
                .inspect_err(|_| self.owner_failed())?;
            self.length = length;
            if !length.is_multiple_of(BLOCK as u64) {
                self.block(length / BLOCK as u64)?;
                self.cached[(length % BLOCK as u64) as usize..].fill(0);
                self.dirty = true;
                self.flush_block()?;
            }
            self.charge.shrink(&self.file, physical)?;
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
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
    }
    fn flush_block(&mut self) -> io::Result<()> {
        self.check_owner()?;
        if self.dirty {
            let index = self.cached_index.expect("dirty spool has a cached block");
            let mut nonce = [0; 24];
            getrandom::fill(&mut nonce).map_err(|_| {
                self.owner_failed();
                io::Error::from(io::ErrorKind::Other)
            })?;
            let aad = self.aad(index);
            self.ciphertext[..24].copy_from_slice(&nonce);
            self.ciphertext[24..24 + BLOCK].copy_from_slice(&self.cached);
            let cipher = XChaCha20Poly1305::new(self.key.as_bytes().into());
            let tag = cipher
                .encrypt_in_place_detached(
                    XNonce::from_slice(&nonce),
                    &aad,
                    &mut self.ciphertext[24..24 + BLOCK],
                )
                .map_err(|_| {
                    crate::scratch_disk::trace_failure(
                        "encrypt [index,length,position,limit,dirty,0,0,0]",
                        [
                            index,
                            self.length,
                            self.position,
                            self.limit,
                            u64::from(self.dirty),
                            0,
                            0,
                            0,
                        ],
                    );
                    self.owner_failed();
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            self.ciphertext[24 + BLOCK..].copy_from_slice(&tag);
            self.file
                .seek(SeekFrom::Start(Self::offset(index)?))
                .inspect_err(|_| self.owner_failed())?;
            self.file
                .write_all(&self.ciphertext)
                .inspect_err(|_| self.owner_failed())?;
            self.charge.observe(&self.file).inspect_err(|_| {
                crate::scratch_disk::trace_failure(
                    "flushed block [index,length,position,limit,dirty,0,0,0]",
                    [
                        index,
                        self.length,
                        self.position,
                        self.limit,
                        u64::from(self.dirty),
                        0,
                        0,
                        0,
                    ],
                );
            })?;
            self.dirty = false;
        }
        Ok(())
    }
    fn block(&mut self, index: u64) -> io::Result<()> {
        self.check_owner()?;
        if self.cached_index == Some(index) {
            return Ok(());
        }
        self.flush_block()?;
        self.cached_index = None;
        self.cached.fill(0);
        if index < self.length.div_ceil(BLOCK as u64) {
            self.file
                .seek(SeekFrom::Start(Self::offset(index)?))
                .inspect_err(|_| self.owner_failed())?;
            self.file
                .read_exact(&mut self.ciphertext)
                .inspect_err(|_| self.owner_failed())?;
            let nonce: [u8; 24] = self.ciphertext[..24].try_into().expect("fixed nonce");
            let tag: [u8; 16] = self.ciphertext[24 + BLOCK..].try_into().expect("fixed tag");
            let aad = self.aad(index);
            let cipher = XChaCha20Poly1305::new(self.key.as_bytes().into());
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(&nonce),
                    &aad,
                    &mut self.ciphertext[24..24 + BLOCK],
                    Tag::from_slice(&tag),
                )
                .map_err(|_| {
                    crate::scratch_disk::trace_failure(
                        "decrypt [index,length,position,limit,dirty,0,0,0]",
                        [
                            index,
                            self.length,
                            self.position,
                            self.limit,
                            u64::from(self.dirty),
                            0,
                            0,
                            0,
                        ],
                    );
                    self.owner_failed();
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            self.cached
                .copy_from_slice(&self.ciphertext[24..24 + BLOCK]);
        }
        self.cached_index = Some(index);
        Ok(())
    }
}

impl Read for EncryptedSpool {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check_owner()?;
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
        self.check_owner()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self
            .position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        // Seeking is bounded to the existing stream: sparse holes cannot turn
        // one peer's tiny write into unbounded allocation or disk work.
        let index = self.position / BLOCK as u64;
        let offset = (self.position % BLOCK as u64) as usize;
        let count = bytes.len().min(BLOCK - offset);
        let end = self.length.max(self.position + count as u64);
        self.reserve_length(end)?;
        self.block(index)?;
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
        self.check_owner()?;
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

/// An immutable, encrypted snapshot with cheap clones and independent readers.
/// Digest and length are computed only after the producer completes successfully.
#[derive(Clone, Debug)]
pub struct SnapshotImage {
    disk: Arc<ScratchDisk>,
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
    pub fn disk(&self) -> &Arc<ScratchDisk> {
        &self.disk
    }
    pub fn capture(
        disk: &Arc<ScratchDisk>,
        limit: u64,
        write: impl FnOnce(&mut dyn Write) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let mut spool = EncryptedSpool::new(disk, limit)?;
        write(&mut spool)?;
        Self::freeze(spool)
    }
    pub fn from_bytes(disk: &Arc<ScratchDisk>, bytes: &[u8]) -> anyhow::Result<Self> {
        Self::capture(disk, bytes.len() as u64, |writer| {
            Ok(writer.write_all(bytes)?)
        })
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
            disk: spool.disk().clone(),
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
    fn interleaved_record_appends_preserve_admission_and_authentication() {
        fn body(sequence: usize, bytes: &mut [u8; 1280]) -> &[u8] {
            let length = 256 + sequence * 37 % 1024;
            for (offset, byte) in bytes[..length].iter_mut().enumerate() {
                *byte = ((sequence + offset * 13) % 251) as u8;
            }
            &bytes[..length]
        }
        fn append(spool: &mut EncryptedSpool, sequence: usize, bytes: &mut [u8; 1280]) {
            let value = body(sequence, bytes);
            spool
                .write_all(&(value.len() as u64).to_be_bytes())
                .unwrap();
            spool.write_all(value).unwrap();
        }
        fn verify(spool: &mut EncryptedSpool, records: usize) {
            spool.flush().unwrap();
            spool.rewind().unwrap();
            let mut expected = [0; 1280];
            let mut actual = [0; 1280];
            for sequence in 0..records {
                let mut prefix = [0; 8];
                spool.read_exact(&mut prefix).unwrap();
                let value = body(sequence, &mut expected);
                assert_eq!(u64::from_be_bytes(prefix), value.len() as u64);
                spool.read_exact(&mut actual[..value.len()]).unwrap();
                assert_eq!(&actual[..value.len()], value);
            }
            assert_eq!(spool.read(&mut actual).unwrap(), 0);
        }

        let disk = ScratchDisk::isolated_fixture(64 << 20);
        let mut commands = EncryptedSpool::new(&disk, 16 << 20).unwrap();
        let mut audit = EncryptedSpool::new(&disk, 16 << 20).unwrap();
        let mut bytes = [0; 1280];
        for sequence in 0..4200 {
            append(&mut commands, sequence, &mut bytes);
            append(&mut audit, sequence * 2, &mut bytes);
            append(&mut audit, sequence * 2 + 1, &mut bytes);
        }
        assert!(commands.len() > 2 << 20);
        assert!(audit.len() > 2 << 20);
        verify(&mut commands, 4200);
        verify(&mut audit, 8400);
        commands.close().unwrap();
        audit.close().unwrap();
    }

    #[test]
    fn encrypted_spool_seek_overwrite_and_bounds() {
        let mut spool =
            EncryptedSpool::new(&ScratchDisk::isolated_fixture(1 << 20), (BLOCK * 3) as u64)
                .unwrap();
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
        let mut spool =
            EncryptedSpool::new(&ScratchDisk::isolated_fixture(1 << 20), (BLOCK * 3) as u64)
                .unwrap();
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
