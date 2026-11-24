//! Document keys arrive in canonical (kind, collection, ID) order. Keep a
//! bounded page of offsets per group and index its final ID on the encrypted
//! scratch disk. A point read needs a single lower-bound seek.
use super::{EncryptedTable, Key, PendingIndex, Result, SnapshotImage, ensure};

const PAGE_BYTES: usize = 16 << 10;
const ROWS: usize = 256;
const KEY_BYTES: usize = 4096;

pub(super) fn packed(kind: u8) -> bool {
    matches!(kind, 3 | 4)
}

fn key_into(key: &Key, buffer: &mut Vec<u8>) -> Result<usize> {
    let (kind, collection, id) = key;
    ensure!(
        4 + collection.len() + id.len() <= KEY_BYTES,
        "snapshot location key exceeds bound"
    );
    buffer.clear();
    // Other records and group spans use JSON tuple keys, starting with '['.
    buffer.extend_from_slice(&[0xff, *kind]);
    buffer.extend_from_slice(&u16::try_from(collection.len())?.to_be_bytes());
    buffer.extend_from_slice(collection.as_bytes());
    let prefix = buffer.len();
    buffer.extend_from_slice(id.as_bytes());
    Ok(prefix)
}

pub(super) struct LocationPage {
    bytes: Vec<u8>,
    last: Vec<u8>,
    rows: usize,
    _charge: kasumi_store::DiskMemoryLease,
}

impl LocationPage {
    pub(super) fn new(image: &SnapshotImage) -> Result<Self> {
        // This temporary structural index stores keys and offsets. Charge its
        // buffers as required snapshot work, like its encrypted scratch table.
        // A document-source lease would reserve another cache-work corridor
        // while the enclosing verifier already holds its admitted index budget.
        let charge = image
            .disk()
            .memory()
            .clone()
            .reserve_installed((PAGE_BYTES + KEY_BYTES + 256) as u64)?;
        Ok(Self {
            bytes: Vec::with_capacity(PAGE_BYTES),
            last: Vec::with_capacity(KEY_BYTES),
            rows: 0,
            _charge: charge,
        })
    }

    pub(super) fn push(
        &mut self,
        key: &Key,
        location: &[u8; 16],
        pending: &mut PendingIndex<'_>,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let id = key.2.as_bytes();
        let size = u16::try_from(id.len())?;
        if self.rows == ROWS || self.bytes.len() + 18 + id.len() > PAGE_BYTES {
            self.flush(pending, check)?;
        }
        key_into(key, &mut self.last)?;
        self.bytes.extend_from_slice(&size.to_be_bytes());
        self.bytes.extend_from_slice(id);
        self.bytes.extend_from_slice(location);
        self.rows += 1;
        Ok(())
    }

    pub(super) fn flush(
        &mut self,
        pending: &mut PendingIndex<'_>,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if self.rows > 0 {
            pending.insert(&self.last, &self.bytes, check)?;
            self.bytes.clear();
            self.rows = 0;
        }
        Ok(())
    }
}

pub(super) fn get(index: &EncryptedTable, key: &Key) -> Result<Option<[u8; 16]>> {
    let mut bound = Vec::new();
    let prefix = key_into(key, &mut bound)?;
    let Some(page) = index.first_at_or_after(&bound[..prefix], &bound)? else {
        return Ok(None);
    };
    ensure!(
        page.len() <= PAGE_BYTES,
        "snapshot location page exceeds bound"
    );
    let mut bytes = page.as_bytes();
    while !bytes.is_empty() {
        let (size, tail) = bytes
            .split_at_checked(2)
            .ok_or_else(|| anyhow::anyhow!("short location ID length"))?;
        let (id, tail) = tail
            .split_at_checked(u16::from_be_bytes(size.try_into()?) as usize)
            .ok_or_else(|| anyhow::anyhow!("short location ID"))?;
        let (location, next) = tail
            .split_at_checked(16)
            .ok_or_else(|| anyhow::anyhow!("short snapshot location"))?;
        match id.cmp(key.2.as_bytes()) {
            std::cmp::Ordering::Equal => return Ok(Some(location.try_into()?)),
            std::cmp::Ordering::Greater => return Ok(None),
            std::cmp::Ordering::Less => bytes = next,
        }
    }
    Ok(None)
}
