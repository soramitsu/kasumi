//! Blocked Bloom filter for optional imported-level membership tests. Each hash
//! selects one cache line and seven bits within it. Positives always read the run.
use crate::invalid;
use sha2::{Digest, Sha256};
use std::io;

const BUCKET: usize = 64;
const MAX_BYTES: usize = 256 << 20;

pub(super) struct BulkFilter {
    bits: Vec<u8>,
}

impl BulkFilter {
    pub(super) fn for_rows(rows: u64) -> io::Result<Self> {
        if rows == 0 {
            return Err(invalid(
                "filtered import requires a nonzero expected row count",
            ));
        }
        let buckets = (u128::from(rows) * 10).div_ceil((8 * BUCKET) as u128);
        let bytes = (buckets * BUCKET as u128).min(MAX_BYTES as u128) as usize;
        Self::with_bytes(bytes)
    }

    pub(super) fn with_bytes(bytes: usize) -> io::Result<Self> {
        if !(BUCKET..=MAX_BYTES).contains(&bytes) || !bytes.is_multiple_of(BUCKET) {
            return Err(invalid("invalid bulk membership filter length"));
        }
        let mut bits = Vec::new();
        bits.try_reserve_exact(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bits.resize(bytes, 0);
        Ok(Self { bits })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bits
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bits
    }

    fn positions(&self, key: &[u8]) -> [usize; 7] {
        let digest = Sha256::digest(key);
        let pick = u64::from_le_bytes(digest[..8].try_into().unwrap());
        let base = (pick % (self.bits.len() / BUCKET) as u64) as usize * BUCKET * 8;
        std::array::from_fn(|i| {
            let offset = 8 + 2 * i;
            let bit = u16::from_le_bytes([digest[offset], digest[offset + 1]]) as usize;
            base + (bit & (BUCKET * 8 - 1))
        })
    }

    pub(super) fn insert(&mut self, key: &[u8]) {
        for bit in self.positions(key) {
            self.bits[bit / 8] |= 1 << (bit % 8);
        }
    }

    pub(super) fn may_contain(&self, key: &[u8]) -> bool {
        self.positions(key)
            .into_iter()
            .all(|bit| self.bits[bit / 8] & (1 << (bit % 8)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_bit_layout_is_stable() {
        let maximum_key: Vec<_> = (0u8..=255).cycle().take(crate::MAX_KEY).collect();
        let keys = [
            b"".as_slice(),
            &[0, 127, 128, 255],
            b"polkaswap-index",
            &maximum_key,
        ];
        let mut filter = BulkFilter::with_bytes(128).unwrap();
        for key in keys {
            filter.insert(key);
        }
        // This digest was generated independently from the documented wire layout.
        assert_eq!(
            format!("{:x}", Sha256::digest(filter.bytes())),
            "bc6a2ea504cbfa50f434743f254a7d4d5aa842070d3db7accc18e7af20c5d690"
        );
        assert!(keys.into_iter().all(|key| filter.may_contain(key)));
        assert!(BulkFilter::for_rows(0).is_err());
        for size in [0, 63, 65, MAX_BYTES + BUCKET] {
            assert!(BulkFilter::with_bytes(size).is_err());
        }
    }
}
