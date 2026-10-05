// Shared fixture-only aggregate credit. Providers keep their existing denial
// hooks and byte ledgers; resizing never allocates another reservation token.
use super::cache_types::{
    AdmissionError, CacheMemoryLease, CacheMemoryQuote, CacheMemoryReservation, StorageAdmission,
};
use std::sync::Arc;

pub(crate) trait Provider: StorageAdmission + 'static {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError>;
    fn release_cache(&self, bytes: u64, last: bool);
}

struct Token<P: Provider> {
    owner: Arc<P>,
    charged: u64,
}

pub(crate) fn quote<P: Provider>(credit: u64) -> Result<CacheMemoryQuote, AdmissionError> {
    // The erased token box is the sole provider allocation. Include an
    // allocator allowance as the native/provider integration fixtures do.
    CacheMemoryQuote::new(credit, std::mem::size_of::<Token<P>>() as u64 + 64)
        .ok_or(AdmissionError::CapacityDenied)
}

pub(crate) fn reserve<P: Provider>(
    owner: Arc<P>,
    credit: u64,
) -> Result<CacheMemoryLease, AdmissionError> {
    owner
        .check_owner()
        .map_err(|_| AdmissionError::OwnerFailed)?;
    let quote = quote::<P>(credit)?;
    owner.acquire_cache(quote.charged_bytes(), true)?;
    Ok(CacheMemoryLease::new(
        quote,
        Token {
            owner,
            charged: quote.charged_bytes(),
        },
    ))
}

impl<P: Provider> CacheMemoryReservation for Token<P> {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        self.owner
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let next = self
            .charged
            .checked_add(bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        self.owner.acquire_cache(bytes, false)?;
        self.charged = next;
        Ok(())
    }

    fn retain_charge(&mut self, bytes: u64) {
        let released = self
            .charged
            .checked_sub(bytes)
            .expect("cache charge only shrinks");
        self.charged = bytes;
        self.owner.release_cache(released, false);
    }
}

impl<P: Provider> Drop for Token<P> {
    fn drop(&mut self) {
        self.owner.release_cache(self.charged, true);
    }
}
