// Fixture wrapper for installed aggregate cache credit. The only extra box is
// quoted and admitted as part of the retained underlying provider reservation.
use kasumi_kv::{
    AdmissionError, CacheMemoryLease, CacheMemoryQuote, CacheMemoryReservation, StorageAdmission,
};
use std::sync::Arc;

pub(crate) trait Provider: StorageAdmission + 'static {
    fn inner_quote(&self, bytes: u64) -> Result<CacheMemoryQuote, AdmissionError>;
    fn inner_reserve(&self, bytes: u64) -> Result<CacheMemoryLease, AdmissionError>;
    fn gate(&self, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn denied(&self) {}
}

struct Token<P: Provider> {
    owner: Arc<P>,
    inner: CacheMemoryLease,
}

fn inner_credit<P: Provider>(bytes: u64) -> Result<u64, AdmissionError> {
    bytes
        .checked_add(std::mem::size_of::<Token<P>>() as u64 + 64)
        .ok_or(AdmissionError::CapacityDenied)
}

pub(crate) fn quote<P: Provider>(
    owner: &P,
    bytes: u64,
) -> Result<CacheMemoryQuote, AdmissionError> {
    let inner = owner.inner_quote(inner_credit::<P>(bytes)?)?;
    CacheMemoryQuote::new(bytes, inner.charged_bytes() - bytes)
        .ok_or(AdmissionError::CapacityDenied)
}

pub(crate) fn reserve<P: Provider>(
    owner: Arc<P>,
    bytes: u64,
) -> Result<CacheMemoryLease, AdmissionError> {
    owner
        .check_owner()
        .map_err(|_| AdmissionError::OwnerFailed)?;
    owner.gate(bytes)?;
    let inner = owner
        .inner_reserve(inner_credit::<P>(bytes)?)
        .inspect_err(|error| {
            if *error == AdmissionError::CapacityDenied {
                owner.denied();
            }
        })?;
    let quote = CacheMemoryQuote::new(bytes, inner.quote().charged_bytes() - bytes)
        .ok_or(AdmissionError::CapacityDenied)?;
    Ok(CacheMemoryLease::new(quote, Token { owner, inner }))
}

impl<P: Provider> CacheMemoryReservation for Token<P> {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        self.owner
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.owner.gate(bytes)?;
        let next = self
            .inner
            .quote()
            .credit_bytes()
            .checked_add(bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        self.inner.try_grow_to(next).inspect_err(|error| {
            if *error == AdmissionError::CapacityDenied {
                self.owner.denied();
            }
        })
    }

    fn retain_charge(&mut self, bytes: u64) {
        let credit = bytes
            .checked_sub(self.inner.quote().overhead_bytes())
            .expect("retained provider overhead");
        assert!(self.inner.shrink_to(credit));
    }
}

pub(crate) trait DiskProvider: crate::NodeDiskMemoryAdmission + 'static {
    fn backing(&self) -> Arc<dyn crate::NodeDiskMemoryAdmission>;
    fn admit(&self, bytes: u64) -> std::io::Result<()>;
}

struct DiskToken<P: DiskProvider> {
    owner: Arc<P>,
    inner: CacheMemoryLease,
}

fn disk_credit<P: DiskProvider>(bytes: u64) -> std::io::Result<u64> {
    bytes
        .checked_add(std::mem::size_of::<DiskToken<P>>() as u64 + 64)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory.into())
}

pub(crate) fn disk_quote<P: DiskProvider>(
    owner: &P,
    bytes: u64,
) -> std::io::Result<CacheMemoryQuote> {
    let inner = owner
        .backing()
        .quote_cache_memory(disk_credit::<P>(bytes)?)?;
    CacheMemoryQuote::new(bytes, inner.charged_bytes() - bytes)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory.into())
}

pub(crate) fn disk_reserve<P: DiskProvider>(
    owner: Arc<P>,
    bytes: u64,
) -> std::io::Result<CacheMemoryLease> {
    owner.admit(bytes)?;
    let inner = owner
        .backing()
        .reserve_cache_memory(disk_credit::<P>(bytes)?)?;
    let quote = CacheMemoryQuote::new(bytes, inner.quote().charged_bytes() - bytes)
        .ok_or(std::io::ErrorKind::OutOfMemory)?;
    Ok(CacheMemoryLease::new(quote, DiskToken { owner, inner }))
}

impl<P: DiskProvider> CacheMemoryReservation for DiskToken<P> {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        self.owner.admit(bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::OutOfMemory {
                AdmissionError::CapacityDenied
            } else {
                AdmissionError::OwnerFailed
            }
        })?;
        let next = self
            .inner
            .quote()
            .credit_bytes()
            .checked_add(bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        self.inner.try_grow_to(next)
    }

    fn retain_charge(&mut self, bytes: u64) {
        let credit = bytes
            .checked_sub(self.inner.quote().overhead_bytes())
            .expect("retained provider overhead");
        assert!(self.inner.shrink_to(credit));
    }
}
