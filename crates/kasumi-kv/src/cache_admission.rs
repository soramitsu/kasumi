//! Aggregate, optional cache credit with exact provider allocation charges.

use crate::AdmissionError;

/// An allocation-free quote, not an admission or an owner-health witness.
/// The provider overhead is fixed for the lifetime of one aggregate lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheMemoryQuote {
    credit_bytes: u64,
    charged_bytes: u64,
}

impl CacheMemoryQuote {
    pub fn new(credit_bytes: u64, overhead_bytes: u64) -> Option<Self> {
        Some(Self {
            credit_bytes,
            charged_bytes: credit_bytes.checked_add(overhead_bytes)?,
        })
    }

    pub fn credit_bytes(self) -> u64 {
        self.credit_bytes
    }

    pub fn charged_bytes(self) -> u64 {
        self.charged_bytes
    }

    pub fn overhead_bytes(self) -> u64 {
        self.charged_bytes - self.credit_bytes
    }

    pub fn with_credit(self, credit_bytes: u64) -> Option<Self> {
        Self::new(credit_bytes, self.overhead_bytes())
    }
}

/// Provider token for one optional cache reservation. The enclosing opaque
/// lease retires the token's Box before dropping the token itself.
pub trait CacheMemoryReservation: Send + Sync {
    /// Admit additional charged bytes without allocating reservation storage or
    /// changing the reservation on refusal. Preserve its optional-cache origin.
    fn try_grow(&mut self, additional_bytes: u64) -> Result<(), AdmissionError>;

    /// Reduce the charge to the supplied total, which never exceeds the
    /// current charge. This is cleanup: no admission, owner callback or I/O,
    /// and no refusal after an owner expires. Fixed token overhead remains.
    fn retain_charge(&mut self, charged_bytes: u64);
}

trait ErasedReservation: Send + Sync {
    fn try_grow(&mut self, additional_bytes: u64) -> Result<(), AdmissionError>;
    fn retain_charge(&mut self, charged_bytes: u64);
    fn retire(self: Box<Self>);
}

impl<T: CacheMemoryReservation + 'static> ErasedReservation for T {
    fn try_grow(&mut self, additional_bytes: u64) -> Result<(), AdmissionError> {
        CacheMemoryReservation::try_grow(self, additional_bytes)
    }

    fn retain_charge(&mut self, charged_bytes: u64) {
        CacheMemoryReservation::retain_charge(self, charged_bytes);
    }

    fn retire(self: Box<Self>) {
        let reservation = {
            let allocation = self;
            *allocation
        };
        drop(reservation);
    }
}

/// One growable aggregate reservation with fixed provider overhead. This value
/// is held inline by its admitted owner; adapters must not box it again.
pub struct CacheMemoryLease {
    quote: CacheMemoryQuote,
    reservation: Option<Box<dyn ErasedReservation>>,
}

impl CacheMemoryLease {
    /// The provider must already have admitted the complete quoted charge,
    /// including `size_of::<T>()` and its allocator allowance, before calling.
    pub fn new<T: CacheMemoryReservation + 'static>(
        quote: CacheMemoryQuote,
        reservation: T,
    ) -> Self {
        Self {
            quote,
            reservation: Some(Box::new(reservation)),
        }
    }

    pub fn quote(&self) -> CacheMemoryQuote {
        self.quote
    }

    /// The caller checks its physical owner before borrowing or growing cache
    /// credit. The retained provider token enforces its exact governor and
    /// optional-cache origin. Requests below current credit are no-ops.
    pub fn try_grow_to(&mut self, credit_bytes: u64) -> Result<(), AdmissionError> {
        if credit_bytes <= self.quote.credit_bytes {
            return Ok(());
        }
        let next = self
            .quote
            .with_credit(credit_bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        self.reservation
            .as_mut()
            .expect("live cache reservation")
            .try_grow(next.charged_bytes - self.quote.charged_bytes)?;
        self.quote = next;
        Ok(())
    }

    /// Cleanup-only shrink. Returns false, without effects, if this would grow
    /// credit. The provider's opaque token overhead stays charged until Drop.
    pub fn shrink_to(&mut self, credit_bytes: u64) -> bool {
        if credit_bytes > self.quote.credit_bytes {
            return false;
        }
        let next = self
            .quote
            .with_credit(credit_bytes)
            .expect("shrinking a valid cache quote");
        self.reservation
            .as_mut()
            .expect("live cache reservation")
            .retain_charge(next.charged_bytes);
        self.quote = next;
        true
    }
}

impl Drop for CacheMemoryLease {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            reservation.retire();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    #[derive(Default)]
    struct State {
        used: AtomicU64,
        grow_calls: AtomicUsize,
        denied: AtomicBool,
    }

    struct Token {
        state: Arc<State>,
        charged: u64,
    }

    impl CacheMemoryReservation for Token {
        fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
            self.state.grow_calls.fetch_add(1, Ordering::AcqRel);
            if self.state.denied.load(Ordering::Acquire) {
                return Err(AdmissionError::CapacityDenied);
            }
            self.charged += bytes;
            self.state.used.fetch_add(bytes, Ordering::AcqRel);
            Ok(())
        }

        fn retain_charge(&mut self, bytes: u64) {
            self.state
                .used
                .fetch_sub(self.charged - bytes, Ordering::AcqRel);
            self.charged = bytes;
        }
    }

    impl Drop for Token {
        fn drop(&mut self) {
            self.state.used.fetch_sub(self.charged, Ordering::AcqRel);
        }
    }

    #[test]
    fn quote_checks_total_and_keeps_fixed_overhead() {
        assert!(CacheMemoryQuote::new(u64::MAX, 1).is_none());
        let quote = CacheMemoryQuote::new(123, 41).unwrap();
        assert_eq!(quote.charged_bytes(), 164);
        assert_eq!(quote.with_credit(0).unwrap().charged_bytes(), 41);
        assert!(quote.with_credit(u64::MAX).is_none());
    }

    #[test]
    fn growth_refusal_preserves_charge_and_cleanup_never_readmits() {
        let quote = CacheMemoryQuote::new(100, 40).unwrap();
        let state = Arc::new(State::default());
        state.used.store(quote.charged_bytes(), Ordering::Release);
        let mut lease = CacheMemoryLease::new(
            quote,
            Token {
                state: state.clone(),
                charged: quote.charged_bytes(),
            },
        );
        lease.try_grow_to(200).unwrap();
        assert_eq!(lease.quote().charged_bytes(), 240);
        state.denied.store(true, Ordering::Release);
        assert_eq!(lease.try_grow_to(201), Err(AdmissionError::CapacityDenied));
        assert_eq!(lease.quote().credit_bytes(), 200);
        assert_eq!(state.used.load(Ordering::Acquire), 240);
        let calls = state.grow_calls.load(Ordering::Acquire);
        assert!(!lease.shrink_to(201));
        assert!(lease.shrink_to(50));
        assert_eq!(state.used.load(Ordering::Acquire), 90);
        assert!(lease.shrink_to(0));
        assert_eq!(state.used.load(Ordering::Acquire), 40);
        drop(lease);
        assert_eq!(state.used.load(Ordering::Acquire), 0);
        assert_eq!(state.grow_calls.load(Ordering::Acquire), calls);
    }
}
