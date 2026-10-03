//! One provider reservation supplies fungible credit to every retained cache
//! allocation. Credits are inline, never individual provider leases. Private
//! Arc handles retire their allocation before returning its final credit.

use super::{ALLOCATION_ALLOWANCE, AdmissionError};
use crate::{CacheMemoryLease, CacheMemoryQuote, StorageAdmission};
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const GROWTH_QUANTUM: u64 = 64 << 10;

pub(super) enum BorrowError {
    Limit,
    Provider(AdmissionError),
}

pub(super) struct Pool(Option<Arc<Inner>>);

struct Inner {
    state: Mutex<State>,
    live_values: AtomicU64,
    cached_values: AtomicU64,
}

struct State {
    lease: Option<CacheMemoryLease>,
    quote: CacheMemoryQuote,
    used: u64,
    control: u64,
    limit: u64,
    // Protect allocation-free rollback while an admitted replacement is
    // allocated. Other threads may release payload credits during this time.
    rollback: Option<u64>,
}

#[derive(Clone, Copy, Default)]
pub(super) struct PoolStats {
    pub(super) used: u64,
    pub(super) credit: u64,
    pub(super) charged: u64,
    pub(super) live_values: u64,
    pub(super) cached_values: u64,
}

pub(super) struct Credit {
    pool: Pool,
    bytes: u64,
    payload: bool,
}

pub(super) struct Exchange<'a> {
    credit: &'a mut Credit,
    original: u64,
    committed: bool,
}

struct Flight<'a> {
    pool: &'a Pool,
    lease: Option<CacheMemoryLease>,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let mut state = self.pool.lock();
        state.quote = lease.quote();
        state.lease = Some(lease);
        trim(&mut state, false);
    }
}

impl Clone for Pool {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live pool handle").clone()))
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(inner) = Arc::into_inner(self.0.take().expect("live pool handle")) {
            // No raw Arc/Weak escapes this module. The last into_inner has
            // deallocated its control block before the provider can refund it.
            let state = inner.state.into_inner().unwrap_or_else(|p| p.into_inner());
            debug_assert_eq!(state.used, state.control);
            debug_assert!(state.rollback.is_none());
            drop(state.lease);
        }
    }
}

impl Pool {
    pub(super) fn backing_bytes() -> u64 {
        (size_of::<Inner>() + 2 * size_of::<usize>()) as u64 + ALLOCATION_ALLOWANCE
    }

    pub(super) fn new(
        admission: &Arc<dyn StorageAdmission>,
        control: u64,
        limit: u64,
    ) -> Result<Self, BorrowError> {
        admission
            .check_owner()
            .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
        let minimum = admission
            .quote_cache_memory(control)
            .map_err(BorrowError::Provider)?;
        if minimum.charged_bytes() > limit {
            return Err(BorrowError::Limit);
        }
        let capacity = growth_target(control, limit - minimum.overhead_bytes());
        let lease = match reserve_checked(admission, capacity) {
            Err(BorrowError::Provider(AdmissionError::CapacityDenied)) if capacity != control => {
                reserve_checked(admission, control)?
            }
            result => result?,
        };
        let quote = lease.quote();
        if !(quote.credit_bytes() == capacity || quote.credit_bytes() == control)
            || quote.overhead_bytes() != minimum.overhead_bytes()
            || quote.charged_bytes() > limit
        {
            return Err(BorrowError::Provider(AdmissionError::OwnerFailed));
        }
        admission
            .check_owner()
            .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
        Ok(Self(Some(Arc::new(Inner {
            state: Mutex::new(State {
                lease: Some(lease),
                quote,
                used: control,
                control,
                limit,
                rollback: None,
            }),
            live_values: AtomicU64::new(0),
            cached_values: AtomicU64::new(0),
        }))))
    }

    fn inner(&self) -> &Inner {
        self.0.as_ref().expect("live pool handle")
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A failed owner cannot borrow again, but retirement must always be
        // able to release exact existing custody without callbacks or I/O.
        self.inner().state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn stats(&self) -> PoolStats {
        let state = self.lock();
        let quote = state.quote;
        PoolStats {
            used: state.used,
            credit: quote.credit_bytes(),
            charged: quote.charged_bytes(),
            live_values: self.inner().live_values.load(Ordering::Acquire),
            cached_values: self.inner().cached_values.load(Ordering::Acquire),
        }
    }

    pub(super) fn fits(&self, remove: u64, add: u64, limit: u64) -> bool {
        let state = self.lock();
        state
            .used
            .checked_sub(remove)
            .and_then(|used| used.checked_add(add))
            .and_then(|used| used.checked_add(state.quote.overhead_bytes()))
            .is_some_and(|charged| charged <= limit)
    }

    pub(super) fn borrow(
        &self,
        admission: &dyn StorageAdmission,
        bytes: u64,
        payload: bool,
    ) -> Result<Credit, BorrowError> {
        self.admit_change(admission, 0, bytes, false)?;
        if payload {
            self.inner().live_values.fetch_add(bytes, Ordering::AcqRel);
        }
        Ok(Credit {
            pool: self.clone(),
            bytes,
            payload,
        })
    }

    pub(super) fn set_limit(&self, limit: u64) -> bool {
        let mut state = self.lock();
        if state.limit == limit {
            return state.quote.charged_bytes() <= limit;
        }
        state.limit = limit;
        trim(&mut state, true);
        state.quote.charged_bytes() <= limit
    }

    pub(super) fn add_cached(&self, bytes: u64) {
        self.inner()
            .cached_values
            .fetch_add(bytes, Ordering::AcqRel);
    }

    pub(super) fn remove_cached(&self, bytes: u64) {
        self.inner()
            .cached_values
            .fetch_sub(bytes, Ordering::AcqRel);
    }

    fn admit_change(
        &self,
        admission: &dyn StorageAdmission,
        remove: u64,
        add: u64,
        exchange: bool,
    ) -> Result<(), BorrowError> {
        admission
            .check_owner()
            .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
        let (lease, target) = {
            let mut state = self.lock();
            if state.rollback.is_some() || state.lease.is_none() {
                return Err(BorrowError::Provider(AdmissionError::OwnerFailed));
            }
            let required = required(&state, remove, add)?;
            let maximum = state
                .limit
                .checked_sub(state.quote.overhead_bytes())
                .ok_or(BorrowError::Limit)?;
            if required > maximum {
                return Err(BorrowError::Limit);
            }
            if required <= state.quote.credit_bytes() {
                state.used = required;
                state.rollback = exchange.then_some(remove.saturating_sub(add));
                return Ok(());
            }
            let target = growth_target(required, maximum);
            let lease = state.lease.take().expect("available lease");
            // Conservative while admission is in flight; no borrow publishes
            // against this capacity until the actual provider call succeeds.
            state.quote = state.quote.with_credit(target).expect("bounded target");
            (lease, target)
        };
        let mut flight = Flight {
            pool: self,
            lease: Some(lease),
        };
        let lease = flight.lease.as_mut().expect("in-flight lease");
        match grow_checked(admission, lease, target) {
            Err(BorrowError::Provider(AdmissionError::CapacityDenied)) => {
                // A refusal callback may release a retained output from this
                // pool. Recompute the exact need with no provider lock held.
                let exact = required(&self.lock(), remove, add)?;
                if exact == target {
                    return Err(BorrowError::Provider(AdmissionError::CapacityDenied));
                }
                grow_checked(admission, lease, exact)?;
            }
            result => result?,
        }
        admission
            .check_owner()
            .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
        // Restoration must not trim capacity that this pending borrow needs.
        let mut state = self.lock();
        let used = required(&state, remove, add)?;
        let lease = flight.lease.take().expect("in-flight lease");
        state.used = used;
        state.rollback = exchange.then_some(remove.saturating_sub(add));
        state.quote = lease.quote();
        state.lease = Some(lease);
        drop(state);
        Ok(())
    }
}

impl Credit {
    pub(super) fn pool(&self) -> &Pool {
        &self.pool
    }

    pub(super) fn exchange(
        &mut self,
        admission: &dyn StorageAdmission,
        bytes: u64,
    ) -> Result<Exchange<'_>, BorrowError> {
        if self.payload {
            return Err(BorrowError::Provider(AdmissionError::OwnerFailed));
        }
        let original = self.bytes;
        self.pool.admit_change(admission, original, bytes, true)?;
        self.bytes = bytes;
        Ok(Exchange {
            credit: self,
            original,
            committed: false,
        })
    }
}

impl Drop for Credit {
    fn drop(&mut self) {
        let mut state = self.pool.lock();
        state.used -= self.bytes;
        if self.payload {
            self.pool
                .inner()
                .live_values
                .fetch_sub(self.bytes, Ordering::AcqRel);
        }
        trim(&mut state, false);
    }
}

impl Exchange<'_> {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        let mut state = self.credit.pool.lock();
        if !self.committed {
            state.used = state.used - self.credit.bytes + self.original;
            self.credit.bytes = self.original;
        }
        state.rollback = None;
        trim(&mut state, false);
    }
}

fn growth_target(required: u64, maximum: u64) -> u64 {
    required
        .checked_add(GROWTH_QUANTUM - 1)
        .map(|bytes| bytes / GROWTH_QUANTUM * GROWTH_QUANTUM)
        .unwrap_or(maximum)
        .min(maximum)
        .max(required)
}

// Refusal callbacks can expire the physical owner as well as release credit.
// Check both sides of each provider call, including a failed exact fallback:
// expiry must never become an optional pressure result or another growth call.
// These functions are only called without the pool mutex held.
fn reserve_checked(
    admission: &Arc<dyn StorageAdmission>,
    credit: u64,
) -> Result<CacheMemoryLease, BorrowError> {
    admission
        .check_owner()
        .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
    let result = admission.clone().reserve_cache_memory(credit);
    admission
        .check_owner()
        .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
    result.map_err(BorrowError::Provider)
}

fn grow_checked(
    admission: &dyn StorageAdmission,
    lease: &mut CacheMemoryLease,
    credit: u64,
) -> Result<(), BorrowError> {
    admission
        .check_owner()
        .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
    let result = lease.try_grow_to(credit);
    admission
        .check_owner()
        .map_err(|_| BorrowError::Provider(AdmissionError::OwnerFailed))?;
    result.map_err(BorrowError::Provider)
}

fn required(state: &State, remove: u64, add: u64) -> Result<u64, BorrowError> {
    state
        .used
        .checked_sub(remove)
        .and_then(|used| used.checked_add(add))
        .ok_or(BorrowError::Limit)
}

fn trim(state: &mut State, exact: bool) {
    let required = state.used + state.rollback.unwrap_or(0);
    let Some(lease) = state.lease.as_mut() else {
        return;
    };
    let maximum = state.limit.saturating_sub(lease.quote().overhead_bytes());
    let target = if exact {
        required
    } else {
        growth_target(required, maximum.max(required))
    };
    if target < lease.quote().credit_bytes() {
        assert!(lease.shrink_to(target));
    }
    state.quote = lease.quote();
}
