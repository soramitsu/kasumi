//! Unwired prototype: one real resident grant owns compact document clones.
//! This module changes no source producer, wire format, cache or read path.
//! Runtime activation also requires context-aware decode and outer apply errors.
//! DocumentSource origin preserves shared cache-work and ordinary protected
//! headroom on acquisition and growth; this is neither a cache nor a full-fit proof.
use crate::admission::{NodeAdmission, Reservation};
use kasumi_types::Document;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::{
    fmt,
    mem::size_of,
    ops::Deref,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

/// Local preparation failure, never a deterministic replicated rejection.
/// Deliberately no conversion into kasumi_types::Error.
#[derive(Debug)]
pub(crate) enum SourceAdmissionError {
    SizeOverflow,
    Provider(kasumi_types::Error),
}
impl fmt::Display for SourceAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SizeOverflow => "document source allocation size overflow",
            Self::Provider(_) => "document source admission failed",
        })
    }
}
impl std::error::Error for SourceAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::SizeOverflow => None,
        }
    }
}
type Result<T> = std::result::Result<T, SourceAdmissionError>;

// std synchronization may allocate private platform backing (for example boxed
// pthread state on Darwin). This is a conservative per-object policy allowance,
// not an exposed-capacity measurement or a portable exact-RSS assertion. The
// control-only allocation test qualifies construction and the actual wait path.
const SYNC_BACKING_ALLOWANCE: u64 = 4096;

fn arc_bytes<T>() -> Result<u64> {
    size_of::<T>()
        .checked_add(2 * size_of::<usize>())
        .and_then(usize::checked_next_power_of_two)
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(SourceAdmissionError::SizeOverflow)
}

/// Private handles never expose a raw Arc or Weak, including to returned reads.
pub(crate) struct DocumentPool(Option<Arc<Inner>>);
struct Inner {
    state: Mutex<State>,
    available: Condvar,
    control: u64,
}
struct State {
    reservation: Option<Reservation>,
    charged: u64,
    used: u64,
}
struct Credit {
    pool: DocumentPool,
    bytes: u64,
}
struct Payload {
    document: Document,
    credit: Credit,
}
pub(crate) struct PooledDocument(Option<Arc<Payload>>);

/// Temporarily removes the provider from the ledger, so a provider's memory
/// observation may drop a document without re-entering the same pool lock.
/// Concurrent construction waits; retirement never waits for provider work.
struct Flight<'a> {
    pool: &'a DocumentPool,
    reservation: Option<Reservation>,
    charged: u64,
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut state = self.pool.lock();
        let mut reservation = self.reservation.take().expect("in-flight reservation");
        // Only successful positive growth updates charged. Denial/unwind leaves
        // the original grant intact; concurrent retirement can only lower used.
        debug_assert!(state.used <= self.charged);
        reservation.retain(state.used);
        state.charged = state.used;
        state.reservation = Some(reservation);
        self.pool.inner().available.notify_all();
    }
}

impl DocumentPool {
    pub(crate) fn new(admission: &Arc<NodeAdmission>) -> Result<Self> {
        let control = Self::control_bytes()?;
        // Reservation is inline in State: no unquoted provider Box/Arc is made.
        let reservation = admission
            .reserve_document_source(control)
            .map_err(SourceAdmissionError::Provider)?;
        Ok(Self(Some(Arc::new(Inner {
            state: Mutex::new(State {
                reservation: Some(reservation),
                charged: control,
                used: control,
            }),
            available: Condvar::new(),
            control,
        }))))
    }
    pub(crate) fn control_bytes() -> Result<u64> {
        arc_bytes::<Inner>()?
            .checked_add(2 * SYNC_BACKING_ALLOWANCE)
            .ok_or(SourceAdmissionError::SizeOverflow)
    }
    pub(crate) fn document_bytes(id: &str, body: &Value) -> Result<u64> {
        kasumi_query::document_parts_clone_bytes(id, body)
            .map_err(SourceAdmissionError::Provider)?
            .checked_add(arc_bytes::<Payload>()?)
            .ok_or(SourceAdmissionError::SizeOverflow)
    }
    pub(crate) fn clone_document(&self, document: &Document) -> Result<PooledDocument> {
        self.clone_parts(&document.id, document.version, &document.body)
    }
    pub(crate) fn clone_parts(
        &self,
        id: &str,
        version: u64,
        body: &Value,
    ) -> Result<PooledDocument> {
        let credit = self.borrow(Self::document_bytes(id, body)?)?;
        // The quote describes these newly allocated compact clones, not source
        // capacities. On unwind partially cloned values die before credit.
        let document = Document {
            id: id.to_owned(),
            version,
            body: body.clone(),
        };
        Ok(PooledDocument(Some(Arc::new(Payload { document, credit }))))
    }
    fn inner(&self) -> &Inner {
        self.0.as_deref().expect("live pool")
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner().state.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn borrow(&self, bytes: u64) -> Result<Credit> {
        let (reservation, charged, required) = {
            let mut state = self.lock();
            while state.reservation.is_none() {
                state = self
                    .inner()
                    .available
                    .wait(state)
                    .unwrap_or_else(|p| p.into_inner());
            }
            let required = state
                .used
                .checked_add(bytes)
                .ok_or(SourceAdmissionError::SizeOverflow)?;
            (
                state.reservation.take().expect("available reservation"),
                state.charged,
                required,
            )
        };
        let mut flight = Flight {
            pool: self,
            reservation: Some(reservation),
            charged,
        };
        let grow = |flight: &mut Flight<'_>, required: u64| -> Result<()> {
            // A zero increment still consults the installed provider's current
            // pressure state, even when a concurrent release freed enough space.
            flight
                .reservation
                .as_mut()
                .expect("in-flight reservation")
                .reserve_additional(required.saturating_sub(flight.charged))
                .map_err(SourceAdmissionError::Provider)?;
            flight.charged = flight.charged.max(required);
            Ok(())
        };
        if let Err(error) = grow(&mut flight, required) {
            let exact = self
                .lock()
                .used
                .checked_add(bytes)
                .ok_or(SourceAdmissionError::SizeOverflow)?;
            if exact >= required {
                return Err(error);
            }
            // The failed provider sample may have retired an existing document.
            // Retry only the now-smaller exact need; no new slot or grant.
            grow(&mut flight, exact)?;
        }
        {
            let mut state = self.lock();
            state.used = state
                .used
                .checked_add(bytes)
                .ok_or(SourceAdmissionError::SizeOverflow)?;
            debug_assert!(state.used <= flight.charged);
        }
        let credit = Credit {
            pool: self.clone(),
            bytes,
        };
        drop(flight);
        Ok(credit)
    }
    #[cfg(test)]
    fn used(&self) -> u64 {
        self.lock().used
    }
}
impl Clone for DocumentPool {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live pool").clone()))
    }
}
impl Drop for DocumentPool {
    fn drop(&mut self) {
        if let Some(inner) = Arc::into_inner(self.0.take().expect("live pool")) {
            // into_inner has already freed the control Arc. No credit can still
            // exist: each credit holds its own private pool handle.
            let Inner {
                state,
                available,
                control,
            } = inner;
            // Both possibly allocated synchronization objects die while the
            // same provider still owns their complete allowance.
            drop(available);
            let state = state.into_inner().unwrap_or_else(|p| p.into_inner());
            debug_assert_eq!(state.used, control);
            debug_assert_eq!(state.charged, control);
            drop(state.reservation.expect("last pool has no provider flight"));
        }
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let mut state = self.pool.lock();
        state.used = state
            .used
            .checked_sub(self.bytes)
            .expect("live document credit");
        let used = state.used;
        if let Some(reservation) = state.reservation.as_mut() {
            reservation.retain(used);
            state.charged = used;
        }
        // If a provider call is in flight, its guard performs the exact shrink.
        // No admission, callback, allocation or I/O occurs during retirement.
    }
}
impl PooledDocument {
    fn payload(&self) -> &Payload {
        self.0.as_deref().expect("live pooled document")
    }
    #[cfg(test)]
    fn charged_bytes(&self) -> u64 {
        self.payload().credit.bytes
    }
}
impl Clone for PooledDocument {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live pooled document").clone()))
    }
}
impl Drop for PooledDocument {
    fn drop(&mut self) {
        if let Some(payload) = Arc::into_inner(self.0.take().expect("live pooled document")) {
            // Arc backing is already gone; destroy all Document backing before
            // the inline credit can return even one byte to shared admission.
            let Payload { document, credit } = payload;
            drop(document);
            drop(credit);
        }
    }
}
impl Deref for PooledDocument {
    type Target = Document;
    fn deref(&self) -> &Document {
        &self.payload().document
    }
}
impl std::borrow::Borrow<Document> for PooledDocument {
    fn borrow(&self) -> &Document {
        self
    }
}
impl AsRef<Document> for PooledDocument {
    fn as_ref(&self) -> &Document {
        self
    }
}
impl fmt::Debug for PooledDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PooledDocument")
            .field(self.as_ref())
            .finish()
    }
}
impl Serialize for PooledDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.as_ref().serialize(serializer)
    }
}

#[cfg(test)]
#[path = "document_pool_alloc_tests.rs"]
pub(crate) mod allocation_tests;
#[cfg(test)]
#[path = "document_pool_tests.rs"]
mod tests;
