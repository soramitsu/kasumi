//! Private envelopes for concrete application-source allocations.
//! Credit has no Weak/raw escape and every clone retires with into_inner.
use super::Reservation;
use std::{
    ops::Deref,
    sync::{Arc, Weak as ArcWeak},
};

#[path = "application_source_capacity.rs"]
mod capacity;
pub(super) use capacity::{LaneFunding, LaneFundingRef};

enum CreditFunding {
    Ordinary(Reservation),
    Publication(capacity::PublicationCredit),
}
pub(super) struct SourceCredit(Option<Arc<CreditFunding>>);
impl SourceCredit {
    pub(super) fn new(reservation: Reservation) -> Self {
        Self(Some(Arc::new(CreditFunding::Ordinary(reservation))))
    }
    pub(super) fn required_bytes() -> anyhow::Result<u64> {
        super::allocated(std::mem::size_of::<CreditFunding>() + 2 * std::mem::size_of::<usize>())
    }
    #[cfg(test)]
    pub(super) fn publication(funding: &LaneFundingRef, lane: usize) -> anyhow::Result<Self> {
        Ok(Self(Some(Arc::new(CreditFunding::Publication(
            funding.assign(lane)?,
        )))))
    }
    pub(super) fn publication_available(funding: &LaneFundingRef) -> anyhow::Result<Self> {
        Ok(Self(Some(Arc::new(CreditFunding::Publication(
            funding.assign_available()?,
        )))))
    }
    pub(super) fn publication_lane(&self) -> Option<usize> {
        self.publication_account()
            .map(capacity::PublicationCredit::lane)
    }
    pub(super) fn seal_publication(&self) {
        if let Some(account) = self.publication_account() {
            account.seal();
        }
    }
    fn publication_account(&self) -> Option<&capacity::PublicationCredit> {
        match self.0.as_deref().expect("source credit") {
            CreditFunding::Publication(account) => Some(account),
            CreditFunding::Ordinary(reservation) => {
                let _ = reservation;
                None
            }
        }
    }
    pub(super) fn prepare_history(&self) -> anyhow::Result<bool> {
        match self.publication_account() {
            Some(account) => account.prepare_history(),
            None => Ok(false),
        }
    }
    pub(super) fn commit_history(&self) {
        self.publication_account()
            .expect("publication credit")
            .commit_history();
    }
    pub(super) fn abort_history(&self) -> std::thread::Result<()> {
        self.publication_account()
            .expect("publication credit")
            .abort_history()
    }
    pub(super) fn prove_retirement(&self) {
        if let Some(account) = self.publication_account() {
            account.prove_retirement();
        }
    }
    #[cfg(test)]
    pub(super) fn is_history(&self) -> bool {
        self.publication_account()
            .is_none_or(capacity::PublicationCredit::is_history)
    }
    #[cfg(test)]
    pub(super) fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.0.as_deref().expect("source credit")) as usize
    }
}
impl Clone for SourceCredit {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for SourceCredit {
    fn drop(&mut self) {
        // With no Weak/raw escape, the winning into_inner frees the credit Arc
        // before the moved Reservation releases its bytes and ledger slot.
        if let Some(credit) = self.0.take() {
            drop(Arc::into_inner(credit));
        }
    }
}

pub(crate) struct Strong<T> {
    value: Option<Arc<T>>,
    credit: SourceCredit,
}
impl<T> Strong<T> {
    pub(super) fn new(value: T, credit: SourceCredit) -> Self {
        Self {
            value: Some(Arc::new(value)),
            credit,
        }
    }
    pub(super) fn downgrade(&self) -> Weak<T> {
        Weak {
            value: Some(Arc::downgrade(self.value.as_ref().expect("source owner"))),
            credit: Some(self.credit.clone()),
        }
    }
    #[cfg(test)]
    pub(super) fn credit_address(&self) -> usize {
        self.credit.allocation_address()
    }
    #[cfg(test)]
    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(
            self.value.as_ref().expect("source owner"),
            other.value.as_ref().expect("source owner"),
        )
    }
    pub(super) fn try_unwrap(mut self) -> Result<Owned<T>, Self> {
        match Arc::try_unwrap(self.value.take().expect("source owner")) {
            Ok(value) => Ok(Owned {
                value: Some(value),
                _credit: self.credit.clone(),
            }),
            Err(value) => {
                self.value = Some(value);
                Err(self)
            }
        }
    }
}
impl<T> Clone for Strong<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            credit: self.credit.clone(),
        }
    }
}
impl<T> Deref for Strong<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_deref().expect("source owner")
    }
}
impl<T> AsRef<T> for Strong<T> {
    fn as_ref(&self) -> &T {
        self
    }
}
impl<T> Drop for Strong<T> {
    fn drop(&mut self) {
        drop(self.value.take());
    }
}

pub(super) struct Weak<T> {
    value: Option<ArcWeak<T>>,
    credit: Option<SourceCredit>,
}
impl<T> Weak<T> {
    pub(super) fn new() -> Self {
        Self {
            value: None,
            credit: None,
        }
    }
    pub(super) fn upgrade(&self) -> Option<Strong<T>> {
        self.value.as_ref()?.upgrade().map(|value| Strong {
            value: Some(value),
            credit: self.credit.as_ref().expect("source weak credit").clone(),
        })
    }
    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.value, &other.value) {
            (Some(left), Some(right)) => ArcWeak::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }
}
impl<T> Clone for Weak<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            credit: self.credit.clone(),
        }
    }
}
impl<T> Drop for Weak<T> {
    fn drop(&mut self) {
        drop(self.value.take());
    }
}

// A unique native view still needs its credit while close consumes the payload.
// The only caller passes TenantStorageReadView::close; no unpaired view escapes.
pub(super) struct Owned<T> {
    value: Option<T>,
    _credit: SourceCredit,
}
impl<T> Owned<T> {
    pub(super) fn consume<R>(mut self, consume: impl FnOnce(T) -> R) -> R {
        consume(self.value.take().expect("unique source payload"))
    }
}
impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        drop(self.value.take());
    }
}
