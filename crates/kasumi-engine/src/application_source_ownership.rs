//! Private envelopes for concrete application-source allocations.
//! Credit has no Weak/raw escape and every clone retires with into_inner.
use super::Reservation;
use std::{
    ops::Deref,
    sync::{Arc, Weak as ArcWeak},
};

// Each variant only holds its grant until the last credit clone retires.
enum CreditFunding {
    Ordinary {
        _reservation: Reservation,
    },
    DocumentRead {
        _workspace: crate::admission::DocumentWorkspace,
    },
}
pub(super) struct SourceCredit(Option<Arc<CreditFunding>>);
impl SourceCredit {
    pub(super) fn new(reservation: Reservation) -> Self {
        Self(Some(Arc::new(CreditFunding::Ordinary {
            _reservation: reservation,
        })))
    }
    pub(super) fn document_read(credit: crate::admission::DocumentWorkspace) -> Self {
        Self(Some(Arc::new(CreditFunding::DocumentRead {
            _workspace: credit,
        })))
    }
    pub(super) fn required_bytes() -> anyhow::Result<u64> {
        super::allocated(std::mem::size_of::<CreditFunding>() + 2 * std::mem::size_of::<usize>())
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
