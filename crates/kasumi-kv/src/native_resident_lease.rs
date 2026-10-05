//! Closed ownership of one actual native provider grant.
use crate::core::ResidentLease;

/// Owns the provider's existing Box without allocating or acquiring credit.
/// Every ordinary drop deallocates that exact Box before its token callback.
/// No clone, weak alias or raw owning extraction is available.
pub(crate) struct NativeResidentLease(Option<Box<dyn ResidentLease>>);
impl NativeResidentLease {
    pub(crate) fn new(actual: Box<dyn ResidentLease>) -> Self {
        Self(Some(actual))
    }
    pub(crate) fn retire(self) {
        drop(self);
    }
    #[cfg(test)]
    pub(crate) fn allocation_address_for_test(&self) -> usize {
        self.0.as_deref().expect("original native grant") as *const dyn ResidentLease as *const ()
            as usize
    }
}
impl Drop for NativeResidentLease {
    fn drop(&mut self) {
        if let Some(actual) = self.0.take() {
            actual.retire();
        }
    }
}
const _: () = {
    assert!(
        std::mem::size_of::<NativeResidentLease>() == std::mem::size_of::<Box<dyn ResidentLease>>()
    );
    assert!(
        std::mem::align_of::<NativeResidentLease>()
            == std::mem::align_of::<Box<dyn ResidentLease>>()
    );
};
