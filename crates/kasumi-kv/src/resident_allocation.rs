//! Shared opaque allocation-before-credit retirement. This is an allocation
//! owner, not a capacity grant or a source-funding capability.
use crate::ResidentLease;

/// Owns one actual concrete token Box. No raw owner extraction, Weak handle or
/// alternate early-release path exists. Construction itself acquires no credit;
/// its caller admits the concrete token layout before allocating.
pub struct ResidentAllocation(Option<Box<dyn RetireToken>>);
trait RetireToken: Send + Sync {
    fn retire(self: Box<Self>);
}
impl<T: Send + Sync> RetireToken for T {
    fn retire(self: Box<Self>) {
        let token = {
            let allocation = self;
            *allocation
        };
        drop(token);
    }
}
impl ResidentAllocation {
    /// Pure owning-constructor quote. It acquires no funding or authority.
    pub fn token_allocation_bytes<T>() -> std::io::Result<u64> {
        (std::mem::size_of::<T>() as u64)
            .checked_add(4096)
            .ok_or_else(|| std::io::ErrorKind::OutOfMemory.into())
    }

    #[cfg(test)]
    pub(crate) fn token_address_for_test(&self) -> usize {
        self.0.as_deref().unwrap() as *const dyn RetireToken as *const () as usize
    }

    pub fn new<T: Send + Sync + 'static>(token: T) -> Self {
        Self(Some(Box::new(token)))
    }
    // The actual Store DiskMemoryLease is a re-export of this owner. Native
    // construction adds its existing outer Box; no callback or third box.
    pub(crate) fn into_native(self) -> Box<dyn ResidentLease> {
        Box::new(self)
    }
}
impl Drop for ResidentAllocation {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.retire();
        }
    }
}
const _: () = {
    assert!(
        std::mem::size_of::<ResidentAllocation>() == std::mem::size_of::<Box<dyn Send + Sync>>()
    );
    assert!(
        std::mem::align_of::<ResidentAllocation>() == std::mem::align_of::<Box<dyn Send + Sync>>()
    );
};
