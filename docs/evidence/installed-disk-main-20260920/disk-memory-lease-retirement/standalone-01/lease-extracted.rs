use std::{io, sync::Arc};
/// Implementations retain the actual resource governor in the returned lease.
/// Reserve `bytes` plus the implementation's lease-allocation workspace before
/// allocating that lease. Acquisition consumes no inflight operation slot.
/// An installed owner is identified by this exact Arc, not equivalent policy.
pub trait NodeDiskMemoryAdmission: Send + Sync {
    fn reserve_installed(self: Arc<Self>, bytes: u64) -> io::Result<DiskMemoryLease>;
}

/// Opaque installed resident lease with allocation-before-credit retirement.
///
/// The provider admits the concrete reservation token's Box allocation before
/// constructing this lease. Dropping the lease retires that actual allocation
/// before invoking the token's destructor, which can then return byte credit.
/// No reference, raw Box, or alternate retirement path is exposed.
pub struct DiskMemoryLease(Option<Box<dyn RetireLease>>);
trait RetireLease: Send + Sync {
    fn retire(self: Box<Self>);
}
// A named Box parameter remains allocated until its scope ends even after its
// payload is moved out. Return the payload from a consuming helper so that the
// Box's storage is retired before the caller can invoke the payload destructor.
fn unbox_lease<T>(allocation: Box<T>) -> T {
    *allocation
}
impl<T: Send + Sync + 'static> RetireLease for T {
    fn retire(self: Box<Self>) {
        drop(unbox_lease(self));
    }
}
impl DiskMemoryLease {
    /// Wrap the concrete, already-admitted reservation token directly. The
    /// caller must fund `size_of::<T>()` and the existing allocator allowance
    /// before this method allocates; this method never acquires admission.
    pub fn new<T: Send + Sync + 'static>(reservation: T) -> Self {
        Self(Some(Box::new(reservation)))
    }
}
impl Drop for DiskMemoryLease {
    fn drop(&mut self) {
        if let Some(reservation) = self.0.take() {
            reservation.retire();
        }
    }
}
// Existing owner/registry planning charges one opaque fat pointer inline. This
// replacement must preserve that layout on every supported compilation target.
const _: () = {
    assert!(std::mem::size_of::<DiskMemoryLease>() == std::mem::size_of::<Box<dyn Send + Sync>>());
    assert!(
        std::mem::align_of::<DiskMemoryLease>() == std::mem::align_of::<Box<dyn Send + Sync>>()
    );
};

pub(crate) type Lease = DiskMemoryLease;
pub(crate) const ALLOCATION_ALLOWANCE: u64 = 4096;

pub(crate) fn overflow() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
pub(crate) fn add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right).ok_or_else(overflow)
}
pub(crate) fn mul(left: u64, right: u64) -> io::Result<u64> {
    left.checked_mul(right).ok_or_else(overflow)
}
pub(crate) fn size<T>() -> io::Result<u64> {
    u64::try_from(std::mem::size_of::<T>()).map_err(|_| overflow())
}
pub(crate) fn allocation<T>(count: u64) -> io::Result<u64> {
    add(mul(size::<T>()?, count)?, ALLOCATION_ALLOWANCE)
}
pub(crate) fn arc<T>() -> io::Result<u64> {
    add(allocation::<T>(1)?, 2 * size::<usize>()?)
}


#[cfg(test)]
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/disk-memory-lease-retirement/proposed/crates/kasumi-store/src/disk_memory_tests.rs"]
mod tests;
