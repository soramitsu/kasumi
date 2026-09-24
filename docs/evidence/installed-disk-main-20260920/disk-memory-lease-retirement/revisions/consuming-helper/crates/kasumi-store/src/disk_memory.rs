//! Required resident admission for installed disk ownership metadata.
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

/// Registry contention is returned inline before any resident acquisition.
/// Other constructor failures preserve their original diagnostic chain.
#[derive(Debug)]
pub enum DiskOpenError {
    RegistryBusy,
    Failed(anyhow::Error),
}
impl std::fmt::Display for DiskOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegistryBusy => formatter.write_str("installed disk registry is busy"),
            Self::Failed(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for DiskOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegistryBusy => None,
            Self::Failed(error) => Some(error.as_ref()),
        }
    }
}
impl From<anyhow::Error> for DiskOpenError {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}
impl From<io::Error> for DiskOpenError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error.into())
    }
}
impl From<io::ErrorKind> for DiskOpenError {
    fn from(kind: io::ErrorKind) -> Self {
        io::Error::from(kind).into()
    }
}
pub(crate) fn require(condition: bool, message: &'static str) -> Result<(), DiskOpenError> {
    if condition {
        Ok(())
    } else {
        Err(DiskOpenError::Failed(anyhow::Error::msg(message)))
    }
}

/// Four independently owned resident allocations for a fresh isolated device.
/// Reusing an existing physical device does not acquire `device_bytes` again.
/// The provider adds its own lease storage to each acquired component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskMemoryRequirements {
    pub owner_bytes: u64,
    pub registry_bytes: u64,
    pub device_bytes: u64,
    pub registration_bytes: u64,
}

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

/// No global Vec/HashMap capacity survives removed entries. Each actual node is
/// admitted by its owning resource before allocation and is removed iteratively.
pub(crate) struct Entry<T> {
    pub(crate) value: T,
    next: Option<Box<Entry<T>>>,
}
pub(crate) struct List<T> {
    head: Option<Box<Entry<T>>>,
}
impl<T> List<T> {
    pub(crate) const fn new() -> Self {
        Self { head: None }
    }
    pub(crate) fn prepare(value: T) -> Box<Entry<T>> {
        Box::new(Entry { value, next: None })
    }
    pub(crate) fn insert(&mut self, mut entry: Box<Entry<T>>) {
        entry.next = self.head.take();
        self.head = Some(entry);
    }
    pub(crate) fn find(&self, mut predicate: impl FnMut(&T) -> bool) -> Option<&T> {
        let mut cursor = self.head.as_deref();
        while let Some(entry) = cursor {
            if predicate(&entry.value) {
                return Some(&entry.value);
            }
            cursor = entry.next.as_deref();
        }
        None
    }
    pub(crate) fn find_mut(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<&mut T> {
        let mut cursor = self.head.as_deref_mut();
        while let Some(entry) = cursor {
            if predicate(&entry.value) {
                return Some(&mut entry.value);
            }
            cursor = entry.next.as_deref_mut();
        }
        None
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::successors(self.head.as_deref(), |entry| entry.next.as_deref())
            .map(|entry| &entry.value)
    }
    pub(crate) fn remove(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<T> {
        let mut cursor = &mut self.head;
        while cursor.is_some() {
            if predicate(&cursor.as_ref().expect("present list entry").value) {
                // Moving out deallocates the actual box before the returned
                // value's lease may release its charge.
                let Entry { value, next } = *cursor.take().expect("present list entry");
                *cursor = next;
                return Some(value);
            }
            cursor = &mut cursor.as_mut().expect("present list entry").next;
        }
        None
    }
}
impl<T> Drop for List<T> {
    fn drop(&mut self) {
        // Never recurse through an arbitrary number of admitted registrations.
        while let Some(value) = self.remove(|_| true) {
            drop(value);
        }
    }
}

#[cfg(test)]
#[path = "disk_memory_tests.rs"]
mod tests;
