//! Backing for the synchronization implementations of the supported toolchain.
//!
//! Rust 1.97.1's pthread implementations allocate a pinned platform Mutex on
//! first lock and a pinned platform Condvar on first notify/wait. Initialize
//! them under their original owning grant before exposing concurrent aliases.
use std::sync::{Condvar, Mutex};

use crate::{CacheMemoryLease, core::NativeResidentLease};

// These are the reviewed Rust 1.97.1 pthread and inline/futex families.
// An unreviewed backend cannot silently receive a zero backing quote.
#[cfg(not(any(
    all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "motor",
            target_os = "hermit"
        ))
    ),
    any(
        all(target_os = "windows", not(target_vendor = "win7")),
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "motor",
        target_os = "hermit",
        all(target_family = "wasm", target_feature = "atomics")
    )
)))]
compile_error!(
    "kasumi native synchronization backing requires a reviewed pthread or inline/futex target"
);

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "motor",
        target_os = "hermit"
    ))
))]
pub(crate) const fn mutex_backing_bytes() -> usize {
    std::mem::size_of::<libc::pthread_mutex_t>() + 64
}
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "motor",
        target_os = "hermit"
    ))
))]
pub(crate) const fn condvar_backing_bytes() -> usize {
    std::mem::size_of::<libc::pthread_cond_t>() + 64
}
#[cfg(any(
    all(target_os = "windows", not(target_vendor = "win7")),
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "motor",
    target_os = "hermit",
    all(target_family = "wasm", target_feature = "atomics")
))]
pub(crate) const fn mutex_backing_bytes() -> usize {
    0
}
#[cfg(any(
    all(target_os = "windows", not(target_vendor = "win7")),
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "motor",
    target_os = "hermit",
    all(target_family = "wasm", target_feature = "atomics")
))]
pub(crate) const fn condvar_backing_bytes() -> usize {
    0
}

/// A borrow of the already acquired original grant. Initialization never
/// acquires another grant or retains this borrow after the synchronous call.
mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::core::NativeResidentLease {}
    impl Sealed for crate::CacheMemoryLease {}
}
pub(crate) trait SyncBackingGrant: sealed::Sealed {
    #[cfg(test)]
    fn allocation_address(&self) -> usize;
}
impl SyncBackingGrant for NativeResidentLease {
    #[cfg(test)]
    fn allocation_address(&self) -> usize {
        self.allocation_address_for_test()
    }
}
impl SyncBackingGrant for CacheMemoryLease {
    #[cfg(test)]
    fn allocation_address(&self) -> usize {
        self.allocation_address_for_test()
    }
}

pub(crate) fn mutex<T>(value: T, _original: &impl SyncBackingGrant) -> Mutex<T> {
    #[cfg(test)]
    let _observation = tests::Construction::new(_original.allocation_address());
    let mutex = Mutex::new(value);
    drop(mutex.lock().expect("new admitted native mutex"));
    mutex
}

pub(crate) fn condvar(_original: &impl SyncBackingGrant) -> Condvar {
    #[cfg(test)]
    let _observation = tests::Construction::new(_original.allocation_address());
    let condvar = Condvar::new();
    condvar.notify_all();
    condvar
}

#[cfg(test)]
#[path = "native_sync_tests.rs"]
pub(crate) mod tests;
