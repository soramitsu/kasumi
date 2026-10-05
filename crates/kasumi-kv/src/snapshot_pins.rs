//! Bounded, admitted ownership of roots retained by live snapshots.
//!
//! Each independent pin occupies one fixed registry slot. Clones share that
//! slot and its admitted allocation. Captures are deduplicated, bounded copies
//! for reclamation planning, not additional pins: their epoch or root coverage
//! must be checked before applying a plan. The enclosing owner serializes root
//! publication, new-pin acquisition and reclamation. Coverage checks tolerate
//! retired pins and new pins of the already-scanned current root.
//! This module never closes the group or notifies admission of owner failure.

#[cfg(test)]
use crate::core::ResidentLease;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

#[cfg(test)]
#[path = "snapshot_pin_allocation_tests.rs"]
pub(crate) mod allocation_tests;
#[path = "snapshot_pin_rights.rs"]
mod rights;
pub(crate) use rights::retained::{PendingSourceRights, RightsRetirement};
pub(crate) use rights::{HistoryPinRight, PreparedProtectedPin};

use crate::core::{AdmissionError, CoreError, NativeResidentLease, StorageAdmission};
use crate::directory::DirectoryRoot;

const ALLOCATION_ALLOWANCE: usize = 64;
const LEASE_ALLOWANCE: usize = 128;
const ARC_HEADER_BYTES: usize = 2 * std::mem::size_of::<usize>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceLane {
    source: u64,
    lane: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinClass {
    Ordinary,
    Protected(SourceLane),
}
#[derive(Clone, Copy)]
struct Slot {
    root: DirectoryRoot,
    token: u64,
    class: PinClass,
}
#[derive(Clone, Copy)]
enum Entry {
    Empty,
    ProtectedIdle {
        lane: SourceLane,
        ticket: Option<u64>,
    },
    HistoryHold {
        ticket: u64,
        target: PinIdentity,
        lane: SourceLane,
    },
    Pinned(Slot),
}
impl Entry {
    fn pinned(&self) -> Option<&Slot> {
        if let Self::Pinned(slot) = self {
            Some(slot)
        } else {
            None
        }
    }
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}
struct RegistryState {
    slots: Box<[Entry]>,
    epoch: u64,
    serial: u64,
}

// Every strong alias uses this destructor; no Weak or raw Arc escapes. The
// allocation is destroyed before the payload's final lease is retired.
struct RetiredArc<T>(Option<Arc<T>>);
impl<T> RetiredArc<T> {
    fn new(value: T) -> Self {
        Self(Some(Arc::new(value)))
    }
    fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(a.0.as_ref().unwrap(), b.0.as_ref().unwrap())
    }
}
impl<T> RetiredArc<T> {
    fn get_mut(&mut self) -> Option<&mut T> {
        Arc::get_mut(self.0.as_mut().expect("live retired Arc"))
    }
    fn into_payload(mut self) -> Option<T> {
        Arc::into_inner(self.0.take().expect("live retired Arc"))
    }
}
impl<T> Clone for RetiredArc<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> std::ops::Deref for RetiredArc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().expect("live retired Arc")
    }
}
impl<T> Drop for RetiredArc<T> {
    fn drop(&mut self) {
        if let Some(allocation) = self.0.take() {
            drop(Arc::into_inner(allocation));
        }
    }
}
struct LeaseCharge(Option<NativeResidentLease>);
impl Drop for LeaseCharge {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lease.retire();
        }
    }
}
type RegistryRef = RetiredArc<RegistryInner>;

struct RegistryInner {
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    max_pins: usize,
    state: Mutex<RegistryState>,
    failed: AtomicBool,
    _lease: LeaseCharge,
}

/// One registry belongs to one physical owner, even if group IDs are equal.
pub(crate) struct SnapshotPins {
    inner: RegistryRef,
}

#[path = "snapshot_pins_opening.rs"]
mod opening;
pub(crate) use opening::SnapshotPinsOpening;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinIdentity {
    slot: usize,
    token: u64,
    root: DirectoryRoot,
}
struct PinInner {
    registry: RegistryRef,
    identity: OnceLock<PinIdentity>,
    // Protected and subsequently demoted pins retain their exact rights owner.
    _rights: Option<rights::RightsRef>,
    _lease: LeaseCharge,
}

/// Cloning allocates nothing and does not consume another registry slot.
#[derive(Clone)]
pub(crate) struct SnapshotPin {
    inner: RetiredArc<PinInner>,
}

/// A bounded root capture requiring epoch or coverage validation before use.
pub(crate) struct SnapshotRoots {
    registry: RegistryRef,
    epoch: u64,
    roots: Vec<DirectoryRoot>,
    _lease: LeaseCharge,
}

impl SnapshotPins {
    /// Callback-free final-drop observation; keeps poison/failure local until
    /// the retained caller has released this mutex and can fence its Core.
    pub(crate) fn check_retirement(&self) -> Result<(), CoreError> {
        let state = self.inner.state.lock().map_err(|poisoned| {
            self.inner.failed.store(true, Ordering::Release);
            drop(poisoned.into_inner());
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })?;
        drop(state);
        if self.inner.failed.load(Ordering::Acquire) {
            Err(CoreError::new(crate::CoreErrorCause::OwnerFailed))
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(crate) fn corrupt_final_release_for_test(&self, poison: bool) {
        if poison {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = self.inner.state.lock().unwrap();
                panic!("final release registry poison");
            }));
        } else {
            let mut state = self.inner.state.lock().unwrap();
            if let Some(Entry::Pinned(slot)) = state
                .slots
                .iter_mut()
                .find(|entry| matches!(entry, Entry::Pinned(_)))
            {
                slot.token += 1;
            } else {
                let entry = state
                    .slots
                    .iter_mut()
                    .find(|entry| matches!(entry, Entry::ProtectedIdle { .. }))
                    .expect("actual idle lane");
                *entry = Entry::Empty;
            }
        }
    }
    pub(crate) const fn pin_backing_request_bytes() -> u64 {
        (std::mem::size_of::<PinInner>()
            + std::mem::size_of::<SnapshotPin>()
            + ARC_HEADER_BYTES
            + ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE) as u64
    }
    pub(crate) const fn rights_request_bytes() -> u64 {
        rights::source_rights_request_bytes()
    }

    #[cfg(test)]
    pub(crate) fn source_lock_available_for_test(&self) -> bool {
        self.inner.state.try_lock().is_ok()
    }
    pub(crate) fn clone_owner(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        RetiredArc::ptr_eq(&self.inner, &other.inner)
    }

    #[cfg(test)]
    #[allow(
        clippy::result_large_err,
        reason = "The fixture retains the actual opening and cleanup inline until observed disposal."
    )]
    pub(crate) fn new(
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        max_pins: usize,
    ) -> Result<Self, opening::SnapshotPinsOpeningFailure> {
        opening::fixture_new(admission, group_id, max_pins)
    }

    /// The enclosing owner supplies only its current, published root.
    pub(crate) fn acquire(&self, root: DirectoryRoot) -> Result<SnapshotPin, CoreError> {
        self.inner.check()?;
        if root.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot root belongs to another group",
            )));
        }
        root.validate()?;
        let lease = self.inner.reserve(Self::pin_backing_request_bytes())?;
        // Allocate the actual PinInner before locking or selecting its slot.
        let pin = SnapshotPin {
            inner: RetiredArc::new(PinInner {
                registry: self.inner.clone(),
                identity: OnceLock::new(),
                _rights: None,
                _lease: lease,
            }),
        };
        let mut state = self.inner.lock()?;
        let slot = state
            .slots
            .iter()
            .position(Entry::is_empty)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let token = self.inner.next_epoch(&state)?;
        pin.inner
            .identity
            .set(PinIdentity { slot, token, root })
            .expect("new pin");
        state.slots[slot] = Entry::Pinned(Slot {
            root,
            token,
            class: PinClass::Ordinary,
        });
        state.epoch = token;
        drop(state);
        self.inner.check()?;
        Ok(pin)
    }

    pub(crate) fn validate(&self, pin: &SnapshotPin) -> Result<DirectoryRoot, CoreError> {
        self.inner.check()?;
        if !RetiredArc::ptr_eq(&self.inner, &pin.inner.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot pin belongs to another owner",
            )));
        }
        let identity = pin.identity();
        let state = self.inner.lock()?;
        let valid = state
            .slots
            .get(identity.slot)
            .and_then(Entry::pinned)
            .is_some_and(|slot| slot.token == identity.token && slot.root == identity.root);
        drop(state);
        if !valid {
            self.inner.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        self.inner.check()?;
        Ok(pin.root())
    }

    /// Copy unique roots into a pre-admitted, fixed-capacity buffer.
    pub(crate) fn capture(&self) -> Result<SnapshotRoots, CoreError> {
        let charge = backing_charge::<DirectoryRoot>(
            self.inner.max_pins,
            std::mem::size_of::<SnapshotRoots>() + ALLOCATION_ALLOWANCE + LEASE_ALLOWANCE,
        )?;
        let lease = self.inner.reserve(charge)?;
        let mut roots = bounded_vec(self.inner.max_pins)?;
        let state = self.inner.lock()?;
        for slot in state.slots.iter().filter_map(Entry::pinned) {
            // Deliberately bounded by the configured pin limit, without a map
            // or an allocation for each independently acquired duplicate root.
            if !roots.contains(&slot.root) {
                roots.push(slot.root);
            }
        }
        let epoch = state.epoch;
        drop(state);
        self.inner.check()?;
        Ok(SnapshotRoots {
            registry: self.inner.clone(),
            epoch,
            roots,
            _lease: lease,
        })
    }

    pub(crate) fn validate_capture(&self, capture: &SnapshotRoots) -> Result<(), CoreError> {
        self.inner.check()?;
        if !RetiredArc::ptr_eq(&self.inner, &capture.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture belongs to another owner",
            )));
        }
        let state = self.inner.lock()?;
        let current = state.epoch == capture.epoch;
        drop(state);
        self.inner.check()?;
        if current {
            Ok(())
        } else {
            Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture is stale",
            )))
        }
    }

    /// Verify that a reclamation scan still covers every active snapshot.
    /// Retired pins and new pins of the scanned current root are harmless.
    /// The caller must independently verify the selected publication and hold
    /// the owner lock that serializes acquisition with reclamation; acquisition
    /// through that owner must expose only its current root.
    pub(crate) fn validate_coverage(
        &self,
        capture: &SnapshotRoots,
        current: DirectoryRoot,
    ) -> Result<(), CoreError> {
        self.inner.check()?;
        if !RetiredArc::ptr_eq(&self.inner, &capture.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture belongs to another owner",
            )));
        }
        if current.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "current snapshot root belongs to another group",
            )));
        }
        current.validate()?;
        let state = self.inner.lock()?;
        let covered = state
            .slots
            .iter()
            .filter_map(Entry::pinned)
            .all(|slot| slot.root == current || capture.roots.contains(&slot.root));
        drop(state);
        self.inner.check()?;
        if covered {
            Ok(())
        } else {
            Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture does not cover active roots",
            )))
        }
    }

    pub(crate) fn epoch(&self) -> Result<u64, CoreError> {
        self.inner.check()?;
        let state = self.inner.lock()?;
        let epoch = state.epoch;
        drop(state);
        self.inner.check()?;
        Ok(epoch)
    }

    /// Cheap scheduling observation only, never root traversal/unlink proof.
    /// Current-root reader churn is irrelevant; a historical root retires only
    /// after its last independent pin (and all clones) disappears.
    pub(crate) fn baseline_retired(
        &self,
        baseline: &[Option<DirectoryRoot>],
        current: DirectoryRoot,
    ) -> Result<bool, CoreError> {
        self.inner.check()?;
        if current.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "warm baseline belongs to another group",
            )));
        }
        let state = self.inner.lock()?;
        let retired = baseline.iter().flatten().any(|root| {
            *root != current
                && !state
                    .slots
                    .iter()
                    .filter_map(Entry::pinned)
                    .any(|slot| slot.root == *root)
        });
        drop(state);
        self.inner.check()?;
        Ok(retired)
    }

    /// Reuse caller-admitted fixed storage for all unique currently pinned
    /// roots, including current: publication may make that root historical.
    /// Returns any prior historical retirement before replacing the baseline.
    pub(crate) fn refresh_baseline(
        &self,
        baseline: &mut [Option<DirectoryRoot>],
        current: DirectoryRoot,
    ) -> Result<bool, CoreError> {
        self.inner.check()?;
        if baseline.len() < self.inner.max_pins || current.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "warm baseline bounds or owner differ",
            )));
        }
        let state = self.inner.lock()?;
        let retired = baseline.iter().flatten().any(|root| {
            *root != current
                && !state
                    .slots
                    .iter()
                    .filter_map(Entry::pinned)
                    .any(|slot| slot.root == *root)
        });
        baseline.fill(None);
        let mut count = 0;
        for slot in state.slots.iter().filter_map(Entry::pinned) {
            if !baseline[..count].contains(&Some(slot.root)) {
                baseline[count] = Some(slot.root);
                count += 1;
            }
        }
        drop(state);
        self.inner.check()?;
        Ok(retired)
    }

    /// Callbacks run after releasing the registry lock. The returned epoch
    /// identifies the captured roots; visitation itself does not pin them.
    pub(crate) fn visit(
        &self,
        mut visitor: impl FnMut(DirectoryRoot) -> Result<(), CoreError>,
    ) -> Result<u64, CoreError> {
        let capture = self.capture()?;
        for root in capture.roots().iter().copied() {
            self.inner.check()?;
            let result = visitor(root);
            let current = self.inner.check();
            result?;
            current?;
        }
        self.inner.check()?;
        Ok(capture.epoch())
    }
}

impl SnapshotRoots {
    pub(crate) fn roots(&self) -> &[DirectoryRoot] {
        &self.roots
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl SnapshotPin {
    fn identity(&self) -> PinIdentity {
        *self.inner.identity.get().expect("installed snapshot pin")
    }
    /// The immutable identity carried by this pin. Reads must still validate
    /// the pin against its exact registry and the current admission owner.
    pub(crate) fn root(&self) -> DirectoryRoot {
        self.identity().root
    }
}

impl RegistryInner {
    fn check(&self) -> Result<(), CoreError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        if self.admission.check_owner().is_err() {
            self.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<LeaseCharge, CoreError> {
        self.check()?;
        let result = self
            .admission
            .reserve_workspace(bytes)
            .map(NativeResidentLease::new)
            .map(|lease| LeaseCharge(Some(lease)));
        if matches!(&result, Err(AdmissionError::OwnerFailed)) {
            self.failed.store(true, Ordering::Release);
        }
        self.check()?;
        result.map_err(CoreError::from)
    }

    // Admission callbacks must never execute while holding the registry lock.
    fn lock(&self) -> Result<MutexGuard<'_, RegistryState>, CoreError> {
        let guard = self.state.lock().map_err(|poisoned| {
            self.failed.store(true, Ordering::Release);
            drop(poisoned.into_inner());
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })?;
        if self.failed.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        Ok(guard)
    }

    fn next_epoch(&self, state: &RegistryState) -> Result<u64, CoreError> {
        state.epoch.checked_add(1).ok_or_else(|| {
            self.failed.store(true, Ordering::Release);
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })
    }
}

impl Drop for PinInner {
    fn drop(&mut self) {
        let Some(identity) = self.identity.get().copied() else {
            return;
        };
        // Inspect the current class: a history transfer may have demoted this
        // very pin without changing its immutable identity.
        let mut state = self.registry.state.lock().unwrap_or_else(|poisoned| {
            self.registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        let entry = &mut state.slots[identity.slot];
        match entry.pinned().copied() {
            Some(slot) if slot.token == identity.token && slot.root == identity.root => {
                *entry = match slot.class {
                    PinClass::Ordinary => Entry::Empty,
                    PinClass::Protected(lane) => Entry::ProtectedIdle { lane, ticket: None },
                };
                match state.epoch.checked_add(1) {
                    Some(epoch) => state.epoch = epoch,
                    None => self.registry.failed.store(true, Ordering::Release),
                }
            }
            _ => self.registry.failed.store(true, Ordering::Release),
        }
        // Payload/credit destructors, including RightsRef, run after unlock.
        drop(state);
    }
}

fn backing_charge<T>(count: usize, overhead: usize) -> Result<u64, CoreError> {
    count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| bytes.checked_add(overhead))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>, CoreError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
    // Do not retain allocator-supplied excess beyond the admitted backing.
    if values.capacity() != capacity {
        return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
    }
    Ok(values)
}

impl fmt::Debug for SnapshotPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotPins")
            .field("group_id", &self.inner.group_id)
            .field("max_pins", &self.inner.max_pins)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SnapshotPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotPin")
            .field("root", &self.root())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SnapshotRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotRoots")
            .field("epoch", &self.epoch)
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::OwnerFailed;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const GROUP_ID: [u8; 16] = [37; 16];

    pub(super) struct Admission {
        pub(super) used: Arc<AtomicU64>,
        limit: AtomicU64,
        expired: AtomicBool,
        expire_on_reserve: AtomicBool,
        fail_next_reserve: AtomicBool,
        pub(super) reserves: AtomicUsize,
        pub(super) checks: AtomicUsize,
        pub(super) last_box: AtomicUsize,
        notifications: AtomicUsize,
    }

    impl Default for Admission {
        fn default() -> Self {
            Self {
                used: Arc::new(AtomicU64::new(0)),
                limit: AtomicU64::new(u64::MAX),
                expired: AtomicBool::new(false),
                expire_on_reserve: AtomicBool::new(false),
                fail_next_reserve: AtomicBool::new(false),
                reserves: AtomicUsize::new(0),
                checks: AtomicUsize::new(0),
                last_box: AtomicUsize::new(0),
                notifications: AtomicUsize::new(0),
            }
        }
    }

    struct Lease {
        used: Arc<AtomicU64>,
        bytes: u64,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            allocation_tests::before_refund(Arc::as_ptr(&self.used) as usize, self.bytes);
            self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            self.checks.fetch_add(1, Ordering::AcqRel);
            if self.expired.load(Ordering::Acquire) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }
        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            self.reserves.fetch_add(1, Ordering::AcqRel);
            if self.fail_next_reserve.swap(false, Ordering::AcqRel) {
                return Err(AdmissionError::OwnerFailed);
            }
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            if self.expire_on_reserve.swap(false, Ordering::AcqRel) {
                self.expired.store(true, Ordering::Release);
            }
            let lease = Box::new(Lease {
                used: Arc::clone(&self.used),
                bytes,
            });
            self.last_box
                .store((&*lease as *const Lease) as usize, Ordering::Release);
            Ok(lease)
        }
        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
        }
        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            self.check_owner()
        }
        fn owner_failed(&self) {
            self.notifications.fetch_add(1, Ordering::AcqRel);
            self.expired.store(true, Ordering::Release);
        }

        fn quote_cache_memory(
            &self,
            bytes: u64,
        ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
            crate::cache_test::quote::<Self>(bytes)
        }
        fn reserve_cache_memory(
            self: std::sync::Arc<Self>,
            bytes: u64,
        ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
            crate::cache_test::reserve(self, bytes)
        }
    }
    impl crate::cache_test::Provider for Admission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            self.reserves.fetch_add(1, Ordering::AcqRel);
            if self.fail_next_reserve.swap(false, Ordering::AcqRel) {
                return Err(AdmissionError::OwnerFailed);
            }
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            if self.expire_on_reserve.swap(false, Ordering::AcqRel) {
                self.expired.store(true, Ordering::Release);
            }
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
            self.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    pub(super) fn root(generation: u64) -> DirectoryRoot {
        DirectoryRoot {
            group_id: GROUP_ID,
            generation,
            page: None,
            height: 0,
            entries: 0,
        }
    }

    pub(super) fn setup(max_pins: usize) -> (Arc<Admission>, SnapshotPins) {
        let admission = Arc::new(Admission::default());
        let pins = SnapshotPins::new(admission.clone(), GROUP_ID, max_pins).unwrap();
        (admission, pins)
    }

    #[test]
    fn backing_is_admitted_before_allocation_and_constructor_failures_release_it() {
        let admission = Arc::new(Admission::default());
        assert!(
            matches!(&(SnapshotPins::new(admission.clone(), GROUP_ID, 0)), Err(native_error) if matches!(native_error.original_error().rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert!(
            matches!(&(SnapshotPins::new(admission.clone(), GROUP_ID, usize::MAX)), Err(native_error) if matches!(native_error.original_error().rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        assert_eq!(admission.reserves.load(Ordering::Acquire), 0);
        admission.limit.store(0, Ordering::Release);
        assert!(
            matches!(&(SnapshotPins::new(admission.clone(), GROUP_ID, 1)), Err(native_error) if matches!(native_error.original_error().rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        admission.limit.store(u64::MAX, Ordering::Release);
        admission.expire_on_reserve.store(true, Ordering::Release);
        assert!(
            matches!(&(SnapshotPins::new(admission.clone(), GROUP_ID, 1)), Err(native_error) if matches!(native_error.original_error().rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn clones_share_the_slot_charge_and_epoch_until_the_last_clone_drops() {
        let (admission, pins) = setup(1);
        let backing = admission.used.load(Ordering::Acquire);
        let pin = pins.acquire(root(1)).unwrap();
        let retained = admission.used.load(Ordering::Acquire);
        assert!(retained > backing);
        let epoch = pins.epoch().unwrap();
        let reserves = admission.reserves.load(Ordering::Acquire);
        let clone = pin.clone();
        assert!(RetiredArc::ptr_eq(&pin.inner, &clone.inner));
        assert_eq!(admission.reserves.load(Ordering::Acquire), reserves);
        assert_eq!(admission.used.load(Ordering::Acquire), retained);
        assert_eq!(pins.epoch().unwrap(), epoch);
        assert!(
            matches!(&(pins.acquire(root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        assert_eq!(admission.used.load(Ordering::Acquire), retained);
        drop(pin);
        assert_eq!(pins.validate(&clone).unwrap(), root(1));
        assert_eq!(pins.epoch().unwrap(), epoch);
        assert!(
            matches!(&(pins.acquire(root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        drop(clone);
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
        assert_eq!(pins.epoch().unwrap(), epoch + 1);
        let retried = pins.acquire(root(2)).unwrap();
        assert_eq!(pins.validate(&retried).unwrap(), root(2));
    }

    #[test]
    fn equal_group_ids_do_not_authorize_foreign_pins_or_captures() {
        let (_, first) = setup(2);
        let (_, second) = setup(2);
        let pin = first.acquire(root(1)).unwrap();
        let capture = first.capture().unwrap();
        assert!(
            matches!(&(second.validate(&pin)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert!(
            matches!(&(second.validate_capture(&capture)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        let mut foreign = root(1);
        foreign.group_id = [38; 16];
        assert!(
            matches!(&(first.acquire(foreign)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert_eq!(first.validate(&pin).unwrap(), root(1));
        assert_eq!(second.epoch().unwrap(), 0);
    }

    #[test]
    fn captures_deduplicate_roots_with_fixed_backing_and_reject_epoch_changes() {
        let (_, pins) = setup(3);
        let first = pins.acquire(root(1)).unwrap();
        let duplicate = pins.acquire(root(1)).unwrap();
        let other = pins.acquire(root(2)).unwrap();
        let capture = pins.capture().unwrap();
        assert_eq!(capture.roots(), &[root(1), root(2)]);
        assert_eq!(capture.roots.capacity(), 3);
        assert_eq!(capture.epoch(), pins.epoch().unwrap());
        let clone = first.clone();
        pins.validate_capture(&capture).unwrap();
        drop(first);
        pins.validate_capture(&capture).unwrap();
        drop(duplicate);
        assert!(
            matches!(&(pins.validate_capture(&capture)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        let fresh = pins.capture().unwrap();
        assert_eq!(fresh.roots(), &[root(1), root(2)]);
        let replacement = pins.acquire(root(3)).unwrap();
        assert!(
            matches!(&(pins.validate_capture(&fresh)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        drop((clone, other, replacement));
        assert!(pins.capture().unwrap().roots().is_empty());
    }

    #[test]
    fn coverage_survives_current_root_pin_churn_without_reserving_memory() {
        let (admission, pins) = setup(3);
        let historical = pins.acquire(root(1)).unwrap();
        let capture = pins.capture().unwrap();
        for _ in 0..100 {
            let first = pins.acquire(root(2)).unwrap();
            let duplicate = pins.acquire(root(2)).unwrap();
            let reserves = admission.reserves.load(Ordering::Acquire);
            let used = admission.used.load(Ordering::Acquire);
            pins.validate_coverage(&capture, root(2)).unwrap();
            assert_eq!(admission.reserves.load(Ordering::Acquire), reserves);
            assert_eq!(admission.used.load(Ordering::Acquire), used);
            drop((first, duplicate));
            pins.validate_coverage(&capture, root(2)).unwrap();
        }
        assert!(
            matches!(&(pins.validate_capture(&capture)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("snapshot capture is stale"))))
        );
        assert_eq!(pins.validate(&historical).unwrap(), root(1));
    }

    #[test]
    fn coverage_survives_retirement_of_captured_roots() {
        let (_, pins) = setup(2);
        let historical = pins.acquire(root(1)).unwrap();
        let capture = pins.capture().unwrap();
        drop(historical);
        pins.validate_coverage(&capture, root(2)).unwrap();
        let current = pins.acquire(root(2)).unwrap();
        pins.validate_coverage(&capture, root(2)).unwrap();
        assert_eq!(capture.roots(), &[root(1)]);
        assert_eq!(pins.validate(&current).unwrap(), root(2));
    }

    #[test]
    fn coverage_rejects_an_uncaptured_historical_root_and_recovers_after_its_drop() {
        let (_, pins) = setup(3);
        let historical = pins.acquire(root(2)).unwrap();
        let capture = pins.capture().unwrap();
        let unscanned = pins.acquire(root(1)).unwrap();
        assert!(
            matches!(&(pins.validate_coverage(&capture, root(3))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(
                "snapshot capture does not cover active roots"
            ))))
        );
        drop(unscanned);
        pins.validate_coverage(&capture, root(3)).unwrap();
        assert_eq!(pins.validate(&historical).unwrap(), root(2));
    }

    #[test]
    fn coverage_requires_exact_registry_identity_and_current_root_group() {
        let (_, first) = setup(1);
        let (_, second) = setup(1);
        let capture = first.capture().unwrap();
        assert!(
            matches!(&(second.validate_coverage(&capture, root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(
                "snapshot capture belongs to another owner"
            ))))
        );
        let mut foreign = root(1);
        foreign.group_id = [38; 16];
        assert!(
            matches!(&(first.validate_coverage(&capture, foreign)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(
                "current snapshot root belongs to another group"
            ))))
        );
        first.validate_coverage(&capture, root(1)).unwrap();
    }

    #[test]
    fn pin_and_capture_admission_denials_are_retryable_and_leave_no_slot_or_charge() {
        let (admission, pins) = setup(2);
        let backing = admission.used.load(Ordering::Acquire);
        admission.limit.store(backing, Ordering::Release);
        assert!(
            matches!(&(pins.acquire(root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        assert!(
            matches!(&(pins.capture()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        assert_eq!(pins.epoch().unwrap(), 0);
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
        admission.limit.store(u64::MAX, Ordering::Release);
        let pin = pins.acquire(root(1)).unwrap();
        let retained = admission.used.load(Ordering::Acquire);
        let capture = pins.capture().unwrap();
        assert!(admission.used.load(Ordering::Acquire) > retained);
        assert_eq!(capture.roots(), &[root(1)]);
        drop(capture);
        assert_eq!(admission.used.load(Ordering::Acquire), retained);
        drop(pin);
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
    }

    #[test]
    fn charges_follow_pin_and_capture_lifetimes_after_registry_handle_is_dropped() {
        let (admission, pins) = setup(1);
        let backing = admission.used.load(Ordering::Acquire);
        let pin = pins.acquire(root(1)).unwrap();
        let pin_charge = admission.used.load(Ordering::Acquire) - backing;
        let capture = pins.capture().unwrap();
        let retained = admission.used.load(Ordering::Acquire);
        drop(pins);
        assert_eq!(admission.used.load(Ordering::Acquire), retained);
        drop(pin);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            retained - pin_charge
        );
        drop(capture);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn visitation_callbacks_can_change_pins_without_reentering_the_lock() {
        let (_, pins) = setup(2);
        let first = pins.acquire(root(1)).unwrap();
        let before = pins.epoch().unwrap();
        let mut visited = 0;
        let captured = pins
            .visit(|seen| {
                assert_eq!(seen, root(1));
                let temporary = pins.acquire(root(2))?;
                assert_eq!(pins.validate(&temporary)?, root(2));
                drop(temporary);
                visited += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, 1);
        assert_eq!(captured, before);
        assert_ne!(captured, pins.epoch().unwrap());
        assert_eq!(pins.validate(&first).unwrap(), root(1));
    }

    #[test]
    fn owner_expiration_is_latched_but_drops_still_release_every_charge() {
        let (admission, pins) = setup(2);
        let pin = pins.acquire(root(1)).unwrap();
        let capture = pins.capture().unwrap();
        admission.expired.store(true, Ordering::Release);
        assert!(
            matches!(&(pins.validate(&pin)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        admission.expired.store(false, Ordering::Release);
        assert!(
            matches!(&(pins.acquire(root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(pins.capture()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(pins.validate_capture(&capture)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(pins.validate_coverage(&capture, root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(pins.epoch()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        drop((capture, pin, pins));
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
        assert_eq!(admission.notifications.load(Ordering::Acquire), 0);
    }

    #[test]
    fn owner_failure_during_reservation_never_publishes_a_pin() {
        for return_failure in [false, true] {
            let (admission, pins) = setup(1);
            let backing = admission.used.load(Ordering::Acquire);
            if return_failure {
                admission.fail_next_reserve.store(true, Ordering::Release);
            } else {
                admission.expire_on_reserve.store(true, Ordering::Release);
            }
            assert!(
                matches!(&(pins.acquire(root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
            );
            assert_eq!(admission.used.load(Ordering::Acquire), backing);
            let state = pins.inner.state.lock().unwrap();
            assert!(state.slots.iter().all(Entry::is_empty));
            assert_eq!(state.epoch, 0);
            drop(state);
            admission.expired.store(false, Ordering::Release);
            assert!(
                matches!(&(pins.acquire(root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
            );
            drop(pins);
            assert_eq!(admission.used.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn poisoned_registry_fails_closed_and_final_pin_drop_still_reclaims_its_slot() {
        let (admission, pins) = setup(1);
        let backing = admission.used.load(Ordering::Acquire);
        let pin = pins.acquire(root(1)).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = pins.inner.state.lock().unwrap();
            panic!("poison registry");
        }));
        assert!(result.is_err());
        assert!(
            matches!(&(pins.validate(&pin)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        drop(pin);
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
        let state = pins
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.slots.iter().all(Entry::is_empty));
        drop(state);
        assert!(
            matches!(&(pins.capture()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        drop(pins);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
        assert_eq!(admission.notifications.load(Ordering::Acquire), 0);
    }

    #[test]
    fn epoch_exhaustion_fails_closed_without_wraparound_or_retained_pin_charge() {
        let (admission, pins) = setup(1);
        let backing = admission.used.load(Ordering::Acquire);
        pins.inner.state.lock().unwrap().epoch = u64::MAX;
        assert!(
            matches!(&(pins.acquire(root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
        let (_, dropping) = setup(1);
        dropping.inner.state.lock().unwrap().epoch = u64::MAX - 1;
        let pin = dropping.acquire(root(1)).unwrap();
        let capture = dropping.capture().unwrap();
        assert_eq!(capture.epoch(), u64::MAX);
        drop(pin);
        assert!(
            matches!(&(dropping.validate_capture(&capture)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        let state = dropping.inner.state.lock().unwrap();
        assert_eq!(state.epoch, u64::MAX);
        assert!(state.slots.iter().all(Entry::is_empty));
    }
}
