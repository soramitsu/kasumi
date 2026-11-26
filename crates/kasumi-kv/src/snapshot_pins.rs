//! Bounded, admitted ownership of roots retained by live snapshots.
//!
//! Each independent pin occupies one fixed registry slot. Clones share that
//! slot and its admitted allocation. Captures are deduplicated, bounded copies
//! for reclamation planning, not additional pins: their epoch or root coverage
//! must be checked before applying a plan. The enclosing owner serializes root
//! publication, new-pin acquisition and reclamation. Coverage checks tolerate
//! retired pins and new pins of the already-scanned current root.
//!
//! A reclamation cohort may outlive several certified root installations. It
//! registers its nonce and the root it certifies; every pin installed at that
//! exact root is stamped with the nonce under the registry lock, and each
//! certified installation advances the registered root. Cohort coverage then
//! accepts a pinned slot only at the current root, at a captured (walked)
//! root, or when it carries the cohort's stamp. Clones share the slot and
//! its stamp. Stamps and nonces are volatile.
//!
//! Acquisitions come in two classes. Critical ones (writes, applies, their
//! successor captures and every other acquisition by default) may take any
//! free slot. Ordinary ones, which clients can hold across publications
//! (snapshot leases, cursors, queries), are charged against the registry less
//! its configured reserve: `ordinary + requested <= max_pins - reserve`. An
//! ordinary credit may stand for a slot the holder will retain later (a
//! lease keeps its selection alive once it becomes historical), so credits
//! are counted apart from occupied slots. A refused ordinary acquisition is a
//! no-effect `CapacityDenied`. A promise reserves a free slot and its backing
//! before an irreversible step, and binds the root current after it: binding
//! never fails for capacity.
//! This module never closes the group or notifies admission of owner failure.

#[cfg(test)]
use crate::core::ResidentLease;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

#[cfg(test)]
#[path = "snapshot_pin_allocation_tests.rs"]
pub(crate) mod allocation_tests;

use crate::core::{AdmissionError, CoreError, NativeResidentLease, StorageAdmission};
use crate::directory::DirectoryRoot;

const ALLOCATION_ALLOWANCE: usize = 64;
const LEASE_ALLOWANCE: usize = 128;
const ARC_HEADER_BYTES: usize = 2 * std::mem::size_of::<usize>();

#[derive(Clone, Copy)]
struct Slot {
    root: DirectoryRoot,
    token: u64,
    /// Nonce of the cohort that certified `root` when this pin was installed;
    /// zero when no active cohort covered that root.
    coverage: u64,
}
#[derive(Clone, Copy)]
enum Entry {
    Empty,
    /// Reserved by the promise with this token; no root is pinned yet.
    Promised(u64),
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
    /// The active reclamation cohort and the root it currently certifies.
    coverage: Option<(u64, DirectoryRoot)>,
    /// Slots not empty: pinned or promised.
    held: usize,
    /// Ordinary credits charged: ordinary pins and retention credits.
    ordinary: usize,
    /// Slots ordinary credits may never use.
    reserve: usize,
    /// Last promise token; promise tokens are distinct from pin epochs.
    promises: u64,
}

impl RegistryState {
    /// Whether `credits` more ordinary credits stay out of the reserve. A
    /// registry without a reserve counts credits but never refuses them: an
    /// ordinary pin there still needs a free slot, as every pin always has.
    fn admits_ordinary(&self, max_pins: usize, credits: usize) -> bool {
        self.ordinary.checked_add(credits).is_some_and(|charged| {
            self.reserve == 0 || charged <= max_pins.saturating_sub(self.reserve)
        })
    }

    /// The stamp for a pin installed at `root` under this lock.
    fn stamp(&self, root: DirectoryRoot) -> u64 {
        self.coverage
            .filter(|(_, certified)| *certified == root)
            .map_or(0, |(nonce, _)| nonce)
    }
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
    /// Charged one ordinary credit, returned with the slot.
    ordinary: bool,
    _lease: LeaseCharge,
}

/// Cloning allocates nothing and does not consume another registry slot.
#[derive(Clone)]
pub(crate) struct SnapshotPin {
    inner: RetiredArc<PinInner>,
}

/// Ordinary credits held without a slot: what a retained selection may
/// occupy once it becomes historical. Returned when dropped.
pub(crate) struct OrdinaryPinCredits {
    registry: RegistryRef,
    credits: usize,
}

/// A free slot and its pin backing reserved for one later critical pin. The
/// slot returns to the registry if the promise is dropped unbound.
pub(crate) struct SnapshotPinPromise {
    pin: Option<SnapshotPin>,
    slot: usize,
    token: u64,
}

/// Occupancy of one registry, for admission decisions and status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotPinUse {
    /// Occupied slots: pinned or promised.
    pub held: u64,
    pub limit: u64,
    /// Slots ordinary credits may never use.
    pub reserve: u64,
    /// Ordinary credits charged.
    pub ordinary: u64,
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
            let Some(Entry::Pinned(slot)) = state
                .slots
                .iter_mut()
                .find(|entry| matches!(entry, Entry::Pinned(_)))
            else {
                panic!("actual pinned slot");
            };
            slot.token += 1;
        }
    }
    pub(crate) const fn pin_backing_request_bytes() -> u64 {
        (std::mem::size_of::<PinInner>()
            + std::mem::size_of::<SnapshotPin>()
            + ARC_HEADER_BYTES
            + ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE) as u64
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

    /// The enclosing owner supplies only its current, published root. A
    /// critical pin may take any free slot.
    pub(crate) fn acquire(&self, root: DirectoryRoot) -> Result<SnapshotPin, CoreError> {
        self.acquire_class(root, false)
    }

    /// An ordinary pin also takes one ordinary credit; it is refused for
    /// capacity once ordinary credits would reach into the reserve.
    pub(crate) fn acquire_ordinary(&self, root: DirectoryRoot) -> Result<SnapshotPin, CoreError> {
        self.acquire_class(root, true)
    }

    fn check_root(&self, root: DirectoryRoot) -> Result<(), CoreError> {
        if root.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot root belongs to another group",
            )));
        }
        root.validate()
    }

    /// The pin owner, allocated with its admitted backing before any slot
    /// is selected.
    fn unbound_pin(&self, ordinary: bool) -> Result<SnapshotPin, CoreError> {
        let lease = self.inner.reserve(Self::pin_backing_request_bytes())?;
        Ok(SnapshotPin {
            inner: RetiredArc::new(PinInner {
                registry: self.inner.clone(),
                identity: OnceLock::new(),
                ordinary,
                _lease: lease,
            }),
        })
    }

    fn acquire_class(&self, root: DirectoryRoot, ordinary: bool) -> Result<SnapshotPin, CoreError> {
        self.inner.check()?;
        self.check_root(root)?;
        // Allocate the actual PinInner before locking or selecting its slot.
        let pin = self.unbound_pin(ordinary)?;
        let mut state = self.inner.lock()?;
        if ordinary && !state.admits_ordinary(self.inner.max_pins, 1) {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
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
        let coverage = state.stamp(root);
        state.slots[slot] = Entry::Pinned(Slot {
            root,
            token,
            coverage,
        });
        state.epoch = token;
        state.held += 1;
        state.ordinary += usize::from(ordinary);
        drop(state);
        self.inner.check()?;
        Ok(pin)
    }

    /// Reserve a free slot and the pin backing for one later critical pin.
    /// This is the only fallible step: `bind` cannot fail for capacity.
    pub(crate) fn promise(&self) -> Result<SnapshotPinPromise, CoreError> {
        self.inner.check()?;
        let pin = self.unbound_pin(false)?;
        let mut state = self.inner.lock()?;
        let slot = state
            .slots
            .iter()
            .position(Entry::is_empty)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let token = state.promises.checked_add(1).ok_or_else(|| {
            self.inner.failed.store(true, Ordering::Release);
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })?;
        state.promises = token;
        state.slots[slot] = Entry::Promised(token);
        state.held += 1;
        drop(state);
        let promise = SnapshotPinPromise {
            pin: Some(pin),
            slot,
            token,
        };
        self.inner.check()?;
        Ok(promise)
    }

    /// Pin `root` in the slot `promise` reserved. Capacity was taken by the
    /// promise; only an owner failure or a foreign root can refuse this.
    pub(crate) fn bind(
        &self,
        mut promise: SnapshotPinPromise,
        root: DirectoryRoot,
    ) -> Result<SnapshotPin, CoreError> {
        self.inner.check()?;
        self.check_root(root)?;
        let pin = promise.pin.as_ref().expect("unbound promise");
        if !RetiredArc::ptr_eq(&self.inner, &pin.inner.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot pin promise belongs to another owner",
            )));
        }
        let mut state = self.inner.lock()?;
        if !matches!(state.slots[promise.slot], Entry::Promised(token) if token == promise.token) {
            drop(state);
            self.inner.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        let token = self.inner.next_epoch(&state)?;
        pin.inner
            .identity
            .set(PinIdentity {
                slot: promise.slot,
                token,
                root,
            })
            .expect("unbound promise");
        let coverage = state.stamp(root);
        state.slots[promise.slot] = Entry::Pinned(Slot {
            root,
            token,
            coverage,
        });
        state.epoch = token;
        drop(state);
        let pin = promise.pin.take().expect("bound promise");
        self.inner.check()?;
        Ok(pin)
    }

    /// Charge `credits` ordinary credits without occupying a slot, refused
    /// for capacity once they would reach into the reserve.
    pub(crate) fn admit_ordinary(&self, credits: usize) -> Result<OrdinaryPinCredits, CoreError> {
        self.inner.check()?;
        let mut state = self.inner.lock()?;
        if !state.admits_ordinary(self.inner.max_pins, credits) {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        state.ordinary += credits;
        drop(state);
        Ok(OrdinaryPinCredits {
            registry: self.inner.clone(),
            credits,
        })
    }

    /// Keep `reserve` slots from ordinary credits. Refused if it would leave
    /// no slot, or if ordinary credits already charged reach into it.
    pub(crate) fn set_reserve(&self, reserve: usize) -> Result<(), CoreError> {
        self.inner.check()?;
        let mut state = self.inner.lock()?;
        if reserve >= self.inner.max_pins || state.ordinary > self.inner.max_pins - reserve {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot pin reserve exceeds the registry or its ordinary credits",
            )));
        }
        state.reserve = reserve;
        drop(state);
        self.inner.check()
    }

    /// Occupancy without scanning the registry.
    pub(crate) fn usage(&self) -> Result<SnapshotPinUse, CoreError> {
        self.inner.check()?;
        let state = self.inner.lock()?;
        let usage = SnapshotPinUse {
            held: state.held as u64,
            limit: self.inner.max_pins as u64,
            reserve: state.reserve as u64,
            ordinary: state.ordinary as u64,
        };
        drop(state);
        self.inner.check()?;
        Ok(usage)
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
        // Deliberately bounded by the configured pin limit, without a map or
        // an allocation for each independently acquired duplicate root. One
        // entry per pinned slot always fits; sorting then removes duplicates
        // in place, so the cost stays O(n log n) for a full registry.
        roots.extend(
            state
                .slots
                .iter()
                .filter_map(Entry::pinned)
                .map(|slot| slot.root),
        );
        let epoch = state.epoch;
        drop(state);
        sort_unique(&mut roots);
        self.inner.check()?;
        Ok(SnapshotRoots {
            registry: self.inner.clone(),
            epoch,
            roots,
            _lease: lease,
        })
    }

    /// Refill an existing capture with the currently pinned roots, reusing
    /// its admitted buffer. Every distinct pinned root occupies a slot, so the
    /// fixed `max_pins` capacity always suffices. A foreground commit admits
    /// its capture before any disk effect and refreshes it here once the
    /// unlocked root publication is durable: readers may have pinned the
    /// then-selected root meanwhile.
    pub(crate) fn recapture(&self, capture: &mut SnapshotRoots) -> Result<(), CoreError> {
        self.inner.check()?;
        if !RetiredArc::ptr_eq(&self.inner, &capture.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture belongs to another owner",
            )));
        }
        let state = self.inner.lock()?;
        capture.roots.clear();
        for slot in state.slots.iter().filter_map(Entry::pinned) {
            if capture.roots.len() == capture.roots.capacity() {
                // Unreachable while slots are bounded by `max_pins`;
                // never grow past the admitted backing.
                drop(state);
                self.inner.failed.store(true, Ordering::Release);
                return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
            }
            capture.roots.push(slot.root);
        }
        capture.epoch = state.epoch;
        drop(state);
        sort_unique(&mut capture.roots);
        self.inner.check()
    }

    #[cfg(test)]
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
            .all(|slot| slot.root == current || capture.contains(&slot.root));
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

    /// Register cohort `nonce` as certifying `root`. Nonce zero is the
    /// unstamped marker, and only one cohort is active at a time.
    pub(crate) fn begin_coverage(&self, nonce: u64, root: DirectoryRoot) -> Result<(), CoreError> {
        self.inner.check()?;
        if nonce == 0 || root.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cohort coverage nonce or root is invalid",
            )));
        }
        let mut state = self.inner.lock()?;
        if state.coverage.is_some() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cohort coverage is already active",
            )));
        }
        state.coverage = Some((nonce, root));
        drop(state);
        self.inner.check()
    }

    /// Move the active cohort's certification to a newly installed root.
    pub(crate) fn advance_coverage(
        &self,
        nonce: u64,
        root: DirectoryRoot,
    ) -> Result<(), CoreError> {
        self.inner.check()?;
        if root.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cohort coverage nonce or root is invalid",
            )));
        }
        let mut state = self.inner.lock()?;
        if state.coverage.map(|(active, _)| active) != Some(nonce) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cohort coverage nonce differs",
            )));
        }
        state.coverage = Some((nonce, root));
        drop(state);
        self.inner.check()
    }

    /// Stop stamping for `nonce`. Ending an inactive cohort is a no-op;
    /// ending another cohort's coverage is refused unchanged.
    pub(crate) fn end_coverage(&self, nonce: u64) -> Result<(), CoreError> {
        let mut state = self.inner.lock()?;
        match state.coverage {
            None => {}
            Some((active, _)) if active == nonce => state.coverage = None,
            Some(_) => {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "cohort coverage nonce differs",
                )));
            }
        }
        drop(state);
        self.inner.check()
    }

    /// Verify, without allocating, that every live pin is at `current`, at a
    /// captured root the cohort walked, or stamped by the still-active
    /// cohort. The caller holds the owner lock that serializes installation,
    /// acquisition and reclamation and has verified the certified chain.
    pub(crate) fn validate_cohort_coverage(
        &self,
        capture: &SnapshotRoots,
        nonce: u64,
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
        let active = nonce != 0 && state.coverage.map(|(active, _)| active) == Some(nonce);
        let covered = active
            && state.slots.iter().filter_map(Entry::pinned).all(|slot| {
                slot.root == current || capture.roots.contains(&slot.root) || slot.coverage == nonce
            });
        drop(state);
        self.inner.check()?;
        if !active {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cohort coverage is not active",
            )));
        }
        if covered {
            Ok(())
        } else {
            Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot capture does not cover active roots",
            )))
        }
    }

    #[cfg(test)]
    pub(crate) fn epoch(&self) -> Result<u64, CoreError> {
        self.inner.check()?;
        let state = self.inner.lock()?;
        let epoch = state.epoch;
        drop(state);
        self.inner.check()?;
        Ok(epoch)
    }

    /// Cheap scheduling observation only, never an unlink proof: whether any
    /// live pin holds a root older than `generation`. Acquisition pins only
    /// the current root, so once no pin is older than a past current root,
    /// none can become so.
    pub(crate) fn pinned_before(&self, generation: u64) -> Result<bool, CoreError> {
        self.inner.check()?;
        let state = self.inner.lock()?;
        let older = state
            .slots
            .iter()
            .filter_map(Entry::pinned)
            .any(|slot| slot.root.generation < generation);
        drop(state);
        self.inner.check()?;
        Ok(older)
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
    #[cfg(test)]
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
    /// Distinct captured roots in `root_order`.
    pub(crate) fn roots(&self) -> &[DirectoryRoot] {
        &self.roots
    }

    /// Membership by binary search over the sorted, deduplicated capture.
    pub(crate) fn contains(&self, root: &DirectoryRoot) -> bool {
        self.roots
            .binary_search_by(|probe| root_order(probe, root))
            .is_ok()
    }

    #[cfg(test)]
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
    pub(crate) fn registry(&self) -> SnapshotPins {
        SnapshotPins {
            inner: self.inner.registry.clone(),
        }
    }
}

impl RegistryInner {
    // Pins are in-memory bookkeeping over roots whose reads verify themselves.
    fn check(&self) -> Result<(), CoreError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        if self.admission.check_owner_live().is_err() {
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
        let mut state = self.registry.state.lock().unwrap_or_else(|poisoned| {
            self.registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        let entry = &mut state.slots[identity.slot];
        match entry.pinned().copied() {
            Some(slot) if slot.token == identity.token && slot.root == identity.root => {
                *entry = Entry::Empty;
                match (
                    state.held.checked_sub(1),
                    state.ordinary.checked_sub(usize::from(self.ordinary)),
                ) {
                    (Some(held), Some(ordinary)) => {
                        state.held = held;
                        state.ordinary = ordinary;
                    }
                    _ => self.registry.failed.store(true, Ordering::Release),
                }
                match state.epoch.checked_add(1) {
                    Some(epoch) => state.epoch = epoch,
                    None => self.registry.failed.store(true, Ordering::Release),
                }
            }
            _ => self.registry.failed.store(true, Ordering::Release),
        }
        // Payload/credit destructors run after unlock.
        drop(state);
    }
}

impl Drop for OrdinaryPinCredits {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock().unwrap_or_else(|poisoned| {
            self.registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        match state.ordinary.checked_sub(self.credits) {
            Some(ordinary) => state.ordinary = ordinary,
            None => self.registry.failed.store(true, Ordering::Release),
        }
        drop(state);
    }
}

impl Drop for SnapshotPinPromise {
    fn drop(&mut self) {
        // A bound promise moved its pin out; its slot belongs to that pin.
        let Some(pin) = self.pin.take() else {
            return;
        };
        let registry = &pin.inner.registry;
        let mut state = registry.state.lock().unwrap_or_else(|poisoned| {
            registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        match (state.slots[self.slot], state.held.checked_sub(1)) {
            (Entry::Promised(token), Some(held)) if token == self.token => {
                state.slots[self.slot] = Entry::Empty;
                state.held = held;
            }
            _ => registry.failed.store(true, Ordering::Release),
        }
        drop(state);
        // The unbound pin has no identity; its backing retires after unlock.
        drop(pin);
    }
}

/// A total order over roots, used only to deduplicate and search captures.
/// Equal under this order exactly when the derived `PartialEq` is equal.
fn root_order(a: &DirectoryRoot, b: &DirectoryRoot) -> std::cmp::Ordering {
    let page = |root: &DirectoryRoot| {
        root.page
            .map(|page| (page.arena_id, page.page_index, page.sha256))
    };
    (a.generation, a.group_id, a.height, a.entries, page(a)).cmp(&(
        b.generation,
        b.group_id,
        b.height,
        b.entries,
        page(b),
    ))
}

/// Sort in place and drop adjacent duplicates; never allocates.
fn sort_unique(roots: &mut Vec<DirectoryRoot>) {
    roots.sort_unstable_by(root_order);
    roots.dedup();
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

    fn capacity_denied<T>(result: &Result<T, CoreError>) -> bool {
        matches!(result, Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    }

    /// Ordinary credits (client-held pins and retention credits) stop at the
    /// registry less its reserve; critical pins still take every other slot.
    #[test]
    fn ordinary_credits_stop_at_the_reserve_while_critical_pins_take_any_slot() {
        let (_, pins) = setup(8);
        pins.set_reserve(3).unwrap();
        let first = pins.acquire_ordinary(root(1)).unwrap();
        let second = pins.acquire_ordinary(root(1)).unwrap();
        let credits = pins.admit_ordinary(3).unwrap();
        let usage = pins.usage().unwrap();
        assert_eq!(
            (usage.held, usage.ordinary, usage.reserve, usage.limit),
            (2, 5, 3, 8)
        );
        // Refused with no effect: no slot and no credit was taken.
        assert!(capacity_denied(&pins.acquire_ordinary(root(1))));
        assert!(capacity_denied(&pins.admit_ordinary(1)));
        assert_eq!(pins.usage().unwrap(), usage);
        // A larger reserve would reach into credits already charged.
        assert!(pins.set_reserve(4).is_err());
        // Critical pins take every free slot, the reserve included.
        let critical = (0..6)
            .map(|_| pins.acquire(root(1)).unwrap())
            .collect::<Vec<_>>();
        assert!(capacity_denied(&pins.acquire(root(1))));
        assert_eq!(pins.usage().unwrap().held, 8);
        drop(critical);
        drop(credits);
        assert_eq!(pins.usage().unwrap().ordinary, 2);
        let third = pins.acquire_ordinary(root(2)).unwrap();
        drop((first, second, third));
        assert_eq!(
            pins.usage().unwrap(),
            SnapshotPinUse {
                held: 0,
                limit: 8,
                reserve: 3,
                ordinary: 0,
            }
        );
        assert!(pins.set_reserve(8).is_err());
        // Without a reserve, credits are counted but never refused; an
        // ordinary pin still needs a free slot.
        pins.set_reserve(0).unwrap();
        let credits = pins.admit_ordinary(9).unwrap();
        assert_eq!(credits.credits, 9);
        let all = (0..8)
            .map(|_| pins.acquire_ordinary(root(1)).unwrap())
            .collect::<Vec<_>>();
        assert!(capacity_denied(&pins.acquire_ordinary(root(1))));
        assert_eq!(pins.usage().unwrap().ordinary, 17);
        drop((all, credits));
        assert_eq!(pins.usage().unwrap().ordinary, 0);
    }

    /// A promise takes its slot and backing before an irreversible step;
    /// binding the then-current root succeeds even with every other slot
    /// held, and an unbound promise returns its slot.
    #[test]
    fn a_promised_slot_binds_after_every_other_slot_is_taken() {
        let (admission, pins) = setup(3);
        let backing = admission.used.load(Ordering::Acquire);
        let promise = pins.promise().unwrap();
        assert!(admission.used.load(Ordering::Acquire) > backing);
        let others = [
            pins.acquire(root(1)).unwrap(),
            pins.acquire(root(1)).unwrap(),
        ];
        assert!(capacity_denied(&pins.acquire(root(2))));
        assert!(capacity_denied(&pins.promise()));
        assert!(
            pins.capture()
                .unwrap()
                .roots()
                .iter()
                .all(|held| *held == root(1))
        );
        let epoch = pins.epoch().unwrap();
        let bound = pins.bind(promise, root(2)).unwrap();
        assert_eq!(pins.validate(&bound).unwrap(), root(2));
        assert!(pins.epoch().unwrap() > epoch);
        assert_eq!(pins.usage().unwrap().held, 3);
        drop(bound);
        drop(others);
        assert_eq!(pins.usage().unwrap().held, 0);
        let unused = pins.promise().unwrap();
        assert_eq!(pins.usage().unwrap().held, 1);
        drop(unused);
        assert_eq!(pins.usage().unwrap().held, 0);
        assert_eq!(admission.used.load(Ordering::Acquire), backing);
        // A promise binds only in its own registry.
        let (_, other) = setup(1);
        let foreign = other.promise().unwrap();
        assert!(pins.bind(foreign, root(1)).is_err());
        assert_eq!(other.usage().unwrap().held, 0);
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

    /// A node database holds one pin per open tenant Generation at distinct
    /// roots. Captures of a full registry are sorted, deduplicated in place
    /// within the original backing, and answer membership by search.
    #[test]
    fn full_registry_captures_sort_and_deduplicate_distinct_roots_in_place() {
        const PINS: usize = 1500;
        let (_, pins) = setup(PINS);
        // Interleave generations so slot order differs from root order, and
        // pin a third of them twice.
        let generations: Vec<u64> = (0..1000u64).map(|i| (i * 7919) % 1000 + 1).collect();
        let mut held = Vec::new();
        for (index, &generation) in generations.iter().enumerate() {
            held.push(pins.acquire(root(generation)).unwrap());
            if index % 2 == 0 && held.len() < PINS {
                held.push(pins.acquire(root(generation)).unwrap());
            }
        }
        assert_eq!(held.len(), PINS);
        assert!(
            matches!(&(pins.acquire(root(5000))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        let mut capture = pins.capture().unwrap();
        let expected: Vec<_> = (1..=1000).map(root).collect();
        assert_eq!(capture.roots(), expected.as_slice());
        assert_eq!(capture.roots.capacity(), PINS);
        assert!(capture.contains(&root(1)) && capture.contains(&root(1000)));
        assert!(!capture.contains(&root(0)) && !capture.contains(&root(1001)));
        let mut foreign = root(500);
        foreign.entries = 1;
        assert!(!capture.contains(&foreign));
        pins.validate_coverage(&capture, root(1000)).unwrap();
        // Release every pin of the odd generations; recapture reuses the
        // admitted buffer and stays sorted and unique.
        held.retain(|pin| pin.root().generation % 2 == 0);
        pins.recapture(&mut capture).unwrap();
        let even: Vec<_> = (1..=500).map(|i| root(i * 2)).collect();
        assert_eq!(capture.roots(), even.as_slice());
        assert_eq!(capture.roots.capacity(), PINS);
        pins.validate_coverage(&capture, root(1001)).unwrap();
        held.push(pins.acquire(root(3)).unwrap());
        assert!(
            matches!(&(pins.validate_coverage(&capture, root(1001))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        drop(held);
        assert!(pins.capture().unwrap().roots().is_empty());
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

    fn stamps(pins: &SnapshotPins) -> Vec<(u64, u64)> {
        let state = pins.inner.state.lock().unwrap();
        let mut stamps: Vec<_> = state
            .slots
            .iter()
            .filter_map(Entry::pinned)
            .map(|slot| (slot.root.generation, slot.coverage))
            .collect();
        stamps.sort_unstable();
        stamps
    }

    #[test]
    fn coverage_nonce_stamps_only_pins_of_the_registered_root() {
        let (_, pins) = setup(8);
        let before = pins.acquire(root(2)).unwrap();
        assert!(
            matches!(&(pins.begin_coverage(0, root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        pins.begin_coverage(9, root(2)).unwrap();
        assert!(
            matches!(&(pins.begin_coverage(10, root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("cohort coverage is already active"))))
        );
        let other = pins.acquire(root(1)).unwrap();
        let stamped = pins.acquire(root(2)).unwrap();
        let restamped = pins.acquire(root(2)).unwrap();
        assert_eq!(stamps(&pins), [(1, 0), (2, 0), (2, 9), (2, 9)]);
        assert!(
            matches!(&(pins.advance_coverage(8, root(3))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("cohort coverage nonce differs"))))
        );
        pins.advance_coverage(9, root(3)).unwrap();
        let later = pins.acquire(root(3)).unwrap();
        let unstamped_old = pins.acquire(root(2)).unwrap();
        assert!(
            matches!(&(pins.end_coverage(8)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        pins.end_coverage(9).unwrap();
        pins.end_coverage(9).unwrap();
        let after = pins.acquire(root(3)).unwrap();
        assert_eq!(
            stamps(&pins),
            [(1, 0), (2, 0), (2, 0), (2, 9), (2, 9), (3, 0), (3, 9)]
        );
        drop((
            before,
            other,
            stamped,
            restamped,
            later,
            unstamped_old,
            after,
        ));
    }

    #[test]
    fn cohort_coverage_accepts_captured_current_and_stamped_and_rejects_unstamped_historical() {
        let (_, pins) = setup(6);
        let captured = pins.acquire(root(1)).unwrap();
        let capture = pins.capture().unwrap();
        assert!(
            matches!(&(pins.validate_cohort_coverage(&capture, 5, root(2))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("cohort coverage is not active"))))
        );
        pins.begin_coverage(5, root(2)).unwrap();
        let stamped = pins.acquire(root(2)).unwrap();
        pins.advance_coverage(5, root(3)).unwrap();
        let current = pins.acquire(root(3)).unwrap();
        pins.validate_cohort_coverage(&capture, 5, root(3)).unwrap();
        // Ordinary coverage does not know the stamp and rejects the
        // intermediate root that the cohort never walked.
        assert!(pins.validate_coverage(&capture, root(3)).is_err());
        // A pin at a historical root it never certified is not covered.
        let unstamped = pins.acquire(root(2)).unwrap();
        assert!(
            matches!(&(pins.validate_cohort_coverage(&capture, 5, root(3))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("snapshot capture does not cover active roots"))))
        );
        drop(unstamped);
        pins.validate_cohort_coverage(&capture, 5, root(3)).unwrap();
        // Another nonce is neither active nor the stamp.
        assert!(pins.validate_cohort_coverage(&capture, 6, root(3)).is_err());
        let (_, foreign) = setup(1);
        assert!(
            matches!(&(foreign.validate_cohort_coverage(&capture, 5, root(3))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("snapshot capture belongs to another owner"))))
        );
        pins.end_coverage(5).unwrap();
        assert!(pins.validate_cohort_coverage(&capture, 5, root(3)).is_err());
        drop((captured, stamped, current));
    }

    #[test]
    fn stamp_survives_clone() {
        let (_, pins) = setup(6);
        let capture = pins.capture().unwrap();
        pins.begin_coverage(3, root(1)).unwrap();
        let stamped = pins.acquire(root(1)).unwrap();
        let clone = stamped.clone();
        pins.advance_coverage(3, root(2)).unwrap();
        drop(stamped);
        pins.validate_cohort_coverage(&capture, 3, root(2)).unwrap();
        let state = pins.inner.state.lock().unwrap();
        assert!(
            state
                .slots
                .iter()
                .filter_map(Entry::pinned)
                .any(|slot| slot.root == root(1) && slot.coverage == 3)
        );
        drop(state);
        drop(clone);
    }

    #[test]
    fn nonce_exhaustion_fails_closed() {
        let (_, pins) = setup(2);
        // Zero is the unstamped marker and can never name a cohort.
        assert!(
            matches!(&(pins.begin_coverage(0, root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput("cohort coverage nonce or root is invalid"))))
        );
        let capture = pins.capture().unwrap();
        assert!(pins.validate_cohort_coverage(&capture, 0, root(1)).is_err());
        // The last nonce is still distinct; nothing wraps to the marker.
        pins.begin_coverage(u64::MAX, root(1)).unwrap();
        let pin = pins.acquire(root(1)).unwrap();
        pins.validate_cohort_coverage(&capture, u64::MAX, root(2))
            .unwrap();
        pins.end_coverage(u64::MAX).unwrap();
        // An ended cohort's stamp no longer covers anything.
        assert!(
            pins.validate_cohort_coverage(&capture, u64::MAX, root(2))
                .is_err()
        );
        drop(pin);
    }

    #[test]
    fn validate_cohort_coverage_allocates_nothing() {
        let (admission, pins) = setup(3);
        let historical = pins.acquire(root(1)).unwrap();
        let capture = pins.capture().unwrap();
        pins.begin_coverage(4, root(2)).unwrap();
        let stamped = pins.acquire(root(2)).unwrap();
        pins.advance_coverage(4, root(3)).unwrap();
        let current = pins.acquire(root(3)).unwrap();
        let reserves = admission.reserves.load(Ordering::Acquire);
        let used = admission.used.load(Ordering::Acquire);
        let counter = allocation_tests::AllocationCount::start();
        for _ in 0..100 {
            pins.validate_cohort_coverage(&capture, 4, root(3)).unwrap();
        }
        assert_eq!(counter.count(), 0);
        drop(counter);
        assert_eq!(admission.reserves.load(Ordering::Acquire), reserves);
        assert_eq!(admission.used.load(Ordering::Acquire), used);
        drop((historical, stamped, current));
    }

    #[test]
    fn pinned_before_sees_pins_until_their_last_clone_drops() {
        let (_, pins) = setup(4);
        assert!(!pins.pinned_before(u64::MAX).unwrap());
        let ordinary = pins.acquire(root(3)).unwrap();
        assert!(pins.pinned_before(4).unwrap());
        assert!(!pins.pinned_before(3).unwrap());
        let older = pins.acquire(root(1)).unwrap();
        let clone = older.clone();
        assert!(pins.pinned_before(2).unwrap());
        assert!(!pins.pinned_before(1).unwrap());
        drop(older);
        // The clone shares the slot; its root stays pinned.
        assert!(pins.pinned_before(2).unwrap());
        drop(clone);
        assert!(!pins.pinned_before(3).unwrap());
        drop(ordinary);
        assert!(!pins.pinned_before(u64::MAX).unwrap());
    }
}
