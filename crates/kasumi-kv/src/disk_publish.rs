//! Reconcile only identities touched by a foreground mutation before refill.
//!
//! The mutation records the identities it supersedes outside the cache, in a
//! fixed record admitted with the capture and proof workspace before the
//! commit's first disk effect (`SupersededIdentities` bounds it by the
//! batch's operations and the selected tree's height). The cache stays fully
//! usable meanwhile: the commit's root publication runs without the Core
//! state lock, and readers keep loading through the cache. Only once that
//! publication is durable, back under the state lock, does the commit
//! recapture pins, begin the candidate scope, mark the record and drain it.
//! The state lock then excludes new pins, mutations and physical reclamation
//! until the scope is drained. Concurrent pin drops are safe: captures
//! conservatively retain their old reachable identities for this pass.

use super::auto_warming::{DeferredIdentity, DeferredWitness};
use super::warming::{CachedIdentityProofWorkspace, CachedReach};
use super::*;
use crate::page_cache::SupersededIdentities;
use crate::snapshot_pins::SnapshotRoots;

#[cfg(test)]
thread_local! {
    /// Deferred identities this thread's publications proved again.
    pub(super) static DEFERRED_PROOFS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) struct PublicationCache {
    cache: NativeSharedCache,
    capture: SnapshotRoots,
    pub(super) proof: CachedIdentityProofWorkspace,
    /// Written only by the commit's own mutation; locked for its `Sync` view.
    pub(super) superseded: Mutex<SupersededIdentities>,
    _superseded_charge: NativeResidentLease,
    active: bool,
}

#[cfg(test)]
impl PublicationCache {
    pub(super) fn replace_capture_for_test(&mut self, capture: SnapshotRoots) {
        self.capture = capture;
    }
}

impl Drop for PublicationCache {
    fn drop(&mut self) {
        if self.active {
            // Cleanup is required even after capacity rollback or unwinding.
            // It does not serve bytes or retire any cached identity. A poisoned
            // lock already fences the owning state and cannot be reused.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if let Ok(mut cache) = self.cache.lock() {
                    let _ = cache.cleanup_publication_candidates();
                }
            }));
        }
    }
}

impl DiskState {
    /// Admit everything a publication of `operations` operations needs, before
    /// any disk effect: the pin capture, the proof workspace and the fixed
    /// superseded-identity record. Nothing here touches cache membership; the
    /// candidate scope begins only in `begin_cache_publication`.
    pub(super) fn prepare_cache_publication(
        &self,
        operations: usize,
    ) -> Result<Option<PublicationCache>, CoreError> {
        self.owner.check()?;
        if self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .config()
            .byte_limit
            == 0
        {
            return Ok(None);
        }
        let capture = self.pins.capture()?;
        let proof = CachedIdentityProofWorkspace::new(&self.owner.admission)?;
        let pages = operations
            .checked_mul(usize::from(self.selected.height))
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let bytes = SupersededIdentities::backing_bytes(pages, operations)
            .and_then(|bytes| {
                bytes.checked_add(
                    crate::native_sync::mutex_backing_bytes()
                        + 2 * ALLOCATION_ALLOWANCE
                        + LEASE_ALLOWANCE,
                )
            })
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let charge = self
            .owner
            .admission
            .reserve_workspace(bytes as u64)
            .map(NativeResidentLease::new)?;
        let superseded = crate::native_sync::mutex(
            SupersededIdentities::with_capacity(pages, operations)?,
            &charge,
        );
        Ok(Some(PublicationCache {
            cache: self.cache.clone(),
            capture,
            proof,
            superseded,
            _superseded_charge: charge,
            active: false,
        }))
    }

    /// Recapture pins, begin the candidate scope and mark every recorded
    /// identity still resident. Call under the same state lock as the
    /// installation that follows: readers may have pinned the then-selected
    /// root, and loaded recorded identities, while the root was published.
    pub(super) fn begin_cache_publication(
        &self,
        publication: &mut PublicationCache,
    ) -> Result<(), CoreError> {
        self.owner.check()?;
        self.pins.recapture(&mut publication.capture)?;
        let superseded = publication
            .superseded
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        // The record is bounded by construction; an overflow would leave the
        // unrecorded identities cached but unreachable, never served.
        debug_assert!(!superseded.overflowed(), "superseded identity bound");
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        cache.begin_publication_candidates()?;
        publication.active = true;
        for identity in superseded.identities(self.owner.group_id) {
            cache.mark_publication_candidate(identity)?;
        }
        Ok(())
    }

    pub(super) fn reconcile_publication(
        &mut self,
        publication: &mut PublicationCache,
    ) -> Result<(), CoreError> {
        // Identities earlier publications kept only for an older pin.
        let deferred = self.auto_warm.deferred.len();
        loop {
            let candidate = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .pop_publication_candidate()?;
            let Some(candidate) = candidate else { break };
            match self.cached_identity_reach(
                &candidate,
                &publication.capture,
                &mut publication.proof,
            )? {
                CachedReach::Selected => {}
                // The engine still pins the root this publication replaced
                // until it installs the new one. Reconsider it once released.
                CachedReach::Pinned(root) => {
                    self.auto_warm.deferred.push(DeferredIdentity {
                        key: candidate.key,
                        incarnation: candidate.incarnation,
                        witness: Some(DeferredWitness {
                            root,
                            superseded: self.selected.generation,
                        }),
                    });
                }
                CachedReach::Unreachable => {
                    self.pins
                        .validate_coverage(&publication.capture, self.selected)?;
                    if !self
                        .cache
                        .lock()
                        .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                        .remove_if_unchanged(&candidate)?
                    {
                        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                            "publication candidate changed under owner lock",
                        )));
                    }
                }
            }
            // Returning cache capacity requires dropping the proof's payload
            // Arc as well; external readers continue to carry their own charge.
            drop(candidate);
        }
        self.cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .clear_publication_candidates()?;
        publication.active = false;
        self.prune_deferred(deferred, publication)?;
        self.cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .trim_metadata()?;
        self.owner.check()
    }

    /// Reconcile the first `count` deferred identities. An unchanged payload
    /// stays while its witnessed root is captured. Once that root is released,
    /// only pins older than the generation that superseded it can reach it;
    /// with no such pins, removal needs no reads. A missing witness or changed
    /// incarnation requires a full proof before either shortcut can be reused.
    /// Identities this publication deferred follow them unchanged.
    fn prune_deferred(
        &mut self,
        count: usize,
        publication: &mut PublicationCache,
    ) -> Result<(), CoreError> {
        self.owner.check()?;
        publication.proof.check_owner(&self.owner.admission)?;
        // Establish the capture's physical owner even on the all-witness-hit
        // path. The enclosing Core lock excludes publication, new pins and GC;
        // a concurrent pin drop can only defer optional cleanup one more time.
        self.pins
            .validate_coverage(&publication.capture, self.selected)?;
        let mut kept = 0;
        for index in 0..count {
            let identity = self.auto_warm.deferred.get(index);
            let candidate = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .candidate(identity.key)?;
            // An evicted, pruned or reclaimed identity needs nothing more.
            let Some(candidate) = candidate else { continue };
            let witness = identity.witness.filter(|witness| {
                identity.incarnation != 0
                    && identity.incarnation == candidate.incarnation
                    && witness.root != self.selected
            });
            let (reach, superseded) = if let Some(witness) = witness {
                if publication.capture.roots().contains(&witness.root) {
                    self.auto_warm.deferred.set(kept, identity);
                    kept += 1;
                    continue;
                }
                let reach = if publication
                    .capture
                    .roots()
                    .iter()
                    .any(|root| root.generation < witness.superseded)
                {
                    #[cfg(test)]
                    DEFERRED_PROOFS.with(|proofs| proofs.set(proofs.get() + 1));
                    self.cached_identity_reach_before(
                        &candidate,
                        witness.superseded,
                        &publication.capture,
                        &mut publication.proof,
                    )
                } else {
                    Ok(CachedReach::Unreachable)
                };
                (reach, witness.superseded)
            } else {
                #[cfg(test)]
                DEFERRED_PROOFS.with(|proofs| proofs.set(proofs.get() + 1));
                (
                    self.cached_identity_reach(
                        &candidate,
                        &publication.capture,
                        &mut publication.proof,
                    ),
                    self.selected.generation,
                )
            };
            let reach = match reach {
                Ok(reach) => reach,
                // Optional cleanup never fails a durable publication: keep
                // the identity for a later proof.
                Err(error) if error.is_capacity_denied() => {
                    self.auto_warm.deferred.set(
                        kept,
                        DeferredIdentity {
                            key: candidate.key,
                            incarnation: candidate.incarnation,
                            witness: None,
                        },
                    );
                    kept += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match reach {
                CachedReach::Selected => {}
                CachedReach::Pinned(root) => {
                    self.auto_warm.deferred.set(
                        kept,
                        DeferredIdentity {
                            key: candidate.key,
                            incarnation: candidate.incarnation,
                            witness: Some(DeferredWitness { root, superseded }),
                        },
                    );
                    kept += 1;
                }
                CachedReach::Unreachable => {
                    self.pins
                        .validate_coverage(&publication.capture, self.selected)?;
                    // No root reaches it, so no reader can load it again: a
                    // mismatch only means it already left the cache.
                    self.cache
                        .lock()
                        .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                        .remove_if_unchanged(&candidate)?;
                }
            }
            drop(candidate);
        }
        self.auto_warm.deferred.remove(kept..count);
        self.owner.check()
    }
}
