//! Reconcile only identities touched by a foreground mutation before refill.
//!
//! Marks borrow cache slots and never allocate an operations-times-height
//! queue. The enclosing Core lock excludes new pins, mutations and physical
//! reclamation until this scope is drained. Concurrent pin drops are safe:
//! captures conservatively retain their old reachable identities for this pass.

use super::warming::{CachedIdentityProofWorkspace, CachedReach};
use super::*;
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
    active: bool,
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
    pub(super) fn prepare_cache_publication(&self) -> Result<Option<PublicationCache>, CoreError> {
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
        self.cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .begin_publication_candidates()?;
        Ok(Some(PublicationCache {
            cache: self.cache.clone(),
            capture,
            proof,
            active: true,
        }))
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
                // until it installs the new one. Prove it again once released.
                CachedReach::Pinned(root) => {
                    self.auto_warm.deferred.push(candidate.key, root);
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

    /// Prove the first `count` deferred identities again under this
    /// publication's capture, but only those whose recorded root it no longer
    /// holds: a captured root is immutable, so it still reaches the others and
    /// their proof would repeat the same digest-checked walk on every commit.
    /// Remove those no root reaches any more, keep those an older pin still
    /// reaches, and forget the rest. Identities this publication deferred
    /// follow them unchanged.
    fn prune_deferred(
        &mut self,
        count: usize,
        publication: &mut PublicationCache,
    ) -> Result<(), CoreError> {
        let mut kept = 0;
        for index in 0..count {
            let (identity, pinned) = self.auto_warm.deferred.get(index);
            let candidate = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .candidate(identity)?;
            // An evicted, pruned or reclaimed identity needs nothing more.
            let Some(candidate) = candidate else { continue };
            let reach = if publication.capture.roots().contains(&pinned) {
                CachedReach::Pinned(pinned)
            } else {
                #[cfg(test)]
                DEFERRED_PROOFS.with(|proofs| proofs.set(proofs.get() + 1));
                match self.cached_identity_reach(
                    &candidate,
                    &publication.capture,
                    &mut publication.proof,
                ) {
                    Ok(reach) => reach,
                    // Optional cleanup never fails a durable publication:
                    // keep the identity for a later proof.
                    Err(error) if error.is_capacity_denied() => CachedReach::Pinned(pinned),
                    Err(error) => return Err(error),
                }
            };
            match reach {
                CachedReach::Selected => {}
                CachedReach::Pinned(root) => {
                    self.auto_warm.deferred.set(kept, identity, root);
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
        Ok(())
    }
}
