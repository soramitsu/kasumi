//! Reconcile only identities touched by a foreground mutation before refill.
//!
//! Marks borrow cache slots and never allocate an operations-times-height
//! queue. The enclosing Core lock excludes new pins, mutations and physical
//! reclamation until this scope is drained. Concurrent pin drops are safe:
//! captures conservatively retain their old reachable identities for this pass.

use super::auto_warming::DeferredIdentity;
use super::warming::{CachedIdentityProofWorkspace, CachedReach};
use super::*;
use crate::snapshot_pins::SnapshotRoots;

pub(super) struct PublicationCache {
    cache: NativeSharedCache,
    capture: SnapshotRoots,
    pub(super) proof: CachedIdentityProofWorkspace,
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
                // until it installs the new one. Prove it again later.
                CachedReach::Pinned(root) => {
                    self.auto_warm.deferred.push(DeferredIdentity {
                        key: candidate.key,
                        incarnation: candidate.incarnation,
                        root: Some(root),
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

    /// Reconcile the first `count` deferred identities under this
    /// publication's capture: remove those no root reaches any more, keep
    /// those an older pin still reaches, and forget the rest. Identities this
    /// publication deferred follow them unchanged.
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
            if identity.incarnation != 0
                && identity.incarnation == candidate.incarnation
                && identity.root.is_some_and(|root| {
                    root != self.selected && publication.capture.roots().contains(&root)
                })
            {
                // This exact immutable payload was proved under this exact
                // root. Keep only; read verification and removal authority
                // remain unchanged. No payload or pin is retained by the hint.
                self.auto_warm.deferred.set(kept, identity);
                kept += 1;
                continue;
            }
            let reach = match self.cached_identity_reach(
                &candidate,
                &publication.capture,
                &mut publication.proof,
            ) {
                Ok(reach) => reach,
                // Optional cleanup never fails a durable publication: keep
                // the identity for a later proof.
                Err(error) if error.is_capacity_denied() => {
                    self.auto_warm.deferred.set(
                        kept,
                        DeferredIdentity {
                            key: candidate.key,
                            incarnation: candidate.incarnation,
                            root: None,
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
                            root: Some(root),
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
