//! Reconcile only identities touched by a foreground mutation before refill.
//!
//! Marks borrow cache slots and never allocate an operations-times-height
//! queue. The enclosing Core lock excludes new pins, mutations and physical
//! reclamation until this scope is drained. Concurrent pin drops are safe:
//! captures conservatively retain their old reachable identities for this pass.

use super::warming::CachedIdentityProofWorkspace;
use super::*;
use crate::snapshot_pins::SnapshotRoots;

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
        &self,
        publication: &mut PublicationCache,
    ) -> Result<(), CoreError> {
        loop {
            let candidate = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .pop_publication_candidate()?;
            let Some(candidate) = candidate else { break };
            if !self.cached_identity_is_live_with(
                &candidate,
                &publication.capture,
                &mut publication.proof,
            )? {
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
            // Returning cache capacity requires dropping the proof's payload
            // Arc as well; external readers continue to carry their own charge.
            drop(candidate);
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        cache.clear_publication_candidates()?;
        publication.active = false;
        cache.trim_metadata()?;
        self.owner.check()
    }
}
