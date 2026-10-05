//! Bounded resident-identity reconciliation followed by policy-neutral refill.
//!
//! Captures do not pin files. Before every serialized step, the current root
//! and unique pinned-root set are recaptured and compared. A changed set resets
//! the continuation before any old root can be read. The owner lock excludes
//! publication, new-pin acquisition and physical GC during each step; concurrent
//! pin drops cannot unlink files. Ordinary readers of the current root do not
//! change the root union and therefore do not prevent finite completion.

use super::*;
use crate::cache::{CacheCandidate, CacheCursor};
use crate::directory::{DirectoryPageRef, DirectoryReadWorkspace};
use crate::snapshot_pins::SnapshotRoots;

/// Fixed proof scratch that a publisher can admit before preparing records.
/// Both page proofs and value-location proofs reuse the same directory buffer.
/// Its exposed directory workspace also serves preflight and final warming.
pub(super) struct CachedIdentityProofWorkspace {
    locator: [u8; segment::CACHED_VALUE_LOCATOR_BYTES],
    admission: Arc<dyn StorageAdmission>,
    // Last: its constructor lease covers this enclosing shell and must outlive
    // every proof field as well as the page buffer it owns.
    pub(super) directory: DirectoryReadWorkspace,
}

impl CachedIdentityProofWorkspace {
    pub(super) fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        let directory = DirectoryReadWorkspace::for_enclosing_owner::<Self>(admission)?;
        Ok(Self {
            locator: [0; segment::CACHED_VALUE_LOCATOR_BYTES],
            admission: admission.clone(),
            directory,
        })
    }
}

#[derive(Default)]
pub(super) struct Warmup {
    root: Option<DirectoryRoot>,
    capture: Option<SnapshotRoots>,
    cursor: CacheCursor,
    pruned: bool,
    root_index: usize,
    after: Option<DirectoryRecord>,
    all_retained: bool,
    evictions: u64,
    complete: bool,
    pub(super) last_work: usize,
}

#[derive(Default)]
pub(super) struct WarmProgress {
    pub(super) work: usize,
    pub(super) pruned: usize,
    pub(super) restarts: usize,
    pub(super) complete: bool,
    pub(super) fully_resident: bool,
    pub(super) provider_limited: bool,
}

impl DiskState {
    /// Work counts examined cache slots, directory successors and phase/root
    /// transitions. A proof is bounded by the cache payload and configured pin
    /// count times maximum tree height; it is not a byte or latency ceiling.
    pub(crate) fn warm(&mut self, work_limit: usize) -> Result<CacheWarmup, CoreError> {
        self.run(|state| {
            state.begin_manual_warm()?;
            let progress = state.warm_inner(work_limit, true)?;
            state.record_auto_warm(&progress)?;
            Ok(CacheWarmup {
                work: progress.work,
                complete: progress.complete,
                fully_resident: progress.fully_resident,
            })
        })
    }

    pub(super) fn warm_inner(
        &mut self,
        work_limit: usize,
        restart_complete: bool,
    ) -> Result<WarmProgress, CoreError> {
        let mut progress = WarmProgress::default();
        // Both manual and automatic drivers enter here. Take the real output
        // pin high water before this step creates temporary proof/capture owners.
        let result = self
            .observe_warm_step_pins()
            .and_then(|()| self.warm_step(work_limit, restart_complete, &mut progress));
        // Ordinary pressure preserves the exact refused item. Every next step
        // still recaptures/compares roots before using a retained continuation.
        // Non-capacity failures must discard any possibly advanced cursor.
        if matches!(&(result), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        {
            self.warmup.last_work = progress.work;
        } else if result.is_err() {
            self.warmup = Warmup::default();
        }
        result?;
        Ok(progress)
    }

    /// Read-only fixture checkpoint for deterministic lifecycle interleavings.
    /// It never changes the actual cursor, retention result or admission state.
    #[cfg(test)]
    pub(super) fn warm_refill_checkpoint(&self) -> (bool, bool) {
        let skipped = self.warmup.pruned && !self.warmup.all_retained;
        let completing = self.warmup.pruned
            && !self.warmup.complete
            && self
                .warmup
                .capture
                .as_ref()
                .is_some_and(|capture| self.warmup.root_index > capture.roots().len());
        (skipped, completing)
    }

    fn warm_step(
        &mut self,
        work_limit: usize,
        restart_complete: bool,
        progress: &mut WarmProgress,
    ) -> Result<(), CoreError> {
        if work_limit == 0 {
            return Ok(());
        }
        let capture = self.pins.capture()?;
        let root = self.selected;
        let same_roots = self.warmup.capture.as_ref().is_some_and(|old| {
            let count = |capture: &SnapshotRoots| {
                capture.roots().iter().filter(|&&pin| pin != root).count()
            };
            count(old) == count(&capture)
                && old
                    .roots()
                    .iter()
                    .all(|pin| *pin == root || capture.roots().contains(pin))
        });
        if self.warmup.root != Some(root)
            || !same_roots
            || (restart_complete && self.warmup.complete)
        {
            self.warmup = Warmup {
                root: Some(root),
                capture: Some(capture),
                all_retained: true,
                evictions: self.cache_stats()?.evictions,
                ..Warmup::default()
            };
        } else {
            // The new capture keeps epoch/coverage diagnostics current without
            // changing the stable iteration order of the original capture.
            drop(capture);
        }
        while progress.work < work_limit && !self.warmup.complete {
            // A prior prune item may have removed the last lookup owner while
            // an external output remains. Its candidate/proof guards are now
            // gone. Sample before any later no-eviction refill decision, so a
            // concurrent output drop after refusal cannot erase the evidence.
            self.observe_warm_step_pins()?;
            if !self.warmup.pruned {
                let cursor = self.warmup.cursor;
                let step = self
                    .cache
                    .lock()
                    .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                    .candidate_step(&mut self.warmup.cursor, work_limit - progress.work)?;
                progress.work += step.work;
                progress.restarts += usize::from(step.restarted);
                if let Some(candidate) = step.candidate {
                    let live = match self.cached_identity_is_live(&candidate) {
                        Ok(live) => live,
                        Err(error) if error.is_capacity_denied() => {
                            self.warmup.cursor = cursor;
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    };
                    if !live {
                        self.pins.validate_coverage(
                            self.warmup
                                .capture
                                .as_ref()
                                .expect("initialized root capture"),
                            self.selected,
                        )?;
                        if self
                            .cache
                            .lock()
                            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                            .remove_candidate(&mut self.warmup.cursor, &candidate)?
                        {
                            progress.pruned += 1;
                        }
                    }
                }
                if step.complete {
                    // Count a retry of the exhausted cursor as one bounded
                    // item. Refusal leaves this phase/cursor intact, so excess
                    // backing cannot turn a fitting union into a parked miss.
                    if step.work == 0 {
                        progress.work += 1;
                    }
                    self.cache
                        .lock()
                        .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                        .trim_metadata_for_warm()?;
                    self.warmup.pruned = true;
                    self.warmup.evictions = self.cache_stats()?.evictions;
                }
                continue;
            }
            let next_root = if self.warmup.root_index == 0 {
                Some(root)
            } else {
                self.warmup
                    .capture
                    .as_ref()
                    .expect("initialized root capture")
                    .roots()
                    .get(self.warmup.root_index - 1)
                    .copied()
            };
            let Some(next_root) = next_root else {
                progress.work += 1;
                self.warmup.complete = true;
                break;
            };
            if self.warmup.root_index != 0 && next_root == root {
                self.warmup.root_index += 1;
                progress.work += 1;
                continue;
            }
            let (lower, exclusive) = self
                .warmup
                .after
                .as_ref()
                .map_or((DirectoryKey::table("\0"), false), |record| {
                    (record.key(), true)
                });
            let denied = AtomicBool::new(false);
            let warming = self.pages.refill_view(&denied);
            // The owner lock excludes other maintenance callers. Clear
            // earlier observations and retain exact per-item refusal evidence.
            self.take_warm_provider_refusal()?;
            progress.work += 1;
            let record = DirectoryReader::new(&warming, self.owner.admission.clone())
                .next(next_root, lower, exclusive)?;
            if self.take_warm_provider_refusal()? {
                progress.provider_limited = true;
                break;
            }
            self.warmup.all_retained &= !denied.load(Ordering::Acquire);
            let Some(record) = record else {
                self.warmup.root_index += 1;
                self.warmup.after = None;
                continue;
            };
            if let DirectoryValue::Row { value, batch_seq } = record.value {
                let retained = self.retain_warm_value(value, batch_seq, record.key())?;
                if self.take_warm_provider_refusal()? {
                    progress.provider_limited = true;
                    break;
                }
                self.warmup.all_retained &= retained;
                #[cfg(test)]
                if !retained {
                    refusal_release_fixture::retire_output();
                }
            }
            self.warmup.after = Some(record);
        }
        self.owner.check()?;
        progress.complete = self.warmup.complete;
        progress.fully_resident = progress.complete
            && self.warmup.all_retained
            && self.cache_stats()?.evictions == self.warmup.evictions;
        Ok(())
    }

    fn take_warm_provider_refusal(&self) -> Result<bool, CoreError> {
        Ok(self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .take_maintenance_provider_refusal())
    }

    fn cached_identity_is_live(
        &self,
        candidate: &CacheCandidate<NativeIdentity>,
    ) -> Result<bool, CoreError> {
        let capture = self.warmup.capture.as_ref().expect("initialized capture");
        let mut workspace = CachedIdentityProofWorkspace::new(&self.owner.admission)?;
        self.cached_identity_is_live_with(candidate, capture, &mut workspace)
    }

    /// Prove candidate membership under the selected root and captured pins
    /// without reserving or allocating proof workspace. This is not removal
    /// authority: the caller validates capture coverage while holding the
    /// publication/GC owner lock before conditionally removing the candidate.
    pub(super) fn cached_identity_is_live_with(
        &self,
        candidate: &CacheCandidate<NativeIdentity>,
        capture: &SnapshotRoots,
        workspace: &mut CachedIdentityProofWorkspace,
    ) -> Result<bool, CoreError> {
        if !Arc::ptr_eq(&workspace.admission, &self.owner.admission) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cache proof workspace belongs to another admission owner",
            )));
        }
        self.owner.check()?;
        let roots = std::iter::once(self.selected).chain(
            capture
                .roots()
                .iter()
                .copied()
                .filter(|&root| root != self.selected),
        );
        let private = self.pages.maintenance_private_view();
        let reader = DirectoryReader::new(&private, self.owner.admission.clone());
        match candidate.key {
            NativeIdentity::Page {
                group_id,
                arena_id,
                page_index,
                sha256,
            } => {
                if group_id != self.owner.group_id {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "cached page belongs to another group",
                    )));
                }
                let reference = DirectoryPageRef {
                    arena_id,
                    page_index,
                    sha256,
                };
                for root in roots {
                    if reader.contains_page_with_workspace(
                        root,
                        reference,
                        candidate.bytes.as_bytes(),
                        &mut workspace.directory,
                    )? {
                        return Ok(true);
                    }
                }
            }
            NativeIdentity::Value {
                group_id,
                segment_id,
                offset,
                len,
                crc,
                table_len,
                key_len,
            } => {
                if group_id != self.owner.group_id {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "cached value belongs to another group",
                    )));
                }
                let location = ValueLocation {
                    segment_id,
                    offset,
                    len,
                    crc,
                };
                let logical = segment::inspect_cached_value_identity(
                    self.owner.backend.as_ref(),
                    &group_id,
                    location,
                    table_len,
                    key_len,
                    candidate.bytes.as_bytes(),
                    &mut workspace.locator,
                )?;
                self.owner.check()?;
                for root in roots {
                    if let Some(DirectoryValue::Row { value, batch_seq }) = reader
                        .get_with_workspace(
                            root,
                            DirectoryKey::row(logical.table, logical.key),
                            &mut workspace.directory,
                        )?
                        && value == location
                    {
                        if batch_seq != logical.logical_batch_seq {
                            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                                "cached value logical version differs",
                            )));
                        }
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn retain_warm_value(
        &self,
        location: ValueLocation,
        batch_seq: u64,
        key: DirectoryKey<'_>,
    ) -> Result<bool, CoreError> {
        let identity = NativeIdentity::value(
            self.owner.group_id,
            location,
            key.table,
            key.row
                .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "warm value has no row key",
                )))?,
        )?;
        if let Some(value) = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .peek(identity)
        {
            if value.as_bytes().len() != location.len as usize
                || crc32c(value.as_bytes()) != location.crc
            {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "cached warm value identity differs",
                )));
            }
            self.owner.check()?;
            return Ok(true);
        }
        // Physical compaction can leave several addresses for one immutable
        // logical version. Cold refill must share its payload just as hot
        // relocation does; otherwise a fitting old/current union can become
        // artificially twice as large after restart or a cache clear.
        let private = self.pages.maintenance_private_view();
        let reader = DirectoryReader::new(&private, self.owner.admission.clone());
        let roots = std::iter::once(self.selected).chain(
            self.warmup
                .capture
                .as_ref()
                .expect("initialized capture")
                .roots()
                .iter()
                .copied()
                .filter(|&root| root != self.selected),
        );
        for root in roots {
            if let Some(DirectoryValue::Row {
                value: peer,
                batch_seq: peer_seq,
            }) = reader.get(root, key)?
                && peer_seq == batch_seq
                && peer != location
            {
                if peer.len != location.len || peer.crc != location.crc {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "relocated logical payload differs",
                    )));
                }
                let peer = NativeIdentity::value(
                    self.owner.group_id,
                    peer,
                    key.table,
                    key.row.expect("validated row key"),
                )?;
                match self
                    .cache
                    .lock()
                    .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                    .alias_if_fits(peer, identity)
                {
                    Ok(true) => {
                        self.owner.check()?;
                        return Ok(true);
                    }
                    Ok(false) => {}
                    Err(crate::AdmissionError::CapacityDenied) => return Ok(false),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let result = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .load_if_fits(identity, location.len as usize, |out| {
                self.owner.check()?;
                self.owner.backend.read(
                    GroupFile::segment(location.segment_id),
                    location.offset,
                    out,
                )?;
                self.owner.check()?;
                if crc32c(out) != location.crc {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "warm value checksum differs",
                    )));
                }
                Ok(())
            });
        self.owner.check()?;
        match result {
            Ok(Some(value)) => {
                if value.as_bytes().len() != location.len as usize
                    || crc32c(value.as_bytes()) != location.crc
                {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "cached warm value identity differs",
                    )));
                }
                Ok(true)
            }
            Ok(None) | Err(CacheLoadError::Admission(crate::AdmissionError::CapacityDenied)) => {
                Ok(false)
            }
            Err(CacheLoadError::Admission(error)) => Err(error.into()),
            Err(CacheLoadError::Load(error)) => Err(error),
        }
    }
}

// The deterministic fixture changes only the destructor timing of a real
// external output after an actual local refusal. It cannot alter warm state.
#[cfg(test)]
pub(super) mod refusal_release_fixture {
    use crate::CachedBytes;
    use std::cell::RefCell;

    thread_local! {
        static OUTPUT: RefCell<Option<CachedBytes>> = const { RefCell::new(None) };
    }

    pub(in crate::disk_state) struct Release;
    impl Release {
        pub(in crate::disk_state) fn arm(output: CachedBytes) -> Self {
            OUTPUT.with_borrow_mut(|slot| {
                assert!(slot.is_none());
                *slot = Some(output);
            });
            Self
        }
        pub(in crate::disk_state) fn released(&self) -> bool {
            OUTPUT.with_borrow(Option::is_none)
        }
    }
    impl Drop for Release {
        fn drop(&mut self) {
            OUTPUT.with_borrow_mut(|slot| drop(slot.take()));
        }
    }
    pub(super) fn retire_output() {
        OUTPUT.with_borrow_mut(|slot| drop(slot.take()));
    }
}
