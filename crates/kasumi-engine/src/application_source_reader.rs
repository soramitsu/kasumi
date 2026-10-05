//! Nonselection reader custody reuses the installed SourceRoots inventory.
//! No reader here can publish latest, carry a canonical position or become a
//! SelectedApplication. All native callbacks execute outside gate/state locks.
use super::*;

pub(crate) struct SourceReader {
    roots: SourceRootsRef,
    cell: CellRef,
    released: bool,
    covered: bool,
}
impl SourceRoots {
    pub(crate) fn primary_installation(&self) -> (&Arc<TenantStorageSet>, &Arc<NodeAdmission>) {
        (&self.stores, &self.admission)
    }
}
impl SourceRootsRef {
    pub(crate) fn open_primary_current(&self) -> Result<SourceReader> {
        let preparation = self.prepare_kind(false)?;
        SourceReader::acquire(preparation, false, || self.stores.read_view())
    }
}
impl SelectedApplication {
    pub(crate) fn open_primary_reader(&self, roots: &SourceRootsRef) -> Result<SourceReader> {
        let installed = self
            .cell
            .roots
            .upgrade()
            .context("selected source registry absent")?;
        ensure!(
            SourceRootsRef::ptr_eq(&installed, roots),
            "selected source installation differs"
        );
        ensure!(
            self.cell.frozen.get() == Some(&false),
            "frozen source cannot lend primary objects"
        );
        let covered = self
            .cell
            .position
            .get()
            .context("selected source proof absent")?
            .is_covered_reconstruction();
        let preparation = roots.prepare_kind(false)?;
        let permit = SourceReader::loan(roots, &self.cell, covered)?;
        let reader = SourceReader::acquire(preparation, covered, || {
            permit.view.as_ref().expect("inflight native view").fork()
        });
        drop(permit);
        reader
    }
}
impl SourceReader {
    fn acquire(
        preparation: RootPreparation,
        covered: bool,
        acquire: impl FnOnce() -> Result<TenantStorageReadView>,
    ) -> Result<Self> {
        let mut preparation = preparation;
        {
            let gate = preparation
                .roots
                .gate
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            ensure!(
                !gate.consumers_closed && !gate.preparations_closed,
                "primary reader acquisition sealed"
            );
            ensure!(
                !covered || !gate.serving,
                "covered source cannot lend primary objects after serving"
            );
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(acquire))
            .unwrap_or_else(|payload| {
                Err(SourcePanic {
                    _payload: Mutex::new(payload),
                }
                .into())
            });
        match outcome {
            Ok(view) => {
                preparation
                    .cell
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .view = Some(ViewRef::new(view, preparation.cell._reservation.clone()))
            }
            Err(error) => preparation.cell.record_failure(error, false),
        }
        let gate = preparation
            .roots
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if gate.consumers_closed || gate.preparations_closed || (covered && gate.serving) {
            preparation
                .cell
                .record_failure(anyhow::anyhow!("primary reader acquisition sealed"), false);
        }
        let failed = preparation.cell.failure.get().is_some();
        {
            let mut state = preparation
                .cell
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !failed {
                preparation.cell.handles.store(1, Ordering::Release);
            }
            state.preparing = false;
            preparation.settled = true;
        }
        drop(gate);
        if failed {
            preparation.roots.retire(&preparation.cell, true);
            return Err(preparation.cell.error());
        }
        Ok(Self {
            roots: preparation.roots.clone(),
            cell: preparation.cell.clone(),
            released: false,
            covered,
        })
    }
    fn loan(roots: &SourceRootsRef, cell: &CellRef, covered: bool) -> Result<ForkPermit> {
        let gate = roots.gate.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !gate.consumers_closed && !gate.preparations_closed,
            "primary reader sealed"
        );
        ensure!(
            !covered || !gate.serving,
            "covered source cannot lend primary objects after serving"
        );
        let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !state.preparing && !state.closed && !state.closing,
            "primary native reader unavailable"
        );
        ensure!(
            cell.failure.get().is_none(),
            "primary native reader previously failed"
        );
        let view = state
            .view
            .as_ref()
            .context("primary native reader absent")?
            .clone();
        state.inflight = state
            .inflight
            .checked_add(1)
            .context("primary inflight read overflow")?;
        drop(state);
        drop(gate);
        Ok(ForkPermit {
            roots: roots.clone(),
            parent: cell.clone(),
            view: Some(view),
        })
    }
    /// Closed test-only custody point read. No arbitrary custody namespace or
    /// decoded applied owner escapes this actual paired read/grant corridor.
    #[cfg(test)]
    pub(crate) fn primary_applied_cursor_fingerprint(
        &mut self,
        workspace: &mut Reservation,
        baseline: u64,
    ) -> Result<(usize, [u8; 32])> {
        use sha2::{Digest, Sha256};
        let (namespace, key, maximum) = kasumi_raft::primary_applied_cursor_read_spec_for_test();
        let permit = Self::loan(&self.roots, &self.cell, self.covered)?;
        let view = permit.view.as_ref().expect("inflight native view");
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            self.roots.admission.memory().clone();
        view.require_memory(&memory)?;
        view.require_domains(
            self.roots.stores.application(),
            self.roots.stores.custody().store(),
        )?;
        workspace.ensure_peak(
            baseline
                .checked_add(view.custody_get_workspace_bytes(
                    namespace.len(),
                    key.len(),
                    maximum,
                )?)
                .context("primary custody point quote overflow")?,
        )?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.custody_get(namespace, key, maximum)
        }))
        .unwrap_or_else(|payload| {
            Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into())
        });
        let result = match outcome {
            Ok(bytes) => {
                let result = bytes
                    .as_deref()
                    .context("primary applied cursor absent")
                    .map(|bytes| (bytes.len(), Sha256::digest(bytes).into()));
                drop(bytes);
                result
            }
            Err(error) => {
                self.cell.record_failure(error, false);
                Err(self.cell.error())
            }
        };
        drop(permit);
        if result.is_ok() {
            workspace.retain(baseline);
        }
        result
    }
    /// The caller's actual grant funds the bounded plaintext until its visitor
    /// returns. Returning an owned decoded payload needs its own explicit quote.
    pub(crate) fn with_record<T>(
        &mut self,
        workspace: &mut Reservation,
        baseline: u64,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        let permit = Self::loan(&self.roots, &self.cell, self.covered)?;
        let view = permit.view.as_ref().expect("inflight native view");
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            self.roots.admission.memory().clone();
        view.require_memory(&memory)?;
        workspace.ensure_peak(
            baseline
                .checked_add(view.application_get_workspace_bytes(
                    namespace.len(),
                    key.len(),
                    max,
                )?)
                .context("primary read quote overflow")?,
        )?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.application_get(namespace, key, max)
        }))
        .unwrap_or_else(|payload| {
            Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into())
        });
        let result = match outcome {
            Ok(bytes) => {
                let result = lend(bytes.as_deref());
                drop(bytes);
                result
            }
            Err(error) => {
                self.cell.record_failure(error, false);
                Err(self.cell.error())
            }
        };
        drop(permit);
        if result.is_ok() {
            workspace.retain(baseline);
        }
        result
    }
    pub(crate) fn close(mut self) -> Result<()> {
        self.release();
        if self.cell.capture_failed()
            || self.cell.close_failure.get().is_some()
            || self.cell.alias_failure.get().is_some()
        {
            return Err(self.cell.error());
        }
        ensure!(
            self.cell
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .closed,
            "primary reader close incomplete"
        );
        Ok(())
    }
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            let previous = self.cell.handles.fetch_sub(1, Ordering::AcqRel);
            assert_eq!(previous, 1, "noncloneable primary reader handle");
            self.roots.retire(&self.cell, false);
        }
    }
}
impl Drop for SourceReader {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
impl SelectedApplication {
    /// Existing-key publication only advances the exact selected Entry.
    /// This checks retained identity, never refreshes or manufactures a source.
    pub(crate) fn require_next_primary_entry(
        &self,
        next: &kasumi_raft::AppliedEntryContext,
        revision_base: u64,
    ) -> Result<()> {
        self.primary_read_proof(revision_base)?;
        let position = self
            .cell
            .position
            .get()
            .context("selected primary proof absent")?;
        let Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) = position.applied() else {
            anyhow::bail!("primary publication prior is not an exact Entry");
        };
        ensure!(
            log_id.index.checked_add(1) == Some(next.log_id.index) && next.previous == Some(log_id),
            "primary publication is not the next exact Entry"
        );
        Ok(())
    }
    /// This primitive accepts only an exact producer/custody pin. Covered replay
    /// needs the future selected primary producer token and remains unavailable.
    pub(crate) fn primary_read_proof(
        &self,
        revision_base: u64,
    ) -> Result<(
        [u8; 32],
        crate::primary_tree::records::boundary::Fingerprint,
        u64,
    )> {
        use crate::primary_tree::records::boundary;
        let position = self
            .cell
            .position
            .get()
            .context("selected primary proof absent")?;
        ensure!(
            !position.is_covered_reconstruction(),
            "covered primary source has no exact producer binding"
        );
        let index = match position.applied() {
            None => 0,
            Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) => log_id.index,
            Some(kasumi_raft::SelectedAppliedRef::Snapshot { meta, .. }) => {
                meta.last_log_id.map_or(0, |id| id.index)
            }
        };
        let revision = revision_base
            .checked_add(index)
            .context("selected primary revision overflow")?;
        let bootstrap = boundary::raw_digest(&position.bootstrap().digest)
            .map_err(|e| anyhow::anyhow!("primary bootstrap digest invalid: {e:?}"))?;
        let fingerprint = boundary::selected(position.applied(), &position.bootstrap().digest)
            .map_err(|e| anyhow::anyhow!("primary producer invalid: {e:?}"))?;
        Ok((bootstrap, fingerprint, revision))
    }
}

#[cfg(test)]
impl SourceReader {
    /// Recheck access through the exact loaned storage pair even when a lookup
    /// needs no I/O (empty tree), or has finished decoding before lending.
    /// Tenant policy/authorization remains the calling service's responsibility.
    pub(crate) fn check_access(&mut self) -> Result<()> {
        let permit = Self::loan(&self.roots, &self.cell, self.covered)?;
        let view = permit.view.as_ref().expect("inflight native view");
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            self.roots.admission.memory().clone();
        view.require_memory(&memory)?;
        view.require_domains(
            self.roots.stores.application(),
            self.roots.stores.custody().store(),
        )?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.roots.stores.check_access()
        }))
        .unwrap_or_else(|payload| {
            Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into())
        });
        let result = match outcome {
            Ok(()) => Ok(()),
            Err(original) => {
                self.cell.record_failure(original, false);
                Err(self.cell.error())
            }
        };
        drop(permit);
        result
    }
}
