//! Nonselection reader custody reuses the installed SourceRoots inventory.
//! No reader here can publish latest, carry a canonical position or become a
//! SelectedApplication. All native callbacks execute outside gate/state locks.
use super::*;

pub(crate) struct SourceReader {
    roots: SourceRootsRef,
    cell: CellRef,
    released: bool,
    covered: bool,
    frozen: bool,
}
impl SourceRoots {
    pub(crate) fn primary_installation(&self) -> (&Arc<TenantStorageSet>, &Arc<NodeAdmission>) {
        (&self.stores, &self.admission)
    }
    /// Source cells prepared so far, and those still registered. Every
    /// document reader takes one of its own.
    #[cfg(test)]
    pub(crate) fn reader_cells_for_test(&self) -> (u64, usize) {
        let gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        (gate.next, gate.cells.len())
    }
}
impl SelectedApplication {
    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        self.cell.ptr_eq(&other.cell)
    }

    fn with_record_reader<T>(
        &self,
        roots: &SourceRootsRef,
        shared: Option<&crate::document_store::SelectedRead>,
        read: impl FnOnce(&SourceReader) -> Result<T>,
    ) -> Result<T> {
        if let Some(shared) = shared {
            return shared.with_directory_reader(self, |reader| match reader {
                DocumentReader::Fork(reader) => read(reader),
                DocumentReader::Borrowed { .. } => self.with_fresh_record_reader(roots, read),
            });
        }
        self.with_fresh_record_reader(roots, read)
    }

    fn with_fresh_record_reader<T>(
        &self,
        roots: &SourceRootsRef,
        read: impl FnOnce(&SourceReader) -> Result<T>,
    ) -> Result<T> {
        let reader = self.open_selected_reader(roots)?;
        let result = read(&reader);
        let close = reader.close();
        match (result, close) {
            (Err(error), Err(close)) => Err(error.context(close)),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Ok(result), Ok(())) => Ok(result),
        }
    }

    /// An ordinary selected entry can carry the previous snapshot while its
    /// log advances. Only an exact, unfrozen logical position may lend the
    /// snapshot's document directory to a serving read.
    pub(crate) fn has_exact_snapshot(&self, base: u64, revision: u64) -> bool {
        self.cell.frozen.get() == Some(&false)
            && self.cell.position.get().is_some_and(|position| {
                !position.is_covered_reconstruction()
                    && position.snapshot().is_some_and(|snapshot| {
                        base.checked_add(snapshot.meta.last_log_id.map_or(0, |log| log.index))
                            == Some(revision)
                    })
            })
    }

    #[cfg(test)]
    pub(crate) fn snapshot_point(
        &self,
        state: &kasumi_types::TenantState,
        collection: &str,
        id: &str,
        admit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<crate::application_records::PrimaryPoint>> {
        self.with_snapshot_records(None, state, |tree, _, _| {
            crate::application_records::snapshot_point(tree, collection, id, state.revision, admit)
        })
    }

    /// Lend a verified application directory only at its exact selected revision.
    /// A deployed snapshot without a manifest must use its original reader.
    pub(crate) fn with_snapshot_records<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        read: impl FnOnce(
            &kasumi_store::ordered_pages::TreeReader<'_>,
            &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
            u32,
        ) -> Result<T>,
    ) -> Result<Option<T>> {
        ensure!(
            self.has_exact_snapshot(state.revision_base, state.revision),
            "record read requires the exact selected snapshot"
        );
        self.with_base_snapshot_records(shared, state, |tree, memory, layout, _| {
            read(tree, memory, layout)
        })
    }

    /// A serving entry may retain its authenticated predecessor snapshot.
    /// Callers using an older directory must explicitly reconcile the prefix
    /// it owns with the selected log tail.
    pub(crate) fn with_base_snapshot_records<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        read: impl FnOnce(
            &kasumi_store::ordered_pages::TreeReader<'_>,
            &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
            u32,
            u64,
        ) -> Result<T>,
    ) -> Result<Option<T>> {
        use kasumi_raft::SelectedAppliedRef;
        use kasumi_store::{application_manifest::ApplicationManifest, ordered_pages::TreeReader};
        let Some(position) =
            self.cell.position.get().filter(|p| {
                self.cell.frozen.get() == Some(&false) && !p.is_covered_reconstruction()
            })
        else {
            return Ok(None);
        };
        let applied = position.applied();
        let log_id = match applied {
            Some(SelectedAppliedRef::Entry { log_id, .. }) => Some(log_id),
            Some(SelectedAppliedRef::Snapshot { meta, .. }) => meta.last_log_id,
            None => None,
        };
        ensure!(
            state
                .revision_base
                .checked_add(log_id.map_or(0, |log| log.index))
                == Some(state.revision),
            "applied directory position differs"
        );
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("selected record installation absent")?;
        self.with_record_reader(&roots, shared, |reader| {
            reader.check_access()?;
            let permit = SourceReader::loan(&reader.roots, &reader.cell, false, false)?;
            let view = permit.view.as_ref().expect("loaned primary view");
            let Some(manifest) = ApplicationManifest::load_from_pair(view)? else {
                return Ok(None);
            };
            let read_snapshot = |snapshot: kasumi_raft::SelectedSnapshotRef<'_>| {
                let snapshot_id = snapshot.meta.last_log_id;
                ensure!(
                    snapshot_id <= log_id
                        && snapshot_id
                            .map(|id| id.index)
                            .cmp(&log_id.map(|id| id.index))
                            == snapshot_id.cmp(&log_id),
                    "snapshot follows or contradicts applied position"
                );
                if let Some(SelectedAppliedRef::Entry { membership, .. }) = applied
                    && snapshot_id == log_id
                {
                    ensure!(
                        snapshot.meta.last_membership == *membership,
                        "snapshot membership differs at applied position"
                    );
                }
                let snapshot_revision = state
                    .revision_base
                    .checked_add(snapshot_id.map_or(0, |id| id.index))
                    .context("snapshot revision overflow")?;
                ensure!(
                    manifest.snapshot_sha256
                        == crate::application_checkpoint::snapshot_identity(
                            snapshot.meta,
                            snapshot.backend_sha256
                        )?
                        && manifest.tenant == state.tenant
                        && manifest.incarnation == state.incarnation
                        && manifest.revision_base == state.revision_base
                        && manifest.revision == snapshot_revision
                        && (snapshot_revision < state.revision
                            || (manifest.document_count == state.document_count
                                && manifest.logical_bytes == state.logical_bytes)),
                    "selected record snapshot identity differs"
                );
                let tree =
                    TreeReader::new(view.as_ref(), &manifest.page_space, manifest.records, None)?;
                let memory = kasumi_store::ordered_pages::PageSource::memory(view.as_ref());
                read(&tree, &memory, manifest.layout_epoch, snapshot_revision)
            };
            if let Some(snapshot) = position.snapshot() {
                return read_snapshot(snapshot).map(Some);
            }
            let workspace = Workspace {
                core: roots.admission.memory().clone(),
                baseline: 0,
                planned_peak: None,
                reservation: roots.admission.reserve_application_source(0)?,
            };
            kasumi_raft::with_published_snapshot_at(view, &roots.limits, workspace, read_snapshot)?
                .context("application directory lacks its selected Raft snapshot")
                .map(Some)
        })
    }

    /// Read primary descriptors and headers from the tree owned by this revision.
    pub(crate) fn with_serving_primary<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        read: impl FnOnce(
            &kasumi_store::ordered_pages::TreeReader<'_>,
            &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
            u32,
        ) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.has_exact_snapshot(state.revision_base, state.revision) {
            return self.with_snapshot_records(shared, state, read);
        }
        self.with_primary_records(shared, state, |tree, memory| {
            read(
                tree,
                memory,
                kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT,
            )
        })
    }

    /// Lend the ordinary primary directory this selection pinned, only when it
    /// is current at exactly this generation's revision. Older generations keep
    /// their own native root, so each reads the rows of its own revision even
    /// after later edits deleted the pages it uses. `None` when the pinned root
    /// holds no current directory at this revision (deployed stores before
    /// their first restore, a stale directory, covered reconstruction).
    pub(crate) fn with_primary_records<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        read: impl FnOnce(
            &kasumi_store::ordered_pages::TreeReader<'_>,
            &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
        ) -> Result<T>,
    ) -> Result<Option<T>> {
        use kasumi_raft::SelectedAppliedRef;
        use kasumi_store::{ordered_pages::TreeReader, primary_manifest::PrimaryManifest};
        let Some(position) =
            self.cell.position.get().filter(|p| {
                self.cell.frozen.get() == Some(&false) && !p.is_covered_reconstruction()
            })
        else {
            return Ok(None);
        };
        let index = match position.applied() {
            Some(SelectedAppliedRef::Entry { log_id, .. }) => log_id.index,
            Some(SelectedAppliedRef::Snapshot { meta, .. }) => {
                meta.last_log_id.map_or(0, |id| id.index)
            }
            None => 0,
        };
        ensure!(
            state.revision_base.checked_add(index) == Some(state.revision),
            "applied directory position differs"
        );
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("selected record installation absent")?;
        self.with_record_reader(&roots, shared, |reader| {
            reader.check_access()?;
            let permit = SourceReader::loan(&reader.roots, &reader.cell, false, false)?;
            let view = permit.view.as_ref().expect("loaned primary view");
            let Some(manifest) = PrimaryManifest::load_from_pair(view)? else {
                return Ok(None);
            };
            if !manifest.is_current()
                || manifest.revision != state.revision
                || !self.matches_primary_boundary(&manifest)?
            {
                return Ok(None);
            }
            ensure!(
                manifest.incarnation == state.incarnation
                    && manifest.revision_base == state.revision_base
                    && manifest.document_count == state.document_count
                    && manifest.logical_bytes == state.logical_bytes,
                "selected primary directory differs from its generation"
            );
            let tree =
                TreeReader::new(view.as_ref(), &manifest.page_space, manifest.records, None)?;
            let memory = kasumi_store::ordered_pages::PageSource::memory(view.as_ref());
            read(&tree, &memory).map(Some)
        })
    }

    /// One document's live or archived record from the pinned primary
    /// directory at this exact revision. A miss there is authoritative.
    pub(crate) fn primary_point(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        collection: &str,
        id: &str,
        admit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<crate::application_records::PrimaryPoint>> {
        self.with_serving_primary(shared, state, |tree, _, _| {
            crate::application_records::snapshot_point(tree, collection, id, state.revision, admit)
        })
    }

    /// Lend the text directory this selection pinned, only when it is current
    /// at exactly this generation's revision. Older generations keep their own
    /// native root, so each searches the shards of its own revision even after
    /// later edits or a rebuild deleted them from the current tree. `None`
    /// when the pinned root holds no current directory at this revision.
    pub(crate) fn with_text_records<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        read: impl FnOnce(
            &kasumi_store::ordered_pages::TreeReader<'_>,
            &dyn kasumi_store::ordered_pages::PageSource,
            &kasumi_store::text_manifest::TextManifest,
            &Arc<crate::admission::NodeAdmission>,
        ) -> Result<T>,
    ) -> Result<Option<T>> {
        use kasumi_store::{ordered_pages::TreeReader, text_manifest::TextManifest};
        let Some(boundary) = self.text_boundary()? else {
            return Ok(None);
        };
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("selected text installation absent")?;
        self.with_record_reader(&roots, shared, |reader| {
            reader.check_access()?;
            let permit = SourceReader::loan(&reader.roots, &reader.cell, false, false)?;
            let view = permit.view.as_ref().expect("loaned text view");
            let Some(manifest) = TextManifest::load_from_pair(view)? else {
                return Ok(None);
            };
            if !manifest.is_current()
                || !manifest.matches(&boundary)
                || manifest.revision != state.revision
                || manifest.incarnation != state.incarnation
                || manifest.revision_base != state.revision_base
            {
                return Ok(None);
            }
            let tree =
                TreeReader::new(view.as_ref(), &manifest.page_space, manifest.records, None)?;
            read(&tree, view.as_ref(), &manifest, &reader.roots.admission).map(Some)
        })
    }

    /// Validate the immutable owner pairing without opening a reader or
    /// reserving another source cell during generation publication.
    pub(crate) fn require_document_roots(&self, roots: &SourceRootsRef) -> Result<()> {
        let installed = self
            .cell
            .roots
            .upgrade()
            .context("selected document source absent")?;
        ensure!(
            SourceRootsRef::ptr_eq(&installed, roots),
            "selected document source installation differs"
        );
        Ok(())
    }

    /// Immutable body objects have independent content identities. A frozen
    /// selection can lend those exact objects for closure/snapshot work without
    /// claiming that covered primary pages are a current serving generation.
    /// This capability cannot read arbitrary application or custody namespaces.
    pub(crate) fn open_document_reader(&self, roots: &SourceRootsRef) -> Result<DocumentReader> {
        self.require_document_roots(roots)?;
        // Ordinary reads can still be refused by native admission after their
        // outer workspace was granted. Keep that failure on an exact child
        // reader; it must never poison the generation's own registered view.
        // Committed apply already owns its exact native and document capacity.
        if crate::admission::ApplyEscrow::current_for(roots.admission.memory()).is_none() {
            return self.open_selected_reader(roots).map(DocumentReader::Fork);
        }
        let frozen = *self
            .cell
            .frozen
            .get()
            .context("selected document frozen state absent")?;
        let covered = self
            .cell
            .position
            .get()
            .context("selected document source proof absent")?
            .is_covered_reconstruction();
        let reader = DocumentReader::Borrowed {
            selected: self.clone(),
            roots: roots.clone(),
            covered,
            frozen,
        };
        reader.check_access()?;
        Ok(reader)
    }

    fn open_selected_reader(&self, roots: &SourceRootsRef) -> Result<SourceReader> {
        let installed = self
            .cell
            .roots
            .upgrade()
            .context("selected source registry absent")?;
        ensure!(
            SourceRootsRef::ptr_eq(&installed, roots),
            "selected source installation differs"
        );
        let frozen = *self
            .cell
            .frozen
            .get()
            .context("selected source frozen state absent")?;
        let covered = self
            .cell
            .position
            .get()
            .context("selected source proof absent")?
            .is_covered_reconstruction();
        let preparation = roots.prepare_kind(false)?;
        let permit = SourceReader::loan(roots, &self.cell, covered, frozen)?;
        let reader = SourceReader::acquire(preparation, covered, frozen, || {
            permit.view.as_ref().expect("inflight native view").fork()
        });
        drop(permit);
        reader
    }
}
impl SelectedApplication {
    /// Lend the ordinary structured directory this selection pinned, only
    /// when it is current at exactly this generation's revision and was
    /// written under this generation's index layout. Older generations keep
    /// their own native root, so each reads the postings of its own revision
    /// even after later edits deleted the pages it uses. `None` when the
    /// pinned root holds no current directory at this revision: deployed
    /// stores before their first restore, a stale directory, covered replay
    /// below the directory, a frozen selection or a covered reconstruction.
    pub(crate) fn with_structured_records<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        layout_sha256: impl FnOnce() -> [u8; 32],
        read: impl FnOnce(&kasumi_store::ordered_pages::TreeReader<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        self.with_structured_records_since(shared, state, layout_sha256, 1, read)
    }

    /// Both layouts use identical canonical compound points. Only the ordinary
    /// tree also contains ordinary-field postings.
    pub(crate) fn with_ordered_tuples<'n, T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        layout: impl FnOnce() -> [u8; 32],
        collections: impl ExactSizeIterator<Item = &'n str>,
        mut read: impl FnMut(&kasumi_store::ordered_pages::TreeReader<'_>, bool) -> Result<T>,
    ) -> Result<Option<T>> {
        if let Some(result) = self.with_structured_records_since(
            shared,
            state,
            layout,
            kasumi_store::structured_manifest::ORDERED_TUPLE_FORMAT,
            |tree| read(tree, true),
        )? {
            return Ok(Some(result));
        }
        self.with_checkpoint_ordered_tuples(shared, state, collections, |tree| read(tree, false))
    }

    pub(super) fn with_checkpoint_ordered_tuples<'n, T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        collections: impl ExactSizeIterator<Item = &'n str>,
        read: impl FnOnce(&kasumi_store::ordered_pages::TreeReader<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        self.with_checkpoint_tuples_since(
            shared,
            state,
            collections,
            kasumi_store::application_manifest::ORDERED_TUPLE_LAYOUT,
            read,
        )
    }

    pub(crate) fn with_checkpoint_tuples_since<'n, T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        collections: impl ExactSizeIterator<Item = &'n str>,
        minimum: u32,
        read: impl FnOnce(&kasumi_store::ordered_pages::TreeReader<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.serving_revision(state.revision_base) != Some(state.revision) {
            return Ok(None);
        }
        let exact = self.has_exact_snapshot(state.revision_base, state.revision);
        self.with_base_snapshot_records(shared, state, |tree, memory, layout, revision| {
            if layout < minimum {
                return Ok(None);
            }
            if !exact {
                if revision >= state.revision || !(1..=32).contains(&collections.len()) {
                    return Ok(None);
                }
                for name in collections {
                    if !crate::application_records::checkpoint_collection_matches(
                        tree, memory, state, name, revision,
                    )? {
                        return Ok(None);
                    }
                }
            }
            read(tree).map(Some)
        })
        .map(Option::flatten)
    }

    fn serving_revision(&self, base: u64) -> Option<u64> {
        use kasumi_raft::SelectedAppliedRef;
        let position =
            self.cell.position.get().filter(|p| {
                self.cell.frozen.get() == Some(&false) && !p.is_covered_reconstruction()
            })?;
        let index = match position.applied() {
            Some(SelectedAppliedRef::Entry { log_id, .. }) => log_id.index,
            Some(SelectedAppliedRef::Snapshot { meta, .. }) => {
                meta.last_log_id.map_or(0, |id| id.index)
            }
            None => 0,
        };
        base.checked_add(index)
    }

    pub(crate) fn with_structured_records_since<T>(
        &self,
        shared: Option<&crate::document_store::SelectedRead>,
        state: &kasumi_types::TenantState,
        layout_sha256: impl FnOnce() -> [u8; 32],
        minimum_format: u32,
        read: impl FnOnce(&kasumi_store::ordered_pages::TreeReader<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        use kasumi_store::{ordered_pages::TreeReader, structured_manifest::StructuredManifest};
        if self.serving_revision(state.revision_base) != Some(state.revision) {
            // The selection belongs to another applied position than this
            // state: its directory says nothing about these indexes.
            return Ok(None);
        }
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("selected record installation absent")?;
        self.with_record_reader(&roots, shared, |reader| {
            reader.check_access()?;
            let permit = SourceReader::loan(&reader.roots, &reader.cell, false, false)?;
            let view = permit.view.as_ref().expect("loaned structured view");
            let Some(manifest) = StructuredManifest::load_from_pair(view)? else {
                return Ok(None);
            };
            if manifest.format < minimum_format
                || !manifest.is_current()
                || manifest.revision != state.revision
                || !self.matches_structured_boundary(&manifest)?
            {
                return Ok(None);
            }
            ensure!(
                manifest.incarnation == state.incarnation
                    && manifest.revision_base == state.revision_base
                    && manifest.layout_sha256 == layout_sha256(),
                "selected structured directory differs from its generation"
            );
            let tree =
                TreeReader::new(view.as_ref(), &manifest.page_space, manifest.records, None)?;
            read(&tree).map(Some)
        })
    }
}

impl SourceReader {
    fn acquire(
        preparation: RootPreparation,
        covered: bool,
        frozen: bool,
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
                !covered || !gate.serving || frozen,
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
        if gate.consumers_closed || gate.preparations_closed || (covered && gate.serving && !frozen)
        {
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
            frozen,
        })
    }
    fn loan(
        roots: &SourceRootsRef,
        cell: &CellRef,
        covered: bool,
        frozen: bool,
    ) -> Result<ForkPermit> {
        let gate = roots.gate.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !gate.consumers_closed && !gate.preparations_closed,
            "primary reader sealed"
        );
        ensure!(
            !covered || !gate.serving || frozen,
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
    /// The caller's actual grant funds the bounded plaintext until its visitor
    /// returns. Returning an owned decoded payload needs its own explicit quote.
    pub(crate) fn with_record<T>(
        &mut self,
        workspace: &mut impl crate::admission::RetainedWorkspace,
        baseline: u64,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            matches!(
                namespace,
                crate::document_store::BODIES | crate::document_store::BLOBS
            ),
            "document reader namespace is outside immutable bodies"
        );
        let permit = Self::loan(&self.roots, &self.cell, self.covered, self.frozen)?;
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
        // Keep the unique handle counted until this consuming close has claimed
        // retirement. Otherwise a concurrent preparation's retirement sweep can
        // take the zero-handle cell and make this close observe its in-progress
        // native close as an incomplete read.
        self.roots.retire(&self.cell, true);
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
            #[cfg(test)]
            close_test_hook::after_release();
            self.roots.retire(&self.cell, false);
        }
    }
}

impl Drop for SourceReader {
    fn drop(&mut self) {
        self.release();
    }
}

impl SourceReader {
    /// Recheck access through the exact loaned storage pair even when a lookup
    /// needs no I/O (empty tree), or has finished decoding before lending.
    /// Tenant policy/authorization remains the calling service's responsibility.
    pub(crate) fn check_access(&self) -> Result<()> {
        let permit = Self::loan(&self.roots, &self.cell, self.covered, self.frozen)?;
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

/// Ordinary reads own a disposable exact child, so transient refusals cannot
/// poison the selected generation. Committed apply borrows its pre-admitted
/// parent without allocating a new source cell or registered reader.
pub(crate) enum DocumentReader {
    Fork(SourceReader),
    Borrowed {
        selected: SelectedApplication,
        roots: SourceRootsRef,
        covered: bool,
        frozen: bool,
    },
}
impl DocumentReader {
    pub(crate) fn check_access(&self) -> Result<()> {
        let Self::Borrowed {
            selected,
            roots,
            covered,
            frozen,
        } = self
        else {
            let Self::Fork(reader) = self else {
                unreachable!()
            };
            return reader.check_access();
        };
        let permit = SourceReader::loan(roots, &selected.cell, *covered, *frozen)?;
        let view = permit.view.as_ref().expect("inflight document source");
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            roots.admission.memory().clone();
        view.require_memory(&memory)?;
        view.require_domains(roots.stores.application(), roots.stores.custody().store())?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| roots.stores.check_access()))
            .unwrap_or_else(|payload| {
                Err(SourcePanic {
                    _payload: Mutex::new(payload),
                }
                .into())
            })
    }
    pub(crate) fn with_record<T>(
        &mut self,
        workspace: &mut impl crate::admission::RetainedWorkspace,
        baseline: u64,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            matches!(
                namespace,
                crate::document_store::BODIES | crate::document_store::BLOBS
            ),
            "document reader namespace is outside immutable bodies"
        );
        let Self::Borrowed {
            selected,
            roots,
            covered,
            frozen,
        } = self
        else {
            let Self::Fork(reader) = self else {
                unreachable!()
            };
            return reader.with_record(workspace, baseline, namespace, key, max, lend);
        };
        let permit = SourceReader::loan(roots, &selected.cell, *covered, *frozen)?;
        let view = permit.view.as_ref().expect("inflight document source");
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            roots.admission.memory().clone();
        view.require_memory(&memory)?;
        workspace.ensure_peak(
            baseline
                .checked_add(view.application_get_workspace_bytes(
                    namespace.len(),
                    key.len(),
                    max,
                )?)
                .context("document read quote overflow")?,
        )?;
        let bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.application_get(namespace, key, max)
        }))
        .unwrap_or_else(|payload| {
            Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into())
        })?;
        let outcome = lend(bytes.as_deref());
        drop(bytes);
        drop(permit);
        if outcome.is_ok() {
            workspace.retain(baseline);
        }
        outcome
    }
    pub(crate) fn close(self) -> Result<()> {
        match self {
            Self::Fork(reader) => {
                // Decryption and JSON reconstruction may outlive a key lease.
                // Recheck before lending the decoded owner, then always settle
                // the child and preserve both original failures if needed.
                let access = reader.check_access();
                match (access, reader.close()) {
                    (Ok(()), result) | (result, Ok(())) => result,
                    (Err(original), Err(retirement)) => Err(original.context(retirement)),
                }
            }
            borrowed => borrowed.check_access(),
        }
    }
}

#[cfg(test)]
pub(super) mod close_test_hook {
    use std::cell::RefCell;

    thread_local! {
        static RELEASE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static CLOSE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(crate) fn on_release(hook: impl FnOnce() + 'static) {
        RELEASE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn on_close(hook: impl FnOnce() + 'static) {
        CLOSE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_release() {
        if let Some(hook) = RELEASE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    pub(crate) fn before_native_close() {
        if let Some(hook) = CLOSE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }
}
