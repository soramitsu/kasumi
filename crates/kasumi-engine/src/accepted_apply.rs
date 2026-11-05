//! Semantic custody of the actual accepted apply result. This is not a primary
//! serving capability or candidate-body/index memory admission. These owners
//! replace existing stack locals; the producer's exact ID map moves once and
//! stays alive through durable publication, source capture and the visible swap.
use super::*;

pub(super) type ChangedIds = BTreeMap<String, BTreeSet<String>>;

pub(super) struct ApplyOwner<'engine> {
    engine: &'engine TenantEngine,
    previous: Arc<Generation>,
    // This inline slot receives the same original input/budget alias BEFORE
    // the known tree factory allocates. It is unset for early/idempotent exits.
    _mutation_change_tree: std::sync::OnceLock<kasumi_raft::MutationChangeTreeRetention>,
    input_position: Option<kasumi_raft::LogId<u64>>,
    // Exact input plus optional known change-tree recipe only. Generation,
    // reducer/body clones, indexes and response remain the separate M03 model.
    _input_retention: Option<kasumi_raft::AdmittedApplicationInput>,
    // Last: the exact previous owner retires while the apply mutex is held.
    _guard: std::sync::MutexGuard<'engine, ()>,
}

impl<'engine> ApplyOwner<'engine> {
    pub(super) fn lock(
        engine: &'engine TenantEngine,
        poisoned: impl FnOnce() -> anyhow::Error,
    ) -> anyhow::Result<Self> {
        let guard = engine.apply_lock.lock().map_err(|_| poisoned())?;
        let previous = engine.current_generation()?;
        Ok(Self {
            engine,
            previous,
            _mutation_change_tree: std::sync::OnceLock::new(),
            input_position: None,
            _input_retention: None,
            _guard: guard,
        })
    }

    pub(super) fn lock_validation(engine: &'engine TenantEngine) -> Result<Self> {
        let guard = engine
            .apply_lock
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant apply lock poisoned"))?;
        let previous = engine.current_generation()?;
        Ok(Self {
            engine,
            previous,
            _mutation_change_tree: std::sync::OnceLock::new(),
            input_position: None,
            _input_retention: None,
            _guard: guard,
        })
    }

    pub(super) fn retain_input(
        &mut self,
        input: Option<kasumi_raft::AdmittedApplicationInput>,
        position: kasumi_raft::LogId<u64>,
    ) {
        self.input_position = input.as_ref().map(|_| position);
        self._input_retention = input;
    }
    /// Only the actual mutation producer calls this, immediately before its
    /// first tree/String allocation. Early rejections and receipt replay never
    /// mint a tree claim. The same ApplyOwner encloses the returned raw private
    /// map and its accepted PrimaryDelta through publication and visible swap.
    pub(super) fn begin_mutation_change_tree(&self, batch: &MutationBatch) -> anyhow::Result<()> {
        let Some(input) = &self._input_retention else {
            // Existing transport/reopen/fixture producers have no prepaid input
            // bank yet. This branch supplies no new allowance or certificate.
            return Ok(());
        };
        anyhow::ensure!(
            self._mutation_change_tree.get().is_none(),
            "mutation change-tree producer repeated"
        );
        let position = self
            .input_position
            .expect("retained input has its checked position");
        let Some(retention) = input
            .claim_mutation_change_tree(position, batch)
            .map_err(|error| anyhow::anyhow!("mutation change-tree binding differs: {error:?}"))?
        else {
            // Replay carries its actual point-input fee, with NO change-tree
            // allowance. Its existing semantic producer remains explicitly open;
            // no recipe/retention is minted and no second grant is requested.
            return Ok(());
        };
        self._mutation_change_tree
            .set(retention)
            .map_err(|_| anyhow::anyhow!("mutation change-tree producer repeated"))
    }
    pub(super) fn engine(&self) -> &TenantEngine {
        self.engine
    }

    pub(super) fn require_engine(&self, engine: &TenantEngine) -> anyhow::Result<()> {
        anyhow::ensure!(
            std::ptr::eq(self.engine, engine),
            "apply owner belongs to another engine"
        );
        Ok(())
    }

    // No clonable Arc or selected-source handle escapes through this borrow.
    pub(super) fn current(&self) -> &Generation {
        &self.previous
    }

    /// Genesis membership is log index zero, the same logical revision as
    /// bootstrap. Replaying that exact boundary must still replace a covered
    /// bootstrap source with its authenticated entry source. This constructor
    /// copies the current state itself; callers cannot submit a same-revision
    /// mutation through the ordinary accepted-generation boundary.
    pub(super) fn accept_initial_metadata(
        self,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> anyhow::Result<AcceptedGeneration<'engine>> {
        let previous = self.current();
        anyhow::ensure!(
            position.log_id.index == 0
                && position.previous.is_none()
                && previous.state.revision == self.engine.revision_base
                && self
                    .engine
                    .current
                    .load()
                    .as_ref()
                    .is_some_and(|current| { Arc::ptr_eq(current, &self.previous) }),
            "initial metadata does not match the current bootstrap generation"
        );
        let candidate = Arc::new(Generation {
            state: previous.state.clone(),
            receipts: previous.receipts.clone(),
            backup_bindings: previous.backup_bindings.clone(),
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            indexes: previous.indexes.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            application_selection: std::sync::OnceLock::new(),
            staged_documents: previous.staged_documents.clone(),
            document_sources: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        });
        Ok(AcceptedGeneration {
            candidate,
            delta: PrimaryDelta {
                changed: ChangedIds::new(),
            },
            receipt_publication: None,
            owner: self,
        })
    }

    pub(super) fn accept(
        self,
        candidate: Arc<Generation>,
        changed: ChangedIds,
    ) -> anyhow::Result<AcceptedGeneration<'engine>> {
        let old = &self.previous.state;
        let new = &candidate.state;
        anyhow::ensure!(
            new.tenant == self.engine.tenant
                && new.incarnation == self.engine.incarnation
                && new.revision_base == self.engine.revision_base
                && old.tenant == new.tenant
                && old.incarnation == new.incarnation
                && old.revision_base == new.revision_base
                && new.revision > old.revision,
            "accepted application scope/revision differs"
        );
        anyhow::ensure!(
            candidate.application_selection.get().is_none()
                && candidate._read_reservations.is_empty(),
            "accepted application is already selected or is a hydrated read view"
        );
        anyhow::ensure!(
            self.engine
                .current
                .load()
                .as_ref()
                .is_some_and(|current| { Arc::ptr_eq(current, &self.previous) }),
            "accepted application current owner changed"
        );
        let delta = PrimaryDelta::new(old, new, changed)?;
        Ok(AcceptedGeneration {
            candidate,
            delta,
            receipt_publication: None,
            owner: self,
        })
    }
}

// The type and constructors are private to the actual state producer module.
// A generic CollectionRecords/BuiltCollection/raw caller Arc cannot mint this
// owner. No fresh-projection conversion is provided.
pub(super) struct AcceptedGeneration<'engine> {
    candidate: Arc<Generation>,
    delta: PrimaryDelta,
    receipt_publication: Option<crate::mutation_receipt::PreparedPublication>,
    // Last: candidate/map destruction and visibility transfer stay serialized.
    owner: ApplyOwner<'engine>,
}

impl AcceptedGeneration<'_> {
    pub(super) fn with_receipt_publication(
        mut self,
        publication: Option<crate::mutation_receipt::PreparedPublication>,
    ) -> anyhow::Result<Self> {
        if let Some(publication) = &publication {
            publication.require_view(&self.candidate.receipts)?;
        }
        anyhow::ensure!(
            self.receipt_publication.is_none(),
            "receipt publication already attached"
        );
        self.receipt_publication = publication;
        Ok(self)
    }

    pub(super) fn prepare_publication_writes(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> anyhow::Result<PreparedApplicationWrites> {
        let mut documents = self.prepare_documents(roots)?;
        let mut receipt = self.receipt_publication.take();
        if receipt.is_some()
            && !crate::mutation_receipt::PreparedPublication::can_join(
                position,
                documents
                    .as_ref()
                    .map_or(&[][..], |documents| documents.writes()),
            )
        {
            // This is the original immutable pair commit, before the publisher
            // is entered. No publisher/capacity error is caught or retried.
            receipt
                .take()
                .expect("checked receipt")
                .stage_separately()?;
        }
        let mut writes = documents
            .as_mut()
            .map_or_else(Vec::new, |documents| documents.take_writes());
        if let Some(receipt) = &mut receipt {
            receipt.append_to(&mut writes)?;
        }
        Ok(PreparedApplicationWrites {
            writes,
            _documents: documents,
            _receipt: receipt,
        })
    }

    /// Stage each changed after-image once. The same compact handle is retained
    /// by both the current document map and its complete change-feed event.
    pub(super) fn prepare_documents(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
    ) -> anyhow::Result<Option<crate::document_store::PreparedDocuments>> {
        // Metadata, rejection, replay and deletion-only publications have no
        // new after-image. They must not obtain a new body grant after commit.
        let pending = self.delta.changed.iter().any(|(name, ids)| {
            self.candidate
                .state
                .collections
                .get(name)
                .is_some_and(|collection| {
                    ids.iter().any(|id| {
                        collection
                            .documents
                            .get(id)
                            .is_some_and(|slot| matches!(slot.as_ref(), DocumentSlot::Pending(_)))
                    })
                })
        });
        if !pending {
            return Ok(None);
        }
        let selected = self
            .owner
            .previous
            .application_selection
            .get()
            .ok_or_else(|| anyhow::anyhow!("previous document selection missing"))?;
        let mut prepared = crate::document_store::PreparedDocuments::new(
            roots,
            selected,
            &self.candidate.state.tenant,
            &self.candidate.state.incarnation,
        )?;
        let candidate = Arc::get_mut(&mut self.candidate)
            .ok_or_else(|| anyhow::anyhow!("unpublished document candidate escaped"))?;
        for (name, ids) in &self.delta.changed {
            let collection = candidate
                .state
                .collections
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("changed document collection absent"))?;
            for id in ids {
                let Some(slot) = collection.documents.get(id) else {
                    continue;
                };
                if let DocumentSlot::Pending(document) = slot.as_ref() {
                    let descriptor = prepared.stage(document)?;
                    collection
                        .documents
                        .insert(id.clone(), Arc::new(DocumentSlot::Stored(descriptor)));
                }
            }
        }
        let latest_key = candidate
            .state
            .change_feed
            .commits
            .get_max()
            .map(|(key, _)| *key);
        if let Some(latest) =
            latest_key.and_then(|key| candidate.state.change_feed.commits.get_mut(&key))
            && latest.revision == candidate.state.revision
        {
            for record in &mut Arc::make_mut(latest).records {
                if record.document.is_some() {
                    let slot = candidate
                        .state
                        .collections
                        .get(&record.collection)
                        .and_then(|collection| collection.documents.get(&record.id))
                        .ok_or_else(|| anyhow::anyhow!("new change-feed after-image absent"))?;
                    slot.stored()?;
                    record.document = Some(slot.clone());
                }
            }
        }
        Ok(Some(prepared))
    }

    pub(super) fn candidate(&self) -> &Generation {
        &self.candidate
    }

    pub(super) fn require_publication(
        &self,
        engine: &TenantEngine,
        position: Option<&kasumi_raft::AppliedEntryContext>,
    ) -> anyhow::Result<()> {
        self.owner.require_engine(engine)?;
        if let Some(position) = position {
            anyhow::ensure!(
                engine.revision_base.checked_add(position.log_id.index)
                    == Some(self.candidate.state.revision),
                "accepted application differs from publisher position"
            );
        }
        Ok(())
    }

    pub(super) fn publish(self) {
        // Check before destructuring: unwinding must retire candidate/payload
        // owners before releasing the apply guard, in the struct's field order.
        assert!(
            self.receipt_publication.is_none(),
            "unpublished receipt pair reached visibility"
        );
        let Self {
            candidate,
            delta,
            receipt_publication: _,
            owner,
        } = self;
        owner.engine.publish_generation(Some(candidate));
        // Preserve the moved exact IDs until the actual visible swap completes.
        drop(delta.changed);
        drop(owner);
    }
}

pub(super) struct PreparedApplicationWrites {
    writes: Vec<kasumi_store::WriteOp>,
    _documents: Option<crate::document_store::PreparedDocuments>,
    _receipt: Option<crate::mutation_receipt::PreparedPublication>,
}
impl PreparedApplicationWrites {
    pub(super) fn writes(&self) -> &[kasumi_store::WriteOp] {
        &self.writes
    }
}

struct PrimaryDelta {
    changed: ChangedIds,
}

impl PrimaryDelta {
    fn new(old: &TenantState, new: &TenantState, changed: ChangedIds) -> Result<Self> {
        for (name, collection) in &new.collections {
            if name != &collection.definition.name || collection.data_epoch > new.revision {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "accepted primary collection identity/epoch differs",
                ));
            }
            let Some(previous) = old.collections.get(name) else {
                continue;
            };
            if previous.definition != collection.definition {
                continue;
            }
            if (!previous.documents.ptr_eq(&collection.documents)
                || !previous
                    .archived_documents
                    .ptr_eq(&collection.archived_documents)
                || previous.data_epoch != collection.data_epoch
                || previous.archived_document_bytes != collection.archived_document_bytes)
                && !changed.get(name).is_some_and(|ids| !ids.is_empty())
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "accepted primary roots have no exact producer delta",
                ));
            }
        }
        if changed
            .iter()
            .any(|(name, ids)| ids.is_empty() || !new.collections.contains_key(name))
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "accepted primary delta targets absent collection or is empty",
            ));
        }
        Ok(Self { changed })
    }
}

#[cfg(test)]
#[path = "accepted_apply_tests.rs"]
mod tests;
