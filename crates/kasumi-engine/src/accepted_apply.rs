//! Semantic custody of the actual accepted apply result. This is not a primary
//! serving capability or candidate-body/index memory admission. These owners
//! replace existing stack locals; the producer's exact ID map moves once and
//! stays alive through durable publication, source capture and the visible swap.
use super::*;

pub(super) type ChangedIds = BTreeMap<String, BTreeSet<String>>;

pub(super) struct ApplyOwner<'engine> {
    engine: &'engine TenantEngine,
    previous: Arc<Generation>,
    // A standalone group's last unpublished candidate, which its next member
    // applies to as it would to that candidate published.
    chained: Option<Arc<Generation>>,
    // This inline slot receives the same original input/budget alias BEFORE
    // the known tree factory allocates. It is unset for early/idempotent exits.
    _mutation_change_tree: std::sync::OnceLock<kasumi_raft::MutationChangeTreeRetention>,
    input_position: Option<kasumi_raft::LogId<u64>>,
    // Exact input plus optional known change-tree recipe only. Generation,
    // reducer/body clones, indexes and response remain the separate M03 model.
    _input_retention: Option<kasumi_raft::AdmittedApplicationInput>,
    // Earlier group members' trees and inputs, each tree before its input, kept
    // through the group's one publication and visible swap.
    _earlier_inputs: Vec<(
        std::sync::OnceLock<kasumi_raft::MutationChangeTreeRetention>,
        Option<kasumi_raft::AdmittedApplicationInput>,
    )>,
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
            chained: None,
            _mutation_change_tree: std::sync::OnceLock::new(),
            input_position: None,
            _input_retention: None,
            _earlier_inputs: Vec::new(),
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
            chained: None,
            _mutation_change_tree: std::sync::OnceLock::new(),
            input_position: None,
            _input_retention: None,
            _earlier_inputs: Vec::new(),
            _guard: guard,
        })
    }

    /// The next member of a standalone group: keep the previous member's
    /// input and change tree, and retain this member's as `retain_input` does.
    pub(super) fn retain_member_input(
        &mut self,
        input: Option<kasumi_raft::AdmittedApplicationInput>,
        position: kasumi_raft::LogId<u64>,
    ) {
        if self.input_position.is_some() || self._mutation_change_tree.get().is_some() {
            self._earlier_inputs.push((
                std::mem::take(&mut self._mutation_change_tree),
                self._input_retention.take(),
            ));
        }
        self.retain_input(input, position);
    }

    /// Apply the next group member to `candidate`, the unpublished result of
    /// the members before it. Its stored documents are the published
    /// generation's, so it reads them through that generation's resolver.
    pub(super) fn chain(&mut self, mut candidate: Arc<Generation>) -> anyhow::Result<()> {
        let next = Arc::get_mut(&mut candidate)
            .ok_or_else(|| anyhow::anyhow!("chained group candidate escaped"))?;
        anyhow::ensure!(
            next.application_selection.get().is_none() && next._read_reservations.is_empty(),
            "chained group candidate is already selected or is a read view"
        );
        if let Some(resolver) = self.previous.document_sources.get() {
            next.document_sources
                .set(resolver.clone())
                .map_err(|_| anyhow::anyhow!("chained group candidate already has a resolver"))?;
        }
        self.chained = Some(candidate);
        Ok(())
    }

    /// The last chained candidate, which the group publishes.
    pub(super) fn take_chained(&mut self) -> anyhow::Result<Arc<Generation>> {
        let mut candidate = self
            .chained
            .take()
            .ok_or_else(|| anyhow::anyhow!("standalone group has no candidate"))?;
        // Publication installs the selected resolver itself.
        let last = Arc::get_mut(&mut candidate)
            .ok_or_else(|| anyhow::anyhow!("chained group candidate escaped"))?;
        last.document_sources = std::sync::OnceLock::new();
        Ok(candidate)
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
    // Within a standalone group, the members before this one have applied.
    pub(super) fn current(&self) -> &Generation {
        self.chained.as_deref().unwrap_or(&self.previous)
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
            receipt_publications: Vec::new(),
            owner: self,
        })
    }

    pub(super) fn accept(
        self,
        candidate: Arc<Generation>,
        changed: ChangedIds,
    ) -> anyhow::Result<AcceptedGeneration<'engine>> {
        anyhow::ensure!(
            self.chained.is_none(),
            "a chained group candidate is accepted only as the last"
        );
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
            receipt_publications: Vec::new(),
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
    // One per member whose receipt pair joins the publication, in log order.
    receipt_publications: Vec<crate::mutation_receipt::PreparedPublication>,
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
            self.receipt_publications.is_empty(),
            "receipt publication already attached"
        );
        self.receipt_publications.extend(publication);
        Ok(self)
    }

    /// The receipt pairs of a standalone group's members, in log order. Each
    /// follows the one before it, and the last is the candidate's own head.
    pub(super) fn with_group_receipts(
        mut self,
        publications: Vec<crate::mutation_receipt::PreparedPublication>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.receipt_publications.is_empty(),
            "receipt publication already attached"
        );
        let receipts = &self.candidate.receipts;
        for pair in publications.windows(2) {
            anyhow::ensure!(
                pair[0].head().count < pair[1].head().count,
                "group receipt pairs are out of order"
            );
        }
        if let Some(last) = publications.last() {
            anyhow::ensure!(
                last.head() == receipts.head(),
                "group receipt head differs from candidate"
            );
        }
        anyhow::ensure!(
            publications
                .iter()
                .all(|publication| publication.joins_rows_of(receipts)),
            "group receipt pair belongs to other rows"
        );
        self.receipt_publications = publications;
        Ok(self)
    }

    pub(super) fn prepare_publication_writes(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> anyhow::Result<PreparedApplicationWrites> {
        let revision = self.candidate.state.revision;
        self.prepare_writes(roots, revision, |documents| {
            crate::mutation_receipt::PreparedPublication::can_join(position, documents)
        })
    }

    /// [`Self::prepare_publication_writes`] for a standalone group of
    /// `members` entries, the first applied at `first_revision`, publishing at
    /// the last member's `position`.
    pub(super) fn prepare_group_publication_writes(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
        position: &kasumi_raft::AppliedEntryContext,
        members: usize,
        first_revision: u64,
    ) -> anyhow::Result<PreparedApplicationWrites> {
        self.prepare_writes(roots, first_revision, |documents| {
            crate::mutation_receipt::PreparedPublication::can_join_group(
                position, documents, members,
            )
        })
    }

    fn prepare_writes(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
        first_revision: u64,
        can_join: impl FnOnce(&[kasumi_store::WriteOp]) -> bool,
    ) -> anyhow::Result<PreparedApplicationWrites> {
        let mut documents = self.prepare_documents_since(roots, first_revision)?;
        let mut receipts = std::mem::take(&mut self.receipt_publications);
        if !receipts.is_empty()
            && !can_join(
                documents
                    .as_ref()
                    .map_or(&[][..], |documents| documents.writes()),
            )
        {
            // This is the original immutable pair commit, before the publisher
            // is entered. No publisher/capacity error is caught or retried.
            for receipt in receipts.drain(..) {
                receipt.stage_separately()?;
            }
        }
        let mut writes = documents
            .as_mut()
            .map_or_else(Vec::new, |documents| documents.take_writes());
        for receipt in &mut receipts {
            receipt.append_to(&mut writes)?;
        }
        Ok(PreparedApplicationWrites {
            writes,
            _documents: documents,
            _receipts: receipts,
        })
    }

    /// Stage each changed after-image once, retaining the same compact handle
    /// in the current document map and its complete change-feed event. Include
    /// every revision since `first_revision`, including earlier group members.
    fn prepare_documents_since(
        &mut self,
        roots: &crate::application_sources::SourceRootsRef,
        first_revision: u64,
    ) -> anyhow::Result<Option<crate::document_store::PreparedDocuments>> {
        // Metadata, rejection, replay and deletion-only publications have no
        // new after-image. They must not obtain a new body grant after commit.
        let feed = &self.candidate.state.change_feed.commits;
        let events = feed
            .iter()
            .rev()
            .take_while(|(_, commit)| commit.revision >= first_revision)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        let superseded = events.iter().any(|key| {
            feed.get(key).is_some_and(|commit| {
                commit.records.iter().any(|record| {
                    record
                        .document
                        .as_ref()
                        .is_some_and(|slot| matches!(slot.as_ref(), DocumentSlot::Pending(_)))
                })
            })
        });
        let pending = superseded
            || self.delta.changed.iter().any(|(name, ids)| {
                self.candidate
                    .state
                    .collections
                    .get(name)
                    .is_some_and(|collection| {
                        ids.iter().any(|id| {
                            collection.documents.get(id).is_some_and(|slot| {
                                matches!(slot.as_ref(), DocumentSlot::Pending(_))
                            })
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
        // Each staged after-image, by the pending slot it replaced; that slot
        // stays allocated until every event is resolved.
        let mut staged = std::collections::BTreeMap::new();
        let mut replaced = Vec::new();
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
                    let stored = Arc::new(DocumentSlot::Stored(descriptor));
                    staged.insert(Arc::as_ptr(slot), stored.clone());
                    replaced.push(slot.clone());
                    collection.documents.insert(id.clone(), stored);
                }
            }
        }
        for key in events.into_iter().rev() {
            let commit = candidate
                .state
                .change_feed
                .commits
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("change-feed event vanished"))?;
            anyhow::ensure!(
                commit.revision <= candidate.state.revision,
                "change-feed event follows its candidate"
            );
            for record in &mut Arc::make_mut(commit).records {
                let Some(slot) = record.document.take() else {
                    continue;
                };
                let stored = match staged.get(&Arc::as_ptr(&slot)) {
                    Some(stored) => stored.clone(),
                    None => match slot.as_ref() {
                        DocumentSlot::Pending(document) => {
                            let stored = Arc::new(DocumentSlot::Stored(prepared.stage(document)?));
                            staged.insert(Arc::as_ptr(&slot), stored.clone());
                            stored
                        }
                        DocumentSlot::Stored(_) => slot.clone(),
                    },
                };
                stored.stored()?;
                replaced.push(slot);
                record.document = Some(stored);
            }
        }
        drop(replaced);
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
            self.receipt_publications.is_empty(),
            "unpublished receipt pair reached visibility"
        );
        let Self {
            candidate,
            delta,
            receipt_publications: _,
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
    _receipts: Vec<crate::mutation_receipt::PreparedPublication>,
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
