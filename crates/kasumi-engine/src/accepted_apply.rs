//! Semantic custody of the actual accepted apply result. This is not a primary
//! serving capability or candidate-body/index memory admission. These owners
//! replace existing stack locals; the producer's exact ID map moves once and
//! stays alive through durable publication, source capture and the visible swap.
use super::*;

pub(super) type ChangedIds = BTreeMap<String, BTreeSet<String>>;

pub(super) struct ApplyOwner<'engine> {
    engine: &'engine TenantEngine,
    previous: Arc<Generation>,
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
            _guard: guard,
        })
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
    // Last: candidate/map destruction and visibility transfer stay serialized.
    owner: ApplyOwner<'engine>,
}

impl AcceptedGeneration<'_> {
    #[cfg(test)]
    pub(crate) fn primary_input(
        &self,
    ) -> anyhow::Result<super::primary_projection::AcceptedPrimary<'_>> {
        use crate::primary_tree::records;
        use anyhow::Context as _;
        let engine = self.owner.engine;
        let roots = engine
            .application_sources
            .get()
            .context("application sources absent")?;
        let bootstrap = records::boundary::raw_digest(
            engine
                .bootstrap_sha256
                .get()
                .context("application bootstrap absent")?,
        )
        .map_err(|error| anyhow::anyhow!("primary bootstrap invalid: {error:?}"))?;
        let scope = records::scope_hash(&engine.tenant, &engine.incarnation, bootstrap)
            .map_err(|error| anyhow::anyhow!("primary scope invalid: {error:?}"))?;
        roots.primary_installation().0.check_access()?;
        Ok(super::primary_projection::AcceptedPrimary {
            authority: super::PrimaryApplyGuard {
                roots,
                scope,
                bootstrap,
                _guard: super::PrimaryApplyLock::Borrowed(&self.owner._guard),
            },
            candidate: super::primary_projection::PrimaryCandidate {
                previous: &self.owner.previous,
                accepted: &self.candidate,
                changed: &self.delta.changed,
                guard: &self.owner._guard,
                roots,
                scope,
                bootstrap,
            },
        })
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
        let Self {
            candidate,
            delta,
            owner,
        } = self;
        owner.engine.publish_generation(Some(candidate));
        // Preserve the moved exact IDs until the actual visible swap completes.
        drop(delta.changed);
        drop(owner);
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

#[cfg(test)]
impl AcceptedGeneration<'_> {
    pub(super) fn omit_primary_id_for_test(&mut self, name: &str, id: &str) {
        self.delta
            .changed
            .get_mut(name)
            .expect("test changed collection")
            .remove(id);
    }
}
