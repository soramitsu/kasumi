use super::*;
use kasumi_types::{KeyRetirementState, KeyRetirementStatus};

/// The original journal persists the position it actually accepted. Only a
/// fresh observation of the installed Control's committed decision may move it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WriterRetirements {
    revision: u64,
    state: KeyRetirementState,
}
impl WriterRetirements {
    pub(super) fn is_empty(&self) -> bool {
        self.revision == 0 && self.state.is_empty()
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.state.validate_journal_scope(self.revision)?;
        ensure!(
            self.is_empty() || self.revision != 0,
            "target writer retirement lacks a Control position"
        );
        Ok(())
    }
    fn require_successor(&self, next: &Self) -> Result<()> {
        next.validate()?;
        ensure!(
            next.revision > self.revision || next == self,
            "target writer Control position regressed or changed"
        );
        ensure!(
            next.state.last_ordinal()? >= self.state.last_ordinal()?,
            "target writer retirement ordinal regressed"
        );
        for record in &self.state.completed {
            ensure!(
                next.state.floor(&record.fence.request.identity)
                    >= record.fence.request.retire_below_version,
                "target writer cannot lower a completed wrapping-key floor"
            );
        }
        if let Some(original) = &self.state.fence {
            let id = &original.request.retirement_id;
            let held = match next.state.status(id) {
                Some(
                    KeyRetirementStatus::Fenced { fence }
                    | KeyRetirementStatus::Aborted { fence, .. },
                ) => fence == *original,
                Some(KeyRetirementStatus::Completed { record }) => record.fence == *original,
                None => false,
            };
            ensure!(
                held,
                "original target writer fence lacks an authenticated decision"
            );
        }
        if self.state.last_ordinal()? == next.state.last_ordinal()? && self.state.fence.is_none() {
            ensure!(
                next.state == self.state,
                "terminal target writer decision changed"
            );
        }
        Ok(())
    }
    pub(super) fn require_verified_checkpoint(&self) -> Result<()> {
        ensure!(
            self.state.fence.is_none() && self.state.completed.is_empty(),
            "new target checkpoint requires verification at its durable writer fence"
        );
        Ok(())
    }
}

impl TargetJournal {
    /// The coordinator supplies the original committed scope and rechecks the
    /// physical member and Control authorization while the mutation lock is held.
    fn persist_writer_retirements(
        &self,
        revision: u64,
        state: &KeyRetirementState,
        confirm: impl Fn() -> Result<()>,
    ) -> Result<String> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        confirm()?;
        let mut head = self.metadata()?;
        let next = WriterRetirements {
            revision,
            state: state.clone(),
        };
        head.retirements.require_successor(&next)?;
        let digest = kasumi_types::staged_digest(&(
            &self.installed.root,
            &self.installed.node.verifier,
            &next,
        ))?
        .0;
        if next != head.retirements {
            head.retirements = next;
            let bytes = serde_json::to_vec(&head)?;
            ensure!(
                bytes.len() <= MAX_RECORD,
                "target writer state exceeds permanent journal head"
            );
            confirm()?;
            self.store
                .write_batch(&[WriteOp::put(NS, b"metadata", bytes)])
                .map_err(journal_unknown)?;
        }
        confirm().map_err(journal_unknown)?;
        Ok(digest)
    }
}

/// Local ownership of the request's physical catalog, original nonce and
/// admission lifetime. It can accept at most one signed quorum observation.
pub struct TargetWriterRead {
    journal: Arc<TargetJournal>,
    challenge: kasumi_types::TargetWriterChallenge,
    deadline: std::time::Instant,
    _workspace: crate::admission::Reservation,
}
impl TargetJournal {
    pub fn begin_writer_read(self: &Arc<Self>) -> Result<TargetWriterRead> {
        let workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let view = self.store.read_view()?;
        let physical = (|| -> Result<Uuid> {
            let mut catalog = None;
            view.wrapping_inventory()?.visit_catalog(|id, _, _, _| {
                ensure!(
                    catalog.replace(id).is_none_or(|old| old == id),
                    "journal wrapping identities differ"
                );
                Ok(())
            })?;
            catalog.context("journal lacks a wrapping catalog")
        })();
        let catalog = match (physical, view.close()) {
            (Ok(id), Ok(())) => id,
            (Err(e), Ok(())) | (Ok(_), Err(e)) => return Err(e),
            (Err(e), Err(close)) => return Err(e.context(close)),
        };
        Ok(TargetWriterRead {
            journal: self.clone(),
            challenge: kasumi_types::TargetWriterChallenge {
                root: self.installed.root.clone(),
                verifier: self.installed.node.verifier.clone(),
                catalog,
                nonce: Uuid::new_v4(),
            },
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            _workspace: workspace,
        })
    }
}
impl TargetWriterRead {
    pub fn challenge(&self) -> &kasumi_types::TargetWriterChallenge {
        &self.challenge
    }
    pub fn accept(self, signed: &kasumi_types::SignedTargetWriterObservation) -> Result<String> {
        kasumi_serving::ControlTrust::install(self.journal.installed.root.clone())?
            .verify_target_writer(&self.challenge, signed)?;
        self.journal.persist_writer_retirements(
            signed.observation.observed_revision,
            &signed.observation.retirements,
            || {
                ensure!(
                    std::time::Instant::now() < self.deadline,
                    "original target writer observation expired"
                );
                self.journal.store.check_access()
            },
        )
    }
}
