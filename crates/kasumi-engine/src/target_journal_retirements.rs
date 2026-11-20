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
    pub(super) fn admit_version(&self, provider: &str, key_ref: &str, version: u64) -> Result<()> {
        ensure!(
            !self.state.rejects_version(provider, key_ref, version),
            "new target checkpoint references a fenced wrapping key"
        );
        Ok(())
    }
    pub(super) fn requires_graph(&self) -> bool {
        self.state.fence.is_some() || !self.state.completed.is_empty()
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
        state.validate_journal_scope(revision)?;
        let next = WriterRetirements {
            revision: state.last_transition_revision(),
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

/// This value can only be constructed after checking every authenticated
/// wrapping identity against the exact writer position for this checkpoint.
pub(super) struct JournalCheckpointPermit {
    installation: kasumi_types::TrustVerifierIdentity,
    control: kasumi_types::ControlSigningRoot,
    binding: GenerationBinding,
    position: WriterRetirements,
}
impl JournalCheckpointPermit {
    pub(super) fn require(
        &self,
        journal: &TargetJournal,
        binding: &GenerationBinding,
        position: &WriterRetirements,
    ) -> Result<()> {
        ensure!(
            self.installation == journal.installed.node.verifier
                && self.control == journal.installed.root
                && self.binding == *binding
                && self.position == *position,
            "checkpoint verification differs from the current journal or writer fence"
        );
        Ok(())
    }
}

impl TargetJournal {
    pub(crate) fn writer_state_sha256(&self) -> Result<String> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        Ok(self.metadata()?.retirements.state.target_writer_digest()?)
    }

    pub(crate) fn writer_admission(&self) -> &Arc<crate::admission::NodeAdmission> {
        &self.admission
    }

    fn new_checkpoint_position(
        &self,
        operation: &TargetOperation,
    ) -> Result<Option<(TargetJournalIntent, WriterRetirements)>> {
        let _workspace = self
            .admission
            .reserve((MAX_RECORD * 8) as u64, Some(operation.token.clone()))?;
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let position = self.metadata()?.retirements;
        let original = self.intent(operation)?;
        let binding = GenerationBinding::from_intent(&original);
        if let Some(existing) = self.store.get_bounded(
            NS,
            &generation_key(&binding.tenant, binding.target_incarnation),
            MAX_RECORD,
        )? {
            ensure!(
                decode_current::<GenerationBinding>(&existing)? == binding,
                "target generation binding differs"
            );
            return Ok(None);
        }
        Ok(Some((original, position)))
    }

    /// Admit an immutable checkpoint under the durable writer position. The
    /// provider is opened only for a new generation subject to a fence/floor.
    pub fn prepare_observed(
        &self,
        operation: &TargetOperation,
        exact_input_sha256: &str,
        writer: &CurrentTargetJournalWriter,
    ) -> Result<TargetJournalIntent> {
        self.prepare_with_checkpoint_permit(operation, exact_input_sha256, None, Some(writer))
    }

    pub async fn prepare_runtime<F>(
        &self,
        operation: &TargetOperation,
        step: &kasumi_types::TargetRuntimeStep,
        exact_input_sha256: &str,
        mut observe_writer: impl FnMut() -> F + Send,
        original_source: impl FnOnce(
            &kasumi_types::TargetMaterializationInput,
        ) -> Result<crate::RestoreSource>
        + Send,
    ) -> std::result::Result<TargetJournalIntent, crate::SnapshotFailure>
    where
        F: std::future::Future<Output = Result<CurrentTargetJournalWriter>> + Send,
    {
        let Some((original, _)) = self.new_checkpoint_position(operation)? else {
            return Ok(self.prepare(operation, exact_input_sha256)?);
        };
        let current = operation
            .run(async { observe_writer().await.map_err(crate::SnapshotFailure::from) })
            .await?;
        if !current.position.requires_graph() {
            return Ok(self.prepare_observed(operation, exact_input_sha256, &current)?);
        }
        let position = current.position;
        let input = match step {
            kasumi_types::TargetRuntimeStep::Materialize(input) => {
                input.validate(&original.intent)?;
                input
            }
            kasumi_types::TargetRuntimeStep::ResumeMaterialization(origin) => {
                origin.accepts_phase(&original.intent, LifecyclePhase::ResumeMaterialize)?;
                if original.intent.request.resume_origin.as_ref() != Some(origin)
                    || original.intent.request.phase_input_sha256 != origin.resume_digest()?
                {
                    return Err(anyhow::anyhow!(
                        "resumption differs from the committed source checkpoint"
                    )
                    .into());
                }
                &origin.input
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "new generation lacks its original materialization source"
                )
                .into());
            }
        };
        let source = original_source(input)?;
        if source.destination_alias != input.destination_alias {
            return Err(anyhow::anyhow!(
                "target writer destination differs from original materialization"
            )
            .into());
        }
        let binding = GenerationBinding::from_intent(&original);
        let observe = |provider: &str, key_ref: &str, version: u64| {
            position.admit_version(provider, key_ref, version)
        };
        operation
            .run(crate::service::verify_target_writer_checkpoint(
                self,
                operation,
                &source,
                &binding.checkpoint,
                input,
                &observe,
            ))
            .await?;
        let permit = JournalCheckpointPermit {
            installation: self.installed.node.verifier.clone(),
            control: self.installed.root.clone(),
            binding,
            position,
        };
        // Long object reads may outlive their first observation. The native
        // mutation checks both the verified graph's position and a fresh grant.
        let current = operation
            .run(async { observe_writer().await.map_err(crate::SnapshotFailure::from) })
            .await?;
        Ok(self.prepare_with_checkpoint_permit(
            operation,
            exact_input_sha256,
            Some(&permit),
            Some(&current),
        )?)
    }
}

/// Local ownership of the request's physical catalog, original nonce and
/// admission lifetime. It can accept at most one signed quorum observation.
pub struct TargetWriterRead {
    journal: Arc<TargetJournal>,
    challenge: kasumi_types::TargetWriterChallenge,
    deadline: kasumi_clock::ElapsedDeadline,
    _workspace: crate::admission::Reservation,
}
impl TargetJournal {
    pub fn begin_writer_read(self: &Arc<Self>) -> Result<TargetWriterRead> {
        self.writer_read(None)
    }

    pub fn begin_generation_writer_read(
        self: &Arc<Self>,
        operation: &TargetOperation,
    ) -> Result<TargetWriterRead> {
        let original = self.intent(operation)?;
        self.writer_read(Some(original.intent.request.command_id))
    }

    fn writer_read(self: &Arc<Self>, lifecycle_command: Option<Uuid>) -> Result<TargetWriterRead> {
        let observation = kasumi_clock::EpochClock::system()?.observe()?;
        let deadline = observation.until(
            observation
                .utc_ms()
                .checked_add(30_000)
                .context("target writer deadline overflow")?,
        )?;
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
                lifecycle_command,
                nonce: Uuid::new_v4(),
            },
            deadline,
            _workspace: workspace,
        })
    }
}
/// Physical journal enrollment and a bounded observation of its original Control.
pub struct CurrentTargetJournalWriter {
    journal: Arc<TargetJournal>,
    position: WriterRetirements,
    deadline: kasumi_clock::ElapsedDeadline,
}
impl CurrentTargetJournalWriter {
    pub(super) fn require(
        &self,
        journal: &TargetJournal,
        position: &WriterRetirements,
    ) -> Result<()> {
        ensure!(
            std::ptr::eq(self.journal.as_ref(), journal) && *position == self.position,
            "target generation writer observation differs from the current physical journal"
        );
        self.deadline.check()?;
        Ok(())
    }
}
impl TargetWriterRead {
    pub fn challenge(&self) -> &kasumi_types::TargetWriterChallenge {
        &self.challenge
    }
    pub fn accept(self, signed: &kasumi_types::SignedTargetWriterObservation) -> Result<String> {
        Ok(self.accept_position(signed)?.0)
    }
    pub fn admit(
        self,
        signed: &kasumi_types::SignedTargetWriterObservation,
    ) -> Result<CurrentTargetJournalWriter> {
        Ok(self.accept_position(signed)?.1)
    }
    fn accept_position(
        self,
        signed: &kasumi_types::SignedTargetWriterObservation,
    ) -> Result<(String, CurrentTargetJournalWriter)> {
        kasumi_serving::ControlTrust::install(self.journal.installed.root.clone())?
            .verify_target_writer(&self.challenge, signed)?;
        let digest = self.journal.persist_writer_retirements(
            signed.observation.observed_revision,
            &signed.observation.retirements,
            || {
                self.deadline.check()?;
                self.journal.store.check_access()
            },
        )?;
        Ok((
            digest,
            CurrentTargetJournalWriter {
                journal: self.journal,
                position: WriterRetirements {
                    revision: signed.observation.retirements.last_transition_revision(),
                    state: signed.observation.retirements.clone(),
                },
                deadline: self.deadline,
            },
        ))
    }
}
