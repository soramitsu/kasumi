//! Actual ordinary-command preparation. This groups existing owners; it does
//! not fund their payloads or certify Raft commitment from a command digest.
use super::*;
use anyhow::Context as _;

pub(super) struct ByteBoundCommand<'entry> {
    position: &'entry kasumi_raft::AppliedEntryContext,
    bytes: &'entry [u8],
}
impl<'entry> ByteBoundCommand<'entry> {
    pub(super) fn check(
        position: &'entry kasumi_raft::AppliedEntryContext,
        bytes: &'entry [u8],
    ) -> anyhow::Result<Self> {
        let digest = Sha256::digest(bytes);
        let mut encoded = [0u8; 64];
        hex::encode_to_slice(digest, &mut encoded)
            .expect("SHA-256 fits its fixed hexadecimal buffer");
        if encoded.as_slice() != position.command_sha256.as_bytes() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "ordered command bytes differ from applied digest",
            )
            .into());
        }
        Ok(Self { position, bytes })
    }
    pub(super) fn position(&self) -> &'entry kasumi_raft::AppliedEntryContext {
        self.position
    }
    pub(super) fn bytes(&self) -> &'entry [u8] {
        self.bytes
    }
}

// The frozen branch owns its real guard too. Moving the existing locals here
// introduces no heap shell or additional candidate/map/response copy.
#[allow(
    clippy::large_enum_variant,
    reason = "Existing accepted/frozen owners stay inline without an unfunded Box."
)]
enum OutcomeOwner<'engine> {
    Candidate(AcceptedGeneration<'engine>),
    Frozen(ApplyOwner<'engine>),
}
pub(super) struct PreparedOrderedCommand<'engine, 'entry> {
    position: &'entry kasumi_raft::AppliedEntryContext,
    response: kasumi_raft::AppliedResponse,
    owner: OutcomeOwner<'engine>,
}
impl<'engine, 'entry> PreparedOrderedCommand<'engine, 'entry> {
    pub(super) fn prepare(
        engine: &'engine TenantEngine,
        input: ByteBoundCommand<'entry>,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        Self::prepare_with_input(engine, input, None)
    }
    fn prepare_with_input(
        engine: &'engine TenantEngine,
        input: ByteBoundCommand<'entry>,
        mut input_retention: Option<kasumi_raft::AdmittedApplicationInput>,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        let position = input.position;
        let (command, applied, apply, reference) =
            kasumi_store::ScratchOperationFailure::ordinary(|| {
                let command = decode_committed_command(input.bytes)?;
                let revision = engine
                    .revision_base
                    .checked_add(position.log_id.index)
                    .ok_or_else(|| anyhow::anyhow!("logical revision exhausted"))?;
                let applied = crate::staged_terminal::AppliedIdentity::ordered(
                    &engine.incarnation,
                    revision,
                    command.timestamp_ms,
                    position,
                )?;
                let mut apply =
                    ApplyOwner::lock(engine, || anyhow::anyhow!("tenant apply lock poisoned"))?;
                // The exact original alias is installed before preparation can
                // allocate any known change tree, including error/unwind paths.
                apply.retain_input(input_retention.take(), position.log_id);
                let previous = apply.current();
                anyhow::ensure!(
                    !matches!(&command.operation, Operation::RetireSource(prepared)
                if prepared.observation.is_some())
                        || position.retirement_seed.is_some(),
                    "prepared retirement is missing its custody seed"
                );
                if let Some(seed) = &position.retirement_seed {
                    seed.reserve_success_capacity()?;
                    let expected = kasumi_raft::RetirementLogSeed::prepare(
                        &command,
                        TenantEngine::retirement_replay_from(previous, &command)?,
                    )?;
                    anyhow::ensure!(
                        expected.encoded()? == seed.encoded()?,
                        "committed retirement seed differs from ordered source state"
                    );
                }
                let reference = position
                    .retirement_seed
                    .as_ref()
                    .map(|seed| seed.request().reference())
                    .transpose()?;
                Ok((command, applied, apply, reference))
            })?;
        let prepared =
            engine.prepare_command_ordered(&apply, &command, &applied, &ApplyScope::Committed)?;
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let previous = apply.current();
            let retirement = if prepared.outcome.is_ok() {
                reference
                    .map(|reference| -> anyhow::Result<RetirementReceipt> {
                        retirement::lookup(
                            &prepared.generation.as_deref().unwrap_or(previous).state,
                            &command.context,
                            &reference,
                        )?
                        .ok_or_else(|| anyhow::anyhow!("successful retirement outcome missing"))?
                        .outcome
                        .clone()
                        .map_err(Into::into)
                    })
                    .transpose()?
            } else {
                None
            };
            let response = kasumi_raft::AppliedResponse {
                data: serde_json::to_vec(&prepared.outcome)?,
                retirement,
            };
            let owner = match prepared.generation {
                Some(candidate) => {
                    OutcomeOwner::Candidate(apply.accept(candidate, prepared.changed)?)
                }
                None => OutcomeOwner::Frozen(apply),
            };
            Ok(Self {
                position,
                response,
                owner,
            })
        })
    }

    pub(super) fn publish(
        self,
        engine: &TenantEngine,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> anyhow::Result<()> {
        self.publish_inner(engine, publisher, None)
    }
    fn publish_inner(
        self,
        engine: &TenantEngine,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
        mut completion: Option<&mut crate::application_sources::CompletionLoan<'_>>,
    ) -> anyhow::Result<()> {
        let Self {
            position,
            response,
            owner,
        } = self;
        match owner {
            OutcomeOwner::Candidate(accepted) => {
                accepted.require_publication(engine, Some(position))?;
                if let Some(completion) = completion.as_mut() {
                    let candidate = accepted.candidate();
                    let Some(selection) = completion.publish_source(
                        position,
                        response,
                        publisher,
                        candidate.state.retired,
                    )?
                    else {
                        return Ok(());
                    };
                    candidate
                        .application_selection
                        .set(selection)
                        .map_err(|_| {
                            anyhow::anyhow!("candidate application selection already installed")
                        })?;
                    #[cfg(test)]
                    completion.checkpoint(
                        crate::application_sources::completion::CompletionCheckpoint::Installed,
                    )?;
                    accepted.publish();
                    #[cfg(test)]
                    completion.checkpoint(
                        crate::application_sources::completion::CompletionCheckpoint::Visible,
                    )?;
                    Ok(())
                } else {
                    anyhow::ensure!(
                        engine.application_sources.get().is_none(),
                        "ordinary source publication requires installed completion"
                    );
                    engine.publish_prepared_generation(
                        accepted,
                        response,
                        Some(position),
                        publisher,
                    )
                }
            }
            OutcomeOwner::Frozen(apply) => {
                apply.require_engine(engine)?;
                anyhow::ensure!(
                    engine.application_sources.get().is_none() || completion.is_some(),
                    "ordinary frozen publication requires installed completion"
                );
                // Explicit use after callback keeps the actual guard through
                // success, error and unwind. No candidate is invented.
                let outcome = publisher.commit(response, &[]);
                drop(apply);
                if completion.is_some() {
                    // The actual completion publisher keeps any original sink
                    // failure; its fixed notification needs no new error box.
                    Ok(())
                } else {
                    outcome.map_err(Into::into)
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn accepted(&self) -> anyhow::Result<&AcceptedGeneration<'engine>> {
        match &self.owner {
            OutcomeOwner::Candidate(accepted) => Ok(accepted),
            OutcomeOwner::Frozen(_) => anyhow::bail!("ordered command has no accepted candidate"),
        }
    }
    #[cfg(test)]
    pub(super) fn position(&self) -> &'entry kasumi_raft::AppliedEntryContext {
        self.position
    }
    #[cfg(test)]
    pub(super) fn response(&self) -> &kasumi_raft::AppliedResponse {
        &self.response
    }
    #[cfg(test)]
    pub(super) fn omit_primary_id_for_test(&mut self, name: &str, id: &str) {
        match &mut self.owner {
            OutcomeOwner::Candidate(accepted) => accepted.omit_primary_id_for_test(name, id),
            OutcomeOwner::Frozen(_) => panic!("test candidate absent"),
        }
    }
    // This consumes the actual factory result. It cannot construct/reassemble
    // an owner from raw parts and does not promote test primary graph authority.
    #[cfg(test)]
    pub(super) fn into_primary_test_parts(
        self,
    ) -> anyhow::Result<(
        AcceptedGeneration<'engine>,
        &'entry kasumi_raft::AppliedEntryContext,
        kasumi_raft::AppliedResponse,
    )> {
        let Self {
            position,
            response,
            owner,
        } = self;
        match owner {
            OutcomeOwner::Candidate(accepted) => Ok((accepted, position, response)),
            OutcomeOwner::Frozen(_) => anyhow::bail!("test primary candidate absent"),
        }
    }
}

struct OrdinaryAction<'engine, 'entry> {
    engine: &'engine TenantEngine,
    input: Option<ByteBoundCommand<'entry>>,
    sources: &'engine crate::application_sources::SourceRootsRef,
}
impl kasumi_raft::CompletionAction for OrdinaryAction<'_, '_> {
    fn run(
        &mut self,
        invocation: &kasumi_raft::CompletionInvocation<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        let mut completion = self.sources.completion()?.enter(invocation)?;
        let input = self
            .input
            .take()
            .context("ordinary completion action repeated")?;
        let retained_input = if let Some(input_loan) = invocation.input_retention() {
            let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
                self.sources.memory_owner().clone();
            input_loan
                .require_memory(&memory)
                .map_err(|_| anyhow::anyhow!("apply input memory owner differs"))?;
            input_loan
                .require_bytes(input.position.log_id, input.bytes)
                .map_err(|_| {
                    anyhow::anyhow!("apply input differs from its accepted encoded owner")
                })?;
            Some(input_loan.retained_input())
        } else {
            // Explicit unsupported producer frontier: transport, stored and
            // reopen entries have no encoded-input custody bank in this cut.
            // Their old model remains unproved; this does not donate credit.
            None
        };
        // Decode/reducer and its borrowed guard begin only inside the actual
        // installed invocation, and end on this same worker before outer finish.
        let prepared =
            PreparedOrderedCommand::prepare_with_input(self.engine, input, retained_input)?;
        prepared
            .publish_inner(self.engine, publisher, Some(&mut completion))
            .map_err(Into::into)
    }
}
pub(super) fn apply_ordinary(
    engine: &TenantEngine,
    input: ByteBoundCommand<'_>,
    publisher: &mut dyn kasumi_raft::ApplyPublisher,
) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
    let Some(sources) = engine.application_sources.get() else {
        return PreparedOrderedCommand::prepare(engine, input)?
            .publish(engine, publisher)
            .map_err(Into::into);
    };
    let expected = sources.completion()?.identity();
    let mut action = OrdinaryAction {
        engine,
        input: Some(input),
        sources,
    };
    match publisher.with_completion(expected, &mut action) {
        Ok(()) | Err(kasumi_raft::CompletionCallError::Recorded) => Ok(()),
        Err(error) => Err(kasumi_store::ScratchOperationFailure::Operation(
            error.into(),
        )),
    }
}
