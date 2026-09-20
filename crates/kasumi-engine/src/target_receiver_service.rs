//! Current Control invocation, actual target quorum and immutable point-prefix
//! observations retained through final encoding. Missing rows never prove a seal.
use super::*;
use crate::state::target::{MAX_COMMAND_BYTES, TargetCommand, TargetOutcome};
use crate::{TargetOperation, target_invocation::TargetReleaseFence};

#[derive(Clone)]
enum Request {
    Prepare(TargetCompletionInput),
    Inspect(Box<TargetCompletionAttemptStatusInput>),
    InspectTerminal(Box<TargetCompletionTerminalStatusInput>),
    Resolve(Box<TargetCompletionResolutionInput>),
    Budget(TargetResolutionBudgetInput),
}
impl Request {
    fn phase(&self) -> LifecyclePhase {
        match self {
            Self::Prepare(_) => LifecyclePhase::Complete,
            Self::Inspect(_) => LifecyclePhase::InspectCompletionAttempt,
            Self::InspectTerminal(_) => LifecyclePhase::InspectCompletionResolution,
            Self::Resolve(_) => LifecyclePhase::ResolveComplete,
            Self::Budget(_) => LifecyclePhase::MaintainTarget,
        }
    }
    fn digest(&self) -> Result<String> {
        match self {
            Self::Prepare(value) => value.digest(),
            Self::Inspect(value) => value.digest(),
            Self::InspectTerminal(value) => value.digest(),
            Self::Resolve(value) => value.digest(),
            Self::Budget(value) => value.digest(),
        }
    }
    fn command(
        &self,
        authorization: crate::target_invocation::PreparedTargetAuthorization,
    ) -> Result<TargetCommand> {
        Ok(match self {
            Self::Inspect(_) | Self::InspectTerminal(_) => {
                return Err(denied("receiver status cannot propose mutations"));
            }
            Self::Prepare(input) => TargetCommand::PrepareComplete {
                authorization,
                input: input.clone(),
            },
            Self::Resolve(input) => TargetCommand::ResolveComplete {
                authorization,
                input: input.clone(),
            },
            Self::Budget(input) => TargetCommand::MaintainBudget {
                authorization,
                input: input.clone(),
            },
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
enum Fact {
    Prepared(Box<TargetCompletionAttempt>),
    Resolved(Box<TargetCompletionResolutionFact>),
    Budget(Box<TargetResolutionBudgetFact>),
}
pub struct VerifiedTargetReceiver {
    database: Arc<Database>,
    request: Request,
    fact: Fact,
    intent: LifecycleIntent,
    node: u64,
    revision: u64,
    term: u64,
    release: TargetReleaseFence,
    _reservation: Reservation,
}
impl VerifiedTargetReceiver {
    pub fn preparation(&self) -> Result<TargetCompletionAttemptObservation> {
        if !matches!(&self.request, Request::Prepare(_)) {
            return Err(invalid(
                "a status proof cannot become an original preparation observation",
            ));
        }
        let observation = TargetCompletionAttemptObservation {
            attempt: self.prepared()?.clone(),
            observer_node_id: self.node,
            observed_revision: self.revision,
            observed_term: self.term,
        };
        observation.validate()?;
        Ok(observation)
    }
    pub fn attempt_status(&self) -> Result<TargetCompletionAttemptStatusObservation> {
        let Request::Inspect(input) = &self.request else {
            return Err(invalid(
                "receiver proof is not a preparation status observation",
            ));
        };
        let observation = TargetCompletionAttemptStatusObservation {
            input: *input.clone(),
            status_intent: self.intent.clone(),
            attempt: self.prepared()?.clone(),
            observer_node_id: self.node,
            observed_revision: self.revision,
            observed_term: self.term,
        };
        observation.validate()?;
        Ok(observation)
    }
    pub fn prepared(&self) -> Result<&TargetCompletionAttempt> {
        match &self.fact {
            Fact::Prepared(value) => Ok(value),
            _ => Err(invalid("receiver proof is not preparation")),
        }
    }
    pub fn resolution(&self) -> Result<TargetCompletionResolutionObservation> {
        if !matches!(&self.request, Request::Resolve(_)) {
            return Err(invalid(
                "terminal status cannot become a resolver observation",
            ));
        }
        let Fact::Resolved(fact) = &self.fact else {
            return Err(invalid("receiver proof is not terminal resolution"));
        };
        let observation = TargetCompletionResolutionObservation {
            fact: *fact.clone(),
            observation_intent: self.intent.clone(),
            observer_node_id: self.node,
            observed_revision: self.revision,
            observed_term: self.term,
        };
        observation.validate()?;
        Ok(observation)
    }
    pub fn terminal_status(&self) -> Result<TargetCompletionTerminalStatusObservation> {
        let (Request::InspectTerminal(input), Fact::Resolved(fact)) = (&self.request, &self.fact)
        else {
            return Err(invalid("receiver proof is not a terminal-only status"));
        };
        let observation = TargetCompletionTerminalStatusObservation {
            input: *input.clone(),
            status_intent: self.intent.clone(),
            fact: *fact.clone(),
            observer_node_id: self.node,
            observed_revision: self.revision,
            observed_term: self.term,
        };
        observation.validate()?;
        Ok(observation)
    }
    pub fn budget(&self) -> Result<TargetResolutionBudgetObservation> {
        let Fact::Budget(fact) = &self.fact else {
            return Err(invalid("receiver proof is not budget maintenance"));
        };
        let observation = TargetResolutionBudgetObservation {
            fact: *fact.clone(),
            observation_intent: self.intent.clone(),
            observer_node_id: self.node,
            observed_revision: self.revision,
            observed_term: self.term,
        };
        observation.validate()?;
        Ok(observation)
    }
    pub async fn release(&self, operation: &TargetOperation) -> Result<()> {
        self.release.check(operation).map_err(unknown)?;
        let fresh = self
            .database
            .receiver_observation(operation, self.request.clone())
            .await
            .map_err(unknown)?;
        if fresh.fact != self.fact
            || fresh.intent != self.intent
            || fresh.node != self.node
            || fresh.term != self.term
            || fresh.revision < self.revision
        {
            return Err(unknown(
                "receiver quorum or original effect changed during release",
            ));
        }
        self.release.check(operation).map_err(unknown)
    }
}
impl Database {
    fn receiver_fact(
        &self,
        operation: &TargetOperation,
        request: &Request,
    ) -> Result<Option<Fact>> {
        let _point = self
            .admission()
            .reserve(4 << 20, Some(operation.token.clone()))?;
        self.target_phase_access(operation, request.phase())?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        let intent = &lease.commitment().intent;
        if intent.request.phase_input_sha256 != request.digest()? {
            return Err(invalid(
                "receiver input differs from original committed phase",
            ));
        }
        let generation = self.engine.generation()?;
        let state = &generation.state;
        let origin = &state
            .target_lifecycle
            .get(&state.incarnation)
            .ok_or_else(|| denied("target origin absent"))?
            .origin;
        let point = |key: String| -> Result<Option<TargetResolutionRecord>> {
            generation
                .target_resolutions
                .get(&key)
                .map(|row| row.map(|row| row.record))
                .map_err(unknown)
        };
        match request {
            Request::InspectTerminal(input) => {
                input.validate(origin, intent)?;
                let selected = generation
                    .target_resolutions
                    .terminal_fact(
                        state,
                        input.original_input.attempt.intent.request.command_id,
                    )
                    .map_err(unknown)?;
                if let Some(fact) = selected {
                    input.matches(&fact)?;
                    Ok(Some(Fact::Resolved(fact)))
                } else {
                    Ok(None)
                }
            }
            Request::Inspect(input) => {
                input.validate(origin, intent)?;
                let attempt = generation
                    .target_resolutions
                    .prepared_attempt(state, input.original_intent.request.command_id)
                    .map_err(unknown)?;
                if let Some(attempt) = attempt {
                    input.matches(&attempt)?;
                    Ok(Some(Fact::Prepared(attempt)))
                } else {
                    Ok(None)
                }
            }
            Request::Prepare(input) => {
                input.validate(origin, intent)?;
                let active = state
                    .target_completion_head
                    .as_ref()
                    .and_then(|head| head.active.as_ref());
                let historical = point(format!(
                    "completion/{}/{}",
                    state.incarnation, intent.request.command_id
                ))?;
                let attempt = match historical {
                    Some(TargetResolutionRecord::Completion(fact)) => Some(fact.input.attempt),
                    None => active.cloned(),
                    _ => return Err(unknown("preparation point kind differs")),
                };
                if let Some(attempt) = attempt {
                    if attempt.intent != *intent || attempt.input != *input {
                        return Err(invalid("preparation is for another original attempt"));
                    }
                    let now = operation
                        .invocation()
                        .gate()
                        .admission_time_ms()
                        .map_err(denied)?;
                    if attempt.dispatch_not_after_ms
                        != operation
                            .prepare(LifecyclePhase::Complete, &input.digest()?, now)?
                            .dispatch_not_after_ms
                    {
                        return Err(invalid(
                            "preparation replay changed the original dispatch cap",
                        ));
                    }
                    attempt.validate()?;
                    Ok(Some(Fact::Prepared(attempt)))
                } else {
                    Ok(None)
                }
            }
            Request::Resolve(input) => {
                input.validate(origin, intent)?;
                match point(format!(
                    "completion/{}/{}",
                    state.incarnation, input.attempt.intent.request.command_id
                ))? {
                    Some(TargetResolutionRecord::Completion(fact)) if fact.input == **input => {
                        Ok(Some(Fact::Resolved(fact)))
                    }
                    None => Ok(None),
                    _ => Err(invalid(
                        "terminal resolution differs from exact original attempt",
                    )),
                }
            }
            Request::Budget(input) => {
                input.validate(origin, intent)?;
                match point(format!(
                    "budget/{}/{}",
                    state.incarnation, input.operation_id
                ))? {
                    Some(TargetResolutionRecord::Budget(fact)) if fact.input == *input => {
                        Ok(Some(Fact::Budget(fact)))
                    }
                    None => Ok(None),
                    _ => Err(invalid("permanent budget identity changed")),
                }
            }
        }
    }
    async fn receiver_observation(
        self: &Arc<Self>,
        operation: &TargetOperation,
        request: Request,
    ) -> Result<VerifiedTargetReceiver> {
        let reservation = self
            .admission()
            .reserve(4 << 20, Some(operation.token.clone()))?;
        self.target_phase_access(operation, request.phase())?;
        operation
            .run(self.group.linearizable_barrier())
            .await
            .map_err(denied)?;
        let fact = self
            .receiver_fact(operation, &request)?
            .ok_or_else(|| unknown("receiver outcome is not positively committed"))?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let generation = self.engine.generation()?;
        let origin = &generation.state.target_lifecycle[&generation.state.incarnation].origin;
        let membership = metrics.membership_config.membership();
        if metrics.current_leader != Some(metrics.id)
            || membership.get_joint_config() != &vec![origin.input.voters.keys().copied().collect()]
            || membership.nodes().count() != origin.input.voters.len()
            || membership.nodes().any(|(id, node)| {
                origin
                    .input
                    .voters
                    .get(id)
                    .is_none_or(|peer| peer.endpoint != node.addr)
            })
        {
            return Err(denied("actual receiver quorum changed"));
        }
        let intent = operation
            .invocation()
            .gate()
            .current()
            .map_err(denied)?
            .commitment()
            .intent
            .clone();
        let proof = VerifiedTargetReceiver {
            database: self.clone(),
            request,
            fact,
            intent,
            node: metrics.id,
            revision: generation.state.revision,
            term: metrics.current_term,
            release: operation.release_fence(),
            _reservation: reservation,
        };
        match &proof.fact {
            Fact::Prepared(attempt) => {
                if attempt.revision > proof.revision || attempt.position.term > proof.term {
                    return Err(unknown("prepared target position exceeds current quorum"));
                }
                if matches!(&proof.request, Request::Inspect(_)) {
                    proof.attempt_status()?;
                }
            }
            Fact::Resolved(_) => {
                if matches!(&proof.request, Request::InspectTerminal(_)) {
                    proof.terminal_status()?;
                } else {
                    proof.resolution()?;
                }
            }
            Fact::Budget(_) => {
                proof.budget()?;
            }
        }
        self.target_phase_access(operation, proof.request.phase())?;
        Ok(proof)
    }
    async fn receiver_request(
        self: &Arc<Self>,
        operation: &TargetOperation,
        request: Request,
    ) -> Result<VerifiedTargetReceiver> {
        self.target_phase_access(operation, request.phase())?;
        // Re-observing a positively present permanent fact consumes no new hot
        // audit record and remains possible at the retained hot budget ceiling.
        if self.receiver_fact(operation, &request)?.is_none() {
            let worker = Proposal {
                database: self.clone(),
                operation: operation.clone(),
                request: request.clone(),
                _reservation: self.admission().reserve(
                    (MAX_COMMAND_BYTES * 4 + (16 << 20)) as u64,
                    Some(operation.token.clone()),
                )?,
                _registration: self.work.begin(operation.token.clone())?,
            };
            let task = tokio::spawn(worker.run());
            operation
                .run(async { task.await? })
                .await
                .map_err(unknown)??;
        }
        let proof = self
            .receiver_observation(operation, request)
            .await
            .map_err(unknown)?;
        proof.release(operation).await?;
        Ok(proof)
    }
    pub async fn prepare_target_completion(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetCompletionInput,
    ) -> Result<VerifiedTargetReceiver> {
        self.receiver_request(operation, Request::Prepare(input))
            .await
    }
    /// Positive read-only recovery of the exact original reservation under a
    /// distinct current Control phase. Absence returns UnknownOutcome.
    pub async fn inspect_target_completion_attempt(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetCompletionAttemptStatusInput,
    ) -> Result<VerifiedTargetReceiver> {
        let proof = self
            .receiver_observation(operation, Request::Inspect(Box::new(input)))
            .await?;
        proof.release(operation).await?;
        Ok(proof)
    }
    /// Fresh read-only recovery of an exact positive original resolver fact.
    /// Absence is UnknownOutcome and never dispatches another resolver.
    pub async fn inspect_target_completion_terminal(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetCompletionTerminalStatusInput,
    ) -> Result<VerifiedTargetReceiver> {
        let proof = self
            .receiver_observation(operation, Request::InspectTerminal(Box::new(input)))
            .await?;
        proof.release(operation).await?;
        Ok(proof)
    }
    pub async fn resolve_target_completion(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetCompletionResolutionInput,
    ) -> Result<VerifiedTargetReceiver> {
        self.receiver_request(operation, Request::Resolve(Box::new(input)))
            .await
    }
    pub async fn maintain_target_resolution_budget(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetResolutionBudgetInput,
    ) -> Result<VerifiedTargetReceiver> {
        self.receiver_request(operation, Request::Budget(input))
            .await
    }
}
struct Proposal {
    database: Arc<Database>,
    operation: TargetOperation,
    request: Request,
    _reservation: Reservation,
    _registration: WorkRegistration,
}
impl Proposal {
    async fn run(self) -> anyhow::Result<Result<()>> {
        let _guard = self
            .operation
            .run(async { Ok(self.database.proposal_gate.clone().lock_owned().await) })
            .await?;
        self.database
            .target_phase_access(&self.operation, self.request.phase())?;
        let now = self.operation.invocation().gate().admission_time_ms()?;
        let authorization =
            self.operation
                .prepare(self.request.phase(), &self.request.digest()?, now)?;
        let bytes = self
            .database
            .group
            .write(self.request.command(authorization)?.encode()?)
            .await?;
        let outcome = serde_json::from_slice::<Result<TargetOutcome>>(&bytes)?;
        match (&self.request, outcome) {
            (Request::Prepare(_), Ok(TargetOutcome::Prepared(_)))
            | (Request::Resolve(_), Ok(TargetOutcome::Resolved(_)))
            | (Request::Budget(_), Ok(TargetOutcome::Budget(_))) => {
                self.database
                    .target_phase_access(&self.operation, self.request.phase())
                    .map_err(unknown)?;
                Ok(Ok(()))
            }
            (_, Err(error)) => Ok(Err(error)),
            _ => Ok(Err(unknown("receiver response kind differs"))),
        }
    }
}
fn invalid(_: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Conflict, "target receiver exact input differs")
}
fn denied(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unauthorized,
        "current Control target authority unavailable",
    )
}
fn unknown(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "target receiver outcome requires positive exact resolution",
    )
}
