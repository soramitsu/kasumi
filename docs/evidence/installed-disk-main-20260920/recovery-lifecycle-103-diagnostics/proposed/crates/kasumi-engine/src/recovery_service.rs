//! Current-quorum recovery administration and exact journal dispatch admission.
use super::*;
use crate::state::recovery::{
    self, MAX_COMMAND_BYTES, RecoveryAuthorization, RecoveryCommand, RecoveryMutation,
};
use uuid::Uuid;

pub struct VerifiedRecoveryStatus {
    database: Arc<Database>,
    context: RequestContext,
    record: RecoveryRecord,
    policy_epoch: u64,
    term: u64,
    _reservation: Reservation,
}
impl VerifiedRecoveryStatus {
    pub fn record(&self) -> &RecoveryRecord {
        &self.record
    }
    pub async fn release(&self) -> Result<()> {
        self.database
            .recovery_release(&self.context, self.policy_epoch, self.term)
            .await
    }
}
/// The serialized phase is history. admit_dispatch separately checks current
/// Control authority and the original phase deadline before any remote effect.
pub struct VerifiedRecoveryPhase {
    database: Arc<Database>,
    context: RequestContext,
    record: RecoveryPhaseRecord,
    policy_epoch: u64,
    term: u64,
    _reservation: Reservation,
}
impl VerifiedRecoveryPhase {
    pub fn record(&self) -> &RecoveryPhaseRecord {
        &self.record
    }
    pub async fn release(&self) -> Result<()> {
        self.database
            .recovery_release(&self.context, self.policy_epoch, self.term)
            .await
    }
    pub async fn dispatch_limit(&self) -> Result<u64> {
        self.release().await?;
        let state = self.database.engine.generation()?;
        let operation = state
            .state
            .recovery_control
            .operations
            .get(&self.record.operation_id.to_string())
            .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
        recovery::dispatch_limit(operation, &self.record)
    }
    /// Current finite wait allowance, measured using the same installed clock as
    /// dispatch admission. It never changes a recorded target command deadline.
    pub async fn dispatch_remaining(&self) -> Result<std::time::Duration> {
        self.admit_dispatch().await?;
        let limit = self.dispatch_limit().await?.min(
            self.context.authorization.expires_at_ms().ok_or_else(|| {
                error(
                    ErrorCode::Forbidden,
                    "recovery dispatch requires finite authorization",
                )
            })?,
        );
        let limit = match &self.record.input {
            RecoveryDispatch::Authority(command) => limit.min(command.not_after_ms),
            RecoveryDispatch::Target { request, .. } => limit.min(request.not_after_ms),
            RecoveryDispatch::RetireSource(request) => limit.min(request.not_after_ms),
            _ => limit,
        };
        let remaining = limit.saturating_sub(self.database.lifecycle_now()?);
        if remaining == 0 {
            return Err(error(
                ErrorCode::Conflict,
                "original recovery dispatch expired",
            ));
        }
        Ok(std::time::Duration::from_millis(remaining))
    }
    pub async fn admit_dispatch(&self) -> Result<()> {
        self.release().await?;
        let current = self.database.engine.generation()?;
        let head = current
            .state
            .recovery_control
            .operations
            .get(&self.record.operation_id.to_string())
            .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
        let phase = recovery::phase(&current.state, head, self.record.phase_id)?;
        let limit = recovery::dispatch_limit(head, &self.record)?;
        let limit = match &phase.input {
            RecoveryDispatch::Authority(command) => limit.min(command.not_after_ms),
            RecoveryDispatch::Target { request, .. } => limit.min(request.not_after_ms),
            RecoveryDispatch::RetireSource(request) => limit.min(request.not_after_ms),
            _ => limit,
        };
        if head.pending_phase != Some(self.record.phase_id)
            || phase.input_sha256 != self.record.input_sha256
            || phase.outcome.is_some()
            || self.database.lifecycle_now()? >= limit
        {
            return Err(error(
                ErrorCode::Conflict,
                "original recovery dispatch is no longer eligible",
            ));
        }
        self.context.authorization.check_live()
    }
}
impl Database {
    async fn recovery_release(
        &self,
        context: &RequestContext,
        epoch: u64,
        term: u64,
    ) -> Result<()> {
        if self.lifecycle_barrier(context).await? != term {
            return Err(error(
                ErrorCode::Unavailable,
                "recovery response quorum term changed",
            ));
        }
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        context.authorization.check_live()?;
        self.access()
    }
    pub async fn recovery_status(
        self: &Arc<Self>,
        context: RequestContext,
        operation_id: Uuid,
    ) -> Result<VerifiedRecoveryStatus> {
        let _work = self.work.begin(QueryCancellation::default())?;
        let mut reservation = self
            .admission()
            .reserve((MAX_RECOVERY_RECORD_BYTES * 2) as u64, None)?;
        let term = self.lifecycle_barrier(&context).await?;
        let state = self.engine.generation()?;
        let record = state
            .state
            .recovery_control
            .operations
            .get(&operation_id.to_string())
            .cloned()
            .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
        let policy_epoch = state.state.policy_epoch;
        drop(state);
        self.control_observation_audit(
            &context,
            operation_id,
            record.request_sha256.clone(),
            record.updated_revision,
            policy_epoch,
        )
        .await?;
        reservation.retain_workspace();
        let result = VerifiedRecoveryStatus {
            database: self.clone(),
            context,
            record,
            policy_epoch,
            term,
            _reservation: reservation,
        };
        result.release().await?;
        Ok(result)
    }
    pub async fn recovery_phase(
        self: &Arc<Self>,
        context: RequestContext,
        operation_id: Uuid,
        phase_id: Uuid,
    ) -> Result<VerifiedRecoveryPhase> {
        let _work = self.work.begin(QueryCancellation::default())?;
        let mut reservation = self
            .admission()
            .reserve((MAX_RECOVERY_RECORD_BYTES * 2) as u64, None)?;
        let term = self.lifecycle_barrier(&context).await?;
        let state = self.engine.generation()?;
        let record = state
            .state
            .recovery_control
            .phases
            .get(&recovery::phase_key(operation_id, phase_id))
            .filter(|record| record.operation_id == operation_id)
            .cloned()
            .ok_or_else(|| error(ErrorCode::NotFound, "recovery phase absent"))?;
        let policy_epoch = state.state.policy_epoch;
        drop(state);
        self.control_observation_audit(
            &context,
            phase_id,
            record.input_sha256.clone(),
            record.prepared_revision,
            policy_epoch,
        )
        .await?;
        reservation.retain_workspace();
        let result = VerifiedRecoveryPhase {
            database: self.clone(),
            context,
            record,
            policy_epoch,
            term,
            _reservation: reservation,
        };
        result.release().await?;
        Ok(result)
    }
    pub async fn recovery_control(
        self: &Arc<Self>,
        context: RequestContext,
        request: RecoveryControlCommand,
    ) -> Result<VerifiedRecoveryStatus> {
        let (operation_id, mutation) = match request {
            RecoveryControlCommand::Start(request) => {
                (request.operation_id, RecoveryMutation::Start(request))
            }
            RecoveryControlCommand::Stop {
                operation_id,
                command_id,
            } => (
                operation_id,
                RecoveryMutation::Stop {
                    operation_id,
                    command_id,
                },
            ),
        };
        self.recovery_write(context.clone(), mutation).await?;
        self.recovery_status(context, operation_id)
            .await
            .map_err(|cause| unknown("status after recovery control write", cause))
    }
    /// Internal coordinator boundary. No native RPC accepts a caller-supplied
    /// phase input or outcome; the reducer checks the installed workflow again.
    pub async fn prepare_recovery_dispatch(
        self: &Arc<Self>,
        context: RequestContext,
        operation_id: Uuid,
        phase_id: Uuid,
        expected_sequence: u64,
        expected_pending: Option<Uuid>,
        input: RecoveryDispatch,
    ) -> Result<VerifiedRecoveryPhase> {
        self.recovery_write(
            context.clone(),
            RecoveryMutation::Prepare {
                operation_id,
                phase_id,
                expected_sequence,
                expected_pending,
                input: Box::new(input),
            },
        )
        .await?;
        self.recovery_phase(context, operation_id, phase_id)
            .await
            .map_err(|cause| unknown("phase after recovery prepare write", cause))
    }
    pub async fn resolve_recovery_dispatch(
        self: &Arc<Self>,
        context: RequestContext,
        operation_id: Uuid,
        phase_id: Uuid,
        outcome: RecoveryDispatchOutcome,
    ) -> Result<VerifiedRecoveryStatus> {
        self.recovery_write(
            context.clone(),
            RecoveryMutation::Resolve {
                operation_id,
                phase_id,
                outcome: Box::new(outcome),
            },
        )
        .await?;
        self.recovery_status(context, operation_id)
            .await
            .map_err(|cause| unknown("status after recovery resolve write", cause))
    }
    /// Closed local publication: topology CAS and permanent phase outcome commit
    /// together. Replaying a completed phase does not touch current topology.
    pub async fn publish_recovery_route(
        self: &Arc<Self>,
        context: RequestContext,
        operation_id: Uuid,
        phase_id: Uuid,
    ) -> Result<VerifiedRecoveryPhase> {
        self.recovery_write(
            context.clone(),
            RecoveryMutation::PublishRoute {
                operation_id,
                phase_id,
            },
        )
        .await?;
        self.recovery_phase(context, operation_id, phase_id)
            .await
            .map_err(|cause| unknown("phase after recovery route write", cause))
    }
    async fn recovery_write(
        self: &Arc<Self>,
        context: RequestContext,
        mutation: RecoveryMutation,
    ) -> Result<RecoveryRecord> {
        let term = self.lifecycle_barrier(&context).await?;
        let policy_epoch = self.engine.generation()?.state.policy_epoch;
        let expires_at_ms = context.authorization.expires_at_ms().ok_or_else(|| {
            error(
                ErrorCode::Unauthorized,
                "recovery requires a finite original credential",
            )
        })?;
        let authorization = RecoveryAuthorization {
            context: context.clone(),
            policy_epoch,
            admitted_at_ms: u64::MAX,
            expires_at_ms,
        };
        let command = RecoveryCommand {
            authorization,
            mutation,
        };
        command.encode()?;
        let mut workspace = (MAX_COMMAND_BYTES * 4) as u64;
        if let RecoveryMutation::PublishRoute {
            operation_id,
            phase_id,
        } = &command.mutation
        {
            let current = self.engine.generation()?;
            let operation = current
                .state
                .recovery_control
                .operations
                .get(&operation_id.to_string())
                .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
            let prepared = recovery::phase(&current.state, operation, *phase_id)?;
            if prepared.outcome.is_none() {
                workspace = workspace
                    .checked_add(recovery::route::workspace(&current.state)?)
                    .ok_or_else(|| {
                        error(
                            ErrorCode::ResourceExhausted,
                            "route publication workspace overflow",
                        )
                    })?;
            }
        }
        let reservation = self.admission().reserve(workspace, None)?;
        let registration = self.work.begin(QueryCancellation::default())?;
        let worker = RecoveryProposal {
            database: self.clone(),
            command,
            term,
            _reservation: reservation,
            _registration: registration,
        };
        let result = tokio::time::timeout(Duration::from_secs(10), tokio::spawn(worker.run()))
            .await
            .map_err(|cause| unknown("recovery proposal deadline", cause))?
            .map_err(|cause| unknown("recovery proposal task join", cause))?
            .map_err(|cause| unknown("recovery proposal worker", cause))??;
        self.recovery_release(&context, policy_epoch, term)
            .await
            .map_err(|cause| unknown("release after recovery proposal", cause))?;
        Ok(result)
    }
    /// Build the next bounded semantic input using the same current Control
    /// admission. The returned DTO grants nothing until prepare commits it.
    pub async fn next_recovery_dispatch(
        self: &Arc<Self>,
        context: &RequestContext,
        operation_id: Uuid,
        phase_id: Uuid,
    ) -> Result<Option<RecoveryDispatch>> {
        let _work = self.work.begin(QueryCancellation::default())?;
        self.lifecycle_barrier(context).await?;
        let now = self.lifecycle_now()?;
        let expires = context.authorization.expires_at_ms().ok_or_else(|| {
            error(
                ErrorCode::Unauthorized,
                "finite recovery credential required",
            )
        })?;
        let current = self.engine.generation()?;
        let state = &current.state;
        let operation = state
            .recovery_control
            .operations
            .get(&operation_id.to_string())
            .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
        if operation.phase.terminal() {
            return Ok(None);
        }
        let workspace = if operation.phase == RecoveryPhase::Publish {
            recovery::route::workspace(state)?
        } else {
            0
        };
        let _reservation = self.admission().reserve(
            workspace
                .checked_add((MAX_RECOVERY_RECORD_BYTES * 4) as u64)
                .ok_or_else(|| {
                    error(
                        ErrorCode::ResourceExhausted,
                        "recovery planning workspace overflow",
                    )
                })?,
            None,
        )?;
        if let Some(id) = operation.pending_phase {
            let pending = recovery::phase(state, operation, id)?;
            if matches!(pending.input, RecoveryDispatch::PublishRoute(_))
                && now >= recovery::dispatch_limit(operation, pending)?
            {
                return Ok(Some(RecoveryDispatch::PublishRoute(
                    recovery::route::next_input(state, operation)?,
                )));
            }
            if let RecoveryDispatch::Target { node_id, request } = &pending.input
                && matches!(
                    operation.phase,
                    RecoveryPhase::Complete | RecoveryPhase::Confirm
                )
                && now < request.not_after_ms
                && (recovery::quorum::established_effect(&request.step)
                    || (operation.phase == RecoveryPhase::Complete
                        && recovery::quorum::established_start(&request.step))
                    || matches!(request.step, TargetRuntimeStep::Activate { .. }))
            {
                let next = if operation.phase == RecoveryPhase::Complete {
                    recovery::quorum::retry_destination(
                        state,
                        operation,
                        request.command_id,
                        *node_id,
                        &request.step,
                    )?
                } else {
                    operation
                        .voters
                        .keys()
                        .copied()
                        .find(|id| id > node_id)
                        .or_else(|| operation.voters.keys().next().copied())
                        .ok_or_else(|| error(ErrorCode::Corruption, "recovery voters absent"))?
                };
                return Ok(Some(RecoveryDispatch::Target {
                    node_id: next,
                    request: request.clone(),
                }));
            }
            if let RecoveryDispatch::Authority(command) = &pending.input
                && operation.phase == RecoveryPhase::Activate
                && now >= command.not_after_ms
                && matches!(command.action, AuthorityAction::ActivateCommitted { .. })
            {
                return Ok(Some(recovery::activation::authority_command(
                    operation,
                    phase_id,
                    AuthorityAction::StopActivation {
                        original: command.clone(),
                    },
                    now,
                    expires,
                )?));
            }
            let fresh_phase = match &pending.input {
                RecoveryDispatch::Target { request, .. } if now >= request.not_after_ms => {
                    match request.step {
                        TargetRuntimeStep::Materialize(_)
                        | TargetRuntimeStep::ResumeMaterialization(_) => {
                            LifecyclePhase::ResumeMaterialize
                        }
                        TargetRuntimeStep::Stop(_) => LifecyclePhase::StopLocal,
                        TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                        | TargetRuntimeStep::Initialize(_)
                            if operation.phase == RecoveryPhase::Initialize =>
                        {
                            LifecyclePhase::Initialize
                        }
                        TargetRuntimeStep::Start(_)
                        | TargetRuntimeStep::Complete(_)
                        | TargetRuntimeStep::PrepareComplete(_)
                        | TargetRuntimeStep::InspectCompletionAttempt(_)
                        | TargetRuntimeStep::InspectCompletionResolution(_)
                        | TargetRuntimeStep::ResolveComplete(_)
                        | TargetRuntimeStep::Inspect(_)
                            if operation.phase == RecoveryPhase::Complete =>
                        {
                            recovery::receiver::fresh_phase(state, operation)?
                        }
                        TargetRuntimeStep::StartActivation { .. }
                        | TargetRuntimeStep::Activate { .. }
                        | TargetRuntimeStep::ConfirmActivation(_)
                            if operation.phase == RecoveryPhase::Confirm =>
                        {
                            LifecyclePhase::Activate
                        }
                        _ => {
                            return Err(error(
                                ErrorCode::Conflict,
                                "pending phase has no fresh admission path",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(error(
                        ErrorCode::Conflict,
                        "resolve pending exact recovery phase before preparing another",
                    ));
                }
            };
            return Ok(Some(RecoveryDispatch::ControlIntent(Box::new(
                recovery::expected_intent(
                    state,
                    operation,
                    phase_id,
                    state.policy_epoch,
                    fresh_phase,
                )?,
            ))));
        }
        if let Some(id) = operation.last_phase {
            let previous = recovery::phase(state, operation, id)?;
            if previous.phase == operation.phase
                && matches!(&previous.outcome,Some(RecoveryDispatchOutcome::Authority(signed)) if matches!(signed.receipt.outcome,AuthorityOutcome::Rejected{..}))
            {
                return Err(error(
                    ErrorCode::Conflict,
                    "issuer rejected the exact recovery input; inspect its retained phase outcome",
                ));
            }
        }
        let input = match operation.phase {
            RecoveryPhase::Prepare | RecoveryPhase::StopTarget | RecoveryPhase::FenceSource => {
                let action = recovery::issuer_action(operation, operation.phase)?;
                RecoveryDispatch::Authority(Box::new(AuthorityCommand {
                    tenant: operation.request.tenant.clone(),
                    command_id: phase_id,
                    expected_policy_epoch: operation.request.authority_policy_epoch,
                    not_after_ms: now
                        .checked_add(operation.request.phase_timeout_ms)
                        .ok_or_else(|| {
                            error(ErrorCode::InvalidArgument, "phase deadline overflow")
                        })?
                        .min(expires),
                    action,
                }))
            }
            RecoveryPhase::Materialize | RecoveryPhase::Cleanup => {
                let current = operation
                    .current_intent
                    .map(|id| recovery::intent(state, operation, id))
                    .transpose()?;
                match current {
                    Some(current) if now < current.original_credential_expires_at_ms => {
                        let node_id = operation
                            .voters
                            .iter()
                            .find(|(_, v)| {
                                if operation.phase == RecoveryPhase::Materialize {
                                    v.materialization.is_none()
                                } else {
                                    v.cleanup.is_none()
                                }
                            })
                            .map(|(id, _)| *id)
                            .ok_or_else(|| {
                                error(
                                    ErrorCode::Corruption,
                                    "recovery phase has no unfinished voter",
                                )
                            })?;
                        let step = if operation.phase == RecoveryPhase::Cleanup {
                            TargetRuntimeStep::Stop(recovery::stop_reference(state, operation)?)
                        } else if current.request.phase == LifecyclePhase::ResumeMaterialize {
                            TargetRuntimeStep::ResumeMaterialization(Box::new(recovery::origin(
                                state, operation,
                            )?))
                        } else {
                            TargetRuntimeStep::Materialize(
                                operation.request.materialization.clone(),
                            )
                        };
                        RecoveryDispatch::Target {
                            node_id,
                            request: Box::new(TargetRuntimeRequest {
                                tenant: operation.request.tenant.clone(),
                                command_id: current.request.command_id,
                                not_after_ms: now
                                    .checked_add(operation.request.phase_timeout_ms)
                                    .ok_or_else(|| {
                                        error(
                                            ErrorCode::InvalidArgument,
                                            "recovery dispatch deadline overflow",
                                        )
                                    })?
                                    .min(expires)
                                    .min(current.original_credential_expires_at_ms),
                                step,
                            }),
                        }
                    }
                    _ => {
                        let phase = if operation.phase == RecoveryPhase::Cleanup {
                            LifecyclePhase::StopLocal
                        } else if operation.materialization_intent.is_none() {
                            LifecyclePhase::Materialize
                        } else {
                            LifecyclePhase::ResumeMaterialize
                        };
                        RecoveryDispatch::ControlIntent(Box::new(recovery::expected_intent(
                            state,
                            operation,
                            phase_id,
                            state.policy_epoch,
                            phase,
                        )?))
                    }
                }
            }

            RecoveryPhase::Activate | RecoveryPhase::Confirm | RecoveryPhase::StopActivation => {
                recovery::activation::next_dispatch(state, operation, phase_id, now, expires)?
            }
            RecoveryPhase::Publish => {
                RecoveryDispatch::PublishRoute(recovery::route::next_input(state, operation)?)
            }
            RecoveryPhase::RetireSource => {
                RecoveryDispatch::RetireSource(recovery::retirement_request(
                    operation,
                    now.checked_add(operation.request.phase_timeout_ms)
                        .ok_or_else(|| {
                            error(ErrorCode::InvalidArgument, "retirement deadline overflow")
                        })?
                        .min(expires),
                )?)
            }
            RecoveryPhase::Initialize | RecoveryPhase::Complete => {
                let kind = if operation.phase == RecoveryPhase::Initialize {
                    LifecyclePhase::Initialize
                } else {
                    LifecyclePhase::Complete
                };
                let current = operation
                    .current_intent
                    .map(|id| recovery::intent(state, operation, id))
                    .transpose()?;
                let preparation_cap = operation
                    .completion_preparation_attempt
                    .map(|_| {
                        recovery::receiver::status_input(state, operation)
                            .map(|input| input.original_dispatch_not_after_ms)
                    })
                    .transpose()?;
                let require_fresh = kind == LifecyclePhase::Complete
                    && current.is_some_and(|current| {
                        (operation.completion_terminal.is_some()
                            && current.request.phase != LifecyclePhase::InspectTarget)
                            || (operation.completion_preparation.is_some()
                                && current.request.phase
                                    == LifecyclePhase::InspectCompletionAttempt)
                            || (current.request.phase == LifecyclePhase::Complete
                                && preparation_cap.is_some_and(|cap| now >= cap))
                    });
                if require_fresh {
                    RecoveryDispatch::ControlIntent(Box::new(recovery::expected_intent(
                        state,
                        operation,
                        phase_id,
                        state.policy_epoch,
                        recovery::receiver::fresh_phase(state, operation)?,
                    )?))
                } else {
                    match current {
                        Some(current)
                            if kind == LifecyclePhase::Complete
                                && matches!(
                                    current.request.phase,
                                    LifecyclePhase::InspectCompletionAttempt
                                        | LifecyclePhase::InspectCompletionResolution
                                        | LifecyclePhase::ResolveComplete
                                )
                                && now < current.original_credential_expires_at_ms =>
                        {
                            recovery::receiver::next(state, operation, current, now, expires)?
                        }
                        Some(current)
                            if kind == LifecyclePhase::Complete
                                && current.request.phase == LifecyclePhase::InspectTarget
                                && now < current.original_credential_expires_at_ms =>
                        {
                            recovery::completion::next_inspection(
                                state, operation, current, now, expires,
                            )?
                        }
                        Some(current) if now < current.original_credential_expires_at_ms => {
                            let quorum = recovery::quorum_input(state, operation)?;
                            let (preferred_observer, mut missing) = if kind
                                == LifecyclePhase::Complete
                            {
                                let (node, startup) = recovery::quorum::established_destination(
                                    state,
                                    operation,
                                    current.request.command_id,
                                )?;
                                (Some(node), startup.then_some(node))
                            } else {
                                (None, None)
                            };
                            for id in operation
                                .voters
                                .keys()
                                .filter(|_| kind == LifecyclePhase::Initialize)
                            {
                                if !recovery::started_for(
                                    state,
                                    operation,
                                    *id,
                                    current.request.command_id,
                                )? {
                                    missing = Some(*id);
                                    break;
                                }
                            }
                            let (node_id, step) = if let Some(id) = missing {
                                (
                                    id,
                                    TargetRuntimeStep::Start(if kind == LifecyclePhase::Complete {
                                        TargetReplicaInput::Completion(
                                            recovery::completion::completion_input(
                                                state, operation,
                                            )?,
                                        )
                                    } else {
                                        TargetReplicaInput::Quorum(quorum)
                                    }),
                                )
                            } else {
                                let first = preferred_observer
                                    .or_else(|| operation.voters.keys().next().copied())
                                    .ok_or_else(|| {
                                        error(ErrorCode::Corruption, "recovery voters absent")
                                    })?;
                                (
                                    first,
                                    if kind == LifecyclePhase::Initialize {
                                        TargetRuntimeStep::Initialize(quorum)
                                    } else {
                                        let input = recovery::completion::completion_input(
                                            state, operation,
                                        )?;
                                        if operation.completion_preparation.is_some() {
                                            TargetRuntimeStep::Complete(input)
                                        } else {
                                            TargetRuntimeStep::PrepareComplete(input)
                                        }
                                    },
                                )
                            };
                            RecoveryDispatch::Target {
                                node_id,
                                request: Box::new(TargetRuntimeRequest {
                                    tenant: operation.request.tenant.clone(),
                                    command_id: current.request.command_id,
                                    not_after_ms: if matches!(step, TargetRuntimeStep::Complete(_))
                                    {
                                        let cap =
                                            recovery::receiver::status_input(state, operation)?
                                                .original_dispatch_not_after_ms;
                                        if cap > expires {
                                            return Err(error(
                                                ErrorCode::Forbidden,
                                                "current coordinator credential cannot cover the original completion dispatch",
                                            ));
                                        }
                                        cap
                                    } else {
                                        now.checked_add(operation.request.phase_timeout_ms)
                                            .ok_or_else(|| {
                                                error(
                                                    ErrorCode::InvalidArgument,
                                                    "recovery dispatch deadline overflow",
                                                )
                                            })?
                                            .min(expires)
                                            .min(current.original_credential_expires_at_ms)
                                    },
                                    step,
                                }),
                            }
                        }
                        Some(_) if kind == LifecyclePhase::Complete => {
                            RecoveryDispatch::ControlIntent(Box::new(recovery::expected_intent(
                                state,
                                operation,
                                phase_id,
                                state.policy_epoch,
                                recovery::receiver::fresh_phase(state, operation)?,
                            )?))
                        }
                        _ => RecoveryDispatch::ControlIntent(Box::new(recovery::expected_intent(
                            state,
                            operation,
                            phase_id,
                            state.policy_epoch,
                            kind,
                        )?)),
                    }
                }
            }
            _ => {
                return Err(error(
                    ErrorCode::Unavailable,
                    "recovery has reached a phase whose coordinator dispatcher is not installed",
                ));
            }
        };
        context.authorization.check_live()?;
        Ok(Some(input))
    }
}
struct RecoveryProposal {
    database: Arc<Database>,
    command: RecoveryCommand,
    term: u64,
    _reservation: Reservation,
    _registration: WorkRegistration,
}
impl RecoveryProposal {
    async fn run(mut self) -> anyhow::Result<Result<RecoveryRecord>> {
        let _gate = self.database.proposal_gate.clone().lock_owned().await;
        let authorization = &mut self.command.authorization;
        if let Err(error) = self
            .database
            .recovery_release(
                &authorization.context,
                authorization.policy_epoch,
                self.term,
            )
            .await
        {
            return Ok(Err(error));
        }
        authorization.admitted_at_ms = self.database.lifecycle_now()?;
        if authorization.admitted_at_ms >= authorization.expires_at_ms {
            return Ok(Err(error(
                ErrorCode::Unauthorized,
                "queued original recovery credential expired",
            )));
        }
        let bytes = self.database.group.write(self.command.encode()?).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
fn error(code: ErrorCode, message: &str) -> Error {
    Error::new(code, message)
}
fn unknown(_stage: &'static str, _cause: impl std::fmt::Display) -> Error {
    // Integration tests compile the library without cfg(test). Keep this
    // temporary cause trace behind their explicit test-utils feature as well.
    #[cfg(any(test, feature = "test-utils"))]
    eprintln!("kasumi-engine recovery unknown: stage={_stage}; cause={_cause:#}");
    error(
        ErrorCode::UnknownOutcome,
        "recovery effect may be committed; resolve its exact permanent operation and phase",
    )
}
