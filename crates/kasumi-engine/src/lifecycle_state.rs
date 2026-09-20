//! Ordered control commitments. This reducer is the only mutator of the closed
//! lifecycle installation; generic policy/retirement cannot invalidate grants.
use super::*;

fn conflict(message: &str) -> Error {
    Error::new(ErrorCode::Conflict, message)
}
fn hash<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(staged_digest(value)?.0)
}
fn same<T: serde::Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(hash(a)? == hash(b)?)
}
fn receipt(revision: u64) -> (Result<WriteReceipt>, bool) {
    (
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        false,
    )
}
fn exact_control(state: &TenantState, context: &RequestContext) -> Result<()> {
    if state.tenant != "__kasumi_control" || context.tenant != state.tenant {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "lifecycle control requires the installed control namespace",
        ));
    }
    context.authorization.require_control(&state.incarnation)?;
    authorize_state(state, context, None, Action::Admin)
}

pub(crate) fn guard(state: &TenantState, operation: &Operation) -> Result<()> {
    let Some(control) = &state.lifecycle_control else {
        return Ok(());
    };
    // Installation/signing keys and issuer membership are immutable for this
    // incarnation. A new installation cannot bypass draining its old authority.
    if !matches!(
        operation,
        Operation::LifecycleControl(_)
            | Operation::Mutate(_)
            | Operation::BeginStaged(_)
            | Operation::AppendStaged(_)
            | Operation::FinalizeStaged(_)
            | Operation::StopStaged(_)
            | Operation::Audit(_)
            | Operation::MaintenanceAudit(_)
    ) {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "closed lifecycle control requires its policy transition; generic authority/schema invalidation is disabled",
        ));
    }
    if control.pending_change.is_some()
        && !matches!(
            operation,
            Operation::LifecycleControl(_) | Operation::Audit(_) | Operation::MaintenanceAudit(_)
        )
    {
        return Err(conflict(
            "control policy transition freezes topology and command publication",
        ));
    }
    if control.retired
        && !matches!(
            operation,
            Operation::LifecycleControl(_) | Operation::Audit(_) | Operation::MaintenanceAudit(_)
        )
    {
        return Err(Error::new(
            ErrorCode::Sealed,
            "lifecycle control incarnation is retired",
        ));
    }
    Ok(())
}

pub(crate) fn apply(
    state: &mut TenantState,
    command: &Command,
    request: &LifecycleControlCommand,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    let mut candidate = state.clone();
    let result = apply_candidate(&mut candidate, command, request, revision)?;
    *state = candidate;
    Ok(result)
}
fn apply_candidate(
    state: &mut TenantState,
    command: &Command,
    request: &LifecycleControlCommand,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    exact_control(state, &command.context)?;
    match request {
        LifecycleControlCommand::Install {
            command_id,
            installation,
        } => {
            installation.validate()?;
            if command_id.is_nil()
                || installation.root.control_incarnation.to_string() != state.incarnation
            {
                return Err(conflict("control installation incarnation differs"));
            }
            if let Some(existing) = &state.lifecycle_control {
                if existing.installation_command_id == *command_id
                    && existing.installation == *installation
                {
                    return Ok(receipt(existing.installation_revision));
                }
                return Err(conflict("control installation is immutable"));
            }
            state.lifecycle_control = Some(LifecycleControlState {
                installation: installation.clone(),
                installation_command_id: *command_id,
                installation_revision: revision,
                installation_policy_epoch: state.policy_epoch,
                installation_policy: state.policy.clone(),
                retired: false,
                pending_change: None,
                intents: BTreeMap::new(),
                changes: BTreeMap::new(),
            });
        }
        LifecycleControlCommand::CommitIntent(request) => {
            request.validate()?;
            let request_sha256 = hash(request)?;
            let control = state
                .lifecycle_control
                .as_mut()
                .ok_or_else(|| conflict("lifecycle control is not installed"))?;
            if let Some(retained) = control.intents.get(&request.command_id) {
                if retained.request_sha256 != request_sha256 {
                    return Err(conflict("permanent lifecycle intent identity differs"));
                }
                return Ok(receipt(retained.revision));
            }
            if control.retired || control.pending_change.is_some() {
                return Err(conflict("lifecycle issuance is closed"));
            }
            if let Some(origin) = &request.resume_origin
                && (control
                    .intents
                    .get(&origin.materialization.request.command_id)
                    != Some(&origin.materialization)
                    || origin.authority_manifest_sha256
                        != control
                            .installation
                            .partitions
                            .get(&request.authority_partition)
                            .ok_or_else(|| conflict("resumption issuer partition missing"))?
                            .manifest_sha256)
            {
                return Err(conflict(
                    "resumption origin is not the exact retained Control commitment",
                ));
            }
            if control.changes.contains_key(&request.command_id)
                || request.command_id == control.installation_command_id
            {
                return Err(conflict("lifecycle command identity already used"));
            }
            if request.expected_policy_epoch != state.policy_epoch
                || request.installation_sha256 != hash(&control.installation)?
                || !control
                    .installation
                    .partitions
                    .contains_key(&request.authority_partition)
            {
                return Err(conflict(
                    "lifecycle current epoch or installed partition differs",
                ));
            }
            let expiry = command
                .context
                .authorization
                .expires_at_ms()
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::Unauthorized,
                        "lifecycle intent needs an original finite verified credential",
                    )
                })?;
            if command.timestamp_ms >= expiry {
                return Err(Error::new(
                    ErrorCode::Unauthorized,
                    "original control credential expired",
                ));
            }
            if control.intents.len() >= control.installation.max_intents {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "permanent lifecycle intent quota reached",
                ));
            }
            control.intents.insert(
                request.command_id,
                LifecycleIntent {
                    request: request.as_ref().clone(),
                    request_sha256,
                    control_incarnation: control.installation.root.control_incarnation,
                    installation_generation: control.installation.generation,
                    original_principal: command.context.principal.clone(),
                    original_credential_expires_at_ms: expiry,
                    accepted_at_ms: command.timestamp_ms,
                    revision,
                },
            );
        }
        LifecycleControlCommand::BeginPolicyChange(request) => {
            request.validate()?;
            validate_policy(&request.candidate.policy, &state.limits)?;
            let request_sha256 = hash(request)?;
            let control = state
                .lifecycle_control
                .as_mut()
                .ok_or_else(|| conflict("lifecycle control is not installed"))?;
            if let Some(retained) = control.changes.get(&request.command_id) {
                if retained.request_sha256 != request_sha256 {
                    return Err(conflict("permanent control change identity differs"));
                }
                return Ok(receipt(retained.accepted_revision));
            }
            if control.retired || control.pending_change.is_some() {
                return Err(conflict(
                    "control policy transition is already closed or pending",
                ));
            }
            if control.intents.contains_key(&request.command_id)
                || request.command_id == control.installation_command_id
            {
                return Err(conflict("lifecycle command identity already used"));
            }
            if request.expected_policy_epoch != state.policy_epoch
                || request.installation_sha256 != hash(&control.installation)?
            {
                return Err(conflict(
                    "control change current epoch or installation differs",
                ));
            }
            if control.changes.len() >= control.installation.max_changes
                || state.policy_epoch == u64::MAX
            {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "control policy history or epoch exhausted",
                ));
            }
            // Copy the exhaustive immutable partition set into the commitment.
            // No operator enrollment path can change this set during the drain.
            control.changes.insert(
                request.command_id,
                ControlPolicyChange {
                    request: request.clone(),
                    request_sha256,
                    control_incarnation: control.installation.root.control_incarnation,
                    installation: control.installation.clone(),
                    original_principal: command.context.principal.clone(),
                    accepted_at_ms: command.timestamp_ms,
                    accepted_revision: revision,
                    completed_revision: None,
                    completion_stops: None,
                },
            );
            control.pending_change = Some(request.command_id);
        }
        LifecycleControlCommand::CompletePolicyChange(request) => {
            let control = state
                .lifecycle_control
                .as_ref()
                .ok_or_else(|| conflict("lifecycle control is not installed"))?;
            let change = control
                .changes
                .get(&request.command_id)
                .ok_or_else(|| conflict("control change is absent"))?
                .clone();
            if change.request_sha256 != request.change_sha256 {
                return Err(conflict("exact control change identity differs"));
            }
            if let Some(completed) = change.completed_revision {
                if change.completion_stops.as_ref() != Some(&request.stops) {
                    return Err(conflict("permanent control completion input differs"));
                }
                return Ok(receipt(completed));
            }
            if control.pending_change != Some(request.command_id)
                || state.policy_epoch != change.request.expected_policy_epoch
            {
                return Err(conflict(
                    "control change is not the current pending transition",
                ));
            }
            kasumi_serving::verify_control_epoch_stops(&change, &request.stops).map_err(|_| {
                conflict("complete exact installed authority stop proofs are required")
            })?;
            state.policy = change.request.candidate.policy.clone();
            state.policy_epoch = next_policy_epoch(state.policy_epoch)?;
            let control = state
                .lifecycle_control
                .as_mut()
                .expect("checked closed control");
            control.retired = change.request.candidate.retire_control;
            control.pending_change = None;
            let finished = control
                .changes
                .get_mut(&request.command_id)
                .expect("checked change");
            finished.completed_revision = Some(revision);
            finished.completion_stops = Some(request.stops.clone());
        }
    }
    validate(state)?;
    Ok(receipt(revision))
}

/// Preserve exact completion headroom before acknowledging Begin and after
/// every later audit. This reservation cannot be spent by unrelated commands.
pub(crate) fn completion_fits(state: &TenantState) -> Result<bool> {
    let Some(control) = &state.lifecycle_control else {
        return Ok(true);
    };
    let Some(id) = control.pending_change else {
        return Ok(true);
    };
    let change = control
        .changes
        .get(&id)
        .ok_or_else(|| conflict("pending control change absent"))?;
    let mut completed = state.clone();
    completed.policy = change.request.candidate.policy.clone();
    completed.policy_epoch = next_policy_epoch(state.policy_epoch)?;
    let closed = completed.lifecycle_control.as_mut().expect("checked");
    closed.pending_change = None;
    closed.retired = change.request.candidate.retire_control;
    let future_stops = change
        .installation
        .partitions
        .iter()
        .map(|(name, partition)| {
            let stop = kasumi_serving::control_stop_for(change, partition)
                .map_err(|_| conflict("invalid completion reservation"))?;
            Ok((
                name.clone(),
                SignedControlEpochStop {
                    observation: ControlEpochStopObservation {
                        stop,
                        accepted_revision: u64::MAX,
                        accepted_term: u64::MAX,
                        observed_revision: u64::MAX,
                        observed_term: u64::MAX,
                        drain_ms: partition.drain_ms,
                    },
                    signature: GenerationSignature {
                        certificate: SigningCertificate {
                            identity: SigningGeneration {
                                domain: SigningDomain {
                                    authority_id: partition.authority_id,
                                    partition: partition.partition,
                                    manifest_sha256: partition.manifest_sha256.clone(),
                                    root_public_key: partition.signing_public_key.clone(),
                                    retirement_drain_ms: partition.drain_ms,
                                },
                                generation: u64::MAX,
                                public_key: "f".repeat(64),
                            },
                            root_signature: "f".repeat(128),
                        },
                        signature: "f".repeat(128),
                    },
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let finished = closed.changes.get_mut(&id).expect("checked");
    finished.completed_revision = Some(u64::MAX);
    finished.completion_stops = Some(future_stops);
    // Conservative full-width future administrative record, not caller capacity.
    super::append_audit(
        &mut completed,
        AuditEvent {
            event_id: "x".repeat(256),
            principal: "x".repeat(256),
            action: "lifecycle_control".into(),
            request_id: "x".repeat(256),
            timestamp_ms: u64::MAX,
            data_revision: Some(u64::MAX),
            outcome: "committed".into(),
            collection: None,
        },
    )?;
    if completed.audit_retention.hot_bytes > completed.limits.audit_retention.hot_bytes
        || encoded_len(completed.lifecycle_control.as_ref().expect("checked"))?
            > control.installation.max_state_bytes
    {
        return Ok(false);
    }
    SnapshotAccounting::rebuild(&completed)?.fits(&completed)
}

pub(crate) fn validate(state: &TenantState) -> Result<()> {
    let Some(control) = &state.lifecycle_control else {
        return Ok(());
    };
    control.installation.validate()?;
    if state.tenant != "__kasumi_control"
        || control.installation.root.control_incarnation.to_string() != state.incarnation
        || control.installation_command_id.is_nil()
        || control.installation_revision == 0
        || control.installation_revision > state.revision
        || state.retired
        || state.pending_restore.is_some()
        || control.intents.len() > control.installation.max_intents
        || control.changes.len() > control.installation.max_changes
        || encoded_len(control)? > control.installation.max_state_bytes
    {
        return Err(conflict("invalid bounded lifecycle control state"));
    }
    validate_policy(&control.installation_policy, &state.limits)?;
    let install_sha = hash(&control.installation)?;
    let mut ids = BTreeSet::from([control.installation_command_id]);
    let mut changes: Vec<_> = control.changes.iter().collect();
    changes.sort_by_key(|(_, change)| change.accepted_revision);
    let mut epoch = control.installation_policy_epoch;
    let mut policy = &control.installation_policy;
    let mut previous = control.installation_revision;
    let mut pending = None;
    let mut retired = false;
    for (id, change) in changes {
        change.request.validate()?;
        validate_policy(&change.request.candidate.policy, &state.limits)?;
        validate_name(&change.original_principal)?;
        if !ids.insert(*id)
            || *id != change.request.command_id
            || change.request_sha256 != hash(&change.request)?
            || change.request.installation_sha256 != install_sha
            || change.installation != control.installation
            || change.control_incarnation != control.installation.root.control_incarnation
            || change.request.expected_policy_epoch != epoch
            || change.accepted_revision <= previous
            || change.accepted_revision > state.revision
            || pending.is_some()
            || retired
        {
            return Err(conflict(
                "control policy history is discontinuous or substituted",
            ));
        }
        match change.completed_revision {
            Some(revision) if revision > change.accepted_revision && revision <= state.revision => {
                kasumi_serving::verify_control_epoch_stops(
                    change,
                    change
                        .completion_stops
                        .as_ref()
                        .ok_or_else(|| conflict("completed control stop proofs absent"))?,
                )
                .map_err(|_| conflict("retained control stop proofs invalid"))?;
                epoch = next_policy_epoch(epoch)?;
                policy = &change.request.candidate.policy;
                retired = change.request.candidate.retire_control;
                previous = revision;
            }
            Some(_) => return Err(conflict("control completion revision differs")),
            None => {
                if change.completion_stops.is_some() {
                    return Err(conflict(
                        "pending control change contains completion proofs",
                    ));
                }
                pending = Some(*id);
                previous = change.accepted_revision;
            }
        }
    }
    if control.pending_change != pending
        || control.retired != retired
        || state.policy_epoch != epoch
        || !same(&state.policy, policy)?
    {
        return Err(conflict(
            "current control policy is outside the closed transition history",
        ));
    }
    for (id, intent) in &control.intents {
        intent.request.validate()?;
        if let Some(origin) = &intent.request.resume_origin
            && (control
                .intents
                .get(&origin.materialization.request.command_id)
                != Some(&origin.materialization)
                || origin.materialization.revision >= intent.revision
                || origin.authority_manifest_sha256
                    != control
                        .installation
                        .partitions
                        .get(&intent.request.authority_partition)
                        .ok_or_else(|| conflict("retained resumption issuer missing"))?
                        .manifest_sha256)
        {
            return Err(conflict(
                "retained resumption lost its original Control commitment",
            ));
        }
        validate_name(&intent.original_principal)?;
        if !ids.insert(*id)
            || *id != intent.request.command_id
            || intent.request_sha256 != hash(&intent.request)?
            || intent.control_incarnation != control.installation.root.control_incarnation
            || intent.installation_generation != control.installation.generation
            || intent.request.installation_sha256 != install_sha
            || !control
                .installation
                .partitions
                .contains_key(&intent.request.authority_partition)
            || intent.revision <= control.installation_revision
            || intent.revision > state.revision
            || intent.accepted_at_ms >= intent.original_credential_expires_at_ms
            || intent.request.expected_policy_epoch < control.installation_policy_epoch
            || intent.request.expected_policy_epoch > epoch
        {
            return Err(conflict("retained lifecycle intent identity differs"));
        }
        for change in control.changes.values() {
            if intent.revision > change.accepted_revision
                && (change
                    .completed_revision
                    .is_none_or(|r| intent.revision < r))
            {
                return Err(conflict(
                    "lifecycle intent was accepted during frozen policy transition",
                ));
            }
            if change
                .completed_revision
                .is_some_and(|r| intent.revision > r)
                && intent.request.expected_policy_epoch <= change.request.expected_policy_epoch
            {
                return Err(conflict("lifecycle intent uses retired control epoch"));
            }
        }
    }
    Ok(())
}
