//! One issuer winner precedes local activation and every voter confirmation.
//! An expired or ambiguous issuer command is resolved by an ordered permanent
//! StopActivation command; time passing alone never permits target deletion.
use super::*;

pub(crate) fn completion(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<CommittedCompletion> {
    let retained = phase(
        state,
        operation,
        operation
            .completion
            .ok_or_else(|| conflict("target completion absent"))?,
    )?;
    match &retained.outcome {
        Some(RecoveryDispatchOutcome::Target(response)) => match &response.outcome {
            TargetRuntimeOutcome::Completed(signed) => {
                Ok(CommittedCompletion::Original(signed.clone()))
            }
            TargetRuntimeOutcome::Inspected(signed) => {
                Ok(CommittedCompletion::Resolved(signed.clone()))
            }
            _ => Err(conflict("retained target completion differs")),
        },
        _ => Err(conflict("retained target completion absent")),
    }
}
pub(crate) fn activation_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<ActivateTargetInput> {
    let retained = phase(
        state,
        operation,
        operation
            .source_fence
            .ok_or_else(|| conflict("source fence absent"))?,
    )?;
    let Some(RecoveryDispatchOutcome::Authority(signed)) = &retained.outcome else {
        return Err(conflict("source fence proof absent"));
    };
    Ok(ActivateTargetInput {
        completion_sha256: completion(state, operation)?.fact().digest()?,
        fence_id: signed.receipt.command.command_id,
        fence_digest: signed
            .receipt
            .digest()
            .map_err(|_| conflict("source fence digest failed"))?,
        target: target(&operation.request),
    })
}
pub(crate) fn action_for_intent(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
) -> Result<AuthorityAction> {
    origin(state, operation)?.accepts_phase(current, LifecyclePhase::Activate)?;
    let input = activation_input(state, operation)?;
    if current.request.phase_input_sha256
        != input
            .digest()
            .map_err(|_| conflict("activation input digest failed"))?
    {
        return Err(conflict(
            "activation Control intent differs from completed target and source fence",
        ));
    }
    let installed = &state
        .lifecycle_control
        .as_ref()
        .ok_or_else(|| conflict("Control installation absent"))?
        .installation;
    let reference = LifecycleAuthorityReference {
        control_incarnation: current.control_incarnation,
        control_policy_epoch: current.request.expected_policy_epoch,
        identity: LifecycleAuthorityIdentity::Intent(current.request.command_id),
    };
    let intent_sha256 = kasumi_serving::accepted_control_intent_digest(
        current,
        &installed.root,
        partition(state, operation)?,
        &staged_digest(&installed.partitions)?.0,
    )
    .map_err(|_| conflict("activation issuer intent digest failed"))?;
    Ok(AuthorityAction::ActivateCommitted {
        fence_id: input.fence_id,
        fence_digest: input.fence_digest,
        target: input.target,
        control: CommittedActivation {
            completion: Box::new(completion(state, operation)?),
            reference,
            intent_sha256,
        },
    })
}
pub(crate) fn current_action(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<AuthorityAction> {
    let current = intent(
        state,
        operation,
        operation
            .current_intent
            .ok_or_else(|| conflict("committed activation intent absent"))?,
    )?;
    action_for_intent(state, operation, current)
}
pub(crate) fn attempt<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a RecoveryPhaseRecord> {
    let retained = phase(
        state,
        operation,
        operation
            .activation_attempt
            .ok_or_else(|| conflict("original activation attempt absent"))?,
    )?;
    if !matches!(&retained.input, RecoveryDispatch::Authority(command) if matches!(command.action,AuthorityAction::ActivateCommitted{..}))
    {
        return Err(conflict("original activation attempt differs"));
    }
    Ok(retained)
}
pub(crate) fn stop_action(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<AuthorityAction> {
    let RecoveryDispatch::Authority(original) = &attempt(state, operation)?.input else {
        unreachable!()
    };
    Ok(AuthorityAction::StopActivation {
        original: original.clone(),
    })
}
pub(crate) fn original_receipt(outcome: &RecoveryDispatchOutcome) -> Result<&AuthorityReceipt> {
    match outcome {
        RecoveryDispatchOutcome::Authority(signed) => Ok(&signed.receipt),
        RecoveryDispatchOutcome::AuthorityResolution(signed) => match &signed.receipt.outcome {
            AuthorityOutcome::ActivationResolved { original } => Ok(original),
            _ => Err(conflict(
                "activation resolution proof lacks the original outcome",
            )),
        },
        _ => Err(conflict("issuer activation outcome absent")),
    }
}
pub(crate) fn winner<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a AuthorityReceipt> {
    let retained = phase(
        state,
        operation,
        operation
            .activation
            .ok_or_else(|| conflict("committed issuer winner absent"))?,
    )?;
    let receipt = original_receipt(
        retained
            .outcome
            .as_ref()
            .ok_or_else(|| conflict("issuer winner unresolved"))?,
    )?;
    if !matches!(receipt.outcome, AuthorityOutcome::Activated { .. }) {
        return Err(conflict(
            "issuer activation reference is not a committed winner",
        ));
    }
    Ok(receipt)
}
pub(crate) fn retained_action(
    state: &TenantState,
    operation: &RecoveryRecord,
    retained: &RecoveryPhaseRecord,
    command: &AuthorityCommand,
) -> Result<AuthorityAction> {
    match (&command.action, retained.phase) {
        (AuthorityAction::ActivateCommitted { control, .. }, RecoveryPhase::Activate) => {
            let LifecycleAuthorityIdentity::Intent(id) = control.reference.identity else {
                return Err(conflict("activation lacks exact Control intent identity"));
            };
            let current = state
                .lifecycle_control
                .as_ref()
                .and_then(|c| c.intents.get(&id))
                .ok_or_else(|| conflict("retained activation Control intent absent"))?;
            let committed = phase(state, operation, id)?;
            if committed.sequence >= retained.sequence
                || !matches!(&committed.outcome,Some(RecoveryDispatchOutcome::ControlIntent(actual)) if actual.as_ref()==current)
            {
                return Err(conflict(
                    "issuer activation lacks preceding exact recovery Control commitment",
                ));
            }
            if current.accepted_at_ms > retained.admitted_at_ms
                || command.not_after_ms > current.original_credential_expires_at_ms
            {
                return Err(conflict(
                    "issuer activation exceeds original Control authorization",
                ));
            }
            action_for_intent(state, operation, current)
        }
        (AuthorityAction::StopActivation { original }, RecoveryPhase::StopActivation) => {
            let prior = phase(state, operation, original.command_id)?;
            if prior.sequence >= retained.sequence
                || !matches!(&prior.input,RecoveryDispatch::Authority(actual) if actual==original && matches!(original.action,AuthorityAction::ActivateCommitted{..}))
            {
                return Err(conflict(
                    "activation stop substitutes the permanent original command",
                ));
            }
            Ok(AuthorityAction::StopActivation {
                original: original.clone(),
            })
        }
        _ => issuer_action(operation, retained.phase),
    }
}
pub(crate) fn receipt_identity(
    issuer: &ControlAuthorityPartition,
    expected: &AuthorityCommand,
    receipt: &AuthorityReceipt,
) -> Result<()> {
    if receipt.command != *expected
        || receipt.authority_id != issuer.authority_id
        || receipt.manifest_digest != issuer.manifest_sha256
        || receipt.partition != issuer.partition
        || receipt.term == 0
        || receipt.revision == 0
        || receipt.command_digest
            != expected
                .digest()
                .map_err(|_| conflict("issuer command digest failed"))?
    {
        return Err(conflict(
            "issuer receipt differs from exact permanent command",
        ));
    }
    Ok(())
}
pub(crate) fn validate_original(
    state: &TenantState,
    operation: &RecoveryRecord,
    expected: &AuthorityCommand,
    receipt: &AuthorityReceipt,
) -> Result<()> {
    receipt_identity(partition(state, operation)?, expected, receipt)?;
    let AuthorityAction::ActivateCommitted {
        target: expected_target,
        control,
        ..
    } = &expected.action
    else {
        return Err(conflict(
            "activation resolution original is not committed activation",
        ));
    };
    match &receipt.outcome {
        AuthorityOutcome::Rejected { .. } => Ok(()),
        AuthorityOutcome::ActivationStopped { original_digest }
            if *original_digest == receipt.command_digest =>
        {
            Ok(())
        }
        AuthorityOutcome::Activated {
            target,
            authority_epoch,
        } if target == expected_target
            && Some(*authority_epoch)
                == operation.request.source_authority_epoch.checked_add(1) =>
        {
            let LifecycleAuthorityIdentity::Intent(id) = control.reference.identity else {
                return Err(conflict("activation reference differs"));
            };
            let current = state
                .lifecycle_control
                .as_ref()
                .and_then(|c| c.intents.get(&id))
                .ok_or_else(|| conflict("activation intent absent"))?;
            if receipt.admitted_at_ms >= expected.not_after_ms
                || receipt.admitted_at_ms >= current.original_credential_expires_at_ms
                || receipt.admitted_at_ms < current.accepted_at_ms
                || receipt.admitted_at_ms < completion(state, operation)?.fact().admitted_at_ms
            {
                return Err(conflict(
                    "activation effect exceeds its immutable original admission",
                ));
            }
            Ok(())
        }
        _ => Err(conflict("issuer returned another activation resolution")),
    }
}
pub(crate) fn validate_resolution(
    state: &TenantState,
    operation: &RecoveryRecord,
    expected: &AuthorityCommand,
    signed: &SignedAuthorityReceipt,
) -> Result<()> {
    let AuthorityAction::StopActivation { original } = &signed.receipt.command.action else {
        return Err(conflict("activation resolution lacks exact stop command"));
    };
    if original.as_ref() != expected {
        return Err(conflict("activation resolution substitutes original input"));
    }
    history(partition(state, operation)?)?
        .verify(
            "kasumi.authority-proof.v1",
            &signed.receipt,
            &signed.signature,
        )
        .map_err(|_| conflict("activation resolution signature differs"))?;
    receipt_identity(
        partition(state, operation)?,
        &signed.receipt.command,
        &signed.receipt,
    )?;
    if signed.receipt.admitted_at_ms >= signed.receipt.command.not_after_ms {
        return Err(conflict(
            "activation stop exceeds its own original deadline",
        ));
    }
    let AuthorityOutcome::ActivationResolved { original } = &signed.receipt.outcome else {
        return Err(conflict(
            "issuer activation stop did not resolve original outcome",
        ));
    };
    if original.revision > signed.receipt.revision
        || original.admitted_at_ms > signed.receipt.admitted_at_ms
    {
        return Err(conflict(
            "activation resolution predates original retained outcome",
        ));
    }
    validate_original(state, operation, expected, original)
}
pub(crate) fn local_proof<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<Option<&'a SignedTargetActivation>> {
    for voter in operation.voters.values() {
        if let Some(id) = voter.confirmation {
            let retained = phase(state, operation, id)?;
            if let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome
                && let TargetRuntimeOutcome::Activated(signed) = &response.outcome
            {
                return Ok(Some(signed));
            }
            return Err(conflict("local activation confirmation proof differs"));
        }
    }
    Ok(None)
}
pub(crate) fn validate_step(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node: u64,
    step: &TargetRuntimeStep,
    admission: bool,
) -> Result<()> {
    origin(state, operation)?.accepts_phase(current, LifecyclePhase::Activate)?;
    if current.request.phase_input_sha256
        != activation_input(state, operation)?
            .digest()
            .map_err(|_| conflict("activation input digest failed"))?
    {
        return Err(conflict("local activation phase input differs"));
    }
    let winner = winner(state, operation)?;
    match step {
        TargetRuntimeStep::StartActivation {
            quorum,
            issuer_command_id,
        } if *quorum == quorum_input(state, operation)?
            && *issuer_command_id == winner.command.command_id =>
        {
            if admission && started_for(state, operation, node, current.request.command_id)? {
                return Err(conflict(
                    "activation voter already started under exact phase",
                ));
            }
        }
        TargetRuntimeStep::Activate {
            quorum,
            issuer_command_id,
        } if *quorum == quorum_input(state, operation)?
            && *issuer_command_id == winner.command.command_id =>
        {
            if admission
                && (local_proof(state, operation)?.is_some()
                    || !quorum::all_started(state, operation, current.request.command_id)?)
            {
                return Err(conflict(
                    "local activation requires every voter started under exact phase",
                ));
            }
        }
        TargetRuntimeStep::ConfirmActivation(signed) => {
            validate_local_proof(state, operation, node, signed, false)?;
            if admission
                && (operation
                    .voters
                    .get(&node)
                    .is_none_or(|v| v.confirmation.is_some())
                    || !quorum::all_started(state, operation, current.request.command_id)?
                    || local_proof(state, operation)?.is_none_or(|prior| {
                        prior.observation.activation != signed.observation.activation
                            || prior.observation.completion != signed.observation.completion
                    }))
            {
                return Err(conflict(
                    "local confirmation lacks exact retained activation or current startup",
                ));
            }
        }
        _ => {
            return Err(conflict(
                "target activation step differs from issuer winner",
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_local_proof(
    state: &TenantState,
    operation: &RecoveryRecord,
    node: u64,
    signed: &SignedTargetActivation,
    exact_observer: bool,
) -> Result<()> {
    kasumi_serving::verify_target_activation(&origin(state, operation)?, signed)
        .map_err(|_| conflict("local activation signature differs"))?;
    let winner = winner(state, operation)?;
    if (exact_observer && signed.observation.observer_node_id != node)
        || &signed.observation.completion != completion(state, operation)?.fact()
        || signed.observation.activation.issuer_receipt_sha256
            != winner
                .digest()
                .map_err(|_| conflict("issuer winner digest failed"))?
        || signed
            .observation
            .activation
            .intent
            .request
            .phase_input_sha256
            != activation_input(state, operation)?
                .digest()
                .map_err(|_| conflict("activation input digest failed"))?
    {
        return Err(conflict(
            "local activation proof differs from committed issuer winner",
        ));
    }
    Ok(())
}

pub(crate) fn authority_command(
    operation: &RecoveryRecord,
    phase_id: Uuid,
    action: AuthorityAction,
    now: u64,
    expires: u64,
) -> Result<RecoveryDispatch> {
    Ok(RecoveryDispatch::Authority(Box::new(AuthorityCommand {
        tenant: operation.request.tenant.clone(),
        command_id: phase_id,
        expected_policy_epoch: operation.request.authority_policy_epoch,
        not_after_ms: now
            .checked_add(operation.request.phase_timeout_ms)
            .ok_or_else(|| conflict("activation phase deadline overflow"))?
            .min(expires),
        action,
    })))
}
pub(crate) fn next_dispatch(
    state: &TenantState,
    operation: &RecoveryRecord,
    phase_id: Uuid,
    now: u64,
    expires: u64,
) -> Result<RecoveryDispatch> {
    if operation.phase == RecoveryPhase::StopActivation {
        return authority_command(
            operation,
            phase_id,
            stop_action(state, operation)?,
            now,
            expires,
        );
    }
    let current = operation
        .current_intent
        .map(|id| intent(state, operation, id))
        .transpose()?;
    let Some(current) = current.filter(|current| now < current.original_credential_expires_at_ms)
    else {
        return Ok(RecoveryDispatch::ControlIntent(Box::new(expected_intent(
            state,
            operation,
            phase_id,
            state.policy_epoch,
            LifecyclePhase::Activate,
        )?)));
    };
    if operation.phase == RecoveryPhase::Activate {
        return authority_command(
            operation,
            phase_id,
            action_for_intent(state, operation, current)?,
            now,
            expires.min(current.original_credential_expires_at_ms),
        );
    }
    if operation.phase != RecoveryPhase::Confirm {
        return Err(conflict("activation planner phase differs"));
    }
    let quorum = quorum_input(state, operation)?;
    let issuer_command_id = winner(state, operation)?.command.command_id;
    let mut missing = None;
    for node in operation.voters.keys() {
        if !started_for(state, operation, *node, current.request.command_id)? {
            missing = Some(*node);
            break;
        }
    }
    let (node_id, step) = if let Some(node) = missing {
        (
            node,
            TargetRuntimeStep::StartActivation {
                quorum,
                issuer_command_id,
            },
        )
    } else if let Some(signed) = local_proof(state, operation)? {
        let node = *operation
            .voters
            .iter()
            .find(|(_, v)| v.confirmation.is_none())
            .ok_or_else(|| conflict("unfinished activation confirmation absent"))?
            .0;
        (
            node,
            TargetRuntimeStep::ConfirmActivation(Box::new(signed.clone())),
        )
    } else {
        let node = *operation
            .voters
            .keys()
            .next()
            .ok_or_else(|| conflict("activation voters absent"))?;
        (
            node,
            TargetRuntimeStep::Activate {
                quorum,
                issuer_command_id,
            },
        )
    };
    Ok(RecoveryDispatch::Target {
        node_id,
        request: Box::new(TargetRuntimeRequest {
            tenant: operation.request.tenant.clone(),
            command_id: current.request.command_id,
            not_after_ms: now
                .checked_add(operation.request.phase_timeout_ms)
                .ok_or_else(|| conflict("activation dispatch deadline overflow"))?
                .min(expires)
                .min(current.original_credential_expires_at_ms),
            step,
        }),
    })
}

/// An unresolved attempt, including an expired one, never authorizes cleanup or
/// another issuer activation. Only its permanent exact negative outcome does.
pub(crate) fn require_negative_attempt(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<()> {
    if operation.activation_attempt.is_none() {
        return Ok(());
    }
    let original = attempt(state, operation)?;
    let receipt = original_receipt(
        original
            .outcome
            .as_ref()
            .ok_or_else(|| conflict("resolve original activation before another effect"))?,
    )?;
    if !matches!(
        receipt.outcome,
        AuthorityOutcome::Rejected { .. } | AuthorityOutcome::ActivationStopped { .. }
    ) {
        return Err(conflict("committed activation must proceed forward"));
    }
    Ok(())
}
