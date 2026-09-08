//! Deterministic planned retirement and permanent exact command outcomes.
use super::*;

fn identity(reference: &RetirementRef) -> Result<String> {
    reference.validate()?;
    Ok(staged_digest(&(
        "kasumi.retirement-identity.v1",
        &reference.source_incarnation,
        &reference.retirement_id,
    ))?
    .0)
}

pub(crate) fn lookup<'a>(
    state: &'a TenantState,
    context: &RequestContext,
    reference: &RetirementRef,
) -> Result<Option<&'a StoredRetirement>> {
    authorize_state(state, context, None, Action::Admin)?;
    reference.validate()?;
    if state.incarnation != reference.source_incarnation {
        return Err(Error::new(
            ErrorCode::Conflict,
            "retirement source incarnation differs",
        ));
    }
    let key = identity(reference)?;
    let Some(record) = state.retirements.get(&key) else {
        return Ok(None);
    };
    if record.request_digest != reference.request_digest {
        return Err(Error::new(
            ErrorCode::Conflict,
            "retirement command identity mismatch",
        ));
    }
    Ok(Some(record))
}

/// Performs current authorization and quota admission before any backup object
/// is accepted into memory; ordered execution repeats both checks.
pub(crate) fn admit(
    state: &TenantState,
    context: &RequestContext,
    request: &RetireSourceRequest,
) -> Result<Option<Result<RetirementReceipt>>> {
    request.validate()?;
    let reference = request.reference()?;
    if let Some(record) = lookup(state, context, &reference)? {
        return Ok(Some(record.outcome.clone()));
    }
    if request.checkpoint.tenant != state.tenant {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "retirement backup tenant differs",
        ));
    }
    if state.retired {
        return Err(Error::new(
            ErrorCode::Sealed,
            "source already permanently retired",
        ));
    }
    let required = StoredRetirement::reservation_bytes(&context.principal, request)?;
    if state
        .retirement_bytes
        .checked_add(required)
        .is_none_or(|n| n > state.limits.max_retirement_bytes)
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "permanent retirement byte budget exhausted",
        ));
    }
    Ok(None)
}

pub(super) fn apply(
    state: &mut TenantState,
    command: &Command,
    request: &PreparedRetirement,
    previous_revision: u64,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    if let Some(outcome) = admit(state, &command.context, &request.request)? {
        return Ok((
            outcome.map(|receipt| WriteReceipt {
                revision: receipt.revision,
                versions: BTreeMap::new(),
            }),
            false,
        ));
    }
    let reference = request.request.reference()?;
    let outcome = decision(state, command, request, previous_revision, revision);
    let policy_epoch = outcome.as_ref().ok().map(|receipt| receipt.policy_epoch);
    let result = outcome.clone().map(|receipt| WriteReceipt {
        revision: receipt.revision,
        versions: BTreeMap::new(),
    });
    store(
        state,
        identity(&reference)?,
        StoredRetirement {
            principal: command.context.principal.clone(),
            request: request.request.clone(),
            request_digest: reference.request_digest,
            accepted_revision: revision,
            outcome,
        },
    )?;
    if let Some(epoch) = policy_epoch {
        state.retired = true;
        state.suspended = true;
        state.policy_epoch = epoch;
    }
    Ok((result, false))
}

pub(super) fn abort(
    state: &mut TenantState,
    context: &RequestContext,
    request: &RetireSourceRequest,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    let reference = request.reference()?;
    if admit(state, context, request)?.is_some() {
        let record = lookup(state, context, &reference)?.expect("accepted identity observed");
        return Ok((
            Ok(WriteReceipt {
                revision: record.accepted_revision,
                versions: BTreeMap::new(),
            }),
            false,
        ));
    }
    store(
        state,
        identity(&reference)?,
        StoredRetirement {
            request: request.clone(),
            principal: context.principal.clone(),
            request_digest: reference.request_digest,
            accepted_revision: revision,
            outcome: Err(Error::new(
                ErrorCode::Conflict,
                "retirement permanently stopped",
            )),
        },
    )?;
    Ok((
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        false,
    ))
}

fn decision(
    state: &TenantState,
    command: &Command,
    prepared: &PreparedRetirement,
    previous_revision: u64,
    revision: u64,
) -> Result<RetirementReceipt> {
    let request = &prepared.request;
    validate_sha256(&prepared.verified_closure_digest)?;
    let observed = prepared
        .observation
        .as_ref()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "retirement was not prepared"))?;
    validate_sha256(&observed.closure_digest)?;
    if command.timestamp_ms > request.not_after_ms {
        return Err(Error::new(
            ErrorCode::Conflict,
            "retirement action deadline expired",
        ));
    }
    if state.pending_restore.is_some()
        || request.checkpoint.revision > previous_revision
        || observed.revision != previous_revision
        || observed.closure_digest != prepared.verified_closure_digest
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "source changed after verified checkpoint",
        ));
    }
    let receipt = RetirementReceipt {
        tenant: state.tenant.clone(),
        principal: command.context.principal.clone(),
        retirement_id: request.retirement_id.clone(),
        request_digest: request.reference()?.request_digest,
        source_incarnation: state.incarnation.clone(),
        target_incarnation: request.target_incarnation.clone(),
        revision,
        policy_epoch: next_policy_epoch(state.policy_epoch)?,
        admitted_at_ms: command.timestamp_ms,
        checkpoint: request.checkpoint.clone(),
        closure_digest: prepared.verified_closure_digest.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

fn entry_bytes(key: &str, record: &StoredRetirement) -> Result<u64> {
    record.entry_bytes(key)
}
pub(super) fn store(state: &mut TenantState, key: String, record: StoredRetirement) -> Result<()> {
    let old = state
        .retirements
        .get(&key)
        .map(|old| entry_bytes(&key, old))
        .transpose()?
        .unwrap_or(0);
    let new = entry_bytes(&key, &record)?;
    let bytes = state
        .retirement_bytes
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "retirement accounting mismatch"))?;
    if bytes > state.limits.max_retirement_bytes {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "permanent retirement byte budget exhausted",
        ));
    }
    state.retirement_bytes = bytes;
    state.retirements.insert(key, record);
    Ok(())
}

pub(super) fn reject_budget(
    previous: &TenantState,
    next: &TenantState,
    rejected: &mut TenantState,
    command: &Command,
    error: &Error,
) -> Result<()> {
    let request = match &command.operation {
        Operation::RetireSource(prepared) => Some(&prepared.request),
        Operation::AbortRetirement(request) => Some(request),
        _ => None,
    };
    if let Some(request) = request {
        let key = identity(&request.reference()?)?;
        if !previous.retirements.contains_key(&key)
            && let Some(record) = next.retirements.get(&key)
        {
            let mut record = record.clone();
            record.outcome = Err(error.clone());
            store(rejected, key, record)?;
        }
    }
    Ok(())
}

pub(super) fn validate_restored(state: &TenantState) -> Result<()> {
    if state.retirement_bytes > state.limits.max_retirement_bytes {
        return Err(Error::new(
            ErrorCode::Corruption,
            "retirement record quota exceeded",
        ));
    }
    let mut bytes = 0u64;
    let mut current_successes = 0usize;
    for (key, record) in &state.retirements {
        let (size, current) = validate_snapshot_record(state, key, record)?;
        current_successes += usize::from(current);
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "retirement byte count overflow"))?;
    }
    if current_successes != usize::from(state.retired) || bytes != state.retirement_bytes {
        return Err(Error::new(
            ErrorCode::Corruption,
            "retirement fence or accounting differs",
        ));
    }
    Ok(())
}

pub(super) fn validate_snapshot_record(
    state: &TenantState,
    key: &str,
    record: &StoredRetirement,
) -> Result<(u64, bool)> {
    let mut current_success = false;
    let reference = record.request.reference()?;
    if identity(&reference)? != *key
        || validate_name(&record.principal).is_err()
        || reference.request_digest != record.request_digest
        || record.request.checkpoint.tenant != state.tenant
        || record.accepted_revision == 0
        || record.accepted_revision > state.revision
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "retirement record identity differs",
        ));
    }
    if let Ok(receipt) = &record.outcome {
        receipt.validate()?;
        if receipt.principal != record.principal
            || receipt.request_digest != reference.request_digest
            || receipt.retirement_id != reference.retirement_id
            || receipt.source_incarnation != reference.source_incarnation
            || receipt.target_incarnation != record.request.target_incarnation
            || receipt.checkpoint != record.request.checkpoint
            || receipt.revision != record.accepted_revision
            || receipt.admitted_at_ms > record.request.not_after_ms
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "retirement outcome binding differs",
            ));
        }
        if receipt.source_incarnation == state.incarnation {
            current_success = true;
            if !state.retired || !state.suspended || receipt.policy_epoch > state.policy_epoch {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "retirement source fence differs",
                ));
            }
        }
    }
    Ok((entry_bytes(key, record)?, current_success))
}
