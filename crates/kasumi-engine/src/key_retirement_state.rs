//! Ordered wrapping-key retirement. The fence, its decision and its removal
//! are replicated commands of the scope's own state machine; every fallible
//! check precedes mutation, so a rejected command publishes nothing but its
//! audit record.
use super::*;

/// The Control scope belongs to the Control tenant and every other tenant
/// retires only its own scope.
fn authorize(
    state: &TenantState,
    context: &RequestContext,
    scope: &KeyRetentionScope,
) -> Result<()> {
    authorize_state(state, context, None, Action::Admin)?;
    let owned = match scope {
        KeyRetentionScope::Tenant { tenant } => {
            *tenant == state.tenant && state.tenant != crate::control::CONTROL_TENANT
        }
        KeyRetentionScope::Control {} => state.tenant == crate::control::CONTROL_TENANT,
        _ => false,
    };
    if !owned {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "key retention scope differs from this state",
        ));
    }
    Ok(())
}

/// The observed dependency position must still be this state's. A history
/// archive, audit segment, recovery record, session binding or authority
/// change that committed after the observation rejects the command.
fn require_position(state: &TenantState, expected: &str) -> Result<()> {
    if state.key_dependency_sha256()? != expected {
        return Err(Error::new(
            ErrorCode::Conflict,
            "key dependencies changed after their coverage was observed",
        ));
    }
    Ok(())
}

fn scope_of(state: &TenantState, retirement_id: &str) -> Result<KeyRetentionScope> {
    state
        .key_retirements
        .status(retirement_id)
        .map(|status| status.request().scope.clone())
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "key retirement is not retained"))
}

/// Commit the fence. A tenant's fence advances its authority epoch, which
/// rejects every history archive and backup session claim that was prepared
/// before it; Control's epoch moves only through its own policy transition,
/// and its one racing publication, the audit segment, names its key.
pub(crate) fn begin(
    state: &mut TenantState,
    command: &Command,
    request: &BeginKeyRetirement,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    request.validate()?;
    authorize(state, &command.context, &request.request.scope)?;
    let mut retirements = state.key_retirements.clone();
    let transition = retirements.begin(request, revision)?;
    if transition == KeyRetirementTransition::Applied {
        require_position(state, &request.expected_dependency_sha256)?;
        if state.tenant != crate::control::CONTROL_TENANT {
            state.policy_epoch = next_policy_epoch(state.policy_epoch)?;
        }
        state.key_retirements = retirements;
    }
    Ok((
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        false,
    ))
}

pub(crate) fn complete(
    state: &mut TenantState,
    command: &Command,
    request: &CompleteKeyRetirement,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    request.validate()?;
    let scope = scope_of(state, &request.retirement_id)?;
    authorize(state, &command.context, &scope)?;
    let mut retirements = state.key_retirements.clone();
    let transition = retirements.complete(request, revision)?;
    if transition == KeyRetirementTransition::Applied {
        require_position(state, &request.expected_dependency_sha256)?;
        state.key_retirements = retirements;
    }
    Ok((
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        false,
    ))
}

pub(crate) fn abort(
    state: &mut TenantState,
    command: &Command,
    request: &AbortKeyRetirement,
    revision: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    request.validate()?;
    let scope = scope_of(state, &request.retirement_id)?;
    authorize(state, &command.context, &scope)?;
    let mut retirements = state.key_retirements.clone();
    if retirements.abort(request, revision)? == KeyRetirementTransition::Applied {
        state.key_retirements = retirements;
    }
    Ok((
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        false,
    ))
}

/// A dependency writer's refusal of a reference the fence or a floor retires.
pub(crate) fn fenced(key: &KeyVersionRef) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!(
            "wrapping key version {} is fenced by key retirement",
            key.version
        ),
    )
}
