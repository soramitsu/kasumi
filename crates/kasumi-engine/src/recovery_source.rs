//! Source retirement and issuer fencing preserve the exact original resource and
//! epoch. Serialized receipts are retained history; the installed coordinator
//! obtains planned retirement evidence through an independent native source.
use super::*;

pub(crate) fn issuer_action(
    operation: &RecoveryRecord,
    phase: RecoveryPhase,
) -> Result<AuthorityAction> {
    let request = &operation.request;
    Ok(match phase {
        RecoveryPhase::Prepare => AuthorityAction::PrepareTarget {
            source_incarnation: request.source_incarnation,
            source_epoch: request.source_authority_epoch,
            target: target(request),
        },
        RecoveryPhase::StopTarget => AuthorityAction::StopTarget {
            source_incarnation: request.source_incarnation,
            source_epoch: request.source_authority_epoch,
            target: target(request),
        },
        RecoveryPhase::FenceSource => AuthorityAction::Fence {
            incarnation: request.source_incarnation,
            authority_epoch: request.source_authority_epoch,
        },
        _ => return Err(conflict("recovery issuer dispatch phase differs")),
    })
}
pub(crate) fn retirement_request(operation: &RecoveryRecord) -> Result<&RetireSourceRequest> {
    match &operation.request.source_mode {
        RecoverySourceMode::Planned { retirement } => Ok(retirement),
        RecoverySourceMode::SourceUnavailable => Err(conflict(
            "source-unavailable recovery cannot claim planned retirement evidence",
        )),
    }
}
pub(crate) fn validate_retirement(
    operation: &RecoveryRecord,
    receipt: &RetirementReceipt,
) -> Result<()> {
    let request = retirement_request(operation)?;
    let reference = request.reference()?;
    receipt.validate()?;
    if receipt.tenant != operation.request.tenant
        || receipt.source_incarnation != reference.source_incarnation
        || receipt.retirement_id != reference.retirement_id
        || receipt.request_digest != reference.request_digest
        || receipt.target_incarnation != request.target_incarnation
        || receipt.checkpoint != request.checkpoint
        || receipt.admitted_at_ms > request.not_after_ms
    {
        return Err(conflict("planned source retirement evidence differs"));
    }
    Ok(())
}
