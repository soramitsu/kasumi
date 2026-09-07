//! Derive only the closed retired state from a validated application generation.
use super::*;

pub(super) fn retired(state: &TenantState) -> Result<Option<kasumi_raft::RetiredSnapshotState>> {
    if !state.retired {
        return Ok(None);
    }
    let record = state
        .retirements
        .values()
        .find(|record| {
            record
                .outcome
                .as_ref()
                .is_ok_and(|receipt| receipt.source_incarnation == state.incarnation)
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "retired snapshot has no accepted retirement",
            )
        })?;
    Ok(Some(kasumi_raft::RetiredSnapshotState {
        revision_base: state.revision_base,
        revision: state.revision,
        policy_epoch: state.policy_epoch,
        administrators: state
            .policy
            .grants
            .iter()
            .filter(|grant| grant.collection.is_none() && grant.actions.contains(&Action::Admin))
            .map(|grant| grant.principal.clone())
            .collect(),
        request: record.request.clone(),
        receipt: record.outcome.clone()?,
    }))
}
