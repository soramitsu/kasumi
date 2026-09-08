//! Typed full-backup authorization. A Control capability authorizes exactly its
//! committed recovery graph; it is never converted into a tenant Data identity.
use super::*;
use crate::target_invocation::TargetLifecycleInvocation;

pub(crate) enum RestoreAuthorization<'a> {
    /// Existing explicitly authorized source-backup Data/Admin path.
    Data(&'a RequestContext),
    Local(&'a LocalRestoreRequest),
    /// Only the native closed target runner can obtain the opaque issuer grant.
    Lifecycle(&'a TargetLifecycleInvocation),
}
impl RestoreAuthorization<'_> {
    pub async fn check_access(
        &self,
        target: &TenantStore,
        audit: &SecurityAudit,
    ) -> anyhow::Result<()> {
        match self {
            Self::Data(context) => restore_access(target, audit, context).await,
            Self::Local(request) => {
                request
                    .source_context
                    .authorization
                    .require_database(&request.checkpoint.source_incarnation)?;
                request
                    .target_context
                    .authorization
                    .require_database(&request.target_incarnation.to_string())?;
                restore_access(target, audit, &request.source_context).await?;
                restore_access(target, audit, &request.target_context).await
            }
            Self::Lifecycle(invocation) => {
                if let Err(error) = invocation.check_target(target, LifecyclePhase::Materialize) {
                    return Err(restore_denial(audit, invocation.context(), error.code)
                        .await
                        .into());
                }
                Ok(())
            }
        }
    }
    pub async fn authorize_state(
        &self,
        target: &TenantStore,
        audit: &SecurityAudit,
        state: &TenantState,
    ) -> anyhow::Result<()> {
        self.check_access(target, audit).await?;
        match self {
            Self::Data(context) => {
                context.authorization.require_database(&state.incarnation)?;
                if context.tenant != state.tenant
                    || !state.policy.allows(context, None, Action::Admin)
                {
                    return Err(restore_denial(audit, context, ErrorCode::Forbidden)
                        .await
                        .into());
                }
            }
            Self::Local(request) => {
                let context = &request.source_context;
                anyhow::ensure!(
                    state.tenant == request.checkpoint.tenant
                        && state.incarnation == request.checkpoint.source_incarnation
                        && state.revision == request.checkpoint.revision,
                    "local source state differs from checkpoint"
                );
                context.authorization.require_database(&state.incarnation)?;
                if context.tenant != state.tenant
                    || !state.policy.allows(context, None, Action::Admin)
                {
                    return Err(restore_denial(audit, context, ErrorCode::Forbidden)
                        .await
                        .into());
                }
                anyhow::ensure!(
                    state
                        .policy
                        .allows(&request.target_context, None, Action::Admin),
                    "target credential has no administrator grant in the restored policy"
                );
            }
            Self::Lifecycle(invocation) => {
                let lease = invocation.gate().current()?;
                let expected = &lease.commitment().intent.request.checkpoint;
                anyhow::ensure!(
                    state.tenant == expected.tenant
                        && state.incarnation == expected.source_incarnation
                        && state.revision == expected.revision,
                    "backup source state differs from exact committed phase checkpoint"
                );
                // The graph verifier separately checks every authenticated object,
                // canonical resident hash, manifest ciphertext and key dependency.
                // No old source policy/credential is invented when its quorum is lost.
            }
        }
        self.check_access(target, audit).await
    }
    pub fn bound_checkpoint(
        &self,
        target: &TenantStore,
        backup_id: uuid::Uuid,
    ) -> anyhow::Result<Option<FullBackupCheckpoint>> {
        let expected = match self {
            Self::Local(request) => Some(request.checkpoint.clone()),
            Self::Lifecycle(invocation) => Some(
                invocation
                    .gate()
                    .current()?
                    .commitment()
                    .intent
                    .request
                    .checkpoint
                    .clone(),
            ),
            Self::Data(_) => target
                .storage_access()
                .serving_gate()
                .map(|gate| gate.recovery_checkpoint())
                .transpose()?
                .flatten(),
        };
        if let Some(checkpoint) = &expected {
            anyhow::ensure!(
                checkpoint.tenant == target.tenant() && checkpoint.backup_id == backup_id,
                "restore request differs from exact authorized backup"
            );
        }
        if target.storage_access().serving_gate().is_some() {
            anyhow::ensure!(
                expected.is_some(),
                "independent target has no authorized backup checkpoint"
            );
        }
        Ok(expected)
    }
}
