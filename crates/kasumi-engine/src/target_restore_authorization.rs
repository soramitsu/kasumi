//! Typed full-backup authorization. A Control capability authorizes exactly its
//! committed recovery graph; it is never converted into a tenant Data identity.
use super::*;
use crate::target_invocation::TargetLifecycleInvocation;

pub(crate) enum RestoreAuthorization<'a> {
    /// Existing explicitly authorized source-backup Data/Admin path.
    Data(&'a RequestContext),
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
