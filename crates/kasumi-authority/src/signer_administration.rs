//! Current quorum authorization for the local verifier's administrative channel.
//! A sealed operational signer cannot issue leases, but cannot lock operators
//! out of the independent mTLS/JWT/quorum boundary needed to finish rotation.
use super::*;

pub struct AuthorityAdministrativeFence {
    authority: Arc<IndependentAuthority>,
    context: RequestContext,
    policy_epoch: u64,
    term: u64,
    _permit: OwnedSemaphorePermit,
}
impl AuthorityAdministrativeFence {
    pub fn local_node_id(&self) -> u64 {
        self.authority.local_node_id
    }
    pub fn signing_domain(&self) -> Result<SigningDomain> {
        self.authority
            .installation()
            .manifest
            .signing_domain(self.authority.installation().partition)
            .map_err(unavailable)
    }
    pub fn context(&self) -> &RequestContext {
        &self.context
    }
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.authority.group.check_access().map_err(unavailable)?;
        self.authority
            .check_installed_configuration()
            .map_err(unavailable)?;
        if self.authority.term() != self.term
            || self.authority.backend.authorize_admin(&self.context)? != self.policy_epoch
        {
            return Err(unavailable(
                "current authority administrative observation changed",
            ));
        }
        Ok(())
    }
    pub async fn release(&self) -> Result<()> {
        if self.authority.barrier(&self.context).await? != self.term {
            return Err(unavailable(
                "authority term changed before administrative release",
            ));
        }
        self.check()
    }
}
impl IndependentAuthority {
    /// Reload only a key already accepted by this exact durable verifier owner.
    /// Existing requests retain their original signer Arc and never consult the
    /// replacement slot during signing or response release.
    pub async fn replace_operational_signer(
        self: &Arc<Self>,
        authorization: Arc<AuthorityAdministrativeFence>,
        signer: Arc<AuthoritySigner>,
    ) -> Result<()> {
        if !Arc::ptr_eq(self, &authorization.authority) {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "signer replacement authority differs",
            ));
        }
        authorization.release().await?;
        {
            let mut current = self.signer.write().map_err(unavailable)?;
            if !current.same_verifier_owner(&signer)
                || signer.certificate().identity.domain != authorization.signing_domain()?
                || self.settings.installed_members[&self.local_node_id].verifier
                    != signer.verifier_identity().map_err(unavailable)?
            {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "signer replacement must retain the exact installed live verifier owner",
                ));
            }
            authorization.check()?;
            signer.check().map_err(unavailable)?;
            *current = signer.clone();
        }
        authorization.release().await.map_err(unknown)?;
        signer.check().map_err(unknown)
    }
    pub async fn authorize_signer_maintenance(
        self: &Arc<Self>,
        context: RequestContext,
    ) -> Result<Arc<AuthorityAdministrativeFence>> {
        context.authorization.check_live()?;
        if context.authorization.expires_at_ms().is_none() {
            return Err(Error::new(
                ErrorCode::Unauthorized,
                "signer maintenance requires a finite verified credential",
            ));
        }
        let permit = self.permit()?;
        let term = self.barrier(&context).await?;
        let policy_epoch = self.backend.authorize_admin(&context)?;
        let fence = Arc::new(AuthorityAdministrativeFence {
            authority: self.clone(),
            context,
            policy_epoch,
            term,
            _permit: permit,
        });
        fence.check()?;
        Ok(fence)
    }
}

/// Constructed only from an actual consensus outcome after current authorization.
/// The wire status remains historical authorization, not a local completion proof.
pub struct CommittedSignerDirective(AuthorityMaintenanceStatus);
impl CommittedSignerDirective {
    pub fn status(&self) -> &AuthorityMaintenanceStatus {
        &self.0
    }
}
impl IndependentAuthority {
    pub async fn commit_signer_directive(
        self: &Arc<Self>,
        context: &RequestContext,
        verifier: &TrustVerifierIdentity,
        domain_sha256: &str,
        command: &SignerTrustCommand,
    ) -> Result<CommittedSignerDirective> {
        use crate::state::maintenance_state::MaintenanceTransition;
        command.digest().map_err(unavailable)?;
        if verifier.node_id != self.local_node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "signer directive targets another local member",
            ));
        }
        let _serial = self.proposal.lock().await;
        let term = self.barrier(context).await?;
        let epoch = self.backend.authorize_admin(context)?;
        let action = AuthorityMaintenanceAction::AuthorizeSignerTrust {
            verifier: verifier.clone(),
            domain_sha256: domain_sha256.into(),
            command: Box::new(command.clone()),
        };
        let status = if let Some(status) = self
            .backend
            .maintenance_status(command.operation_id)
            .map_err(unavailable)?
        {
            if status.command.action != action {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "permanent signer directive differs",
                ));
            }
            status
        } else {
            let current = self
                .backend
                .operational_configuration()
                .map_err(unavailable)?;
            self.maintenance_write(
                context,
                term,
                MaintenanceTransition::Begin {
                    command: AuthorityMaintenanceCommand {
                        operation_id: command.operation_id,
                        expected_policy_epoch: epoch,
                        expected_operational_revision: current.revision,
                        not_after_ms: command.not_after_ms,
                        action,
                    },
                },
            )
            .await?
        };
        if status.phase != AuthorityMaintenancePhase::Completed {
            return Err(Error::new(
                ErrorCode::Conflict,
                "signer directive did not commit permission for local dispatch",
            ));
        }
        Ok(CommittedSignerDirective(status))
    }
    pub async fn signer_directive(
        &self,
        context: &RequestContext,
        verifier: &TrustVerifierIdentity,
        domain_sha256: &str,
        operation_id: uuid::Uuid,
    ) -> Result<Option<AuthorityMaintenanceStatus>> {
        self.barrier(context).await?;
        self.backend.authorize_admin(context)?;
        let status = self
            .backend
            .maintenance_status(operation_id)
            .map_err(unavailable)?;
        if let Some(status) = &status
            && !matches!(&status.command.action, AuthorityMaintenanceAction::AuthorizeSignerTrust { verifier: actual, domain_sha256: domain, .. } if actual == verifier && domain == domain_sha256)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "operation belongs to another verifier or directive",
            ));
        }
        Ok(status)
    }
}
