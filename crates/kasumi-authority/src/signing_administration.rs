//! Current quorum observation of replicated signer state. No operational signer
//! is needed to resolve the activation which has just sealed that signer.
use super::*;
use crate::state::maintenance_state::MaintenanceTransition;

pub struct AuthoritySigningResponseFence {
    authorization: Arc<AuthorityAdministrativeFence>,
    observation: (AuthoritySigningHead, u64, u64),
}
impl AuthoritySigningResponseFence {
    pub fn check(&self) -> Result<()> {
        self.authorization.check()?;
        if self
            .authorization
            .authority
            .backend
            .signing_observation()
            .map_err(unavailable)?
            != self.observation
        {
            return Err(unavailable("current authority signing observation changed"));
        }
        Ok(())
    }
    pub async fn release(&self) -> Result<()> {
        self.authorization.release().await?;
        self.check()
    }
}
impl IndependentAuthority {
    pub async fn signing_maintenance(
        self: &Arc<Self>,
        context: RequestContext,
        request: AuthoritySigningRequest,
    ) -> Result<(AuthoritySigningResponse, AuthoritySigningResponseFence)> {
        request
            .validate()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let domain = self
            .installation()
            .manifest
            .signing_domain(self.installation().partition)
            .map_err(unavailable)?;
        if request.domain_sha256 != domain.digest()? {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "global signing domain differs",
            ));
        }
        let authorization = self.authorize_signer_maintenance(context.clone()).await?;
        let status = match &request.action {
            AuthoritySigningAction::Observe | AuthoritySigningAction::Verifiers { .. } => None,
            AuthoritySigningAction::Receipt { operation_id } => self
                .backend
                .maintenance_status(*operation_id)
                .map_err(unavailable)?,
            AuthoritySigningAction::Start { command } => {
                let _serial = self.proposal.lock().await;
                authorization.release().await?;
                let term = self.barrier(&context).await?;
                let previous = self
                    .backend
                    .maintenance_status(command.operation_id)
                    .map_err(unavailable)?;
                Some(if let Some(previous) = previous {
                    if previous.command != *command {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "permanent global signing operation differs",
                        ));
                    }
                    previous
                } else {
                    self.maintenance_write(
                        &context,
                        term,
                        MaintenanceTransition::Begin {
                            command: command.clone(),
                        },
                    )
                    .await?
                })
            }
        };
        if status
            .as_ref()
            .is_some_and(|status| !status.command.action.is_signing_head_transition())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "operation belongs to another maintenance action",
            ));
        }
        let observation = self.backend.signing_observation().map_err(unavailable)?;
        let verifier_page = if let AuthoritySigningAction::Verifiers {
            expected_operational_revision,
            after,
            limit,
        } = &request.action
        {
            Some(
                self.backend
                    .signer_verifier_page(*expected_operational_revision, after.as_ref(), *limit)
                    .map_err(|error| Error::new(ErrorCode::Conflict, error.to_string()))?,
            )
        } else {
            None
        };
        let response = AuthoritySigningResponse {
            verifier_page,
            request_sha256: request.digest().map_err(unavailable)?,
            current: observation.0.clone(),
            policy_epoch: observation.1,
            operational_revision: observation.2,
            status,
        };
        response
            .validate_for(&request, &domain)
            .map_err(unavailable)?;
        let fence = AuthoritySigningResponseFence {
            authorization,
            observation,
        };
        fence.release().await.map_err(|error| {
            if matches!(request.action, AuthoritySigningAction::Start { .. }) {
                unknown(error)
            } else {
                error
            }
        })?;
        Ok((response, fence))
    }
}
