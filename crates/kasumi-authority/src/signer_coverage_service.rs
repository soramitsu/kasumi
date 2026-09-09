//! The installed transport must return the SDK's opaque actual-TLS observation.
//! Public callers may ask for dispatch or resume; none may submit an ack DTO.
use super::*;
use crate::state::signer_coverage_state::{CoverageTransition, PreparedCoverage};

#[async_trait::async_trait]
pub trait SignerPublicationTransport: Send + Sync {
    async fn observe(
        &self,
        dispatch: &SignerCoverageDispatch,
    ) -> anyhow::Result<kasumi_client::CurrentSignerPublication>;
}
pub struct SignerCoverageFence {
    authority: Arc<AuthorityAdministrativeFence>,
    status: SignerCoverageStatus,
    publication: Option<kasumi_client::CurrentSignerPublication>,
}
impl SignerCoverageFence {
    pub fn check(&self) -> Result<()> {
        self.authority.check()?;
        if let Some(publication) = &self.publication {
            publication
                .check(&self.status.dispatch)
                .map_err(unavailable)?;
        }
        if self
            .authority
            .authority
            .backend
            .signer_coverage_status(self.status.dispatch.command.operation_id)
            .map_err(unavailable)?
            .as_ref()
            != Some(&self.status)
        {
            return Err(unavailable("original coverage observation changed"));
        }
        Ok(())
    }
    pub async fn release(&self) -> Result<()> {
        self.authority.release().await?;
        self.check()
    }
}
impl IndependentAuthority {
    pub fn install_signer_publication_transport(
        &self,
        transport: Arc<dyn SignerPublicationTransport>,
    ) -> anyhow::Result<()> {
        self.signer_publication_transport
            .set(transport)
            .map_err(|_| anyhow::anyhow!("signer publication transport already installed"))
    }
    pub async fn signer_coverage(
        self: &Arc<Self>,
        context: RequestContext,
        request: SignerCoverageRequest,
    ) -> Result<(SignerCoverageStatus, SignerCoverageFence)> {
        request
            .validate()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let authorization = self.authorize_signer_maintenance(context.clone()).await?;
        let operation_id = request.operation_id();
        let resume = matches!(request, SignerCoverageRequest::Resume { .. });
        let read_only = matches!(request, SignerCoverageRequest::Status { .. });
        let mut status = match request {
            SignerCoverageRequest::Start { command } => {
                let _serial = self.proposal.lock().await;
                authorization.release().await?;
                let term = self.barrier(&context).await?;
                self.coverage_write(&context, term, CoverageTransition::Begin { command })
                    .await?
            }
            SignerCoverageRequest::Resume { .. } | SignerCoverageRequest::Status { .. } => self
                .backend
                .signer_coverage_status(operation_id)
                .map_err(unavailable)?
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "coverage dispatch absent"))?,
        };
        // Start durably publishes the exact dispatch before any external work.
        // Resume may inspect an expired original local command, but the receiver
        // cannot perform its first effect after that command's original bound.
        let mut current_publication = None;
        if resume && status.acknowledgment.is_none() {
            let transport = self
                .signer_publication_transport
                .get()
                .ok_or_else(|| unavailable("installed signer publication transport unavailable"))?;
            authorization.release().await?;
            status
                .dispatch
                .command
                .publication
                .validate_for_head(&self.backend.signing_head().map_err(unavailable)?)
                .map_err(unavailable)?;
            self.coverage_permission_before_dispatch(&context, &authorization, &status.dispatch)
                .await?;
            let publication = transport.observe(&status.dispatch).await.map_err(unknown)?;
            publication.check(&status.dispatch).map_err(unknown)?;
            publication
                .response()
                .validate_for(
                    &status.dispatch.command.publication,
                    &self.installation().manifest,
                )
                .map_err(unknown)?;
            self.backend
                .check_signer_coverage_publication(&status.dispatch, publication.response())
                .map_err(unknown)?;
            let _serial = self.proposal.lock().await;
            authorization.release().await.map_err(unknown)?;
            publication.check(&status.dispatch).map_err(unknown)?;
            let term = self.barrier(&context).await.map_err(unknown)?;
            status = self
                .coverage_write(
                    &context,
                    term,
                    CoverageTransition::Acknowledge {
                        operation_id,
                        dispatch_sha256: status.dispatch.digest().map_err(unknown)?,
                        publication: publication.response().clone(),
                    },
                )
                .await
                .map_err(unknown)?;
            publication.check(&status.dispatch).map_err(unknown)?;
            current_publication = Some(publication);
        }
        let fence = SignerCoverageFence {
            authority: authorization,
            status: status.clone(),
            publication: current_publication,
        };
        fence
            .release()
            .await
            .map_err(|error| if read_only { error } else { unknown(error) })?;
        Ok((status, fence))
    }
    async fn coverage_permission_before_dispatch(
        &self,
        context: &RequestContext,
        authorization: &AuthorityAdministrativeFence,
        dispatch: &SignerCoverageDispatch,
    ) -> Result<()> {
        use crate::state::maintenance_state::MaintenanceTransition;
        let _serial = self.proposal.lock().await;
        authorization.release().await?;
        let local = dispatch.command.publication.command();
        let action = match &dispatch.command.publication {
            SignerPublicationRequest::Issuer { directive, .. } => {
                AuthorityMaintenanceAction::AuthorizeSignerTrust {
                    directive: directive.clone(),
                }
            }
            SignerPublicationRequest::Control { request } => {
                AuthorityMaintenanceAction::AuthorizeControlSigner {
                    directive: Box::new(request.directive.clone()),
                }
            }
        };
        let status = if let Some(status) = self
            .backend
            .maintenance_status(local.operation_id)
            .map_err(unavailable)?
        {
            status
        } else {
            let configuration = self
                .backend
                .operational_configuration()
                .map_err(unavailable)?;
            if configuration.policy_epoch != dispatch.command.expected_policy_epoch {
                return Err(unavailable(
                    "original coverage policy no longer permits first dispatch",
                ));
            }
            let term = self.barrier(context).await?;
            self.maintenance_write(
                context,
                term,
                MaintenanceTransition::Begin {
                    command: AuthorityMaintenanceCommand {
                        operation_id: local.operation_id,
                        not_after_ms: local.not_after_ms,
                        expected_policy_epoch: dispatch.command.expected_policy_epoch,
                        expected_operational_revision: configuration.revision,
                        action: action.clone(),
                    },
                },
            )
            .await?
        };
        if status.phase != AuthorityMaintenancePhase::Completed || status.command.action != action {
            return Err(unknown(
                "original local publication permission did not complete exactly",
            ));
        }
        authorization.release().await
    }
    async fn coverage_write(
        &self,
        context: &RequestContext,
        term: u64,
        transition: CoverageTransition,
    ) -> Result<SignerCoverageStatus> {
        if self.barrier(context).await? != term {
            return Err(unknown("coverage proposal leader changed"));
        }
        self.backend.authorize_admin(context)?;
        let admitted_at_ms = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        let prepared = PreparedOperation::Coverage(Box::new(PreparedCoverage {
            context: context.clone(),
            admitted_at_ms,
            authority_term: term,
            transition,
        }));
        let response = self
            .write_proposal(serde_json::to_vec(&prepared).map_err(unavailable)?, term)
            .await?;
        serde_json::from_slice(&response).map_err(unknown)?
    }
}
