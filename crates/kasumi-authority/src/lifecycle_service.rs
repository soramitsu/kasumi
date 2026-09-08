use super::*;
use crate::state::lifecycle_state::PreparedLifecycle;
use kasumi_types::{ControlEpochStopObservation, SignedControlEpochStop};
impl IndependentAuthority {
    pub async fn execute_lifecycle(
        self: &Arc<Self>,
        context: RequestContext,
        request: LifecycleAuthorityRequest,
    ) -> Result<(SignedLifecycleAuthorityReceipt, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        self.installation()
            .manifest
            .verify_lifecycle_request(self.installation().partition, &request)
            .map_err(|_| {
                Error::new(
                    ErrorCode::Forbidden,
                    "installed committed control proof required",
                )
            })?;
        self.barrier(&context).await?;
        self.backend.authorize_admin(&context)?;
        let service = self.clone();
        let job = tokio::spawn(async move {
            let _permit = permit;
            service
                .execute_lifecycle_owned(signer, context, request)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), job)
            .await
            .map_err(unknown)?
            .map_err(unknown)?
    }
    async fn execute_lifecycle_owned(
        self: Arc<Self>,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        request: LifecycleAuthorityRequest,
    ) -> Result<(SignedLifecycleAuthorityReceipt, AuthorityResponseFence)> {
        let _gate = self.proposal.lock().await;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        self.installation()
            .manifest
            .verify_lifecycle_request(self.installation().partition, &request)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "control proof verification failed"))?;
        let reference = request.reference();
        if let Some(retained) = self
            .backend
            .lifecycle_receipt(&reference)
            .map_err(unavailable)?
        {
            if retained.request_sha256 != request.digest().map_err(unavailable)? {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "permanent control issuer identity differs",
                ));
            }
            return self
                .release_lifecycle(signer.clone(), context, retained, epoch, term, false)
                .await;
        }
        let admitted_at_ms = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_live()?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        let prepared = PreparedLifecycle {
            context: context.clone(),
            request,
            admitted_at_ms,
            authority_term: term,
            expected_policy_epoch: epoch,
        };
        let bytes = self
            .write_proposal(
                serde_json::to_vec(&PreparedOperation::Lifecycle(Box::new(prepared)))
                    .map_err(unavailable)?,
                term,
            )
            .await?;
        let receipt: Result<LifecycleAuthorityReceipt> =
            serde_json::from_slice(&bytes).map_err(unknown)?;
        self.release_lifecycle(signer.clone(), context, receipt?, epoch, term, true)
            .await
    }
    async fn release_lifecycle(
        self: &Arc<Self>,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        receipt: LifecycleAuthorityReceipt,
        epoch: u64,
        term: u64,
        accepted: bool,
    ) -> Result<(SignedLifecycleAuthorityReceipt, AuthorityResponseFence)> {
        let outcome = async {
            if self.barrier(&context).await? != term {
                return Err(unavailable("control receipt release term changed"));
            }
            let fence = self.fence(signer.clone(), context, Some(epoch), None, term);
            fence.check()?;
            let signed = signer
                .sign_lifecycle_receipt(receipt)
                .map_err(unavailable)?;
            fence.check()?;
            Ok((signed, fence))
        }
        .await;
        if accepted {
            outcome.map_err(unknown)
        } else {
            outcome
        }
    }
    pub async fn read_lifecycle_receipt(
        self: &Arc<Self>,
        context: RequestContext,
        reference: LifecycleAuthorityReference,
    ) -> Result<(
        Option<SignedLifecycleAuthorityReceipt>,
        AuthorityResponseFence,
    )> {
        let _permit = self.permit()?;
        let signer = self.request_signer()?;
        reference.validate().map_err(unavailable)?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let receipt = self
            .backend
            .lifecycle_receipt(&reference)
            .map_err(unavailable)?
            .map(|value| signer.sign_lifecycle_receipt(value).map_err(unavailable))
            .transpose()?;
        let fence = self.fence(signer.clone(), context, Some(epoch), None, term);
        fence.release().await?;
        Ok((receipt, fence))
    }
    pub async fn verify_control_stop(
        self: &Arc<Self>,
        context: RequestContext,
        reference: LifecycleAuthorityReference,
    ) -> Result<(SignedControlEpochStop, AuthorityResponseFence)> {
        let _permit = self.permit()?;
        let signer = self.request_signer()?;
        reference.validate().map_err(unavailable)?;
        if !matches!(reference.identity, LifecycleAuthorityIdentity::EpochStop) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "exact stopped control epoch required",
            ));
        }
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let receipt = self
            .backend
            .lifecycle_receipt(&reference)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("control epoch not stopped"))?;
        let LifecycleAuthorityRequest::StopEpoch(signed) = &receipt.request else {
            return Err(unavailable("control epoch receipt is not a stop"));
        };
        let witness = format!("control/{}", receipt.request_sha256);
        self.require_drain(&witness, term)?;
        let fence = self.fence(signer.clone(), context, Some(epoch), None, term);
        fence.release().await?;
        self.require_drain(&witness, term)?;
        let observation = ControlEpochStopObservation {
            stop: signed.observation.stop.clone(),
            accepted_revision: receipt.accepted_revision,
            accepted_term: receipt.accepted_term,
            observed_revision: self.backend.revision().map_err(unavailable)?,
            observed_term: term,
            drain_ms: self
                .installation()
                .manifest
                .drain_ms()
                .map_err(unavailable)?,
        };
        let signed = signer
            .sign_control_epoch_stop(observation)
            .map_err(unavailable)?;
        fence.check()?;
        Ok((signed, fence))
    }
    pub async fn acquire_lifecycle(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: LifecycleLeaseRequest,
    ) -> Result<(SignedLifecycleLease, AuthorityResponseFence)> {
        let _permit = self.permit()?;
        let signer = self.request_signer()?;
        request
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid lifecycle acquisition"))?;
        let context = caller.context;
        context.authorization.require_authority(
            self.installation().manifest.authority_id,
            self.installation().partition,
        )?;
        if context.tenant != self.installation().tenant()
            || !context.scopes.contains(&kasumi_types::Action::Read)
            || context.principal != request.target_node.principal
            || caller.certificate_sha256 != request.target_node.certificate_sha256
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "lifecycle node credential or authenticated peer differs",
            ));
        }
        let term = self.barrier(&context).await?;
        let material = self.backend.lifecycle_lease_view(&request).map_err(|_| {
            Error::new(
                ErrorCode::Forbidden,
                "control intent or target is stopped or differs",
            )
        })?;
        if let Some(digest) = &material.target_drain {
            self.require_drain(&format!("target/{digest}"), term)?;
        }
        let now = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_live()?;
        context.authorization.check_admitted_at(now)?;
        let expiry = context
            .authorization
            .expires_at_ms()
            .map(|e| e.min(material.commitment.intent.original_credential_expires_at_ms))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unauthorized,
                    "actual expiring node credential required",
                )
            })?;
        let remaining = expiry.checked_sub(now).filter(|n| *n > 0).ok_or_else(|| {
            Error::new(
                ErrorCode::Unauthorized,
                "original control or node credential expired",
            )
        })?;
        let max = self.installation().manifest.max_lease_ms;
        self.check_active_signer(&signer)?;
        let signed = signer
            .sign_lifecycle_lease(LifecycleLeaseClaims {
                request: request.clone(),
                commitment: material.commitment,
                authority_id: self.installation().manifest.authority_id,
                partition: self.installation().partition,
                authority_term: term,
                authority_revision: material.revision,
                application_purpose: material.application_purpose,
                lifetime_ms: max,
                credential_lifetime_ms: max.min(remaining),
            })
            .map_err(unavailable)?;
        let mut fence = self.fence(signer.clone(), context, None, None, term);
        fence.lifecycle_lease = Some(request);
        fence.release().await?;
        Ok((signed, fence))
    }
}
