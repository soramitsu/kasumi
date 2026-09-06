//! Source-quorum-backed planned retirement; never an unavailable-source bypass.
use super::*;
use crate::{VerifiedRetirementReceipt, VerifiedRetirementResolution, VerifiedRetirementStop};

impl Database {
    pub async fn retire_source(
        &self,
        context: RequestContext,
        request: RetireSourceRequest,
    ) -> Result<VerifiedRetirementReceipt> {
        // Verification is a substantial state machine. Keep its resident
        // future off callers' stacks without detaching cancellation or guards.
        let result = Box::pin(self.retire_source_inner(&context, request)).await;
        self.audit_write_result(&context, result).await
    }

    async fn retire_source_inner(
        &self,
        context: &RequestContext,
        request: RetireSourceRequest,
    ) -> Result<VerifiedRetirementReceipt> {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        request.validate()?;
        let reference = request.reference()?;
        self.barrier().await?;
        self.engine.authorize(context, None, Action::Admin)?;
        let existing =
            crate::state::retirement::admit(&self.engine.generation()?.state, context, &request)?;
        if let Some(outcome) = existing {
            outcome?;
            return self
                .verify_retirement_receipt(context.clone(), &reference)
                .await;
        }
        let destination = self.archive_destination(&request.destination)?;
        let verified_closure_digest = self
            .verified_retirement_closure(context, destination.as_ref(), request.checkpoint.clone())
            .await?;
        self.engine.authorize(context, None, Action::Admin)?;
        self.submit(
            context.clone(),
            Operation::RetireSource(PreparedRetirement {
                request,
                verified_closure_digest,
                observation: None,
            }),
        )
        .await?;
        // Once consensus accepted the fence, an unavailable/expired proof
        // release is an uncertain acknowledgement, never a rolled-back source.
        self.verify_retirement_receipt(context.clone(), &reference)
            .await
            .map_err(|error| {
                if error.code == ErrorCode::UnknownOutcome {
                    error
                } else {
                    Error::new(
                        ErrorCode::UnknownOutcome,
                        "retirement committed; resolve its exact permanent outcome",
                    )
                }
            })
    }

    pub async fn retirement_status(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<Option<RetirementStatus>> {
        let result = self.retirement_status_inner(context, reference).await;
        self.audit_result(context, result).await
    }

    async fn retirement_status_inner(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<Option<RetirementStatus>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        reference.validate()?;
        let fence = self.response_fence(context)?;
        self.barrier().await?;
        self.engine.authorize(context, None, Action::Admin)?;
        let generation = self.engine.generation()?;
        let result = crate::state::retirement::lookup(&generation.state, context, reference)?.map(
            |record| RetirementStatus {
                tenant: generation.state.tenant.clone(),
                principal: record.principal.clone(),
                reference: reference.clone(),
                accepted_revision: record.accepted_revision,
                outcome: record.outcome.clone(),
            },
        );
        let revision = generation.state.revision;
        drop(generation);
        self.maintenance_audit_inner(context.clone(), "retirement_status", "completed", revision)
            .await?;
        self.engine.authorize(context, None, Action::Admin)?;
        fence.check()?;
        Ok(result)
    }

    pub async fn verify_retirement_receipt(
        &self,
        context: RequestContext,
        reference: &RetirementRef,
    ) -> Result<VerifiedRetirementReceipt> {
        let result = async {
            self.engine.authorize(&context, None, Action::Admin)?;
            let fence = self.response_fence(&context)?;
            let status = self
                .retirement_status(&context, reference)
                .await?
                .ok_or_else(|| {
                    Error::new(ErrorCode::NotFound, "retirement command not accepted")
                })?;
            let receipt = status.outcome?;
            let proof = VerifiedRetirementReceipt::new(receipt);
            self.retirement_response_fence(&context, &proof)?.check()?;
            fence.check()?;
            Ok(proof)
        }
        .await;
        self.audit_result(&context, result).await
    }

    /// Ordered durable stop for the full exact request. An accepted retirement
    /// wins permanently; otherwise the stored failure/stop defeats every delayed
    /// same-ID preparation. The old action deadline does not prevent stopping it.
    pub async fn abort_retirement(
        &self,
        context: RequestContext,
        request: RetireSourceRequest,
    ) -> Result<VerifiedRetirementResolution> {
        let result = async {
            self.engine.authorize(&context, None, Action::Admin)?;
            let reference = request.reference()?;
            self.submit(context.clone(), Operation::AbortRetirement(request))
                .await?;
            let resolved = async {
                let status = self
                    .retirement_status(&context, &reference)
                    .await?
                    .ok_or_else(|| {
                        Error::new(ErrorCode::NotFound, "retirement resolution absent")
                    })?;
                let resolution = match &status.outcome {
                    Ok(receipt) => VerifiedRetirementResolution::Retired(
                        VerifiedRetirementReceipt::new(receipt.clone()),
                    ),
                    Err(_) => {
                        VerifiedRetirementResolution::Stopped(VerifiedRetirementStop::new(status))
                    }
                };
                self.retirement_resolution_response_fence(&context, &resolution)?
                    .check()?;
                Ok(resolution)
            }
            .await;
            resolved.map_err(|_: Error| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "retirement stop admitted; resolve the exact permanent outcome",
                )
            })
        }
        .await;
        self.audit_write_result(&context, result).await
    }

    pub fn retirement_resolution_response_fence(
        &self,
        context: &RequestContext,
        resolution: &VerifiedRetirementResolution,
    ) -> Result<ResponseFence<'_>> {
        match resolution {
            VerifiedRetirementResolution::Retired(proof) => {
                self.retirement_response_fence(context, proof)
            }
            VerifiedRetirementResolution::Stopped(proof) => {
                let fence = self.response_fence(context)?;
                self.engine.authorize(context, None, Action::Admin)?;
                let generation = self.engine.generation()?;
                let record = crate::state::retirement::lookup(
                    &generation.state,
                    context,
                    proof.reference(),
                )?
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "retirement stop absent"))?;
                if generation.state.retired
                    || generation.state.tenant != proof.tenant()
                    || record.accepted_revision != proof.revision()
                    || record.principal != proof.principal()
                    || record.outcome != proof.status().outcome
                    || record.outcome.is_ok()
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "retirement stop observation differs",
                    ));
                }
                fence.check()?;
                Ok(fence)
            }
        }
    }

    pub fn retirement_response_fence(
        &self,
        context: &RequestContext,
        proof: &VerifiedRetirementReceipt,
    ) -> Result<ResponseFence<'_>> {
        let fence = self.response_fence(context)?;
        self.engine.authorize(context, None, Action::Admin)?;
        let generation = self.engine.generation()?;
        let reference = RetirementRef {
            source_incarnation: proof.source_incarnation().into(),
            retirement_id: proof.retirement_id().into(),
            request_digest: proof.request_digest().into(),
        };
        let record = crate::state::retirement::lookup(&generation.state, context, &reference)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "retirement receipt absent"))?;
        if !generation.state.retired
            || !generation.state.suspended
            || record.outcome.as_ref().ok() != Some(proof.receipt())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "source retirement fence differs",
            ));
        }
        fence.check()?;
        Ok(fence)
    }
}
