use super::*;

impl NativeAdmin {
    pub(super) async fn abort_retirement_rpc(
        &self,
        request: Request<RetireSourceRequest>,
    ) -> Result<Response<RetirementStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::RetireSourceRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let reference = request.reference().map_err(status)?;
        let database = self
            .retirement_source(&context, &reference.source_incarnation)
            .await?;
        let resolution = database
            .abort_retirement(context.clone(), request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let fence = self
            .auth
            .audit_result(
                &context,
                database.retirement_resolution_response_fence(&context, &resolution),
            )
            .await
            .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
        let observation = match &resolution {
            kasumi_engine::VerifiedRetirementResolution::Stopped(proof) => proof.status().clone(),
            kasumi_engine::VerifiedRetirementResolution::Retired(proof) => {
                kasumi_types::RetirementStatus {
                    tenant: proof.tenant().into(),
                    principal: proof.receipt().principal.clone(),
                    reference,
                    accepted_revision: proof.revision(),
                    outcome: Ok(proof.receipt().clone()),
                }
            }
        };
        let response = RetirementStatusResponse {
            response_json: encode_json(&Some(observation)).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, true)
                .await
                .map_err(status)?,
        ))
    }

    async fn retirement_source(
        &self,
        context: &RequestContext,
        incarnation: &str,
    ) -> Result<kasumi_engine::InstalledRetirementSource, Status> {
        let source = self
            .auth
            .audit_result(
                context,
                self.registry.retirement_source(context, incarnation),
            )
            .await
            .map_err(status)?;
        self.auth
            .audit_result(
                context,
                source
                    .response_fence(context)
                    .and_then(|fence| fence.check()),
            )
            .await
            .map_err(status)?;
        Ok(source)
    }

    pub(super) async fn read_custody_rpc(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<CustodyStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let reference: kasumi_types::RetirementRef =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let source = self
            .retirement_source(&context, &reference.source_incarnation)
            .await?;
        let custody = source.retired().map_err(status)?;
        let fence = custody.response_fence(&context).map_err(status)?;
        let result = custody.status(&context, &reference).await.map_err(status)?;
        let response = CustodyStatusResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }
    pub(super) async fn execute_custody_rpc(
        &self,
        request: Request<CustodyCommandRequest>,
    ) -> Result<Response<CustodyReceiptResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::CustodyRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let source = self
            .retirement_source(&context, &request.retirement.source_incarnation)
            .await?;
        let custody = source.retired().map_err(status)?;
        let result = custody
            .execute(context.clone(), request)
            .await
            .map_err(status)?;
        let fence = custody
            .response_fence(&context)
            .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
        let response = CustodyReceiptResponse {
            response_json: encode_json(&result)
                .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, true)
                .await
                .map_err(status)?,
        ))
    }

    pub(super) async fn read_custody_receipt_rpc(
        &self,
        request: Request<CustodyCommandRequest>,
    ) -> Result<Response<CustodyReceiptResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::CustodyRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let source = self
            .retirement_source(&context, &request.retirement.source_incarnation)
            .await?;
        let custody = source.retired().map_err(status)?;
        let fence = custody.response_fence(&context).map_err(status)?;
        let receipt = custody.receipt(&context, &request).await.map_err(status)?;
        let response = CustodyReceiptResponse {
            response_json: encode_json(&receipt).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }

    pub(super) async fn retire_source_rpc(
        &self,
        request: Request<RetireSourceRequest>,
    ) -> Result<Response<RetirementReceiptResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::RetireSourceRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self
            .retirement_source(&context, &request.expected_source_incarnation)
            .await?;
        let proof = database
            .retire_source(context.clone(), request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        // Retirement intentionally changes the policy epoch. This is the
        // committed epoch fence, while the original live credential is retained.
        let fence = self
            .auth
            .audit_result(
                &context,
                database.retirement_response_fence(&context, &proof),
            )
            .await
            .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
        let response = RetirementReceiptResponse {
            response_json: encode_json(proof.receipt()).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, true)
                .await
                .map_err(status)?,
        ))
    }

    pub(super) async fn retirement_status_rpc(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<RetirementStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let reference: kasumi_types::RetirementRef =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self
            .retirement_source(&context, &reference.source_incarnation)
            .await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .retirement_status(&context, &reference)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = RetirementStatusResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }

    pub(super) async fn verify_retirement_receipt_rpc(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<RetirementReceiptResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let reference: kasumi_types::RetirementRef =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self
            .retirement_source(&context, &reference.source_incarnation)
            .await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let proof = database
            .verify_retirement_receipt(context.clone(), &reference)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let proof_fence = self
            .auth
            .audit_result(
                &context,
                database.retirement_response_fence(&context, &proof),
            )
            .await
            .map_err(status)?;
        let response = RetirementReceiptResponse {
            response_json: encode_json(proof.receipt()).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof_fence.check())
            .await
            .map_err(status)?;
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }
}
