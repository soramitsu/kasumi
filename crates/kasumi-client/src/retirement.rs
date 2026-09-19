use super::*;
use kasumi_types::{RetireSourceRequest, RetirementReceipt, RetirementRef, RetirementStatus};

fn invalid(error: impl std::fmt::Display) -> ClientError {
    ClientError::Json(<serde_json::Error as serde::de::Error>::custom(error))
}
fn verified(
    bytes: &[u8],
    reference: &RetirementRef,
) -> Result<VerifiedRetirementReceipt, ClientError> {
    let receipt: RetirementReceipt = serde_json::from_slice(bytes)?;
    receipt.validate().map_err(invalid)?;
    if receipt.source_incarnation != reference.source_incarnation
        || receipt.retirement_id != reference.retirement_id
        || receipt.request_digest != reference.request_digest
    {
        return Err(invalid("retirement response identity differs"));
    }
    Ok(VerifiedRetirementReceipt::new(receipt))
}
fn observed_status(
    bytes: &[u8],
    reference: &RetirementRef,
) -> Result<Option<RetirementStatus>, ClientError> {
    let status: Option<RetirementStatus> = serde_json::from_slice(bytes)?;
    if let Some(status) = &status {
        if status.reference != *reference || status.accepted_revision == 0 {
            return Err(invalid("retirement status identity differs"));
        }
        kasumi_types::validate_name(&status.principal).map_err(invalid)?;
        kasumi_types::validate_name(&status.tenant).map_err(invalid)?;
        if let Ok(receipt) = &status.outcome {
            receipt.validate().map_err(invalid)?;
            if receipt.source_incarnation != reference.source_incarnation
                || receipt.retirement_id != reference.retirement_id
                || receipt.request_digest != reference.request_digest
                || receipt.tenant != status.tenant
                || receipt.revision != status.accepted_revision
                || receipt.principal != status.principal
            {
                return Err(invalid("retirement status outcome differs"));
            }
        }
    }
    Ok(status)
}
impl KasumiAdminClient {
    pub async fn read_custody(
        &mut self,
        bearer: &str,
        reference: &RetirementRef,
    ) -> Result<kasumi_types::CustodyStatus, ClientError> {
        reference.validate().map_err(invalid)?;
        let response = self
            .inner
            .read_custody(self.authorized(
                bearer,
                proto::RetirementReference {
                    request_json: encode(reference)?,
                },
            )?)
            .await?
            .into_inner();
        let status: kasumi_types::CustodyStatus = serde_json::from_slice(&response.response_json)?;
        if status.retirement != *reference || status.policy_epoch == 0 || status.revision == 0 {
            return Err(invalid("custody response identity differs"));
        }
        status.limits.validate().map_err(invalid)?;
        kasumi_types::validate_custody_administrators(&status.administrators).map_err(invalid)?;
        Ok(status)
    }
    pub async fn execute_custody(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CustodyRequest,
    ) -> Result<kasumi_types::CustodyReceipt, ClientError> {
        request.validate().map_err(invalid)?;
        let response = self
            .inner
            .execute_custody(self.authorized(
                bearer,
                proto::CustodyCommandRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let receipt: kasumi_types::CustodyReceipt =
            serde_json::from_slice(&response.response_json)?;
        receipt.validate().map_err(invalid)?;
        if receipt.command_id != request.command_id
            || receipt.request_digest != request.digest().map_err(invalid)?
        {
            return Err(invalid("custody receipt identity differs"));
        }
        Ok(receipt)
    }

    /// Source-incarnation-scoped permanent command. A repeated exact request
    /// observes the original actor/outcome under current Admin; it never renews
    /// serving authority or advances the retirement epoch again.
    pub async fn retire_source(
        &mut self,
        bearer: &str,
        request: &RetireSourceRequest,
    ) -> Result<VerifiedRetirementReceipt, ClientError> {
        let reference = request.reference().map_err(invalid)?;
        let mut wire = self.authorized(
            bearer,
            proto::RetireSourceRequest {
                request_json: encode(request)?,
            },
        )?;
        if self.deadline.is_none() {
            wire.set_timeout(std::time::Duration::from_secs(310));
        }
        let response = self.inner.retire_source(wire).await?.into_inner();
        let proof = verified(&response.response_json, &reference)?;
        if proof.checkpoint() != &request.checkpoint
            || proof.target_incarnation() != request.target_incarnation
            || proof.receipt().admitted_at_ms > request.not_after_ms
        {
            return Err(invalid("retirement response request binding differs"));
        }
        Ok(proof)
    }

    pub async fn retirement_status(
        &mut self,
        bearer: &str,
        reference: &RetirementRef,
    ) -> Result<Option<RetirementStatus>, ClientError> {
        reference.validate().map_err(invalid)?;
        let response = self
            .inner
            .retirement_status(self.authorized(
                bearer,
                proto::RetirementReference {
                    request_json: encode(reference)?,
                },
            )?)
            .await?
            .into_inner();
        observed_status(&response.response_json, reference)
    }

    pub async fn abort_retirement(
        &mut self,
        bearer: &str,
        request: &RetireSourceRequest,
    ) -> Result<VerifiedRetirementResolution, ClientError> {
        let reference = request.reference().map_err(invalid)?;
        let response = self
            .inner
            .abort_retirement(self.authorized(
                bearer,
                proto::RetireSourceRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let status = observed_status(&response.response_json, &reference)?
            .ok_or_else(|| invalid("retirement stop outcome absent"))?;
        if status.tenant != request.checkpoint.tenant {
            return Err(invalid("retirement stop tenant differs"));
        }
        match &status.outcome {
            Ok(receipt) => {
                if receipt.checkpoint != request.checkpoint
                    || receipt.target_incarnation != request.target_incarnation
                    || receipt.admitted_at_ms > request.not_after_ms
                {
                    return Err(invalid("retirement stop resolved a different request"));
                }
                Ok(VerifiedRetirementResolution::Retired(
                    VerifiedRetirementReceipt::new(receipt.clone()),
                ))
            }
            Err(_) => Ok(VerifiedRetirementResolution::Stopped(
                VerifiedRetirementStop::new(status),
            )),
        }
    }

    /// Only a successful response from the configured authenticated Admin
    /// channel can construct this proof. Wire observations cannot do so.
    pub async fn verify_retirement_receipt(
        &mut self,
        bearer: &str,
        reference: &RetirementRef,
    ) -> Result<VerifiedRetirementReceipt, ClientError> {
        reference.validate().map_err(invalid)?;
        let response = self
            .inner
            .verify_retirement_receipt(self.authorized(
                bearer,
                proto::RetirementReference {
                    request_json: encode(reference)?,
                },
            )?)
            .await?
            .into_inner();
        verified(&response.response_json, reference)
    }
}
