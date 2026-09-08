use crate::{ClientError, KasumiAdminClient, authorized, encode, proto};
use kasumi_clock::{ClockObservation, ElapsedDeadline};
use kasumi_serving::{
    AuthorityManifest, ControlSignerObservation, ControlSignerRequest, ControlSignerResponse,
};

/// Constructed only from an actual pinned issuer response. Copies retain the
/// original suspend-aware clock anchor; deserialization cannot create one.
#[derive(Clone)]
pub struct CurrentControlSignerObservation {
    observation: ControlSignerObservation,
    deadline: ElapsedDeadline,
}
impl CurrentControlSignerObservation {
    pub(crate) fn from_current_response(
        observation: ControlSignerObservation,
        anchor: ClockObservation,
    ) -> Result<Self, ClientError> {
        let deadline = anchor.until(
            anchor
                .utc_ms()
                .checked_add(observation.lifetime_ms)
                .ok_or_else(|| anyhow::anyhow!("current issuer observation deadline overflow"))?,
        )?;
        let current = Self {
            observation,
            deadline,
        };
        current.check()?;
        Ok(current)
    }
    pub fn check(&self) -> anyhow::Result<()> {
        self.deadline.check()
    }
    pub fn observation(&self) -> &ControlSignerObservation {
        &self.observation
    }
}

impl KasumiAdminClient {
    pub async fn control_signer_maintenance(
        &mut self,
        bearer: &str,
        request: &ControlSignerRequest,
        manifest: &AuthorityManifest,
    ) -> Result<ControlSignerResponse, ClientError> {
        request.digest()?;
        let reply = self
            .inner
            .control_signer_maintenance(authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let reply: ControlSignerResponse = serde_json::from_slice(&reply.response_json)?;
        reply.validate_for(request, manifest)?;
        Ok(reply)
    }
}
