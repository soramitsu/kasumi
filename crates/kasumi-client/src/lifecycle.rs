use crate::{ClientError, KasumiClientConfig, encode, proto};
use kasumi_serving::{ControlTrust, VerifiedControlChange, VerifiedControlIntent};
use kasumi_types::*;
use tonic::transport::Channel;

/// Explicit pinned mTLS plus installed control signer trust. Verified immutable
/// commitments are not live phase grants; the independent issuer supplies those.
#[derive(Clone)]
pub struct KasumiLifecycleClient {
    deadline: Option<tokio::time::Instant>,
    inner: proto::kasumi_lifecycle_control_client::KasumiLifecycleControlClient<Channel>,
    trust: ControlTrust,
}
impl KasumiLifecycleClient {
    pub(crate) fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        self.deadline = Some(deadline);
    }
    fn authorized<T>(
        &self,
        bearer: &str,
        value: T,
    ) -> std::result::Result<tonic::Request<T>, ClientError> {
        crate::authorized_until(bearer, value, self.deadline)
    }
    pub async fn connect(
        config: &KasumiClientConfig,
        trust: ControlTrust,
    ) -> std::result::Result<Self, ClientError> {
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            deadline: None,
            inner: proto::kasumi_lifecycle_control_client::KasumiLifecycleControlClient::new(
                channel,
            )
            .max_encoding_message_size(16 << 20)
            .max_decoding_message_size(16 << 20),
            trust,
        })
    }
    pub async fn execute(
        &mut self,
        bearer: &str,
        command: &LifecycleControlCommand,
    ) -> std::result::Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .execute(self.authorized(
                bearer,
                proto::ControlJsonRequest {
                    request_json: encode(command)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
    pub async fn observe_intent(
        &mut self,
        bearer: &str,
        id: uuid::Uuid,
    ) -> std::result::Result<VerifiedControlIntent, ClientError> {
        let response = self
            .inner
            .observe_intent(self.authorized(
                bearer,
                proto::ControlIntentReference {
                    command_id: id.to_string(),
                },
            )?)
            .await?
            .into_inner();
        let signed: SignedControlIntent = serde_json::from_slice(&response.response_json)?;
        if signed.observation.intent.request.command_id != id {
            return Err(anyhow::anyhow!("control intent response identity differs").into());
        }
        Ok(self.trust.verify_intent(&signed)?)
    }
    pub async fn observe_change(
        &mut self,
        bearer: &str,
        id: uuid::Uuid,
        partition: &str,
    ) -> std::result::Result<VerifiedControlChange, ClientError> {
        let response = self
            .inner
            .observe_change(self.authorized(
                bearer,
                proto::ControlChangeReference {
                    command_id: id.to_string(),
                    authority_partition: partition.into(),
                },
            )?)
            .await?
            .into_inner();
        let signed: SignedControlChange = serde_json::from_slice(&response.response_json)?;
        if signed.observation.stop.change_id != id
            || signed.observation.stop.authority_partition.key() != partition
        {
            return Err(anyhow::anyhow!("control change response identity differs").into());
        }
        Ok(self.trust.verify_change(&signed)?)
    }
    pub async fn read_status(
        &mut self,
        bearer: &str,
        request: &ReadLifecycleStatus,
    ) -> std::result::Result<LifecycleStatus, ClientError> {
        if request.expected_incarnation != self.trust.root().control_incarnation {
            return Err(
                anyhow::anyhow!("control status requested another installed incarnation").into(),
            );
        }
        let response = self
            .inner
            .read_status(self.authorized(
                bearer,
                proto::ControlJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let status: LifecycleStatus = serde_json::from_slice(&response.response_json)?;
        if status.request.command_id != request.command_id
            || status.request.expected_incarnation != request.expected_incarnation
        {
            return Err(anyhow::anyhow!("control status response identity differs").into());
        }
        Ok(status)
    }
}
