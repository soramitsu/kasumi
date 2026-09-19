//! Typed, bounded Control recovery observations. Each call uses the caller's
//! current credential. Responses remain historical state and grant no phase
//! authority; ambiguous operations retain their original semantic identity.
use crate::{ClientError, KasumiClientConfig, encode, proto};
use kasumi_types::*;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct KasumiRecoveryClient {
    deadline: Option<tokio::time::Instant>,
    inner: proto::kasumi_recovery_control_client::KasumiRecoveryControlClient<Channel>,
}
impl KasumiRecoveryClient {
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
    pub async fn connect(config: &KasumiClientConfig) -> std::result::Result<Self, ClientError> {
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            deadline: None,
            inner: proto::kasumi_recovery_control_client::KasumiRecoveryControlClient::new(channel)
                .max_encoding_message_size(MAX_RECOVERY_RECORD_BYTES + 1024)
                .max_decoding_message_size(MAX_RECOVERY_RECORD_BYTES + 1024),
        })
    }
    pub async fn start(
        &mut self,
        bearer: &str,
        request: &RecoveryStart,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        request.validate().map_err(anyhow::Error::from)?;
        let response = self
            .inner
            .start(self.wire(bearer, request)?)
            .await?
            .into_inner();
        let record = head(response, request.operation_id)?;
        if record.request != *request {
            return Err(anyhow::anyhow!(
                "recovery start response differs from exact original input"
            )
            .into());
        }
        Ok(record)
    }
    pub async fn status(
        &mut self,
        bearer: &str,
        request: &RecoveryStatusRequest,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        let response = self
            .inner
            .status(self.wire(bearer, request)?)
            .await?
            .into_inner();
        head(response, request.operation_id)
    }
    pub async fn resume(
        &mut self,
        bearer: &str,
        request: &RecoveryResume,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        if !(1..=16).contains(&request.max_steps) {
            return Err(
                anyhow::anyhow!("recovery resume work limit is one to sixteen phases").into(),
            );
        }
        let response = self
            .inner
            .resume(self.wire(bearer, request)?)
            .await?
            .into_inner();
        head(response, request.operation_id)
    }
    pub async fn stop(
        &mut self,
        bearer: &str,
        request: &RecoveryStop,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        if request.command_id.is_nil() {
            return Err(ClientError::Authorization);
        }
        let response = self
            .inner
            .stop(self.wire(bearer, request)?)
            .await?
            .into_inner();
        let record = head(response, request.operation_id)?;
        if record.stop_request != Some(request.command_id) {
            return Err(
                anyhow::anyhow!("recovery stop response differs from original command").into(),
            );
        }
        Ok(record)
    }
    pub async fn read_phase(
        &mut self,
        bearer: &str,
        request: &RecoveryPhaseRequest,
    ) -> std::result::Result<RecoveryPhaseRecord, ClientError> {
        let response = self
            .inner
            .read_phase(self.wire(bearer, request)?)
            .await?
            .into_inner();
        let phase: RecoveryPhaseRecord = decode(response)?;
        phase.validate().map_err(anyhow::Error::from)?;
        if phase.operation_id != request.operation_id || phase.phase_id != request.phase_id {
            return Err(anyhow::anyhow!("recovery phase response identity differs").into());
        }
        Ok(phase)
    }
    fn wire(
        &self,
        bearer: &str,
        value: &impl serde::Serialize,
    ) -> std::result::Result<tonic::Request<proto::ControlJsonRequest>, ClientError> {
        if staged_digest(value).map_err(anyhow::Error::from)?.1 > MAX_RECOVERY_RECORD_BYTES {
            return Err(ClientError::RequestTooLarge);
        }
        self.authorized(
            bearer,
            proto::ControlJsonRequest {
                request_json: encode(value)?,
            },
        )
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    response: proto::ControlJsonResponse,
) -> std::result::Result<T, ClientError> {
    if response.response_json.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(ClientError::RequestTooLarge);
    }
    Ok(serde_json::from_slice(&response.response_json)?)
}
fn head(
    response: proto::ControlJsonResponse,
    operation: uuid::Uuid,
) -> std::result::Result<RecoveryRecord, ClientError> {
    let record: RecoveryRecord = decode(response)?;
    record.validate().map_err(anyhow::Error::from)?;
    if operation.is_nil() || record.request.operation_id != operation {
        return Err(anyhow::anyhow!("recovery response operation differs").into());
    }
    Ok(record)
}
