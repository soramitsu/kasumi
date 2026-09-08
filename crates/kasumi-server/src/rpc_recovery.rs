//! Protected native Control coordinator. Only semantic start/resume/stop and
//! bounded point observations are exposed; dispatch journal mutations are closed.
use super::*;
use crate::recovery_runtime::ControlRecoveryCoordinator;
use kasumi_types::{
    MAX_RECOVERY_RECORD_BYTES, RecoveryControlCommand, RecoveryPhaseRequest, RecoveryResume,
    RecoveryStart, RecoveryStatusRequest, RecoveryStop,
};
#[derive(Clone)]
pub struct NativeRecoveryControl {
    runtime: Arc<ControlRecoveryCoordinator>,
    auth: Arc<Authenticator>,
}
impl NativeRecoveryControl {
    pub(crate) fn new(runtime: Arc<ControlRecoveryCoordinator>, auth: Arc<Authenticator>) -> Self {
        Self { runtime, auth }
    }
    pub fn service(self) -> kasumi_recovery_control_server::KasumiRecoveryControlServer<Self> {
        kasumi_recovery_control_server::KasumiRecoveryControlServer::new(self)
            .max_decoding_message_size((1 << 20) + 1024)
            .max_encoding_message_size((1 << 20) + 1024)
    }
    async fn context<T>(&self, request: &Request<T>) -> Result<RequestContext, Status> {
        let context = verified(&self.auth, request).await?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated("actual mutual TLS required"));
        }
        context
            .authorization
            .require_control(&self.runtime.control_incarnation().to_string())
            .map_err(status)?;
        if context.tenant != "__kasumi_control" {
            return Err(Status::permission_denied(
                "exact installed Control resource required",
            ));
        }
        Ok(context)
    }
    async fn response(
        &self,
        context: &RequestContext,
        proof: kasumi_engine::VerifiedRecoveryStatus,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        proof.release().await.map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode(proof.record()).map_err(status)?,
        };
        self.auth
            .audit_result(context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
}
fn failure(error: anyhow::Error) -> kasumi_types::Error {
    error
        .downcast_ref::<kasumi_types::Error>()
        .cloned()
        .unwrap_or_else(|| {
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "recovery phase unresolved; inspect and resume its exact durable operation",
            )
        })
}
fn encode(value: &impl serde::Serialize) -> kasumi_types::Result<Vec<u8>> {
    if kasumi_types::staged_digest(value)?.1 > MAX_RECOVERY_RECORD_BYTES {
        return Err(kasumi_types::Error::new(
            kasumi_types::ErrorCode::ResourceExhausted,
            "recovery response work limit",
        ));
    }
    encode_json(value)
}
#[tonic::async_trait]
impl kasumi_recovery_control_server::KasumiRecoveryControl for NativeRecoveryControl {
    async fn start(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: RecoveryStart =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.runtime
                    .start(context.clone(), input)
                    .await
                    .map_err(failure),
            )
            .await
            .map_err(status)?;
        self.response(&context, proof).await.map_err(|_| {
            Status::unknown("recovery start may be committed; resolve its exact operation identity")
        })
    }
    async fn status(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: RecoveryStatusRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.runtime
                    .database
                    .recovery_status(context.clone(), input.operation_id)
                    .await,
            )
            .await
            .map_err(status)?;
        self.response(&context, proof).await
    }
    async fn resume(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: RecoveryResume =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.runtime
                    .resume(context.clone(), input.operation_id, input.max_steps)
                    .await
                    .map_err(failure),
            )
            .await
            .map_err(status)?;
        self.response(&context, proof).await.map_err(|_| {
            Status::unknown("recovery phases may be committed; resolve the same operation")
        })
    }
    async fn stop(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: RecoveryStop =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.runtime
                    .database
                    .recovery_control(
                        context.clone(),
                        RecoveryControlCommand::Stop {
                            operation_id: input.operation_id,
                            command_id: input.command_id,
                        },
                    )
                    .await,
            )
            .await
            .map_err(status)?;
        self.response(&context, proof).await.map_err(|_| {
            Status::unknown("recovery stop may be committed; resume exact operation cleanup")
        })
    }
    async fn read_phase(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: RecoveryPhaseRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.runtime
                    .database
                    .recovery_phase(context.clone(), input.operation_id, input.phase_id)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode(proof.record()).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
}
