use super::*;
use crate::target_runtime::TargetRecoveryRuntime;
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct NativeTargetRecovery {
    runtime: Arc<TargetRecoveryRuntime>,
    auth: Arc<Authenticator>,
}
impl NativeTargetRecovery {
    pub fn new(runtime: Arc<TargetRecoveryRuntime>, auth: Arc<Authenticator>) -> Self {
        Self { runtime, auth }
    }
    pub fn service(self) -> kasumi_target_recovery_server::KasumiTargetRecoveryServer<Self> {
        kasumi_target_recovery_server::KasumiTargetRecoveryServer::new(self)
            .max_decoding_message_size(512 << 10)
            .max_encoding_message_size(1 << 20)
    }
}
fn error(e: anyhow::Error) -> kasumi_types::Error {
    e.downcast_ref::<kasumi_types::Error>()
        .cloned()
        .unwrap_or_else(|| {
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "target recovery authority or installed resources unavailable",
            )
        })
}
fn unresolved(_: impl std::fmt::Display) -> Status {
    status(kasumi_types::Error::new(
        kasumi_types::ErrorCode::UnknownOutcome,
        "target acknowledgement unavailable; recover the exact committed identity",
    ))
}
#[tonic::async_trait]
impl kasumi_target_recovery_server::KasumiTargetRecovery for NativeTargetRecovery {
    async fn execute(
        &self,
        request: Request<TargetRuntimeRequest>,
    ) -> Result<Response<TargetRuntimeResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        context
            .authorization
            .require_control(&self.runtime.control_root().control_incarnation.to_string())
            .map_err(status)?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|p| p.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated("actual mutual TLS required"));
        }
        let bearer = Zeroizing::new(
            request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| Status::unauthenticated("original bearer unavailable"))?
                .to_owned(),
        );
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let reply = match self.runtime.execute(context.clone(), bearer, input).await {
            Ok(reply) => {
                self.auth
                    .audit_result(&context, Ok(()))
                    .await
                    .map_err(unresolved)?;
                reply
            }
            Err(failure) => {
                let failure = error(failure);
                let failure = self
                    .auth
                    .audit_result::<()>(&context, Err(failure))
                    .await
                    .unwrap_err();
                return Err(status(failure));
            }
        };
        let response = TargetRuntimeResponse {
            response_json: encode_json(&reply.response).map_err(unresolved)?,
        };
        self.auth
            .audit_result(&context, reply.release().await.map_err(error))
            .await
            .map_err(unresolved)?;
        reply.release().await.map_err(unresolved)?;
        context.authorization.check_live().map_err(unresolved)?;
        Ok(Response::new(response))
    }
}
