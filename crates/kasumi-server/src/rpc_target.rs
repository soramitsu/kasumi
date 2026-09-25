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
    async fn read_initial_start(
        &self,
        request: Request<kasumi_client::proto::TargetStartQuery>,
    ) -> Result<Response<kasumi_client::proto::TargetStartStatus>, Status> {
        let context = verified(&self.auth, &request).await?;
        context
            .authorization
            .require_control(&self.runtime.control_root().control_incarnation.to_string())
            .map_err(status)?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated("actual mutual TLS required"));
        }
        let bearer = Zeroizing::new(
            request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .ok_or_else(|| Status::unauthenticated("original bearer unavailable"))?
                .to_owned(),
        );
        let query: kasumi_types::TargetInitialStartRequest =
            decode_json(&request.into_inner().query_json).map_err(status)?;
        query
            .validate_for_node(self.runtime.node_id())
            .map_err(|cause| status(error(cause)))?;
        let reply = match self
            .runtime
            .read_initial_start(context.clone(), bearer, query)
            .await
        {
            Ok(reply) => {
                self.auth
                    .audit_result(&context, Ok(()))
                    .await
                    .map_err(status)?;
                reply
            }
            Err(cause) => {
                return Err(status(
                    self.auth
                        .audit_result::<()>(&context, Err(error(cause)))
                        .await
                        .unwrap_err(),
                ));
            }
        };
        let response = kasumi_client::proto::TargetStartStatus {
            status_json: encode_json(&reply.status).map_err(status)?,
        };
        self.auth
            .audit_result(&context, reply.release().await.map_err(error))
            .await
            .map_err(status)?;
        reply
            .release()
            .await
            .map_err(|cause| status(error(cause)))?;
        context.authorization.check_live().map_err(status)?;
        Ok(Response::new(response))
    }

    async fn read_initial_membership_history(
        &self,
        request: Request<TargetHistoryQuery>,
    ) -> Result<Response<TargetHistoryStatus>, Status> {
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
        let query: kasumi_types::TargetInitialMembershipHistoryRequest =
            decode_json(&request.into_inner().query_json).map_err(status)?;
        query
            .validate_for_node(self.runtime.node_id())
            .map_err(|cause| status(error(cause)))?;
        let result = self
            .runtime
            .read_initial_membership_history(context.clone(), bearer, query)
            .await;
        let result = self
            .auth
            .audit_result(&context, result.map_err(error))
            .await;
        let reply = result.map_err(status)?;
        let response = TargetHistoryStatus {
            status_json: encode_json(&reply.status).map_err(status)?,
        };
        self.auth
            .audit_result(&context, reply.release().await.map_err(error))
            .await
            .map_err(status)?;
        reply
            .release()
            .await
            .map_err(|cause| status(error(cause)))?;
        context.authorization.check_live().map_err(status)?;
        Ok(Response::new(response))
    }

    async fn execute(
        &self,
        request: Request<TargetExecuteRequest>,
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
        let input: kasumi_types::TargetExecuteRequest =
            decode_json(&request.into_inner().envelope_json).map_err(status)?;
        input
            .validate_for_node(self.runtime.node_id())
            .map_err(|cause| status(error(cause)))?;
        // The wire identity is structural only. Runtime authority and journal
        // admission remain separate; never turn these claimed IDs into a ticket.
        #[cfg(test)]
        let command_id = input.request.command_id;
        let reply = match self.runtime.execute(context.clone(), bearer, input).await {
            Ok(reply) => {
                self.auth
                    .audit_result(&context, Ok(()))
                    .await
                    .map_err(unresolved)?;
                reply
            }
            Err(failure) => {
                #[cfg(test)]
                eprintln!("target RPC execution command={command_id} error={failure:#}");
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
            .audit_result(
                &context,
                reply.release().await.map_err(|failure| {
                    #[cfg(test)]
                    eprintln!(
                        "target RPC audited release command={} error={failure:#}",
                        reply.response.command_id
                    );
                    error(failure)
                }),
            )
            .await
            .map_err(unresolved)?;
        reply.release().await.map_err(|failure| {
            #[cfg(test)]
            eprintln!(
                "target RPC final release command={} error={failure:#}",
                reply.response.command_id
            );
            unresolved(failure)
        })?;
        context.authorization.check_live().map_err(unresolved)?;
        Ok(Response::new(response))
    }
}
