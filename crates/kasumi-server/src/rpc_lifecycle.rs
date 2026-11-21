//! Installed control listener. No method accepts a source URL, signer key or
//! deserialized live proof. The database and signer are bound at server startup.
use super::*;
use kasumi_engine::{Database, LifecycleSigner};
use kasumi_types::{LifecycleControlCommand, ReadLifecycleStatus};
#[path = "rpc_control_topology.rs"]
mod topology;
#[derive(Clone)]
pub struct NativeLifecycleControl {
    database: Arc<Database>,
    signer: Arc<LifecycleSigner>,
    coordinator: Option<Arc<crate::recovery_runtime::ControlRecoveryCoordinator>>,
    auth: Arc<Authenticator>,
}
impl NativeLifecycleControl {
    pub fn new(
        database: Arc<Database>,
        signer: Arc<LifecycleSigner>,
        auth: Arc<Authenticator>,
    ) -> anyhow::Result<Self> {
        let state = database.engine().generation()?;
        anyhow::ensure!(
            state.tenant() == "__kasumi_control"
                && state.incarnation() == signer.root().control_incarnation.to_string(),
            "installed lifecycle database or signer resource differs"
        );
        drop(state);
        Ok(Self {
            database,
            signer,
            coordinator: None,
            auth,
        })
    }
    pub(crate) fn with_writer_callbacks(
        mut self,
        coordinator: Arc<crate::recovery_runtime::ControlRecoveryCoordinator>,
    ) -> Self {
        self.coordinator = Some(coordinator);
        self
    }
    pub fn service(self) -> kasumi_lifecycle_control_server::KasumiLifecycleControlServer<Self> {
        kasumi_lifecycle_control_server::KasumiLifecycleControlServer::new(self)
            .max_decoding_message_size(16 << 20)
            .max_encoding_message_size(16 << 20)
    }
    async fn context<T>(&self, request: &Request<T>) -> Result<RequestContext, Status> {
        let context = verified(&self.auth, request).await?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|p| p.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated(
                "actual mutually authenticated TLS peer required",
            ));
        }
        context
            .authorization
            .require_control(&self.signer.root().control_incarnation.to_string())
            .map_err(status)?;
        if context.tenant != "__kasumi_control" {
            return Err(Status::permission_denied(
                "installed lifecycle control resource required",
            ));
        }
        Ok(context)
    }
}
#[tonic::async_trait]
impl kasumi_lifecycle_control_server::KasumiLifecycleControl for NativeLifecycleControl {
    async fn observe_target_writer(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let actor = self.context(&request).await?;
        let mut headers = request
            .metadata()
            .get_all(kasumi_client::TARGET_WRITER_REFRESH_HEADER)
            .iter();
        let nonce = headers
            .next()
            .map(|v| {
                v.to_str()
                    .ok()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .ok_or_else(|| Status::invalid_argument("invalid writer refresh nonce"))
            })
            .transpose()?;
        if headers.next().is_some() {
            return Err(Status::invalid_argument("duplicate writer refresh nonce"));
        }
        let peer = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|p| p.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body = request.into_inner().request_json;
        if body.len() > 4096 {
            return Err(Status::resource_exhausted(
                "target writer challenge exceeds bound",
            ));
        }
        let challenge = decode_json(&body).map_err(status)?;
        let fence = self
            .database
            .admitted_response_fence(&actor)
            .map_err(status)?;
        let callback = nonce
            .map(|nonce| {
                self.coordinator
                    .as_ref()
                    .ok_or_else(|| {
                        kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Unavailable,
                            "original writer coordinator unavailable",
                        )
                    })
                    .and_then(|owner| {
                        owner.writer_callbacks.resolve(
                            nonce,
                            &actor,
                            &peer,
                            &challenge,
                            &self.database,
                        )
                    })
            })
            .transpose();
        let callback = self
            .auth
            .audit_result(&actor, callback)
            .await
            .map_err(status)?;
        let original = callback.as_ref().map_or(&actor, |active| active.original());
        let result = self
            .signer
            .observe_target_writer(&self.database, original, &challenge)
            .await;
        let output = self
            .auth
            .audit_result(&actor, result)
            .await
            .map_err(status)?;
        if let Some(active) = &callback {
            active.check(&actor, &self.database).map_err(status)?;
            if output
                .observation
                .retirements
                .target_writer_digest()
                .map_err(status)?
                != active.state_sha256()
            {
                return Err(Status::aborted(
                    "original writer state changed before callback release",
                ));
            }
        }
        let reply = response_owner::PendingReply::new(output, fence)
            .convert(|value, fence| {
                Ok(ControlJsonResponse {
                    response_json: response_owner::encode_json(value, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &actor)
            .await?;
        if let Some(active) = &callback {
            active.check(&actor, &self.database).map_err(status)?;
        }
        Ok(reply)
    }
    async fn observe_topology(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        self.observe_topology_response(request).await
    }
    async fn release_topology(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        self.release_topology_response(request).await
    }
    async fn execute(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let command: LifecycleControlCommand =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        if let LifecycleControlCommand::Install { installation, .. } = &command
            && &installation.root != self.signer.root()
        {
            return Err(Status::permission_denied(
                "installation does not match the configured control signer",
            ));
        }
        let result = self
            .auth
            .audit_result(
                &context,
                self.database
                    .lifecycle_control(context.clone(), command)
                    .await,
            )
            .await
            .map_err(status)?;
        let released = async {
            let fence = self.database.response_fence(&context)?;
            self.database
                .engine()
                .authorize(&context, None, kasumi_types::Action::Admin)?;
            let response = ControlJsonResponse {
                response_json: encode_json(&result)?,
            };
            release_response(&self.auth, &context, fence, response, true).await
        }
        .await
        .map_err(|_| {
            status(kasumi_types::Error::new(
                kasumi_types::ErrorCode::UnknownOutcome,
                "control effect accepted; current response authority was lost",
            ))
        })?;
        Ok(Response::new(released))
    }
    async fn observe_intent(
        &self,
        request: Request<ControlIntentReference>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let id = uuid::Uuid::parse_str(&request.into_inner().command_id)
            .map_err(|_| Status::invalid_argument("invalid control intent identity"))?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.database
                    .observe_lifecycle_intent(context.clone(), id)
                    .await,
            )
            .await
            .map_err(status)?;
        let signed = self
            .auth
            .audit_result(&context, self.signer.sign_intent(&proof).await)
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
    async fn observe_change(
        &self,
        request: Request<ControlChangeReference>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let request = request.into_inner();
        let id = uuid::Uuid::parse_str(&request.command_id)
            .map_err(|_| Status::invalid_argument("invalid control change identity"))?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.database
                    .observe_lifecycle_change(context.clone(), id)
                    .await,
            )
            .await
            .map_err(status)?;
        let signed = self
            .auth
            .audit_result(
                &context,
                self.signer
                    .sign_change(&proof, &request.authority_partition)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
    async fn read_status(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let input: ReadLifecycleStatus =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let result = self
            .auth
            .audit_result(
                &context,
                self.database.read_lifecycle_status(&context, input).await,
            )
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        self.auth
            .audit_result(
                &context,
                self.database
                    .check_lifecycle_status_release(&context, &result)
                    .await,
            )
            .await
            .map_err(status)?;
        self.database
            .check_lifecycle_status_release(&context, &result)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
}
