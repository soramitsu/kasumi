//! Closed independent authority adapter. The peer identity comes exclusively
//! from the completed mTLS handshake extension, never a body/header assertion.
use super::*;
use kasumi_authority::{AuthenticatedNode, AuthorityResponseFence, IndependentAuthority};
use kasumi_serving::{AuthorityCommand, LeaseDiscovery, LeaseRequest};

#[derive(Clone)]
pub struct NativeAuthority {
    authority: Arc<IndependentAuthority>,
    auth: Arc<Authenticator>,
}
impl NativeAuthority {
    pub fn new(authority: Arc<IndependentAuthority>, auth: Arc<Authenticator>) -> Self {
        Self { authority, auth }
    }
    pub fn service(self) -> kasumi_authority_server::KasumiAuthorityServer<Self> {
        kasumi_authority_server::KasumiAuthorityServer::new(self)
            .max_decoding_message_size(256 << 10)
            .max_encoding_message_size(512 << 10)
    }
    async fn release(
        &self,
        context: &RequestContext,
        fence: AuthorityResponseFence,
        response: AuthorityJsonResponse,
        accepted: bool,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let result = self.auth.audit_result(context, fence.release().await).await;
        let result = match result {
            Ok(()) => fence.release().await,
            Err(error) => Err(error),
        };
        result.map_err(|error| status(if accepted { kasumi_types::Error::new(kasumi_types::ErrorCode::UnknownOutcome, "authority outcome accepted; response release failed, recover exact command identity") } else { error }))?;
        Ok(Response::new(response))
    }
}
#[tonic::async_trait]
impl kasumi_authority_server::KasumiAuthority for NativeAuthority {
    async fn maintenance(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: kasumi_serving::AuthorityMaintenanceRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let accepted = !matches!(
            body,
            kasumi_serving::AuthorityMaintenanceRequest::Status { .. }
                | kasumi_serving::AuthorityMaintenanceRequest::Configuration
        );
        let (reply, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority.maintenance(context.clone(), body).await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&reply).map_err(status)?,
        };
        self.release(&context, fence, response, accepted).await
    }

    async fn execute_lifecycle(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: kasumi_serving::LifecycleAuthorityRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let _pin = pin;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .execute_lifecycle(context.clone(), body)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(|_| {
                Status::unknown("lifecycle command accepted but response encoding failed")
            })?,
        };
        self.release(&context, fence, response, true).await
    }

    async fn read_lifecycle_receipt(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: kasumi_serving::LifecycleAuthorityReference =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let _pin = pin;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .read_lifecycle_receipt(context.clone(), body)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }

    async fn verify_control_stop(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: kasumi_serving::LifecycleAuthorityReference =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let _pin = pin;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .verify_control_stop(context.clone(), body)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }

    async fn acquire_lifecycle(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: kasumi_serving::LifecycleLeaseRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let caller = AuthenticatedNode::from_verified_transport(context.clone(), hex::encode(pin))
            .map_err(status)?;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority.acquire_lifecycle(caller, body).await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }

    async fn verify_target_stop(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated(
                "actual mutually authenticated TLS peer required",
            ));
        }
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .verify_target_stop(context.clone(), input)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }
    async fn discover_lease(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: LeaseDiscovery =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let caller = AuthenticatedNode::from_verified_transport(context.clone(), hex::encode(pin))
            .map_err(status)?;
        let (identity, fence) = self
            .auth
            .audit_result(&context, self.authority.discover(caller, body).await)
            .await
            .map_err(status)?;
        self.release(
            &context,
            fence,
            AuthorityJsonResponse {
                response_json: encode_json(&identity).map_err(status)?,
            },
            false,
        )
        .await
    }
    async fn acquire_lease(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: LeaseRequest = decode_json(&request.into_inner().request_json).map_err(status)?;
        let caller = AuthenticatedNode::from_verified_transport(context.clone(), hex::encode(pin))
            .map_err(status)?;
        let (signed, fence) = self
            .auth
            .audit_result(&context, self.authority.acquire(caller, body).await)
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }
    async fn execute(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated(
                "actual mutually authenticated TLS peer required",
            ));
        }
        let body: AuthorityCommand =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority.execute(context.clone(), body).await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(|_| {
                Status::unknown("authority outcome accepted but response encoding failed")
            })?,
        };
        self.release(&context, fence, response, true).await
    }
    async fn receipt(
        &self,
        request: Request<AuthorityReceiptRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        if request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .is_none()
        {
            return Err(Status::unauthenticated(
                "actual mutually authenticated TLS peer required",
            ));
        }
        let body = request.into_inner();
        let id = uuid::Uuid::parse_str(&body.command_id)
            .map_err(|_| Status::invalid_argument("invalid authority command identity"))?;
        let (signed, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .receipt(context.clone(), &body.tenant, id)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.release(&context, fence, response, false).await
    }
}
