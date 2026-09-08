//! Closed independent authority adapter. The peer identity comes exclusively
//! from the completed mTLS handshake extension, never a body/header assertion.
use super::*;
use kasumi_authority::{AuthenticatedNode, AuthorityResponseFence, IndependentAuthority};
use kasumi_serving::{
    AuthorityCommand, LeaseDiscovery, LeaseRequest, SigningCertificateVerification,
};

#[derive(Clone)]
pub struct NativeAuthority {
    authority: Arc<IndependentAuthority>,
    auth: Arc<Authenticator>,
    signer_verifier: Option<Arc<crate::signer_runtime::InstalledSignerVerifier>>,
    operational_signer_file: Option<std::path::PathBuf>,
}
impl NativeAuthority {
    pub fn new(authority: Arc<IndependentAuthority>, auth: Arc<Authenticator>) -> Self {
        Self {
            authority,
            auth,
            signer_verifier: None,
            operational_signer_file: None,
        }
    }
    pub(crate) fn with_signer_verifier(
        mut self,
        verifier: Arc<crate::signer_runtime::InstalledSignerVerifier>,
    ) -> Self {
        self.signer_verifier = Some(verifier);
        self
    }
    pub(crate) fn with_operational_signer_file(mut self, path: std::path::PathBuf) -> Self {
        self.operational_signer_file = Some(path);
        self
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
    async fn observe_control_signer(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| Status::unauthenticated("actual mTLS Control receiver required"))?;
        let caller = AuthenticatedNode::from_verified_transport(context.clone(), hex::encode(pin))
            .map_err(status)?;
        let body: kasumi_serving::ControlSignerRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let (reply, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority.observe_control_signer(caller, body).await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&reply).map_err(status)?,
        };
        self.auth
            .audit_result(&context, fence.release().await)
            .await
            .map_err(status)?;
        fence.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
    async fn signing_maintenance(
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
        let body: kasumi_serving::AuthoritySigningRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let mutation = matches!(
            body.action,
            kasumi_serving::AuthoritySigningAction::Start { .. }
        );
        let (reply, fence) = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .signing_maintenance(context.clone(), body)
                    .await,
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&reply).map_err(|error| {
                if mutation {
                    Status::unknown(format!(
                        "global signer outcome retained; encoding failed: {error}"
                    ))
                } else {
                    status(error)
                }
            })?,
        };
        let outcome = self
            .auth
            .audit_result(&context, fence.release().await)
            .await;
        let outcome = match outcome {
            Ok(()) => fence.release().await,
            Err(error) => Err(error),
        };
        outcome.map_err(|error| {
            if mutation {
                Status::unknown(format!(
                    "global signer outcome retained; recover original identity: {error}"
                ))
            } else {
                status(error)
            }
        })?;
        Ok(Response::new(response))
    }
    async fn signer_maintenance(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        use kasumi_serving::{SignerVerifierAction, SignerVerifierRequest, SignerVerifierResponse};
        let context = verified(&self.auth, &request).await?;
        request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| {
                Status::unauthenticated("actual mutually authenticated TLS peer required")
            })?;
        let body: SignerVerifierRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        body.validate()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let verifier = self
            .signer_verifier
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("installed signer verifier unavailable"))?;
        let domain = self
            .authority
            .installation()
            .manifest
            .signing_domain(self.authority.installation().partition)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let fence = self
            .auth
            .audit_result(
                &context,
                self.authority
                    .authorize_signer_maintenance(context.clone())
                    .await,
            )
            .await
            .map_err(status)?;
        let (owner, scope) = self
            .auth
            .audit_result(
                &context,
                verifier
                    .authorize(&body, fence.clone(), &domain)
                    .await
                    .map_err(|error| {
                        kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Forbidden,
                            error.to_string(),
                        )
                    }),
            )
            .await
            .map_err(status)?;
        // Recheck after waiting for the exact local slot. Any first mutation is
        // authorized by a committed consensus directive before local dispatch.
        self.auth
            .audit_result(&context, fence.release().await)
            .await
            .map_err(status)?;
        let mut source_directive = None;
        let authorization = match &body.action {
            SignerVerifierAction::Observe
            | SignerVerifierAction::ReloadOperationalSigner { .. } => None,
            SignerVerifierAction::Receipt { operation_id } => self
                .auth
                .audit_result(
                    &context,
                    self.authority
                        .signer_directive(
                            &context,
                            &body.verifier,
                            &body.domain_sha256,
                            *operation_id,
                        )
                        .await,
                )
                .await
                .map_err(status)?,
            SignerVerifierAction::Administer { command } => {
                let committed = Arc::new(
                    self.auth
                        .audit_result(
                            &context,
                            self.authority
                                .commit_signer_directive(
                                    &context,
                                    &body.verifier,
                                    &body.domain_sha256,
                                    command,
                                )
                                .await,
                        )
                        .await
                        .map_err(status)?,
                );
                let status = committed.status().clone();
                source_directive = Some(committed);
                Some(status)
            }
        };
        let mutated = matches!(
            body.action,
            SignerVerifierAction::Administer { .. }
                | SignerVerifierAction::ReloadOperationalSigner { .. }
        );
        let loaded_signer = if let SignerVerifierAction::ReloadOperationalSigner {
            expected_revision,
            certificate_sha256,
            not_after_ms,
        } = &body.action
        {
            let load = || -> anyhow::Result<_> {
                anyhow::ensure!(
                    context
                        .authorization
                        .expires_at_ms()
                        .is_some_and(|expiry| *not_after_ms <= expiry),
                    "reload deadline exceeds original credential"
                );
                let deadline = self.auth.signer_admission_deadline(*not_after_ms)?;
                scope.bind_deadline(deadline.clone())?;
                scope.check()?;
                let current = owner.current()?;
                anyhow::ensure!(
                    current.revision == *expected_revision
                        && current.active.digest()? == *certificate_sha256,
                    "reload requires the exact current durable signer head"
                );
                let path = self.operational_signer_file.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("installed operational signer source unavailable")
                })?;
                let source = crate::signer_runtime::OperationalSignerConfig::load(path, &domain)?;
                anyhow::ensure!(
                    source.certificate == current.active,
                    "configured signer is not the requested active generation"
                );
                Ok((source.open(verifier)?, deadline))
            };
            let (signer, deadline) = self
                .auth
                .audit_result(
                    &context,
                    load().map_err(|error| {
                        kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Conflict,
                            error.to_string(),
                        )
                    }),
                )
                .await
                .map_err(status)?;
            // Candidate validation is complete before publication. The original
            // finite admission and physical owner remain fenced through release.
            scope
                .check()
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            self.auth
                .audit_result(
                    &context,
                    self.authority
                        .replace_operational_signer(fence.clone(), signer.clone(), deadline)
                        .await,
                )
                .await
                .map_err(status)?;
            Some(signer)
        } else {
            None
        };
        let mut effect_dispatched = loaded_signer.is_some();
        let execute = || -> anyhow::Result<_> {
            let receipt = match &body.action {
                SignerVerifierAction::Observe
                | SignerVerifierAction::ReloadOperationalSigner { .. } => None,
                SignerVerifierAction::Receipt { operation_id } => {
                    owner.status(&context, *operation_id)?
                }
                SignerVerifierAction::Administer { command } => {
                    if let Some(receipt) = owner.status(&context, command.operation_id)? {
                        anyhow::ensure!(
                            receipt.command == *command,
                            "permanent signer operation has different input"
                        );
                        Some(receipt)
                    } else {
                        scope.bind_directive(source_directive.clone().ok_or_else(|| {
                            anyhow::anyhow!("current source signer permission absent")
                        })?)?;
                        anyhow::ensure!(
                            context
                                .authorization
                                .expires_at_ms()
                                .is_some_and(|expiry| command.not_after_ms <= expiry),
                            "signer admission deadline exceeds original credential"
                        );
                        scope.bind_deadline(
                            self.auth.signer_admission_deadline(command.not_after_ms)?,
                        )?;
                        effect_dispatched = true;
                        Some(owner.administer(&context, command.clone())?)
                    }
                }
            };
            let observation = owner.observe()?;
            let reply = SignerVerifierResponse {
                observation_id: body.observation_id,
                request_sha256: body.digest()?,
                domain_sha256: body.domain_sha256.clone(),
                current: observation.record().clone(),
                receipt,
                loaded_certificate: loaded_signer
                    .as_ref()
                    .map(|signer| signer.certificate().clone()),
                authorization,
            };
            reply.validate_for(&body, &domain)?;
            Ok((reply, observation))
        };
        let executed = execute();
        let (reply, observation) = self
            .auth
            .audit_result(
                &context,
                executed.map_err(|error| {
                    kasumi_types::Error::new(
                        if effect_dispatched {
                            kasumi_types::ErrorCode::UnknownOutcome
                        } else {
                            kasumi_types::ErrorCode::Conflict
                        },
                        format!("signer maintenance failed; resolve the exact requested operation or reload head: {error}"),
                    )
                }),
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&reply).map_err(|error| {
                if mutated {
                    Status::unknown(format!(
                        "signer outcome retained but encoding failed: {error}"
                    ))
                } else {
                    status(error)
                }
            })?,
        };
        let release = || -> kasumi_types::Result<()> {
            scope
                .check()
                .and_then(|_| observation.check())
                .and_then(|_| {
                    loaded_signer
                        .as_ref()
                        .map_or(Ok(()), |signer| signer.check())
                })
                .map_err(|error| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        error.to_string(),
                    )
                })
        };
        let outcome = self.auth.audit_result(&context, release()).await;
        let outcome = match outcome {
            Ok(()) => fence.release().await.and_then(|_| release()),
            Err(error) => Err(error),
        };
        outcome.map_err(|error| {
            if mutated {
                Status::unknown(format!(
                    "signer outcome retained; response release failed: {error}"
                ))
            } else {
                status(error)
            }
        })?;
        Ok(Response::new(response))
    }

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
