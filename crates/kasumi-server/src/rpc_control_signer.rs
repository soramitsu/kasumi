use super::*;
use kasumi_serving::{ControlSignerRequest, ControlSignerResponse};

impl NativeAdmin {
    pub(super) async fn control_signer_maintenance_impl(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| Status::unauthenticated("actual administrative mTLS required"))?;
        if context.tenant != crate::runtime::CONTROL_TENANT {
            return Err(Status::permission_denied(
                "current Control administrator required",
            ));
        }
        let body: ControlSignerRequest =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        body.digest()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let runtime = self.control_signer.as_ref().ok_or_else(|| {
            Status::failed_precondition("installed remote Control signer unavailable")
        })?;
        let database = runtime.control();
        let (domain, manifest, mut issuer_pool) = runtime
            .route(&body)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let partition = manifest
            .control_partition(domain.partition)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let fence = self
            .auth
            .audit_result(
                &context,
                database
                    .authorize_control_administration(context.clone(), partition)
                    .await,
            )
            .await
            .map_err(status)?;
        let issuer = issuer_pool
            .observe_control_signer(
                &body,
                std::time::Duration::from_millis(manifest.max_lease_ms.min(5000)),
            )
            .await
            .map_err(|error| {
                Status::unavailable(format!(
                    "current installed issuer observation unavailable: {error}"
                ))
            })?;
        let source_observation = issuer.observation().clone();
        let (owner, scope) = runtime
            .authorize(&body, fence.clone(), issuer, &domain)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        self.auth
            .audit_result(&context, fence.release().await)
            .await
            .map_err(status)?;
        let mut effect_dispatched = false;
        let executed = (|| -> anyhow::Result<_> {
            scope.check()?;
            let receipt = if let Some(receipt) =
                owner.status(&context, body.directive.command.operation_id)?
            {
                anyhow::ensure!(
                    receipt.command == body.directive.command,
                    "permanent physical signer identity differs"
                );
                receipt
            } else {
                anyhow::ensure!(
                    source_observation.may_apply,
                    "source policy permits historical resolution only"
                );
                anyhow::ensure!(
                    context
                        .authorization
                        .expires_at_ms()
                        .is_some_and(|expiry| body.directive.command.not_after_ms <= expiry),
                    "remote effect exceeds its original Control credential"
                );
                scope.bind_deadline(
                    self.auth
                        .signer_admission_deadline(body.directive.command.not_after_ms)?,
                )?;
                scope.check()?;
                effect_dispatched = true;
                owner.administer(&context, body.directive.command.clone())?
            };
            let observed = owner.observe()?;
            let reply = ControlSignerResponse {
                observation_id: body.observation_id,
                request_sha256: body.digest()?,
                current: observed.record().clone(),
                receipt,
                issuer: source_observation,
            };
            reply.validate_for(&body, &manifest)?;
            scope.check()?;
            Ok((reply, observed))
        })();
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
                        format!(
                            "remote signer outcome requires exact original resolution: {error}"
                        ),
                    )
                }),
            )
            .await
            .map_err(status)?;
        let response = AuthorityJsonResponse {
            response_json: encode_json(&reply).map_err(|error| {
                Status::unknown(format!(
                    "local signer outcome retained; encoding failed: {error}"
                ))
            })?,
        };
        let check = || -> kasumi_types::Result<()> {
            fence.check()?;
            scope.check().map_err(|error| {
                kasumi_types::Error::new(kasumi_types::ErrorCode::Unavailable, error.to_string())
            })?;
            observation.check().map_err(|error| {
                kasumi_types::Error::new(kasumi_types::ErrorCode::Unavailable, error.to_string())
            })
        };
        self.auth
            .audit_result(&context, check())
            .await
            .map_err(|error| {
                Status::unknown(format!(
                    "local signer outcome retained; response fenced: {error}"
                ))
            })?;
        fence.release().await.map_err(|error| {
            Status::unknown(format!(
                "local signer outcome retained; Control quorum changed: {error}"
            ))
        })?;
        check().map_err(|error| {
            Status::unknown(format!(
                "local signer outcome retained; current response closed: {error}"
            ))
        })?;
        Ok(Response::new(response))
    }
}
