use crate::{ClientError, KasumiClientConfig, authorized, encode, proto};
use kasumi_serving::{
    AuthorityCommand, AuthorityTrust, LeaseAttempt, LeaseDiscovery, ServingIdentity,
    SignedAuthorityReceipt, SignedLease, VerifiedActivation, VerifiedLease,
};
use tonic::transport::Channel;

/// Pinned mTLS transport and independently installed issuer trust. A client
/// cannot turn a deserialized lease into a fresh clock anchor.
#[derive(Clone)]
pub struct KasumiAuthorityClient {
    inner: proto::kasumi_authority_client::KasumiAuthorityClient<Channel>,
    trust: AuthorityTrust,
    certificate_sha256: String,
    deadline: Option<tokio::time::Instant>,
}
impl KasumiAuthorityClient {
    pub async fn observe_control_signer(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::ControlSignerRequest,
    ) -> Result<crate::CurrentControlSignerObservation, ClientError> {
        let anchor = kasumi_clock::EpochClock::system()?.observe()?;
        let reply = self.observe_control_signer_wire(bearer, request).await?;
        crate::CurrentControlSignerObservation::from_current_response(reply, anchor)
    }
    pub(crate) async fn observe_control_signer_wire(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::ControlSignerRequest,
    ) -> Result<kasumi_serving::ControlSignerObservation, ClientError> {
        request.digest()?;
        if request.directive.node.certificate_sha256 != self.certificate_sha256 {
            return Err(ClientError::InvalidResponse(
                "current Control observation must use its actual installed client identity",
            ));
        }
        let response = self
            .inner
            .observe_control_signer(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let response: kasumi_serving::ControlSignerObservation =
            serde_json::from_slice(&response.response_json)?;
        response.validate_for(request, self.trust.manifest())?;
        Ok(response)
    }
    /// Current authenticated global signer maintenance. Preserve the exact
    /// operation and request when resolving an uncertain activation.
    pub async fn signing_maintenance(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::AuthoritySigningRequest,
    ) -> Result<kasumi_serving::AuthoritySigningResponse, ClientError> {
        request.validate()?;
        let domain = self
            .trust
            .manifest()
            .partitions
            .keys()
            .map(|partition| self.trust.manifest().signing_domain(*partition))
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .find(|domain| domain.digest().ok().as_deref() == Some(&request.domain_sha256))
            .ok_or_else(|| {
                anyhow::anyhow!("global signer domain is not independently installed")
            })?;
        let response = self
            .inner
            .signing_maintenance(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let response: kasumi_serving::AuthoritySigningResponse =
            serde_json::from_slice(&response.response_json)?;
        response.validate_for(request, &domain)?;
        Ok(response)
    }
    /// This operates on the exact local verifier in the request. Do not route
    /// it to another member or interpret its receipt as global rotation completion.
    pub async fn signer_maintenance(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::SignerVerifierRequest,
    ) -> Result<kasumi_serving::SignerVerifierResponse, ClientError> {
        request.validate()?;
        let domain = self
            .trust
            .manifest()
            .partitions
            .keys()
            .map(|partition| self.trust.manifest().signing_domain(*partition))
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .find(|domain| domain.digest().ok().as_deref() == Some(&request.domain_sha256))
            .ok_or_else(|| anyhow::anyhow!("signer domain is not independently installed"))?;
        let response = self
            .inner
            .signer_maintenance(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let response: kasumi_serving::SignerVerifierResponse =
            serde_json::from_slice(&response.response_json)?;
        response.validate_for(request, &domain)?;
        Ok(response)
    }
    pub async fn maintenance(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::AuthorityMaintenanceRequest,
    ) -> Result<kasumi_serving::AuthorityMaintenanceResponse, ClientError> {
        request.validate()?;
        let response = self
            .inner
            .maintenance(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let response: kasumi_serving::AuthorityMaintenanceResponse =
            serde_json::from_slice(&response.response_json)?;
        let validate = || -> anyhow::Result<()> {
            match &response {
                kasumi_serving::AuthorityMaintenanceResponse::Configuration { configuration } => {
                    anyhow::ensure!(
                        matches!(
                            request,
                            kasumi_serving::AuthorityMaintenanceRequest::Configuration
                        ),
                        "maintenance response kind differs"
                    );
                    configuration.membership.validate()?;
                    configuration.capacity.validate()?;
                }
                kasumi_serving::AuthorityMaintenanceResponse::Operation { status } => {
                    status.validate()?;
                    anyhow::ensure!(
                        Some(status.command.operation_id) == request.operation_id(),
                        "maintenance operation identity differs"
                    );
                    if let kasumi_serving::AuthorityMaintenanceRequest::Start { command } = request
                    {
                        anyhow::ensure!(
                            status.command == *command,
                            "maintenance command input differs"
                        );
                    }
                }
            }
            Ok(())
        };
        validate()?;
        Ok(response)
    }

    pub(crate) fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        self.deadline = Some(deadline);
    }
    fn authorized<T>(&self, bearer: &str, value: T) -> Result<tonic::Request<T>, ClientError> {
        let mut request = authorized(bearer, value)?;
        if let Some(deadline) = self.deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(tonic::Status::deadline_exceeded(
                    "authority operation deadline elapsed",
                )
                .into());
            }
            request.set_timeout(remaining);
        }
        Ok(request)
    }

    pub async fn execute_lifecycle(
        &mut self,
        bearer: &str,
        request: &kasumi_serving::LifecycleAuthorityRequest,
    ) -> Result<kasumi_serving::SignedLifecycleAuthorityReceipt, ClientError> {
        let reference = request.reference();
        let partition = match request {
            kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(s) => {
                s.observation.authority_partition.partition
            }
            kasumi_serving::LifecycleAuthorityRequest::StopEpoch(s) => {
                s.observation.stop.authority_partition.partition
            }
        };
        self.trust
            .manifest()
            .verify_lifecycle_request(partition, request)?;
        let response = self
            .inner
            .execute_lifecycle(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let signed: kasumi_serving::SignedLifecycleAuthorityReceipt =
            serde_json::from_slice(&response.response_json)?;
        self.trust.verify_lifecycle_receipt(&signed, &reference)?;
        if signed.receipt.request_sha256 != request.digest()? {
            return Err(anyhow::anyhow!("accepted control request differs").into());
        }
        Ok(signed)
    }
    pub async fn read_lifecycle_receipt(
        &mut self,
        bearer: &str,
        reference: &kasumi_serving::LifecycleAuthorityReference,
    ) -> Result<Option<kasumi_serving::SignedLifecycleAuthorityReceipt>, ClientError> {
        reference.validate()?;
        let response = self
            .inner
            .read_lifecycle_receipt(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(reference)?,
                },
            )?)
            .await?
            .into_inner();
        let signed: Option<kasumi_serving::SignedLifecycleAuthorityReceipt> =
            serde_json::from_slice(&response.response_json)?;
        if let Some(signed) = &signed {
            self.trust.verify_lifecycle_receipt(signed, reference)?;
        }
        Ok(signed)
    }
    pub async fn verify_control_stop(
        &mut self,
        bearer: &str,
        expected: &kasumi_types::ControlEpochStop,
    ) -> Result<kasumi_types::SignedControlEpochStop, ClientError> {
        if expected.authority_partition
            != self
                .trust
                .manifest()
                .control_partition(expected.authority_partition.partition)?
        {
            return Err(anyhow::anyhow!("control stop issuer installation differs").into());
        }
        let reference = kasumi_serving::LifecycleAuthorityReference {
            control_incarnation: expected.control_incarnation,
            control_policy_epoch: expected.control_policy_epoch,
            identity: kasumi_serving::LifecycleAuthorityIdentity::EpochStop,
        };
        let response = self
            .inner
            .verify_control_stop(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(&reference)?,
                },
            )?)
            .await?
            .into_inner();
        let signed: kasumi_types::SignedControlEpochStop =
            serde_json::from_slice(&response.response_json)?;
        kasumi_serving::verify_control_epoch_stop(expected, &signed)?;
        Ok(signed)
    }
    pub async fn acquire_lifecycle(
        &mut self,
        bearer: &str,
        attempt: &kasumi_serving::LifecycleAttempt,
    ) -> Result<kasumi_serving::VerifiedLifecycleLease, ClientError> {
        if attempt.request().authority_manifest_sha256 != self.trust.digest()
            || attempt.request().target_node.certificate_sha256 != self.certificate_sha256
        {
            return Err(anyhow::anyhow!(
                "phase attempt differs from installed issuer or client TLS identity"
            )
            .into());
        }
        let response = self
            .inner
            .acquire_lifecycle(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(attempt.request())?,
                },
            )?)
            .await?
            .into_inner();
        Ok(attempt.verify(serde_json::from_slice(&response.response_json)?)?)
    }

    pub async fn verify_target_stop(
        &mut self,
        bearer: &str,
        reference: &kasumi_serving::TargetStopReference,
    ) -> Result<kasumi_serving::VerifiedTargetStop, ClientError> {
        reference.validate()?;
        let response = self
            .inner
            .verify_target_stop(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(reference)?,
                },
            )?)
            .await?
            .into_inner();
        let signed: kasumi_serving::SignedTargetStop =
            serde_json::from_slice(&response.response_json)?;
        Ok(self.trust.verify_target_stop(signed, reference)?)
    }

    pub async fn connect(
        config: &KasumiClientConfig,
        trust: AuthorityTrust,
    ) -> Result<Self, ClientError> {
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            deadline: None,
            inner: proto::kasumi_authority_client::KasumiAuthorityClient::new(channel)
                .max_encoding_message_size(256 << 10)
                .max_decoding_message_size(512 << 10),
            trust,
            certificate_sha256: hex::encode(config.identity.certificate_pin()),
        })
    }
    pub async fn acquire_lease(
        &mut self,
        bearer: &str,
        attempt: &LeaseAttempt,
    ) -> Result<VerifiedLease, ClientError> {
        if attempt.request().manifest_digest != self.trust.digest()
            || attempt.request().identity.node.certificate_sha256 != self.certificate_sha256
        {
            return Err(anyhow::anyhow!(
                "lease attempt differs from installed issuer or client TLS identity"
            )
            .into());
        }
        let response = self
            .inner
            .acquire_lease(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(attempt.request())?,
                },
            )?)
            .await?
            .into_inner();
        let signed: SignedLease = serde_json::from_slice(&response.response_json)?;
        Ok(attempt.verify(signed)?)
    }
    /// Epoch discovery grants no capability. Storage still requires a verified
    /// signed lease from a fresh, pre-dispatch LeaseAttempt for this identity.
    pub async fn discover_lease(
        &mut self,
        bearer: &str,
        request: &LeaseDiscovery,
    ) -> Result<ServingIdentity, ClientError> {
        request.validate()?;
        if request.node.certificate_sha256 != self.certificate_sha256 {
            return Err(anyhow::anyhow!("discovery differs from client TLS identity").into());
        }
        let response = self
            .inner
            .discover_lease(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let identity: ServingIdentity = serde_json::from_slice(&response.response_json)?;
        identity.validate()?;
        if identity.tenant != request.tenant
            || identity.incarnation != request.incarnation
            || identity.node != request.node
        {
            return Err(
                anyhow::anyhow!("discovery returned a different requested identity").into(),
            );
        }
        Ok(identity)
    }
    /// Returned signed wire records describe immutable outcomes. They do not
    /// reopen data access; acquire_lease supplies the separate live capability.
    pub async fn execute(
        &mut self,
        bearer: &str,
        command: &AuthorityCommand,
    ) -> Result<SignedAuthorityReceipt, ClientError> {
        let response = self
            .inner
            .execute(self.authorized(
                bearer,
                proto::AuthorityJsonRequest {
                    request_json: encode(command)?,
                },
            )?)
            .await?
            .into_inner();
        let receipt: SignedAuthorityReceipt = serde_json::from_slice(&response.response_json)?;
        self.trust.verify_receipt(&receipt)?;
        if receipt.receipt.command != *command {
            return Err(anyhow::anyhow!("authority returned another command identity").into());
        }
        Ok(receipt)
    }
    pub async fn receipt(
        &mut self,
        bearer: &str,
        tenant: &str,
        command_id: uuid::Uuid,
    ) -> Result<Option<SignedAuthorityReceipt>, ClientError> {
        let response = self
            .inner
            .receipt(self.authorized(
                bearer,
                proto::AuthorityReceiptRequest {
                    tenant: tenant.to_owned(),
                    command_id: command_id.to_string(),
                },
            )?)
            .await?
            .into_inner();
        let receipt: Option<SignedAuthorityReceipt> =
            serde_json::from_slice(&response.response_json)?;
        if let Some(receipt) = &receipt {
            self.trust.verify_receipt(receipt)?;
            if receipt.receipt.command.tenant != tenant
                || receipt.receipt.command.command_id != command_id
            {
                return Err(anyhow::anyhow!(
                    "authority observation returned another command identity"
                )
                .into());
            }
        }
        Ok(receipt)
    }
    pub async fn activate(
        &mut self,
        bearer: &str,
        command: &AuthorityCommand,
    ) -> Result<VerifiedActivation, ClientError> {
        let receipt = self.execute(bearer, command).await?;
        Ok(self.trust.verify_activation(receipt)?)
    }
    pub async fn recover_activation(
        &mut self,
        bearer: &str,
        tenant: &str,
        command_id: uuid::Uuid,
    ) -> Result<Option<VerifiedActivation>, ClientError> {
        self.receipt(bearer, tenant, command_id)
            .await?
            .map(|receipt| {
                self.trust
                    .verify_activation(receipt)
                    .map_err(ClientError::from)
            })
            .transpose()
    }
}
