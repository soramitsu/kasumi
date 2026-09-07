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
}
impl KasumiAuthorityClient {
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
            .acquire_lease(authorized(
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
            .discover_lease(authorized(
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
            .execute(authorized(
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
            .receipt(authorized(
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
