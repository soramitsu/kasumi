use crate::{ClientError, KasumiAdminClient, authorized, encode, proto};
impl KasumiAdminClient {
    pub async fn create_credential(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CreateCredential,
    ) -> Result<kasumi_types::IssuedCredential, ClientError> {
        let response = self
            .inner
            .create_credential(authorized(
                bearer,
                proto::CredentialJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
    pub async fn renew_credential(
        &mut self,
        bearer: &str,
        request: &kasumi_types::RenewCredential,
    ) -> Result<kasumi_types::IssuedCredential, ClientError> {
        let response = self
            .inner
            .renew_credential(authorized(
                bearer,
                proto::CredentialJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
    /// Renew `request`'s family from its expired latest credential, within
    /// the fixed window after it expired (docs/credential-lifetime.md). Retry
    /// an uncertain outcome with the same `request`: it replays the issuance.
    pub async fn recover_credential(
        &mut self,
        expired_bearer: &str,
        request: &kasumi_types::RenewCredential,
    ) -> Result<kasumi_types::IssuedCredential, ClientError> {
        let response = self
            .inner
            .recover_credential(authorized(
                expired_bearer,
                proto::CredentialJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
    pub async fn revoke_credential(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CredentialReference,
    ) -> Result<kasumi_types::CredentialStatus, ClientError> {
        let response = self
            .inner
            .revoke_credential(authorized(
                bearer,
                proto::CredentialJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
    pub async fn credential_status(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CredentialReference,
    ) -> Result<kasumi_types::CredentialStatus, ClientError> {
        let response = self
            .inner
            .credential_status(authorized(
                bearer,
                proto::CredentialJsonRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }
}
