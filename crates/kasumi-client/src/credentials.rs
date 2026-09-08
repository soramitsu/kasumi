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
