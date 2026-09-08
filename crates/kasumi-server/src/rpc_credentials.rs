use super::*;

#[derive(Clone, Copy)]
pub(super) enum CredentialOperation {
    Create,
    Renew,
    Revoke,
    Status,
}
impl NativeAdmin {
    pub(super) async fn credential_rpc(
        &self,
        request: Request<CredentialJsonRequest>,
        operation: CredentialOperation,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let payload = request.into_inner().request_json;
        let own_family = context.authorization.credential_family();
        let control = context.tenant == crate::runtime::CONTROL_TENANT;
        if !control
            && matches!(
                operation,
                CredentialOperation::Create | CredentialOperation::Revoke
            )
        {
            return Err(status(
                self.auth
                    .audit_result::<()>(
                        &context,
                        Err(kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Forbidden,
                            "credential administration requires Control administrator",
                        )),
                    )
                    .await
                    .unwrap_err(),
            ));
        }
        let database = self.database(&context).await?;
        if control {
            self.auth
                .audit_result(
                    &context,
                    database
                        .engine()
                        .authorize(&context, None, kasumi_types::Action::Admin),
                )
                .await
                .map_err(status)?;
        }
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let manager = self.auth.local_credentials().map_err(status)?.clone();
        let caller = context.clone();
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            caller.authorization.check_live()?;
            match operation {
                CredentialOperation::Create => {
                    let specification: kasumi_types::CreateCredential = decode_json(&payload)?;
                    Ok(encode_json(
                        &manager.create(specification, &caller.principal)?,
                    )?)
                }
                CredentialOperation::Renew => {
                    let renewal: kasumi_types::RenewCredential = decode_json(&payload)?;
                    anyhow::ensure!(
                        own_family == Some(renewal.family_id),
                        kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Forbidden,
                            "renewal requires the original live credential family"
                        )
                    );
                    Ok(encode_json(&manager.renew(&renewal, &caller.principal)?)?)
                }
                CredentialOperation::Revoke => {
                    let reference: kasumi_types::CredentialReference = decode_json(&payload)?;
                    Ok(encode_json(
                        &manager.revoke(reference.family_id, &caller.principal)?,
                    )?)
                }
                CredentialOperation::Status => {
                    let reference: kasumi_types::CredentialReference = decode_json(&payload)?;
                    anyhow::ensure!(
                        control || own_family == Some(reference.family_id),
                        kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Forbidden,
                            "credential status requires its owner or Control administrator"
                        )
                    );
                    Ok(encode_json(&manager.status(reference.family_id)?)?)
                }
            }
        })
        .await
        .map_err(|_| Status::unavailable("credential worker stopped"))?;
        let bytes = self
            .auth
            .audit_result(
                &context,
                result.map_err(|error| {
                    error
                        .downcast_ref::<kasumi_types::Error>()
                        .cloned()
                        .unwrap_or_else(|| {
                            kasumi_types::Error::new(
                                kasumi_types::ErrorCode::Unavailable,
                                "credential operation failed",
                            )
                        })
                }),
            )
            .await
            .map_err(status)?;
        let response = release_response(
            &self.auth,
            &context,
            fence,
            CredentialJsonResponse {
                response_json: bytes,
            },
            !matches!(operation, CredentialOperation::Status),
        )
        .await
        .map_err(status)?;
        Ok(Response::new(response))
    }
}
