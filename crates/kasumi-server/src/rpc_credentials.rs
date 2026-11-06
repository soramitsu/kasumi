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
        let create_specification = if matches!(operation, CredentialOperation::Create) {
            let specification: kasumi_types::CreateCredential =
                decode_json(&payload).map_err(status)?;
            specification.validate().map_err(status)?;
            if let kasumi_types::CredentialResource::Database { incarnation } =
                &specification.resource
            {
                // A Control administrator may issue a database credential only
                // for the currently installed serving incarnation. An old or
                // invented UUID must not enter the credential ledger.
                let target = self
                    .registry
                    .installed_generation(&specification.tenant, &incarnation.to_string())
                    .and_then(|database| {
                        let database = database.ok_or_else(|| {
                            kasumi_types::Error::new(
                                kasumi_types::ErrorCode::Forbidden,
                                "database credential target unavailable",
                            )
                        })?;
                        database.check_serving()
                    });
                self.auth
                    .audit_result(&context, target)
                    .await
                    .map_err(status)?;
            }
            Some(specification)
        } else {
            None
        };
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
                    let specification = create_specification
                        .expect("create credential was validated before worker entry");
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
        #[cfg(test)]
        if matches!(operation, CredentialOperation::Renew) {
            cancelled_reply::after_commit(own_family, &response)?;
        }
        Ok(Response::new(response))
    }
}

impl NativeAdmin {
    /// Renew a family from its expired latest credential, which the listener
    /// verified (`Authenticator::verify_recovery`) before reading this body.
    /// The family's resource must still be routed and every registered scope
    /// still granted by current policy, as stopped-installation recovery
    /// requires. Each recovery is recorded as started before any issuance,
    /// and its success is durable before the new credential is released.
    pub(super) async fn recover_credential_rpc(
        &self,
        request: Request<CredentialJsonRequest>,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        let recovery = request
            .extensions()
            .get::<crate::request_admission::RecoveryAuthenticated>()
            .and_then(|verified| verified.recovery(&self.auth))
            .cloned()
            .ok_or_else(|| {
                Status::unauthenticated(
                    "credential recovery requires a verified expired credential",
                )
            })?;
        let context = &recovery.context;
        self.auth
            .record_recovery(context, kasumi_types::SecurityOutcome::Started)
            .await
            .map_err(status)?;
        let result = self
            .recover_credential(&recovery, request.into_inner().request_json)
            .await;
        let outcome = match &result {
            Ok(_) => kasumi_types::SecurityOutcome::Succeeded,
            Err((outcome, _)) => outcome.clone(),
        };
        let recorded = self.auth.record_recovery(context, outcome).await;
        let response = result.map_err(|(_, refused)| refused)?;
        recorded.map_err(status)?;
        Ok(Response::new(response))
    }

    /// The recovery itself. A failure carries the outcome to record (denied
    /// by policy, or failed for availability) with the status to return.
    async fn recover_credential(
        &self,
        recovery: &crate::auth::VerifiedRecovery,
        payload: Vec<u8>,
    ) -> Result<CredentialJsonResponse, (kasumi_types::SecurityOutcome, Status)> {
        let refused =
            |error: kasumi_types::Error| (crate::auth::recovery_outcome(error.code), status(error));
        let context = &recovery.context;
        let renewal: kasumi_types::RenewCredential = decode_json(&payload).map_err(refused)?;
        if renewal.family_id != recovery.proof.family_id {
            return Err(refused(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Forbidden,
                "recovery requires the expired credential's own family",
            )));
        }
        // Routing refusals are already audited with this identity.
        let database = self.database(context).await.map_err(|refusal| {
            let outcome = match refusal.code() {
                tonic::Code::Unauthenticated
                | tonic::Code::PermissionDenied
                | tonic::Code::InvalidArgument
                | tonic::Code::NotFound
                | tonic::Code::FailedPrecondition => kasumi_types::SecurityOutcome::Denied,
                _ => kasumi_types::SecurityOutcome::Failed,
            };
            (outcome, refusal)
        })?;
        let current = async {
            if context.tenant == crate::runtime::CONTROL_TENANT {
                database
                    .engine()
                    .authorize(context, None, kasumi_types::Action::Admin)?;
            }
            // Collection restrictions remain enforced by every request; like
            // stopped-installation recovery, recovery preserves only scopes
            // that some current grant still gives the principal.
            let generation = database.engine().generation()?;
            let policy = generation.policy();
            if !context.scopes.iter().all(|action| {
                policy.grants.iter().any(|grant| {
                    grant.principal == context.principal && grant.actions.contains(action)
                })
            }) {
                return Err(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "credential recovery scopes are no longer granted by current policy",
                ));
            }
            database.response_fence(context)
        };
        let fence = self
            .auth
            .audit_result(context, current.await)
            .await
            .map_err(refused)?;
        let manager = self.auth.local_credentials().map_err(refused)?.clone();
        let caller = context.clone();
        let proof = recovery.proof.clone();
        let issued = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            caller.authorization.check_live()?;
            Ok(encode_json(&manager.recover(
                &proof,
                &renewal,
                &caller.principal,
            )?)?)
        })
        .await
        .map_err(|_| {
            refused(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "credential worker stopped",
            ))
        })?
        .map_err(|error| {
            error
                .downcast_ref::<kasumi_types::Error>()
                .cloned()
                .unwrap_or_else(|| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "credential operation failed",
                    )
                })
        })
        .map_err(refused)?;
        release_response(
            &self.auth,
            context,
            fence,
            CredentialJsonResponse {
                response_json: issued,
            },
            true,
        )
        .await
        .map_err(refused)
    }
}

#[cfg(test)]
pub(crate) use cancelled_reply::install as cancel_next_renewal_reply;

/// Lose only a selected fixture family's reply, after the durable issuance and
/// the ordinary authenticated response fence have both completed.
#[cfg(test)]
mod cancelled_reply {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    use tokio::sync::oneshot;
    use uuid::Uuid;

    static PENDING: Mutex<BTreeMap<Uuid, oneshot::Sender<kasumi_types::IssuedCredential>>> =
        Mutex::new(BTreeMap::new());

    pub(crate) struct Guard(Uuid);
    impl Drop for Guard {
        fn drop(&mut self) {
            PENDING.lock().unwrap().remove(&self.0);
        }
    }

    pub(crate) fn install(
        family: Uuid,
    ) -> (Guard, oneshot::Receiver<kasumi_types::IssuedCredential>) {
        let (send, receive) = oneshot::channel();
        assert!(PENDING.lock().unwrap().insert(family, send).is_none());
        (Guard(family), receive)
    }

    pub(super) fn after_commit(
        family: Option<Uuid>,
        response: &CredentialJsonResponse,
    ) -> Result<(), Status> {
        let pending = family.and_then(|family| PENDING.lock().unwrap().remove(&family));
        if let Some(send) = pending {
            let issued = serde_json::from_slice(&response.response_json)
                .map_err(|_| Status::internal("fixture renewal response could not be decoded"))?;
            send.send(issued)
                .map_err(|_| Status::internal("fixture renewal observer stopped"))?;
            return Err(Status::cancelled("fixture lost committed renewal reply"));
        }
        Ok(())
    }
}
