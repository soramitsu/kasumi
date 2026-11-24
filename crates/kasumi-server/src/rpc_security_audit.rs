use super::*;
use kasumi_types::*;
#[derive(Clone, Copy)]
pub(super) enum AuditOperation {
    Status,
    Capacity,
    Export,
    Archives,
    Verify,
    Prune,
}

fn audit_error(error: anyhow::Error) -> kasumi_types::Error {
    error
        .downcast_ref::<kasumi_types::Error>()
        .cloned()
        .unwrap_or_else(|| {
            kasumi_types::Error::new(
                ErrorCode::Unavailable,
                "service audit operation unavailable",
            )
        })
}
struct AuditResponseFence<'a> {
    control: kasumi_engine::ResponseFence<'a>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    _workspace: kasumi_engine::admission::Reservation,
}
impl kasumi_engine::EncodedResponseFence for AuditResponseFence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        self.audit.store().check_access().map_err(audit_error)?;
        self.control.check()
    }
}
impl NativeAdmin {
    pub(super) async fn security_audit_rpc(
        &self,
        request: Request<SecurityAuditJsonRequest>,
        operation: AuditOperation,
    ) -> std::result::Result<Response<SecurityAuditJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        self.auth
            .audit_result(
                &context,
                if context.tenant == crate::runtime::CONTROL_TENANT {
                    Ok(())
                } else {
                    Err(kasumi_types::Error::new(
                        ErrorCode::Forbidden,
                        "service audit requires a Control administrator",
                    ))
                },
            )
            .await
            .map_err(status)?;
        let database = self.database(&context).await?;
        self.auth
            .audit_result(
                &context,
                database.engine().authorize(&context, None, Action::Admin),
            )
            .await
            .map_err(status)?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let payload = request.into_inner().request_json;
        let management = self
            .management
            .as_ref()
            .ok_or_else(|| Status::unavailable("private audit route unavailable"))?;
        let audit = management.security_audit().clone();
        let workspace = self
            .auth
            .audit_result(
                &context,
                management.security_audit_workspace(matches!(operation, AuditOperation::Archives)),
            )
            .await
            .map_err(status)?;
        let fence = AuditResponseFence {
            control: fence,
            audit: audit.clone(),
            _workspace: workspace,
        };
        let result = async {
            anyhow::ensure!(
                payload.len() <= MAX_SECURITY_AUDIT_PAGE_BYTES,
                kasumi_types::Error::new(
                    ErrorCode::ResourceExhausted,
                    "service audit request exceeds its byte limit"
                )
            );
            let encoded = match operation {
                AuditOperation::Status => {
                    let _: SecurityAuditStatusRequest = decode_json(&payload)?;
                    let value = audit.read_status().await?;
                    encode_json(&value)?
                }
                AuditOperation::Capacity => {
                    let _: SecurityAuditCapacityRequest = decode_json(&payload)?;
                    let value = audit.read_capacity().await?;
                    encode_json(&value)?
                }
                AuditOperation::Export => {
                    let request: SecurityAuditExportRequest = decode_json(&payload)?;
                    request.validate()?;
                    if let Some(cursor) = &request.cursor {
                        let state = audit.status()?;
                        anyhow::ensure!(
                            cursor.stream_id == state.position.stream_id
                                && cursor.through_sequence <= state.position.next_sequence
                                && cursor.snapshot_segments <= state.archive_segments,
                            kasumi_types::Error::new(
                                ErrorCode::InvalidArgument,
                                "audit cursor belongs to another stream or future range"
                            )
                        );
                    }
                    // The engine checks the cursor's snapshot head, snapshot tail
                    // and previous record digest against durable history before
                    // it returns any record.
                    encode_json(&audit.export_page(request.cursor, request.limit).await?)?
                }
                AuditOperation::Archives => {
                    let request: SecurityAuditArchivePageRequest = decode_json(&payload)?;
                    let value = audit.read_archive_page(request).await?;
                    encode_json(&value)?
                }
                AuditOperation::Verify => {
                    let request: SecurityAuditVerifyRequest = decode_json(&payload)?;
                    request.validate()?;
                    let state = audit.status()?;
                    anyhow::ensure!(
                        request.stream_id == state.position.stream_id
                            && request.index < state.archive_segments,
                        kasumi_types::Error::new(
                            ErrorCode::InvalidArgument,
                            "audit verification stream or index differs"
                        )
                    );
                    let archive = audit.verify_archive(request.index).await?;
                    anyhow::ensure!(
                        archive.stream_id == request.stream_id,
                        "verified archive stream differs"
                    );
                    encode_json(&SecurityAuditArchiveVerification {
                        stream_id: request.stream_id,
                        index: request.index,
                        archive,
                    })?
                }
                AuditOperation::Prune => {
                    let request: SecurityAuditPruneRequest = decode_json(&payload)?;
                    request.validate()?;
                    let minimum_age = std::time::Duration::from_secs(
                        u64::from(management.config.security_audit.prune_minimum_age_days) * 86_400,
                    );
                    // Checked again immediately before the retirement commits:
                    // a credential revoked or a policy changed while archives
                    // were read refuses the prune instead of only its reply.
                    let commit_fence = database.owned_response_fence(&context)?;
                    let commit_database = database.clone();
                    let commit_context = context.clone();
                    let result = audit
                        .prune(
                            request.clone(),
                            kasumi_engine::ArchivePrune {
                                principal: context.principal.clone(),
                                tenant: context.tenant.clone(),
                                request_id: context.request_id.clone(),
                                minimum_age,
                                authorize: Box::new(move || {
                                    commit_fence.check()?;
                                    commit_database.engine().authorize(
                                        &commit_context,
                                        None,
                                        Action::Admin,
                                    )
                                }),
                            },
                        )
                        .await?;
                    result.validate(&request)?;
                    encode_json(&result)?
                }
            };
            anyhow::ensure!(
                encoded.len() <= MAX_SECURITY_AUDIT_PAGE_BYTES,
                kasumi_types::Error::new(
                    ErrorCode::ResourceExhausted,
                    "service audit response exceeds its byte limit"
                )
            );
            Ok::<_, anyhow::Error>(encoded)
        }
        .await
        .map_err(audit_error);
        let bytes = self
            .auth
            .audit_result(&context, result)
            .await
            .map_err(status)?;
        #[cfg(test)]
        let gate = self.audit_release_gate.lock().await.take();
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        // The original live credential and captured Control policy epoch remain
        // attached through encoding and the final plaintext handoff.
        self.auth
            .audit_result(
                &context,
                database.engine().authorize(&context, None, Action::Admin),
            )
            .await
            .map_err(status)?;
        let response = release_response(
            &self.auth,
            &context,
            fence,
            SecurityAuditJsonResponse {
                response_json: bytes,
            },
            false,
        )
        .await
        .map_err(status)?;
        Ok(Response::new(response))
    }
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct AuditReleaseGate {
    pub entered: Arc<tokio::sync::Notify>,
    pub release: Arc<tokio::sync::Notify>,
}
