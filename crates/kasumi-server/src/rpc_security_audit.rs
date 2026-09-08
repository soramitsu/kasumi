use super::*;
use kasumi_types::*;
#[derive(Clone, Copy)]
pub(super) enum AuditOperation {
    Status,
    Export,
    Archives,
    Verify,
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
            .audit_result(&context, management.security_audit_workspace())
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
                    let value = tokio::task::spawn_blocking(move || audit.status()).await??;
                    encode_json(&value)?
                }
                AuditOperation::Export => {
                    let request: SecurityAuditExportRequest = decode_json(&payload)?;
                    request.validate()?;
                    if let Some(cursor) = &request.cursor {
                        let state = audit.status()?;
                        anyhow::ensure!(
                            cursor.stream_id == state.position.stream_id
                                && cursor.through_sequence <= state.position.next_sequence,
                            kasumi_types::Error::new(
                                ErrorCode::InvalidArgument,
                                "audit cursor belongs to another stream or future range"
                            )
                        );
                    }
                    encode_json(&audit.export_page(request.cursor, request.limit).await?)?
                }
                AuditOperation::Archives => {
                    let request: SecurityAuditArchivePageRequest = decode_json(&payload)?;
                    request.validate()?;
                    let value = tokio::task::spawn_blocking(
                        move || -> anyhow::Result<SecurityAuditArchivePage> {
                            let state = audit.status()?;
                            let cursor = request.cursor.unwrap_or(SecurityAuditArchiveCursor {
                                stream_id: state.position.stream_id,
                                next_index: 0,
                                through_index: state.archive_segments,
                            });
                            anyhow::ensure!(
                                cursor.stream_id == state.position.stream_id
                                    && cursor.through_index <= state.archive_segments,
                                kasumi_types::Error::new(
                                    ErrorCode::InvalidArgument,
                                    "archive cursor belongs to another stream or future range"
                                )
                            );
                            let limit = u64::from(request.limit)
                                .min(cursor.through_index - cursor.next_index)
                                as u16;
                            let archives = if limit == 0 {
                                Vec::new()
                            } else {
                                audit.archive_page(cursor.next_index, limit)?
                            };
                            Ok(SecurityAuditArchivePage {
                                stream_id: cursor.stream_id,
                                next_index: cursor
                                    .next_index
                                    .checked_add(archives.len() as u64)
                                    .ok_or_else(|| anyhow::anyhow!("archive index overflow"))?,
                                through_index: cursor.through_index,
                                archives,
                            })
                        },
                    )
                    .await??;
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
