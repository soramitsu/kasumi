//! Durable session outcomes are independent of a particular API waiter. Only a
//! verified terminal abort grants narrowly scoped, repeatable cleanup authority.
use super::*;
use kasumi_store::{BackupSessionSlot, VerifiedBackupSession};

fn storage_error(error: anyhow::Error) -> Error {
    error.downcast_ref::<Error>().cloned().unwrap_or_else(|| {
        Error::new(
            ErrorCode::Unavailable,
            "backup session storage unavailable or invalid",
        )
    })
}
fn status(session: &VerifiedBackupSession) -> Result<BackupSessionStatus> {
    Ok(BackupSessionStatus {
        intent: session.intent().clone(),
        outcome: session.outcome().cloned(),
        source_purpose_sha256: staged_digest(session.source_purpose())?.0,
    })
}
impl Database {
    pub(super) async fn session_work<T>(
        &self,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let _registration = self.work.begin(cancellation.clone())?;
        let _reservation = self
            .admission()
            .reserve(16 << 20, Some(cancellation.clone()))?;
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(300), work) => result.map_err(|_| Error::new(ErrorCode::UnknownOutcome, "backup session operation deadline expired; inspect its durable outcome"))?,
            _ = cancelled(&cancellation) => Err(cancelled_error()),
        }
    }

    pub(super) async fn backup_session(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        id: uuid::Uuid,
    ) -> Result<Option<VerifiedBackupSession>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let result = self
            .store
            .verify_backup_session(destination, id)
            .await
            .map_err(storage_error)?;
        if let Some(session) = &result {
            let generation = self.engine.generation()?;
            let state = &generation.state;
            let permitted = if session.intent().source_incarnation == state.incarnation {
                session
                    .source_purpose()
                    .same_application_resource(self.store.storage_access().purpose())
            } else {
                matches!(session.outcome(), Some(BackupSessionOutcome::Complete { checkpoint, .. })
                    if state.restore_lineage.iter().any(|link| &link.checkpoint == checkpoint))
            };
            if !permitted {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "backup session lacks current installation or exact restore lineage binding",
                ));
            }
        }
        self.response_fence(context)?.check()?;
        Ok(result)
    }
    pub(super) async fn finish_backup_session(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        session: &VerifiedBackupSession,
        checkpoint: &FullBackupCheckpoint,
    ) -> Result<VerifiedBackupSession> {
        let outcome = BackupSessionOutcome::Complete {
            intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
            checkpoint: checkpoint.clone(),
        };
        outcome.validate(session.intent(), session.intent_ciphertext_sha256())?;
        self.response_fence(context)?.check()?;
        let bytes = self
            .store
            .encrypt_backup_session_outcome(session, &outcome)
            .await
            .map_err(storage_error)?;
        self.response_fence(context)?.check()?;
        // A failed create may already have committed. Always resolve the same
        // permanent outcome; never classify uncertainty as cleanup permission.
        let _publication = destination
            .session_put(
                session.intent().session_id,
                BackupSessionSlot::Outcome,
                bytes,
            )
            .await;
        let resolved = self
            .backup_session(context, destination, session.intent().session_id)
            .await?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "backup session disappeared while resolving completion",
                )
            })?;
        if resolved.outcome() != Some(&outcome) {
            return Err(Error::new(
                ErrorCode::UnknownOutcome,
                "backup completion did not win the permanent session outcome; inspect session status",
            ));
        }
        Ok(resolved)
    }
    pub async fn backup_session_status(
        &self,
        context: RequestContext,
        request: BackupSessionRequest,
    ) -> Result<BackupSessionStatus> {
        let result = self
            .session_work(async {
                let destination = self.archive_destination(&request.destination)?;
                let session = self
                    .backup_session(&context, destination.as_ref(), request.session_id)
                    .await?
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "backup session not found"))?;
                let result = status(&session)?;
                self.response_fence(&context)?.check()?;
                Ok(result)
            })
            .await;
        self.audit_result(&context, result).await
    }
    pub async fn abort_backup_session(
        &self,
        context: RequestContext,
        request: AbortBackupSession,
    ) -> Result<BackupSessionStatus> {
        let result = self
            .session_work(async {
                self.engine.authorize(&context, None, Action::Admin)?;
                if request.reason.is_empty() || request.reason.len() > 1024 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "backup abort reason outside bounds",
                    ));
                }
                let destination = self.archive_destination(&request.destination)?;
                let session = self
                    .backup_session(&context, destination.as_ref(), request.session_id)
                    .await?
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "backup session not found"))?;
                if session.outcome().is_some() {
                    return status(&session);
                }
                let root = destination
                    .session_get(
                        request.session_id,
                        BackupSessionSlot::Object(request.session_id),
                        crate::backup_format::MANIFEST_BYTES
                            + crate::backup_format::OBJECT_OVERHEAD,
                    )
                    .await
                    .map_err(storage_error)?;
                // A published root might have completed before its waiter died. Resolve
                // its full graph and completion before deciding whether abort can win.
                if root.is_some() {
                    let checkpoint = self
                        .verify_pending_backup_checkpoint(&context, destination.as_ref(), &session)
                        .await?;
                    let resolved = self
                        .finish_backup_session(
                            &context,
                            destination.as_ref(),
                            &session,
                            checkpoint.checkpoint(),
                        )
                        .await?;
                    return status(&resolved);
                }
                let outcome = BackupSessionOutcome::Aborted {
                    intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
                    session_id: request.session_id,
                    principal: context.principal.clone(),
                    reason: request.reason,
                };
                let bytes = self
                    .store
                    .encrypt_backup_session_outcome(&session, &outcome)
                    .await
                    .map_err(storage_error)?;
                self.maintenance_audit(
                    context.clone(),
                    "backup_abort",
                    "started",
                    session.intent().revision,
                )
                .await?;
                let _publication = destination
                    .session_put(request.session_id, BackupSessionSlot::Outcome, bytes)
                    .await;
                let resolved = self
                    .backup_session(&context, destination.as_ref(), request.session_id)
                    .await?
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::UnknownOutcome,
                            "backup abort publication uncertain",
                        )
                    })?;
                if resolved.outcome().is_none() {
                    return Err(Error::new(
                        ErrorCode::UnknownOutcome,
                        "backup abort publication uncertain",
                    ));
                }
                self.maintenance_audit(
                    context.clone(),
                    "backup_abort",
                    "completed",
                    session.intent().revision,
                )
                .await?;
                self.response_fence(&context)?.check()?;
                status(&resolved)
            })
            .await;
        self.audit_write_result(&context, result).await
    }
    pub async fn cleanup_backup_session(
        &self,
        context: RequestContext,
        request: CleanupBackupSession,
    ) -> Result<BackupCleanupResult> {
        let result = self
            .session_work(async {
                self.engine.authorize(&context, None, Action::Admin)?;
                if !(1..=kasumi_store::MAX_SESSION_GC_OBJECTS).contains(&request.max_objects) {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "backup cleanup page limit outside bounds",
                    ));
                }
                let destination = self.archive_destination(&request.destination)?;
                let session = self
                    .backup_session(&context, destination.as_ref(), request.session_id)
                    .await?
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "backup session not found"))?;
                let proof = session.aborted().map_err(|_| {
                    Error::new(
                        ErrorCode::Conflict,
                        "only permanently aborted backup sessions can be reclaimed",
                    )
                })?;
                // The actual storage worker owns this registration and charge.
                // Dropping its API waiter cancels the gate without allowing
                // shutdown to drain before the worker has finished.
                let cancellation = QueryCancellation::default();
                let _cancel_on_drop = CancelOnDrop(cancellation.clone());
                let registration = self.work.begin(cancellation.clone())?;
                let reservation = self
                    .admission()
                    .reserve(2 << 20, Some(cancellation.clone()))?;
                let engine = self.engine.clone();
                let store = self.store.clone();
                let admission = self.admission().clone();
                let actor = context.clone();
                let epoch = engine.generation()?.state.policy_epoch;
                let proof = proof.with_request_guard(Arc::new(move || {
                    let _owned = (&reservation, &registration);
                    cancellation.check()?;
                    store.check_access()?;
                    admission.check_release(&cancellation)?;
                    engine.authorize_release(&actor, None, Action::Admin, epoch)?;
                    Ok(())
                }));
                self.maintenance_audit(
                    context.clone(),
                    "backup_cleanup",
                    "started",
                    session.intent().revision,
                )
                .await?;
                let page = destination
                    .session_objects(&proof, request.max_objects)
                    .await
                    .map_err(storage_error)?;
                self.response_fence(&context)?.check()?;
                destination
                    .session_delete(&proof, &page.objects)
                    .await
                    .map_err(storage_error)?;
                self.maintenance_audit(
                    context.clone(),
                    "backup_cleanup",
                    "completed",
                    session.intent().revision,
                )
                .await?;
                self.response_fence(&context)?.check()?;
                Ok(BackupCleanupResult {
                    session_id: request.session_id,
                    deleted_objects: page.objects.len() as u64,
                    more_objects_observed: page.more,
                })
            })
            .await;
        self.audit_write_result(&context, result).await
    }
}
