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
const SESSION_WORKSPACE_BYTES: u64 = 16 << 20;
const MAX_SESSION_FUTURE_BYTES: usize = 1 << 20;

async fn admitted_session_work<T, F>(
    fence: &Arc<WorkFence>,
    admission: &Arc<NodeAdmission>,
    build: impl FnOnce() -> F + Send,
) -> Result<T>
where
    T: Send,
    F: std::future::Future<Output = Result<T>> + Send,
{
    let future_bytes = std::mem::size_of::<F>();
    if future_bytes > MAX_SESSION_FUTURE_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "backup session future exceeds its workspace bound",
        ));
    }
    let cancellation = QueryCancellation::default();
    let _cancel_on_drop = CancelOnDrop(cancellation.clone());
    let _registration = fence.begin(cancellation.clone())?;
    let mut reservation = admission.reserve(SESSION_WORKSPACE_BYTES, Some(cancellation.clone()))?;
    // Charge the exact concrete future separately from the existing workspace,
    // without consuming a second operation slot. Admission precedes even its
    // construction, and the box drops before the reservation on every exit.
    reservation.reserve_additional(future_bytes as u64)?;
    let work: std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + '_>> =
        Box::pin(build());
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(300), work) => result.map_err(|_| Error::new(ErrorCode::UnknownOutcome, "backup session operation deadline expired; inspect its durable outcome"))?,
        _ = cancelled(&cancellation) => Err(cancelled_error()),
    }
}

impl Database {
    pub(super) async fn session_work<T, F>(&self, build: impl FnOnce() -> F + Send) -> Result<T>
    where
        T: Send,
        F: std::future::Future<Output = Result<T>> + Send,
    {
        // The caller retains only the builder's captures. Its concrete future
        // is constructed after admission and erased before any work is polled.
        admitted_session_work(&self.work, self.admission(), build).await
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
            .session_work(|| async {
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
            .session_work(|| async {
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
                        .verify_pending_backup_checkpoint(
                            &context,
                            destination.as_ref(),
                            &session,
                            None,
                        )
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
            .session_work(|| async {
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

#[cfg(test)]
mod work_tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll},
    };

    fn admission(max_bytes: u64) -> Arc<NodeAdmission> {
        NodeAdmission::with_fixed_memory(
            crate::test_utils::admission_config_with_bookkeeping(
                crate::admission::AdmissionConfig {
                    max_inflight_bytes: Some(max_bytes),
                    ..Default::default()
                },
            )
            .unwrap(),
            1 << 30,
            0,
        )
        .unwrap()
    }
    struct OversizeFuture([u8; MAX_SESSION_FUTURE_BYTES + 1]);
    impl Future for OversizeFuture {
        type Output = Result<()>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            std::hint::black_box(&self.0);
            unreachable!("oversize future must never be built or polled")
        }
    }
    #[tokio::test]
    async fn oversized_future_is_denied_before_builder_or_charge() {
        let node = admission(64 << 20);
        let fence = Arc::new(WorkFence::default());
        let builds = AtomicUsize::new(0);
        let result = admitted_session_work(&fence, &node, || -> OversizeFuture {
            builds.fetch_add(1, Ordering::AcqRel);
            unreachable!("oversize builder must not run")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::ResourceExhausted);
        assert_eq!(builds.load(Ordering::Acquire), 0);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 0);
        assert_eq!(node.snapshot().inflight_operations, 0);
    }

    struct ObservedFuture {
        node: Arc<NodeAdmission>,
        bytes_at_drop: Arc<AtomicU64>,
        fail: bool,
        metadata: [u8; 257],
    }
    impl Future for ObservedFuture {
        type Output = Result<()>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            std::hint::black_box(&self.metadata);
            if self.fail {
                Poll::Ready(Err(Error::new(
                    ErrorCode::Conflict,
                    "original session failure",
                )))
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for ObservedFuture {
        fn drop(&mut self) {
            self.bytes_at_drop.store(
                crate::test_utils::reserved_payload_bytes(&self.node),
                Ordering::Release,
            );
        }
    }
    #[tokio::test]
    async fn future_charge_precedes_builder_and_outlives_box_on_cancel_and_error() {
        let future_bytes = std::mem::size_of::<ObservedFuture>() as u64;
        for fail in [false, true] {
            let node = admission(64 << 20);
            let fence = Arc::new(WorkFence::default());
            let bytes_at_drop = Arc::new(AtomicU64::new(0));
            let mut operation = Box::pin(admitted_session_work(&fence, &node, || {
                assert_eq!(
                    crate::test_utils::reserved_payload_bytes(&node),
                    SESSION_WORKSPACE_BYTES + future_bytes
                );
                assert_eq!(node.snapshot().inflight_operations, 1);
                ObservedFuture {
                    node: node.clone(),
                    bytes_at_drop: bytes_at_drop.clone(),
                    fail,
                    metadata: [0; 257],
                }
            }));
            if fail {
                assert_eq!(
                    operation.as_mut().await.unwrap_err().code,
                    ErrorCode::Conflict
                );
            } else {
                std::future::poll_fn(|cx| {
                    assert!(operation.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(
                    crate::test_utils::reserved_payload_bytes(&node),
                    SESSION_WORKSPACE_BYTES + future_bytes
                );
            }
            drop(operation);
            assert_eq!(
                bytes_at_drop.load(Ordering::Acquire),
                SESSION_WORKSPACE_BYTES + future_bytes
            );
            assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 0);
            assert_eq!(node.snapshot().inflight_operations, 0);
            tokio::time::timeout(Duration::from_secs(5), fence.drain())
                .await
                .unwrap();
        }
    }
    #[tokio::test]
    async fn additional_future_charge_denial_never_invokes_builder() {
        let node = admission(SESSION_WORKSPACE_BYTES);
        let fence = Arc::new(WorkFence::default());
        let builds = AtomicUsize::new(0);
        let result = admitted_session_work(&fence, &node, || -> ObservedFuture {
            builds.fetch_add(1, Ordering::AcqRel);
            unreachable!("unfunded builder must not run")
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::ResourceExhausted);
        assert_eq!(builds.load(Ordering::Acquire), 0);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 0);
        assert_eq!(node.snapshot().inflight_operations, 0);
        tokio::time::timeout(Duration::from_secs(5), fence.drain())
            .await
            .unwrap();
    }
}
