//! Current administrative backup proof boundary. The same graph verifier also
//! serves empty-target restore, with a distinct reader/authority implementation.
use super::*;
use crate::{
    VerifiedBackupCheckpoint,
    backup_format::OBJECT_OVERHEAD,
    backup_verify::{BackupReader, VerificationDeadline, VerificationWork},
};

const BACKUP_OPERATION_TIMEOUT_MS: u64 = 300_000;

struct LiveBackupReader<'a> {
    database: &'a Database,
    destination: &'a dyn BackupDestination,
    context: &'a RequestContext,
    policy_epoch: u64,
    cancellation: QueryCancellation,
    registration: Arc<VerificationWork>,
    source_purpose: &'a kasumi_store::StoragePurpose,
    session_key_catalog: &'a str,
}
impl BackupReader for LiveBackupReader<'_> {
    fn session_key_catalog(&self) -> &str {
        self.session_key_catalog
    }
    fn tenant(&self) -> &str {
        &self.context.tenant
    }
    fn work_registration(&self) -> Option<Arc<VerificationWork>> {
        Some(self.registration.clone())
    }
    fn cancellation(&self) -> Option<kasumi_query::QueryCancellation> {
        Some(self.cancellation.clone())
    }
    async fn check_access(&self) -> anyhow::Result<()> {
        self.cancellation.check()?;
        self.database.access()?;
        self.database.engine.authorize_release(
            self.context,
            None,
            Action::Admin,
            self.policy_epoch,
        )?;
        Ok(())
    }
    async fn authorize_state<'a>(&'a self, _: &'a TenantState) -> anyhow::Result<()> {
        self.check_access().await
    }
    async fn object<'a>(
        &'a self,
        id: uuid::Uuid,
        max_plaintext: usize,
        expected_ciphertext: Option<&'a str>,
        history: bool,
    ) -> anyhow::Result<kasumi_store::BackupContents> {
        self.check_access().await?;
        let max_encrypted = max_plaintext.saturating_add(OBJECT_OVERHEAD);
        let encrypted = tokio::select! {
            result = self.destination.get(id, max_encrypted) => result.map_err(|_| Error::new(ErrorCode::Unavailable, "backup dependency unavailable"))?,
            _ = cancelled(&self.cancellation) => return Err(cancelled_error().into()),
        };
        self.check_access().await?;
        if encrypted.len() > max_encrypted
            || expected_ciphertext
                .is_some_and(|expected| hex::encode(Sha256::digest(&encrypted)) != expected)
        {
            return Err(Error::new(ErrorCode::Corruption, "backup ciphertext differs").into());
        }
        let contents = tokio::select! {
            result = self.database.store.decrypt_backup_object(&encrypted, id, max_plaintext) => result.map_err(|_| Error::new(ErrorCode::Corruption, "backup authenticated object verification failed"))?,
            _ = cancelled(&self.cancellation) => return Err(cancelled_error().into()),
        };
        if !history && &contents.source_purpose != self.source_purpose {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup object source purpose differs from session",
            )
            .into());
        }
        self.check_access().await?;
        Ok(contents)
    }
}

fn verification_error(error: anyhow::Error, deadline: VerificationDeadline) -> Error {
    if let Some(error) = error.downcast_ref::<Error>() {
        return error.clone();
    }
    if deadline.check().is_err() {
        return Error::new(
            ErrorCode::ResourceExhausted,
            "backup verification deadline expired",
        );
    }
    Error::new(
        ErrorCode::Corruption,
        "complete backup graph verification failed",
    )
}

impl Database {
    pub async fn backup_checkpoint(
        &self,
        context: RequestContext,
        destination: &dyn BackupDestination,
        session_id: uuid::Uuid,
    ) -> Result<VerifiedBackupCheckpoint> {
        let mut publication_admitted = false;
        let result = self
            .session_work(async {
                tokio::time::timeout(Duration::from_millis(BACKUP_OPERATION_TIMEOUT_MS), async {
                    let fence = self.response_fence(&context)?;
                    self.engine.authorize(&context, None, Action::Admin)?;
                    if session_id.is_nil() {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "nil backup session identity",
                        ));
                    }
                    if let Some(session) = self
                        .backup_session(&context, destination, session_id)
                        .await?
                    {
                        match session.outcome() {
                            Some(BackupSessionOutcome::Complete { .. }) => {
                                return self
                                    .verify_backup_checkpoint_inner(
                                        &context,
                                        destination,
                                        session_id,
                                    )
                                    .await;
                            }
                            Some(BackupSessionOutcome::Aborted { .. }) => {
                                return Err(Error::new(
                                    ErrorCode::Conflict,
                                    "backup session was permanently aborted",
                                ));
                            }
                            None => {
                                publication_admitted = true;
                                let proof = self
                                    .verify_pending_backup_checkpoint(
                                        &context,
                                        destination,
                                        &session,
                                    )
                                    .await?;
                                self.finish_backup_session(
                                    &context,
                                    destination,
                                    &session,
                                    proof.checkpoint(),
                                )
                                .await?;
                                fence.check()?;
                                return Ok(proof);
                            }
                        }
                    }
                    publication_admitted = true;
                    let (expected, session) = self
                        .publish_full_backup(context.clone(), destination, session_id)
                        .await?;
                    let proof = self
                        .verify_pending_backup_checkpoint(&context, destination, &session)
                        .await?;
                    if !expected.matches(proof.checkpoint()) {
                        return Err(Error::new(
                            ErrorCode::Corruption,
                            "published backup checkpoint differs from complete readback",
                        ));
                    }
                    self.finish_backup_session(&context, destination, &session, proof.checkpoint())
                        .await?;
                    fence.check()?;
                    Ok(proof)
                })
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorCode::UnknownOutcome,
                        "backup publication deadline expired; immutable artifacts may exist",
                    )
                })
                .and_then(|result| result)
            })
            .await;
        let result = self.audit_result(&context, result).await;
        if publication_admitted {
            result.map_err(|_| Error::new(ErrorCode::UnknownOutcome,
                "backup publication was admitted but complete proof release failed; immutable artifacts may exist and no verified proof was released"))
        } else {
            result
        }
    }

    pub async fn backup_checkpoint_named(
        &self,
        context: RequestContext,
        destination: &str,
        session_id: uuid::Uuid,
    ) -> Result<VerifiedBackupCheckpoint> {
        let result = async {
            self.engine.authorize(&context, None, Action::Admin)?;
            let destination = self.archive_destination(destination)?;
            self.backup_checkpoint(context.clone(), destination.as_ref(), session_id)
                .await
        }
        .await;
        self.audit_write_result(&context, result).await
    }

    pub async fn verify_backup_checkpoint_named(
        &self,
        context: RequestContext,
        destination: &str,
        backup_id: uuid::Uuid,
    ) -> Result<VerifiedBackupCheckpoint> {
        let result = async {
            self.engine.authorize(&context, None, Action::Admin)?;
            let destination = self.archive_destination(destination)?;
            self.verify_backup_checkpoint(context.clone(), destination.as_ref(), backup_id)
                .await
        }
        .await;
        self.audit_result(&context, result).await
    }

    pub async fn verify_backup_checkpoint(
        &self,
        context: RequestContext,
        destination: &dyn BackupDestination,
        backup_id: uuid::Uuid,
    ) -> Result<VerifiedBackupCheckpoint> {
        let result = self
            .verify_backup_checkpoint_inner(&context, destination, backup_id)
            .await;
        self.audit_result(&context, result).await
    }

    async fn verify_backup_checkpoint_inner(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        backup_id: uuid::Uuid,
    ) -> Result<VerifiedBackupCheckpoint> {
        self.with_verified_backup(context, destination, backup_id, None, |verified, _, _| {
            Ok(VerifiedBackupCheckpoint::verified(
                verified.checkpoint.clone(),
            ))
        })
        .await
    }

    pub(super) async fn verify_pending_backup_checkpoint(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        session: &kasumi_store::VerifiedBackupSession,
    ) -> Result<VerifiedBackupCheckpoint> {
        self.with_verified_backup(
            context,
            destination,
            session.intent().session_id,
            Some(session),
            |verified, _, _| {
                Ok(VerifiedBackupCheckpoint::verified(
                    verified.checkpoint.clone(),
                ))
            },
        )
        .await
    }

    pub(super) async fn verified_retirement_closure(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        expected: FullBackupCheckpoint,
    ) -> Result<String> {
        let credential = context.authorization.clone();
        self.with_verified_backup(
            context,
            destination,
            expected.backup_id,
            None,
            move |verified, deadline, cancellation| {
                if verified.checkpoint != expected {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "retirement checkpoint differs from verified backup",
                    )
                    .into());
                }
                crate::retirement_closure::digest(&verified.state, || {
                    credential.check_live()?;
                    cancellation.check()?;
                    deadline.check().map_err(|_| {
                        Error::new(
                            ErrorCode::ResourceExhausted,
                            "retirement verification deadline expired",
                        )
                    })
                })
                .map_err(Into::into)
            },
        )
        .await
    }

    async fn with_verified_backup<T, F>(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        backup_id: uuid::Uuid,
        pending: Option<&kasumi_store::VerifiedBackupSession>,
        finish: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(
                crate::backup_verify::VerifiedBackup,
                VerificationDeadline,
                QueryCancellation,
            ) -> anyhow::Result<T>
            + Send
            + 'static,
    {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        if backup_id.is_nil() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "nil backup identity",
            ));
        }
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = self.work.begin(cancellation.clone())?;
        let slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "backup verification concurrency exhausted",
            )
        })?;
        let registration = VerificationWork::new(registration, slot);
        let deadline = VerificationDeadline::new(BACKUP_OPERATION_TIMEOUT_MS)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup deadline unavailable"))?;
        tokio::select! {
            result = deadline.run(self.barrier()) => result.map_err(|error| verification_error(error, deadline))??,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        let state = self.engine.generation()?;
        let epoch = state.state.policy_epoch;
        let current_revision = state.state.revision;
        drop(state);
        let session = tokio::select! {
            result = deadline.run(self.backup_session(context, destination, backup_id)) => result.map_err(|error| verification_error(error, deadline))??,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }.ok_or_else(|| Error::new(ErrorCode::NotFound, "backup session not found"))?;
        if let Some(expected) = pending
            && (expected.intent() != session.intent()
                || expected.intent_ciphertext_sha256() != session.intent_ciphertext_sha256())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "backup session intent changed",
            ));
        }
        let completed = match session.outcome() {
            Some(BackupSessionOutcome::Complete { checkpoint, .. }) => Some(checkpoint.clone()),
            Some(BackupSessionOutcome::Aborted { .. }) => {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "backup session was permanently aborted",
                ));
            }
            None if pending.is_some() => None,
            None => {
                return Err(Error::new(
                    ErrorCode::UnknownOutcome,
                    "backup session has no permanent completion; resolve its creation first",
                ));
            }
        };
        let objects = kasumi_store::BackupSessionObjects::new(destination, backup_id)
            .map_err(|error| verification_error(error, deadline))?;
        let reader = LiveBackupReader {
            database: self,
            destination: &objects,
            source_purpose: session.source_purpose(),
            session_key_catalog: session.key_catalog_sha256(),
            context,
            policy_epoch: epoch,
            cancellation: cancellation.clone(),
            registration: registration.clone(),
        };
        let verified = tokio::select! {
            result = deadline.run(Box::pin(crate::backup_verify::verify(&reader, backup_id, self.admission(), deadline))) => result.map_err(|error| verification_error(error, deadline))?.map_err(|error| verification_error(error, deadline))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        if completed
            .as_ref()
            .is_some_and(|expected| expected != &verified.checkpoint)
            || verified.checkpoint.tenant != session.intent().tenant
            || verified.checkpoint.source_incarnation != session.intent().source_incarnation
            || verified.checkpoint.revision != session.intent().revision
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup graph differs from permanent session identity or outcome",
            ));
        }
        // Decoded resident state can be large; its destructor and reservation
        // also belong to the actual blocking worker, not a canceled caller.
        let worker_cancellation = cancellation.clone();
        let proof = deadline
            .blocking(
                verified._reservation.clone(),
                Some(registration),
                move || finish(verified, deadline, worker_cancellation),
            )
            .await
            .map_err(|error| verification_error(error, deadline))?;
        tokio::select! {
            result = deadline.run(self.maintenance_audit_inner(context.clone(), "backup_verification", "completed", current_revision)) => { result.map_err(|error| verification_error(error, deadline))??; },
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        self.admission().check_release(&cancellation)?;
        self.access()?;
        Ok(proof)
    }

    pub fn backup_checkpoint_response_fence(
        &self,
        context: &RequestContext,
        proof: &VerifiedBackupCheckpoint,
    ) -> Result<ResponseFence<'_>> {
        let fence = self.response_fence(context)?;
        self.engine.authorize(context, None, Action::Admin)?;
        if proof.tenant() != context.tenant {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "backup checkpoint tenant mismatch",
            ));
        }
        fence.check()?;
        Ok(fence)
    }
}
