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
}
impl BackupReader for LiveBackupReader<'_> {
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
        _: bool,
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
    ) -> Result<VerifiedBackupCheckpoint> {
        let result =
            tokio::time::timeout(Duration::from_millis(BACKUP_OPERATION_TIMEOUT_MS), async {
                let fence = self.response_fence(&context)?;
                let expected = self
                    .publish_full_backup(context.clone(), destination)
                    .await?;
                let proof = self
                    .verify_backup_checkpoint_inner(&context, destination, expected.backup_id)
                    .await?;
                if proof.checkpoint() != &expected {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "published backup checkpoint differs from complete readback",
                    ));
                }
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
            .and_then(|result| result);
        self.audit_result(&context, result).await
    }

    pub async fn backup_checkpoint_named(
        &self,
        context: RequestContext,
        destination: &str,
    ) -> Result<VerifiedBackupCheckpoint> {
        let result = async {
            self.engine.authorize(&context, None, Action::Admin)?;
            let destination = self.archive_destination(destination)?;
            self.backup_checkpoint(context.clone(), destination.as_ref())
                .await
        }
        .await;
        self.audit_result(&context, result).await
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
        let reader = LiveBackupReader {
            database: self,
            destination,
            context,
            policy_epoch: epoch,
            cancellation: cancellation.clone(),
            registration: registration.clone(),
        };
        let verified = tokio::select! {
            result = deadline.run(Box::pin(crate::backup_verify::verify(&reader, backup_id, self.admission(), deadline))) => result.map_err(|error| verification_error(error, deadline))?.map_err(|error| verification_error(error, deadline))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        // Decoded resident state can be large; its destructor and reservation
        // also belong to the actual blocking worker, not a canceled caller.
        let proof = deadline
            .blocking(
                verified._reservation.clone(),
                Some(registration),
                move || {
                    let checkpoint = verified.checkpoint.clone();
                    drop(verified);
                    Ok(VerifiedBackupCheckpoint::verified(checkpoint))
                },
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
