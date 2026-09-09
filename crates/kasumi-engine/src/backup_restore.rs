//! Empty-target authorization and deterministic namespace rebinding around the
//! common complete-backup graph verifier.
use super::*;
use crate::{
    admission::NodeAdmission,
    backup_format::*,
    backup_verify::{BackupReader, VerificationDeadline, VerifiedBackup},
};
#[path = "target_restore_authorization.rs"]
mod authorization;
pub(super) use authorization::RestoreAuthorization;

/// Trusted operator binding for a complete backup and its copied history.
/// The same alias must be configured on every restored replica. Historical
/// archive keys must also remain accessible to the target tenant provider.
pub struct RestoreSource {
    pub destination_alias: String,
    pub destination: Arc<dyn BackupDestination>,
    pub keys: Arc<dyn KeyProvider>,
    /// One budget for gate admission and verification, before synchronous
    /// bootstrap persistence. Required; valid range is 1..=600,000 ms.
    pub timeout_ms: u64,
}

impl RestoreSource {
    pub(super) fn deadline(&self) -> anyhow::Result<VerificationDeadline> {
        VerificationDeadline::new(self.timeout_ms)
    }
}
pub(super) struct PreparedState {
    pub bytes: kasumi_store::SnapshotImage,
    pub engine: Arc<TenantEngine>,
    pub sha256: String,
    _materialization: Arc<crate::admission::Reservation>,
    registration: Option<Arc<crate::backup_verify::VerificationWork>>,
}

impl PreparedState {
    pub(super) fn publication_registration(
        &self,
    ) -> Option<Arc<crate::backup_verify::VerificationWork>> {
        self.registration.clone()
    }

    pub(super) fn publication_workspace(&self) -> Arc<crate::admission::Reservation> {
        self._materialization.clone()
    }
}

impl VerifiedBackup {
    pub(super) async fn into_genesis(
        self,
        deadline: VerificationDeadline,
        admission: Arc<NodeAdmission>,
        tenant: String,
        incarnation: String,
        target_origin: Option<TargetOrigin>,
    ) -> anyhow::Result<PreparedState> {
        let crate::backup_verify::VerifiedState::Indexed(source) = &self.state else {
            anyhow::bail!("restore requires independently verified indexed state");
        };
        // The authenticated index records exact resident and point spans. The
        // permanent ciphertext tables remain on the shared scratch governor.
        let workspace = source.index().summary().materialization_workspace()?;
        // The completed verifier owns one operation and its bounded indexes.
        // Its worker transfers that charge only after dropping those indexes.
        let materialization = self._reservation.clone();
        let retained_materialization = materialization.clone();
        deadline
            .blocking(materialization, self._registration.clone(), move || {
                let crate::backup_verify::VerifiedState::Indexed(source) = self.state else {
                    anyhow::bail!("restore requires independently verified indexed state");
                };
                drop(self.bytes);
                let (bytes, engine) = TenantEngine::materialize_verified_restore(
                    *source,
                    &tenant,
                    incarnation,
                    self.checkpoint,
                    target_origin,
                    || retained_materialization.handoff_workspace(&admission, workspace),
                )?;
                // This is still the original reservation identity and work slot.
                // The prepared result owns it through target publication.
                drop(self._reservation);
                deadline.check()?;
                let engine = Arc::new(engine);
                let sha256 = bytes.sha256().to_owned();
                Ok(PreparedState {
                    bytes,
                    engine,
                    sha256,
                    _materialization: retained_materialization,
                    registration: self._registration,
                })
            })
            .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn object(
    source: &RestoreSource,
    session: &kasumi_store::VerifiedBackupSession,
    target: &TenantStore,
    id: uuid::Uuid,
    max_plaintext: usize,
    expected_ciphertext: Option<&str>,
    target_history_keys: bool,
) -> anyhow::Result<kasumi_store::BackupContents> {
    target.check_access()?;
    let encrypted = source
        .destination
        .session_get(
            session.intent().session_id,
            kasumi_store::BackupSessionSlot::Object(id),
            max_plaintext.saturating_add(OBJECT_OVERHEAD),
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("backup session dependency missing"))?;
    target.check_access()?;
    if let Some(expected) = expected_ciphertext {
        anyhow::ensure!(
            hex::encode(Sha256::digest(&encrypted)) == expected,
            "backup object ciphertext differs"
        );
    }
    let envelope = EncryptedBackup::from_bytes(&encrypted, max_plaintext)?;
    anyhow::ensure!(
        envelope.id() == id && envelope.source_tenant() == target.tenant(),
        "backup object identity mismatch"
    );
    let contents = envelope
        .decrypt(
            target.tenant(),
            source.keys.clone(),
            target.storage_access(),
        )
        .await?;
    anyhow::ensure!(
        target_history_keys || &contents.source_purpose == session.source_purpose(),
        "backup object source purpose differs from session"
    );
    target.check_access()?;
    if target_history_keys {
        let verified = target
            .decrypt_backup_object(&encrypted, id, max_plaintext)
            .await?;
        anyhow::ensure!(
            verified.snapshot == contents.snapshot,
            "target cannot verify historical backup dependency"
        );
    }
    target.check_access()?;
    Ok(contents)
}

struct RestoreReader<'a> {
    source: &'a RestoreSource,
    target: &'a Arc<TenantStore>,
    authorization: RestoreAuthorization<'a>,
    work: Option<Arc<crate::backup_verify::VerificationWork>>,
    token: Option<kasumi_query::QueryCancellation>,
    audit: &'a SecurityAudit,
    bound_checkpoint: Option<FullBackupCheckpoint>,
    session: kasumi_store::VerifiedBackupSession,
}
impl BackupReader for RestoreReader<'_> {
    fn scratch_disk(&self) -> &Arc<kasumi_store::ScratchDisk> {
        self.target.scratch_disk()
    }
    fn session_key_catalog(&self) -> &str {
        self.session.key_catalog_sha256()
    }
    fn tenant(&self) -> &str {
        self.target.tenant()
    }
    fn work_registration(&self) -> Option<Arc<crate::backup_verify::VerificationWork>> {
        self.work.clone()
    }
    fn cancellation(&self) -> Option<kasumi_query::QueryCancellation> {
        self.token.clone()
    }
    async fn check_access(&self) -> anyhow::Result<()> {
        self.authorization
            .check_access(self.target, self.audit)
            .await
    }
    async fn authorize_state<'a>(&'a self, state: &'a TenantState) -> anyhow::Result<()> {
        self.authorization
            .authorize_state(self.target, self.audit, state)
            .await
    }
    fn audit_target(&self) -> Option<Arc<TenantStore>> {
        Some(self.target.clone())
    }
    async fn audit_dependency<'a>(
        &'a self,
        state: &'a crate::backup_verify::VerifiedState,
        root: &'a kasumi_store::StoragePurpose,
        link: &'a AuditArchiveLink,
    ) -> anyhow::Result<kasumi_store::PreparedAuditSegment> {
        self.check_access().await?;
        let ciphertext = self
            .source
            .destination
            .session_get(
                self.session.intent().session_id,
                kasumi_store::BackupSessionSlot::Object(link.object_id),
                MAX_AUDIT_SEGMENT_BYTES,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("backup audit dependency missing"))?;
        self.check_access().await?;
        let dependency = kasumi_store::InspectedAuditDependency::from_link(&ciphertext, link)?;
        anyhow::ensure!(
            dependency.source_tenant() == state.metadata().tenant
                && dependency.reference().stream_id == state.metadata().audit_retention.stream_id,
            "restore audit stream differs"
        );
        state.authorize_source(root, dependency.source_purpose())?;
        let verifier = kasumi_store::HistoricalAuditVerifier::new(
            &state.metadata().tenant,
            dependency.source_purpose(),
            self.source.keys.as_ref(),
            self.target.storage_access(),
        )?;
        dependency.verify(&verifier).await?;
        self.check_access().await?;
        // The target must independently retain access to every original archive
        // key before its new genesis can depend on this local ciphertext cache.
        let reference = crate::backup_verify::verify_indexed_audit_dependency(
            state,
            root,
            self.target,
            &ciphertext,
            link,
        )
        .await?;
        self.check_access().await?;
        Ok(kasumi_store::PreparedAuditSegment {
            reference,
            ciphertext,
        })
    }
    async fn object<'a>(
        &'a self,
        id: uuid::Uuid,
        max_plaintext: usize,
        expected_ciphertext: Option<&'a str>,
        history: bool,
    ) -> anyhow::Result<kasumi_store::BackupContents> {
        let expected_ciphertext = match &self.bound_checkpoint {
            Some(checkpoint) if id == checkpoint.backup_id => {
                if let Some(expected) = expected_ciphertext {
                    anyhow::ensure!(
                        expected == checkpoint.manifest_ciphertext_sha256,
                        "restore manifest dependency differs from authority binding"
                    );
                }
                Some(checkpoint.manifest_ciphertext_sha256.as_str())
            }
            _ => expected_ciphertext,
        };
        object(
            self.source,
            &self.session,
            self.target,
            id,
            max_plaintext,
            expected_ciphertext,
            history,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load_authorized(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    target: &Arc<TenantStore>,
    authorization: RestoreAuthorization<'_>,
    audit: &SecurityAudit,
    admission: &Arc<NodeAdmission>,
    deadline: VerificationDeadline,
    work: Option<Arc<crate::backup_verify::VerificationWork>>,
    token: Option<kasumi_query::QueryCancellation>,
) -> anyhow::Result<VerifiedBackup> {
    validate_name(&source.destination_alias)?;
    if let RestoreAuthorization::Lifecycle(invocation) = &authorization {
        anyhow::ensure!(
            work.as_ref().is_some_and(|w| w.binds(invocation)) && token.is_some(),
            "target verification lacks original registered work"
        );
    }
    let bound_checkpoint = authorization.bound_checkpoint(target, backup_id)?;
    authorization.check_access(target, audit).await?;
    let session = deadline
        .run(kasumi_store::verify_backup_session(
            source.destination.as_ref(),
            backup_id,
            target.tenant(),
            source.keys.clone(),
            target.storage_access(),
        ))
        .await??
        .ok_or_else(|| anyhow::anyhow!("backup session missing"))?;
    if let RestoreAuthorization::Local(request) = &authorization {
        anyhow::ensure!(
            session.source_purpose() == &request.source_purpose,
            "local backup source purpose differs from authorized recovery"
        );
    }
    let completed = match session.outcome() {
        Some(BackupSessionOutcome::Complete { checkpoint, .. }) => checkpoint.clone(),
        _ => anyhow::bail!("restore requires a permanently completed backup session"),
    };
    anyhow::ensure!(
        bound_checkpoint
            .as_ref()
            .is_none_or(|expected| expected == &completed),
        "completed session differs from authorized checkpoint"
    );
    let bound_checkpoint = Some(completed);
    let reader = RestoreReader {
        source,
        target,
        authorization,
        audit,
        bound_checkpoint,
        session,
        work,
        token,
    };
    let verified = Box::pin(crate::backup_verify::verify(
        &reader,
        backup_id,
        admission.clone(),
        deadline,
        None,
    ))
    .await?;
    if let Some(expected) = &reader.bound_checkpoint {
        anyhow::ensure!(
            &verified.checkpoint == expected,
            "verified restore graph differs from signed authority checkpoint"
        );
    }
    let VerifiedBackup {
        state,
        bytes,
        checkpoint,
        source_purpose,
        _reservation: reservation,
        _registration: registration,
    } = verified;
    // One trusted deterministic relocation for every replica, leaving the
    // immutable source manifest and object ciphertext unchanged.
    let alias = source.destination_alias.clone();
    let relocation_work = registration.clone();
    let relocation_reservation = reservation.clone();
    let relocation_cancellation = reader.cancellation();
    let (state, bytes) = deadline
        .blocking(reservation.clone(), registration.clone(), move || {
            drop(bytes.ok_or_else(|| anyhow::anyhow!("restore snapshot image missing"))?);
            let state = match state {
                crate::backup_verify::VerifiedState::Indexed(state) => state,
                _ => anyhow::bail!("restore requires independently verified indexed state"),
            };
            let state = (*state).relocate(
                &alias,
                backup_id,
                |layout| {
                    relocation_reservation
                        .handoff_workspace(&admission, layout.index_workspace()?)
                        .map_err(Into::into)
                },
                || {
                    deadline.check()?;
                    if let Some(work) = &relocation_work {
                        work.check()?;
                    }
                    if let Some(token) = &relocation_cancellation {
                        token.check()?;
                    }
                    Ok(())
                },
            )?;
            let bytes = state.image().clone();
            Ok((state, bytes))
        })
        .await?;
    reader.check_access().await?;
    Ok(VerifiedBackup {
        source_purpose,
        state: crate::backup_verify::VerifiedState::Indexed(Box::new(state)),
        bytes: Some(bytes),
        checkpoint,
        _reservation: reservation,
        _registration: registration,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn expired_restore_worker_keeps_its_admission_charge_until_actual_completion() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let reservation = Arc::new(admission.reserve(1 << 20, None).unwrap());
        let weak = Arc::downgrade(&reservation);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let deadline = VerificationDeadline::new(100).unwrap();
        let task = tokio::spawn(async move {
            deadline
                .blocking(reservation, None, move || {
                    let _ = started_tx.send(());
                    release_rx.recv()?;
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(weak.upgrade().is_some());
        assert_eq!(admission.snapshot().inflight_operations, 1);
        assert_eq!(admission.snapshot().reserved_bytes, 1 << 20);
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            // Weak::upgrade can fail after the final strong count reaches zero
            // while Reservation::drop is still releasing the governor charge.
            // Observe the resource owner finishing, not only Arc availability.
            while weak.upgrade().is_some()
                || admission.snapshot().inflight_operations != 0
                || admission.snapshot().reserved_bytes != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(admission.snapshot().inflight_operations, 0);
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
