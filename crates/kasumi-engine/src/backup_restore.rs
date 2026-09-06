//! Verify an entire full-backup dependency graph before bootstrap persistence.
use super::*;
use crate::{
    admission::{NodeAdmission, Reservation},
    backup_format::*,
};

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

#[derive(Clone, Copy)]
pub(super) struct RestoreDeadline(tokio::time::Instant);

impl RestoreSource {
    pub(super) fn deadline(&self) -> anyhow::Result<RestoreDeadline> {
        anyhow::ensure!(
            (1..=600_000).contains(&self.timeout_ms),
            "restore timeout outside bounds"
        );
        Ok(RestoreDeadline(
            tokio::time::Instant::now() + std::time::Duration::from_millis(self.timeout_ms),
        ))
    }
}

impl RestoreDeadline {
    pub fn check(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            tokio::time::Instant::now() < self.0,
            "restore verification deadline expired"
        );
        Ok(())
    }
    pub async fn run<T>(self, future: impl std::future::Future<Output = T>) -> anyhow::Result<T> {
        self.check()?;
        tokio::time::timeout_at(self.0, future)
            .await
            .map_err(|_| anyhow::anyhow!("restore verification deadline expired"))
    }
    pub async fn blocking<T, F>(self, reservation: Arc<Reservation>, work: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    {
        self.run(tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            self.check()?;
            let result = work()?;
            self.check()?;
            Ok(result)
        }))
        .await??
    }
}

pub(super) struct VerifiedBackup {
    pub state: TenantState,
    pub bytes: Vec<u8>,
    pub _reservation: Arc<Reservation>,
}

pub(super) struct PreparedState {
    pub bytes: Vec<u8>,
    pub engine: Arc<TenantEngine>,
    pub sha256: String,
}

impl VerifiedBackup {
    pub async fn into_genesis(
        self,
        deadline: RestoreDeadline,
        tenant: String,
        incarnation: String,
        backup_id: uuid::Uuid,
    ) -> anyhow::Result<PreparedState> {
        deadline
            .blocking(self._reservation.clone(), move || {
                let bytes =
                    TenantEngine::restored_bootstrap(&self.bytes, &tenant, incarnation, backup_id)?;
                deadline.check()?;
                let engine = Arc::new(TenantEngine::from_bootstrap(&tenant, &bytes)?);
                let sha256 = hex::encode(Sha256::digest(&bytes));
                Ok(PreparedState {
                    bytes,
                    engine,
                    sha256,
                })
            })
            .await
    }
}

async fn object(
    source: &RestoreSource,
    target: &TenantStore,
    id: uuid::Uuid,
    max_plaintext: usize,
    expected_ciphertext: Option<&str>,
    target_history_keys: bool,
) -> anyhow::Result<kasumi_store::BackupContents> {
    target.check_access()?;
    let encrypted = source
        .destination
        .get(id, max_plaintext.saturating_add(OBJECT_OVERHEAD))
        .await?;
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
        .decrypt(target.tenant(), source.keys.clone())
        .await?;
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

pub(super) async fn load(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    target: &TenantStore,
    context: &RequestContext,
    audit: &SecurityAudit,
    admission: &Arc<NodeAdmission>,
    deadline: RestoreDeadline,
) -> anyhow::Result<VerifiedBackup> {
    validate_name(&source.destination_alias)?;
    restore_access(target, audit, context).await?;
    // Bound the envelope before trusting its declared resident size.
    let reservation = admission.reserve((MANIFEST_BYTES * 3 + (8 << 20)) as u64, None)?;
    let envelope = object(source, target, backup_id, MANIFEST_BYTES, None, false).await?;
    let manifest: FullBackupManifest = serde_json::from_slice(&envelope.snapshot)?;
    manifest.validate()?;
    anyhow::ensure!(
        manifest.tenant == target.tenant() && manifest.revision == envelope.revision,
        "full backup manifest identity differs"
    );
    drop(envelope);
    drop(reservation);
    let reservation = Arc::new(
        admission.reserve(
            manifest
                .resident_bytes
                .saturating_mul(6)
                .saturating_add(64 << 20) as u64,
            None,
        )?,
    );
    let mut bytes = Vec::with_capacity(manifest.resident_bytes);
    let mut digest = Sha256::new();
    for chunk in &manifest.chunks {
        restore_access(target, audit, context).await?;
        let contents = object(
            source,
            target,
            chunk.object_id,
            chunk.plaintext_bytes,
            Some(&chunk.ciphertext_sha256),
            false,
        )
        .await?;
        anyhow::ensure!(
            contents.revision == manifest.revision
                && contents.snapshot.len() == chunk.plaintext_bytes
                && hex::encode(Sha256::digest(&contents.snapshot)) == chunk.plaintext_sha256,
            "full backup chunk plaintext differs"
        );
        digest.update(&contents.snapshot);
        bytes.extend_from_slice(&contents.snapshot);
    }
    anyhow::ensure!(
        bytes.len() == manifest.resident_bytes
            && hex::encode(digest.finalize()) == manifest.resident_sha256,
        "full backup resident stream differs"
    );
    let (state, bytes) = deadline
        .blocking(reservation.clone(), move || {
            let state: TenantState = serde_json::from_slice(&bytes)?;
            Ok((state, bytes))
        })
        .await?;
    if context.tenant != state.tenant || !state.policy.allows(context, None, Action::Admin) {
        return Err(restore_denial(audit, context, ErrorCode::Forbidden)
            .await
            .into());
    }
    anyhow::ensure!(
        state.tenant == manifest.tenant
            && state.incarnation == manifest.source_incarnation
            && state.revision == manifest.revision,
        "full backup state identity differs"
    );
    // Check all source accounting, structured indexes, identities, and archive
    // references before trusting any transitive catalog descriptor.
    let (mut state, bytes) = deadline
        .blocking(reservation.clone(), move || {
            TenantEngine::verify_logical_snapshot(&bytes, &state)?;
            Ok((state, bytes))
        })
        .await?;
    for archive in state.history_archives.values() {
        restore_access(target, audit, context).await?;
        let contents = object(
            source,
            target,
            uuid::Uuid::parse_str(&archive.manifest_object_id)?,
            MAX_ARCHIVE_MANIFEST_BYTES,
            Some(&archive.manifest_ciphertext_sha256),
            true,
        )
        .await?;
        let stored: HistoryArchiveManifest = serde_json::from_slice(&contents.snapshot)?;
        anyhow::ensure!(
            stored == archive.manifest,
            "full backup history manifest differs"
        );
        for (index, chunk) in archive.manifest.chunks.iter().enumerate() {
            let contents = object(
                source,
                target,
                uuid::Uuid::parse_str(&chunk.object_id)?,
                chunk.plaintext_bytes,
                Some(&chunk.ciphertext_sha256),
                true,
            )
            .await?;
            anyhow::ensure!(
                contents.snapshot.len() == chunk.plaintext_bytes
                    && hex::encode(Sha256::digest(&contents.snapshot)) == chunk.plaintext_sha256,
                "full backup history chunk plaintext differs"
            );
            let body: HistoryArchiveChunk = serde_json::from_slice(&contents.snapshot)?;
            anyhow::ensure!(
                body.archive_id == archive.manifest.archive_id
                    && body.collection == archive.manifest.collection
                    && body.source_incarnation == archive.manifest.source_incarnation
                    && body.index == index
                    && body.documents.len() == chunk.document_count
                    && body
                        .documents
                        .first()
                        .is_some_and(|doc| doc.id == chunk.first_id)
                    && body
                        .documents
                        .last()
                        .is_some_and(|doc| doc.id == chunk.last_id)
                    && body
                        .documents
                        .windows(2)
                        .all(|pair| pair[0].id < pair[1].id),
                "full backup history chunk identity differs"
            );
            let collection = &state.collections[&archive.manifest.collection];
            for doc in &body.documents {
                let reference = collection.archived_documents.get(&doc.id).ok_or_else(|| {
                    anyhow::anyhow!("full backup archived document reference missing")
                })?;
                anyhow::ensure!(
                    reference.archive_id == archive.manifest.archive_id
                        && reference.chunk_index == index
                        && reference.version == doc.version
                        && reference.document_sha256 == staged_digest(doc)?.0
                        && reference.document_bytes == crate::accounting::encoded_len(doc)?
                        && reference.indexed_fields
                            == crate::state::history::index_fields(&collection.definition, doc),
                    "full backup archived document differs from retained metadata"
                );
            }
        }
    }
    // One trusted deterministic relocation for every replica, leaving the
    // immutable source manifest and object ciphertext unchanged.
    let alias = source.destination_alias.clone();
    let (state, bytes) = deadline
        .blocking(reservation.clone(), move || {
            drop(bytes);
            state.history_archive_bytes = 0;
            for (id, archive) in state.history_archives.iter_mut() {
                archive.storage_destination = alias.clone();
                state.history_archive_bytes = state
                    .history_archive_bytes
                    .checked_add(crate::state::history::metadata_entry(id, archive)?)
                    .ok_or_else(|| anyhow::anyhow!("restored history catalog size overflow"))?;
            }
            let bytes = serde_json::to_vec(&state)?;
            deadline.check()?;
            TenantEngine::verify_logical_snapshot(&bytes, &state)?;
            Ok((state, bytes))
        })
        .await?;
    restore_access(target, audit, context).await?;
    Ok(VerifiedBackup {
        state,
        bytes,
        _reservation: reservation,
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
        let deadline =
            RestoreDeadline(tokio::time::Instant::now() + std::time::Duration::from_millis(100));
        let task = tokio::spawn(async move {
            deadline
                .blocking(reservation, move || {
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
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(admission.snapshot().inflight_operations, 0);
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
