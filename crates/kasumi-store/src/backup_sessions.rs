//! Immutable authenticated full-backup session control and narrowly scoped GC.
use crate::{BackupDestination, EncryptedBackup, KeyProvider, StorageAccess, TenantStore};
use anyhow::{Context, Result, ensure};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
#[path = "backup_sessions_fs.rs"]
pub(crate) mod filesystem;

pub const MAX_SESSION_RECORD_BYTES: usize = 64 << 10;
pub const MAX_SESSION_GC_OBJECTS: usize = 256;
/// Control records live outside the only deletable subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupSessionSlot {
    Intent,
    Outcome,
    Object(Uuid),
}
impl BackupSessionSlot {
    pub(crate) fn relative(self, session: Uuid) -> Result<String> {
        ensure!(!session.is_nil(), "nil backup session");
        let leaf = match self {
            Self::Intent => "intent.kasumi".to_owned(),
            Self::Outcome => "outcome.kasumi".to_owned(),
            Self::Object(id) => {
                ensure!(!id.is_nil(), "nil backup object");
                format!("objects/{id}.kasumi")
            }
        };
        Ok(format!("sessions/{session}/{leaf}"))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionObjectPage {
    pub objects: Vec<Uuid>,
    /// More objects were observed. A new pass always starts at the namespace head.
    pub more: bool,
}
/// A caller cannot mint cleanup authority from an untrusted wire outcome. This
/// proof follows fresh decryption and exact intent/outcome binding at destination.
#[derive(Clone)]
pub struct VerifiedBackupAbort {
    session: Uuid,
    outcome_sha256: String,
    access: StorageAccess,
    request_guard: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}
impl VerifiedBackupAbort {
    pub fn session_id(&self) -> Uuid {
        self.session
    }
    /// Adds a stricter live request gate to already verified abort authority.
    /// Cloned filesystem workers retain this gate and its owned work resources.
    pub fn with_request_guard(mut self, guard: Arc<dyn Fn() -> Result<()> + Send + Sync>) -> Self {
        self.request_guard = Some(match self.request_guard.take() {
            Some(previous) => Arc::new(move || {
                previous()?;
                guard()
            }),
            None => guard,
        });
        self
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.access.check()?;
        if let Some(guard) = &self.request_guard {
            guard()?;
        }
        Ok(())
    }
    pub(crate) fn matches_outcome(&self, bytes: &[u8]) -> Result<()> {
        self.check()?;
        ensure!(
            hex::encode(Sha256::digest(bytes)) == self.outcome_sha256,
            "abort publication differs before cleanup"
        );
        Ok(())
    }
}
pub struct VerifiedBackupSession {
    intent: BackupSessionIntent,
    outcome: Option<BackupSessionOutcome>,
    intent_ciphertext_sha256: String,
    outcome_ciphertext_sha256: Option<String>,
    access: StorageAccess,
    source_purpose: crate::StoragePurpose,
    intent_bytes: Vec<u8>,
    key_catalog_sha256: String,
}
impl VerifiedBackupSession {
    pub async fn encrypt_outcome(
        &self,
        value: &BackupSessionOutcome,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Vec<u8>> {
        value.validate(&self.intent, &self.intent_ciphertext_sha256)?;
        self.access.check()?;
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= MAX_SESSION_RECORD_BYTES,
            "backup outcome exceeds limit"
        );
        let original = EncryptedBackup::from_bytes(&self.intent_bytes, MAX_SESSION_RECORD_BYTES)?;
        original
            .encrypt_related(&bytes, provider, &self.access)
            .await?
            .to_bytes()
    }
    pub fn key_catalog_sha256(&self) -> &str {
        &self.key_catalog_sha256
    }
    pub fn source_purpose(&self) -> &crate::StoragePurpose {
        &self.source_purpose
    }
    pub fn intent(&self) -> &BackupSessionIntent {
        &self.intent
    }
    pub fn outcome(&self) -> Option<&BackupSessionOutcome> {
        self.outcome.as_ref()
    }
    pub fn intent_ciphertext_sha256(&self) -> &str {
        &self.intent_ciphertext_sha256
    }

    pub fn aborted(&self) -> Result<VerifiedBackupAbort> {
        ensure!(
            matches!(self.outcome, Some(BackupSessionOutcome::Aborted { .. })),
            "session is not permanently aborted"
        );
        Ok(VerifiedBackupAbort {
            session: self.intent.session_id,
            request_guard: None,
            access: self.access.clone(),
            outcome_sha256: self
                .outcome_ciphertext_sha256
                .clone()
                .context("abort ciphertext missing")?,
        })
    }
}
async fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    tenant: &str,
    provider: Arc<dyn KeyProvider>,
    access: &StorageAccess,
) -> Result<(T, crate::StoragePurpose, u64, String)> {
    let envelope = EncryptedBackup::from_bytes(bytes, MAX_SESSION_RECORD_BYTES)?;
    let contents = envelope.decrypt(tenant, provider, access).await?;
    Ok((
        serde_json::from_slice(&contents.snapshot)?,
        envelope.source_purpose().clone(),
        contents.revision,
        contents.key_catalog_sha256,
    ))
}
pub async fn verify_backup_session(
    destination: &dyn BackupDestination,
    session: Uuid,
    tenant: &str,
    provider: Arc<dyn KeyProvider>,
    access: &StorageAccess,
) -> Result<Option<VerifiedBackupSession>> {
    access.check()?;
    let Some(intent_bytes) = destination
        .session_get(
            session,
            BackupSessionSlot::Intent,
            MAX_SESSION_RECORD_BYTES + crate::backup::HEADER_LIMIT + 84,
        )
        .await?
    else {
        return Ok(None);
    };
    let (intent, source_purpose, revision, key_catalog_sha256): (BackupSessionIntent, _, _, _) =
        decode(&intent_bytes, tenant, provider.clone(), access).await?;
    intent.validate()?;
    ensure!(
        intent.revision == revision,
        "backup intent revision differs from encrypted record"
    );
    source_purpose.validate_application_identity(tenant, &intent.source_incarnation)?;
    ensure!(
        intent.session_id == session && intent.tenant == tenant,
        "backup intent identity differs"
    );
    let intent_ciphertext_sha256 = hex::encode(Sha256::digest(&intent_bytes));
    let outcome_bytes = destination
        .session_get(
            session,
            BackupSessionSlot::Outcome,
            MAX_SESSION_RECORD_BYTES + crate::backup::HEADER_LIMIT + 84,
        )
        .await?;
    let outcome = if let Some(bytes) = &outcome_bytes {
        let (outcome, purpose, revision, outcome_catalog): (BackupSessionOutcome, _, _, _) =
            decode(bytes, tenant, provider, access).await?;
        ensure!(
            purpose == source_purpose
                && revision == intent.revision
                && outcome_catalog == key_catalog_sha256,
            "backup outcome source purpose or revision differs from intent"
        );
        outcome.validate(&intent, &intent_ciphertext_sha256)?;
        Some(outcome)
    } else {
        None
    };
    access.check()?;
    Ok(Some(VerifiedBackupSession {
        intent,
        outcome,
        access: access.clone(),
        source_purpose,
        intent_bytes,
        key_catalog_sha256,
        intent_ciphertext_sha256,
        outcome_ciphertext_sha256: outcome_bytes
            .as_ref()
            .map(|b| hex::encode(Sha256::digest(b))),
    }))
}
impl TenantStore {
    pub async fn verify_backup_session(
        &self,
        destination: &dyn BackupDestination,
        session: Uuid,
    ) -> Result<Option<VerifiedBackupSession>> {
        self.check_access()?;
        let result = verify_backup_session(
            destination,
            session,
            self.tenant(),
            self.provider.clone(),
            self.storage_access(),
        )
        .await?;
        self.check_access()?;
        Ok(result)
    }
    pub async fn encrypt_backup_session_outcome(
        &self,
        session: &VerifiedBackupSession,
        value: &BackupSessionOutcome,
    ) -> Result<Vec<u8>> {
        self.check_access()?;
        ensure!(
            session.intent().tenant == self.tenant(),
            "backup session tenant differs"
        );
        let bytes = session
            .encrypt_outcome(value, self.provider.clone())
            .await?;
        self.check_access()?;
        Ok(bytes)
    }
    pub fn encrypt_session_record(&self, revision: u64, value: &impl Serialize) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= MAX_SESSION_RECORD_BYTES,
            "backup session record exceeds limit"
        );
        self.encrypt_backup(revision, &bytes)?.to_bytes()
    }
}

/// A bounded object graph resolves only within its durable session namespace.
/// Archive destinations retain their independent unscoped object namespace.
pub struct BackupSessionObjects<'a> {
    destination: &'a dyn BackupDestination,
    session: Uuid,
}
impl<'a> BackupSessionObjects<'a> {
    pub fn new(destination: &'a dyn BackupDestination, session: Uuid) -> Result<Self> {
        ensure!(!session.is_nil(), "nil backup session");
        Ok(Self {
            destination,
            session,
        })
    }
}
#[async_trait::async_trait]
impl BackupDestination for BackupSessionObjects<'_> {
    async fn put(&self, id: Uuid, encrypted: Vec<u8>) -> Result<()> {
        self.destination
            .session_put(self.session, BackupSessionSlot::Object(id), encrypted)
            .await
    }
    async fn get(&self, id: Uuid, max_bytes: usize) -> Result<Vec<u8>> {
        self.destination
            .session_get(self.session, BackupSessionSlot::Object(id), max_bytes)
            .await?
            .context("backup session dependency missing")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FilesystemBackupDestination, NodeStore, test_utils::LocalKeyProvider};
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<TenantStore>,
        Arc<LocalKeyProvider>,
        FilesystemBackupDestination,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeyProvider::new([71; 32]));
        let store = TenantStore::initialize_catalog_fixture(
            NodeStore::create_new(
                dir.path().join("node"),
                crate::test_utils::NODE_STORE_ID,
                crate::ScratchDisk::fixture(),
            )
            .unwrap(),
            "tenant".into(),
            keys.clone(),
        )
        .await
        .unwrap();
        let destination = FilesystemBackupDestination::new(
            dir.path().join("backup"),
            crate::MAX_BACKUP_BUNDLE_BYTES,
        )
        .unwrap();
        (dir, store, keys, destination)
    }
    pub(super) async fn begin(
        destination: &dyn BackupDestination,
        store: &TenantStore,
        keys: Arc<dyn KeyProvider>,
    ) -> VerifiedBackupSession {
        let session = Uuid::new_v4();
        let intent = BackupSessionIntent {
            session_id: session,
            tenant: "tenant".into(),
            source_incarnation: "source".into(),
            revision: 7,
            principal: "admin".into(),
            request_id: "backup-request".into(),
        };
        let bytes = store.encrypt_session_record(7, &intent).unwrap();
        destination
            .session_put(session, BackupSessionSlot::Intent, bytes.clone())
            .await
            .unwrap();
        assert!(
            destination
                .session_put(session, BackupSessionSlot::Intent, bytes)
                .await
                .is_err()
        );
        let verified =
            verify_backup_session(destination, session, "tenant", keys, store.storage_access())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(verified.intent(), &intent);
        assert!(verified.outcome().is_none());
        assert!(verified.aborted().is_err());
        verified
    }
    pub(super) async fn abort(
        destination: &dyn BackupDestination,
        store: &TenantStore,
        keys: Arc<dyn KeyProvider>,
        session: &VerifiedBackupSession,
    ) -> VerifiedBackupAbort {
        let value = BackupSessionOutcome::Aborted {
            intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
            session_id: session.intent().session_id,
            principal: "admin".into(),
            reason: "operator cancelled".into(),
        };
        destination
            .session_put(
                session.intent().session_id,
                BackupSessionSlot::Outcome,
                store.encrypt_session_record(7, &value).unwrap(),
            )
            .await
            .unwrap();
        verify_backup_session(
            destination,
            session.intent().session_id,
            "tenant",
            keys,
            store.storage_access(),
        )
        .await
        .unwrap()
        .unwrap()
        .aborted()
        .unwrap()
    }
    #[tokio::test]
    async fn filesystem_abort_cleanup_is_bounded_repeatable_and_retains_control_and_other_namespaces()
     {
        let (dir, store, keys, destination) = fixture().await;
        let session = begin(&destination, &store, keys.clone()).await;
        let id = session.intent().session_id;
        let shared = Uuid::new_v4();
        destination
            .put(shared, b"independent audit archive".to_vec())
            .await
            .unwrap();
        let other = begin(&destination, &store, keys.clone()).await;
        destination
            .session_put(
                other.intent().session_id,
                BackupSessionSlot::Object(shared),
                b"other session".to_vec(),
            )
            .await
            .unwrap();
        for object in 1..=260 {
            destination
                .session_put(
                    id,
                    BackupSessionSlot::Object(Uuid::from_u128(object)),
                    vec![42],
                )
                .await
                .unwrap();
        }
        let proof = abort(&destination, &store, keys.clone(), &session).await;
        let page = destination.session_objects(&proof, 256).await.unwrap();
        assert_eq!(page.objects.len(), 256);
        let denied = proof
            .clone()
            .with_request_guard(Arc::new(|| anyhow::bail!("original request revoked")));
        assert!(destination.session_objects(&denied, 1).await.is_err());
        assert!(
            destination
                .session_delete(&denied, &page.objects)
                .await
                .is_err()
        );
        assert_eq!(
            destination
                .session_objects(&proof, 256)
                .await
                .unwrap()
                .objects,
            page.objects
        );
        assert!(page.more);
        let late_id = page.objects[0];
        destination
            .session_delete(&proof, &page.objects)
            .await
            .unwrap();
        // An already-admitted upload can publish after the first cleanup pass.
        destination
            .session_put(id, BackupSessionSlot::Object(late_id), vec![99])
            .await
            .unwrap();
        let tail = destination.session_objects(&proof, 256).await.unwrap();
        assert_eq!(tail.objects.len(), 5);
        assert!(!tail.more);
        destination
            .session_delete(&proof, &tail.objects)
            .await
            .unwrap();
        destination
            .session_put(id, BackupSessionSlot::Object(late_id), vec![88])
            .await
            .unwrap();
        let late = destination.session_objects(&proof, 256).await.unwrap();
        assert_eq!(late.objects, vec![late_id]);
        destination
            .session_delete(&proof, &late.objects)
            .await
            .unwrap();
        destination
            .session_delete(&proof, &late.objects)
            .await
            .unwrap();
        assert!(
            destination
                .session_objects(&proof, 256)
                .await
                .unwrap()
                .objects
                .is_empty()
        );
        assert!(destination.session_objects(&proof, 257).await.is_err());
        assert!(
            verify_backup_session(&destination, id, "tenant", keys, store.storage_access())
                .await
                .unwrap()
                .unwrap()
                .aborted()
                .is_ok()
        );
        assert_eq!(
            destination.get(shared, 1024).await.unwrap(),
            b"independent audit archive"
        );
        assert_eq!(
            destination
                .session_get(
                    other.intent().session_id,
                    BackupSessionSlot::Object(shared),
                    1024
                )
                .await
                .unwrap()
                .unwrap(),
            b"other session"
        );
        assert!(
            dir.path()
                .join(format!("backup/sessions/{id}/intent.kasumi"))
                .is_file()
        );
        assert!(
            dir.path()
                .join(format!("backup/sessions/{id}/outcome.kasumi"))
                .is_file()
        );
    }
    #[tokio::test]
    async fn completion_excludes_abort_and_corrupt_publication_never_grants_cleanup() {
        let (dir, store, keys, destination) = fixture().await;
        let session = begin(&destination, &store, keys.clone()).await;
        let id = session.intent().session_id;
        let checkpoint = FullBackupCheckpoint {
            tenant: "tenant".into(),
            source_incarnation: "source".into(),
            revision: 7,
            resident_sha256: "a".repeat(64),
            backup_id: id,
            manifest_ciphertext_sha256: "b".repeat(64),
            key_lineage_digest: "c".repeat(64),
        };
        let complete = BackupSessionOutcome::Complete {
            intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
            checkpoint,
        };
        destination
            .session_put(
                id,
                BackupSessionSlot::Outcome,
                store.encrypt_session_record(7, &complete).unwrap(),
            )
            .await
            .unwrap();
        let verified = verify_backup_session(
            &destination,
            id,
            "tenant",
            keys.clone(),
            store.storage_access(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(verified.aborted().is_err());
        let abort = BackupSessionOutcome::Aborted {
            intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
            session_id: id,
            principal: "admin".into(),
            reason: "cancel".into(),
        };
        assert!(
            destination
                .session_put(
                    id,
                    BackupSessionSlot::Outcome,
                    store.encrypt_session_record(7, &abort).unwrap()
                )
                .await
                .is_err()
        );
        let abandoned = begin(&destination, &store, keys.clone()).await;
        let proof = self::abort(&destination, &store, keys.clone(), &abandoned).await;
        let object = Uuid::new_v4();
        destination
            .session_put(
                proof.session_id(),
                BackupSessionSlot::Object(object),
                vec![1],
            )
            .await
            .unwrap();
        std::fs::write(
            dir.path().join(format!(
                "backup/sessions/{}/outcome.kasumi",
                proof.session_id()
            )),
            b"corrupt",
        )
        .unwrap();
        assert!(destination.session_objects(&proof, 1).await.is_err());
        assert!(destination.session_delete(&proof, &[object]).await.is_err());
        assert!(
            verify_backup_session(
                &destination,
                proof.session_id(),
                "tenant",
                keys,
                store.storage_access()
            )
            .await
            .is_err()
        );
        assert_eq!(
            destination
                .session_get(proof.session_id(), BackupSessionSlot::Object(object), 1)
                .await
                .unwrap()
                .unwrap(),
            [1]
        );
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn filesystem_cleanup_rejects_directory_symlink_substitution() {
        use std::os::unix::fs::symlink;
        let (dir, store, keys, destination) = fixture().await;
        let session = begin(&destination, &store, keys.clone()).await;
        let proof = abort(&destination, &store, keys, &session).await;
        let object = Uuid::new_v4();
        let external = dir.path().join("unrelated");
        std::fs::create_dir(&external).unwrap();
        let external_object = external.join(format!("{object}.kasumi"));
        std::fs::write(&external_object, b"unrelated").unwrap();
        let objects = dir
            .path()
            .join(format!("backup/sessions/{}/objects", proof.session_id()));
        std::fs::remove_dir(&objects).unwrap();
        symlink(&external, &objects).unwrap();
        assert!(destination.session_objects(&proof, 1).await.is_err());
        assert!(destination.session_delete(&proof, &[object]).await.is_err());
        assert!(
            destination
                .session_put(
                    proof.session_id(),
                    BackupSessionSlot::Object(object),
                    vec![0]
                )
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(external_object).unwrap(), b"unrelated");
    }
    #[tokio::test]
    async fn session_keeps_historical_source_purpose_separate_from_current_access() {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeyProvider::new([81; 32]));
        let source_incarnation = Uuid::new_v4();
        let installation = Uuid::new_v4();
        let access = StorageAccess::standalone(installation, "tenant", source_incarnation).unwrap();
        let store = TenantStore::initialize_catalog_fixture_with_access(
            NodeStore::create_new(
                dir.path().join("source"),
                crate::test_utils::NODE_STORE_ID,
                crate::ScratchDisk::fixture(),
            )
            .unwrap(),
            "tenant".into(),
            keys.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        let destination = FilesystemBackupDestination::new(
            dir.path().join("backups"),
            crate::MAX_BACKUP_BUNDLE_BYTES,
        )
        .unwrap();
        let id = Uuid::new_v4();
        let intent = BackupSessionIntent {
            session_id: id,
            tenant: "tenant".into(),
            source_incarnation: source_incarnation.to_string(),
            revision: 7,
            principal: "admin".into(),
            request_id: "historical".into(),
        };
        destination
            .session_put(
                id,
                BackupSessionSlot::Intent,
                store.encrypt_session_record(7, &intent).unwrap(),
            )
            .await
            .unwrap();
        let target = StorageAccess::standalone(installation, "tenant", Uuid::new_v4()).unwrap();
        let session = verify_backup_session(&destination, id, "tenant", keys.clone(), &target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.source_purpose(), access.purpose());
        assert_ne!(session.source_purpose(), target.purpose());
        let outcome = BackupSessionOutcome::Aborted {
            intent_ciphertext_sha256: session.intent_ciphertext_sha256().into(),
            session_id: id,
            principal: "admin".into(),
            reason: "historical cleanup".into(),
        };
        destination
            .session_put(
                id,
                BackupSessionSlot::Outcome,
                session
                    .encrypt_outcome(&outcome, keys.clone())
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();
        let verified = verify_backup_session(&destination, id, "tenant", keys.clone(), &target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified.source_purpose(), access.purpose());
        assert!(verified.aborted().is_ok());
        let wrong = BackupSessionIntent {
            session_id: Uuid::new_v4(),
            source_incarnation: Uuid::new_v4().to_string(),
            ..intent
        };
        destination
            .session_put(
                wrong.session_id,
                BackupSessionSlot::Intent,
                store.encrypt_session_record(7, &wrong).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            verify_backup_session(&destination, wrong.session_id, "tenant", keys, &target)
                .await
                .is_err()
        );
    }
}
