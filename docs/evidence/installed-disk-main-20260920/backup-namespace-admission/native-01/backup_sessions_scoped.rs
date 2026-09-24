use anyhow::{Context, Result, ensure};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use kasumi_store::StorageAccess;
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
/// One exact reclaimable object. S3 selectors include a version ID for both
/// object versions and delete markers; the literal `null` is a version ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupSessionObject {
    File { id: Uuid },
    S3Version { id: Uuid, version_id: String },
}
impl BackupSessionObject {
    pub fn id(&self) -> Uuid {
        match self {
            Self::File { id } | Self::S3Version { id, .. } => *id,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionObjectPage {
    pub objects: Vec<BackupSessionObject>,
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

#[path="backup_sessions_fs.rs"]
pub(crate) mod filesystem;
