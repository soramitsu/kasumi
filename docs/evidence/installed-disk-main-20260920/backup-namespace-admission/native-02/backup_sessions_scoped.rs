use anyhow::{Context, Result, ensure};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use uuid::Uuid;
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

#[path="backup_sessions_fs.rs"]
pub(crate) mod filesystem;
