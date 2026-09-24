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

#[path="backup_sessions_fs.rs"]
pub(crate) mod filesystem;
