//! Protected service-audit observations. Cursors retain the original stream and
//! exclusive end; transports must never restart them against another snapshot.
use crate::{
    AuditArchiveReference, AuditRetentionBudget, AuditRetentionState, Error, ErrorCode, Result,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub const MAX_SECURITY_AUDIT_PAGE_BYTES: usize = 1 << 20;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditStatus {
    pub position: AuditRetentionState,
    pub budget: AuditRetentionBudget,
    pub archived_bytes: u64,
    pub archive_segments: u64,
    pub draining: bool,
    pub persistence_failed: bool,
    pub maintenance_failures: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub last_failure: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditCursor {
    pub stream_id: Uuid,
    pub next_sequence: u64,
    pub through_sequence: u64,
}
impl SecurityAuditCursor {
    pub fn validate(&self) -> Result<()> {
        if self.stream_id.is_nil() || self.next_sequence > self.through_sequence {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid service audit cursor",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditPage {
    pub stream_id: Uuid,
    pub through_sequence: u64,
    pub next_sequence: u64,
    pub records: Vec<serde_json::Value>,
}
impl SecurityAuditPage {
    pub fn cursor(&self) -> Option<SecurityAuditCursor> {
        (self.next_sequence < self.through_sequence).then_some(SecurityAuditCursor {
            stream_id: self.stream_id,
            next_sequence: self.next_sequence,
            through_sequence: self.through_sequence,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditExportRequest {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<SecurityAuditCursor>,
    pub limit: u16,
}
impl SecurityAuditExportRequest {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.limit) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "service audit page limit must be 1..1024",
            ));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditArchiveCursor {
    pub stream_id: Uuid,
    pub next_index: u64,
    pub through_index: u64,
}
impl SecurityAuditArchiveCursor {
    pub fn validate(&self) -> Result<()> {
        if self.stream_id.is_nil() || self.next_index > self.through_index {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid service audit archive cursor",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditArchivePageRequest {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<SecurityAuditArchiveCursor>,
    pub limit: u16,
}
impl SecurityAuditArchivePageRequest {
    pub fn validate(&self) -> Result<()> {
        if !(1..=256).contains(&self.limit) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "service audit archive page limit must be 1..256",
            ));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditArchivePage {
    pub stream_id: Uuid,
    pub next_index: u64,
    pub through_index: u64,
    pub archives: Vec<AuditArchiveReference>,
}
impl SecurityAuditArchivePage {
    pub fn cursor(&self) -> Option<SecurityAuditArchiveCursor> {
        (self.next_index < self.through_index).then_some(SecurityAuditArchiveCursor {
            stream_id: self.stream_id,
            next_index: self.next_index,
            through_index: self.through_index,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditVerifyRequest {
    pub stream_id: Uuid,
    pub index: u64,
}
impl SecurityAuditVerifyRequest {
    pub fn validate(&self) -> Result<()> {
        if self.stream_id.is_nil() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "audit archive verification requires an exact stream",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditStatusRequest {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditArchiveVerification {
    pub stream_id: Uuid,
    pub index: u64,
    pub archive: AuditArchiveReference,
}
