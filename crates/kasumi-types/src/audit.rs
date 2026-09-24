//! Permanent audit positions and bounded immutable archive dependencies.
use crate::{Error, ErrorCode, Result, validate_sha256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_AUDIT_SEGMENT_BYTES: usize = 8 << 20;
pub const MAX_AUDIT_EVENT_BYTES: usize = 64 << 10;
/// Bounds a pruning batch even when individual events are very small.
pub const MAX_AUDIT_SEGMENT_RECORDS: u64 = 8192;

/// Hot history and immutable archives have separate expandable byte budgets.
/// The maintenance workspace is reserved before ordinary request admission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionBudget {
    pub hot_bytes: u64,
    pub archive_bytes: u64,
}

impl Default for AuditRetentionBudget {
    fn default() -> Self {
        Self {
            hot_bytes: 64 << 20,
            archive_bytes: 64 << 30,
        }
    }
}

impl AuditRetentionBudget {
    pub const MAINTENANCE_BYTES: u64 = 64 << 20;
    pub fn validate(&self) -> Result<()> {
        if self.hot_bytes < (2 * MAX_AUDIT_EVENT_BYTES) as u64
            || self.archive_bytes < MAX_AUDIT_SEGMENT_BYTES as u64
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "audit budget cannot hold a bounded maintenance segment",
            ));
        }
        Ok(())
    }
    pub fn starts_at(&self) -> u64 {
        self.hot_bytes - self.hot_bytes / 4
    }
    pub fn drains_to(&self) -> u64 {
        self.hot_bytes / 2
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditArchiveLink {
    pub object_id: Uuid,
    pub first_sequence: u64,
    pub next_sequence: u64,
    pub ciphertext_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditArchiveKeyDependency {
    pub provider: String,
    pub key_ref: String,
    pub version: u64,
    pub wrapped_key_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditArchiveReference {
    pub stream_id: Uuid,
    pub object: AuditArchiveLink,
    pub previous: Option<AuditArchiveLink>,
    pub record_count: u64,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub key: AuditArchiveKeyDependency,
}

impl AuditArchiveReference {
    pub fn validate(&self) -> Result<()> {
        let invalid = || {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid audit archive reference",
            )
        };
        if self.stream_id.is_nil()
            || self.object.object_id.is_nil()
            || self.record_count == 0
            || self.record_count > MAX_AUDIT_SEGMENT_RECORDS
            || self
                .object
                .next_sequence
                .checked_sub(self.object.first_sequence)
                != Some(self.record_count)
            || self.plaintext_bytes > MAX_AUDIT_SEGMENT_BYTES as u64
            || self.ciphertext_bytes > MAX_AUDIT_SEGMENT_BYTES as u64
            || self.ciphertext_bytes <= self.plaintext_bytes
            || self.key.provider.is_empty()
            || self.key.provider.len() > 1024
            || self.key.key_ref.is_empty()
            || self.key.key_ref.len() > 8192
            || self.key.version == 0
        {
            return Err(invalid());
        }
        validate_sha256(&self.object.ciphertext_sha256)?;
        validate_sha256(&self.key.wrapped_key_sha256)?;
        match &self.previous {
            None if self.object.first_sequence != 0 => return Err(invalid()),
            Some(previous) => {
                if previous.object_id.is_nil()
                    || previous.object_id == self.object.object_id
                    || previous.first_sequence >= previous.next_sequence
                    || previous.next_sequence != self.object.first_sequence
                {
                    return Err(invalid());
                }
                validate_sha256(&previous.ciphertext_sha256)?;
            }
            None => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionState {
    pub stream_id: Uuid,
    pub next_sequence: u64,
    pub pruned_before: u64,
    pub hot_bytes: u64,
    pub archive_bytes: u64,
    pub archive_segments: u64,
    pub draining: bool,
    pub archive_head: Option<AuditArchiveReference>,
}

impl AuditRetentionState {
    pub fn empty(stream_id: Uuid) -> Self {
        Self {
            stream_id,
            next_sequence: 0,
            pruned_before: 0,
            hot_bytes: 0,
            archive_bytes: 0,
            archive_segments: 0,
            draining: false,
            archive_head: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let invalid = || {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid audit retention position",
            )
        };
        if self.stream_id.is_nil() || self.pruned_before > self.next_sequence {
            return Err(invalid());
        }
        match &self.archive_head {
            Some(head) => {
                head.validate()?;
                if head.stream_id != self.stream_id
                    || head.object.next_sequence != self.pruned_before
                    || self.archive_segments == 0
                    || self.archive_bytes < head.ciphertext_bytes
                {
                    return Err(invalid());
                }
            }
            None if self.pruned_before != 0
                || self.archive_bytes != 0
                || self.archive_segments != 0 =>
            {
                return Err(invalid());
            }
            None => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditArchiveKeyDependency, AuditArchiveLink, AuditArchiveReference};
    use uuid::Uuid;

    #[test]
    fn archive_key_dependency_requires_a_real_wrapping_version() {
        let mut reference = AuditArchiveReference {
            stream_id: Uuid::from_u128(1),
            object: AuditArchiveLink {
                object_id: Uuid::from_u128(2),
                first_sequence: 0,
                next_sequence: 1,
                ciphertext_sha256: "0".repeat(64),
            },
            previous: None,
            record_count: 1,
            plaintext_bytes: 1,
            ciphertext_bytes: 2,
            key: AuditArchiveKeyDependency {
                provider: "file".into(),
                key_ref: "installed-key".into(),
                version: 1,
                wrapped_key_sha256: "0".repeat(64),
            },
        };
        reference.validate().unwrap();
        reference.key.version = 0;
        assert!(reference.validate().is_err());
    }

    #[test]
    fn limits_reject_removed_count_ceiling_and_missing_format_fields() {
        let current = serde_json::to_value(crate::Limits::default()).unwrap();
        serde_json::from_value::<crate::Limits>(current.clone()).unwrap();
        let mut obsolete = current.clone();
        obsolete["max_audit_records"] = 1.into();
        assert!(serde_json::from_value::<crate::Limits>(obsolete).is_err());
        let mut incomplete = current;
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("max_snapshot_bytes");
        assert!(serde_json::from_value::<crate::Limits>(incomplete).is_err());
    }
}
