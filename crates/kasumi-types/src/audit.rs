//! Permanent audit positions and bounded immutable archive dependencies.
use crate::{Error, ErrorCode, Result, validate_sha256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_AUDIT_SEGMENT_BYTES: usize = 8 << 20;
pub const MAX_AUDIT_EVENT_BYTES: usize = 64 << 10;
/// Bounds a pruning batch even when individual events are very small.
pub const MAX_AUDIT_SEGMENT_RECORDS: u64 = 8192;

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
    pub archive_head: Option<AuditArchiveReference>,
}

impl AuditRetentionState {
    pub fn empty(stream_id: Uuid) -> Self {
        Self {
            stream_id,
            next_sequence: 0,
            pruned_before: 0,
            hot_bytes: 0,
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
                {
                    return Err(invalid());
                }
            }
            None if self.pruned_before != 0 => return Err(invalid()),
            None => {}
        }
        Ok(())
    }
}
