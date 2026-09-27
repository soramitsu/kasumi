//! Protected service-audit observations. Cursors retain the original stream,
//! exclusive end and captured archive snapshot, and bind each continuation to
//! the exact record returned before it and to the exact last hot record of the
//! snapshot; transports must never restart them against another snapshot.
use crate::{
    AuditArchiveLink, AuditArchiveReference, AuditRetentionBudget, AuditRetentionState, Error,
    ErrorCode, Result, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;
pub const MAX_SECURITY_AUDIT_PAGE_BYTES: usize = 1 << 20;
pub const SECURITY_AUDIT_RECORD_FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityEventKind {
    NodeStarted,
    NodeStopping,
    AuthenticationSucceeded,
    AuthenticationDenied,
    TransportAuthenticated,
    TransportDenied,
    AccessDenied,
    TenantSealed,
    KeyAdministration,
    Administration,
    Membership,
    Backup,
    Restore,
    ControlCommitmentObserved {
        control_incarnation: String,
        command_id: String,
        commitment_sha256: String,
        control_policy_epoch: u64,
        committed_revision: u64,
    },
    RetirementObserved {
        source_incarnation: String,
        retirement_id: String,
        request_digest: String,
        source_revision: u64,
        custody_policy_epoch: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityOutcome {
    Succeeded,
    Denied,
    Failed,
    Started,
    Unknown,
}

/// Closed metadata fields cannot carry document bodies, query values or tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub kind: SecurityEventKind,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub principal: Option<String>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub tenant: Option<String>,
    pub request_id: String,
    pub outcome: SecurityOutcome,
}
impl SecurityEvent {
    pub fn validate(&self) -> Result<()> {
        for value in [
            self.principal.as_deref(),
            self.tenant.as_deref(),
            Some(&self.request_id),
        ]
        .into_iter()
        .flatten()
        {
            validate_name(value)?;
        }
        match &self.kind {
            SecurityEventKind::ControlCommitmentObserved {
                control_incarnation,
                command_id,
                commitment_sha256,
                committed_revision,
                ..
            } => {
                let identity = |value: &str| Uuid::parse_str(value).is_ok_and(|id| !id.is_nil());
                if !identity(control_incarnation)
                    || !identity(command_id)
                    || *committed_revision == 0
                {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid control observation identity",
                    ));
                }
                validate_sha256(commitment_sha256)?;
            }
            SecurityEventKind::RetirementObserved {
                source_incarnation,
                retirement_id,
                request_digest,
                source_revision,
                custody_policy_epoch,
            } => {
                validate_name(source_incarnation)?;
                validate_name(retirement_id)?;
                validate_sha256(request_digest)?;
                if *source_revision == 0 || *custody_policy_epoch == 0 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid retirement observation position",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportAuditMetadata {
    pub peer_address: SocketAddr,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub certificate_pin: Option<String>,
    pub observed_at_ms: u64,
}
impl TransportAuditMetadata {
    pub fn validate(&self) -> Result<()> {
        if self
            .certificate_pin
            .as_deref()
            .is_some_and(|pin| validate_sha256(pin).is_err())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid transport audit certificate pin",
            ));
        }
        Ok(())
    }
}

/// One durable service-audit row. Its exact current-writer encoding is both
/// the hot/archived record and the input to continuation anchors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditRecord {
    pub format: u32,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub event: SecurityEvent,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub transport: Option<TransportAuditMetadata>,
}
impl SecurityAuditRecord {
    pub fn validate(&self) -> Result<()> {
        if self.format != SECURITY_AUDIT_RECORD_FORMAT {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unsupported service audit record format",
            ));
        }
        self.event.validate()?;
        if let Some(transport) = &self.transport {
            transport.validate()?;
        }
        Ok(())
    }
    /// Digest of this record's exact current-writer bytes.
    pub fn sha256(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "service audit record encoding failed",
            )
        })?;
        Ok(audit_record_sha256(&bytes))
    }
}

/// Continuation anchors digest the exact stored record bytes, never a decoded
/// equivalent spelling.
pub fn audit_record_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

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
    /// Exact record digest at position.next_sequence - 1 while that record is
    /// hot, observed together with the position.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub hot_tail_sha256: Option<String>,
}
impl SecurityAuditStatus {
    pub fn validate(&self) -> Result<()> {
        self.position.validate()?;
        self.budget.validate()?;
        if self.archive_segments != self.position.archive_segments
            || self.archived_bytes != self.position.archive_bytes
            || self.draining != self.position.draining
            || self.position.hot_bytes > self.budget.hot_bytes
            || self.position.archive_bytes > self.budget.archive_bytes
            || !hot_tail_valid(&self.position, self.hot_tail_sha256.as_deref())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "service audit status differs from its position",
            ));
        }
        Ok(())
    }

    /// The first cursor of an export fixed at this one observation: its
    /// exclusive end, archive snapshot and hot tail are never re-read.
    pub fn snapshot_cursor(&self) -> SecurityAuditCursor {
        SecurityAuditCursor {
            stream_id: self.position.stream_id,
            next_sequence: 0,
            through_sequence: self.position.next_sequence,
            snapshot_segments: self.position.archive_segments,
            snapshot_head: self
                .position
                .archive_head
                .as_ref()
                .map(|archive| archive.object.clone()),
            snapshot_tail_sha256: self.hot_tail_sha256.clone(),
            previous_record_sha256: None,
        }
    }
}

/// A position has a hot tail exactly when it retains records after its
/// archived prefix.
pub(crate) fn hot_tail_valid(position: &AuditRetentionState, hot_tail: Option<&str>) -> bool {
    (position.next_sequence > position.pruned_before) == hot_tail.is_some()
        && hot_tail.is_none_or(|digest| validate_sha256(digest).is_ok())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditCursor {
    pub stream_id: Uuid,
    pub next_sequence: u64,
    pub through_sequence: u64,
    /// Archive roots committed when through_sequence was captured.
    pub snapshot_segments: u64,
    /// Exact root at snapshot_segments - 1. A rolled-back or substituted
    /// archive chain cannot continue this cursor.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    /// Exact record digest at through_sequence - 1 when the snapshot ended in
    /// hot records. Every page checks it, so a copy that diverged after the
    /// anchor cannot serve any part of this range.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_tail_sha256: Option<String>,
    /// Exact record digest at next_sequence - 1, returned by the preceding page.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous_record_sha256: Option<String>,
}
impl SecurityAuditCursor {
    pub fn validate(&self) -> Result<()> {
        if self.stream_id.is_nil()
            || self.next_sequence > self.through_sequence
            || !record_anchors_valid(
                self.next_sequence,
                self.through_sequence,
                self.snapshot_segments,
                self.snapshot_head.as_ref(),
                self.snapshot_tail_sha256.as_deref(),
                self.previous_record_sha256.as_deref(),
            )
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid service audit cursor",
            ));
        }
        Ok(())
    }
}

/// Shared by service and tenant record cursors and pages: the snapshot head is
/// present exactly when archive roots were captured and lies within the range,
/// the tail exactly when hot records follow that head, and only a continuation
/// after the first record carries a previous digest. A completed range ends at
/// its captured tail.
pub(crate) fn record_anchors_valid(
    next_sequence: u64,
    through_sequence: u64,
    snapshot_segments: u64,
    snapshot_head: Option<&AuditArchiveLink>,
    snapshot_tail_sha256: Option<&str>,
    previous_record_sha256: Option<&str>,
) -> bool {
    let archived = snapshot_head.map_or(0, |head| head.next_sequence);
    (snapshot_segments == 0) == snapshot_head.is_none()
        && snapshot_head.is_none_or(|head| {
            head.validate().is_ok()
                && head.next_sequence <= through_sequence
                && head.next_sequence >= snapshot_segments
        })
        && (through_sequence > archived) == snapshot_tail_sha256.is_some()
        && snapshot_tail_sha256.is_none_or(|digest| validate_sha256(digest).is_ok())
        && (next_sequence == 0) == previous_record_sha256.is_none()
        && previous_record_sha256.is_none_or(|digest| validate_sha256(digest).is_ok())
        && (next_sequence < through_sequence
            || snapshot_tail_sha256.is_none()
            || previous_record_sha256 == snapshot_tail_sha256)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditPage {
    pub stream_id: Uuid,
    pub through_sequence: u64,
    pub next_sequence: u64,
    pub snapshot_segments: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_tail_sha256: Option<String>,
    /// Exact record digest at next_sequence - 1: this page's last record, or
    /// the request cursor's anchor when the page returned no record.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous_record_sha256: Option<String>,
    pub records: Vec<SecurityAuditRecord>,
}
impl SecurityAuditPage {
    /// This page's own anchors as a continuation, even when it is complete.
    pub fn resumed(&self) -> SecurityAuditCursor {
        SecurityAuditCursor {
            stream_id: self.stream_id,
            next_sequence: self.next_sequence,
            through_sequence: self.through_sequence,
            snapshot_segments: self.snapshot_segments,
            snapshot_head: self.snapshot_head.clone(),
            snapshot_tail_sha256: self.snapshot_tail_sha256.clone(),
            previous_record_sha256: self.previous_record_sha256.clone(),
        }
    }
    pub fn cursor(&self) -> Option<SecurityAuditCursor> {
        (self.next_sequence < self.through_sequence).then(|| self.resumed())
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
    /// Exact immutable archive head at through_index, even as new archives append.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    /// Last object from the preceding page; binds the next page to its chain.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous: Option<AuditArchiveLink>,
}
impl SecurityAuditArchiveCursor {
    pub fn validate(&self) -> Result<()> {
        if self.stream_id.is_nil()
            || !archive_anchors_valid(
                self.next_index,
                self.through_index,
                self.snapshot_head.as_ref(),
                self.previous.as_ref(),
            )
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid service audit archive cursor",
            ));
        }
        Ok(())
    }
}

/// Shared by service and tenant archive cursors.
pub(crate) fn archive_anchors_valid(
    next_index: u64,
    through_index: u64,
    snapshot_head: Option<&AuditArchiveLink>,
    previous: Option<&AuditArchiveLink>,
) -> bool {
    next_index <= through_index
        && (through_index == 0) == snapshot_head.is_none()
        && (next_index == 0) == previous.is_none()
        && (next_index != through_index || previous == snapshot_head)
        && snapshot_head.is_none_or(|head| head.validate().is_ok())
        && previous.is_none_or(|link| link.validate().is_ok())
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
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    pub archives: Vec<AuditArchiveReference>,
}
impl SecurityAuditArchivePage {
    pub fn cursor(&self) -> Option<SecurityAuditArchiveCursor> {
        (self.next_index < self.through_index).then_some(SecurityAuditArchiveCursor {
            stream_id: self.stream_id,
            next_index: self.next_index,
            through_index: self.through_index,
            snapshot_head: self.snapshot_head.clone(),
            previous: self.archives.last().map(|archive| archive.object.clone()),
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
pub struct SecurityAuditCapacityRequest {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditArchiveVerification {
    pub stream_id: Uuid,
    pub index: u64,
    pub archive: AuditArchiveReference,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditCapacity, exact_json::decode_exact};
    use serde_json::json;

    fn link(first_sequence: u64, next_sequence: u64) -> AuditArchiveLink {
        AuditArchiveLink {
            object_id: Uuid::from_u128(u128::from(next_sequence) + 5),
            first_sequence,
            next_sequence,
            ciphertext_sha256: "e".repeat(64),
        }
    }

    fn record(sequence: u64) -> SecurityAuditRecord {
        SecurityAuditRecord {
            format: SECURITY_AUDIT_RECORD_FORMAT,
            sequence,
            timestamp_ms: 17,
            event: SecurityEvent {
                kind: SecurityEventKind::ControlCommitmentObserved {
                    control_incarnation: Uuid::from_u128(1).to_string(),
                    command_id: Uuid::from_u128(2).to_string(),
                    commitment_sha256: "f".repeat(64),
                    control_policy_epoch: 3,
                    committed_revision: 4,
                },
                principal: None,
                tenant: Some("tenant-a".into()),
                request_id: "request-1".into(),
                outcome: SecurityOutcome::Succeeded,
            },
            transport: Some(TransportAuditMetadata {
                peer_address: "127.0.0.1:7443".parse().unwrap(),
                certificate_pin: None,
                observed_at_ms: 16,
            }),
        }
    }

    #[test]
    fn typed_records_reject_unknown_implicit_and_invalid_metadata() {
        let valid = record(4);
        valid.validate().unwrap();
        let bytes = serde_json::to_vec(&valid).unwrap();
        assert_eq!(
            decode_exact::<SecurityAuditRecord>(&bytes, 64 << 10, "record").unwrap(),
            valid
        );
        assert_eq!(valid.sha256().unwrap(), audit_record_sha256(&bytes));
        let encoded = serde_json::to_value(&valid).unwrap();
        for pointer in [
            "",
            "/event",
            "/event/kind/control_commitment_observed",
            "/transport",
        ] {
            let mut unknown = encoded.clone();
            unknown.pointer_mut(pointer).unwrap()["legacy"] = json!(true);
            assert!(
                serde_json::from_value::<SecurityAuditRecord>(unknown).is_err(),
                "{pointer}"
            );
        }
        for (pointer, field) in [
            ("", "transport"),
            ("/event", "principal"),
            ("/event", "tenant"),
            ("/transport", "certificate_pin"),
        ] {
            let mut missing = encoded.clone();
            missing
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<SecurityAuditRecord>(missing).is_err(),
                "{pointer}/{field}"
            );
        }
        // An untyped document-bearing value is never a service audit record.
        assert!(
            serde_json::from_value::<SecurityAuditRecord>(json!({"sequence":4,"body":{}})).is_err()
        );
        let mut invalid = valid.clone();
        invalid.format = 2;
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.event.request_id.clear();
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.transport.as_mut().unwrap().certificate_pin = Some("A".repeat(64));
        assert!(invalid.validate().is_err());
        let mut invalid = valid;
        invalid.event.kind = SecurityEventKind::RetirementObserved {
            source_incarnation: "source".into(),
            retirement_id: "retirement".into(),
            request_digest: "0".repeat(64),
            source_revision: 0,
            custody_policy_epoch: 1,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn record_cursor_anchors_bind_snapshot_and_previous_record() {
        let valid = SecurityAuditCursor {
            stream_id: Uuid::from_u128(3),
            next_sequence: 9,
            through_sequence: 30,
            snapshot_segments: 2,
            snapshot_head: Some(link(6, 12)),
            snapshot_tail_sha256: Some(record(29).sha256().unwrap()),
            previous_record_sha256: Some(record(8).sha256().unwrap()),
        };
        valid.validate().unwrap();
        let encoded = serde_json::to_value(&valid).unwrap();
        for field in [
            "snapshot_segments",
            "snapshot_head",
            "snapshot_tail_sha256",
            "previous_record_sha256",
        ] {
            let mut missing = encoded.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SecurityAuditCursor>(missing).is_err(),
                "{field}"
            );
        }
        let mut unknown = encoded;
        unknown["snapshot_head"]["legacy"] = json!(true);
        assert!(serde_json::from_value::<SecurityAuditCursor>(unknown).is_err());
        let invalid = [
            SecurityAuditCursor {
                stream_id: Uuid::nil(),
                ..valid.clone()
            },
            SecurityAuditCursor {
                next_sequence: 31,
                ..valid.clone()
            },
            SecurityAuditCursor {
                snapshot_head: None,
                ..valid.clone()
            },
            SecurityAuditCursor {
                snapshot_segments: 0,
                ..valid.clone()
            },
            SecurityAuditCursor {
                snapshot_head: Some(link(6, 31)),
                ..valid.clone()
            },
            SecurityAuditCursor {
                snapshot_head: Some(AuditArchiveLink {
                    object_id: Uuid::nil(),
                    ..link(6, 12)
                }),
                ..valid.clone()
            },
            SecurityAuditCursor {
                previous_record_sha256: None,
                ..valid.clone()
            },
            SecurityAuditCursor {
                next_sequence: 0,
                ..valid.clone()
            },
            SecurityAuditCursor {
                previous_record_sha256: Some("digest".into()),
                ..valid.clone()
            },
            // Hot records after the captured head require their exact tail.
            SecurityAuditCursor {
                snapshot_tail_sha256: None,
                ..valid.clone()
            },
            SecurityAuditCursor {
                snapshot_tail_sha256: Some("F".repeat(64)),
                ..valid.clone()
            },
            // A range that ends at its archived head has no hot tail.
            SecurityAuditCursor {
                through_sequence: 12,
                ..valid.clone()
            },
            // A completed range must end at its captured tail.
            SecurityAuditCursor {
                next_sequence: 30,
                ..valid.clone()
            },
        ];
        for (case, cursor) in invalid.into_iter().enumerate() {
            assert!(cursor.validate().is_err(), "case {case}");
        }
        SecurityAuditCursor {
            next_sequence: 30,
            previous_record_sha256: valid.snapshot_tail_sha256.clone(),
            ..valid.clone()
        }
        .validate()
        .unwrap();
        SecurityAuditCursor {
            through_sequence: 12,
            snapshot_tail_sha256: None,
            ..valid.clone()
        }
        .validate()
        .unwrap();
        for limit in [0, 1025] {
            assert!(
                SecurityAuditExportRequest {
                    cursor: Some(valid.clone()),
                    limit
                }
                .validate()
                .is_err()
            );
        }
        let page = SecurityAuditPage {
            stream_id: valid.stream_id,
            through_sequence: 30,
            next_sequence: 10,
            snapshot_segments: 2,
            snapshot_head: Some(link(6, 12)),
            snapshot_tail_sha256: valid.snapshot_tail_sha256.clone(),
            previous_record_sha256: Some(record(9).sha256().unwrap()),
            records: vec![record(9)],
        };
        let bytes = serde_json::to_vec(&page).unwrap();
        assert_eq!(
            decode_exact::<SecurityAuditPage>(&bytes, MAX_SECURITY_AUDIT_PAGE_BYTES, "page")
                .unwrap(),
            page
        );
        let continuation = page.cursor().unwrap();
        continuation.validate().unwrap();
        assert_eq!(continuation.snapshot_head, page.snapshot_head);
        assert_eq!(
            continuation.snapshot_tail_sha256,
            valid.snapshot_tail_sha256
        );
        assert_eq!(
            continuation.previous_record_sha256,
            Some(record(9).sha256().unwrap())
        );
        serde_json::from_value::<SecurityAuditCapacityRequest>(json!({})).unwrap();
        assert!(
            serde_json::from_value::<SecurityAuditCapacityRequest>(json!({"verbose":true}))
                .is_err()
        );
    }

    #[test]
    fn status_fixes_one_snapshot_cursor_with_its_hot_tail() {
        let budget = AuditRetentionBudget {
            hot_bytes: 128 << 10,
            archive_bytes: 128 << 20,
        };
        let mut position = AuditRetentionState::empty(Uuid::from_u128(3));
        let status =
            |position: &AuditRetentionState, hot_tail_sha256: Option<String>| SecurityAuditStatus {
                position: position.clone(),
                budget: budget.clone(),
                archived_bytes: position.archive_bytes,
                archive_segments: position.archive_segments,
                draining: position.draining,
                persistence_failed: false,
                maintenance_failures: 0,
                last_failure: None,
                hot_tail_sha256,
            };
        let empty = status(&position, None);
        empty.validate().unwrap();
        let cursor = empty.snapshot_cursor();
        cursor.validate().unwrap();
        assert_eq!(
            (cursor.through_sequence, cursor.snapshot_tail_sha256),
            (0, None)
        );
        assert!(
            status(&position, Some(record(0).sha256().unwrap()))
                .validate()
                .is_err()
        );

        position.next_sequence = 5;
        position.hot_bytes = 500;
        let hot = status(&position, Some(record(4).sha256().unwrap()));
        hot.validate().unwrap();
        let cursor = hot.snapshot_cursor();
        cursor.validate().unwrap();
        assert_eq!(cursor.through_sequence, 5);
        assert_eq!(cursor.snapshot_tail_sha256, hot.hot_tail_sha256);
        assert!(status(&position, None).validate().is_err());
        let mut missing = serde_json::to_value(&hot).unwrap();
        missing.as_object_mut().unwrap().remove("hot_tail_sha256");
        assert!(serde_json::from_value::<SecurityAuditStatus>(missing).is_err());
        for changed in [
            SecurityAuditStatus {
                archive_segments: 1,
                ..hot.clone()
            },
            SecurityAuditStatus {
                draining: true,
                ..hot.clone()
            },
            SecurityAuditStatus {
                hot_tail_sha256: Some("digest".into()),
                ..hot.clone()
            },
        ] {
            assert!(changed.validate().is_err());
        }

        // Once every record is archived, the head alone binds the range.
        let archived = AuditArchiveReference {
            stream_id: position.stream_id,
            object: link(0, 5),
            previous: None,
            record_count: 5,
            plaintext_bytes: 10,
            ciphertext_bytes: 20,
            key: crate::AuditArchiveKeyDependency {
                provider: "file".into(),
                key_ref: "installed-key".into(),
                version: 1,
                wrapped_key_sha256: "b".repeat(64),
            },
        };
        position.pruned_before = 5;
        position.hot_bytes = 0;
        position.archive_bytes = 20;
        position.archive_segments = 1;
        position.archive_head = Some(archived.clone());
        let pruned = status(&position, None);
        pruned.validate().unwrap();
        let cursor = pruned.snapshot_cursor();
        cursor.validate().unwrap();
        assert_eq!(cursor.snapshot_head, Some(archived.object));
        assert_eq!(cursor.snapshot_tail_sha256, None);
        assert!(
            status(&position, Some(record(4).sha256().unwrap()))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn capacity_is_derived_from_the_budget_and_rejects_changed_thresholds() {
        let budget = AuditRetentionBudget {
            hot_bytes: 128 << 10,
            archive_bytes: 128 << 20,
        };
        let mut position = AuditRetentionState::empty(Uuid::from_u128(3));
        position.hot_bytes = budget.starts_at() - 1;
        let below = AuditCapacity::new(
            &position,
            &budget,
            AuditRetentionBudget::MAINTENANCE_BYTES,
            None,
        );
        below.validate().unwrap();
        assert_eq!(below.archive_backlog_bytes, 0);
        position.hot_bytes = budget.starts_at();
        let crossing = AuditCapacity::new(
            &position,
            &budget,
            AuditRetentionBudget::MAINTENANCE_BYTES,
            Some(link(0, 4)),
        );
        crossing.validate().unwrap();
        assert_eq!(
            crossing.archive_backlog_bytes,
            budget.starts_at() - budget.drains_to()
        );
        // An earlier crossing keeps draining below the start threshold.
        position.hot_bytes = budget.starts_at() - 1;
        position.draining = true;
        assert_eq!(
            budget.archive_backlog_bytes(position.hot_bytes, position.draining),
            position.hot_bytes - budget.drains_to()
        );
        assert_eq!(budget.archive_backlog_bytes(budget.drains_to(), true), 0);
        let bytes = serde_json::to_vec(&crossing).unwrap();
        assert_eq!(
            decode_exact::<AuditCapacity>(&bytes, 64 << 10, "capacity").unwrap(),
            crossing
        );
        let mut missing = serde_json::to_value(&crossing).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("pending_publication");
        assert!(serde_json::from_value::<AuditCapacity>(missing).is_err());
        let changed = [
            AuditCapacity {
                starts_at_bytes: crossing.starts_at_bytes - 1,
                ..crossing.clone()
            },
            AuditCapacity {
                drains_to_bytes: crossing.drains_to_bytes + 1,
                ..crossing.clone()
            },
            AuditCapacity {
                archive_backlog_bytes: 0,
                ..crossing.clone()
            },
            AuditCapacity {
                hot_bytes: crossing.hot_budget_bytes + 1,
                ..crossing.clone()
            },
            AuditCapacity {
                archive_segments: 1,
                ..crossing.clone()
            },
            AuditCapacity {
                max_segment_bytes: 1,
                ..crossing.clone()
            },
            AuditCapacity {
                maintenance_reserved_bytes: 0,
                ..crossing.clone()
            },
            AuditCapacity {
                pending_publication: Some(link(4, 4)),
                ..crossing.clone()
            },
            AuditCapacity {
                hot_budget_bytes: 1,
                ..crossing.clone()
            },
        ];
        for (case, capacity) in changed.into_iter().enumerate() {
            assert!(capacity.validate().is_err(), "case {case}");
        }
    }
}
