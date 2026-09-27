//! Protected tenant (application or Control) audit observations. Every cursor
//! is bound to the tenant incarnation, stream, exclusive end, captured archive
//! snapshot and hot tail; transports must never restart one against another
//! state.
use crate::{
    AuditArchiveLink, AuditArchiveReference, AuditEvent, AuditRetentionBudget, AuditRetentionState,
    Error, ErrorCode, MAX_SECURITY_AUDIT_PAGE_BYTES, Result, audit_record_sha256,
    security_audit::{archive_anchors_valid, hot_tail_valid, record_anchors_valid},
    validate_name,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_TENANT_AUDIT_PAGE_BYTES: usize = MAX_SECURITY_AUDIT_PAGE_BYTES;
pub const MAX_TENANT_AUDIT_VERIFY_LIMIT: u16 = 8;

fn identity_valid(tenant: &str, incarnation: &str) -> bool {
    validate_name(tenant).is_ok()
        && Uuid::parse_str(incarnation)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == incarnation)
}

fn page_limit(limit: u16, max: u16, message: &'static str) -> Result<()> {
    if !(1..=max).contains(&limit) {
        return Err(Error::new(ErrorCode::InvalidArgument, message));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditStatusRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditCapacityRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditStatus {
    pub tenant: String,
    pub incarnation: String,
    pub revision: u64,
    pub position: AuditRetentionState,
    pub budget: AuditRetentionBudget,
    /// Exact stored event digest at position.next_sequence - 1 while that
    /// event is hot, observed together with the position.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub hot_tail_sha256: Option<String>,
}
impl TenantAuditStatus {
    pub fn validate(&self) -> Result<()> {
        self.position.validate()?;
        self.budget.validate()?;
        if !identity_valid(&self.tenant, &self.incarnation)
            || self.position.hot_bytes > self.budget.hot_bytes
            || self.position.archive_bytes > self.budget.archive_bytes
            || !hot_tail_valid(&self.position, self.hot_tail_sha256.as_deref())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid tenant audit status",
            ));
        }
        Ok(())
    }

    /// The first cursor of an export fixed at this one observation.
    pub fn snapshot_cursor(&self) -> TenantAuditCursor {
        TenantAuditCursor {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.clone(),
            stream_id: self.position.stream_id,
            next_sequence: 0,
            through_sequence: self.position.next_sequence,
            snapshot_head: self
                .position
                .archive_head
                .as_ref()
                .map(|archive| archive.object.clone()),
            snapshot_segments: self.position.archive_segments,
            snapshot_tail_sha256: self.hot_tail_sha256.clone(),
            previous_record_sha256: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditCursor {
    pub tenant: String,
    pub incarnation: String,
    pub stream_id: Uuid,
    pub next_sequence: u64,
    pub through_sequence: u64,
    /// Exact root at snapshot_segments - 1 when through_sequence was captured.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    pub snapshot_segments: u64,
    /// Exact stored event digest at through_sequence - 1 when the snapshot
    /// ended in hot events. Binds every continuation to that suffix.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_tail_sha256: Option<String>,
    /// Exact stored event digest at next_sequence - 1, returned by the
    /// preceding page. Binds the continuation to that prefix.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous_record_sha256: Option<String>,
}
impl TenantAuditCursor {
    pub fn validate(&self) -> Result<()> {
        if !identity_valid(&self.tenant, &self.incarnation)
            || self.stream_id.is_nil()
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
                "invalid tenant audit cursor",
            ));
        }
        Ok(())
    }
}

/// Tenant hot and archived records are the exact encoded AuditEvent; the
/// sequence is its position in the tenant stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditRecord {
    pub sequence: u64,
    pub event: AuditEvent,
}
impl TenantAuditRecord {
    /// Digest of the exact current-writer event bytes stored for this sequence.
    pub fn event_sha256(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.event).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "tenant audit event encoding failed",
            )
        })?;
        Ok(audit_record_sha256(&bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditExportRequest {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<TenantAuditCursor>,
    pub limit: u16,
}
impl TenantAuditExportRequest {
    pub fn validate(&self) -> Result<()> {
        page_limit(self.limit, 1024, "tenant audit page limit must be 1..1024")?;
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditPage {
    pub tenant: String,
    pub incarnation: String,
    pub stream_id: Uuid,
    pub through_sequence: u64,
    pub next_sequence: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    pub snapshot_segments: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_tail_sha256: Option<String>,
    /// Exact event digest at next_sequence - 1: this page's last record, or
    /// the request cursor's anchor when the page returned no record.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous_record_sha256: Option<String>,
    pub records: Vec<TenantAuditRecord>,
}
impl TenantAuditPage {
    /// This page's own anchors as a continuation, even when it is complete.
    pub fn resumed(&self) -> TenantAuditCursor {
        TenantAuditCursor {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.clone(),
            stream_id: self.stream_id,
            next_sequence: self.next_sequence,
            through_sequence: self.through_sequence,
            snapshot_head: self.snapshot_head.clone(),
            snapshot_segments: self.snapshot_segments,
            snapshot_tail_sha256: self.snapshot_tail_sha256.clone(),
            previous_record_sha256: self.previous_record_sha256.clone(),
        }
    }
    pub fn cursor(&self) -> Option<TenantAuditCursor> {
        (self.next_sequence < self.through_sequence).then(|| self.resumed())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditArchiveCursor {
    pub tenant: String,
    pub incarnation: String,
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
impl TenantAuditArchiveCursor {
    pub fn validate(&self) -> Result<()> {
        if !identity_valid(&self.tenant, &self.incarnation)
            || self.stream_id.is_nil()
            || !archive_anchors_valid(
                self.next_index,
                self.through_index,
                self.snapshot_head.as_ref(),
                self.previous.as_ref(),
            )
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid tenant audit archive cursor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditArchivePageRequest {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<TenantAuditArchiveCursor>,
    pub limit: u16,
}
impl TenantAuditArchivePageRequest {
    pub fn validate(&self) -> Result<()> {
        page_limit(
            self.limit,
            256,
            "tenant audit archive page limit must be 1..256",
        )?;
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditArchivePage {
    pub tenant: String,
    pub incarnation: String,
    pub stream_id: Uuid,
    pub next_index: u64,
    pub through_index: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    pub archives: Vec<AuditArchiveReference>,
}
impl TenantAuditArchivePage {
    pub fn cursor(&self) -> Option<TenantAuditArchiveCursor> {
        (self.next_index < self.through_index).then(|| TenantAuditArchiveCursor {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.clone(),
            stream_id: self.stream_id,
            next_index: self.next_index,
            through_index: self.through_index,
            snapshot_head: self.snapshot_head.clone(),
            previous: self.archives.last().map(|archive| archive.object.clone()),
        })
    }
}

/// Independent outcome for one copy of an immutable archive object. Only
/// `Verified` proves the exact range, key binding and digest were read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditObjectCheck {
    Verified,
    Missing,
    Corrupt,
    Unavailable,
}

/// Paged verification walks the same anchored archive chain as archive pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditVerifyRequest {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<TenantAuditArchiveCursor>,
    pub limit: u16,
}
impl TenantAuditVerifyRequest {
    pub fn validate(&self) -> Result<()> {
        page_limit(
            self.limit,
            MAX_TENANT_AUDIT_VERIFY_LIMIT,
            "tenant audit verification limit must be 1..8",
        )?;
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditObjectVerification {
    pub index: u64,
    pub reference: AuditArchiveReference,
    /// The replica's local cache copy.
    pub cache: AuditObjectCheck,
    /// The installed external or local-replica archive destination copy.
    pub destination: AuditObjectCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAuditVerificationPage {
    pub tenant: String,
    pub incarnation: String,
    pub stream_id: Uuid,
    pub next_index: u64,
    pub through_index: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub snapshot_head: Option<AuditArchiveLink>,
    pub results: Vec<TenantAuditObjectVerification>,
}
impl TenantAuditVerificationPage {
    pub fn cursor(&self) -> Option<TenantAuditArchiveCursor> {
        (self.next_index < self.through_index).then(|| TenantAuditArchiveCursor {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.clone(),
            stream_id: self.stream_id,
            next_index: self.next_index,
            through_index: self.through_index,
            snapshot_head: self.snapshot_head.clone(),
            previous: self
                .results
                .last()
                .map(|result| result.reference.object.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditArchiveKeyDependency, exact_json::decode_exact};
    use serde_json::{Value, json};

    fn link(first_sequence: u64, next_sequence: u64) -> AuditArchiveLink {
        AuditArchiveLink {
            object_id: Uuid::from_u128(u128::from(next_sequence) + 7),
            first_sequence,
            next_sequence,
            ciphertext_sha256: "c".repeat(64),
        }
    }

    fn cursor() -> TenantAuditCursor {
        TenantAuditCursor {
            tenant: "tenant-a".into(),
            incarnation: incarnation(),
            stream_id: Uuid::from_u128(3),
            next_sequence: 12,
            through_sequence: 20,
            snapshot_head: Some(link(4, 10)),
            snapshot_segments: 2,
            snapshot_tail_sha256: Some("e".repeat(64)),
            previous_record_sha256: Some("d".repeat(64)),
        }
    }

    fn archive_cursor() -> TenantAuditArchiveCursor {
        TenantAuditArchiveCursor {
            tenant: "tenant-a".into(),
            incarnation: incarnation(),
            stream_id: Uuid::from_u128(3),
            next_index: 1,
            through_index: 2,
            snapshot_head: Some(link(4, 10)),
            previous: Some(link(0, 4)),
        }
    }

    fn event() -> AuditEvent {
        AuditEvent {
            event_id: "event-1".into(),
            principal: "admin".into(),
            action: "write".into(),
            request_id: "request-1".into(),
            timestamp_ms: 1,
            data_revision: None,
            outcome: "ok".into(),
            collection: Some("docs".into()),
        }
    }

    fn incarnation() -> String {
        Uuid::from_u128(0x9abc).to_string()
    }

    fn rejects<T: serde::de::DeserializeOwned>(value: &Value, pointer: &str, field: &str) {
        let mut unknown = value.clone();
        unknown.pointer_mut(pointer).unwrap()[field] = json!(true);
        assert!(
            serde_json::from_value::<T>(unknown).is_err(),
            "{pointer}/{field}"
        );
    }

    fn omits<T: serde::de::DeserializeOwned>(value: &Value, field: &str) {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<T>(missing).is_err(), "{field}");
    }

    #[test]
    fn cursors_reject_unknown_implicit_nil_reversed_and_unanchored_positions() {
        let valid = cursor();
        valid.validate().unwrap();
        let encoded = serde_json::to_value(&valid).unwrap();
        rejects::<TenantAuditCursor>(&encoded, "", "legacy_offset");
        rejects::<TenantAuditCursor>(&encoded, "/snapshot_head", "legacy");
        for field in [
            "snapshot_head",
            "snapshot_tail_sha256",
            "previous_record_sha256",
            "snapshot_segments",
        ] {
            omits::<TenantAuditCursor>(&encoded, field);
        }
        let invalid = [
            TenantAuditCursor {
                stream_id: Uuid::nil(),
                ..valid.clone()
            },
            TenantAuditCursor {
                next_sequence: 21,
                ..valid.clone()
            },
            TenantAuditCursor {
                incarnation: Uuid::nil().to_string(),
                ..valid.clone()
            },
            TenantAuditCursor {
                incarnation: valid.incarnation.to_uppercase(),
                ..valid.clone()
            },
            TenantAuditCursor {
                tenant: String::new(),
                ..valid.clone()
            },
            // A captured archive root requires its exact head and vice versa.
            TenantAuditCursor {
                snapshot_head: None,
                ..valid.clone()
            },
            TenantAuditCursor {
                snapshot_segments: 0,
                ..valid.clone()
            },
            // The captured head cannot lie beyond the captured exclusive end.
            TenantAuditCursor {
                snapshot_head: Some(link(4, 21)),
                ..valid.clone()
            },
            TenantAuditCursor {
                snapshot_segments: 11,
                ..valid.clone()
            },
            // Only a continuation after the first record carries a digest.
            TenantAuditCursor {
                previous_record_sha256: None,
                ..valid.clone()
            },
            TenantAuditCursor {
                next_sequence: 0,
                ..valid.clone()
            },
            TenantAuditCursor {
                previous_record_sha256: Some("D".repeat(64)),
                ..valid.clone()
            },
            // Hot events after the captured head require their exact tail,
            // and a range ending at that head has none.
            TenantAuditCursor {
                snapshot_tail_sha256: None,
                ..valid.clone()
            },
            TenantAuditCursor {
                through_sequence: 12,
                snapshot_head: Some(link(4, 12)),
                ..valid.clone()
            },
            // A completed range must end at its captured tail.
            TenantAuditCursor {
                next_sequence: 20,
                ..valid.clone()
            },
        ];
        for (case, cursor) in invalid.into_iter().enumerate() {
            assert!(cursor.validate().is_err(), "case {case}");
        }
        let initial = TenantAuditCursor {
            next_sequence: 0,
            previous_record_sha256: None,
            snapshot_head: None,
            snapshot_segments: 0,
            ..valid.clone()
        };
        initial.validate().unwrap();
        TenantAuditCursor {
            next_sequence: 20,
            previous_record_sha256: valid.snapshot_tail_sha256.clone(),
            ..valid.clone()
        }
        .validate()
        .unwrap();

        let archive = archive_cursor();
        archive.validate().unwrap();
        let encoded = serde_json::to_value(&archive).unwrap();
        rejects::<TenantAuditArchiveCursor>(&encoded, "", "legacy_index");
        for field in ["snapshot_head", "previous", "tenant", "incarnation"] {
            omits::<TenantAuditArchiveCursor>(&encoded, field);
        }
        let invalid = [
            TenantAuditArchiveCursor {
                next_index: 3,
                ..archive.clone()
            },
            TenantAuditArchiveCursor {
                previous: None,
                ..archive.clone()
            },
            TenantAuditArchiveCursor {
                snapshot_head: None,
                ..archive.clone()
            },
            // A completed cursor must end exactly at its captured head.
            TenantAuditArchiveCursor {
                next_index: 2,
                ..archive.clone()
            },
            TenantAuditArchiveCursor {
                stream_id: Uuid::nil(),
                ..archive.clone()
            },
        ];
        for (case, cursor) in invalid.into_iter().enumerate() {
            assert!(cursor.validate().is_err(), "archive case {case}");
        }
    }

    #[test]
    fn requests_bound_limits_and_reject_implicit_or_unknown_fields() {
        for limit in [0, 1025] {
            assert!(
                TenantAuditExportRequest {
                    cursor: None,
                    limit
                }
                .validate()
                .is_err()
            );
        }
        for limit in [0, 257] {
            assert!(
                TenantAuditArchivePageRequest {
                    cursor: None,
                    limit
                }
                .validate()
                .is_err()
            );
        }
        for limit in [0, MAX_TENANT_AUDIT_VERIFY_LIMIT + 1] {
            assert!(
                TenantAuditVerifyRequest {
                    cursor: None,
                    limit
                }
                .validate()
                .is_err()
            );
        }
        for limit in 1..=MAX_TENANT_AUDIT_VERIFY_LIMIT {
            TenantAuditVerifyRequest {
                cursor: Some(archive_cursor()),
                limit,
            }
            .validate()
            .unwrap();
        }
        TenantAuditExportRequest {
            cursor: Some(cursor()),
            limit: 1024,
        }
        .validate()
        .unwrap();
        let mut invalid = cursor();
        invalid.next_sequence = 0;
        assert!(
            TenantAuditExportRequest {
                cursor: Some(invalid),
                limit: 1
            }
            .validate()
            .is_err()
        );
        for (value, name) in [
            (json!({"limit":1}), "export"),
            (json!({"cursor":null,"limit":1,"offset":0}), "export"),
        ] {
            assert!(
                serde_json::from_value::<TenantAuditExportRequest>(value).is_err(),
                "{name}"
            );
        }
        assert!(serde_json::from_value::<TenantAuditVerifyRequest>(json!({"limit":1})).is_err());
        assert!(
            serde_json::from_value::<TenantAuditArchivePageRequest>(json!({"limit":1})).is_err()
        );
        assert!(serde_json::from_value::<TenantAuditStatusRequest>(json!({"all":true})).is_err());
        assert!(serde_json::from_value::<TenantAuditCapacityRequest>(json!({"all":true})).is_err());
        serde_json::from_value::<TenantAuditCapacityRequest>(json!({})).unwrap();
    }

    #[test]
    fn records_pages_status_and_verification_round_trip_exact_current_bytes() {
        let record = TenantAuditRecord {
            sequence: 11,
            event: event(),
        };
        let encoded = serde_json::to_value(&record).unwrap();
        rejects::<TenantAuditRecord>(&encoded, "/event", "legacy_actor");
        omits::<TenantAuditRecord>(&encoded, "sequence");
        let mut implicit = encoded.clone();
        implicit["event"]
            .as_object_mut()
            .unwrap()
            .remove("data_revision");
        assert!(serde_json::from_value::<TenantAuditRecord>(implicit).is_err());
        assert_eq!(
            record.event_sha256().unwrap(),
            audit_record_sha256(&serde_json::to_vec(&record.event).unwrap())
        );

        let page = TenantAuditPage {
            tenant: "tenant-a".into(),
            incarnation: incarnation(),
            stream_id: Uuid::from_u128(3),
            through_sequence: 20,
            next_sequence: 12,
            snapshot_head: Some(link(4, 10)),
            snapshot_segments: 2,
            snapshot_tail_sha256: Some("e".repeat(64)),
            previous_record_sha256: Some(record.event_sha256().unwrap()),
            records: vec![record],
        };
        let bytes = serde_json::to_vec(&page).unwrap();
        assert_eq!(
            decode_exact::<TenantAuditPage>(&bytes, MAX_TENANT_AUDIT_PAGE_BYTES, "page").unwrap(),
            page
        );
        let continuation = page.cursor().unwrap();
        continuation.validate().unwrap();
        assert_eq!(
            continuation.previous_record_sha256,
            page.previous_record_sha256
        );
        assert!(
            TenantAuditPage {
                next_sequence: 20,
                ..page.clone()
            }
            .cursor()
            .is_none()
        );
        let pretty = serde_json::to_vec_pretty(&page).unwrap();
        assert!(decode_exact::<TenantAuditPage>(&pretty, 1 << 20, "page").is_err());

        let status = TenantAuditStatus {
            tenant: "tenant-a".into(),
            incarnation: incarnation(),
            revision: 7,
            position: AuditRetentionState::empty(Uuid::from_u128(3)),
            budget: AuditRetentionBudget::default(),
            hot_tail_sha256: None,
        };
        status.validate().unwrap();
        let bytes = serde_json::to_vec(&status).unwrap();
        assert_eq!(
            decode_exact::<TenantAuditStatus>(&bytes, 64 << 10, "status").unwrap(),
            status
        );
        omits::<TenantAuditStatus>(&serde_json::to_value(&status).unwrap(), "hot_tail_sha256");
        let mut over = status.clone();
        over.position.hot_bytes = over.budget.hot_bytes + 1;
        assert!(over.validate().is_err());
        // A retained hot event requires its exact tail, and the fixed first
        // cursor carries that tail with the captured end.
        let mut hot = status.clone();
        hot.position.next_sequence = 3;
        hot.position.hot_bytes = 300;
        assert!(hot.validate().is_err());
        hot.hot_tail_sha256 = Some("e".repeat(64));
        hot.validate().unwrap();
        let first = hot.snapshot_cursor();
        first.validate().unwrap();
        assert_eq!(
            (first.through_sequence, first.snapshot_tail_sha256),
            (3, hot.hot_tail_sha256.clone())
        );
        let mut empty = status.clone();
        empty.hot_tail_sha256 = Some("e".repeat(64));
        assert!(empty.validate().is_err());

        let reference = AuditArchiveReference {
            stream_id: Uuid::from_u128(3),
            object: link(0, 4),
            previous: None,
            record_count: 4,
            plaintext_bytes: 10,
            ciphertext_bytes: 20,
            key: AuditArchiveKeyDependency {
                provider: "file".into(),
                key_ref: "installed-key".into(),
                version: 1,
                wrapped_key_sha256: "b".repeat(64),
            },
        };
        let verification = TenantAuditVerificationPage {
            tenant: "tenant-a".into(),
            incarnation: incarnation(),
            stream_id: Uuid::from_u128(3),
            next_index: 1,
            through_index: 2,
            snapshot_head: Some(link(4, 10)),
            results: vec![TenantAuditObjectVerification {
                index: 0,
                reference,
                cache: AuditObjectCheck::Verified,
                destination: AuditObjectCheck::Unavailable,
            }],
        };
        let encoded = serde_json::to_value(&verification).unwrap();
        assert_eq!(encoded["results"][0]["destination"], "unavailable");
        let bytes = serde_json::to_vec(&verification).unwrap();
        assert_eq!(
            decode_exact::<TenantAuditVerificationPage>(&bytes, 1 << 20, "verification").unwrap(),
            verification
        );
        let cursor = verification.cursor().unwrap();
        cursor.validate().unwrap();
        assert_eq!(cursor.previous, Some(link(0, 4)));
        let mut unknown = encoded.clone();
        unknown["results"][0]["cache"] = json!("skipped");
        assert!(serde_json::from_value::<TenantAuditVerificationPage>(unknown).is_err());
        rejects::<TenantAuditVerificationPage>(&encoded, "/results/0", "legacy");
    }
}
