//! Private audit requests stay on this installed, pinned administrative endpoint.
use crate::{ClientError, KasumiAdminClient, authorized, encode, proto};
use kasumi_types::{
    AuditCapacity, AuditRetentionBudget, MAX_SECURITY_AUDIT_PAGE_BYTES, SecurityAuditArchivePage,
    SecurityAuditArchivePageRequest, SecurityAuditArchiveVerification, SecurityAuditExportRequest,
    SecurityAuditPage, SecurityAuditStatus, SecurityAuditStatusRequest, SecurityAuditVerifyRequest,
};
use serde::{Serialize, de::DeserializeOwned};

/// Evidence returned only after an authorized server verifies an encrypted
/// archive's exact range, key binding and digest. Catalog entries alone cannot
/// construct this proof, and the proof grants no present access.
/// ```compile_fail
/// let _: kasumi_client::VerifiedSecurityAuditArchive = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedSecurityAuditArchive {
    observation: SecurityAuditArchiveVerification,
}
impl VerifiedSecurityAuditArchive {
    pub fn observation(&self) -> &SecurityAuditArchiveVerification {
        &self.observation
    }
}

fn invalid(message: impl std::fmt::Display) -> ClientError {
    ClientError::Json(<serde_json::Error as serde::de::Error>::custom(message))
}
fn request(
    bearer: &str,
    value: &impl Serialize,
) -> Result<tonic::Request<proto::SecurityAuditJsonRequest>, ClientError> {
    let request_json = encode(value)?;
    if request_json.len() > MAX_SECURITY_AUDIT_PAGE_BYTES {
        return Err(ClientError::RequestTooLarge);
    }
    let mut request = authorized(bearer, proto::SecurityAuditJsonRequest { request_json })?;
    request.set_timeout(std::time::Duration::from_secs(30));
    Ok(request)
}
fn decode<T: DeserializeOwned>(
    response: proto::SecurityAuditJsonResponse,
) -> Result<T, ClientError> {
    if response.response_json.len() > MAX_SECURITY_AUDIT_PAGE_BYTES {
        return Err(invalid("audit response exceeds its byte limit"));
    }
    Ok(serde_json::from_slice(&response.response_json)?)
}
/// Status and capacity share one derivation from the installed budget; a
/// response whose thresholds or usage that budget cannot hold is rejected.
pub(crate) fn validate_capacity(capacity: &AuditCapacity) -> Result<(), ClientError> {
    capacity.validate().map_err(invalid)
}
pub(crate) fn validate_page(
    input: &SecurityAuditExportRequest,
    page: &SecurityAuditPage,
) -> Result<(), ClientError> {
    let first = input
        .cursor
        .as_ref()
        .map_or(0, |cursor| cursor.next_sequence);
    // The page's own anchors must form a valid continuation even when
    // complete; a completed range must end at its captured hot tail.
    if page.resumed().validate().is_err()
        || page.next_sequence.checked_sub(first) != Some(page.records.len() as u64)
        || page.records.len() > usize::from(input.limit)
        || (first < page.through_sequence && page.records.is_empty())
        || input.cursor.as_ref().is_some_and(|cursor| {
            cursor.stream_id != page.stream_id
                || cursor.through_sequence != page.through_sequence
                || cursor.snapshot_segments != page.snapshot_segments
                || cursor.snapshot_head != page.snapshot_head
                || cursor.snapshot_tail_sha256 != page.snapshot_tail_sha256
        })
        || page
            .records
            .iter()
            .enumerate()
            .any(|(offset, record)| Some(record.sequence) != first.checked_add(offset as u64))
    {
        return Err(invalid(
            "audit page changed its original stream, range, snapshot or sequence",
        ));
    }
    for record in &page.records {
        record.validate().map_err(invalid)?;
    }
    // The next cursor is anchored to the exact last record returned here; an
    // empty page must return its request's anchor unchanged.
    let anchor = match page.records.last() {
        Some(last) => Some(last.sha256().map_err(invalid)?),
        None => input
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.previous_record_sha256.clone()),
    };
    if page.previous_record_sha256 != anchor {
        return Err(invalid("audit page anchor differs from its last record"));
    }
    Ok(())
}
fn validate_archives(
    input: &SecurityAuditArchivePageRequest,
    page: &SecurityAuditArchivePage,
) -> Result<(), ClientError> {
    let first = input.cursor.as_ref().map_or(0, |cursor| cursor.next_index);
    if page.stream_id.is_nil()
        || page.next_index > page.through_index
        || page.next_index.checked_sub(first) != Some(page.archives.len() as u64)
        || page.archives.len() > usize::from(input.limit)
        || (first < page.through_index && page.archives.is_empty())
        || (page.through_index == 0) != page.snapshot_head.is_none()
        || page.snapshot_head.as_ref().is_some_and(|head| {
            head.object_id.is_nil()
                || head.first_sequence >= head.next_sequence
                || kasumi_types::validate_sha256(&head.ciphertext_sha256).is_err()
        })
        || input.cursor.as_ref().is_some_and(|cursor| {
            cursor.stream_id != page.stream_id
                || cursor.through_index != page.through_index
                || cursor.snapshot_head != page.snapshot_head
        })
    {
        return Err(invalid("archive page changed its original stream or range"));
    }
    for (offset, archive) in page.archives.iter().enumerate() {
        archive.validate().map_err(invalid)?;
        if archive.stream_id != page.stream_id
            || (offset == 0
                && archive.previous.as_ref()
                    != input
                        .cursor
                        .as_ref()
                        .and_then(|cursor| cursor.previous.as_ref()))
            || (offset > 0 && archive.previous.as_ref() != Some(&page.archives[offset - 1].object))
        {
            return Err(invalid(
                "archive page contains a different stream or broken range chain",
            ));
        }
    }
    if page.next_index == page.through_index
        && page
            .archives
            .last()
            .map(|archive| &archive.object)
            .or_else(|| {
                input
                    .cursor
                    .as_ref()
                    .and_then(|cursor| cursor.previous.as_ref())
            })
            != page.snapshot_head.as_ref()
    {
        return Err(invalid("archive page differs from its snapshot head"));
    }
    Ok(())
}
impl KasumiAdminClient {
    pub async fn security_audit_status(
        &mut self,
        bearer: &str,
    ) -> Result<SecurityAuditStatus, ClientError> {
        let response = self
            .inner
            .security_audit_status(request(bearer, &SecurityAuditStatusRequest {})?)
            .await?
            .into_inner();
        let status: SecurityAuditStatus = decode(response)?;
        // Its position, archive counts and hot tail fix the first cursor.
        status.validate().map_err(invalid)?;
        validate_capacity(&AuditCapacity::new(
            &status.position,
            &status.budget,
            AuditRetentionBudget::MAINTENANCE_BYTES,
            None,
        ))?;
        Ok(status)
    }
    pub async fn security_audit_archives(
        &mut self,
        bearer: &str,
        input: &SecurityAuditArchivePageRequest,
    ) -> Result<SecurityAuditArchivePage, ClientError> {
        input.validate().map_err(invalid)?;
        let response = self
            .inner
            .security_audit_archives(request(bearer, input)?)
            .await?
            .into_inner();
        let page = decode(response)?;
        validate_archives(input, &page)?;
        Ok(page)
    }
    pub async fn verify_security_audit_archive(
        &mut self,
        bearer: &str,
        input: &SecurityAuditVerifyRequest,
    ) -> Result<VerifiedSecurityAuditArchive, ClientError> {
        input.validate().map_err(invalid)?;
        let response = self
            .inner
            .security_audit_verify(request(bearer, input)?)
            .await?
            .into_inner();
        let observation: SecurityAuditArchiveVerification = decode(response)?;
        observation.archive.validate().map_err(invalid)?;
        if observation.stream_id != input.stream_id
            || observation.index != input.index
            || observation.archive.stream_id != input.stream_id
        {
            return Err(invalid(
                "verified audit archive differs from the requested stream or index",
            ));
        }
        Ok(VerifiedSecurityAuditArchive { observation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::{
        AuditArchiveKeyDependency, AuditArchiveLink, AuditArchiveReference, AuditRetentionState,
        SECURITY_AUDIT_RECORD_FORMAT, SecurityAuditCursor, SecurityAuditRecord, SecurityEvent,
        SecurityEventKind, SecurityOutcome,
    };

    fn archive(
        stream_id: uuid::Uuid,
        first_sequence: u64,
        previous: Option<AuditArchiveLink>,
    ) -> AuditArchiveReference {
        AuditArchiveReference {
            stream_id,
            object: AuditArchiveLink {
                object_id: uuid::Uuid::new_v4(),
                first_sequence,
                next_sequence: first_sequence + 1,
                ciphertext_sha256: "a".repeat(64),
            },
            previous,
            record_count: 1,
            plaintext_bytes: 10,
            ciphertext_bytes: 20,
            key: AuditArchiveKeyDependency {
                provider: "test".into(),
                key_ref: "key".into(),
                version: 1,
                wrapped_key_sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn archive_cursor_binds_snapshot_head_and_page_boundary() {
        let stream_id = uuid::Uuid::new_v4();
        let first = archive(stream_id, 0, None);
        let second = archive(stream_id, 1, Some(first.object.clone()));
        let input = SecurityAuditArchivePageRequest {
            cursor: None,
            limit: 1,
        };
        let first_page = SecurityAuditArchivePage {
            stream_id,
            next_index: 1,
            through_index: 2,
            snapshot_head: Some(second.object.clone()),
            archives: vec![first.clone()],
        };
        validate_archives(&input, &first_page).unwrap();
        let cursor = first_page.cursor().unwrap();
        cursor.validate().unwrap();
        assert_eq!(cursor.previous, Some(first.object.clone()));
        assert_eq!(cursor.snapshot_head, Some(second.object.clone()));
        let continuation = SecurityAuditArchivePageRequest {
            cursor: Some(cursor.clone()),
            limit: 1,
        };
        let mut second_page = SecurityAuditArchivePage {
            stream_id,
            next_index: 2,
            through_index: 2,
            snapshot_head: Some(second.object.clone()),
            archives: vec![second],
        };
        validate_archives(&continuation, &second_page).unwrap();
        second_page.archives[0].previous.as_mut().unwrap().object_id = uuid::Uuid::new_v4();
        assert!(validate_archives(&continuation, &second_page).is_err());
        second_page.archives[0].previous = Some(first.object);
        second_page.snapshot_head.as_mut().unwrap().object_id = uuid::Uuid::new_v4();
        assert!(validate_archives(&continuation, &second_page).is_err());
        let mut missing_boundary = cursor;
        missing_boundary.previous = None;
        assert!(missing_boundary.validate().is_err());
        assert!(
            serde_json::from_value::<kasumi_types::SecurityAuditArchiveCursor>(serde_json::json!({
                "stream_id": stream_id,
                "next_index": 0,
                "through_index": 0
            }))
            .is_err()
        );
    }

    fn record(sequence: u64) -> SecurityAuditRecord {
        SecurityAuditRecord {
            format: SECURITY_AUDIT_RECORD_FORMAT,
            sequence,
            timestamp_ms: 1_700_000_000_000 + sequence,
            event: SecurityEvent {
                kind: SecurityEventKind::AccessDenied,
                principal: Some("principal".into()),
                tenant: Some("tenant-a".into()),
                request_id: format!("request-{sequence}"),
                outcome: SecurityOutcome::Denied,
            },
            transport: None,
        }
    }

    fn head() -> AuditArchiveLink {
        AuditArchiveLink {
            object_id: uuid::Uuid::from_u128(77),
            first_sequence: 0,
            next_sequence: 40,
            ciphertext_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn rejects_historical_restart_holes_empty_progress_and_oversize() {
        let stream_id = uuid::Uuid::new_v4();
        let input = SecurityAuditExportRequest {
            cursor: Some(SecurityAuditCursor {
                stream_id,
                next_sequence: 42,
                through_sequence: 44,
                snapshot_segments: 1,
                snapshot_head: Some(head()),
                snapshot_tail_sha256: Some(record(43).sha256().unwrap()),
                previous_record_sha256: Some(record(41).sha256().unwrap()),
            }),
            limit: 2,
        };
        let mut page = SecurityAuditPage {
            stream_id,
            next_sequence: 43,
            through_sequence: 44,
            snapshot_segments: 1,
            snapshot_head: Some(head()),
            snapshot_tail_sha256: Some(record(43).sha256().unwrap()),
            previous_record_sha256: Some(record(42).sha256().unwrap()),
            records: vec![record(42)],
        };
        validate_page(&input, &page).unwrap();
        page.through_sequence = 45;
        assert!(validate_page(&input, &page).is_err());
        page.through_sequence = 44;
        page.stream_id = uuid::Uuid::new_v4();
        assert!(validate_page(&input, &page).is_err());
        page.stream_id = stream_id;
        page.records[0].sequence = 43;
        assert!(validate_page(&input, &page).is_err());
        page.records.clear();
        page.next_sequence = 42;
        assert!(validate_page(&input, &page).is_err());
        assert!(
            decode::<SecurityAuditStatus>(proto::SecurityAuditJsonResponse {
                response_json: vec![b' '; MAX_SECURITY_AUDIT_PAGE_BYTES + 1]
            })
            .is_err()
        );
    }

    #[test]
    fn record_pages_bind_snapshot_anchor_and_exact_last_record() {
        let stream_id = uuid::Uuid::new_v4();
        let initial = SecurityAuditExportRequest {
            cursor: None,
            limit: 2,
        };
        let first = SecurityAuditPage {
            stream_id,
            next_sequence: 2,
            through_sequence: 50,
            snapshot_segments: 1,
            snapshot_head: Some(head()),
            snapshot_tail_sha256: Some(record(49).sha256().unwrap()),
            previous_record_sha256: Some(record(1).sha256().unwrap()),
            records: vec![record(0), record(1)],
        };
        validate_page(&initial, &first).unwrap();
        let cursor = first.cursor().unwrap();
        cursor.validate().unwrap();
        let continuation = SecurityAuditExportRequest {
            cursor: Some(cursor.clone()),
            limit: 2,
        };
        let second = SecurityAuditPage {
            next_sequence: 4,
            previous_record_sha256: Some(record(3).sha256().unwrap()),
            records: vec![record(2), record(3)],
            ..first.clone()
        };
        validate_page(&continuation, &second).unwrap();
        // The returned anchor must digest the exact last record returned.
        let mut changed = second.clone();
        changed.previous_record_sha256 = Some(record(2).sha256().unwrap());
        assert!(validate_page(&continuation, &changed).is_err());
        let mut changed = second.clone();
        changed.records[1].timestamp_ms += 1;
        assert!(validate_page(&continuation, &changed).is_err());
        // A continuation keeps the snapshot it was issued with.
        let mut changed = second.clone();
        changed.snapshot_segments = 2;
        changed.snapshot_head.as_mut().unwrap().next_sequence = 45;
        assert!(validate_page(&continuation, &changed).is_err());
        let mut changed = second.clone();
        changed.snapshot_head.as_mut().unwrap().object_id = uuid::Uuid::new_v4();
        assert!(validate_page(&continuation, &changed).is_err());
        // It also keeps the hot tail captured with that snapshot.
        let mut changed = second.clone();
        changed.snapshot_tail_sha256 = Some(record(48).sha256().unwrap());
        assert!(validate_page(&continuation, &changed).is_err());
        let mut changed = first.clone();
        changed.snapshot_tail_sha256 = None;
        assert!(validate_page(&initial, &changed).is_err());
        // Page anchors must themselves form a valid continuation.
        let mut changed = first.clone();
        changed.snapshot_head = None;
        assert!(validate_page(&initial, &changed).is_err());
        let mut changed = first.clone();
        changed.snapshot_head.as_mut().unwrap().next_sequence = 51;
        assert!(validate_page(&initial, &changed).is_err());
        // Typed records must pass their own closed metadata validation.
        let mut changed = second.clone();
        changed.records[0].format = 2;
        assert!(validate_page(&continuation, &changed).is_err());
        let mut changed = second.clone();
        changed.records[0].event.request_id.clear();
        assert!(validate_page(&continuation, &changed).is_err());
        // A completed range returns no records and keeps its request anchor.
        let complete = SecurityAuditExportRequest {
            cursor: Some(SecurityAuditCursor {
                next_sequence: 50,
                previous_record_sha256: Some(record(49).sha256().unwrap()),
                ..cursor.clone()
            }),
            limit: 2,
        };
        let empty = SecurityAuditPage {
            next_sequence: 50,
            previous_record_sha256: Some(record(49).sha256().unwrap()),
            records: vec![],
            ..first.clone()
        };
        validate_page(&complete, &empty).unwrap();
        assert!(empty.cursor().is_none());
        let mut changed = empty;
        changed.previous_record_sha256 = Some(record(48).sha256().unwrap());
        assert!(validate_page(&complete, &changed).is_err());
        // The page that returns the last record must return the exact tail.
        let last = SecurityAuditExportRequest {
            cursor: Some(SecurityAuditCursor {
                next_sequence: 48,
                previous_record_sha256: Some(record(47).sha256().unwrap()),
                ..cursor
            }),
            limit: 2,
        };
        let mut end = SecurityAuditPage {
            next_sequence: 50,
            previous_record_sha256: Some(record(49).sha256().unwrap()),
            records: vec![record(48), record(49)],
            ..first.clone()
        };
        validate_page(&last, &end).unwrap();
        end.records[1].event.request_id.push('x');
        end.previous_record_sha256 = Some(end.records[1].sha256().unwrap());
        assert!(validate_page(&last, &end).is_err());
    }

    #[test]
    fn status_hot_tail_fixes_the_first_cursor() {
        let budget = kasumi_types::AuditRetentionBudget::default();
        let mut position = AuditRetentionState::empty(uuid::Uuid::new_v4());
        position.next_sequence = 3;
        position.hot_bytes = 300;
        let status = SecurityAuditStatus {
            position: position.clone(),
            budget,
            archived_bytes: 0,
            archive_segments: 0,
            draining: false,
            persistence_failed: false,
            maintenance_failures: 0,
            last_failure: None,
            hot_tail_sha256: Some(record(2).sha256().unwrap()),
        };
        status.validate().unwrap();
        let cursor = status.snapshot_cursor();
        cursor.validate().unwrap();
        assert_eq!(cursor.snapshot_tail_sha256, status.hot_tail_sha256);
        for changed in [
            SecurityAuditStatus {
                hot_tail_sha256: None,
                ..status.clone()
            },
            SecurityAuditStatus {
                archive_segments: 1,
                ..status.clone()
            },
        ] {
            assert!(changed.validate().is_err());
        }
        let mut missing = serde_json::to_value(&status).unwrap();
        missing.as_object_mut().unwrap().remove("hot_tail_sha256");
        assert!(
            decode::<SecurityAuditStatus>(proto::SecurityAuditJsonResponse {
                response_json: serde_json::to_vec(&missing).unwrap(),
            })
            .is_err()
        );
    }

    #[test]
    fn capacity_thresholds_and_usage_must_match_the_installed_budget() {
        let budget = kasumi_types::AuditRetentionBudget::default();
        let mut position = AuditRetentionState::empty(uuid::Uuid::new_v4());
        position.hot_bytes = budget.starts_at() + 1;
        let capacity = AuditCapacity::new(
            &position,
            &budget,
            kasumi_types::AuditRetentionBudget::MAINTENANCE_BYTES,
            None,
        );
        validate_capacity(&capacity).unwrap();
        let encoded = serde_json::to_vec(&capacity).unwrap();
        let decoded: AuditCapacity = decode(proto::SecurityAuditJsonResponse {
            response_json: encoded,
        })
        .unwrap();
        assert_eq!(decoded, capacity);
        for changed in [
            AuditCapacity {
                starts_at_bytes: capacity.starts_at_bytes + 1,
                ..capacity.clone()
            },
            AuditCapacity {
                drains_to_bytes: capacity.drains_to_bytes - 1,
                ..capacity.clone()
            },
            AuditCapacity {
                archive_backlog_bytes: 0,
                ..capacity.clone()
            },
            AuditCapacity {
                hot_bytes: capacity.hot_budget_bytes + 1,
                ..capacity.clone()
            },
        ] {
            assert!(validate_capacity(&changed).is_err());
        }
        let mut missing = serde_json::to_value(&capacity).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("pending_publication");
        assert!(
            decode::<AuditCapacity>(proto::SecurityAuditJsonResponse {
                response_json: serde_json::to_vec(&missing).unwrap(),
            })
            .is_err()
        );
    }
}
