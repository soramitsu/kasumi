//! Private audit requests stay on this installed, pinned administrative endpoint.
use crate::{ClientError, KasumiAdminClient, authorized, encode, proto};
use kasumi_types::{
    MAX_SECURITY_AUDIT_PAGE_BYTES, SecurityAuditArchivePage, SecurityAuditArchivePageRequest,
    SecurityAuditArchiveVerification, SecurityAuditExportRequest, SecurityAuditPage,
    SecurityAuditStatus, SecurityAuditStatusRequest, SecurityAuditVerifyRequest,
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
pub(crate) fn validate_page(
    input: &SecurityAuditExportRequest,
    page: &SecurityAuditPage,
) -> Result<(), ClientError> {
    let first = input
        .cursor
        .as_ref()
        .map_or(0, |cursor| cursor.next_sequence);
    if page.stream_id.is_nil()
        || page.next_sequence > page.through_sequence
        || page.next_sequence.checked_sub(first) != Some(page.records.len() as u64)
        || page.records.len() > usize::from(input.limit)
        || (first < page.through_sequence && page.records.is_empty())
        || input.cursor.as_ref().is_some_and(|cursor| {
            cursor.stream_id != page.stream_id || cursor.through_sequence != page.through_sequence
        })
        || page.records.iter().enumerate().any(|(offset, record)| {
            record.get("sequence").and_then(serde_json::Value::as_u64)
                != first.checked_add(offset as u64)
        })
    {
        return Err(invalid(
            "audit page changed its original stream, range or sequence",
        ));
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
        status.position.validate().map_err(invalid)?;
        status.budget.validate().map_err(invalid)?;
        if (status.archive_segments == 0) != status.position.archive_head.is_none()
            || (status.archive_segments == 0) != (status.archived_bytes == 0)
        {
            return Err(invalid("audit status archive count differs from its roots"));
        }
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
        AuditArchiveKeyDependency, AuditArchiveLink, AuditArchiveReference, SecurityAuditCursor,
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

    #[test]
    fn rejects_historical_restart_holes_empty_progress_and_oversize() {
        let stream_id = uuid::Uuid::new_v4();
        let input = SecurityAuditExportRequest {
            cursor: Some(SecurityAuditCursor {
                stream_id,
                next_sequence: 42,
                through_sequence: 44,
            }),
            limit: 2,
        };
        let mut page = SecurityAuditPage {
            stream_id,
            next_sequence: 43,
            through_sequence: 44,
            records: vec![serde_json::json!({"sequence":42})],
        };
        validate_page(&input, &page).unwrap();
        page.through_sequence = 45;
        assert!(validate_page(&input, &page).is_err());
        page.through_sequence = 44;
        page.stream_id = uuid::Uuid::new_v4();
        assert!(validate_page(&input, &page).is_err());
        page.stream_id = stream_id;
        page.records[0]["sequence"] = serde_json::json!(43);
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
}
