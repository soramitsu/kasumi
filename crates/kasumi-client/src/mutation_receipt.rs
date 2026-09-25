//! Resolve a retained mutation only against the exact original canonical input.
use crate::{ClientError, KasumiClient, proto};
use kasumi_types::{MutationBatch, MutationReceipt, MutationReceiptScope, WriteReceipt};
use std::collections::{BTreeMap, BTreeSet};

fn canonical_target_path(collection: &str, id: &str) -> String {
    let escape = |value: &str| value.replace('~', "~0").replace('/', "~1");
    format!("/{}/{}", escape(collection), escape(id))
}

fn decode_path_component(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            decoded.push(match chars.next()? {
                '0' => '~',
                '1' => '/',
                _ => return None,
            });
        } else {
            decoded.push(ch);
        }
    }
    kasumi_types::validate_name(&decoded).ok()?;
    Some(decoded)
}

fn canonical_target_path_on_wire(path: &str) -> bool {
    let Some((collection, id)) = path.strip_prefix('/').and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    let (Some(collection), Some(id)) =
        (decode_path_component(collection), decode_path_component(id))
    else {
        return false;
    };
    canonical_target_path(&collection, &id) == path
}

/// Decode the current native receipt contract without collapsing duplicate
/// protobuf rows. Every reply path, including staging and administration,
/// uses the same strict ordered, canonical version-entry decoder.
pub(crate) fn decode_write_receipt(
    response: proto::WriteReceipt,
) -> Result<WriteReceipt, ClientError> {
    if response.contract != crate::NATIVE_WRITE_RECEIPT_CONTRACT {
        return Err(ClientError::InvalidResponse(
            "write receipt contract identity differs",
        ));
    }
    if response.revision == 0 {
        return Err(ClientError::InvalidResponse(
            "write receipt has no applying revision",
        ));
    }
    let mut versions = BTreeMap::new();
    let mut previous: Option<String> = None;
    for entry in response.versions {
        if !canonical_target_path_on_wire(&entry.target_path)
            || entry.revision != response.revision
            || previous
                .as_deref()
                .is_some_and(|path| entry.target_path.as_str() <= path)
        {
            return Err(ClientError::InvalidResponse(
                "write receipt has invalid, unordered or duplicate target versions",
            ));
        }
        previous = Some(entry.target_path.clone());
        if versions.insert(entry.target_path, entry.revision).is_some() {
            return Err(ClientError::InvalidResponse(
                "write receipt repeats a target",
            ));
        }
    }
    Ok(WriteReceipt {
        revision: response.revision,
        versions,
    })
}

/// A committed ordinary mutation must identify each distinct target in the
/// exact original batch at its applying revision. This applies equally to a
/// direct Mutate reply and a retained ReceiptResponse outcome. The native
/// reply alone is not enough to acknowledge an application journal compare-and-swap.
pub(crate) fn verify_committed_write_receipt(
    original: &MutationBatch,
    response: proto::WriteReceipt,
) -> Result<WriteReceipt, ClientError> {
    if original.operations.is_empty() {
        return Err(ClientError::InvalidResponse(
            "committed mutation has no targets",
        ));
    }
    let mut targets = BTreeSet::new();
    for operation in &original.operations {
        let (collection, id) = operation.target();
        kasumi_types::validate_name(collection)
            .and_then(|()| kasumi_types::validate_name(id))
            .map_err(|_| ClientError::InvalidResponse("invalid committed mutation target"))?;
        if !targets.insert(canonical_target_path(collection, id)) {
            return Err(ClientError::InvalidResponse(
                "committed mutation repeats a target",
            ));
        }
    }
    let receipt = decode_write_receipt(response)?;
    if receipt.versions.len() != targets.len()
        || receipt.versions.keys().any(|path| !targets.contains(path))
    {
        return Err(ClientError::InvalidResponse(
            "committed mutation versions differ from the original targets",
        ));
    }
    Ok(receipt)
}

/// Verify a response from an authenticated native connection against the
/// original batch. This is input matching, not independent authentication.
/// No retained record means unknown, and never authorizes a new mutation.
pub fn verify_mutation_receipt(
    expected_scope: &MutationReceiptScope,
    original: &MutationBatch,
    response: proto::ReceiptResponse,
) -> Result<Option<MutationReceipt>, ClientError> {
    let Some(outcome) = response.outcome else {
        if !response.request_digest.is_empty() || response.scope.is_some() {
            return Err(ClientError::InvalidResponse(
                "receipt identity has no outcome",
            ));
        }
        return Ok(None);
    };
    let scope = response
        .scope
        .ok_or(ClientError::InvalidResponse("receipt scope missing"))?;
    let scope = MutationReceiptScope {
        tenant: scope.tenant,
        incarnation: scope.incarnation,
        principal: scope.principal,
    };
    if scope != *expected_scope {
        return Err(ClientError::InvalidResponse(
            "receipt belongs to another original namespace",
        ));
    }
    let expected = original
        .digest()
        .map_err(|_| ClientError::InvalidResponse("original mutation cannot be encoded"))?;
    if response.request_digest != expected {
        return Err(ClientError::InvalidResponse(
            "receipt does not identify the exact original mutation",
        ));
    }
    let outcome = match outcome {
        proto::receipt_response::Outcome::Committed(receipt) => {
            Ok(verify_committed_write_receipt(original, receipt)?)
        }
        proto::receipt_response::Outcome::Rejected(error) => Err(kasumi_types::Error::new(
            serde_json::from_value(serde_json::Value::String(error.code))?,
            error.message,
        )),
    };
    Ok(Some(MutationReceipt {
        scope,
        request_digest: expected,
        outcome,
    }))
}

impl KasumiClient {
    /// Read the retained outcome for the original principal/key and verify the
    /// full input digest. Does not dispatch or retry the mutation.
    pub async fn resolve_mutation(
        &mut self,
        bearer: &str,
        expected_scope: &MutationReceiptScope,
        original: &MutationBatch,
        timeout: std::time::Duration,
    ) -> Result<Option<MutationReceipt>, ClientError> {
        let now = tokio::time::Instant::now();
        let end = now
            .checked_add(timeout)
            .filter(|end| *end > now)
            .ok_or_else(|| {
                tonic::Status::deadline_exceeded("receipt resolution deadline elapsed")
            })?;
        let end = self.deadline.map_or(end, |original| original.min(end));
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(
                tonic::Status::deadline_exceeded("receipt resolution deadline elapsed").into(),
            );
        }
        let mut request = self.authorized(
            bearer,
            proto::ReceiptRequest {
                idempotency_key: original.idempotency_key.clone(),
            },
        )?;
        request.set_timeout(remaining);
        let result = tokio::time::timeout_at(end, async {
            let response = self.inner.receipt(request).await?.into_inner();
            verify_mutation_receipt(expected_scope, original, response)
        })
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("receipt resolution deadline elapsed"))?;
        if tokio::time::Instant::now() >= end {
            return Err(
                tonic::Status::deadline_exceeded("receipt resolution deadline elapsed").into(),
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::{Mutation, Precondition};
    use prost::Message;
    use serde_json::json;

    fn version(target_path: &str, revision: u64) -> proto::VersionEntry {
        proto::VersionEntry {
            target_path: target_path.into(),
            revision,
        }
    }

    fn wire_receipt(revision: u64, versions: Vec<proto::VersionEntry>) -> proto::WriteReceipt {
        proto::WriteReceipt {
            revision,
            contract: crate::NATIVE_WRITE_RECEIPT_CONTRACT.into(),
            versions,
        }
    }

    fn append_length_delimited(wire: &mut Vec<u8>, field: u8, payload: &[u8]) {
        wire.push((field << 3) | 2);
        let mut len = payload.len();
        while len >= 0x80 {
            wire.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        wire.push(len as u8);
        wire.extend_from_slice(payload);
    }

    fn scope() -> MutationReceiptScope {
        MutationReceiptScope {
            tenant: "tenant-a".into(),
            incarnation: "source-incarnation".into(),
            principal: "writer".into(),
        }
    }
    fn wire_scope() -> proto::MutationReceiptScope {
        let scope = scope();
        proto::MutationReceiptScope {
            tenant: scope.tenant,
            incarnation: scope.incarnation,
            principal: scope.principal,
        }
    }
    fn original() -> MutationBatch {
        MutationBatch {
            idempotency_key: "original".into(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "same-id".into(),
                body: json!({"value":1}),
                expected: Precondition::Absent,
            }],
        }
    }

    #[test]
    fn retained_outcome_requires_the_exact_body_read_set_preconditions_and_key() {
        let original = original();
        let response = proto::ReceiptResponse {
            scope: Some(wire_scope()),
            request_digest: original.digest().unwrap(),
            outcome: Some(proto::receipt_response::Outcome::Committed(
                proto::WriteReceipt {
                    revision: 7,
                    contract: crate::NATIVE_WRITE_RECEIPT_CONTRACT.into(),
                    versions: vec![version("/docs/same-id", 7)],
                },
            )),
        };
        assert_eq!(
            verify_mutation_receipt(&scope(), &original, response.clone())
                .unwrap()
                .unwrap()
                .outcome
                .unwrap()
                .revision,
            7
        );
        let mut changed_body = original.clone();
        let Mutation::Put { body, .. } = &mut changed_body.operations[0] else {
            unreachable!()
        };
        *body = json!({"value":2});
        let mut changed_key = original.clone();
        changed_key.idempotency_key = "different".into();
        let mut changed_precondition = original.clone();
        let Mutation::Put { expected, .. } = &mut changed_precondition.operations[0] else {
            unreachable!()
        };
        *expected = Precondition::Any;
        let mut changed_reads = original.clone();
        changed_reads
            .read_set
            .push(kasumi_types::ReadAssertion::Document {
                collection: "docs".into(),
                id: "read-id".into(),
                expected: kasumi_types::ReadPrecondition::Absent,
            });
        for substituted in [
            changed_body,
            changed_key,
            changed_precondition,
            changed_reads,
        ] {
            assert!(verify_mutation_receipt(&scope(), &substituted, response.clone()).is_err());
        }
        for field in 0..3 {
            let mut substituted_scope = scope();
            match field {
                0 => substituted_scope.tenant = "another-tenant".into(),
                1 => substituted_scope.incarnation = "restored-target".into(),
                _ => substituted_scope.principal = "another-principal".into(),
            }
            assert!(
                verify_mutation_receipt(&substituted_scope, &original, response.clone()).is_err()
            );
        }
        let mut missing_scope = response.clone();
        missing_scope.scope = None;
        assert!(verify_mutation_receipt(&scope(), &original, missing_scope).is_err());
        let mut missing_digest = response;
        missing_digest.request_digest.clear();
        assert!(verify_mutation_receipt(&scope(), &original, missing_digest).is_err());
    }

    #[test]
    fn committed_reply_and_retained_outcome_require_exact_canonical_ordered_targets() {
        let original = MutationBatch {
            idempotency_key: "journal-cas".into(),
            read_set: vec![],
            operations: vec![
                Mutation::Put {
                    collection: "fi/journal".into(),
                    id: "attempt~1".into(),
                    body: json!({"phase":"dispatched"}),
                    expected: Precondition::Absent,
                },
                Mutation::Delete {
                    collection: "fi/journal".into(),
                    id: "claim-2".into(),
                    expected: Precondition::Any,
                },
            ],
        };
        let valid = wire_receipt(
            19,
            vec![
                version("/fi~1journal/attempt~01", 19),
                version("/fi~1journal/claim-2", 19),
            ],
        );
        assert_eq!(
            verify_committed_write_receipt(&original, valid.clone())
                .unwrap()
                .versions
                .len(),
            2
        );
        assert!(
            verify_mutation_receipt(
                &scope(),
                &original,
                proto::ReceiptResponse {
                    scope: Some(wire_scope()),
                    request_digest: original.digest().unwrap(),
                    outcome: Some(proto::receipt_response::Outcome::Committed(valid.clone())),
                },
            )
            .is_ok()
        );

        let wrong = [
            wire_receipt(19, vec![version("/fi~1journal/attempt~01", 19)]),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/attempt~01", 19),
                    version("/fi~1journal/claim-2", 19),
                    version("/other-tenant/journal", 19),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/attempt~01", 19),
                    version("/fi~1journal/another-claim", 19),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/attempt~01", 19),
                    version("/fi~1journal/claim-2", 18),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/claim-2", 19),
                    version("/fi~1journal/attempt~01", 19),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/attempt~01", 19),
                    version("/fi~1journal/attempt~01", 19),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~1journal/attempt~1", 19),
                    version("/fi~1journal/claim-2", 19),
                ],
            ),
            wire_receipt(
                19,
                vec![
                    version("/fi~2journal/attempt~01", 19),
                    version("/fi~1journal/claim-2", 19),
                ],
            ),
            wire_receipt(0, valid.versions.clone()),
        ];
        for response in wrong {
            assert!(verify_committed_write_receipt(&original, response.clone()).is_err());
            assert!(
                verify_mutation_receipt(
                    &scope(),
                    &original,
                    proto::ReceiptResponse {
                        scope: Some(wire_scope()),
                        request_digest: original.digest().unwrap(),
                        outcome: Some(proto::receipt_response::Outcome::Committed(response)),
                    },
                )
                .is_err()
            );
        }
        let mut repeated_target = original.clone();
        repeated_target
            .operations
            .push(original.operations[0].clone());
        assert!(verify_committed_write_receipt(&repeated_target, valid).is_err());
    }

    #[test]
    fn duplicate_protobuf_version_entries_survive_raw_wire_and_fail_both_receipt_paths() {
        let original = original();
        let mut write_wire = wire_receipt(7, vec![version("/docs/same-id", 6)]).encode_to_vec();
        append_length_delimited(
            &mut write_wire,
            3,
            &version("/docs/same-id", 7).encode_to_vec(),
        );
        let direct = proto::WriteReceipt::decode(write_wire.as_slice()).unwrap();
        assert_eq!(
            direct.versions.len(),
            2,
            "duplicate raw rows must remain visible"
        );
        assert!(verify_committed_write_receipt(&original, direct).is_err());

        let mut retained_wire = Vec::new();
        append_length_delimited(&mut retained_wire, 1, &write_wire);
        append_length_delimited(&mut retained_wire, 3, original.digest().unwrap().as_bytes());
        append_length_delimited(&mut retained_wire, 4, &wire_scope().encode_to_vec());
        let retained = proto::ReceiptResponse::decode(retained_wire.as_slice()).unwrap();
        let Some(proto::receipt_response::Outcome::Committed(receipt)) = &retained.outcome else {
            panic!("raw retained committed receipt missing");
        };
        assert_eq!(receipt.versions.len(), 2);
        assert!(verify_mutation_receipt(&scope(), &original, retained).is_err());

        let same_revision = wire_receipt(
            7,
            vec![version("/docs/same-id", 7), version("/docs/same-id", 7)],
        );
        assert!(decode_write_receipt(same_revision).is_err());
    }

    #[test]
    fn non_mutation_write_replies_use_the_same_strict_row_decoder() {
        assert!(decode_write_receipt(wire_receipt(8, vec![])).is_ok());
        assert!(decode_write_receipt(wire_receipt(8, vec![version("/docs/same-id", 8)])).is_ok());
        let mut missing_contract = wire_receipt(8, vec![]);
        missing_contract.contract.clear();
        assert!(decode_write_receipt(missing_contract).is_err());
        let mut wrong_contract = wire_receipt(8, vec![]);
        wrong_contract.contract = "kasumi.write-receipt.v0".into();
        assert!(decode_write_receipt(wrong_contract).is_err());
        for wrong in [
            wire_receipt(0, vec![]),
            wire_receipt(8, vec![version("/docs/same-id", 7)]),
            wire_receipt(8, vec![version("docs/same-id", 8)]),
            wire_receipt(8, vec![version("/docs/same/id", 8)]),
            wire_receipt(8, vec![version("/docs/~2bad", 8)]),
            wire_receipt(8, vec![version("/docs/", 8)]),
            wire_receipt(8, vec![version("/docs/\n", 8)]),
            wire_receipt(
                8,
                vec![version("/docs/same-id", 8), version("/docs/same-id", 8)],
            ),
        ] {
            assert!(decode_write_receipt(wrong).is_err());
        }
    }

    #[test]
    fn former_map_wire_is_not_a_first_release_receipt() {
        let mut old_wire = vec![0x08, 7];
        append_length_delimited(
            &mut old_wire,
            2,
            &version("/docs/same-id", 7).encode_to_vec(),
        );
        if let Ok(decoded) = proto::WriteReceipt::decode(old_wire.as_slice()) {
            assert!(decode_write_receipt(decoded).is_err());
        }
    }

    #[test]
    fn rejected_and_absent_receipts_are_distinct_and_malformed_pairs_fail() {
        let original = original();
        let rejected = proto::ReceiptResponse {
            scope: Some(wire_scope()),
            request_digest: original.digest().unwrap(),
            outcome: Some(proto::receipt_response::Outcome::Rejected(
                proto::DatabaseError {
                    code: "CONFLICT".into(),
                    message: "original precondition failed".into(),
                },
            )),
        };
        assert_eq!(
            verify_mutation_receipt(&scope(), &original, rejected)
                .unwrap()
                .unwrap()
                .outcome
                .unwrap_err()
                .code,
            kasumi_types::ErrorCode::Conflict
        );
        assert!(
            verify_mutation_receipt(&scope(), &original, proto::ReceiptResponse::default())
                .unwrap()
                .is_none()
        );
        assert!(
            verify_mutation_receipt(
                &scope(),
                &original,
                proto::ReceiptResponse {
                    scope: Some(wire_scope()),
                    request_digest: original.digest().unwrap(),
                    outcome: None,
                }
            )
            .is_err()
        );
    }
}
