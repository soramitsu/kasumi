//! Resolve a retained mutation only against the exact original canonical input.
use crate::{ClientError, KasumiClient, proto};
use kasumi_types::{MutationBatch, MutationReceipt, MutationReceiptScope, WriteReceipt};

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
        proto::receipt_response::Outcome::Committed(receipt) => Ok(WriteReceipt {
            revision: receipt.revision,
            versions: receipt.versions.into_iter().collect(),
        }),
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
    ) -> Result<Option<MutationReceipt>, ClientError> {
        let response = self
            .inner
            .receipt(self.authorized(
                bearer,
                proto::ReceiptRequest {
                    idempotency_key: original.idempotency_key.clone(),
                },
            )?)
            .await?
            .into_inner();
        verify_mutation_receipt(expected_scope, original, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::{Mutation, Precondition};
    use serde_json::json;

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
                    versions: [("/docs/same-id".into(), 7)].into(),
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
