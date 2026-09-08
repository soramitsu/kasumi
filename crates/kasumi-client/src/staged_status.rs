use crate::ClientError;
use kasumi_types::{StagedTransactionRef, StagedTransactionStatus, staged_digest};

pub(crate) fn decode(
    bytes: &[u8],
    expected: &StagedTransactionRef,
) -> Result<StagedTransactionStatus, ClientError> {
    let status: StagedTransactionStatus = serde_json::from_slice(bytes)?;
    if status.transaction != *expected
        || staged_digest(&status.manifest)
            .ok()
            .map(|value| value.0)
            .as_ref()
            != Some(&expected.manifest_digest)
    {
        return Err(ClientError::InvalidResponse(
            "staged status differs from the original scope and manifest",
        ));
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::*;
    #[test]
    fn rejects_foreign_status_scope_and_missing_original_identity() {
        let begin = BeginStagedTransaction {
            scope: StagedTransactionScope {
                tenant: "tenant".into(),
                incarnation: "original".into(),
                principal: "owner".into(),
            },
            transaction_id: "transaction".into(),
            ttl_ms: 60_000,
            manifest: StagedManifest::from_chunks(&[StagedChunk {
                read_set: vec![],
                operations: vec![Mutation::Delete {
                    collection: "rows".into(),
                    id: "row".into(),
                    expected: Precondition::Any,
                }],
            }])
            .unwrap(),
        };
        let expected = begin.reference().unwrap();
        let status = StagedTransactionStatus {
            transaction: expected.clone(),
            manifest: begin.manifest,
            received_chunks: vec![],
            expires_at_ms: None,
            outcome: StagedOutcome::Aborted {
                receipt: WriteReceipt {
                    revision: 10,
                    versions: Default::default(),
                },
            },
        };
        let bytes = serde_json::to_vec(&status).unwrap();
        decode(&bytes, &expected).unwrap();
        for field in 0..6 {
            let mut bad = status.clone();
            match field {
                0 => bad.transaction.scope.principal = "replacement".into(),
                1 => bad.transaction.scope.tenant = "other".into(),
                2 => bad.transaction.scope.incarnation = "new".into(),
                3 => bad.transaction.transaction_id = "other".into(),
                4 => bad.transaction.manifest_digest = "9".repeat(64),
                _ => bad.manifest.encoded_chunk_bytes += 1,
            }
            assert!(
                decode(&serde_json::to_vec(&bad).unwrap(), &expected).is_err(),
                "field {field}"
            );
        }
        let mut missing = serde_json::to_value(&status).unwrap();
        missing["transaction"]
            .as_object_mut()
            .unwrap()
            .remove("scope");
        assert!(decode(&serde_json::to_vec(&missing).unwrap(), &expected).is_err());
    }
}
