use super::*;
use std::sync::Mutex;

#[derive(Clone, Copy, Default)]
enum ReplyFault {
    #[default]
    None,
    BeforeDispatch,
    LostAfterCommit,
    LostAfterCommitWithoutReceipt,
}

#[derive(Default)]
struct QuotaState {
    records: BTreeMap<(String, String), Document>,
    receipts: BTreeMap<String, MutationReceipt>,
    dispatched: Vec<MutationBatch>,
    rejected: Option<ErrorCode>,
    fault: ReplyFault,
    hide_receipts: bool,
    resolve_unavailable: bool,
    revision: u64,
    committed_batches: usize,
    read_documents: usize,
}

/// Models the relevant server semantics: an exact receipt is permanent, including
/// quota refusals; replay precedes today's quota check; writes are atomic/absent-only.
#[derive(Clone, Default)]
struct QuotaBackend {
    state: Arc<Mutex<QuotaState>>,
    before_next_mutation: Option<Arc<tokio::sync::Barrier>>,
}

impl QuotaBackend {
    fn custody(&self) -> PrivateEvidenceCustody<Self> {
        PrivateEvidenceCustody::new(
            self.clone(),
            "evidence_manifests".into(),
            "evidence_chunks".into(),
            identity().scope,
            2 * CHUNK_BYTES + 1,
        )
        .unwrap()
    }
}

#[async_trait]
impl CustodyBackend for QuotaBackend {
    async fn mutate(&mut self, batch: &MutationBatch, _: Duration) -> anyhow::Result<WriteReceipt> {
        validate_append_batch(batch, "evidence_manifests", "evidence_chunks")?;
        if let Some(barrier) = self.before_next_mutation.take() {
            barrier.wait().await;
        }
        let mut state = self.state.lock().unwrap();
        state.dispatched.push(batch.clone());
        let digest = batch.digest()?;
        if let Some(receipt) = state.receipts.get(&batch.idempotency_key) {
            ensure!(receipt.request_digest == digest, "changed original batch");
            return Ok(receipt.outcome.clone()?);
        }
        let fault = std::mem::take(&mut state.fault);
        if matches!(fault, ReplyFault::BeforeDispatch) {
            bail!("request was not dispatched");
        }
        state.revision += 1;
        let revision = state.revision;
        let conflict = batch.operations.iter().any(|operation| {
            let (collection, id) = operation.target();
            state.records.contains_key(&(collection.into(), id.into()))
        });
        let outcome = if let Some(code) = state.rejected {
            Err(kasumi_types::Error::new(
                code,
                "configured terminal refusal",
            ))
        } else if conflict {
            Err(kasumi_types::Error::new(
                ErrorCode::Conflict,
                "document exists",
            ))
        } else {
            let mut versions = BTreeMap::new();
            for operation in &batch.operations {
                let Mutation::Put {
                    collection,
                    id,
                    body,
                    expected,
                } = operation
                else {
                    bail!("append-only puts required");
                };
                ensure!(*expected == Precondition::Absent, "overwrite refused");
                state.records.insert(
                    (collection.clone(), id.clone()),
                    Document {
                        id: id.clone(),
                        version: revision,
                        body: body.clone(),
                    },
                );
                versions.insert(document_receipt_path(collection, id), revision);
            }
            state.committed_batches += 1;
            Ok(WriteReceipt { revision, versions })
        };
        if !matches!(fault, ReplyFault::LostAfterCommitWithoutReceipt) {
            state.receipts.insert(
                batch.idempotency_key.clone(),
                MutationReceipt {
                    scope: identity().scope,
                    request_digest: digest,
                    outcome: outcome.clone(),
                },
            );
        }
        if matches!(
            fault,
            ReplyFault::LostAfterCommit | ReplyFault::LostAfterCommitWithoutReceipt
        ) {
            bail!("reply lost");
        }
        Ok(outcome?)
    }

    async fn resolve(
        &mut self,
        _: &MutationReceiptScope,
        original: &MutationBatch,
        _: Duration,
    ) -> anyhow::Result<Option<MutationReceipt>> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        ensure!(!state.resolve_unavailable, "receipt service unavailable");
        Ok(if state.hide_receipts {
            None
        } else {
            state.receipts.get(&original.idempotency_key).cloned()
        })
    }

    async fn read_records(
        &mut self,
        collection: &str,
        ids: &[String],
        _: Duration,
    ) -> anyhow::Result<Vec<Option<Document>>> {
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        state.read_documents += ids.len();
        Ok(ids
            .iter()
            .map(|id| state.records.get(&(collection.into(), id.clone())).cloned())
            .collect())
    }
}

const RETRY_TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn reject_original(backend: &QuotaBackend) {
    backend.state.lock().unwrap().rejected = Some(ErrorCode::QuotaExceeded);
    let result = backend
        .custody()
        .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
        .await;
    assert!(matches!(result, Err(CustodyError::Rejected)));
    let state = backend.state.lock().unwrap();
    assert_eq!(
        state.receipts.len(),
        1,
        "a fresh quota refusal ends this invocation"
    );
    assert!(state.records.is_empty());
}

#[tokio::test]
async fn quota_recovery_survives_restart_and_preserves_originals() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    backend.state.lock().unwrap().rejected = None;
    let outcome = backend
        .custody()
        .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(outcome, vec![AppendOutcome::Recovered]);
    let restored = backend
        .custody()
        .read(&component(0), RETRY_TEST_TIMEOUT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.bytes, b"original");
    let state = backend.state.lock().unwrap();
    assert_eq!(state.receipts.len(), 2);
    assert_eq!(state.committed_batches, 1);
    assert_eq!(
        state.dispatched[0].operations,
        state.dispatched[1].operations
    );
    assert_ne!(
        state.dispatched[0].idempotency_key,
        state.dispatched[1].idempotency_key
    );
}

#[tokio::test]
async fn single_component_append_recovers_its_quota_rejected_chunk() {
    let backend = QuotaBackend::default();
    backend.state.lock().unwrap().rejected = Some(ErrorCode::QuotaExceeded);
    assert!(matches!(
        backend
            .custody()
            .append(&component(0), b"single", RETRY_TEST_TIMEOUT)
            .await,
        Err(CustodyError::Rejected)
    ));
    backend.state.lock().unwrap().rejected = None;
    assert_eq!(
        backend
            .custody()
            .append(&component(0), b"single", RETRY_TEST_TIMEOUT)
            .await
            .unwrap(),
        AppendOutcome::Recovered
    );
    let state = backend.state.lock().unwrap();
    assert_eq!(
        state.receipts.len(),
        3,
        "failed chunk, successor chunk, manifest"
    );
    assert_eq!(state.committed_batches, 2);
    assert_eq!(
        state.dispatched[0].operations,
        state.dispatched[1].operations
    );
}

#[tokio::test]
async fn quota_refusal_with_an_orphan_chunk_retains_only_the_missing_manifest() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    let documents = backend
        .custody()
        .component_documents(&component(0), b"original", 0)
        .unwrap();
    let chunk = &documents[0];
    {
        let mut state = backend.state.lock().unwrap();
        state.rejected = None;
        state.records.insert(
            (chunk.collection.clone(), chunk.id.clone()),
            Document {
                id: chunk.id.clone(),
                version: 100,
                body: chunk.body.clone(),
            },
        );
    }
    backend
        .custody()
        .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
        .await
        .unwrap();
    let restored = backend
        .custody()
        .read(&component(0), RETRY_TEST_TIMEOUT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.bytes, b"original");
    let state = backend.state.lock().unwrap();
    assert_eq!(state.dispatched.len(), 2);
    assert_eq!(state.dispatched[1].operations.len(), 1);
    assert_eq!(
        state.dispatched[1].operations[0].target().1,
        component(0).manifest_id()
    );
    assert_eq!(
        state.records[&(chunk.collection.clone(), chunk.id.clone())].version,
        100,
        "the existing chunk must never be rewritten"
    );
}

#[tokio::test]
async fn quota_refusal_with_conflicting_retained_chunk_never_dispatches_successor() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    let documents = backend
        .custody()
        .component_documents(&component(0), b"original", 0)
        .unwrap();
    let chunk = &documents[0];
    {
        let mut state = backend.state.lock().unwrap();
        state.rejected = None;
        let mut altered = chunk.body.clone();
        altered["data_hex"] = "00".into();
        state.records.insert(
            (chunk.collection.clone(), chunk.id.clone()),
            Document {
                id: chunk.id.clone(),
                version: 100,
                body: altered,
            },
        );
    }
    assert!(matches!(
        backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await,
        Err(CustodyError::Conflict)
    ));
    assert_eq!(backend.state.lock().unwrap().dispatched.len(), 1);
}

#[tokio::test]
async fn persistent_quota_records_one_new_refusal_per_invocation_then_exhausts() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    for attempt in 1..=MAX_QUOTA_RETRIES {
        let result = backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await;
        assert!(
            matches!(result, Err(CustodyError::Rejected)),
            "attempt {attempt}: {result:?}"
        );
        let state = backend.state.lock().unwrap();
        assert_eq!(state.receipts.len(), attempt + 1);
        assert_eq!(state.dispatched.len(), attempt + 1);
    }
    backend.state.lock().unwrap().rejected = None;
    assert!(matches!(
        backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await,
        Err(CustodyError::RetryLimitReached)
    ));
    let state = backend.state.lock().unwrap();
    assert_eq!(state.receipts.len(), MAX_QUOTA_RETRIES + 1);
    assert_eq!(state.dispatched.len(), MAX_QUOTA_RETRIES + 1);
    assert!(state.records.is_empty());
}

#[tokio::test]
async fn deep_quota_history_reads_each_document_once_before_successor() {
    let backend = QuotaBackend::default();
    let mut custody = backend.custody();
    let documents: Vec<_> = (0..MAX_APPEND_BATCH_DOCUMENTS / 2)
        .flat_map(|index| {
            custody
                .component_documents(&component(index), b"original", index)
                .unwrap()
        })
        .collect();
    let original = append_batch(&documents).unwrap();
    validate_append_batch(&original, "evidence_manifests", "evidence_chunks").unwrap();
    {
        let mut state = backend.state.lock().unwrap();
        for attempt in 0..MAX_QUOTA_RETRIES {
            let mut refused = original.clone();
            if attempt > 0 {
                refused.idempotency_key = quota_retry_key(&original, attempt).unwrap();
            }
            state.receipts.insert(
                refused.idempotency_key.clone(),
                MutationReceipt {
                    scope: identity().scope,
                    request_digest: refused.digest().unwrap(),
                    outcome: Err(kasumi_types::Error::new(
                        ErrorCode::QuotaExceeded,
                        "retained quota refusal",
                    )),
                },
            );
        }
    }
    let (receipt, recovered) = custody
        .put_batch(&original, Instant::now() + RETRY_TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(receipt.is_some());
    assert!(recovered);
    let state = backend.state.lock().unwrap();
    assert_eq!(state.read_documents, MAX_APPEND_BATCH_DOCUMENTS);
    assert_eq!(state.dispatched.len(), 1);
    assert_eq!(state.committed_batches, 1);
    assert_eq!(state.receipts.len(), MAX_QUOTA_RETRIES + 1);
    assert_eq!(
        state.dispatched[0].idempotency_key,
        quota_retry_key(&original, MAX_QUOTA_RETRIES).unwrap()
    );
}

#[tokio::test]
async fn concurrent_recovery_uses_one_successor_and_one_commit() {
    let mut backend = QuotaBackend::default();
    reject_original(&backend).await;
    backend.state.lock().unwrap().rejected = None;
    backend.before_next_mutation = Some(Arc::new(tokio::sync::Barrier::new(2)));
    let mut first = backend.custody();
    let mut second = backend.custody();
    let components = [(component(0), &b"original"[..])];
    let (a, b) = tokio::time::timeout(RETRY_TEST_TIMEOUT, async {
        tokio::join!(
            first.append_many(&components, RETRY_TEST_TIMEOUT),
            second.append_many(&components, RETRY_TEST_TIMEOUT)
        )
    })
    .await
    .expect("concurrent successor requests must finish");
    assert_eq!(a.unwrap(), vec![AppendOutcome::Recovered]);
    assert_eq!(b.unwrap(), vec![AppendOutcome::Recovered]);
    let state = backend.state.lock().unwrap();
    assert_eq!(state.receipts.len(), 2);
    assert_eq!(state.committed_batches, 1);
    assert_eq!(state.dispatched.len(), 3);
    assert_eq!(state.dispatched[1], state.dispatched[2]);
}

#[tokio::test]
async fn lost_successful_successor_reply_resolves_without_another_attempt() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    {
        let mut state = backend.state.lock().unwrap();
        state.rejected = None;
        state.fault = ReplyFault::LostAfterCommit;
    }
    assert_eq!(
        backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await
            .unwrap(),
        vec![AppendOutcome::Recovered]
    );
    let state = backend.state.lock().unwrap();
    assert_eq!(state.receipts.len(), 2);
    assert_eq!(state.dispatched.len(), 2);
    assert_eq!(state.committed_batches, 1);
}

#[tokio::test]
async fn unknown_successor_outcome_does_not_advance_and_restart_reuses_it() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    {
        let mut state = backend.state.lock().unwrap();
        state.rejected = None;
        state.fault = ReplyFault::BeforeDispatch;
    }
    let result = backend
        .custody()
        .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
        .await;
    let Err(CustodyError::UnknownOutcome(key)) = result else {
        panic!("outcome must remain unknown: {result:?}")
    };
    assert_eq!(backend.state.lock().unwrap().receipts.len(), 1);
    backend
        .custody()
        .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
        .await
        .unwrap();
    let state = backend.state.lock().unwrap();
    assert_eq!(state.dispatched.len(), 3);
    assert_eq!(state.dispatched[1], state.dispatched[2]);
    assert_eq!(state.dispatched[1].idempotency_key, key);
}

#[tokio::test]
async fn lost_commit_without_receipt_stays_unknown_until_exact_readback() {
    let backend = QuotaBackend::default();
    reject_original(&backend).await;
    {
        let mut state = backend.state.lock().unwrap();
        state.rejected = None;
        state.fault = ReplyFault::LostAfterCommitWithoutReceipt;
    }
    assert!(matches!(
        backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await,
        Err(CustodyError::UnknownOutcome(_))
    ));
    assert_eq!(
        backend
            .custody()
            .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
            .await
            .unwrap(),
        vec![AppendOutcome::AlreadyPresent]
    );
    let state = backend.state.lock().unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.dispatched.len(), 2);
    assert_eq!(state.committed_batches, 1);
}

#[tokio::test]
async fn absent_or_unavailable_receipt_never_authorizes_successor() {
    for unavailable in [false, true] {
        let backend = QuotaBackend::default();
        reject_original(&backend).await;
        {
            let mut state = backend.state.lock().unwrap();
            state.rejected = None;
            state.hide_receipts = !unavailable;
            state.resolve_unavailable = unavailable;
        }
        assert!(matches!(
            backend
                .custody()
                .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
                .await,
            Err(CustodyError::UnknownOutcome(_))
        ));
        let state = backend.state.lock().unwrap();
        assert_eq!(state.receipts.len(), 1);
        assert!(state.records.is_empty());
        assert!(
            state
                .dispatched
                .iter()
                .all(|batch| batch.idempotency_key == state.dispatched[0].idempotency_key)
        );
    }
}

#[tokio::test]
async fn changed_scope_digest_or_original_bytes_never_authorizes_recovery() {
    for fault in ["scope", "digest", "bytes"] {
        let backend = QuotaBackend::default();
        reject_original(&backend).await;
        {
            let mut state = backend.state.lock().unwrap();
            state.rejected = None;
            let receipt = state.receipts.values_mut().next().unwrap();
            if fault == "scope" {
                receipt.scope.principal = "another-principal".into();
            }
            if fault == "digest" {
                receipt.request_digest = "ff".repeat(32);
            }
        }
        let bytes: &[u8] = if fault == "bytes" {
            b"changed"
        } else {
            b"original"
        };
        assert!(
            matches!(
                backend
                    .custody()
                    .append_many(&[(component(0), bytes)], RETRY_TEST_TIMEOUT)
                    .await,
                Err(CustodyError::Inconsistent)
            ),
            "{fault}"
        );
        assert_eq!(backend.state.lock().unwrap().dispatched.len(), 1);
    }
}

#[tokio::test]
async fn nonquota_terminal_refusals_do_not_receive_new_attempts() {
    for code in [
        ErrorCode::Forbidden,
        ErrorCode::SchemaViolation,
        ErrorCode::Conflict,
        ErrorCode::ResourceExhausted,
    ] {
        let backend = QuotaBackend::default();
        backend.state.lock().unwrap().rejected = Some(code);
        assert!(matches!(
            backend
                .custody()
                .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
                .await,
            Err(CustodyError::Rejected)
        ));
        backend.state.lock().unwrap().rejected = None;
        assert!(matches!(
            backend
                .custody()
                .append_many(&[(component(0), b"original")], RETRY_TEST_TIMEOUT)
                .await,
            Err(CustodyError::Rejected)
        ));
        let state = backend.state.lock().unwrap();
        assert_eq!(state.receipts.len(), 1);
        assert_eq!(state.dispatched.len(), 1);
        assert!(state.records.is_empty());
    }
}

#[test]
fn successor_admission_binds_exact_original_and_canonical_attempt_number() {
    let backend = QuotaBackend::default();
    let custody = backend.custody();
    let documents = custody
        .component_documents(&component(0), b"original", 0)
        .unwrap();
    let original = append_batch(&documents).unwrap();
    let mut candidate = original.clone();
    candidate.idempotency_key = quota_retry_key(&original, 1).unwrap();
    validate_append_batch(&candidate, "evidence_manifests", "evidence_chunks").unwrap();
    for suffix in ["0", "01", "+1", "65", "1/2"] {
        let mut wrong = candidate.clone();
        wrong.idempotency_key =
            format!("{RETRY_KEY_PREFIX}{}/{suffix}", original.digest().unwrap());
        assert!(validate_append_batch(&wrong, "evidence_manifests", "evidence_chunks").is_err());
    }
    let Mutation::Put { body, .. } = &mut candidate.operations[0] else {
        unreachable!()
    };
    body["data_hex"] = "00".into();
    assert!(validate_append_batch(&candidate, "evidence_manifests", "evidence_chunks").is_err());
}
