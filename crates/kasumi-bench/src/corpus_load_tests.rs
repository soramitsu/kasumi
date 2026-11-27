use super::*;
use std::{cell::RefCell, collections::VecDeque};

fn scope() -> MutationReceiptScope {
    MutationReceiptScope {
        tenant: "alpha".into(),
        incarnation: "8c5cbe63-0d55-4d6c-9a43-1f1f5d0f5a9e".into(),
        principal: "bench-app".into(),
    }
}

fn bounds() -> LoadBounds {
    LoadBounds {
        attempts: 4,
        budget_milliseconds: 5_000,
        initial_backoff_milliseconds: 1,
        maximum_backoff_milliseconds: 4,
        maximum_affected_batches: 2,
    }
}

fn batch() -> LoadBatch {
    LoadBatch::new(0, &[0, 3], 3, "unit-load-0".into(), scope()).unwrap()
}

fn written(revision: u64) -> WriteReceipt {
    WriteReceipt {
        revision,
        versions: [("/docs/0".into(), revision), ("/docs/3".into(), revision)].into(),
    }
}

fn retained(batch: &LoadBatch, outcome: kasumi_types::Result<WriteReceipt>) -> MutationReceipt {
    MutationReceipt {
        scope: batch.scope.clone(),
        request_digest: batch.digest.clone(),
        outcome,
    }
}

fn deadline() -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "write deadline exceeded; resolve or retry with the same idempotency key",
    )
}

/// Replies in order; the default after a script ends is still uncertain.
#[derive(Default)]
struct Script {
    sends: RefCell<VecDeque<kasumi_types::Result<WriteReceipt>>>,
    lookups: RefCell<VecDeque<kasumi_types::Result<Option<MutationReceipt>>>>,
    documents: RefCell<BTreeMap<String, (u64, String)>>,
    sent: RefCell<Vec<MutationBatch>>,
    stall: Option<Duration>,
}

impl Script {
    fn new(
        sends: impl IntoIterator<Item = kasumi_types::Result<WriteReceipt>>,
        lookups: impl IntoIterator<Item = kasumi_types::Result<Option<MutationReceipt>>>,
    ) -> Self {
        Self {
            sends: RefCell::new(sends.into_iter().collect()),
            lookups: RefCell::new(lookups.into_iter().collect()),
            ..Self::default()
        }
    }

    /// The durable state after `batch` committed once at `revision`.
    fn committed(self, batch: &LoadBatch, revision: u64) -> Self {
        for (id, body) in batch.targets() {
            let digest = staged_digest(&CanonicalJsonValue(body)).unwrap().0;
            self.documents
                .borrow_mut()
                .insert(id.to_owned(), (revision, digest));
        }
        self
    }
}

impl LoadTarget for Script {
    async fn send(&self, batch: MutationBatch) -> kasumi_types::Result<WriteReceipt> {
        self.sent.borrow_mut().push(batch);
        if let Some(stall) = self.stall {
            tokio::time::sleep(stall).await;
        }
        self.sends
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(deadline()))
    }
    async fn lookup(&self, key: &str) -> kasumi_types::Result<Option<MutationReceipt>> {
        assert_eq!(key, "unit-load-0");
        self.lookups.borrow_mut().pop_front().unwrap_or(Ok(None))
    }
    async fn observe(&self, id: &str) -> kasumi_types::Result<Option<(u64, String)>> {
        Ok(self.documents.borrow().get(id).cloned())
    }
}

async fn load(script: &Script, batch: &LoadBatch, bounds: &LoadBounds) -> BatchRecord {
    load_batch(script, batch, bounds, Instant::now()).await
}

fn actions(record: &BatchRecord) -> Vec<(&'static str, &'static str)> {
    record
        .steps
        .iter()
        .map(|step| (step.action, step.outcome))
        .collect()
}

fn tally(records: &[&BatchRecord]) -> LoadSummary {
    let mut tally = LoadTally::default();
    for record in records {
        tally.add(record);
    }
    tally.summary(bounds())
}

#[test]
fn digest_matches_the_release_verifier_reconstruction() {
    // scripts/verify_release_acceptance.py rebuilds the same canonical encoding.
    let batch = batch();
    assert_eq!(
        batch.digest,
        "dd19f062d74cb61fa8d6b56be2619c0c78325842c317d6c25abea052618997da"
    );
    assert_eq!(batch.canonical_bytes, 2048);
    let bodies: Vec<_> = batch
        .targets()
        .map(|(_, body)| staged_digest(&CanonicalJsonValue(body)).unwrap().0)
        .collect();
    assert_eq!(
        bodies,
        [
            "224169d68453ee4cc5a0461aa6d44ee016a711e5bfab723f74785e25aaa9a560",
            "25af119de508f39cf6e36570ed791d713f2856c46a3e308b1d6f41a08ab36f8b"
        ]
    );
    assert!(LoadBatch::new(0, &[], 3, "k".into(), scope()).is_err());
    let oversized: Vec<_> = (0..=BATCH_DOCUMENTS).collect();
    assert!(LoadBatch::new(0, &oversized, 1, "k".into(), scope()).is_err());
}

#[tokio::test]
async fn first_attempt_commit_needs_no_lookup_or_effect_reads() {
    let batch = batch();
    let script = Script::new([Ok(written(7))], []);
    let record = load(&script, &batch, &bounds()).await;
    assert!(record.settled());
    assert_eq!(record.resolution, FIRST_ATTEMPT);
    assert_eq!(actions(&record), [("send", "committed")]);
    assert_eq!(record.revision, Some(7));
    assert_eq!(
        record.elapsed_ns,
        record.steps[0].offset_ns + record.steps[0].elapsed_ns
    );
    assert!(record.receipt.is_none() && record.effects.is_none());
    assert_eq!(record.effects_elapsed_ns, 0);
    let row = serde_json::to_value(&record).unwrap();
    let fields: Vec<_> = row.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        fields.len(),
        17,
        "every row field is explicit, including nulls: {fields:?}"
    );
    assert!(row["failure"].is_null() && row["receipt"].is_null() && row["effects"].is_null());
    assert!(row["steps"][0]["code"].is_null() && row["steps"][0]["message"].is_null());
    let summary = tally(&[&record]);
    assert_eq!(
        (
            summary.batches,
            summary.documents,
            summary.canonical_bytes,
            summary.affected_batches,
            summary.first_attempt_deadline_misses,
            summary.resends,
            summary.lookups,
            summary.unresolved
        ),
        (1, 2, 2048, 0, 0, 0, 0, 0)
    );
    assert_eq!(summary.first_attempt_deadline_miss_rate, 0.0);
    let explicit = serde_json::to_value(&summary).unwrap();
    assert_eq!(explicit["unresolved"], 0);
    assert_eq!(explicit["first_attempt_deadline_miss_rate"], 0.0);
}

#[tokio::test]
async fn receipt_found_before_resend_settles_without_a_resend() {
    let batch = batch();
    let script = Script::new(
        [Err(deadline())],
        [Ok(Some(retained(&batch, Ok(written(7)))))],
    )
    .committed(&batch, 7);
    let record = load(&script, &batch, &bounds()).await;
    assert!(record.settled(), "{:?}", record.failure);
    assert_eq!(record.resolution, FOUND_BEFORE_RESEND);
    assert_eq!(
        actions(&record),
        [("send", "uncertain"), ("lookup", "found")]
    );
    assert_eq!(record.steps[0].code, Some("UNKNOWN_OUTCOME"));
    assert_eq!(script.sent.borrow().len(), 1);
    let receipt = record.receipt.as_ref().unwrap();
    assert_eq!(
        (
            &receipt.scope,
            receipt.request_digest.as_str(),
            receipt.revision
        ),
        (&batch.scope, batch.digest.as_str(), 7)
    );
    assert_eq!(receipt.versions, written(7).versions);
    let effects = record.effects.as_ref().unwrap();
    assert_eq!(
        effects
            .iter()
            .map(|e| (e.id.as_str(), e.version))
            .collect::<Vec<_>>(),
        [("0", 7), ("3", 7)]
    );
    let summary = tally(&[&record]);
    assert_eq!(
        (
            summary.affected_batches,
            summary.first_attempt_deadline_misses,
            summary.receipt_found_before_resend,
            summary.commit_confirmed_after_resend,
            summary.resends,
            summary.lookups
        ),
        (1, 1, 1, 0, 0, 1)
    );
    assert_eq!(summary.first_attempt_deadline_miss_rate, 1.0);
}

#[tokio::test]
async fn commit_confirmed_after_resend_and_a_refused_resend_settles_nothing() {
    let batch = batch();
    let script = Script::new(
        [
            Err(deadline()),
            Err(Error::new(ErrorCode::ResourceExhausted, "admission full")),
            Ok(written(9)),
        ],
        [
            Ok(None),
            Ok(None),
            Ok(Some(retained(&batch, Ok(written(9))))),
        ],
    )
    .committed(&batch, 9);
    let record = load(&script, &batch, &bounds()).await;
    assert!(record.settled(), "{:?}", record.failure);
    assert_eq!(record.resolution, CONFIRMED_AFTER_RESEND);
    assert_eq!(
        actions(&record),
        [
            ("send", "uncertain"),
            ("lookup", "absent"),
            ("backoff", "slept"),
            ("send", "refused"),
            ("lookup", "absent"),
            ("backoff", "slept"),
            ("send", "committed"),
            ("lookup", "found"),
        ]
    );
    // Every send is the identical batch under the same key.
    assert!(script.sent.borrow().iter().all(|sent| *sent == batch.batch));
    for pair in record.steps.windows(2) {
        assert!(pair[1].offset_ns >= pair[0].offset_ns + pair[0].elapsed_ns);
    }
    let summary = tally(&[&record]);
    assert_eq!(
        (
            summary.commit_confirmed_after_resend,
            summary.resends,
            summary.lookups
        ),
        (1, 2, 3)
    );
}

#[tokio::test]
async fn definitive_rejections_fail_the_batch() {
    let batch = batch();
    let script = Script::new([Err(Error::new(ErrorCode::Conflict, "exists"))], []);
    let record = load(&script, &batch, &bounds()).await;
    assert!(!record.settled());
    assert_eq!(record.resolution, UNRESOLVED);
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("definitively rejected")
    );
    assert_eq!(actions(&record), [("send", "refused")]);

    let script = Script::new(
        [Err(deadline())],
        [Ok(Some(retained(
            &batch,
            Err(Error::new(ErrorCode::QuotaExceeded, "tenant quota")),
        )))],
    );
    let record = load(&script, &batch, &bounds()).await;
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("definitive rejection")
    );
    assert_eq!(
        actions(&record),
        [("send", "uncertain"), ("lookup", "rejected")]
    );
    assert_eq!(script.sent.borrow().len(), 1, "a rejection is never resent");
    assert_eq!(tally(&[&record]).unresolved, 1);
}

#[tokio::test]
async fn mismatched_receipts_fail_the_batch() {
    let batch = batch();
    let mut other_input = retained(&batch, Ok(written(7)));
    other_input.request_digest = "0".repeat(64);
    let mut other_scope = retained(&batch, Ok(written(7)));
    other_scope.scope.incarnation = "another".into();
    let mut missing_version = written(7);
    missing_version.versions.remove("/docs/3");
    for (receipt, reason) in [
        (other_input, "identifies other input"),
        (other_scope, "another scope"),
        (
            retained(&batch, Ok(missing_version.clone())),
            "differs from the submitted batch",
        ),
    ] {
        let script = Script::new([Err(deadline())], [Ok(Some(receipt))]);
        let record = load(&script, &batch, &bounds()).await;
        assert!(
            record.failure.as_ref().unwrap().contains(reason),
            "{reason}"
        );
        assert_eq!(record.steps.last().unwrap().outcome, "mismatched");
        assert!(record.revision.is_none() && record.receipt.is_none());
    }

    let script = Script::new([Ok(missing_version)], []);
    let record = load(&script, &batch, &bounds()).await;
    assert_eq!(actions(&record), [("send", "mismatched")]);

    // A resend acknowledgement must be retained under the same identity.
    let script = Script::new([Err(deadline()), Ok(written(9))], [Ok(None), Ok(None)]);
    let record = load(&script, &batch, &bounds()).await;
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("acknowledged resend has no retained receipt")
    );

    // Durable state must show one effect at the receipt's revision.
    let script = Script::new(
        [Err(deadline())],
        [Ok(Some(retained(&batch, Ok(written(7)))))],
    )
    .committed(&batch, 8);
    let record = load(&script, &batch, &bounds()).await;
    assert_eq!(record.resolution, FOUND_BEFORE_RESEND);
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("one committed effect")
    );
    assert!(!record.settled());
    let script = Script::new(
        [Err(deadline())],
        [Ok(Some(retained(&batch, Ok(written(7)))))],
    );
    let record = load(&script, &batch, &bounds()).await;
    assert!(record.failure.as_ref().unwrap().contains("is missing"));
}

#[tokio::test]
async fn attempt_limit_and_budget_bound_resolution() {
    let batch = batch();
    let limited = LoadBounds {
        attempts: 3,
        ..bounds()
    };
    let script = Script::new([], []);
    let record = load(&script, &batch, &limited).await;
    assert_eq!(
        record.failure.as_deref(),
        Some("outcome unresolved after 3 sends")
    );
    assert_eq!(script.sent.borrow().len(), 3);
    assert_eq!(
        actions(&record)
            .iter()
            .filter(|(a, _)| *a == "lookup")
            .count(),
        3
    );

    let budget = LoadBounds {
        attempts: 100,
        budget_milliseconds: 200,
        initial_backoff_milliseconds: 20,
        maximum_backoff_milliseconds: 40,
        maximum_affected_batches: 1,
    };
    let stalled = Script {
        stall: Some(Duration::from_millis(30)),
        ..Script::default()
    };
    let record = load(&stalled, &batch, &budget).await;
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("budget exhausted"),
        "{:?}",
        record.failure
    );
    assert!(stalled.sent.borrow().len() < 100);
    assert!(record.elapsed_ns < 400_000_000, "{}", record.elapsed_ns);
    let slept: Vec<_> = record
        .steps
        .iter()
        .filter(|step| step.action == "backoff")
        .map(|step| step.elapsed_ns)
        .collect();
    assert!(!slept.is_empty() && slept.iter().all(|ns| *ns >= 20_000_000));

    // A stalled send is cut at the budget, not left to finish.
    let hung = Script {
        stall: Some(Duration::from_secs(30)),
        ..Script::default()
    };
    let record = load(&hung, &batch, &budget).await;
    assert_eq!(actions(&record), [("send", "expired")]);
    assert!(
        record
            .failure
            .as_ref()
            .unwrap()
            .contains("budget exhausted")
    );
}

#[test]
fn bounds_and_distributions_use_declared_values_and_nearest_rank() {
    assert!(bounds().validate().is_ok());
    for invalid in [
        LoadBounds {
            attempts: 0,
            ..bounds()
        },
        LoadBounds {
            initial_backoff_milliseconds: 5,
            ..bounds()
        },
        LoadBounds {
            maximum_backoff_milliseconds: 5_000,
            ..bounds()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    assert_eq!(distribution(vec![]), None);
    assert_eq!(
        distribution(vec![5, 1, 3, 2, 4]),
        Some(Distribution {
            p50: 3,
            p99: 5,
            max: 5
        })
    );
    assert_eq!(
        distribution((1..=100).rev().collect()),
        Some(Distribution {
            p50: 50,
            p99: 99,
            max: 100
        })
    );
}
