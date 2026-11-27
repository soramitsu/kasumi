//! Installed corpus loading under the documented client contract for an
//! uncertain write (`UNKNOWN_OUTCOME` in docs/operations.md).
//!
//! A logical batch keeps its exact value, request digest, idempotency key and
//! receipt scope (tenant, incarnation, principal) from before its first
//! dispatch. After a typed uncertain outcome the driver first looks up the
//! retained receipt. While the outcome stays unknown it resends the identical
//! batch under the same identity, with capped exponential backoff, a fixed send
//! limit and one elapsed-time budget covering every send, lookup and sleep.
//! Only a retained receipt that matches the scope, digest and every target
//! version settles a disputed batch. A refusal on resend never settles the
//! earlier attempt. Every step and its elapsed time is recorded.
//!
//! The labels say only what the evidence shows. `receipt found before resend`
//! means a lookup found the receipt before any resend was dispatched.
//! `commit confirmed after resend` means it settled after at least one resend;
//! an identical resend returns the stored outcome whichever attempt applied.
use crate::raw::document_body;
use anyhow::{Result, ensure};
use kasumi_types::{
    CanonicalJsonValue, Error, ErrorCode, Mutation, MutationBatch, MutationReceipt,
    MutationReceiptScope, Precondition, WriteReceipt, staged_digest,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, time::Duration};
use tokio::time::{Instant, timeout_at};

/// Documents per logical load batch.
pub const BATCH_DOCUMENTS: usize = 256;
pub const FIRST_ATTEMPT: &str = "acknowledged on first attempt";
pub const FOUND_BEFORE_RESEND: &str = "receipt found before resend";
pub const CONFIRMED_AFTER_RESEND: &str = "commit confirmed after resend";
pub const UNRESOLVED: &str = "unresolved";
/// The engine's message prefix when the native write deadline elapses.
pub const DEADLINE_MISS: &str = "write deadline exceeded";

/// Resolution bounds, declared in the hash-bound plan before the run.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoadBounds {
    /// Sends per logical batch, including the first attempt.
    pub attempts: u32,
    /// One budget per batch from its first dispatch: sends, lookups and sleeps.
    /// Document-effect reads after settlement get a separate budget of the same length.
    pub budget_milliseconds: u64,
    pub initial_backoff_milliseconds: u64,
    pub maximum_backoff_milliseconds: u64,
    /// Batches whose first attempt may end uncertain before the case fails.
    pub maximum_affected_batches: u64,
}

impl LoadBounds {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.attempts >= 1
                && self.budget_milliseconds > 0
                && self.initial_backoff_milliseconds > 0
                && self.initial_backoff_milliseconds <= self.maximum_backoff_milliseconds
                && self.maximum_backoff_milliseconds < self.budget_milliseconds,
            "invalid corpus load bounds"
        );
        Ok(())
    }
    fn budget(&self) -> Duration {
        Duration::from_millis(self.budget_milliseconds)
    }
}

/// One logical batch and the identity retained before its first dispatch.
#[derive(Clone, Debug)]
pub struct LoadBatch {
    pub sequence: u64,
    pub first: usize,
    pub canonical_bytes: u64,
    pub scope: MutationReceiptScope,
    pub digest: String,
    pub batch: MutationBatch,
}

impl LoadBatch {
    /// The deterministic corpus batch for these tenant-strided ordinals: version
    /// 0 bodies with `absent` preconditions, digested before any dispatch.
    pub fn new(
        sequence: u64,
        ordinals: &[usize],
        tenants: usize,
        idempotency_key: String,
        scope: MutationReceiptScope,
    ) -> Result<Self> {
        ensure!(
            !ordinals.is_empty() && ordinals.len() <= BATCH_DOCUMENTS,
            "corpus batch size outside bounds"
        );
        let mut canonical_bytes = 0;
        let mut operations = Vec::with_capacity(ordinals.len());
        for &ordinal in ordinals {
            let body = document_body(ordinal, 0, tenants);
            canonical_bytes += serde_json::to_vec(&body)?.len() as u64;
            operations.push(Mutation::Put {
                collection: "docs".into(),
                id: ordinal.to_string(),
                body,
                expected: Precondition::Absent,
            });
        }
        let batch = MutationBatch {
            read_set: vec![],
            idempotency_key,
            operations,
        };
        let digest = batch.digest()?;
        Ok(Self {
            sequence,
            first: ordinals[0],
            canonical_bytes,
            scope,
            digest,
            batch,
        })
    }

    pub fn documents(&self) -> usize {
        self.batch.operations.len()
    }

    fn targets(&self) -> impl Iterator<Item = (&str, &serde_json::Value)> {
        self.batch
            .operations
            .iter()
            .map(|operation| match operation {
                Mutation::Put { id, body, .. } => (id.as_str(), body),
                _ => unreachable!("corpus batches contain only puts"),
            })
    }

    /// A commit of exactly this batch: one new version per target at its revision.
    fn check(&self, receipt: &WriteReceipt) -> std::result::Result<(), String> {
        let exact = receipt.revision > 0
            && receipt.versions.len() == self.documents()
            && self.targets().all(|(id, _)| {
                receipt.versions.get(&format!("/docs/{id}")) == Some(&receipt.revision)
            });
        if exact {
            Ok(())
        } else {
            Err("write receipt differs from the submitted batch targets".into())
        }
    }

    /// Settle by a retained receipt only when it identifies this exact invocation.
    fn retained(
        &self,
        receipt: MutationReceipt,
    ) -> std::result::Result<(WriteReceipt, RetainedReceipt), (&'static str, String)> {
        if receipt.scope != self.scope {
            return Err((
                "mismatched",
                "retained receipt belongs to another scope".into(),
            ));
        }
        if receipt.request_digest != self.digest {
            return Err((
                "mismatched",
                "retained receipt identifies other input".into(),
            ));
        }
        let written = match receipt.outcome {
            Ok(written) => written,
            Err(error) => {
                return Err((
                    "rejected",
                    format!("retained outcome is a definitive rejection: {error}"),
                ));
            }
        };
        self.check(&written)
            .map_err(|failure| ("mismatched", failure))?;
        let retained = RetainedReceipt {
            scope: receipt.scope,
            request_digest: receipt.request_digest,
            revision: written.revision,
            versions: written.versions.clone(),
        };
        Ok((written, retained))
    }
}

/// The installed operations one tenant's load uses.
pub trait LoadTarget {
    fn send(
        &self,
        batch: MutationBatch,
    ) -> impl Future<Output = kasumi_types::Result<WriteReceipt>>;
    fn lookup(
        &self,
        idempotency_key: &str,
    ) -> impl Future<Output = kasumi_types::Result<Option<MutationReceipt>>>;
    /// The committed version and canonical body SHA-256 of one corpus document.
    fn observe(
        &self,
        id: &str,
    ) -> impl Future<Output = kasumi_types::Result<Option<(u64, String)>>>;
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Step {
    /// `send`, `lookup` or `backoff`.
    pub action: &'static str,
    /// From the batch's first dispatch.
    pub offset_ns: u64,
    pub elapsed_ns: u64,
    /// send: committed, uncertain, refused, mismatched or expired;
    /// lookup: found, absent, uncertain, refused, mismatched, rejected or expired;
    /// backoff: slept.
    pub outcome: &'static str,
    pub code: Option<&'static str>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RetainedReceipt {
    pub scope: MutationReceiptScope,
    pub request_digest: String,
    pub revision: u64,
    pub versions: BTreeMap<String, u64>,
}

/// Durable document state read after a disputed batch settled.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Effect {
    pub id: String,
    pub version: u64,
    pub body_sha256: String,
}

/// One ordered row of `load-batches.jsonl`.
#[derive(Clone, Debug, Serialize)]
pub struct BatchRecord {
    pub sequence: u64,
    pub tenant: String,
    pub first: usize,
    pub documents: usize,
    pub canonical_bytes: u64,
    pub idempotency_key: String,
    pub request_digest: String,
    pub scope: MutationReceiptScope,
    /// First dispatch, from the start of the load phase.
    pub started_ns: u64,
    /// First dispatch to the end of the settling step.
    pub elapsed_ns: u64,
    pub steps: Vec<Step>,
    pub resolution: &'static str,
    pub failure: Option<String>,
    pub revision: Option<u64>,
    /// Disputed batches only: the retained receipt that settled them.
    pub receipt: Option<RetainedReceipt>,
    /// Disputed batches only: one committed effect per target.
    pub effects: Option<Vec<Effect>>,
    pub effects_elapsed_ns: u64,
}

impl BatchRecord {
    pub fn settled(&self) -> bool {
        self.failure.is_none() && self.resolution != UNRESOLVED
    }
    fn first_step(&self) -> Option<&Step> {
        self.steps.first()
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn uncertain(error: &Error) -> bool {
    matches!(
        error.code,
        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
    )
}

enum Sent {
    Committed(WriteReceipt),
    Uncertain,
    Refused(Error),
    Expired,
}

enum Looked {
    Settled(WriteReceipt, RetainedReceipt),
    Absent,
    Unsettled,
    Expired,
}

type Settlement = (&'static str, WriteReceipt, Option<RetainedReceipt>);

struct Attempts<'a, T> {
    target: &'a T,
    batch: &'a LoadBatch,
    start: Instant,
    end: Instant,
    steps: Vec<Step>,
}

impl<T: LoadTarget> Attempts<'_, T> {
    fn record(
        &mut self,
        action: &'static str,
        begun: Instant,
        outcome: &'static str,
        error: Option<Error>,
    ) {
        self.steps.push(Step {
            action,
            offset_ns: nanos(begun.duration_since(self.start)),
            elapsed_ns: nanos(begun.elapsed()),
            outcome,
            code: error.as_ref().map(|error| error.code.as_str()),
            message: error.map(|error| error.message),
        });
    }

    fn mark(&mut self, outcome: &'static str) {
        if let Some(step) = self.steps.last_mut() {
            step.outcome = outcome;
        }
    }

    async fn send(&mut self) -> Sent {
        // Clone outside the timed step: the attempt starts at dispatch.
        let value = self.batch.batch.clone();
        let begun = Instant::now();
        match timeout_at(self.end, self.target.send(value)).await {
            Err(_) => {
                self.record("send", begun, "expired", None);
                Sent::Expired
            }
            Ok(Ok(receipt)) => {
                self.record("send", begun, "committed", None);
                Sent::Committed(receipt)
            }
            Ok(Err(error)) if uncertain(&error) => {
                self.record("send", begun, "uncertain", Some(error));
                Sent::Uncertain
            }
            Ok(Err(error)) => {
                self.record("send", begun, "refused", Some(error.clone()));
                Sent::Refused(error)
            }
        }
    }

    async fn lookup(&mut self) -> std::result::Result<Looked, String> {
        let begun = Instant::now();
        let key = &self.batch.batch.idempotency_key;
        let (outcome, error, looked) = match timeout_at(self.end, self.target.lookup(key)).await {
            Err(_) => ("expired", None, Ok(Looked::Expired)),
            Ok(Err(error)) => (
                if uncertain(&error) {
                    "uncertain"
                } else {
                    "refused"
                },
                Some(error),
                Ok(Looked::Unsettled),
            ),
            Ok(Ok(None)) => ("absent", None, Ok(Looked::Absent)),
            Ok(Ok(Some(receipt))) => match self.batch.retained(receipt) {
                Ok((written, retained)) => ("found", None, Ok(Looked::Settled(written, retained))),
                Err((outcome, failure)) => (outcome, None, Err(failure)),
            },
        };
        self.record("lookup", begun, outcome, error);
        looked
    }

    /// Sleep `delay` unless it would leave no budget for another step.
    async fn backoff(&mut self, delay: Duration) -> bool {
        let begun = Instant::now();
        if begun + delay >= self.end {
            return false;
        }
        tokio::time::sleep(delay).await;
        self.record("backoff", begun, "slept", None);
        true
    }

    async fn resolve(&mut self, bounds: &LoadBounds) -> std::result::Result<Settlement, String> {
        let budget = || "resolution budget exhausted with the outcome unresolved".to_owned();
        match self.send().await {
            Sent::Committed(receipt) => {
                return match self.batch.check(&receipt) {
                    Ok(()) => Ok((FIRST_ATTEMPT, receipt, None)),
                    Err(failure) => {
                        self.mark("mismatched");
                        Err(failure)
                    }
                };
            }
            Sent::Uncertain => {}
            Sent::Refused(error) => {
                return Err(format!("first attempt was definitively rejected: {error}"));
            }
            Sent::Expired => return Err(budget()),
        }
        let mut sends = 1;
        let mut confirmations = 0;
        let mut acknowledged: Option<WriteReceipt> = None;
        let mut delay = Duration::from_millis(bounds.initial_backoff_milliseconds);
        let ceiling = Duration::from_millis(bounds.maximum_backoff_milliseconds);
        loop {
            match self.lookup().await? {
                Looked::Settled(receipt, retained) => {
                    if acknowledged
                        .as_ref()
                        .is_some_and(|resent| *resent != receipt)
                    {
                        self.mark("mismatched");
                        return Err("retained receipt differs from the acknowledged resend".into());
                    }
                    let label = if sends > 1 {
                        CONFIRMED_AFTER_RESEND
                    } else {
                        FOUND_BEFORE_RESEND
                    };
                    return Ok((label, receipt, Some(retained)));
                }
                Looked::Absent if acknowledged.is_some() => {
                    return Err("an acknowledged resend has no retained receipt".into());
                }
                Looked::Expired => return Err(budget()),
                Looked::Absent | Looked::Unsettled => {}
            }
            if acknowledged.is_some() {
                confirmations += 1;
                if confirmations >= bounds.attempts {
                    return Err("retained receipt confirmation exhausted its attempts".into());
                }
            } else if sends >= bounds.attempts {
                return Err(format!("outcome unresolved after {sends} sends"));
            }
            if !self.backoff(delay).await {
                return Err(budget());
            }
            delay = (delay * 2).min(ceiling);
            if acknowledged.is_some() {
                continue;
            }
            sends += 1;
            match self.send().await {
                Sent::Committed(receipt) => match self.batch.check(&receipt) {
                    Ok(()) => acknowledged = Some(receipt),
                    Err(failure) => {
                        self.mark("mismatched");
                        return Err(failure);
                    }
                },
                // A refusal on resend cannot settle the earlier attempt; only a
                // retained receipt can.
                Sent::Uncertain | Sent::Refused(_) => {}
                Sent::Expired => return Err(budget()),
            }
        }
    }
}

/// Read every target of a settled disputed batch: exactly one committed effect
/// at the receipt's revision with the submitted body.
async fn effects<T: LoadTarget>(
    target: &T,
    batch: &LoadBatch,
    receipt: &WriteReceipt,
    bounds: &LoadBounds,
) -> std::result::Result<Vec<Effect>, String> {
    let end = Instant::now() + bounds.budget();
    let pause = Duration::from_millis(bounds.initial_backoff_milliseconds);
    let mut observed = Vec::with_capacity(batch.documents());
    for (id, body) in batch.targets() {
        let expected = staged_digest(&CanonicalJsonValue(body))
            .map_err(|error| format!("corpus body cannot be digested: {error}"))?
            .0;
        loop {
            match timeout_at(end, target.observe(id)).await {
                Err(_) => return Err("document effect evidence budget exhausted".into()),
                Ok(Ok(Some((version, body_sha256)))) => {
                    if version != receipt.revision
                        || receipt.versions.get(&format!("/docs/{id}")) != Some(&version)
                        || body_sha256 != expected
                    {
                        return Err(format!(
                            "document {id} does not show one committed effect at revision {}",
                            receipt.revision
                        ));
                    }
                    observed.push(Effect {
                        id: id.to_owned(),
                        version,
                        body_sha256,
                    });
                    break;
                }
                Ok(Ok(None)) => return Err(format!("committed document {id} is missing")),
                Ok(Err(error)) if uncertain(&error) => {
                    if Instant::now() + pause >= end {
                        return Err("document effect evidence budget exhausted".into());
                    }
                    tokio::time::sleep(pause).await;
                }
                Ok(Err(error)) => return Err(format!("document {id} read refused: {error}")),
            }
        }
    }
    Ok(observed)
}

/// Load one logical batch to a verified commit, or record why it did not settle.
pub async fn load_batch<T: LoadTarget>(
    target: &T,
    batch: &LoadBatch,
    bounds: &LoadBounds,
    load_started: Instant,
) -> BatchRecord {
    let start = Instant::now();
    let mut attempts = Attempts {
        target,
        batch,
        start,
        end: start + bounds.budget(),
        steps: Vec::new(),
    };
    let settled = attempts.resolve(bounds).await;
    let steps = attempts.steps;
    let elapsed_ns = steps
        .last()
        .map_or(0, |step| step.offset_ns.saturating_add(step.elapsed_ns));
    let mut record = BatchRecord {
        sequence: batch.sequence,
        tenant: batch.scope.tenant.clone(),
        first: batch.first,
        documents: batch.documents(),
        canonical_bytes: batch.canonical_bytes,
        idempotency_key: batch.batch.idempotency_key.clone(),
        request_digest: batch.digest.clone(),
        scope: batch.scope.clone(),
        started_ns: nanos(start.duration_since(load_started)),
        elapsed_ns,
        steps,
        resolution: UNRESOLVED,
        failure: None,
        revision: None,
        receipt: None,
        effects: None,
        effects_elapsed_ns: 0,
    };
    let (resolution, receipt, retained) = match settled {
        // A settling step that completed exactly at the budget edge still
        // exceeds it once measured; keep the record and the verifier consistent.
        Ok(_) if elapsed_ns > nanos(bounds.budget()) => {
            record.failure = Some("settled after the resolution budget".into());
            return record;
        }
        Ok(settlement) => settlement,
        Err(failure) => {
            record.failure = Some(failure);
            return record;
        }
    };
    record.resolution = resolution;
    record.revision = Some(receipt.revision);
    if resolution != FIRST_ATTEMPT {
        record.receipt = retained;
        let begun = Instant::now();
        match effects(target, batch, &receipt, bounds).await {
            Ok(observed) => record.effects = Some(observed),
            Err(failure) => record.failure = Some(failure),
        }
        record.effects_elapsed_ns = nanos(begun.elapsed());
    }
    record
}

/// Nearest-rank percentiles of one batch latency distribution.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct Distribution {
    pub p50: u64,
    pub p99: u64,
    pub max: u64,
}

fn distribution(mut samples: Vec<u64>) -> Option<Distribution> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let rank = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
    Some(Distribution {
        p50: rank(50),
        p99: rank(99),
        max: samples[samples.len() - 1],
    })
}

/// The recovery cost and corpus totals, recomputed by the release verifier
/// from the ordered batch records. Zero counts are always written.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct LoadSummary {
    pub bounds: LoadBounds,
    pub batches: u64,
    pub documents: u64,
    pub canonical_bytes: u64,
    pub first_attempt_deadline_misses: u64,
    pub first_attempt_deadline_miss_rate: f64,
    pub affected_batches: u64,
    pub receipt_found_before_resend: u64,
    pub commit_confirmed_after_resend: u64,
    pub resends: u64,
    pub lookups: u64,
    pub unresolved: u64,
    pub first_attempt_ns: Option<Distribution>,
    pub end_to_end_ns: Option<Distribution>,
    pub wall_ns: u64,
    pub documents_per_second: f64,
}

#[derive(Default)]
pub struct LoadTally {
    batches: u64,
    documents: u64,
    canonical_bytes: u64,
    misses: u64,
    affected: u64,
    found: u64,
    confirmed: u64,
    resends: u64,
    lookups: u64,
    unresolved: u64,
    first_attempt: Vec<u64>,
    end_to_end: Vec<u64>,
    wall_ns: u64,
}

impl LoadTally {
    pub fn batches(&self) -> u64 {
        self.batches
    }
    pub fn affected(&self) -> u64 {
        self.affected
    }

    pub fn add(&mut self, record: &BatchRecord) {
        self.batches += 1;
        if let Some(first) = record.first_step() {
            self.first_attempt.push(first.elapsed_ns);
            if first.outcome == "uncertain" {
                self.affected += 1;
                if first.code == Some(ErrorCode::UnknownOutcome.as_str())
                    && first
                        .message
                        .as_deref()
                        .is_some_and(|message| message.starts_with(DEADLINE_MISS))
                {
                    self.misses += 1;
                }
            }
        }
        let sends = record.steps.iter().filter(|s| s.action == "send").count() as u64;
        self.resends += sends.saturating_sub(1);
        self.lookups += record.steps.iter().filter(|s| s.action == "lookup").count() as u64;
        if record.settled() {
            self.documents += record.documents as u64;
            self.canonical_bytes += record.canonical_bytes;
            self.end_to_end.push(record.elapsed_ns);
            match record.resolution {
                FOUND_BEFORE_RESEND => self.found += 1,
                CONFIRMED_AFTER_RESEND => self.confirmed += 1,
                _ => {}
            }
        } else {
            self.unresolved += 1;
        }
        self.wall_ns = self.wall_ns.max(
            record
                .started_ns
                .saturating_add(record.elapsed_ns)
                .saturating_add(record.effects_elapsed_ns),
        );
    }

    pub fn summary(&self, bounds: LoadBounds) -> LoadSummary {
        let ratio = |count: u64, total: u64| {
            if total == 0 {
                0.0
            } else {
                count as f64 / total as f64
            }
        };
        LoadSummary {
            bounds,
            batches: self.batches,
            documents: self.documents,
            canonical_bytes: self.canonical_bytes,
            first_attempt_deadline_misses: self.misses,
            first_attempt_deadline_miss_rate: ratio(self.misses, self.batches),
            affected_batches: self.affected,
            receipt_found_before_resend: self.found,
            commit_confirmed_after_resend: self.confirmed,
            resends: self.resends,
            lookups: self.lookups,
            unresolved: self.unresolved,
            first_attempt_ns: distribution(self.first_attempt.clone()),
            end_to_end_ns: distribution(self.end_to_end.clone()),
            wall_ns: self.wall_ns,
            documents_per_second: if self.wall_ns == 0 {
                0.0
            } else {
                self.documents as f64 * 1e9 / self.wall_ns as f64
            },
        }
    }
}

#[cfg(test)]
#[path = "corpus_load_tests.rs"]
mod tests;
