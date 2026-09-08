//! Canonical closure of all application state for planned retirement.
//! No application collection or command-identity exclusion is configurable.
use kasumi_types::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

/// Covers borrowed sorting nodes; bodies are streamed, never cloned or encoded
/// into an additional resident-state Vec. The caller owns this reservation for
/// the entire actual blocking worker, including cancellation/destruction.
pub(crate) fn workspace_bytes(state: &TenantState) -> Result<u64> {
    let entries = state
        .collections
        .values()
        .try_fold(0usize, |count, collection| {
            count
                .checked_add(collection.documents.len())
                .and_then(|count| count.checked_add(collection.archived_documents.len()))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "retirement workspace overflow",
                    )
                })
        })?;
    let entries = [
        state.receipts.len(),
        state.staged_transactions.len(),
        state.history_archives.len(),
        state.schema_activations.len(),
    ]
    .into_iter()
    .try_fold(entries, |count, next| {
        count.checked_add(next).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "retirement workspace overflow",
            )
        })
    })?;
    u64::try_from(entries)
        .ok()
        .and_then(|count| count.checked_mul(128))
        .and_then(|bytes| bytes.checked_add(1 << 20))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "retirement workspace overflow",
            )
        })
}

struct Sink<'a> {
    digest: &'a mut Sha256,
    check: &'a mut dyn FnMut() -> Result<()>,
    since_check: usize,
    interrupted: Option<Error>,
}
impl Write for Sink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.since_check >= 64 << 10 {
            if let Err(error) = (self.check)() {
                self.interrupted = Some(error);
                return Err(std::io::Error::other("retirement closure interrupted"));
            }
            self.since_check = 0;
        }
        self.digest.update(bytes);
        self.since_check = self.since_check.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json(
    digest: &mut Sha256,
    value: &impl Serialize,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let mut sink = Sink {
        digest,
        check,
        since_check: 0,
        interrupted: None,
    };
    if serde_json::to_writer(&mut sink, value).is_err() {
        return Err(sink.interrupted.take().unwrap_or_else(|| {
            Error::new(ErrorCode::Corruption, "retirement closure encoding failed")
        }));
    }
    (sink.check)()?;
    Ok(())
}
fn record(
    digest: &mut Sha256,
    value: &impl Serialize,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    json(digest, value, check)?;
    digest.update(b"\n");
    Ok(())
}
fn map<V: Serialize + Clone>(
    digest: &mut Sha256,
    name: &str,
    values: &imbl::OrdMap<String, V>,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    record(digest, &(name, values.len()), check)?;
    let mut ordered = BTreeMap::new();
    for (key, value) in values {
        check()?;
        ordered.insert(key, value);
    }
    for (key, value) in ordered {
        record(digest, &(key, value), check)?;
    }
    Ok(())
}

pub(crate) fn digest(state: &TenantState, mut check: impl FnMut() -> Result<()>) -> Result<String> {
    let mut digest = Sha256::new();
    record(&mut digest, &"kasumi.retirement-closure.v1", &mut check)?;
    record(
        &mut digest,
        &(
            &state.tenant,
            &state.incarnation,
            state.revision_base,
            state.policy_epoch,
            state.schema_epoch,
            state.suspended,
            state.retired,
            &state.pending_restore,
            &state.restored_from,
        ),
        &mut check,
    )?;
    record(&mut digest, &(&state.policy, &state.limits), &mut check)?;
    record(
        &mut digest,
        &(state.document_count, state.logical_bytes),
        &mut check,
    )?;
    record(
        &mut digest,
        &("collections", state.collections.len()),
        &mut check,
    )?;
    enum LogicalDocument<'a> {
        Hot(&'a Document),
        Cold(&'a ArchivedDocument),
    }
    for (name, collection) in &state.collections {
        record(
            &mut digest,
            &(name, &collection.definition, collection.data_epoch),
            &mut check,
        )?;
        let mut ordered = BTreeMap::new();
        for (id, document) in &collection.documents {
            check()?;
            ordered.insert(id, LogicalDocument::Hot(document));
        }
        for (id, document) in &collection.archived_documents {
            check()?;
            if ordered
                .insert(id, LogicalDocument::Cold(document))
                .is_some()
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "retirement document has two representations",
                ));
            }
        }
        record(&mut digest, &ordered.len(), &mut check)?;
        for (id, document) in ordered {
            let (version, hash) = match document {
                LogicalDocument::Hot(document) => {
                    let mut hash = Sha256::new();
                    // ArchivedDocument.document_sha256 also hashes the full
                    // Document, not merely its user body.
                    json(&mut hash, document, &mut check)?;
                    (document.version, hex::encode(hash.finalize()))
                }
                LogicalDocument::Cold(document) => {
                    validate_sha256(&document.document_sha256)?;
                    (document.version, document.document_sha256.clone())
                }
            };
            record(&mut digest, &(id, version, hash), &mut check)?;
        }
    }
    // Permanent operational identities matter even when their accepted outcome
    // changed no application document. These are part of what must be restored.
    map(&mut digest, "receipts", &state.receipts, &mut check)?;
    map(
        &mut digest,
        "staged",
        &state.staged_transactions,
        &mut check,
    )?;
    record(&mut digest, &state.active_staged_transactions, &mut check)?;
    map(&mut digest, "schema", &state.schema_activations, &mut check)?;
    map(&mut digest, "archives", &state.history_archives, &mut check)?;
    record(&mut digest, &state.change_feed, &mut check)?;
    // Intrinsic audit/Raft revisions and retirement-attempt bookkeeping are
    // deliberately absent. No application payload path is omitted.
    check()?;
    Ok(hex::encode(digest.finalize()))
}
