//! Canonical closure of all application state for planned retirement.
//! No application collection or command-identity exclusion is configurable.
use kasumi_types::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Covers borrowed sorting nodes; bodies are streamed, never cloned or encoded
/// into an additional resident-state Vec. The caller owns this reservation for
/// the entire actual blocking worker, including cancellation/destruction.
pub(crate) fn workspace_bytes(_: &TenantState) -> Result<u64> {
    // One bounded semantic record plus its canonical/hash workspace. Resident
    // roots are borrowed and the indexed path retains only encrypted page caches.
    Ok(64 << 20)
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

trait ClosureRecords {
    fn metadata(&self) -> &TenantState;
    fn records(
        &self,
        kind: u8,
        primary: Option<&str>,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<crate::snapshot_codec::Record>> + Send + '_>,
    >;
}
impl ClosureRecords for TenantState {
    fn metadata(&self) -> &TenantState {
        self
    }
    fn records(
        &self,
        kind: u8,
        primary: Option<&str>,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<crate::snapshot_codec::Record>> + Send + '_>,
    > {
        crate::snapshot_codec::records(self, kind, primary)
    }
}
impl ClosureRecords for crate::backup_verify::VerifiedState {
    fn metadata(&self) -> &TenantState {
        self.metadata()
    }
    fn records(
        &self,
        kind: u8,
        primary: Option<&str>,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<crate::snapshot_codec::Record>> + Send + '_>,
    > {
        self.records(kind, primary)
    }
}
fn corrupt(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Corruption, error.to_string())
}

pub(crate) fn digest(state: &TenantState, check: impl FnMut() -> Result<()>) -> Result<String> {
    digest_records(state, check)
}
pub(crate) fn digest_verified(
    state: &crate::backup_verify::VerifiedState,
    check: impl FnMut() -> Result<()>,
) -> Result<String> {
    digest_records(state, check)
}
fn digest_records(
    view: &impl ClosureRecords,
    mut check: impl FnMut() -> Result<()>,
) -> Result<String> {
    use crate::snapshot_codec::Record;
    let state = view.metadata();
    let mut digest = Sha256::new();
    record(&mut digest, &"kasumi.retirement-closure.v2", &mut check)?;
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
    // Strictly ordered typed records include an authenticated terminal count for
    // every category. Staging and change-feed payloads never become one value.
    let mut collections = 0u64;
    for collection in view.records(2, None).map_err(corrupt)? {
        check()?;
        let Record::Collection(name, collection) = collection.map_err(corrupt)? else {
            unreachable!()
        };
        record(
            &mut digest,
            &(
                "collection",
                &name,
                &collection.definition,
                collection.data_epoch,
            ),
            &mut check,
        )?;
        let mut hot = view.records(3, Some(&name)).map_err(corrupt)?.peekable();
        let mut cold = view.records(4, Some(&name)).map_err(corrupt)?.peekable();
        let mut count = 0u64;
        loop {
            check()?;
            let a = match hot.peek() {
                Some(Ok(Record::Document(_, doc))) => Some(doc.id.as_str()),
                Some(Err(error)) => return Err(corrupt(error)),
                None => None,
                _ => return Err(corrupt("unexpected closure document record")),
            };
            let b = match cold.peek() {
                Some(Ok(Record::Archived(_, id, _))) => Some(id.as_str()),
                Some(Err(error)) => return Err(corrupt(error)),
                None => None,
                _ => return Err(corrupt("unexpected closure archived record")),
            };
            let hot_next = match (a, b) {
                (None, None) => break,
                (Some(a), Some(b)) if a == b => {
                    return Err(corrupt("retirement document has two representations"));
                }
                (Some(a), Some(b)) => a < b,
                (Some(_), None) => true,
                (None, Some(_)) => false,
            };
            let (id, version, hash) = if hot_next {
                let Some(Ok(Record::Document(_, doc))) = hot.next() else {
                    unreachable!()
                };
                let mut hash = Sha256::new();
                json(&mut hash, doc.as_ref(), &mut check)?;
                (doc.id.clone(), doc.version, hex::encode(hash.finalize()))
            } else {
                let Some(Ok(Record::Archived(_, id, doc))) = cold.next() else {
                    unreachable!()
                };
                validate_sha256(&doc.document_sha256)?;
                (id, doc.version, doc.document_sha256)
            };
            record(&mut digest, &("document", id, version, hash), &mut check)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| corrupt("retirement document count overflow"))?;
        }
        record(&mut digest, &("collection-end", count), &mut check)?;
        collections = collections
            .checked_add(1)
            .ok_or_else(|| corrupt("retirement collection count overflow"))?;
    }
    record(&mut digest, &("collections-end", collections), &mut check)?;
    for kind in [1u8, 5, 6, 7, 8, 9, 10, 11, 12, 17] {
        record(&mut digest, &("category", kind), &mut check)?;
        let mut count = 0u64;
        for value in view.records(kind, None).map_err(corrupt)? {
            check()?;
            record(&mut digest, &value.map_err(corrupt)?, &mut check)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| corrupt("retirement record count overflow"))?;
        }
        record(&mut digest, &("category-end", kind, count), &mut check)?;
    }
    // Full feed metadata accompanies its independently emitted commit/items.
    record(
        &mut digest,
        &(
            state.change_feed.next_sequence,
            state.change_feed.event_count,
            state.change_feed.encoded_commit_bytes,
        ),
        &mut check,
    )?;
    // Intrinsic audit/Raft revisions and retirement-attempt bookkeeping remain
    // absent. Every application collection and permanent command identity is bound.
    check()?;
    Ok(hex::encode(digest.finalize()))
}
