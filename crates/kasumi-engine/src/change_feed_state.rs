//! Deterministic full-after-image feed publication in the document commit.
use crate::accounting::encoded_len;
use kasumi_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(crate) fn entry_bytes(sequence: u64, commit: &ChangeCommit) -> Result<usize> {
    #[derive(serde::Serialize)]
    struct Header {
        revision: u64,
        first_sequence: u64,
        records: Vec<()>,
        record_bytes: usize,
    }
    let header = encoded_len(&Header {
        revision: commit.revision,
        first_sequence: commit.first_sequence,
        records: vec![],
        record_bytes: commit.record_bytes,
    })?;
    encoded_len(&sequence.to_string())?
        .checked_add(1)
        .and_then(|n| n.checked_add(header))
        .and_then(|n| n.checked_add(commit.record_bytes))
        .and_then(|n| n.checked_add(commit.records.len().saturating_sub(1)))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed accounting overflow"))
}

pub(crate) fn trim(feed: &mut ChangeFeedState, limits: &HistoryLimits) -> Result<()> {
    while feed.event_count > limits.max_feed_events
        || feed.encoded_commit_bytes > limits.max_feed_bytes
    {
        let Some((sequence, commit)) = feed.commits.get_min() else {
            return Err(Error::new(
                ErrorCode::Corruption,
                "missing change feed retention entry",
            ));
        };
        let sequence = *sequence;
        feed.event_count = feed
            .event_count
            .checked_sub(commit.records.len())
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed count underflow"))?;
        feed.encoded_commit_bytes = feed
            .encoded_commit_bytes
            .checked_sub(entry_bytes(sequence, commit)?)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed byte underflow"))?;
        feed.commits.remove(&sequence);
    }
    Ok(())
}

pub(crate) fn append(
    previous: &TenantState,
    next: &mut TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let mut records = Vec::new();
    let mut record_bytes = 0usize;
    for (collection, ids) in changed {
        let old = &previous.collections[collection];
        let new = &next.collections[collection];
        for id in ids {
            let before = old.documents.get(id);
            let after = new.documents.get(id);
            if before.map(|document| document.version) == after.map(|document| document.version) {
                continue;
            }
            let record = ChangeRecord {
                collection: collection.clone(),
                id: id.clone(),
                document: after.cloned(),
            };
            record_bytes = record_bytes
                .checked_add(encoded_len(&record)?)
                .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "change feed size overflow"))?;
            records.push(record);
        }
    }
    if records.is_empty() {
        return Ok(());
    }
    let feed = &mut next.change_feed;
    let commit = Arc::new(ChangeCommit {
        revision: next.revision,
        first_sequence: feed.next_sequence,
        records,
        record_bytes,
    });
    let bytes = entry_bytes(commit.first_sequence, &commit)?;
    if commit.records.len() > next.limits.history.max_feed_events
        || bytes > next.limits.history.max_feed_bytes
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "complete transaction exceeds change feed retention capacity",
        ));
    }
    feed.next_sequence = feed
        .next_sequence
        .checked_add(commit.records.len() as u64)
        .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "change feed sequence exhausted"))?;
    feed.event_count = feed
        .event_count
        .checked_add(commit.records.len())
        .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "change feed count overflow"))?;
    feed.encoded_commit_bytes = feed
        .encoded_commit_bytes
        .checked_add(bytes)
        .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "change feed byte overflow"))?;
    feed.commits.insert(commit.first_sequence, commit);
    trim(feed, &next.limits.history)
}

pub(crate) fn validate_restored(state: &TenantState) -> Result<()> {
    let feed = &state.change_feed;
    if feed.next_sequence == 0
        || feed.event_count > state.limits.history.max_feed_events
        || feed.encoded_commit_bytes > state.limits.history.max_feed_bytes
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "change feed outside limits",
        ));
    }
    let mut expected = feed.first_available_sequence();
    let mut revision = 0;
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (&sequence, commit) in &feed.commits {
        if sequence != expected
            || commit.first_sequence != sequence
            || commit.records.is_empty()
            || commit.revision <= revision
            || commit.revision > state.revision
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "change feed sequence or revision mismatch",
            ));
        }
        let mut identities = BTreeSet::new();
        let mut record_bytes = 0usize;
        for record in &commit.records {
            validate_name(&record.collection)?;
            validate_name(&record.id)?;
            if !state.collections.contains_key(&record.collection)
                || !identities.insert((&record.collection, &record.id))
                || record
                    .document
                    .as_ref()
                    .is_some_and(|doc| doc.id != record.id || doc.version != commit.revision)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "invalid retained change record",
                ));
            }
            record_bytes = record_bytes
                .checked_add(encoded_len(record)?)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed record overflow"))?;
        }
        if record_bytes != commit.record_bytes {
            return Err(Error::new(
                ErrorCode::Corruption,
                "change record accounting mismatch",
            ));
        }
        expected = expected
            .checked_add(commit.records.len() as u64)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed sequence overflow"))?;
        count = count
            .checked_add(commit.records.len())
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed count overflow"))?;
        bytes = bytes
            .checked_add(entry_bytes(sequence, commit)?)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed byte overflow"))?;
        revision = commit.revision;
    }
    if expected != feed.next_sequence
        || count != feed.event_count
        || bytes != feed.encoded_commit_bytes
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "change feed accounting mismatch",
        ));
    }
    Ok(())
}
