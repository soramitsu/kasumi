//! Encrypted local seek hints for a tenant's immutable archive chain. A lookup
//! starts at the committed head. Its point rows are keyed by stream, ordinal
//! and exact ciphertext hash, so an unpublished segment cannot select a fork.
//! Each even ordinal also points to the ordinal obtained by clearing its low
//! set bit. This bounds a seek without retaining the chain in native memory.
use anyhow::{Context, Result, ensure};
use kasumi_store::{DiskMemoryLease, TenantStore, WriteOp};
use kasumi_types::{AuditArchiveLink, AuditArchiveReference};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DIRECTORY: &str = "engine.tenant.audit.directory";
const ROW_LIMIT: usize = 32 << 10;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    index: u64,
    reference: AuditArchiveReference,
    skip: Option<AuditArchiveLink>,
}

fn skip_index(index: u64) -> Option<u64> {
    (index > 0 && index.is_multiple_of(2)).then(|| index & (index - 1))
}

fn key(stream: Uuid, index: u64, link: &AuditArchiveLink) -> Result<[u8; 56]> {
    let mut bytes = [0u8; 56];
    bytes[..16].copy_from_slice(stream.as_bytes());
    bytes[16..24].copy_from_slice(&index.to_be_bytes());
    hex::decode_to_slice(&link.ciphertext_sha256, &mut bytes[24..])?;
    Ok(bytes)
}

impl Row {
    fn validate(&self, stream: Uuid, index: u64, link: &AuditArchiveLink) -> Result<()> {
        self.reference.validate()?;
        ensure!(
            self.reference.stream_id == stream
                && self.index == index
                && self.reference.object == *link
                && self.reference.previous.is_some() == (index > 0)
                && self.skip.is_some() == skip_index(index).is_some(),
            "audit seek row identity differs"
        );
        if let Some(skip) = &self.skip {
            skip.validate()?;
            ensure!(
                self.reference
                    .previous
                    .as_ref()
                    .is_some_and(|prev| skip.next_sequence <= prev.first_sequence),
                "audit seek row skips outside its verified prefix"
            );
        }
        Ok(())
    }

    fn read(
        store: &TenantStore,
        stream: Uuid,
        index: u64,
        link: &AuditArchiveLink,
    ) -> Result<Self> {
        let bytes = store
            .get_bounded(DIRECTORY, &key(stream, index, link)?, ROW_LIMIT)?
            .context("tenant audit seek row missing")?;
        let row: Row = serde_json::from_slice(&bytes)?;
        row.validate(stream, index, link)?;
        Ok(row)
    }

    fn write(&self, store: &TenantStore) -> Result<()> {
        let reference = &self.reference;
        self.validate(reference.stream_id, self.index, &reference.object)?;
        let key = key(reference.stream_id, self.index, &reference.object)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= ROW_LIMIT, "tenant audit seek row too large");
        if let Some(old) = store.get_bounded(DIRECTORY, &key, ROW_LIMIT)? {
            ensure!(
                old.as_bytes() == bytes,
                "immutable tenant audit seek row changed"
            );
            return Ok(());
        }
        store.write_batch(&[WriteOp::put(DIRECTORY, key, bytes)])
    }
}

fn seek(
    store: &TenantStore,
    stream: Uuid,
    mut index: u64,
    head: &AuditArchiveLink,
    keep: impl Fn(u64, &AuditArchiveLink) -> bool,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Row> {
    let mut link = head.clone();
    loop {
        check()?;
        let row = Row::read(store, stream, index, &link)?;
        if let (Some(target), Some(skip)) = (skip_index(index), &row.skip)
            && keep(target, skip)
        {
            index = target;
            link = skip.clone();
        } else if let Some(previous) = &row.reference.previous
            && keep(index - 1, previous)
        {
            index -= 1;
            link = previous.clone();
        } else {
            return Ok(row);
        }
    }
}

pub(crate) fn containing(
    store: &TenantStore,
    head: &AuditArchiveReference,
    count: u64,
    sequence: u64,
    check: impl FnMut() -> Result<()>,
) -> Result<AuditArchiveReference> {
    let index = count
        .checked_sub(1)
        .context("empty tenant archive directory")?;
    let row = seek(
        store,
        head.stream_id,
        index,
        &head.object,
        |_, link| sequence < link.next_sequence,
        check,
    )?;
    ensure!(
        row.reference.object.first_sequence <= sequence
            && sequence < row.reference.object.next_sequence,
        "tenant audit sequence outside its selected archive"
    );
    Ok(row.reference)
}

/// Materialize the new link while the committed-prune owner has the verified
/// previous generation. Visibility is still determined by the replicated head.
pub(crate) fn append(
    store: &TenantStore,
    index: u64,
    reference: &AuditArchiveReference,
) -> Result<()> {
    let skip = if let Some(target) = skip_index(index) {
        let previous = reference
            .previous
            .as_ref()
            .context("missing tenant audit predecessor")?;
        let ancestor = seek(
            store,
            reference.stream_id,
            index - 1,
            previous,
            |i, _| i >= target,
            || Ok(()),
        )?;
        ensure!(
            ancestor.index == target,
            "tenant audit predecessor index differs"
        );
        Some(ancestor.reference.object)
    } else {
        None
    };
    Row {
        index,
        reference: reference.clone(),
        skip,
    }
    .write(store)
}

/// Restore sends the verified chain in reverse order. Intervals with a fixed
/// low set bit are disjoint, so at most one unresolved skip per bit is live.
pub(crate) struct Rebuild<'a> {
    store: &'a TenantStore,
    remaining: u64,
    pending: Vec<(u64, Row)>,
    _memory: DiskMemoryLease,
}
impl<'a> Rebuild<'a> {
    pub(crate) fn new(store: &'a TenantStore, count: u64) -> Result<Self> {
        let slots = u64::BITS - count.leading_zeros();
        let memory = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed((u64::from(slots) + 2) * ROW_LIMIT as u64)?;
        Ok(Self {
            store,
            remaining: count,
            pending: Vec::with_capacity(slots as usize),
            _memory: memory,
        })
    }
    pub(crate) fn visit(&mut self, reference: &AuditArchiveReference) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .context("too many audit dependencies")?;
        let index = self.remaining;
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 == index {
                let (_, mut row) = self.pending.swap_remove(i);
                row.skip = Some(reference.object.clone());
                row.write(self.store)?;
            } else {
                i += 1;
            }
        }
        let row = Row {
            index,
            reference: reference.clone(),
            skip: None,
        };
        if let Some(target) = skip_index(index) {
            ensure!(
                self.pending.len() < self.pending.capacity(),
                "audit directory workspace exhausted"
            );
            self.pending.push((target, row));
        } else {
            row.write(self.store)?;
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<()> {
        ensure!(
            self.remaining == 0 && self.pending.is_empty(),
            "incomplete tenant audit directory"
        );
        Ok(())
    }
}
