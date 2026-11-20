//! Each large edit owns a sequence of bounded journals. The owner flips to
//! published in the transaction selecting the root. Reclamation consumes the
//! sequence backwards, committing the remaining count with every deletion.
use super::*;

pub(super) const OWNERS: &str = "kasumi.app.edit-owners.v2";
pub(super) const BATCHES: &str = "kasumi.app.edit-batches.v2";
pub const EDIT_JOURNAL: &str = "kasumi.app.edit-journal";
pub(super) const STAGE_ROWS: usize = 14;
const LEGACY_STAGE_ROWS: usize = 15;
const MAX_JOURNAL_BYTES: usize = 64 << 10;

pub(super) fn validate_space(space: &str) -> Result<()> {
    validate_record(space, &[], 0)?;
    ensure!(
        ![OWNERS, BATCHES, EDIT_JOURNAL].contains(&space),
        "ordered page space overlaps edit metadata"
    );
    Ok(())
}

pub(super) struct EditJournal<'a> {
    store: &'a TenantStore,
    owner: Vec<u8>,
    pub(super) batches: u32,
    max_batches: u32,
}

impl<'a> EditJournal<'a> {
    pub(super) fn new(store: &'a TenantStore, space: &str, max_batches: u32) -> Result<Self> {
        validate_space(space)?;
        let mut owner = Vec::with_capacity(2 + space.len() + 16);
        owner.extend_from_slice(&(space.len() as u16).to_be_bytes());
        owner.extend_from_slice(space.as_bytes());
        owner.extend_from_slice(Uuid::new_v4().as_bytes());
        Ok(Self {
            store,
            owner,
            batches: 0,
            max_batches,
        })
    }

    pub(super) fn stage(
        &mut self,
        space: &str,
        created: BTreeMap<Vec<u8>, Vec<u8>>,
        retired: std::collections::BTreeSet<Vec<u8>>,
    ) -> Result<()> {
        let rows = created.len() + retired.len();
        ensure!(
            (1..=STAGE_ROWS).contains(&rows),
            "edit batch row count differs"
        );
        let next = self
            .batches
            .checked_add(1)
            .context("ordered edit batch count exhausted")?;
        ensure!(
            next <= self.max_batches,
            "ordered edit exceeds its staged transaction budget"
        );
        let mut entries = Vec::with_capacity(rows * 22);
        let mut writes = Vec::with_capacity(created.len() + 2);
        for (key, value) in created {
            entries.push(b'+');
            entries.extend_from_slice(&key);
            writes.push(WriteOp::put(space, key, value));
        }
        for key in retired {
            entries.push(b'-');
            entries.extend_from_slice(&key);
        }
        writes.push(WriteOp::put(
            BATCHES,
            batch_key(&self.owner, self.batches),
            entries,
        ));
        writes.push(owner_write(&self.owner, false, next));
        self.store.write_batch(&writes)?;
        self.batches = next;
        Ok(())
    }

    pub(super) fn publish(&self) -> WriteOp {
        owner_write(&self.owner, true, self.batches)
    }
}

fn owner_write(owner: &[u8], published: bool, count: u32) -> WriteOp {
    let mut value = [0; 5];
    value[0] = u8::from(published);
    value[1..].copy_from_slice(&count.to_be_bytes());
    WriteOp::put(OWNERS, owner, value)
}

fn batch_key(owner: &[u8], batch: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(owner.len() + 4);
    key.extend_from_slice(owner);
    key.extend_from_slice(&batch.to_be_bytes());
    key
}

fn owner_space(key: &[u8]) -> Result<&str> {
    let mut reader = Reader {
        bytes: key,
        offset: 0,
    };
    let len = usize::from(reader.u16()?);
    let space = std::str::from_utf8(reader.take(len)?)?;
    let _id = reader.array::<16>()?;
    ensure!(reader.offset == key.len(), "invalid edit owner key");
    validate_space(space)?;
    Ok(space)
}

fn row_len(tag: u8) -> Result<usize> {
    match tag {
        PAGE_ROW => Ok(17),
        CHUNK_ROW => Ok(21),
        _ => anyhow::bail!("invalid ordered row key"),
    }
}

fn reclaim(store: &TenantStore, owner: &[u8], state: &[u8]) -> Result<u64> {
    let space = owner_space(owner)?;
    ensure!(
        state.len() == 5 && state[0] <= 1,
        "invalid ordered edit owner"
    );
    let published = state[0] == 1;
    let count = u32::from_be_bytes(state[1..].try_into()?);
    ensure!(count > 0, "empty ordered edit owner");
    for batch in (0..count).rev() {
        let key = batch_key(owner, batch);
        let entries = store
            .get_bounded(BATCHES, &key, STAGE_ROWS * 22)?
            .context("owned ordered edit batch missing")?;
        let mut rows = Reader {
            bytes: entries.as_bytes(),
            offset: 0,
        };
        let mut writes = Vec::with_capacity(STAGE_ROWS + 2);
        let mut seen = 0;
        while rows.offset < entries.len() {
            let disposition = rows.take(1)?[0];
            ensure!(
                b"+-".contains(&disposition) && seen < STAGE_ROWS,
                "invalid edit disposition"
            );
            let tag = *rows
                .bytes
                .get(rows.offset)
                .context("truncated ordered row")?;
            let row = rows.take(row_len(tag)?)?;
            if published == (disposition == b'-') {
                writes.push(WriteOp::delete(space, row));
            }
            seen += 1;
        }
        ensure!(seen > 0, "empty ordered edit batch");
        writes.push(WriteOp::delete(BATCHES, key));
        writes.push(if batch == 0 {
            WriteOp::delete(OWNERS, owner)
        } else {
            owner_write(owner, published, batch)
        });
        store.write_batch(&writes)?;
    }
    Ok(u64::from(count))
}

/// Finish retiring displaced rows of published edits and abandon unselected
/// edits. Call under the edit publication gate. One bounded batch and one
/// owner fit in memory, including when cleanup itself restarts after a crash.
pub fn recover_abandoned_edits(store: &Arc<TenantStore>) -> Result<u64> {
    let view = store.read_view()?;
    let mut removed = 0u64;
    view.visit(OWNERS, 5, |owner, value| {
        removed = removed
            .checked_add(reclaim(store, owner, value)?)
            .context("edit recovery count exhausted")?;
        Ok(())
    })?;
    removed = removed
        .checked_add(recover_legacy(store, &view)?)
        .context("edit recovery count exhausted")?;
    view.close()?;
    Ok(removed)
}

/// `recover_abandoned_edits` restricted to the page spaces of one family:
/// the family's initial space and its `family@<uuid>` generations. Callers
/// hold that family's publication gate; other families' editors and the
/// legacy journal are left to their own gates.
pub fn recover_abandoned_edits_in(store: &Arc<TenantStore>, family: &str) -> Result<u64> {
    validate_space(family)?;
    let view = store.read_view()?;
    let mut removed = 0u64;
    view.visit(OWNERS, 5, |owner, value| {
        let space = owner_space(owner)?;
        let owned = space == family
            || space
                .strip_prefix(family)
                .and_then(|rest| rest.strip_prefix('@'))
                .is_some_and(|id| Uuid::parse_str(id).is_ok());
        if owned {
            removed = removed
                .checked_add(reclaim(store, owner, value)?)
                .context("edit recovery count exhausted")?;
        }
        Ok(())
    })?;
    view.close()?;
    Ok(removed)
}

fn recover_legacy(store: &Arc<TenantStore>, view: &TenantReadView) -> Result<u64> {
    let mut removed = 0u64;
    // The earlier journal disappeared in the publication itself. Every
    // surviving V1 record therefore names newly staged, unselected rows.
    view.visit(EDIT_JOURNAL, MAX_JOURNAL_BYTES, |key, value| {
        let end = key
            .len()
            .checked_sub(4)
            .context("truncated legacy edit journal key")?;
        let space = owner_space(&key[..end])?;
        let mut rows = Reader {
            bytes: value,
            offset: 0,
        };
        let mut writes = Vec::with_capacity(LEGACY_STAGE_ROWS + 1);
        while rows.offset < value.len() {
            let len = usize::from(rows.u16()?);
            let row = rows.take(len)?;
            ensure!(
                !row.is_empty()
                    && row.len() == row_len(row[0])?
                    && writes.len() < LEGACY_STAGE_ROWS,
                "invalid legacy edit journal row"
            );
            writes.push(WriteOp::delete(space, row));
        }
        writes.push(WriteOp::delete(EDIT_JOURNAL, key));
        store.write_batch(&writes)?;
        removed = removed
            .checked_add(1)
            .context("edit recovery count exhausted")?;
        Ok(())
    })?;
    Ok(removed)
}
