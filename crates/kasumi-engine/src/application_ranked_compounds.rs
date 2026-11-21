//! A checkpoint's full-order compound tuples. Ranks belong to this immutable
//! index. Document IDs point back to the original selected value, so wide
//! repeated components do not have to be duplicated in this directory.
use super::{Direction, TreeReader, field_prefix, posting_id};
use anyhow::{Context, Result, ensure};
use kasumi_query::{QueryIndexes, RankedCompound, RankedOwner};
use kasumi_store::ordered_pages::ValueRef;
use std::ops::Bound;

pub(crate) fn publish(
    indexes: &QueryIndexes,
    mut emit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    indexes.visit_ranked_compounds(|name, ordinal, row| {
        let mut key = field_prefix(b'W', name, ordinal);
        match row {
            RankedCompound::Count(count) => emit(&key, &count.to_be_bytes()),
            RankedCompound::Owner { rank, digest, id } => {
                key.extend_from_slice(&rank.to_be_bytes());
                let mut value = Vec::with_capacity(32 + id.len());
                value.extend_from_slice(&digest);
                value.extend_from_slice(id.as_bytes());
                emit(&key, &value)
            }
        }
    })
}

pub(crate) fn count(tree: &TreeReader<'_>, name: &str, ordinal: usize) -> Result<Option<u64>> {
    tree.with_value(&field_prefix(b'W', name, ordinal), 8, |value| {
        value
            .map(|raw| Ok(u64::from_be_bytes(raw.try_into()?)))
            .transpose()
    })
}

/// The first missing or non-consecutive ordinal invalidates the window.
pub(crate) fn window(
    tree: &TreeReader<'_>,
    name: &str,
    ordinal: usize,
    start: u64,
    end: u64,
    descending: bool,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Vec<RankedOwner>> {
    ensure!(start <= end, "invalid ranked compound bounds");
    let size = (end - start).min(kasumi_query::ORDERED_TUPLE_WINDOW as u64) as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    let prefix = field_prefix(b'W', name, ordinal);
    let first = if descending { end - 1 } else { start };
    let mut key = prefix.clone();
    key.extend_from_slice(&first.to_be_bytes());
    let mut rows = Vec::with_capacity(size);
    tree.scan(
        Bound::Included(&key),
        if descending {
            Direction::Reverse
        } else {
            Direction::Forward
        },
        &mut |key, value| {
            check()?;
            let suffix = key
                .strip_prefix(prefix.as_slice())
                .context("ranked compound row missing")?;
            let rank = u64::from_be_bytes(suffix.try_into()?);
            let expected = if descending {
                first - rows.len() as u64
            } else {
                first + rows.len() as u64
            };
            ensure!(
                rank == expected,
                "ranked compound window skipped its ordinal"
            );
            let ValueRef::Inline(value) = value else {
                anyhow::bail!("ranked compound owner exceeds inline storage")
            };
            let (digest, id) = value
                .split_at_checked(32)
                .context("truncated ranked compound owner")?;
            rows.push(RankedOwner {
                rank,
                digest: digest.try_into()?,
                id: posting_id(id)?.to_owned(),
            });
            Ok(rows.len() < size)
        },
    )?;
    ensure!(
        rows.len() == size,
        "ranked compound window ended prematurely"
    );
    Ok(rows)
}
