//! Fields use ordinal dictionary keys to keep long strings and compound JSON
//! pointers outside the ordered page key limit. Equality probes binary-search
//! the authenticated dictionary then stream only the matching document IDs.
use super::KeyBuilder;
use anyhow::{Context, Result, ensure};
use kasumi_query::{FieldPostingRow, FieldPredicate, FieldValue, QueryIndexes};
use kasumi_store::ordered_pages::{Direction, MAX_VALUE_BYTES, TreeReader};
use std::{cmp::Ordering, ops::Bound};

fn field_key(collection: &str, field: usize) -> Vec<u8> {
    let mut key = KeyBuilder::new(25).text(collection).finish();
    key.extend_from_slice(&(field as u64).to_be_bytes());
    key
}
fn ranked(field: &[u8], rank: u64, family: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(field.len() + 9);
    key.extend_from_slice(field);
    key.extend_from_slice(&rank.to_be_bytes());
    key.push(family);
    key
}

pub(crate) fn publish(
    indexes: &QueryIndexes,
    emit: &mut impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    indexes.visit_field_values(|collection, field, row| {
        let field = field_key(collection, field);
        match row {
            FieldPostingRow::Count(n) => emit(&field, &(n as u64).to_be_bytes()),
            FieldPostingRow::Value { ordinal, value } => {
                emit(&ranked(&field, ordinal as u64, 0), &[value.tag])?;
                if value.tag >= 4 {
                    emit(&ranked(&field, ordinal as u64, 1), &value.bytes)?;
                }
                Ok(())
            }
            FieldPostingRow::Id { ordinal, id } => {
                let mut key = ranked(&field, ordinal as u64, 2);
                key.extend_from_slice(id.as_bytes());
                emit(&key, &[])
            }
        }
    })
}

/// Return the insertion rank and whether its value equals the target.
fn lookup(
    reader: &TreeReader<'_>,
    field: &[u8],
    count: u64,
    target: FieldValue<'_>,
    mut check: impl FnMut() -> Result<()>,
) -> Result<(u64, bool)> {
    let (mut start, mut end) = (0, count);
    while start < end {
        check()?;
        let mid = start + (end - start) / 2;
        let tag = reader.with_value(&ranked(field, mid, 0), 1, |value| {
            let Some(&[tag @ 0..=5]) = value else {
                anyhow::bail!("invalid field dictionary tag")
            };
            Ok(tag)
        })?;
        let order = match tag.cmp(&target.tag) {
            Ordering::Equal if tag >= 4 => {
                reader.with_value(&ranked(field, mid, 1), MAX_VALUE_BYTES, |value| {
                    Ok(value
                        .context("missing field dictionary payload")?
                        .cmp(target.bytes.as_ref()))
                })?
            }
            order => order,
        };
        match order {
            Ordering::Less => start = mid + 1,
            Ordering::Greater => end = mid,
            Ordering::Equal => return Ok((mid, true)),
        }
    }
    Ok((start, false))
}

pub(crate) fn visit_value_ids(
    reader: &TreeReader<'_>,
    collection: &str,
    ordinal: usize,
    predicate: FieldPredicate<'_>,
    mut check: impl FnMut() -> Result<()>,
    mut visit: impl FnMut(&str) -> Result<bool>,
) -> Result<()> {
    let field = field_key(collection, ordinal);
    let count = reader.with_value(&field, 8, |value| {
        Ok(u64::from_be_bytes(
            value.context("missing field dictionary")?.try_into()?,
        ))
    })?;
    let mut find = |value, kind| {
        lookup(
            reader,
            &field,
            count,
            FieldValue::predicate(value, kind)?,
            &mut check,
        )
    };
    let (start, end) = match predicate {
        FieldPredicate::Equals { value, kind } => {
            let (at, found) = find(value, kind)?;
            (at, at + u64::from(found))
        }
        FieldPredicate::In { values, kind } => {
            // Input count is limited by the wire contract. Equal decimal
            // spellings match the same dictionary rank. Read that posting once.
            let mut ranks = [0u64; kasumi_types::MAX_FILTER_IN_VALUES];
            ensure!(
                values.len() <= ranks.len(),
                "too many indexed membership values"
            );
            let mut matched = 0;
            for value in values {
                let (rank, found) = find(value, kind)?;
                if found {
                    ranks[matched] = rank;
                    matched += 1;
                }
            }
            let ranks = &mut ranks[..matched];
            ranks.sort_unstable();
            let mut previous = None;
            for &rank in ranks.iter() {
                check()?;
                if previous != Some(rank) && !visit_rank(reader, &field, rank, &mut visit)? {
                    break;
                }
                previous = Some(rank);
            }
            return Ok(());
        }
        FieldPredicate::Range { lower, upper, kind } => {
            // Missing and null sort ahead of every comparable scalar.
            let null = serde_json::Value::Null;
            let (value, exclusive) = match lower {
                Bound::Unbounded => (&null, true),
                Bound::Included(value) => (value, false),
                Bound::Excluded(value) => (value, true),
            };
            let (rank, found) = find(value, kind)?;
            let start = rank + u64::from(exclusive && found);
            let end = match upper {
                Bound::Included(value) => {
                    let (at, found) = find(value, kind)?;
                    at + u64::from(found)
                }
                Bound::Excluded(value) => find(value, kind)?.0,
                Bound::Unbounded => count,
            };
            (start, end)
        }
        FieldPredicate::Exists(_) => {
            anyhow::bail!("presence requires the field presence directory")
        }
    };
    for rank in start..end {
        check()?;
        if !visit_rank(reader, &field, rank, &mut visit)? {
            break;
        }
    }
    Ok(())
}

fn visit_rank(
    reader: &TreeReader<'_>,
    field: &[u8],
    rank: u64,
    visit: &mut impl FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    let prefix = ranked(field, rank, 2);
    let mut keep_going = true;
    reader.scan(
        Bound::Included(&prefix),
        Direction::Forward,
        &mut |key, value| {
            let Some(id) = key.strip_prefix(prefix.as_slice()) else {
                return Ok(false);
            };
            ensure!(value.is_empty(), "field posting carries a payload");
            let id = std::str::from_utf8(id)?;
            kasumi_types::validate_name(id)?;
            keep_going = visit(id)?;
            Ok(keep_going)
        },
    )?;
    Ok(keep_going)
}
