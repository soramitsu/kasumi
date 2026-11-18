//! Fields use ordinal dictionary keys to keep long strings and compound JSON
//! pointers outside the ordered page key limit. Equality probes binary-search
//! the authenticated dictionary then stream only the matching document IDs.
use super::KeyBuilder;
use anyhow::{Context, Result, ensure};
use kasumi_query::{FieldPostingRow, FieldValue, QueryIndexes};
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

pub(super) fn publish(
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

pub(crate) fn visit_value_ids(
    reader: &TreeReader<'_>,
    collection: &str,
    field: usize,
    target: &FieldValue<'_>,
    mut check: impl FnMut() -> Result<()>,
    mut visit: impl FnMut(&str) -> Result<bool>,
) -> Result<()> {
    let field = field_key(collection, field);
    let mut end = reader.with_value(&field, 8, |value| {
        Ok(u64::from_be_bytes(
            value.context("missing field dictionary")?.try_into()?,
        ))
    })?;
    let mut start = 0;
    while start < end {
        check()?;
        let mid = start + (end - start) / 2;
        let tag = reader.with_value(&ranked(&field, mid, 0), 1, |value| {
            let Some(&[tag @ 0..=5]) = value else {
                anyhow::bail!("invalid field dictionary tag")
            };
            Ok(tag)
        })?;
        let order = match tag.cmp(&target.tag) {
            Ordering::Equal if tag >= 4 => {
                reader.with_value(&ranked(&field, mid, 1), MAX_VALUE_BYTES, |value| {
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
            Ordering::Equal => {
                let prefix = ranked(&field, mid, 2);
                return reader.scan(
                    Bound::Included(&prefix),
                    Direction::Forward,
                    &mut |key, value| {
                        let Some(id) = key.strip_prefix(prefix.as_slice()) else {
                            return Ok(false);
                        };
                        ensure!(value.is_empty(), "field posting carries a payload");
                        let id = std::str::from_utf8(id)?;
                        kasumi_types::validate_name(id)?;
                        visit(id)
                    },
                );
            }
        }
    }
    Ok(())
}
