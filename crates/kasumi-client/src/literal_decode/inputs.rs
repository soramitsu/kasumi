//! Canonical intent inputs. Optional members match the defaults their typed
//! Serialize output omits; no generic from_value conversion can reclassify
//! document or filter marker keys, and duplicate members are rejected.
use super::json::{Object, array, definition};
use crate::{
    ClientError,
    snapshot_decode::{
        resources::{Call, invalid},
        tokens,
    },
};
use kasumi_types::{
    Aggregation, Condition, Filter, MAX_FILTER_IN_VALUES, Mutation, MutationBatch, QueryRequest,
    SchemaChange, SchemaChangeSet, StagedChunk,
};
use serde_json::value::RawValue;
use std::collections::BTreeMap;

const MAX_FILTER_DEPTH: usize = 16;

fn mutation(raw: &RawValue, call: &Call) -> Result<Mutation, ClientError> {
    call.check()?;
    let mut object = Object::new(raw)?;
    let op: &str = object.field("op")?;
    let collection = object.field("collection")?;
    let id = object.field("id")?;
    let expected = object.optional("expected")?;
    let value = match op {
        "put" => Mutation::Put {
            collection,
            id,
            expected,
            body: tokens::literal(object.raw("body")?.get().as_bytes(), call)?,
        },
        "patch" => Mutation::Patch {
            collection,
            id,
            expected,
            patch: tokens::literal(object.raw("patch")?.get().as_bytes(), call)?,
        },
        "delete" => Mutation::Delete {
            collection,
            id,
            expected,
        },
        _ => return Err(invalid("unknown mutation operation")),
    };
    object.finish()?;
    Ok(value)
}
fn operations(raw: &RawValue, call: &Call) -> Result<Vec<Mutation>, ClientError> {
    array(raw, call.limits.max_rows)?
        .into_iter()
        .map(|raw| mutation(raw, call))
        .collect()
}
pub(super) fn mutation_batch(raw: &RawValue, call: &Call) -> Result<MutationBatch, ClientError> {
    let mut object = Object::new(raw)?;
    let value = MutationBatch {
        idempotency_key: object.field("idempotency_key")?,
        read_set: object.optional("read_set")?,
        operations: operations(object.raw("operations")?, call)?,
    };
    object.finish()?;
    Ok(value)
}
pub(super) fn staged_chunk(raw: &RawValue, call: &Call) -> Result<StagedChunk, ClientError> {
    let mut object = Object::new(raw)?;
    let value = StagedChunk {
        read_set: object.field("read_set")?,
        operations: operations(object.raw("operations")?, call)?,
    };
    object.finish()?;
    Ok(value)
}
fn literal_values(raw: &RawValue, call: &Call) -> Result<Vec<serde_json::Value>, ClientError> {
    array(raw, MAX_FILTER_IN_VALUES.min(call.limits.max_rows))?
        .into_iter()
        .map(|raw| tokens::literal(raw.get().as_bytes(), call))
        .collect()
}
fn condition(raw: &RawValue, call: &Call) -> Result<Condition, ClientError> {
    call.check()?;
    match raw.get().as_bytes().first() {
        Some(b'{') => {}
        Some(b'[') => return Err(invalid("filter values cannot be arrays")),
        _ => {
            return Ok(Condition {
                eq: Some(tokens::literal(raw.get().as_bytes(), call)?),
                ..Condition::default()
            });
        }
    }
    let mut condition = Condition::default();
    for (operator, raw) in Object::new(raw)?.into_entries() {
        let literal = || tokens::literal(raw.get().as_bytes(), call);
        match operator.as_str() {
            "eq" => condition.eq = Some(literal()?),
            "ne" => condition.ne = Some(literal()?),
            "gt" => condition.gt = Some(literal()?),
            "gte" => condition.gte = Some(literal()?),
            "lt" => condition.lt = Some(literal()?),
            "lte" => condition.lte = Some(literal()?),
            "contains" => condition.contains = Some(literal()?),
            "in" => condition.r#in = Some(literal_values(raw, call)?),
            "nin" => condition.nin = Some(literal_values(raw, call)?),
            "exists" => condition.exists = Some(serde_json::from_str(raw.get())?),
            _ => return Err(invalid("unknown filter operator")),
        }
    }
    if condition.is_empty() {
        return Err(invalid("empty filter condition"));
    }
    Ok(condition)
}
fn filter(raw: &RawValue, call: &Call, depth: usize) -> Result<Filter, ClientError> {
    call.check()?;
    if depth > MAX_FILTER_DEPTH {
        return Err(invalid("filter exceeds its nesting limit"));
    }
    let mut filter = Filter::default();
    for (key, raw) in Object::new(raw)?.into_entries() {
        if key.starts_with('/') {
            filter.fields.insert(key, condition(raw, call)?);
            continue;
        }
        match key.as_str() {
            "not" => filter.not = Some(Box::new(self::filter(raw, call, depth + 1)?)),
            "and" | "or" => {
                let filters = array(raw, call.limits.max_rows)?
                    .into_iter()
                    .map(|raw| self::filter(raw, call, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                if filters.is_empty() {
                    return Err(invalid("empty filter combinator"));
                }
                if key == "and" {
                    filter.and = filters;
                } else {
                    filter.or = filters;
                }
            }
            _ => return Err(invalid("unknown filter key")),
        }
    }
    Ok(filter)
}
pub(super) fn query(raw: &RawValue, call: &Call) -> Result<QueryRequest, ClientError> {
    let mut object = Object::new(raw)?;
    let mut aggregate = BTreeMap::new();
    if let Some(raw) = object.optional_raw("aggregate") {
        for (alias, raw) in Object::new(raw)?.into_entries() {
            let value: Aggregation = serde_json::from_str(raw.get())?;
            aggregate.insert(alias, value);
        }
    }
    let value = QueryRequest {
        collection: object.field("collection")?,
        filter: match object.optional_raw("filter") {
            Some(raw) => filter(raw, call, 0)?,
            None => Filter::default(),
        },
        search: object.optional("search")?,
        sort: object.optional("sort")?,
        select: object.optional("select")?,
        group_by: object.optional("group_by")?,
        aggregate,
        limit: object.optional("limit")?,
        cursor: object.optional("cursor")?,
        paging: object.optional("paging")?,
        allow_scan: object.optional("allow_scan")?,
    };
    object.finish()?;
    if !value.is_aggregate() && (value.page_size() == 0 || value.page_size() > call.limits.max_rows)
    {
        return Err(invalid("query limit exceeds admitted row work"));
    }
    Ok(value)
}
pub(super) fn schema_change(raw: &RawValue, call: &Call) -> Result<SchemaChangeSet, ClientError> {
    let mut object = Object::new(raw)?;
    let activation_id = object.field("activation_id")?;
    let expected_incarnation = object.field("expected_incarnation")?;
    let expected_schema_epoch = object.field("expected_schema_epoch")?;
    let read_set = object.field("read_set")?;
    let rows = array(object.raw("changes")?, call.limits.max_rows)?;
    object.finish()?;
    let mut changes = Vec::with_capacity(rows.len());
    for raw in rows {
        call.check()?;
        let mut object = Object::new(raw)?;
        let kind: &str = object.field("kind")?;
        let definition = definition(object.raw("definition")?, call)?;
        let value = match kind {
            "create" => SchemaChange::Create { definition },
            "replace" => SchemaChange::Replace {
                definition,
                expected_data_epoch: object.field("expected_data_epoch")?,
            },
            _ => return Err(invalid("unknown schema change")),
        };
        object.finish()?;
        changes.push(value);
    }
    Ok(SchemaChangeSet {
        activation_id,
        expected_incarnation,
        expected_schema_epoch,
        read_set,
        changes,
    })
}
