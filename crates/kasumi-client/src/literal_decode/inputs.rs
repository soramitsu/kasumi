//! Canonical intent inputs. Required fields match Serialize output; no generic
//! from_value conversion can reclassify document or predicate marker keys.
use super::json::{Object, array, definition};
use crate::{
    ClientError,
    snapshot_decode::{
        resources::{Call, invalid},
        tokens,
    },
};
use kasumi_types::{
    Mutation, MutationBatch, Predicate, QueryRequest, SchemaChange, SchemaChangeSet, StagedChunk,
};
use serde_json::value::RawValue;

fn mutation(raw: &RawValue, call: &Call) -> Result<Mutation, ClientError> {
    call.check()?;
    let mut object = Object::new(raw)?;
    let op: &str = object.field("op")?;
    let collection = object.field("collection")?;
    let id = object.field("id")?;
    let expected = object.field("expected")?;
    let value = match op {
        "put" => Mutation::Put {
            collection,
            id,
            expected,
            body: tokens::literal(object.raw("body")?.get().as_bytes(), call)?,
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
        read_set: object.field("read_set")?,
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
fn predicate(raw: &RawValue, call: &Call) -> Result<Predicate, ClientError> {
    call.check()?;
    let mut object = Object::new(raw)?;
    let op: &str = object.field("op")?;
    let value = match op {
        "all" => Predicate::All,
        "eq" => Predicate::Eq {
            field: object.field("field")?,
            value: tokens::literal(object.raw("value")?.get().as_bytes(), call)?,
        },
        "in" => Predicate::In {
            field: object.field("field")?,
            values: array(object.raw("values")?, call.limits.max_rows)?
                .into_iter()
                .map(|raw| tokens::literal(raw.get().as_bytes(), call))
                .collect::<Result<_, _>>()?,
        },
        "compare" => Predicate::Compare {
            field: object.field("field")?,
            comparison: object.field("comparison")?,
            value: tokens::literal(object.raw("value")?.get().as_bytes(), call)?,
        },
        "exists" => Predicate::Exists {
            field: object.field("field")?,
            exists: object.field("exists")?,
        },
        "contains" => Predicate::Contains {
            field: object.field("field")?,
            value: tokens::literal(object.raw("value")?.get().as_bytes(), call)?,
        },
        "and" | "or" => {
            let predicates = array(object.raw("predicates")?, call.limits.max_rows)?
                .into_iter()
                .map(|raw| predicate(raw, call))
                .collect::<Result<_, _>>()?;
            if op == "and" {
                Predicate::And { predicates }
            } else {
                Predicate::Or { predicates }
            }
        }
        "not" => Predicate::Not {
            predicate: Box::new(predicate(object.raw("predicate")?, call)?),
        },
        _ => return Err(invalid("unknown predicate operation")),
    };
    object.finish()?;
    Ok(value)
}
pub(super) fn query(raw: &RawValue, call: &Call) -> Result<QueryRequest, ClientError> {
    let mut object = Object::new(raw)?;
    let value = QueryRequest {
        collection: object.field("collection")?,
        filter: predicate(object.raw("filter")?, call)?,
        sort: object.field("sort")?,
        projection: object.field("projection")?,
        aggregates: object.field("aggregates")?,
        group_by: object.field("group_by")?,
        text: object.field("text")?,
        limit: object.field("limit")?,
        cursor: object.field("cursor")?,
        allow_scan: object.field("allow_scan")?,
    };
    object.finish()?;
    if value.limit == 0 || value.limit > call.limits.max_rows {
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
