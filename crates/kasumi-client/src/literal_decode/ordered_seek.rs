//! Literal, allocation-admitted ordered seek response boundary. Only metadata
//! passes through stock Deserialize; document and tuple values stay literal.
use super::{
    json::{Object, array},
    tokens,
};
use crate::{
    ClientError,
    snapshot_decode::resources::{Call, invalid},
};
use kasumi_types::{OrderedSeekContinuation, OrderedSeekRequest, OrderedSeekResponse, QueryRow};
use serde_json::{Value, value::RawValue};
use std::collections::BTreeSet;

fn tuple(raw: &RawValue, call: &Call) -> Result<Vec<Value>, ClientError> {
    array(raw, 8)?
        .into_iter()
        .map(|v| {
            if v.get().len() > 1024 {
                return Err(invalid("ordered seek tuple scalar bound"));
            }
            let value = tokens::literal(v.get().as_bytes(), call)?;
            if value.is_array() || value.is_object() {
                return Err(invalid("ordered seek tuple must be scalar"));
            }
            Ok(value)
        })
        .collect()
}
fn continuation(
    raw: &RawValue,
    call: &Call,
) -> Result<Option<OrderedSeekContinuation>, ClientError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    let mut o = Object::new(raw)?;
    let result = OrderedSeekContinuation {
        revision: o.field("revision")?,
        tenant: o.field("tenant")?,
        incarnation: o.field("incarnation")?,
        collection_epoch: o.field("collection_epoch")?,
        policy_epoch: o.field("policy_epoch")?,
        schema_epoch: o.field("schema_epoch")?,
        index_sha256: o.field("index_sha256")?,
        request_sha256: o.field("request_sha256")?,
        after_key: tuple(o.raw("after_key")?, call)?,
    };
    o.finish()?;
    Ok(Some(result))
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .is_some_and(|u| !u.is_nil() && u.to_string() == value)
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn same_source(c: &OrderedSeekContinuation, r: &OrderedSeekResponse) -> bool {
    c.revision == r.revision
        && c.tenant == r.tenant
        && c.incarnation == r.incarnation
        && c.collection_epoch == r.collection_epoch
        && c.policy_epoch == r.policy_epoch
        && c.schema_epoch == r.schema_epoch
        && c.index_sha256 == r.index_sha256
        && c.request_sha256 == r.request_sha256
}
pub(super) fn decode(
    raw: &RawValue,
    request: &OrderedSeekRequest,
    digest: &str,
    call: &Call,
) -> Result<OrderedSeekResponse, ClientError> {
    let mut o = Object::new(raw)?;
    let mut result = OrderedSeekResponse {
        revision: o.field("revision")?,
        observed_revision: o.field("observed_revision")?,
        tenant: o.field("tenant")?,
        incarnation: o.field("incarnation")?,
        collection_epoch: o.field("collection_epoch")?,
        policy_epoch: o.field("policy_epoch")?,
        schema_epoch: o.field("schema_epoch")?,
        index_sha256: o.field("index_sha256")?,
        request_sha256: o.field("request_sha256")?,
        index_entries_visited: o.field("index_entries_visited")?,
        rows: Vec::new(),
        continuation: continuation(o.raw("continuation")?, call)?,
    };
    let rows = array(o.raw("rows")?, request.limit.min(call.limits.max_rows))?;
    o.finish()?;
    if kasumi_types::validate_name(&result.tenant).is_err()
        || !uuid(&result.incarnation)
        || !hash(&result.index_sha256)
        || !hash(&result.request_sha256)
        || result.request_sha256 != digest
        || result.revision > result.observed_revision
        || result.collection_epoch > result.revision
        || result.schema_epoch > result.policy_epoch
        || result.policy_epoch > result.observed_revision
        || result.index_entries_visited > request.limit as u64 + 1
        || result.index_entries_visited < rows.len() as u64
        || request.continuation.as_ref().is_none() && result.revision != result.observed_revision
        || request
            .continuation
            .as_ref()
            .is_some_and(|c| !same_source(c, &result))
        || result.continuation.as_ref().is_some_and(|c| {
            !same_source(c, &result)
                || rows.len() != request.limit
                || c.after_key.len() <= request.prefix.len()
                || !c.after_key.starts_with(&request.prefix)
                || request
                    .continuation
                    .as_ref()
                    .is_some_and(|old| old.after_key == c.after_key)
        })
    {
        return Err(invalid("ordered seek source or continuation differs"));
    }
    let mut ids = BTreeSet::new();
    for raw in rows {
        call.check()?;
        let mut row = Object::new(raw)?;
        let id: String = row.field("id")?;
        let version: u64 = row.field("version")?;
        let score: Option<f32> = row.field("score")?;
        let body = row.raw("body")?;
        row.finish()?;
        if id.is_empty()
            || !ids.insert(id.clone())
            || version == 0
            || version > result.revision
            || score.is_some()
        {
            return Err(invalid("ordered seek row identity/version differs"));
        }
        result.rows.push(QueryRow {
            id,
            version,
            score,
            body: tokens::literal(body.get().as_bytes(), call)?,
        });
    }
    call.check()?;
    Ok(result)
}
