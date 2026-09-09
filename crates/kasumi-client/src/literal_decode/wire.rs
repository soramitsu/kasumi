//! Allocation-free protobuf traversal before query DTO/body construction.
use crate::{
    ClientError,
    snapshot_decode::{
        resources::{Call, exhausted, invalid},
        tokens::{self, TokenBudget},
    },
};
use kasumi_types::{QueryRequest, QueryResponse, QueryRow};

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn varint(&mut self) -> Result<u64, ClientError> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let (&byte, rest) = self
                .0
                .split_first()
                .ok_or_else(|| invalid("truncated protobuf varint"))?;
            self.0 = rest;
            if shift == 63 && byte > 1 {
                return Err(invalid("protobuf integer overflow"));
            }
            value |= u64::from(byte & 127) << shift;
            if byte < 128 {
                if shift != 0 && byte == 0 {
                    return Err(invalid("noncanonical protobuf integer"));
                }
                return Ok(value);
            }
        }
        Err(invalid("protobuf integer overflow"))
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ClientError> {
        if length > self.0.len() {
            return Err(invalid("truncated protobuf field"));
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }
    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, ClientError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        if key >> 3 == 0 {
            return Err(invalid("invalid protobuf field number"));
        }
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| exhausted())?;
                Value::Bytes(self.take(length)?)
            }
            5 => Value::Fixed32(u32::from_le_bytes(self.take(4)?.try_into().unwrap())),
            _ => return Err(invalid("unsupported protobuf field kind")),
        };
        Ok(Some((key >> 3, value)))
    }
}
fn text<'a>(bytes: &'a [u8], call: &Call) -> Result<&'a str, ClientError> {
    if bytes.len() > call.limits.max_string_bytes {
        return Err(exhausted());
    }
    std::str::from_utf8(bytes).map_err(|_| invalid("invalid protobuf UTF-8"))
}
struct Row<'a> {
    id: &'a str,
    version: u64,
    body: &'a [u8],
    score: Option<f32>,
}
fn row<'a>(input: &'a [u8], call: &Call) -> Result<Row<'a>, ClientError> {
    let mut fields = Fields(input);
    let mut document = None;
    let mut score = None;
    while let Some((key, value)) = fields.next()? {
        call.check()?;
        match (key, value) {
            (1, Value::Bytes(value)) if document.is_none() => document = Some(value),
            (2, Value::Fixed32(value)) if score.is_none() => {
                let value = f32::from_bits(value);
                if !value.is_finite() {
                    return Err(invalid("invalid query score"));
                }
                score = Some(value);
            }
            _ => return Err(invalid("unknown/duplicate query row field")),
        }
    }
    let mut fields = Fields(document.ok_or_else(|| invalid("missing query document"))?);
    let mut id = None;
    let mut version = None;
    let mut body = None;
    while let Some((key, value)) = fields.next()? {
        call.check()?;
        match (key, value) {
            (1, Value::Bytes(value)) if id.is_none() => id = Some(text(value, call)?),
            (2, Value::Varint(value)) if version.is_none() => version = Some(value),
            (3, Value::Bytes(value)) if body.is_none() => body = Some(value),
            _ => return Err(invalid("unknown/duplicate document field")),
        }
    }
    Ok(Row {
        id: id
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("missing query document ID"))?,
        version: version
            .filter(|v| *v != 0)
            .ok_or_else(|| invalid("missing query document version"))?,
        body: body.ok_or_else(|| invalid("missing query document body"))?,
        score,
    })
}
pub(super) fn query(
    input: &[u8],
    request: &QueryRequest,
    expected_revision: Option<u64>,
    call: &Call,
) -> Result<QueryResponse, ClientError> {
    let mut fields = Fields(input);
    let mut revision = None;
    let mut rows = 0usize;
    let mut aggregates = 0usize;
    let mut cursor = None;
    let mut budget = TokenBudget::default();
    while let Some((key, value)) = fields.next()? {
        call.check()?;
        match (key, value) {
            (1, Value::Varint(value)) if revision.is_none() => revision = Some(value),
            (2, Value::Bytes(value)) => {
                rows = rows.checked_add(1).ok_or_else(exhausted)?;
                if rows > request.limit.min(call.limits.max_rows) {
                    return Err(exhausted());
                }
                let value = row(value, call)?;
                budget.metadata(value.id.len(), 8, call)?;
                tokens::admit_with(value.body, call, &mut budget)?;
            }
            (3, Value::Bytes(value)) => {
                aggregates = aggregates.checked_add(1).ok_or_else(exhausted)?;
                if aggregates > call.limits.max_rows {
                    return Err(exhausted());
                }
                tokens::admit_with(value, call, &mut budget)?;
            }
            (4, Value::Bytes(value)) if cursor.is_none() => {
                cursor = Some(text(value, call)?);
                budget.metadata(value.len(), 1, call)?;
            }
            _ => return Err(invalid("unknown/duplicate query response field")),
        }
    }
    let revision = revision.unwrap_or(0); // Protobuf's canonical omitted zero.
    if expected_revision.is_some_and(|expected| expected != revision) {
        return Err(invalid("query pagination changed its original revision"));
    }
    // No body or returned DTO exists until all bodies, tokens and lengths have
    // passed aggregate admission. Re-traverse the bounded borrowed wire.
    let mut result = QueryResponse {
        revision,
        rows: Vec::with_capacity(rows),
        aggregates: Vec::with_capacity(aggregates),
        cursor: cursor.map(str::to_owned),
    };
    let mut fields = Fields(input);
    let mut ids = std::collections::BTreeSet::new();
    while let Some((key, value)) = fields.next()? {
        call.check()?;
        match (key, value) {
            (2, Value::Bytes(value)) => {
                let row = row(value, call)?;
                if row.version > revision || !ids.insert(row.id) {
                    return Err(invalid("query row identity/revision differs"));
                }
                result.rows.push(QueryRow {
                    id: row.id.to_owned(),
                    version: row.version,
                    body: tokens::literal(row.body, call)?,
                    score: row.score,
                });
            }
            (3, Value::Bytes(value)) => result.aggregates.push(tokens::literal(value, call)?),
            _ => {}
        }
    }
    call.check()?;
    Ok(result)
}
