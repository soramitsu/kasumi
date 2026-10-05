use crate::{QueryMemory, QueryWorkspace, allocation};
use bigdecimal::BigDecimal;
use kasumi_types::{Error, ErrorCode, Result, ScalarType};
use serde_json::Value;
use std::str::FromStr;

/// Order is explicit: absent < null < boolean < number < string.
/// Declared fields never mix non-null types. Decimal fields use numeric order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scalar {
    Missing,
    Null,
    Boolean(bool),
    Number(BigDecimal),
    String(String),
    /// Internal ordered-prefix upper bound; never parsed from or stored as JSON.
    UpperBound,
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
pub(crate) fn exhausted(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::ResourceExhausted, message)
}

pub(crate) fn decimal(text: &str) -> Result<BigDecimal> {
    if text.len() > 256 {
        return Err(invalid("number exceeds 256-byte limit"));
    }
    let (coefficient, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    if coefficient.bytes().filter(u8::is_ascii_digit).count() > 100 {
        return Err(invalid("number exceeds 100 significant/input digits"));
    }
    let exponent: i32 = exponent
        .parse()
        .map_err(|_| invalid("invalid numeric exponent"))?;
    if !(-1000..=1000).contains(&exponent) {
        return Err(invalid("numeric exponent must be between -1000 and 1000"));
    }
    let number = BigDecimal::from_str(text).map_err(|_| invalid("invalid exact decimal"))?;
    Ok(number.normalized())
}

pub(crate) fn scalar(value: Option<&Value>, kind: Option<ScalarType>) -> Result<Scalar> {
    let Some(value) = value else {
        return Ok(Scalar::Missing);
    };
    if value.is_null() {
        return Ok(Scalar::Null);
    }
    match (kind, value) {
        (Some(ScalarType::Decimal), Value::String(text)) => Ok(Scalar::Number(decimal(text)?)),
        (Some(ScalarType::String | ScalarType::StringArray) | None, Value::String(text)) => {
            Ok(Scalar::String(text.clone()))
        }
        (Some(ScalarType::Number | ScalarType::NumberArray) | None, Value::Number(n)) => {
            Ok(Scalar::Number(decimal(n.as_str())?))
        }
        (Some(ScalarType::Boolean) | None, Value::Bool(b)) => Ok(Scalar::Boolean(*b)),
        _ => Err(invalid("value does not match the declared scalar type")),
    }
}

// Explicit provisional allowances, not measured bounds on bigdecimal/num-bigint
// allocation. Parsing, normalization and numeric comparisons need a separate
// library audit before complete decimal workspace accounting is qualified.
const PROVISIONAL_DECIMAL_KEY_BYTES: u64 = 256;
pub(crate) const PROVISIONAL_DECIMAL_SCRATCH_BYTES: u64 = 4096;

/// Sort-key copies admit their actual String backing before construction.
/// Decimal ownership and temporary arithmetic remain explicitly provisional.
pub(crate) fn query_scalar<W: QueryWorkspace>(
    value: Option<&Value>,
    kind: Option<ScalarType>,
    memory: &mut QueryMemory<W>,
) -> Result<(Scalar, u64)> {
    let numeric = matches!(
        (kind, value),
        (Some(ScalarType::Decimal), Some(Value::String(_)))
            | (
                Some(ScalarType::Number | ScalarType::NumberArray) | None,
                Some(Value::Number(_))
            )
    );
    if numeric {
        let key = memory.scope::<_, Error>(|memory| {
            memory.reserve(allocation::add(
                PROVISIONAL_DECIMAL_KEY_BYTES,
                PROVISIONAL_DECIMAL_SCRATCH_BYTES,
            )?)?;
            Ok((scalar(value, kind)?, PROVISIONAL_DECIMAL_KEY_BYTES))
        })?;
        return Ok((key, PROVISIONAL_DECIMAL_KEY_BYTES));
    }
    let bytes = match (kind, value) {
        (Some(ScalarType::String | ScalarType::StringArray) | None, Some(Value::String(text))) => {
            allocation::string_clone_bytes(text)?
        }
        _ => 0,
    };
    memory.reserve(bytes)?;
    Ok((scalar(value, kind)?, bytes))
}

pub(crate) fn indexed_values(value: Option<&Value>, kind: ScalarType) -> Result<Vec<Scalar>> {
    match kind {
        ScalarType::StringArray | ScalarType::NumberArray => match value {
            None => Ok(vec![Scalar::Missing]),
            Some(Value::Null) => Ok(vec![Scalar::Null]),
            Some(Value::Array(values)) => {
                if values.len() > 4096 {
                    return Err(invalid("indexed arrays are limited to 4096 values"));
                }
                values
                    .iter()
                    .map(|v| {
                        if v.is_null() {
                            return Err(invalid("indexed array elements cannot be null"));
                        }
                        scalar(Some(v), Some(kind))
                    })
                    .collect()
            }
            _ => Err(invalid("array index requires an array")),
        },
        _ => Ok(vec![scalar(value, Some(kind))?]),
    }
}

pub(crate) fn validate_pointer(path: &str) -> Result<()> {
    if path.len() > 1024 || (!path.is_empty() && !path.starts_with('/')) {
        return Err(invalid(
            "field must be a JSON Pointer of at most 1024 bytes",
        ));
    }
    let mut chars = path.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return Err(invalid("invalid JSON Pointer escape"));
        }
    }
    Ok(())
}

/// An exact computed number in its field's declared form: a decimal string
/// for `decimal` fields and an exact JSON number otherwise.
pub(crate) fn numeric_value(n: &BigDecimal, kind: Option<ScalarType>) -> Result<Value> {
    let text = n.normalized().to_string();
    if kind == Some(ScalarType::Decimal) {
        return Ok(Value::String(text));
    }
    serde_json::from_str(&text).map_err(|_| invalid("cannot encode exact number"))
}
