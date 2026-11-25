use crate::{QueryMemory, QueryWorkspace, allocation};
use bigdecimal::BigDecimal;
use bigdecimal::num_bigint::BigInt;
use kasumi_types::{Error, ErrorCode, Result, ScalarType};
use serde_json::Value;
use std::str::FromStr;

/// A query owns its temporary string. Persistent compound tuples can instead
/// share the immutable scalar already held by the field posting root.
#[derive(Clone)]
pub(crate) enum IndexString {
    Owned(String),
    Shared(std::sync::Arc<str>),
}

impl IndexString {
    pub(crate) fn into_string(self) -> String {
        match self {
            Self::Owned(text) => text,
            Self::Shared(text) => text.to_string(),
        }
    }
}
impl From<String> for IndexString {
    fn from(text: String) -> Self {
        Self::Owned(text)
    }
}
impl From<&str> for IndexString {
    fn from(text: &str) -> Self {
        Self::Owned(text.to_owned())
    }
}
impl std::ops::Deref for IndexString {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            Self::Owned(text) => text,
            Self::Shared(text) => text,
        }
    }
}
impl std::fmt::Debug for IndexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}
impl PartialEq for IndexString {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl Eq for IndexString {}
impl Ord for IndexString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (**self).cmp(other)
    }
}
impl PartialOrd for IndexString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Order is explicit: absent < null < boolean < number < string.
/// Declared fields never mix non-null types. Decimal fields use numeric order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scalar {
    Missing,
    Null,
    Boolean(bool),
    Number(BigDecimal),
    String(IndexString),
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
    match short_decimal(text) {
        Some(number) => Ok(number),
        None => parse_decimal(text),
    }
}

/// The value `parse_decimal` returns for plain decimal text,
/// `-?digits[.digits]` with at most 18 digits in all, which covers almost
/// every stored number. Its coefficient fits an `i64`, so it is built and
/// normalized directly: the same value and representation as parsing and
/// then calling `normalized`, without the base-10 digit vector round trip
/// that `normalized` makes. Other text, including a `+` sign, an exponent or
/// digit separators, returns `None` for the general parser and its limits.
fn short_decimal(text: &str) -> Option<BigDecimal> {
    let (negative, unsigned) = match text.as_bytes() {
        [b'-', rest @ ..] => (true, rest),
        bytes => (false, bytes),
    };
    let mut coefficient = 0i64;
    let mut digits = 0;
    let mut whole_digits = 0;
    let mut scale = 0i64;
    let mut point = false;
    for &byte in unsigned {
        match byte {
            b'0'..=b'9' if digits < 18 => {
                coefficient = coefficient * 10 + i64::from(byte - b'0');
                digits += 1;
                if point {
                    scale += 1;
                } else {
                    whole_digits += 1;
                }
            }
            b'.' if !point => point = true,
            _ => return None,
        }
    }
    if whole_digits == 0 || (point && scale == 0) {
        return None;
    }
    if coefficient == 0 {
        return Some(BigDecimal::new(BigInt::from(0), 0));
    }
    while coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    if negative {
        coefficient = -coefficient;
    }
    Some(BigDecimal::new(BigInt::from(coefficient), scale))
}

fn parse_decimal(text: &str) -> Result<BigDecimal> {
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
            Ok(Scalar::String(text.clone().into()))
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
pub(crate) const PROVISIONAL_DECIMAL_KEY_BYTES: u64 = 256;
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

/// Lend a declared array's elements individually. Missing and explicit null
/// still represent one index key; an empty array has no keys.
fn indexed_inputs(
    value: Option<&Value>,
    kind: ScalarType,
) -> Result<impl Iterator<Item = Result<Option<&Value>>>> {
    let array = match (kind, value) {
        (ScalarType::StringArray | ScalarType::NumberArray, Some(Value::Array(values))) => {
            if values.len() > 4096 {
                return Err(invalid("indexed arrays are limited to 4096 values"));
            }
            Some(values.as_slice())
        }
        (ScalarType::StringArray | ScalarType::NumberArray, Some(value)) if !value.is_null() => {
            return Err(invalid("array index requires an array"));
        }
        _ => None,
    };
    let single = array.is_none().then_some(value);
    Ok(single
        .into_iter()
        .map(Ok)
        .chain(array.unwrap_or_default().iter().map(|element| {
            if element.is_null() {
                Err(invalid("indexed array elements cannot be null"))
            } else {
                Ok(Some(element))
            }
        })))
}

pub(crate) fn indexed_values(value: Option<&Value>, kind: ScalarType) -> Result<Vec<Scalar>> {
    indexed_inputs(value, kind)?
        .map(|part| scalar(part?, Some(kind)))
        .collect()
}

pub(crate) fn validate_indexed_values(value: Option<&Value>, kind: ScalarType) -> Result<()> {
    for part in indexed_inputs(value, kind)? {
        let part = part?;
        // Arbitrary UTF-8 strings are valid for both string index kinds.
        // Validation needs their type, while the writer constructs the key.
        if !matches!(
            (kind, part),
            (
                ScalarType::String | ScalarType::StringArray,
                Some(Value::String(_))
            )
        ) {
            scalar(part, Some(kind))?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(number: BigDecimal) -> (BigInt, i64) {
        number.into_bigint_and_scale()
    }

    type Outcome = std::result::Result<(BigInt, i64), (ErrorCode, String)>;

    fn outcome(parsed: Result<BigDecimal>) -> Outcome {
        parsed
            .map(parts)
            .map_err(|error| (error.code, error.message))
    }

    /// Deterministic digit strings: every length up to 19 digits, with and
    /// without a sign, leading zeros, trailing zeros and a decimal point.
    fn generated() -> Vec<String> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut inputs = Vec::new();
        for length in 1..=19usize {
            for _ in 0..400 {
                let mut digits: Vec<u8> = (0..length).map(|_| b'0' + (next() % 10) as u8).collect();
                match next() % 4 {
                    0 => digits[0] = b'0',
                    1 => *digits.last_mut().unwrap() = b'0',
                    2 => {
                        let zeros = (next() as usize % length) + 1;
                        for digit in &mut digits[length - zeros..] {
                            *digit = b'0';
                        }
                    }
                    _ => {}
                }
                let mut text = String::from_utf8(digits).unwrap();
                if length > 1 && next() % 2 == 0 {
                    text.insert(1 + next() as usize % (length - 1), '.');
                }
                if next() % 2 == 0 {
                    text.insert(0, '-');
                }
                inputs.push(text);
            }
        }
        inputs
    }

    #[test]
    fn short_decimals_equal_the_general_parser_in_value_and_representation() {
        let mut inputs: Vec<String> = [
            "0",
            "-0",
            "00",
            "0.0",
            "-0.000",
            "1",
            "-1",
            "10",
            "-10",
            "100",
            "5000",
            "-5000",
            "1.50",
            "-1.50",
            "0.001",
            "-0.001",
            "0012.3400",
            "7919",
            "120.000",
            "999999999999999999",
            "-999999999999999999",
            "100000000000000000",
            "0.00000000000000001",
            "-99999999.9999999999",
            "123456789012345678",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        inputs.extend(generated());
        let mut short = 0;
        for text in &inputs {
            let general = outcome(parse_decimal(text));
            match short_decimal(text) {
                Some(number) => {
                    short += 1;
                    assert_eq!(Ok(parts(number)), general, "{text}");
                }
                // Too many digits for the short form.
                None => assert!(
                    text.bytes().filter(u8::is_ascii_digit).count() > 18,
                    "{text}"
                ),
            }
            assert_eq!(outcome(decimal(text)), general, "{text}");
        }
        assert!(short > inputs.len() / 2);
    }

    #[test]
    fn other_decimal_text_keeps_the_general_parser_and_its_limits() {
        for text in [
            "",
            "-",
            ".",
            "-.",
            ".5",
            "5.",
            "-5.",
            "1.2.3",
            "+5",
            "--5",
            "1_000",
            "1e3",
            "1E-3",
            "-2.5e+10",
            " 1",
            "1 ",
            "0x10",
            "1,5",
            "١",
            "NaN",
            "inf",
            "1234567890123456789",
            "-0.000000000000000001",
            "1e1001",
        ] {
            assert!(short_decimal(text).is_none(), "{text}");
            assert_eq!(
                outcome(decimal(text)),
                outcome(parse_decimal(text)),
                "{text}"
            );
        }
        assert_eq!(
            parts(decimal("1e3").unwrap()),
            parts(decimal("1000").unwrap())
        );
        assert_eq!(
            decimal(&"9".repeat(101)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
}
