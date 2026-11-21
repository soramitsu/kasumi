//! Canonical ordered components for a bounded compound directory key.
//! Missing fields make a tuple sparse. A tuple exceeding the native key
//! budget remains a valid unique tuple and keeps its generation's fallback.
use crate::{FieldValue, Record, Scalar, structured::record_value};
use kasumi_types::{IndexField, Result};

/// Leaves room for the collection and fixed ordinal in a 1 KiB page key.
pub const MAX_ORDERED_TUPLE_BYTES: usize = 720;
pub const ORDERED_TUPLE_WINDOW: usize = 16;
pub type OrderedTupleWindow = Vec<(Vec<u8>, String)>;

fn part(out: &mut Vec<u8>, value: FieldValue<'_>) -> bool {
    let payload = value.bytes.as_ref();
    if payload.len() > MAX_ORDERED_TUPLE_BYTES.saturating_sub(out.len()) {
        return false;
    }
    let size = if value.tag < 4 || value.tag > 5 {
        1
    } else {
        3 + payload.len() + payload.iter().filter(|b| **b == 0).count()
    };
    if out.len() + size > MAX_ORDERED_TUPLE_BYTES {
        return false;
    }
    out.push(value.tag);
    if matches!(value.tag, 4 | 5) {
        for byte in payload {
            out.push(*byte);
            if *byte == 0 {
                out.push(255);
            }
        }
        out.extend_from_slice(&[0, 1]);
    }
    true
}

pub(crate) fn encode(key: &[Scalar]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    for scalar in key {
        let value = if *scalar == Scalar::UpperBound {
            FieldValue {
                tag: 6,
                bytes: std::borrow::Cow::Borrowed(&[]),
            }
        } else {
            FieldValue::from_scalar(scalar)
        };
        if !part(&mut result, value) {
            return None;
        }
    }
    Some(result)
}

/// Encode the same logical key directly from a live or archived projection.
pub fn ordered_record_tuple(fields: &[IndexField], record: Record<'_>) -> Result<Option<Vec<u8>>> {
    let mut result = Vec::new();
    for field in fields {
        let Some(value) = record_value(record, &field.path) else {
            return Ok(None);
        };
        if !part(&mut result, FieldValue::predicate(value, field.kind)?) {
            return Ok(None);
        }
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::decimal;
    #[test]
    fn bounded_compound_encoding_matches_scalar_order_including_prefixes_and_sentinels() {
        let fields = vec![
            Scalar::Null,
            Scalar::Boolean(false),
            Scalar::Boolean(true),
            Scalar::Number(decimal("-20.5").unwrap()),
            Scalar::Number(decimal("-1.2").unwrap()),
            Scalar::Number(decimal("0").unwrap()),
            Scalar::Number(decimal("1.21").unwrap()),
            Scalar::String("".into()),
            Scalar::String("a".into()),
            Scalar::String("a\0".into()),
            Scalar::String("a\0z".into()),
            Scalar::String("aa".into()),
            Scalar::String("é".into()),
            Scalar::UpperBound,
        ];
        let mut tuples = vec![vec![]];
        for field in &fields {
            tuples.push(vec![field.clone()]);
            for other in &fields {
                tuples.push(vec![field.clone(), other.clone()]);
            }
        }
        tuples.sort();
        let encoded = tuples
            .iter()
            .map(|tuple| encode(tuple).unwrap())
            .collect::<Vec<_>>();
        assert!(encoded.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(encode(&[Scalar::String("x".repeat(MAX_ORDERED_TUPLE_BYTES - 3))]).is_some());
        assert!(encode(&[Scalar::String("x".repeat(MAX_ORDERED_TUPLE_BYTES - 2))]).is_none());
        assert!(encode(&[Scalar::String("\0".repeat(MAX_ORDERED_TUPLE_BYTES / 2))]).is_none());
    }
}
