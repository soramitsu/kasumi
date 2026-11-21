//! Canonical ordered components for a bounded compound directory key.
//! Missing fields make a tuple sparse. A tuple exceeding the native key
//! budget remains a valid unique tuple and keeps its generation's fallback.
use crate::{FieldValue, Record, Scalar, structured::record_value};
use kasumi_types::{IndexField, Result};

/// Leaves room for the collection and fixed ordinal in a 1 KiB page key.
pub const MAX_ORDERED_TUPLE_BYTES: usize = 720;
pub const ORDERED_TUPLE_WINDOW: usize = 16;
pub type OrderedTupleWindow = Vec<(Vec<u8>, String)>;

pub(crate) fn check_window(
    rows: &[(Vec<u8>, String)],
    lower: std::ops::Bound<&[u8]>,
    upper: std::ops::Bound<&[u8]>,
    descending: bool,
) -> Result<()> {
    use std::ops::RangeBounds;
    let corrupt = || {
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::Corruption,
            "compound directory returned an invalid ordered window",
        )
    };
    if rows.len() > ORDERED_TUPLE_WINDOW {
        return Err(corrupt());
    }
    let mut previous = None;
    for (key, id) in rows {
        if key.is_empty()
            || key.len() > MAX_ORDERED_TUPLE_BYTES
            || !RangeBounds::<[u8]>::contains(&(lower, upper), key.as_slice())
            || previous.is_some_and(|last: &[u8]| {
                if descending {
                    last <= key.as_slice()
                } else {
                    last >= key.as_slice()
                }
            })
            || kasumi_types::validate_name(id).is_err()
        {
            return Err(corrupt());
        }
        previous = Some(key);
    }
    Ok(())
}

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
    fn seek_windows_enforce_the_bound_and_progress_in_both_directions() {
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let rows = |keys: &[u8]| -> OrderedTupleWindow {
            keys.iter()
                .map(|&key| (vec![key], format!("id{key}")))
                .collect()
        };
        check_window(&rows(&[2, 3]), Excluded(&[1]), Included(&[3]), false).unwrap();
        check_window(&rows(&[3, 2]), Excluded(&[1]), Included(&[3]), true).unwrap();
        for keys in [&[3, 1][..], &[2, 2], &[1], &[4]] {
            assert_eq!(
                check_window(&rows(keys), Excluded(&[1]), Included(&[3]), false)
                    .unwrap_err()
                    .code,
                kasumi_types::ErrorCode::Corruption
            );
        }
        assert!(
            check_window(
                &rows(&[1; ORDERED_TUPLE_WINDOW + 1]),
                Unbounded,
                Unbounded,
                false
            )
            .is_err()
        );
        assert!(check_window(&[(vec![1], String::new())], Unbounded, Unbounded, false).is_err());
    }
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
