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
    let mut push = |byte| {
        if out.len() == MAX_ORDERED_TUPLE_BYTES {
            return false;
        }
        out.push(byte);
        true
    };
    if !push(value.tag) {
        return false;
    }
    if matches!(value.tag, 4 | 5) {
        for &byte in value.bytes.as_ref() {
            if !push(byte) || (byte == 0 && !push(255)) {
                return false;
            }
        }
        if !push(0) || !push(1) {
            return false;
        }
    }
    true
}

fn parts(key: &[Scalar], keep_prefix: bool) -> (Vec<u8>, bool) {
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
        if (!keep_prefix && value.bytes.len() > MAX_ORDERED_TUPLE_BYTES - result.len())
            || !part(&mut result, value)
        {
            return (result, false);
        }
    }
    (result, true)
}

pub(crate) fn encode(key: &[Scalar]) -> Option<Vec<u8>> {
    let (result, complete) = parts(key, false);
    complete.then_some(result)
}

/// Every stored key is at most M bytes. For a longer limit, a stored key
/// equal to its first M bytes sorts strictly before the complete limit.
/// This remains true if the cut splits a zero escape or a tuple terminator.
pub(crate) fn range_bound(
    bound: &std::ops::Bound<Vec<Scalar>>,
    lower: bool,
) -> std::ops::Bound<Vec<u8>> {
    use std::ops::Bound;
    let (key, inclusive) = match bound {
        Bound::Included(key) => (key, true),
        Bound::Excluded(key) => (key, false),
        Bound::Unbounded => return Bound::Unbounded,
    };
    let (prefix, complete) = parts(key, true);
    let inclusive = if complete { inclusive } else { !lower };
    if inclusive {
        Bound::Included(prefix)
    } else {
        Bound::Excluded(prefix)
    }
}

/// Compare an entire native key against an oversized typed tuple without
/// materializing the latter. Equal prefixes sort before the longer tuple.
pub(crate) fn compare_overflow(native: &[u8], overflow: &[Scalar]) -> std::cmp::Ordering {
    let (prefix, complete) = parts(overflow, true);
    debug_assert!(!complete);
    native.cmp(&prefix).then(std::cmp::Ordering::Less)
}

/// Encode the same logical key directly from a live or archived projection.
pub fn ordered_record_tuple(fields: &[IndexField], record: Record<'_>) -> Result<Option<Vec<u8>>> {
    let mut result = Vec::new();
    for field in fields {
        let Some(value) = record_value(record, &field.path) else {
            return Ok(None);
        };
        let value = FieldValue::predicate(value, field.kind)?;
        if value.bytes.len() > MAX_ORDERED_TUPLE_BYTES - result.len() || !part(&mut result, value) {
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
    fn very_long_seek_bounds_preserve_order_for_every_storable_key() {
        use std::ops::{Bound, RangeBounds};
        let long = "k".repeat(MAX_ORDERED_TUPLE_BYTES - 4);
        let stored = [
            vec![Scalar::Null],
            vec![Scalar::String(long.clone().into())],
            vec![Scalar::String(format!("{long}a").into())],
            vec![Scalar::String(format!("{long}b").into())],
            vec![Scalar::String(long.clone().into()), Scalar::Boolean(true)],
            vec![Scalar::String("z".into())],
        ];
        let limits = [
            vec![Scalar::String(
                format!("{long}a{}", "a".repeat(4096)).into(),
            )],
            vec![Scalar::String(format!("{long}\0x").into())],
            vec![
                Scalar::String(long.into()),
                Scalar::String("k".repeat(1024).into()),
            ],
            vec![Scalar::UpperBound],
        ];
        for limit in limits {
            for original in [Bound::Included(limit.clone()), Bound::Excluded(limit)] {
                for tuple in &stored {
                    let native = encode(tuple).expect("stored key fits");
                    for lower in [true, false] {
                        let capped = range_bound(&original, lower);
                        let logical = if lower {
                            (original.as_ref(), Bound::Unbounded)
                        } else {
                            (Bound::Unbounded, original.as_ref())
                        };
                        let physical = if lower {
                            (capped.as_ref(), Bound::Unbounded)
                        } else {
                            (Bound::Unbounded, capped.as_ref())
                        };
                        assert_eq!(logical.contains(tuple), physical.contains(&native));
                    }
                }
            }
        }
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
        assert!(
            encode(&[Scalar::String(
                "x".repeat(MAX_ORDERED_TUPLE_BYTES - 3).into()
            )])
            .is_some()
        );
        assert!(
            encode(&[Scalar::String(
                "x".repeat(MAX_ORDERED_TUPLE_BYTES - 2).into()
            )])
            .is_none()
        );
        assert!(
            encode(&[Scalar::String(
                "\0".repeat(MAX_ORDERED_TUPLE_BYTES / 2).into()
            )])
            .is_none()
        );
    }
}
