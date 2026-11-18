//! Scalar dictionary order for the durable structured index. Long UTF-8 keys
//! stay borrowed. Numeric ordering is independent of the original spelling.
use crate::{QueryIndexes, Scalar};
use kasumi_types::{Result, ScalarType};
use serde_json::Value;
use std::{borrow::Cow, ops::Bound};

/// A field index selected by the current query plan.
#[derive(Clone, Copy)]
pub enum FieldPredicate<'a> {
    Exists(bool),
    Equals {
        value: &'a Value,
        kind: ScalarType,
    },
    Range {
        lower: Bound<&'a Value>,
        upper: Bound<&'a Value>,
        kind: ScalarType,
    },
}

/// Type tag and ordered payload in a selected field dictionary.
pub struct FieldValue<'a> {
    pub tag: u8,
    pub bytes: Cow<'a, [u8]>,
}

impl<'a> FieldValue<'a> {
    fn empty(tag: u8) -> Self {
        Self {
            tag,
            bytes: Cow::Borrowed(&[]),
        }
    }
    fn string(value: &'a str) -> Self {
        Self {
            tag: 5,
            bytes: Cow::Borrowed(value.as_bytes()),
        }
    }
    fn number(n: &crate::BigDecimal) -> Self {
        use bigdecimal::num_bigint::Sign;
        let (coefficient, scale) = n.normalized().as_bigint_and_exponent();
        let sign = coefficient.sign();
        let bytes = if sign == Sign::NoSign {
            vec![1]
        } else {
            // Inputs have at most 100 digits and a bounded exponent. Compare
            // exponent first, then significand digits with a low terminator.
            let digits = coefficient.magnitude().to_str_radix(10);
            let exponent = digits.len() as i64 - scale;
            let mut bytes = Vec::with_capacity(10 + digits.len());
            bytes.push(if sign == Sign::Minus { 0 } else { 2 });
            bytes.extend_from_slice(&((exponent as u64) ^ (1 << 63)).to_be_bytes());
            bytes.extend_from_slice(digits.as_bytes());
            bytes.push(0);
            if sign == Sign::Minus {
                for b in &mut bytes[1..] {
                    *b = !*b;
                }
            }
            bytes
        };
        Self {
            tag: 4,
            bytes: Cow::Owned(bytes),
        }
    }
    fn from_scalar(value: &'a Scalar) -> Self {
        match value {
            Scalar::Missing => Self::empty(0),
            Scalar::Null => Self::empty(1),
            Scalar::Boolean(b) => Self::empty(2 + u8::from(*b)),
            Scalar::Number(n) => Self::number(n),
            Scalar::String(s) => Self::string(s),
            Scalar::UpperBound => unreachable!("range sentinel cannot be inserted into a posting"),
        }
    }
    pub fn predicate(value: &'a Value, kind: ScalarType) -> Result<Self> {
        if value.is_null() {
            return Ok(Self::empty(1));
        }
        Ok(match (kind, value) {
            (ScalarType::String | ScalarType::StringArray, Value::String(s)) => Self::string(s),
            (ScalarType::Number | ScalarType::NumberArray, Value::Number(n)) => {
                Self::number(&crate::scalar::decimal(n.as_str())?)
            }
            (ScalarType::Decimal, Value::String(s)) => Self::number(&crate::scalar::decimal(s)?),
            (ScalarType::Boolean, Value::Bool(b)) => Self::empty(2 + u8::from(*b)),
            _ => {
                return Err(crate::invalid(
                    "value does not match the declared scalar type",
                ));
            }
        })
    }
}

/// Each field starts with its dictionary size. Its values are ranked in
/// canonical scalar order, and each associated ID list is in document order.
pub enum FieldPostingRow<'a> {
    Count(usize),
    Value {
        ordinal: usize,
        value: FieldValue<'a>,
    },
    Id {
        ordinal: usize,
        id: &'a str,
    },
}

impl QueryIndexes {
    pub fn visit_field_values<E>(
        &self,
        mut emit: impl FnMut(&str, usize, FieldPostingRow<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        for (collection, indexes) in &self.collections {
            for (field, index) in indexes.structured.fields.values().enumerate() {
                emit(
                    collection,
                    field,
                    FieldPostingRow::Count(index.entries.len()),
                )?;
                for (ordinal, (key, ids)) in index.entries.iter().enumerate() {
                    emit(
                        collection,
                        field,
                        FieldPostingRow::Value {
                            ordinal,
                            value: FieldValue::from_scalar(key),
                        },
                    )?;
                    for id in ids {
                        emit(collection, field, FieldPostingRow::Id { ordinal, id })?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_numeric_dictionary_preserves_exact_scalar_order() {
        let values = [
            "-1e1000", "-9.99", "-1.21", "-1.2", "-1.01", "-1", "-0.01", "-1e-1000", "0",
            "1e-1000", "0.01", "1", "1.01", "1.2", "1.21", "9.99", "1e1000",
        ];
        let representations: Vec<_> = values
            .iter()
            .map(|s| FieldValue::number(&crate::scalar::decimal(s).unwrap()).bytes)
            .collect();
        assert!(representations.windows(2).all(|pair| pair[0] < pair[1]));
        for (a, b) in [("-0.0", "0"), ("1.2000", "12e-1"), ("-55", "-0.55e2")] {
            assert_eq!(
                FieldValue::number(&crate::scalar::decimal(a).unwrap()).bytes,
                FieldValue::number(&crate::scalar::decimal(b).unwrap()).bytes
            );
        }
    }
}
