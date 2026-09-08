//! Stable literal JSON values inside otherwise typed Serde contracts.
use serde::{
    Serialize, Serializer,
    ser::{Error, SerializeMap, SerializeSeq},
};
use serde_json::Value;

/// Borrowed JSON serialization with recursively sorted object keys.
///
/// Keys use Rust string ordering, matching serde_json's default BTreeMap order.
/// Arrays retain their order; strings and arbitrary-precision numbers retain
/// their exact values. Literal objects, including Serde's private marker keys,
/// remain maps. Only an actual `Value::Number` uses Number's serializer.
///
/// Use with a JSON writer or `staged_digest`. This does not make generic
/// `to_value`/`from_value` bridges safe literal JSON decoders. It neither clones
/// the payload nor constructs an encoded payload buffer. Unsorted objects use
/// temporary borrowed-entry metadata; already sorted objects stream directly.
#[derive(Clone, Copy)]
pub struct CanonicalJsonValue<'a>(pub &'a Value);

impl Serialize for CanonicalJsonValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => value.serialize(serializer),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Self(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                if values.keys().is_sorted() {
                    for (key, value) in values {
                        map.serialize_entry(key, &Self(value))?;
                    }
                } else {
                    let mut entries = Vec::new();
                    entries
                        .try_reserve_exact(values.len())
                        .map_err(|_| S::Error::custom("canonical object metadata exhausted"))?;
                    entries.extend(values.iter());
                    entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                    for (key, value) in entries {
                        map.serialize_entry(key, &Self(value))?;
                    }
                }
                map.end()
            }
        }
    }
}

pub(crate) fn serialize<S: Serializer>(value: &Value, serializer: S) -> Result<S::Ok, S::Error> {
    CanonicalJsonValue(value).serialize(serializer)
}
