//! JSON object keys are strings, including when an enclosing tagged enum uses
//! Serde's buffered value decoder. Require one canonical decimal spelling and
//! reject duplicate keys before they can collapse an exact signed identity.
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt, marker::PhantomData, str::FromStr};
pub fn deserialize_u64_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<u64, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    deserialize_unsigned_map::<D, u64, V>(deserializer)
}
pub fn deserialize_u16_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<u16, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    deserialize_unsigned_map::<D, u16, V>(deserializer)
}
fn deserialize_unsigned_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Ord + FromStr + fmt::Display,
    V: Deserialize<'de>,
{
    struct Canonical<K, V>(PhantomData<(K, V)>);
    impl<'de, K: Ord + FromStr + fmt::Display, V: Deserialize<'de>> Visitor<'de>
        for Canonical<K, V>
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an object with unique canonical unsigned decimal keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                let id = key
                    .parse::<K>()
                    .map_err(|_| A::Error::custom("invalid unsigned decimal object key"))?;
                if id.to_string() != key || result.contains_key(&id) {
                    return Err(A::Error::custom("noncanonical or duplicate object key"));
                }
                result.insert(id, map.next_value()?);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Canonical(PhantomData))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Tagged {
        Value {
            #[serde(deserialize_with = "deserialize_u64_map")]
            nodes: BTreeMap<u64, String>,
        },
    }
    #[test]
    fn tagged_json_keys_are_canonical_and_duplicates_cannot_change_identity() {
        let value = Tagged::Value {
            nodes: BTreeMap::from([(1, "one".into()), (u64::MAX, "last".into())]),
        };
        assert_eq!(
            serde_json::from_slice::<Tagged>(&serde_json::to_vec(&value).unwrap()).unwrap(),
            value
        );
        for text in [
            r#"{"kind":"value","nodes":{"01":"one"}}"#,
            r#"{"kind":"value","nodes":{"+1":"one"}}"#,
            r#"{"kind":"value","nodes":{"1":"one","1":"other"}}"#,
        ] {
            assert!(serde_json::from_str::<Tagged>(text).is_err());
        }
    }

    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Partitions {
        Value {
            #[serde(deserialize_with = "deserialize_u16_map")]
            partitions: BTreeMap<u16, String>,
        },
    }
    #[test]
    fn tagged_partition_keys_round_trip_through_bytes_and_values() {
        let value = Partitions::Value {
            partitions: BTreeMap::from([(0, "first".into()), (u16::MAX, "last".into())]),
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(serde_json::from_slice::<Partitions>(&bytes).unwrap(), value);
        assert_eq!(
            serde_json::from_value::<Partitions>(serde_json::to_value(&value).unwrap()).unwrap(),
            value
        );
    }
    #[test]
    fn tagged_partition_keys_reject_aliases_duplicates_and_out_of_range_values() {
        for key in ["00", "+0", "-0", "-1", "65536", "1.0", " 1", "1e1"] {
            let text = format!(r#"{{"kind":"value","partitions":{{"{key}":"bad"}}}}"#);
            assert!(serde_json::from_str::<Partitions>(&text).is_err(), "{key}");
        }
        assert!(
            serde_json::from_str::<Partitions>(
                r#"{"kind":"value","partitions":{"0":"first","0":"replacement"}}"#
            )
            .is_err()
        );
    }
}
