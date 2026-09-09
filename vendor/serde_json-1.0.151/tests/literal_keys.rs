use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const NUMBER: &str = "$serde_json::private::Number";
const RAW: &str = "$serde_json::private::RawValue";

fn object(key: &str, value: Value) -> Value {
    let mut map = Map::new();
    map.insert(key.to_owned(), value);
    Value::Object(map)
}

#[test]
fn every_string_marker_is_literal_including_escapes_and_invalid_inner_json() {
    for key in [NUMBER, RAW] {
        for value in [
            Value::String("7".to_owned()),
            Value::String("{\"nested\":[1,2]}".to_owned()),
            Value::String("not JSON".to_owned()),
            Value::Null,
            object("ordinary", Value::Bool(true)),
        ] {
            let expected = object(key, value);
            let text = serde_json::to_string(&expected).unwrap();
            for input in [text.clone(), text.replace('$', "\\u0024")] {
                let decoded: Value = serde_json::from_str(&input).unwrap();
                assert_eq!(decoded, expected);
                assert_eq!(
                    serde_json::from_value::<Value>(decoded.clone()).unwrap(),
                    expected
                );
                assert_eq!(Value::deserialize(&decoded).unwrap(), expected);
            }
        }
    }
}

#[test]
fn marker_order_never_changes_object_meaning() {
    for key in [NUMBER, RAW] {
        let first = format!(r#"{{"{key}":"7","ordinary":true}}"#);
        let last = format!(r#"{{"ordinary":true,"{key}":"7"}}"#);
        let expected = match object(key, Value::String("7".to_owned())) {
            Value::Object(mut map) => {
                map.insert("ordinary".to_owned(), Value::Bool(true));
                Value::Object(map)
            }
            _ => unreachable!(),
        };
        for input in [first, last] {
            assert_eq!(serde_json::from_str::<Value>(&input).unwrap(), expected);
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Tagged {
    Put { body: Value },
}

#[test]
fn tagged_content_preserves_the_string_and_byte_key_distinction() {
    for key in [NUMBER, RAW] {
        let expected = Tagged::Put {
            body: Value::Array(vec![object(key, Value::String("7".to_owned()))]),
        };
        let text = serde_json::to_string(&expected).unwrap();
        assert_eq!(serde_json::from_str::<Tagged>(&text).unwrap(), expected);
        let value = serde_json::to_value(&expected).unwrap();
        assert_eq!(
            serde_json::from_value::<Tagged>(value.clone()).unwrap(),
            expected
        );
        assert_eq!(Tagged::deserialize(&value).unwrap(), expected);
    }
}

#[test]
fn a_literal_string_does_not_start_another_json_parser() {
    // Far deeper than the stock parser limit, but ordinary string data.
    let inner = format!("{}0{}", "[".repeat(256), "]".repeat(256));
    let expected = object(RAW, Value::String(inner));
    let bytes = serde_json::to_vec(&expected).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
}

#[cfg(feature = "arbitrary_precision")]
#[test]
fn genuine_numbers_survive_direct_owned_borrowed_and_tagged_paths() {
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(untagged)]
    enum Untagged {
        Number(serde_json::Number),
        Tagged(Tagged),
    }
    for text in [
        "18446744073709551616000000000000001",
        "90071992547409931234567890.123456789",
        "18446744073709551615",                     // u64::MAX
        "18446744073709551616",                     // u64::MAX + 1
        "100000000000000000000", // Also representable as f64; retain integer lexeme.
        "170141183460469231731687303715884105727", // i128::MAX
        "170141183460469231731687303715884105728", // i128::MAX + 1
        "340282366920938463463374607431768211455", // u128::MAX
        "340282366920938463463374607431768211456", // u128::MAX + 1
        "-9223372036854775808",  // i64::MIN
        "-9223372036854775809",  // i64::MIN - 1
        "-100000000000000000000", // Negative integer also representable as f64.
        "-170141183460469231731687303715884105728", // i128::MIN
        "-170141183460469231731687303715884105729", // i128::MIN - 1
    ] {
        let number: serde_json::Number = text.parse().unwrap();
        let expected = Value::Number(number.clone());
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<serde_json::Number>(text).unwrap(),
            number
        );
        assert_eq!(
            serde_json::from_value::<Value>(expected.clone()).unwrap(),
            expected
        );
        assert_eq!(Value::deserialize(&expected).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<Untagged>(text).unwrap(),
            Untagged::Number(number.clone())
        );
        assert_eq!(
            serde_json::from_value::<Untagged>(expected.clone()).unwrap(),
            Untagged::Number(number.clone())
        );
        assert_eq!(
            Untagged::deserialize(&expected).unwrap(),
            Untagged::Number(number)
        );
        let tagged = Tagged::Put { body: expected };
        let encoded = serde_json::to_vec(&tagged).unwrap();
        assert_eq!(serde_json::from_slice::<Tagged>(&encoded).unwrap(), tagged);
        let value = serde_json::to_value(&tagged).unwrap();
        assert_eq!(
            serde_json::from_value::<Tagged>(value.clone()).unwrap(),
            tagged
        );
        assert_eq!(Tagged::deserialize(&value).unwrap(), tagged);
        let untagged = Untagged::Tagged(tagged);
        assert_eq!(
            serde_json::from_slice::<Untagged>(&encoded).unwrap(),
            untagged
        );
        assert_eq!(
            serde_json::from_value::<Untagged>(value.clone()).unwrap(),
            untagged
        );
        assert_eq!(Untagged::deserialize(&value).unwrap(), untagged);
    }
}

#[cfg(feature = "arbitrary_precision")]
#[test]
fn explicit_128_bit_integer_requests_remain_exact_and_reject_overflow() {
    for expected in [0u128, u64::MAX as u128, u64::MAX as u128 + 1, u128::MAX] {
        let text = expected.to_string();
        let value = Value::Number(text.parse().unwrap());
        assert_eq!(serde_json::from_str::<u128>(&text).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<u128>(value.clone()).unwrap(),
            expected
        );
        assert_eq!(u128::deserialize(&value).unwrap(), expected);
    }
    for expected in [
        i128::MIN,
        i64::MIN as i128 - 1,
        i64::MIN as i128,
        0,
        i128::MAX,
    ] {
        let text = expected.to_string();
        let value = Value::Number(text.parse().unwrap());
        assert_eq!(serde_json::from_str::<i128>(&text).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<i128>(value.clone()).unwrap(),
            expected
        );
        assert_eq!(i128::deserialize(&value).unwrap(), expected);
    }
    for text in ["-1", "340282366920938463463374607431768211456"] {
        let value = Value::Number(text.parse().unwrap());
        assert!(serde_json::from_str::<u128>(text).is_err());
        assert!(serde_json::from_value::<u128>(value.clone()).is_err());
        assert!(u128::deserialize(&value).is_err());
    }
    for text in [
        "-170141183460469231731687303715884105729",
        "170141183460469231731687303715884105728",
    ] {
        let value = Value::Number(text.parse().unwrap());
        assert!(serde_json::from_str::<i128>(text).is_err());
        assert!(serde_json::from_value::<i128>(value.clone()).is_err());
        assert!(i128::deserialize(&value).is_err());
    }
}

#[cfg(feature = "arbitrary_precision")]
#[test]
fn typed_number_rejects_a_literal_marker_object_even_in_untagged_buffering() {
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(untagged)]
    enum Either {
        Number(serde_json::Number),
        Literal(Value),
    }
    let expected = object(NUMBER, Value::String("7".to_owned()));
    let bytes = serde_json::to_vec(&expected).unwrap();
    assert!(serde_json::from_slice::<serde_json::Number>(&bytes).is_err());
    assert!(serde_json::from_value::<serde_json::Number>(expected.clone()).is_err());
    assert!(serde_json::Number::deserialize(&expected).is_err());
    assert_eq!(
        serde_json::from_slice::<Either>(&bytes).unwrap(),
        Either::Literal(expected)
    );
    let number = "18446744073709551616000000000000001";
    assert_eq!(
        serde_json::from_str::<Either>(number).unwrap(),
        Either::Number(number.parse().unwrap())
    );
}

#[cfg(feature = "raw_value")]
#[test]
fn real_raw_capture_round_trips_without_interpreting_literal_marker_keys() {
    use serde_json::value::RawValue;
    for key in [NUMBER, RAW] {
        let expected = object(key, Value::String("not JSON".to_owned()));
        let bytes = serde_json::to_vec(&expected).unwrap();
        let borrowed: &RawValue = serde_json::from_slice(&bytes).unwrap();
        let owned: Box<RawValue> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(borrowed.get().as_bytes(), bytes);
        assert_eq!(owned.get(), borrowed.get());
        assert_eq!(serde_json::to_value(borrowed).unwrap(), expected);
        assert_eq!(serde_json::to_value(&owned).unwrap(), expected);
        assert_eq!(serde_json::to_vec(&owned).unwrap(), bytes);
        let from_value: Box<RawValue> = serde_json::from_value(expected.clone()).unwrap();
        let from_borrowed = Box::<RawValue>::deserialize(&expected).unwrap();
        assert_eq!(from_value.get().as_bytes(), bytes);
        assert_eq!(from_borrowed.get().as_bytes(), bytes);
    }
}
