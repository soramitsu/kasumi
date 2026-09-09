#[cfg(test)]
#[path = "../../../crates/kasumi-types/tests/canonical_json.rs"]
mod canonical_json;

#[test]
fn feature_graph_really_changes_raw_value_order() {
    let mut object = serde_json::Map::new();
    object.insert("z".into(), serde_json::Value::Null);
    object.insert("a".into(), serde_json::Value::Null);
    let raw = serde_json::to_string(&serde_json::Value::Object(object)).unwrap();
    if cfg!(feature = "preserve-order") {
        assert_eq!(raw, r#"{"z":null,"a":null}"#);
    } else {
        assert_eq!(raw, r#"{"a":null,"z":null}"#);
    }
}
