use kasumi_types::{
    CanonicalJsonValue, CollectionDefinition, CollectionRetentionClass, CollectionWriteMode,
    Document, HistoryArchiveChunk, HistoryArchiveKind, Mutation, MutationBatch, Precondition,
    ReadAssertion, SchemaChange, SchemaChangeSet, StagedChunk, StagedManifest, staged_digest,
};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, sync::Arc};

const NUMBER: &str = "900719925474099312345678901234567890.123456789";
const BODY: &str = r#"{"$serde_json::private::Number":"literal","a":{"$serde_json::private::RawValue":"null"},"b":[{"a":true,"z":900719925474099312345678901234567890.123456789}],"q\"\\\n":"escaped"}"#;

fn object(mut fields: Vec<(&str, Value)>, reverse: bool) -> Value {
    if reverse {
        fields.reverse();
    }
    let mut object = Map::new();
    for (key, value) in fields {
        object.insert(key.into(), value);
    }
    Value::Object(object)
}

fn body(reverse: bool) -> Value {
    object(
        vec![
            (
                "$serde_json::private::Number",
                Value::String("literal".into()),
            ),
            (
                "a",
                object(
                    vec![(
                        "$serde_json::private::RawValue",
                        Value::String("null".into()),
                    )],
                    reverse,
                ),
            ),
            (
                "b",
                Value::Array(vec![object(
                    vec![
                        ("a", Value::Bool(true)),
                        ("z", Value::Number(NUMBER.parse::<Number>().unwrap())),
                    ],
                    reverse,
                )]),
            ),
            ("q\"\\\n", Value::String("escaped".into())),
        ],
        reverse,
    )
}

fn operation(reverse: bool) -> Mutation {
    Mutation::Put {
        collection: "docs".into(),
        id: "row".into(),
        body: body(reverse),
        expected: Precondition::Version(7),
    }
}

fn mutation_json() -> String {
    format!(
        r#"{{"op":"put","collection":"docs","id":"row","body":{BODY},"expected":{{"kind":"version","version":7}}}}"#
    )
}

fn assert_encoding(value: &impl Serialize, expected: &str) -> String {
    assert_eq!(serde_json::to_string(value).unwrap(), expected);
    let (digest, length) = staged_digest(value).unwrap();
    assert_eq!(length, expected.len());
    assert_eq!(digest, format!("{:x}", Sha256::digest(expected.as_bytes())));
    digest
}

#[test]
fn literal_json_has_one_explicit_byte_contract() {
    for reverse in [false, true] {
        let value = body(reverse);
        let raw_before = serde_json::to_string(&value).unwrap();
        assert_encoding(&CanonicalJsonValue(&value), BODY);
        // Canonicalization borrows; it must not reorder the caller's map in place.
        assert_eq!(serde_json::to_string(&value).unwrap(), raw_before);
    }
    let literal = object(
        vec![(
            "$serde_json::private::Number",
            Value::String("1e400".into()),
        )],
        true,
    );
    assert_encoding(
        &CanonicalJsonValue(&literal),
        r#"{"$serde_json::private::Number":"1e400"}"#,
    );
    let actual_number = Value::Number("1e400".parse().unwrap());
    assert_ne!(
        staged_digest(&CanonicalJsonValue(&literal)).unwrap().0,
        staged_digest(&CanonicalJsonValue(&actual_number))
            .unwrap()
            .0
    );
    let first = Value::Number("1.0000000000000000000000000001".parse().unwrap());
    let second = Value::Number("1.0000000000000000000000000002".parse().unwrap());
    assert_ne!(
        staged_digest(&CanonicalJsonValue(&first)).unwrap().0,
        staged_digest(&CanonicalJsonValue(&second)).unwrap().0
    );
}

#[test]
fn mutation_replay_and_staging_manifest_are_feature_independent() {
    let mut previous = None;
    for reverse in [false, true] {
        let batch = MutationBatch {
            idempotency_key: "same-command".into(),
            read_set: vec![ReadAssertion::Before { not_after_ms: 42 }],
            operations: vec![operation(reverse)],
        };
        let expected_batch = format!(
            r#"{{"idempotency_key":"same-command","read_set":[{{"kind":"before","not_after_ms":42}}],"operations":[{}]}}"#,
            mutation_json()
        );
        let digest = assert_encoding(&batch, &expected_batch);
        assert_eq!(batch.digest().unwrap(), digest);
        assert_eq!(
            digest,
            "208fa37019dbd9ac50c00ea58b11fee223b75f3b18c3fcef0d103260b3e3ac1a"
        );
        let chunk = StagedChunk {
            read_set: batch.read_set,
            operations: batch.operations,
        };
        let expected_chunk = format!(
            r#"{{"read_set":[{{"kind":"before","not_after_ms":42}}],"operations":[{}]}}"#,
            mutation_json()
        );
        let chunk_digest = assert_encoding(&chunk, &expected_chunk);
        assert_eq!(
            chunk_digest,
            "40a75569fb16d6aefa589e060b89f632874c38ed59fbcb9664db459665904a4f"
        );
        let manifest = StagedManifest::from_chunks(&[chunk]).unwrap();
        assert_eq!(manifest.chunk_digests, [chunk_digest]);
        assert_eq!(manifest.encoded_chunk_bytes, expected_chunk.len());
        assert_eq!(manifest.operation_count, 1);
        assert_eq!(manifest.read_assertion_count, 1);
        let identities = (digest, staged_digest(&manifest).unwrap());
        if let Some(previous) = &previous {
            assert_eq!(&identities, previous);
        }
        previous = Some(identities);
    }
}

#[test]
fn archive_plaintext_and_document_references_share_the_same_encoding() {
    let mut previous = None;
    for reverse in [false, true] {
        let document = Arc::new(Document {
            id: "row".into(),
            version: 8,
            body: body(reverse),
        });
        let expected_doc = format!(r#"{{"id":"row","version":8,"body":{BODY}}}"#);
        let document_digest = assert_encoding(&document, &expected_doc);
        assert_eq!(
            document_digest,
            "90a49ebbea0fa8f991ef4613d968fafeca5367aa8bd1acc22d08249928c22e37"
        );
        let chunk = HistoryArchiveChunk {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: "archive".into(),
            source_incarnation: "source".into(),
            collection: "docs".into(),
            index: 3,
            documents: vec![document],
        };
        let expected_chunk = format!(
            r#"{{"kind":"history_subset","archive_id":"archive","source_incarnation":"source","collection":"docs","index":3,"documents":[{expected_doc}]}}"#
        );
        let chunk_digest = assert_encoding(&chunk, &expected_chunk);
        // This is the history export plaintext path, not just a digest wrapper.
        let plaintext = serde_json::to_vec(&chunk).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&plaintext)), chunk_digest);
        let identities = (document_digest, chunk_digest, plaintext);
        if let Some(previous) = &previous {
            assert_eq!(&identities, previous);
        }
        previous = Some(identities);
    }
}

#[test]
fn schema_activation_identity_preserves_typed_field_order() {
    let mut previous = None;
    for reverse in [false, true] {
        let definition = CollectionDefinition {
            name: "docs".into(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: body(reverse),
            indexes: vec![],
            strict_read_audit: false,
        };
        let expected_definition = format!(
            r#"{{"name":"docs","write_mode":"mutable","retention_class":"operational","schema":{BODY},"indexes":[],"strict_read_audit":false}}"#
        );
        assert_encoding(&definition, &expected_definition);
        let request = SchemaChangeSet {
            activation_id: "activation".into(),
            expected_incarnation: "source".into(),
            expected_schema_epoch: 4,
            read_set: vec![],
            changes: vec![SchemaChange::Create { definition }],
        };
        let expected = format!(
            r#"{{"activation_id":"activation","expected_incarnation":"source","expected_schema_epoch":4,"read_set":[],"changes":[{{"kind":"create","definition":{expected_definition}}}]}}"#
        );
        let digest = assert_encoding(&request, &expected);
        assert_eq!(request.reference().unwrap().request_digest, digest);
        assert_eq!(
            digest,
            "912de563ad022d64af90d6559465f2633c0c99675580dd4b4595bb18ebf48716"
        );
        if let Some(previous) = &previous {
            assert_eq!(&digest, previous);
        }
        previous = Some(digest);
    }
}

#[test]
fn typed_maps_and_enclosing_field_order_are_explicit() {
    #[derive(Serialize)]
    struct Typed {
        z: u8,
        a: BTreeMap<u64, &'static str>,
    }
    let value = Typed {
        z: 1,
        a: BTreeMap::from([(2, "two"), (10, "ten")]),
    };
    // Canonical literal objects do not lexically reorder numeric typed keys or
    // sort struct declarations as a generic JSON canonicalizer would.
    assert_encoding(&value, r#"{"z":1,"a":{"2":"two","10":"ten"}}"#);
}

#[test]
fn bounded_writer_failure_does_not_require_an_encoded_payload_copy() {
    struct Limited {
        remaining: usize,
        written: usize,
    }
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(std::io::Error::other("bounded output full"));
            }
            self.remaining -= bytes.len();
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let value = object(
        vec![
            ("z", Value::String("x".repeat(1 << 20))),
            ("a", Value::Null),
        ],
        false,
    );
    let mut output = Limited {
        remaining: 64,
        written: 0,
    };
    assert!(serde_json::to_writer(&mut output, &CanonicalJsonValue(&value)).is_err());
    assert!(output.written <= 64);
}
