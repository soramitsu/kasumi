//! External caller tests: only public SDK/types APIs, no server or listeners.
use kasumi_client::{
    ClientDecodeLimits, ClientError, ClientResources, JsonReadOptions, decode_mutation_json,
    decode_query_json, decode_schema_change_json, decode_staged_chunk_json,
};
use kasumi_types::*;
use serde::Serialize;
use serde_json::{Map, Number, Value};
use std::time::Duration;
use tonic::Code;

const LARGE: &str = "340282366920938463463374607431768211456";

fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Map<_, _>>(),
    )
}
fn body() -> Value {
    object([
        (
            "number",
            object([("$serde_json::private::Number", Value::String("7".into()))]),
        ),
        (
            "raw",
            object([(
                "$serde_json::private::RawValue",
                Value::String("not JSON".into()),
            )]),
        ),
        (
            "nested",
            Value::Array(vec![object([(
                "$serde_json::private::RawValue",
                Value::String("[1,2]".into()),
            )])]),
        ),
        ("large", Value::Number(LARGE.parse::<Number>().unwrap())),
        (
            "negative",
            Value::Number(
                "-170141183460469231731687303715884105729"
                    .parse::<Number>()
                    .unwrap(),
            ),
        ),
        (
            "decimal",
            Value::Number(
                "90071992547409931234567890.123456789"
                    .parse::<Number>()
                    .unwrap(),
            ),
        ),
    ])
}
fn batch(body: Value) -> MutationBatch {
    MutationBatch {
        idempotency_key: "external-intent".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "a".into(),
            body,
            expected: Precondition::Absent,
        }],
    }
}
fn bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn options() -> JsonReadOptions {
    JsonReadOptions {
        resources: ClientResources::new(128 << 20, 4).unwrap(),
        limits: ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 256 << 10,
            max_json_bytes: 64 << 10,
            max_depth: 32,
            max_nodes: 10_000,
            max_string_bytes: 16 << 10,
            max_number_bytes: 1024,
            max_rows: 32,
            max_decoded_bytes: 16 << 20,
        },
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
    }
}
fn rejected<T: std::fmt::Debug>(value: std::result::Result<T, ClientError>, expected: Code) {
    let ClientError::DecodeRejected { code, .. } = value.unwrap_err() else {
        panic!("unexpected SDK error kind")
    };
    assert_eq!(code, expected);
}
async fn drained(options: &JsonReadOptions) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while options.resources.usage().live_owners != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("SDK decode owner did not drain");
    assert_eq!(options.resources.usage().accounted_bytes, 0);
}

#[test]
fn stock_decoder_counterexample_is_present_in_this_external_graph() {
    // This is deliberately a stock-dependency witness, not an SDK decode path.
    let value: Value = serde_json::from_str(r#"{"$serde_json::private::Number":"7"}"#).unwrap();
    assert_eq!(value, Value::Number(7.into()));
    assert!(
        serde_json::from_str::<Value>(r#"{"$serde_json::private::RawValue":"not JSON"}"#).is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn public_mutation_decoder_preserves_literals_large_numbers_and_owned_dtos() {
    let options = options();
    let expected = batch(body());
    let encoded = bytes(&expected);
    let decoded = decode_mutation_json(&encoded, &options).await.unwrap();
    assert_eq!(*decoded, expected);
    assert_eq!(decoded.digest().unwrap(), expected.digest().unwrap());
    let owned: MutationBatch = (*decoded).clone(); // Caller-owned memory, outside SDK accounting.
    let copy = decoded.clone();
    let charged = options.resources.usage();
    assert_eq!(charged.live_owners, 1);
    assert_eq!(charged.accounted_bytes, decoded.accounted_bytes());
    drop(decoded);
    assert_eq!(options.resources.usage(), charged);
    drop(copy);
    drained(&options).await;
    let roundtrip = decode_mutation_json(&bytes(&owned), &options)
        .await
        .unwrap();
    assert_eq!(*roundtrip, owned);
    drop(roundtrip);
    let escaped = String::from_utf8(encoded).unwrap().replace('$', "\\u0024");
    let decoded = decode_mutation_json(escaped.as_bytes(), &options)
        .await
        .unwrap();
    assert_eq!(*decoded, expected);
    drop(decoded);
    drained(&options).await;
}

#[tokio::test(flavor = "current_thread")]
async fn public_chunk_query_and_schema_helpers_preserve_literal_fields() {
    let options = options();
    let original = batch(body());
    let chunk = StagedChunk {
        read_set: vec![],
        operations: original.operations,
    };
    let decoded = decode_staged_chunk_json(&bytes(&chunk), &options)
        .await
        .unwrap();
    assert_eq!(bytes(&*decoded), bytes(&chunk));
    assert_eq!(
        staged_digest(&*decoded).unwrap(),
        staged_digest(&chunk).unwrap()
    );
    let manifest = StagedManifest::from_chunks(&[(*decoded).clone()]).unwrap();
    assert_eq!(
        bytes(&manifest),
        bytes(&StagedManifest::from_chunks(&[chunk]).unwrap())
    );
    drop(decoded);
    let query = QueryRequest {
        collection: "docs".into(),
        filter: Predicate::And {
            predicates: vec![Predicate::Eq {
                field: "/body".into(),
                value: body(),
            }],
        },
        sort: vec![],
        projection: vec![],
        aggregates: vec![],
        group_by: vec![],
        text: None,
        limit: 1,
        cursor: None,
        allow_scan: true,
    };
    let decoded = decode_query_json(&bytes(&query), &options).await.unwrap();
    assert_eq!(*decoded, query);
    drop(decoded);
    let change = SchemaChangeSet {
        activation_id: "schema".into(),
        expected_incarnation: "00000000-0000-0000-0000-000000000001".into(),
        expected_schema_epoch: 1,
        read_set: vec![],
        changes: vec![SchemaChange::Create {
            definition: CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: body(),
                indexes: vec![],
                strict_read_audit: false,
            },
        }],
    };
    let decoded = decode_schema_change_json(&bytes(&change), &options)
        .await
        .unwrap();
    assert_eq!(bytes(&*decoded), bytes(&change));
    drop(decoded);
    drained(&options).await;
}

#[tokio::test(flavor = "current_thread")]
async fn literal_inner_text_does_not_consume_outer_nesting_as_json() {
    let mut options = options();
    options.limits.max_depth = 8;
    let expected = batch(object([(
        "$serde_json::private::RawValue",
        Value::String(format!("{}0{}", "[".repeat(256), "]".repeat(256))),
    )]));
    let decoded = decode_mutation_json(&bytes(&expected), &options)
        .await
        .unwrap();
    assert_eq!(*decoded, expected);
    drop(decoded);
    drained(&options).await;
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_inputs_and_bounded_work_are_rejected_without_leaked_owners() {
    let base = options();
    for input in [
        b"{".as_slice(),
        b"[]",
        b"null",
        b"{} {}",
        b"{\"idempotency_key\":\"a\",\"idempotency_key\":\"b\"}",
    ] {
        rejected(decode_mutation_json(input, &base).await, Code::DataLoss);
        drained(&base).await;
    }
    let encoded = bytes(&batch(body()));
    let mut bounded = options();
    bounded.limits.max_request_bytes = encoded.len() - 1;
    rejected(
        decode_mutation_json(&encoded, &bounded).await,
        Code::ResourceExhausted,
    );
    drained(&bounded).await;
    let mut bounded = options();
    bounded.limits.max_nodes = 16;
    rejected(
        decode_mutation_json(
            &bytes(&batch(Value::Array(vec![Value::Null; 128]))),
            &bounded,
        )
        .await,
        Code::ResourceExhausted,
    );
    drained(&bounded).await;
    let mut bounded = options();
    bounded.limits.max_number_bytes = LARGE.len() - 1;
    rejected(
        decode_mutation_json(&encoded, &bounded).await,
        Code::ResourceExhausted,
    );
    drained(&bounded).await;
    let mut expired = options();
    expired.deadline = tokio::time::Instant::now();
    rejected(
        decode_mutation_json(&encoded, &expired).await,
        Code::DeadlineExceeded,
    );
    drained(&expired).await;
}

#[tokio::test(flavor = "current_thread")]
async fn retained_response_enforces_the_shared_owner_limit() {
    let mut options = options();
    options.resources = ClientResources::new(128 << 20, 1).unwrap();
    let input = bytes(&batch(body()));
    let first = decode_mutation_json(&input, &options).await.unwrap();
    rejected(
        decode_mutation_json(&input, &options).await,
        Code::ResourceExhausted,
    );
    let clone = first.clone();
    drop(first);
    rejected(
        decode_mutation_json(&input, &options).await,
        Code::ResourceExhausted,
    );
    drop(clone);
    drained(&options).await;
    let next = decode_mutation_json(&input, &options).await.unwrap();
    drop(next);
    drained(&options).await;
}
