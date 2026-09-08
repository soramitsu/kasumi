use super::*;
use crate::{ClientDecodeLimits, ClientResources};
use prost::Message;
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

fn read_options() -> JsonReadOptions {
    JsonReadOptions {
        resources: ClientResources::new(256 << 20, 8).unwrap(),
        limits: ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 512 << 10,
            max_json_bytes: 512 << 10,
            max_depth: 32,
            max_nodes: 5000,
            max_string_bytes: 64 << 10,
            max_number_bytes: 1024,
            max_rows: 100,
            max_decoded_bytes: 16 << 20,
        },
        deadline: tokio::time::Instant::now() + Duration::from_secs(30),
    }
}
fn body() -> Value {
    json!({
        "number": {"$serde_json::private::Number":"7"},
        "raw": {"$serde_json::private::RawValue":"not JSON"},
        "deep_text": {"$serde_json::private::RawValue":format!("{}0{}", "[".repeat(256), "]".repeat(256))},
        "integer": "340282366920938463463374607431768211456".parse::<serde_json::Number>().unwrap(),
        "decimal": "90071992547409931234567890.123456789".parse::<serde_json::Number>().unwrap(),
        "exponent": "1e400".parse::<serde_json::Number>().unwrap()
    })
}
fn query_request() -> QueryRequest {
    QueryRequest {
        collection: "docs".into(),
        filter: Predicate::All,
        sort: vec![],
        projection: vec![],
        aggregates: vec![],
        group_by: vec![],
        text: None,
        limit: 10,
        cursor: None,
        allow_scan: true,
    }
}
fn query_wire(body: &Value, count: usize) -> Vec<u8> {
    proto::QueryResponse {
        revision: 4,
        rows: (0..count)
            .map(|i| proto::QueryRow {
                document: Some(proto::Document {
                    id: format!("id-{i}"),
                    version: 4,
                    body_json: serde_json::to_vec(body).unwrap(),
                }),
                score: None,
            })
            .collect(),
        aggregates_json: vec![serde_json::to_vec(body).unwrap()],
        cursor: Some("opaque-original".into()),
    }
    .encode_to_vec()
}
fn raw<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
#[test]
fn ordinary_query_preserves_literal_keys_numbers_and_original_page_revision() {
    let options = read_options();
    let call = options.admit().unwrap();
    let request = query_request();
    let expected = body();
    let bytes = query_wire(&expected, 2);
    let response = wire::query(&bytes, &request, Some(4), &call).unwrap();
    assert_eq!(response.rows[0].body, expected);
    assert_eq!(response.aggregates, vec![expected]);
    assert!(wire::query(&bytes, &request, Some(3), &call).is_err());
    let prepared = prepare_query_page(&request, "opaque-original", 4, &call).unwrap();
    let response: QueryResponse = decode(&bytes, &prepared, &call).unwrap();
    assert_eq!(response.revision, 4);
    let mut small = options.clone();
    small.limits.max_string_bytes = 3;
    assert!(
        prepare_query_page(
            &request,
            "oversized-original-cursor",
            4,
            &small.admit().unwrap()
        )
        .is_err()
    );
}
#[test]
fn query_budget_is_aggregate_across_rows_and_ignored_wire_is_rejected() {
    let mut options = read_options();
    let expected = json!({"x":"data"});
    let bytes = query_wire(&expected, 2);
    options.limits.max_nodes = 20;
    let call = options.admit().unwrap();
    assert!(wire::query(&bytes, &query_request(), None, &call).is_err());
    drop(call);
    options.limits.max_nodes = 5000;
    options.limits.max_decoded_bytes = 9000;
    assert!(wire::query(&bytes, &query_request(), None, &options.admit().unwrap()).is_err());
    let mut options = read_options();
    options.limits.max_json_bytes = raw(&expected).len() * 2;
    assert!(wire::query(&bytes, &query_request(), None, &options.admit().unwrap()).is_err());
    let mut wire = query_wire(&expected, 1);
    wire.extend([40, 0]);
    assert!(
        wire::query(
            &wire,
            &query_request(),
            None,
            &read_options().admit().unwrap()
        )
        .is_err()
    );
}
#[test]
fn numeric_lexeme_and_request_clone_work_are_admitted_before_construction() {
    let mut options = read_options();
    options.limits.max_number_bytes = 8;
    let call = options.admit().unwrap();
    let large = "340282366920938463463374607431768211456"
        .parse::<serde_json::Number>()
        .unwrap();
    let mut request = query_request();
    request.filter = Predicate::Eq {
        field: "/x".into(),
        value: Value::Number(large),
    };
    assert!(prepare_query(&request, None, &call).is_err());
    assert!(wire::query(&query_wire(&body(), 1), &query_request(), None, &call).is_err());
    drop(call);
    assert_eq!(options.resources.usage().live_owners, 0);
    let mut options = read_options();
    options.limits.max_decoded_bytes = 512;
    let call = options.admit().unwrap();
    assert!(prepare_query(&query_request(), None, &call).is_err());
}
#[test]
fn numeric_request_lexemes_do_not_consume_literal_string_key_limits() {
    let mut options = read_options();
    options.limits.max_string_bytes = 1;
    options.limits.max_number_bytes = 3;
    let call = options.admit().unwrap();
    let value = Value::Number("123".parse().unwrap());
    assert_eq!(snapshot_decode::encode(&value, &call).unwrap(), b"123");
    let value = Value::Number("1234".parse().unwrap());
    assert!(snapshot_decode::encode(&value, &call).is_err());
    assert!(snapshot_decode::encode(&Value::String("123".into()), &call).is_err());
    assert!(snapshot_decode::encode(&json!({"$serde_json::private::Number":"1"}), &call).is_err());
    assert!(
        snapshot_decode::encode(&json!({"$serde_json::private::RawValue":"1"}), &call).is_err()
    );
    drop(call);
    options.limits.max_string_bytes = 64;
    options.limits.max_number_bytes = 1;
    let call = options.admit().unwrap();
    let literal = json!({"$serde_json::private::Number":"1234"});
    assert_eq!(
        snapshot_decode::encode(&literal, &call).unwrap(),
        raw(&literal)
    );
    let literal = json!({"$serde_json::private::RawValue":"1234"});
    assert_eq!(
        snapshot_decode::encode(&literal, &call).unwrap(),
        raw(&literal)
    );
}
#[test]
fn change_feed_schema_and_audit_construct_values_from_literal_spans() {
    let options = read_options();
    let call = options.admit().unwrap();
    let expected = body();
    let feed_request = ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: ChangeFeedStart::Beginning,
        limit: 10,
    };
    let event = ChangeFeedPage::Events {
        revision: 4,
        first_available_sequence: 1,
        head_sequence: 1,
        events: vec![ChangeEvent {
            sequence: 1,
            revision: 4,
            ordinal: 0,
            commit_event_count: 1,
            collection: "docs".into(),
            id: "a".into(),
            document: Some(Arc::new(Document {
                id: "a".into(),
                version: 4,
                body: expected.clone(),
            })),
        }],
        next: ChangeFeedCursor {
            tenant: "tenant".into(),
            incarnation: uuid::Uuid::new_v4().to_string(),
            principal: "owner".into(),
            collections: feed_request.collections.clone(),
            after_sequence: 1,
        },
        caught_up: true,
    };
    let prepared = Prepared {
        input: vec![],
        kind: Kind::Feed(feed_request),
        path: "",
        _owner: call.clone(),
    };
    let decoded: ChangeFeedPage = decode(&raw(&event), &prepared, &call).unwrap();
    let ChangeFeedPage::Events { events, .. } = decoded else {
        panic!("feed kind changed")
    };
    assert_eq!(events[0].document.as_ref().unwrap().body, expected);
    let definition = CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: expected.clone(),
        indexes: vec![],
        strict_read_audit: false,
    };
    let schema = SchemaSnapshot {
        incarnation: uuid::Uuid::new_v4().to_string(),
        revision: 4,
        policy_epoch: 1,
        schema_epoch: 1,
        collections: [(
            "docs".into(),
            Some(SchemaCollection {
                definition,
                data_epoch: 4,
                archived_document_count: 0,
            }),
        )]
        .into(),
    };
    let prepared = Prepared {
        input: vec![],
        kind: Kind::Schema(ReadSchema {
            collections: BTreeSet::from(["docs".into()]),
        }),
        path: "",
        _owner: call.clone(),
    };
    let decoded: SchemaSnapshot = decode(&raw(&schema), &prepared, &call).unwrap();
    assert_eq!(
        decoded.collections["docs"]
            .as_ref()
            .unwrap()
            .definition
            .schema,
        expected
    );
    let audit = SecurityAuditPage {
        stream_id: uuid::Uuid::new_v4(),
        through_sequence: 1,
        next_sequence: 1,
        records: vec![json!({"sequence":0,"body":expected})],
    };
    let prepared = Prepared {
        input: vec![],
        kind: Kind::Audit(SecurityAuditExportRequest {
            cursor: None,
            limit: 1,
        }),
        path: "",
        _owner: call.clone(),
    };
    let decoded: SecurityAuditPage = decode(&raw(&audit), &prepared, &call).unwrap();
    assert_eq!(decoded.records, audit.records);
}
#[tokio::test]
async fn canonical_intent_helpers_preserve_body_predicates_schema_and_exact_digest() {
    let options = read_options();
    let expected = body();
    let batch = MutationBatch {
        idempotency_key: "intent".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "a".into(),
            body: expected.clone(),
            expected: Precondition::Absent,
        }],
    };
    let bytes = raw(&batch);
    let decoded = decode_mutation_json(&bytes, &options).await.unwrap();
    assert_eq!(*decoded, batch);
    assert_eq!(decoded.digest().unwrap(), batch.digest().unwrap());
    let clone = decoded.clone();
    drop(decoded);
    assert!(options.resources.usage().accounted_bytes > 0);
    drop(clone);
    let chunk = StagedChunk {
        read_set: vec![],
        operations: batch.operations.clone(),
    };
    let decoded_chunk = decode_staged_chunk_json(&raw(&chunk), &options)
        .await
        .unwrap();
    assert_eq!(raw(&*decoded_chunk), raw(&chunk));
    drop(decoded_chunk);
    let mut query = query_request();
    query.filter = Predicate::And {
        predicates: vec![Predicate::Eq {
            field: "/x".into(),
            value: expected.clone(),
        }],
    };
    let decoded = decode_query_json(&raw(&query), &options).await.unwrap();
    assert_eq!(*decoded, query);
    drop(decoded);
    let schema = SchemaChangeSet {
        activation_id: "schema".into(),
        expected_incarnation: uuid::Uuid::new_v4().to_string(),
        expected_schema_epoch: 1,
        read_set: vec![],
        changes: vec![SchemaChange::Create {
            definition: CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: expected,
                indexes: vec![],
                strict_read_audit: false,
            },
        }],
    };
    let decoded = decode_schema_change_json(&raw(&schema), &options)
        .await
        .unwrap();
    assert_eq!(raw(&*decoded), raw(&schema));
    drop(decoded);
    let escaped = String::from_utf8(bytes).unwrap().replace('$', "\\u0024");
    assert_eq!(
        *decode_mutation_json(escaped.as_bytes(), &options)
            .await
            .unwrap(),
        batch
    );
    let mut limited = options.clone();
    limited.limits.max_request_bytes = 8;
    assert!(
        decode_mutation_json(escaped.as_bytes(), &limited)
            .await
            .is_err()
    );
    let mut expired = options.clone();
    expired.deadline = tokio::time::Instant::now();
    assert!(decode_query_json(&raw(&query), &expired).await.is_err());
}
fn feed_result(
    value: &Value,
    request: &ReadChangeFeed,
    call: &Call,
) -> Result<ChangeFeedPage, ClientError> {
    let prepared = Prepared {
        input: vec![],
        kind: Kind::Feed(request.clone()),
        path: "",
        _owner: call.clone(),
    };
    decode(&raw(value), &prepared, call)
}
#[test]
fn change_feed_retention_gap_binds_original_position_and_checked_range() {
    let options = read_options();
    let call = options.admit().unwrap();
    let mut request = ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: ChangeFeedStart::After {
            cursor: ChangeFeedCursor {
                tenant: "tenant".into(),
                principal: "reader".into(),
                incarnation: uuid::Uuid::new_v4().to_string(),
                collections: BTreeSet::from(["docs".into()]),
                after_sequence: 5,
            },
        },
        limit: 10,
    };
    let valid = json!({"kind":"retention_gap","first_available_sequence":7,
        "head_sequence":10,"requested_after_sequence":5});
    assert!(feed_result(&valid, &request, &call).is_ok());
    for (field, value) in [
        ("requested_after_sequence", 0),
        ("first_available_sequence", 6),
        ("first_available_sequence", 0),
        ("first_available_sequence", 12),
        ("head_sequence", 4),
        ("head_sequence", u64::MAX),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = json!(value);
        assert!(feed_result(&invalid, &request, &call).is_err(), "{invalid}");
    }
    request.start = ChangeFeedStart::Now;
    assert!(feed_result(&valid, &request, &call).is_err());
    request.start = ChangeFeedStart::Beginning;
    let mut beginning = valid;
    beginning["requested_after_sequence"] = json!(0);
    assert!(feed_result(&beginning, &request, &call).is_ok());
}
#[test]
fn change_feed_events_bind_scope_and_commit_metadata_without_rejecting_filtered_gaps() {
    let options = read_options();
    let call = options.admit().unwrap();
    let mut request = ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: ChangeFeedStart::Beginning,
        limit: 10,
    };
    let valid = json!({"kind":"events","revision":5,"first_available_sequence":1,
    "head_sequence":7,"next":{"tenant":"tenant","principal":"reader",
        "incarnation":uuid::Uuid::new_v4().to_string(),"collections":["docs"],"after_sequence":7},
    "caught_up":true,"events":[
        {"sequence":2,"revision":3,"ordinal":1,"commit_event_count":4,
            "collection":"docs","id":"b","document":null},
        {"sequence":4,"revision":3,"ordinal":3,"commit_event_count":4,
            "collection":"docs","id":"d","document":null},
        {"sequence":6,"revision":5,"ordinal":0,"commit_event_count":2,
            "collection":"docs","id":"f","document":null}
    ]});
    assert!(feed_result(&valid, &request, &call).is_ok());
    for (pointer, value) in [
        ("/next/incarnation", json!(uuid::Uuid::nil().to_string())),
        ("/next/incarnation", json!("invalid")),
        ("/next/tenant", json!("")),
        ("/next/principal", json!("")),
        ("/next/collections", json!(["other"])),
        ("/next/after_sequence", json!(8)),
        ("/first_available_sequence", json!(2)),
        ("/caught_up", json!(false)),
        ("/events/0/id", json!("")),
        ("/events/0/revision", json!(0)),
        ("/events/0/ordinal", json!(2)),
        ("/events/1/ordinal", json!(2)),
        ("/events/1/commit_event_count", json!(5)),
        ("/events/2/revision", json!(2)),
        ("/events/2/commit_event_count", json!(3)),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(feed_result(&invalid, &request, &call).is_err(), "{invalid}");
    }
    request.start = ChangeFeedStart::After {
        cursor: serde_json::from_value(valid["next"].clone()).unwrap(),
    };
    let mut resumed = valid.clone();
    resumed["events"] = json!([]);
    assert!(feed_result(&resumed, &request, &call).is_ok());
    resumed["next"]["principal"] = json!("other");
    assert!(feed_result(&resumed, &request, &call).is_err());
    request.start = ChangeFeedStart::Now;
    resumed["next"]["principal"] = json!("reader");
    assert!(feed_result(&resumed, &request, &call).is_ok());
    resumed["next"]["after_sequence"] = json!(6);
    resumed["caught_up"] = json!(false);
    assert!(feed_result(&resumed, &request, &call).is_err());
}
type Pause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
static PAUSE: std::sync::Mutex<Option<Pause>> = std::sync::Mutex::new(None);
fn paused(_: &serde_json::value::RawValue, _: &Call) -> Result<(), ClientError> {
    let (entered, release) = PAUSE.lock().unwrap().take().unwrap();
    entered.send(()).unwrap();
    release.recv().unwrap();
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_canonical_input_retains_reservation_until_worker_exit() {
    let options = read_options();
    let resources = options.resources.clone();
    let (entered, started) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    *PAUSE.lock().unwrap() = Some((entered, resumed));
    let task = tokio::spawn(async move { input(b"{}", &options, paused).await });
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(resources.usage().live_owners, 1);
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while resources.usage().live_owners != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resources.usage().accounted_bytes, 0);
}
