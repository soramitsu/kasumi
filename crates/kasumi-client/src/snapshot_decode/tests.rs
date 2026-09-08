use super::*;
use bytes::Bytes;
use kasumi_types::DocumentKey;
use serde_json::json;
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;

fn options() -> SnapshotReadOptions {
    SnapshotReadOptions {
        resources: ClientResources::new(16 << 20, 2).unwrap(),
        limits: ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 64 << 10,
            max_json_bytes: 64 << 10,
            max_decoded_bytes: 2 << 20,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        expected_incarnation: uuid::Uuid::new_v4(),
    }
}
fn response(call: &Call) -> serde_json::Value {
    json!({"revision":4, "incarnation":call.expected_incarnation, "policy_epoch":1, "schema_epoch":1, "collection_epochs":{}, "documents":[], "queries":[]})
}
#[test]
fn shared_response_retains_exact_original_reservation() {
    let mut options = options();
    options.resources = ClientResources::new(options.limits.accounted_bytes().unwrap(), 1).unwrap();
    let call = options.admit().unwrap();
    let value = AdmittedResponse::new(vec![1u8, 2], &call);
    let clone = value.clone();
    let initial = options.resources.usage();
    assert_eq!(initial.live_owners, 1);
    drop(call);
    drop(value);
    assert!(options.admit().is_err());
    assert_eq!(options.resources.usage(), initial);
    assert_eq!(&**clone, &[1, 2]);
    drop(clone);
    assert_eq!(options.resources.usage(), ClientResourceUsage::default());
}
#[test]
fn exact_points_scope_order_and_revision_are_checked_before_values() {
    let options = options();
    let call = options.admit().unwrap();
    let input = ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "a".into(),
        }],
        queries: vec![],
    };
    let expected = Expected::read(&input, &call).unwrap();
    let mut valid = response(&call);
    valid["documents"] = json!([{"key":{"collection":"docs","id":"a"},"document":{"id":"a","version":4,"body":{"data":[1,2]}}}]);
    let bytes = serde_json::to_vec(&valid).unwrap();
    tokens::admit(&bytes, &call).unwrap();
    expected.validate(&bytes, &call).unwrap();
    for change in 0..5 {
        let mut candidate = valid.clone();
        match change {
            0 => candidate["documents"][0]["key"]["id"] = json!("foreign"),
            1 => candidate["documents"][0]["document"]["version"] = json!(5),
            2 => candidate["incarnation"] = json!(uuid::Uuid::new_v4()),
            3 => candidate["documents"]
                .as_array_mut()
                .unwrap()
                .push(valid["documents"][0].clone()),
            _ => candidate["queries"] = json!([{}]),
        }
        assert!(
            expected
                .validate(&serde_json::to_vec(&candidate).unwrap(), &call)
                .is_err()
        );
    }
    let lease = SnapshotLease {
        lease_id: uuid::Uuid::new_v4().to_string(),
        incarnation: call.expected_incarnation.unwrap().to_string(),
        revision: 4,
        policy_epoch: 1,
        schema_epoch: 1,
        ttl_ms: 1000,
    };
    let scan = Expected::Scan {
        lease: lease.clone(),
        collection: "docs".into(),
        after: Some("a".into()),
        limit: 2,
    };
    let mut page = json!({"snapshot":lease,"collection":"docs","data_epoch":4,"documents":[{"id":"b","version":4,"body":{}}],"next_after_id":"b"});
    scan.validate(&serde_json::to_vec(&page).unwrap(), &call)
        .unwrap();
    page["documents"][0]["id"] = json!("a");
    assert!(
        scan.validate(&serde_json::to_vec(&page).unwrap(), &call)
            .is_err()
    );
    page["documents"][0]["id"] = json!("b");
    page["data_epoch"] = json!(3);
    assert!(
        scan.validate(&serde_json::to_vec(&page).unwrap(), &call)
            .is_err()
    );
    page["data_epoch"] = json!(5);
    assert!(
        scan.validate(&serde_json::to_vec(&page).unwrap(), &call)
            .is_err()
    );
}
struct Hooks {
    entered: tokio::sync::oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
    panic: bool,
}
static HOOKS: OnceLock<Mutex<Option<Hooks>>> = OnceLock::new();
struct PausedValue;
impl SnapshotOutput for PausedValue {
    fn from_decoded(_: semantic::Decoded) -> Result<Self, ClientError> {
        let hooks = HOOKS.get().unwrap().lock().unwrap().take().unwrap();
        hooks.entered.send(()).ok();
        hooks.release.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(!hooks.panic, "injected owned decoder panic");
        Ok(Self)
    }
}
#[tokio::test]
async fn cancelled_and_panicking_decoder_keeps_charge_until_actual_worker_exit() {
    for mode in 0..3 {
        let panic = mode == 1;
        let mut options = options();
        if mode == 2 {
            options.deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        }
        let call = options.admit().unwrap();
        let mut waiter = Some(call.waiter());
        let prepared = prepare_read(
            &ReadSnapshotRequest {
                documents: vec![],
                queries: vec![],
            },
            &call,
        )
        .unwrap();
        let bytes = Bytes::from(serde_json::to_vec(&response(&call)).unwrap());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = mpsc::channel();
        *HOOKS.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(Hooks {
            entered,
            release: wait,
            panic,
        });
        let worker = decode_wire::<PausedValue>(
            transport::Wire {
                bytes,
                call: call.clone(),
            },
            prepared,
        );
        drop(call);
        tokio::time::timeout(Duration::from_secs(5), observed)
            .await
            .unwrap()
            .unwrap();
        if mode == 2 {
            // The actual worker has entered its final conversion; expiration
            // must still fence release when the conversion completes.
            tokio::time::sleep_until(options.deadline).await;
        }
        if mode != 2 {
            drop(waiter.take());
        }
        assert_eq!(options.resources.usage().live_owners, 1);
        release.send(()).unwrap();
        let result = worker.await;
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(options.resources.usage(), ClientResourceUsage::default());
        drop(waiter);
    }
}

#[test]
fn literal_marker_keys_and_nested_payloads_round_trip_as_ordinary_documents() {
    let options = options();
    let call = options.admit().unwrap();
    let raw = br#"{"$serde_json::private::RawValue":"[null,null]","\u0024serde_json::private::Number":"123456789012345678901234567890","ordinary":{"values":[1,true,null,"text"]}}"#;
    tokens::admit(raw, &call).unwrap();
    let literal = tokens::literal(raw, &call).unwrap();
    let object = literal.as_object().unwrap();
    assert_eq!(
        object["$serde_json::private::RawValue"].as_str(),
        Some("[null,null]")
    );
    assert_eq!(
        object["$serde_json::private::Number"].as_str(),
        Some("123456789012345678901234567890")
    );
    assert_eq!(object["ordinary"]["values"], json!([1, true, null, "text"]));
    let repeated = tokens::literal(&serde_json::to_vec(&literal).unwrap(), &call).unwrap();
    assert_eq!(literal, repeated);
    let input = ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "a".into(),
        }],
        queries: vec![],
    };
    let expected = Expected::read(&input, &call).unwrap();
    let mut outer = response(&call);
    outer["documents"] = json!([{"key":{"collection":"docs","id":"a"},"document":{"id":"a","version":4,"body":literal.clone()}}]);
    let outer = serde_json::to_vec(&outer).unwrap();
    tokens::admit(&outer, &call).unwrap();
    let semantic::Decoded::Read(result) = expected.decode(&outer, &call).unwrap() else {
        panic!("wrong snapshot kind")
    };
    assert_eq!(result.documents[0].document.as_ref().unwrap().body, literal);
}

#[test]
fn outbound_borrowed_walk_and_nil_scope_fail_before_encoding_growth() {
    let mut options = options();
    options.limits.max_depth = 3;
    let call = options.admit().unwrap();
    let mut value = json!("leaf");
    for _ in 0..8 {
        value = serde_json::Value::Array(vec![value]);
    }
    assert!(request::admit(&value, &call).is_err());
    assert!(encode(&value, &call).is_err());
    drop(call);
    options.expected_incarnation = uuid::Uuid::nil();
    assert!(options.admit().is_err());
    assert_eq!(options.resources.usage(), ClientResourceUsage::default());
}

#[tokio::test]
async fn parser_error_payload_drops_before_worker_admission_is_released() {
    let options = options();
    let call = options.admit().unwrap();
    let prepared = prepare_read(
        &ReadSnapshotRequest {
            documents: vec![],
            queries: vec![],
        },
        &call,
    )
    .unwrap();
    let mut reply = response(&call);
    // Unknown-field diagnostics from stock metadata Deserialize would otherwise
    // retain this peer-controlled field name after the owned worker exits.
    reply
        .as_object_mut()
        .unwrap()
        .insert("x".repeat(16 << 10), json!(0));
    let wire = transport::Wire {
        bytes: Bytes::from(serde_json::to_vec(&reply).unwrap()),
        call: call.clone(),
    };
    let worker = decode_wire::<SnapshotReadResponse>(wire, prepared);
    drop(call);
    let error = worker.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        ClientError::DecodeRejected {
            code: tonic::Code::DataLoss,
            reason: "snapshot JSON failed validation"
        }
    ));
    assert_eq!(options.resources.usage(), ClientResourceUsage::default());
}

#[test]
fn transport_error_retains_code_without_peer_message_details_or_metadata() {
    let options = options();
    let call = options.admit().unwrap();
    let mut status = tonic::Status::with_details(
        tonic::Code::Unavailable,
        "peer text".repeat(4096),
        Bytes::from(vec![42; 16 << 10]),
    );
    status
        .metadata_mut()
        .insert("peer-data", "x".repeat(16 << 10).parse().unwrap());
    let error = normalize(ClientError::Transport(status));
    assert_eq!(options.resources.usage().live_owners, 1);
    drop(call);
    assert!(matches!(
        error,
        ClientError::DecodeRejected {
            code: tonic::Code::Unavailable,
            reason: "snapshot transport failed"
        }
    ));
    assert_eq!(options.resources.usage(), ClientResourceUsage::default());
}

#[test]
fn query_rows_cannot_advance_beyond_their_collection_epoch() {
    let options = options();
    let call = options.admit().unwrap();
    let input = ReadSnapshotRequest {
        documents: vec![],
        queries: vec![
            serde_json::from_value(
                json!({"collection":"docs", "filter":{"op":"all"}, "limit":2, "allow_scan":true}),
            )
            .unwrap(),
        ],
    };
    let expected = Expected::read(&input, &call).unwrap();
    let mut reply = response(&call);
    reply["revision"] = json!(10);
    reply["collection_epochs"] = json!({"docs":2});
    reply["queries"] = json!([{"revision":10,"rows":[{"id":"a","version":9,"body":{"value":"too new for this collection"},"score":null}],"aggregates":[],"cursor":null}]);
    let bytes = serde_json::to_vec(&reply).unwrap();
    tokens::admit(&bytes, &call).unwrap();
    assert!(expected.validate(&bytes, &call).is_err());
    assert!(expected.decode(&bytes, &call).is_err());
    reply["queries"][0]["rows"][0]["version"] = json!(2);
    let bytes = serde_json::to_vec(&reply).unwrap();
    tokens::admit(&bytes, &call).unwrap();
    expected.validate(&bytes, &call).unwrap();
    let semantic::Decoded::Read(decoded) = expected.decode(&bytes, &call).unwrap() else {
        panic!("wrong snapshot kind")
    };
    assert_eq!(decoded.queries[0].rows[0].version, 2);
    assert_eq!(decoded.collection_epochs["docs"], 2);
}
