//! Parser-boundary regressions only; these do not start listeners or authenticate.
use kasumi_types::*;
use serde_json::{Value, json};

fn body() -> Value {
    json!({
        "number_object": {"$serde_json::private::Number": "7"},
        "raw_object": {"$serde_json::private::RawValue": "not JSON"},
        "nested": [{"$serde_json::private::RawValue": "{\"changed\":true}"}],
        "exact": "90071992547409931234567890.123456789".parse::<serde_json::Number>().unwrap()
    })
}

fn batch() -> MutationBatch {
    MutationBatch {
        idempotency_key: "literal-markers".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "first".into(),
            body: body(),
            expected: Precondition::Absent,
        }],
    }
}

#[test]
fn native_mutation_query_and_canonical_command_keep_literal_values() {
    let expected = batch();
    let bytes = serde_json::to_vec(&expected).unwrap();
    let decoded: MutationBatch = crate::api::decode_json(&bytes).unwrap();
    assert_eq!(decoded, expected);
    let chunk = AppendStagedChunk {
        transaction: StagedTransactionRef {
            scope: StagedTransactionScope {
                tenant: "tenant".into(),
                incarnation: "source".into(),
                principal: "owner".into(),
            },
            transaction_id: "transaction".into(),
            manifest_digest: "a".repeat(64),
        },
        index: 0,
        chunk: StagedChunk {
            read_set: vec![],
            operations: expected.operations.clone(),
        },
    };
    let encoded = serde_json::to_vec(&chunk).unwrap();
    let observed: AppendStagedChunk = crate::api::decode_json(&encoded).unwrap();
    assert_eq!(observed.chunk.operations, expected.operations);
    let predicate = Predicate::Eq {
        field: "/x".into(),
        value: json!({"$serde_json::private::Number":"7"}),
    };
    let encoded = serde_json::to_vec(&predicate).unwrap();
    let observed: Predicate = crate::api::decode_json(&encoded).unwrap();
    assert_eq!(observed, predicate);
    let command = Command {
        context: RequestContext {
            authorization: RequestAuthorization::service_identity(),
            tenant: "tenant".into(),
            principal: "owner".into(),
            scopes: [Action::Write].into_iter().collect(),
            request_id: "literal-command".into(),
        },
        timestamp_ms: 1,
        operation: Operation::Mutate(decoded),
    };
    let committed = serde_json::to_vec(&command).unwrap();
    let applied: Command = serde_json::from_slice(&committed).unwrap();
    assert_eq!(serde_json::to_vec(&applied).unwrap(), committed);
    let Operation::Mutate(applied) = applied.operation else {
        panic!("operation changed")
    };
    assert_eq!(applied, expected);
}

#[test]
fn rmcp_earliest_message_decode_and_typed_arguments_preserve_literals() {
    let expected = batch();
    let envelope = json!({
        "jsonrpc":"2.0", "id":1, "method":"tools/call",
        "params":{
            "name":"kasumi_mutate", "arguments":expected,
            "_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"literal-test","version":"1"},
                "io.modelcontextprotocol/clientCapabilities":{}
            }
        }
    });
    let bytes = serde_json::to_vec(&envelope).unwrap();
    // This is the exact type instantiated by rmcp's bounded expect_json reader.
    let message: rmcp::model::ClientJsonRpcMessage = serde_json::from_slice(&bytes).unwrap();
    let observed: Value = serde_json::from_slice(&serde_json::to_vec(&message).unwrap()).unwrap();
    let arguments = observed["params"]["arguments"].clone();
    assert_eq!(arguments, envelope["params"]["arguments"]);
    let typed: MutationBatch = serde_json::from_value(arguments).unwrap();
    assert_eq!(typed, expected);
}

#[test]
fn history_chunk_documents_keep_the_original_body_digest() {
    let expected = HistoryArchiveChunk {
        kind: HistoryArchiveKind::HistorySubset,
        archive_id: "archive".into(),
        collection: "docs".into(),
        source_incarnation: "source".into(),
        index: 0,
        documents: vec![std::sync::Arc::new(Document {
            id: "first".into(),
            version: 1,
            body: body(),
        })],
    };
    let bytes = serde_json::to_vec(&expected).unwrap();
    let decoded: HistoryArchiveChunk = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.documents, expected.documents);
    assert_eq!(
        staged_digest(&decoded.documents[0]).unwrap(),
        staged_digest(&expected.documents[0]).unwrap()
    );
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}
