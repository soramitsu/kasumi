mod common;
use kasumi_engine::test_utils::open_fixture;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};
fn context(principal: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: "seek".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: format!("seek-{principal}"),
    }
}
fn policy(reader: bool) -> Policy {
    let mut grants = vec![Grant {
        principal: "owner".into(),
        collection: None,
        actions: context("owner").scopes,
    }];
    if reader {
        grants.push(Grant {
            principal: "reader".into(),
            collection: Some("rows".into()),
            actions: BTreeSet::from([Action::Read]),
        });
    }
    Policy {
        grants,
        strict_read_audit: true,
    }
}
fn request() -> OrderedSeekRequest {
    OrderedSeekRequest {
        collection: "rows".into(),
        index: "scope_time_id".into(),
        prefix: vec![json!("a")],
        lower: None,
        upper: None,
        direction: Direction::Desc,
        limit: 2,
        continuation: None,
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_store_ordered_seek_has_bounded_visits_and_epoch_fenced_continuation() {
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::create_new(
        directory.path().join("seek.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "seek".into(),
        Arc::new(LocalKeyProvider::new([55; 32])),
    )
    .await
    .unwrap();
    let database = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store,
            Arc::new(LocalKeyProvider::new([56; 32])),
        )
        .await
        .unwrap(),
        policy(true),
        Limits {
            max_query_candidates: 3,
            ..Limits::default()
        },
        audit.clone(),
    )
    .await
    .unwrap();
    database
        .administer(
            context("owner"),
            Operation::CreateCollection(CollectionDefinition {
                name: "rows".into(),
                schema: json!({"type":"object"}),
                indexes: vec![IndexDefinition {
                    name: "scope_time_id".into(),
                    fields: ["/scope", "/at", "/literalId"]
                        .into_iter()
                        .map(|path| IndexField {
                            path: path.into(),
                            kind: ScalarType::String,
                        })
                        .collect(),
                    unique: true,
                    text: None,
                }],
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                strict_read_audit: true,
            }),
        )
        .await
        .unwrap();
    for chunk in 0..51 {
        let operations=(chunk*200..((chunk+1)*200).min(10_005)).map(|n|Mutation::Put{collection:"rows".into(),id:format!("row-{n:05}"),body:json!({"scope":"a","at":format!("{n:020}"),"literalId":format!("literal-{n:05}")}),expected:Precondition::Absent}).collect::<Vec<_>>();
        if operations.is_empty() {
            continue;
        }
        database
            .mutate(
                context("owner"),
                MutationBatch {
                    idempotency_key: format!("seed-{chunk}"),
                    read_set: vec![],
                    operations,
                },
            )
            .await
            .unwrap();
    }
    let first = database
        .ordered_seek(&context("reader"), request())
        .await
        .unwrap();
    assert_eq!(first.rows.len(), 2);
    assert_eq!(first.index_entries_visited, 3);
    assert_eq!(first.rows[0].body["at"], "00000000000000010004");
    let cursor = first.continuation.clone().unwrap();
    let next = database
        .ordered_seek(
            &context("reader"),
            OrderedSeekRequest {
                continuation: Some(cursor.clone()),
                ..request()
            },
        )
        .await
        .unwrap();
    // The strict read audit changes global revision, while source collection
    // contents, membership, index definition and policy remain exactly pinned.
    assert_eq!(next.revision, first.revision);
    assert!(next.observed_revision > first.observed_revision);
    assert_eq!(next.collection_epoch, first.collection_epoch);
    assert_eq!(next.rows[0].body["at"], "00000000000000010002");
    assert_eq!(next.index_entries_visited, 3);
    // The ordinary complete query still enforces its original candidate bound.
    let ordinary: QueryRequest = serde_json::from_value(
        json!({"collection":"rows","filter":{"op":"eq","field":"/scope","value":"a"},"limit":2}),
    )
    .unwrap();
    assert_eq!(
        database
            .query(&context("reader"), ordinary)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    database
        .mutate(
            context("owner"),
            MutationBatch {
                idempotency_key: "change-source".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "rows".into(),
                    id: "new".into(),
                    body: json!({"scope":"a","at":"00000000000000020000","literalId":"new"}),
                    expected: Precondition::Absent,
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        database
            .ordered_seek(
                &context("reader"),
                OrderedSeekRequest {
                    continuation: Some(cursor),
                    ..request()
                }
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let current = database
        .ordered_seek(&context("reader"), request())
        .await
        .unwrap();
    database
        .administer(context("owner"), Operation::SetPolicy(policy(false)))
        .await
        .unwrap();
    assert_eq!(
        database
            .ordered_seek(
                &context("reader"),
                OrderedSeekRequest {
                    continuation: current.continuation,
                    ..request()
                }
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    database.shutdown().await.unwrap();
    audit.shutdown().await;
}
