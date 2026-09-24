mod common;

use kasumi_engine::admission::AdmissionConfig;
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

#[tokio::test]
async fn reserved_capacity_rejects_proposals_and_queries_but_committed_raft_work_still_applies() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    const MAX_BYTES: u64 = 256 << 20;
    let physical = common::PhysicalFixture::new(
        &directory.path().join("node.kv"),
        kasumi_engine::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            max_inflight_bytes: Some(MAX_BYTES),
            ..Default::default()
        })
        .unwrap(),
    );
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let admission = physical.storage.admission.clone();
    let audit = common::security_audit(node.clone(), admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([9; 32])),
    )
    .await
    .unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Write, Action::Read]),
        request_id: "request".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: context.principal.clone(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: false,
    };
    let stores = kasumi_store::test_utils::initialize_custody_fixture(
        store,
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let database =
        kasumi_engine::test_utils::open_fixture(stores, policy, Limits::default(), audit.clone())
            .await
            .unwrap();
    let group = database.raft_group().clone();
    // Startup and audit use the same healthy facade. A real retained reservation
    // exhausts capacity after startup; no governor is replaced or reconfigured.
    let occupied = kasumi_engine::test_utils::reserved_payload_bytes(&admission)
        .checked_sub(physical.initial_disk_metadata_bytes)
        .unwrap();
    let held_capacity = admission
        .reserve(MAX_BYTES.checked_sub(occupied).unwrap(), None)
        .unwrap();
    assert_eq!(
        kasumi_engine::test_utils::reserved_payload_bytes(&admission),
        MAX_BYTES + physical.initial_disk_metadata_bytes
    );
    let operation = Operation::CreateCollection(CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "docs".into(),
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
    });
    let before = database.engine().generation().unwrap().state.revision;
    assert_eq!(
        database
            .administer(context.clone(), operation.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        database.engine().generation().unwrap().state.revision,
        before
    );
    // Followers and already-proposed records enter through Raft, not the local
    // client admission gate. The exact same operation must materialize normally.
    let command = Command {
        context: context.clone(),
        timestamp_ms: 1_000,
        operation,
    };
    let result = group
        .write(serde_json::to_vec(&command).unwrap())
        .await
        .unwrap();
    assert!(
        serde_json::from_slice::<Result<WriteReceipt>>(&result)
            .unwrap()
            .is_ok()
    );
    assert!(
        database
            .engine()
            .generation()
            .unwrap()
            .state
            .collections
            .contains_key("docs")
    );
    let query: QueryRequest = serde_json::from_value(json!({"collection":"docs"})).unwrap();
    assert_eq!(
        database.query(&context, query).await.unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        database.collections(&context).await.unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        database
            .operation_receipt(&context, "absent")
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    drop(held_capacity);
    database.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_local_bootstrap_reads_the_complete_committed_generation() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("local.kv"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("local.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "local".into(),
        Arc::new(LocalKeyProvider::new([8; 32])),
    )
    .await
    .unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "local".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Write, Action::Read]),
        request_id: "request".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: context.principal.clone(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: false,
    };
    let database = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy,
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("engine.deployment", b"mode").unwrap().as_deref(),
        Some(b"local-v1".as_slice())
    );
    database
        .administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                name: "docs".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_str(r#"{"exact":123456789012345678901234567890.00001}"#).unwrap();
    let receipt = database
        .mutate(
            context.clone(),
            MutationBatch {
                read_set: Vec::new(),
                idempotency_key: "batch".into(),
                operations: vec![
                    Mutation::Put {
                        collection: "docs".into(),
                        id: "a".into(),
                        body: body.clone(),
                        expected: Precondition::Absent,
                    },
                    Mutation::Put {
                        collection: "docs".into(),
                        id: "b".into(),
                        body: body.clone(),
                        expected: Precondition::Absent,
                    },
                ],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        database.get(&context, "docs", "a").await.unwrap().body,
        body
    );
    let query: QueryRequest = serde_json::from_value(json!({"collection":"docs"})).unwrap();
    let response = database.query(&context, query).await.unwrap();
    assert_eq!(response.rows.len(), 2);
    assert_eq!(response.revision, receipt.revision);
    assert_eq!(response.rows[0].body, response.rows[1].body);
    database.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}
