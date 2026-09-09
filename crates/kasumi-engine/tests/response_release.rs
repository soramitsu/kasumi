mod common;

use kasumi_engine::open_local;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

#[tokio::test]
async fn encoded_response_is_fenced_by_policy_changes_and_actual_key_denial() {
    let directory = tempfile::tempdir().unwrap();
    let keys = Arc::new(LocalKeyProvider::new([41; 32]));
    let node = NodeStore::create_new(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let admission =
        kasumi_engine::admission::NodeAdmission::new(kasumi_engine::admission::AdmissionConfig {
            max_inflight_operations: 1,
            ..Default::default()
        })
        .unwrap();
    let audit = common::security_audit_with_admission(node.clone(), admission.clone()).await;
    let store = TenantStore::open_fixture(node, "tenant".into(), keys.clone())
        .await
        .unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "tenant".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "release-test".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: true,
    };
    let database = open_local(
        kasumi_store::test_utils::with_custody(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy.clone(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    database.install_admission(admission).unwrap();
    database
        .administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                name: "docs".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: true,
            }),
        )
        .await
        .unwrap();
    database
        .mutate(
            context.clone(),
            MutationBatch {
                read_set: Vec::new(),
                idempotency_key: "once".into(),
                operations: vec![Mutation::Put {
                    collection: "docs".into(),
                    id: "one".into(),
                    body: json!({"exact":9007199254740993u64}),
                    expected: Precondition::Absent,
                }],
            },
        )
        .await
        .unwrap();

    let fence = database.response_fence(&context).unwrap();
    let document = database.get(&context, "docs", "one").await.unwrap();
    let encoded = serde_json::to_vec(&document).unwrap();
    // A strict audit is nested work. The prepared response retains its bytes,
    // but must not occupy the only execution slot needed to persist its audit.
    assert_eq!(database.collections(&context).await.unwrap().len(), 1);
    assert!(
        database
            .operation_receipt(&context, "once")
            .await
            .unwrap()
            .is_some()
    );
    fence.check().unwrap();
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains("9007199254740993")
    );
    // Revocation lands after authorized read/audit/serialization and before the
    // adapter hands its payload to the transport. The old payload cannot pass.
    let mut denied = policy.clone();
    denied.grants[0].actions.remove(&Action::Read);
    database
        .administer(context.clone(), Operation::SetPolicy(denied))
        .await
        .unwrap();
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(
        database
            .get(&context, "docs", "one")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );

    database
        .administer(context.clone(), Operation::SetPolicy(policy))
        .await
        .unwrap();
    let fence = database.response_fence(&context).unwrap();
    let _encoded =
        serde_json::to_vec(&database.get(&context, "docs", "one").await.unwrap()).unwrap();
    keys.revoke();
    assert!(store.refresh_lease().await.is_err());
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Sealed);
    assert!(database.engine().generation().is_err());
    database.shutdown().await.unwrap();
    audit.shutdown().await;
}
