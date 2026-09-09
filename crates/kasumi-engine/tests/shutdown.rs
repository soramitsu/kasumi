mod common;

use kasumi_engine::open_local;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_shutdown_reopens_immediately_with_receipts_and_retained_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node.redb");
    let provider = Arc::new(LocalKeyProvider::new([29; 32]));
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "shutdown".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: "shutdown-test".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: context.principal.clone(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: false,
    };
    for round in 0..4 {
        // Reopening is immediate: no sleep, lock retry, or ignored open error.
        let node = NodeStore::create_new(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let audit = common::security_audit(node.clone()).await;
        let store =
            TenantStore::open_fixture(node.clone(), context.tenant.clone(), provider.clone())
                .await
                .unwrap();
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
        if round == 0 {
            database
                .administer(
                    context.clone(),
                    Operation::CreateCollection(CollectionDefinition {
                        retention_class: kasumi_types::CollectionRetentionClass::Operational,
                        write_mode: kasumi_types::CollectionWriteMode::Mutable,
                        name: "docs".into(),
                        schema: json!({"type":"object","required":["n"]}),
                        indexes: vec![],
                        strict_read_audit: false,
                    }),
                )
                .await
                .unwrap();
        } else {
            assert_eq!(
                database.get(&context, "docs", "a").await.unwrap().body["n"],
                round - 1
            );
            assert!(
                database
                    .operation_receipt(&context, &format!("write-{}", round - 1))
                    .await
                    .unwrap()
                    .unwrap()
                    .outcome
                    .is_ok()
            );
        }
        database
            .mutate(
                context.clone(),
                MutationBatch {
                    read_set: Vec::new(),
                    idempotency_key: format!("write-{round}"),
                    operations: ["a", "b"]
                        .into_iter()
                        .map(|id| Mutation::Put {
                            collection: "docs".into(),
                            id: id.into(),
                            body: json!({"n":round}),
                            expected: Precondition::Any,
                        })
                        .collect(),
                },
            )
            .await
            .unwrap();
        let retained = database.get_shared(&context, "docs", "a").await.unwrap();
        let page = database
            .query(
                &context,
                serde_json::from_value(json!({"collection":"docs","allow_scan":true,"limit":1}))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(page.cursor.is_some());
        database
            .raft_group()
            .raft()
            .trigger()
            .snapshot()
            .await
            .unwrap();
        let (first, second) = tokio::join!(database.shutdown(), database.shutdown());
        first.unwrap();
        second.unwrap();
        assert_eq!(
            database.get(&context, "docs", "a").await.unwrap_err().code,
            ErrorCode::Unavailable
        );
        assert!(database.engine().generation().is_err());
        assert!(store.check_access().is_err());
        // Previously released documents belong to the trusted embedding caller.
        assert_eq!(retained.body["n"], round);
        drop(database);
        drop(store);
        audit.shutdown().await;
        drop(audit);
        drop(node);
        let reopened = NodeStore::open_existing(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        drop(reopened);
    }
}
