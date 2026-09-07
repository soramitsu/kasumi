mod common;

use kasumi_engine::open_local;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn identity(principal: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: "pages".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: format!("pagination-{principal}"),
    }
}

fn policy(reader: bool) -> Policy {
    let mut grants = vec![Grant {
        principal: "owner".into(),
        collection: None,
        actions: identity("owner").scopes,
    }];
    if reader {
        grants.push(Grant {
            principal: "reader".into(),
            collection: Some("docs".into()),
            actions: BTreeSet::from([Action::Read]),
        });
    }
    Policy {
        grants,
        strict_read_audit: true,
    }
}

fn batch(phase: usize) -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: format!("phase-{phase}"),
        operations: (0..32)
            .map(|ordinal| Mutation::Put {
                collection: "docs".into(),
                id: format!("{ordinal:02}"),
                body: json!({"ordinal": ordinal, "phase": phase}),
                expected: Precondition::Any,
            })
            .collect(),
    }
}

fn request() -> QueryRequest {
    serde_json::from_value(json!({"collection":"docs","allow_scan":true,"limit":1})).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_pages_overlap_atomic_writers_and_current_policy_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "pages".into(),
        Arc::new(LocalKeyProvider::new([62; 32])),
    )
    .await
    .unwrap();
    let database = open_local(
        kasumi_store::test_utils::with_custody(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy(true),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    database
        .administer(
            identity("owner"),
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
    database.mutate(identity("owner"), batch(0)).await.unwrap();
    let first = database
        .query(&identity("reader"), request())
        .await
        .unwrap();
    let revision = first.revision;
    let mut next = request();
    next.cursor = first.cursor;
    let mut seen = BTreeSet::from([first.rows[0].id.clone()]);
    assert_eq!(first.rows[0].body["phase"], 0);

    // Separate tasks enter every page/write pair together. The second barrier
    // prevents either task from finishing all its work before the other starts.
    let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
    let writer_db = database.clone();
    let writer_barrier = rendezvous.clone();
    let writer = tokio::spawn(async move {
        for phase in 1..32 {
            writer_barrier.wait().await;
            writer_db
                .mutate(identity("owner"), batch(phase))
                .await
                .unwrap();
            writer_barrier.wait().await;
        }
    });
    let reader_db = database.clone();
    let reader = tokio::spawn(async move {
        for _ in 1..32 {
            rendezvous.wait().await;
            let page = reader_db
                .query(&identity("reader"), next.clone())
                .await
                .unwrap();
            assert_eq!(page.revision, revision);
            assert_eq!(page.rows.len(), 1);
            assert_eq!(page.rows[0].body["phase"], 0);
            assert!(
                seen.insert(page.rows[0].id.clone()),
                "duplicate historical row"
            );
            next.cursor = page.cursor;
            rendezvous.wait().await;
        }
        assert!(next.cursor.is_none());
        assert_eq!(seen.len(), 32);
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let (writer, reader) = tokio::join!(writer, reader);
        writer.unwrap();
        reader.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(
        database
            .get(&identity("owner"), "docs", "00")
            .await
            .unwrap()
            .body["phase"],
        31
    );

    let reader_page = database
        .query(&identity("reader"), request())
        .await
        .unwrap();
    let mut reader_cursor = request();
    reader_cursor.cursor = reader_page.cursor;
    let owner_page = database.query(&identity("owner"), request()).await.unwrap();
    let mut owner_cursor = request();
    owner_cursor.cursor = owner_page.cursor;
    let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
    let revoke_db = database.clone();
    let revoke_barrier = rendezvous.clone();
    let revoke = tokio::spawn(async move {
        revoke_barrier.wait().await;
        revoke_db
            .administer(identity("owner"), Operation::SetPolicy(policy(false)))
            .await
            .unwrap();
    });
    let paging_db = database.clone();
    let racing_cursor = reader_cursor.clone();
    let page = tokio::spawn(async move {
        rendezvous.wait().await;
        paging_db.query(&identity("reader"), racing_cursor).await
    });
    let (revoked, page) = tokio::join!(revoke, page);
    revoked.unwrap();
    match page.unwrap() {
        // This result may have been authorized before revocation committed.
        Ok(page) => assert_eq!(page.rows[0].body["phase"], 31),
        Err(error) => assert!(matches!(
            error.code,
            ErrorCode::Forbidden | ErrorCode::CursorExpired | ErrorCode::Conflict
        )),
    }
    // Once revocation returns, every continuation rechecks current access.
    assert_eq!(
        database
            .query(&identity("reader"), reader_cursor.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        database
            .query(&identity("owner"), owner_cursor)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    database
        .administer(identity("owner"), Operation::SetPolicy(policy(true)))
        .await
        .unwrap();
    assert_eq!(
        database
            .query(&identity("reader"), reader_cursor)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    assert!(database.query(&identity("reader"), request()).await.is_ok());
    database.shutdown().await.unwrap();
    audit.shutdown().await;
}
