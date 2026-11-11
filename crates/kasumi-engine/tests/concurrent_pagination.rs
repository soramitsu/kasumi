mod common;

use kasumi_engine::test_utils::open_fixture;
use kasumi_engine::{AdmittedOutput, Database};
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

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

/// Fixture budget for resolving one request whose attempts keep missing a
/// production deadline on a CPU-starved host (load 90-350 on 16 cores). Every
/// attempt keeps its production deadline; a snapshot continuation is still
/// bounded by its own cursor lifetime.
const RESOLUTION_WINDOW: Duration = Duration::from_secs(300);

/// A page withheld only because a production deadline passed: the 5 s read
/// deadline, admission of its strict read audit, or the audit write itself
/// ("could not be confirmed durable"). None of them released a row.
fn withheld_page(error: &Error) -> bool {
    match error.code {
        ErrorCode::ResourceExhausted => matches!(
            error.message.as_str(),
            "query deadline exceeded"
                | "document read deadline exceeded"
                | "proposal admission deadline exceeded"
        ),
        ErrorCode::AuditUnavailable => {
            error.message == "required read audit could not be confirmed durable"
        }
        _ => false,
    }
}

/// A strict-audited page can miss its production deadlines before release on a
/// loaded host. Its continuation is replaced only after a successful release,
/// so the client retries the identical request; every other outcome, including
/// each expected rejection below, is returned unchanged.
async fn query(
    db: &Database,
    principal: &str,
    request: &QueryRequest,
) -> Result<AdmittedOutput<QueryResponse>> {
    let window = tokio::time::Instant::now() + RESOLUTION_WINDOW;
    loop {
        match db.query(&identity(principal), request.clone()).await {
            Err(error) if withheld_page(&error) && tokio::time::Instant::now() < window => {
                eprintln!(
                    "fixture retry of a page withheld by a production deadline: {}",
                    error.message
                );
            }
            result => return result,
        }
    }
}

/// A batch that misses its write deadline may still commit. Resolve it as the
/// error instructs: retry the same idempotency key, which replays its receipt.
async fn mutate(db: &Database, batch: MutationBatch) -> WriteReceipt {
    let window = tokio::time::Instant::now() + RESOLUTION_WINDOW;
    loop {
        match db.mutate(identity("owner"), batch.clone()).await {
            Ok(receipt) => return receipt,
            Err(error)
                if error.code == ErrorCode::UnknownOutcome
                    && tokio::time::Instant::now() < window =>
            {
                eprintln!("fixture retry of an uncertain batch: {}", error.message);
            }
            Err(error) => panic!("mutation {} rejected: {error:?}", batch.idempotency_key),
        }
    }
}

/// Administrative writes carry no idempotency key. Resolve an uncertain one by
/// observing its applied effect; never propose it a second time.
async fn administer(db: &Database, operation: Operation, applied: impl Fn(&TenantState) -> bool) {
    match db.administer(identity("owner"), operation).await {
        Ok(_) => {}
        Err(error) if error.code == ErrorCode::UnknownOutcome => {
            eprintln!(
                "fixture resolves an uncertain administrative write: {}",
                error.message
            );
            tokio::time::timeout(RESOLUTION_WINDOW, async {
                while !applied(&db.engine().generation().unwrap().state) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("uncertain administrative write never applied: {error:?}"));
        }
        Err(error) => panic!("administrative write rejected: {error:?}"),
    }
}

fn reader_granted(state: &TenantState) -> bool {
    state
        .policy
        .grants
        .iter()
        .any(|grant| grant.principal == "reader")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_pages_overlap_atomic_writers_and_current_policy_revocation() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("node.kv"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "pages".into(),
        Arc::new(LocalKeyProvider::new([62; 32])),
    )
    .await
    .unwrap();
    let stores = kasumi_store::test_utils::initialize_custody_fixture(
        store,
        std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    // One cursor must span all 32 pages and the 31 batches that overlap them,
    // but cursor lifetime is capped at 60 s, which a loaded host can exceed.
    // Run the database's elapsed clock (cursor lifetimes) on a manual clock
    // that this test never advances; cursor expiry has its own test in
    // fixture_epoch_clock.rs. This mirrors `open_fixture` otherwise.
    kasumi_engine::test_utils::install_fixture_audit_placement(stores.application()).unwrap();
    let elapsed = Arc::new(kasumi_store::test_utils::ManualClock::new());
    let epoch = Arc::new(
        kasumi_clock::EpochClock::new(elapsed, Arc::new(kasumi_clock::SystemWallClock)).unwrap(),
    );
    let database = kasumi_engine::open_fixture_with_epoch_clock(
        stores,
        policy(true),
        Limits::default(),
        audit.clone(),
        physical.storage.admission.clone(),
        epoch,
    )
    .await
    .unwrap();
    administer(
        &database,
        Operation::CreateCollection(CollectionDefinition {
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            name: "docs".into(),
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: true,
        }),
        |state| state.collections.contains_key("docs"),
    )
    .await;
    mutate(&database, batch(0)).await;
    let first = query(&database, "reader", &request()).await.unwrap();
    let revision = first.revision;
    let mut next = request();
    next.cursor = first.cursor.clone();
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
            mutate(&writer_db, batch(phase)).await;
            writer_barrier.wait().await;
        }
    });
    let reader_db = database.clone();
    let reader = tokio::spawn(async move {
        for _ in 1..32 {
            rendezvous.wait().await;
            let page = query(&reader_db, "reader", &next).await.unwrap();
            assert_eq!(page.revision, revision);
            assert_eq!(page.rows.len(), 1);
            assert_eq!(page.rows[0].body["phase"], 0);
            assert!(
                seen.insert(page.rows[0].id.clone()),
                "duplicate historical row"
            );
            next.cursor = page.cursor.clone();
            rendezvous.wait().await;
        }
        assert!(next.cursor.is_none());
        assert_eq!(seen.len(), 32);
    });
    // A deadlock budget only; each step above resolves within its own window.
    // Return as soon as either task fails rather than waiting at its barrier.
    tokio::time::timeout(RESOLUTION_WINDOW * 4, async {
        tokio::try_join!(writer, reader).unwrap();
    })
    .await
    .unwrap();
    let window = tokio::time::Instant::now() + RESOLUTION_WINDOW;
    let latest = loop {
        match database.get(&identity("owner"), "docs", "00").await {
            Err(error)
                if error.code == ErrorCode::ResourceExhausted
                    && error.message == "point read deadline exceeded"
                    && tokio::time::Instant::now() < window => {}
            result => break result.unwrap().expect("document exists"),
        }
        eprintln!("fixture retry after a missed production point-read deadline");
    };
    assert_eq!(latest.body["phase"], 31);

    let reader_page = query(&database, "reader", &request()).await.unwrap();
    let mut reader_cursor = request();
    reader_cursor.cursor = reader_page.cursor.clone();
    let owner_page = query(&database, "owner", &request()).await.unwrap();
    let mut owner_cursor = request();
    owner_cursor.cursor = owner_page.cursor.clone();
    let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
    let revoke_db = database.clone();
    let revoke_barrier = rendezvous.clone();
    let revoke = tokio::spawn(async move {
        revoke_barrier.wait().await;
        administer(&revoke_db, Operation::SetPolicy(policy(false)), |state| {
            !reader_granted(state)
        })
        .await;
    });
    let paging_db = database.clone();
    let racing_cursor = reader_cursor.clone();
    let page = tokio::spawn(async move {
        rendezvous.wait().await;
        query(&paging_db, "reader", &racing_cursor).await
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
        query(&database, "reader", &reader_cursor)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        query(&database, "owner", &owner_cursor)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    administer(
        &database,
        Operation::SetPolicy(policy(true)),
        reader_granted,
    )
    .await;
    assert_eq!(
        query(&database, "reader", &reader_cursor)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    assert!(query(&database, "reader", &request()).await.is_ok());
    database.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_documents_page_by_bytes_instead_of_failing_and_count_reads_nothing() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("node.kv"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "pages".into(),
        Arc::new(LocalKeyProvider::new([63; 32])),
    )
    .await
    .unwrap();
    // Ten 20 KiB documents exceed one 64 KiB page several times over.
    let limits = Limits {
        max_result_bytes: 64 << 10,
        ..Limits::default()
    };
    let database = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store,
            Arc::new(LocalKeyProvider::new([242; 32])),
        )
        .await
        .unwrap(),
        policy(false),
        limits,
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
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut batch = MutationBatch::with_key("large");
    for ordinal in 0..10 {
        batch = batch.insert(
            "docs",
            format!("{ordinal:02}"),
            json!({"ordinal": ordinal, "payload": "x".repeat(20 << 10)}),
        );
    }
    database.mutate(identity("owner"), batch).await.unwrap();

    let mut query = QueryRequest::new("docs").limit(100);
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let page = database
            .query(&identity("owner"), query.clone())
            .await
            .unwrap();
        assert!(!page.rows.is_empty() && page.rows.len() <= 3);
        assert!(serde_json::to_vec(&*page).unwrap().len() <= 64 << 10);
        seen.extend(page.rows.iter().map(|row| row.id.clone()));
        pages += 1;
        match page.cursor.clone() {
            Some(cursor) => query.cursor = Some(cursor),
            None => break,
        }
    }
    assert!(pages >= 4);
    assert_eq!(
        seen,
        (0..10)
            .map(|ordinal| format!("{ordinal:02}"))
            .collect::<Vec<_>>()
    );
    let count = database
        .query(
            &identity("owner"),
            QueryRequest::new("docs").aggregate("n", Aggregation::count()),
        )
        .await
        .unwrap();
    assert!(count.rows.is_empty() && count.cursor.is_none());
    assert_eq!(
        count.aggregates,
        [json!({"group": {}, "values": {"n": 10}})]
    );
    database.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}
