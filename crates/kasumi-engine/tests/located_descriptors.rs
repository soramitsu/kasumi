//! A published generation whose selected primary directory is current keeps
//! each live descriptor only in its located form. Reads and ordinary writes
//! resolve the rest of the descriptor from the authenticated directory rows,
//! across later generations, a cold reopen and a reopen from a Raft snapshot.
//! A change feed record of the current version shares the located slot; a
//! superseded one keeps its complete descriptor, so old after-images stay
//! readable.
mod common;
use kasumi_engine::{
    Database, SecurityAudit,
    test_utils::{fixture_descriptor, fixture_document},
};
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

const SEEDED: usize = 24;

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "located".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "located-descriptors".into(),
    }
}

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context().scopes,
        }],
        strict_read_audit: false,
    }
}

fn definition() -> CollectionDefinition {
    CollectionDefinition {
        name: "accounts".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type":"object"}),
        indexes: vec![IndexDefinition {
            name: "email".into(),
            fields: vec![IndexField {
                path: "/email".into(),
                kind: ScalarType::String,
            }],
            unique: true,
            text: None,
        }],
        strict_read_audit: false,
    }
}

fn id(i: usize) -> String {
    format!("acct-{i:04}")
}

fn email(i: usize) -> String {
    format!("user-{i:04}@example.test")
}

fn put(i: usize, email: &str, expected: Precondition) -> Mutation {
    Mutation::Put {
        collection: "accounts".into(),
        id: id(i),
        body: json!({"email": email, "memo": format!("{} {}", id(i), "x".repeat(96))}),
        expected,
    }
}

async fn mutate(db: &Database, key: &str, operations: Vec<Mutation>) -> Result<WriteReceipt> {
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: key.into(),
            read_set: vec![],
            operations,
        },
    )
    .await
}

async fn open(
    physical: &common::PhysicalFixture,
    path: &std::path::Path,
    create: bool,
) -> (Arc<Database>, Arc<SecurityAudit>, kasumi_store::NodeStore) {
    let node = (if create {
        physical
            .storage
            .create_new(path, kasumi_store::test_utils::NODE_STORE_ID)
    } else {
        physical
            .storage
            .open_existing(path, kasumi_store::test_utils::NODE_STORE_ID)
    })
    .unwrap();
    let audit = if create {
        common::security_audit(node.clone(), physical.storage.admission.clone()).await
    } else {
        common::existing_security_audit(node.clone(), physical.storage.admission.clone()).await
    };
    let key = || Arc::new(LocalKeyProvider::new([0xA7; 32]));
    let store = (if create {
        TenantStore::initialize_catalog_fixture(node.clone(), "located".into(), key()).await
    } else {
        TenantStore::open_existing_fixture(node.clone(), "located".into(), key()).await
    })
    .unwrap();
    let custody = || Arc::new(LocalKeyProvider::new([0xA8; 32]));
    let db = kasumi_engine::test_utils::open_fixture(
        (if create {
            kasumi_store::test_utils::initialize_custody_fixture(store, custody()).await
        } else {
            kasumi_store::test_utils::open_existing_custody_fixture(store, custody()).await
        })
        .unwrap(),
        policy(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    (db, audit, node)
}

async fn close(db: Arc<Database>, audit: Arc<SecurityAudit>, node: kasumi_store::NodeStore) {
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// Every live slot is located, resolves to the exact directory row and
/// lends its body; reads and the unique index see the same documents.
async fn assert_located(db: &Database, expected: &[(usize, String)]) {
    let generation = db.engine().generation().unwrap();
    let documents = &generation.state.collections["accounts"].documents;
    assert_eq!(documents.len(), expected.len());
    for (i, email) in expected {
        let slot = &documents[&id(*i)];
        let DocumentSlot::Located(located) = slot.as_ref() else {
            panic!("published descriptor {} stayed complete: {slot:?}", id(*i));
        };
        assert!(slot.stored().is_err(), "a located slot names no body alone");
        let descriptor = fixture_descriptor(&generation, "accounts", &id(*i)).unwrap();
        assert_eq!(LocatedDocument::of(&descriptor), Some(*located));
        let document = fixture_document(&generation, "accounts", &id(*i)).unwrap();
        assert_eq!(document.version, located.version());
        assert_eq!(document.body["email"], email.as_str());
    }
    drop(generation);
    for (i, email) in expected {
        let shared = db
            .get_shared(&context(), "accounts", &id(*i))
            .await
            .unwrap()
            .expect("live document");
        assert_eq!(shared.body["email"], email.as_str());
        let rows = db
            .query(
                &context(),
                QueryRequest::new("accounts").filter(Filter::new().eq("/email", email.as_str())),
            )
            .await
            .unwrap();
        assert_eq!(rows.rows.len(), 1, "email {email}");
        assert_eq!(rows.rows[0].id, id(*i));
    }
}

/// Retained records of current versions share the located slot; a record
/// superseded by a later change keeps a complete descriptor.
fn assert_feed(db: &Database) {
    let generation = db.engine().generation().unwrap();
    let documents = &generation.state.collections["accounts"].documents;
    let mut shared = 0;
    let mut superseded = 0;
    for commit in generation.state.change_feed.commits.values() {
        for record in &commit.records {
            let Some(slot) = &record.document else {
                continue;
            };
            match documents.get(&record.id) {
                Some(current) if current.version() == slot.version() => {
                    if matches!(slot.as_ref(), DocumentSlot::Located(_)) {
                        assert!(Arc::ptr_eq(current, slot), "located record not shared");
                        shared += 1;
                    }
                }
                _ => {
                    assert!(
                        matches!(slot.as_ref(), DocumentSlot::Stored(_)),
                        "superseded record {} lost its complete descriptor",
                        record.id
                    );
                    superseded += 1;
                }
            }
        }
    }
    assert!(
        shared > 0 && superseded > 0,
        "{shared} shared, {superseded} superseded"
    );
}

/// Every retained after-image, including superseded versions, is readable.
async fn assert_feed_readable(db: &Database) -> usize {
    let mut start = ChangeFeedStart::Beginning;
    let mut seen = 0;
    loop {
        let page = db
            .read_change_feed(
                &context(),
                ReadChangeFeed {
                    collections: BTreeSet::from(["accounts".into()]),
                    start,
                    limit: 16,
                },
            )
            .await
            .unwrap();
        let ChangeFeedPage::Events {
            events,
            next,
            caught_up,
            ..
        } = page.as_ref()
        else {
            panic!("unexpected retention gap")
        };
        for event in events {
            if let Some(document) = &event.document {
                assert_eq!(document.id, event.id);
                assert_eq!(document.version, event.revision);
                assert!(document.body["email"].is_string());
            }
        }
        seen += events.len();
        if *caught_up {
            return seen;
        }
        start = ChangeFeedStart::After {
            cursor: next.clone(),
        };
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_descriptors_stay_located_across_writes_and_reopens() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = root.path().join("node.kv");
    let physical = common::PhysicalFixture::new(&path, Default::default());
    let (db, audit, node) = open(&physical, &path, true).await;
    let generation = db.engine().generation().unwrap();
    db.activate_schema(
        context(),
        SchemaChangeSet {
            activation_id: "create".into(),
            expected_incarnation: generation.state.incarnation.clone(),
            expected_schema_epoch: generation.state.schema_epoch,
            read_set: vec![],
            changes: vec![SchemaChange::Create {
                definition: definition(),
            }],
        },
    )
    .await
    .unwrap();
    drop(generation);
    mutate(
        &db,
        "seed",
        (0..SEEDED)
            .map(|i| put(i, &email(i), Precondition::Absent))
            .collect(),
    )
    .await
    .unwrap();
    let mut expected: Vec<(usize, String)> = (0..SEEDED).map(|i| (i, email(i))).collect();
    assert_located(&db, &expected).await;

    // The ordered writer checks located versions, patches a located body and
    // replaces old index keys read from the directory rows.
    let version =
        db.engine().generation().unwrap().state.collections["accounts"].documents[&id(0)].version();
    let stale = mutate(
        &db,
        "stale",
        vec![put(
            0,
            "stale@example.test",
            Precondition::Version(version + 1),
        )],
    )
    .await
    .unwrap_err();
    assert_eq!(stale.code, ErrorCode::Conflict);
    mutate(
        &db,
        "patch",
        vec![Mutation::Patch {
            collection: "accounts".into(),
            id: id(0),
            patch: json!({"email": "renamed@example.test"}),
            expected: Precondition::Version(version),
        }],
    )
    .await
    .unwrap();
    expected[0].1 = "renamed@example.test".into();
    let duplicate = mutate(
        &db,
        "duplicate",
        vec![put(90, &email(2), Precondition::Absent)],
    )
    .await
    .unwrap_err();
    assert_eq!(duplicate.code, ErrorCode::Conflict);
    // The patch released the old email and a delete removes a located row.
    mutate(
        &db,
        "reuse",
        vec![
            put(SEEDED, &email(0), Precondition::Absent),
            Mutation::Delete {
                collection: "accounts".into(),
                id: id(1),
                expected: Precondition::Version(version),
            },
        ],
    )
    .await
    .unwrap();
    expected.retain(|(i, _)| *i != 1);
    expected.push((SEEDED, email(0)));
    let taken = mutate(
        &db,
        "taken",
        vec![put(91, "renamed@example.test", Precondition::Absent)],
    )
    .await
    .unwrap_err();
    assert_eq!(taken.code, ErrorCode::Conflict);
    assert_located(&db, &expected).await;
    assert_feed(&db);
    let events = assert_feed_readable(&db).await;
    assert!(events >= SEEDED + 3);

    // A cold reopen replays into complete descriptors and compacts them once
    // its directory is current again.
    close(db, audit, node).await;
    let (db, audit, node) = open(&physical, &path, false).await;
    mutate(
        &db,
        "after-reopen",
        vec![put(SEEDED + 1, &email(SEEDED + 1), Precondition::Absent)],
    )
    .await
    .unwrap();
    expected.push((SEEDED + 1, email(SEEDED + 1)));
    assert_located(&db, &expected).await;
    assert_eq!(assert_feed_readable(&db).await, events + 1);

    // A reopen from a Raft snapshot restores the verified snapshot directory
    // and compacts the restored descriptors in its publication.
    db.raft_group().snapshot().await.unwrap();
    if db.raft_group().is_local() {
        db.raft_group().local_snapshot_settled().await.unwrap();
    }
    close(db, audit, node).await;
    let (db, audit, node) = open(&physical, &path, false).await;
    assert_located(&db, &expected).await;
    mutate(
        &db,
        "after-snapshot",
        vec![Mutation::Patch {
            collection: "accounts".into(),
            id: id(2),
            patch: json!({"email": "moved@example.test"}),
            expected: Precondition::Any,
        }],
    )
    .await
    .unwrap();
    expected.iter_mut().find(|(i, _)| *i == 2).unwrap().1 = "moved@example.test".into();
    assert_located(&db, &expected).await;
    assert!(assert_feed_readable(&db).await > 0);
    close(db, audit, node).await;
}
