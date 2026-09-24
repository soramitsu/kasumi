#![cfg(feature = "test-utils")]

mod common;

use kasumi_clock::{EpochClock, WallClock};
use kasumi_engine::{
    Database, SecurityAudit, admission::NodeAdmission, open_fixture_with_epoch_clock,
};
use kasumi_store::{
    NodeStore, StorageAccess, TenantStore,
    test_utils::{LocalKeyProvider, ManualClock, initialize_custody_fixture},
};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

const EPOCH_MS: u64 = 1_700_000_000_000;
struct Wall;
impl WallClock for Wall {
    fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(EPOCH_MS)
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        }],
        strict_read_audit: false,
    }
}
fn context(database: &Database, clock: &EpochClock) -> RequestContext {
    let observation = clock.observe().unwrap();
    RequestContext {
        authorization: RequestAuthorization::from_verified_credential(
            observation.utc_ms() + 60_000,
            &observation,
            CredentialResource::Database {
                incarnation: database
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .incarnation
                    .parse()
                    .unwrap(),
            },
        )
        .unwrap(),
        tenant: "clock-fixture".into(),
        principal: "owner".into(),
        scopes: policy().grants[0].actions.clone(),
        request_id: "clock-fixture".into(),
    }
}
async fn audit(node: Arc<NodeStore>, admission: Arc<NodeAdmission>) -> Arc<SecurityAudit> {
    SecurityAudit::initialize(
        TenantStore::initialize_catalog_fixture(
            node,
            kasumi_engine::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([201; 32])),
        )
        .await
        .unwrap(),
        AuditRetentionBudget::default(),
        admission,
    )
    .unwrap()
}
fn batch(version: u64) -> MutationBatch {
    MutationBatch {
        idempotency_key: "original-command".into(),
        read_set: vec![],
        operations: (0..3)
            .map(|id| Mutation::Put {
                collection: "docs".into(),
                id: id.to_string(),
                body: json!({"version": version}),
                expected: Precondition::Any,
            })
            .collect(),
    }
}
fn query() -> QueryRequest {
    serde_json::from_value(json!({"collection":"docs", "allow_scan":true, "limit":1})).unwrap()
}

#[tokio::test]
async fn one_epoch_expires_leases_and_credentials_but_preserves_permanent_command_identity() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let admission = physical.storage.admission.clone();
    let audit = audit(node.clone(), admission.clone()).await;
    let elapsed = Arc::new(ManualClock::new());
    let epoch = Arc::new(EpochClock::new(elapsed.clone(), Arc::new(Wall)).unwrap());
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "clock-fixture".into(),
        Arc::new(LocalKeyProvider::new([202; 32])),
    )
    .await
    .unwrap();
    let database = open_fixture_with_epoch_clock(
        initialize_custody_fixture(store, Arc::new(LocalKeyProvider::new([203; 32])))
            .await
            .unwrap(),
        policy(),
        Limits::default(),
        audit.clone(),
        admission,
        epoch.clone(),
    )
    .await
    .unwrap();
    let original = context(&database, &epoch);
    database
        .administer(
            original.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
            }),
        )
        .await
        .unwrap();
    let receipt = database.mutate(original.clone(), batch(1)).await.unwrap();
    assert_eq!(
        database
            .operation_receipt(&original, "original-command")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    let first = database.query(&original, query()).await.unwrap();
    let mut next = query();
    next.cursor = Some(first.cursor.unwrap());
    let lease = database
        .open_snapshot_lease(&original, OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let page = ReadSnapshotPage {
        lease_id: lease.lease_id,
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "0".into(),
        }],
    };
    let original_release = database.response_fence(&original).unwrap();

    elapsed.advance(Duration::from_millis(59_999));
    original.authorization.check_live().unwrap();
    database
        .read_snapshot_page(&original, page.clone())
        .await
        .unwrap();
    original_release.check().unwrap();
    elapsed.advance(Duration::from_millis(1));
    let renewed = context(&database, &epoch);
    assert_eq!(
        original.authorization.check_live().unwrap_err().code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        original_release.check().unwrap_err().code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        database
            .mutate(original.clone(), batch(1))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        database.query(&renewed, next).await.unwrap_err().code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        database
            .read_snapshot_page(&renewed, page)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        database
            .operation_receipt(&renewed, "original-command")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );

    elapsed.advance(Duration::from_millis(86_400_001 - 60_000));
    assert_eq!(epoch.now_ms().unwrap(), EPOCH_MS + 86_400_001);
    let fresh = context(&database, &epoch);
    assert_eq!(
        renewed.authorization.check_live().unwrap_err().code,
        ErrorCode::Unauthorized
    );
    // Credentials and leases expire; permanent command identity does not.
    let stored = database
        .operation_receipt(&fresh, "original-command")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.outcome, Ok(receipt.clone()));
    assert_eq!(stored.request_digest, batch(1).digest().unwrap());
    assert_eq!(
        database.mutate(fresh.clone(), batch(1)).await.unwrap(),
        receipt
    );
    assert_eq!(
        database
            .mutate(fresh.clone(), batch(2))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        database.get(&fresh, "docs", "0").await.unwrap().body["version"],
        1
    );
    let mut next_command = batch(2);
    next_command.idempotency_key = "next-command".into();
    let replacement = database.mutate(fresh.clone(), next_command).await.unwrap();
    assert!(replacement.revision > receipt.revision);
    assert_eq!(
        database.get(&fresh, "docs", "0").await.unwrap().body["version"],
        2
    );
    assert_eq!(
        database
            .operation_receipt(&fresh, "original-command")
            .await
            .unwrap()
            .unwrap()
            .outcome,
        Ok(receipt)
    );
    assert_eq!(
        original.authorization.check_live().unwrap_err().code,
        ErrorCode::Unauthorized
    );
    drop(original_release);
    database.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn fixture_epoch_rejects_production_storage_before_bootstrap() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let admission = physical.storage.admission.clone();
    let audit = audit(node.clone(), admission.clone()).await;
    let epoch = Arc::new(EpochClock::new(Arc::new(ManualClock::new()), Arc::new(Wall)).unwrap());
    let store = TenantStore::initialize_catalog_fixture_with_access(
        node,
        "clock-fixture".into(),
        Arc::new(LocalKeyProvider::new([204; 32])),
        StorageAccess::standalone(uuid::Uuid::new_v4(), "clock-fixture", uuid::Uuid::new_v4())
            .unwrap(),
    )
    .await
    .unwrap();
    let stores =
        initialize_custody_fixture(store.clone(), Arc::new(LocalKeyProvider::new([205; 32])))
            .await
            .unwrap();
    let result = open_fixture_with_epoch_clock(
        stores.clone(),
        policy(),
        Limits::default(),
        audit.clone(),
        admission.clone(),
        epoch.clone(),
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("cannot open production storage")
    );
    assert!(store.get("engine.deployment", b"mode").unwrap().is_none());
    assert!(
        store
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    assert!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
    );
    store.shutdown().await.unwrap();
    stores.custody().store().shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn fixture_epoch_rejects_a_different_audit_facade_before_bootstrap() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&directory.path().join("node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let admission = physical.storage.admission.clone();
    let audit = audit(node.clone(), admission).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "clock-fixture".into(),
        Arc::new(LocalKeyProvider::new([206; 32])),
    )
    .await
    .unwrap();
    let stores =
        initialize_custody_fixture(store.clone(), Arc::new(LocalKeyProvider::new([207; 32])))
            .await
            .unwrap();
    let epoch = Arc::new(EpochClock::new(Arc::new(ManualClock::new()), Arc::new(Wall)).unwrap());
    let result = open_fixture_with_epoch_clock(
        stores.clone(),
        policy(),
        Limits::default(),
        audit.clone(),
        NodeAdmission::from_memory(physical.storage.admission.memory().clone()).unwrap(),
        epoch,
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("node governors differ")
    );
    assert!(store.get("engine.deployment", b"mode").unwrap().is_none());
    assert!(
        store
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    assert!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
    );
    store.shutdown().await.unwrap();
    stores.custody().store().shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}
