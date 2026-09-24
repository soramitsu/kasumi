#[allow(dead_code)]
mod common;
use kasumi_engine::test_utils::open_fixture;
use kasumi_engine::{Database, SECURITY_TENANT, SecurityAudit};
use kasumi_store::{
    FilesystemBackupDestination, NodeStore, TenantStore, test_utils::LocalKeyProvider,
};
use kasumi_types::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet, future::Future, sync::Arc, task::Poll};

fn context(principal: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        // Deliberately reused: distinct denied calls each require a record.
        request_id: "reused-request-id".into(),
    }
}

async fn fixture(
    node: Arc<NodeStore>,
    provider: Arc<LocalKeyProvider>,
    audit_provider: Arc<LocalKeyProvider>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> (Arc<Database>, Arc<TenantStore>, Arc<SecurityAudit>) {
    let store = TenantStore::initialize_catalog_fixture(node.clone(), "tenant".into(), provider)
        .await
        .unwrap();
    let service =
        TenantStore::initialize_catalog_fixture(node, SECURITY_TENANT.into(), audit_provider)
            .await
            .unwrap();
    let audit = SecurityAudit::initialize(
        service,
        kasumi_types::AuditRetentionBudget::default(),
        admission,
    )
    .unwrap();
    let db = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context("owner").scopes,
            }],
            strict_read_audit: false,
        },
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    (db, store, audit)
}

#[tokio::test]
async fn every_embedded_request_boundary_durably_audits_denials_and_sealed_tenants() {
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = dir.path().join("node.kv");
    let physical = common::PhysicalFixture::new(&path, Default::default());
    let node = physical
        .storage
        .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let provider = Arc::new(LocalKeyProvider::new([31; 32]));
    let service_provider = Arc::new(LocalKeyProvider::new([32; 32]));
    let (db, store, audit) = fixture(
        node.clone(),
        provider,
        service_provider.clone(),
        physical.storage.admission.clone(),
    )
    .await;
    let visitor = context("visitor");
    macro_rules! denied {
        ($call:expr) => {{
            let error = $call.await.unwrap_err();
            assert_eq!(error.code, ErrorCode::Forbidden);
            assert!(error.denial_audit_attempted());
        }};
    }
    denied!(db.get(&visitor, "docs", "id"));
    denied!(db.get_shared(&visitor, "docs", "id"));
    denied!(
        db.query(
            &visitor,
            serde_json::from_value(json!({
                "collection":"docs", "filter":{"op":"eq","field":"/private","value":"query-secret"},
                "allow_scan":true
            }))
            .unwrap()
        )
    );
    denied!(db.collections(&visitor));
    denied!(db.operation_receipt(&visitor, "private-receipt-value"));
    denied!(db.mutate(
        visitor.clone(),
        MutationBatch {
            read_set: Vec::new(),
            idempotency_key: "private-receipt-value".into(),
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "id".into(),
                body: json!({"private":"document-secret"}),
                expected: Precondition::Any,
            }],
        }
    ));
    denied!(db.administer(visitor.clone(), Operation::Suspend(true)));
    denied!(db.maintenance_audit(visitor.clone(), "backup", "started", 0));
    denied!(db.complete_restore(visitor.clone()));
    let destination = Arc::new(
        FilesystemBackupDestination::new(
            dir.path().join("backups"),
            16 << 20,
            physical.storage.persistent.clone(),
        )
        .unwrap(),
    );
    denied!(db.backup(visitor.clone(), destination.as_ref(), uuid::Uuid::new_v4()));
    let mut cross_tenant = context("owner");
    cross_tenant.tenant = "other-tenant".into();
    denied!(db.get(&cross_tenant, "docs", "id"));
    store.seal();
    assert_eq!(
        db.get(&context("owner"), "docs", "id")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    let rows = audit.store().scan("security.audit").unwrap();
    assert_eq!(rows.len(), 12);
    let values: Vec<Value> = rows
        .iter()
        .map(|(_, bytes)| serde_json::from_slice(bytes).unwrap())
        .collect();
    assert_eq!(
        values
            .iter()
            .filter(|v| v["event"]["kind"] == "access_denied")
            .count(),
        11
    );
    assert_eq!(values.last().unwrap()["event"]["kind"], "tenant_sealed");
    for value in &values {
        assert_eq!(value["event"]["request_id"], "reused-request-id");
        let encoded = value.to_string();
        for secret in [
            "query-secret",
            "document-secret",
            "private-receipt-value",
            "denial_audit_attempted",
        ] {
            assert!(!encoded.contains(secret));
        }
    }
    // Audit failure cannot override the original enforced denial.
    audit.seal();
    let error = db.get(&context("owner"), "docs", "id").await.unwrap_err();
    assert_eq!(error.code, ErrorCode::Sealed);
    assert!(error.denial_audit_attempted());
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(db);
    drop(store);
    drop(audit);
    drop(node);
    let reopened = physical
        .storage
        .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let service =
        TenantStore::open_existing_fixture(reopened.clone(), SECURITY_TENANT.into(), service_provider)
            .await
            .unwrap();
    assert_eq!(service.scan("security.audit").unwrap().len(), 12);
    service.shutdown().await.unwrap();
    reopened.shutdown().await.unwrap();
}

#[test]
fn cancelled_embedded_denial_writer_is_drained_before_shutdown_and_reopen() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = dir.path().join("node.kv");
        let physical = common::PhysicalFixture::new(&path, Default::default());
        let node = physical
            .storage
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let weak = Arc::downgrade(&node);
        let service_provider = Arc::new(LocalKeyProvider::new([44; 32]));
        let (db, store, audit) = fixture(
            node.clone(),
            Arc::new(LocalKeyProvider::new([43; 32])),
            service_provider.clone(),
            physical.storage.admission.clone(),
        )
        .await;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let occupying = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            blocked.recv().unwrap();
        });
        started.await.unwrap();
        let visitor = context("visitor");
        let mut denied = Box::pin(db.get(&visitor, "docs", "id"));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(denied.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(denied);
        let mut shutdown = Box::pin(db.shutdown());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(shutdown);
        release.send(()).unwrap();
        occupying.await.unwrap();
        db.shutdown().await.unwrap();
        assert_eq!(audit.store().scan("security.audit").unwrap().len(), 1);
        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        drop(db);
        drop(store);
        drop(audit);
        drop(node);
        assert!(weak.upgrade().is_none());
        let reopened = physical
            .storage
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let service =
            TenantStore::open_existing_fixture(reopened.clone(), SECURITY_TENANT.into(), service_provider)
                .await
                .unwrap();
        assert_eq!(service.scan("security.audit").unwrap().len(), 1);
        service.shutdown().await.unwrap();
        reopened.shutdown().await.unwrap();
    });
}

#[tokio::test]
async fn standalone_restore_denials_are_audited_before_a_database_exists() {
    use kasumi_engine::{ReplicaPlacement, ReplicaRestoreConfig, prepare_replicated_restore};
    use kasumi_raft::{Config, InProcessRouter};
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let source_root = dir.path().join("source");
    kasumi_store::private_files::create_directory(&source_root).unwrap();
    let source_physical =
        common::PhysicalFixture::new(&source_root.join("source.kv"), Default::default());
    let source_node = source_physical
        .storage
        .create_new(
            source_root.join("source.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let source_key = Arc::new(LocalKeyProvider::new([51; 32]));
    let (source, source_store, source_audit) = fixture(
        source_node.clone(),
        source_key.clone(),
        Arc::new(LocalKeyProvider::new([52; 32])),
        source_physical.storage.admission.clone(),
    )
    .await;
    let destination = Arc::new(
        FilesystemBackupDestination::new(
            source_root.join("backups"),
            16 << 20,
            source_physical.storage.persistent.clone(),
        )
        .unwrap(),
    );
    let checkpoint = source
        .backup_checkpoint(context("owner"), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let backup = checkpoint.backup_id();
    let target_root = dir.path().join("target");
    kasumi_store::private_files::create_directory(&target_root).unwrap();
    let target_path = target_root.join("target.kv");
    let target_physical = common::PhysicalFixture::new(&target_path, Default::default());
    let target_node = target_physical
        .storage
        .create_new(&target_path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let target_store = TenantStore::initialize_catalog_fixture(
        target_node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([53; 32])),
    )
    .await
    .unwrap();
    let target_domains = kasumi_store::test_utils::initialize_custody_fixture(
        target_store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let service_key = Arc::new(LocalKeyProvider::new([54; 32]));
    let service_store = TenantStore::initialize_catalog_fixture(
        target_node.clone(),
        SECURITY_TENANT.into(),
        service_key.clone(),
    )
    .await
    .unwrap();
    let audit = SecurityAudit::initialize(
        service_store,
        kasumi_types::AuditRetentionBudget::default(),
        target_physical.storage.admission.clone(),
    )
    .unwrap();
    let local = kasumi_engine::restore_local(
        &kasumi_engine::RestoreSource {
            timeout_ms: 300_000,
            destination_alias: "backup".into(),
            destination: destination.clone(),
            keys: source_key.clone(),
        },
        target_domains.clone(),
        common::local_restore_request(
            context("visitor"),
            checkpoint.checkpoint(),
            uuid::Uuid::new_v4(),
        ),
        audit.admission().clone(),
        audit.clone(),
    )
    .await;
    let error = local.err().expect("unauthorized local restore rejected");
    let error = error.downcast_ref::<Error>().unwrap();
    assert_eq!(error.code, ErrorCode::Forbidden);
    assert!(error.denial_audit_attempted());
    let replica = ReplicaRestoreConfig {
        node_id: 1,
        incarnation: uuid::Uuid::new_v4(),
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    ReplicaPlacement {
                        address: format!("node-{id}"),
                        failure_domain: format!("domain-{id}"),
                    },
                )
            })
            .collect(),
        raft: Config::default(),
        admission: audit.admission().clone(),
    };
    let replicated = prepare_replicated_restore(
        &kasumi_engine::RestoreSource {
            timeout_ms: 300_000,
            destination_alias: "backup".into(),
            destination: destination.clone(),
            keys: source_key.clone(),
        },
        backup,
        target_domains.clone(),
        context("visitor"),
        replica,
        Arc::new(InProcessRouter::default()),
        audit.clone(),
    )
    .await;
    assert_eq!(
        replicated
            .err()
            .expect("unauthorized replicated restore rejected")
            .downcast_ref::<Error>()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    assert!(
        target_store
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    assert!(
        target_domains
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
    );
    target_store.seal();
    let sealed = kasumi_engine::restore_local(
        &kasumi_engine::RestoreSource {
            timeout_ms: 300_000,
            destination_alias: "backup".into(),
            destination: destination.clone(),
            keys: source_key,
        },
        target_domains.clone(),
        common::local_restore_request(
            context("owner"),
            checkpoint.checkpoint(),
            uuid::Uuid::new_v4(),
        ),
        audit.admission().clone(),
        audit.clone(),
    )
    .await;
    assert_eq!(
        sealed
            .err()
            .expect("sealed restore rejected")
            .downcast_ref::<Error>()
            .unwrap()
            .code,
        ErrorCode::Sealed
    );
    let entries = audit.store().scan("security.audit").unwrap();
    assert_eq!(entries.len(), 3);
    let last: Value = serde_json::from_slice(&entries[2].1).unwrap();
    assert_eq!(last["event"]["kind"], "tenant_sealed");
    target_domains.custody().store().shutdown().await.unwrap();
    target_store.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(target_store);
    drop(target_domains);
    drop(audit);
    drop(target_node);
    let reopened = target_physical
        .storage
        .open_existing(&target_path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let service = TenantStore::open_existing_fixture(reopened.clone(), SECURITY_TENANT.into(), service_key)
        .await
        .unwrap();
    assert_eq!(service.scan("security.audit").unwrap().len(), 3);
    service.shutdown().await.unwrap();
    reopened.shutdown().await.unwrap();
    source.shutdown().await.unwrap();
    source_audit.shutdown().await.unwrap();
    source_node.shutdown().await.unwrap();
    drop(source);
    drop(source_store);
    drop(source_audit);
    drop(source_node);
}
