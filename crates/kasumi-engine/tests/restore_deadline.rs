mod common;
use kasumi_engine::{RestoreSource, open_local};
use kasumi_store::{BackupDestination, NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct PendingSource {
    reads: AtomicUsize,
    entered: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl BackupDestination for PendingSource {
    async fn session_get(
        &self,
        _session: uuid::Uuid,
        _slot: kasumi_store::BackupSessionSlot,
        _limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending().await
    }

    async fn put(&self, _id: uuid::Uuid, _bytes: Vec<u8>) -> anyhow::Result<()> {
        anyhow::bail!("read-only test destination")
    }
    async fn get(&self, _id: uuid::Uuid, _limit: usize) -> anyhow::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending().await
    }
}
fn context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: tenant.into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "restore-deadline".into(),
    }
}

#[tokio::test]
async fn restore_deadline_bounds_source_io_and_gate_queue_without_blocking_another_tenant() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeStore::open(root.path().join("node.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let keys = Arc::new(LocalKeyProvider::new([0xA6; 32]));
    let first = TenantStore::open_fixture(node.clone(), "first".into(), keys.clone())
        .await
        .unwrap();
    let queued = TenantStore::open_fixture(node.clone(), "queued".into(), keys.clone())
        .await
        .unwrap();
    let other = TenantStore::open_fixture(node, "other".into(), keys.clone())
        .await
        .unwrap();
    let pending = Arc::new(PendingSource {
        reads: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
    });
    let task = tokio::spawn({
        let pending = pending.clone();
        let keys = keys.clone();
        let audit = audit.clone();
        let first = first.clone();
        async move {
            kasumi_engine::restore_local(
                &RestoreSource {
                    destination_alias: "backup".into(),
                    destination: pending,
                    keys,
                    timeout_ms: 400,
                },
                kasumi_store::test_utils::with_custody(
                    first,
                    std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
                )
                .await
                .unwrap(),
                common::local_restore_request(
                    context("first"),
                    &common::unavailable_checkpoint("first", uuid::Uuid::new_v4()),
                    uuid::Uuid::new_v4(),
                ),
                kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
                audit,
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), pending.entered.notified())
        .await
        .unwrap();
    let queued_error = kasumi_engine::restore_local(
        &RestoreSource {
            destination_alias: "backup".into(),
            destination: pending.clone(),
            keys,
            timeout_ms: 30,
        },
        kasumi_store::test_utils::with_custody(
            queued.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        common::local_restore_request(
            context("queued"),
            &common::unavailable_checkpoint("queued", uuid::Uuid::new_v4()),
            uuid::Uuid::new_v4(),
        ),
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        audit.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(queued_error.to_string().contains("deadline"));
    assert_eq!(
        pending.reads.load(Ordering::SeqCst),
        1,
        "queue timeout must occur before source I/O"
    );
    let other_open = tokio::spawn({
        let audit = audit.clone();
        async move {
            open_local(
                kasumi_store::test_utils::with_custody(
                    other,
                    std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
                )
                .await
                .unwrap(),
                Policy {
                    grants: vec![Grant {
                        principal: "owner".into(),
                        collection: None,
                        actions: context("other").scopes,
                    }],
                    strict_read_audit: false,
                },
                Limits::default(),
                audit,
            )
            .await
        }
    });
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .err()
        .unwrap();
    assert!(error.to_string().contains("deadline"));
    for target in [first, queued] {
        assert!(
            target
                .get("engine.bootstrap", b"manifest")
                .unwrap()
                .is_none()
        );
        assert!(
            kasumi_store::test_utils::with_custody(
                target.clone(),
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap()
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
        );
    }
    let database = tokio::time::timeout(Duration::from_secs(2), other_open)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    database.shutdown().await.unwrap();
    audit.shutdown().await;
}
