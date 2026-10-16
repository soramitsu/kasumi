//! A committed strict read audit must apply with capacity admitted before its
//! proposal. Concurrent readers may exhaust ordinary admission after that point;
//! they can refuse new requests but must never fail the committed entry and
//! close the tenant.
mod common;

use kasumi_engine::admission::{AdmissionConfig, NodeAdmission, Reservation};
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

const TENANT: &str = "audited";
// Installed Raft/archive protection that ordinary Operation charges cannot spend.
const PROTECTED: u64 = kasumi_engine::test_utils::NATIVE_RAFT_HEADROOM_BYTES;
// The installed kasumid value: retained source and cache charges keep it free.
const CACHE_WORK_RESERVE: u64 = 64 << 20;

fn context(request_id: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: TENANT.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: request_id.into(),
    }
}

fn snapshot() -> ReadSnapshotRequest {
    ReadSnapshotRequest {
        documents: ["a", "b"]
            .into_iter()
            .map(|id| DocumentKey {
                collection: "docs".into(),
                id: id.into(),
            })
            .collect(),
        queries: Vec::new(),
        time_bounds: None,
    }
}

fn put(key: &str, id: &str) -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: key.into(),
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"id": id, "key": key}),
            expected: Precondition::Any,
        }],
    }
}

fn read_audited(database: &kasumi_engine::Database, request_id: &str) -> bool {
    database
        .engine()
        .generation()
        .unwrap()
        .state
        .audits
        .iter()
        .any(|event| {
            event.action == "read"
                && event.outcome == "authorized_release"
                && event.request_id == request_id
                && event.collection.as_deref() == Some("docs")
        })
}

struct Fixture {
    database: Arc<kasumi_engine::Database>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    admission: Arc<NodeAdmission>,
    _physical: common::PhysicalFixture,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn open() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical = common::PhysicalFixture::new(
            &directory.path().join("node.kv"),
            kasumi_engine::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
                max_inflight_bytes: Some(2 * PROTECTED + (256 << 20)),
                cache_work_reserve_bytes: Some(CACHE_WORK_RESERVE),
                cache_work_reserve_slots: Some(64),
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
            TENANT.into(),
            Arc::new(LocalKeyProvider::new([83; 32])),
        )
        .await
        .unwrap();
        let database = kasumi_engine::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
                store,
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: context("owner").scopes,
                }],
                strict_read_audit: true,
            },
            Limits::default(),
            audit.clone(),
        )
        .await
        .unwrap();
        // Production standalone owners install this native escrow and the
        // ordinary-operation protection before replay; fixtures opt in.
        kasumi_engine::test_utils::install_fixture_native_maintenance(&database, &admission)
            .unwrap();
        database
            .administer(
                context("schema"),
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
        for id in ["a", "b"] {
            database.mutate(context("seed"), put(id, id)).await.unwrap();
        }
        Self {
            database,
            audit,
            admission,
            _physical: physical,
            _directory: directory,
        }
    }

    /// Hold every byte ordinary admission may still spend, except `keep`, the
    /// way concurrent in-flight readers do. Ordinary work can still use `keep`;
    /// retained source charges must also leave the cache-work reserve free.
    fn exhaust_ordinary_capacity(admission: &Arc<NodeAdmission>, keep: u64) -> Reservation {
        let max = admission.policy().max_inflight_bytes.unwrap();
        let free = max - admission.snapshot().reserved_bytes;
        admission
            .reserve(free.checked_sub(PROTECTED + keep).unwrap(), None)
            .unwrap()
    }

    async fn finish(self) {
        assert_eq!(self.database.serving_failure_class(), None);
        self.database
            .mutate(context("after"), put("after", "a"))
            .await
            .unwrap();
        self.database
            .read_snapshot(&context("after-read"), snapshot())
            .await
            .unwrap();
        assert!(read_audited(&self.database, "after-read"));
        self.database.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_strict_read_audit_spends_capacity_admitted_before_its_proposal() {
    let fixture = Fixture::open().await;
    // Concurrent readers take all ordinary capacity after this read's audit was
    // admitted and proposed, immediately before the committed entry applies.
    let window = Arc::new(Mutex::new(None));
    let held = window.clone();
    let admission = fixture.admission.clone();
    fixture
        .database
        .raft_group()
        .fixture_local_before_apply(Box::new(move || {
            *held.lock().unwrap() = Some(Fixture::exhaust_ordinary_capacity(&admission, 0));
        }))
        .unwrap();
    let outcome = fixture
        .database
        .read_snapshot(&context("pinned-read"), snapshot())
        .await
        .map(|response| response.revision);
    assert!(
        window.lock().unwrap().is_some(),
        "the strict read's audit entry was not applied through the local writer"
    );
    // The committed audit applied durably and the tenant keeps serving.
    assert_eq!(fixture.database.serving_failure_class(), None);
    assert!(read_audited(&fixture.database, "pinned-read"));
    assert!(outcome.is_ok(), "strict read failed: {outcome:?}");
    drop(window.lock().unwrap().take());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_pinned_strict_reads_refuse_before_proposal_and_keep_the_tenant() {
    let fixture = Fixture::open().await;
    // Pinned concurrent readers leave room for one strict read and its audit
    // proposal (about 67 MiB with default limits). After those charges, less
    // than the cache-work reserve remains for the committed entry's sources.
    let held = Fixture::exhaust_ordinary_capacity(&fixture.admission, 100 << 20);
    let in_flight = Arc::new(tokio::sync::Semaphore::new(3));
    let mut reads = tokio::task::JoinSet::new();
    for number in 0..24 {
        let permit = in_flight.clone().acquire_owned().await.unwrap();
        let database = fixture.database.clone();
        reads.spawn(async move {
            let outcome = database
                .read_snapshot(&context(&format!("concurrent-{number}")), snapshot())
                .await;
            drop(permit);
            // Keep each released response pinned until every reader finishes.
            outcome.map_err(|error| error.code)
        });
    }
    let mut pinned = Vec::new();
    while let Some(outcome) = reads.join_next().await {
        match outcome.unwrap() {
            Ok(response) => pinned.push(response),
            Err(code) => assert!(
                matches!(
                    code,
                    ErrorCode::ResourceExhausted | ErrorCode::AuditUnavailable
                ),
                "strict read failed with {code:?}"
            ),
        }
        assert_eq!(fixture.database.serving_failure_class(), None);
    }
    drop(pinned);
    drop(held);
    fixture.finish().await;
}
