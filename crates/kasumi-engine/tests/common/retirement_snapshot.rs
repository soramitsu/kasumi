//! Actual source backup -> retirement -> snapshot-only replica catch-up. The
//! custody-only reader remains recovery input and never becomes an Admin proof.
use super::*;
use kasumi_raft::{Config, ControlLog, InProcessRouter, RaftGroup, StateMachineBackend};
use kasumi_store::{CustodyStore, TenantStorageSet, WriteOp};
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_retired_snapshot_only_replica_preserves_rotated_custody_after_encrypted_restart() {
    let source = Fixture::new().await;
    for index in 0..32 {
        source
            .write(&format!("private-journal-entry-{index}"))
            .await;
    }
    let request = source.request("snapshot-custody").await;
    let proof = source
        .db
        .retire_source(context(), request.clone())
        .await
        .unwrap();
    source
        .db
        .administer(
            context(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "new-custodian".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let expected = StateMachineBackend::snapshot(source.db.engine().as_ref())
        .unwrap()
        .retirement
        .unwrap();
    assert_eq!(
        expected.administrators,
        BTreeSet::from(["new-custodian".into()])
    );
    let base = expected.revision_base;
    let retirement_index = proof.revision() - base;
    source.db.raft_group().snapshot().await.unwrap();
    let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(snapshot) = source.db.raft_group().raft().get_snapshot().await.unwrap()
                && snapshot.meta.last_log_id.unwrap().index + base >= expected.revision
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let group = format!(
        "{}/{}",
        context().tenant,
        request.expected_source_incarnation
    );
    let source_control = ControlLog::open(
        source.db.raft_group().storage_domains().custody().clone(),
        1,
        group.clone(),
    )
    .unwrap();
    let vote = source_control.read_vote().unwrap().unwrap();
    let source_binding = source
        .db
        .raft_group()
        .storage_domains()
        .custody()
        .binding()
        .digest()
        .unwrap();
    let bootstrap_digest = source
        .db
        .raft_group()
        .storage_domains()
        .custody()
        .store()
        .get("raft.meta", b"application_bootstrap_sha256")
        .unwrap()
        .unwrap();
    let recipient = tempfile::tempdir().unwrap();
    let path = recipient.path().join("replica.redb");
    let app_provider = Arc::new(LocalKeyProvider::new([0xe2; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([0xe3; 32]));
    let domains = TenantStorageSet::open(
        NodeStore::open(&path).unwrap(),
        context().tenant,
        app_provider.clone(),
        custody_provider.clone(),
    )
    .await
    .unwrap();
    // Installed bootstrap identity comes from the trusted replica installer. No
    // municipality payload or retirement log is copied by this fixture setup.
    domains
        .custody()
        .store()
        .write_batch(&[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            bootstrap_digest,
        )])
        .unwrap();
    assert_ne!(
        source_binding,
        domains.custody().binding().digest().unwrap()
    );
    let backend = Arc::new(
        kasumi_engine::TenantEngine::new(
            context().tenant,
            request.expected_source_incarnation.clone(),
            policy(),
            Limits::default(),
        )
        .unwrap(),
    );
    let raft = RaftGroup::open(
        2,
        group.clone(),
        domains.clone(),
        backend.clone(),
        Arc::new(InProcessRouter::default()),
        Config::default(),
    )
    .await
    .unwrap();
    raft.raft()
        .install_full_snapshot(vote, snapshot)
        .await
        .unwrap();
    assert_eq!(
        StateMachineBackend::snapshot(backend.as_ref())
            .unwrap()
            .retirement,
        Some(expected.clone())
    );
    assert!(backend.generation().unwrap().state.retired);
    assert!(
        domains.application().scan("raft.log").unwrap().is_empty(),
        "replica received snapshot only"
    );
    let control = ControlLog::open(domains.custody().clone(), 2, group.clone()).unwrap();
    assert_eq!(
        control
            .retirement_seed(retirement_index)
            .unwrap()
            .unwrap()
            .seed()
            .request(),
        &request
    );
    drop(control);
    raft.shutdown().await.unwrap();
    domains.application().shutdown().await;
    domains.custody().store().shutdown().await;
    drop(raft);
    drop(backend);
    drop(domains);
    // Normal encrypted replica restart validates the image and capsule together.
    let domains = TenantStorageSet::open(
        NodeStore::open(&path).unwrap(),
        context().tenant,
        app_provider.clone(),
        custody_provider.clone(),
    )
    .await
    .unwrap();
    let backend = Arc::new(
        kasumi_engine::TenantEngine::new(
            context().tenant,
            request.expected_source_incarnation.clone(),
            policy(),
            Limits::default(),
        )
        .unwrap(),
    );
    let raft = RaftGroup::open(
        2,
        group.clone(),
        domains.clone(),
        backend.clone(),
        Arc::new(InProcessRouter::default()),
        Config::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        StateMachineBackend::snapshot(backend.as_ref())
            .unwrap()
            .retirement,
        Some(expected)
    );
    raft.shutdown().await.unwrap();
    drop(raft);
    // Reopening randomizes persistent map serialization order. Recapture at the
    // same applied position must reuse the fully verified persisted image.
    let mut machine = kasumi_raft::StateMachine::open(domains.clone(), backend.clone())
        .await
        .unwrap();
    let before = machine.get_current_snapshot().await.unwrap().unwrap();
    let rebuilt = machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .unwrap();
    assert_eq!(rebuilt.meta, before.meta);
    assert_eq!(rebuilt.snapshot.as_bytes(), before.snapshot.as_bytes());
    drop(machine);
    app_provider.revoke();
    assert!(domains.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    domains.application().shutdown().await;
    domains.custody().store().shutdown().await;
    drop(backend);
    drop(domains);
    // Closed metadata recovery never opens an application provider or decoder.
    let custody = CustodyStore::open(
        NodeStore::open(&path).unwrap(),
        context().tenant,
        custody_provider,
    )
    .await
    .unwrap();
    let control = ControlLog::open(custody.clone(), 2, group).unwrap();
    assert_eq!(
        control
            .retirement_seed(retirement_index)
            .unwrap()
            .unwrap()
            .seed()
            .request(),
        &request
    );
    assert_eq!(app_provider.probe_count(), probes);
    custody.store().shutdown().await;
    source.close().await;
}

#[tokio::test]
async fn actual_stopped_retirement_snapshot_has_no_retired_custody_marker() {
    let source = Fixture::new().await;
    let request = source.request("stopped-snapshot").await;
    let resolution = source
        .db
        .abort_retirement(context(), request)
        .await
        .unwrap();
    assert!(matches!(
        resolution,
        kasumi_engine::VerifiedRetirementResolution::Stopped(_)
    ));
    let captured = StateMachineBackend::snapshot(source.db.engine().as_ref()).unwrap();
    assert!(captured.retirement.is_none());
    assert!(
        StateMachineBackend::validate_snapshot(source.db.engine().as_ref(), &captured.data)
            .unwrap()
            .is_none()
    );
    source.close().await;
}
