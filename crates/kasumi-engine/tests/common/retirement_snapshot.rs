//! Actual source backup -> retirement -> closed rotation -> snapshot-only catchup.
//! The learner can recover closed metadata; it cannot manufacture quorum proof.
use super::*;
use kasumi_raft::{
    Config, ControlLog, CustodyRaftGroup, InProcessRouter, RaftGroup, StateMachineBackend,
};
use kasumi_store::{CustodyStore, TenantStorageSet, WriteOp};
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
    let reference = request.reference().unwrap();
    let warm = source.db.retired_custody().unwrap();
    assert_eq!(
        warm.execute(
            context(),
            CustodyRequest {
                retirement: reference.clone(),
                command_id: "snapshot-rotate".into(),
                expected_policy_epoch: 1,
                not_after_ms: u64::MAX,
                action: CustodyAction::ReplaceAdministrators(BTreeSet::from([
                    "new-custodian".into()
                ])),
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::UnknownOutcome
    );
    drop(warm);
    let source_store = source.db.detach_retired_custody().await.unwrap();
    let group = format!(
        "{}/{}",
        context().tenant,
        request.expected_source_incarnation
    );
    let router = Arc::new(InProcessRouter::default());
    // Sharing the process memory core does not grant a different runtime facade
    // ownership of this security ledger or permission to start a custody group.
    let wrong_facade = kasumi_engine::admission::NodeAdmission::from_memory(
        source.audit.admission().memory().clone(),
    )
    .unwrap();
    let before_rejected_startup = wrong_facade.snapshot().reserved_bytes;
    let rejected = kasumi_engine::RetiredCustody::open_replicated(
        source_store.clone(),
        1,
        group.clone(),
        router.clone(),
        kasumi_raft::RaftGroupConfig::default(),
        wrong_facade.clone(),
        source.audit.clone(),
    )
    .await;
    assert!(
        rejected
            .err()
            .unwrap()
            .to_string()
            .contains("node governors differ")
    );
    assert_eq!(
        wrong_facade.snapshot().reserved_bytes,
        before_rejected_startup
    );
    drop(wrong_facade);
    let closed = kasumi_engine::RetiredCustody::open_replicated(
        source_store.clone(),
        1,
        group.clone(),
        router.clone(),
        kasumi_raft::RaftGroupConfig::default(),
        source.audit.admission().clone(),
        source.audit.clone(),
    )
    .await
    .unwrap();
    let raft = closed.raft_group().unwrap();
    router.register(group.clone(), 1, raft.raft().clone());
    raft.raft()
        .wait(Some(Duration::from_secs(10)))
        .current_leader(1, "closed source")
        .await
        .unwrap();
    let custodian = RequestContext {
        principal: "new-custodian".into(),
        ..context()
    };
    assert_eq!(
        closed
            .verify_retirement_receipt(custodian, &reference)
            .await
            .unwrap()
            .receipt(),
        proof.receipt()
    );
    assert_eq!(
        closed
            .verify_retirement_receipt(context(), &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    // An old retained Database cannot seal the custody store after ownership moved.
    source.db.shutdown().await.unwrap();
    closed
        .raft_group()
        .unwrap()
        .linearizable_barrier()
        .await
        .unwrap();
    raft.snapshot().await.unwrap();
    let mut snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(snapshot) = raft.raft().get_snapshot().await.unwrap()
                && snapshot.meta.last_log_id.unwrap().index >= raft.view().unwrap().revision()
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    assert!(snapshot.snapshot.len() <= 2 << 20);
    let mut closed_bytes = Vec::new();
    snapshot
        .snapshot
        .read_to_end(&mut closed_bytes)
        .await
        .unwrap();
    snapshot.snapshot.rewind().await.unwrap();
    assert!(
        !closed_bytes
            .windows(b"private-journal-entry".len())
            .any(|bytes| bytes == b"private-journal-entry")
    );
    let source_control = ControlLog::open(source_store.clone(), 1, group.clone()).unwrap();
    let vote = source_control.read_vote().unwrap().unwrap();
    let bootstrap_digest = source_store
        .store()
        .get("raft.meta", b"application_bootstrap_sha256")
        .unwrap()
        .unwrap();
    let source_binding = source_store.binding().digest().unwrap();
    let recipient = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = recipient.path().join("replica.redb");
    let app_provider = Arc::new(LocalKeyProvider::new([0xe2; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([0xe3; 32]));
    let domains = TenantStorageSet::initialize_catalogs_fixture(
        NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap(),
        context().tenant,
        app_provider.clone(),
        custody_provider.clone(),
    )
    .await
    .unwrap();
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
    let recipient_group = RaftGroup::open(
        2,
        group.clone(),
        domains.clone(),
        backend.clone(),
        Arc::new(InProcessRouter::default()),
        kasumi_raft::RaftGroupConfig {
            raft: Config::default(),
            limits: kasumi_raft::RaftLimits::default(),
        },
        kasumi_raft::SnapshotBufferOwner::fixture(),
    )
    .await
    .unwrap();
    recipient_group
        .raft()
        .install_full_snapshot(vote, snapshot)
        .await
        .unwrap();
    assert!(
        backend.generation().is_err(),
        "closed snapshot must evict application state before publication"
    );
    assert!(domains.application().scan("raft.log").unwrap().is_empty());
    assert!(
        domains
            .application()
            .scan("raft.snapshot")
            .unwrap()
            .is_empty(),
        "closed snapshot cannot publish application chunks"
    );
    recipient_group.shutdown().await.unwrap();
    app_provider.revoke();
    assert!(domains.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    domains.shutdown().await.unwrap();
    drop(recipient_group);
    drop(backend);
    drop(domains);
    // Only the independently keyed domain is opened after the encrypted restart.
    let custody = CustodyStore::open(
        NodeStore::open_existing_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap(),
        context().tenant,
        custody_provider,
    )
    .await
    .unwrap();
    let learner = CustodyRaftGroup::open(
        2,
        group.clone(),
        custody.clone(),
        Arc::new(InProcessRouter::default()),
        kasumi_raft::RaftGroupConfig::default(),
        kasumi_raft::SnapshotBufferOwner::fixture(),
    )
    .await
    .unwrap();
    let view = learner.view().unwrap();
    assert_eq!(view.retirement(), proof.receipt());
    assert_eq!(view.policy_epoch(), 2);
    assert_eq!(
        view.administrators(),
        &BTreeSet::from(["new-custodian".into()])
    );
    assert_eq!(app_provider.probe_count(), probes);
    assert!(
        learner.linearizable_barrier().await.is_err(),
        "snapshot-only learner cannot claim current source quorum"
    );
    let control = ControlLog::open(custody.clone(), 2, group).unwrap();
    assert!(control.recover_retired().unwrap());
    learner.shutdown().await.unwrap();
    custody.store().shutdown().await.unwrap();
    closed.shutdown().await.unwrap();
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
    let mut captured = Vec::new();
    let retirement =
        StateMachineBackend::snapshot(source.db.engine().as_ref(), &mut captured).unwrap();
    assert!(retirement.is_none());
    assert!(
        StateMachineBackend::validate_snapshot(
            source.db.engine().as_ref(),
            &mut captured.as_slice()
        )
        .unwrap()
        .is_none()
    );
    source.close().await;
}
