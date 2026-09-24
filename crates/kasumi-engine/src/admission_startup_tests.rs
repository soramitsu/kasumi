//! Exercise the facade census through a real, cancelled Raft constructor.
use super::*;
use kasumi_raft::{RaftGroup, SnapshotBufferOwner, startup_test_utils::LocalStartupGate};
use kasumi_types::drain::DrainCompletion;
use std::{future::Future, task::Poll};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct OriginalStartupFailure(u64);
impl std::fmt::Display for OriginalStartupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node census startup failure {}", self.0)
    }
}
impl std::error::Error for OriginalStartupFailure {}

struct Backend;
impl kasumi_raft::StateMachineBackend for Backend {
    fn close_application(&self) {}
    fn apply(
        &self,
        _: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
    ) -> anyhow::Result<kasumi_raft::AppliedResponse> {
        Ok(kasumi_raft::AppliedResponse::application(bytes.to_vec()))
    }
    fn capture_snapshot(&self) -> anyhow::Result<kasumi_raft::CapturedSnapshot> {
        Ok(kasumi_raft::CapturedSnapshot::new(None, |_| Ok(())))
    }
    fn validate_snapshot(
        &self,
        _: &mut dyn std::io::Read,
    ) -> anyhow::Result<Option<kasumi_raft::RetiredSnapshotState>> {
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _: &kasumi_raft::SnapshotRestoreContext,
        _: &mut dyn std::io::Read,
    ) -> anyhow::Result<Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>> {
        anyhow::bail!("empty startup fixture has no snapshot")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_local_startup_and_node_census_keep_actual_group_and_charges_until_join()
-> anyhow::Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent_config, scratch_config) =
        crate::test_utils::fixture_disk_configs(directory.path())?;
    let metadata_bytes =
        crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)?;
    // The original fixed 2 GiB source resolves Default to a 256 MiB total.
    // Add only the new physical metadata; do not resolve against host RAM.
    let config = crate::admission::AdmissionConfig {
        max_inflight_bytes: Some(
            (256_u64 << 20)
                .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                    &persistent_config,
                    &scratch_config,
                )?)
                .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
        ),
        ..Default::default()
    };
    let core_base = MemoryCore::required_bookkeeping_bytes(&config)?;
    let facade_bytes = NodeAdmission::required_bookkeeping_bytes(&config)? - core_base;
    let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
    let storage = crate::test_utils::FixtureStorage::with_admission(
        &persistent_config,
        &scratch_config,
        admission.clone(),
    )?;
    let core = admission.memory().clone();
    let owner = admission.snapshot_buffer_owner()?;
    let owner_bytes = SnapshotBufferOwner::required_bytes(kasumi_raft::SNAPSHOT_BUFFER_SLOTS)?;
    let owner_weak = Arc::downgrade(&owner);
    let gate = LocalStartupGate::install(&owner, OriginalStartupFailure(211).into())?;
    let stores = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
        storage.create_new(
            directory
                .path()
                .join("persistent/cancelled-node-startup.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?,
        "cancelled-startup".into(),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([19; 32])),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await?;
    // The live native KV index is charged to this same admission owner until
    // the store drains. Keep that installed charge in the startup baseline.
    let installed = admission.snapshot();
    let mut startup = Box::pin(RaftGroup::local(
        1,
        "cancelled-startup".into(),
        stores.clone(),
        Arc::new(Backend),
        owner.clone(),
    ));
    tokio::select! {
        result = &mut startup => panic!("startup finished before fixture gate: {}", result.is_ok()),
        result = tokio::time::timeout(WAIT, gate.entered()) => result?,
    }
    assert!(gate.claim_is_live());
    assert!(gate.router_is_alive());
    drop(startup);
    drop(owner);
    assert!(
        owner_weak.upgrade().is_some(),
        "abandoned startup lost global custody"
    );
    let mut census = Box::pin(admission.drain_snapshot_startups());
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(census.as_mut().poll(cx))).await;
    assert!(first_poll.is_pending());
    drop(census);
    assert!(
        admission.snapshot_buffer_owner().is_err(),
        "cancelled census reopened admission"
    );
    let pending = admission.snapshot();
    assert_eq!(pending.bookkeeping_bytes, installed.bookkeeping_bytes);
    assert_eq!(pending.reserved_bytes, installed.reserved_bytes);
    assert_eq!(
        pending.resident_reserved_bytes,
        installed.resident_reserved_bytes
    );
    assert_eq!(pending.inflight_operations, 0);
    assert!(gate.claim_is_live());
    assert!(owner_weak.upgrade().is_some());
    gate.release();
    let failure = tokio::time::timeout(WAIT, admission.drain_snapshot_startups())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let original = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<OriginalStartupFailure>()
                .is_some()
        })
        .expect("actual initializer failure retained")
        .clone();
    assert_eq!(
        original
            .error()
            .downcast_ref::<OriginalStartupFailure>()
            .unwrap()
            .0,
        211
    );
    assert!(!gate.claim_is_live());
    assert!(!gate.router_is_alive());
    let raft = gate.raft().expect("actual OpenRaft observer captured");
    assert!(raft.metrics().borrow().running_state.is_err());
    tokio::time::timeout(WAIT, raft.shutdown()).await??;
    drop(raft);
    drop(gate);
    assert!(
        owner_weak.upgrade().is_none(),
        "drained owner charge still retained"
    );
    let completed = admission.snapshot();
    // The completed error report keeps its inventory envelope; only the actual
    // child's resident owner charge is released at successful census completion.
    assert_eq!(completed.bookkeeping_bytes, installed.bookkeeping_bytes);
    assert_eq!(
        completed.reserved_bytes,
        installed.reserved_bytes - owner_bytes
    );
    assert_eq!(
        completed.resident_reserved_bytes,
        installed.resident_reserved_bytes - owner_bytes
    );
    for _ in 0..2 {
        let repeated = admission.drain_snapshot_startups().await.unwrap_err();
        assert_eq!(repeated.completion(), DrainCompletion::Complete);
        assert!(
            repeated
                .issues()
                .iter()
                .any(|issue| Arc::ptr_eq(issue, &original))
        );
        assert_eq!(
            admission.snapshot().reserved_bytes,
            installed.reserved_bytes - owner_bytes
        );
    }
    let facade_weak = Arc::downgrade(&admission);
    drop(failure);
    drop(original);
    drop(storage);
    let retained_before_facade_drop = core.snapshot().reserved_bytes;
    drop(admission);
    assert!(facade_weak.upgrade().is_none());
    // The live store still owns its resident native index while waiting for
    // the replacement group. Dropping the facade releases only its fixed
    // bookkeeping; final shutdown below releases the exact storage delta.
    assert_eq!(
        core.snapshot().reserved_bytes,
        retained_before_facade_drop - facade_bytes
    );
    // The old facade remains sealed; a fresh facade shares accounting and a
    // real group can reopen the exact same storage only after actual join.
    let replacement = NodeAdmission::from_memory(core.clone())?;
    let reopened = tokio::time::timeout(
        WAIT,
        RaftGroup::local(
            1,
            "cancelled-startup".into(),
            stores,
            Arc::new(Backend),
            replacement.snapshot_buffer_owner()?,
        ),
    )
    .await??;
    tokio::time::timeout(WAIT, reopened.shutdown()).await??;
    drop(reopened);
    replacement.drain_snapshot_startups().await?;
    drop(replacement);
    assert_eq!(core.snapshot().reserved_bytes, core_base + metadata_bytes);
    Ok(())
}
