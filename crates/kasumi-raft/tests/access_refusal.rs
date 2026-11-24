//! A target phase capability is time-bounded, while its Raft group keeps
//! running until the next phase replaces it. A committed entry can then meet
//! the closed access fence when it is applied. The machine must stay fenced
//! with that exact refusal, but shutdown must complete, so the replacement
//! phase can drain this owner and reopen the same physical store.
mod common;

use kasumi_raft::test_utils::FixtureResult;
use kasumi_raft::{ApplicationProposal, RaftCommand, StateMachineBackend};
use kasumi_types::drain::DrainCompletion;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const WAIT: Duration = Duration::from_secs(10);
const GROUP: &str = "access-refusal";

// A whole sealed store fails OpenRaft's own log write before any apply; the
// storage worker test covers the apply worker's `KeyAccessDenied` check.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    /// The engine's apply owner refuses with its own typed access error once
    /// the phase capability closed after the entry committed.
    TypedSealed,
    /// The same refusal under an owning context keeps full custody.
    OwningContext,
}

struct Refusing {
    inner: common::Backend,
    refusal: Refusal,
    refuse: AtomicBool,
}

impl StateMachineBackend for Refusing {
    fn close_application(&self) {
        self.inner.close_application();
    }
    fn apply_with_publisher(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        input: kasumi_raft::AppliedInput<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        if self.refuse.load(Ordering::Acquire) {
            let sealed = anyhow::Error::from(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Sealed,
                "tenant key authorization expired; recovery required",
            ));
            return Err(match self.refusal {
                Refusal::OwningContext => sealed.context("owning apply context"),
                _ => sealed,
            }
            .into());
        }
        self.inner.apply_with_publisher(position, input, publisher)
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<kasumi_raft::CapturedSnapshot, kasumi_store::ScratchOperationFailure>
    {
        self.inner.capture_snapshot()
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<kasumi_raft::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        self.inner.validate_snapshot(bytes)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        self.inner.prepare_restore(context, bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn engine_access_refusal_fences_a_committed_entry_without_retaining_shutdown()
-> FixtureResult<()> {
    for refusal in [Refusal::TypedSealed, Refusal::OwningContext] {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let path = directory.path().join("access-refusal.kv");
        let stores = common::store(&path, true, scratch.clone(), 1, GROUP).await?;
        let backend = Arc::new(Refusing {
            inner: common::Backend::default(),
            refusal,
            refuse: AtomicBool::new(false),
        });
        let group = common::singleton_raft(
            1,
            GROUP.into(),
            stores.clone(),
            backend.clone(),
            common::snapshot_owner(),
        )
        .await?;
        group
            .write(ApplicationProposal::generated(b"acknowledged".to_vec()))
            .await?;
        backend.refuse.store(true, Ordering::Release);
        // Commit an entry the way a leader's own or an already replicated
        // entry arrives: through consensus, not the closed admission path.
        // Its log record is durable; only its apply meets the closed fence.
        let committed = tokio::time::timeout(
            WAIT,
            group
                .raft()
                .client_write(RaftCommand::application(b"after expiry".to_vec())),
        )
        .await?;
        assert!(committed.is_err(), "{refusal:?}: a closed fence applied");
        let waited = tokio::time::timeout(WAIT, async {
            while !matches!(group.try_with_retained_apply_report(|_| ()), Ok(Some(()))) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if waited.is_err() {
            let metrics = group.raft().metrics().borrow().clone();
            panic!(
                "{refusal:?}: no retained apply; access={:?} term={} last_log={:?} applied={:?} state={:?}",
                group.access_failure_class(),
                metrics.current_term,
                metrics.last_log_index,
                metrics.last_applied,
                metrics.running_state
            );
        }
        group
            .try_with_retained_apply_report(|report| {
                let kasumi_raft::RetainedApplyReport::Single(original) = report else {
                    panic!("{refusal:?}: an access refusal has a single original")
                };
                assert_eq!(
                    original
                        .downcast_ref::<kasumi_types::Error>()
                        .map(|error| error.code),
                    Some(kasumi_types::ErrorCode::Sealed),
                    "{refusal:?}"
                );
            })
            .expect("settled retained report is busy");
        assert!(
            group
                .write(ApplicationProposal::generated(b"refused".to_vec()))
                .await
                .is_err(),
            "{refusal:?}: a fenced machine admitted another write"
        );
        let failure = tokio::time::timeout(WAIT, group.shutdown())
            .await?
            .expect_err("the fenced apply stays in the shutdown report");
        if matches!(refusal, Refusal::OwningContext) {
            assert_eq!(failure.completion(), DrainCompletion::Retained);
            continue;
        }
        assert_eq!(
            failure.completion(),
            DrainCompletion::Complete,
            "{refusal:?}"
        );
        drop(group);
        kasumi_store::test_utils::shutdown_owned_stores_fixture(&stores).await?;
        drop(stores);
        drop(backend);

        // The replacement phase reopens the same physical store and replays it.
        let recovered = Arc::new(common::Backend::default());
        let reopened = common::singleton_raft(
            1,
            GROUP.into(),
            common::store(&path, false, scratch.clone(), 1, GROUP).await?,
            recovered.clone(),
            common::snapshot_owner(),
        )
        .await?;
        // The durable refused entry is applied exactly once by the new owner.
        assert_eq!(
            recovered.values(),
            vec![b"acknowledged".to_vec(), b"after expiry".to_vec()],
            "{refusal:?}"
        );
        reopened
            .write(ApplicationProposal::generated(b"next phase".to_vec()))
            .await?;
        reopened.shutdown().await?;
    }
    Ok(())
}
