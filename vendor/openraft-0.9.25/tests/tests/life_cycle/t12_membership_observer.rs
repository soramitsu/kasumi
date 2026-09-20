use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use maplit::btreeset;
use openraft::Config;
use openraft::MembershipObserver;
use openraft::MembershipObserverAlreadyInstalled;

use crate::fixtures::init_default_ut_tracing;
use crate::fixtures::RaftRouter;

#[derive(Debug, Default)]
struct Observer(AtomicUsize);
impl MembershipObserver for Observer {
    fn membership_changing(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

/// The synchronous public installer reaches the actual follower membership
/// owner: remote AppendEntries invalidates before the new state is observable.
#[async_entry::test(worker_threads = 8, init = "init_default_ut_tracing()", tracing_span = "debug")]
async fn remote_membership_append_invalidates_installed_observer() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_tick: false,
            ..Default::default()
        }
        .validate()?,
    );
    let mut router = RaftRouter::new(config);
    router.new_cluster(btreeset! {0, 1, 2}, btreeset! {}).await?;
    let leader = router.get_raft_handle(&0)?;
    let follower = router.get_raft_handle(&1)?;
    let observer = Arc::new(Observer::default());
    follower.install_membership_observer(observer.clone())?;
    follower.clone().install_membership_observer(observer.clone())?;
    assert_eq!(observer.0.load(Ordering::Acquire), 1);
    assert_eq!(
        follower.install_membership_observer(Arc::new(Observer::default())),
        Err(MembershipObserverAlreadyInstalled)
    );
    let result = leader.change_membership([0, 1], false).await?;
    router
        .wait_for_log(
            &btreeset! {0, 1},
            Some(result.log_id.index),
            Some(Duration::from_secs(5)),
            "membership replicated",
        )
        .await?;
    let observed = observer.clone();
    let (voters, invalidations) = follower
        .with_raft_state(move |state| {
            (
                state.membership_state.effective().membership().voter_ids().collect::<Vec<_>>(),
                observed.0.load(Ordering::Acquire),
            )
        })
        .await?;
    assert_eq!(voters, vec![0, 1]);
    assert!(
        invalidations > 1,
        "actual follower membership mutation must invalidate installed observer"
    );
    for id in [0, 1, 2] {
        router.get_raft_handle(&id)?.shutdown().await?;
    }
    Ok(())
}
