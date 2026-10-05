//! Actual core/worker ordering while the committed reader is held.
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "generic-snapshot-data")]
use super::SnapshotResponse;
use super::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, Raft, VoteRequest,
    VoteResponse,
};
use crate::error::{Fatal, InstallSnapshotError, RPCError, RaftError};
#[cfg(feature = "generic-snapshot-data")]
use crate::error::{ReplicationClosed, StreamingError};
use crate::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use crate::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use crate::type_config::TypeConfigExt;
use crate::{
    CommittedLeaderId, Config, Entry, EntryPayload, LogId, LogState, Membership, OptionalSend, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, SnapshotPolicy, StorageError, StoredMembership, TokioRuntime, Vote,
};

crate::declare_raft_types!(TestConfig: D = (), R = u64, NodeId = u64, Node = (), Entry = Entry<TestConfig>, SnapshotData = Cursor<Vec<u8>>, AsyncRuntime = TokioRuntime);

fn id(index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(1, 2), index)
}
fn membership() -> StoredMembership<u64, ()> {
    StoredMembership::new(Some(id(0)), Membership::new(vec![[1, 2].into()], ()))
}
fn entry(index: u64) -> Entry<TestConfig> {
    Entry {
        log_id: id(index),
        payload: if index == 0 {
            EntryPayload::Membership(membership().membership().clone())
        } else {
            EntryPayload::Blank
        },
    }
}
#[derive(Default)]
struct State {
    logs: BTreeMap<u64, Entry<TestConfig>>,
    purged: Option<LogId<u64>>,
    committed: Option<LogId<u64>>,
    vote: Option<Vote<u64>>,
    applied: Vec<u64>,
    last: Option<LogId<u64>>,
    installed: Option<Snapshot<TestConfig>>,
    apply_failure: Option<StorageError<u64>>,
    panic_apply: bool,
}
#[derive(Clone)]
struct Store {
    state: Arc<Mutex<State>>,
    reads: mpsc::UnboundedSender<(u64, u64, oneshot::Sender<()>)>,
}
impl RaftLogReader<TestConfig> for Store {
    async fn try_get_log_entries<R: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<TestConfig>>, StorageError<u64>> {
        Ok(self.state.lock().unwrap().logs.range(range).map(|(_, entry)| entry.clone()).collect())
    }
    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<TestConfig>>, StorageError<u64>> {
        let (release, held) = oneshot::channel();
        self.reads.send((start, end, release)).unwrap();
        held.await.unwrap();
        self.try_get_log_entries(start..end).await
    }
}
#[cfg(not(feature = "storage-v2"))]
impl crate::storage::v2::sealed::Sealed for Store {}
impl RaftLogStorage<TestConfig> for Store {
    type LogReader = Self;
    async fn get_log_state(&mut self) -> Result<LogState<TestConfig>, StorageError<u64>> {
        let state = self.state.lock().unwrap();
        Ok(LogState {
            last_purged_log_id: state.purged,
            last_log_id: state.logs.last_key_value().map(|(_, entry)| entry.log_id).or(state.purged),
        })
    }
    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }
    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        self.state.lock().unwrap().vote = Some(*vote);
        Ok(())
    }
    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        Ok(self.state.lock().unwrap().vote)
    }
    async fn save_committed(&mut self, committed: Option<LogId<u64>>) -> Result<(), StorageError<u64>> {
        self.state.lock().unwrap().committed = committed;
        Ok(())
    }
    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        Ok(self.state.lock().unwrap().committed)
    }
    async fn append<I>(&mut self, entries: I, callback: LogFlushed<TestConfig>) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TestConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        self.state.lock().unwrap().logs.extend(entries.into_iter().map(|entry| (entry.log_id.index, entry)));
        callback.log_io_completed(Ok(()));
        Ok(())
    }
    async fn truncate(&mut self, from: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.state.lock().unwrap().logs.retain(|index, _| *index < from.index);
        Ok(())
    }
    async fn purge(&mut self, upto: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(
            state.applied,
            [0, 1, 2, 3, 4],
            "the incoming snapshot must not purge an unread committed prefix"
        );
        state.logs.retain(|index, _| *index > upto.index);
        state.purged = Some(upto);
        Ok(())
    }
}
struct Machine(Arc<Mutex<State>>);
#[cfg(not(feature = "storage-v2"))]
impl crate::storage::v2::sealed::Sealed for Machine {}
struct Builder;
impl RaftSnapshotBuilder<TestConfig> for Builder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TestConfig>, StorageError<u64>> {
        panic!("automatic snapshot disabled")
    }
}
impl RaftStateMachine<TestConfig> for Machine {
    type SnapshotBuilder = Builder;
    async fn applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, ()>), StorageError<u64>> {
        Ok((self.0.lock().unwrap().last, StoredMembership::default()))
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<u64>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TestConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let (failure, panic_apply) = {
            let state = self.0.lock().unwrap();
            (state.apply_failure.clone(), state.panic_apply)
        };
        if let Some(failure) = failure {
            return Err(failure);
        }
        assert!(!panic_apply, "controlled original apply panic");
        let mut state = self.0.lock().unwrap();
        Ok(entries
            .into_iter()
            .map(|entry| {
                state.applied.push(entry.log_id.index);
                state.last = Some(entry.log_id);
                entry.log_id.index
            })
            .collect())
    }
    async fn get_snapshot_builder(&mut self) -> Builder {
        Builder
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, ()>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let mut state = self.0.lock().unwrap();
        assert_eq!(
            state.applied,
            [0, 1, 2, 3, 4],
            "committed application must finish before replacement"
        );
        assert_eq!(snapshot.get_ref(), &[8, 9, 10]);
        state.last = meta.last_log_id;
        state.installed = Some(Snapshot {
            meta: meta.clone(),
            snapshot,
        });
        Ok(())
    }
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TestConfig>>, StorageError<u64>> {
        Ok(self.0.lock().unwrap().installed.as_ref().map(|snapshot| Snapshot {
            meta: snapshot.meta.clone(),
            snapshot: Box::new(snapshot.snapshot.as_ref().clone()),
        }))
    }
}
struct Network;
impl RaftNetworkFactory<TestConfig> for Network {
    type Network = Self;
    async fn new_client(&mut self, _: u64, _: &()) -> Self {
        Self
    }
}
impl RaftNetwork<TestConfig> for Network {
    async fn append_entries(
        &mut self,
        _: AppendEntriesRequest<TestConfig>,
        _: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, (), RaftError<u64>>> {
        panic!("follower must not replicate")
    }
    async fn vote(
        &mut self,
        _: VoteRequest<u64>,
        _: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, (), RaftError<u64>>> {
        panic!("elections disabled")
    }
    #[allow(deprecated)]
    async fn install_snapshot(
        &mut self,
        _: InstallSnapshotRequest<TestConfig>,
        _: RPCOption,
    ) -> Result<InstallSnapshotResponse<u64>, RPCError<u64, (), RaftError<u64, InstallSnapshotError>>> {
        panic!("follower must not send snapshots")
    }
    #[cfg(feature = "generic-snapshot-data")]
    async fn full_snapshot(
        &mut self,
        _: Vote<u64>,
        _: Snapshot<TestConfig>,
        _: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<TestConfig, Fatal<u64>>> {
        panic!("follower must not send snapshots")
    }
}

#[tokio::test]
async fn blocked_committed_read_keeps_votes_and_appends_live_and_cancelled_snapshot_behind_exact_apply() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let state = Arc::new(Mutex::new(State {
            logs: (0..5).map(|index| (index, entry(index))).collect(),
            vote: Some(Vote::new_committed(1, 2)),
            ..State::default()
        }));
        let (read_tx, mut reads) = mpsc::unbounded_channel();
        let config = Config {
            enable_tick: false,
            enable_elect: false,
            enable_heartbeat: false,
            max_payload_entries: 2,
            snapshot_policy: SnapshotPolicy::Never,
            ..Config::default()
        };
        let raft = Raft::new(
            1,
            Arc::new(config.validate().unwrap()),
            Network,
            Store {
                state: state.clone(),
                reads: read_tx,
            },
            Machine(state.clone()),
        )
        .await
        .unwrap();
        assert!(raft
            .append_entries(AppendEntriesRequest {
                vote: Vote::new_committed(1, 2),
                prev_log_id: Some(id(4)),
                entries: vec![],
                leader_commit: Some(id(4))
            })
            .await
            .unwrap()
            .is_success());
        let (start, end, release) = reads.recv().await.unwrap();
        assert_eq!((start, end), (0, 2));
        // Actual RPC responses must return while the committed reader is held.
        assert!(!raft.vote(VoteRequest::new(Vote::new(0, 2), Some(id(4)))).await.unwrap().vote_granted);
        assert!(raft
            .append_entries(AppendEntriesRequest {
                vote: Vote::new_committed(1, 2),
                prev_log_id: Some(id(4)),
                entries: vec![entry(5)],
                leader_commit: Some(id(4))
            })
            .await
            .unwrap()
            .is_success());
        assert!(state.lock().unwrap().logs.contains_key(&5));
        let incoming_raft = raft.clone();
        let caller = tokio::spawn(async move {
            incoming_raft
                .install_full_snapshot(
                    Vote::new_committed(1, 2),
                    Snapshot {
                        meta: SnapshotMeta {
                            last_log_id: Some(id(7)),
                            last_membership: membership(),
                            snapshot_id: "replacement".into(),
                        },
                        snapshot: Box::new(Cursor::new(vec![8, 9, 10])),
                    },
                )
                .await
        });
        while raft.inner.pending_snapshot.retained().is_none() {
            tokio::task::yield_now().await;
        }
        // This later actual actor message also proves the pending snapshot does
        // not place a blocking engine condition ahead of vote handling.
        assert!(!raft.vote(VoteRequest::new(Vote::new(0, 2), Some(id(5)))).await.unwrap().vote_granted);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(raft.inner.pending_snapshot.retained().is_some());
        assert!(state.lock().unwrap().purged.is_none());
        assert!(state.lock().unwrap().installed.is_none());
        release.send(()).unwrap();
        for range in [(2, 4), (4, 5)] {
            let (start, end, release) = reads.recv().await.unwrap();
            assert_eq!((start, end), range);
            assert!(state.lock().unwrap().purged.is_none());
            release.send(()).unwrap();
        }
        raft.wait(Some(Duration::from_secs(2)))
            .applied_index(Some(7), "replacement installed after exact committed prefix")
            .await
            .unwrap();
        assert_eq!(state.lock().unwrap().applied, [0, 1, 2, 3, 4]);
        assert_eq!(state.lock().unwrap().purged, Some(id(7)));
        assert!(raft.inner.pending_snapshot.retained().is_none());
        raft.shutdown().await.unwrap();
        assert!(raft.inner.state_machine_tasks.apply_batch.retained().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_shutdown_retains_pending_snapshot_and_unconsumed_real_apply_owner() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let state = Arc::new(Mutex::new(State {
            logs: (0..5).map(|index| (index, entry(index))).collect(),
            vote: Some(Vote::new_committed(1, 2)),
            ..State::default()
        }));
        let (read_tx, mut reads) = mpsc::unbounded_channel();
        let config = Config {
            enable_tick: false,
            enable_elect: false,
            enable_heartbeat: false,
            max_payload_entries: 2,
            snapshot_policy: SnapshotPolicy::Never,
            ..Config::default()
        };
        let raft = Raft::new(
            1,
            Arc::new(config.validate().unwrap()),
            Network,
            Store {
                state: state.clone(),
                reads: read_tx,
            },
            Machine(state.clone()),
        )
        .await
        .unwrap();
        assert!(raft
            .append_entries(AppendEntriesRequest {
                vote: Vote::new_committed(1, 2),
                prev_log_id: Some(id(4)),
                entries: vec![],
                leader_commit: Some(id(4))
            })
            .await
            .unwrap()
            .is_success());
        let (start, end, release) = reads.recv().await.unwrap();
        assert_eq!((start, end), (0, 2));
        let incoming_raft = raft.clone();
        let caller = tokio::spawn(async move {
            incoming_raft
                .install_full_snapshot(
                    Vote::new_committed(1, 2),
                    Snapshot {
                        meta: SnapshotMeta {
                            last_log_id: Some(id(7)),
                            last_membership: membership(),
                            snapshot_id: "pending-at-shutdown".into(),
                        },
                        snapshot: Box::new(Cursor::new(vec![8, 9, 10])),
                    },
                )
                .await
        });
        while raft.inner.pending_snapshot.retained().is_none() {
            tokio::task::yield_now().await;
        }
        let original_snapshot = raft.inner.pending_snapshot.retained().unwrap();
        assert!(!raft.vote(VoteRequest::new(Vote::new(0, 2), Some(id(4)))).await.unwrap().vote_granted);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let stopping = raft.clone();
        let shutdown = tokio::spawn(async move { stopping.shutdown().await });
        // Join the actual core; the state-machine worker is still in its held
        // physical read. Cancelling the shutdown caller must not detach it.
        assert!(matches!(raft.inner.join_core_task().await.fatal, Fatal::Stopped));
        shutdown.abort();
        assert!(shutdown.await.unwrap_err().is_cancelled());
        assert!(original_snapshot.same_owner(&raft.inner.pending_snapshot.retained().unwrap()));
        release.send(()).unwrap();
        let failure = raft.shutdown().await.unwrap_err();
        assert!(failure.state_machine().unwrap().storage_error().is_some());
        assert!(original_snapshot.same_owner(failure.pending_snapshot().unwrap()));
        assert!(failure.unconsumed_apply().is_some());
        let again = raft.shutdown().await.unwrap_err();
        assert!(failure.unconsumed_apply().unwrap().same_owner(again.unconsumed_apply().unwrap()));
        assert!(failure.pending_snapshot().unwrap().same_owner(again.pending_snapshot().unwrap()));
        assert!(Arc::ptr_eq(
            failure.state_machine().unwrap().storage_error().unwrap(),
            again.state_machine().unwrap().storage_error().unwrap()
        ));
        assert_eq!(state.lock().unwrap().applied, [0, 1]);
        assert!(state.lock().unwrap().installed.is_none());
        assert!(state.lock().unwrap().purged.is_none());
        assert!(reads.try_recv().is_err());
    })
    .await
    .unwrap();
}

async fn graceful_fixture() -> (
    Raft<TestConfig>,
    Arc<Mutex<State>>,
    mpsc::UnboundedReceiver<(u64, u64, oneshot::Sender<()>)>,
) {
    let state = Arc::new(Mutex::new(State {
        logs: (0..5).map(|index| (index, entry(index))).collect(),
        vote: Some(Vote::new_committed(1, 2)),
        ..State::default()
    }));
    let (read_tx, reads) = mpsc::unbounded_channel();
    let config = Config {
        enable_tick: false,
        enable_elect: false,
        enable_heartbeat: false,
        max_payload_entries: 2,
        snapshot_policy: SnapshotPolicy::Never,
        ..Config::default()
    };
    let raft = Raft::new(
        1,
        Arc::new(config.validate().unwrap()),
        Network,
        Store {
            state: state.clone(),
            reads: read_tx,
        },
        Machine(state.clone()),
    )
    .await
    .unwrap();
    assert!(raft
        .append_entries(AppendEntriesRequest {
            vote: Vote::new_committed(1, 2),
            prev_log_id: Some(id(4)),
            entries: vec![],
            leader_commit: Some(id(4)),
        })
        .await
        .unwrap()
        .is_success());
    (raft, state, reads)
}

async fn poll_shutdown_signal(raft: &Raft<TestConfig>) {
    let mut closing = Box::pin(raft.shutdown_gracefully());
    std::future::poll_fn(|cx| {
        assert!(
            closing.as_mut().poll(cx).is_pending(),
            "held committed read must keep the core alive"
        );
        std::task::Poll::Ready(())
    })
    .await;
    // The actual core owns the signalled policy after this waiter disappears.
    drop(closing);
}

async fn wait_ingress_closed(raft: &Raft<TestConfig>) {
    while !raft.inner.tx_api.is_closed() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn graceful_shutdown_fences_ingress_and_drains_coalesced_apply_after_waiter_cancellation() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (raft, state, mut reads) = graceful_fixture().await;
        let (start, end, release) = reads.recv().await.unwrap();
        assert_eq!((start, end), (0, 2));
        // This admitted later commit is in the scalar pending handoff while
        // the worker still owns its preceding physical read.
        assert!(raft
            .append_entries(AppendEntriesRequest {
                vote: Vote::new_committed(1, 2),
                prev_log_id: Some(id(4)),
                entries: vec![entry(5), entry(6)],
                leader_commit: Some(id(6)),
            })
            .await
            .unwrap()
            .is_success());
        poll_shutdown_signal(&raft).await;
        // No yield occurred since signalling: this original API request is
        // queued behind the stop cut and must receive channel termination.
        let (response, received) = TestConfig::oneshot();
        assert!(raft
            .inner
            .tx_api
            .send(crate::core::raft_msg::RaftMsg::AppendEntries {
                rpc: AppendEntriesRequest {
                    vote: Vote::new_committed(1, 2),
                    prev_log_id: Some(id(6)),
                    entries: vec![entry(7)],
                    leader_commit: Some(id(7)),
                },
                tx: response,
            })
            .is_ok());
        let (response, original_writer) = TestConfig::oneshot();
        assert!(raft
            .inner
            .tx_api
            .send(crate::core::raft_msg::RaftMsg::ClientWriteRequest {
                app_data: (),
                tx: crate::impls::OneshotResponder::<TestConfig>::new(response),
            })
            .is_ok());
        wait_ingress_closed(&raft).await;
        assert!(
            received.await.is_err(),
            "queued unprocessed request must terminate without acceptance"
        );
        assert!(
            original_writer.await.is_err(),
            "queued original responder must terminate without a fabricated reply"
        );
        assert!(raft
            .inner
            .tx_notify
            .send(crate::core::notify::Notify::HigherVote {
                target: 2,
                higher: Vote::new(9, 2),
                sender_vote: Vote::new_committed(1, 2),
            })
            .is_ok());
        assert!(!state.lock().unwrap().logs.contains_key(&7));
        release.send(()).unwrap();
        for range in [(2, 4), (4, 5), (5, 7)] {
            let (start, end, release) = reads.recv().await.unwrap();
            assert_eq!((start, end), range);
            release.send(()).unwrap();
        }
        raft.shutdown_gracefully().await.unwrap();
        assert_eq!(state.lock().unwrap().applied, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(state.lock().unwrap().committed, Some(id(6)));
        assert_eq!(state.lock().unwrap().vote, Some(Vote::new_committed(1, 2)));
        assert!(reads.try_recv().is_err());
        assert!(raft.inner.state_machine_tasks.apply_batch.retained().is_none());
        assert!(raft.inner.tx_api.is_closed());
        raft.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_drains_offered_snapshot_before_queued_activation_and_rejects_late_offer() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (raft, state, mut reads) = graceful_fixture().await;
        let (start, end, release) = reads.recv().await.unwrap();
        assert_eq!((start, end), (0, 2));
        let mut incoming = Box::pin(raft.install_full_snapshot(
            Vote::new_committed(1, 2),
            Snapshot {
                meta: SnapshotMeta {
                    last_log_id: Some(id(7)),
                    last_membership: membership(),
                    snapshot_id: "offered-before-stop-cut".into(),
                },
                snapshot: Box::new(Cursor::new(vec![8, 9, 10])),
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(incoming.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let original = raft.inner.pending_snapshot.retained().unwrap();
        drop(incoming);
        // The activation actor message remains queued. The ownership cut
        // must include the exact offer even when that message never executes.
        poll_shutdown_signal(&raft).await;
        wait_ingress_closed(&raft).await;
        assert!(original.same_owner(&raft.inner.pending_snapshot.retained().unwrap()));
        let late_raft = raft.clone();
        let late = tokio::spawn(async move {
            late_raft
                .install_full_snapshot(
                    Vote::new_committed(1, 2),
                    Snapshot {
                        meta: SnapshotMeta {
                            last_log_id: Some(id(8)),
                            last_membership: membership(),
                            snapshot_id: "unadmitted-after-stop-cut".into(),
                        },
                        snapshot: Box::new(Cursor::new(vec![42])),
                    },
                )
                .await
        });
        release.send(()).unwrap();
        for range in [(2, 4), (4, 5)] {
            let (start, end, release) = reads.recv().await.unwrap();
            assert_eq!((start, end), range);
            release.send(()).unwrap();
        }
        raft.shutdown_gracefully().await.unwrap();
        assert_eq!(late.await.unwrap().unwrap_err(), Fatal::Stopped);
        let state = state.lock().unwrap();
        assert_eq!(state.applied, [0, 1, 2, 3, 4]);
        assert_eq!(
            state.installed.as_ref().unwrap().meta.snapshot_id,
            "offered-before-stop-cut"
        );
        assert_eq!(state.installed.as_ref().unwrap().snapshot.get_ref(), &[8, 9, 10]);
        assert!(raft.inner.pending_snapshot.retained().is_none());
        assert!(raft.inner.state_machine_tasks.apply_batch.retained().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_preserves_original_apply_error_and_panic_across_cancelled_waiter_and_retry() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for panic_apply in [false, true] {
            let (raft, state, mut reads) = graceful_fixture().await;
            let (_, _, release) = reads.recv().await.unwrap();
            {
                let mut state = state.lock().unwrap();
                state.panic_apply = panic_apply;
                if !panic_apply {
                    state.apply_failure = Some(
                        crate::StorageIOError::apply(
                            id(1),
                            anyerror::AnyError::error("controlled original graceful apply failure"),
                        )
                        .into(),
                    );
                }
            }
            poll_shutdown_signal(&raft).await;
            wait_ingress_closed(&raft).await;
            release.send(()).unwrap();
            let first = raft.shutdown_gracefully().await.unwrap_err();
            let again = raft.shutdown_gracefully().await.unwrap_err();
            let original = first.state_machine().unwrap();
            let repeated = again.state_machine().unwrap();
            if panic_apply {
                let original = original.join_error().unwrap();
                assert!(original.is_panic());
                assert!(Arc::ptr_eq(original, repeated.join_error().unwrap()));
            } else {
                let original = original.storage_error().unwrap();
                assert!(original.to_string().contains("controlled original graceful apply failure"));
                assert!(Arc::ptr_eq(original, repeated.storage_error().unwrap()));
            }
            assert!(state.lock().unwrap().applied.is_empty());
            assert!(reads.try_recv().is_err());
        }
    })
    .await
    .unwrap();
}
