//! Actual core/worker ordering while the committed reader is held.
use std::collections::BTreeMap;
use std::fmt::Debug;
#[cfg(feature = "generic-snapshot-data")]
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
#[cfg(feature = "generic-snapshot-data")]
use crate::error::{Fatal, ReplicationClosed, StreamingError};
use crate::error::{InstallSnapshotError, RPCError, RaftError};
use crate::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use crate::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
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
        assert!(matches!(
            raft.inner.join_core_task().await.fatal,
            crate::error::Fatal::Stopped
        ));
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
