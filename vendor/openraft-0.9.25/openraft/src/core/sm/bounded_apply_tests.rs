//! Actual worker reads and response ownership, not simulated admission tokens.
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::{Bound, RangeBounds};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};

use super::pending_snapshot::{IncomingSnapshot, PendingSnapshot};
use super::worker::Worker;
use super::{Command, Response};
use crate::async_runtime::AsyncOneshotSendExt;
use crate::core::notify::Notify;
use crate::storage::RaftStateMachine;
use crate::type_config::TypeConfigExt;
use crate::{
    CommittedLeaderId, Entry, EntryPayload, LogId, Membership, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    RaftTypeConfig, Snapshot, SnapshotMeta, StorageError, StoredMembership, TokioRuntime, Vote,
};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct Config;
impl RaftTypeConfig for Config {
    type D = ();
    type R = Reply;
    type NodeId = u64;
    type Node = ();
    type Entry = Entry<Self>;
    type SnapshotData = Cursor<Vec<u8>>;
    type AsyncRuntime = TokioRuntime;
    type Responder = crate::impls::OneshotResponder<Self>;
}
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct Reply {
    index: u64,
    #[cfg_attr(feature = "serde", serde(skip))]
    dropped: Arc<AtomicUsize>,
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
fn id(index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(1, 1), index)
}
fn entry(index: u64) -> Entry<Config> {
    Entry {
        log_id: id(index),
        payload: EntryPayload::Blank,
    }
}
fn meta(index: u64) -> SnapshotMeta<u64, ()> {
    SnapshotMeta {
        last_log_id: Some(id(index)),
        last_membership: StoredMembership::default(),
        snapshot_id: format!("snapshot-{index}"),
    }
}
struct Reader(mpsc::UnboundedSender<(u64, u64, oneshot::Sender<Vec<Entry<Config>>>)>);
impl RaftLogReader<Config> for Reader {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<Config>>, StorageError<u64>> {
        let (Bound::Included(&start), Bound::Excluded(&end)) = (range.start_bound(), range.end_bound()) else {
            panic!("worker must request bounded half-open ranges")
        };
        let (tx, rx) = oneshot::channel();
        self.0.send((start, end, tx)).unwrap();
        Ok(rx.await.unwrap())
    }
}
struct Machine {
    dropped: Arc<AtomicUsize>,
    last: Option<LogId<u64>>,
    snapshots: mpsc::UnboundedSender<Option<LogId<u64>>>,
}
struct Builder {
    last: Option<LogId<u64>>,
}
#[cfg(not(feature = "storage-v2"))]
impl crate::storage::v2::sealed::Sealed for Machine {}
impl RaftSnapshotBuilder<Config> for Builder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<Config>, StorageError<u64>> {
        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id: self.last,
                last_membership: StoredMembership::default(),
                snapshot_id: "built".into(),
            },
            snapshot: Box::new(Cursor::new(Vec::new())),
        })
    }
}
impl RaftStateMachine<Config> for Machine {
    type SnapshotBuilder = Builder;
    async fn applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, ()>), StorageError<u64>> {
        Ok((self.last, StoredMembership::default()))
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Reply>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<Config>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        Ok(entries
            .into_iter()
            .map(|entry| {
                self.last = Some(entry.log_id);
                Reply {
                    index: entry.log_id.index,
                    dropped: self.dropped.clone(),
                }
            })
            .collect())
    }
    async fn get_snapshot_builder(&mut self) -> Builder {
        self.snapshots.send(self.last).unwrap();
        Builder { last: self.last }
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, ()>,
        _data: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        self.last = meta.last_log_id;
        Ok(())
    }
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<Config>>, StorageError<u64>> {
        Ok(None)
    }
}

#[tokio::test]
async fn actual_worker_waits_for_each_consumed_prefix_before_reading_or_building_snapshot() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let (read_tx, mut reads) = mpsc::unbounded_channel();
    let (notify, mut notifications) = mpsc::unbounded_channel();
    let (snapshot_tx, mut snapshots) = mpsc::unbounded_channel();
    let (mut handle, tasks) = Worker::spawn(
        Machine {
            dropped: dropped.clone(),
            last: None,
            snapshots: snapshot_tx,
        },
        Reader(read_tx),
        2,
        notify,
    );
    // No await here: several actual commits coalesce before worker selection.
    handle.send(Command::apply(0, id(0)).with_seq(5)).unwrap();
    handle.send(Command::apply(1, id(2)).with_seq(6)).unwrap();
    handle.send(Command::apply(3, id(4)).with_seq(7)).unwrap();
    handle.send(Command::build_snapshot().with_seq(8)).unwrap();
    handle.send(Command::apply(5, id(5)).with_seq(9)).unwrap();
    handle.send(Command::apply(6, id(6)).with_seq(10)).unwrap();
    for (start, end) in [(0, 2), (2, 4), (4, 5)] {
        let (first, stop, reply) = reads.recv().await.unwrap();
        assert_eq!((first, stop), (start, end));
        let mut entries = (start..end).map(entry).collect::<Vec<_>>();
        if start == 2 {
            entries[1].payload = EntryPayload::Membership(Membership::new(vec![[1, 2].into()], None));
        }
        reply.send(entries).unwrap();
        let Notify::StateMachine { command_result } = notifications.recv().await.unwrap() else {
            panic!("expected actual apply notification")
        };
        assert_eq!(command_result.command_seq, 7);
        let Response::Apply {
            batch,
            final_batch,
            consumed,
        } = command_result.result.unwrap()
        else {
            panic!("expected actual apply batch")
        };
        assert_eq!(batch.progress().unwrap(), (start, end, id(end - 1)));
        assert_eq!(final_batch, end == 5);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reads.recv()).await.is_err(),
            "an unconsumed response must prevent the next physical read"
        );
        assert!(snapshots.try_recv().is_err());
        for index in start..end {
            let (metadata, response) = batch.next().unwrap();
            assert_eq!(metadata.log_id, id(index));
            assert_eq!(metadata.membership.is_some(), index == 3);
            assert_eq!(response.index, index);
            drop(response);
            batch.delivered();
        }
        batch.finish().unwrap();
        consumed.send(()).unwrap();
    }
    assert_eq!(snapshots.recv().await.unwrap(), Some(id(4)));
    let (start, end, reply) = reads.recv().await.unwrap();
    assert_eq!((start, end), (5, 7), "later commits stay after the snapshot boundary");
    reply.send((start..end).map(entry).collect()).unwrap();
    let mut built = false;
    let mut applied = false;
    for _ in 0..2 {
        let Notify::StateMachine { command_result } = notifications.recv().await.unwrap() else {
            panic!("state machine completion")
        };
        match command_result.result.unwrap() {
            Response::BuildSnapshot(meta) => {
                assert!(!built);
                built = true;
                assert_eq!(command_result.command_seq, 8);
                assert_eq!(meta.last_log_id, Some(id(4)));
            }
            Response::Apply {
                batch,
                final_batch,
                consumed,
            } => {
                assert!(!applied);
                applied = true;
                assert_eq!(command_result.command_seq, 10);
                assert!(final_batch);
                assert_eq!(batch.progress().unwrap(), (5, 7, id(6)));
                for index in 5..7 {
                    let (metadata, response) = batch.next().unwrap();
                    assert_eq!(metadata.log_id, id(index));
                    assert_eq!(response.index, index);
                    drop(response);
                    batch.delivered();
                }
                batch.finish().unwrap();
                consumed.send(()).unwrap();
            }
            _ => panic!("unexpected completion"),
        }
    }
    assert!(built && applied);
    drop(handle);
    let (worker, builder) = tasks.shutdown().await;
    assert!(worker.is_none() && builder.is_none());
    assert!(tasks.apply_batch.retained().is_none());
    assert_eq!(dropped.load(Ordering::Acquire), 7);
}

#[tokio::test]
async fn dropped_core_notification_retains_the_actual_opaque_responses_and_original_worker_error() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let (read_tx, mut reads) = mpsc::unbounded_channel();
    let (notify, mut notifications) = mpsc::unbounded_channel();
    let (snapshot_tx, _snapshots) = mpsc::unbounded_channel();
    let (mut handle, tasks) = Worker::spawn(
        Machine {
            dropped: dropped.clone(),
            last: None,
            snapshots: snapshot_tx,
        },
        Reader(read_tx),
        2,
        notify,
    );
    handle.send(Command::apply(0, id(4)).with_seq(7)).unwrap();
    let (start, end, reply) = reads.recv().await.unwrap();
    assert_eq!((start, end), (0, 2));
    reply.send((start..end).map(entry).collect()).unwrap();
    let notification = notifications.recv().await.unwrap();
    drop(notification); // Drops the real acknowledgement sender without consuming.
    drop(handle);
    let (worker, _) = tasks.shutdown().await;
    let error = worker.unwrap();
    let (again, _) = tasks.shutdown().await;
    assert!(Arc::ptr_eq(
        error.storage_error().unwrap(),
        again.as_ref().unwrap().storage_error().unwrap()
    ));
    assert!(reads.try_recv().is_err());
    let retained = tasks.apply_batch.retained().unwrap();
    assert!(retained.same_owner(&tasks.apply_batch.retained().unwrap()));
    drop(tasks);
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    drop(retained);
    assert_eq!(dropped.load(Ordering::Acquire), 2);
}

#[test]
fn terminal_boundary_captures_last_coalesced_range_and_rejects_all_later_senders() {
    use super::pending_apply::PendingApply;
    use super::CommandPayload;

    let cell = PendingApply::<Config>::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    cell.send(&tx, Command::apply(0, id(2)).with_seq(1)).unwrap();
    cell.send(&tx, Command::build_snapshot().with_seq(2)).unwrap();
    cell.send(&tx, Command::apply(3, id(4)).with_seq(3)).unwrap();
    cell.seal(&tx).unwrap();
    assert!(
        !tx.is_closed(),
        "the admission seal must also govern upgraded weak senders"
    );
    assert!(cell.send(&tx, Command::apply(5, id(6)).with_seq(4)).is_err());
    let (response, _receiver) = Config::oneshot();
    assert!(cell.send(&tx, Command::get_snapshot(response)).is_err());
    let boundary = cell.take_next(&mut rx).unwrap();
    assert!(matches!(boundary.payload, CommandPayload::BuildSnapshot));
    let before = boundary.apply_before.unwrap();
    assert_eq!((before.since, before.upto, before.seq), (0, id(2), 1));
    let terminal = cell.take_next(&mut rx).unwrap();
    assert!(matches!(terminal.payload, CommandPayload::Stop));
    let before = terminal.apply_before.unwrap();
    assert_eq!((before.since, before.upto, before.seq), (3, id(4), 3));
    cell.seal(&tx).unwrap();
    assert!(cell.take_next(&mut rx).is_err());
}

#[tokio::test]
async fn pending_snapshot_keeps_source_and_permit_after_waiter_cancel_until_safe_acceptance() {
    let cell = PendingSnapshot::<Config>::new();
    let gate = Arc::new(Mutex::new(()));
    let permit = gate.clone().lock_owned().await;
    let (tx, rx) = Config::oneshot();
    assert!(cell
        .offer(
            IncomingSnapshot {
                vote: Vote::new(1, 1),
                snapshot: Snapshot {
                    meta: meta(7),
                    snapshot: Box::new(Cursor::new(vec![4, 5, 6])),
                },
                tx,
            },
            permit,
        )
        .is_ok());
    drop(rx);
    assert!(gate.clone().try_lock_owned().is_err());
    assert!(
        cell.take_ready(Some(&id(3)), Some(&id(3))).is_none(),
        "not activated by the actor yet"
    );
    cell.activate();
    assert!(cell.take_ready(Some(&id(3)), Some(&id(1))).is_none());
    assert!(cell.take_ready(Some(&id(5)), Some(&id(3))).is_none());
    let retained = cell.retained().unwrap();
    assert!(retained.same_owner(&cell.retained().unwrap()));
    // Continuing commits reach the snapshot's fixed boundary: the engine will
    // now discard it as obsolete, so lagging applied progress cannot starve it.
    let incoming = cell.take_ready(Some(&id(7)), Some(&id(3))).unwrap();
    assert_eq!(incoming.snapshot.snapshot.get_ref(), &[4, 5, 6]);
    assert!(
        gate.clone().try_lock_owned().is_err(),
        "engine acceptance has not returned"
    );
    cell.accepted();
    assert!(gate.try_lock_owned().is_ok());
    assert!(cell.retained().is_none());
    drop(incoming);
    drop(retained);
}

#[test]
fn actual_commit_handoff_coalesces_without_channel_nodes_and_rejects_disconnected_ranges() {
    use super::pending_apply::PendingApply;
    use super::CommandPayload;
    let cell = PendingApply::<Config>::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    for index in 0..128 {
        cell.send(&tx, Command::apply(index, id(index)).with_seq(index + 1)).unwrap();
        assert!(rx.is_empty(), "commit-only traffic must not allocate queue nodes");
    }
    // A queued real command detaches exactly the range preceding that boundary.
    cell.send(&tx, Command::build_snapshot().with_seq(129)).unwrap();
    cell.send(&tx, Command::apply(128, id(129)).with_seq(130)).unwrap();
    cell.send(&tx, Command::apply(130, id(131)).with_seq(131)).unwrap();
    assert_eq!(rx.len(), 1);
    let command = cell.take_next(&mut rx).unwrap();
    assert!(matches!(command.payload, CommandPayload::BuildSnapshot));
    let range = command.apply_before.unwrap();
    assert_eq!((range.since, range.upto, range.seq), (0, id(127), 128));
    let command = cell.take_next(&mut rx).unwrap();
    assert_eq!(command, Command::apply(128, id(131)).with_seq(131));
    // Continuity still applies after the preceding range left the cell.
    for invalid in [
        Command::apply(133, id(134)).with_seq(132),
        Command::apply(131, id(132)).with_seq(132),
        Command::apply(132, id(133)).with_seq(131),
        Command::apply(132, id(u64::MAX)).with_seq(132),
    ] {
        assert!(cell.send(&tx, invalid).is_err());
        assert!(cell.take_next(&mut rx).is_err());
    }
    cell.send(&tx, Command::apply(132, id(133)).with_seq(132)).unwrap();
    drop(tx);
    assert_eq!(
        cell.take_next(&mut rx).unwrap(),
        Command::apply(132, id(133)).with_seq(132)
    );
    assert!(matches!(
        cell.take_next(&mut rx),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
}

#[test]
fn queued_command_and_pending_take_race_preserves_one_exact_preceding_obligation() {
    use super::pending_apply::PendingApply;
    use super::CommandPayload;
    for _ in 0..32 {
        let cell = PendingApply::<Config>::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        cell.send(&tx, Command::apply(0, id(2)).with_seq(1)).unwrap();
        let start = Arc::new(std::sync::Barrier::new(2));
        let producer = {
            let cell = cell.clone();
            let tx = tx.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                cell.send(&tx, Command::build_snapshot().with_seq(2)).unwrap();
            })
        };
        start.wait();
        let first = cell.take_next(&mut rx).unwrap();
        producer.join().unwrap();
        match first.payload {
            CommandPayload::Apply { since, upto } => {
                assert_eq!((since, upto, first.seq), (0, id(2), 1));
                let boundary = cell.take_next(&mut rx).unwrap();
                assert!(matches!(boundary.payload, CommandPayload::BuildSnapshot));
                assert!(boundary.apply_before.is_none());
            }
            CommandPayload::BuildSnapshot => {
                let before = first.apply_before.unwrap();
                assert_eq!((before.since, before.upto, before.seq), (0, id(2), 1));
            }
            _ => panic!("unexpected boundary"),
        }
        cell.send(&tx, Command::apply(3, id(4)).with_seq(3)).unwrap();
        assert_eq!(cell.take_next(&mut rx).unwrap(), Command::apply(3, id(4)).with_seq(3));
        assert!(cell.take_next(&mut rx).is_err());
    }
}

#[tokio::test]
async fn closed_core_before_notification_retains_the_actual_response_batch() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let (read_tx, mut reads) = mpsc::unbounded_channel();
    let (notify, notifications) = mpsc::unbounded_channel();
    let (snapshot_tx, _snapshots) = mpsc::unbounded_channel();
    let (mut handle, tasks) = Worker::spawn(
        Machine {
            dropped: dropped.clone(),
            last: None,
            snapshots: snapshot_tx,
        },
        Reader(read_tx),
        2,
        notify,
    );
    handle.send(Command::apply(0, id(4)).with_seq(7)).unwrap();
    let (start, end, reply) = reads.recv().await.unwrap();
    drop(notifications);
    reply.send((start..end).map(entry).collect()).unwrap();
    drop(handle);
    let (worker, _) = tasks.shutdown().await;
    assert!(worker.unwrap().storage_error().is_some());
    let retained = tasks.apply_batch.retained().unwrap();
    assert!(reads.try_recv().is_err());
    drop(tasks);
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    drop(retained);
    assert_eq!(dropped.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn unknown_response_delivery_unwind_retains_remaining_originals_and_a_delivery_marker() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let (read_tx, mut reads) = mpsc::unbounded_channel();
    let (notify, mut notifications) = mpsc::unbounded_channel();
    let (snapshot_tx, _snapshots) = mpsc::unbounded_channel();
    let (mut handle, tasks) = Worker::spawn(
        Machine {
            dropped: dropped.clone(),
            last: None,
            snapshots: snapshot_tx,
        },
        Reader(read_tx),
        2,
        notify,
    );
    handle.send(Command::apply(0, id(2)).with_seq(1)).unwrap();
    let (start, end, reply) = reads.recv().await.unwrap();
    reply.send((start..end).map(entry).collect()).unwrap();
    let Notify::StateMachine { command_result } = notifications.recv().await.unwrap() else {
        panic!("apply notification")
    };
    let Response::Apply { batch, consumed, .. } = command_result.result.unwrap() else {
        panic!("apply batch")
    };
    let delivery = batch.clone();
    let panic = tokio::spawn(async move {
        let (_metadata, _actual_moved_reply) = delivery.next().unwrap();
        let _ack = consumed;
        panic!("actual delivery task unwound after moving one reply");
    })
    .await
    .unwrap_err();
    assert!(panic.is_panic());
    assert_eq!(
        dropped.load(Ordering::Acquire),
        1,
        "the moved reply unwinds with its delivery task, not the retained cell"
    );
    assert!(batch.finish().is_err());
    assert!(batch.next().is_err());
    drop(handle);
    assert!(tasks.shutdown().await.0.is_some());
    let retained = batch.retained().unwrap();
    drop(tasks);
    drop(batch);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    drop(retained);
    assert_eq!(dropped.load(Ordering::Acquire), 2);
}
