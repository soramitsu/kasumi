//! Actual Worker and snapshot tasks with controlled storage entry/exit gates.
use std::future::Future;
use std::io::Cursor;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::core::sm::tasks::Task;
use crate::core::sm::tasks::TaskError;
use crate::core::sm::tasks::Tasks;
use crate::core::sm::worker::Worker;
use crate::core::sm::Command;
use crate::error::ShutdownTaskError;
use crate::storage::RaftStateMachine;
use crate::type_config::TypeConfigExt;
use crate::LogId;
use crate::OptionalSend;
use crate::RaftSnapshotBuilder;
use crate::RaftTypeConfig;
use crate::Snapshot;
use crate::SnapshotMeta;
use crate::StorageError;
use crate::StorageIOError;
use crate::StoredMembership;
use crate::TokioRuntime;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct TestConfig;
impl RaftTypeConfig for TestConfig {
    type D = ();
    type R = ();
    type NodeId = u64;
    type Node = ();
    type Entry = crate::Entry<Self>;
    type SnapshotData = Cursor<Vec<u8>>;
    type AsyncRuntime = TokioRuntime;
    type Responder = crate::impls::OneshotResponder<Self>;
}

#[derive(Clone, Copy)]
enum Exit {
    Normal,
    Panic,
    Storage,
}

struct Gate {
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    exit: Exit,
}
impl Gate {
    fn new(exit: Exit) -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, entry) = oneshot::channel();
        let (release, waiting) = oneshot::channel();
        (
            Self {
                entered: Some(entered),
                release: waiting,
                exit,
            },
            entry,
            release,
        )
    }
    async fn run(&mut self) -> Result<(), StorageError<u64>> {
        self.entered.take().unwrap().send(()).unwrap();
        let _ = (&mut self.release).await;
        match self.exit {
            Exit::Normal => Ok(()),
            Exit::Panic => panic!("controlled actual storage task panic"),
            Exit::Storage => {
                Err(StorageIOError::read_state_machine(anyerror::AnyError::error("retained storage failure")).into())
            }
        }
    }
}

#[derive(Default)]
struct Counts {
    active: AtomicUsize,
    max_active: AtomicUsize,
    started: AtomicUsize,
    dropped: AtomicUsize,
}
struct Builder {
    gate: Option<Gate>,
    counts: Arc<Counts>,
}
impl Drop for Builder {
    fn drop(&mut self) {
        self.counts.active.fetch_sub(1, Ordering::AcqRel);
        self.counts.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
impl RaftSnapshotBuilder<TestConfig> for Builder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TestConfig>, StorageError<u64>> {
        if let Some(gate) = &mut self.gate {
            gate.run().await?;
        }
        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id: None,
                last_membership: StoredMembership::default(),
                snapshot_id: "retained-test".into(),
            },
            snapshot: Box::new(Cursor::new(vec![])),
        })
    }
}
struct Machine {
    receive: Option<Gate>,
    builder: Option<Gate>,
    counts: Arc<Counts>,
    dropped: Arc<AtomicBool>,
}
impl Drop for Machine {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
#[cfg(not(feature = "storage-v2"))]
impl crate::storage::v2::sealed::Sealed for Machine {}
impl RaftStateMachine<TestConfig> for Machine {
    type SnapshotBuilder = Builder;
    async fn applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, ()>), StorageError<u64>> {
        Ok((None, StoredMembership::default()))
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<()>, StorageError<u64>>
    where
        I: IntoIterator<Item = crate::Entry<TestConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        Ok(entries.into_iter().map(|_| ()).collect())
    }
    async fn get_snapshot_builder(&mut self) -> Builder {
        let active = self.counts.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.counts.max_active.fetch_max(active, Ordering::AcqRel);
        self.counts.started.fetch_add(1, Ordering::AcqRel);
        Builder {
            gate: self.builder.take(),
            counts: self.counts.clone(),
        }
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        if let Some(gate) = &mut self.receive {
            gate.run().await?;
        }
        Ok(Box::new(Cursor::new(vec![])))
    }
    async fn install_snapshot(
        &mut self,
        _meta: &SnapshotMeta<u64, ()>,
        _snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        Ok(())
    }
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TestConfig>>, StorageError<u64>> {
        Ok(None)
    }
}

fn same_original(left: &TaskError<TestConfig>, right: &TaskError<TestConfig>) {
    match (left, right) {
        (ShutdownTaskError::Join(a), ShutdownTaskError::Join(b)) => assert!(Arc::ptr_eq(a, b)),
        (ShutdownTaskError::Storage(a), ShutdownTaskError::Storage(b)) => assert!(Arc::ptr_eq(a, b)),
        _ => panic!("terminal error changed kind"),
    }
}
async fn entered(entry: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), entry).await.unwrap().unwrap();
}
async fn cancel_after_worker_join(tasks: &Tasks<TestConfig>) {
    let mut draining = Box::pin(tasks.shutdown());
    tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| {
            assert!(
                draining.as_mut().poll(cx).is_pending(),
                "held snapshot must still be owned"
            );
            if tasks.worker.try_lock().is_ok_and(|state| matches!(*state, Task::Done(_))) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    drop(draining);
}

#[tokio::test]
async fn cancelled_worker_join_retains_actual_panic_and_storage_failure() {
    for exit in [Exit::Panic, Exit::Storage] {
        let (receive, entry, release) = Gate::new(exit);
        let dropped = Arc::new(AtomicBool::new(false));
        let machine = Machine {
            receive: Some(receive),
            builder: None,
            counts: Arc::default(),
            dropped: dropped.clone(),
        };
        let (mut handle, tasks) = Worker::spawn(machine, mpsc::unbounded_channel().0);
        let (tx, _rx) = TestConfig::oneshot();
        handle.send(Command::begin_receiving_snapshot(tx)).unwrap();
        entered(entry).await;
        drop(handle);
        let mut first = Box::pin(tasks.shutdown());
        let mut concurrent = Box::pin(tasks.shutdown());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            assert!(concurrent.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        drop(concurrent);
        assert!(!dropped.load(Ordering::Acquire));
        release.send(()).unwrap();
        let (worker, snapshot) = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown()).await.unwrap();
        let error = worker.unwrap();
        assert!(snapshot.is_none());
        assert!(dropped.load(Ordering::Acquire));
        match exit {
            Exit::Panic => assert!(error.join_error().unwrap().is_panic()),
            Exit::Storage => assert!(error.storage_error().unwrap().to_string().contains("retained storage failure")),
            Exit::Normal => unreachable!(),
        }
        let (again, _) = tasks.shutdown().await;
        same_original(&error, &again.unwrap());
    }
}

#[tokio::test]
async fn worker_completion_never_discards_held_snapshot_or_either_failure() {
    for worker_panics in [false, true] {
        for snapshot_exit in [Exit::Normal, Exit::Panic, Exit::Storage] {
            let (builder, entry, release) = Gate::new(snapshot_exit);
            let (receive, worker_entry, worker_release) = Gate::new(Exit::Panic);
            let counts = Arc::<Counts>::default();
            let dropped = Arc::new(AtomicBool::new(false));
            let machine = Machine {
                receive: Some(receive),
                builder: Some(builder),
                counts: counts.clone(),
                dropped: dropped.clone(),
            };
            let (mut handle, tasks) = Worker::spawn(machine, mpsc::unbounded_channel().0);
            handle.send(Command::build_snapshot()).unwrap();
            entered(entry).await;
            if worker_panics {
                let (tx, _rx) = TestConfig::oneshot();
                handle.send(Command::begin_receiving_snapshot(tx)).unwrap();
                entered(worker_entry).await;
                worker_release.send(()).unwrap();
            }
            drop(handle);
            cancel_after_worker_join(&tasks).await;
            cancel_after_worker_join(&tasks).await;
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(counts.active.load(Ordering::Acquire), 1);
            assert_eq!(counts.dropped.load(Ordering::Acquire), 0);
            release.send(()).unwrap();
            let (worker, snapshot) = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown()).await.unwrap();
            assert_eq!(worker.is_some(), worker_panics);
            if let Some(error) = &worker {
                assert!(error.join_error().unwrap().is_panic());
            }
            match snapshot_exit {
                Exit::Normal => assert!(snapshot.is_none()),
                Exit::Panic => assert!(snapshot.as_ref().unwrap().join_error().unwrap().is_panic()),
                Exit::Storage => assert!(snapshot.as_ref().unwrap().storage_error().is_some()),
            }
            assert_eq!(counts.active.load(Ordering::Acquire), 0);
            assert_eq!(counts.dropped.load(Ordering::Acquire), 1);
            let (worker_again, snapshot_again) = tasks.shutdown().await;
            if let Some(error) = &worker {
                same_original(error, worker_again.as_ref().unwrap());
            }
            if let Some(error) = &snapshot {
                same_original(error, snapshot_again.as_ref().unwrap());
            }
            if let (Some(worker), Some(snapshot)) = (&worker, &snapshot) {
                if let (Some(worker), Some(snapshot)) = (worker.join_error(), snapshot.join_error()) {
                    assert!(!Arc::ptr_eq(worker, snapshot));
                }
            }
        }
    }
}

#[tokio::test]
async fn live_worker_observes_snapshot_failure_without_detached_monitor() {
    for exit in [Exit::Panic, Exit::Storage] {
        let (builder, entry, release) = Gate::new(exit);
        let dropped = Arc::new(AtomicBool::new(false));
        let machine = Machine {
            receive: None,
            builder: Some(builder),
            counts: Arc::default(),
            dropped: dropped.clone(),
        };
        let (mut handle, tasks) = Worker::spawn(machine, mpsc::unbounded_channel().0);
        handle.send(Command::build_snapshot()).unwrap();
        entered(entry).await;
        release.send(()).unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(5), handle.stopped()).await.unwrap().unwrap_err();
        assert!(dropped.load(Ordering::Acquire));
        let (worker, snapshot) = tasks.shutdown().await;
        same_original(&observed, worker.as_ref().unwrap());
        same_original(&observed, snapshot.as_ref().unwrap());
    }
}

#[tokio::test]
async fn successful_snapshot_history_reuses_one_joined_builder_cell() {
    let counts = Arc::<Counts>::default();
    let machine = Machine {
        receive: None,
        builder: None,
        counts: counts.clone(),
        dropped: Arc::default(),
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (mut handle, tasks) = Worker::spawn(machine, tx);
    for _ in 0..32 {
        handle.send(Command::build_snapshot()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().is_some());
    }
    drop(handle);
    let (worker, snapshot) = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown()).await.unwrap();
    assert!(worker.is_none());
    assert!(snapshot.is_none());
    assert_eq!(counts.started.load(Ordering::Acquire), 32);
    assert_eq!(counts.dropped.load(Ordering::Acquire), 32);
    assert_eq!(counts.max_active.load(Ordering::Acquire), 1);
    assert_eq!(counts.active.load(Ordering::Acquire), 0);
    assert!(matches!(*tasks.snapshot.lock().await, Some(Task::Done(Ok(())))));
}
