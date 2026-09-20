//! Real Raft ownership cells and actual held I/O children; the consensus core is
//! completed in this fixture, so these do not replace cluster snapshot tests.
use std::future::Future;
use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch, Mutex};

use super::core_state::CoreState;
use super::raft_inner::RaftInner;
use super::Raft;
use crate::config::RuntimeConfig;
use crate::core::TickHandle;
use crate::error::Fatal;
use crate::metrics::{RaftDataMetrics, RaftServerMetrics};
use crate::network::snapshot_transport::{Chunked, SnapshotTransport, Streaming};
use crate::raft::InstallSnapshotRequest;
use crate::{
    Config, RaftMetrics, RaftTypeConfig, SnapshotMeta, StoredMembership, TokioRuntime, Vote,
};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct TestConfig;
impl RaftTypeConfig for TestConfig {
    type D = ();
    type R = ();
    type NodeId = u64;
    type Node = ();
    type Entry = crate::Entry<Self>;
    type SnapshotData = Data;
    type AsyncRuntime = TokioRuntime;
    type Responder = crate::impls::OneshotResponder<Self>;
}

#[derive(Debug)]
struct Data {
    bytes: Cursor<Vec<u8>>,
    child: Option<tokio::task::JoinHandle<io::Result<()>>>,
    dropped: Arc<AtomicBool>,
    fail_write: bool,
    panic_close: bool,
}
impl Drop for Data {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
impl AsyncRead for Data {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.bytes).poll_read(cx, buf)
    }
}
impl AsyncSeek for Data {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.bytes).start_seek(position)
    }
    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.bytes).poll_complete(cx)
    }
}
impl AsyncWrite for Data {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail_write {
            return Poll::Ready(Err(io::Error::other("original incoming write failure")));
        }
        Pin::new(&mut self.bytes).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(!self.panic_close, "actual incoming shutdown poll panic");
        let Some(child) = self.child.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(child).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.child = None;
                Poll::Ready(result.unwrap_or_else(|error| Err(io::Error::other(error))))
            }
        }
    }
}

fn raft(streaming: Option<Streaming<TestConfig>>) -> Raft<TestConfig> {
    let config = Arc::new(Config::default());
    Raft {
        inner: Arc::new(RaftInner {
            id: 1,
            runtime_config: Arc::new(RuntimeConfig::new(&config)),
            membership_observer: Arc::default(),
            config,
            tick_handle: TickHandle::retain_test_task(tokio::spawn(async {})),
            state_machine_tasks: crate::core::sm::tasks::Tasks::completed_test_tasks(),
            replication_tasks: Arc::new(crate::replication::tasks::Registry::new(4)),
            auxiliary_tasks: Arc::new(crate::core::auxiliary::Registry::new(2)),
            tx_api: mpsc::unbounded_channel().0,
            tx_notify: mpsc::unbounded_channel().0,
            rx_metrics: watch::channel(RaftMetrics::new_initial(1)).1,
            rx_data_metrics: watch::channel(RaftDataMetrics::default()).1,
            rx_server_metrics: watch::channel(RaftServerMetrics::default()).1,
            tx_shutdown: Mutex::new(None),
            core_state: Mutex::new(CoreState::Running(tokio::spawn(async {
                Err(Fatal::Stopped)
            }))),
            snapshot: Mutex::new(streaming),
        }),
    }
}

fn request(done: bool) -> InstallSnapshotRequest<TestConfig> {
    InstallSnapshotRequest {
        vote: Vote::new(1, 1),
        meta: SnapshotMeta {
            snapshot_id: "stream".into(),
            last_log_id: None,
            last_membership: StoredMembership::default(),
        },
        offset: 0,
        data: vec![1, 2, 3],
        done,
    }
}

fn stream(
    panic_child: bool,
    fail_write: bool,
) -> (
    Streaming<TestConfig>,
    oneshot::Sender<()>,
    Arc<AtomicBool>,
    tokio::task::Id,
) {
    let (release, waiting) = oneshot::channel();
    let child = tokio::spawn(async move {
        let _ = waiting.await;
        assert!(!panic_child, "actual incoming I/O child panic");
        Ok(())
    });
    let id = child.id();
    let dropped = Arc::new(AtomicBool::new(false));
    (
        Streaming::new(
            "stream".into(),
            Box::new(Data {
                bytes: Cursor::new(vec![]),
                child: Some(child),
                dropped: dropped.clone(),
                fail_write,
                panic_close: false,
            }),
        ),
        release,
        dropped,
        id,
    )
}

#[tokio::test]
async fn cancelled_raft_shutdown_keeps_incoming_owner_until_actual_child_joins() {
    let (stream, release, dropped, _) = stream(false, false);
    let raft = raft(Some(stream));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), raft.shutdown())
            .await
            .is_err()
    );
    assert!(!dropped.load(Ordering::Acquire));
    assert!(raft.inner.snapshot.lock().await.is_some());
    release.send(()).unwrap();
    raft.shutdown().await.unwrap();
    assert!(dropped.load(Ordering::Acquire));
    assert!(raft.inner.snapshot.lock().await.is_none());
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn receive_and_close_failures_retain_independent_original_errors_and_owner() {
    let (mut stream, release, dropped, task_id) = stream(true, true);
    stream.receive(request(false)).await.unwrap_err();
    let receive = stream.shutdown_error().unwrap();
    let raft = raft(Some(stream));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), raft.shutdown())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    let first = raft.shutdown().await.unwrap_err();
    let errors = first.incoming_snapshot().unwrap();
    assert!(Arc::ptr_eq(
        receive.receive.as_ref().unwrap(),
        errors.receive.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        receive.receive_io.as_ref().unwrap(),
        errors.receive_io.as_ref().unwrap()
    ));
    let original = errors
        .close_io
        .as_ref()
        .unwrap()
        .get_ref()
        .unwrap()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(original.is_panic());
    assert_eq!(original.id(), task_id);
    let again = raft.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        errors.close.as_ref().unwrap(),
        again.incoming_snapshot().unwrap().close.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        errors.close_io.as_ref().unwrap(),
        again
            .incoming_snapshot()
            .unwrap()
            .close_io
            .as_ref()
            .unwrap()
    ));
    assert!(!dropped.load(Ordering::Acquire));
    assert!(raft.inner.snapshot.lock().await.is_some());
}

#[tokio::test]
async fn cancelled_final_chunk_keeps_stream_until_successful_close_then_transfers_data() {
    let (stream, release, dropped, _) = stream(false, false);
    let raft = raft(None);
    let mut cell = Some(stream);
    assert!(tokio::time::timeout(
        Duration::from_millis(20),
        Chunked::receive_snapshot(&mut cell, &raft, request(true))
    )
    .await
    .is_err());
    assert!(cell.is_some());
    assert!(!dropped.load(Ordering::Acquire));
    release.send(()).unwrap();
    let snapshot = Chunked::receive_snapshot(&mut cell, &raft, request(true))
        .await
        .unwrap()
        .unwrap();
    assert!(cell.is_none());
    assert_eq!(snapshot.snapshot.bytes.get_ref(), &[1, 2, 3]);
    assert!(!dropped.load(Ordering::Acquire));
    drop(snapshot);
    assert!(dropped.load(Ordering::Acquire));
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_stream_cannot_be_overwritten_by_replacement() {
    let (mut stream, release, dropped, _) = stream(false, true);
    stream.receive(request(false)).await.unwrap_err();
    let original = stream.shutdown_error().unwrap();
    let raft = raft(None);
    let mut cell = Some(stream);
    let mut next = request(false);
    next.meta.snapshot_id = "replacement".into();
    release.send(()).unwrap();
    Chunked::receive_snapshot(&mut cell, &raft, next)
        .await
        .unwrap_err();
    assert!(!dropped.load(Ordering::Acquire));
    assert_eq!(cell.as_ref().unwrap().snapshot_id(), "stream");
    assert!(Arc::ptr_eq(
        original.receive_io.as_ref().unwrap(),
        cell.as_ref()
            .unwrap()
            .shutdown_error()
            .unwrap()
            .receive_io
            .as_ref()
            .unwrap()
    ));
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn unwound_data_poll_retains_uncertain_owner_without_polling_it_again() {
    let dropped = Arc::new(AtomicBool::new(false));
    let stream = Streaming::new(
        "stream".into(),
        Box::new(Data {
            bytes: Cursor::new(vec![]),
            child: None,
            dropped: dropped.clone(),
            fail_write: false,
            panic_close: true,
        }),
    );
    let raft = raft(Some(stream));
    let calling = raft.clone();
    let waiter = tokio::spawn(async move { calling.shutdown().await });
    assert!(waiter.await.unwrap_err().is_panic());
    let error = raft.shutdown().await.unwrap_err();
    assert!(error.incoming_snapshot().unwrap().poll_panicked);
    assert!(!dropped.load(Ordering::Acquire));
    assert!(raft.inner.snapshot.lock().await.is_some());
}

#[tokio::test]
async fn retained_failure_notifies_live_core_exactly_once() {
    let (mut stream, release, _, _) = stream(false, true);
    stream.receive(request(false)).await.unwrap_err();
    release.send(()).unwrap();
    let mut cell = Some(stream);
    let (tx, mut rx) = mpsc::unbounded_channel();
    drop(super::IncomingSnapshotGuard {
        streaming: &mut cell,
        notifications: &tx,
    });
    assert!(matches!(
        rx.try_recv().unwrap(),
        crate::core::notify::Notify::IncomingSnapshotFailed {
            error: Fatal::StorageError(_)
        }
    ));
    drop(super::IncomingSnapshotGuard {
        streaming: &mut cell,
        notifications: &tx,
    });
    assert!(rx.try_recv().is_err());
    cell.as_mut().unwrap().close().await;
}

#[tokio::test]
async fn unwound_incoming_rpc_notifies_live_core_and_preserves_owner() {
    let dropped = Arc::new(AtomicBool::new(false));
    let stream = Streaming::new(
        "stream".into(),
        Box::new(Data {
            bytes: Cursor::new(vec![]),
            child: None,
            dropped: dropped.clone(),
            fail_write: false,
            panic_close: true,
        }),
    );
    let mut raft = raft(Some(stream));
    let (tx, mut rx) = mpsc::unbounded_channel();
    Arc::get_mut(&mut raft.inner).unwrap().tx_notify = tx;
    let calling = raft.clone();
    let caller = tokio::spawn(async move {
        let mut cell = calling.inner.snapshot.lock().await;
        let guard = super::IncomingSnapshotGuard {
            streaming: &mut cell,
            notifications: &calling.inner.tx_notify,
        };
        Chunked::receive_snapshot(guard.streaming, &calling, request(true)).await
    });
    assert!(caller.await.unwrap_err().is_panic());
    assert!(matches!(
        rx.try_recv().unwrap(),
        crate::core::notify::Notify::IncomingSnapshotFailed {
            error: Fatal::Panicked
        }
    ));
    assert!(rx.try_recv().is_err());
    assert!(!dropped.load(Ordering::Acquire));
    assert!(
        raft.shutdown()
            .await
            .unwrap_err()
            .incoming_snapshot()
            .unwrap()
            .poll_panicked
    );
}

#[tokio::test]
async fn premature_data_transfer_returns_same_pending_owner_without_unwinding() {
    let (stream, release, dropped, _) = stream(false, false);
    let mut owner = match stream.into_snapshot_data() {
        Err(owner) => owner,
        Ok(_) => panic!("pending data must not transfer"),
    };
    assert!(!dropped.load(Ordering::Acquire));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), owner.close())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    owner.close().await;
    let data = match owner.into_snapshot_data() {
        Ok(data) => data,
        Err(_) => panic!("joined successful data must transfer"),
    };
    assert!(!dropped.load(Ordering::Acquire));
    drop(data);
    assert!(dropped.load(Ordering::Acquire));
}
