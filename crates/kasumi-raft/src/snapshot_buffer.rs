//! Bounded snapshot transfer children. The retained owner, never an awaiting
//! future or a background reaper, owns every actual blocking-task handle.
use kasumi_store::{EncryptedSpool, SnapshotImage};
use kasumi_types::drain::{DrainReport, DrainResult};
use std::{
    collections::BTreeMap,
    future::Future,
    io::{self, Read, Seek, SeekFrom, Write},
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

const WORKSPACE: usize = 64 << 10;
// Two 64KiB encrypted-spool buffers, one transfer Vec, and the bounded
// freeze/hash workspace. The authentication slot overhead fits metadata.
const BUFFER_WORKSPACE: u64 = 4 * WORKSPACE as u64;
const CELL_METADATA: u64 = 16 << 10;
// Each admitted slot covers its receiving spool's separate allocation before
// acquire invokes the constructor; child custody retains the same owner charge.
const RECEIVING_BACKING: u64 = std::mem::size_of::<EncryptedSpool>() as u64;
pub const SNAPSHOT_BUFFER_SLOTS: usize = 32;

#[derive(Debug)]
enum Backing {
    Receiving(Box<EncryptedSpool>),
    Captured(SnapshotImage),
}
#[derive(Debug)]
enum Completion {
    Read { bytes: Vec<u8>, offset: usize },
    Write(usize),
    Flush,
}
#[derive(Debug)]
enum Kind {
    Read,
    Write { count: usize, digest: [u8; 32] },
    Flush,
}
#[derive(Debug)]
struct Pending {
    kind: Kind,
    task: tokio::task::JoinHandle<io::Result<Completion>>,
}
#[derive(Debug, Default)]
struct State {
    position: u64,
    pending: Option<Pending>,
    completion: Option<Completion>,
    shutdown_started: bool,
    shutdown_done: bool,
    released: bool,
    report: DrainReport,
}

/// There are exactly two polling roles: the exclusively borrowed buffer and
/// the owner's serialized drain. A cancelled waiter replaces only its own slot.
#[derive(Debug, Default)]
struct ChildWake(Mutex<[Option<Waker>; 2]>);
impl ChildWake {
    fn register(&self, role: usize, waker: &Waker) {
        let mut waiters = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if waiters[role]
            .as_ref()
            .is_none_or(|old| !old.will_wake(waker))
        {
            waiters[role] = Some(waker.clone());
        }
    }
}
impl Wake for ChildWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()));
        for waker in waiters.into_iter().flatten() {
            waker.wake();
        }
    }
}
#[derive(Debug)]
struct Cell {
    backing: Arc<Mutex<Option<Backing>>>,
    length: Arc<AtomicU64>,
    limit: u64,
    failed: Arc<AtomicBool>,
    state: Mutex<State>,
    wake: Arc<ChildWake>,
    #[cfg(test)]
    next_child: Mutex<Option<Arc<tests::ChildControl>>>,
}

/// A trusted installer reserves `required_bytes` from its node governor before
/// constructing this owner. Its fixed inventory covers transfer workspace and
/// child/handle metadata; encrypted extents retain their ScratchDisk charges.
pub struct SnapshotBufferOwner {
    id: uuid::Uuid,
    cells: Mutex<Box<[Option<Arc<Cell>>]>>,
    closed: AtomicBool,
    startup_closing: AtomicBool,
    failed: Arc<AtomicBool>,
    drain_gate: tokio::sync::Mutex<()>,
    startup: tokio::sync::Mutex<crate::startup_owner::StartupState>,
    #[cfg(test)]
    pub(crate) local_startup_gate: Mutex<Option<Arc<crate::startup_owner_tests::LocalStartupGate>>>,
    report: Mutex<DrainReport>,
    _charge: Arc<dyn Send + Sync>,
}
impl std::fmt::Debug for SnapshotBufferOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBufferOwner")
            .field("id", &self.id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
fn retained() -> &'static Mutex<BTreeMap<uuid::Uuid, Arc<SnapshotBufferOwner>>> {
    static OWNERS: OnceLock<Mutex<BTreeMap<uuid::Uuid, Arc<SnapshotBufferOwner>>>> =
        OnceLock::new();
    OWNERS.get_or_init(Default::default)
}
impl SnapshotBufferOwner {
    pub fn required_bytes(max_buffers: usize) -> anyhow::Result<u64> {
        anyhow::ensure!(
            max_buffers > 0 && max_buffers <= 4096,
            "snapshot buffer inventory outside supported bounds"
        );
        u64::try_from(max_buffers)?
            .checked_mul(BUFFER_WORKSPACE + CELL_METADATA + RECEIVING_BACKING)
            .and_then(|bytes| {
                bytes.checked_add(CELL_METADATA + crate::startup_owner::STARTUP_WORKSPACE)
            })
            .ok_or_else(|| anyhow::anyhow!("snapshot buffer inventory overflow"))
    }
    pub fn new(max_buffers: usize, charge: Arc<dyn Send + Sync>) -> anyhow::Result<Arc<Self>> {
        Self::required_bytes(max_buffers)?;
        let owner = Arc::new(Self {
            id: uuid::Uuid::new_v4(),
            cells: Mutex::new((0..max_buffers).map(|_| None).collect()),
            closed: AtomicBool::new(false),
            startup_closing: AtomicBool::new(false),
            failed: Arc::new(AtomicBool::new(false)),
            drain_gate: Default::default(),
            startup: Default::default(),
            #[cfg(test)]
            local_startup_gate: Default::default(),
            report: Default::default(),
            _charge: charge,
        });
        Ok(owner)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Arc<Self> {
        Self::new(SNAPSHOT_BUFFER_SLOTS, Arc::new(())).unwrap()
    }

    pub(crate) fn start<F>(
        self: &Arc<Self>,
        future: F,
    ) -> impl Future<Output = anyhow::Result<crate::startup_owner::StartedGroup>> + Send + '_
    where
        F: Future<Output = anyhow::Result<crate::startup_owner::StartedGroup>> + Send + 'static,
    {
        // Synchronous admission erases F before any caller awaits. A single
        // owner can never accumulate multiple prepared, charged allocations.
        let prepared = (|| {
            let mut startup = self
                .startup
                .try_lock()
                .map_err(|_| anyhow::anyhow!("Raft startup owner is already in use"))?;
            self.check_startup()?;
            let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
            anyhow::ensure!(
                registry
                    .get(&self.id)
                    .is_none_or(|owner| Arc::ptr_eq(owner, self)),
                "snapshot custody identity collision"
            );
            // install checks the concrete opening + cleanup sizes before boxing.
            // Registry custody exists before the first actual Opening poll.
            startup.install(future)?;
            registry.insert(self.id, self.clone());
            Ok(())
        })();
        self.claim_startup(prepared)
    }

    async fn claim_startup(
        self: &Arc<Self>,
        prepared: anyhow::Result<()>,
    ) -> anyhow::Result<crate::startup_owner::StartedGroup> {
        prepared?;
        // This non-generic future contains only the owner and admission result.
        let mut startup = self.startup.lock().await;
        let result = startup.claim(self).await;
        // A delivered group now owns startup custody. Actual snapshot cells,
        // if any, retain their original global enrollment independently.
        let cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
        if startup.can_release_custody() && cells.iter().all(Option::is_none) {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }

    pub(crate) fn record_startup_error(
        &self,
        error: anyhow::Error,
    ) -> kasumi_types::drain::DrainFailure {
        self.failed.store(true, Ordering::Release);
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        let unresolved = match error.downcast::<kasumi_types::drain::DrainFailure>() {
            Ok(failure) => {
                report.merge(&failure);
                (failure.completion() == kasumi_types::drain::DrainCompletion::Retained)
                    .then_some(failure)
            }
            Err(error) => {
                report.record("Raft startup", 0, error);
                None
            }
        };
        report
            .outcome(unresolved)
            .expect_err("startup failure was recorded")
    }

    pub(crate) fn record_startup_poll_panic(
        &self,
        error: crate::startup_owner::StartupPollPanic,
    ) -> kasumi_types::drain::DrainFailure {
        self.failed.store(true, Ordering::Release);
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        let issue = report.record("Raft startup poll panic", 0, error.into());
        report
            .outcome(Some(kasumi_types::drain::DrainFailure::retained(issue)))
            .expect_err("poll panic retains unresolved ownership")
    }

    #[cfg(test)]
    pub(crate) async fn install_cleanup_fixture<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = DrainResult> + Send + 'static,
    {
        self.startup.lock().await.install_cleanup_fixture(future);
        retained()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(self.id, self.clone());
    }

    pub(crate) fn check_startup(&self) -> io::Result<()> {
        if self.startup_closing.load(Ordering::Acquire) {
            return Err(io::Error::other("Raft startup admission is closed"));
        }
        self.check()
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            Err(io::Error::other("snapshot transfer admission is closed"))
        } else {
            Ok(())
        }
    }
    fn acquire(
        self: &Arc<Self>,
        backing: impl FnOnce() -> io::Result<Backing>,
        length: u64,
        limit: u64,
    ) -> io::Result<SnapshotBuffer> {
        let mut cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
        self.check()?;
        // Reclaim only abandoned cells whose exact child has already joined.
        // A running cell remains charged and consumes its original fixed slot.
        for slot in cells.iter_mut() {
            if let Some(cell) = slot {
                let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                if state.released {
                    let mut cx = Context::from_waker(Waker::noop());
                    let _ = cell.join(&mut state, &mut cx, 1);
                    if state.pending.is_none() {
                        self.report
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .merge_result(&state.report.complete());
                        drop(state);
                        *slot = None;
                    }
                }
            }
        }
        self.check()?;
        let slot = cells
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| io::Error::other("snapshot buffer inventory exhausted"))?;
        // Admission precedes file creation. Idle owners have no global custody;
        // the first actual cell installs it before any worker can be spawned.
        let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
        if registry
            .get(&self.id)
            .is_some_and(|owner| !Arc::ptr_eq(owner, self))
        {
            return Err(io::Error::other("snapshot custody identity collision"));
        }
        let cell = Arc::new(Cell {
            backing: Arc::new(Mutex::new(Some(backing()?))),
            length: Arc::new(AtomicU64::new(length)),
            limit,
            failed: self.failed.clone(),
            state: Default::default(),
            wake: Default::default(),
            #[cfg(test)]
            next_child: Default::default(),
        });
        *slot = Some(cell.clone());
        registry.entry(self.id).or_insert_with(|| self.clone());
        Ok(SnapshotBuffer {
            owner: self.clone(),
            cell,
        })
    }

    /// Stop new work and join every actual child, including abandoned buffer
    /// facades. Cancellation leaves the same handles, report and charge installed.
    pub async fn drain(&self) -> DrainResult {
        self.closed.store(true, Ordering::Release);
        self.drain_startup().await?;
        self.drain_buffers().await
    }

    /// Drain only a pending or unclaimed startup. An already delivered group
    /// keeps its buffer admission and is drained through its own shutdown API.
    /// Node shutdown can census these owners independently of startup callers.
    pub async fn drain_startup(&self) -> DrainResult {
        // Close delivery before waiting for a currently polled startup caller.
        // Claimed groups keep their independent buffer admission unchanged.
        self.startup_closing.store(true, Ordering::Release);
        let mut startup = self.startup.lock().await;
        if matches!(*startup, crate::startup_owner::StartupState::Delivered) {
            return Ok(());
        }
        self.closed.store(true, Ordering::Release);
        let unresolved = match startup.drain(self).await {
            Err(failure) => {
                self.report
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .merge(&failure);
                (failure.completion() == kasumi_types::drain::DrainCompletion::Retained)
                    .then_some(failure)
            }
            Ok(()) => None,
        };
        let buffers = self.drain_buffers().await;
        let result = {
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            report.merge_result(&buffers);
            report.outcome(unresolved)
        };
        if startup.can_release_custody() {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }

    // Startup error cleanup and a retained unclaimed group's shutdown must not
    // await the startup gate that currently owns their future.
    pub(crate) async fn drain_buffers(&self) -> DrainResult {
        self.closed.store(true, Ordering::Release);
        let _exclusive = self.drain_gate.lock().await;
        let result = std::future::poll_fn(|cx| {
            let mut all_ready = true;
            let mut cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            for slot in cells.iter_mut() {
                let Some(cell) = slot else { continue };
                let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                match cell.shutdown(&mut state, cx, 1, &self.failed) {
                    Poll::Pending => all_ready = false,
                    Poll::Ready(result) => {
                        report.merge_result(&result);
                        // No child can still use the backing after shutdown.
                        cell.backing
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .take();
                        drop(state);
                        *slot = None;
                    }
                }
            }
            if all_ready {
                Poll::Ready(report.complete())
            } else {
                Poll::Pending
            }
        })
        .await;
        // Internal cleanup may be running inside the retained startup future.
        // Only a non-running startup can release this global custody root.
        if self
            .startup
            .try_lock()
            .is_ok_and(|startup| startup.can_release_custody())
        {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }
}
trait MergeResult {
    fn merge_result(&mut self, result: &DrainResult);
}
impl MergeResult for DrainReport {
    fn merge_result(&mut self, result: &DrainResult) {
        if let Err(failure) = result {
            self.merge(failure);
        }
    }
}

struct FailureGuard {
    failed: Arc<AtomicBool>,
    returned: bool,
}
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if !self.returned {
            self.failed.store(true, Ordering::Release);
        }
    }
}
impl Cell {
    fn spawn(
        &self,
        state: &mut State,
        kind: Kind,
        failed: &Arc<AtomicBool>,
        work: impl FnOnce() -> io::Result<Completion> + Send + 'static,
    ) {
        let failed = failed.clone();
        #[cfg(test)]
        let control = self.next_child.lock().unwrap().take();
        let task = tokio::task::spawn_blocking(move || {
            let mut guard = FailureGuard {
                failed,
                returned: false,
            };
            #[cfg(test)]
            if let Some(control) = control {
                control.run()?;
            }
            let result = work();
            if result.is_err() {
                guard.failed.store(true, Ordering::Release);
            }
            guard.returned = true;
            drop(guard);
            result
        });
        state.pending = Some(Pending { kind, task });
    }
    fn join(&self, state: &mut State, cx: &mut Context<'_>, role: usize) -> Poll<()> {
        let Some(pending) = &mut state.pending else {
            return Poll::Ready(());
        };
        self.wake.register(role, cx.waker());
        let waker = Waker::from(self.wake.clone());
        let result = match Pin::new(&mut pending.task).poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        state.pending.take();
        match result {
            Ok(Ok(completion)) => {
                if let Completion::Write(count) = &completion {
                    state.position += *count as u64;
                }
                state.completion = Some(completion);
            }
            Ok(Err(error)) => {
                self.failed.store(true, Ordering::Release);
                state
                    .report
                    .record("snapshot blocking I/O", 0, error.into());
            }
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                state
                    .report
                    .record("snapshot blocking child", 0, error.into());
            }
        }
        Poll::Ready(())
    }
    fn flush(
        &self,
        state: &mut State,
        cx: &mut Context<'_>,
        role: usize,
        failed: &Arc<AtomicBool>,
    ) -> Poll<DrainResult> {
        if self.join(state, cx, role).is_pending() {
            return Poll::Pending;
        }
        if let Err(error) = state.report.complete() {
            return Poll::Ready(Err(error));
        }
        if matches!(state.completion.take(), Some(Completion::Flush)) {
            return Poll::Ready(Ok(()));
        }
        let backing = self.backing.clone();
        self.spawn(state, Kind::Flush, failed, move || {
            match backing.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
                Some(Backing::Receiving(spool)) => spool.flush()?,
                Some(Backing::Captured(_)) => {}
                None => return Err(io::Error::other("snapshot storage is closed")),
            }
            Ok(Completion::Flush)
        });
        if self.join(state, cx, role).is_pending() {
            return Poll::Pending;
        }
        state.completion.take();
        Poll::Ready(state.report.complete())
    }
    fn shutdown(
        &self,
        state: &mut State,
        cx: &mut Context<'_>,
        role: usize,
        failed: &Arc<AtomicBool>,
    ) -> Poll<DrainResult> {
        state.shutdown_started = true;
        if state.shutdown_done {
            return Poll::Ready(state.report.complete());
        }
        match self.flush(state, cx, role, failed) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.shutdown_done = true;
                Poll::Ready(result)
            }
        }
    }
}

/// One exclusively polled transfer facade; dropping it never drops an unjoined
/// handle. Its fixed owner slot remains charged until actual completion/drain.
#[derive(Debug)]
pub struct SnapshotBuffer {
    owner: Arc<SnapshotBufferOwner>,
    cell: Arc<Cell>,
}
impl SnapshotBuffer {
    pub fn new(
        disk: &Arc<kasumi_store::ScratchDisk>,
        limit: u64,
        owner: &Arc<SnapshotBufferOwner>,
    ) -> io::Result<Self> {
        owner.acquire(
            || {
                Ok(Backing::Receiving(Box::new(EncryptedSpool::new(
                    disk, limit,
                )?)))
            },
            0,
            limit,
        )
    }
    pub fn from_image(image: SnapshotImage, owner: &Arc<SnapshotBufferOwner>) -> io::Result<Self> {
        let length = image.len();
        owner.acquire(|| Ok(Backing::Captured(image)), length, length)
    }
    pub fn from_bytes(
        disk: &Arc<kasumi_store::ScratchDisk>,
        bytes: Vec<u8>,
        limit: u64,
        owner: &Arc<SnapshotBufferOwner>,
    ) -> io::Result<Self> {
        if bytes.len() as u64 > limit {
            return Err(io::Error::other("snapshot exceeds byte limit"));
        }
        owner.acquire(
            || {
                Ok(Backing::Captured(
                    SnapshotImage::from_bytes(disk, &bytes).map_err(io::Error::other)?,
                ))
            },
            bytes.len() as u64,
            limit,
        )
    }
    pub fn len(&self) -> u64 {
        self.cell.length.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub async fn drain(&mut self) -> DrainResult {
        std::future::poll_fn(|cx| {
            let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
            self.cell.shutdown(&mut state, cx, 0, &self.owner.failed)
        })
        .await
    }
    pub fn into_image(self) -> anyhow::Result<SnapshotImage> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            state.pending.is_none(),
            "snapshot transfer work has not drained"
        );
        state.report.complete()?;
        state.shutdown_started = true;
        state.shutdown_done = true;
        state.completion.take();
        let backing = self
            .cell
            .backing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| anyhow::anyhow!("snapshot storage is closed"))?;
        drop(state);
        match backing {
            Backing::Receiving(spool) => SnapshotImage::freeze(*spool),
            Backing::Captured(image) => Ok(image),
        }
    }
    pub(crate) fn image(&self) -> anyhow::Result<SnapshotImage> {
        match self
            .cell
            .backing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            Some(Backing::Captured(image)) => Ok(image.clone()),
            _ => anyhow::bail!("snapshot is not a captured image"),
        }
    }
}
impl Drop for SnapshotBuffer {
    fn drop(&mut self) {
        self.cell
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .released = true;
    }
}
fn check_open(state: &State) -> io::Result<()> {
    if state.shutdown_started {
        Err(io::Error::other("snapshot transfer is closing"))
    } else {
        state.report.complete().map_err(io::Error::other)
    }
}
impl AsyncRead for SnapshotBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let cell = &self.cell;
        let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        if state.pending.is_none() {
            self.owner.check()?;
        }
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| !matches!(pending.kind, Kind::Read))
            || state
                .completion
                .as_ref()
                .is_some_and(|value| !matches!(value, Completion::Read { .. }))
        {
            return Poll::Ready(Err(io::Error::other(
                "different snapshot operation pending",
            )));
        }
        if state.pending.is_none() && state.completion.is_none() {
            let backing = cell.backing.clone();
            let position = state.position;
            let count = buffer.remaining().min(WORKSPACE);
            cell.spawn(&mut state, Kind::Read, &self.owner.failed, move || {
                let mut bytes = vec![0; count];
                let count = match backing.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
                    Some(Backing::Receiving(spool)) => {
                        spool.seek(SeekFrom::Start(position))?;
                        spool.read(&mut bytes)?
                    }
                    Some(Backing::Captured(image)) => {
                        let mut reader = image.reader();
                        reader.seek(SeekFrom::Start(position))?;
                        reader.read(&mut bytes)?
                    }
                    None => return Err(io::Error::other("snapshot storage is closed")),
                };
                bytes.truncate(count);
                Ok(Completion::Read { bytes, offset: 0 })
            });
        }
        if cell.join(&mut state, cx, 0).is_pending() {
            return Poll::Pending;
        }
        state.report.complete().map_err(io::Error::other)?;
        let Some(Completion::Read { bytes, offset }) = state.completion.as_mut() else {
            unreachable!("read child outcome")
        };
        let count = (bytes.len() - *offset).min(buffer.remaining());
        buffer.put_slice(&bytes[*offset..*offset + count]);
        *offset += count;
        let done = *offset == bytes.len();
        state.position += count as u64;
        if done {
            state.completion.take();
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for SnapshotBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        use sha2::Digest;
        let cell = &self.cell;
        let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        if state.pending.is_none() {
            self.owner.check()?;
        }
        if state.completion.is_some() {
            return Poll::Ready(Err(io::Error::other(
                "different snapshot operation pending",
            )));
        }
        if bytes.is_empty() && state.pending.is_none() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(WORKSPACE);
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes[..count]).into();
        if let Some(pending) = &state.pending {
            if !matches!(&pending.kind, Kind::Write { count: original, digest: original_digest } if *original == count && *original_digest == digest)
            {
                return Poll::Ready(Err(io::Error::other(
                    "different snapshot operation pending",
                )));
            }
        } else {
            if state
                .position
                .checked_add(count as u64)
                .is_none_or(|end| end > cell.limit)
            {
                return Poll::Ready(Err(io::Error::other("snapshot exceeds byte limit")));
            }
            let bytes = bytes[..count].to_vec();
            let backing = cell.backing.clone();
            let position = state.position;
            let length = cell.length.clone();
            cell.spawn(
                &mut state,
                Kind::Write { count, digest },
                &self.owner.failed,
                move || {
                    let mut backing = backing.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(Backing::Receiving(spool)) = backing.as_mut() else {
                        return Err(io::Error::other("snapshot is not writable"));
                    };
                    spool.seek(SeekFrom::Start(position))?;
                    let count = spool.write(&bytes)?;
                    length.store(spool.len(), Ordering::Release);
                    Ok(Completion::Write(count))
                },
            );
        }
        if cell.join(&mut state, cx, 0).is_pending() {
            return Poll::Pending;
        }
        state.report.complete().map_err(io::Error::other)?;
        let Some(Completion::Write(count)) = state.completion.take() else {
            unreachable!("write child outcome")
        };
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.shutdown_done {
            return Poll::Ready(state.report.complete().map_err(io::Error::other));
        }
        self.cell
            .flush(&mut state, cx, 0, &self.owner.failed)
            .map(|result| result.map_err(io::Error::other))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        self.cell
            .shutdown(&mut state, cx, 0, &self.owner.failed)
            .map(|result| result.map_err(io::Error::other))
    }
}
impl AsyncSeek for SnapshotBuffer {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        self.owner.check()?;
        if state.pending.is_some() || state.completion.is_some() {
            return Err(io::Error::other("snapshot operation still pending"));
        }
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(state.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.len()) {
            return Err(io::Error::other("snapshot seek outside existing stream"));
        }
        state.position = position as u64;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self
            .cell
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .position))
    }
}

#[cfg(test)]
#[path = "snapshot_buffer_tests.rs"]
mod tests;
