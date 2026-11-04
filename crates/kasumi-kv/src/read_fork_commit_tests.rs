use super::*;
use crate::group::{GroupFile, TransactionReserveError, TransactionSpacePlan};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::ffi::OsStr;
use std::sync::mpsc;
use std::time::Duration;

struct CommitPause {
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

struct CommitGate {
    inner: InMemoryGroup,
    pause: Mutex<Option<CommitPause>>,
}

impl SegmentGroupBackend for CommitGate {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError> {
        self.inner.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.inner.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.inner.cancel_transaction(group_id, batch_seq)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.inner.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.inner.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.inner.sync_root()?;
        let pause = self.pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.entered.send(()).unwrap();
            pause.resume.recv().unwrap();
        }
        Ok(())
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.inner.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.inner.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.inner.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.inner.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.inner.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.inner.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.inner.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.inner.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.inner.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.inner.close()
    }
}

#[test]
fn selected_snapshot_fork_progresses_while_a_real_commit_waits_for_durability() {
    let admission = CountedAdmission::new();
    let backend = Arc::new(CommitGate {
        inner: InMemoryGroup::new(),
        pause: Mutex::new(None),
    });
    let opening = opening_with_backend(&admission, Box::new(backend.clone()));
    let database = opening.database().unwrap();
    let parent = Arc::new(database.begin_read().unwrap());
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"new-a".as_slice())
        .unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    *backend.pause.lock().unwrap() = Some(CommitPause {
        entered: entered_tx,
        resume: resume_rx,
    });
    let commit = std::thread::spawn(move || writer.commit());
    let entered = entered_rx.recv_timeout(Duration::from_secs(10));
    if entered.is_err() {
        let _ = resume_tx.send(());
        let _ = commit.join();
        panic!("native commit did not reach its durability gate: {entered:?}");
    }
    let baseline = admission.census();
    let worker_parent = parent.clone();
    let (fork_tx, fork_rx) = mpsc::channel();
    let fork = std::thread::spawn(move || fork_tx.send(worker_parent.fork()).unwrap());
    // A successful fork owns only the immutable selected root. It must not
    // wait for the unrelated writer's native durability callback to return.
    let child = fork_rx.recv_timeout(Duration::from_secs(10));
    let before_release = child
        .as_ref()
        .ok()
        .and_then(|child| child.as_ref().ok())
        .map(|child| (child.generation(), admission.census()));
    // Always release and join the writer, including on a progress regression.
    resume_tx.send(()).unwrap();
    commit.join().unwrap().unwrap();
    fork.join().unwrap();
    let child = child.expect("fork waited behind disk commit").unwrap();
    assert_eq!(
        before_release,
        Some((
            parent.generation(),
            (baseline.0 + SnapshotHandle::CHARGE_BYTES, baseline.1 + 1)
        ))
    );
    assert_eq!(
        child
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    let current = database.begin_read().unwrap();
    assert!(current.generation() > child.generation());
    assert_eq!(
        current
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"new-a"
    );
    drop(current);
    let with_child = admission.census();
    drop(child);
    assert_eq!(
        admission.census(),
        (
            with_child.0 - SnapshotHandle::CHARGE_BYTES,
            with_child.1 - 1
        )
    );
    drop(parent);
    finish(opening, &admission);
}
