// Include as disk_state::tests::publication_failures. The fault observer and
// in-memory disk are test-fixture memory, outside the native admission ledger.
use super::*;

struct PublicationGate {
    inner: Arc<Admission>,
    deny_workspace: AtomicBool,
    denied: AtomicUsize,
}

impl StorageAdmission for PublicationGate {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.deny_workspace.load(Ordering::Acquire) {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }

    fn reserve_growth(&self, before: u64, after: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(before, after)
    }

    fn settle_growth(&self, bytes: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(bytes)
    }

    fn owner_failed(&self) {
        self.inner.owner_failed();
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for PublicationGate {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        if self.deny_workspace.load(Ordering::Acquire) {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

#[derive(Clone, Copy)]
enum AfterPublication {
    DenyWorkspace,
    FailRead,
}

#[derive(Clone, Copy, Debug)]
struct PublishedStage {
    superblock_generation: u64,
    directory: DirectoryCommit,
    mirrored: bool,
    creates: usize,
}

#[derive(Clone, Copy, Debug)]
struct FailedRead {
    file: GroupFile,
    at: u64,
    len: usize,
}

struct PublicationBoundary {
    group: InMemoryGroup,
    admission: Arc<PublicationGate>,
    action: AfterPublication,
    armed: AtomicBool,
    root_syncs: AtomicUsize,
    creates: AtomicUsize,
    post_publication_reads: AtomicUsize,
    fail_read: AtomicBool,
    published: Mutex<Option<PublishedStage>>,
    failed_read: Mutex<Option<FailedRead>>,
}

impl PublicationBoundary {
    fn arm(&self) {
        assert!(!self.armed.swap(true, Ordering::AcqRel));
        assert!(self.published.lock().unwrap().is_none());
        self.root_syncs.store(0, Ordering::Release);
    }
}

impl SegmentGroupBackend for PublicationBoundary {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }

    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }

    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()?;
        if self.armed.load(Ordering::Acquire)
            && self.root_syncs.fetch_add(1, Ordering::AcqRel) + 1 == 2
        {
            // Observe the underlying backend directly: its extra observation
            // sync cannot recurse through this hook or consume the read fault.
            let RootSelection::Selected {
                superblock,
                mirrored,
                ..
            } = select_root(&self.group).unwrap()
            else {
                panic!("publication selected no root");
            };
            *self.published.lock().unwrap() = Some(PublishedStage {
                superblock_generation: superblock.generation(),
                directory: superblock.directory().expect("published directory"),
                mirrored,
                creates: self.creates.load(Ordering::Acquire),
            });
            self.armed.store(false, Ordering::Release);
            match self.action {
                AfterPublication::DenyWorkspace => {
                    self.admission.deny_workspace.store(true, Ordering::Release);
                }
                AfterPublication::FailRead => self.fail_read.store(true, Ordering::Release),
            }
        }
        Ok(())
    }

    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }

    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }

    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.creates.fetch_add(1, Ordering::AcqRel);
        self.group.create(file)
    }

    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }

    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.published.lock().unwrap().is_some() {
            self.post_publication_reads.fetch_add(1, Ordering::AcqRel);
        }
        if self.fail_read.swap(false, Ordering::AcqRel) {
            *self.failed_read.lock().unwrap() = Some(FailedRead {
                file,
                at,
                len: out.len(),
            });
            return Err(io::Error::other("publication proof read failed"));
        }
        self.group.read(file, at, out)
    }

    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }

    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.group.set_len(file, len)
    }

    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }

    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }

    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }

    fn close(&self) -> BackendCloseOutcome {
        self.group.close()
    }
}

fn fixture(action: AfterPublication) -> (DiskState, Arc<PublicationBoundary>) {
    let admission = Arc::new(PublicationGate {
        inner: Admission::new(16 << 20),
        deny_workspace: AtomicBool::new(false),
        denied: AtomicUsize::new(0),
    });
    let backend = Arc::new(PublicationBoundary {
        group: InMemoryGroup::new(),
        admission: admission.clone(),
        action,
        armed: AtomicBool::new(false),
        root_syncs: AtomicUsize::new(0),
        creates: AtomicUsize::new(0),
        post_publication_reads: AtomicUsize::new(0),
        fail_read: AtomicBool::new(false),
        published: Mutex::new(None),
        failed_read: Mutex::new(None),
    });
    let mut state = DiskState::create(backend.clone(), admission, GROUP, LARGE_CACHE).unwrap();
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; 8192]),
            Operation::put("accounts", b"b", vec![2; 8192]),
            Operation::put("accounts", b"hot", vec![3; 8192]),
        ])
        .unwrap();
    assert!(warm_all(&mut state).fully_resident);
    (state, backend)
}

fn stage(state: &DiskState, backend: &PublicationBoundary) -> PublishedStage {
    let root = state.owner.lock().unwrap();
    PublishedStage {
        superblock_generation: root.generation(),
        directory: root.directory().unwrap(),
        mirrored: true,
        creates: backend.creates.load(Ordering::Acquire),
    }
}

fn assert_commit_boundary(
    state: &DiskState,
    backend: &PublicationBoundary,
    before: PublishedStage,
) -> PublishedStage {
    let published = backend.published.lock().unwrap().unwrap();
    assert!(published.mirrored);
    assert!(!backend.armed.load(Ordering::Acquire));
    assert_eq!(backend.root_syncs.load(Ordering::Acquire), 2);
    assert_eq!(
        published.superblock_generation,
        before.superblock_generation + 1
    );
    assert_eq!(
        published.directory.root.generation,
        before.directory.root.generation + 1
    );
    assert_eq!(
        published.directory.start.batch_seq,
        before.directory.start.batch_seq + 1
    );
    assert_eq!(published.directory.root, state.selected);
    assert_eq!(
        published.creates, before.creates,
        "the hook caught a file roll"
    );
    assert_eq!(backend.creates.load(Ordering::Acquire), before.creates);
    assert_eq!(
        published.directory.start.position.segment_id,
        before.directory.start.position.segment_id
    );
    assert!(published.directory.start.position.offset > before.directory.start.position.offset);
    assert_eq!(
        published.directory.root.page.unwrap().arena_id,
        before.directory.root.page.unwrap().arena_id
    );
    published
}

#[test]
fn post_publication_workspace_denial_uses_preadmitted_proofs_and_keeps_commit_successful() {
    let (mut state, backend) = fixture(AfterPublication::DenyWorkspace);
    let old = state.snapshot().unwrap();
    let before = stage(&state, &backend);
    backend.arm();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap();
    assert_commit_boundary(&state, &backend, before);
    assert!(backend.admission.deny_workspace.load(Ordering::Acquire));
    assert!(
        backend.admission.denied.load(Ordering::Acquire) > 0,
        "optional cache retention must exercise the post-publication denial"
    );
    assert!(backend.post_publication_reads.load(Ordering::Acquire) > 0);
    assert!(!state.is_fenced());
    assert!(backend.admission.check_owner().is_ok());
    // Ordinary reads may acquire their own output/workspace reservations.
    // The completed commit above had no permission to obtain a fresh one.
    backend
        .admission
        .deny_workspace
        .store(false, Ordering::Release);
    let current = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &old, b"a").unwrap(), vec![1; 8192]);
    assert_eq!(value(&mut state, &current, b"a").unwrap(), vec![9; 8192]);
    for pin in [&old, &current] {
        assert_eq!(value(&mut state, pin, b"b").unwrap(), vec![2; 8192]);
        assert_eq!(value(&mut state, pin, b"hot").unwrap(), vec![3; 8192]);
    }
    assert!(warm_all(&mut state).fully_resident);
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(backend.admission.inner.used.load(Ordering::Acquire), 0);
}

#[test]
fn post_publication_locator_read_failure_fences_and_reopens_the_whole_new_generation() {
    let (mut state, backend) = fixture(AfterPublication::FailRead);
    let old_b = match DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
        .get(state.selected, DirectoryKey::row("accounts", b"b"))
        .unwrap()
        .unwrap()
    {
        DirectoryValue::Row { value, .. } => value,
        _ => panic!("fixture row is absent"),
    };
    let before = stage(&state, &backend);
    backend.arm();
    let error = state
        .commit(&[
            Operation::put("accounts", b"a", vec![9; 8192]),
            Operation::put("accounts", b"b", vec![8; 8192]),
        ])
        .unwrap_err();
    assert!(
        error.is_unknown_commit(),
        "post-publication proof did not return UnknownCommit: {error}"
    );
    assert!(error.to_string().contains("publication proof read failed"));
    let published = assert_commit_boundary(&state, &backend, before);
    assert_eq!(backend.post_publication_reads.load(Ordering::Acquire), 1);
    let failed = backend.failed_read.lock().unwrap().unwrap();
    // Candidates drain in reverse first-mark order. The last overwritten value
    // must prove its envelope before any new-root directory traversal.
    assert_eq!(failed.file, GroupFile::segment(old_b.segment_id));
    assert!(failed.at < old_b.offset);
    assert_eq!(failed.at + failed.len as u64, old_b.offset);
    assert!(failed.len <= segment::CACHED_VALUE_LOCATOR_BYTES);
    assert!(state.is_fenced());
    assert!(
        matches!(&(state.snapshot()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert!(
        matches!(&(state.commit(&[Operation::delete("accounts", b"hot")])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    drop(state);
    assert_eq!(backend.admission.inner.used.load(Ordering::Acquire), 0);

    let mut reopened = DiskState::open(
        Arc::new(backend.group.crash()),
        Admission::new(16 << 20),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    assert_eq!(reopened.selected, published.directory.root);
    assert_eq!(
        reopened.owner.lock().unwrap().directory(),
        Some(published.directory)
    );
    let current = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), vec![9; 8192]);
    assert_eq!(value(&mut reopened, &current, b"b").unwrap(), vec![8; 8192]);
    assert_eq!(
        value(&mut reopened, &current, b"hot").unwrap(),
        vec![3; 8192]
    );
    assert!(!reopened.is_fenced());
}

#[test]
fn disabled_cache_skips_post_publication_proofs_and_warming() {
    let (mut state, backend) = fixture(AfterPublication::DenyWorkspace);
    state
        .configure_cache(CacheConfig { byte_limit: 0 })
        .unwrap();
    let before = stage(&state, &backend);
    backend.arm();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap();
    assert_commit_boundary(&state, &backend, before);
    assert_eq!(backend.post_publication_reads.load(Ordering::Acquire), 0);
    assert_eq!(backend.admission.denied.load(Ordering::Acquire), 0);
    assert_eq!(state.cache_stats().unwrap().entries, 0);
    assert!(!state.is_fenced());
    drop(state);
    assert_eq!(backend.admission.inner.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(backend.group.crash()),
        Admission::new(16 << 20),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), vec![9; 8192]);
}

#[test]
fn post_publication_warm_read_failure_fences_and_reopens_durable_version() {
    let (mut state, backend) = fixture(AfterPublication::FailRead);
    // No resident candidate exists, so reconciliation cannot consume the
    // fault. The first read after the durable root is the optional warmer.
    state.pages.clear().unwrap();
    let before = stage(&state, &backend);
    backend.arm();
    let error = state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap_err();
    assert!(
        error.is_unknown_commit(),
        "post-publication warm read did not return UnknownCommit: {error}"
    );
    assert!(error.to_string().contains("publication proof read failed"));
    let published = assert_commit_boundary(&state, &backend, before);
    let failed = backend.failed_read.lock().unwrap().unwrap();
    assert_eq!(
        failed.file,
        GroupFile::directory(published.directory.root.page.unwrap().arena_id)
    );
    // The arena verifies its header before reading the requested page body.
    assert_eq!(failed.at, 0);
    assert_eq!(failed.len, 4096);
    assert_eq!(backend.post_publication_reads.load(Ordering::Acquire), 1);
    assert!(state.is_fenced());
    drop(state);
    assert_eq!(backend.admission.inner.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(backend.group.crash()),
        Admission::new(16 << 20),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    assert_eq!(reopened.selected, published.directory.root);
    let current = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), vec![9; 8192]);
    assert_eq!(value(&mut reopened, &current, b"b").unwrap(), vec![2; 8192]);
    assert_eq!(
        value(&mut reopened, &current, b"hot").unwrap(),
        vec![3; 8192]
    );
}
