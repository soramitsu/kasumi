use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use crate::{CensusCancellation, NodeDiskConfig, NodeDiskMemoryAdmission};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let directory = private_tempdir().unwrap();
    let config = NodeDisk::fixture_config(directory.path().join("unused")).unwrap();
    (directory, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn root(disk: &Arc<NodeDisk>) -> NodeDiskDirectory {
    disk.open_directory("fixture", Path::new("")).unwrap()
}
fn native_original(disk: &NodeDisk) -> (i32, usize) {
    let mut originals = disk.pending_directory_originals().unwrap();
    let mut found = None;
    for (descriptor, error) in originals.close_errors().into_iter().flatten() {
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(found.is_none(), "one injected original native failure");
        found = Some((descriptor, std::ptr::from_ref(error) as usize));
    }
    found.expect("retained actual native close outcome")
}

#[test]
fn unknown_pending_child_close_preserves_original_and_never_retries_reused_descriptor() {
    // dup2 deliberately occupies a consumed descriptor number. A separate
    // process protects unrelated parallel fixtures; this is one distinct case.
    const CHILD: &str = "KASUMI_PENDING_DIRECTORY_CLOSE_REUSE_CHILD";
    const CASE: &str = "node_disk::directory::managed::custody_tests::unknown_pending_child_close_preserves_original_and_never_retries_reused_descriptor";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        print!("{stdout}");
        eprint!("{stderr}");
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {CASE} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
                && stdout
                    .lines()
                    .filter(|line| line.starts_with("test result:"))
                    .count()
                    == 1,
            "actual isolated close-reuse case failed: {}",
            output.status
        );
        return;
    }
    use std::os::fd::{AsRawFd, FromRawFd};
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    let before = disk.snapshot();
    let memory_before = memory.snapshot();
    FAILURE.with(|slot| slot.set(Some(NodeDiskDirectoryOperationStep::CloseChild)));
    let attempts = native_file::close_attempts();
    assert_eq!(
        child.remove_if_empty().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(native_file::close_attempts(), attempts + 2);
    assert!(!directory.path().join("child").exists());
    assert_eq!(disk.snapshot().open_directories, before.open_directories);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    let original = native_original(&disk);
    assert_eq!(disk.lock_state().accepted_census_generation, 0);
    drop(parent);
    let observer = File::open(directory.path()).unwrap();
    let reused = if observer.as_raw_fd() == original.0 {
        observer
    } else {
        assert_eq!(
            unsafe { libc::dup2(observer.as_raw_fd(), original.0) },
            original.0
        );
        // SAFETY: the isolated process owns this new descriptor; production
        // retains the consumed integer only as diagnostic data.
        unsafe { File::from_raw_fd(original.0) }
    };
    let identity = Identity::of(&reused.metadata().unwrap());
    for _ in 0..2 {
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        assert_eq!(native_file::close_attempts(), attempts + 2);
        assert_eq!(native_original(&disk), original);
        assert_eq!(Identity::of(&reused.metadata().unwrap()), identity);
        assert_eq!(disk.snapshot().open_directories, 1);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.lock_state().accepted_census_generation, 0);
        assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
    }
}

#[test]
fn unknown_intermediate_walk_close_retains_both_original_resources_before_publication() {
    let (directory, config, memory) = fixture();
    for relative in ["a", "a/b", "a/b/c"] {
        crate::private_files::create_directory(&directory.path().join(relative)).unwrap();
    }
    let disk = open(&config, &memory);
    let before = disk.snapshot();
    let memory_before = memory.snapshot();
    native_file::fail_next_close(libc::EIO);
    let attempts = native_file::close_attempts();
    assert_eq!(
        disk.open_directory("fixture", Path::new("a/b/c"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(native_file::close_attempts(), attempts + 1);
    let original = native_original(&disk);
    {
        let state = disk.lock_state();
        let pending = state.pending_directory.as_ref().unwrap();
        assert!(pending.walk_current.is_none());
        assert!(pending.walk_current_close.is_some());
        assert!(
            pending.walk_next.is_some(),
            "new independent walk descriptor remains owned"
        );
        assert!(
            pending.allocation.is_some(),
            "actual prospective owner backing remains retained"
        );
        assert!(pending.child.is_none());
    }
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(native_file::close_attempts(), attempts + 2);
    for _ in 0..2 {
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        assert_eq!(native_file::close_attempts(), attempts + 2);
        assert_eq!(native_original(&disk), original);
        assert_eq!(disk.snapshot().open_directories, 1);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.lock_state().accepted_census_generation, 0);
        assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
    }
}

#[derive(Debug)]
struct Marker(u8);
struct Diagnostic {
    disk: std::sync::Weak<NodeDisk>,
    drops: Arc<AtomicUsize>,
    panic: std::sync::Mutex<Option<Box<dyn std::any::Any + Send>>>,
}
impl std::fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original directory diagnostic")
    }
}
impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original directory diagnostic")
    }
}
impl std::error::Error for Diagnostic {}
impl Drop for Diagnostic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        let disk = self.disk.upgrade().unwrap();
        assert!(
            disk.state.try_lock().is_ok(),
            "metadata guard released before original destructor"
        );
        assert!(
            super::super::super::registry().try_lock().is_some(),
            "registry guard released before original destructor"
        );
        assert_eq!(disk.snapshot().open_directories, 1);
        assert_eq!(disk.lock_state().accepted_census_generation, 0);
        let reentrant = disk.reconcile(&CensusCancellation::default()).unwrap_err();
        assert_eq!(
            reentrant.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        if let Some(payload) = self.panic.get_mut().unwrap().take() {
            std::panic::resume_unwind(payload);
        }
    }
}

#[test]
fn original_diagnostic_destructor_panic_retains_exact_payload_and_charge_without_replay() {
    // The registry gate is process-global. An exact child isolates this real
    // callback-lock proof from unrelated parallel fixtures holding the gate.
    const CHILD: &str = "KASUMI_PENDING_DIRECTORY_DIAGNOSTIC_CHILD";
    const CASE: &str = "node_disk::directory::managed::custody_tests::original_diagnostic_destructor_panic_retains_exact_payload_and_charge_without_replay";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        print!("{stdout}");
        eprint!("{stderr}");
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {CASE} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
                && stdout
                    .lines()
                    .filter(|line| line.starts_with("test result:"))
                    .count()
                    == 1,
            "actual isolated diagnostic-lock case failed: {}",
            output.status
        );
        return;
    }
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    // Known fixture diagnostic/control/counter/panic allocations are funded and
    // prebuilt before the actual mkdir/open step; no failure-time allocation.
    let bookkeeping_bytes =
        crate::disk_memory::allocation::<Diagnostic>(1).unwrap()
            + crate::disk_memory::arc::<AtomicUsize>().unwrap()
            + crate::disk_memory::allocation::<Marker>(1).unwrap()
            + crate::disk_memory::allocation::<(
                io::ErrorKind,
                Box<dyn std::error::Error + Send + Sync>,
            )>(1)
            .unwrap();
    let _bookkeeping = memory.clone().reserve_installed(bookkeeping_bytes).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let payload: Box<dyn std::any::Any + Send> = Box::new(Marker(1));
    let payload_address = std::ptr::from_ref(payload.downcast_ref::<Marker>().unwrap()) as usize;
    let diagnostic = Diagnostic {
        disk: Arc::downgrade(&disk),
        drops: drops.clone(),
        panic: std::sync::Mutex::new(Some(payload)),
    };
    drop(diagnostic.panic.lock().unwrap());
    let error = io::Error::other(diagnostic);
    let original_address = std::ptr::from_ref(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<Diagnostic>()
            .unwrap(),
    ) as usize;
    ORIGINAL_FAILURE
        .with(|slot| *slot.borrow_mut() = Some((NodeDiskDirectoryOperationStep::OpenChild, error)));
    assert_eq!(
        parent
            .create_child(c"pending", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    {
        let originals = disk.pending_directory_originals().unwrap();
        assert_eq!(
            std::ptr::from_ref(
                originals
                    .error()
                    .unwrap()
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Diagnostic>()
                    .unwrap()
            ) as usize,
            original_address
        );
        assert!(!originals.retirement_entered());
    }
    drop(parent);
    let before = disk.snapshot();
    let memory_before = memory.snapshot();
    let attempts = native_file::close_attempts();
    // The reopen caller must also release its registry guard before callback.
    assert!(
        NodeDisk::reopen_fenced(&config, memory.clone(), &CensusCancellation::default()).is_err()
    );
    assert_eq!(native_file::close_attempts(), attempts + 1);
    for _ in 0..2 {
        let originals = disk.pending_directory_originals().unwrap();
        assert!(
            originals.error().is_none(),
            "entered original destructor is never replayed"
        );
        assert!(originals.retirement_entered());
        assert!(!originals.retirement_completed());
        let retained = originals
            .retirement_panic()
            .unwrap()
            .downcast_ref::<Marker>()
            .unwrap();
        assert_eq!(retained.0, 1);
        assert_eq!(std::ptr::from_ref(retained) as usize, payload_address);
        drop(originals);
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(native_file::close_attempts(), attempts + 1);
        assert_eq!(disk.snapshot().open_directories, before.open_directories);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
        assert_eq!(disk.lock_state().accepted_census_generation, 0);
        assert!(
            disk.lock_state()
                .pending_directory
                .as_ref()
                .unwrap()
                .allocation
                .is_some()
        );
    }
}

#[test]
fn operation_unwind_retains_original_before_explicit_positive_cleanup() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let _bookkeeping = memory
        .clone()
        .reserve_installed(crate::disk_memory::allocation::<Marker>(1).unwrap())
        .unwrap();
    let payload: Box<dyn std::any::Any + Send> = Box::new(Marker(2));
    let address = std::ptr::from_ref(payload.downcast_ref::<Marker>().unwrap()) as usize;
    ORIGINAL_PANIC.with(|slot| {
        *slot.borrow_mut() = Some((NodeDiskDirectoryOperationStep::OpenChild, payload))
    });
    assert_eq!(
        parent
            .create_child(c"pending", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert!(directory.path().join("pending").is_dir());
    {
        let originals = disk.pending_directory_originals().unwrap();
        let retained = originals.panic().unwrap().downcast_ref::<Marker>().unwrap();
        assert_eq!(retained.0, 2);
        assert_eq!(std::ptr::from_ref(retained) as usize, address);
        assert!(!originals.retirement_entered());
    }
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().open_directories, 2);
    assert_eq!(disk.lock_state().accepted_census_generation, 0);
    drop(parent);
    let attempts = native_file::close_attempts();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(native_file::close_attempts(), attempts + 1);
    assert!(disk.pending_directory_operation().is_none());
    assert_eq!(disk.snapshot().open_directories, 0);
    assert_eq!(disk.lock_state().accepted_census_generation, 1);
    root(&disk)
        .open_child(c"pending")
        .unwrap()
        .sync_all()
        .unwrap();
}
