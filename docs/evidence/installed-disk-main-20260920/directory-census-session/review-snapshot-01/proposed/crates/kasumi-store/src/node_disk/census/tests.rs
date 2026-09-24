use super::*;
use super::super::{DiskWork, NodeDisk, NodeDiskPhase, PreparedCensus, PreparedResources, fixed_map};
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{panic::{AssertUnwindSafe, catch_unwind}, sync::Arc};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let root = private_tempdir().unwrap();
    let mut config = NodeDisk::fixture_config(root.path().join("anchor")).unwrap();
    config.max_persistent_files = 8;
    config.max_persistent_subdirectories = 8;
    config.census_work_per_step = 8;
    (root, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())).unwrap()
}
fn file(path: &Path) {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.sync_all().unwrap();
}
fn root_set(config: &NodeDiskConfig) -> (BTreeMap<String, Root>, Vec<File>, u64) {
    let roots = open_roots(config).unwrap();
    let locks = lock_roots(&roots, config.max_depth).unwrap();
    let unit = super::super::filesystem(&roots.values().next().unwrap().file).unwrap().1;
    (roots, locks, unit)
}

#[test]
fn original_tiny_file_population_reconciles_without_reducing_admission() {
    let (root, config, memory) = fixture();
    let disk = open(&config, &memory);
    for index in 0..8 {
        let name = format!("file-{index}");
        let file = disk.create_file("fixture", Path::new(&name), DiskWork::Foreground).unwrap();
        file.sync_all().unwrap();
        file.settle_growth(0).unwrap();
        drop(file);
        if index == 6 {
            disk.pause().unwrap();
            disk.reconcile(&CensusCancellation::default()).unwrap();
            assert_eq!(disk.snapshot().persistent_files, 7);
        }
    }
    assert!(disk.create_file("fixture", Path::new("overflow"), DiskWork::Foreground).is_err());
    assert!(!root.path().join("overflow").exists());
    let old = disk.snapshot();
    let memory_before = memory.snapshot();
    disk.pause().unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    let after = disk.snapshot();
    assert_eq!(after.persistent_files, 8);
    assert_eq!(after.phase, NodeDiskPhase::Open);
    assert_eq!(after.charged_bytes, old.charged_bytes);
    assert_eq!(after.pending_bytes, old.pending_bytes);
    assert_eq!(after.open_census_streams, 0);
    assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
    assert_eq!(memory.snapshot().attempts, memory_before.attempts);
}

#[test]
fn full_file_and_directory_geometry_progresses_without_reopening_streams() {
    let (root, config, _memory) = fixture();
    for index in 0..8 {
        let path = root.path().join(format!("directory-{index}"));
        crate::private_files::create_directory(&path).unwrap();
        file(&path.join("data"));
    }
    let (roots, _locks, unit) = root_set(&config);
    let (limit, _) = super::super::ledger::map_limits(&config).unwrap();
    let mut banks = fixed_map::Banks::new(limit).unwrap();
    let streams = Streams::default();
    let cancel = CensusCancellation::default();
    let mut session = CensusSession::new(&roots, &config, unit, &cancel, banks.stage(limit).unwrap(), &streams).unwrap();
    let mut previous_work = 0;
    let mut root_stream = None;
    let mut pending = 0;
    loop {
        let progress = session.advance();
        assert!(session.work - previous_work <= 8);
        previous_work = session.work;
        assert_eq!(streams.outstanding() as usize, session.stack.len());
        if progress != Progress::Pending { assert_eq!(progress, Progress::Complete); break; }
        pending += 1;
        let pointer = session.stack[0].entries.unwrap();
        let fd = unsafe { libc::dirfd(pointer.as_ptr()) };
        if let Some((old_pointer, old_fd)) = root_stream { assert_eq!((pointer, fd), (old_pointer, old_fd)); }
        root_stream = Some((pointer, fd));
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    }
    assert_eq!(pending, 5);
    assert_eq!(session.work, 8 + 4 * 8 + 3);
    let totals = session.finish().unwrap();
    assert_eq!((totals.files, totals.directories), (8, 9));
    assert_eq!(streams.outstanding(), 0);
    assert_eq!(unsafe { libc::fcntl(root_stream.unwrap().1, libc::F_GETFD) }, -1);
    banks.commit_stage();
    assert_eq!(banks.len(), 17);
}

#[test]
fn file_and_subdirectory_excess_fail_without_candidate_publication() {
    for directories in [false, true] {
        let (root, config, memory) = fixture();
        for index in 0..9 {
            let path = root.path().join(format!("entry-{index}"));
            if directories { crate::private_files::create_directory(&path).unwrap(); } else { file(&path); }
        }
        let before = memory.snapshot();
        let error = retry_disk_registry(|| NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())).unwrap_err();
        assert!(format!("{error:#}").contains(if directories { "subdirectory cardinality" } else { "file cardinality" }));
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(memory.snapshot().live_reservations, before.live_reservations);
        // Fully closed failed scans release root locks for a later valid census.
        if directories { std::fs::remove_dir(root.path().join("entry-8")).unwrap(); }
        else { std::fs::remove_file(root.path().join("entry-8")).unwrap(); }
        let disk = open(&config, &memory);
        assert_eq!(disk.snapshot().persistent_files, if directories { 0 } else { 8 });
        assert_eq!(disk.snapshot().persistent_directories, if directories { 9 } else { 1 });
    }
}

#[test]
fn cancellation_between_steps_closes_actual_stream_and_resets_partial_spare() {
    let (root, mut config, _memory) = fixture();
    config.census_work_per_step = 1;
    file(&root.path().join("data"));
    let (roots, _locks, unit) = root_set(&config);
    let mut banks = fixed_map::Banks::new(17).unwrap();
    let streams = Streams::default();
    let cancel = CensusCancellation::default();
    let mut session = CensusSession::new(&roots, &config, unit, &cancel, banks.stage(17).unwrap(), &streams).unwrap();
    assert_eq!(session.advance(), Progress::Pending);
    assert_eq!(streams.outstanding(), 1);
    let fd = unsafe { libc::dirfd(session.stack[0].entries.unwrap().as_ptr()) };
    cancel.cancel();
    assert_eq!(session.advance(), Progress::Failed);
    assert_eq!(session.advance(), Progress::Failed);
    assert_eq!(streams.outstanding(), 0);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(session.scan.accounted.len(), 0);
    assert!(format!("{:#}", session.finish().unwrap_err()).contains("cancelled"));
    assert_eq!(banks.len(), 0);
}

#[test]
fn cancellation_retains_independent_native_close_error_without_retry() {
    let (root, mut config, _memory) = fixture();
    config.census_work_per_step = 1;
    file(&root.path().join("data"));
    let (roots, _locks, unit) = root_set(&config);
    let mut banks = fixed_map::Banks::new(17).unwrap();
    let streams = Streams::default();
    let cancel = CensusCancellation::default();
    let mut session = CensusSession::new(&roots, &config, unit, &cancel, banks.stage(17).unwrap(), &streams).unwrap();
    assert_eq!(session.advance(), Progress::Pending);
    streams.fail_next_close.set(true);
    cancel.cancel();
    assert_eq!(session.advance(), Progress::Failed);
    assert_eq!(streams.outstanding(), 1);
    assert_eq!(streams.close_errno(), Some(libc::EIO));
    let error = format!("{:#}", session.finish().unwrap_err());
    assert!(error.contains("cancelled"));
    assert!(error.contains("close also failed"));
    assert_eq!(streams.outstanding(), 1);
    assert!(CensusSession::new(&roots, &config, unit, &CensusCancellation::default(), banks.stage(17).unwrap(), &streams).is_err());
}

#[test]
fn unfinished_or_unwound_session_cannot_publish_partial_candidate() {
    for unwind in [false, true] {
        let (_root, mut config, _memory) = fixture();
        config.census_work_per_step = 1;
        let (roots, _locks, unit) = root_set(&config);
        let mut banks = fixed_map::Banks::new(17).unwrap();
        let streams = Streams::default();
        let cancel = CensusCancellation::default();
        if unwind {
            assert!(catch_unwind(AssertUnwindSafe(|| {
                let mut session = CensusSession::new(&roots, &config, unit, &cancel, banks.stage(17).unwrap(), &streams).unwrap();
                assert_eq!(session.advance(), Progress::Pending);
                panic!("injected census unwind");
            })).is_err());
        } else {
            let mut session = CensusSession::new(&roots, &config, unit, &cancel, banks.stage(17).unwrap(), &streams).unwrap();
            assert_eq!(session.advance(), Progress::Pending);
            assert!(session.finish().is_err());
        }
        assert_eq!(streams.outstanding(), 0);
        // commit_stage is deliberately attempted only to verify the failed
        // candidate was emptied; production never publishes failed sessions.
        banks.commit_stage();
        assert_eq!(banks.len(), 0);
    }
}

#[test]
fn uncertain_reconcile_close_retains_old_ledger_promises_and_drain_fence() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let file = disk.create_file("fixture", Path::new("data"), DiskWork::Foreground).unwrap();
    file.sync_all().unwrap(); file.settle_growth(0).unwrap(); drop(file);
    let before = disk.snapshot();
    let memory_before = memory.snapshot();
    let entries = disk.lock_state().accounted.iter().map(|(k, v)| (*k, *v)).collect::<BTreeMap<_, _>>();
    disk.lock_state().census_streams.fail_next_close.set(true);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    let after = disk.snapshot();
    assert_eq!(after.phase, NodeDiskPhase::Failed);
    assert_eq!(after.open_census_streams, 1);
    assert_eq!(after.census_close_errno, Some(libc::EIO));
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.pending_bytes, before.pending_bytes);
    assert_eq!(after.filesystem_pending_bytes, before.filesystem_pending_bytes);
    assert_eq!(disk.lock_state().accounted.iter().map(|(k,v)|(*k,*v)).collect::<BTreeMap<_,_>>(), entries);
    assert!(disk.pause().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
    assert_eq!(disk.snapshot().open_census_streams, 1);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
}

fn prepared(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> (PreparedCensus, u64) {
    use crate::NodeDiskMemoryAdmission;
    let requirements = NodeDisk::memory_requirements(config).unwrap();
    let charge = memory.clone().reserve_installed(requirements.owner_bytes).unwrap();
    let registry_charge = memory.clone().reserve_installed(requirements.registry_bytes).unwrap();
    let (roots, ancestor_locks, unit) = root_set(config);
    let (limit, _) = super::super::ledger::map_limits(config).unwrap();
    let accounted = fixed_map::Banks::new(limit).unwrap();
    let live = fixed_map::Banks::new(config.max_open_files as usize).unwrap();
    (PreparedCensus { resources: Some(PreparedResources { roots, ancestor_locks, accounted, live, charge, registry_charge }), streams: Streams::default() }, unit)
}

#[test]
fn uncertain_initial_close_retains_actual_admission_and_root_lock_through_error_or_unwind() {
    for unwind in [false, true] {
        let (_root, mut config, memory) = fixture();
        config.census_work_per_step = 1;
        let (mut prepared, unit) = prepared(&config, &memory);
        let before = memory.snapshot();
        let root_fd = prepared.resources.as_ref().unwrap().roots.values().next().unwrap().file.as_raw_fd();
        let cancel = CensusCancellation::default();
        let run = || {
            let resources = prepared.resources.as_mut().unwrap();
            let mut session = CensusSession::new(&resources.roots, &config, unit, &cancel,
                resources.accounted.stage(17).unwrap(), &prepared.streams).unwrap();
            assert_eq!(session.advance(), Progress::Pending);
            prepared.streams.fail_next_close.set(true);
            if unwind { panic!("injected initial census unwind"); }
            cancel.cancel();
            assert_eq!(session.advance(), Progress::Failed);
            assert!(session.finish().is_err());
        };
        assert_eq!(catch_unwind(AssertUnwindSafe(run)).is_err(), unwind);
        assert_eq!(prepared.streams.outstanding(), 1);
        drop(prepared);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(memory.snapshot().live_reservations, before.live_reservations);
        assert!(unsafe { libc::fcntl(root_fd, libc::F_GETFD) } >= 0);
        let other = open_roots(&config).unwrap();
        assert!(lock_roots(&other, config.max_depth).is_err());
    }
}

#[test]
fn ordinary_initial_failure_retires_descriptors_before_admission_credit() {
    let (_root, config, memory) = fixture();
    let (mut prepared, _unit) = prepared(&config, &memory);
    let resources = prepared.resources.as_mut().unwrap();
    let fds = resources.roots.values().map(|root| root.file.as_raw_fd())
        .chain(resources.ancestor_locks.iter().map(AsRawFd::as_raw_fd)).collect::<Vec<_>>();
    struct ObserveRetirement { lease: Option<crate::DiskMemoryLease>, fds: Vec<i32>, observed: Arc<std::sync::atomic::AtomicBool> }
    impl Drop for ObserveRetirement {
        fn drop(&mut self) {
            for fd in &self.fds { assert_eq!(unsafe { libc::fcntl(*fd, libc::F_GETFD) }, -1, "descriptor still owned at lease retirement"); }
            self.observed.store(true, std::sync::atomic::Ordering::Release);
            drop(self.lease.take());
        }
    }
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Only the test adds this callback wrapper; production retirement is the
    // ordinary ordered resource bundle with its original mandatory leases.
    let lease = std::mem::replace(&mut resources.charge, crate::DiskMemoryLease::new(()));
    resources.charge = crate::DiskMemoryLease::new(ObserveRetirement { lease: Some(lease), fds, observed: observed.clone() });
    assert!(memory.snapshot().used_bytes > 0);
    drop(prepared);
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn checked_geometry_never_substitutes_step_work_for_namespace_capacity() {
    let (_root, mut config, _memory) = fixture();
    assert_eq!(config.census_work_bound().unwrap(), 43);
    config.census_work_per_step = 1;
    assert_eq!(config.census_work_bound().unwrap(), 43);
    assert_eq!(super::super::ledger::map_limits(&config).unwrap(), (17, 17));
    config.max_persistent_subdirectories = u64::MAX / 4 + 1;
    assert!(config.validate().is_err());
}
