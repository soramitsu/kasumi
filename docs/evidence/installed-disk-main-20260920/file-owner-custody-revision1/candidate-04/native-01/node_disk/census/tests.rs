use super::super::{
    DiskWork, NodeDisk, NodeDiskPhase, PreparedResources, PreparingRegistration, RegisteredDisk,
    Registration, fixed_map,
};
use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let root = private_tempdir().unwrap();
    let mut config = NodeDisk::fixture_config(root.path().join("anchor")).unwrap();
    config.max_persistent_files = 8;
    config.max_persistent_subdirectories = 8;
    config.census_work_per_step = 8;
    (root, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn file(path: &Path) {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.sync_all().unwrap();
}
fn root_set(config: &NodeDiskConfig) -> (BTreeMap<String, Root>, Vec<File>, u64) {
    let roots = open_roots(config).unwrap();
    let locks = lock_roots(&roots, config.max_depth).unwrap();
    let unit = super::super::filesystem(&roots.values().next().unwrap().file)
        .unwrap()
        .1;
    (roots, locks, unit)
}

#[test]
fn original_tiny_file_population_reconciles_without_reducing_admission() {
    let (root, config, memory) = fixture();
    let disk = open(&config, &memory);
    for index in 0..8 {
        let name = format!("file-{index}");
        let file = disk
            .create_file("fixture", Path::new(&name), DiskWork::Foreground)
            .unwrap();
        file.sync_all().unwrap();
        file.settle_growth(0).unwrap();
        drop(file);
        if index == 6 {
            disk.pause().unwrap();
            disk.reconcile(&CensusCancellation::default()).unwrap();
            assert_eq!(disk.snapshot().persistent_files, 7);
        }
    }
    assert!(
        disk.create_file("fixture", Path::new("overflow"), DiskWork::Foreground)
            .is_err()
    );
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
    let mut session = CensusSession::new(
        &roots,
        &config,
        unit,
        &cancel,
        banks.stage(limit).unwrap(),
        &streams,
    )
    .unwrap();
    let mut previous_work = 0;
    let mut root_stream = None;
    let mut pending = 0;
    loop {
        let progress = session.advance();
        assert!(session.work - previous_work <= 8);
        previous_work = session.work;
        assert_eq!(streams.outstanding() as usize, session.stack.len());
        if progress != Progress::Pending {
            assert_eq!(progress, Progress::Complete);
            break;
        }
        pending += 1;
        let pointer = session.stack[0].entries.unwrap();
        let fd = unsafe { libc::dirfd(pointer.as_ptr()) };
        if let Some((old_pointer, old_fd)) = root_stream {
            assert_eq!((pointer, fd), (old_pointer, old_fd));
        }
        root_stream = Some((pointer, fd));
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    }
    assert_eq!(pending, 5);
    assert_eq!(session.work, 8 + 4 * 8 + 3);
    let totals = session.finish().unwrap();
    assert_eq!((totals.files, totals.directories), (8, 9));
    assert_eq!(streams.outstanding(), 0);
    assert_eq!(
        unsafe { libc::fcntl(root_stream.unwrap().1, libc::F_GETFD) },
        -1
    );
    banks.commit_stage();
    assert_eq!(banks.len(), 17);
}

#[test]
fn file_and_subdirectory_excess_fail_without_candidate_publication() {
    for directories in [false, true] {
        let (root, config, memory) = fixture();
        for index in 0..9 {
            let path = root.path().join(format!("entry-{index}"));
            if directories {
                crate::private_files::create_directory(&path).unwrap();
            } else {
                file(&path);
            }
        }
        let before = memory.snapshot();
        let error = retry_disk_registry(|| {
            NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains(if directories {
            "subdirectory cardinality"
        } else {
            "file cardinality"
        }));
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
        // Fully closed failed scans release root locks for a later valid census.
        if directories {
            std::fs::remove_dir(root.path().join("entry-8")).unwrap();
        } else {
            std::fs::remove_file(root.path().join("entry-8")).unwrap();
        }
        let disk = open(&config, &memory);
        assert_eq!(
            disk.snapshot().persistent_files,
            if directories { 0 } else { 8 }
        );
        assert_eq!(
            disk.snapshot().persistent_directories,
            if directories { 9 } else { 1 }
        );
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
    let mut session = CensusSession::new(
        &roots,
        &config,
        unit,
        &cancel,
        banks.stage(17).unwrap(),
        &streams,
    )
    .unwrap();
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
    let mut session = CensusSession::new(
        &roots,
        &config,
        unit,
        &cancel,
        banks.stage(17).unwrap(),
        &streams,
    )
    .unwrap();
    assert_eq!(session.advance(), Progress::Pending);
    streams.fail_next_close.set(true);
    cancel.cancel();
    assert_eq!(session.advance(), Progress::Failed);
    assert_eq!(streams.outstanding(), 1);
    assert_eq!(streams.close_errno(), Some(libc::EIO));
    let error = session.finish().unwrap_err();
    assert_eq!(
        error.downcast_ref::<CensusCloseFailure>().unwrap().errno,
        libc::EIO
    );
    let rendered = format!("{error:#}");
    assert!(rendered.contains("cancelled"));
    assert!(rendered.contains("close also failed"));
    assert_eq!(streams.outstanding(), 1);
    assert!(
        CensusSession::new(
            &roots,
            &config,
            unit,
            &CensusCancellation::default(),
            banks.stage(17).unwrap(),
            &streams
        )
        .is_err()
    );
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
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let mut session = CensusSession::new(
                        &roots,
                        &config,
                        unit,
                        &cancel,
                        banks.stage(17).unwrap(),
                        &streams,
                    )
                    .unwrap();
                    assert_eq!(session.advance(), Progress::Pending);
                    panic!("injected census unwind");
                }))
                .is_err()
            );
        } else {
            let mut session = CensusSession::new(
                &roots,
                &config,
                unit,
                &cancel,
                banks.stage(17).unwrap(),
                &streams,
            )
            .unwrap();
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
    let file = disk
        .create_file("fixture", Path::new("data"), DiskWork::Foreground)
        .unwrap();
    file.sync_all().unwrap();
    file.settle_growth(0).unwrap();
    drop(file);
    let before = disk.snapshot();
    let memory_before = memory.snapshot();
    let entries = disk
        .lock_state()
        .accounted
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect::<BTreeMap<_, _>>();
    disk.lock_state().census_streams.fail_next_close.set(true);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    let after = disk.snapshot();
    assert_eq!(after.phase, NodeDiskPhase::Failed);
    assert_eq!(after.open_census_streams, 1);
    assert_eq!(after.census_close_errno, Some(libc::EIO));
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.pending_bytes, before.pending_bytes);
    assert_eq!(
        after.filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert_eq!(
        disk.lock_state()
            .accounted
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<BTreeMap<_, _>>(),
        entries
    );
    assert!(disk.pause().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(memory.snapshot().used_bytes, memory_before.used_bytes);
    assert_eq!(disk.snapshot().open_census_streams, 1);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
}

fn registered_preparation(
    config: &NodeDiskConfig,
    memory: &Arc<TestDiskMemory>,
    installed: &mut super::super::List<RegisteredDisk>,
) -> (Identity, u64, *const ()) {
    use crate::NodeDiskMemoryAdmission;
    let requirements = NodeDisk::memory_requirements(config).unwrap();
    let charge = memory
        .clone()
        .reserve_installed(requirements.owner_bytes)
        .unwrap();
    let registry_charge = memory
        .clone()
        .reserve_installed(requirements.registry_bytes)
        .unwrap();
    let file_custody = super::super::file::CustodySlots::new(config.max_open_files).unwrap();
    let (roots, ancestor_locks, unit) = root_set(config);
    let identity = roots.values().next().unwrap().identity;
    let (limit, _) = super::super::ledger::map_limits(config).unwrap();
    let accounted = fixed_map::Banks::new(limit).unwrap();
    let live = fixed_map::Banks::new(config.max_open_files as usize).unwrap();
    let entry = super::super::List::prepare(RegisteredDisk {
        identity,
        registration: Registration::Preparing(PreparedResources {
            config: config.clone(),
            memory: memory.clone(),
            roots,
            ancestor_locks,
            accounted,
            live,
            file_custody,
            streams: Streams::default(),
            charge,
        }),
        _charge: registry_charge,
    });
    let allocation = std::ptr::from_ref(entry.as_ref()).cast::<()>();
    installed.insert(entry);
    (identity, unit, allocation)
}

#[test]
fn uncertain_initial_close_retains_registered_outcome_and_resources_through_error_or_unwind() {
    for unwind in [false, true] {
        let (_root, mut config, memory) = fixture();
        config.census_work_per_step = 1;
        let mut installed = super::super::registry().lock();
        let (identity, unit, _allocation) =
            registered_preparation(&config, &memory, &mut installed);
        let before = memory.snapshot();
        let root_fd = installed
            .find(|entry| entry.identity == identity)
            .unwrap()
            .roots()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .file
            .as_raw_fd();
        let cancel = CensusCancellation::default();
        let run = || {
            let mut registration = PreparingRegistration {
                installed: &mut installed,
                identity,
                committed: false,
            };
            let prepared = registration.prepared();
            let mut session = CensusSession::new(
                &prepared.roots,
                &prepared.config,
                unit,
                &cancel,
                prepared.accounted.stage(17).unwrap(),
                &prepared.streams,
            )
            .unwrap();
            assert_eq!(session.advance(), Progress::Pending);
            prepared.streams.fail_next_close.set(true);
            if unwind {
                panic!("injected initial census unwind");
            }
            cancel.cancel();
            assert_eq!(session.advance(), Progress::Failed);
            assert!(session.finish().is_err());
        };
        assert_eq!(catch_unwind(AssertUnwindSafe(run)).is_err(), unwind);
        let entry = installed.find(|entry| entry.identity == identity).unwrap();
        let Registration::Preparing(prepared) = &entry.registration else {
            panic!("lost initial custody");
        };
        assert_eq!(prepared.streams.outstanding(), 1);
        assert_eq!(prepared.streams.close_errno(), Some(libc::EIO));
        assert_eq!(prepared.accounted.len(), 0);
        assert!(entry.owner().is_err());
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
        assert!(unsafe { libc::fcntl(root_fd, libc::F_GETFD) } >= 0);
        drop(installed);
        // The production constructor finds the pre-effect registration without
        // acquiring new memory or silently retrying the failed native resource.
        let error = NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
            .unwrap_err();
        let crate::DiskOpenError::Failed(error) = error else {
            panic!("lost retained failure");
        };
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(memory.snapshot().attempts, before.attempts);
        let other = open_roots(&config).unwrap();
        assert!(lock_roots(&other, config.max_depth).is_err());
    }
}

#[test]
fn ordinary_initial_failure_retires_descriptors_before_admission_credit() {
    let (_root, config, memory) = fixture();
    let mut installed = super::super::registry().lock();
    let (identity, _unit, allocation) = registered_preparation(&config, &memory, &mut installed);
    let mut registration = PreparingRegistration {
        installed: &mut installed,
        identity,
        committed: false,
    };
    let prepared = registration.prepared();
    let fds = prepared
        .roots
        .values()
        .map(|root| root.file.as_raw_fd())
        .chain(prepared.ancestor_locks.iter().map(AsRawFd::as_raw_fd))
        .collect::<Vec<_>>();
    struct ObserveRetirement {
        lease: Option<crate::DiskMemoryLease>,
        fds: Vec<i32>,
        observed: Arc<std::sync::atomic::AtomicBool>,
        allocation: Arc<crate::allocation_tests::DeallocationObservation>,
    }
    impl Drop for ObserveRetirement {
        fn drop(&mut self) {
            assert!(
                self.allocation.finished(),
                "actual registry backing still live at owner credit retirement"
            );
            for fd in &self.fds {
                assert_eq!(
                    unsafe { libc::fcntl(*fd, libc::F_GETFD) },
                    -1,
                    "descriptor still owned at lease retirement"
                );
            }
            self.observed
                .store(true, std::sync::atomic::Ordering::Release);
            drop(self.lease.take());
        }
    }
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let deallocation = Arc::new(crate::allocation_tests::DeallocationObservation::new(false));
    // Only the test adds this callback wrapper; production retirement is the
    // ordinary ordered resource bundle with its original mandatory leases.
    let lease = std::mem::replace(&mut prepared.charge, crate::DiskMemoryLease::new(()));
    prepared.charge = crate::DiskMemoryLease::new(ObserveRetirement {
        lease: Some(lease),
        fds,
        observed: observed.clone(),
        allocation: deallocation.clone(),
    });
    assert!(memory.snapshot().used_bytes > 0);
    crate::allocation_tests::observe_deallocation(allocation, &deallocation, || drop(registration));
    assert_eq!(deallocation.count(), 1);
    assert_eq!(
        deallocation.bytes(),
        std::mem::size_of::<crate::disk_memory::Entry<RegisteredDisk>>()
    );
    assert!(installed.find(|entry| entry.identity == identity).is_none());
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

#[test]
fn provisional_arc_allocation_retires_before_lease_on_error_and_unwind() {
    use super::super::ProvisionalOwner;
    use crate::NodeDiskMemoryAdmission;
    use crate::allocation_tests::{DeallocationObservation, observe_deallocation};
    struct Credit {
        lease: Option<crate::DiskMemoryLease>,
        observation: Arc<DeallocationObservation>,
    }
    impl Drop for Credit {
        fn drop(&mut self) {
            assert!(
                self.observation.finished(),
                "provisional Arc backing still live at resident credit retirement"
            );
            drop(self.lease.take());
        }
    }
    for unwind in [false, true] {
        let memory = TestDiskMemory::new(1 << 20, 4);
        let observation = Arc::new(DeallocationObservation::new(false));
        let owner = ProvisionalOwner::new(Credit {
            lease: Some(memory.clone().reserve_installed(4096).unwrap()),
            observation: observation.clone(),
        });
        // Pinned std ArcInner is repr(C): strong, weak, then aligned T. The
        // observer verifies this exact native allocation and requested layout.
        let (layout, offset) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<Credit>())
            .unwrap();
        let value = Arc::as_ptr(owner.0.as_ref().unwrap()).cast::<u8>();
        let allocation = unsafe { value.sub(offset) }.cast::<()>();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            observe_deallocation(allocation, &observation, || -> Result<()> {
                let _owner = owner;
                if unwind {
                    panic!("original provisional publication panic");
                }
                Err(io::Error::from_raw_os_error(libc::EIO).into())
            })
        }));
        if unwind {
            assert_eq!(
                outcome.unwrap_err().downcast_ref::<&str>(),
                Some(&"original provisional publication panic")
            );
        } else {
            assert_eq!(
                outcome
                    .unwrap()
                    .unwrap_err()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EIO)
            );
        }
        assert_eq!(observation.count(), 1);
        assert_eq!(observation.bytes(), layout.pad_to_align().size());
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().live_reservations, 0);
    }
}

#[test]
fn actual_initial_promise_overflow_removes_only_the_unpublished_registration() {
    let (_root, config, memory) = fixture();
    let device = super::super::DeviceDisk::isolated(0, memory.clone()).unwrap();
    device.lock().set_pending(u64::MAX).unwrap();
    let before = memory.snapshot();
    // Keep the original aggregate in this anchor. A typed RegistryBusy retry
    // drops only its fresh zero-pending registration, preserving the same
    // overflow trigger and the original five-second fixture retry policy.
    let error = retry_disk_registry(|| {
        NodeDisk::open_inner(
            &config,
            memory.clone(),
            &CensusCancellation::default(),
            super::super::DeviceSelection::Existing(device.share(0)),
        )
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("promises overflow"));
    assert!(
        super::super::registry()
            .lock()
            .find(|entry| entry
                .config()
                .is_some_and(|candidate| candidate.roots == config.roots))
            .is_none()
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
    device.lock().set_pending(0).unwrap();
    drop(device);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
    let disk = open(&config, &memory);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}
