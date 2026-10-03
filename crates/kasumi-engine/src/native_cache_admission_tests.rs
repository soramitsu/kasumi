//! Installed governor qualification for native cache cardinality.
//!
//! The governor and its opaque cache leases are production implementations.
//! The filesystem adapter is a bounded, fixture-only group with eight cached
//! file descriptors, instrumented to distinguish segment and directory reads.
//! This measures admitted residency and backend calls, not process RSS or I/O
//! throughput. Fixture paths, operation inputs and descriptor backing are not
//! part of the database's allocation ledger.

use crate::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, CacheConfig, CacheMemoryLease, CacheMemoryQuote,
    CacheWarmupState, Core, FileKind, GroupFile, Operation, OwnerFailed, ROOT_FILE_NAME,
    ROOT_SLOT_BYTES, ResidentLease, RootSlot, SegmentGroupBackend, StorageAdmission,
};
use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const GROUP_ID: [u8; 16] = [0x8b; 16];
const ROWS: u32 = 16_513;
const VALUE: [u8; 128] = [0x73; 128];
const CACHE_BYTES: u64 = 64 << 20;

struct Admission {
    memory: Arc<MemoryCore>,
    failed: AtomicBool,
}

impl Admission {
    fn new(memory: Arc<MemoryCore>) -> Arc<Self> {
        Arc::new(Self {
            memory,
            failed: AtomicBool::new(false),
        })
    }

    fn map_error(error: io::Error) -> AdmissionError {
        if error.kind() == io::ErrorKind::OutOfMemory {
            AdmissionError::CapacityDenied
        } else {
            AdmissionError::OwnerFailed
        }
    }
}

impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        // Match the installed ordinary native adapter's separately boxed
        // DiskMemoryLease. The provider admits its concrete token as well.
        let bytes = bytes
            .checked_add(std::mem::size_of::<DiskMemoryLease>() as u64 + 4096)
            .ok_or(AdmissionError::CapacityDenied)?;
        let lease = self
            .memory
            .clone()
            .reserve_installed(bytes)
            .map_err(Self::map_error)?;
        Ok(Box::new(lease))
    }

    fn quote_cache_memory(&self, bytes: u64) -> Result<CacheMemoryQuote, AdmissionError> {
        self.memory
            .quote_cache_memory(bytes)
            .map_err(Self::map_error)
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<CacheMemoryLease, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let lease = self
            .memory
            .clone()
            .reserve_cache_memory(bytes)
            .map_err(Self::map_error)?;
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        Ok(lease)
    }

    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if requested < current {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }

    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }

    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

struct Files {
    root: File,
    directory: File,
    cached: [Option<(GroupFile, File)>; 8],
    next: usize,
}

struct CountedGroup {
    admission: Arc<Admission>,
    transaction: Mutex<Option<(kasumi_kv::TransactionSpacePlan, bool)>>,
    path: PathBuf,
    files: Mutex<Option<Files>>,
    segment_reads: AtomicU64,
    directory_reads: AtomicU64,
}

impl CountedGroup {
    fn transaction_effect(&self) {
        if let Some((_, entered)) = self.transaction.lock().unwrap().as_mut() {
            *entered = true;
        }
    }

    fn open(path: &Path, create: bool, admission: Arc<Admission>) -> io::Result<Arc<Self>> {
        let root = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .open(path.join(ROOT_FILE_NAME))?;
        if create {
            root.set_len((2 * ROOT_SLOT_BYTES) as u64)?;
        }
        Ok(Arc::new(Self {
            admission,
            transaction: Mutex::new(None),
            path: path.to_owned(),
            files: Mutex::new(Some(Files {
                root,
                directory: File::open(path)?,
                cached: std::array::from_fn(|_| None),
                next: 0,
            })),
            segment_reads: AtomicU64::new(0),
            directory_reads: AtomicU64::new(0),
        }))
    }

    fn with_files<T>(&self, work: impl FnOnce(&mut Files) -> io::Result<T>) -> io::Result<T> {
        let mut owner = self.files.lock().unwrap();
        let files = owner.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        work(files)
    }

    fn with_file<T>(
        &self,
        file: GroupFile,
        work: impl FnOnce(&File) -> io::Result<T>,
    ) -> io::Result<T> {
        self.with_files(|files| {
            let found = files
                .cached
                .iter()
                .position(|slot| slot.as_ref().is_some_and(|(key, _)| *key == file));
            let index = if let Some(index) = found {
                index
            } else {
                let handle = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(self.path.join(file.file_name()))?;
                let index = files.next;
                files.next = (index + 1) % files.cached.len();
                files.cached[index] = Some((file, handle));
                index
            };
            work(&files.cached[index].as_ref().unwrap().1)
        })
    }

    fn reads(&self) -> (u64, u64) {
        (
            self.segment_reads.load(Ordering::Acquire),
            self.directory_reads.load(Ordering::Acquire),
        )
    }
}

fn root_offset(slot: RootSlot) -> u64 {
    match slot {
        RootSlot::A => 0,
        RootSlot::B => ROOT_SLOT_BYTES as u64,
    }
}

impl SegmentGroupBackend for CountedGroup {
    // This fixture uses ordinary temporary files and has no installed disk
    // quota. Its explicit attempt tracks real effects and exact settlement;
    // it must not attest production admission or mint CapacityDenied.
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> Result<(), kasumi_kv::TransactionReserveError> {
        let result = (|| -> io::Result<()> {
            plan.validate()?;
            let mut attempt = self.transaction.lock().unwrap();
            if attempt.is_some() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut a = [0; ROOT_SLOT_BYTES];
            let mut b = [0; ROOT_SLOT_BYTES];
            self.read_root(RootSlot::A, &mut a)?;
            self.read_root(RootSlot::B, &mut b)?;
            // The actual fixture admission funds canonical decoder backing.
            // This grant outlives both decoded root images and error conversion.
            let _roots_workspace = self
                .admission
                .reserve_workspace(kasumi_kv::TRANSACTION_SPACE_ROOTS_HEAP_BYTES)
                .map_err(io::Error::other)?;
            kasumi_kv::validate_transaction_space_roots(plan, &a, &b).map_err(io::Error::other)?;
            *attempt = Some((*plan, false));
            Ok(())
        })();
        result.map_err(kasumi_kv::TransactionReserveError::Failed)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        let plan = {
            let attempt = self.transaction.lock().unwrap();
            let (plan, _) = attempt.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
            if plan.group_id != group_id || plan.batch_seq != batch_seq {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            *plan
        };
        for existing in plan.segment.into_iter().chain(plan.directory) {
            let length = self.len(existing.file)?;
            if length < existing.initial_len || length > existing.maximum_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.sync(existing.file)?;
        }
        for (kind, range) in [
            (FileKind::Segment, plan.new_segments),
            (FileKind::Directory, plan.new_directories),
        ] {
            let mut absent = false;
            let mut total = 0u64;
            for offset in 0..range.count {
                let file = GroupFile {
                    kind,
                    id: range.first_id + offset,
                };
                if !self.exists(file)? {
                    absent = true;
                    continue;
                }
                if absent {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let length = self.len(file)?;
                if length < range.minimum_len || length > range.maximum_len(file.id).unwrap() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                total = total
                    .checked_add(length)
                    .ok_or(io::ErrorKind::InvalidData)?;
                if total > range.total_len {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.sync(file)?;
            }
        }
        self.sync_root()?;
        self.sync_names()?;
        let mut attempt = self.transaction.lock().unwrap();
        if !attempt.as_ref().is_some_and(|(held, _)| *held == plan) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        *attempt = None;
        Ok(())
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        let mut attempt = self.transaction.lock().unwrap();
        if !attempt.as_ref().is_some_and(|(plan, entered)| {
            !entered && plan.group_id == group_id && plan.batch_seq == batch_seq
        }) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        *attempt = None;
        Ok(())
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.with_files(|files| files.root.read_exact_at(out, root_offset(slot)))
    }

    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.transaction_effect();
        self.with_files(|files| files.root.write_all_at(bytes, root_offset(slot)))
    }

    fn sync_root(&self) -> io::Result<()> {
        self.with_files(|files| files.root.sync_data())
    }

    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        // Callbacks may use this adapter; never retain its descriptor lock.
        for entry in fs::read_dir(&self.path)? {
            visitor(&entry?.file_name())?;
        }
        Ok(())
    }

    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.path.join(file.file_name()).try_exists()
    }

    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.transaction_effect();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(file.file_name()))?;
        self.sync_names()
    }

    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.with_file(file, |handle| Ok(handle.metadata()?.len()))
    }

    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        match file.kind {
            FileKind::Segment => &self.segment_reads,
            FileKind::Directory => &self.directory_reads,
            FileKind::Checkpoint => return self.with_file(file, |f| f.read_exact_at(out, at)),
        }
        .fetch_add(1, Ordering::AcqRel);
        self.with_file(file, |handle| handle.read_exact_at(out, at))
    }

    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.transaction_effect();
        self.with_file(file, |handle| handle.write_all_at(bytes, at))
    }

    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.transaction_effect();
        self.with_file(file, |handle| handle.set_len(length))
    }

    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.with_file(file, File::sync_data)
    }

    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.transaction_effect();
        self.with_files(|files| {
            for slot in &mut files.cached {
                if slot.as_ref().is_some_and(|(key, _)| *key == file) {
                    *slot = None;
                }
            }
            match fs::remove_file(self.path.join(file.file_name())) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            files.directory.sync_all()
        })
    }

    fn sync_names(&self) -> io::Result<()> {
        self.with_files(|files| files.directory.sync_all())
    }

    fn close(&self) -> BackendCloseOutcome {
        self.files.lock().unwrap().take();
        BackendCloseOutcome::drained(Ok(()))
    }
}

#[test]
fn sixteen_thousand_rows_fit_with_one_hundred_twenty_eight_governor_slots() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let config = AdmissionConfig {
        max_reservations: 128,
        max_inflight_bytes: Some(256 << 20),
        ..AdmissionConfig::default()
    };
    let node = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
    let memory = node.memory().clone();
    let baseline = memory.snapshot();
    let first_admission = Admission::new(memory.clone());
    let first_backend = CountedGroup::open(directory.path(), true, first_admission.clone())?;
    let first = Core::create_with_backend(
        first_backend,
        first_admission,
        GROUP_ID,
        CacheConfig { byte_limit: 0 },
    )?;
    let mut operations = Vec::with_capacity(ROWS as usize + 1);
    operations.push(Operation::create_table("rows"));
    for index in 0..ROWS {
        operations.push(Operation::put("rows", index.to_be_bytes(), VALUE));
    }
    first.commit(&operations)?;
    drop(operations);
    first.close().into_result()?;
    drop(first);
    assert_eq!(memory.snapshot().reserved_bytes, baseline.reserved_bytes);

    let admission = Admission::new(memory.clone());
    let backend = CountedGroup::open(directory.path(), false, admission.clone())?;
    let core = Core::open_with_backend(
        backend.clone(),
        admission,
        GROUP_ID,
        CacheConfig {
            byte_limit: CACHE_BYTES,
        },
    )?;
    let cold = memory.snapshot();
    assert_eq!(core.cache_stats()?.entries, 0);
    let cold_reads = backend.reads();
    let mut completed = false;
    for _ in 0..(ROWS as usize * 4 + 8192).div_ceil(128) {
        let progress = core.warm_cache_if_needed(128)?;
        assert!(core.cache_stats()?.resident_bytes <= CACHE_BYTES);
        assert!(memory.snapshot().live_reservations <= 128);
        if progress.complete {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "warm-up did not complete: {:?}",
        core.cache_warmup_status()?
    );
    assert_eq!(
        core.cache_warmup_status()?.state,
        CacheWarmupState::Resident
    );
    let hot = core.cache_stats()?;
    assert!(
        hot.entries > ROWS as usize,
        "directory pages must also be resident"
    );
    assert_eq!(hot.evictions, 0);
    let warmed = memory.snapshot();
    assert!(
        warmed.live_reservations <= cold.live_reservations + 2,
        "cache reservations must scale independently of {ROWS} rows: cold={cold:?}, hot={warmed:?}"
    );
    let warm_reads = backend.reads();
    assert!(warm_reads.0 > cold_reads.0 && warm_reads.1 > cold_reads.1);
    assert_eq!(
        warm_reads.0 - cold_reads.0,
        u64::from(ROWS),
        "cold warming should fetch each row payload once"
    );
    eprintln!(
        "rows={ROWS} cache_limit={CACHE_BYTES} hot={hot:?} cold_slots={} hot_slots={} warm_segment_reads={} warm_directory_reads={}",
        cold.live_reservations,
        warmed.live_reservations,
        warm_reads.0 - cold_reads.0,
        warm_reads.1 - cold_reads.1
    );
    let snapshot = core.snapshot()?;
    for _ in 0..2 {
        for index in 0..ROWS {
            let value = core
                .get_admitted(&snapshot, "rows", &index.to_be_bytes(), VALUE.len())?
                .expect("committed row");
            assert_eq!(value.as_bytes(), VALUE);
        }
    }
    assert_eq!(
        backend.reads(),
        warm_reads,
        "fitting reads touched backing files"
    );
    drop(snapshot);
    let work = core.cache_warmup_status()?.cumulative_work;
    for _ in 0..10 {
        assert!(core.warm_cache_if_needed(128)?.complete);
    }
    assert_eq!(core.cache_warmup_status()?.cumulative_work, work);
    assert_eq!(backend.reads(), warm_reads);
    core.close().into_result()?;
    drop(core);
    assert_eq!(memory.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

#[test]
fn installed_cache_credit_survives_clear_and_cross_thread_final_reader_release()
-> anyhow::Result<()> {
    let node = NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            max_reservations: 128,
            max_inflight_bytes: Some(32 << 20),
            ..AdmissionConfig::default()
        },
        2 << 30,
        0,
    )?;
    let memory = node.memory().clone();
    let baseline = memory.snapshot();
    let provider = Admission::new(memory.clone());
    let mut cache = kasumi_kv::NativeCache::new(
        CacheConfig {
            byte_limit: 1 << 20,
        },
        provider.clone(),
    );
    let held = cache
        .load(1_u64, 8192, |out| {
            out.fill(0x5b);
            Ok::<_, ()>(())
        })
        .unwrap();
    let another = held.clone();
    let warm = memory.snapshot();
    assert_eq!(warm.live_reservations, baseline.live_reservations + 1);
    assert_eq!(
        warm.reserved_bytes - baseline.reserved_bytes,
        cache.stats().resident_bytes,
        "cache bound must include the complete installed provider charge"
    );
    provider.failed.store(true, Ordering::Release);
    assert!(matches!(
        cache.load(2_u64, 8, |_| Ok::<_, ()>(())),
        Err(kasumi_kv::CacheLoadError::Admission(
            AdmissionError::OwnerFailed
        ))
    ));
    cache.clear();
    assert_eq!(cache.stats().entries, 0);
    assert!(cache.stats().pinned_bytes >= 8192);
    drop(cache);
    drop(held);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert!(memory.snapshot().reserved_bytes > baseline.reserved_bytes);
    std::thread::spawn(move || {
        assert!(another.as_bytes().iter().all(|byte| *byte == 0x5b));
        drop(another);
    })
    .join()
    .expect("final reader thread");
    assert_eq!(memory.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}
