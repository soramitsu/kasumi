use kasumi_raft::Entry;
use kasumi_raft::test_utils::FixtureResult;
mod common;

use anyhow::Result;
use kasumi_raft::{LogStore, SnapshotBuffer, StateMachine, TypeConfig};
use openraft::{
    EntryPayload, LogId, OptionalSend, RaftLogReader, RaftSnapshotBuilder, StorageError,
    StorageIOError, Vote,
    storage::{LogFlushed, LogState, RaftLogStorage, RaftLogStorageExt, RaftStateMachine},
    testing::{StoreBuilder, Suite},
};
use std::sync::{Arc, atomic::Ordering};
use tempfile::TempDir;

struct Builder {
    failure: std::sync::Mutex<Option<kasumi_store::ScratchOperationFailure>>,
    snapshot_root: std::sync::Mutex<Option<Arc<kasumi_raft::SnapshotBufferOwner>>>,
    // The same original fee outlives both mutexes and every deferred scope.
    cleanup: CleanupInventory,
}

#[derive(Debug)]
struct RetainedConstructor;
impl std::fmt::Display for RetainedConstructor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("conformance constructor original retained by fixture")
    }
}
impl std::error::Error for RetainedConstructor {}

impl Builder {
    fn prepare() -> FixtureResult<Self> {
        use kasumi_store::NodeDiskMemoryAdmission;
        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
        let bytes = u64::try_from(std::mem::size_of::<
            std::sync::Mutex<Option<kasumi_store::ScratchOperationFailure>>,
        >())?
        .checked_add(u64::try_from(std::mem::size_of::<
            std::sync::Mutex<Option<Arc<kasumi_raft::SnapshotBufferOwner>>>,
        >())?)
        .expect("bounded fixture root quote")
        .checked_add(64 + 4096)
        .expect("bounded fixture root control quote")
        .checked_add(64 + 4096)
        .expect("bounded fixture control quote")
        .checked_add(CleanupInventory::required_bytes()?)
        .expect("bounded fixture cleanup quote");
        let charge = memory.reserve_installed(bytes)?;
        let result = Self {
            failure: std::sync::Mutex::new(None),
            snapshot_root: std::sync::Mutex::new(None),
            cleanup: CleanupInventory::new(charge),
        };
        // Initialize the actual platform control while its original fee exists.
        drop(result.failure.lock().unwrap());
        drop(result.snapshot_root.lock().unwrap());
        Ok(result)
    }

    fn retain(&self, original: kasumi_store::ScratchOperationFailure) -> StorageError<u64> {
        let mut slot = self.failure.lock().unwrap();
        assert!(
            slot.is_none(),
            "fixture overwrote an original constructor failure"
        );
        *slot = Some(original);
        StorageIOError::write(&RetainedConstructor).into()
    }

    fn take_failure(&self) -> Option<kasumi_store::ScratchOperationFailure> {
        self.failure.lock().unwrap().take()
    }

    fn diagnose_apply_failure(&self) {
        let root = self.snapshot_root.lock().unwrap();
        let Some(root) = root.as_ref() else {
            eprintln!("conformance apply root: not entered");
            return;
        };
        let result = root.try_with_retained_apply_report(|report| match report {
            kasumi_raft::RetainedApplyReport::Single(original) => {
                diagnose_original("single", original);
            }
            kasumi_raft::RetainedApplyReport::Preparation {
                original,
                publication,
                response,
                violation,
            } => {
                eprintln!("conformance preparation original: {original}");
                if let Some(original) = publication {
                    diagnose_original("publication", original);
                }
                eprintln!(
                    "conformance preparation response_bytes={:?} retirement={:?} violation={violation:?}",
                    response.map(|response| response.data.len()),
                    response.map(|response| response.retirement.is_some()),
                );
            }
            kasumi_raft::RetainedApplyReport::Ordinary(report) => {
                eprintln!(
                    "conformance ordinary ordinal={} violation={:?} response_bytes={:?} retirement={:?}",
                    report.ordinal,
                    report.violation,
                    report.response.map(|response| response.data.len()),
                    report.response.map(|response| response.retirement.is_some()),
                );
                if let Some(original) = report.single {
                    diagnose_original("ordinary single", original);
                }
                diagnose_observation("sink", report.sink);
                diagnose_observation("action", report.action);
                diagnose_observation("backend", report.backend);
                diagnose_observation("finish", report.finish);
                diagnose_observation("cleanup", report.cleanup);
                diagnose_observation("drain", report.drain);
                if let Some(original) = report.wake_panic {
                    eprintln!("conformance wake original: {:?}", original.type_id());
                }
            }
        });
        match result {
            Ok(Some(())) => {}
            Ok(None) => eprintln!("conformance apply root: no retained report"),
            Err(busy) => eprintln!("conformance apply root: {busy:?}"),
        }
    }
}

fn diagnose_original(phase: &str, original: &anyhow::Error) {
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
    eprintln!(
        "conformance {phase} original_address={} original={original:#}",
        std::ptr::from_ref(outer) as *const () as usize,
    );
}

fn diagnose_observation(phase: &str, observation: kasumi_raft::ApplyObservationRef<'_>) {
    match observation {
        kasumi_raft::ApplyObservationRef::NotEntered => {
            eprintln!("conformance {phase}: not entered");
        }
        kasumi_raft::ApplyObservationRef::Running => eprintln!("conformance {phase}: running"),
        kasumi_raft::ApplyObservationRef::Returned => eprintln!("conformance {phase}: returned"),
        kasumi_raft::ApplyObservationRef::Error(original) => diagnose_original(phase, original),
        kasumi_raft::ApplyObservationRef::AdmissionRefused(original) => {
            eprintln!("conformance {phase}: admission refused {original:?}");
        }
        kasumi_raft::ApplyObservationRef::Creation(original) => {
            eprintln!("conformance {phase}: creation original {original}");
        }
        kasumi_raft::ApplyObservationRef::Unwound(original) => {
            eprintln!(
                "conformance {phase}: unwind original {:?}",
                original.type_id()
            );
        }
        kasumi_raft::ApplyObservationRef::Refused(original) => {
            eprintln!("conformance {phase}: completion refused {original:?}");
        }
    }
}
struct PendingScope {
    queried: Option<Arc<kasumi_store::TenantStorageSet>>,
    source: Option<Arc<kasumi_store::TenantStorageSet>>,
    snapshot_root: Option<Arc<kasumi_raft::SnapshotBufferOwner>>,
    entry_admissions: Option<EntryAdmissions>,
    installed: [Option<Arc<kasumi_store::NodeDisk>>; 2],
    installed_scratch: Option<Arc<kasumi_store::ScratchDisk>>,
    installed_baseline: Option<InstalledBaseline>,
    memory: Option<Arc<kasumi_store::test_utils::TestDiskMemory>>,
    failures: [Option<kasumi_types::drain::DrainFailure>; 3],
    directory: Option<TempDir>,
    source_directory: Option<TempDir>,
    scratch_directory: Option<TempDir>,
}

impl PendingScope {
    fn new() -> Self {
        Self {
            directory: None,
            source_directory: None,
            scratch_directory: None,
            memory: None,
            queried: None,
            source: None,
            snapshot_root: None,
            entry_admissions: None,
            installed: std::array::from_fn(|_| None),
            installed_scratch: None,
            installed_baseline: None,
            failures: std::array::from_fn(|_| None),
        }
    }

    async fn drain(&mut self) -> Result<(), StorageError<u64>> {
        if self.failures.iter().any(Option::is_some) || self.installed_baseline.is_none() {
            // An incomplete physical installation has no completed original
            // baseline; its returned constructor original remains in Builder.
            return Err(StorageIOError::write(&RetainedScope).into());
        }
        if let Some(root) = &self.snapshot_root
            && let Err(original) = root.drain_startup().await
        {
            self.failures[0] = Some(original);
            return Err(StorageIOError::write(&RetainedScope).into());
        }
        for (index, stores) in [&self.queried, &self.source].into_iter().enumerate() {
            if let Some(stores) = stores
                && let Err(original) =
                    kasumi_store::test_utils::shutdown_owned_stores_fixture(stores).await
            {
                self.failures[index + 1] = Some(original);
                return Err(StorageIOError::write(&RetainedScope).into());
            }
        }
        if let Some(admissions) = &self.entry_admissions {
            admissions.retire_after_drain();
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct InstalledBaseline {
    bytes: u64,
    reservations: usize,
    census: kasumi_store::StorageCensusSnapshot,
}
impl InstalledBaseline {
    fn quoted(
        paths: [&std::path::Path; 2],
        scratch: &kasumi_store::ScratchDiskConfig,
    ) -> anyhow::Result<Self> {
        let mut bytes = 0_u64;
        let mut reservations = 0_usize;
        let queried = kasumi_store::NodeDisk::fixture_config(paths[0])?;
        let source = kasumi_store::NodeDisk::fixture_config(paths[1])?;
        for required in [
            kasumi_store::NodeDisk::memory_requirements(&queried)?,
            kasumi_store::NodeDisk::memory_requirements(&source)?,
            kasumi_store::ScratchDisk::memory_requirements(scratch)?,
        ] {
            for original in [
                required.owner_bytes,
                required.registry_bytes,
                required.device_bytes,
                required.registration_bytes,
            ] {
                bytes = bytes
                    .checked_add(
                        kasumi_store::test_utils::TestDiskMemory::required_reservation_bytes(
                            original,
                        )?,
                    )
                    .ok_or_else(|| std::io::Error::other("installed fixture quote overflow"))?;
                reservations = reservations
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("installed fixture slot overflow"))?;
            }
        }
        Ok(Self {
            bytes,
            reservations,
            census: kasumi_store::StorageCensusSnapshot {
                capacity: 4096,
                ..Default::default()
            },
        })
    }

    fn assert_drained(
        self,
        memory: &kasumi_store::test_utils::TestDiskMemory,
        installed: &[Arc<kasumi_store::NodeDisk>; 2],
        scratch: &kasumi_store::ScratchDisk,
    ) {
        use kasumi_store::NodeDiskMemoryAdmission;
        let actual = memory.snapshot();
        // The process registry still owns the exact installed metadata, root
        // locks and isolated device controls. Every per-case owner must retire.
        assert_eq!(
            actual.used_bytes.checked_sub(self.bytes),
            Some(0),
            "actual transient owner or staging credit remains after positive drains"
        );
        assert_eq!(
            actual.live_reservations.checked_sub(self.reservations),
            Some(0),
            "actual transient reservation remains after positive drains"
        );
        assert_eq!(memory.storage_census().snapshot(), self.census);
        for owner in installed {
            let state = owner.snapshot();
            assert_eq!(state.phase, kasumi_store::NodeDiskPhase::Open);
            assert_eq!(state.open_files, 0);
            assert_eq!(state.open_directories, 0);
            assert_eq!(state.open_directory_cursors, 0);
            assert_eq!(state.open_census_streams, 0);
            assert_eq!(state.retained_file_attempts, 0);
            assert!(state.uncertain_file_close.is_none());
            assert!(state.census_close_errno.is_none());
        }
        let state = scratch.snapshot();
        assert_eq!(state.live_files, 0);
        assert_eq!(state.charged_bytes, 0);
        assert_eq!(state.filesystem_pending_bytes, 0);
        assert!(state.filesystem_admission_ready);
    }
}

#[derive(Debug)]
struct RetainedScope;
impl std::fmt::Display for RetainedScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("conformance scope remains in its admitted cleanup seat")
    }
}
impl std::error::Error for RetainedScope {}

struct CleanupState {
    scopes: tokio::sync::Mutex<[Option<PendingScope>; 2]>,
    active: [std::sync::atomic::AtomicBool; 2],
    charge: Option<kasumi_store::DiskMemoryLease>,
}
impl Drop for CleanupState {
    fn drop(&mut self) {
        let scopes = self.scopes.get_mut();
        if scopes.iter().any(Option::is_some) {
            // A failed or abandoned actual drain supplies no disposal proof.
            // Preserve the same original owners and fee; never remove paths.
            for scope in scopes {
                if let Some(original) = scope.take() {
                    std::mem::forget(original);
                }
            }
            std::mem::forget(self.charge.take().expect("original cleanup fee"));
        }
    }
}
struct CleanupInventory(Option<Arc<CleanupState>>);
impl CleanupInventory {
    fn required_bytes() -> std::io::Result<u64> {
        let (layout, _) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<CleanupState>())
            .map_err(std::io::Error::other)?;
        u64::try_from(layout.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| std::io::Error::other("fixture cleanup quote overflow"))
    }
    fn new(charge: kasumi_store::DiskMemoryLease) -> Self {
        Self(Some(Arc::new(CleanupState {
            scopes: tokio::sync::Mutex::new(std::array::from_fn(|_| None)),
            active: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            charge: Some(charge),
        })))
    }
    fn state(&self) -> &CleanupState {
        self.0.as_deref().expect("live fixture cleanup inventory")
    }
    async fn drain_ready(&self) -> Result<(), StorageError<u64>> {
        let state = self.state();
        let mut scopes = state.scopes.lock().await;
        for (index, scope) in scopes.iter_mut().enumerate() {
            if state.active[index].load(Ordering::Acquire) {
                continue;
            }
            if let Some(original) = scope {
                original.drain().await?;
                let baseline = original
                    .installed_baseline
                    .expect("completed fixture has its original installed baseline");
                let memory = original.memory.as_ref().unwrap().clone();
                let installed = std::array::from_fn(|owner| {
                    original.installed[owner].as_ref().unwrap().clone()
                });
                let scratch = original.installed_scratch.as_ref().unwrap().clone();
                // Only the actual returned buffer and physical-owner drains
                // permit these same owners and private paths to be destroyed.
                *scope = None;
                baseline.assert_drained(&memory, &installed, &scratch);
            }
        }
        Ok(())
    }
    async fn drain_final(&self) -> Result<(), StorageError<u64>> {
        self.drain_ready().await?;
        if self.state().scopes.lock().await.iter().any(Option::is_some) {
            // A still accepted scope is an independent retained owner, even
            // when no earlier drain returned an error.
            return Err(StorageIOError::write(&RetainedScope).into());
        }
        Ok(())
    }
    async fn diagnose_failures(&self) {
        let scopes = self.state().scopes.lock().await;
        for (index, scope) in scopes.iter().enumerate() {
            if let Some(scope) = scope {
                for (stage, original) in scope.failures.iter().enumerate() {
                    if let Some(original) = original {
                        eprintln!(
                            "conformance cleanup seat={index} stage={stage} completion={:?}",
                            original.completion()
                        );
                        for issue in original.issues() {
                            diagnose_original(issue.component(), issue.error());
                        }
                    }
                }
            }
        }
    }
}
impl Clone for CleanupInventory {
    fn clone(&self) -> Self {
        Self(Some(
            self.0.as_ref().expect("live cleanup inventory").clone(),
        ))
    }
}
impl Drop for CleanupInventory {
    fn drop(&mut self) {
        // The last actual shared control frees before its payload and fee.
        drop(Arc::into_inner(
            self.0.take().expect("live cleanup inventory"),
        ));
    }
}
struct StoreScope {
    cleanup: CleanupInventory,
    index: usize,
}
impl Drop for StoreScope {
    fn drop(&mut self) {
        // Suite has disposed its machine/log futures before this scope. This
        // only hands off custody; the next build or final runner does the drain.
        self.cleanup.state().active[self.index].store(false, Ordering::Release);
    }
}

struct ConformanceMachine {
    machine: StateMachine,
    source_log: LogStore,
    memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    admissions: EntryAdmissions,
}

struct EntryFees {
    previous: Option<Box<EntryFees>>,
    metadata: Option<kasumi_store::DiskMemoryLease>,
    cloned: kasumi_store::DiskMemoryLease,
    control: kasumi_store::DiskMemoryLease,
}
fn free_entry_control(original: Box<EntryFees>) -> EntryFees {
    // The original Box is gone when this whole fee payload reaches its caller.
    *original
}
struct EntryAdmissionState {
    fees: std::sync::Mutex<Option<Box<EntryFees>>>,
    // Only a successfully returned actual native publication or installed
    // snapshot changes this scalar. It never witnesses owner disposal.
    published: std::sync::Mutex<Option<LogId<u64>>>,
    _charge: kasumi_store::DiskMemoryLease,
}
impl Drop for EntryAdmissionState {
    fn drop(&mut self) {
        // A nonempty ledger has not observed physical worker drain.
        if let Some(original) = self
            .fees
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            std::mem::forget(original);
        }
    }
}
struct EntryAdmissions(Option<Arc<EntryAdmissionState>>);
impl EntryAdmissions {
    fn prepare(memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>) -> std::io::Result<Self> {
        let (layout, _) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<EntryAdmissionState>())
            .map_err(std::io::Error::other)?;
        let bytes = u64::try_from(layout.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(4096 + 2 * (64 + 4096)))
            .ok_or_else(|| std::io::Error::other("entry ledger quote overflow"))?;
        let charge = memory.clone().reserve_installed(bytes)?;
        let state = EntryAdmissionState {
            fees: std::sync::Mutex::new(None),
            published: std::sync::Mutex::new(None),
            _charge: charge,
        };
        drop(state.fees.lock().unwrap());
        drop(state.published.lock().unwrap());
        Ok(Self(Some(Arc::new(state))))
    }
    fn published(&self) -> Option<LogId<u64>> {
        *self
            .0
            .as_ref()
            .expect("live entry ledger")
            .published
            .lock()
            .unwrap()
    }
    fn record_publication(&self, original: Option<LogId<u64>>) {
        *self
            .0
            .as_ref()
            .expect("live entry ledger")
            .published
            .lock()
            .unwrap() = original;
    }
    fn retain(
        &self,
        metadata: Option<kasumi_store::DiskMemoryLease>,
        cloned: kasumi_store::DiskMemoryLease,
        control: kasumi_store::DiskMemoryLease,
    ) {
        let mut fees = self
            .0
            .as_ref()
            .expect("live entry ledger")
            .fees
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let original = Box::new(EntryFees {
            previous: fees.take(),
            metadata,
            cloned,
            control,
        });
        *fees = Some(original);
    }
    fn retire_after_drain(&self) {
        let mut fees = self
            .0
            .as_ref()
            .expect("live entry ledger")
            .fees
            .lock()
            .unwrap();
        while let Some(original) = fees.take() {
            let EntryFees {
                previous,
                metadata,
                cloned,
                control,
            } = free_entry_control(original);
            *fees = previous;
            drop(metadata);
            drop(cloned);
            drop(control);
        }
    }
}
impl Clone for EntryAdmissions {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live entry ledger").clone()))
    }
}
impl Drop for EntryAdmissions {
    fn drop(&mut self) {
        drop(Arc::into_inner(self.0.take().expect("live entry ledger")));
    }
}

fn allocation_quote<T>(count: usize) -> std::io::Result<u64> {
    let layout = std::alloc::Layout::array::<T>(count).map_err(std::io::Error::other)?;
    u64::try_from(layout.size())
        .ok()
        .and_then(|bytes| bytes.checked_add(if bytes == 0 { 0 } else { 4096 }))
        .ok_or_else(|| std::io::Error::other("entry allocation quote overflow"))
}
fn add_quote(total: &mut u64, extra: u64) -> std::io::Result<()> {
    *total = total
        .checked_add(extra)
        .ok_or_else(|| std::io::Error::other("entry clone quote overflow"))?;
    Ok(())
}
fn entry_clone_quote(entry: &Entry<TypeConfig>) -> std::io::Result<u64> {
    let mut bytes = 0;
    if let Some(initialization) = &entry.initialization {
        add_quote(&mut bytes, allocation_quote::<u8>(initialization.len())?)?;
    }
    match &entry.payload {
        EntryPayload::Blank => {}
        EntryPayload::Normal(command) => {
            add_quote(&mut bytes, allocation_quote::<u8>(command.bytes().len())?)?;
            if let kasumi_raft::RaftCommand::Retirement { seed, .. } = command {
                add_quote(&mut bytes, allocation_quote::<u8>(seed.len())?)?;
            }
        }
        EntryPayload::Membership(membership) => {
            let configs = membership.get_joint_config();
            add_quote(
                &mut bytes,
                allocation_quote::<std::collections::BTreeSet<u64>>(configs.len())?,
            )?;
            for config in configs {
                // Each element conservatively admits one concrete tree node;
                // the allocator allowance covers its links and spare keys.
                for _ in config {
                    add_quote(&mut bytes, allocation_quote::<u64>(1)?)?;
                }
            }
            for (_, node) in membership.nodes() {
                add_quote(
                    &mut bytes,
                    allocation_quote::<(u64, openraft::BasicNode)>(1)?,
                )?;
                add_quote(&mut bytes, allocation_quote::<u8>(node.addr.len())?)?;
            }
        }
    }
    Ok(bytes)
}

#[derive(Default)]
struct AdmittedEntries {
    entries: Vec<Entry<TypeConfig>>,
    metadata: Option<kasumi_store::DiskMemoryLease>,
}
impl AdmittedEntries {
    fn push(
        &mut self,
        entry: Entry<TypeConfig>,
        memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ) -> std::io::Result<()> {
        if self.entries.len() == self.entries.capacity() {
            let capacity = self
                .entries
                .capacity()
                .max(2)
                .checked_mul(2)
                .ok_or_else(|| std::io::Error::other("entry container capacity overflow"))?;
            // The old actual backing and fee remain live during reallocation.
            let admitted = allocation_quote::<Entry<TypeConfig>>(capacity)?;
            let replacement = memory.clone().reserve_installed(admitted)?;
            self.entries
                .try_reserve_exact(capacity - self.entries.len())
                .map_err(std::io::Error::other)?;
            self.metadata = Some(replacement);
            if allocation_quote::<Entry<TypeConfig>>(self.entries.capacity())? > admitted {
                return Err(std::io::Error::other("entry allocation exceeded admission"));
            }
        }
        self.entries.push(entry);
        Ok(())
    }
}

fn admit_entry_backing(
    entries: &[Entry<TypeConfig>],
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
) -> Result<(kasumi_store::DiskMemoryLease, kasumi_store::DiskMemoryLease), StorageError<u64>> {
    let mut bytes = allocation_quote::<Entry<TypeConfig>>(entries.len())
        .map_err(|error| StorageIOError::write(&error))?;
    for entry in entries {
        add_quote(
            &mut bytes,
            entry_clone_quote(entry).map_err(|error| StorageIOError::write(&error))?,
        )
        .map_err(|error| StorageIOError::write(&error))?;
    }
    let backing = memory
        .clone()
        .reserve_installed(bytes)
        .map_err(|error| StorageIOError::write(&error))?;
    let control = memory
        .clone()
        .reserve_installed(
            allocation_quote::<EntryFees>(1).map_err(|error| StorageIOError::write(&error))?,
        )
        .map_err(|error| StorageIOError::write(&error))?;
    Ok((backing, control))
}

struct ConformanceLog {
    log: LogStore,
    memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    admissions: EntryAdmissions,
}
impl RaftLogReader<TypeConfig> for ConformanceLog {
    async fn try_get_log_entries<
        RB: std::ops::RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend,
    >(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        self.log.try_get_log_entries(range).await
    }
    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        self.log.limited_get_log_entries(start, end).await
    }
}
impl RaftLogStorage<TypeConfig> for ConformanceLog {
    type LogReader = LogStore;
    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        self.log.get_log_state().await
    }
    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.log.get_log_reader().await
    }
    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        self.log.save_vote(vote).await
    }
    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        self.log.read_vote().await
    }
    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        self.log.save_committed(committed).await
    }
    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        self.log.read_committed().await
    }
    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut staged = AdmittedEntries::default();
        for entry in entries {
            staged
                .push(entry, &self.memory)
                .map_err(|error| StorageIOError::write(&error))?;
        }
        if staged.entries.is_empty() {
            return self
                .log
                .append(std::mem::take(&mut staged.entries), callback)
                .await;
        }
        let first = staged.entries[0].log_id;
        let (backing, control) = admit_entry_backing(&staged.entries, &self.memory)?;
        self.admissions
            .retain(staged.metadata.take(), backing, control);
        if let Some(last) = self.log.get_log_state().await?.last_log_id
            && first.index as u128 > last.index as u128 + 1
            && let Some(published) = self.admissions.published()
            && published.index as u128 + 1 >= first.index as u128
        {
            // The Suite intentionally omits queried rows already represented
            // by its actual state machine. Compact to that exact successful
            // endpoint, never to an inferred missing entry or ancestor ID.
            self.log.purge(published).await?;
        }
        self.log
            .append(std::mem::take(&mut staged.entries), callback)
            .await
    }
    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.log.truncate(log_id).await
    }
    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.log.purge(log_id).await
    }
}

impl RaftStateMachine<TypeConfig> for ConformanceMachine {
    type SnapshotBuilder = <StateMachine as RaftStateMachine<TypeConfig>>::SnapshotBuilder;
    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<u64>>,
            openraft::StoredMembership<u64, openraft::BasicNode>,
        ),
        StorageError<u64>,
    > {
        self.machine.applied_state().await
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Vec<u8>>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + openraft::OptionalSend,
        I::IntoIter: openraft::OptionalSend,
    {
        let mut staged = AdmittedEntries::default();
        for entry in entries {
            staged
                .push(entry, &self.memory)
                .map_err(|error| StorageIOError::write(&error))?;
        }
        if staged.entries.is_empty() {
            return self
                .machine
                .apply(std::mem::take(&mut staged.entries))
                .await;
        }
        let first = staged.entries[0].log_id;
        let last = staged.entries.last().unwrap().log_id;
        let (cloned, control) = admit_entry_backing(&staged.entries, &self.memory)?;
        let source = staged.entries.clone();
        // Transfer every fee before either actual worker can outlive its waiter.
        self.admissions
            .retain(staged.metadata.take(), cloned, control);
        if let Some(previous) = self.source_log.get_log_state().await?.last_log_id
            && first.index as u128 > previous.index as u128 + 1
            && self.admissions.published() == Some(previous)
        {
            // Direct state-machine cases can start a later disjoint window.
            // Retire only the exact prefix the actual previous publication
            // completed; the Suite never supplied the skipped entry.
            self.source_log.purge(previous).await?;
        }
        self.source_log.blocking_append(source).await?;
        let result = self
            .machine
            .apply(std::mem::take(&mut staged.entries))
            .await;
        if result.is_ok() {
            self.admissions.record_publication(Some(last));
        }
        result
    }
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.machine.get_snapshot_builder().await
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotBuffer>, StorageError<u64>> {
        self.machine.begin_receiving_snapshot().await
    }
    async fn install_snapshot(
        &mut self,
        meta: &openraft::SnapshotMeta<u64, openraft::BasicNode>,
        snapshot: Box<SnapshotBuffer>,
    ) -> Result<(), StorageError<u64>> {
        let result = self.machine.install_snapshot(meta, snapshot).await;
        if result.is_ok() {
            self.admissions.record_publication(meta.last_log_id);
        }
        result
    }
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<openraft::Snapshot<TypeConfig>>, StorageError<u64>> {
        self.machine.get_current_snapshot().await
    }
}

impl StoreBuilder<TypeConfig, ConformanceLog, ConformanceMachine, StoreScope> for Builder {
    async fn build(
        &self,
    ) -> Result<(StoreScope, ConformanceLog, ConformanceMachine), StorageError<u64>> {
        self.cleanup.drain_ready().await?;
        let mut scopes = self.cleanup.state().scopes.lock().await;
        let Some(index) = scopes.iter().position(Option::is_none) else {
            return Err(StorageIOError::write(&RetainedScope).into());
        };
        self.cleanup.state().active[index].store(true, Ordering::Release);
        scopes[index] = Some(PendingScope::new());
        let pending = scopes[index]
            .as_mut()
            .expect("preowned fixture cleanup seat");
        let result = async {
            let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
            pending.memory = Some(disk_memory.clone());
            let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = disk_memory.clone();
            pending.scratch_directory = Some(kasumi_store::test_utils::private_tempdir()?);
            // This is the same explicit fixture policy used by ScratchDisk::fixture.
            // One config quotes and installs the actual original governor.
            let scratch_config = kasumi_store::ScratchDiskConfig {
                directory: pending
                    .scratch_directory
                    .as_ref()
                    .unwrap()
                    .path()
                    .to_owned(),
                max_bytes: 256 << 30,
                min_free_bytes: 0,
                native_cache_bytes: 8 << 20,
            };
            pending.directory = Some(kasumi_store::test_utils::private_tempdir()?);
            pending.source_directory = Some(kasumi_store::test_utils::private_tempdir()?);
            let queried_path = pending.directory.as_ref().unwrap().path().join("node.kv");
            let source_path = pending
                .source_directory
                .as_ref()
                .unwrap()
                .path()
                .join("node.kv");
            let baseline =
                InstalledBaseline::quoted([&queried_path, &source_path], &scratch_config)?;
            pending.installed_scratch = Some(
                kasumi_store::test_utils::retry_disk_registry(|| {
                    kasumi_store::ScratchDisk::open_fixture(&scratch_config, memory.clone())
                })
                .map_err(anyhow::Error::from)?,
            );
            for (index, path) in [&queried_path, &source_path].into_iter().enumerate() {
                pending.installed[index] = Some(
                    kasumi_store::test_utils::retry_disk_registry(|| {
                        kasumi_store::NodeDisk::fixture_for_path(path, memory.clone())
                    })
                    .map_err(anyhow::Error::from)?,
                );
            }
            // Establish all twelve original standing grants: the exact four
            // metadata components for each physical installation and scratch
            // governor, before native databases, logs, workers or entry staging.
            let installed =
                std::array::from_fn(|index| pending.installed[index].as_ref().unwrap().clone());
            let fixture_scratch = pending.installed_scratch.as_ref().unwrap().clone();
            baseline.assert_drained(&disk_memory, &installed, &fixture_scratch);
            pending.installed_baseline = Some(baseline);
            let admissions = EntryAdmissions::prepare(&memory)?;
            pending.entry_admissions = Some(admissions.clone());
            let store =
                common::store(&queried_path, true, fixture_scratch.clone(), 1, "tenant-a").await?;
            pending.queried = Some(store.clone());
            let log = LogStore::open(store.clone(), 1).await?;
            let source = common::store(&source_path, true, fixture_scratch, 1, "tenant-a").await?;
            pending.source = Some(source.clone());
            let source_log = LogStore::open(source.clone(), 1).await?;
            let snapshot_root = common::snapshot_owner();
            pending.snapshot_root = Some(snapshot_root.clone());
            *self.snapshot_root.lock().unwrap() = Some(snapshot_root.clone());
            let machine =
                StateMachine::open(source, Arc::new(common::Backend::default()), snapshot_root)
                    .await?;
            Ok::<_, kasumi_store::ScratchOperationFailure>((
                StoreScope {
                    cleanup: self.cleanup.clone(),
                    index,
                },
                ConformanceLog {
                    log,
                    memory: memory.clone(),
                    admissions: admissions.clone(),
                },
                ConformanceMachine {
                    machine,
                    source_log,
                    memory,
                    admissions,
                },
            ))
        }
        .await;
        match result {
            Ok(opened) => Ok(opened),
            Err(original) => {
                self.cleanup.state().active[index].store(false, Ordering::Release);
                Err(self.retain(original))
            }
        }
    }
}

type ConformanceSuite = Suite<TypeConfig, ConformanceLog, ConformanceMachine, Builder, StoreScope>;

async fn run_conformance_case<F, Fu>(builder: &Builder, test: F) -> Result<(), StorageError<u64>>
where
    F: FnOnce(ConformanceLog, ConformanceMachine) -> Fu,
    Fu: std::future::Future<Output = Result<(), StorageError<u64>>>,
{
    let (scope, store, machine) = builder.build().await?;
    let result = test(store, machine).await;
    drop(scope);
    // The unchanged Suite case has returned and disposed its accepted machine
    // and log. Join their original workers before this same runtime can stop.
    // Any independent cleanup failure stays in its original admitted seat.
    let cleanup = builder.cleanup.drain_final().await;
    result?;
    cleanup
}

async fn run_conformance_suite(builder: &Builder) -> Result<(), StorageError<u64>> {
    // Keep the exact public cases and order in upstream Suite::test_store.
    // Its synchronous driver stops one runtime after each case; this fixture
    // needs those workers alive until their explicit physical-owner drains.
    macro_rules! case {
        ($name:ident) => {
            eprintln!("conformance case entered: {}", stringify!($name));
            run_conformance_case(builder, ConformanceSuite::$name).await?;
            eprintln!(
                "conformance case returned and drained: {}",
                stringify!($name)
            );
        };
    }
    case!(last_membership_in_log_initial);
    case!(last_membership_in_log);
    case!(last_membership_in_log_multi_step);
    case!(get_membership_initial);
    case!(get_membership_from_log_and_empty_sm);
    case!(get_membership_from_empty_log_and_sm);
    case!(get_membership_from_log_le_sm_last_applied);
    case!(get_membership_from_log_gt_sm_last_applied_1);
    case!(get_membership_from_log_gt_sm_last_applied_2);
    case!(get_initial_state_without_init);
    case!(get_initial_state_membership_from_log_and_sm);
    case!(get_initial_state_with_state);
    case!(get_initial_state_last_log_gt_sm);
    case!(get_initial_state_last_log_lt_sm);
    case!(get_initial_state_log_ids);
    case!(get_initial_state_re_apply_committed);
    case!(save_vote);
    case!(get_log_entries);
    case!(limited_get_log_entries);
    case!(try_get_log_entry);
    case!(initial_logs);
    case!(get_log_state);
    case!(get_log_id);
    case!(last_id_in_log);
    case!(last_applied_state);
    case!(purge_logs_upto_0);
    case!(purge_logs_upto_5);
    case!(purge_logs_upto_20);
    case!(delete_logs_since_11);
    case!(delete_logs_since_0);
    case!(append_to_log);
    case!(snapshot_meta);
    case!(apply_single);
    case!(apply_multiple);
    // This original case holds two simultaneous scopes. Both are returned to
    // the same fixed inventory before its final observed drain.
    eprintln!("conformance case entered: transfer_snapshot");
    let result = ConformanceSuite::transfer_snapshot(builder).await;
    let cleanup = builder.cleanup.drain_final().await;
    result?;
    cleanup
}

#[test]
fn openraft_storage_conformance_suite() -> FixtureResult<()> {
    let builder = Builder::prepare()?;
    let runtime = tokio::runtime::Runtime::new()?;
    let (result, cleanup) = runtime.block_on(async {
        let result = run_conformance_suite(&builder).await;
        if result.is_err() {
            builder.diagnose_apply_failure();
        }
        let cleanup = builder.cleanup.drain_final().await;
        if cleanup.is_err() {
            builder.cleanup.diagnose_failures().await;
        }
        (result, cleanup)
    });
    if let Some(original) = builder.take_failure() {
        return Err(original.into());
    }
    result.map_err(kasumi_raft::test_utils::FixtureFailure::from)?;
    cleanup.map_err(Into::into)
}

fn entry_digest(entry: &Entry<TypeConfig>) -> [u8; 32] {
    use sha2::Digest;
    struct DigestWriter(sha2::Sha256);
    impl std::io::Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter(sha2::Sha256::new());
    serde_json::to_writer(&mut writer, entry).unwrap();
    writer.0.finalize().into()
}

#[tokio::test]
async fn conformance_adapter_appends_whole_entries_to_only_its_actual_source_and_drains_both()
-> FixtureResult<()> {
    let builder = Builder::prepare()?;
    let (scope, mut queried, mut machine) = builder.build().await?;
    let (memory, installed_baseline, installed, scratch) = {
        let scopes = builder.cleanup.state().scopes.lock().await;
        let pending = scopes[scope.index].as_ref().unwrap();
        (
            pending.memory.as_ref().unwrap().clone(),
            pending.installed_baseline.unwrap(),
            std::array::from_fn(|index| pending.installed[index].as_ref().unwrap().clone()),
            pending.installed_scratch.as_ref().unwrap().clone(),
        )
    };
    let blank = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 1),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    let membership = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 2),
        payload: EntryPayload::Membership(openraft::Membership::new(
            vec![std::collections::BTreeSet::from([1, 2])],
            std::collections::BTreeMap::from([
                (1, openraft::BasicNode::new("actual-node-one")),
                (2, openraft::BasicNode::new("actual-node-two")),
            ]),
        )),
        initialization: None,
    };
    let expected = [entry_digest(&blank), entry_digest(&membership)];
    let last = membership.log_id;
    assert_eq!(machine.apply([blank, membership]).await?.len(), 2);
    assert!(
        queried.try_get_log_entries(..).await?.is_empty(),
        "Suite's independent queried log changed"
    );
    let source = machine.source_log.try_get_log_entries(..).await?;
    assert_eq!(source.len(), 2);
    for (entry, expected) in source.iter().zip(expected) {
        assert_eq!(entry_digest(entry), expected);
    }
    assert_eq!(machine.applied_state().await?.0, Some(last));
    drop(source);
    // The unchanged Suite supplies an older counterfactual membership to its
    // independent queried log, then skips the exact already applied index.
    let older_query = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(2, 0), 1),
        payload: EntryPayload::Membership(openraft::Membership::new(
            vec![std::collections::BTreeSet::from([3, 4])],
            std::collections::BTreeMap::from([
                (3, openraft::BasicNode::new("queried-node-three")),
                (4, openraft::BasicNode::new("queried-node-four")),
            ]),
        )),
        initialization: None,
    };
    let later_query = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(2, 0), 3),
        payload: EntryPayload::Membership(openraft::Membership::new(
            vec![std::collections::BTreeSet::from([5, 6])],
            std::collections::BTreeMap::from([
                (5, openraft::BasicNode::new("queried-node-five")),
                (6, openraft::BasicNode::new("queried-node-six")),
            ]),
        )),
        initialization: None,
    };
    let later_query_id = later_query.log_id;
    let later_query_digest = entry_digest(&later_query);
    queried.blocking_append([older_query]).await?;
    queried.blocking_append([later_query]).await?;
    let queried_state = queried.get_log_state().await?;
    assert_eq!(queried_state.last_purged_log_id, Some(last));
    assert_eq!(queried_state.last_log_id, Some(later_query_id));
    let queried_entries = queried.try_get_log_entries(..).await?;
    assert_eq!(queried_entries.len(), 1);
    assert_eq!(entry_digest(&queried_entries[0]), later_query_digest);
    drop(queried_entries);
    let source = machine.source_log.try_get_log_entries(..).await?;
    assert_eq!(source.len(), 2, "queried compaction altered actual source");
    for (entry, expected) in source.iter().zip(expected) {
        assert_eq!(entry_digest(entry), expected);
    }
    drop(source);

    // A later direct state-machine call provides no entry at index three.
    // Its actual source can retire only the exact completed endpoint two.
    let later_source = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 4),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    let later_source_id = later_source.log_id;
    let later_source_digest = entry_digest(&later_source);
    assert_eq!(machine.apply([later_source]).await?.len(), 1);
    let source_state = machine.source_log.get_log_state().await?;
    assert_eq!(source_state.last_purged_log_id, Some(last));
    assert_eq!(source_state.last_log_id, Some(later_source_id));
    let source = machine.source_log.try_get_log_entries(..).await?;
    assert_eq!(source.len(), 1);
    assert_eq!(entry_digest(&source[0]), later_source_digest);
    drop(source);
    let (applied, membership) = machine.applied_state().await?;
    assert_eq!(applied, Some(later_source_id));
    assert_eq!(membership.log_id(), &Some(last));
    assert_eq!(
        membership.membership().get_joint_config(),
        &vec![std::collections::BTreeSet::from([1, 2])],
    );
    let queried_state = queried.get_log_state().await?;
    assert_eq!(queried_state.last_purged_log_id, Some(last));
    assert_eq!(queried_state.last_log_id, Some(later_query_id));
    let queried_entries = queried.try_get_log_entries(..).await?;
    assert_eq!(queried_entries.len(), 1);
    assert_eq!(entry_digest(&queried_entries[0]), later_query_digest);
    drop(queried_entries);
    drop(membership);
    assert!(
        builder.cleanup.drain_final().await.is_err(),
        "live accepted scope was declared drained"
    );
    drop(machine);
    drop(queried);
    drop(scope);
    builder.cleanup.drain_final().await?;
    assert!(
        builder
            .cleanup
            .state()
            .scopes
            .lock()
            .await
            .iter()
            .all(Option::is_none)
    );
    installed_baseline.assert_drained(&memory, &installed, &scratch);
    Ok(())
}

#[tokio::test]
async fn conformance_gap_without_actual_publication_keeps_original_log_and_no_purge()
-> FixtureResult<()> {
    let builder = Builder::prepare()?;
    let (scope, mut queried, mut machine) = builder.build().await?;
    let (memory, installed_baseline, installed, scratch) = {
        let scopes = builder.cleanup.state().scopes.lock().await;
        let pending = scopes[scope.index].as_ref().unwrap();
        (
            pending.memory.as_ref().unwrap().clone(),
            pending.installed_baseline.unwrap(),
            std::array::from_fn(|index| pending.installed[index].as_ref().unwrap().clone()),
            pending.installed_scratch.as_ref().unwrap().clone(),
        )
    };
    let original = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 1),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    let original_id = original.log_id;
    let original_digest = entry_digest(&original);
    queried.blocking_append([original]).await?;
    let missing_publication = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 3),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    assert!(
        queried
            .blocking_append([missing_publication])
            .await
            .is_err()
    );
    assert_eq!(machine.admissions.published(), None);
    let state = queried.get_log_state().await?;
    assert_eq!(state.last_purged_log_id, None);
    assert_eq!(state.last_log_id, Some(original_id));
    let actual = queried.try_get_log_entries(..).await?;
    assert_eq!(actual.len(), 1);
    assert_eq!(entry_digest(&actual[0]), original_digest);
    drop(actual);
    assert!(machine.source_log.try_get_log_entries(..).await?.is_empty());
    assert_eq!(machine.applied_state().await?.0, None);
    drop(machine);
    drop(queried);
    drop(scope);
    builder.cleanup.drain_final().await?;
    assert!(
        builder
            .cleanup
            .state()
            .scopes
            .lock()
            .await
            .iter()
            .all(Option::is_none)
    );
    installed_baseline.assert_drained(&memory, &installed, &scratch);
    Ok(())
}

#[tokio::test]
async fn conformance_entry_container_refuses_before_clone_or_either_log_changes()
-> FixtureResult<()> {
    use kasumi_store::NodeDiskMemoryAdmission;
    let builder = Builder::prepare()?;
    let (scope, mut queried, mut machine) = builder.build().await?;
    let (memory, installed_baseline, installed, scratch) = {
        let scopes = builder.cleanup.state().scopes.lock().await;
        let pending = scopes[scope.index].as_ref().unwrap();
        (
            pending.memory.as_ref().unwrap().clone(),
            pending.installed_baseline.unwrap(),
            std::array::from_fn(|index| pending.installed[index].as_ref().unwrap().clone()),
            pending.installed_scratch.as_ref().unwrap().clone(),
        )
    };
    let before = memory.snapshot();
    let remaining = (256_u64 << 20) - before.bookkeeping_bytes - before.used_bytes;
    let pressure = memory.clone().reserve_installed(
        remaining - kasumi_store::test_utils::TestDiskMemory::required_reservation_bytes(0)?,
    )?;
    let full = memory.snapshot();
    let blank = Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 1),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    assert!(machine.apply([blank]).await.is_err());
    assert_eq!(memory.snapshot().used_bytes, full.used_bytes);
    assert_eq!(memory.snapshot().live_reservations, full.live_reservations);
    assert!(
        machine
            .admissions
            .0
            .as_ref()
            .unwrap()
            .fees
            .lock()
            .unwrap()
            .is_none(),
        "refused staging installed a replacement fee"
    );
    drop(pressure);
    assert!(machine.source_log.try_get_log_entries(..).await?.is_empty());
    assert!(queried.try_get_log_entries(..).await?.is_empty());
    assert!(machine.applied_state().await?.0.is_none());
    drop(machine);
    drop(queried);
    drop(scope);
    builder.cleanup.drain_final().await?;
    installed_baseline.assert_drained(&memory, &installed, &scratch);
    Ok(())
}

#[test]
fn conformance_protocol_marker_retains_the_actual_registered_creation_original() -> FixtureResult<()>
{
    use std::os::unix::fs::PermissionsExt;
    let builder = Builder::prepare()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64);
    let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory.clone());
    let baseline = memory.snapshot();
    let permissions = std::fs::metadata(directory.path())?.permissions();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
    let original =
        kasumi_store::EncryptedTable::new(&disk, 8 << 20, kasumi_kv::CacheConfig { byte_limit: 0 })
            .err()
            .expect("actual constructor unexpectedly accepted public scratch directory");
    std::fs::set_permissions(directory.path(), permissions)?;
    let id = original.owner_id().expect("actual constructor registered");
    let address = original.with_diagnostic(|report| {
        std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
    });
    let retained = memory.snapshot();
    let marker = builder.retain(original.into());
    assert!(marker.to_string().contains("constructor original retained"));
    {
        let slot = builder.failure.lock().unwrap();
        let original = slot.as_ref().unwrap().creation().unwrap();
        assert_eq!(original.owner_id(), Some(id));
        assert_eq!(
            original.with_diagnostic(|report| {
                std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
            }),
            address
        );
    }
    assert_eq!(memory.snapshot().used_bytes, retained.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        retained.live_reservations
    );
    let public = kasumi_raft::test_utils::FixtureFailure::from(builder.take_failure().unwrap());
    assert!(public.operation_error().is_none());
    assert_eq!(public.creation().unwrap().owner_id(), Some(id));
    let kasumi_raft::test_utils::FixtureFailure::Scratch(
        kasumi_store::ScratchOperationFailure::Creation(original),
    ) = public
    else {
        panic!("original creation branch changed")
    };
    assert_eq!(
        original.retire().disposition(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

fn entry(index: u64, data: &[u8]) -> Entry<TypeConfig> {
    Entry {
        initialization: None,
        log_id: LogId::new(openraft::CommittedLeaderId::new(3, 1), index),
        payload: EntryPayload::Normal(kasumi_raft::RaftCommand::application(data.to_vec())),
    }
}

#[tokio::test]
async fn log_vote_and_committed_cursor_survive_full_reopen() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("node.kv");
    {
        let store = common::store(&path, true, fixture_scratch.clone(), 1, "tenant-a").await?;
        let mut log = LogStore::open(store.clone(), 1).await?;
        log.save_vote(&Vote::new_committed(3, 1)).await?;
        log.blocking_append([entry(0, b"a"), entry(1, b"b"), entry(2, b"uncommitted")])
            .await?;
        log.save_committed(Some(entry(1, b"").log_id)).await?;
        drop(log);
        kasumi_store::test_utils::shutdown_owned_stores_fixture(&store).await?;
    }
    let store = common::store(&path, false, fixture_scratch.clone(), 1, "tenant-a").await?;
    let mut log = LogStore::open(store, 1).await?;
    assert_eq!(log.read_vote().await?, Some(Vote::new_committed(3, 1)));
    assert_eq!(log.read_committed().await?, Some(entry(1, b"").log_id));
    assert_eq!(log.try_get_log_entries(..).await?.len(), 3);
    log.truncate(entry(2, b"").log_id).await?;
    assert_eq!(
        log.get_log_state().await?.last_log_id,
        Some(entry(1, b"").log_id)
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_survives_reopen_and_failed_apply_makes_replica_unavailable() -> FixtureResult<()>
{
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("node.kv");
    let snapshot_meta;
    {
        let store = common::store(&path, true, fixture_scratch.clone(), 1, "tenant-a").await?;
        let backend = Arc::new(common::Backend::default());
        let mut machine =
            StateMachine::open(store.clone(), backend.clone(), common::snapshot_owner()).await?;
        machine.apply([entry(0, b"before")]).await?;
        snapshot_meta = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await?
            .meta;
        backend.fail_apply.store(true, Ordering::Release);
        assert!(machine.apply([entry(1, b"fail")]).await.is_err());
        assert!(machine.failed());
        backend.fail_apply.store(false, Ordering::Release);
        assert!(machine.apply([entry(2, b"must-not-apply")]).await.is_err());
        assert_eq!(backend.values(), vec![b"before".to_vec()]);
        drop(machine);
        kasumi_store::test_utils::shutdown_owned_stores_fixture(&store).await?;
    }
    let store = common::store(&path, false, fixture_scratch.clone(), 1, "tenant-a").await?;
    let backend = Arc::new(common::Backend::default());
    let mut machine = StateMachine::open(store, backend.clone(), common::snapshot_owner()).await?;
    assert!(!machine.failed());
    assert_eq!(machine.applied_state().await?.0, snapshot_meta.last_log_id);
    assert_eq!(backend.values(), vec![b"before".to_vec()]);
    assert_eq!(
        machine.get_current_snapshot().await?.unwrap().meta,
        snapshot_meta
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_buffer_caps_total_size_and_sparse_seeks() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use std::io::SeekFrom;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let mut buffer = SnapshotBuffer::new(&fixture_scratch.clone(), 16, &common::snapshot_owner())?;
    buffer.write_all(b"12345678").await?;
    assert!(buffer.seek(SeekFrom::Start(15)).await.is_err());
    buffer.write_all(b"1234567").await?;
    assert!(buffer.write_all(b"xx").await.is_err());
    buffer.write_all(b"x").await?;
    assert_eq!(buffer.len(), 16);
    assert!(buffer.seek(SeekFrom::Start(17)).await.is_err());
    assert!(buffer.seek(SeekFrom::Current(i64::MIN)).await.is_err());
    assert!(
        SnapshotBuffer::from_bytes(
            &fixture_scratch.clone(),
            vec![0; 17],
            16,
            &common::snapshot_owner()
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn committed_log_replay_survives_every_append_and_commit_io_failure() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use kasumi_store::{
        NodeStore, TenantStore,
        test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
    };
    use openraft::storage::StorageHelper;
    async fn open(
        disk: FaultBackend,
        create: bool,
        persistent: Arc<kasumi_store::NodeDisk>,
        fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    ) -> FixtureResult<Arc<kasumi_store::TenantStorageSet>> {
        let application = (if create {
            TenantStore::initialize_catalog_fixture_with_clock(
                NodeStore::create_fixture_backend_on_disk(
                    disk,
                    kasumi_store::test_utils::storage_admission(),
                    persistent,
                    fixture_scratch.clone(),
                )?,
                "log-crash".into(),
                Arc::new(LocalKeyProvider::new([4; 32])),
                Arc::new(ManualClock::new()),
            )
            .await
        } else {
            TenantStore::open_existing_fixture_with_clock(
                NodeStore::open_fixture_backend_on_disk(
                    disk,
                    kasumi_store::test_utils::storage_admission(),
                    persistent,
                    fixture_scratch.clone(),
                )?,
                "log-crash".into(),
                Arc::new(LocalKeyProvider::new([4; 32])),
                Arc::new(ManualClock::new()),
            )
            .await
        })?;
        let stores = if create {
            kasumi_store::test_utils::initialize_custody_fixture(
                application,
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await?
        } else {
            kasumi_store::test_utils::open_existing_custody_fixture(
                application,
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await?
        };
        if create {
            stores.write_batch(&[], &kasumi_raft::initial_storage_identity(1, "log-crash")?)?;
        }
        Ok(stores)
    }
    async fn append_commit(log: &mut LogStore) -> Result<()> {
        log.blocking_append([entry(1, b"new-a"), entry(2, b"new-b")])
            .await?;
        log.save_committed(Some(entry(2, b"").log_id)).await?;
        Ok(())
    }
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let persistent = kasumi_store::NodeDisk::fixture_for_path(
        &directory.path().join("replay.kv"),
        fixture_scratch.memory().clone(),
    )?;
    let seed = FaultBackend::new();
    let mut initial = LogStore::open(
        open(
            seed.clone(),
            true,
            persistent.clone(),
            fixture_scratch.clone(),
        )
        .await?,
        1,
    )
    .await?;
    initial.save_vote(&Vote::new_committed(3, 1)).await?;
    initial
        .blocking_append([entry(0, b"already-acknowledged")])
        .await?;
    initial.save_committed(Some(entry(0, b"").log_id)).await?;
    let baseline = seed.crash();
    let mut log = LogStore::open(
        open(
            baseline.clone(),
            false,
            persistent.clone(),
            fixture_scratch.clone(),
        )
        .await?,
        1,
    )
    .await?;
    let start = baseline.operations();
    append_commit(&mut log).await?;
    let operations = baseline.operations() - start;
    assert!(operations > 4);
    for failure in 0..=operations {
        let disk = seed.crash();
        let mut log = LogStore::open(
            open(
                disk.clone(),
                false,
                persistent.clone(),
                fixture_scratch.clone(),
            )
            .await?,
            1,
        )
        .await?;
        disk.fail_after(failure);
        let acknowledged = append_commit(&mut log).await.is_ok();
        let store = open(
            disk.crash(),
            false,
            persistent.clone(),
            fixture_scratch.clone(),
        )
        .await?;
        let backend = Arc::new(common::Backend::default());
        let mut log = LogStore::open(store.clone(), 1).await?;
        let mut machine =
            StateMachine::open(store, backend.clone(), common::snapshot_owner()).await?;
        StorageHelper::new(&mut log, &mut machine)
            .get_initial_state()
            .await?;
        let values = backend.values();
        assert_eq!(
            values[0], b"already-acknowledged",
            "previous ACK lost at operation {failure}"
        );
        assert!(
            values.len() == 1
                || values
                    == vec![
                        b"already-acknowledged".to_vec(),
                        b"new-a".to_vec(),
                        b"new-b".to_vec()
                    ]
        );
        if acknowledged {
            assert_eq!(values.len(), 3, "new ACK lost at operation {failure}");
        }
    }
    Ok(())
}
