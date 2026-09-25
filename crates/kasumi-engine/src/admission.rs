//! Node-local admission, never deterministic state-machine validation.
//!
//! RSS is sampled (and can overshoot between samples). Reservations are bounded
//! workspace estimates, not allocator accounting or an OOM-proof RAM guarantee.
//! All resident state, including immutable generations, Tantivy writers, receipts
//! and audit retention, contributes to observed RSS. Committed work bypasses this
//! gate and must finish materializing or make its replica unavailable.
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_query::QueryCancellation;
use kasumi_types::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConfig {
    /// None: half physical memory, limited by the Linux cgroup memory ceiling.
    /// An explicit value must not exceed that detected capacity either.
    pub high_water_bytes: Option<u64>,
    /// None: seven eighths of the high-water mark, providing hysteresis.
    pub low_water_bytes: Option<u64>,
    /// Total reservation cap, including resident and bookkeeping charges.
    /// None: min(high-water / 4, 512 MiB).
    pub max_inflight_bytes: Option<u64>,
    pub max_inflight_operations: usize,
    /// Fixed charge ledger capacity, including facade and resident reservations.
    pub max_reservations: usize,
    /// Fixed startup-owner inventory per independent runtime facade.
    pub max_snapshot_startups: usize,
    /// Fixed strong census of admitted startup lifecycles on this memory core.
    pub max_startup_scopes: usize,
    pub sample_interval_ms: u64,
    pub max_sample_age_ms: u64,
}
impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            high_water_bytes: None,
            low_water_bytes: None,
            max_inflight_bytes: None,
            max_inflight_operations: 64,
            max_reservations: 4096,
            max_snapshot_startups: 64,
            max_startup_scopes: 64,
            sample_interval_ms: 250,
            max_sample_age_ms: 1000,
        }
    }
}
impl AdmissionConfig {
    fn resolve_high_water(&self, capacity: u64) -> anyhow::Result<u64> {
        anyhow::ensure!(capacity > 0, "physical RAM capacity is zero");
        let high = self.high_water_bytes.unwrap_or(capacity / 2);
        anyhow::ensure!(
            high > 0 && high <= capacity,
            "configured admission high-water mark exceeds detected host/container memory capacity"
        );
        Ok(high)
    }

    fn resolve_budgets(&self, high: u64) -> anyhow::Result<(u64, u64)> {
        let low = self.low_water_bytes.unwrap_or(high.saturating_mul(7) / 8);
        let total = self.max_inflight_bytes.unwrap_or((high / 4).min(512 << 20));
        anyhow::ensure!(
            high > 0 && low < high && total > 0 && total <= high,
            "invalid resolved admission budgets"
        );
        Ok((low, total))
    }

    /// Resolve the current total without allocating a governor or adding any
    /// bookkeeping. Fixture storage planners add only their new retained leases.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn resolved_fixture_total_bytes(&self) -> anyhow::Result<u64> {
        self.validate()?;
        let high = self.resolve_high_water(physical_capacity()?)?;
        self.resolve_budgets(high).map(|(_, total)| total)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_reservations >= 3
                && self.max_snapshot_startups > 0
                && self.max_startup_scopes > 0,
            "admission ledger or startup inventory capacity is invalid"
        );
        MemoryCore::required_bookkeeping_bytes(self)?;
        NodeAdmission::inventory_bytes(self)?;
        anyhow::ensure!(
            self.max_inflight_operations > 0,
            "admission operation capacity is zero"
        );
        anyhow::ensure!(
            (10..=10_000).contains(&self.sample_interval_ms),
            "RSS sample interval must be 10..10000 ms"
        );
        anyhow::ensure!(
            self.max_sample_age_ms >= self.sample_interval_ms && self.max_sample_age_ms <= 60_000,
            "RSS sample age must cover interval and be at most 60 seconds"
        );
        anyhow::ensure!(
            self.high_water_bytes != Some(0) && self.max_inflight_bytes != Some(0),
            "admission byte capacity is zero"
        );
        if let (Some(low), Some(high)) = (self.low_water_bytes, self.high_water_bytes) {
            anyhow::ensure!(low < high, "RSS low water must be below high water");
        }
        Ok(())
    }
}

mod disk_memory;
mod installed;
pub mod snapshot_work;
pub mod startup;

trait MemorySource: Send + Sync {
    fn resident_bytes(&self) -> anyhow::Result<u64>;
}
struct ProcessMemory;
impl MemorySource for ProcessMemory {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        #[cfg(target_os = "linux")]
        {
            let pages: u64 = std::fs::read_to_string("/proc/self/statm")?
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("RSS missing"))?
                .parse()?;
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            anyhow::ensure!(page_size > 0, "page size unavailable");
            pages
                .checked_mul(page_size as u64)
                .ok_or_else(|| anyhow::anyhow!("RSS overflow"))
        }
        #[cfg(target_os = "macos")]
        {
            let mut info: libc::mach_task_basic_info_data_t = unsafe { std::mem::zeroed() };
            let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
            #[allow(deprecated)]
            let status = unsafe {
                libc::task_info(
                    libc::mach_task_self(),
                    libc::MACH_TASK_BASIC_INFO,
                    (&mut info as *mut libc::mach_task_basic_info_data_t).cast(),
                    &mut count,
                )
            };
            anyhow::ensure!(status == libc::KERN_SUCCESS, "task RSS unavailable");
            Ok(info.resident_size)
        }
    }
}

fn physical_capacity() -> anyhow::Result<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut bytes = 0u64;
        let mut len = std::mem::size_of::<u64>();
        let status = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                (&mut bytes as *mut u64).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        anyhow::ensure!(status == 0 && bytes > 0, "physical RAM unavailable");
        Ok(bytes)
    }
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo")?;
        let mut bytes = info
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))
            .and_then(|line| line.split_whitespace().next())
            .ok_or_else(|| anyhow::anyhow!("physical RAM unavailable"))?
            .parse::<u64>()?
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("physical RAM overflow"))?;
        // Respect ancestor ceilings too. Names are read from the kernel and never
        // accepted from a remote request. Hybrid/v1 installations use the v1 root.
        let groups = std::fs::read_to_string("/proc/self/cgroup")?;
        for line in groups.lines() {
            let fields: Vec<_> = line.splitn(3, ':').collect();
            if fields.len() != 3 {
                continue;
            }
            let (root, filename) = if fields[1].is_empty() {
                (std::path::Path::new("/sys/fs/cgroup"), "memory.max")
            } else if fields[1].split(',').any(|s| s == "memory") {
                (
                    std::path::Path::new("/sys/fs/cgroup/memory"),
                    "memory.limit_in_bytes",
                )
            } else {
                continue;
            };
            let mut path = root.to_path_buf();
            for component in std::path::Path::new(fields[2]).components() {
                if let std::path::Component::Normal(component) = component {
                    path.push(component);
                }
            }
            while path.starts_with(root) {
                match std::fs::read_to_string(path.join(filename)) {
                    Ok(value) if value.trim() == "max" => {}
                    Ok(value) => bytes = bytes.min(value.trim().parse::<u64>()?),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if path == root {
                    break;
                }
                path.pop();
            }
        }
        anyhow::ensure!(bytes > 0, "physical RAM capacity is zero");
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AdmissionSnapshot {
    pub resident_bytes: u64,
    pub high_water_bytes: u64,
    pub low_water_bytes: u64,
    /// All charged bytes, including fixed governor and facade bookkeeping.
    pub reserved_bytes: u64,
    pub bookkeeping_bytes: u64,
    /// Non-operation reservations, excluding separately reported bookkeeping.
    pub resident_reserved_bytes: u64,
    pub live_reservations: usize,
    pub inflight_operations: usize,
    pub pressured: bool,
    pub sample_usable: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChargeKind {
    Operation,
    Resident,
    Bookkeeping,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChargeOrigin {
    OrdinaryOperation,
    OtherOrdinary,
    AuditMaintenance,
}
#[derive(Clone, Copy)]
enum ReserveKindError {
    Exhausted,
    IdentifierExhausted,
}
struct Charge {
    bytes: u64,
    kind: ChargeKind,
    // This never changes when an operation is retained as resident state.
    origin: ChargeOrigin,
    cancellation: Option<QueryCancellation>,
}
struct ChargeSlot {
    id: u64,
    charge: Option<Charge>,
    next_free: Option<usize>,
}
struct State {
    resident: u64,
    sampled_at: Duration,
    usable: bool,
    pressured: bool,
    bytes: u64,
    // Capacity unavailable to ordinary Operation reservations, including
    // their retained descendants, while Raft and archive work may need it.
    ordinary_protected: u64,
    ordinary_protected_slots: usize,
    operations: usize,
    next: u64,
    slots: Box<[ChargeSlot]>,
    free: Option<usize>,
    live: usize,
}
impl State {
    fn charge(&self, slot: usize, id: u64) -> Option<&Charge> {
        self.slots
            .get(slot)
            .filter(|slot| slot.id == id)?
            .charge
            .as_ref()
    }
    fn charge_mut(&mut self, slot: usize, id: u64) -> Option<&mut Charge> {
        self.slots
            .get_mut(slot)
            .filter(|slot| slot.id == id)?
            .charge
            .as_mut()
    }
}

// This is an admitted workspace estimate, not an allocator-layout guarantee.
// Charge requested storage plus an explicit allocation allowance for each fixed
// allocation, and an explicitly configured sampler stack and probe workspace.
const ALLOCATION_ALLOWANCE: u64 = 4096;
const SAMPLER_STACK_BYTES: usize = 128 << 10;
const SAMPLE_WORKSPACE_BYTES: u64 = 16 << 10;
// std does not expose its thread control allocation layout. This is a named
// workspace estimate for the thread name, closure, packet and synchronization
// bookkeeping, separate from the explicitly configured stack.
const SAMPLER_CONTROL_BYTES: u64 = 16 << 10;
fn allocation_bytes<T>(count: usize) -> anyhow::Result<u64> {
    u64::try_from(std::mem::size_of::<T>())?
        .checked_mul(u64::try_from(count)?)
        .and_then(|bytes| bytes.checked_add(ALLOCATION_ALLOWANCE))
        .ok_or_else(|| anyhow::anyhow!("memory bookkeeping size overflow"))
}
fn arc_bytes<T>() -> anyhow::Result<u64> {
    allocation_bytes::<T>(1)?
        .checked_add((2 * std::mem::size_of::<usize>()) as u64)
        .ok_or_else(|| anyhow::anyhow!("memory owner size overflow"))
}

/// Shared resource accounting and the bounded strong startup-scope census.
/// Runtime admission fences remain separate; a resident lease retains this core.
///
/// `new` creates an independent governor for an explicit embedding policy.
/// `installed` selects the single process-wide installed governor. Runtime
/// facades deliberately reuse this exact core; installed NodeDisk caller wiring
/// remains separately tracked in the storage-admission workstream.
pub struct MemoryCore {
    storage_census: kasumi_store::StorageCensus,
    startups: Mutex<startup::Census>,
    snapshot_work: Mutex<snapshot_work::Census>,
    sampler: Option<std::thread::JoinHandle<()>>,
    data: Arc<MemoryState>,
}
// The sampler owns only this data. It can never own, upgrade, or finally drop
// the outer MemoryCore that owns its actual JoinHandle.
struct MemoryState {
    config: AdmissionConfig,
    high: u64,
    low: u64,
    max_bytes: u64,
    base_bytes: u64,
    memory: Arc<dyn MemorySource>,
    clock: Arc<dyn LeaseClock>,
    state: Mutex<State>,
    stop: Mutex<bool>,
    wake: std::sync::Condvar,
    sampler_failed: std::sync::atomic::AtomicBool,
}
struct PreparedCore {
    config: AdmissionConfig,
    high: u64,
    low: u64,
    max_bytes: u64,
    base_bytes: u64,
    resident: u64,
    sampled_at: Duration,
}
impl MemoryCore {
    /// Select the one installed process governor. Runtime replacements construct
    /// a fresh NodeAdmission facade on this same retained resource core.
    pub fn installed(config: AdmissionConfig) -> anyhow::Result<Arc<Self>> {
        installed::select(config)
    }
    /// Explicit core injection must preserve the complete configured policy.
    pub fn require_policy(&self, config: &AdmissionConfig) -> anyhow::Result<()> {
        anyhow::ensure!(
            &self.data.config == config,
            "installed memory admission policy differs from retained core"
        );
        Ok(())
    }
    pub fn required_bookkeeping_bytes(config: &AdmissionConfig) -> anyhow::Result<u64> {
        let source = arc_bytes::<ProcessMemory>()?;
        let clock = arc_bytes::<SystemLeaseClock>()?;
        let data = arc_bytes::<MemoryState>()?;
        let startups = startup::Census::required_bytes(config.max_startup_scopes)?;
        let snapshot_work = snapshot_work::Census::required_bytes(config.max_inflight_operations)?;
        let storage = kasumi_store::StorageCensus::required_bytes(config.max_reservations)?;
        arc_bytes::<Self>()?
            .checked_add(allocation_bytes::<ChargeSlot>(config.max_reservations)?)
            .and_then(|bytes| bytes.checked_add(data))
            .and_then(|bytes| bytes.checked_add(startups))
            .and_then(|bytes| bytes.checked_add(snapshot_work))
            .and_then(|bytes| bytes.checked_add(storage))
            .and_then(|bytes| bytes.checked_add(source))
            .and_then(|bytes| bytes.checked_add(clock))
            .and_then(|bytes| bytes.checked_add(SAMPLER_STACK_BYTES as u64))
            .and_then(|bytes| bytes.checked_add(SAMPLE_WORKSPACE_BYTES))
            .and_then(|bytes| bytes.checked_add(SAMPLER_CONTROL_BYTES))
            .ok_or_else(|| anyhow::anyhow!("memory core bookkeeping overflow"))
    }
    fn prepare(
        config: AdmissionConfig,
        high: u64,
        memory: &dyn MemorySource,
        clock: &dyn LeaseClock,
    ) -> anyhow::Result<PreparedCore> {
        config.validate()?;
        let (low, max_bytes) = config.resolve_budgets(high)?;
        let base_bytes = Self::required_bookkeeping_bytes(&config)?;
        let sampled_at = clock.now();
        let resident = memory.resident_bytes()?;
        anyhow::ensure!(
            clock.now().saturating_sub(sampled_at)
                < Duration::from_millis(config.max_sample_age_ms)
                && resident <= low
                && base_bytes <= max_bytes
                && resident
                    .checked_add(base_bytes)
                    .is_some_and(|total| total < high),
            "memory core bookkeeping admission denied"
        );
        // The base is accepted before allocating the fixed ledger, owner Arc,
        // source/clock Arcs, or sampling thread. Failure publishes no core.
        Ok(PreparedCore {
            config,
            high,
            low,
            max_bytes,
            base_bytes,
            resident,
            sampled_at,
        })
    }
    fn allocate(
        prepared: PreparedCore,
        memory: Arc<dyn MemorySource>,
        clock: Arc<dyn LeaseClock>,
    ) -> anyhow::Result<Arc<Self>> {
        let storage_census =
            kasumi_store::StorageCensus::allocate(prepared.config.max_reservations)?;
        let startups = Mutex::new(startup::Census::allocate(
            prepared.config.max_startup_scopes,
        )?);
        let snapshot_work = Mutex::new(snapshot_work::Census::allocate(
            prepared.config.max_inflight_operations,
        )?);
        let mut slots = Vec::new();
        slots.try_reserve_exact(prepared.config.max_reservations)?;
        for index in 0..prepared.config.max_reservations {
            slots.push(ChargeSlot {
                id: 0,
                charge: None,
                next_free: (index + 1 < prepared.config.max_reservations).then_some(index + 1),
            });
        }
        let data = Arc::new(MemoryState {
            config: prepared.config,
            high: prepared.high,
            low: prepared.low,
            max_bytes: prepared.max_bytes,
            base_bytes: prepared.base_bytes,
            memory,
            clock,
            state: Mutex::new(State {
                resident: prepared.resident,
                sampled_at: prepared.sampled_at,
                usable: true,
                pressured: false,
                bytes: prepared.base_bytes,
                ordinary_protected: 0,
                ordinary_protected_slots: 0,
                operations: 0,
                next: 0,
                slots: slots.into_boxed_slice(),
                free: Some(0),
                live: 0,
            }),
            stop: Mutex::new(false),
            wake: std::sync::Condvar::new(),
            sampler_failed: std::sync::atomic::AtomicBool::new(false),
        });
        drop(data.state.lock().unwrap());
        drop(data.stop.lock().unwrap());
        let core = Arc::new(Self {
            storage_census,
            startups,
            snapshot_work,
            sampler: None,
            data,
        });
        let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = core.clone();
        core.storage_census.bind_provider(&provider)?;
        // Binding stores the exact address, not a Weak. Unpublished sampler
        // startup still has the unique Arc required by Arc::get_mut.
        drop(provider);
        Ok(core)
    }
    pub fn new(config: AdmissionConfig) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let high = config.resolve_high_water(physical_capacity()?)?;
        let memory = ProcessMemory;
        let clock = SystemLeaseClock;
        let prepared = Self::prepare(config, high, &memory, &clock)?;
        let mut core = Self::allocate(prepared, Arc::new(memory), Arc::new(clock))?;
        Arc::get_mut(&mut core)
            .expect("unpublished memory core")
            .start_sampler()?;
        Ok(core)
    }
    fn start_sampler(&mut self) -> std::io::Result<()> {
        if self.sampler.is_some() {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        let data = self.data.clone();
        let interval = Duration::from_millis(data.config.sample_interval_ms);
        let sampler = std::thread::Builder::new()
            .name("kasumi-rss".into())
            .stack_size(SAMPLER_STACK_BYTES)
            .spawn(move || {
                loop {
                    let stopped = data.stop.lock().unwrap_or_else(|p| p.into_inner());
                    let (stopped, _) = data
                        .wake
                        .wait_timeout_while(stopped, interval, |stop| !*stop)
                        .unwrap_or_else(|p| p.into_inner());
                    if *stopped {
                        break;
                    }
                    drop(stopped);
                    data.refresh();
                }
            })?;
        self.sampler = Some(sampler);
        Ok(())
    }
    #[cfg(test)]
    fn create(
        config: AdmissionConfig,
        high: u64,
        memory: Arc<dyn MemorySource>,
        clock: Arc<dyn LeaseClock>,
    ) -> anyhow::Result<Arc<Self>> {
        let prepared = Self::prepare(config, high, memory.as_ref(), clock.as_ref())?;
        Self::allocate(prepared, memory, clock)
    }
    #[cfg(test)]
    fn refresh(&self) {
        self.data.refresh();
    }
}
impl Drop for MemoryCore {
    fn drop(&mut self) {
        *self.data.stop.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.data.wake.notify_one();
        if let Some(sampler) = self.sampler.take() {
            // The actual sampler has no outer-core reference. Its original panic
            // outcome, if any, remains owned until this join finishes. Only then
            // may the accounting data, base charge and thread metadata disappear.
            drop(sampler.join());
        }
    }
}
impl MemoryState {
    fn refresh(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.sample(&mut state);
    }
    fn sample(&self, state: &mut State) {
        if self
            .sampler_failed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            state.usable = false;
            state.pressured = true;
            return;
        }
        state.usable = false;
        // The state lock remains held while recording a terminal probe panic,
        // so no competing admission can reuse a pre-panic successful sample.
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let start = self.clock.now();
            let result = self.memory.resident_bytes();
            (start, result, self.clock.now())
        }));
        let (start, result, finished) = match observed {
            Ok(observed) => observed,
            Err(panic) => {
                self.sampler_failed
                    .store(true, std::sync::atomic::Ordering::Release);
                state.pressured = true;
                for slot in &state.slots {
                    if let Some(token) = slot
                        .charge
                        .as_ref()
                        .and_then(|charge| charge.cancellation.as_ref())
                    {
                        token.cancel();
                    }
                }
                std::panic::resume_unwind(panic);
            }
        };
        state.sampled_at = start;
        if let Ok(resident) = result {
            state.resident = resident;
            state.usable = finished.saturating_sub(start)
                < Duration::from_millis(self.config.max_sample_age_ms);
            if resident >= self.high {
                state.pressured = true;
            } else if resident <= self.low {
                state.pressured = false;
            }
        }
        if !state.usable || state.pressured {
            for slot in &state.slots {
                if let Some(charge) = &slot.charge
                    && let Some(token) = &charge.cancellation
                {
                    token.cancel();
                }
            }
        }
    }
    fn refresh_stale(&self, state: &mut State) {
        if !state.usable
            || self.clock.now().saturating_sub(state.sampled_at)
                >= Duration::from_millis(self.config.max_sample_age_ms)
        {
            self.sample(state);
        }
    }
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut bookkeeping_bytes = self.base_bytes;
        let mut resident_reserved_bytes = 0;
        for charge in state.slots.iter().filter_map(|slot| slot.charge.as_ref()) {
            match charge.kind {
                ChargeKind::Bookkeeping => bookkeeping_bytes += charge.bytes,
                ChargeKind::Resident => resident_reserved_bytes += charge.bytes,
                ChargeKind::Operation => {}
            }
        }
        AdmissionSnapshot {
            resident_bytes: state.resident,
            high_water_bytes: self.high,
            low_water_bytes: self.low,
            reserved_bytes: state.bytes,
            bookkeeping_bytes,
            resident_reserved_bytes,
            live_reservations: state.live,
            inflight_operations: state.operations,
            pressured: state.pressured,
            sample_usable: state.usable
                && self.clock.now().saturating_sub(state.sampled_at)
                    < Duration::from_millis(self.config.max_sample_age_ms),
        }
    }
    fn check_release(&self, token: &QueryCancellation) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.refresh_stale(&mut state);
        if !state.usable || state.pressured {
            token.cancel();
        }
        token.check()
    }
}
impl MemoryCore {
    pub(crate) fn protect_ordinary(
        self: &Arc<Self>,
        bytes: u64,
        slots: usize,
    ) -> Result<OrdinaryProtection> {
        let mut state = self.data.state.lock().unwrap_or_else(|p| p.into_inner());
        self.data.refresh_stale(&mut state);
        let protected = state.ordinary_protected.checked_add(bytes);
        let protected_slots = state.ordinary_protected_slots.checked_add(slots);
        if !state.usable
            || state.pressured
            || protected_slots.is_none_or(|slots| {
                state
                    .live
                    .checked_add(slots)
                    .is_none_or(|live| live > state.slots.len())
            })
            || protected.is_none_or(|protected| {
                state.bytes.checked_add(protected).is_none_or(|total| {
                    total > self.data.max_bytes
                        || state
                            .resident
                            .checked_add(total)
                            .is_none_or(|observed| observed >= self.data.high)
                })
            })
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "node maintenance headroom unavailable",
            ));
        }
        state.ordinary_protected = protected.expect("checked protected headroom");
        state.ordinary_protected_slots = protected_slots.expect("checked protected slots");
        Ok(OrdinaryProtection {
            core: self.clone(),
            bytes,
            slots,
        })
    }

    pub fn snapshot(&self) -> AdmissionSnapshot {
        self.data.snapshot()
    }
    fn check_release(&self, token: &QueryCancellation) -> Result<()> {
        self.data.check_release(token)
    }
    fn reserve_kind(
        self: &Arc<Self>,
        bytes: u64,
        cancellation: Option<QueryCancellation>,
        kind: ChargeKind,
    ) -> Result<Reservation> {
        let origin = if kind == ChargeKind::Operation {
            ChargeOrigin::OrdinaryOperation
        } else {
            ChargeOrigin::OtherOrdinary
        };
        self.reserve_kind_raw(bytes, cancellation, kind, origin)
            .map_err(|error| match error {
                ReserveKindError::Exhausted => Error::new(
                    ErrorCode::ResourceExhausted,
                    "node memory or work admission budget exhausted",
                ),
                ReserveKindError::IdentifierExhausted => {
                    Error::new(ErrorCode::Unavailable, "admission identifier exhausted")
                }
            })
    }
    fn reserve_audit_escrow(self: &Arc<Self>, bytes: u64) -> Result<Reservation> {
        self.reserve_kind_raw(
            bytes,
            None,
            ChargeKind::Resident,
            ChargeOrigin::AuditMaintenance,
        )
        .map_err(|error| match error {
            ReserveKindError::Exhausted => Error::new(
                ErrorCode::ResourceExhausted,
                "node memory or work admission budget exhausted",
            ),
            ReserveKindError::IdentifierExhausted => {
                Error::new(ErrorCode::Unavailable, "admission identifier exhausted")
            }
        })
    }
    // Installed storage needs a typed refusal before its first resident buffer
    // allocation or physical read. This path avoids constructing a rich Error
    // for the refusal; the existing sampler may have its own workspace.
    fn reserve_kind_raw(
        self: &Arc<Self>,
        bytes: u64,
        cancellation: Option<QueryCancellation>,
        kind: ChargeKind,
        origin: ChargeOrigin,
    ) -> std::result::Result<Reservation, ReserveKindError> {
        let mut state = self.data.state.lock().unwrap_or_else(|p| p.into_inner());
        self.data.refresh_stale(&mut state);
        let total = state.bytes.checked_add(bytes);
        if !state.usable
            || state.pressured
            || state.free.is_none()
            || (kind == ChargeKind::Operation
                && state.operations >= self.data.config.max_inflight_operations)
            || (origin == ChargeOrigin::OrdinaryOperation
                && state
                    .live
                    .checked_add(1)
                    .and_then(|live| live.checked_add(state.ordinary_protected_slots))
                    .is_none_or(|live| live > state.slots.len()))
            || total.is_none_or(|total| {
                total > self.data.max_bytes
                    || state
                        .resident
                        .checked_add(total)
                        .is_none_or(|observed| observed >= self.data.high)
                    || (origin == ChargeOrigin::OrdinaryOperation
                        && total.checked_add(state.ordinary_protected).is_none_or(
                            |protected_total| {
                                protected_total > self.data.max_bytes
                                    || state
                                        .resident
                                        .checked_add(protected_total)
                                        .is_none_or(|observed| observed >= self.data.high)
                            },
                        ))
            })
        {
            return Err(ReserveKindError::Exhausted);
        }
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or(ReserveKindError::IdentifierExhausted)?;
        let slot = state.free.expect("checked free charge slot");
        state.free = state.slots[slot].next_free;
        state.slots[slot] = ChargeSlot {
            id,
            charge: Some(Charge {
                bytes,
                kind,
                origin,
                cancellation,
            }),
            next_free: None,
        };
        state.bytes = total.expect("checked reservation total");
        state.operations += usize::from(kind == ChargeKind::Operation);
        state.live += 1;
        Ok(Reservation {
            core: self.clone(),
            slot,
            id,
        })
    }
    pub fn reserve_resident(self: &Arc<Self>, bytes: u64) -> Result<Reservation> {
        self.reserve_kind(bytes, None, ChargeKind::Resident)
    }
}

struct SnapshotStartups {
    closed: bool,
    owners: Option<Box<[Option<Weak<kasumi_raft::SnapshotBufferOwner>>]>>,
    // This covers allocated inventory capacity independently of child charges.
    inventory: Option<Reservation>,
}
pub struct NodeAdmission {
    core: Arc<MemoryCore>,
    snapshot_startup_drain: tokio::sync::Mutex<kasumi_types::drain::DrainReport>,
    // Report is destroyed before an inventory charge retained for its failures.
    snapshot_startups: Mutex<SnapshotStartups>,
    // Core-only reservation avoids facade -> charge -> facade ownership cycles.
    _facade: Reservation,
}
impl NodeAdmission {
    /// Fixed workspace estimate for a new core and its first runtime facade.
    /// Add the intended payload allowance to this value when configuring a
    /// small total reservation cap. Additional facades reserve their own base.
    pub fn required_bookkeeping_bytes(config: &AdmissionConfig) -> anyhow::Result<u64> {
        let inventory = Self::inventory_bytes(config)?;
        MemoryCore::required_bookkeeping_bytes(config)?
            .checked_add(arc_bytes::<Self>()?)
            .and_then(|bytes| bytes.checked_add(inventory))
            .ok_or_else(|| anyhow::anyhow!("node admission bookkeeping overflow"))
    }
    fn inventory_bytes(config: &AdmissionConfig) -> anyhow::Result<u64> {
        // A Weak retains the owner's inline Arc allocation even after strong
        // owners release the child reservation. Cover that retained storage too.
        let owner = arc_bytes::<kasumi_raft::SnapshotBufferOwner>()?;
        allocation_bytes::<Option<Weak<kasumi_raft::SnapshotBufferOwner>>>(
            config.max_snapshot_startups,
        )?
        .checked_add(
            owner
                .checked_mul(u64::try_from(config.max_snapshot_startups)?)
                .ok_or_else(|| anyhow::anyhow!("startup weak-owner inventory overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("startup inventory overflow"))
    }
    /// Create a new independent runtime startup lifecycle on an existing core.
    /// Resource equivalence does not grant security or service facade identity.
    pub fn from_memory(core: Arc<MemoryCore>) -> anyhow::Result<Arc<Self>> {
        let facade = core.reserve_kind(arc_bytes::<Self>()?, None, ChargeKind::Bookkeeping)?;
        let inventory = core.reserve_kind(
            Self::inventory_bytes(&core.data.config)?,
            None,
            ChargeKind::Bookkeeping,
        )?;
        let mut owners = Vec::new();
        owners.try_reserve_exact(core.data.config.max_snapshot_startups)?;
        owners.resize_with(core.data.config.max_snapshot_startups, || None);
        let facade = Arc::new(Self {
            core,
            snapshot_startups: Mutex::new(SnapshotStartups {
                closed: false,
                owners: Some(owners.into_boxed_slice()),
                inventory: Some(inventory),
            }),
            snapshot_startup_drain: Default::default(),
            _facade: facade,
        });
        drop(facade.snapshot_startups.lock().unwrap());
        Ok(facade)
    }
    /// Construct a fresh independent embedding governor and its runtime facade.
    /// Installed replacements must instead reuse a core through `from_memory`.
    pub fn new(config: AdmissionConfig) -> anyhow::Result<Arc<Self>> {
        Self::from_memory(MemoryCore::new(config)?)
    }
    pub fn memory(&self) -> &Arc<MemoryCore> {
        &self.core
    }
    pub fn shares_memory(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.core, &other.core)
    }
    pub fn snapshot(&self) -> AdmissionSnapshot {
        self.core.snapshot()
    }
    pub(crate) fn check_release(&self, token: &QueryCancellation) -> Result<()> {
        self.core.check_release(token)
    }
    pub fn reserve(
        self: &Arc<Self>,
        bytes: u64,
        cancellation: Option<QueryCancellation>,
    ) -> Result<Reservation> {
        self.core
            .reserve_kind(bytes, cancellation, ChargeKind::Operation)
    }
    pub fn reserve_resident(self: &Arc<Self>, bytes: u64) -> Result<Reservation> {
        self.core.reserve_resident(bytes)
    }
    pub(crate) fn reserve_audit_escrow(self: &Arc<Self>, bytes: u64) -> Result<Reservation> {
        self.core.reserve_audit_escrow(bytes)
    }
    #[cfg(test)]
    fn refresh(&self) {
        self.core.refresh();
    }
    #[cfg(test)]
    fn create(
        config: AdmissionConfig,
        high: u64,
        memory: Arc<dyn MemorySource>,
        clock: Arc<dyn LeaseClock>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::from_memory(MemoryCore::create(config, high, memory, clock)?)
    }
    #[cfg(test)]
    pub(crate) fn with_fixed_memory(
        config: AdmissionConfig,
        capacity: u64,
        resident: u64,
    ) -> anyhow::Result<Arc<Self>> {
        struct FixedMemory(u64);
        impl MemorySource for FixedMemory {
            fn resident_bytes(&self) -> anyhow::Result<u64> {
                Ok(self.0)
            }
        }
        let high = config.resolve_high_water(capacity)?;
        Self::create(
            config,
            high,
            Arc::new(FixedMemory(resident)),
            Arc::new(SystemLeaseClock),
        )
    }
    pub fn snapshot_buffer_owner(
        self: &Arc<Self>,
    ) -> anyhow::Result<Arc<kasumi_raft::SnapshotBufferOwner>> {
        let mut startups = self
            .snapshot_startups
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(!startups.closed, "snapshot startup admission is closed");
        let owners = startups.owners.as_mut().expect("open facade inventory");
        for slot in owners.iter_mut() {
            if slot.as_ref().is_some_and(|owner| owner.strong_count() == 0) {
                *slot = None;
            }
        }
        let slot = owners
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| anyhow::anyhow!("snapshot startup inventory exhausted"))?;
        let buffers = kasumi_raft::SNAPSHOT_BUFFER_SLOTS;
        let bytes = kasumi_raft::SnapshotBufferOwner::required_bytes(buffers)?;
        let charge = self.reserve_resident(bytes)?;
        let owner = kasumi_raft::SnapshotBufferOwner::new(buffers, Arc::new(charge))?;
        *slot = Some(Arc::downgrade(&owner));
        Ok(owner)
    }
    pub async fn drain_snapshot_startups(&self) -> kasumi_types::drain::DrainResult {
        use kasumi_types::drain::DrainCompletion;
        let mut report = self.snapshot_startup_drain.lock().await;
        let count = {
            let mut startups = self
                .snapshot_startups
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            startups.closed = true;
            startups.owners.as_ref().map_or(0, |owners| owners.len())
        };
        let mut retained = None;
        for index in 0..count {
            let owner = {
                let startups = self
                    .snapshot_startups
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                startups.owners.as_ref().expect("retained drain inventory")[index]
                    .as_ref()
                    .and_then(Weak::upgrade)
            };
            if let Some(owner) = owner
                && let Err(failure) = owner.drain_startup().await
            {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                    continue;
                }
            }
            // Delivered owners are now the group's responsibility. Complete
            // failures remain in report; their Weak entry is no longer custody.
            self.snapshot_startups
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .owners
                .as_mut()
                .expect("retained drain inventory")[index] = None;
        }
        if retained.is_none() {
            let (owners, inventory) = {
                let mut startups = self
                    .snapshot_startups
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                // Complete failures still retain report entries and their
                // original issues. Keep the proportional envelope with them.
                let inventory = if report.issues().is_empty() {
                    startups.inventory.take()
                } else {
                    None
                };
                (startups.owners.take(), inventory)
            };
            drop(owners);
            drop(inventory);
        }
        report.outcome(retained)
    }
}

/// Owned by actual work or resident storage, never by its timeout wrapper.
/// Keeping this reservation alive does not keep a stopped runtime facade alive.
pub struct Reservation {
    core: Arc<MemoryCore>,
    slot: usize,
    id: u64,
}
/// An installed maintenance owner holds this guard for its full lifetime.
/// Its bytes and ledger slots remain free for Raft and archive work while
/// ordinary Operation charges, including retained descendants, cannot grow
/// into them. Native Resident traffic still shares this free capacity.
pub(crate) struct OrdinaryProtection {
    core: Arc<MemoryCore>,
    bytes: u64,
    slots: usize,
}
impl Drop for OrdinaryProtection {
    fn drop(&mut self) {
        let mut state = self
            .core
            .data
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.ordinary_protected -= self.bytes;
        state.ordinary_protected_slots -= self.slots;
    }
}
impl Reservation {
    pub(crate) fn reserve_additional(&mut self, bytes: u64) -> Result<()> {
        let mut state = self
            .core
            .data
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.core.data.refresh_stale(&mut state);
        let total = state.bytes.checked_add(bytes);
        let ordinary_operation = state
            .charge(self.slot, self.id)
            .is_some_and(|charge| charge.origin == ChargeOrigin::OrdinaryOperation);
        if !state.usable
            || state.pressured
            || total.is_none_or(|total| {
                total > self.core.data.max_bytes
                    || state
                        .resident
                        .checked_add(total)
                        .is_none_or(|observed| observed >= self.core.data.high)
                    || (ordinary_operation
                        && total.checked_add(state.ordinary_protected).is_none_or(
                            |protected_total| {
                                protected_total > self.core.data.max_bytes
                                    || state
                                        .resident
                                        .checked_add(protected_total)
                                        .is_none_or(|observed| observed >= self.core.data.high)
                            },
                        ))
            })
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "node rebuild workspace budget exhausted",
            ));
        }
        let charge = state
            .charge_mut(self.slot, self.id)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "admission reservation absent"))?;
        charge.bytes = charge.bytes.checked_add(bytes).ok_or_else(|| {
            Error::new(ErrorCode::ResourceExhausted, "admission workspace overflow")
        })?;
        state.bytes = total.expect("checked additional reservation");
        Ok(())
    }
    pub(crate) fn handoff_workspace(&self, node: &Arc<NodeAdmission>, bytes: u64) -> Result<()> {
        if !Arc::ptr_eq(&node.core, &self.core) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "workspace handoff changed memory governor",
            ));
        }
        let mut state = self
            .core
            .data
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let previous = state
            .charge(self.slot, self.id)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "admission reservation absent"))?
            .bytes;
        let ordinary_operation = state
            .charge(self.slot, self.id)
            .is_some_and(|charge| charge.origin == ChargeOrigin::OrdinaryOperation);
        let total = state
            .bytes
            .checked_sub(previous)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| {
                Error::new(ErrorCode::ResourceExhausted, "workspace handoff overflow")
            })?;
        if bytes > previous {
            self.core.data.refresh_stale(&mut state);
            if !state.usable
                || state.pressured
                || total > self.core.data.max_bytes
                || state
                    .resident
                    .checked_add(total)
                    .is_none_or(|observed| observed >= self.core.data.high)
                || (ordinary_operation
                    && total
                        .checked_add(state.ordinary_protected)
                        .is_none_or(|protected_total| {
                            protected_total > self.core.data.max_bytes
                                || state
                                    .resident
                                    .checked_add(protected_total)
                                    .is_none_or(|observed| observed >= self.core.data.high)
                        }))
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "node handoff workspace budget exhausted",
                ));
            }
        }
        state
            .charge_mut(self.slot, self.id)
            .expect("live reservation")
            .bytes = bytes;
        state.bytes = total;
        Ok(())
    }
    pub(crate) fn retain_workspace(&mut self) {
        self.retain(u64::MAX);
    }
    pub fn retain(&mut self, bytes: u64) {
        let mut state = self
            .core
            .data
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let charge = state
            .charge_mut(self.slot, self.id)
            .expect("live reservation");
        let bytes = bytes.min(charge.bytes);
        let removed = charge.bytes - bytes;
        let operation = charge.kind == ChargeKind::Operation;
        charge.bytes = bytes;
        if operation {
            charge.kind = ChargeKind::Resident;
        }
        state.bytes -= removed;
        state.operations -= usize::from(operation);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self
            .core
            .data
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if state.charge(self.slot, self.id).is_none() {
            return;
        }
        let charge = state.slots[self.slot]
            .charge
            .take()
            .expect("live reservation");
        let bytes = charge.bytes;
        let operation = charge.kind == ChargeKind::Operation;
        // The charge can retain the final cancellation-state Arc. Retire that
        // backing under serialization before another reservation can reuse its
        // bytes or ledger slot. QueryCancellation destruction only releases its
        // atomic-state Arc; it neither calls user code nor takes this lock.
        drop(charge);
        state.bytes -= bytes;
        state.operations -= usize::from(operation);
        state.live -= 1;
        state.slots[self.slot].next_free = state.free;
        state.free = Some(self.slot);
    }
}
#[derive(Default)]
pub(crate) struct WorkFence(Mutex<FenceState>, tokio::sync::Notify);
#[derive(Default)]
struct FenceState {
    sealed: bool,
    next: u64,
    work: HashMap<u64, QueryCancellation>,
}
impl WorkFence {
    pub fn begin(self: &Arc<Self>, token: QueryCancellation) -> Result<WorkRegistration> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.sealed {
            return Err(Error::new(ErrorCode::Sealed, "tenant query work sealed"));
        }
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "work identifier exhausted"))?;
        state.work.insert(id, token);
        Ok(WorkRegistration {
            fence: self.clone(),
            id,
        })
    }
    pub fn seal(&self) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.sealed = true;
        for token in state.work.values() {
            token.cancel();
        }
    }
    pub async fn drain(&self) {
        loop {
            let notified = self.1.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .work
                .is_empty()
            {
                return;
            }
            notified.await;
        }
    }
    pub fn release<T>(
        &self,
        token: &QueryCancellation,
        release: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.sealed {
            return Err(Error::new(ErrorCode::Sealed, "tenant query work sealed"));
        }
        token.check()?;
        let result = release()?;
        token.check()?;
        Ok(result)
    }
}
pub(crate) struct WorkRegistration {
    fence: Arc<WorkFence>,
    id: u64,
}
impl Drop for WorkRegistration {
    fn drop(&mut self) {
        self.fence
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .work
            .remove(&self.id);
        self.fence.1.notify_waiters();
    }
}
pub(crate) struct CancelOnDrop(pub QueryCancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
#[path = "admission_startup_tests.rs"]
mod startup_integration_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_drain_waits_for_detached_work_to_release_its_registration() {
        use std::{future::Future, task::Poll};
        let fence = Arc::new(WorkFence::default());
        let token = QueryCancellation::default();
        let registration = fence.begin(token.clone()).unwrap();
        fence.seal();
        assert!(token.is_cancelled());
        assert!(fence.begin(QueryCancellation::default()).is_err());
        let mut draining = Box::pin(fence.drain());
        let first_poll = std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx))).await;
        assert!(first_poll.is_pending());
        drop(registration);
        draining.await;
    }
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    #[derive(Default)]
    struct Clock(AtomicU64);
    impl LeaseClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    struct Memory {
        rss: AtomicU64,
        fail: AtomicBool,
        delay: AtomicU64,
        clock: Arc<Clock>,
    }
    impl MemorySource for Memory {
        fn resident_bytes(&self) -> anyhow::Result<u64> {
            self.clock
                .0
                .fetch_add(self.delay.load(Ordering::SeqCst), Ordering::SeqCst);
            anyhow::ensure!(
                !self.fail.load(Ordering::SeqCst),
                "injected RSS probe failure"
            );
            Ok(self.rss.load(Ordering::SeqCst))
        }
    }
    fn fixture() -> (Arc<NodeAdmission>, Arc<Memory>, Arc<Clock>) {
        let clock = Arc::new(Clock::default());
        let memory = Arc::new(Memory {
            rss: AtomicU64::new(100),
            fail: AtomicBool::new(false),
            delay: AtomicU64::new(0),
            clock: clock.clone(),
        });
        let mut config = AdmissionConfig {
            high_water_bytes: None,
            low_water_bytes: None,
            max_inflight_bytes: None,
            max_inflight_operations: 2,
            max_reservations: 16,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            sample_interval_ms: 10,
            max_sample_age_ms: 100,
        };
        let base = NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
        config.high_water_bytes = Some(base * 4 + 1000);
        config.low_water_bytes = Some(600);
        config.max_inflight_bytes = Some(base + 500);
        (
            NodeAdmission::create(config, base * 4 + 1000, memory.clone(), clock.clone()).unwrap(),
            memory,
            clock,
        )
    }
    fn payload_bytes(node: &NodeAdmission) -> u64 {
        let snapshot = node.snapshot();
        snapshot.reserved_bytes - snapshot.bookkeeping_bytes
    }
    #[test]
    fn explicit_high_water_cannot_bypass_detected_memory_capacity() {
        let mut config = AdmissionConfig::default();
        assert_eq!(config.resolve_high_water(1000).unwrap(), 500);
        config.high_water_bytes = Some(750);
        assert_eq!(config.resolve_high_water(1000).unwrap(), 750);
        config.high_water_bytes = Some(1000);
        assert_eq!(config.resolve_high_water(1000).unwrap(), 1000);
        config.high_water_bytes = Some(1001);
        assert!(config.resolve_high_water(1000).is_err());
        config.high_water_bytes = Some(1);
        assert!(config.resolve_high_water(0).is_err());
        config.high_water_bytes = None;
        assert!(config.resolve_high_water(0).is_err());
        assert_eq!(config.resolve_high_water(u64::MAX).unwrap(), u64::MAX / 2);
        // The public production constructor must use this validation even when
        // the operator supplied an explicit value. It fails before starting a
        // sampling worker or admitting operations.
        assert!(
            NodeAdmission::new(AdmissionConfig {
                high_water_bytes: Some(u64::MAX),
                ..Default::default()
            })
            .is_err()
        );
    }
    #[test]
    fn fixture_total_resolution_preserves_the_original_runtime_payload_boundary() {
        let capacity = physical_capacity().unwrap();
        for high in [capacity / 2, capacity] {
            for explicit in [None, Some((high / 4).min(64 << 20))] {
                let config = AdmissionConfig {
                    high_water_bytes: Some(high),
                    max_inflight_bytes: explicit,
                    ..Default::default()
                };
                let total = config.resolved_fixture_total_bytes().unwrap();
                let node = NodeAdmission::with_fixed_memory(config, high, 0).unwrap();
                let base = node.snapshot().bookkeeping_bytes;
                let payload = node.reserve(total - base, None).unwrap();
                assert_eq!(node.snapshot().reserved_bytes, total);
                assert!(node.reserve(1, None).is_err());
                drop(payload);
                assert_eq!(node.snapshot().reserved_bytes, base);
            }
        }
        let invalid = AdmissionConfig {
            high_water_bytes: Some(u64::MAX),
            ..Default::default()
        };
        assert!(invalid.resolved_fixture_total_bytes().is_err());
    }

    #[test]
    fn workspace_handoff_preserves_slot_owner_and_checks_only_replacement_growth() {
        let (node, memory, _) = fixture();
        let (other, _, _) = fixture();
        let permanent = node.reserve(200, None).unwrap();
        let token = QueryCancellation::default();
        let work = Arc::new(node.reserve(250, Some(token.clone())).unwrap());
        let retained = work.clone();
        assert!(node.reserve(300, None).is_err());
        work.handoff_workspace(&node, 300).unwrap();
        assert_eq!(payload_bytes(&node), 500);
        assert_eq!(node.snapshot().inflight_operations, 2);
        assert!(work.handoff_workspace(&node, 301).is_err());
        assert!(work.handoff_workspace(&other, 1).is_err());
        assert_eq!(payload_bytes(&node), 500);
        memory.rss.store(node.core.data.high, Ordering::SeqCst);
        node.refresh();
        assert!(token.is_cancelled());
        work.handoff_workspace(&node, 200).unwrap();
        assert!(work.handoff_workspace(&node, 201).is_err());
        assert_eq!(payload_bytes(&node), 400);
        drop(work);
        assert_eq!(payload_bytes(&node), 400);
        drop(permanent);
        assert_eq!(payload_bytes(&node), 200);
        drop(retained);
        assert_eq!(payload_bytes(&node), 0);
        assert_eq!(node.snapshot().inflight_operations, 0);
    }

    #[test]
    fn pressure_cancels_queries_but_never_changes_write_work_and_uses_hysteresis() {
        let (node, memory, _) = fixture();
        let query = QueryCancellation::default();
        let query_charge = node.reserve(100, Some(query.clone())).unwrap();
        let write_charge = node.reserve(100, None).unwrap();
        memory.rss.store(node.core.data.high, Ordering::SeqCst);
        node.refresh();
        assert!(query.is_cancelled());
        assert!(node.reserve(1, None).is_err());
        // Pressure cancellation cannot release either still-running worker.
        assert_eq!(payload_bytes(&node), 200);
        memory.rss.store(node.core.data.low + 100, Ordering::SeqCst);
        node.refresh();
        assert!(node.snapshot().pressured);
        memory.rss.store(node.core.data.low, Ordering::SeqCst);
        node.refresh();
        assert!(!node.snapshot().pressured);
        drop(query_charge);
        drop(write_charge);
        assert!(node.reserve(100, None).is_ok());
    }

    #[test]
    fn reserved_audit_workspace_remains_usable_under_rss_pressure() {
        let clock = Arc::new(Clock::default());
        let memory = Arc::new(Memory {
            rss: AtomicU64::new(100),
            fail: AtomicBool::new(false),
            delay: AtomicU64::new(0),
            clock: clock.clone(),
        });
        let node = NodeAdmission::create(
            AdmissionConfig {
                high_water_bytes: Some(1 << 30),
                low_water_bytes: Some(512 << 20),
                max_inflight_bytes: Some(
                    3 * crate::audit_maintenance::NodeAuditMaintenance::WORKSPACE_BYTES,
                ),
                ..Default::default()
            },
            1 << 30,
            memory.clone(),
            clock,
        )
        .unwrap();
        let pool = crate::audit_maintenance::NodeAuditMaintenance::install(&node).unwrap();
        memory.rss.store(1 << 30, Ordering::SeqCst);
        node.refresh();
        assert!(node.reserve(1, None).is_err());
        // Joining an existing installed pool requires no new capacity, and
        // recovery materialization does not re-enter ordinary admission.
        assert!(Arc::ptr_eq(
            &pool,
            &crate::audit_maintenance::NodeAuditMaintenance::install(&node).unwrap()
        ));
        drop(pool.applying.try_lock().unwrap());
        drop(pool.preparation.try_acquire().unwrap());
        drop(pool);
        assert_eq!(payload_bytes(&node), 0);
    }
    #[test]
    fn retained_cursor_releases_operation_slot_but_keeps_bytes_until_last_owner() {
        let (node, _, _) = fixture();
        let mut charge = node.reserve(400, None).unwrap();
        assert!(node.reserve(101, None).is_err());
        charge.retain(300);
        assert_eq!(node.snapshot().inflight_operations, 0);
        assert_eq!(payload_bytes(&node), 300);
        let cursor = Arc::new(charge);
        let continuation = cursor.clone();
        drop(cursor);
        assert_eq!(payload_bytes(&node), 300);
        drop(continuation);
        assert_eq!(payload_bytes(&node), 0);
    }
    #[test]
    fn queued_rebuild_expands_its_existing_slot_and_rejects_growth_without_losing_charge() {
        let (node, memory, clock) = fixture();
        let first = node.reserve(100, None).unwrap();
        let mut rebuild = node.reserve(100, None).unwrap();
        assert!(node.reserve(1, None).is_err());
        rebuild.reserve_additional(100).unwrap();
        assert_eq!(payload_bytes(&node), 300);
        assert_eq!(node.snapshot().inflight_operations, 2);
        assert!(rebuild.reserve_additional(201).is_err());
        assert_eq!(payload_bytes(&node), 300);
        clock.0.store(60_000, Ordering::SeqCst);
        memory.rss.store(node.core.data.high, Ordering::SeqCst);
        assert!(rebuild.reserve_additional(1).is_err());
        assert_eq!(payload_bytes(&node), 300);
        drop(rebuild);
        drop(first);
        assert_eq!(payload_bytes(&node), 0);
    }
    #[test]
    fn suspend_invalidates_old_measurement_and_slow_or_failed_probe_denies() {
        let (node, memory, clock) = fixture();
        clock.0.store(60_000, Ordering::SeqCst);
        memory.rss.store(node.core.data.high + 1, Ordering::SeqCst);
        // No background thread ran during suspend: admission itself refreshes.
        assert!(node.reserve(1, None).is_err());
        memory.rss.store(100, Ordering::SeqCst);
        memory.delay.store(101, Ordering::SeqCst);
        node.refresh();
        assert!(!node.snapshot().sample_usable);
        assert!(node.reserve(1, None).is_err());
        memory.delay.store(0, Ordering::SeqCst);
        memory.fail.store(true, Ordering::SeqCst);
        assert!(node.reserve(1, None).is_err());
        memory.fail.store(false, Ordering::SeqCst);
        assert!(node.reserve(1, None).is_ok());
    }
    #[test]
    fn result_release_rechecks_pressure_after_suspend_even_for_completed_work() {
        let (node, memory, clock) = fixture();
        let token = QueryCancellation::default();
        let mut retained = node.reserve(100, Some(token.clone())).unwrap();
        retained.retain(50);
        clock.0.store(60_000, Ordering::SeqCst);
        memory.rss.store(node.core.data.high + 1, Ordering::SeqCst);
        assert!(node.check_release(&token).is_err());
        assert_eq!(payload_bytes(&node), 50);
        drop(retained);
        assert_eq!(payload_bytes(&node), 0);
    }
    #[tokio::test]
    async fn cancelled_detached_worker_keeps_semaphore_and_reservation_until_exit() {
        let (node, _, _) = fixture();
        let token = QueryCancellation::default();
        let charge = node.reserve(100, Some(token.clone())).unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().acquire_owned().await.unwrap();
        let fence = Arc::new(WorkFence::default());
        let group_fence = Arc::new(WorkFence::default());
        let registration = fence.begin(token.clone()).unwrap();
        let group_registration = group_fence.begin(token.clone()).unwrap();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, stopped) = std::sync::mpsc::channel();
        let worker_token = token.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let (_charge, _permit, _registration) = (charge, permit, registration);
            started.send(()).unwrap();
            // Represents one bounded library call between cooperative checks.
            stopped.recv().unwrap();
            assert!(worker_token.check().is_err());
        });
        entered.await.unwrap();
        fence.seal();
        group_fence.seal();
        assert!(token.is_cancelled());
        assert_eq!(
            fence.release(&token, || Ok(())).unwrap_err().code,
            ErrorCode::Sealed
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), worker)
                .await
                .is_err()
        );
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(payload_bytes(&node), 100);
        let mut draining = Box::pin(fence.drain());
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(draining.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(draining);
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(payload_bytes(&node), 100);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), fence.drain())
            .await
            .unwrap();
        // Finite work can finish while the exact group owner remains held.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), group_fence.drain())
                .await
                .is_err()
        );
        drop(group_registration);
        tokio::time::timeout(Duration::from_secs(1), group_fence.drain())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while payload_bytes(&node) != 0 || slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(slots.available_permits(), 1);
    }
    #[tokio::test]
    async fn snapshot_startup_inventory_is_charged_without_a_governor_cycle() {
        let node =
            NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 1 << 30, 0).unwrap();
        let owner = node.snapshot_buffer_owner().unwrap();
        let charge =
            kasumi_raft::SnapshotBufferOwner::required_bytes(kasumi_raft::SNAPSHOT_BUFFER_SLOTS)
                .unwrap();
        assert_eq!(payload_bytes(&node), charge);
        let weak = Arc::downgrade(&owner);
        drop(owner);
        assert!(
            weak.upgrade().is_none(),
            "an idle inventory entry cannot retain its owner"
        );
        assert_eq!(payload_bytes(&node), 0);
        let owner = node.snapshot_buffer_owner().unwrap();
        node.drain_snapshot_startups().await.unwrap();
        assert!(node.snapshot_buffer_owner().is_err());
        assert_eq!(payload_bytes(&node), charge);
        drop(owner);
        node.drain_snapshot_startups().await.unwrap();
        assert_eq!(payload_bytes(&node), 0);
    }

    #[test]
    fn resident_admission_never_consumes_an_operation_slot() {
        let (node, memory, _) = fixture();
        let first = node.reserve(100, None).unwrap();
        let second = node.reserve(100, None).unwrap();
        assert!(node.reserve(1, None).is_err());
        let resident = node.reserve_resident(300).unwrap();
        assert_eq!(node.snapshot().inflight_operations, 2);
        assert_eq!(node.snapshot().resident_reserved_bytes, 300);
        assert_eq!(payload_bytes(&node), 500);
        assert!(node.reserve_resident(1).is_err());
        drop(resident);
        memory.rss.store(node.core.data.high, Ordering::SeqCst);
        node.refresh();
        assert!(node.reserve_resident(1).is_err());
        assert_eq!(payload_bytes(&node), 200);
        drop((first, second));
    }

    #[test]
    fn fixed_charge_slots_reuse_capacity_without_forgetting_live_owners() {
        let (node, _, _) = fixture();
        let mut charges = Vec::new();
        let slots = node.core.data.state.lock().unwrap().slots.as_ptr();
        // Two slots belong to the facade and its independent inventory.
        for _ in 2..node.core.data.config.max_reservations {
            charges.push(node.reserve_resident(0).unwrap());
        }
        assert!(node.reserve_resident(0).is_err());
        let previous = charges.pop().unwrap();
        let previous_slot = previous.slot;
        let previous_id = previous.id;
        drop(previous);
        let successor = node.reserve_resident(0).unwrap();
        assert_eq!(successor.slot, previous_slot);
        assert_ne!(successor.id, previous_id);
        assert_eq!(node.core.data.state.lock().unwrap().slots.as_ptr(), slots);
        assert!(node.reserve_resident(0).is_err());
        drop((successor, charges));
        assert_eq!(node.snapshot().live_reservations, 2);
        assert_eq!(payload_bytes(&node), 0);
    }

    #[tokio::test]
    async fn replacement_facade_preserves_resident_charge_and_has_fresh_startup_fence() {
        let first =
            NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 1 << 30, 0).unwrap();
        let core = first.memory().clone();
        let retained = first.reserve_resident(1 << 20).unwrap();
        first.drain_snapshot_startups().await.unwrap();
        assert!(first.snapshot_buffer_owner().is_err());
        let replacement = NodeAdmission::from_memory(core.clone()).unwrap();
        assert!(!Arc::ptr_eq(&first, &replacement));
        assert!(first.shares_memory(&replacement));
        assert_eq!(core.snapshot().resident_reserved_bytes, 1 << 20);
        let weak_facade = Arc::downgrade(&first);
        drop(first);
        assert!(
            weak_facade.upgrade().is_none(),
            "resident lease retained the stopped facade"
        );
        assert_eq!(core.snapshot().resident_reserved_bytes, 1 << 20);
        let owner = replacement.snapshot_buffer_owner().unwrap();
        replacement.drain_snapshot_startups().await.unwrap();
        drop(owner);
        drop(replacement);
        assert_eq!(
            core.snapshot().reserved_bytes,
            core.data.base_bytes + (1 << 20)
        );
        drop(retained);
        assert_eq!(core.snapshot().reserved_bytes, core.data.base_bytes);
    }

    #[tokio::test]
    async fn empty_inventory_capacity_is_charged_until_actual_sealed_drain() {
        let node =
            NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 1 << 30, 0).unwrap();
        let initial = node.snapshot().bookkeeping_bytes;
        let inventory = NodeAdmission::inventory_bytes(&node.core.data.config).unwrap();
        let owner = node.snapshot_buffer_owner().unwrap();
        let weak = Arc::downgrade(&owner);
        drop(owner);
        assert!(weak.upgrade().is_none());
        assert_eq!(payload_bytes(&node), 0);
        assert_eq!(node.snapshot().bookkeeping_bytes, initial);
        node.drain_snapshot_startups().await.unwrap();
        assert!(node.snapshot_startups.lock().unwrap().owners.is_none());
        assert_eq!(node.snapshot().bookkeeping_bytes, initial - inventory);
        node.drain_snapshot_startups().await.unwrap();
        assert_eq!(node.snapshot().bookkeeping_bytes, initial - inventory);
    }

    #[test]
    fn fixed_bookkeeping_is_denied_before_its_allocation_when_budget_is_too_small() {
        let mut config = AdmissionConfig::default();
        let required = MemoryCore::required_bookkeeping_bytes(&config).unwrap();
        config.max_inflight_bytes = Some(required - 1);
        assert!(NodeAdmission::with_fixed_memory(config, 1 << 30, 0).is_err());
        let config = AdmissionConfig {
            max_reservations: usize::MAX,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        let config = AdmissionConfig {
            max_snapshot_startups: usize::MAX,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        let config = AdmissionConfig {
            max_startup_scopes: usize::MAX,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn initial_bookkeeping_obeys_the_existing_low_water_startup_fence() {
        let config = AdmissionConfig {
            high_water_bytes: Some(1 << 30),
            low_water_bytes: Some(256 << 20),
            max_inflight_bytes: Some(128 << 20),
            ..Default::default()
        };
        assert!(
            NodeAdmission::with_fixed_memory(config.clone(), 1 << 30, (256 << 20) + 1).is_err()
        );
        let node = NodeAdmission::with_fixed_memory(config.clone(), 1 << 30, 256 << 20).unwrap();
        assert_eq!(
            node.snapshot().reserved_bytes,
            NodeAdmission::required_bookkeeping_bytes(&config).unwrap()
        );
        assert_eq!(
            node.snapshot().reserved_bytes,
            node.snapshot().bookkeeping_bytes
        );
        assert_eq!(node.snapshot().inflight_operations, 0);
    }

    #[tokio::test]
    async fn exhausted_startup_inventory_denies_before_charging_another_owner() {
        let config = AdmissionConfig {
            max_snapshot_startups: 1,
            ..Default::default()
        };
        let node = NodeAdmission::with_fixed_memory(config, 1 << 30, 0).unwrap();
        let owner = node.snapshot_buffer_owner().unwrap();
        let before = node.snapshot();
        assert!(node.snapshot_buffer_owner().is_err());
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
        assert_eq!(node.snapshot().inflight_operations, 0);
        drop(owner);
        let replacement = node.snapshot_buffer_owner().unwrap();
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
        node.drain_snapshot_startups().await.unwrap();
        assert!(node.snapshot_buffer_owner().is_err());
        drop(replacement);
    }

    #[test]
    fn new_inventory_policies_are_required_without_legacy_aliases() {
        let value = serde_json::to_value(AdmissionConfig::default()).unwrap();
        for field in [
            "max_reservations",
            "max_snapshot_startups",
            "max_startup_scopes",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<AdmissionConfig>(missing).is_err());
        }
        let mut unknown = value;
        unknown["reservation_slots"] = 4096.into();
        assert!(serde_json::from_value::<AdmissionConfig>(unknown).is_err());
    }

    #[test]
    fn identifier_exhaustion_preserves_existing_charge_and_free_slot() {
        let (node, _, _) = fixture();
        let existing = node.reserve_resident(100).unwrap();
        let before = node.snapshot();
        let (free, slots) = {
            let mut state = node.core.data.state.lock().unwrap();
            state.next = u64::MAX;
            (state.free, state.slots.as_ptr())
        };
        assert_eq!(
            node.reserve_resident(1).err().unwrap().code,
            ErrorCode::Unavailable
        );
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
        let state = node.core.data.state.lock().unwrap();
        assert_eq!(state.free, free);
        assert_eq!(state.slots.as_ptr(), slots);
        drop(state);
        drop(existing);
        assert_eq!(payload_bytes(&node), 0);
    }

    #[tokio::test]
    async fn completed_failure_keeps_original_report_and_inventory_charge_until_facade_drop() {
        let node =
            NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 1 << 30, 0).unwrap();
        let core = node.memory().clone();
        let initial = node.snapshot().bookkeeping_bytes;
        let inventory = NodeAdmission::inventory_bytes(&core.data.config).unwrap();
        // This is the persisted retry boundary after an earlier child completed
        // with a real typed error, before the facade completed its census.
        let issue = node.snapshot_startup_drain.lock().await.record(
            "completed startup",
            0,
            std::io::Error::from(std::io::ErrorKind::BrokenPipe).into(),
        );
        for _ in 0..2 {
            let failure = node.drain_snapshot_startups().await.unwrap_err();
            assert_eq!(
                failure.completion(),
                kasumi_types::drain::DrainCompletion::Complete
            );
            assert!(Arc::ptr_eq(&failure.issues()[0], &issue));
            assert_eq!(node.snapshot().bookkeeping_bytes, initial);
            let startups = node.snapshot_startups.lock().unwrap();
            assert!(
                startups.owners.is_none(),
                "completed census must deallocate the box"
            );
            assert!(
                startups.inventory.is_some(),
                "original report still retains its envelope"
            );
        }
        drop(issue);
        drop(node);
        assert_eq!(core.snapshot().reserved_bytes, core.data.base_bytes);
        assert!(initial > inventory);
    }

    #[test]
    fn last_reservation_waits_for_paused_sampler_and_actual_source_destruction() {
        struct Probe {
            pause: Arc<AtomicBool>,
            entered: std::sync::mpsc::Sender<()>,
            release: Arc<(Mutex<bool>, std::sync::Condvar)>,
            destroyed: Arc<AtomicBool>,
        }
        impl MemorySource for Probe {
            fn resident_bytes(&self) -> anyhow::Result<u64> {
                if self.pause.swap(false, Ordering::SeqCst) {
                    self.entered.send(()).unwrap();
                    let (lock, wake) = self.release.as_ref();
                    drop(
                        wake.wait_while(lock.lock().unwrap(), |released| !*released)
                            .unwrap(),
                    );
                }
                Ok(0)
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.destroyed.store(true, Ordering::SeqCst);
            }
        }
        let (entered, observed) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let destroyed = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let memory = Arc::new(Probe {
            pause: pause.clone(),
            entered,
            release: release.clone(),
            destroyed: destroyed.clone(),
        });
        let config = AdmissionConfig {
            sample_interval_ms: 10,
            ..Default::default()
        };
        let mut core =
            MemoryCore::create(config, 1 << 30, memory, Arc::new(SystemLeaseClock)).unwrap();
        Arc::get_mut(&mut core).unwrap().start_sampler().unwrap();
        let reservation = core.reserve_resident(1).unwrap();
        pause.store(true, Ordering::SeqCst);
        let data = Arc::downgrade(&core.data);
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(core);
        assert!(data.upgrade().is_some());
        assert!(!destroyed.load(Ordering::SeqCst));
        let (dropping, started) = std::sync::mpsc::channel();
        let (finished, completed) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            dropping.send(()).unwrap();
            drop(reservation);
            finished.send(()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        let still_waiting = matches!(
            completed.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        let was_alive = !destroyed.load(Ordering::SeqCst);
        *release.0.lock().unwrap() = true;
        release.1.notify_one();
        completed.recv_timeout(Duration::from_secs(2)).unwrap();
        dropper.join().unwrap();
        assert!(
            still_waiting && was_alive,
            "final owner returned before the paused sampler drained"
        );
        assert!(destroyed.load(Ordering::SeqCst));
        assert!(
            data.upgrade().is_none(),
            "sampler detached or retained its accounting data after join"
        );
    }

    #[test]
    fn sampler_panic_fences_fresh_admission_and_preserves_original_join_outcome() {
        struct PanicProbe(std::sync::atomic::AtomicUsize);
        impl MemorySource for PanicProbe {
            fn resident_bytes(&self) -> anyhow::Result<u64> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 1 {
                    std::panic::panic_any(0x51_u64);
                }
                Ok(0)
            }
        }
        let config = AdmissionConfig {
            sample_interval_ms: 10,
            ..Default::default()
        };
        let mut core = MemoryCore::create(
            config,
            1 << 30,
            Arc::new(PanicProbe(std::sync::atomic::AtomicUsize::new(0))),
            Arc::new(SystemLeaseClock),
        )
        .unwrap();
        Arc::get_mut(&mut core).unwrap().start_sampler().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !core.sampler.as_ref().unwrap().is_finished() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(core.reserve_resident(1).is_err());
        assert!(!core.snapshot().sample_usable);
        core.refresh();
        assert!(
            core.reserve_resident(1).is_err(),
            "a fresh successful fallback probe reopened a dead sampler"
        );
        let panic = Arc::get_mut(&mut core)
            .unwrap()
            .sampler
            .take()
            .unwrap()
            .join()
            .unwrap_err();
        assert_eq!(panic.downcast_ref::<u64>(), Some(&0x51));
        drop(panic);
        drop(core);
    }
    #[test]
    fn real_process_rss_and_physical_capacity_are_measured() {
        assert!(ProcessMemory.resident_bytes().unwrap() > 0);
        assert!(physical_capacity().unwrap() > 0);
    }
}
