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
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionConfig {
    /// None: half physical memory, limited by the Linux cgroup memory ceiling.
    pub high_water_bytes: Option<u64>,
    /// None: seven eighths of the high-water mark, providing hysteresis.
    pub low_water_bytes: Option<u64>,
    /// None: min(high-water / 4, 512 MiB).
    pub max_inflight_bytes: Option<u64>,
    pub max_inflight_operations: usize,
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
            sample_interval_ms: 250,
            max_sample_age_ms: 1000,
        }
    }
}
impl AdmissionConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
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
    pub reserved_bytes: u64,
    pub inflight_operations: usize,
    pub pressured: bool,
    pub sample_usable: bool,
}
struct Charge {
    bytes: u64,
    operation: bool,
    cancellation: Option<QueryCancellation>,
}
struct State {
    resident: u64,
    sampled_at: Duration,
    usable: bool,
    pressured: bool,
    bytes: u64,
    operations: usize,
    next: u64,
    charges: HashMap<u64, Charge>,
}
pub struct NodeAdmission {
    config: AdmissionConfig,
    high: u64,
    low: u64,
    max_bytes: u64,
    memory: Arc<dyn MemorySource>,
    clock: Arc<dyn LeaseClock>,
    state: Mutex<State>,
}
impl NodeAdmission {
    pub fn new(config: AdmissionConfig) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let high = match config.high_water_bytes {
            Some(high) => high,
            None => physical_capacity()? / 2,
        };
        let node = Self::create(
            config,
            high,
            Arc::new(ProcessMemory),
            Arc::new(SystemLeaseClock),
        )?;
        let weak = Arc::downgrade(&node);
        let interval = Duration::from_millis(node.config.sample_interval_ms);
        // Also works for embedding callers outside Tokio. The thread holds no
        // strong reference while asleep and exits after its final owner drops.
        std::thread::Builder::new()
            .name("kasumi-rss".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(interval);
                    let Some(node) = weak.upgrade() else {
                        break;
                    };
                    node.refresh();
                }
            })?;
        Ok(node)
    }
    fn create(
        config: AdmissionConfig,
        high: u64,
        memory: Arc<dyn MemorySource>,
        clock: Arc<dyn LeaseClock>,
    ) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let low = config.low_water_bytes.unwrap_or(high.saturating_mul(7) / 8);
        let max_bytes = config
            .max_inflight_bytes
            .unwrap_or((high / 4).min(512 << 20));
        anyhow::ensure!(
            high > 0 && low < high && max_bytes > 0 && max_bytes <= high,
            "invalid resolved admission budgets"
        );
        let node = Arc::new(Self {
            config,
            high,
            low,
            max_bytes,
            memory,
            clock,
            state: Mutex::new(State {
                resident: 0,
                sampled_at: Duration::ZERO,
                usable: false,
                pressured: true,
                bytes: 0,
                operations: 0,
                next: 0,
                charges: HashMap::new(),
            }),
        });
        node.refresh();
        Ok(node)
    }
    pub(crate) fn process_default() -> Arc<Self> {
        static DEFAULT: OnceLock<Arc<NodeAdmission>> = OnceLock::new();
        DEFAULT
            .get_or_init(|| {
                Self::new(AdmissionConfig::default()).unwrap_or_else(|_| {
                    // Construction of existing embedded API is infallible. Failure to
                    // determine RAM must deny admission, never silently disable the gate.
                    Self::create(
                        AdmissionConfig {
                            max_inflight_bytes: Some(1),
                            ..Default::default()
                        },
                        1,
                        Arc::new(ProcessMemory),
                        Arc::new(SystemLeaseClock),
                    )
                    .expect("fail-closed admission configuration")
                })
            })
            .clone()
    }
    fn refresh(&self) {
        // Serialize probes: a delayed earlier probe cannot overwrite a newer one.
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.sample(&mut state);
    }
    fn sample(&self, state: &mut State) {
        let start = self.clock.now();
        let result = self.memory.resident_bytes();
        state.sampled_at = start;
        state.usable = false;
        if let Ok(resident) = result {
            state.resident = resident;
            state.usable = self.clock.now().saturating_sub(start)
                < Duration::from_millis(self.config.max_sample_age_ms);
            if resident >= self.high {
                state.pressured = true;
            } else if resident <= self.low {
                state.pressured = false;
            }
        }
        if !state.usable || state.pressured {
            for charge in state.charges.values() {
                if let Some(token) = &charge.cancellation {
                    token.cancel();
                }
            }
        }
    }
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        AdmissionSnapshot {
            resident_bytes: state.resident,
            high_water_bytes: self.high,
            low_water_bytes: self.low,
            reserved_bytes: state.bytes,
            inflight_operations: state.operations,
            pressured: state.pressured,
            sample_usable: state.usable
                && self.clock.now().saturating_sub(state.sampled_at)
                    < Duration::from_millis(self.config.max_sample_age_ms),
        }
    }
    /// Refresh stale measurements before releasing query data after an async
    /// wait or suspend. The caller already owns its work/result reservation.
    pub(crate) fn check_release(&self, token: &QueryCancellation) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.usable
            || self.clock.now().saturating_sub(state.sampled_at)
                >= Duration::from_millis(self.config.max_sample_age_ms)
        {
            self.sample(&mut state);
        }
        if !state.usable || state.pressured {
            token.cancel();
        }
        token.check()
    }
    /// Reserve before proposing or retaining query work. A write reservation has
    /// no cancellation token; committed materialization never enters this method.
    pub fn reserve(
        self: &Arc<Self>,
        bytes: u64,
        cancellation: Option<QueryCancellation>,
    ) -> Result<Reservation> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.usable
            || self.clock.now().saturating_sub(state.sampled_at)
                >= Duration::from_millis(self.config.max_sample_age_ms)
        {
            self.sample(&mut state);
        }
        if !state.usable
            || state.pressured
            || state.operations >= self.config.max_inflight_operations
            || state.bytes.saturating_add(bytes) > self.max_bytes
            || state
                .resident
                .saturating_add(state.bytes)
                .saturating_add(bytes)
                >= self.high
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "node memory or work admission budget exhausted",
            ));
        }
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "admission identifier exhausted"))?;
        state.bytes += bytes;
        state.operations += 1;
        state.charges.insert(
            id,
            Charge {
                bytes,
                operation: true,
                cancellation,
            },
        );
        Ok(Reservation {
            node: self.clone(),
            id,
        })
    }
}

/// Owned by actual work, never its timeout wrapper. Dropping a caller does not
/// release a worker's reservation. Completed results may keep a reduced byte
/// charge until the final cursor reference expires.
pub struct Reservation {
    node: Arc<NodeAdmission>,
    id: u64,
}
impl Reservation {
    /// Increase the workspace of an already admitted operation after its queued
    /// dependencies are known. This rechecks fresh pressure/byte limits without
    /// consuming another operation slot, and leaves the old charge on failure.
    pub(crate) fn reserve_additional(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.node.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.usable
            || self.node.clock.now().saturating_sub(state.sampled_at)
                >= Duration::from_millis(self.node.config.max_sample_age_ms)
        {
            self.node.sample(&mut state);
        }
        if !state.usable
            || state.pressured
            || state.bytes.saturating_add(bytes) > self.node.max_bytes
            || state
                .resident
                .saturating_add(state.bytes)
                .saturating_add(bytes)
                >= self.node.high
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "node rebuild workspace budget exhausted",
            ));
        }
        let charge = state
            .charges
            .get_mut(&self.id)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "admission reservation absent"))?;
        charge.bytes = charge.bytes.checked_add(bytes).ok_or_else(|| {
            Error::new(ErrorCode::ResourceExhausted, "admission workspace overflow")
        })?;
        state.bytes += bytes;
        Ok(())
    }
    /// Transfer the same operation slot to its next workspace after the previous
    /// allocations have actually drained. Existing Arc owners continue to fence
    /// the one charge; growth rechecks capacity and never changes it on failure.
    pub(crate) fn handoff_workspace(&self, node: &Arc<NodeAdmission>, bytes: u64) -> Result<()> {
        if !Arc::ptr_eq(node, &self.node) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "workspace handoff changed node governor",
            ));
        }
        let mut state = self.node.state.lock().unwrap_or_else(|p| p.into_inner());
        let previous = state
            .charges
            .get(&self.id)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "admission reservation absent"))?
            .bytes;
        let total = state
            .bytes
            .checked_sub(previous)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| {
                Error::new(ErrorCode::ResourceExhausted, "workspace handoff overflow")
            })?;
        if bytes > previous {
            if !state.usable
                || self.node.clock.now().saturating_sub(state.sampled_at)
                    >= Duration::from_millis(self.node.config.max_sample_age_ms)
            {
                self.node.sample(&mut state);
            }
            if !state.usable
                || state.pressured
                || total > self.node.max_bytes
                || state.resident.saturating_add(total) >= self.node.high
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "node handoff workspace budget exhausted",
                ));
            }
        }
        state
            .charges
            .get_mut(&self.id)
            .expect("live reservation")
            .bytes = bytes;
        state.bytes = total;
        Ok(())
    }

    /// Completed computation may retain its response bytes while a nested
    /// strict-audit proposal occupies the operation slot.
    pub(crate) fn retain_workspace(&mut self) {
        self.retain(u64::MAX);
    }

    pub(crate) fn retain(&mut self, bytes: u64) {
        let mut state = self.node.state.lock().unwrap_or_else(|p| p.into_inner());
        let charge = state.charges.get_mut(&self.id).expect("live reservation");
        let bytes = bytes.min(charge.bytes);
        let removed = charge.bytes - bytes;
        let operation = charge.operation;
        charge.bytes = bytes;
        charge.operation = false;
        state.bytes -= removed;
        state.operations -= usize::from(operation);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.node.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(charge) = state.charges.remove(&self.id) {
            state.bytes -= charge.bytes;
            state.operations -= usize::from(charge.operation);
        }
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
        let config = AdmissionConfig {
            high_water_bytes: Some(1000),
            low_water_bytes: Some(600),
            max_inflight_bytes: Some(500),
            max_inflight_operations: 2,
            sample_interval_ms: 10,
            max_sample_age_ms: 100,
        };
        (
            NodeAdmission::create(config, 1000, memory.clone(), clock.clone()).unwrap(),
            memory,
            clock,
        )
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
        assert_eq!(node.snapshot().reserved_bytes, 500);
        assert_eq!(node.snapshot().inflight_operations, 2);
        assert!(work.handoff_workspace(&node, 301).is_err());
        assert!(work.handoff_workspace(&other, 1).is_err());
        assert_eq!(node.snapshot().reserved_bytes, 500);
        memory.rss.store(1000, Ordering::SeqCst);
        node.refresh();
        assert!(token.is_cancelled());
        work.handoff_workspace(&node, 200).unwrap();
        assert!(work.handoff_workspace(&node, 201).is_err());
        assert_eq!(node.snapshot().reserved_bytes, 400);
        drop(work);
        assert_eq!(node.snapshot().reserved_bytes, 400);
        drop(permanent);
        assert_eq!(node.snapshot().reserved_bytes, 200);
        drop(retained);
        assert_eq!(node.snapshot().reserved_bytes, 0);
        assert_eq!(node.snapshot().inflight_operations, 0);
    }

    #[test]
    fn pressure_cancels_queries_but_never_changes_write_work_and_uses_hysteresis() {
        let (node, memory, _) = fixture();
        let query = QueryCancellation::default();
        let query_charge = node.reserve(100, Some(query.clone())).unwrap();
        let write_charge = node.reserve(100, None).unwrap();
        memory.rss.store(1000, Ordering::SeqCst);
        node.refresh();
        assert!(query.is_cancelled());
        assert!(node.reserve(1, None).is_err());
        // Pressure cancellation cannot release either still-running worker.
        assert_eq!(node.snapshot().reserved_bytes, 200);
        memory.rss.store(700, Ordering::SeqCst);
        node.refresh();
        assert!(node.snapshot().pressured);
        memory.rss.store(600, Ordering::SeqCst);
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
                max_inflight_bytes: Some(256 << 20),
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
        assert_eq!(node.snapshot().reserved_bytes, 0);
    }
    #[test]
    fn retained_cursor_releases_operation_slot_but_keeps_bytes_until_last_owner() {
        let (node, _, _) = fixture();
        let mut charge = node.reserve(400, None).unwrap();
        assert!(node.reserve(101, None).is_err());
        charge.retain(300);
        assert_eq!(node.snapshot().inflight_operations, 0);
        assert_eq!(node.snapshot().reserved_bytes, 300);
        let cursor = Arc::new(charge);
        let continuation = cursor.clone();
        drop(cursor);
        assert_eq!(node.snapshot().reserved_bytes, 300);
        drop(continuation);
        assert_eq!(node.snapshot().reserved_bytes, 0);
    }
    #[test]
    fn queued_rebuild_expands_its_existing_slot_and_rejects_growth_without_losing_charge() {
        let (node, memory, clock) = fixture();
        let first = node.reserve(100, None).unwrap();
        let mut rebuild = node.reserve(100, None).unwrap();
        assert!(node.reserve(1, None).is_err());
        rebuild.reserve_additional(100).unwrap();
        assert_eq!(node.snapshot().reserved_bytes, 300);
        assert_eq!(node.snapshot().inflight_operations, 2);
        assert!(rebuild.reserve_additional(201).is_err());
        assert_eq!(node.snapshot().reserved_bytes, 300);
        clock.0.store(60_000, Ordering::SeqCst);
        memory.rss.store(1000, Ordering::SeqCst);
        assert!(rebuild.reserve_additional(1).is_err());
        assert_eq!(node.snapshot().reserved_bytes, 300);
        drop(rebuild);
        drop(first);
        assert_eq!(node.snapshot().reserved_bytes, 0);
    }
    #[test]
    fn suspend_invalidates_old_measurement_and_slow_or_failed_probe_denies() {
        let (node, memory, clock) = fixture();
        clock.0.store(60_000, Ordering::SeqCst);
        memory.rss.store(1001, Ordering::SeqCst);
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
        memory.rss.store(1001, Ordering::SeqCst);
        assert!(node.check_release(&token).is_err());
        assert_eq!(node.snapshot().reserved_bytes, 50);
        drop(retained);
        assert_eq!(node.snapshot().reserved_bytes, 0);
    }
    #[tokio::test]
    async fn cancelled_detached_worker_keeps_semaphore_and_reservation_until_exit() {
        let (node, _, _) = fixture();
        let token = QueryCancellation::default();
        let charge = node.reserve(100, Some(token.clone())).unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().acquire_owned().await.unwrap();
        let fence = Arc::new(WorkFence::default());
        let registration = fence.begin(token.clone()).unwrap();
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
        assert_eq!(node.snapshot().reserved_bytes, 100);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while node.snapshot().reserved_bytes != 0 || slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(slots.available_permits(), 1);
    }
    #[test]
    fn real_process_rss_and_physical_capacity_are_measured() {
        assert!(ProcessMemory.resident_bytes().unwrap() > 0);
        assert!(physical_capacity().unwrap() > 0);
    }
}
