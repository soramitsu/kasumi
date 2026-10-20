//! Optional physical synchronization trace for write-throughput diagnosis.
//!
//! Compiled only with the `sync-trace` feature; the default build turns every
//! hook into its plain operation. With the feature, each durable
//! synchronization issued by NodeDisk and scratch owners is counted and timed
//! under the call site that requested it, and NodeDisk state-lock contention
//! is timed. When `KASUMI_SYNC_TRACE_SECS` is set, a detached thread prints one
//! line of per-interval deltas to stderr. Labels never carry payloads, paths or
//! identities.

/// Which NodeDisk mutex a timed acquisition waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Lock {
    State,
    File,
}

/// The requesting call site of a synchronization, from the innermost label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Site {
    // The label of unlabeled syncs, read only by the trace itself.
    #[cfg_attr(not(feature = "sync-trace"), allow(dead_code))]
    Other,
    KvSegment,
    KvDirectory,
    KvCheckpoint,
    KvRoot,
    KvNames,
    ReserveSettle,
    FinishSettle,
    FinishRoot,
    FinishNames,
    GrowthSettle,
    EvictSettle,
    Envelope,
    Create,
    Unlink,
    Shrink,
    Scratch,
}

#[cfg(feature = "sync-trace")]
const SITES: [(Site, &str); 17] = [
    (Site::Other, "other"),
    (Site::KvSegment, "kv_segment"),
    (Site::KvDirectory, "kv_directory"),
    (Site::KvCheckpoint, "kv_checkpoint"),
    (Site::KvRoot, "kv_root"),
    (Site::KvNames, "kv_names"),
    (Site::ReserveSettle, "reserve_settle"),
    (Site::FinishSettle, "finish_settle"),
    (Site::FinishRoot, "finish_root"),
    (Site::FinishNames, "finish_names"),
    (Site::GrowthSettle, "growth_settle"),
    (Site::EvictSettle, "evict_settle"),
    (Site::Envelope, "envelope"),
    (Site::Create, "create"),
    (Site::Unlink, "unlink"),
    (Site::Shrink, "shrink"),
    (Site::Scratch, "scratch"),
];

#[cfg(not(feature = "sync-trace"))]
mod imp {
    #[inline(always)]
    pub(crate) fn site<R>(_: super::Site, operation: impl FnOnce() -> R) -> R {
        operation()
    }
    #[inline(always)]
    pub(crate) fn sync<R>(operation: impl FnOnce() -> R) -> R {
        operation()
    }
    #[inline(always)]
    pub(crate) fn skipped() {}
    #[inline(always)]
    pub(crate) fn commit(_: &std::path::Path) {}
    #[inline(always)]
    pub(crate) fn lock<T>(
        mutex: &std::sync::Mutex<T>,
        _: super::Lock,
    ) -> std::sync::LockResult<std::sync::MutexGuard<'_, T>> {
        mutex.lock()
    }
}

#[cfg(feature = "sync-trace")]
mod imp {
    use super::{Lock, SITES, Site};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::time::{Duration, Instant};

    const COUNT: usize = SITES.len();
    static SYNCS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
    static NANOS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
    static SKIPPED: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
    static COMMITS: AtomicU64 = AtomicU64::new(0);
    // Commit counts by the last two components of the group path.
    static GROUPS: std::sync::Mutex<Vec<(String, u64)>> = std::sync::Mutex::new(Vec::new());
    // Commit counts by caller frames, only with KASUMI_SYNC_TRACE_STACKS=1.
    static STACKS: std::sync::Mutex<Vec<(String, u64)>> = std::sync::Mutex::new(Vec::new());
    static STACKS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    fn caller_key() -> String {
        let trace = std::backtrace::Backtrace::force_capture().to_string();
        let mut frames = Vec::new();
        for line in trace.lines() {
            let line = line.trim();
            let Some((_, symbol)) = line.split_once(": ") else {
                continue;
            };
            if !(symbol.starts_with("kasumi_engine::")
                || symbol.starts_with("kasumi_raft::")
                || symbol.starts_with("kasumi_server::")
                || symbol.starts_with("<kasumi_engine::")
                || symbol.starts_with("<kasumi_raft::"))
            {
                continue;
            }
            let symbol = symbol.rsplit_once("::h").map_or(symbol, |(name, _)| name);
            if frames.last() != Some(&symbol.to_owned()) {
                frames.push(symbol.to_owned());
            }
            if frames.len() == 4 {
                break;
            }
        }
        if frames.is_empty() {
            "unattributed".into()
        } else {
            frames.join(" < ")
        }
    }
    static LOCK_WAITS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static LOCK_WAIT_NANOS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static REPORTER: std::sync::Once = std::sync::Once::new();
    thread_local! {
        static CURRENT: Cell<Site> = const { Cell::new(Site::Other) };
    }

    struct Restore(Site);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.with(|current| current.set(self.0));
        }
    }

    pub(crate) fn site<R>(site: Site, operation: impl FnOnce() -> R) -> R {
        let _restore = Restore(CURRENT.with(|current| current.replace(site)));
        operation()
    }

    pub(crate) fn sync<R>(operation: impl FnOnce() -> R) -> R {
        start_reporter();
        let started = Instant::now();
        let result = operation();
        let site = CURRENT.with(Cell::get) as usize;
        SYNCS[site].fetch_add(1, Relaxed);
        NANOS[site].fetch_add(started.elapsed().as_nanos() as u64, Relaxed);
        result
    }

    pub(crate) fn skipped() {
        SKIPPED[CURRENT.with(Cell::get) as usize].fetch_add(1, Relaxed);
    }

    pub(crate) fn commit(path: &std::path::Path) {
        COMMITS.fetch_add(1, Relaxed);
        let mut components = path.components().rev().take(2).collect::<Vec<_>>();
        components.reverse();
        let name = components
            .iter()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let mut groups = GROUPS.lock().unwrap_or_else(|poison| poison.into_inner());
        match groups.iter_mut().find(|(group, _)| *group == name) {
            Some((_, count)) => *count += 1,
            None => groups.push((name, 1)),
        }
        drop(groups);
        if *STACKS_ENABLED.get_or_init(|| std::env::var("KASUMI_SYNC_TRACE_STACKS").is_ok()) {
            let key = caller_key();
            let mut stacks = STACKS.lock().unwrap_or_else(|poison| poison.into_inner());
            match stacks.iter_mut().find(|(stack, _)| *stack == key) {
                Some((_, count)) => *count += 1,
                None => stacks.push((key, 1)),
            }
        }
    }

    pub(crate) fn lock<T>(
        mutex: &std::sync::Mutex<T>,
        kind: Lock,
    ) -> std::sync::LockResult<std::sync::MutexGuard<'_, T>> {
        match mutex.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Err(poisoned),
            Err(std::sync::TryLockError::WouldBlock) => {
                let started = Instant::now();
                let result = mutex.lock();
                LOCK_WAITS[kind as usize].fetch_add(1, Relaxed);
                LOCK_WAIT_NANOS[kind as usize]
                    .fetch_add(started.elapsed().as_nanos() as u64, Relaxed);
                result
            }
        }
    }

    fn start_reporter() {
        REPORTER.call_once(|| {
            let Some(seconds) = std::env::var("KASUMI_SYNC_TRACE_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|seconds| *seconds > 0)
            else {
                return;
            };
            let _ = std::thread::Builder::new()
                .name("kasumi-sync-trace".into())
                .spawn(move || report(Duration::from_secs(seconds)));
        });
    }

    fn report(interval: Duration) {
        use std::io::Write;
        let snapshot = || {
            let mut values = [(0u64, 0u64, 0u64); COUNT];
            for (index, value) in values.iter_mut().enumerate() {
                *value = (
                    SYNCS[index].load(Relaxed),
                    NANOS[index].load(Relaxed),
                    SKIPPED[index].load(Relaxed),
                );
            }
            (
                values,
                COMMITS.load(Relaxed),
                [LOCK_WAITS[0].load(Relaxed), LOCK_WAITS[1].load(Relaxed)],
                [
                    LOCK_WAIT_NANOS[0].load(Relaxed),
                    LOCK_WAIT_NANOS[1].load(Relaxed),
                ],
            )
        };
        let mut previous = snapshot();
        let mut previous_groups: Vec<(String, u64)> = Vec::new();
        let started = Instant::now();
        loop {
            std::thread::sleep(interval);
            let current = snapshot();
            let mut line = format!(
                "kasumi-sync-trace elapsed_s={} commits={} state_waits={} state_wait_ms={} file_waits={} file_wait_ms={}",
                started.elapsed().as_secs(),
                current.1 - previous.1,
                current.2[0] - previous.2[0],
                (current.3[0] - previous.3[0]) / 1_000_000,
                current.2[1] - previous.2[1],
                (current.3[1] - previous.3[1]) / 1_000_000,
            );
            let mut syncs = 0;
            let mut nanos = 0;
            for (index, (_, name)) in SITES.iter().enumerate() {
                let (count, time, skipped) = (
                    current.0[index].0 - previous.0[index].0,
                    current.0[index].1 - previous.0[index].1,
                    current.0[index].2 - previous.0[index].2,
                );
                syncs += count;
                nanos += time;
                if count != 0 || skipped != 0 {
                    line.push_str(&format!(
                        " {name}={count}/{}ms/skip{skipped}",
                        time / 1_000_000
                    ));
                }
            }
            line.push_str(&format!(" syncs={syncs} sync_ms={}", nanos / 1_000_000));
            let groups = GROUPS
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone();
            for (group, count) in groups {
                let before = previous_groups
                    .iter()
                    .find(|(name, _)| *name == group)
                    .map_or(0, |(_, count)| *count);
                if count != before {
                    line.push_str(&format!(" commits[{group}]={}", count - before));
                }
                match previous_groups.iter_mut().find(|(name, _)| *name == group) {
                    Some((_, previous)) => *previous = count,
                    None => previous_groups.push((group, count)),
                }
            }
            let _ = writeln!(std::io::stderr().lock(), "{line}");
            let mut stacks = STACKS
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone();
            stacks.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            for (stack, count) in stacks.iter().take(12) {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "kasumi-sync-trace-stack total={count} {stack}"
                );
            }
            previous = current;
        }
    }
}

pub(crate) use imp::{commit, lock, site, skipped, sync};
