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
const SITES: [(Site, &str); 16] = [
    (Site::Other, "other"),
    (Site::KvSegment, "kv_segment"),
    (Site::KvDirectory, "kv_directory"),
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
        caller_key_from(&std::backtrace::Backtrace::force_capture().to_string())
    }

    /// The innermost frames of a captured trace in the crates that request
    /// durable writes, as "function crate/src/file.rs:line", followed by the
    /// kv step that finished the transaction ("[complete_staged
    /// disk_state.rs:1114]" for a foreground commit, a `disk_compact.rs` step
    /// for compaction, also when it runs inline before a foreground write).
    /// A frame's symbol line is followed by its "at path:line:column" line.
    /// With `debug = line-tables-only` a symbol is a bare function name
    /// ("{closure#0}") without its crate path, so the crate is read from the
    /// source path. Commits with no caller frame (the node worker's
    /// maintenance) are keyed by their outermost store frames instead.
    pub(super) fn caller_key_from(trace: &str) -> String {
        const CALLERS: [&str; 3] = ["kasumi-engine/", "kasumi-raft/", "kasumi-server/"];
        const STORES: [&str; 2] = ["kasumi-store/", "kasumi-kv/"];
        const KV_STEPS: &str = "kasumi-kv/src/disk_";
        let mut callers: Vec<String> = Vec::new();
        let mut stores: Vec<String> = Vec::new();
        let mut step: Option<String> = None;
        let mut symbol: Option<&str> = None;
        for line in trace.lines() {
            let line = line.trim_start();
            let Some(location) = line.strip_prefix("at ") else {
                symbol = Some(line.split_once(": ").map_or(line, |(_, name)| name));
                continue;
            };
            let Some(name) = symbol.take() else {
                continue;
            };
            let Some((_, relative)) = location.rsplit_once("/crates/") else {
                continue;
            };
            let relative = relative.rsplit_once(':').map_or(relative, |(path, _)| path);
            let name = short_name(name);
            if step.is_none()
                && let Some(file) = relative.strip_prefix(KV_STEPS)
            {
                step = Some(format!("{name} disk_{file}"));
            }
            let frame = format!("{name} {relative}");
            if CALLERS.iter().any(|krate| relative.starts_with(krate)) {
                if callers.last() != Some(&frame) {
                    callers.push(frame);
                }
                if callers.len() == 4 {
                    break;
                }
            } else if callers.is_empty() && STORES.iter().any(|krate| relative.starts_with(krate)) {
                stores.push(frame);
            }
        }
        let mut key = if !callers.is_empty() {
            callers.join(" < ")
        } else if !stores.is_empty() {
            let outer = stores.len().saturating_sub(3);
            format!("store: {}", stores[outer..].join(" < "))
        } else {
            return "unattributed".into();
        };
        if let Some(step) = step {
            key.push_str(&format!(" [{step}]"));
        }
        key
    }

    // A symbol's trailing path segments up to its function, without generic
    // arguments or impl qualifiers: "kasumi_raft::storage::LogStore::
    // append_original::{{closure}}" becomes "append_original::{{closure}}",
    // "<impl X>::step" becomes "step" and "poll<T>" becomes "poll".
    fn short_name(name: &str) -> String {
        let mut plain = String::with_capacity(name.len());
        let mut depth = 0usize;
        let mut previous = '\0';
        for character in name.chars() {
            match character {
                '<' => depth += 1,
                '>' if previous != '-' => depth = depth.saturating_sub(1),
                _ if depth == 0 => plain.push(character),
                _ => {}
            }
            previous = character;
        }
        let mut start = plain.len();
        while let Some(separator) = plain[..start].rfind("::") {
            let segment = &plain[separator + 2..start];
            start = separator;
            if !segment.is_empty() && !segment.starts_with('{') {
                return plain[separator + 2..].to_owned();
            }
        }
        plain
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
            for (stack, count) in stacks.iter().take(24) {
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

#[cfg(all(test, feature = "sync-trace"))]
mod tests {
    use super::imp::caller_key_from;

    // Frame lines as `std::backtrace::Backtrace` prints them in a release
    // build with `debug = line-tables-only`: bare function names, one
    // source location each, innermost first.
    fn trace(frames: &[(&str, &str)]) -> String {
        frames
            .iter()
            .enumerate()
            .map(|(index, (name, location))| {
                format!("  {index:2}: {name}\n             at {location}:7:9\n")
            })
            .collect()
    }

    #[test]
    fn a_foreground_commit_is_keyed_by_its_callers_and_kv_step() {
        let trace = trace(&[
            ("trace", "/rustc/x/library/std/src/backtrace.rs"),
            ("commit", "/k/crates/kasumi-store/src/sync_trace.rs"),
            (
                "finish_transaction_plan",
                "/k/crates/kasumi-store/src/node_file/segment_group/transaction.rs",
            ),
            (
                "finish_transaction",
                "/k/crates/kasumi-kv/src/checked_group.rs",
            ),
            ("complete_staged", "/k/crates/kasumi-kv/src/disk_state.rs"),
            ("commit", "/k/crates/kasumi-kv/src/core.rs"),
            ("{closure#1}", "/k/crates/kasumi-raft/src/storage.rs"),
            (
                "{closure#0}<kasumi_raft::storage::X>",
                "/k/crates/kasumi-raft/src/storage.rs",
            ),
            ("poll<T>", "/r/tokio-1.53.1/src/runtime/blocking/task.rs"),
        ]);
        assert_eq!(
            caller_key_from(&trace),
            "{closure#1} kasumi-raft/src/storage.rs:7 < {closure#0} kasumi-raft/src/storage.rs:7 [complete_staged disk_state.rs:7]"
        );
    }

    #[test]
    fn full_symbols_keep_their_function_and_unindexed_frames_count() {
        // With full debug info, or none, a symbol carries its whole path. A
        // frame inlined into the same physical frame has no index.
        let trace = "   3: kasumi_kv::disk_compact::<impl kasumi_kv::disk_state::DiskState>::finish_maintenance
             at /src/crates/kasumi-kv/src/disk_compact.rs:983:13
      kasumi_raft::storage::LogStore::append_original::{{closure}}::{{closure}}
             at /src/crates/kasumi-raft/src/storage.rs:628:17
   4: kasumi_engine::service::ProposalWork::run_staged
             at /src/crates/kasumi-engine/src/service.rs:620:13
";
        assert_eq!(
            caller_key_from(trace),
            "append_original::{{closure}}::{{closure}} kasumi-raft/src/storage.rs:628 < run_staged kasumi-engine/src/service.rs:620 [finish_maintenance disk_compact.rs:983]"
        );
    }

    #[test]
    fn a_background_commit_is_keyed_by_its_outermost_store_frames() {
        let trace = trace(&[
            ("commit", "/k/crates/kasumi-store/src/sync_trace.rs"),
            (
                "finish_maintenance",
                "/k/crates/kasumi-kv/src/disk_compact.rs",
            ),
            ("run_maintenance", "/k/crates/kasumi-kv/src/tables.rs"),
            (
                "run_maintenance",
                "/k/crates/kasumi-store/src/storage_opening.rs",
            ),
            ("step", "/k/crates/kasumi-store/src/cache_warmer.rs"),
            ("run", "/k/crates/kasumi-serving/src/background.rs"),
        ]);
        assert_eq!(
            caller_key_from(&trace),
            "store: run_maintenance kasumi-kv/src/tables.rs:7 < run_maintenance kasumi-store/src/storage_opening.rs:7 < step kasumi-store/src/cache_warmer.rs:7 [finish_maintenance disk_compact.rs:7]"
        );
        assert_eq!(caller_key_from("   0: main\n"), "unattributed");
    }
}
