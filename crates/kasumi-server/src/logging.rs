//! Daemon diagnostics contain operational events, never request bodies or secrets.
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

fn targets() -> Targets {
    // Dependencies can trace entire commands/documents. They must remain disabled
    // even when the host has an unrelated RUST_LOG setting. OpenRaft formats
    // storage error chains, so its fatal outcomes surface only through Kasumi's
    // fixed closure and typed failure classes. Kasumi's own engine, Raft and store warnings carry
    // fixed labels and component names, never error chains or tenant data.
    Targets::new()
        .with_target("kasumi_server", tracing::Level::INFO)
        .with_target("kasumi_engine", tracing::Level::WARN)
        .with_target("kasumi_raft", tracing::Level::WARN)
        .with_target("kasumi_store", tracing::Level::WARN)
}

/// Install JSON diagnostics on stderr. CLI result documents remain on stdout.
pub fn initialize() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(targets())
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .try_init()
        .map_err(|_| anyhow::anyhow!("structured daemon logging could not be installed"))
}

/// Private diagnostic files one process writes for panics. Beyond this a
/// panic still logs its fixed line, so a panic loop cannot fill a filesystem.
const PANIC_DIAGNOSTICS: usize = 32;

/// Replace the default panic hook, which prints each panic message on stderr
/// and so into the journal. A message can format an error or a value that
/// names a provider, a key or tenant data. The journal line carries only the
/// thread and source location; the message, with a backtrace when
/// `RUST_BACKTRACE` asks for one, goes to a new private (0600) file, as a
/// `daemon_failed` chain does.
pub fn install_panic_hook() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static WRITTEN: AtomicUsize = AtomicUsize::new(0);
    std::panic::set_hook(Box::new(|panic| {
        let location = panic.location();
        let thread = std::thread::current();
        let path = crate::startup_preparation::diagnostic_path("panic");
        let written = WRITTEN.fetch_add(1, Ordering::Relaxed) < PANIC_DIAGNOSTICS
            && crate::startup_preparation::write_private_text(&path, &panic_text(panic)).is_ok();
        tracing::error!(
            event = "panic",
            thread = thread.name().unwrap_or("unnamed"),
            file = location.map_or("unknown", |at| at.file()),
            line = location.map_or(0, |at| at.line()),
            diagnostic_written = written,
            diagnostic_path = %path.display(),
            "a thread panicked; its message is in diagnostic_path"
        );
    }));
}

/// Everything the default hook would have printed, for the private file only.
fn panic_text(panic: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = panic.payload();
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("the panic payload is not a string");
    let mut text = match panic.location() {
        Some(at) => format!("panicked at {at}:\n{message}"),
        None => format!("panicked:\n{message}"),
    };
    let backtrace = std::backtrace::Backtrace::capture();
    if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
        text.push_str(&format!("\n{backtrace}"));
    }
    text
}

/// Private diagnostic files one process writes for drain failures. A drain
/// that is retried logs each attempt; only these many write a file.
const DRAIN_DIAGNOSTICS: usize = 32;

/// A drain failure's completion and component names are fixed labels. The
/// text of its issues is not: a joined worker's error, for one, quotes that
/// worker's panic message. The journal line carries the labels, and the text
/// goes to a new private (0600) file, as a `daemon_failed` chain does.
pub(crate) fn drain_failed(
    event: &'static str,
    failure: &kasumi_types::drain::DrainFailure,
    retry_after_secs: Option<u64>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static WRITTEN: AtomicUsize = AtomicUsize::new(0);
    let components = failure
        .issues()
        .iter()
        .map(|issue| format!("{}[{}]", issue.component(), issue.instance()))
        .collect::<Vec<_>>()
        .join(",");
    let path = crate::startup_preparation::diagnostic_path("drain");
    let written = WRITTEN.fetch_add(1, Ordering::Relaxed) < DRAIN_DIAGNOSTICS
        && crate::startup_preparation::write_private_text(&path, &failure.to_string()).is_ok();
    tracing::error!(
        event,
        completion = ?failure.completion(),
        components = %components,
        retry_after_secs,
        diagnostic_written = written,
        diagnostic_path = %path.display(),
        "a drain did not complete cleanly; its issues are in diagnostic_path"
    );
}

/// A family has used its whole renewal budget. This is logged when the last
/// renewal is issued, so at most once per earned renewal, not per refusal.
pub(crate) fn credential_renewal_budget_spent(family: uuid::Uuid) {
    tracing::warn!(
        event = "credential_renewal_budget_spent",
        family_id = %family,
        "a credential family used its whole renewal budget; further renewals are refused until it refills"
    );
}

/// Deliberately does not accept an error value: provider errors may contain URLs,
/// key names or transport details that belong only in protected operator output.
pub fn tls_reload_failed() {
    tracing::warn!(
        event = "tls_reload_failed",
        "installed TLS replacement rejected"
    );
}

/// The journal line carries only typed failure classes. The whole error chain,
/// which can name provider details, goes to a new private (0600) diagnostic file
/// whose path the line gives (see `startup_preparation::diagnostic_directory`).
pub fn daemon_failed(error: &anyhow::Error) {
    let classes = failure_classes(error);
    let path = crate::startup_preparation::diagnostic_path("daemon");
    let written =
        crate::startup_preparation::write_private_text(&path, &format!("{error:?}")).is_ok();
    tracing::error!(
        event = "daemon_failed",
        failure_classes = %classes.join(","),
        diagnostic_written = written,
        diagnostic_path = %path.display(),
        "daemon failed ({}); the full error chain is in diagnostic_path",
        if classes.is_empty() { "unclassified" } else { classes[0] }
    );
}

/// The options this daemon serves with, so the journal shows the snapshot form
/// and compaction schedule a node actually ran with.
pub fn serve_options(options: &crate::serve_options::ServeOptions) {
    let growth = options.storage_maintenance.growth_percent;
    tracing::info!(
        event = "serve_options",
        local_snapshot_archive = options.local_snapshot_archive.name(),
        storage_compaction_growth_percent = growth,
        "standalone snapshots store the audit archive {}; storage compaction starts at {growth}% growth",
        match options.local_snapshot_archive {
            crate::serve_options::LocalSnapshotArchive::Reference => "by reference (KASUMIL1)",
            crate::serve_options::LocalSnapshotArchive::Embedded => "embedded (KASUMID1)",
        }
    );
}

/// Typed classes of every cause in `error`, outermost first, without formatting
/// any cause: a cause's own text may carry provider details.
pub fn failure_classes(error: &anyhow::Error) -> Vec<&'static str> {
    let mut classes = Vec::new();
    if let Some(class) = kasumi_raft::raft_failure_class(error) {
        classes.push(class);
    }
    for cause in error.chain() {
        let class = if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            Some(io_failure_class(error.kind()))
        } else if let Some(error) = cause.downcast_ref::<kasumi_types::Error>() {
            Some(database_failure_class(error.code))
        } else if let Some(error) = cause.downcast_ref::<kasumi_store::StorageError>() {
            Some(match error {
                kasumi_store::StorageError::DatabaseClosed => "kv_database_closed",
                kasumi_store::StorageError::Io(error) => io_failure_class(error.kind()),
                kasumi_store::StorageError::UnknownCommit(_) => "kv_unknown_commit",
                kasumi_store::StorageError::Core(_) => "kv_core",
                kasumi_store::StorageError::RetainedOwner { error, .. } => {
                    io_failure_class(error.kind())
                }
            })
        } else if cause.is::<kasumi_store::KeyAccessDenied>() {
            Some("key_access_denied")
        } else if cause
            .downcast_ref::<kasumi_engine::admission::TotalExceedsHighWater>()
            .is_some()
        {
            Some("admission_exceeds_high_water")
        } else if let Some(error) = cause.downcast_ref::<serde_json::Error>() {
            Some(match error.classify() {
                serde_json::error::Category::Io => "json_io",
                serde_json::error::Category::Syntax => "json_syntax",
                serde_json::error::Category::Data => "json_data",
                serde_json::error::Category::Eof => "json_eof",
            })
        } else if let Some(error) = cause.downcast_ref::<tokio::task::JoinError>() {
            Some(if error.is_panic() {
                "task_panicked"
            } else {
                "task_cancelled"
            })
        } else {
            None
        };
        if let Some(class) = class
            && !classes.contains(&class)
        {
            classes.push(class);
        }
    }
    classes
}

fn io_failure_class(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "io_not_found",
        std::io::ErrorKind::PermissionDenied => "io_permission_denied",
        std::io::ErrorKind::StorageFull => "io_storage_full",
        std::io::ErrorKind::OutOfMemory => "io_out_of_memory",
        std::io::ErrorKind::InvalidData => "io_invalid_data",
        std::io::ErrorKind::TimedOut => "io_timed_out",
        std::io::ErrorKind::AddrInUse => "io_address_in_use",
        std::io::ErrorKind::AlreadyExists => "io_already_exists",
        std::io::ErrorKind::ReadOnlyFilesystem => "io_read_only_filesystem",
        _ => "io_other",
    }
}

/// The configured admission total cannot start below the RSS high-water mark.
/// Both figures come from configuration and detected memory, never a provider.
pub fn admission_exceeds_high_water(refusal: &kasumi_engine::admission::TotalExceedsHighWater) {
    tracing::error!(
        event = "admission_exceeds_high_water",
        max_inflight_bytes = refusal.max_inflight_bytes,
        high_water_bytes = refusal.high_water_bytes,
        "admission.max_inflight_bytes exceeds the RSS high-water mark, which defaults to half of host or container memory; lower it together with the persistent_disk file and handle caps whose metadata it covers, set high_water_bytes up to the detected memory, or add memory"
    );
}

pub fn daemon_starting() {
    tracing::info!(
        event = "daemon_starting",
        "opening installed daemon configuration"
    );
}

pub fn daemon_stopped() {
    tracing::info!(event = "daemon_stopped", "daemon owners drained");
}

/// Only bounded typed classes leave the original failure owner. In particular,
/// neither an Anyhow context nor a provider's Display/Debug output is logged.
pub(crate) fn original_engine_open_failed(tenant: &str, original: &kasumi_engine::SnapshotFailure) {
    tracing::warn!(
        tenant,
        event = "original_engine_open_failed",
        failure_class = snapshot_failure_class(original),
        "fresh original engine admission failed"
    );
}

fn snapshot_failure_class(original: &kasumi_engine::SnapshotFailure) -> &'static str {
    use kasumi_engine::SnapshotFailure;
    match original {
        SnapshotFailure::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Busy) => {
            "scratch_busy"
        }
        SnapshotFailure::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Sealed) => {
            "scratch_sealed"
        }
        SnapshotFailure::Creation(_) => "scratch_creation",
        SnapshotFailure::Operation(error) => database_failure_class(error.code),
        SnapshotFailure::Source(error) => {
            if let Some(class) = kasumi_raft::raft_failure_class(error) {
                return class;
            }
            if let Some(error) = error.downcast_ref::<kasumi_types::Error>() {
                return database_failure_class(error.code);
            }
            if let Some(error) = error.downcast_ref::<std::io::Error>() {
                return io_failure_class(error.kind());
            }
            if let Some(error) = error.downcast_ref::<tokio::task::JoinError>() {
                return if error.is_panic() {
                    "task_panicked"
                } else {
                    "task_cancelled"
                };
            }
            "source_unclassified"
        }
    }
}

fn database_failure_class(code: kasumi_types::ErrorCode) -> &'static str {
    use kasumi_types::ErrorCode;
    match code {
        ErrorCode::InvalidArgument => "invalid_argument",
        ErrorCode::Unauthorized => "unauthorized",
        ErrorCode::Forbidden => "forbidden",
        ErrorCode::NotFound => "not_found",
        ErrorCode::AlreadyExists => "already_exists",
        ErrorCode::Conflict => "conflict",
        ErrorCode::SchemaViolation => "schema_violation",
        ErrorCode::QuotaExceeded => "quota_exceeded",
        ErrorCode::ResourceExhausted => "resource_exhausted",
        ErrorCode::IndexRequired => "index_required",
        ErrorCode::CursorExpired => "cursor_expired",
        ErrorCode::Unavailable => "unavailable",
        ErrorCode::UnknownOutcome => "unknown_outcome",
        ErrorCode::Corruption => "corruption",
        ErrorCode::Sealed => "sealed",
        ErrorCode::AuditUnavailable => "audit_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[test]
    fn json_diagnostics_exclude_dependency_payloads_and_span_fields() {
        let bytes = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::registry().with(targets()).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(bytes.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", token = "secret-span-token");
            let _entered = span.enter();
            tracing::info!(target: "openraft", document = "private-document", "replicated command");
            tracing::error!(target: "openraft", error = "private-storage-chain", "quit");
            tracing::info!(target: "kasumi_engine", document = "private-engine", "applied");
            tracing::debug!(token = "private-debug", "debug details");
            tls_reload_failed();
            tracing::warn!(target: "kasumi_engine", event = "engine_warning", "fixed");
            original_engine_open_failed(
                "fixture-tenant",
                &kasumi_engine::SnapshotFailure::Source(
                    anyhow::Error::new(std::io::Error::new(
                        std::io::ErrorKind::StorageFull,
                        "private-storage-chain",
                    ))
                    .context("private-provider-url"),
                ),
            );
        });
        let lines = bytes.0.lock().unwrap().clone();
        let values = lines
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 3);
        assert_eq!(values[0]["fields"]["event"], "tls_reload_failed");
        assert_eq!(values[1]["fields"]["event"], "engine_warning");
        assert_eq!(values[2]["fields"]["event"], "original_engine_open_failed");
        assert_eq!(values[2]["fields"]["failure_class"], "io_storage_full");
        for value in values {
            let encoded = value.to_string();
            assert!(!encoded.contains("private-") && !encoded.contains("secret-span-token"));
        }
    }

    /// The hook is process-wide, so a child process installs it and panics.
    #[test]
    fn panic_messages_reach_only_a_private_diagnostic_file() {
        use std::os::unix::fs::PermissionsExt;
        const NAME: &str = "logging::tests::panic_messages_reach_only_a_private_diagnostic_file";
        const MARKER: &str = "KASUMI_PANIC_HOOK_CHILD";
        if std::env::var(MARKER).as_deref() == Ok(NAME) {
            initialize().unwrap();
            install_panic_hook();
            let panics = |panic: fn()| {
                let thread = std::thread::Builder::new().name("worker".into());
                assert!(thread.spawn(panic).unwrap().join().is_err());
            };
            panics(|| panic!("{} refused", "https://vault.internal/v1/tenant-key"));
            panics(|| std::panic::panic_any(7u32));
            for _ in 0..PANIC_DIAGNOSTICS {
                panics(|| panic!("private-repeated"));
            }
            // A joined worker's error quotes its panic message; a drain
            // failure that carries it is logged by its labels only.
            let mut report = kasumi_types::drain::DrainReport::default();
            let issue = report.record(
                "background worker",
                3,
                anyhow::anyhow!("task 7 panicked with message \"private-drain-payload\""),
            );
            let failure = kasumi_types::drain::DrainFailure::retained(issue);
            drain_failed("fixture_drain_retained", &failure, Some(4));
            credential_renewal_budget_spent(uuid::Uuid::nil());
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(MARKER, NAME)
            .env("KASUMI_DIAGNOSTIC_DIRECTORY", directory.path())
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{stderr}"
        );
        // Nothing the process printed carries a panic message.
        for printed in [&stdout, &stderr] {
            for private in [
                "vault.internal",
                "private-repeated",
                "private-drain-payload",
            ] {
                assert!(!printed.contains(private), "{private}");
            }
        }
        let events = stderr
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|line| line["fields"]["event"] == "panic")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), PANIC_DIAGNOSTICS + 2);
        let diagnostic = |event: &serde_json::Value| {
            let fields = &event["fields"];
            assert_eq!(event["level"], "ERROR");
            assert_eq!(fields["thread"], "worker");
            assert!(fields["file"].as_str().unwrap().ends_with("logging.rs"));
            assert!(fields["line"].as_u64().unwrap() > 0);
            let path = std::path::PathBuf::from(fields["diagnostic_path"].as_str().unwrap());
            assert_eq!(path.parent(), Some(directory.path()));
            fields["diagnostic_written"].as_bool().unwrap().then(|| {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
                std::fs::read_to_string(path).unwrap()
            })
        };
        let first = diagnostic(&events[0]).unwrap();
        assert!(first.starts_with("panicked at ") && first.contains("logging.rs"));
        assert!(first.contains("https://vault.internal/v1/tenant-key refused"));
        let second = diagnostic(&events[1]).unwrap();
        assert!(second.contains("the panic payload is not a string"));
        // The file bound holds; the fixed journal line continues past it.
        let written = events.iter().filter_map(diagnostic).count();
        assert_eq!(written, PANIC_DIAGNOSTICS);
        assert!(diagnostic(&events[PANIC_DIAGNOSTICS + 1]).is_none());

        let logged = stderr
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect::<Vec<_>>();
        let event = |name: &str| {
            let mut matching = logged.iter().filter(|line| line["fields"]["event"] == name);
            let found = matching.next().unwrap_or_else(|| panic!("no {name} line"));
            assert!(matching.next().is_none());
            found
        };
        let drain = event("fixture_drain_retained");
        assert_eq!(drain["level"], "ERROR");
        assert_eq!(drain["fields"]["completion"], "Retained");
        assert_eq!(drain["fields"]["components"], "background worker[3]");
        assert_eq!(drain["fields"]["retry_after_secs"], 4);
        assert_eq!(drain["fields"]["diagnostic_written"], true);
        let path = std::path::PathBuf::from(drain["fields"]["diagnostic_path"].as_str().unwrap());
        assert_eq!(path.parent(), Some(directory.path()));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("drain Retained; background worker[3]: "));
        assert!(text.contains("private-drain-payload"));
        let spent = event("credential_renewal_budget_spent");
        assert_eq!(spent["level"], "WARN");
        assert_eq!(
            spent["fields"]["family_id"],
            "00000000-0000-0000-0000-000000000000"
        );

        let files = |kind: &str| {
            std::fs::read_dir(directory.path())
                .unwrap()
                .filter(|entry| {
                    let name = entry.as_ref().unwrap().file_name();
                    name.to_string_lossy().starts_with(kind)
                })
                .count()
        };
        assert_eq!(files("kasumi-panic-"), PANIC_DIAGNOSTICS);
        assert_eq!(files("kasumi-drain-"), 1);
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            PANIC_DIAGNOSTICS + 1
        );
    }

    #[test]
    fn daemon_failures_name_every_typed_cause_without_formatting_any() {
        #[derive(Debug)]
        struct Opaque;
        impl std::fmt::Display for Opaque {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("opaque originals must not be formatted")
            }
        }
        impl std::error::Error for Opaque {}
        let error =
            anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::StorageFull, Opaque))
                .context("opening encrypted node runtime");
        assert_eq!(failure_classes(&error), ["io_storage_full"]);
        let error = anyhow::Error::new(kasumi_types::Error::new(
            kasumi_types::ErrorCode::Corruption,
            "private-record",
        ))
        .context(Opaque);
        assert_eq!(failure_classes(&error), ["corruption"]);
        let json = serde_json::from_slice::<serde_json::Value>(b"{").unwrap_err();
        assert_eq!(
            failure_classes(
                &anyhow::Error::new(json).context("invalid runtime configuration JSON")
            ),
            ["json_eof"]
        );
        assert!(failure_classes(&anyhow::Error::new(Opaque)).is_empty());
    }

    #[test]
    fn engine_open_classifies_typed_causes_without_formatting_originals() {
        use kasumi_engine::SnapshotFailure;
        assert_eq!(
            snapshot_failure_class(&SnapshotFailure::from(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Corruption,
                "private-record"
            ),)),
            "corruption"
        );
        assert_eq!(
            snapshot_failure_class(&SnapshotFailure::AdmissionRefused(
                kasumi_store::ScratchAdmissionRefusal::Busy,
            )),
            "scratch_busy"
        );
        assert_eq!(
            snapshot_failure_class(&SnapshotFailure::AdmissionRefused(
                kasumi_store::ScratchAdmissionRefusal::Sealed,
            )),
            "scratch_sealed"
        );
        #[derive(Debug)]
        struct Opaque;
        impl std::fmt::Display for Opaque {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("opaque originals must not be formatted")
            }
        }
        impl std::error::Error for Opaque {}
        assert_eq!(
            snapshot_failure_class(&SnapshotFailure::Source(anyhow::Error::new(Opaque))),
            "source_unclassified"
        );
    }
}
