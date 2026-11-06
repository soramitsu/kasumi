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
