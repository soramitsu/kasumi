//! Diagnostics for the one-use Initialize packet. A durable target reservation
//! enables the report. Subsequent calls to inspect or replay it do not.
use super::TargetTaskFailure;
use kasumi_engine::SnapshotFailure;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct InitializeDiagnostic {
    pub(crate) phase: Option<Uuid>,
    pub(crate) stage: &'static str,
}

// One fixed-size copy for the installed target. The caller retains its original
// error and performs no diagnostic I/O on its execution or response deadline.
#[derive(Default)]
pub(super) struct InitializeFailures {
    first: std::sync::OnceLock<Failure>,
    exported: AtomicBool,
}

struct Failure {
    phase: Uuid,
    stage: &'static str,
    class: &'static str,
    io: Option<std::io::ErrorKind>,
    transport: Option<tonic::Code>,
    database: Option<kasumi_types::ErrorCode>,
}

impl InitializeFailures {
    pub(super) fn record(&self, diagnostic: &InitializeDiagnostic, original: &TargetTaskFailure) {
        let Some(phase) = diagnostic.phase else {
            return;
        };
        let mut failure = Failure {
            phase,
            stage: diagnostic.stage,
            class: "source",
            io: None,
            transport: None,
            database: None,
        };
        failure.class = match original {
            TargetTaskFailure::Snapshot(SnapshotFailure::Source(source)) => {
                if let Some(error) = source.downcast_ref::<kasumi_client::ClientError>() {
                    match error {
                        kasumi_client::ClientError::Transport(status) => {
                            failure.transport = Some(status.code());
                            "transport"
                        }
                        kasumi_client::ClientError::DecodeRejected { code, database, .. } => {
                            failure.transport = Some(*code);
                            failure.database = *database;
                            "decode"
                        }
                        kasumi_client::ClientError::LocalDeadline(_) => "installed_route_deadline",
                        _ => "installed_client",
                    }
                } else if let Some(error) = source.downcast_ref::<kasumi_types::Error>() {
                    failure.database = Some(error.code);
                    "database"
                } else if let Some(error) = source.downcast_ref::<std::io::Error>() {
                    failure.io = Some(error.kind());
                    "io"
                } else {
                    "source"
                }
            }
            TargetTaskFailure::Snapshot(SnapshotFailure::Operation(error)) => {
                failure.database = Some(error.code);
                "operation"
            }
            TargetTaskFailure::Snapshot(SnapshotFailure::AdmissionRefused(_)) => "admission",
            TargetTaskFailure::Snapshot(SnapshotFailure::Creation(_)) => "creation",
            TargetTaskFailure::NodeStartup(_) => "node_startup",
            TargetTaskFailure::RetiredSource(_) => "retired_source",
        };
        let _ = self.first.set(failure);
    }

    pub(super) fn export(&self) {
        let Some(failure) = self.first.get() else {
            return;
        };
        if self.exported.swap(true, Ordering::Relaxed) {
            return;
        }
        let path = crate::startup_preparation::diagnostic_path("target-initialize");
        // Never format or retain the original message, transport metadata, or payload.
        let detail = std::fmt::from_fn(|f| {
            write!(
                f,
                "phase={} stage={} failure={} io={:?} transport={:?} database={:?}",
                failure.phase,
                failure.stage,
                failure.class,
                failure.io,
                failure.transport,
                failure.database
            )
        });
        let written = crate::startup_preparation::write_private_text(&path, &detail).is_ok();
        tracing::error!(
            event = "target_initialize_failed",
            diagnostic_written = written,
            diagnostic_path = %path.display(),
            "the first locally accepted Initialize failure has a private diagnostic"
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn only_first_durable_initialize_failure_records_private_stage_and_typed_code() {
        const NAME: &str = "target_runtime::initialize_diagnostic::tests::only_first_durable_initialize_failure_records_private_stage_and_typed_code";
        const CHILD: &str = "KASUMI_TEST_ACCEPTED_INITIALIZE_DIAGNOSTIC";
        if std::env::var_os(CHILD).is_some() {
            crate::logging::initialize().unwrap();
            let directory = crate::startup_preparation::diagnostic_directory();
            let mut diagnostic = InitializeDiagnostic::default();
            let failures = InitializeFailures::default();
            let source = kasumi_client::ClientError::Transport(tonic::Status::unavailable(
                "protected fixture detail",
            ));
            let original = TargetTaskFailure::Snapshot(SnapshotFailure::Source(source.into()));
            failures.record(&diagnostic, &original);
            failures.export();
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            diagnostic.phase = Some(Uuid::from_u128(1));
            diagnostic.stage = "acquire_lifecycle_grant";
            failures.record(&diagnostic, &original);
            diagnostic.phase = Some(Uuid::from_u128(2));
            failures.record(&diagnostic, &original);
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            failures.export();
            failures.export();
            let files: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(files.len(), 1);
            assert_eq!(
                std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::read_to_string(&files[0]).unwrap(),
                format!(
                    "phase={} stage=acquire_lifecycle_grant failure=transport io=None transport=Some(Unavailable) database=None\n",
                    Uuid::from_u128(1)
                )
            );
            let TargetTaskFailure::Snapshot(SnapshotFailure::Source(source)) = original else {
                unreachable!()
            };
            let Some(kasumi_client::ClientError::Transport(status)) = source.downcast_ref() else {
                unreachable!()
            };
            assert_eq!(status.message(), "protected fixture detail");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("KASUMI_DIAGNOSTIC_DIRECTORY", directory.path())
            .output()
            .unwrap();
        let logs = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{logs}");
        assert!(logs.contains("target_initialize_failed"));
        assert!(
            !logs.contains("protected fixture detail") && !logs.contains("acquire_lifecycle_grant")
        );
    }
}
