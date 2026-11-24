//! Private diagnostics for the first locally accepted Start and Initialize failures.
use super::TargetTaskFailure;
use kasumi_engine::SnapshotFailure;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct MembershipDiagnostic {
    accepted: Option<(Packet, Uuid)>,
    pub(crate) stage: &'static str,
}

#[derive(Clone, Copy)]
enum Packet {
    Start,
    Initialize,
}

impl MembershipDiagnostic {
    pub(crate) fn accepted(&mut self, step: &kasumi_types::TargetRuntimeStep, phase: Uuid) {
        use kasumi_types::{TargetReplicaInput, TargetRuntimeStep};
        let packet = match step {
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_)) => Packet::Start,
            TargetRuntimeStep::Initialize(_) => Packet::Initialize,
            _ => return,
        };
        self.accepted = Some((packet, phase));
        self.stage = "verify_reserved_membership";
    }
}

// Fixed-size summaries. Recording a failure never performs I/O on the request deadline.
#[derive(Default)]
pub(super) struct MembershipFailures {
    start: FailureSlot,
    initialize: FailureSlot,
}

#[derive(Default)]
struct FailureSlot {
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

impl MembershipFailures {
    pub(super) fn record(&self, diagnostic: &MembershipDiagnostic, original: &TargetTaskFailure) {
        let Some((packet, phase)) = diagnostic.accepted else {
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
        let slot = match packet {
            Packet::Start => &self.start,
            Packet::Initialize => &self.initialize,
        };
        let _ = slot.first.set(failure);
    }

    pub(super) fn export(&self) {
        self.start.export("target-start", "target_start_failed");
        self.initialize
            .export("target-initialize", "target_initialize_failed");
    }
}

impl FailureSlot {
    fn export(&self, kind: &'static str, event: &'static str) {
        let Some(failure) = self.first.get() else {
            return;
        };
        if self.exported.swap(true, Ordering::Relaxed) {
            return;
        }
        let path = crate::startup_preparation::diagnostic_path(kind);
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
            event,
            diagnostic_written = written,
            diagnostic_path = %path.display(),
            "the first locally accepted membership packet failure has a private diagnostic"
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn durably_accepted_start_and_initialize_keep_separate_private_failures() {
        const NAME: &str = "target_runtime::membership_diagnostic::tests::durably_accepted_start_and_initialize_keep_separate_private_failures";
        const CHILD: &str = "KASUMI_TEST_ACCEPTED_MEMBERSHIP_DIAGNOSTIC";
        if std::env::var_os(CHILD).is_some() {
            crate::logging::initialize().unwrap();
            let directory = crate::startup_preparation::diagnostic_directory();
            let mut diagnostic = MembershipDiagnostic::default();
            let failures = MembershipFailures::default();
            let source = kasumi_client::ClientError::Transport(tonic::Status::unavailable(
                "protected fixture detail",
            ));
            let original = TargetTaskFailure::Snapshot(SnapshotFailure::Source(source.into()));
            use kasumi_types::{TargetQuorumInput, TargetReplicaInput, TargetRuntimeStep};
            let quorum = TargetQuorumInput {
                origin_sha256: "0".repeat(64),
                materialized: Default::default(),
            };
            let activation = TargetRuntimeStep::StartActivation {
                quorum: quorum.clone(),
                issuer_command_id: Uuid::from_u128(5),
            };
            let start = TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum.clone()));
            let initialize = TargetRuntimeStep::Initialize(quorum);
            failures.record(&diagnostic, &original);
            diagnostic.accepted(&activation, Uuid::from_u128(6));
            failures.record(&diagnostic, &original);
            failures.export();
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            diagnostic.accepted(&initialize, Uuid::from_u128(1));
            diagnostic.stage = "acquire_lifecycle_grant";
            failures.record(&diagnostic, &original);
            diagnostic.accepted(&initialize, Uuid::from_u128(2));
            failures.record(&diagnostic, &original);
            diagnostic.accepted(&start, Uuid::from_u128(3));
            diagnostic.stage = "open_target_replica";
            failures.record(&diagnostic, &original);
            diagnostic.accepted(&start, Uuid::from_u128(4));
            failures.record(&diagnostic, &original);
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            failures.export();
            failures.export();
            let files: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(files.len(), 2);
            for (kind, stage, phase) in [
                ("target-initialize", "acquire_lifecycle_grant", 1),
                ("target-start", "open_target_replica", 3),
            ] {
                let file = files
                    .iter()
                    .find(|p| p.file_name().unwrap().to_str().unwrap().contains(kind))
                    .unwrap();
                assert_eq!(
                    std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    std::fs::read_to_string(file).unwrap(),
                    format!(
                        "phase={} stage={stage} failure=transport io=None transport=Some(Unavailable) database=None\n",
                        Uuid::from_u128(phase)
                    )
                );
            }
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
        assert!(logs.contains("target_initialize_failed") && logs.contains("target_start_failed"));
        assert!(
            !logs.contains("protected fixture detail")
                && !logs.contains("acquire_lifecycle_grant")
                && !logs.contains("open_target_replica")
        );
    }
}
