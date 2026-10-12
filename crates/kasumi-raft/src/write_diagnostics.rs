//! Borrowed failure diagnostics. Never format an opaque error, response or
//! panic payload, and never move the original out of its retained owner.
use crate::{ApplyObservationRef, RetainedApplyReport, apply_failure::RetainedApplyFailure};
use openraft::{
    BasicNode, StorageError,
    error::{ClientWriteError, Fatal, RaftError},
};
use sha2::{Digest, Sha256};

struct ErrorClass {
    io: Option<std::io::ErrorKind>,
    database: Option<kasumi_types::ErrorCode>,
    raft: &'static str,
    // Only an actual source-owned static label may be printed. Owned strings
    // can contain request material; fingerprint them without invoking Display.
    source_label: Option<&'static str>,
    owned_message_sha256: Option<[u8; 32]>,
    json: Option<(serde_json::error::Category, usize, usize)>,
}

impl std::fmt::Debug for ErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErrorClass")
            .field("io", &self.io)
            .field("database", &self.database)
            .field("raft", &self.raft)
            .field("source_label", &self.source_label)
            .field("owned_message_sha256", &self.owned_message_sha256)
            .field("json", &self.json)
            .finish()
    }
}

fn creation(stage: &'static str, failure: &kasumi_store::ScratchCreationFailure) {
    failure.with_diagnostic(|report| {
        let admission = report.admission_error().map(std::io::Error::kind);
        let opening = report.opening_error().map(|error| (
            error.disposition(), error.io_error().map(std::io::Error::kind), error.is_capacity_denied(),
        ));
        eprintln!("Kasumi retained creation: stage={stage} admission={admission:?} opening={opening:?} constructor={}", report.constructor_report().is_some());
    });
}

fn classify(error: &anyhow::Error) -> ErrorClass {
    let raft = match error.downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>() {
        Some(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => "redirect",
        Some(RaftError::APIError(ClientWriteError::TaskCapacity(_))) => "capacity",
        Some(RaftError::APIError(_)) => "api_other",
        Some(RaftError::Fatal(Fatal::StorageError(StorageError::IO { .. }))) => "storage_io",
        Some(RaftError::Fatal(Fatal::StorageError(StorageError::Defensive { .. }))) => {
            "storage_defensive"
        }
        Some(RaftError::Fatal(Fatal::Panicked)) => "panicked",
        Some(RaftError::Fatal(Fatal::TaskCapacity(_))) => "fatal_capacity",
        Some(RaftError::Fatal(Fatal::Cancelled)) => "cancelled",
        Some(RaftError::Fatal(Fatal::Stopped)) => "stopped",
        None => "none",
    };
    ErrorClass {
        io: error.chain().find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind)
        }),
        database: error.chain().find_map(|cause| {
            cause
                .downcast_ref::<kasumi_types::Error>()
                .map(|error| error.code)
        }),
        raft,
        source_label: error.downcast_ref::<&'static str>().copied(),
        owned_message_sha256: error
            .downcast_ref::<String>()
            .map(|text| Sha256::digest(text.as_bytes()).into()),
        json: error
            .downcast_ref::<serde_json::Error>()
            .map(|error| (error.classify(), error.line(), error.column())),
    }
}

fn observation(stage: &'static str, value: ApplyObservationRef<'_>) {
    let state = match value {
        ApplyObservationRef::NotEntered => "not_entered",
        ApplyObservationRef::Running => "running",
        ApplyObservationRef::Returned => "returned",
        ApplyObservationRef::Error(error) => {
            eprintln!(
                "Kasumi retained apply observation: stage={stage} state=error class={:?}",
                classify(error)
            );
            return;
        }
        ApplyObservationRef::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Busy) => {
            "admission_busy"
        }
        ApplyObservationRef::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Sealed) => {
            "admission_sealed"
        }
        ApplyObservationRef::Creation(failure) => {
            creation(stage, failure);
            "creation_failed"
        }
        ApplyObservationRef::Unwound(_) => "unwound",
        ApplyObservationRef::Refused(crate::CompletionSettleError::Busy) => "settle_busy",
        ApplyObservationRef::Refused(crate::CompletionSettleError::Retained) => "settle_retained",
        ApplyObservationRef::Refused(crate::CompletionSettleError::Foreign) => "settle_foreign",
        ApplyObservationRef::Refused(crate::CompletionSettleError::Protocol) => "settle_protocol",
    };
    eprintln!("Kasumi retained apply observation: stage={stage} state={state}");
}

pub(super) fn report(
    stage: &'static str,
    error: &anyhow::Error,
    access: Option<&'static str>,
    retained: Option<&RetainedApplyFailure>,
) {
    eprintln!(
        "Kasumi application write failed: stage={stage} access={access:?} class={:?}",
        classify(error)
    );
    let Some(retained) = retained else {
        return;
    };
    if retained.try_with_report(|report| match report {
        RetainedApplyReport::Single(error) => {
            eprintln!("Kasumi retained apply: kind=single class={:?}", classify(error));
        }
        RetainedApplyReport::Preparation { original, publication, violation, .. } => {
            let kind = match original {
                kasumi_store::ScratchOperationFailure::Operation(_) => "operation",
                kasumi_store::ScratchOperationFailure::Creation(failure) => {
                    creation("preparation", failure);
                    "creation"
                }
                kasumi_store::ScratchOperationFailure::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Busy) => "admission_busy",
                kasumi_store::ScratchOperationFailure::AdmissionRefused(kasumi_store::ScratchAdmissionRefusal::Sealed) => "admission_sealed",
            };
            eprintln!("Kasumi retained apply: kind=preparation original={kind} violation={violation:?}");
            if let Some(error) = original.operation_error() {
                eprintln!("Kasumi retained preparation error: class={:?}", classify(error));
            }
            if let Some(error) = publication {
                eprintln!("Kasumi retained publication error: class={:?}", classify(error));
            }
        }
        RetainedApplyReport::Ordinary(report) => {
            eprintln!("Kasumi retained apply: kind=ordinary violation={:?} wake_panic={}", report.violation, report.wake_panic.is_some());
            if let Some(error) = report.single {
                eprintln!("Kasumi retained ordinary error: class={:?}", classify(error));
            }
            observation("sink", report.sink);
            observation("action", report.action);
            observation("backend", report.backend);
            observation("finish", report.finish);
            observation("cleanup", report.cleanup);
            observation("drain", report.drain);
        }
    }).is_err() {
        eprintln!("Kasumi retained apply: kind=report_busy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Opaque;
    impl std::fmt::Display for Opaque {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("opaque errors must not be formatted");
        }
    }
    impl std::error::Error for Opaque {}

    #[test]
    fn diagnostics_keep_source_labels_and_never_format_opaque_payloads() {
        let error = anyhow::Error::new(Opaque).context("fixed apply source label");
        assert_eq!(
            classify(&error).source_label,
            Some("fixed apply source label")
        );
        report("test", &error, None, None);
        assert!(error.downcast_ref::<Opaque>().is_some());
        let private = anyhow::Error::msg(String::from("private dynamic payload"));
        let diagnostic = format!("{:?}", classify(&private));
        assert!(!diagnostic.contains("private dynamic payload"));
        assert!(classify(&private).owned_message_sha256.is_some());
    }
}
