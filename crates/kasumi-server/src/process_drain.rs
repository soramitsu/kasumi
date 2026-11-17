//! The last traversal before a Kasumi process exits.
//!
//! An open, an operator command, an enrollment and a serving runtime each hand
//! their unpublished owner to a process-wide registry, so that a cancelled or
//! failed caller cannot drop it; blocking children stay with background
//! custody, their installed disk or the installed memory core. Returning from `main` drops the Tokio
//! runtime, which cancels any retained cleanup at its next await and forgets
//! every outcome nobody collected. A binary therefore seals those registries
//! and joins them here first, for at most its retained grace.
use kasumi_types::drain::{DrainCompletion, DrainReport, DrainResult};
use std::{future::Future, sync::Arc, time::Duration};

/// How a process's final drain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessDrain {
    /// Every registry joined its owners and none reported a failure.
    Clean,
    /// Every registry joined; the logged failures are its owners' outcomes.
    Failed,
    /// The grace expired while an owner was still retained.
    Retained,
}

/// Join every process-wide registry. Each failure is logged under its
/// registry's fixed name, with its text in a private diagnostic file. On
/// `Retained` the caller exits rather than returning into the runtime's own
/// teardown, which would wait for a blocked child without any bound.
pub async fn drain(grace: Duration) -> ProcessDrain {
    bounded(grace, |failed| async move {
        // An owner admitted after its registry's census would start only to
        // be dropped with the runtime. Seal each registry before its census.
        for kind in [
            crate::serving_owner::Kind::Data,
            crate::serving_owner::Kind::Authority,
        ] {
            crate::serving_owner::seal(kind);
        }
        seal_startups().await;
        // Serving first: a supervisor still closing its runtime owns every
        // worker and child that the later registries report.
        for (registry, kind) in [
            ("data_serving", crate::serving_owner::Kind::Data),
            ("authority_serving", crate::serving_owner::Kind::Authority),
        ] {
            failed.observe(registry, crate::serving_owner::drain(kind).await);
        }
        startups(&failed).await;
        failed.observe(
            "background_custody",
            background_custody().await.map_err(Into::into),
        );
        // Every owner that could still start a blocking child while closing
        // has now been joined.
        kasumi_store::NodeDisk::seal_installed_filesystem_children();
        kasumi_engine::admission::MemoryCore::seal_installed_blocking_children();
        failed.observe(
            "installed_disk_children",
            kasumi_store::NodeDisk::drain_installed_filesystem_children()
                .await
                .map_err(Into::into),
        );
        failed.observe(
            "installed_blocking_children",
            kasumi_engine::admission::MemoryCore::drain_installed_blocking_children()
                .await
                .map_err(Into::into),
        );
    })
    .await
}

/// A binary's last step after its command or its daemon returned `status`.
/// A drained owner's failure makes the exit a failure. When the grace expires
/// the process exits here, exactly as a daemon whose serving drain stays
/// retained: its stores recover on the next start as after a crash.
pub async fn finish(status: std::process::ExitCode, daemon: bool) -> std::process::ExitCode {
    use crate::startup_progress::{RETAINED_GRACE, Retained, exit_with_retained_owners};
    match drain(RETAINED_GRACE).await {
        ProcessDrain::Clean => {
            // An invoked command prints only its own result.
            if daemon {
                crate::logging::process_drained();
            }
            status
        }
        ProcessDrain::Failed => std::process::ExitCode::FAILURE,
        ProcessDrain::Retained => exit_with_retained_owners(Retained::Exit, RETAINED_GRACE),
    }
}

const STARTUPS: [(&str, crate::startup_owner::Kind); 6] = {
    use crate::startup_owner::Kind;
    [
        ("data_startup", Kind::Data),
        ("authority_startup", Kind::Authority),
        ("local_operator", Kind::LocalOperator),
        ("tenant_enrollment", Kind::TenantEnrollment),
        ("signer_verifier", Kind::SignerVerifier),
        ("target_journal", Kind::TargetJournal),
    ]
};

async fn seal_startups() {
    for (_, kind) in STARTUPS {
        crate::startup_owner::seal(kind).await;
    }
}

/// Opens, operator commands and enrollments whose caller was cancelled, or
/// whose publication was refused, and which are still closing their owner.
async fn startups(failed: &Failures) {
    for (registry, kind) in STARTUPS {
        failed.observe(registry, crate::startup_owner::drain(kind).await);
    }
}

/// Workers whose runtime or verifier facade was dropped without joining them.
/// Draining a cell closes it and joins its exact child.
async fn background_custody() -> DrainResult {
    let mut report = DrainReport::default();
    let mut retained = None;
    let mut after = None;
    loop {
        let page = match kasumi_serving::pending_background_custody(after, 256) {
            Ok(page) => page,
            Err(error) => {
                report.record("background custody inventory", 0, error);
                break;
            }
        };
        let Some((last, _)) = page.last() else { break };
        after = Some(*last);
        for (_, work) in page {
            if let Err(failure) = work.drain().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
    }
    report.outcome(retained)
}

/// Whether any registry reported a failure. Shared with the bounded traversal
/// so an expired grace still knows what was logged before it.
#[derive(Default)]
struct Failures(std::sync::atomic::AtomicBool);
impl Failures {
    fn observe(&self, registry: &'static str, outcome: anyhow::Result<()>) {
        if let Err(error) = outcome {
            self.0.store(true, std::sync::atomic::Ordering::Release);
            crate::logging::process_drain_failed(registry, &error);
        }
    }
}

async fn bounded<Joining: Future<Output = ()>>(
    grace: Duration,
    traversal: impl FnOnce(Arc<Failures>) -> Joining,
) -> ProcessDrain {
    let failures = Arc::new(Failures::default());
    match tokio::time::timeout(grace, traversal(failures.clone())).await {
        Err(_) => {
            crate::logging::process_drain_retained(grace);
            ProcessDrain::Retained
        }
        Ok(()) if failures.0.load(std::sync::atomic::Ordering::Acquire) => ProcessDrain::Failed,
        Ok(()) => ProcessDrain::Clean,
    }
}

#[cfg(test)]
#[path = "process_drain_tests.rs"]
mod tests;
