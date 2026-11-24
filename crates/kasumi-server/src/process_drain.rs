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
use std::{future::Future, time::Duration};

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
    bounded(grace, async |progress| {
        // An owner admitted after its registry's census would start only to
        // be dropped with the runtime. Seal each registry before its census.
        for kind in [
            crate::serving_owner::Kind::Data,
            crate::serving_owner::Kind::Authority,
        ] {
            crate::serving_owner::seal(kind);
        }
        seal_startups(progress).await;
        // Serving first: a supervisor still closing its runtime owns every
        // worker and child that the later registries report.
        for (registry, kind) in [
            ("data_serving", crate::serving_owner::Kind::Data),
            ("authority_serving", crate::serving_owner::Kind::Authority),
        ] {
            progress
                .join(registry, crate::serving_owner::drain(kind))
                .await;
        }
        startups(progress).await;
        progress
            .join("background_custody", background_custody())
            .await;
        // Every owner that could still start a blocking child while closing
        // has now been joined.
        kasumi_store::NodeDisk::seal_installed_filesystem_children();
        kasumi_engine::admission::MemoryCore::seal_installed_blocking_children();
        progress
            .join(
                "installed_disk_children",
                kasumi_store::NodeDisk::drain_installed_filesystem_children(),
            )
            .await;
        progress
            .join(
                "installed_blocking_children",
                kasumi_engine::admission::MemoryCore::drain_installed_blocking_children(),
            )
            .await;
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

async fn seal_startups(progress: &mut DrainProgress) {
    for (registry, kind) in STARTUPS {
        progress.current = registry;
        crate::startup_owner::seal(kind).await;
    }
}

/// Opens, operator commands and enrollments whose caller was cancelled, or
/// whose publication was refused, and which are still closing their owner.
async fn startups(progress: &mut DrainProgress) {
    for (registry, kind) in STARTUPS {
        progress
            .join(registry, crate::startup_owner::drain(kind))
            .await;
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

/// Only this serial traversal writes these fields. A timed-out wait drops its
/// borrow, leaving the original registry name available to the exit log.
struct DrainProgress {
    current: &'static str,
    failed: bool,
}
impl DrainProgress {
    async fn join<E: Into<anyhow::Error>>(
        &mut self,
        registry: &'static str,
        work: impl Future<Output = Result<(), E>>,
    ) {
        self.current = registry;
        if let Err(error) = work.await {
            self.failed = true;
            crate::logging::process_drain_failed(registry, &error.into());
        }
    }
}

async fn bounded(grace: Duration, traversal: impl AsyncFnOnce(&mut DrainProgress)) -> ProcessDrain {
    let mut progress = DrainProgress {
        current: "startup_seal",
        failed: false,
    };
    match tokio::time::timeout(grace, traversal(&mut progress)).await {
        Err(_) => {
            crate::logging::process_drain_retained(grace, progress.current);
            ProcessDrain::Retained
        }
        Ok(()) if progress.failed => ProcessDrain::Failed,
        Ok(()) => ProcessDrain::Clean,
    }
}

#[cfg(test)]
#[path = "process_drain_tests.rs"]
mod tests;
