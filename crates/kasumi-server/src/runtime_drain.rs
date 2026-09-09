//! Aggregate exact child outcomes before awaiting another runtime component.
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};

pub(crate) fn observe(
    report: &mut DrainReport,
    retained: &mut Option<DrainFailure>,
    outcome: DrainResult,
) {
    if let Err(failure) = outcome {
        report.merge(&failure);
        if failure.completion() == DrainCompletion::Retained {
            *retained = Some(failure);
        }
    }
}

pub(crate) fn combine(
    outcome: anyhow::Result<()>,
    cleanup: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(cleanup)),
    }
}
