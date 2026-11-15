//! Aggregate exact child outcomes before awaiting another runtime component.
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainIssueRef, DrainReport, DrainResult};

/// Drop a complete outcome that only repeats already reported observations.
///
/// `reported` holds complete drains that were observed and logged before, such
/// as a superseded original database's closure drain. An independent census
/// of the same owners repeats those exact issues. It is no new evidence when
/// every issue is the identical observation (`DrainIssueRef::ptr_eq`), not
/// merely one with the same component name. A retained outcome, or one with
/// any unmatched issue, is returned unchanged with all of its issues.
pub(crate) fn unless_reported(outcome: DrainResult, reported: &[DrainFailure]) -> DrainResult {
    match outcome {
        Err(failure)
            if failure.completion() == DrainCompletion::Complete
                && failure.issues().iter().all(|issue| {
                    reported
                        .iter()
                        .filter(|prior| prior.completion() == DrainCompletion::Complete)
                        .flat_map(DrainFailure::issues)
                        .any(|prior| DrainIssueRef::ptr_eq(prior, issue))
                }) =>
        {
            Ok(())
        }
        outcome => outcome,
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(report: &DrainReport) -> DrainFailure {
        report.complete().unwrap_err()
    }

    #[test]
    fn census_repeating_a_reported_complete_drain_is_no_new_failure() {
        let mut owner = DrainReport::default();
        owner.record("Raft apply", 0, anyhow::anyhow!("retained apply failure"));
        let closure = complete(&owner);
        // The census re-records the same slot and returns the same observation.
        owner.record("Raft apply", 0, anyhow::anyhow!("later census"));
        assert!(unless_reported(Err(complete(&owner)), std::slice::from_ref(&closure)).is_ok());
        assert!(unless_reported(Ok(()), &[closure]).is_ok());
    }

    #[test]
    fn unmatched_mixed_or_retained_outcomes_stay_failures() {
        let mut owner = DrainReport::default();
        let apply = owner.record("Raft apply", 0, anyhow::anyhow!("reported"));
        let closure = complete(&owner);

        // Same component name and slot, but a different observation.
        let mut other = DrainReport::default();
        other.record("Raft apply", 0, anyhow::anyhow!("unreported"));
        let unrelated =
            unless_reported(Err(complete(&other)), std::slice::from_ref(&closure)).unwrap_err();
        assert_eq!(unrelated.issues().len(), 1);
        assert!(!DrainIssueRef::ptr_eq(&unrelated.issues()[0], &apply));

        // One new issue keeps the whole outcome, including the repeated one.
        let mut mixed = DrainReport::default();
        mixed.merge(&closure);
        mixed.record("Raft startup", 0, anyhow::anyhow!("new"));
        let mixed =
            unless_reported(Err(complete(&mixed)), std::slice::from_ref(&closure)).unwrap_err();
        assert_eq!(mixed.completion(), DrainCompletion::Complete);
        assert_eq!(mixed.issues().len(), 2);

        // A retained census never becomes success, even for reported issues.
        let retained = owner
            .outcome(Some(DrainFailure::retained(apply.clone())))
            .unwrap_err();
        let kept = unless_reported(Err(retained), &[closure]).unwrap_err();
        assert_eq!(kept.completion(), DrainCompletion::Retained);

        // Only complete earlier drains count as reported evidence.
        let unresolved = owner
            .outcome(Some(DrainFailure::retained(apply)))
            .unwrap_err();
        let census = unless_reported(Err(complete(&owner)), &[unresolved]).unwrap_err();
        assert_eq!(census.completion(), DrainCompletion::Complete);
    }
}
