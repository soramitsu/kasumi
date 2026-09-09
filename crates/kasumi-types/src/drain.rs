//! Process-local ownership evidence. These values are never accepted from wire
//! input or persisted as authorization, receipts, or distributed fencing proof.
use std::{collections::BTreeMap, fmt, sync::Arc};

pub type DrainResult = std::result::Result<(), DrainFailure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainCompletion {
    /// Every owner in the closed admission scope has actually drained.
    Complete,
    /// Keep the exact owner: completion is not yet established.
    Retained,
}

/// One terminal observation for one local owner. Clones of this Arc preserve the
/// original error object and identify repeated reports of the same failure.
#[derive(Debug)]
pub struct DrainIssue {
    component: &'static str,
    instance: usize,
    error: anyhow::Error,
}
impl DrainIssue {
    pub fn error(&self) -> &anyhow::Error {
        &self.error
    }
    pub fn component(&self) -> &'static str {
        self.component
    }
    pub fn instance(&self) -> usize {
        self.instance
    }
}
impl fmt::Display for DrainIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]: {}", self.component, self.instance, self.error)
    }
}

#[derive(Clone, Debug)]
pub struct DrainFailure {
    completion: DrainCompletion,
    issues: Vec<Arc<DrainIssue>>,
}
impl DrainFailure {
    pub fn retained(issue: Arc<DrainIssue>) -> Self {
        Self {
            completion: DrainCompletion::Retained,
            issues: vec![issue],
        }
    }
    pub fn completion(&self) -> DrainCompletion {
        self.completion
    }
    pub fn issues(&self) -> &[Arc<DrainIssue>] {
        &self.issues
    }
}
impl fmt::Display for DrainFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "drain {:?}", self.completion)?;
        for issue in &self.issues {
            write!(f, "; {issue}")?;
        }
        Ok(())
    }
}
impl std::error::Error for DrainFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.issues
            .first()
            .map(|issue| issue.error.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Keep this report in the resource owner, not a cancellable drain future.
/// Local slots are stable positions in that owner's bounded component inventory.
/// Reusing a slot preserves its first actual error; propagated typed issues keep
/// their own Arc identities even when components use the same local slot names.
#[derive(Default, Debug)]
pub struct DrainReport {
    local: BTreeMap<(&'static str, usize), Arc<DrainIssue>>,
    issues: Vec<Arc<DrainIssue>>,
}
impl DrainReport {
    pub fn record(
        &mut self,
        component: &'static str,
        instance: usize,
        error: anyhow::Error,
    ) -> Arc<DrainIssue> {
        let issue = self
            .local
            .entry((component, instance))
            .or_insert_with(|| {
                Arc::new(DrainIssue {
                    component,
                    instance,
                    error,
                })
            })
            .clone();
        self.include(issue.clone());
        issue
    }
    fn include(&mut self, issue: Arc<DrainIssue>) {
        if !self.issues.iter().any(|prior| Arc::ptr_eq(prior, &issue)) {
            self.issues.push(issue);
        }
    }
    /// Record before awaiting another owner; cancelling that later await must
    /// not erase an already joined worker's failure.
    pub fn merge(&mut self, failure: &DrainFailure) {
        for issue in failure.issues() {
            self.include(issue.clone());
        }
    }
    /// Caller has positively established completion of its entire inventory.
    pub fn complete(&self) -> DrainResult {
        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(DrainFailure {
                completion: DrainCompletion::Complete,
                issues: self.issues.clone(),
            })
        }
    }
    /// Finish a complete census. Any retained child prevents a completion claim;
    /// its evidence is included even if the caller did not previously merge it.
    pub fn outcome(&self, retained: Option<DrainFailure>) -> DrainResult {
        match retained {
            None => self.complete(),
            Some(mut failure) => {
                // Retained ownership is the conservative result even if a caller
                // supplies a completed child's diagnostic as its unresolved cause.
                failure.completion = DrainCompletion::Retained;
                let mut issues = self.issues.clone();
                for issue in failure.issues {
                    if !issues.iter().any(|prior| Arc::ptr_eq(prior, &issue)) {
                        issues.push(issue);
                    }
                }
                failure.issues = issues;
                Err(failure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, thiserror::Error)]
    #[error("original worker failure {0}")]
    struct WorkerFailure(u64);

    #[test]
    fn retries_retain_original_error_and_one_issue_per_owned_slot() {
        let mut report = DrainReport::default();
        let original = report.record("worker", 0, WorkerFailure(7).into());
        for _ in 0..1000 {
            let repeated = report.record("worker", 0, WorkerFailure(99).into());
            assert!(Arc::ptr_eq(&original, &repeated));
        }
        let complete = report.complete().unwrap_err();
        assert_eq!(complete.completion(), DrainCompletion::Complete);
        assert_eq!(complete.issues().len(), 1);
        assert_eq!(
            complete.issues()[0]
                .error()
                .downcast_ref::<WorkerFailure>()
                .unwrap()
                .0,
            7
        );
    }
    #[test]
    fn parent_merge_keeps_distinct_owners_and_explicit_remaining_ownership() {
        let mut parent = DrainReport::default();
        let mut first = DrainReport::default();
        let mut second = DrainReport::default();
        first.record("worker", 0, WorkerFailure(1).into());
        let pending = second.record("worker", 0, WorkerFailure(2).into());
        let complete = first.complete().unwrap_err();
        for _ in 0..1000 {
            parent.merge(&complete);
        }
        let retained = parent
            .outcome(Some(DrainFailure::retained(pending)))
            .unwrap_err();
        assert_eq!(retained.completion(), DrainCompletion::Retained);
        assert_eq!(retained.issues().len(), 2);
        parent.merge(&retained);
        assert_eq!(parent.complete().unwrap_err().issues().len(), 2);
    }
}
