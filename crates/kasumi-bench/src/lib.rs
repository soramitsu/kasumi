use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Serialize)]
pub struct Latency {
    operations: usize,
    elapsed_seconds: f64,
    throughput_ops_per_second: f64,
    p50_microseconds: f64,
    p99_microseconds: f64,
    max_microseconds: f64,
}
pub fn latency(mut samples: Vec<u64>, duration: Duration) -> Latency {
    assert!(
        !samples.is_empty(),
        "empty latency distributions are represented as null"
    );
    samples.sort_unstable();
    let percentile = |p: usize| {
        samples[(samples.len().saturating_mul(p).div_ceil(100))
            .saturating_sub(1)
            .min(samples.len() - 1)] as f64
            / 1000.0
    };
    Latency {
        operations: samples.len(),
        elapsed_seconds: duration.as_secs_f64(),
        throughput_ops_per_second: samples.len() as f64 / duration.as_secs_f64(),
        p50_microseconds: percentile(50),
        p99_microseconds: percentile(99),
        max_microseconds: *samples.last().unwrap() as f64 / 1000.0,
    }
}
#[derive(Clone, Serialize)]
pub struct FailedAttempt {
    pub operation_index: usize,
    pub elapsed_microseconds: f64,
    pub error_code: Option<kasumi_types::ErrorCode>,
    pub message: String,
}
#[derive(Clone, Serialize)]
pub struct Measurement {
    pub name: String,
    pub requested_operations: usize,
    pub attempted_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub unattempted_operations: usize,
    /// Successful samples only; denominator includes elapsed workload time and
    /// failed-attempt delay. Failed latency remains separate below.
    pub latency: Option<Latency>,
    pub failed_attempts: Vec<FailedAttempt>,
}
impl Measurement {
    pub fn failed(&self) -> bool {
        self.failed_operations != 0
    }
}

/// Stop the current workload at its first failure, keeping every preceding
/// successful sample and the failed attempt's duration. Never retry an outcome.
pub struct Samples {
    name: String,
    requested: usize,
    started: Instant,
    succeeded: Vec<u64>,
    failures: Vec<FailedAttempt>,
}
impl Samples {
    pub fn new(name: impl Into<String>, requested: usize) -> Self {
        Self {
            name: name.into(),
            requested,
            started: Instant::now(),
            succeeded: Vec::with_capacity(requested),
            failures: Vec::new(),
        }
    }
    pub fn record(&mut self, elapsed: Duration, result: anyhow::Result<()>) -> bool {
        assert!(
            self.failures.is_empty(),
            "stop workload after a failed attempt"
        );
        match result {
            Ok(()) => {
                self.succeeded.push(elapsed.as_nanos() as u64);
                true
            }
            Err(error) => {
                let error_code = error.downcast_ref::<kasumi_types::Error>().map(|e| e.code);
                #[cfg(feature = "network")]
                let error_code = error_code.or_else(|| {
                    error
                        .downcast_ref::<tonic::Status>()
                        .and_then(|status| {
                            serde_json::from_slice::<kasumi_types::Error>(status.details()).ok()
                        })
                        .map(|error| error.code)
                });
                let bounded = kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Unavailable,
                    format!("{error:#}"),
                );
                self.failures.push(FailedAttempt {
                    operation_index: self.succeeded.len(),
                    elapsed_microseconds: elapsed.as_secs_f64() * 1e6,
                    error_code,
                    message: bounded.message,
                });
                false
            }
        }
    }
    pub fn finish(self) -> Measurement {
        let successful_operations = self.succeeded.len();
        let failed_operations = self.failures.len();
        Measurement {
            name: self.name,
            requested_operations: self.requested,
            attempted_operations: successful_operations + failed_operations,
            successful_operations,
            failed_operations,
            unattempted_operations: self
                .requested
                .saturating_sub(successful_operations + failed_operations),
            latency: (!self.succeeded.is_empty())
                .then(|| latency(self.succeeded, self.started.elapsed())),
            failed_attempts: self.failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_failure_keeps_prior_samples_and_never_counts_unattempted_work() {
        let mut samples = Samples::new("mixed", 1000);
        assert!(samples.record(Duration::from_micros(20), Ok(())));
        assert!(
            !samples.record(
                Duration::from_millis(5),
                Err(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::UnknownOutcome,
                    "resolve receipt"
                )
                .into())
            )
        );
        let measured = samples.finish();
        assert_eq!(
            (
                measured.attempted_operations,
                measured.successful_operations,
                measured.failed_operations,
                measured.unattempted_operations
            ),
            (2, 1, 1, 998)
        );
        assert_eq!(measured.latency.unwrap().p99_microseconds, 20.0);
        assert_eq!(measured.failed_attempts[0].elapsed_microseconds, 5000.0);
        assert_eq!(
            measured.failed_attempts[0].error_code,
            Some(kasumi_types::ErrorCode::UnknownOutcome)
        );
    }
    #[test]
    fn failure_before_any_success_has_no_success_percentiles() {
        let mut samples = Samples::new("read", 1000);
        assert!(!samples.record(
            Duration::from_millis(1),
            Err(anyhow::anyhow!("unavailable"))
        ));
        assert!(samples.finish().latency.is_none());
    }
}
