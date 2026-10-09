//! Retire actual point backing before settling its original registered result.
use super::*;

pub(crate) fn retire_point_backing<T>(backing: T) -> std::thread::Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(backing)))
}

impl ViewTransaction {
    pub(crate) fn point_retirement_failure(
        &self,
        payload: Box<dyn std::any::Any + Send>,
    ) -> anyhow::Error {
        match self {
            Self::Registered(reader) => {
                reader.preserve_body_panic(payload);
                self.preserve_report(NodeReadAccessError::Reported.into())
            }
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(_) => PointRetirementFailure::new(
                anyhow::anyhow!("prepared point replacement retirement failed"),
                payload,
            )
            .into(),
        }
    }

    pub(crate) fn finish_point_retirement<T>(
        self,
        node: &NodeStore,
        result: Result<T>,
        retirement: std::thread::Result<()>,
    ) -> Result<T> {
        let deadline = std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT;
        match self {
            Self::Registered(reader) => {
                if let Err(payload) = retirement {
                    // The result stays owned outside the destructor catch. Put
                    // the exact payload in this reader's preadmitted report
                    // before finish can retire anything or expose the original.
                    reader.preserve_body_panic(payload);
                }
                node.settle_registered_read_until(reader, result, Some(deadline))
            }
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(_) => match retirement {
                Ok(()) => result,
                Err(payload) => Err(PointRetirementFailure {
                    original: result.err(),
                    _payload: Mutex::new(payload),
                }
                .into()),
            },
        }
    }
}

/// A destructor panic after a point owner has left its registered session.
/// Keeps the original failure and exact panic together. It never proves clean
/// native retirement and must not be classified as a routine refusal.
pub struct PointRetirementFailure {
    original: Option<anyhow::Error>,
    _payload: Mutex<Box<dyn std::any::Any + Send>>,
}
impl std::fmt::Debug for PointRetirementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PointRetirementFailure")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for PointRetirementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("point backing retirement panicked")
    }
}
impl std::error::Error for PointRetirementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().map(|error| error.as_ref() as _)
    }
}

impl PointRetirementFailure {
    /// Preserve both actual observations when retirement follows an existing error.
    pub fn new(original: anyhow::Error, payload: Box<dyn std::any::Any + Send>) -> Self {
        Self {
            original: Some(original),
            _payload: Mutex::new(payload),
        }
    }

    pub fn original_error(&self) -> Option<&anyhow::Error> {
        self.original.as_ref()
    }

    /// Inspect the original payload without transferring or replacing it.
    pub fn with_panic_payload<T>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> T,
    ) -> T {
        inspect(self._payload.lock().as_ref())
    }
}
