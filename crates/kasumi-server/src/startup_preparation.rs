//! Catch preparation unwinds only while its actual resource owners live outside
//! the caught future. This is not recovery from process abort or a drain panic.
use anyhow::Result;
use std::{any::Any, fmt, future::Future, panic::AssertUnwindSafe, sync::Mutex, task::Poll};

/// Retain the original payload while redacting this error's display. The
/// process panic hook still runs before capture and is not changed here.
pub(crate) struct PreparationPanic {
    component: &'static str,
    _payload: Mutex<Box<dyn Any + Send>>,
}
impl fmt::Debug for PreparationPanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparationPanic")
            .field("component", &self.component)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for PreparationPanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} preparation panicked", self.component)
    }
}
impl std::error::Error for PreparationPanic {}

/// The caller must retain pending resources and any partial runtime outside
/// `preparing`, then drain those exact owners on every returned error. The caught
/// future is never polled again after unwinding; its mutable state is not reused.
pub(crate) async fn capture<T>(
    component: &'static str,
    preparing: impl Future<Output = Result<T>>,
) -> Result<T> {
    let mut preparing = std::pin::pin!(preparing);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(AssertUnwindSafe(|| preparing.as_mut().poll(cx))) {
            Ok(result) => result,
            Err(payload) => Poll::Ready(Err(PreparationPanic {
                component,
                _payload: Mutex::new(payload),
            }
            .into())),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, OnceLock},
    };
    use tokio::sync::Notify;

    fn faults() -> &'static Mutex<BTreeSet<(uuid::Uuid, &'static str)>> {
        static FAULTS: OnceLock<Mutex<BTreeSet<(uuid::Uuid, &'static str)>>> = OnceLock::new();
        FAULTS.get_or_init(Default::default)
    }
    pub(crate) struct FaultGuard(uuid::Uuid, &'static str);
    impl Drop for FaultGuard {
        fn drop(&mut self) {
            faults().lock().unwrap().remove(&(self.0, self.1));
        }
    }
    pub(crate) fn install(id: uuid::Uuid, phase: &'static str) -> FaultGuard {
        assert!(faults().lock().unwrap().insert((id, phase)));
        FaultGuard(id, phase)
    }
    pub(crate) fn checkpoint(id: uuid::Uuid, phase: &'static str) {
        let selected = faults().lock().unwrap().remove(&(id, phase));
        if selected {
            std::panic::panic_any(phase);
        }
    }
    #[derive(Default)]
    struct FailurePause {
        entered: Notify,
        release: Notify,
    }
    fn failure_pauses() -> &'static Mutex<BTreeMap<uuid::Uuid, Arc<FailurePause>>> {
        static PAUSES: OnceLock<Mutex<BTreeMap<uuid::Uuid, Arc<FailurePause>>>> = OnceLock::new();
        PAUSES.get_or_init(Default::default)
    }
    pub(crate) struct FailurePauseGuard(uuid::Uuid, Arc<FailurePause>);
    impl FailurePauseGuard {
        pub(crate) async fn entered(&self) {
            self.1.entered.notified().await;
        }
        pub(crate) fn release(&self) {
            self.1.release.notify_one();
        }
    }
    impl Drop for FailurePauseGuard {
        fn drop(&mut self) {
            failure_pauses().lock().unwrap().remove(&self.0);
            self.release();
        }
    }
    pub(crate) fn pause_failure(id: uuid::Uuid) -> FailurePauseGuard {
        let pause = Arc::new(FailurePause::default());
        assert!(
            failure_pauses()
                .lock()
                .unwrap()
                .insert(id, pause.clone())
                .is_none()
        );
        FailurePauseGuard(id, pause)
    }
    pub(crate) async fn failure_checkpoint(id: uuid::Uuid) {
        let pause = failure_pauses().lock().unwrap().remove(&id);
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }
    #[tokio::test]
    async fn preparation_panic_keeps_original_payload_without_exposing_it() {
        #[derive(Debug, PartialEq)]
        struct Original(u64);
        let failure = capture::<()>("test owner", async {
            tokio::task::yield_now().await;
            std::panic::panic_any(Original(29));
        })
        .await
        .unwrap_err();
        let panic = failure.downcast_ref::<PreparationPanic>().unwrap();
        assert_eq!(
            panic._payload.lock().unwrap().downcast_ref::<Original>(),
            Some(&Original(29))
        );
        assert_eq!(failure.to_string(), "test owner preparation panicked");
        assert!(!format!("{failure:?}").contains("29"));
    }
}

#[cfg(test)]
pub(crate) use tests::{checkpoint, failure_checkpoint, install, pause_failure};
