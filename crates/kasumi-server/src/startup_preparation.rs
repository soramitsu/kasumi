//! Catch preparation unwinds only while its actual resource owners live outside
//! the caught future. This is not recovery from process abort or a drain panic.
use std::{any::Any, fmt, future::Future, panic::AssertUnwindSafe, sync::Mutex, task::Poll};

/// Record the original before cleanup can wait on retained native ownership.
/// Public logs contain only fixed stages/classes; details stay in private tmp.
pub(crate) fn record_failure(stage: &'static str, class: &'static str, error: &dyn fmt::Debug) {
    let path = std::env::temp_dir().join(format!(
        "kasumi-startup-{}-{}.log",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let written = write_private_failure(&path, error).is_ok();
    tracing::error!(
        event = "startup_preparation_failed",
        stage,
        class,
        diagnostic_written = written,
        diagnostic_path = %path.display(),
        "startup preparation failed; original retained before cleanup"
    );
}

fn write_private_failure(path: &std::path::Path, error: &dyn fmt::Debug) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    struct BoundedFile(std::fs::File, usize);
    impl Write for BoundedFile {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = bytes.len().min(self.1);
            self.0.write_all(&bytes[..count])?;
            self.1 -= count;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let mut output = BoundedFile(file, 64 << 10);
    writeln!(output, "{error:#?}")?;
    output.0.sync_all()
}

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
pub(crate) fn capture<T, E: From<anyhow::Error>>(
    component: &'static str,
    preparing: impl Future<Output = std::result::Result<T, E>>,
) -> impl Future<Output = std::result::Result<T, E>> {
    // Box before constructing the returned future. Keeping a large preparation
    // inline in an async wrapper duplicates its state in each enclosing startup
    // layer and can overflow a normal executor thread before the first poll.
    let mut preparing = Box::pin(preparing);
    std::future::poll_fn(move |cx| {
        match std::panic::catch_unwind(AssertUnwindSafe(|| preparing.as_mut().poll(cx))) {
            Ok(result) => result,
            Err(payload) => Poll::Ready(Err(E::from(anyhow::Error::new(PreparationPanic {
                component,
                _payload: Mutex::new(payload),
            })))),
        }
    })
}

#[cfg(test)]
pub(crate) use tests::{checkpoint, failure_checkpoint, install, pause_failure};

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, OnceLock},
    };
    use tokio::sync::Notify;

    #[test]
    fn startup_failure_detail_is_private_bounded_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("failure.log");
        let detail = "private detail".repeat(10_000);
        write_private_failure(&path, &detail).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 64 << 10);
        let before = std::fs::read(&path).unwrap();
        assert!(write_private_failure(&path, &"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let link = directory.path().join("link.log");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(write_private_failure(&link, &"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

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
    async fn nested_preparation_keeps_large_captured_state_off_the_executor_stack() {
        let payload = [31_u8; 128 << 10];
        let inner = capture("inner", async move {
            tokio::task::yield_now().await;
            Ok::<_, anyhow::Error>(std::hint::black_box(payload)[(128 << 10) - 1])
        });
        assert!(std::mem::size_of_val(&inner) < 1024);
        let outer = capture("outer", inner);
        assert!(std::mem::size_of_val(&outer) < 1024);
        assert_eq!(outer.await.unwrap(), 31);
    }

    #[tokio::test]
    async fn preparation_panic_keeps_original_payload_without_exposing_it() {
        #[derive(Debug, PartialEq)]
        struct Original(u64);
        let failure = capture::<(), anyhow::Error>("test owner", async {
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
