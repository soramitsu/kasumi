//! Admitted audit jobs retain their actual task until its outcome is observed.
use super::{AuditWork, SecurityAudit};
use anyhow::{Context, Result};
use kasumi_types::drain::{DrainFailure, DrainIssue};
use std::{future::Future, sync::Arc};

#[derive(Default)]
pub(super) struct Jobs {
    next: usize,
    handles: Vec<Job>,
}
struct Job {
    id: usize,
    handle: tokio::task::JoinHandle<()>,
    // Charge retained task/registry metadata until the actual handle is reaped.
    // The separately reserved maintenance worker never needs this admission.
    _reservation: crate::admission::Reservation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_audit::{
        SECURITY_TENANT, SecurityEvent, SecurityEventKind, SecurityOutcome,
    };
    use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
    use kasumi_types::drain::DrainCompletion;
    use std::{task::Poll, time::Duration};

    fn event(sequence: u64) -> SecurityEvent {
        SecurityEvent {
            kind: SecurityEventKind::AccessDenied,
            principal: Some("principal".into()),
            tenant: Some("tenant".into()),
            request_id: format!("event-{sequence}-{}", "a".repeat(120)),
            outcome: SecurityOutcome::Denied,
        }
    }

    #[tokio::test]
    async fn cancelled_record_and_drain_retain_actual_blocking_panic_before_physical_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.redb");
        let provider = Arc::new(LocalKeyProvider::new([74; 32]));
        let node = NodeStore::create_new(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let weak = Arc::downgrade(&node);
        let store =
            TenantStore::initialize_catalog_fixture(node, SECURITY_TENANT.into(), provider.clone())
                .await
                .unwrap();
        let audit = SecurityAudit::initialize(
            store.clone(),
            Default::default(),
            crate::admission::NodeAdmission::new(Default::default()).unwrap(),
        )
        .unwrap();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        *audit.writer.record_fault.lock().unwrap() = Some(RecordFault {
            entered,
            release: blocked,
        });
        let caller = tokio::spawn({
            let audit = audit.clone();
            async move { audit.record_transport(event(0), None).await }
        });
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let mut first = Box::pin(audit.shutdown());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        assert!(
            NodeStore::open_existing(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture()
            )
            .is_err()
        );
        release.send(()).unwrap();
        let failure = tokio::time::timeout(Duration::from_secs(5), audit.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert_eq!(failure.issues().len(), 1);
        assert!(
            failure.issues()[0]
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        assert!(Arc::ptr_eq(
            &failure.issues()[0],
            &audit.shutdown().await.unwrap_err().issues()[0]
        ));
        assert!(audit.record_sync(event(1)).is_err());
        assert!(audit.writer.jobs.lock().await.handles.is_empty());
        drop(audit);
        drop(store);
        assert!(weak.upgrade().is_none());
        let reopened = TenantStore::open_existing_fixture(
            NodeStore::open_existing(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            SECURITY_TENANT.into(),
            provider,
        )
        .await
        .unwrap();
        assert!(reopened.scan("security.audit").unwrap().is_empty());
        reopened.shutdown().await.unwrap();
    }

    struct PanickingArchive {
        inner: kasumi_store::FilesystemAuditArchive,
        entered: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }
    #[async_trait::async_trait]
    impl kasumi_store::AuditArchiveDestination for PanickingArchive {
        fn identity(&self) -> String {
            self.inner.identity()
        }
        async fn publish(&self, segment: &kasumi_store::PreparedAuditSegment) -> Result<()> {
            self.inner.publish(segment).await?;
            self.entered.notify_one();
            self.release.acquire().await?.forget();
            panic!("actual admitted archive publication panic");
        }
        async fn read(&self, link: &kasumi_types::AuditArchiveLink) -> Result<Vec<u8>> {
            self.inner.read(link).await
        }
    }

    #[tokio::test]
    async fn cancelled_maintenance_retains_publication_panic_and_unpruned_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.redb");
        let provider = Arc::new(LocalKeyProvider::new([75; 32]));
        let node = NodeStore::create_new(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let weak = Arc::downgrade(&node);
        let store =
            TenantStore::initialize_catalog_fixture(node, SECURITY_TENANT.into(), provider.clone())
                .await
                .unwrap();
        let archive = Arc::new(PanickingArchive {
            inner: kasumi_store::FilesystemAuditArchive::open(directory.path().join("archives"))
                .unwrap(),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        let audit = SecurityAudit::initialize_with_archive(
            store.clone(),
            kasumi_types::AuditRetentionBudget {
                hot_bytes: 128 << 10,
                archive_bytes: 128 << 20,
            },
            archive.clone(),
            crate::admission::NodeAdmission::new(Default::default()).unwrap(),
        )
        .unwrap();
        // Hold the actual automatic worker before admission so this regression
        // selects the explicit maintain job, not a competing background turn.
        let pause = Arc::new(crate::security_audit::retention::WorkerPause::default());
        *audit.writer.worker_pause.lock().unwrap() = Some(pause.clone());
        tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
            .await
            .unwrap();
        let mut count = 0;
        while audit.status().unwrap().position.hot_bytes < audit.writer.budget.starts_at() {
            audit.record_sync(event(count)).unwrap();
            count += 1;
        }
        let caller = tokio::spawn({
            let audit = audit.clone();
            async move { audit.maintain().await }
        });
        tokio::time::timeout(Duration::from_secs(5), archive.entered.notified())
            .await
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let mut first = Box::pin(audit.shutdown());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        pause.release.notify_one();
        archive.release.add_permits(1);
        let failure = tokio::time::timeout(Duration::from_secs(5), audit.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert_eq!(failure.issues().len(), 1);
        assert!(
            failure.issues()[0]
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        assert!(Arc::ptr_eq(
            &failure.issues()[0],
            &audit.shutdown().await.unwrap_err().issues()[0]
        ));
        drop(audit);
        drop(store);
        assert!(weak.upgrade().is_none());
        let reopened = TenantStore::open_existing_fixture(
            NodeStore::open_existing(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            SECURITY_TENANT.into(),
            provider,
        )
        .await
        .unwrap();
        assert_eq!(reopened.scan("security.audit").unwrap().len() as u64, count);
        assert!(
            reopened
                .get("security.audit.meta", b"pending")
                .unwrap()
                .is_some()
        );
        reopened.shutdown().await.unwrap();
    }
}

#[cfg(test)]
pub(super) struct RecordFault {
    pub entered: tokio::sync::oneshot::Sender<()>,
    pub release: std::sync::mpsc::Receiver<()>,
}

impl SecurityAudit {
    pub(super) fn record_terminal(
        &self,
        component: &'static str,
        id: usize,
        error: anyhow::Error,
    ) -> Arc<DrainIssue> {
        // Terminal evidence stops new admissions. Concurrent admitted owners
        // remain registered, so the failure inventory is bounded by that work.
        self.writer.work.seal();
        self.writer.wake.notify_one();
        self.writer
            .report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record(component, id, error)
    }

    pub(super) fn observe_join<T>(
        &self,
        component: &'static str,
        id: usize,
        outcome: std::result::Result<Result<T>, tokio::task::JoinError>,
    ) -> Result<T> {
        match outcome {
            Ok(result) => result,
            Err(error) => {
                Err(
                    DrainFailure::retained(self.record_terminal(component, id, error.into()))
                        .into(),
                )
            }
        }
    }

    pub(super) async fn run_owned<T, F, R>(&self, run: R) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
        R: FnOnce(AuditWork, usize) -> F + Send + 'static,
    {
        let (send, receive) = tokio::sync::oneshot::channel();
        {
            // Registration and the shutdown census share this lock. WorkFence
            // admission is checked inside it, after reaping actual outcomes.
            let mut jobs = self.writer.jobs.lock().await;
            let mut index = 0;
            while index < jobs.handles.len() {
                if jobs.handles[index].handle.is_finished() {
                    let outcome = (&mut jobs.handles[index].handle).await;
                    if let Err(error) = outcome {
                        self.record_terminal("audit job", jobs.handles[index].id, error.into());
                    }
                    jobs.handles.swap_remove(index);
                } else {
                    index += 1;
                }
            }
            let work = self.begin()?;
            let reservation = self.writer.admission.reserve(4096, None)?;
            let id = jobs.next;
            jobs.next = id.checked_add(1).context("audit job identity exhausted")?;
            // No await between dispatch and retained registration. The caller
            // only awaits the reply; abandoning it never cancels accepted work.
            jobs.handles.push(Job {
                id,
                handle: tokio::spawn(async move {
                    let outcome = run(work, id).await;
                    let _ = send.send(outcome);
                }),
                _reservation: reservation,
            });
        }
        receive.await.context("audit job stopped before replying")?
    }

    pub(super) async fn drain_jobs(&self) {
        let mut jobs = self.writer.jobs.lock().await;
        while let Some(job) = jobs.handles.last_mut() {
            let id = job.id;
            if let Err(error) = (&mut job.handle).await {
                self.record_terminal("audit job", id, error.into());
            }
            // Record before another await; a cancelled waiter keeps both the
            // completed failure and every remaining exact task in their owner.
            jobs.handles.pop();
        }
    }
}
