//! Separately protected, durable service records shared by embedded and network APIs.
use crate::admission::{WorkFence, WorkRegistration};
use anyhow::{Context, Result, ensure};
use kasumi_query::QueryCancellation;
use kasumi_store::{TenantStore, WriteOp};
use kasumi_types::AuditRetentionBudget;
#[path = "security_audit_jobs.rs"]
mod jobs;
#[path = "security_audit_retention.rs"]
mod retention;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SECURITY_TENANT: &str = "__kasumi_security";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    NodeStarted,
    NodeStopping,
    AuthenticationSucceeded,
    AuthenticationDenied,
    TransportAuthenticated,
    TransportDenied,
    AccessDenied,
    TenantSealed,
    KeyAdministration,
    Administration,
    Membership,
    Backup,
    Restore,
    ControlCommitmentObserved {
        control_incarnation: String,
        command_id: String,
        commitment_sha256: String,
        control_policy_epoch: u64,
        committed_revision: u64,
    },
    RetirementObserved {
        source_incarnation: String,
        retirement_id: String,
        request_digest: String,
        source_revision: u64,
        custody_policy_epoch: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityOutcome {
    Succeeded,
    Denied,
    Failed,
    Started,
    Unknown,
}

/// Closed metadata fields cannot carry document bodies, query values or tokens.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub kind: SecurityEventKind,
    pub principal: Option<String>,
    pub tenant: Option<String>,
    pub request_id: String,
    pub outcome: SecurityOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportAuditMetadata {
    pub peer_address: SocketAddr,
    pub certificate_pin: Option<String>,
    pub observed_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSecurityEvent {
    format: u32,
    sequence: u64,
    timestamp_ms: u64,
    event: SecurityEvent,
    transport: Option<TransportAuditMetadata>,
}

/// Share one writer across all databases and authentication adapters on a node.
/// Its reserved store must use a wrapping key distinct from customer tenants.
#[derive(Clone)]
pub struct SecurityAudit {
    writer: Arc<AuditWriter>,
}

struct AuditWriter {
    // Store ownership belongs to this shared inner object, including value
    // clones held by blocking jobs after every outer Arc<SecurityAudit> drops.
    store: Arc<TenantStore>,
    sequence: Mutex<AuditSequence>,
    budget: AuditRetentionBudget,
    destination: Arc<dyn kasumi_store::AuditArchiveDestination>,
    maintenance: tokio::sync::Mutex<()>,
    wake: Arc<tokio::sync::Notify>,
    worker: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    jobs: tokio::sync::Mutex<jobs::Jobs>,
    report: Mutex<kasumi_types::drain::DrainReport>,
    #[cfg(test)]
    worker_pause: Mutex<Option<Arc<retention::WorkerPause>>>,
    #[cfg(test)]
    record_fault: Mutex<Option<jobs::RecordFault>>,
    workspace: Mutex<Option<crate::admission::Reservation>>,
    admission: Arc<crate::admission::NodeAdmission>,
    work: Arc<WorkFence>,
}

static LIVE_WRITERS: LazyLock<Mutex<HashMap<usize, Weak<AuditWriter>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct AuditSequence {
    head: retention::Head,
    failed: bool,
    failures: u64,
    last_failure: Option<String>,
}

// Keep resource ownership before the registration: draining must not finish
// before a cancelled async caller's blocking job releases its store and counter.
struct AuditWork {
    writer: SecurityAudit,
    _registration: WorkRegistration,
}
impl AuditWork {
    fn record(self, event: SecurityEvent, transport: Option<TransportAuditMetadata>) -> Result<()> {
        self.writer.record_inner(event, transport)
    }
}

#[derive(Clone, Copy)]
enum AuditOpen {
    Initialize,
    Existing,
}

impl SecurityAudit {
    /// Create the canonical stream exactly once at explicit installation time.
    /// The caller must own a newly provisioned security domain and its node.
    pub fn initialize(
        store: Arc<TenantStore>,
        budget: AuditRetentionBudget,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        let root = store.durable_directory()?.join("audit-archives");
        let destination = Arc::new(kasumi_store::FilesystemAuditArchive::open(
            root,
            store.persistent_disk().clone(),
        )?);
        Self::initialize_with_archive(store, budget, destination, admission)
    }

    pub fn initialize_with_archive(
        store: Arc<TenantStore>,
        budget: AuditRetentionBudget,
        destination: Arc<dyn kasumi_store::AuditArchiveDestination>,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(store, budget, destination, admission, AuditOpen::Initialize)
    }

    /// The default archive is beneath the durable data directory. Embedded
    /// backends without a directory must install an explicit durable destination.
    pub fn open(
        store: Arc<TenantStore>,
        budget: AuditRetentionBudget,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        let root = store.durable_directory()?.join("audit-archives");
        let destination = Arc::new(kasumi_store::FilesystemAuditArchive::open(
            root,
            store.persistent_disk().clone(),
        )?);
        Self::open_with_archive(store, budget, destination, admission)
    }

    pub fn open_with_archive(
        store: Arc<TenantStore>,
        budget: AuditRetentionBudget,
        destination: Arc<dyn kasumi_store::AuditArchiveDestination>,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(store, budget, destination, admission, AuditOpen::Existing)
    }

    fn open_inner(
        store: Arc<TenantStore>,
        budget: AuditRetentionBudget,
        destination: Arc<dyn kasumi_store::AuditArchiveDestination>,
        admission: Arc<crate::admission::NodeAdmission>,
        mode: AuditOpen,
    ) -> Result<Arc<Self>> {
        budget.validate()?;
        ensure!(
            store.tenant() == SECURITY_TENANT,
            "invalid service audit store"
        );
        store.check_access()?;
        let runtime = tokio::runtime::Handle::try_current()
            .context("audit maintenance requires a running runtime")?;
        let mut writers = LIVE_WRITERS
            .lock()
            .map_err(|_| anyhow::anyhow!("service audit ownership unavailable"))?;
        writers.retain(|_, writer| writer.strong_count() > 0);
        let identity = Arc::as_ptr(&store) as usize;
        if let Some(writer) = writers.get(&identity).and_then(Weak::upgrade) {
            ensure!(
                matches!(mode, AuditOpen::Existing),
                "service audit already has an installed writer"
            );
            ensure!(
                writer.budget == budget
                    && writer.destination.identity() == destination.identity()
                    && Arc::ptr_eq(&writer.admission, &admission),
                "live service audit retention configuration or node governor differs"
            );
            {
                // Keep the writer's reserved maintenance workspace alive while
                // the strict retained-head observation reads bounded records.
                let _registration = writer.work.begin(QueryCancellation::default())?;
                let current = writer
                    .sequence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("service audit state unavailable"))?;
                let head = retention::Head::open(&store, &destination.identity(), &budget)?;
                ensure!(
                    !current.failed && head == current.head,
                    "live service audit head differs from durable state"
                );
            }
            return Ok(Arc::new(Self { writer }));
        }
        let mut workspace = admission.reserve(AuditRetentionBudget::MAINTENANCE_BYTES, None)?;
        workspace.retain_workspace();
        let head = match mode {
            AuditOpen::Initialize => retention::Head::initialize(&store, &destination.identity())?,
            AuditOpen::Existing => retention::Head::open(&store, &destination.identity(), &budget)?,
        };
        let writer = Arc::new(AuditWriter {
            store,
            sequence: Mutex::new(AuditSequence {
                head,
                failed: false,
                failures: 0,
                last_failure: None,
            }),
            budget,
            destination,
            maintenance: tokio::sync::Mutex::new(()),
            wake: Arc::new(tokio::sync::Notify::new()),
            worker: tokio::sync::Mutex::new(None),
            jobs: tokio::sync::Mutex::new(jobs::Jobs::default()),
            report: Mutex::new(kasumi_types::drain::DrainReport::default()),
            #[cfg(test)]
            worker_pause: Mutex::new(None),
            #[cfg(test)]
            record_fault: Mutex::new(None),
            work: Arc::new(WorkFence::default()),
            workspace: Mutex::new(Some(workspace)),
            admission,
        });
        // Register the worker before another open can observe this owner.
        // Its strong upgrade can precede WorkFence admission, so the work
        // counter alone cannot prove that its final storage owner has drained.
        {
            let mut worker = writer
                .worker
                .try_lock()
                .map_err(|_| anyhow::anyhow!("new audit worker ownership unavailable"))?;
            *worker = Some(retention::start_worker(&runtime, Arc::downgrade(&writer)));
        }
        writers.insert(identity, Arc::downgrade(&writer));
        Ok(Arc::new(Self { writer }))
    }

    /// The installed node governor, shared by all application and Control
    /// bootstrap/restore work using this security ledger.
    pub fn admission(&self) -> &Arc<crate::admission::NodeAdmission> {
        &self.writer.admission
    }

    pub(crate) fn require_admission(
        &self,
        admission: &Arc<crate::admission::NodeAdmission>,
    ) -> Result<()> {
        ensure!(
            Arc::ptr_eq(self.admission(), admission),
            "service audit and database node governors differ"
        );
        Ok(())
    }

    /// The caller owns the separately keyed store's configuration and lifecycle.
    pub fn store(&self) -> &Arc<TenantStore> {
        &self.writer.store
    }

    fn begin(&self) -> Result<AuditWork> {
        let registration = self
            .writer
            .work
            .begin(QueryCancellation::default())
            .map_err(|_| anyhow::anyhow!("service audit writer is shutting down"))?;
        Ok(AuditWork {
            writer: self.clone(),
            _registration: registration,
        })
    }

    pub async fn record(&self, event: SecurityEvent) -> Result<()> {
        self.record_transport(event, None).await
    }

    /// Register before spawning so queued jobs remain drainable after cancellation.
    pub async fn record_transport(
        &self,
        event: SecurityEvent,
        transport: Option<TransportAuditMetadata>,
    ) -> Result<()> {
        self.run_owned(move |work, id| async move {
            let owner = work.writer.clone();
            let outcome = tokio::task::spawn_blocking(move || work.record(event, transport)).await;
            owner.observe_join("audit record", id, outcome)
        })
        .await
    }

    /// Blocking entry for an engine-owned, independently tracked request job.
    /// This writer also tracks its own record until durable persistence finishes.
    pub fn record_sync(&self, event: SecurityEvent) -> Result<()> {
        self.begin()?.record(event, None)
    }

    fn record_inner(
        &self,
        event: SecurityEvent,
        transport: Option<TransportAuditMetadata>,
    ) -> Result<()> {
        #[cfg(test)]
        if let Some(fault) = self.writer.record_fault.lock().unwrap().take() {
            fault.entered.send(()).unwrap();
            fault
                .release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            panic!("injected real blocking audit record panic");
        }
        for value in [
            event.principal.as_deref(),
            event.tenant.as_deref(),
            Some(&event.request_id),
        ]
        .into_iter()
        .flatten()
        {
            kasumi_types::validate_name(value)?;
        }
        if let SecurityEventKind::ControlCommitmentObserved {
            control_incarnation,
            command_id,
            commitment_sha256,
            committed_revision,
            ..
        } = &event.kind
        {
            ensure!(
                !uuid::Uuid::parse_str(control_incarnation)?.is_nil()
                    && !uuid::Uuid::parse_str(command_id)?.is_nil()
                    && *committed_revision > 0,
                "invalid control observation identity"
            );
            kasumi_types::validate_sha256(commitment_sha256)?;
        }
        if let SecurityEventKind::RetirementObserved {
            source_incarnation,
            retirement_id,
            request_digest,
            source_revision,
            custody_policy_epoch,
        } = &event.kind
        {
            kasumi_types::validate_name(source_incarnation)?;
            kasumi_types::validate_name(retirement_id)?;
            kasumi_types::validate_sha256(request_digest)?;
            ensure!(
                *source_revision > 0 && *custody_policy_epoch > 0,
                "invalid retirement observation position"
            );
        }
        if let Some(pin) = transport
            .as_ref()
            .and_then(|metadata| metadata.certificate_pin.as_ref())
        {
            ensure!(
                pin.len() == 64
                    && pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid transport audit certificate pin"
            );
        }
        let mut sequence = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("service audit state unavailable"))?;
        ensure!(
            !sequence.failed,
            "service audit persistence requires recovery"
        );
        let timestamp_ms =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let entry = StoredSecurityEvent {
            format: 1,
            sequence: sequence.head.position.next_sequence,
            timestamp_ms,
            event,
            transport,
        };
        let encoded = serde_json::to_vec(&entry)?;
        ensure!(
            encoded.len() <= kasumi_types::MAX_AUDIT_EVENT_BYTES,
            "security audit event exceeds record limit"
        );
        let mut updated = sequence.head.clone();
        updated.position.next_sequence = updated
            .position
            .next_sequence
            .checked_add(1)
            .context("service audit sequence overflow")?;
        updated.position.hot_bytes = updated
            .position
            .hot_bytes
            .checked_add(encoded.len() as u64 + 8)
            .context("service audit byte count overflow")?;
        ensure!(
            updated.position.hot_bytes <= self.writer.budget.hot_bytes,
            "service audit hot budget exhausted; archive maintenance is pending"
        );
        if let Err(error) = self.writer.store.write_batch(&[
            WriteOp::put(
                "security.audit",
                sequence.head.position.next_sequence.to_be_bytes(),
                encoded,
            ),
            updated.write()?,
        ]) {
            // Unknown fsync outcomes fence every queued writer until reopen.
            sequence.failed = true;
            return Err(
                kasumi_types::drain::DrainFailure::retained(self.record_terminal(
                    "audit persistence",
                    0,
                    error,
                ))
                .into(),
            );
        }
        sequence.head = updated;
        if sequence.head.position.hot_bytes >= self.writer.budget.starts_at() {
            self.writer.wake.notify_one();
        }
        Ok(())
    }

    /// Wait for previously admitted audit work; concurrent callers may still enqueue.
    pub async fn drain(&self) {
        self.writer.work.drain().await;
    }

    /// Close audit admission immediately. Explicit shutdown additionally drains
    /// any writes that already hold the store before stopping its key monitors.
    pub fn seal(&self) {
        self.writer.work.seal();
        self.writer.store.seal();
    }

    /// Called once all databases/listeners sharing the writer have stopped.
    /// Cancellation leaves the fence closed and permits a later call to finish.
    pub async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        self.writer.work.seal();
        self.writer.wake.notify_one();
        {
            let mut worker = self.writer.worker.lock().await;
            if let Some(task) = worker.as_mut() {
                // Keep the handle in place across await: cancellation must not
                // detach the worker or allow a repeated shutdown to skip it.
                // Do not abort an admitted archive publication.
                if let Err(error) = task.await {
                    self.record_terminal("audit archive worker", 0, error.into());
                }
                worker.take();
            }
        }
        self.drain_jobs().await;
        self.writer.work.drain().await;
        let store = self.writer.store.shutdown().await;
        let mut report = self.writer.report.lock().unwrap_or_else(|p| p.into_inner());
        let retained = store.err().and_then(|failure| {
            report.merge(&failure);
            (failure.completion() == kasumi_types::drain::DrainCompletion::Retained)
                .then_some(failure)
        });
        // Retained closed handles cannot perform more work. Release the node's
        // maintenance reservation only after every actual store owner drains.
        if retained.is_none() {
            self.writer
                .workspace
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }
        report.outcome(retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
    use std::{future::Future, task::Poll};

    fn audit_destination(store: &TenantStore) -> String {
        use kasumi_store::AuditArchiveDestination;
        kasumi_store::FilesystemAuditArchive::open_fixture(
            store.durable_directory().unwrap().join("audit-archives"),
        )
        .unwrap()
        .identity()
    }

    fn event() -> SecurityEvent {
        SecurityEvent {
            kind: SecurityEventKind::AccessDenied,
            principal: Some("principal".into()),
            tenant: Some("tenant-a".into()),
            request_id: "cancelled-denial".into(),
            outcome: SecurityOutcome::Denied,
        }
    }

    #[tokio::test]
    async fn archive_worker_before_registration_is_joined_through_cancelled_shutdown_and_reopen() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("worker-security.redb");
        let node = NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let weak_node = Arc::downgrade(&node);
        let provider = Arc::new(LocalKeyProvider::new([89; 32]));
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
        let audit =
            SecurityAudit::initialize(store.clone(), AuditRetentionBudget::default(), admission)
                .unwrap();
        audit.record_sync(event()).unwrap();
        let pause = Arc::new(retention::WorkerPause::default());
        *audit.writer.worker_pause.lock().unwrap() = Some(pause.clone());
        // This current-thread fixture installs its gate before the new worker
        // can first run. Pause after its strong upgrade and before registration.
        pause.entered.notified().await;
        assert!(Arc::strong_count(&audit.writer) >= 2);
        audit.writer.work.drain().await;
        // Drain key monitors first to isolate the missing worker ownership from
        // unrelated asynchronous store shutdown. No timing sleep drives this race.
        store.shutdown().await.unwrap();

        let mut shutdown = Box::pin(audit.shutdown());
        std::future::poll_fn(|cx| {
            assert!(
                shutdown.as_mut().poll(cx).is_pending(),
                "zero registered work cannot release the paused archive worker"
            );
            Poll::Ready(())
        })
        .await;
        drop(shutdown);
        let mut repeated = Box::pin(audit.shutdown());
        std::future::poll_fn(|cx| {
            assert!(
                repeated.as_mut().poll(cx).is_pending(),
                "cancelled shutdown must retain the same worker join"
            );
            Poll::Ready(())
        })
        .await;
        pause.release.notify_one();
        repeated.await.unwrap();
        assert!(audit.writer.worker.lock().await.is_none());
        drop(audit);
        drop(store);
        drop(node);
        assert!(weak_node.upgrade().is_none());

        let reopened = TenantStore::open_existing_fixture(
            NodeStore::open_existing_fixture(
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
        assert_eq!(reopened.scan("security.audit").unwrap().len(), 1);
        assert_eq!(
            retention::Head::open(
                &reopened,
                &audit_destination(&reopened),
                &AuditRetentionBudget::default()
            )
            .unwrap()
            .position
            .next_sequence,
            1
        );
        reopened.shutdown().await.unwrap();
    }

    #[test]
    fn cancelled_queued_audit_and_cancelled_shutdown_drain_before_immediate_reopen() {
        // Occupy the only blocking worker so the real record task is definitely
        // queued when its caller is cancelled. No timing sleep controls the race.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = kasumi_store::test_utils::private_tempdir().unwrap();
            let path = directory.path().join("security.redb");
            let node = NodeStore::create_new_fixture(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap();
            let weak_node = Arc::downgrade(&node);
            let provider = Arc::new(LocalKeyProvider::new([83; 32]));
            let store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                SECURITY_TENANT.into(),
                provider.clone(),
            )
            .await
            .unwrap();
            let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
            let audit = SecurityAudit::initialize(
                store.clone(),
                kasumi_types::AuditRetentionBudget::default(),
                admission.clone(),
            )
            .unwrap();
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, paused) = std::sync::mpsc::sync_channel(1);
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                paused.recv().unwrap();
            });
            started.await.unwrap();

            let mut recording = Box::pin(audit.record(event()));
            std::future::poll_fn(|cx| {
                assert!(recording.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(recording);

            // The queued job holds a value clone, not the original outer Arc.
            // Reopening must find that clone's live inner writer and drain it.
            let writer = Arc::downgrade(&audit.writer);
            drop(audit);
            let audit = SecurityAudit::open(
                store.clone(),
                kasumi_types::AuditRetentionBudget::default(),
                admission.clone(),
            )
            .unwrap();
            assert!(Arc::ptr_eq(&writer.upgrade().unwrap(), &audit.writer));

            let mut shutdown = Box::pin(audit.shutdown());
            std::future::poll_fn(|cx| {
                assert!(shutdown.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            // Shutdown must wait for the admitted audit before sealing its keys.
            store.check_access().unwrap();
            assert!(audit.record_sync(event()).is_err());
            drop(shutdown);
            let mut repeated = Box::pin(audit.shutdown());
            std::future::poll_fn(|cx| {
                assert!(repeated.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            release.send(()).unwrap();
            repeated.await.unwrap();
            blocker.await.unwrap();
            assert!(store.check_access().is_err());
            drop(audit);
            drop(store);
            drop(node);
            assert!(weak_node.upgrade().is_none());

            let reopened = TenantStore::open_existing_fixture(
                NodeStore::open_existing_fixture(
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
            let records = reopened.scan("security.audit").unwrap();
            assert_eq!(records.len(), 1);
            let record: serde_json::Value = serde_json::from_slice(&records[0].1).unwrap();
            assert_eq!(record["event"]["kind"], "access_denied");
            assert_eq!(record["event"]["request_id"], "cancelled-denial");
            assert_eq!(
                retention::Head::open(
                    &reopened,
                    &audit_destination(&reopened),
                    &AuditRetentionBudget::default()
                )
                .unwrap()
                .position
                .next_sequence,
                1
            );
            reopened.shutdown().await.unwrap();
        });
    }

    #[tokio::test]
    async fn live_opens_share_sequence_and_preserve_concurrent_records_through_reopen() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("shared-security.redb");
        let node = NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let weak_node = Arc::downgrade(&node);
        let provider = Arc::new(LocalKeyProvider::new([85; 32]));
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
        let first = SecurityAudit::initialize(
            store.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            admission.clone(),
        )
        .unwrap();
        let second = SecurityAudit::open(
            store.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            admission.clone(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&first.writer, &second.writer));
        assert!(
            SecurityAudit::open(
                store.clone(),
                kasumi_types::AuditRetentionBudget {
                    hot_bytes: 65 << 20,
                    ..Default::default()
                },
                admission.clone()
            )
            .is_err()
        );
        let mut other = event();
        other.request_id = "concurrent-denial".into();
        let (one, two) = tokio::join!(first.record(event()), second.record(other));
        one.unwrap();
        two.unwrap();
        // A cloned value must preserve the ownership claim independently of
        // both Arc handles returned by open.
        let retained = (*first).clone();
        drop(first);
        drop(second);
        let third = SecurityAudit::open(
            store.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            admission.clone(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&retained.writer, &third.writer));
        let mut other = event();
        other.request_id = "third-denial".into();
        third.record(other).await.unwrap();
        third.shutdown().await.unwrap();
        drop(retained);
        drop(third);
        drop(store);
        drop(node);
        assert!(weak_node.upgrade().is_none());

        let reopened = TenantStore::open_existing_fixture(
            NodeStore::open_existing_fixture(
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
        let records = reopened.scan("security.audit").unwrap();
        assert_eq!(records.len(), 3);
        let mut identities = std::collections::BTreeSet::new();
        for (sequence, (_, bytes)) in records.into_iter().enumerate() {
            let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(record["sequence"], sequence);
            identities.insert(record["event"]["request_id"].as_str().unwrap().to_owned());
        }
        assert_eq!(
            identities,
            std::collections::BTreeSet::from([
                "cancelled-denial".to_owned(),
                "concurrent-denial".to_owned(),
                "third-denial".to_owned()
            ])
        );
        assert_eq!(
            retention::Head::open(
                &reopened,
                &audit_destination(&reopened),
                &AuditRetentionBudget::default()
            )
            .unwrap()
            .position
            .next_sequence,
            3
        );
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn uncertain_audit_commit_fences_queued_writers_until_sequence_recovery() {
        use kasumi_store::test_utils::{FaultBackend, ManualClock};
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let archive = Arc::new(
            kasumi_store::FilesystemAuditArchive::open_fixture(directory.path().join("archive"))
                .unwrap(),
        );
        let admission = crate::admission::NodeAdmission::process_default();
        let disk = FaultBackend::new();
        let clock = Arc::new(ManualClock::new());
        let provider = Arc::new(LocalKeyProvider::new([84; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::open_with_backend(
                disk.clone(),
                kasumi_store::test_utils::storage_admission(),
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            SECURITY_TENANT.into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::initialize_with_archive(
            store.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            archive.clone(),
            admission.clone(),
        )
        .unwrap();
        let queued = audit.begin().unwrap();
        disk.advance_clock_on_next_sync(clock.clone(), std::time::Duration::from_secs(60));
        let error = audit.record_sync(event()).unwrap_err();
        assert!(error.to_string().contains("outcome unknown"));
        // Even explicit key reauthorization cannot reuse the uncertain counter.
        store.refresh_lease().await.unwrap();
        assert!(
            SecurityAudit::open_with_archive(
                store.clone(),
                kasumi_types::AuditRetentionBudget::default(),
                archive.clone(),
                admission.clone(),
            )
            .is_err()
        );
        assert!(queued.record(event(), None).is_err());
        assert!(audit.record_sync(event()).is_err());
        assert_eq!(store.scan("security.audit").unwrap().len(), 1);

        let recovered = TenantStore::open_existing_fixture_with_clock(
            NodeStore::open_with_backend(
                disk.crash(),
                kasumi_store::test_utils::storage_admission(),
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            SECURITY_TENANT.into(),
            provider,
            clock,
        )
        .await
        .unwrap();
        let reopened = SecurityAudit::open_with_archive(
            recovered.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            archive.clone(),
            admission,
        )
        .unwrap();
        let mut subsequent = event();
        subsequent.request_id = "after-recovery".into();
        reopened.record(subsequent).await.unwrap();
        let records = recovered.scan("security.audit").unwrap();
        assert_eq!(records.len(), 2);
        let first: serde_json::Value = serde_json::from_slice(&records[0].1).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&records[1].1).unwrap();
        assert_eq!(first["sequence"], 0);
        assert_eq!(first["event"]["request_id"], "cancelled-denial");
        assert_eq!(second["sequence"], 1);
        assert_eq!(second["event"]["request_id"], "after-recovery");
        audit.shutdown().await.unwrap();
        reopened.shutdown().await.unwrap();
    }
}

#[cfg(test)]
#[path = "security_audit_existing_tests.rs"]
mod existing_tests;
