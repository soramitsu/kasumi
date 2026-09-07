//! Separately protected, durable service records shared by embedded and network APIs.
use crate::admission::{WorkFence, WorkRegistration};
use anyhow::{Context, Result, ensure};
use kasumi_query::QueryCancellation;
use kasumi_store::{TenantStore, WriteOp};
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

#[derive(Clone, Debug, Serialize)]
pub struct TransportAuditMetadata {
    pub peer_address: SocketAddr,
    pub certificate_pin: Option<String>,
    pub observed_at_ms: u64,
}

#[derive(Serialize)]
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
    max_records: u64,
    work: Arc<WorkFence>,
}

static LIVE_WRITERS: LazyLock<Mutex<HashMap<usize, Weak<AuditWriter>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct AuditSequence {
    next: u64,
    failed: bool,
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

impl SecurityAudit {
    /// Repeated opens of the same live store share its sequence and shutdown
    /// fence. Changing its retention limit requires closing the existing writer.
    pub fn open(store: Arc<TenantStore>, max_records: u64) -> Result<Arc<Self>> {
        ensure!(
            max_records > 0 && store.tenant() == SECURITY_TENANT,
            "invalid service audit store"
        );
        store.check_access()?;
        let mut writers = LIVE_WRITERS
            .lock()
            .map_err(|_| anyhow::anyhow!("service audit ownership unavailable"))?;
        writers.retain(|_, writer| writer.strong_count() > 0);
        let identity = Arc::as_ptr(&store) as usize;
        if let Some(writer) = writers.get(&identity).and_then(Weak::upgrade) {
            ensure!(
                writer.max_records == max_records,
                "live service audit retention limit differs"
            );
            return Ok(Arc::new(Self { writer }));
        }
        let next = store
            .get("security.audit.meta", b"next")?
            .map(|bytes| -> Result<u64> {
                Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
                    anyhow::anyhow!("invalid service audit sequence")
                })?))
            })
            .transpose()?
            .unwrap_or(0);
        ensure!(
            next <= max_records,
            "service audit retention quota exceeded"
        );
        let writer = Arc::new(AuditWriter {
            store,
            sequence: Mutex::new(AuditSequence {
                next,
                failed: false,
            }),
            max_records,
            work: Arc::new(WorkFence::default()),
        });
        writers.insert(identity, Arc::downgrade(&writer));
        Ok(Arc::new(Self { writer }))
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
        let work = self.begin()?;
        tokio::task::spawn_blocking(move || work.record(event, transport)).await?
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
        ensure!(
            sequence.next < self.writer.max_records,
            "service audit retention quota exhausted"
        );
        let timestamp_ms =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let entry = StoredSecurityEvent {
            format: 1,
            sequence: sequence.next,
            timestamp_ms,
            event,
            transport,
        };
        let updated = sequence
            .next
            .checked_add(1)
            .context("service audit sequence overflow")?;
        if let Err(error) = self.writer.store.write_batch(&[
            WriteOp::put(
                "security.audit",
                sequence.next.to_be_bytes(),
                serde_json::to_vec(&entry)?,
            ),
            WriteOp::put("security.audit.meta", b"next", updated.to_be_bytes()),
        ]) {
            // An fsync may have committed before a key-lease release check
            // returned an unknown outcome. Never reuse this sequence: queued
            // writers must fail too until reopening reads its durable value.
            sequence.failed = true;
            return Err(error);
        }
        sequence.next = updated;
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
    pub async fn shutdown(&self) {
        self.writer.work.seal();
        self.writer.work.drain().await;
        self.writer.store.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
    use std::{future::Future, task::Poll};

    fn event() -> SecurityEvent {
        SecurityEvent {
            kind: SecurityEventKind::AccessDenied,
            principal: Some("principal".into()),
            tenant: Some("tenant-a".into()),
            request_id: "cancelled-denial".into(),
            outcome: SecurityOutcome::Denied,
        }
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
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("security.redb");
            let node = NodeStore::open(&path).unwrap();
            let weak_node = Arc::downgrade(&node);
            let provider = Arc::new(LocalKeyProvider::new([83; 32]));
            let store =
                TenantStore::open_fixture(node.clone(), SECURITY_TENANT.into(), provider.clone())
                    .await
                    .unwrap();
            let audit = SecurityAudit::open(store.clone(), 10).unwrap();
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
            let audit = SecurityAudit::open(store.clone(), 10).unwrap();
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
            repeated.await;
            blocker.await.unwrap();
            assert!(store.check_access().is_err());
            drop(audit);
            drop(store);
            drop(node);
            assert!(weak_node.upgrade().is_none());

            let reopened = TenantStore::open_fixture(
                NodeStore::open(&path).unwrap(),
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
                reopened.get("security.audit.meta", b"next").unwrap(),
                Some(1u64.to_be_bytes().to_vec())
            );
            reopened.shutdown().await;
        });
    }

    #[tokio::test]
    async fn live_opens_share_sequence_and_preserve_concurrent_records_through_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared-security.redb");
        let node = NodeStore::open(&path).unwrap();
        let weak_node = Arc::downgrade(&node);
        let provider = Arc::new(LocalKeyProvider::new([85; 32]));
        let store =
            TenantStore::open_fixture(node.clone(), SECURITY_TENANT.into(), provider.clone())
                .await
                .unwrap();
        let first = SecurityAudit::open(store.clone(), 10).unwrap();
        let second = SecurityAudit::open(store.clone(), 10).unwrap();
        assert!(Arc::ptr_eq(&first.writer, &second.writer));
        assert!(SecurityAudit::open(store.clone(), 11).is_err());
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
        let third = SecurityAudit::open(store.clone(), 10).unwrap();
        assert!(Arc::ptr_eq(&retained.writer, &third.writer));
        let mut other = event();
        other.request_id = "third-denial".into();
        third.record(other).await.unwrap();
        third.shutdown().await;
        drop(retained);
        drop(third);
        drop(store);
        drop(node);
        assert!(weak_node.upgrade().is_none());

        let reopened = TenantStore::open_fixture(
            NodeStore::open(&path).unwrap(),
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
            reopened.get("security.audit.meta", b"next").unwrap(),
            Some(3u64.to_be_bytes().to_vec())
        );
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn uncertain_audit_commit_fences_queued_writers_until_sequence_recovery() {
        use kasumi_store::test_utils::{FaultBackend, ManualClock};
        let disk = FaultBackend::new();
        let clock = Arc::new(ManualClock::new());
        let provider = Arc::new(LocalKeyProvider::new([84; 32]));
        let store = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(disk.clone()).unwrap(),
            SECURITY_TENANT.into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(store.clone(), 10).unwrap();
        let queued = audit.begin().unwrap();
        disk.advance_clock_on_next_sync(clock.clone(), std::time::Duration::from_secs(60));
        let error = audit.record_sync(event()).unwrap_err();
        assert!(error.to_string().contains("outcome unknown"));
        // Even explicit key reauthorization cannot reuse the uncertain counter.
        store.refresh_lease().await.unwrap();
        let duplicate = SecurityAudit::open(store.clone(), 10).unwrap();
        assert!(duplicate.record_sync(event()).is_err());
        assert!(queued.record(event(), None).is_err());
        assert!(audit.record_sync(event()).is_err());
        assert_eq!(store.scan("security.audit").unwrap().len(), 1);

        let recovered = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(disk.crash()).unwrap(),
            SECURITY_TENANT.into(),
            provider,
            clock,
        )
        .await
        .unwrap();
        let reopened = SecurityAudit::open(recovered.clone(), 10).unwrap();
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
        audit.shutdown().await;
        reopened.shutdown().await;
    }
}
