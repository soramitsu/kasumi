use super::*;

// The actual blocking preparation retains every owner even if its async caller
// disappears. The proposal keeps its separate lane through the Raft outcome.
struct Prepared {
    bytes: Option<Vec<u8>>,
    _engine: Arc<TenantEngine>,
    _pool: Arc<crate::audit_maintenance::NodeAuditMaintenance>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _registration: Arc<WorkRegistration>,
}

impl Database {
    pub(crate) fn start_audit_worker(self: &Arc<Self>) {
        if self
            .engine
            .audit_maintenance
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
        {
            return;
        }
        self.audit_worker_started.store(true, Ordering::Release);
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let Some(database) = weak.upgrade() else {
                    return;
                };
                if database.closing.load(Ordering::Acquire) {
                    return;
                }
                let metrics = database.group.raft().metrics().borrow().clone();
                if metrics.current_leader != Some(metrics.id) {
                    continue;
                }
                let Ok(registration) = database.work.begin(QueryCancellation::default()) else {
                    return;
                };
                let registration = Arc::new(registration);
                match database.maintain_tenant_audit(registration).await {
                    Ok(true) => {
                        database
                            .audit_worker_completed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {}
                    Err(_) => {
                        database
                            .audit_worker_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        *self.audit_worker.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
    }

    async fn maintain_tenant_audit(
        &self,
        registration: Arc<WorkRegistration>,
    ) -> anyhow::Result<bool> {
        let pool = self
            .engine
            .audit_maintenance
            .lock()
            .map_err(|_| anyhow::anyhow!("audit maintenance ownership unavailable"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("audit maintenance not installed"))?;
        let _serial = self.proposal_gate.clone().lock_owned().await;
        let permit = pool.preparation.clone().acquire_owned().await?;
        if self.closing.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.access()?;
        let engine = self.engine.clone();
        let mut prepared = tokio::task::spawn_blocking(move || {
            let bytes = engine.prepare_audit_prune_inner()?;
            Ok::<_, anyhow::Error>(Prepared {
                bytes,
                _engine: engine,
                _pool: pool,
                _permit: permit,
                _registration: registration,
            })
        })
        .await??;
        let Some(bytes) = prepared.bytes.take() else {
            return Ok(false);
        };
        // Shutdown drains this task and the separately owned Raft materializer;
        // it never aborts a proposal just because an API request disappeared.
        let bytes = self.group.write(bytes).await?;
        let outcome: Result<()> = serde_json::from_slice(&bytes)?;
        outcome?;
        Ok(true)
    }

    /// None means no automatic worker was installed. These are process counters,
    /// separate from durable archive totals in the authenticated tenant state.
    pub fn audit_maintenance_status(&self) -> Option<crate::AuditMaintenanceStatus> {
        self.audit_worker_started
            .load(Ordering::Acquire)
            .then(|| crate::AuditMaintenanceStatus {
                failures: self.audit_worker_failures.load(Ordering::Relaxed),
                committed_segments: self.audit_worker_completed.load(Ordering::Relaxed),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encrypted_worker_drains_hot_history_when_ordinary_capacity_is_full() {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
        let admission = NodeAdmission::new(crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(512 << 20),
            ..Default::default()
        })
        .unwrap();
        let store = TenantStore::open_fixture(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([41; 32])),
        )
        .await
        .unwrap();
        let audit_store = TenantStore::open_fixture(
            node,
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([42; 32])),
        )
        .await
        .unwrap();
        let audit =
            SecurityAudit::open(audit_store, Default::default(), admission.clone()).unwrap();
        let policy = Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Read, Action::Admin]),
            }],
            strict_read_audit: false,
        };
        let incarnation = uuid::Uuid::new_v4().to_string();
        let engine = Arc::new(
            TenantEngine::new(
                "tenant".into(),
                incarnation.clone(),
                policy,
                Limits {
                    audit_retention: AuditRetentionBudget {
                        hot_bytes: 128 << 10,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        engine.install_storage_access(&store).unwrap();
        engine.install_audit_maintenance(&admission).unwrap();
        let pool = engine.audit_maintenance.lock().unwrap().clone().unwrap();
        let pause = pool.preparation.clone().acquire_owned().await.unwrap();
        let stores = kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let group = RaftGroup::local(1, format!("tenant/{incarnation}"), stores, engine.clone())
            .await
            .unwrap();
        let database = Database::new_with_admission(
            engine.clone(),
            group.clone(),
            store,
            admission.clone(),
            audit.clone(),
        );
        for number in 0..50 {
            let command = Command {
                context: RequestContext {
                    authorization: RequestAuthorization::service_identity(),
                    tenant: "tenant".into(),
                    principal: "owner".into(),
                    scopes: BTreeSet::from([Action::Read]),
                    request_id: "read".into(),
                },
                timestamp_ms: 1_000,
                operation: Operation::Audit(AuditEvent {
                    event_id: format!("{number}:{}", "x".repeat(2_000)),
                    principal: "owner".into(),
                    action: "read".into(),
                    request_id: "read".into(),
                    timestamp_ms: 1_000,
                    data_revision: None,
                    outcome: "authorized_release".into(),
                    collection: None,
                }),
            };
            let response = group
                .write(serde_json::to_vec(&command).unwrap())
                .await
                .unwrap();
            serde_json::from_slice::<Result<WriteReceipt>>(&response)
                .unwrap()
                .unwrap();
        }
        assert!(engine.generation().unwrap().state.audit_retention.hot_bytes >= 96 << 10);
        let ordinary = admission
            .reserve((512 << 20) - admission.snapshot().reserved_bytes, None)
            .unwrap();
        assert!(admission.reserve(1, None).is_err());
        drop(pause);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let current = engine.generation().unwrap();
                if current.state.audit_retention.archive_segments > 0
                    && current.state.audit_retention.hot_bytes <= 64 << 10
                    && database
                        .audit_maintenance_status()
                        .unwrap()
                        .committed_segments
                        > 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let current = engine.generation().unwrap();
        assert_eq!(current.state.audit_retention.next_sequence, 50);
        assert_eq!(
            current.state.audit_retention.pruned_before + current.state.audits.len() as u64,
            50
        );
        let status = database.audit_maintenance_status().unwrap();
        assert_eq!(status.failures, 0);
        assert!(status.committed_segments > 0);
        drop(current);
        drop(ordinary);
        drop(pool);
        database.shutdown().await.unwrap();
        audit.shutdown().await;
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
