use super::*;

// The actual blocking preparation retains every owner even if its async caller
// disappears. The proposal keeps its separate lane through the Raft outcome.
pub(super) struct Prepared {
    bytes: Option<Vec<u8>>,
    _engine: Arc<TenantEngine>,
    _pool: Arc<crate::audit_maintenance::NodeAuditMaintenance>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _registration: Arc<WorkRegistration>,
}

#[cfg(test)]
pub(super) struct WorkerPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
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
        let wake = self.audit_worker_wake.clone();
        let mut stop = self.background_stop.subscribe();
        let mut exit = BackgroundWorkerExit {
            database: weak.clone(),
            completed: false,
        };
        let task = tokio::spawn(async move {
            let result = async {
                loop {
                    if *stop.borrow() {
                        return Ok(());
                    }
                    tokio::select! {
                        _ = stop.changed() => return Ok(()),
                        _ = wake.notified() => {},
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {},
                    }
                    let Some(database) = weak.upgrade() else {
                        return Ok(());
                    };
                    #[cfg(test)]
                    {
                        let pause = database.audit_worker_pause.lock().unwrap().take();
                        if let Some(pause) = pause {
                            pause.entered.notify_one();
                            pause.release.notified().await;
                        }
                    }
                    if database.closing.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let metrics = database.group.raft().metrics().borrow().clone();
                    if metrics.current_leader != Some(metrics.id) {
                        continue;
                    }
                    let Ok(registration) = database.work.begin(QueryCancellation::default()) else {
                        return Ok(());
                    };
                    let registration = Arc::new(registration);
                    match database.maintain_tenant_audit(registration).await {
                        Ok(true) => {
                            database
                                .audit_worker_completed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(error) => {
                            database
                                .audit_worker_failures
                                .fetch_add(1, Ordering::Relaxed);
                            // Archive connectivity and proposal errors remain
                            // retryable. An actual blocking worker panic/abort is a
                            // terminal failure, retained intact in this task result.
                            if let Ok(failure) = error.downcast::<DrainFailure>() {
                                return Err(failure);
                            }
                        }
                    }
                }
            }
            .await;
            exit.complete(&result);
            result
        });
        *self
            .audit_worker
            .try_lock()
            .expect("new tenant audit worker") = Some(task);
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
        let mut stop = self.background_stop.subscribe();
        if *stop.borrow() {
            return Ok(false);
        }
        // No work has been dispatched while these capacities are awaited.
        // Stop must release this registration even when another database owns
        // the shared preparation permit in an abandoned completed child.
        let _serial = tokio::select! {
            biased;
            _ = stop.changed() => return Ok(false),
            guard = self.proposal_gate.clone().lock_owned() => guard,
        };
        #[cfg(test)]
        self.worker_test_hooks.waiting_preparation.notify_one();
        let permit = tokio::select! {
            biased;
            _ = stop.changed() => return Ok(false),
            permit = pool.preparation.clone().acquire_owned() => permit?,
        };
        if self.closing.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.access()?;
        let engine = self.engine.clone();
        #[cfg(test)]
        let hook = self.worker_test_hooks.audit.lock().unwrap().take();
        let mut prepared = self
            .audit_preparation
            .run(move || {
                #[cfg(test)]
                if let Some(hook) = hook {
                    hook();
                }
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
    use kasumi_store::{
        AuditArchiveDestination, FilesystemAuditArchive, NodeStore, PreparedAuditSegment,
        test_utils::LocalKeyProvider,
    };
    use std::future::Future;

    struct UncertainArchive {
        inner: FilesystemAuditArchive,
        fail: AtomicBool,
    }
    #[async_trait::async_trait]
    impl AuditArchiveDestination for UncertainArchive {
        fn identity(&self) -> String {
            self.inner.identity()
        }
        async fn publish(&self, segment: &PreparedAuditSegment) -> anyhow::Result<()> {
            self.inner.publish(segment).await?;
            anyhow::ensure!(
                !self.fail.load(Ordering::Acquire),
                "injected uncertain external publication"
            );
            Ok(())
        }
        async fn read(&self, link: &AuditArchiveLink) -> anyhow::Result<Vec<u8>> {
            self.inner.read(link).await
        }
    }

    #[tokio::test]
    async fn tenant_audit_worker_keeps_its_owner_through_cancelled_shutdown() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let directory = kasumi_store::test_utils::private_tempdir().unwrap();
            let path = directory.path().join("node.redb");
            let node = NodeStore::create_new_fixture(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap();
            let weak_node = Arc::downgrade(&node);
            let admission = NodeAdmission::new(Default::default()).unwrap();
            let provider = Arc::new(LocalKeyProvider::new([51; 32]));
            let store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                "tenant".into(),
                provider.clone(),
            )
            .await
            .unwrap();
            store
                .write_batch(&[kasumi_store::WriteOp::put(
                    "drain-test",
                    b"marker",
                    b"durable".to_vec(),
                )])
                .unwrap();
            let audit_store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                Arc::new(LocalKeyProvider::new([52; 32])),
            )
            .await
            .unwrap();
            let audit =
                SecurityAudit::initialize(audit_store, Default::default(), admission.clone())
                    .unwrap();
            let incarnation = uuid::Uuid::new_v4().to_string();
            let engine = Arc::new(
                TenantEngine::new(
                    "tenant".into(),
                    incarnation.clone(),
                    Policy {
                        grants: vec![Grant {
                            principal: "owner".into(),
                            collection: None,
                            actions: BTreeSet::from([Action::Read, Action::Admin]),
                        }],
                        strict_read_audit: false,
                    },
                    Limits::default(),
                )
                .unwrap(),
            );
            engine.install_storage_access(&store).unwrap();
            engine.install_audit_maintenance(&admission).unwrap();
            let stores = kasumi_store::test_utils::initialize_custody_fixture(
                store.clone(),
                Arc::new(LocalKeyProvider::new([53; 32])),
            )
            .await
            .unwrap();
            let group = RaftGroup::local(
                1,
                format!("tenant/{incarnation}"),
                stores,
                engine.clone(),
                kasumi_raft::SnapshotBufferOwner::fixture(),
            )
            .await
            .unwrap();
            let database = Database::new(engine, group, store.clone(), audit.clone());
            let weak_database = Arc::downgrade(&database);
            let pause = Arc::new(WorkerPause {
                entered: Default::default(),
                release: Default::default(),
            });
            *database.audit_worker_pause.lock().unwrap() = Some(pause.clone());
            database.audit_worker_wake.notify_one();
            pause.entered.notified().await;
            assert!(Arc::strong_count(&database) >= 2);
            // Isolate the owner before work registration from every other monitor.
            database.work.drain().await;
            {
                let mut monitor = database.seal_monitor.lock().await;
                let task = monitor.as_mut().unwrap();
                task.abort();
                let _ = task.await;
                monitor.take();
            }
            database.group.shutdown().await.unwrap();
            store.shutdown().await.unwrap();
            let mut first = Box::pin(database.shutdown());
            std::future::poll_fn(|cx| {
                assert!(first.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert!(
                database.audit_worker.try_lock().is_err(),
                "shutdown reached the worker join"
            );
            drop(first);
            assert!(database.audit_worker.try_lock().unwrap().is_some());
            let mut retry = Box::pin(database.shutdown());
            std::future::poll_fn(|cx| {
                assert!(retry.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            pause.release.notify_one();
            retry.await.unwrap();
            assert!(database.audit_worker.try_lock().unwrap().is_none());
            audit.shutdown().await.unwrap();
            drop(database);
            assert!(weak_database.upgrade().is_none());
            drop(store);
            drop(audit);
            drop(node);
            assert!(weak_node.upgrade().is_none());
            // No delay or lock retry is allowed to hide a surviving file owner.
            let reopened = NodeStore::open_existing_fixture(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap();
            let store = TenantStore::open_existing_fixture(reopened, "tenant".into(), provider)
                .await
                .unwrap();
            assert_eq!(
                store.get("drain-test", b"marker").unwrap().unwrap(),
                b"durable"
            );
            store.shutdown().await.unwrap();
        })
        .await
        .expect("shutdown ownership fixture timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encrypted_worker_drains_hot_history_when_ordinary_capacity_is_full() {
        worker_drains_hot_history(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_archive_outage_before_proposal_preserves_hot_history_and_raft_availability() {
        worker_drains_hot_history(true).await;
    }

    async fn worker_drains_hot_history(outage: bool) {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let node = NodeStore::create_new_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let admission = NodeAdmission::new(
            crate::test_utils::admission_config_with_bookkeeping(
                crate::admission::AdmissionConfig {
                    max_inflight_bytes: Some(512 << 20),
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([41; 32])),
        )
        .await
        .unwrap();
        let archive = Arc::new(UncertainArchive {
            inner: FilesystemAuditArchive::open_fixture(directory.path().join("external")).unwrap(),
            fail: AtomicBool::new(outage),
        });
        store
            .install_tenant_audit_archive(
                Arc::new(
                    FilesystemAuditArchive::open_fixture(
                        directory.path().join("tenant-audit-archives"),
                    )
                    .unwrap(),
                ),
                archive.clone(),
            )
            .unwrap();
        let audit_store = TenantStore::initialize_catalog_fixture(
            node,
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([42; 32])),
        )
        .await
        .unwrap();
        let audit =
            SecurityAudit::initialize(audit_store, Default::default(), admission.clone()).unwrap();
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
        let stores = kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let group = RaftGroup::local(
            1,
            format!("tenant/{incarnation}"),
            stores,
            engine.clone(),
            kasumi_raft::SnapshotBufferOwner::fixture(),
        )
        .await
        .unwrap();
        let database = Database::new(engine.clone(), group.clone(), store, audit.clone());
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
                    data_revision: Some(engine.generation().unwrap().state.revision),
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
            .reserve(
                (512 << 20) - crate::test_utils::reserved_payload_bytes(&admission),
                None,
            )
            .unwrap();
        assert!(admission.reserve(1, None).is_err());
        let before = engine.generation().unwrap();
        drop(pause);
        if outage {
            tokio::time::timeout(Duration::from_secs(10), async {
                while database.audit_maintenance_status().unwrap().failures == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let current = engine.generation().unwrap();
            assert_eq!(current.state.audit_retention, before.state.audit_retention);
            assert_eq!(current.state.revision, before.state.revision);
            group.check_access().unwrap();
            assert_eq!(
                group.linearizable_barrier().await.unwrap().unwrap().index,
                before.state.revision
            );
            archive.fail.store(false, Ordering::Release);
            database.audit_worker_wake.notify_one();
        }
        drop(before);
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
        assert_eq!(status.failures > 0, outage);
        assert!(status.committed_segments > 0);
        drop(current);
        drop(ordinary);
        drop(pool);
        database.shutdown().await.unwrap();
        audit.shutdown().await.unwrap();
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);
    }
}
