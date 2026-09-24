use super::*;
use std::{collections::BTreeSet, future::Future, task::Poll};

#[tokio::test]
async fn target_monitor_and_outer_owner_survive_cancelled_shutdown_until_journal_reopens() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                .unwrap();
        let path = directory.path().join("persistent/target-journal.kv");
        let generation_root = directory.path().join("persistent/targets");
        let generation_directory = crate::persistent_disk::open_or_create_directory(
            &kasumi_store::NodeDisk::fixture_config(&path).unwrap(),
            &physical.persistent,
            &generation_root,
        )
        .unwrap();

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = certificate.pem().into_bytes();
        let tls =
            kasumi_transport::TlsIdentity::from_pem(&pem, key.serialize_pem().as_bytes()).unwrap();
        let identity = NodeIdentity {
            node_id: 1,
            verifier: kasumi_serving::test_utils::fixture_verifier(1),
            principal: "target-node".into(),
            certificate_sha256: hex::encode(tls.certificate_pin()),
        };
        let root = ControlSigningRoot {
            control_incarnation: Uuid::new_v4(),
            public_key: hex::encode(key.public_key_raw()),
        };
        let node_id = kasumi_store::node_store_ids::target_journal(
            root.control_incarnation,
            &identity.verifier,
        )
        .unwrap();
        let node = physical.create_new(&path, node_id).unwrap();
        let weak_node = Arc::downgrade(&node);
        let provider = Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([41; 32]));
        let journal_tenant = format!("kasumi.target.{}.1", root.control_incarnation);
        let access = StorageAccess::target_journal(&root, &identity).unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            journal_tenant.clone(),
            provider.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        let admission = physical.admission.clone();
        let journal = TargetJournal::create_new(
            store.clone(),
            TargetJournalInstallation {
                root: root.clone(),
                node: identity.clone(),
            },
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            admission.clone(),
        )
        .unwrap();
        let audit_store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([42; 32])),
        )
        .await
        .unwrap();
        let audit =
            SecurityAudit::initialize(audit_store, Default::default(), admission.clone()).unwrap();
        let cluster = ClusterNetwork::new(
            1,
            &tls,
            &pem,
            vec![crate::cluster::PeerConfig {
                node_id: 1,
                endpoint: "https://localhost:9".into(),
                certificate_pins: BTreeSet::from([tls.certificate_pin()]),
            }],
            Default::default(),
        )
        .unwrap();
        let config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        // No network or recovery operation is dispatched by this ownership fixture.
        // The actual monitor is stopped at its first upgrade, before discovery.
        let installed = TargetRecoveryConfig {
            control_root: root,
            control_endpoints: BTreeMap::from([(
                1,
                crate::serving_runtime::AuthorityEndpoint {
                    endpoint: "https://localhost:9".into(),
                    certificate_pins: BTreeSet::from(["ab".repeat(32)]),
                },
            )]),
            control_tls: config.native.tls.clone(),
            control_ca: directory.path().join("ca.pem"),
            node: identity.clone(),
            attestation_key: directory.path().join("target.pk8"),
            issuer_admin_bearer_file: BTreeMap::new(),
            journal_path: path.clone(),
            journal_keys: config.security_audit.keys.clone(),
            generation_root: generation_root.clone(),
            tenants: BTreeMap::new(),
            limits: crate::target_runtime_config::TargetRunnerLimits {
                journal: TargetJournalLimits {
                    max_metadata_bytes: 4 << 20,
                },
                max_live_generations: 1,
                operation_timeout_ms: 1000,
            },
        };
        let runtime = Arc::new(TargetRecoveryRuntime {
            recovery_health: std::sync::Mutex::new(serving::RecoveryHealth::new()),
            registry: Default::default(),
            serving_monitor: Default::default(),
            shutdown_gate: Mutex::new(DrainReport::default()),
            config,
            authority_trusts: BTreeMap::new(),
            installed,
            credential: Arc::new(|_| anyhow::bail!("ownership fixture cannot request credentials")),
            journal,
            journal_node: node.clone(),
            signer: TargetSigner::from_pkcs8(identity, &key.serialize_der()).unwrap(),
            cleanup_key: Ed25519KeyPair::from_pkcs8(&key.serialize_der()).unwrap(),
            admission,
            audit: audit.clone(),
            cluster,
            destinations: BTreeMap::new(),
            root: std::fs::canonicalize(&generation_root).unwrap(),
            generation_directory,
            generations: Mutex::new(BTreeMap::new()),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            call_jobs: TargetCallJobs::new(&physical.admission).unwrap(),
            closing: AtomicBool::new(false),
        });
        let weak_runtime = Arc::downgrade(&runtime);
        // A materializer can fail after opening both key domains but before a Raft
        // owner exists. Generation close must still join those store monitors.
        let partial_path = directory.path().join("persistent/partial-target.kv");
        let partial_id = Uuid::new_v4();
        let partial_node = physical.create_new(&partial_path, partial_id).unwrap();
        let weak_partial = Arc::downgrade(&partial_node);
        let partial_store = TenantStore::initialize_catalog_fixture(
            partial_node.clone(),
            "city".into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let partial_stores = kasumi_store::test_utils::initialize_custody_fixture(
            partial_store,
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([44; 32])),
        )
        .await
        .unwrap();
        // This generation is installed by the admitted child only after
        // shutdown starts. The generation census must follow the child join.
        let late_generation = Arc::new(Mutex::new(Generation {
            node: Some(partial_node),
            stores: Some(partial_stores),
            ..Default::default()
        }));
        let pause = runtime.serving_monitor.pause_next_upgrade();
        let bytes = kasumi_serving::BackgroundWorkBudget::required_bytes(1, 1).unwrap();
        let mut charge = runtime.admission.reserve(bytes, None).unwrap();
        charge.retain(bytes);
        let budget = kasumi_serving::BackgroundWorkBudget::new(1, Arc::new(charge)).unwrap();
        runtime.start_serving_reconciliation(&budget).unwrap();
        pause.entered.notified().await;
        let monitor = runtime.serving_monitor.work();
        let calls = runtime.calls.clone();
        let permit = calls.clone().acquire_owned().await.unwrap();
        let (finish_call, blocked_call) = tokio::sync::oneshot::channel::<()>();
        let installer = runtime.clone();
        let response = runtime
            .call_jobs
            .submit(
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                async move {
                    blocked_call.await?;
                    installer
                        .generations
                        .lock()
                        .await
                        .insert(("city".into(), Uuid::new_v4()), late_generation);
                    drop(permit);
                    Ok::<(), anyhow::Error>(())
                },
            )
            .await
            .unwrap();
        drop(response);
        assert_eq!(calls.available_permits(), MAX_CALLS as usize - 1);
        let mut outer = Some(runtime);
        let mut first = Box::pin(shutdown_target(&mut outer));
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        assert!(
            outer.is_some(),
            "cancelled outer shutdown lost its target owner"
        );
        let mut retry = Box::pin(shutdown_target(&mut outer));
        std::future::poll_fn(|cx| {
            assert!(retry.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        pause.release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                // The pinned shutdown owns the exact handle's join lock while
                // pending. Drive that waiter to publish the terminal outcome
                // before a separate nonblocking observation can see it.
                std::future::poll_fn(|cx| {
                    assert!(retry.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                if let Some(result) = monitor.observed() {
                    result.unwrap();
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        std::future::poll_fn(|cx| {
            assert!(retry.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(calls.available_permits(), MAX_CALLS as usize - 1);
        finish_call.send(()).unwrap();
        retry.await.unwrap();
        assert!(outer.is_none());
        assert!(weak_runtime.upgrade().is_none());
        assert!(weak_partial.upgrade().is_none());
        physical
            .open_existing(&partial_path, partial_id)
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        assert!(
            store.check_access().is_err(),
            "target journal key workers were not drained"
        );
        audit.shutdown().await.unwrap();
        drop(audit);
        drop(store);
        drop(node);
        assert!(weak_node.upgrade().is_none());
        let reopened = physical.open_existing(&path, node_id).unwrap();
        let store = TenantStore::open_existing(reopened.clone(), journal_tenant, provider, access)
            .await
            .unwrap();
        store.shutdown().await.unwrap();
        reopened.shutdown().await.unwrap();
    })
    .await
    .expect("shutdown ownership fixture timed out");
}

#[tokio::test]
async fn stop_local_generation_root_substitution_fences_before_cleanup_claim() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    // Keep the configured spelling: macOS temp roots can resolve from /var
    // to /private/var while NodeDisk still binds the installed /var path.
    let installation = directory.path().to_path_buf();
    let physical =
        crate::runtime_storage_fixtures::physical(&installation, Default::default()).unwrap();
    let generation_root = installation.join("persistent/targets");
    let config =
        kasumi_store::NodeDisk::fixture_config(installation.join("persistent/target-journal.kv"))
            .unwrap();
    let generation_directory = crate::persistent_disk::open_or_create_directory(
        &config,
        &physical.persistent,
        &generation_root,
    )
    .unwrap();
    let opened_root = std::fs::canonicalize(&generation_root).unwrap();
    let key = ("city".to_owned(), Uuid::new_v4());
    let path = checked_generation_path(&generation_directory, &generation_root, &opened_root, &key)
        .unwrap();
    assert_eq!(path.parent(), Some(generation_root.as_path()));
    let file_id = Uuid::new_v4();
    let node = physical.create_new(&path, file_id).unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    assert!(path.is_file());

    // An operator or attacker substitutes the configured root after startup.
    // The original inode remains under the moved directory, while the new
    // configured path has no generation file to claim as an absence proof.
    let moved = installation.join("persistent/moved-targets");
    std::fs::rename(&generation_root, &moved).unwrap();
    kasumi_store::private_files::create_directory(&generation_root).unwrap();
    let retained_file = moved.join(path.file_name().unwrap());
    assert!(retained_file.is_file());
    assert!(!path.exists());

    // This is the exact path gate called by StopLocal cleanup before it can
    // claim an inode, sync the parent, or construct SignedLocalTargetCleanup.
    assert!(
        checked_generation_path(&generation_directory, &generation_root, &opened_root, &key)
            .is_err()
    );
    assert_eq!(
        physical.persistent.snapshot().phase,
        kasumi_store::NodeDiskPhase::Failed
    );
    assert!(NodeStore::claim_cleanup(&path, file_id, physical.persistent.clone()).is_err());
    assert!(
        retained_file.is_file(),
        "failed cleanup must retain the original inode"
    );
}

#[tokio::test]
async fn transient_root_swap_during_path_probe_cannot_prove_target_absence() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let installation = directory.path().to_path_buf();
    let physical =
        crate::runtime_storage_fixtures::physical(&installation, Default::default()).unwrap();
    let generation_root = installation.join("persistent/targets");
    let config =
        kasumi_store::NodeDisk::fixture_config(installation.join("persistent/target-journal.kv"))
            .unwrap();
    let _generation_directory = crate::persistent_disk::open_or_create_directory(
        &config,
        &physical.persistent,
        &generation_root,
    )
    .unwrap();
    let opened_root = std::fs::canonicalize(&generation_root).unwrap();
    let key = ("city".to_owned(), Uuid::new_v4());
    let path =
        checked_generation_path(&_generation_directory, &generation_root, &opened_root, &key)
            .unwrap();
    let node = physical.create_new(&path, Uuid::new_v4()).unwrap();
    node.shutdown().await.unwrap();
    drop(node);

    // The old path probe can see NotFound while the actual enrolled directory
    // and its target file are only temporarily at a different pathname.
    let moved = installation.join("persistent/moved-targets");
    std::fs::rename(&generation_root, &moved).unwrap();
    kasumi_store::private_files::create_directory(&generation_root).unwrap();
    assert!(!target_file_exists(&path).unwrap());
    std::fs::remove_dir(&generation_root).unwrap();
    std::fs::rename(&moved, &generation_root).unwrap();

    // Restoring the path before a later directory sync cannot turn the earlier
    // path lookup into an absence proof. The managed observation sees the
    // retained file or rejects changed directory accounting.
    assert!(target_absence_from_installed_disk(&config, &physical.persistent, &path).is_err());
    assert!(path.is_file(), "the original target inode must remain");
}

#[test]
fn never_enrolled_target_leaf_has_a_managed_absence_proof() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let installation = directory.path().to_path_buf();
    let physical =
        crate::runtime_storage_fixtures::physical(&installation, Default::default()).unwrap();
    let generation_root = installation.join("persistent/targets");
    let config =
        kasumi_store::NodeDisk::fixture_config(installation.join("persistent/target-journal.kv"))
            .unwrap();
    let generation_directory = crate::persistent_disk::open_or_create_directory(
        &config,
        &physical.persistent,
        &generation_root,
    )
    .unwrap();
    let opened_root = std::fs::canonicalize(&generation_root).unwrap();
    let key = ("city".to_owned(), Uuid::new_v4());
    let path = checked_generation_path(&generation_directory, &generation_root, &opened_root, &key)
        .unwrap();
    assert!(!target_file_exists(&path).unwrap());
    target_absence_from_installed_disk(&config, &physical.persistent, &path).unwrap();
    assert_eq!(
        physical.persistent.snapshot().phase,
        kasumi_store::NodeDiskPhase::Open
    );
    generation_directory.sync_all().unwrap();
}

#[tokio::test]
async fn missing_previously_enrolled_target_leaf_is_not_an_absence_proof() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let installation = directory.path().to_path_buf();
    let physical =
        crate::runtime_storage_fixtures::physical(&installation, Default::default()).unwrap();
    let generation_root = installation.join("persistent/targets");
    let config =
        kasumi_store::NodeDisk::fixture_config(installation.join("persistent/target-journal.kv"))
            .unwrap();
    let generation_directory = crate::persistent_disk::open_or_create_directory(
        &config,
        &physical.persistent,
        &generation_root,
    )
    .unwrap();
    let opened_root = std::fs::canonicalize(&generation_root).unwrap();
    let key = ("city".to_owned(), Uuid::new_v4());
    let path = checked_generation_path(&generation_directory, &generation_root, &opened_root, &key)
        .unwrap();
    let node = physical.create_new(&path, Uuid::new_v4()).unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    std::fs::remove_file(&path).unwrap();
    assert!(!target_file_exists(&path).unwrap());
    assert!(target_absence_from_installed_disk(&config, &physical.persistent, &path).is_err());
    assert_eq!(
        physical.persistent.snapshot().phase,
        kasumi_store::NodeDiskPhase::Failed
    );
}

#[test]
fn target_absence_requires_a_successful_filesystem_observation() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = directory.path().join("target.kv");
    assert!(!target_file_exists(&path).unwrap());
    std::fs::write(&path, b"owned").unwrap();
    assert!(target_file_exists(&path).unwrap());
    assert!(target_file_exists(directory.path()).is_err());
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(target_file_exists(&alias).is_err());
    // A cyclic parent produces an actual ELOOP observation failure. It is not
    // NotFound, and must not authorize a cleanup success for the child path.
    let cycle = directory.path().join("cycle");
    std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
    assert!(target_file_exists(&cycle.join("target.kv")).is_err());
}

struct PausedCatalogProvider {
    inner: kasumi_store::test_utils::LocalKeyProvider,
    paused: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl kasumi_store::KeyProvider for PausedCatalogProvider {
    async fn generate_key(&self, tenant: &str) -> Result<kasumi_store::GeneratedKey> {
        if !self.paused.swap(true, Ordering::AcqRel) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.generate_key(tenant).await
    }
    async fn unwrap_key(
        &self,
        tenant: &str,
        key: &kasumi_store::WrappedKey,
    ) -> Result<kasumi_store::SecretKey> {
        self.inner.unwrap_key(tenant, key).await
    }
    async fn rewrap_key(
        &self,
        tenant: &str,
        key: &kasumi_store::WrappedKey,
    ) -> Result<kasumi_store::WrappedKey> {
        self.inner.rewrap_key(tenant, key).await
    }
}

#[tokio::test]
async fn target_generation_close_joins_cancelled_catalog_initializers_before_file_cleanup() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                .unwrap();
        let path = directory.path().join("persistent/unpublished-target.kv");
        let id = Uuid::new_v4();
        let node = physical.create_new(&path, id).unwrap();
        let weak = Arc::downgrade(&node);
        let provider = Arc::new(PausedCatalogProvider {
            inner: kasumi_store::test_utils::LocalKeyProvider::new([63; 32]),
            paused: AtomicBool::new(false),
            entered: Default::default(),
            release: Default::default(),
        });
        let mut opening = Box::pin(TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "city".into(),
            provider.clone(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([64; 32])),
        ));
        std::future::poll_fn(|cx| {
            assert!(opening.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        provider.entered.notified().await;
        drop(opening);
        let mut generation = Generation {
            node: Some(node),
            fresh_catalogs: true,
            ..Default::default()
        };
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = certificate.pem().into_bytes();
        let tls =
            kasumi_transport::TlsIdentity::from_pem(&pem, key.serialize_pem().as_bytes()).unwrap();
        let cluster = ClusterNetwork::new(
            1,
            &tls,
            &pem,
            vec![crate::cluster::PeerConfig {
                node_id: 1,
                endpoint: "https://localhost:9".into(),
                certificate_pins: BTreeSet::from([tls.certificate_pin()]),
            }],
            Default::default(),
        )
        .unwrap();
        let registry = crate::api::DatabaseRegistry::default();
        let mut closing = Box::pin(generation.close(&cluster, &registry));
        std::future::poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(closing);
        assert!(generation.node.is_some());
        assert!(weak.upgrade().is_some());
        assert!(NodeStore::claim_cleanup(&path, id, physical.persistent.clone()).is_err());
        provider.release.notify_one();
        let failure = generation.close(&cluster, &registry).await.unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        let issue = failure
            .issues()
            .iter()
            .find(|issue| issue.component() == "node catalog initialization")
            .expect("original cancelled initializer diagnostic")
            .clone();
        assert!(format!("{:#}", issue.error()).contains("catalog initialization receiver closed"));
        let repeated = generation.close(&cluster, &registry).await.unwrap_err();
        assert_eq!(repeated.completion(), DrainCompletion::Complete);
        let repeated_issue = repeated
            .issues()
            .iter()
            .find(|entry| entry.component() == "node catalog initialization")
            .unwrap();
        assert!(Arc::ptr_eq(&issue, repeated_issue));
        assert!(generation.node.is_none());
        assert!(!generation.fresh_catalogs);
        assert!(weak.upgrade().is_none());
        let ownership = NodeStore::claim_cleanup(&path, id, physical.persistent.clone()).unwrap();
        ownership.delete().unwrap();
        assert!(!path.exists());
    })
    .await
    .unwrap();
}
