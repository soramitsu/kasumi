use super::*;
use std::{collections::BTreeSet, future::Future, task::Poll};

#[tokio::test]
async fn target_monitor_and_outer_owner_survive_cancelled_shutdown_until_journal_reopens() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target-journal.redb");
        let node = NodeStore::open(&path, kasumi_store::ScratchDisk::fixture()).unwrap();
        let weak_node = Arc::downgrade(&node);
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
        let provider = Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([41; 32]));
        let journal_tenant = format!("kasumi.target.{}.1", root.control_incarnation);
        let access = StorageAccess::target_journal(&root, &identity).unwrap();
        let store = TenantStore::open(
            node.clone(),
            journal_tenant.clone(),
            provider.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let journal = TargetJournal::open(
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
        let audit_store = TenantStore::open_fixture(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([42; 32])),
        )
        .await
        .unwrap();
        let audit =
            SecurityAudit::open(audit_store, Default::default(), admission.clone()).unwrap();
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
        let config = crate::runtime::example_config();
        // No network or recovery operation is dispatched by this ownership fixture.
        // The actual monitor is stopped at its first upgrade, before discovery.
        let installed = TargetRecoveryConfig {
            control_root: root,
            control_endpoint: crate::serving_runtime::AuthorityEndpoint {
                endpoint: "https://localhost:9".into(),
                certificate_pins: BTreeSet::from(["ab".repeat(32)]),
            },
            control_tls: config.native.tls.clone(),
            control_ca: directory.path().join("ca.pem"),
            node: identity.clone(),
            attestation_key: directory.path().join("target.pk8"),
            issuer_admin_bearer_file: BTreeMap::new(),
            journal_path: path.clone(),
            journal_keys: config.security_audit.keys.clone(),
            generation_root: directory.path().join("targets"),
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
            shutdown_gate: Mutex::new(()),
            config,
            authority_trusts: BTreeMap::new(),
            installed,
            credential: Arc::new(|_| anyhow::bail!("ownership fixture cannot request credentials")),
            journal,
            signer: TargetSigner::from_pkcs8(identity, &key.serialize_der()).unwrap(),
            cleanup_key: Ed25519KeyPair::from_pkcs8(&key.serialize_der()).unwrap(),
            admission,
            audit: audit.clone(),
            cluster,
            destinations: BTreeMap::new(),
            root: directory.path().to_owned(),
            generations: Mutex::new(BTreeMap::new()),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            closing: AtomicBool::new(false),
        });
        let weak_runtime = Arc::downgrade(&runtime);
        // A materializer can fail after opening both key domains but before a Raft
        // owner exists. Generation close must still join those store monitors.
        let partial_path = directory.path().join("partial-target.redb");
        let partial_node =
            NodeStore::open(&partial_path, kasumi_store::ScratchDisk::fixture()).unwrap();
        let weak_partial = Arc::downgrade(&partial_node);
        let partial_store = TenantStore::open_fixture(
            partial_node.clone(),
            "city".into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let partial_stores = kasumi_store::test_utils::with_custody(
            partial_store,
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([44; 32])),
        )
        .await
        .unwrap();
        runtime.generations.lock().await.insert(
            ("city".into(), Uuid::new_v4()),
            Arc::new(Mutex::new(Generation {
                node: Some(partial_node),
                stores: Some(partial_stores),
                ..Default::default()
            })),
        );
        let pause = runtime.serving_monitor.pause_next_upgrade();
        runtime.start_serving_reconciliation();
        pause.entered.notified().await;
        assert_eq!(runtime.calls.available_permits(), MAX_CALLS as usize);
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
        retry.await.unwrap();
        assert!(outer.is_none());
        assert!(weak_runtime.upgrade().is_none());
        assert!(weak_partial.upgrade().is_none());
        drop(NodeStore::open(&partial_path, kasumi_store::ScratchDisk::fixture()).unwrap());
        assert!(
            store.check_access().is_err(),
            "target journal key workers were not drained"
        );
        audit.shutdown().await;
        drop(audit);
        drop(store);
        drop(node);
        assert!(weak_node.upgrade().is_none());
        let reopened = NodeStore::open(&path, kasumi_store::ScratchDisk::fixture()).unwrap();
        let store = TenantStore::open_existing(reopened, journal_tenant, provider, access)
            .await
            .unwrap();
        store.shutdown().await;
    })
    .await
    .expect("shutdown ownership fixture timed out");
}
