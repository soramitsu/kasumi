use super::*;
use crate::test_fixture_failure::FixtureResult;
use kasumi_store::{
    NodeStore, StorageAccess, TenantStorageSet,
    test_utils::{
        FixturePlaintextCopy, FixtureWrite, FixtureWriteBatch, LocalKeyProvider,
        write_plaintext_copy_for_fixture,
    },
};
use ring::signature::KeyPair;

struct Fixture {
    storage: crate::test_utils::FixtureStorage,
    config: crate::admission::AdmissionConfig,
    id: Uuid,
    node: NodeStore,
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    admission: Arc<crate::admission::NodeAdmission>,
    directory: tempfile::TempDir,
    control_key: ring::signature::Ed25519KeyPair,
}
impl Fixture {
    fn dispatch(
        &self,
        journal: &Arc<TargetJournal>,
        root: &ControlSigningRoot,
        phase: &kasumi_types::RecoveryPhaseRecord,
        intent: &LifecycleIntent,
        request: &kasumi_types::TargetRuntimeRequest,
    ) -> Result<InitialDispatchReservation> {
        match journal.reserve_initial_dispatch(root, phase, intent, request) {
            Err(error) if error.is::<MissingTargetWriter>() => {
                let read = journal.begin_writer_read()?;
                let observation = kasumi_types::TargetWriterObservation {
                    challenge: read.challenge().clone(),
                    observed_term: 1,
                    observed_revision: 1,
                    membership_epoch: 1,
                    observed_policy_epoch: 1,
                    retirements: Default::default(),
                };
                let bytes = serde_json::to_vec(&("kasumi.target-journal-writer.v1", &observation))?;
                let signature = hex::encode(self.control_key.sign(&bytes).as_ref());
                let writer = read.admit(&kasumi_types::SignedTargetWriterObservation {
                    observation,
                    signature,
                })?;
                journal.reserve_observed_initial_dispatch(root, phase, intent, request, &writer)
            }
            result => result,
        }
    }
    async fn new() -> Result<Self> {
        Self::with_provider(Arc::new(LocalKeyProvider::new([39; 32]))).await
    }

    async fn with_provider(provider: Arc<LocalKeyProvider>) -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let control_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[71; 32])
            .map_err(|_| anyhow::anyhow!("fixture Control signing key failed"))?;
        let installed = TargetJournalInstallation {
            source_key_bindings_sha256: None,
            root: ControlSigningRoot {
                control_incarnation: Uuid::new_v4(),
                public_key: hex::encode(control_key.public_key().as_ref()),
            },
            node: NodeIdentity {
                node_id: 1,
                verifier: kasumi_types::TrustVerifierIdentity {
                    installation_id: Uuid::new_v4(),
                    node_id: 1,
                },
                principal: "target-node".into(),
                certificate_sha256: "22".repeat(32),
            },
            audit_placement_bindings: std::collections::BTreeMap::from([(
                "documents".into(),
                "ab".repeat(32),
            )]),
        };
        let id = kasumi_store::node_store_ids::target_journal(
            installed.root.control_incarnation,
            &installed.node.verifier,
        )?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // The original fixed 2 GiB source resolves Default to a 256 MiB total.
        // Add only the new physical metadata; do not resolve against host RAM.
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (256_u64 << 20)
                    .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                        &persistent_config,
                        &scratch_config,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
            ),
            ..Default::default()
        };
        let admission =
            crate::admission::NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent_config,
            &scratch_config,
            admission.clone(),
        )?;
        let node = storage
            .create_new(directory.path().join("persistent/journal.kv"), id)
            .unwrap_or_else(|original| std::panic::panic_any(original));
        let store = TenantStore::initialize_catalog(
            node.clone(),
            format!("kasumi.target.{}.1", installed.root.control_incarnation),
            provider,
            StorageAccess::target_journal(&installed.root, &installed.node)?,
        )
        .await?;
        Ok(Self {
            directory,
            storage,
            config,
            id,
            node,
            store,
            installed,
            admission,
            control_key,
        })
    }
    fn create(&self) -> Result<Arc<TargetJournal>> {
        TargetJournal::create_new(
            self.store.clone(),
            self.installed.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            self.admission.clone(),
        )
    }
    fn reopen(&self) -> Result<Arc<TargetJournal>> {
        TargetJournal::open_existing(
            self.store.clone(),
            self.installed.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            self.admission.clone(),
        )
    }

    fn verified_control(
        &self,
        lifecycle: &LifecycleIntent,
    ) -> Result<kasumi_serving::VerifiedControlIntent> {
        let partition = kasumi_types::ControlAuthorityPartition {
            authority_id: Uuid::from_u128(999),
            manifest_sha256: "aa".repeat(32),
            partition: 0,
            signing_public_key: "bb".repeat(32),
            maximum_lifetime_ms: 1_000,
            drain_ms: 1_000,
        };
        ensure!(
            lifecycle.request.authority_partition == partition.key(),
            "fixture Control partition differs"
        );
        let observation = kasumi_types::ControlIntentCommitment {
            intent: lifecycle.clone(),
            root: self.installed.root.clone(),
            authority_partition: partition,
            partition_set_sha256: "cc".repeat(32),
            observed_policy_epoch: lifecycle.request.expected_policy_epoch,
            observed_revision: lifecycle.revision,
            observed_term: 1,
        };
        self.sign_control_observation(observation)
    }

    fn sign_control_observation(
        &self,
        observation: kasumi_types::ControlIntentCommitment,
    ) -> Result<kasumi_serving::VerifiedControlIntent> {
        let signed = kasumi_types::SignedControlIntent {
            signature: hex::encode(
                self.control_key
                    .sign(&serde_json::to_vec(&(
                        "kasumi.committed-control-intent.v1",
                        &observation,
                    ))?)
                    .as_ref(),
            ),
            observation,
        };
        kasumi_serving::ControlTrust::install(self.installed.root.clone())?.verify_intent(&signed)
    }
}

/// The journal and paired target custody share a fixture NodeStore but retain
/// independent encrypted catalogs and storage purposes. The serving lease is
/// actually signed and verified for the journal's installed physical node.
async fn target_prebind_stores(
    f: &Fixture,
    lifecycle: &LifecycleIntent,
    bootstrap_sha256: &str,
) -> Result<(Arc<TenantStorageSet>, StorageAccess)> {
    let tenant = &lifecycle.request.tenant;
    let incarnation = lifecycle.request.target_incarnation;
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("fixture signing root generation failed"))?;
    let root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(pkcs8.as_ref())?;
    let manifest = kasumi_serving::AuthorityManifest {
        lifecycle_controls: Default::default(),
        authority_id: Uuid::new_v4(),
        max_lease_ms: 60_000,
        clock_rate_error_ppm: 0,
        partitions: std::collections::BTreeMap::from([(
            0,
            kasumi_serving::AuthorityPartition {
                group: "target-prebind-issuer".into(),
                public_key: root.public_key(),
            },
        )]),
    };
    let signing = root
        .install(manifest.clone(), 0)?
        .for_verifier(f.installed.node.verifier.clone())?;
    let signer = signing.signer.clone();
    let boot = kasumi_serving::ServingBoot::new(
        signing.trust,
        kasumi_serving::ServingIdentity {
            tenant: tenant.clone(),
            incarnation,
            authority_epoch: lifecycle
                .request
                .source_authority_epoch
                .checked_add(1)
                .context("target authority epoch exhausted")?,
            node: f.installed.node.clone(),
        },
    )?;
    let attempt = boot.begin_acquisition()?;
    let lease = attempt.verify(signer.sign_lease(kasumi_serving::LeaseClaims {
        request: attempt.request().clone(),
        authority_id: manifest.authority_id,
        partition: 0,
        authority_term: 1,
        authority_revision: 1,
        lifetime_ms: manifest.max_lease_ms,
        credential_lifetime_ms: manifest.max_lease_ms,
        activation_digest: "aa".repeat(32),
        recovery_checkpoint: Some(lifecycle.request.checkpoint.clone()),
    })?)?;
    let access = StorageAccess::serving(kasumi_serving::ServingGate::new(lease)?)?;
    let stores = TenantStorageSet::initialize_catalogs(
        f.node.clone(),
        tenant.clone(),
        Arc::new(LocalKeyProvider::new([40; 32])),
        Arc::new(LocalKeyProvider::new([41; 32])),
        access.clone(),
    )
    .await?;
    let mut identity = kasumi_raft::initial_storage_identity(
        f.installed.node.node_id,
        &format!("{tenant}/{incarnation}"),
    )?
    .to_vec();
    identity.push(WriteOp::put(
        "raft.meta",
        b"application_bootstrap_sha256",
        serde_json::to_vec(bootstrap_sha256)?,
    ));
    stores.initialize_state(
        &[WriteOp::put(
            "engine.bootstrap",
            b"manifest",
            serde_json::to_vec(&serde_json::json!({
                "format": 2,
                "bytes": 0,
                "chunks": 0,
                "digest": bootstrap_sha256,
            }))?,
        )],
        &identity,
    )?;
    Ok((stores, access))
}

#[tokio::test]
async fn missing_journal_head_never_initializes_and_explicit_installation_cannot_repeat()
-> Result<()> {
    let f = Fixture::new().await?;
    assert!(f.reopen().is_err());
    assert!(f.store.get(NS, b"metadata")?.is_none());
    let journal = f.create()?;
    let head = f.store.get(NS, b"metadata")?.unwrap();
    assert!(f.create().is_err());
    assert!(Arc::ptr_eq(&journal, &f.reopen()?));
    f.store.write_batch(&[WriteOp::delete(NS, b"metadata")])?;
    assert!(
        f.reopen().is_err(),
        "cached owner must not bypass durable head validation"
    );
    assert!(f.store.get(NS, b"metadata")?.is_none());
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", head.as_bytes())?;
    drop(journal);
    assert!(f.create().is_err());
    let journal = f.reopen()?;
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(head.as_bytes())
    );
    journal.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn audit_placement_roster_is_required_before_installation_and_first_target_effect()
-> Result<()> {
    let f = Fixture::new().await?;
    let mut missing = serde_json::to_value(&f.installed)?;
    missing
        .as_object_mut()
        .unwrap()
        .remove("audit_placement_bindings");
    assert!(serde_json::from_value::<TargetJournalInstallation>(missing).is_err());
    let mut null = serde_json::to_value(&f.installed)?;
    null["audit_placement_bindings"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<TargetJournalInstallation>(null).is_err());
    for bindings in [
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::from([("documents".into(), "".into())]),
        std::collections::BTreeMap::from([("documents".into(), "AB".repeat(32))]),
        std::collections::BTreeMap::from([("__kasumi_control".into(), "ab".repeat(32))]),
    ] {
        let mut wrong = f.installed.clone();
        wrong.audit_placement_bindings = bindings;
        assert!(
            TargetJournal::create_new(
                f.store.clone(),
                wrong,
                TargetJournalLimits {
                    max_metadata_bytes: 4 << 20
                },
                f.admission.clone(),
            )
            .is_err()
        );
        assert!(f.store.get(NS, b"metadata")?.is_none());
    }
    let journal = f.create()?;
    let original = f.store.get(NS, b"metadata")?.unwrap();
    assert_eq!(
        journal.metadata()?.installation.audit_placement_bindings,
        f.installed.audit_placement_bindings
    );
    let mut substituted = f.installed.clone();
    substituted
        .audit_placement_bindings
        .insert("documents".into(), "cd".repeat(32));
    // The empty journal already owns the choice: neither a cached owner nor a
    // later reopen may substitute it before the first materialization.
    assert!(
        TargetJournal::open_existing(
            f.store.clone(),
            substituted.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20
            },
            f.admission.clone(),
        )
        .is_err()
    );
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(original.as_bytes())
    );
    drop(journal);
    assert!(
        TargetJournal::open_existing(
            f.store.clone(),
            substituted,
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20
            },
            f.admission.clone(),
        )
        .is_err()
    );

    let mut missing_head = serde_json::to_value(decode_current::<Metadata>(&original)?)?;
    missing_head["installation"]
        .as_object_mut()
        .unwrap()
        .remove("audit_placement_bindings");
    let mut old = decode_current::<Metadata>(&original)?;
    old.format = 4;
    for bytes in [
        serde_json::to_vec(&missing_head)?,
        serde_json::to_vec(&old)?,
    ] {
        write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", &bytes)?;
        assert!(f.reopen().is_err());
        assert!(f.create().is_err());
        assert_eq!(
            f.store.get(NS, b"metadata")?.as_deref(),
            Some(bytes.as_slice())
        );
    }
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original.as_bytes())?;
    f.reopen()?.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn first_dispatch_rejects_a_tenant_outside_the_installed_placement_roster() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.installed.audit_placement_bindings =
        std::collections::BTreeMap::from([("another-target".into(), "ab".repeat(32))]);
    let journal = f.create()?;
    let original = f.store.scan(NS)?;
    let (lifecycle, phase, request) = initial_dispatch(&f, true)?;
    assert!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)
            .is_err()
    );
    assert_eq!(f.store.scan(NS)?, original);
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn corrupt_or_wrong_installed_journal_head_is_rejected_without_replacement() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    drop(journal);
    let original = f.store.get(NS, b"metadata")?.unwrap();
    let mut wrong: Metadata = serde_json::from_slice(&original)?;
    wrong.installation.root.control_incarnation = Uuid::new_v4();
    for bytes in [b"{".to_vec(), serde_json::to_vec(&wrong)?] {
        write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", bytes.as_slice())?;
        assert!(f.reopen().is_err());
        assert!(f.create().is_err());
        assert_eq!(
            f.store.get(NS, b"metadata")?.as_deref(),
            Some(bytes.as_slice())
        );
    }
    f.store.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn current_head_requires_exact_current_json_bytes() -> Result<()> {
    let f = Fixture::new().await?;
    drop(f.create()?);
    let original = f.store.get(NS, b"metadata")?.unwrap();
    let alternate = FixturePlaintextCopy::with_suffix(&f.store, original.as_bytes(), b" ")?;
    assert_eq!(
        serde_json::from_slice::<Metadata>(&alternate)?,
        serde_json::from_slice::<Metadata>(&original)?
    );
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", alternate.as_bytes())?;
    let error = f
        .reopen()
        .err()
        .expect("alternate format-3 head bytes must reject");
    assert!(
        format!("{error:#}").contains("noncanonical target journal record"),
        "{error:#}"
    );
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(alternate.as_bytes())
    );
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original.as_bytes())?;
    f.reopen()?.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn installed_empty_journal_reopens_only_its_exact_node_after_owner_drain() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.installed.source_key_bindings_sha256 = Some("ab".repeat(32));
    let journal = f.create()?;
    let original = f.store.get(NS, b"metadata")?.unwrap();
    journal.shutdown().await.unwrap();
    drop(journal);
    let Fixture {
        directory,
        storage,
        config: _,
        id,
        node,
        store,
        installed,
        admission,
        control_key: _,
    } = f;
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    drop(node);
    let path = directory.path().join("persistent/journal.kv");
    let group_image = || {
        kasumi_store::test_utils::capture_native_group_image(
            &path,
            storage.persistent.memory().clone(),
        )
    };
    let bytes = group_image()?;
    assert!(storage.open_existing(&path, Uuid::new_v4()).is_err());
    assert_eq!(group_image()?, bytes);
    let node = storage
        .open_existing(&path, id)
        .unwrap_or_else(|original| std::panic::panic_any(original));
    let store = TenantStore::open_existing(
        node.clone(),
        format!("kasumi.target.{}.1", installed.root.control_incarnation),
        Arc::new(LocalKeyProvider::new([39; 32])),
        StorageAccess::target_journal(&installed.root, &installed.node)?,
    )
    .await?;
    for binding in [None, Some("cd".repeat(32))] {
        let mut altered = installed.clone();
        altered.source_key_bindings_sha256 = binding;
        assert!(
            TargetJournal::open_existing(
                store.clone(),
                altered,
                TargetJournalLimits {
                    max_metadata_bytes: 4 << 20
                },
                admission.clone()
            )
            .is_err()
        );
        assert_eq!(
            store.get(NS, b"metadata")?.as_deref(),
            Some(original.as_bytes())
        );
    }
    let journal = TargetJournal::open_existing(
        store.clone(),
        installed,
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        admission,
    )?;
    assert_eq!(
        store.get(NS, b"metadata")?.as_deref(),
        Some(original.as_bytes())
    );
    journal.shutdown().await.unwrap();
    store.shutdown().await?;
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn paused_registry_handoff_cannot_publish_two_journal_mutation_owners() -> Result<()> {
    let f = Fixture::new().await?;
    drop(f.create()?);
    let original = f.store.get(NS, b"metadata")?.unwrap();

    // Deterministically pause the first opener after registry selection but
    // before locking the selected gate. Run the second opener to completion,
    // then resume the first at that exact handoff; no timing race is required.
    let first_gate = TargetJournal::owner_gate(&f.store)?;
    let second = f.reopen()?;
    let first = TargetJournal::open_with_owner(
        f.store.clone(),
        f.installed.clone(),
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        f.admission.clone(),
        false,
        &first_gate,
    )?;
    assert!(
        Arc::ptr_eq(&first, &second),
        "one catalog must have one journal mutation owner"
    );
    assert!(
        f.create().is_err(),
        "the shared owner cannot initialize the head again"
    );
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(original.as_bytes())
    );
    first.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn journal_rejects_foreign_equal_policy_core_before_creating_or_reopening_head() -> Result<()>
{
    let f = Fixture::new().await?;
    f.node
        .drain_initializers()
        .await
        .map_err(|failure| failure.observation())?;
    let foreign = crate::admission::NodeAdmission::with_fixed_memory(f.config.clone(), 2 << 30, 0)?;
    f.admission.memory().require_policy(&f.config)?;
    foreign.memory().require_policy(&f.config)?;
    assert!(!f.admission.shares_memory(&foreign));
    let limits = TargetJournalLimits {
        max_metadata_bytes: 4 << 20,
    };

    // No head exists yet. A foreign equal-policy core must not create one or
    // charge work to either governor before rejecting the owner mismatch.
    let before = f.admission.snapshot();
    let foreign_before = foreign.snapshot();
    let disk_before = f.storage.persistent.snapshot();
    let error = match TargetJournal::create_new(
        f.store.clone(),
        f.installed.clone(),
        limits.clone(),
        foreign.clone(),
    ) {
        Ok(_) => panic!("foreign core must not initialize a target journal"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "engine and physical storage memory owners differ"
    );
    assert!(f.store.get(NS, b"metadata")?.is_none());
    for (admission, prior) in [(&f.admission, before), (&foreign, foreign_before)] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let disk_after = f.storage.persistent.snapshot();
    assert_eq!(disk_after.phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(disk_after.open_files, disk_before.open_files);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(disk_after.pending_bytes, disk_before.pending_bytes);

    let original = f.create()?;
    let head = f.store.get(NS, b"metadata")?.unwrap();
    // Remove the cached journal facade, leaving the store live. Without the
    // entry guard this reopen can publish a new facade on the foreign core.
    drop(original);
    let before = f.admission.snapshot();
    let foreign_before = foreign.snapshot();
    let error = match TargetJournal::open_existing(
        f.store.clone(),
        f.installed.clone(),
        limits,
        foreign.clone(),
    ) {
        Ok(_) => panic!("foreign core must not reopen an installed target journal"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "engine and physical storage memory owners differ"
    );
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(head.as_bytes())
    );
    for (admission, prior) in [(&f.admission, before), (&foreign, foreign_before)] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let exact = f.reopen()?;
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(head.as_bytes())
    );
    assert!(Arc::ptr_eq(&exact.admission, &f.admission));
    exact.shutdown().await?;
    f.admission.drain_snapshot_startups().await?;
    foreign.drain_snapshot_startups().await?;
    f.node.shutdown().await?;
    Ok(())
}

fn initial_dispatch(
    f: &Fixture,
    initialize: bool,
) -> Result<(
    LifecycleIntent,
    kasumi_types::RecoveryPhaseRecord,
    kasumi_types::TargetRuntimeRequest,
)> {
    use crate::target_completion_machine::tests as fixture;
    use kasumi_types::{
        RecoveryDispatch, RecoveryEffect, RecoveryEffectAttempt, RecoveryPhase,
        RecoveryPhaseRecord, TargetQuorumInput, TargetReplicaInput, TargetRuntimeRequest,
        TargetRuntimeStep, staged_digest,
    };
    use std::collections::BTreeMap;
    let origin = fixture::origin();
    let quorum = TargetQuorumInput {
        origin_sha256: origin.digest()?,
        materialized: BTreeMap::new(),
    };
    let mut lifecycle = fixture::intent(
        &origin,
        LifecyclePhase::Initialize,
        quorum.digest()?,
        9,
        150,
        1_000,
    );
    lifecycle.control_incarnation = f.installed.root.control_incarnation;
    let installed_node = &f.installed.node;
    let node = lifecycle
        .request
        .target_nodes
        .get_mut(&installed_node.node_id)
        .unwrap();
    node.verifier = installed_node.verifier.clone();
    node.principal = installed_node.principal.clone();
    node.certificate_sha256 = installed_node.certificate_sha256.clone();
    lifecycle.request_sha256 = staged_digest(&lifecycle.request)?.0;
    let request = TargetRuntimeRequest {
        tenant: lifecycle.request.tenant.clone(),
        command_id: lifecycle.request.command_id,
        not_after_ms: 500,
        step: if initialize {
            TargetRuntimeStep::Initialize(quorum)
        } else {
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum))
        },
    };
    let input = RecoveryDispatch::Target {
        node_id: installed_node.node_id,
        request: Box::new(request.clone()),
    };
    let digest = staged_digest(&input)?.0;
    let phase = RecoveryPhaseRecord {
        operation_id: Uuid::from_u128(if initialize { 701 } else { 700 }),
        phase_id: Uuid::from_u128(if initialize { 711 } else { 710 }),
        sequence: if initialize { 4 } else { 1 },
        phase: RecoveryPhase::Initialize,
        completion_scope: None,
        previous_phase: initialize.then_some(Uuid::from_u128(709)),
        input,
        input_sha256: digest.clone(),
        principal: lifecycle.original_principal.clone(),
        admitted_at_ms: 200,
        original_credential_expires_at_ms: 1_000,
        prepared_revision: 1,
        effect_attempts: BTreeMap::from([(
            RecoveryEffect::TargetCommand,
            RecoveryEffectAttempt {
                attempt_id: Uuid::from_u128(if initialize { 721 } else { 720 }),
                input_sha256: digest,
                admitted_at_ms: 201,
                begun_revision: 2,
            },
        )]),
        activation_acceptance: None,
        outcome: None,
        resolved_revision: None,
    };
    phase.validate()?;
    Ok((lifecycle, phase, request))
}

fn signed_initial_dispatch(
    f: &Fixture,
    initialize: bool,
) -> Result<(
    LifecycleIntent,
    kasumi_types::RecoveryPhaseRecord,
    kasumi_types::TargetRuntimeRequest,
)> {
    use crate::target_completion_machine::tests as fixture;
    use kasumi_types::{
        RecoveryDispatch, RecoveryEffect, SignedTargetMaterialization, TargetMaterializationFact,
        TargetQuorumInput, TargetReplicaInput, TargetRuntimeStep, staged_digest,
    };
    let (mut lifecycle, mut phase, mut request) = initial_dispatch(f, initialize)?;
    let mut origin = fixture::origin();
    let authority_partition = format!("{}/0", Uuid::from_u128(999));
    lifecycle.request.authority_partition = authority_partition.clone();
    origin.materialization.control_incarnation = f.installed.root.control_incarnation;
    origin.materialization.request.authority_partition = authority_partition;
    origin.materialization.request.target_nodes = lifecycle.request.target_nodes.clone();
    origin.materialization.request_sha256 = staged_digest(&origin.materialization.request)?.0;
    origin.validate()?;
    let quorum = TargetQuorumInput {
        origin_sha256: origin.digest()?,
        materialized: origin
            .input
            .voters
            .keys()
            .map(|node_id| {
                let fact = TargetMaterializationFact {
                    origin: origin.clone(),
                    node_id: *node_id,
                    bootstrap_sha256: "77".repeat(32),
                    revision_base: origin.materialization.request.checkpoint.revision + 1,
                };
                (
                    *node_id,
                    SignedTargetMaterialization {
                        signature: fixture::sign(&fact, "kasumi.materialized-target.v1", *node_id),
                        fact,
                    },
                )
            })
            .collect(),
    };
    lifecycle.request.phase_input_sha256 = quorum.digest()?;
    lifecycle.request_sha256 = staged_digest(&lifecycle.request)?.0;
    request.step = if initialize {
        TargetRuntimeStep::Initialize(quorum)
    } else {
        TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum))
    };
    phase.input = RecoveryDispatch::Target {
        node_id: f.installed.node.node_id,
        request: Box::new(request.clone()),
    };
    phase.input_sha256 = staged_digest(&phase.input)?.0;
    phase
        .effect_attempts
        .get_mut(&RecoveryEffect::TargetCommand)
        .context("signed initial marker missing")?
        .input_sha256 = phase.input_sha256.clone();
    phase.validate()?;
    Ok((lifecycle, phase, request))
}

// Storage/journal unit fixture only: signed cause is explicitly built from its
// accepted phase fixture. It grants no live InitialInitializePermit or child.
fn fixture_initial_cause(
    f: &Fixture,
    lifecycle: &LifecycleIntent,
    start: &kasumi_types::RecoveryPhaseRecord,
    request: &kasumi_types::TargetRuntimeRequest,
) -> Result<kasumi_types::SignedTargetInitializationAssociation> {
    use kasumi_types::*;
    let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum)) = &request.step else {
        anyhow::bail!("fixture cause needs original Start")
    };
    let mut initialize = start.clone();
    initialize.phase_id = Uuid::new_v4();
    initialize.sequence += 1;
    initialize.previous_phase = Some(start.phase_id);
    initialize.prepared_revision = 3;
    let mut packet = request.clone();
    packet.step = TargetRuntimeStep::Initialize(quorum.clone());
    initialize.input = RecoveryDispatch::Target {
        node_id: 1,
        request: Box::new(packet),
    };
    initialize.input_sha256 = staged_digest(&initialize.input)?.0;
    let marker = initialize
        .effect_attempts
        .get_mut(&RecoveryEffect::TargetCommand)
        .unwrap();
    marker.attempt_id = Uuid::new_v4();
    marker.input_sha256 = initialize.input_sha256.clone();
    marker.begun_revision = 4;
    let association = TargetInitializationAssociation {
        control_root: f.installed.root.clone(),
        original_intent: lifecycle.clone(),
        quorum: quorum.clone(),
        start: start.clone(),
        initialize,
    };
    association.validate()?;
    Ok(SignedTargetInitializationAssociation {
        signature: crate::target_completion_machine::tests::sign(
            &association,
            "kasumi.target-initialization-association.v1",
            1,
        ),
        association,
    })
}

#[tokio::test]
async fn accepted_dispatch_derives_only_exact_signed_initial_membership() -> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    use kasumi_types::{
        RecoveryDispatch, RecoveryEffect, TargetReplicaInput, TargetRuntimeStep, staged_digest,
    };
    for initialize in [false, true] {
        let f = Fixture::new().await?;
        let journal = f.create()?;
        let (lifecycle, phase, request) = signed_initial_dispatch(&f, initialize)?;
        assert!(
            matches!(journal.reserve_initial_dispatch(&f.installed.root,&phase,&lifecycle,&request),Err(error) if error.is::<MissingTargetWriter>())
        );
        let Decision::NewlyAccepted(candidate) =
            f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
        else {
            anyhow::bail!("signed first dispatch returned no candidate")
        };
        let mut checkpoints = Vec::new();
        journal.visit_key_dependencies(
            &kasumi_query::QueryCancellation::default(),
            |_| Ok(()),
            |id, checkpoint| {
                checkpoints.push((id, checkpoint.clone()));
                Ok(())
            },
        )?;
        assert_eq!(
            checkpoints,
            [(
                lifecycle.request.target_incarnation,
                lifecycle.request.checkpoint.clone()
            )]
        );
        let membership = candidate
            .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
        let expected: std::collections::BTreeMap<u64, String> = (1..=3)
            .map(|id| (id, format!("https://target-{id}:7400")))
            .collect();
        assert_eq!(membership.voters(), &expected);
        let bootstrap_sha256 = "77".repeat(32);
        assert_eq!(membership.bootstrap_sha256(), bootstrap_sha256.as_str());
        assert_eq!(membership.prebind().identity().phase_id, phase.phase_id);
        assert!(matches!(
            f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?,
            Decision::ExistingStatusOnly
        ));
    }

    for wrong_phase in [false, true] {
        let f = Fixture::new().await?;
        let journal = f.create()?;
        let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
        let Decision::NewlyAccepted(candidate) =
            f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
        else {
            anyhow::bail!("signed first dispatch returned no candidate")
        };
        let (node, phase) = if wrong_phase {
            (f.installed.node.node_id, LifecyclePhase::Complete)
        } else {
            (f.installed.node.node_id + 1, LifecyclePhase::Initialize)
        };
        assert!(candidate.verify_initial_membership(node, phase).is_err());
    }

    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (mut lifecycle, mut phase, mut request) = signed_initial_dispatch(&f, false)?;
    let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum)) = &mut request.step else {
        unreachable!("signed Start fixture")
    };
    quorum
        .materialized
        .get_mut(&2)
        .context("second materialization missing")?
        .fact
        .origin
        .input
        .voters
        .get_mut(&2)
        .context("second voter missing")?
        .endpoint = "https://substituted:7400".into();
    lifecycle.request.phase_input_sha256 = quorum.digest()?;
    lifecycle.request_sha256 = staged_digest(&lifecycle.request)?.0;
    phase.input = RecoveryDispatch::Target {
        node_id: f.installed.node.node_id,
        request: Box::new(request.clone()),
    };
    phase.input_sha256 = staged_digest(&phase.input)?.0;
    phase
        .effect_attempts
        .get_mut(&RecoveryEffect::TargetCommand)
        .context("changed initial marker missing")?
        .input_sha256 = phase.input_sha256.clone();
    phase.validate()?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("changed signed dispatch returned no candidate")
    };
    assert!(
        candidate
            .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn verified_initial_prebind_persists_reopens_and_rejects_substituted_accepted_row()
-> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    use kasumi_raft::{
        TARGET_PREBIND_KEY, TARGET_PREBIND_NAMESPACE, read_target_first_membership_prebind,
    };
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("signed first dispatch returned no one-use candidate")
    };
    let verified = candidate
        .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
    let (stores, access) =
        target_prebind_stores(&f, &lifecycle, verified.bootstrap_sha256()).await?;
    assert_eq!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"node_id")?
            .as_deref(),
        Some(serde_json::to_vec(&f.installed.node.node_id)?.as_slice())
    );
    assert_eq!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"group")?
            .as_deref(),
        Some(
            serde_json::to_vec(&format!(
                "{}/{}",
                lifecycle.request.tenant, lifecycle.request.target_incarnation
            ))?
            .as_slice()
        )
    );
    let materialized_identity = stores.custody().store().scan("raft.meta")?;
    let expected = verified.persist_target_raft_prebind(&journal, &stores)?;
    for (key, value) in &materialized_identity {
        assert_eq!(
            stores.custody().store().get("raft.meta", key)?.as_deref(),
            Some(value)
        );
    }
    assert_eq!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"node_id")?
            .as_deref(),
        Some(serde_json::to_vec(&f.installed.node.node_id)?.as_slice())
    );
    assert_eq!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"group")?
            .as_deref(),
        Some(serde_json::to_vec(&expected.group)?.as_slice())
    );
    assert_eq!(
        read_target_first_membership_prebind(&stores, &expected)?,
        expected
    );
    assert!(matches!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));

    stores.shutdown().await?;
    drop(stores);
    let reopened = TenantStorageSet::open_existing(
        f.node.clone(),
        lifecycle.request.tenant.clone(),
        Arc::new(LocalKeyProvider::new([40; 32])),
        Arc::new(LocalKeyProvider::new([41; 32])),
        access,
    )
    .await?;
    assert_eq!(
        read_target_first_membership_prebind(&reopened, &expected)?,
        expected
    );

    // A second valid signed dispatch can reserve a different phase, but its
    // candidate cannot survive substitution of its accepted canonical row.
    let (later_lifecycle, later_phase, later_request) = signed_initial_dispatch(&f, true)?;
    let Decision::NewlyAccepted(later) = f.dispatch(
        &journal,
        &f.installed.root,
        &later_phase,
        &later_lifecycle,
        &later_request,
    )?
    else {
        anyhow::bail!("second signed dispatch returned no one-use candidate")
    };
    let later =
        later.verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
    let key = format!(
        "dispatch/{}/{}",
        later_phase.operation_id, later_phase.phase_id
    );
    let accepted = f
        .store
        .get_bounded(NS, key.as_bytes(), MAX_RECORD)?
        .context("second accepted dispatch absent")?;
    let mut changed: serde_json::Value = serde_json::from_slice(&accepted)?;
    changed["phase"]["effect_attempts"]["target_command"]["attempt_id"] =
        serde_json::json!(Uuid::new_v4());
    let changed: super::dispatch::AcceptedInitialDispatch = serde_json::from_value(changed)?;
    let substituted = serde_json::to_vec(&changed)?;
    journal.validate_dispatch_record(key.as_bytes(), &substituted)?;
    assert_ne!(accepted, substituted);
    write_plaintext_copy_for_fixture(&f.store, NS, key.as_bytes(), &substituted)?;
    let error = later
        .persist_target_raft_prebind(&journal, &reopened)
        .err()
        .context("substituted accepted row unexpectedly wrote a Raft prebind")?;
    assert!(
        error
            .to_string()
            .contains("historical target dispatch differs from accepted row"),
        "unexpected substituted-row failure: {error:#}"
    );
    assert_eq!(
        read_target_first_membership_prebind(&reopened, &expected)?,
        expected
    );

    // The reopened reader also rejects a canonical local row with a changed
    // dispatch, the same comparison used before opt-in target Raft startup.
    let mut local_substitution = expected.clone();
    local_substitution.dispatch.attempt_id = Uuid::new_v4();
    write_plaintext_copy_for_fixture(
        reopened.custody().store(),
        TARGET_PREBIND_NAMESPACE,
        TARGET_PREBIND_KEY,
        &serde_json::to_vec(&local_substitution)?,
    )?;
    assert!(read_target_first_membership_prebind(&reopened, &expected).is_err());
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn first_prebind_rejects_partial_or_competing_raft_identity_without_repair() -> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    for mutation in [
        WriteOp::delete("raft.meta", b"node_id"),
        WriteOp::delete("raft.meta", b"group"),
        WriteOp::put("raft.meta", b"node_id", serde_json::to_vec(&2_u64)?),
        WriteOp::put(
            "raft.meta",
            b"group",
            serde_json::to_vec("acme/other-incarnation")?,
        ),
        WriteOp::put("raft.meta", b"applied", b"prior consensus progress"),
    ] {
        let f = Fixture::new().await?;
        let journal = f.create()?;
        let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
        let Decision::NewlyAccepted(candidate) =
            f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
        else {
            anyhow::bail!("signed first dispatch returned no one-use candidate")
        };
        let verified = candidate
            .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
        let (stores, _) =
            target_prebind_stores(&f, &lifecycle, verified.bootstrap_sha256()).await?;
        kasumi_store::test_utils::inject_authenticated_rows_below_facade(
            &stores,
            &[],
            &[mutation],
        )?;
        let before = stores.custody().store().scan("raft.meta")?;
        let error = verified
            .persist_target_raft_prebind(&journal, &stores)
            .err()
            .context("partial Raft identity unexpectedly consumed one-use prebind")?;
        assert!(
            error
                .to_string()
                .contains("target Raft prebind installed group differs")
                || error
                    .to_string()
                    .contains("target Raft metadata is not a pristine materialized identity"),
            "unexpected partial-identity failure: {error:#}"
        );
        assert!(
            stores
                .custody()
                .store()
                .get("raft.meta", kasumi_raft::TARGET_PREBIND_KEY)?
                .is_none()
        );
        assert_eq!(stores.custody().store().scan("raft.meta")?, before,);
        stores.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn historical_initial_membership_requires_exact_control_journal_and_applied_custody()
-> FixtureResult<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        return Err(anyhow::anyhow!("first dispatch returned no one-use candidate").into());
    };
    let identity = candidate.identity().clone();
    let verified = candidate
        .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
    let (stores, _) = target_prebind_stores(&f, &lifecycle, verified.bootstrap_sha256()).await?;
    let expected = verified.persist_target_raft_prebind(&journal, &stores)?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "prebind and accepted row alone cannot resolve first membership"
    );
    let first = kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
        Some(&fixture_initial_cause(&f, &lifecycle, &phase, &request)?),
    )
    .await?;
    assert!(
        kasumi_raft::read_initialization_association(&stores)?.is_some(),
        "target first membership must atomically retain its original cause"
    );
    let resolved = journal
        .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    assert_eq!(resolved.identity(), &identity);
    assert_eq!(resolved.local().first_log_id(), first);
    assert_eq!(resolved.local().applied_log_id(), first);
    assert_eq!(resolved.local().committed_log_id(), first);
    let mut other_lifecycle = lifecycle.clone();
    other_lifecycle.accepted_at_ms += 1;
    let other_control = f.verified_control(&other_lifecycle)?;
    assert!(
        journal
            .resolve_initial_membership_history(
                &other_control,
                &phase,
                &identity,
                &request,
                &stores,
            )
            .is_err(),
        "a different valid signed Control original cannot reuse this row"
    );

    let key = format!("dispatch/{}/{}", identity.operation_id, identity.phase_id);
    let original = f
        .store
        .get_bounded(NS, key.as_bytes(), MAX_RECORD)?
        .context("accepted journal row absent")?;
    let mut substituted: serde_json::Value = serde_json::from_slice(&original)?;
    substituted["phase"]["effect_attempts"]["target_command"]["attempt_id"] =
        serde_json::json!(Uuid::new_v4());
    let substituted: super::dispatch::AcceptedInitialDispatch =
        serde_json::from_value(substituted)?;
    let substituted = serde_json::to_vec(&substituted)?;
    journal.validate_dispatch_record(key.as_bytes(), &substituted)?;
    write_plaintext_copy_for_fixture(&f.store, NS, key.as_bytes(), &substituted)?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "a different valid journal row cannot inherit the applied fact"
    );
    write_plaintext_copy_for_fixture(&f.store, NS, key.as_bytes(), original.as_bytes())?;
    stores.custody().store().write_batch(&[WriteOp::delete(
        kasumi_raft::TARGET_PREBIND_NAMESPACE,
        b"target_first_membership_association",
    )])?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "deleted local association cannot be inferred from the applied cursor"
    );
    stores.custody().store().write_batch(&[WriteOp::delete(
        kasumi_raft::TARGET_PREBIND_NAMESPACE,
        kasumi_raft::TARGET_PREBIND_KEY,
    )])?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "deleted local prebind cannot be reconstructed from the journal"
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn first_membership_terminal_requires_history_and_uses_original_reserved_capacity()
-> FixtureResult<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        return Err(anyhow::anyhow!("first dispatch returned no one-use candidate").into());
    };
    let identity = candidate.identity().clone();
    let candidate = candidate.verify_initial_membership(1, LifecyclePhase::Initialize)?;
    let (stores, _) = target_prebind_stores(&f, &lifecycle, candidate.bootstrap_sha256()).await?;
    let expected = candidate.persist_target_raft_prebind(&journal, &stores)?;
    let terminal_key = format!(
        "dispatch-terminal/{}/{}",
        identity.operation_id, identity.phase_id
    );
    let before = f.store.get(NS, b"metadata")?.unwrap();
    assert!(
        journal
            .record_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "accepted dispatch and prebind alone cannot terminalize a first membership"
    );
    assert!(f.store.get(NS, terminal_key.as_bytes())?.is_none());
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(before.as_bytes())
    );
    let first = kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
        Some(&fixture_initial_cause(&f, &lifecycle, &phase, &request)?),
    )
    .await?;
    let before: Metadata = decode_current(&before)?;
    drop(journal);
    // Occupy all admitted capacity with the original reservation. Positive
    // terminal publication must not request additional permanent space.
    let journal = TargetJournal::open_existing(
        f.store.clone(),
        f.installed.clone(),
        TargetJournalLimits {
            max_metadata_bytes: before.charged_bytes,
        },
        f.admission.clone(),
    )?;
    let history = journal
        .record_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    assert_eq!(history.local().first_log_id(), first);
    let terminal = f.store.get(NS, terminal_key.as_bytes())?.unwrap();
    let after: Metadata = decode_current(&f.store.get(NS, b"metadata")?.unwrap())?;
    assert_eq!(after.dispatch_terminals, 1);
    assert_eq!(after.dispatches, before.dispatches);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert!(terminal.len() as u64 <= DISPATCH_TERMINAL_RESERVE);
    journal.record_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    assert_eq!(
        f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
        Some(terminal.as_bytes())
    );
    assert_eq!(
        decode_current::<Metadata>(&f.store.get(NS, b"metadata")?.unwrap())?,
        after
    );
    assert!(matches!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));
    drop(journal);
    let journal = f.reopen()?;
    journal.record_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    assert_eq!(
        f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
        Some(terminal.as_bytes())
    );
    stores.shutdown().await?;
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn first_membership_terminal_rejects_substitution_missing_custody_and_torn_accounting()
-> FixtureResult<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        return Err(anyhow::anyhow!("first dispatch returned no one-use candidate").into());
    };
    let identity = candidate.identity().clone();
    let candidate = candidate.verify_initial_membership(1, LifecyclePhase::Initialize)?;
    let (stores, _) = target_prebind_stores(&f, &lifecycle, candidate.bootstrap_sha256()).await?;
    let expected = candidate.persist_target_raft_prebind(&journal, &stores)?;
    kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
        Some(&fixture_initial_cause(&f, &lifecycle, &phase, &request)?),
    )
    .await?;
    journal.record_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    let terminal_key = format!(
        "dispatch-terminal/{}/{}",
        identity.operation_id, identity.phase_id
    );
    let original = f.store.get(NS, terminal_key.as_bytes())?.unwrap();
    let original_head = f.store.get(NS, b"metadata")?.unwrap();

    let mut other = lifecycle.clone();
    other.accepted_at_ms += 1;
    assert!(
        journal
            .record_initial_membership_history(
                &f.verified_control(&other)?,
                &phase,
                &identity,
                &request,
                &stores,
            )
            .is_err()
    );
    assert_eq!(
        f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
        Some(original.as_bytes())
    );

    let association_key = b"target_first_membership_association";
    let association = stores
        .custody()
        .store()
        .get("raft.meta", association_key)?
        .unwrap();
    stores
        .custody()
        .store()
        .write_batch(&[WriteOp::delete("raft.meta", association_key)])?;
    assert!(
        journal
            .record_initial_membership_history(&control, &phase, &identity, &request, &stores,)
            .is_err(),
        "terminal alone cannot replace missing atomic Raft association"
    );
    assert_eq!(
        f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
        Some(original.as_bytes())
    );
    write_plaintext_copy_for_fixture(
        stores.custody().store(),
        "raft.meta",
        association_key,
        association.as_bytes(),
    )?;
    drop(journal);

    for (field, value) in [
        ("journal_row_sha256", serde_json::json!("11".repeat(32))),
        ("prebind_sha256", serde_json::json!("22".repeat(32))),
        ("format", serde_json::json!(2)),
    ] {
        let mut invalid: serde_json::Value = serde_json::from_slice(&original)?;
        invalid[field] = value;
        let invalid: super::dispatch::InitialMembershipTerminal = serde_json::from_value(invalid)?;
        let invalid = serde_json::to_vec(&invalid)?;
        write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), &invalid)?;
        assert!(f.reopen().is_err(), "substituted terminal {field} reopened");
        assert_eq!(
            f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
            Some(invalid.as_slice())
        );
        write_plaintext_copy_for_fixture(
            &f.store,
            NS,
            terminal_key.as_bytes(),
            original.as_bytes(),
        )?;
    }
    let padded = FixturePlaintextCopy::with_suffix(&f.store, original.as_bytes(), b" ")?;
    write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), padded.as_bytes())?;
    assert!(f.reopen().is_err(), "noncanonical terminal reopened");
    write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), original.as_bytes())?;

    // A canonical terminal digest is still only retained observation. Exact
    // live local history must detect substitution at the same log position.
    let mut invalid: serde_json::Value = serde_json::from_slice(&original)?;
    invalid["first_fact_sha256"] = serde_json::json!("33".repeat(32));
    let invalid: super::dispatch::InitialMembershipTerminal = serde_json::from_value(invalid)?;
    let invalid = serde_json::to_vec(&invalid)?;
    write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), &invalid)?;
    let journal = f.reopen()?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores,)
            .is_err()
    );
    assert!(
        journal
            .record_initial_membership_history(&control, &phase, &identity, &request, &stores,)
            .is_err()
    );
    assert_eq!(
        f.store.get(NS, terminal_key.as_bytes())?.as_deref(),
        Some(invalid.as_slice())
    );
    drop(journal);
    write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), original.as_bytes())?;

    f.store
        .write_batch(&[WriteOp::delete(NS, terminal_key.as_bytes())])?;
    assert!(
        f.reopen().is_err(),
        "missing terminal with counted publication reopened"
    );
    write_plaintext_copy_for_fixture(&f.store, NS, terminal_key.as_bytes(), original.as_bytes())?;
    let mut invalid: Metadata = decode_current(&original_head)?;
    invalid.dispatch_terminals = 0;
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", &serde_json::to_vec(&invalid)?)?;
    assert!(
        f.reopen().is_err(),
        "terminal without counted publication reopened"
    );
    invalid.format = 2;
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", &serde_json::to_vec(&invalid)?)?;
    assert!(
        f.reopen().is_err(),
        "retired format cannot be upgraded during reopen"
    );
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original_head.as_bytes())?;
    let journal = f.reopen()?;
    journal.resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    stores.shutdown().await?;
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn marked_initial_dispatch_requires_exact_phase_attempt_and_lifecycle() -> Result<()> {
    use kasumi_types::{RecoveryEffect, TargetInitialDispatchIdentity};
    let f = Fixture::new().await?;
    let journal = f.create()?;
    for initialize in [false, true] {
        let (lifecycle, phase, request) = initial_dispatch(&f, initialize)?;
        let identity = TargetInitialDispatchIdentity {
            operation_id: phase.operation_id,
            phase_id: phase.phase_id,
            attempt_id: phase.effect_attempts[&RecoveryEffect::TargetCommand].attempt_id,
            input_sha256: phase.input_sha256.clone(),
        };
        identity.validate_marked_phase(
            &f.installed.root,
            f.installed.node.node_id,
            &request,
            &lifecycle,
            &phase,
        )?;
        let mut wrong = identity.clone();
        wrong.attempt_id = Uuid::new_v4();
        assert!(
            wrong
                .validate_marked_phase(
                    &f.installed.root,
                    f.installed.node.node_id,
                    &request,
                    &lifecycle,
                    &phase,
                )
                .is_err()
        );
        let mut unmarked = phase.clone();
        unmarked.effect_attempts.clear();
        unmarked.validate()?;
        assert!(
            identity
                .validate_marked_phase(
                    &f.installed.root,
                    f.installed.node.node_id,
                    &request,
                    &lifecycle,
                    &unmarked,
                )
                .is_err()
        );
        let mut wrong_lifecycle = lifecycle.clone();
        wrong_lifecycle.request.command_id = Uuid::new_v4();
        assert!(
            identity
                .validate_marked_phase(
                    &f.installed.root,
                    f.installed.node.node_id,
                    &request,
                    &wrong_lifecycle,
                    &phase,
                )
                .is_err()
        );
    }
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn current_intent_and_generation_require_current_writer_bytes_on_reopen() -> Result<()> {
    let provider = Arc::new(LocalKeyProvider::new([39; 32]));
    let f = Fixture::with_provider(provider.clone()).await?;
    let journal = f.create()?;
    let (mut lifecycle, _, _) = initial_dispatch(&f, true)?;
    let partition = ControlAuthorityPartition {
        authority_id: Uuid::new_v4(),
        manifest_sha256: "aa".repeat(32),
        partition: 0,
        signing_public_key: "bb".repeat(32),
        maximum_lifetime_ms: 1_000,
        drain_ms: 1_000,
    };
    lifecycle.request.authority_partition = partition.key();
    lifecycle.request_sha256 = kasumi_serving::digest(&lifecycle.request)?;
    let intent = TargetJournalIntent {
        intent: lifecycle,
        authority_partition: partition,
        partition_set_sha256: "cc".repeat(32),
        node: f.installed.node.clone(),
    };
    journal.validate_intent(&intent)?;
    let binding = GenerationBinding::from_intent(&intent);
    let token = kasumi_query::QueryCancellation::default();
    let mut catalogs = Vec::new();
    journal.visit_key_dependencies(
        &token,
        |row| {
            ensure!(
                matches!(
                    row.reference,
                    kasumi_types::KeyReference::Catalog {
                        node_id: 1,
                        domain: kasumi_types::KeyCatalogDomain::TargetJournal,
                        ..
                    }
                ),
                "empty journal returned an unowned reference"
            );
            catalogs.push(row.key);
            Ok(())
        },
        |_, _| anyhow::bail!("empty journal returned a checkpoint"),
    )?;
    assert!(!catalogs.is_empty());
    let intent_key = intent_key(intent.intent.request.command_id);
    let generation_key = generation_key(&binding.tenant, binding.target_incarnation);
    let intent_bytes = serde_json::to_vec(&intent)?;
    let generation_bytes = serde_json::to_vec(&binding)?;
    let mut head: Metadata = serde_json::from_slice(&f.store.get(NS, b"metadata")?.unwrap())?;
    head.intents = 1;
    head.generations = 1;
    head.charged_bytes += intent_bytes.len() as u64
        + COMPLETION_RESERVE
        + generation_bytes.len() as u64
        + GENERATION_RESERVE;
    let head_bytes = serde_json::to_vec(&head)?;
    write_plaintext_copy_for_fixture(&f.store, NS, &intent_key, &intent_bytes)?;
    assert_eq!(provider.rotate(), 2);
    f.store.rotate_data_key().await?;
    FixtureWriteBatch::prepare(
        &f.store,
        &[
            FixtureWrite::Put(NS, &generation_key, &generation_bytes),
            FixtureWrite::Put(NS, b"metadata", &head_bytes),
        ],
    )?
    .write(&f.store)?;
    drop(journal);
    let reopened = f.reopen()?;
    let mut dependencies = Vec::new();
    let mut record_keys = Vec::new();
    let authenticated = reopened.visit_key_dependencies(
        &token,
        |row| {
            if let kasumi_types::KeyReference::TargetJournal {
                node_id,
                incarnation,
            } = row.reference
            {
                ensure!(
                    node_id == 1 && incarnation == binding.target_incarnation,
                    "unrelated journal reference"
                );
                record_keys.push(row.key);
            }
            Ok(())
        },
        |id, checkpoint| {
            dependencies.push((id, checkpoint.clone()));
            Ok(())
        },
    )?;
    assert_eq!(
        dependencies,
        [(binding.target_incarnation, binding.checkpoint)]
    );
    assert_eq!(record_keys.len(), 2);
    assert_eq!(
        record_keys
            .iter()
            .map(|key| key.version)
            .collect::<std::collections::BTreeSet<_>>(),
        [1, 2].into()
    );
    assert!(record_keys.iter().any(|key| catalogs.contains(key)));
    let original = f.store.get(NS, b"metadata")?.unwrap();
    let mut false_head = head.clone();
    false_head.generations = 0;
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", &serde_json::to_vec(&false_head)?)?;
    assert!(
        reopened
            .visit_key_dependencies(&token, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original.as_bytes())?;
    assert_eq!(
        reopened.visit_key_dependencies(&token, |_| Ok(()), |_, _| Ok(()))?,
        authenticated
    );
    token.cancel();
    assert!(
        reopened
            .visit_key_dependencies(&token, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
    drop(reopened);

    for (key, original) in [
        (intent_key, intent_bytes),
        (generation_key, generation_bytes),
    ] {
        let alternate = FixturePlaintextCopy::with_suffix(&f.store, &original, b" ")?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&alternate)?,
            serde_json::from_slice::<serde_json::Value>(&original)?
        );
        let mut alternate_head = head.clone();
        alternate_head.charged_bytes += 1;
        FixtureWriteBatch::prepare(
            &f.store,
            &[
                FixtureWrite::Put(NS, &key, alternate.as_bytes()),
                FixtureWrite::Put(NS, b"metadata", &serde_json::to_vec(&alternate_head)?),
            ],
        )?
        .write(&f.store)?;
        let error = f.reopen().err().expect("alternate journal row must reject");
        assert!(
            format!("{error:#}").contains("noncanonical target journal record"),
            "{error:#}"
        );
        assert_eq!(
            f.store.get(NS, &key)?.as_deref(),
            Some(alternate.as_bytes())
        );
        FixtureWriteBatch::prepare(
            &f.store,
            &[
                FixtureWrite::Put(NS, &key, &original),
                FixtureWrite::Put(NS, b"metadata", &head_bytes),
            ],
        )?
        .write(&f.store)?;
    }
    f.reopen()?.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn serving_candidate_point_read_and_reopen_reject_alternate_json() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let candidate = serde_json::json!({
        "tenant": "documents",
        "incarnation": Uuid::new_v4(),
        "source_epoch": 1,
        "projection_sha256": "dd".repeat(32),
    });
    let key = b"serving/documents";
    let mut alternate = serde_json::to_vec(&candidate)?;
    alternate.push(b' ');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&alternate)?,
        candidate
    );
    write_plaintext_copy_for_fixture(&f.store, NS, key, &alternate)?;
    let point_error = journal
        .serving_candidate("documents")
        .expect_err("alternate candidate point read must reject");
    assert!(
        format!("{point_error:#}").contains("noncanonical target journal record"),
        "{point_error:#}"
    );
    drop(journal);
    let reopen_error = f
        .reopen()
        .err()
        .expect("alternate candidate startup scan must reject");
    assert!(
        format!("{reopen_error:#}").contains("noncanonical target journal record"),
        "{reopen_error:#}"
    );
    assert_eq!(f.store.get(NS, key)?.as_deref(), Some(alternate.as_slice()));
    f.store.write_batch(&[WriteOp::delete(NS, key)])?;
    f.reopen()?.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn exact_dispatch_reservation_is_one_use_and_reopen_recounts_terminal_capacity() -> Result<()>
{
    use super::dispatch::{
        InitialDispatchReservation as Decision, InitialDispatchStatus as Status,
    };
    use kasumi_types::{RecoveryEffect, TargetInitialDispatchIdentity};
    use sha2::Digest;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = initial_dispatch(&f, false)?;
    let attempt_id = phase
        .effect_attempts
        .get(&RecoveryEffect::TargetCommand)
        .unwrap()
        .attempt_id;
    let identity = TargetInitialDispatchIdentity {
        operation_id: phase.operation_id,
        phase_id: phase.phase_id,
        attempt_id,
        input_sha256: phase.input_sha256.clone(),
    };
    assert_eq!(
        journal.read_initial_dispatch_status(&f.installed.root, &identity, &request)?,
        Status::NoLocalRecord
    );
    let mut wrong_digest = identity.clone();
    wrong_digest.input_sha256 = "ff".repeat(32);
    assert!(
        journal
            .read_initial_dispatch_status(&f.installed.root, &wrong_digest, &request)
            .is_err()
    );
    let first = f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?;
    let Decision::NewlyAccepted(prebind) = first else {
        anyhow::bail!("first exact dispatch did not return a one-use prebind")
    };
    assert_eq!(prebind.identity(), &identity);
    assert_eq!(prebind.control_root(), &f.installed.root);
    assert_eq!(prebind.node(), &f.installed.node);
    assert_eq!(prebind.tenant(), lifecycle.request.tenant.as_str());
    assert_eq!(
        prebind.target_incarnation(),
        lifecycle.request.target_incarnation
    );
    assert_eq!(prebind.request(), &request);
    let exact_row = f
        .store
        .get(
            NS,
            format!("dispatch/{}/{}", phase.operation_id, phase.phase_id).as_bytes(),
        )?
        .context("accepted dispatch row absent")?;
    let row_sha256 = hex::encode(sha2::Sha256::digest(&exact_row));
    assert_eq!(prebind.journal_row_sha256(), row_sha256.as_str());
    assert_eq!(
        journal.read_initial_dispatch_status(&f.installed.root, &identity, &request)?,
        Status::AcceptedOnly
    );
    let mut wrong_attempt = identity.clone();
    wrong_attempt.attempt_id = Uuid::new_v4();
    assert!(
        journal
            .read_initial_dispatch_status(&f.installed.root, &wrong_attempt, &request)
            .is_err()
    );
    let metadata_before = f.store.get(NS, b"metadata")?.unwrap();
    let mut damaged_head: Metadata = serde_json::from_slice(&metadata_before)?;
    damaged_head.format = 1;
    write_plaintext_copy_for_fixture(
        &f.store,
        NS,
        b"metadata",
        &serde_json::to_vec(&damaged_head)?,
    )?;
    assert!(
        journal
            .read_initial_dispatch_status(&f.installed.root, &identity, &request)
            .is_err()
    );
    assert!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)
            .is_err()
    );
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", metadata_before.as_bytes())?;
    assert!(matches!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));
    assert_eq!(
        f.store.get(NS, b"metadata")?.as_deref(),
        Some(metadata_before.as_bytes())
    );
    let mut changed = phase.clone();
    changed
        .effect_attempts
        .get_mut(&RecoveryEffect::TargetCommand)
        .unwrap()
        .attempt_id = Uuid::new_v4();
    changed.validate()?;
    assert!(
        f.dispatch(&journal, &f.installed.root, &changed, &lifecycle, &request)
            .is_err()
    );
    let mut wrong_root = f.installed.root.clone();
    wrong_root.public_key = "ff".repeat(32);
    assert!(
        f.dispatch(&journal, &wrong_root, &phase, &lifecycle, &request)
            .is_err()
    );
    let (initialize_lifecycle, initialize_phase, initialize_request) = initial_dispatch(&f, true)?;
    let stopped_key = stop_key(
        &initialize_lifecycle.request.tenant,
        initialize_lifecycle.request.target_incarnation,
    );
    write_plaintext_copy_for_fixture(&f.store, NS, &stopped_key, b"{}")?;
    assert!(
        f.dispatch(
            &journal,
            &f.installed.root,
            &initialize_phase,
            &initialize_lifecycle,
            &initialize_request
        )
        .is_err()
    );
    f.store.write_batch(&[WriteOp::delete(NS, stopped_key)])?;
    assert!(matches!(
        f.dispatch(
            &journal,
            &f.installed.root,
            &initialize_phase,
            &initialize_lifecycle,
            &initialize_request
        )?,
        Decision::NewlyAccepted(_)
    ));
    let metadata: Metadata = serde_json::from_slice(&f.store.get(NS, b"metadata")?.unwrap())?;
    assert_eq!(metadata.format, 5);
    assert_eq!(metadata.dispatches, 2);
    assert_eq!(metadata.dispatch_terminals, 0);
    assert_eq!(metadata.dispatch_starts, 0);
    assert_eq!(metadata.dispatch_initializes, 0);
    assert!(metadata.charged_bytes >= MAX_RECORD as u64 + 2 * DISPATCH_TERMINAL_RESERVE);
    drop(journal);
    let reopened = f.reopen()?;
    assert!(matches!(
        f.dispatch(&reopened, &f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn previous_formats_and_corrupt_dispatch_or_accounting_fail_closed_on_reopen() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = initial_dispatch(&f, false)?;
    f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?;
    drop(journal);
    let original_head = f.store.get(NS, b"metadata")?.unwrap();
    let key = format!("dispatch/{}/{}", phase.operation_id, phase.phase_id).into_bytes();
    let original_row = f.store.get(NS, &key)?.unwrap();
    for format in 1..4 {
        let mut old: Metadata = serde_json::from_slice(&original_head)?;
        old.format = format;
        write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", &serde_json::to_vec(&old)?)?;
        assert!(
            f.reopen().is_err(),
            "retired journal format {format} reopened"
        );
    }
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original_head.as_bytes())?;
    let mut missing_field: serde_json::Value = serde_json::from_slice(&original_head)?;
    missing_field.as_object_mut().unwrap().remove("dispatches");
    write_plaintext_copy_for_fixture(
        &f.store,
        NS,
        b"metadata",
        &serde_json::to_vec(&missing_field)?,
    )?;
    assert!(f.reopen().is_err());
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original_head.as_bytes())?;
    let mut wrong_count: Metadata = serde_json::from_slice(&original_head)?;
    wrong_count.dispatches = 0;
    write_plaintext_copy_for_fixture(
        &f.store,
        NS,
        b"metadata",
        &serde_json::to_vec(&wrong_count)?,
    )?;
    assert!(f.reopen().is_err());
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original_head.as_bytes())?;
    let mut wrong_bytes: Metadata = serde_json::from_slice(&original_head)?;
    wrong_bytes.charged_bytes -= 1;
    write_plaintext_copy_for_fixture(
        &f.store,
        NS,
        b"metadata",
        &serde_json::to_vec(&wrong_bytes)?,
    )?;
    assert!(f.reopen().is_err());
    write_plaintext_copy_for_fixture(&f.store, NS, b"metadata", original_head.as_bytes())?;
    let noncanonical = FixturePlaintextCopy::with_suffix(&f.store, original_row.as_bytes(), b" ")?;
    write_plaintext_copy_for_fixture(&f.store, NS, &key, noncanonical.as_bytes())?;
    assert!(f.reopen().is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&original_row)?;
    altered["phase"]["effect_attempts"]["target_command"]["input_sha256"] =
        serde_json::Value::String("ff".repeat(32));
    write_plaintext_copy_for_fixture(&f.store, NS, &key, &serde_json::to_vec(&altered)?)?;
    assert!(f.reopen().is_err());
    FixtureWriteBatch::prepare(
        &f.store,
        &[
            FixtureWrite::Delete(NS, &key),
            FixtureWrite::Put(NS, b"dispatch/foreign/phase", original_row.as_bytes()),
        ],
    )?
    .write(&f.store)?;
    assert!(f.reopen().is_err());
    FixtureWriteBatch::prepare(
        &f.store,
        &[
            FixtureWrite::Delete(NS, b"dispatch/foreign/phase"),
            FixtureWrite::Put(NS, &key, original_row.as_bytes()),
        ],
    )?
    .write(&f.store)?;
    let reopened = f.reopen()?;
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn terminal_reserve_failure_never_writes_an_accepted_dispatch() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = TargetJournal::create_new(
        f.store.clone(),
        f.installed.clone(),
        TargetJournalLimits {
            max_metadata_bytes: 2 * MAX_RECORD as u64,
        },
        f.admission.clone(),
    )?;
    let (lifecycle, phase, request) = initial_dispatch(&f, false)?;
    assert!(
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)
            .is_err()
    );
    let metadata: Metadata = serde_json::from_slice(&f.store.get(NS, b"metadata")?.unwrap())?;
    assert_eq!(metadata.dispatches, 0);
    assert_eq!(metadata.charged_bytes, MAX_RECORD as u64);
    assert!(
        f.store
            .get(
                NS,
                format!("dispatch/{}/{}", phase.operation_id, phase.phase_id).as_bytes()
            )?
            .is_none()
    );
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn target_first_entry_rejects_missing_invalid_and_substituted_original_cause() -> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    use kasumi_types::*;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let Decision::NewlyAccepted(candidate) =
        f.dispatch(&journal, &f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("candidate absent")
    };
    let candidate = candidate.verify_initial_membership(1, LifecyclePhase::Initialize)?;
    let (stores, _) = target_prebind_stores(&f, &lifecycle, candidate.bootstrap_sha256()).await?;
    let expected = candidate.persist_target_raft_prebind(&journal, &stores)?;
    let valid = fixture_initial_cause(&f, &lifecycle, &phase, &request)?;
    let mut bad_signature = valid.clone();
    bad_signature.signature = "00".repeat(64);
    let mut replaced = valid.clone();
    replaced.association.start.phase_id = Uuid::new_v4();
    replaced.signature = crate::target_completion_machine::tests::sign(
        &replaced.association,
        "kasumi.target-initialization-association.v1",
        1,
    );
    replaced.association.validate()?;
    for cause in [None, Some(&bad_signature), Some(&replaced)] {
        let before = stores.custody().store().scan("raft.meta")?;
        assert!(
            kasumi_raft::historical_test_utils::publish_committed_first_membership(
                stores.clone(),
                &expected,
                cause
            )
            .await
            .is_err(),
            "invalid first cause admitted"
        );
        assert_eq!(stores.custody().store().scan("raft.meta")?, before);
        assert!(stores.custody().store().scan("raft.headers")?.is_empty());
        assert!(kasumi_raft::read_initialization_association(&stores)?.is_none());
    }
    let first = kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
        Some(&valid),
    )
    .await?;
    let retained = kasumi_raft::read_initialization_association(&stores)?.unwrap();
    assert_eq!(retained.signed, valid);
    assert_eq!(first.index, retained.position.index);
    assert_eq!(first.index, 0);
    stores.shutdown().await?;
    Ok(())
}

// A cleanup record exists only after its permanent stop, and a file binding
// only for a target file the journal's original materialization created.
#[tokio::test]
async fn cleanup_and_binding_records_require_their_stop_and_original_creation() -> Result<()> {
    let f = Fixture::new().await?;
    drop(f.create()?);
    let target = Uuid::new_v4();
    let cleanup = TargetCleanup {
        tenant: "documents".into(),
        target_incarnation: target,
        stage: TargetCleanupStage::Deleted,
        binding: None,
    };
    let key = cleanup_key("documents", target);
    write_plaintext_copy_for_fixture(&f.store, NS, &key, serde_json::to_vec(&cleanup)?.as_slice())?;
    let error = f
        .reopen()
        .err()
        .expect("cleanup without a stop must reject");
    assert!(
        format!("{error:#}").contains("target cleanup precedes its permanent stop"),
        "{error:#}"
    );
    f.store.write_batch(&[WriteOp::delete(NS, key)])?;
    let binding = TargetFileBinding {
        tenant: "documents".into(),
        target_incarnation: target,
        path: f.directory.path().join("persistent/targets/target.kv"),
        directory: kasumi_store::private_files::directory_identity(f.directory.path())?,
        directory_stamp: None,
        node_store_id: kasumi_store::node_store_ids::target_generation(
            f.installed.root.control_incarnation,
            "documents",
            target,
            &f.installed.node.verifier,
        )?,
    };
    let key = binding_key("documents", target);
    write_plaintext_copy_for_fixture(&f.store, NS, &key, serde_json::to_vec(&binding)?.as_slice())?;
    let error = f
        .reopen()
        .err()
        .expect("binding without its creation must reject");
    assert!(
        format!("{error:#}").contains("no original creation"),
        "{error:#}"
    );
    f.store.write_batch(&[WriteOp::delete(NS, key)])?;
    f.reopen()?.shutdown().await?;
    Ok(())
}

/// The durable cut contains the original materialization, its exact physical
/// binding, an issuer-signed permanent stop, and the last published cleanup
/// stage. Reopen from the encrypted native files after dropping every handle.
#[tokio::test]
async fn stopped_cleanup_recovers_its_original_binding_after_native_reopen() -> Result<()> {
    use kasumi_serving::{
        AuthorityAction, AuthorityCommand, AuthorityManifest, AuthorityOutcome, AuthorityPartition,
        AuthorityReceipt, RecoveryTarget, TargetStopObservation, TargetStopReference,
    };
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (mut lifecycle, mut marked, mut packet) = initial_dispatch(&f, true)?;
    let signing_key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture signing key generation failed"))?;
    let root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(signing_key.as_ref())?;
    let authority = AuthorityManifest {
        lifecycle_controls: [(
            f.installed.root.control_incarnation,
            f.installed.root.public_key.clone(),
        )]
        .into(),
        authority_id: Uuid::new_v4(),
        max_lease_ms: 60_000,
        clock_rate_error_ppm: 0,
        partitions: [(
            0,
            AuthorityPartition {
                group: "cleanup".into(),
                public_key: root.public_key(),
            },
        )]
        .into(),
    };
    let issuer = root
        .install(authority.clone(), 0)?
        .for_verifier(f.installed.node.verifier.clone())?;
    let partition = authority.control_partition(0)?;
    lifecycle.request.authority_partition = partition.key();
    lifecycle.request.phase = LifecyclePhase::Materialize;
    lifecycle.request_sha256 = kasumi_serving::digest(&lifecycle.request)?;
    let intent = TargetJournalIntent {
        intent: lifecycle.clone(),
        authority_partition: partition,
        partition_set_sha256: "cc".repeat(32),
        node: f.installed.node.clone(),
    };
    let request = &lifecycle.request;
    let tenant = request.tenant.clone();
    let incarnation = request.target_incarnation;
    let source_incarnation = request.source_incarnation;
    let source_epoch = request.source_authority_epoch;
    let target = RecoveryTarget {
        incarnation,
        checkpoint: request.checkpoint.clone(),
        nodes: request
            .target_nodes
            .values()
            .map(|node| NodeIdentity {
                node_id: node.node_id,
                verifier: node.verifier.clone(),
                principal: node.principal.clone(),
                certificate_sha256: node.certificate_sha256.clone(),
            })
            .collect(),
    };
    let command = AuthorityCommand {
        tenant: tenant.clone(),
        command_id: Uuid::new_v4(),
        expected_policy_epoch: 1,
        not_after_ms: 1000,
        action: AuthorityAction::StopTarget {
            source_incarnation,
            source_epoch,
            target: target.clone(),
        },
    };
    let command_id = command.command_id;
    let receipt = AuthorityReceipt {
        authority_id: authority.authority_id,
        manifest_digest: authority.digest()?,
        partition: 0,
        command_digest: command.digest()?,
        command,
        principal: "owner".into(),
        term: 1,
        revision: 5,
        admitted_at_ms: 200,
        outcome: AuthorityOutcome::TargetStopped {
            source_incarnation,
            source_epoch,
            target,
        },
    };
    let reference = TargetStopReference {
        tenant: tenant.clone(),
        command_id,
        receipt_digest: receipt.digest()?,
    };
    let mut stop_intent = intent.clone();
    stop_intent.intent.request.command_id = Uuid::new_v4();
    stop_intent.intent.request.phase = LifecyclePhase::StopLocal;
    stop_intent.intent.request.phase_input_sha256 =
        kasumi_serving::digest(&("kasumi.stop-local-target-input.v1", &reference))?;
    stop_intent.intent.request_sha256 = kasumi_serving::digest(&stop_intent.intent.request)?;
    let stopped = issuer.signer.sign_target_stop(TargetStopObservation {
        reference,
        stop: receipt,
        observed_term: 1,
        observed_revision: 5,
        drain_ms: authority.drain_ms()?,
    })?;
    let stop = TargetJournalStop {
        intent: stop_intent,
        owner_drain: None,
        stopped,
        authority,
    };
    journal.validate_stop(&stop)?;

    {
        let before = journal.metadata()?;
        let mut head = before.clone();
        let mut terminal = GenerationBinding::from_intent(&stop.intent);
        terminal.stop_before_prepare = true;
        let bytes = serde_json::to_vec(&terminal)?;
        head.generations = 1;
        head.charged_bytes += bytes.len() as u64 + GENERATION_RESERVE + CLEANUP_RESERVE as u64;
        let cleanup = TargetCleanup {
            tenant: tenant.clone(),
            target_incarnation: incarnation,
            stage: TargetCleanupStage::Deleted,
            binding: None,
        };
        f.store.write_batch(&[
            WriteOp::put(NS, generation_key(&tenant, incarnation), bytes),
            WriteOp::put(
                NS,
                stop_key(&tenant, incarnation),
                serde_json::to_vec(&stop)?,
            ),
            WriteOp::put(
                NS,
                cleanup_key(&tenant, incarnation),
                serde_json::to_vec(&cleanup)?,
            ),
            WriteOp::put(NS, b"metadata", serde_json::to_vec(&head)?),
        ])?;
        for physically_absent in [false, true] {
            let mut unresolved = Vec::new();
            journal.visit_scoped_key_dependencies(
                &kasumi_query::QueryCancellation::default(),
                |_| Ok(()),
                |id, _, negative| {
                    unresolved.push((id, negative));
                    Ok(())
                },
                |name, id| {
                    assert_eq!((name, id), (tenant.as_str(), incarnation));
                    Ok(physically_absent)
                },
            )?;
            assert_eq!(
                unresolved,
                if physically_absent {
                    vec![]
                } else {
                    vec![(incarnation, true)]
                }
            );
        }
        f.store.write_batch(&[
            WriteOp::delete(NS, generation_key(&tenant, incarnation)),
            WriteOp::delete(NS, stop_key(&tenant, incarnation)),
            WriteOp::delete(NS, cleanup_key(&tenant, incarnation)),
            WriteOp::put(NS, b"metadata", serde_json::to_vec(&before)?),
        ])?;
    }
    let committed = &stop.intent.intent;
    let observation = kasumi_types::ControlIntentCommitment {
        intent: committed.clone(),
        root: f.installed.root.clone(),
        authority_partition: stop.intent.authority_partition.clone(),
        partition_set_sha256: stop.intent.partition_set_sha256.clone(),
        observed_policy_epoch: committed.request.expected_policy_epoch,
        observed_revision: committed.revision,
        observed_term: 1,
    };
    let verified = f.sign_control_observation(observation)?;
    packet.command_id = committed.request.command_id;
    packet.tenant = committed.request.tenant.clone();
    packet.step = kasumi_types::TargetRuntimeStep::Stop(stop.stopped.observation.reference.clone());
    marked.phase = kasumi_types::RecoveryPhase::Cleanup;
    marked.input = kasumi_types::RecoveryDispatch::Target {
        node_id: f.installed.node.node_id,
        request: Box::new(packet),
    };
    marked.input_sha256 = kasumi_types::staged_digest(&marked.input)?.0;
    marked
        .effect_attempts
        .get_mut(&kasumi_types::RecoveryEffect::TargetCommand)
        .unwrap()
        .input_sha256 = marked.input_sha256.clone();
    let query = kasumi_types::TargetDeletionQuery {
        node_id: f.installed.node.node_id,
        operation_id: marked.operation_id,
        phase_id: marked.phase_id,
        target_incarnation: incarnation,
    };

    let original = TargetFileBinding {
        tenant: tenant.clone(),
        target_incarnation: incarnation,
        path: f.directory.path().join("persistent/targets/target.kv"),
        directory: kasumi_store::private_files::directory_identity(f.directory.path())?,
        directory_stamp: Some(Uuid::new_v4()),
        node_store_id: kasumi_store::node_store_ids::target_generation(
            f.installed.root.control_incarnation,
            &tenant,
            incarnation,
            &f.installed.node.verifier,
        )?,
    };
    let cleanup = TargetCleanup {
        tenant: tenant.clone(),
        target_incarnation: incarnation,
        stage: TargetCleanupStage::Deleting,
        binding: Some(original.clone()),
    };
    let mut head = journal.metadata()?;
    let creation = serde_json::to_vec(&FileCreation {
        directory_stamp: original.directory_stamp,
        materialization_command_id: request.command_id,
    })?;
    let accepted = serde_json::to_vec(&intent)?;
    let generation = serde_json::to_vec(&GenerationBinding::from_intent(&intent))?;
    head.intents = 1;
    head.generations = 1;
    head.charged_bytes += (accepted.len() + generation.len() + creation.len()) as u64
        + COMPLETION_RESERVE
        + GENERATION_RESERVE;
    let key = cleanup_key(&tenant, incarnation);
    f.store.write_batch(&[
        WriteOp::put(NS, intent_key(request.command_id), accepted),
        WriteOp::put(NS, generation_key(&tenant, incarnation), generation),
        WriteOp::put(NS, file_key(&tenant, incarnation), creation),
        WriteOp::put(
            NS,
            stop_key(&tenant, incarnation),
            serde_json::to_vec(&stop)?,
        ),
        WriteOp::put(NS, b"metadata", serde_json::to_vec(&head)?),
    ])?;
    let mut substituted = original.clone();
    substituted.directory_stamp = Some(Uuid::new_v4());
    assert!(
        journal
            .cleanup_writes(&TargetCleanup {
                binding: Some(substituted),
                ..cleanup.clone()
            })
            .is_err()
    );
    assert!(
        journal
            .materialization_file_binding(&tenant, incarnation)?
            .is_none()
    );
    assert!(journal.target_cleanup(&tenant, incarnation)?.is_none());
    let writes = journal.cleanup_writes(&cleanup)?;
    f.store.write_batch(&writes)?;
    assert!(journal.cleanup_writes(&cleanup)?.is_empty());
    assert_eq!(
        journal.metadata()?.charged_bytes,
        head.charged_bytes + serde_json::to_vec(&original)?.len() as u64 + CLEANUP_RESERVE as u64
    );
    journal.shutdown().await?;
    f.store.shutdown().await?;
    f.node.shutdown().await?;
    drop((journal, f.store, f.node));
    let path = f.directory.path().join("persistent/journal.kv");
    let node = f
        .storage
        .open_existing(&path, f.id)
        .unwrap_or_else(|original| std::panic::panic_any(original));
    let store = TenantStore::open_existing(
        node.clone(),
        format!("kasumi.target.{}.1", f.installed.root.control_incarnation),
        Arc::new(LocalKeyProvider::new([39; 32])),
        StorageAccess::target_journal(&f.installed.root, &f.installed.node)?,
    )
    .await?;
    let reopen = || {
        TargetJournal::open_existing(
            store.clone(),
            f.installed.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            f.admission.clone(),
        )
    };
    let journal = reopen()?;
    assert_eq!(
        journal.target_cleanup(&tenant, incarnation)?,
        Some(cleanup.clone())
    );
    let observed = journal.deletion_status(&query, &verified, &marked)?;
    assert_eq!(
        observed.progress,
        kasumi_types::TargetDeletionProgress::Deleting
    );
    assert_eq!(
        observed.binding_sha256,
        Some(kasumi_serving::digest(&original)?)
    );
    let mut other = query.clone();
    other.phase_id = Uuid::new_v4();
    assert!(journal.deletion_status(&other, &verified, &marked).is_err());
    let mut no_attempt = marked.clone();
    no_attempt.effect_attempts.clear();
    assert!(
        journal
            .deletion_status(&query, &verified, &no_attempt)
            .is_err()
    );
    drop(journal);
    let mut terminal = cleanup;
    for (stage, expected) in [
        (
            TargetCleanupStage::Unlinked,
            kasumi_types::TargetDeletionProgress::Unlinked,
        ),
        (
            TargetCleanupStage::ParentSynced,
            kasumi_types::TargetDeletionProgress::ParentSynced,
        ),
        (
            TargetCleanupStage::Deleted,
            kasumi_types::TargetDeletionProgress::Deleted,
        ),
    ] {
        terminal.stage = stage;
        store.write_batch(&[WriteOp::put(
            NS,
            key.clone(),
            serde_json::to_vec(&terminal)?,
        )])?;
        let next = reopen()?.deletion_status(&query, &verified, &marked)?;
        assert_eq!(next.progress, expected);
        assert_eq!(next.binding_sha256, observed.binding_sha256);
        assert_eq!(next.attempt_id, observed.attempt_id);
    }
    assert_eq!(
        reopen()?.target_cleanup(&tenant, incarnation)?,
        Some(terminal.clone())
    );
    for replacement in [
        None,
        Some(TargetFileBinding {
            path: path.clone(),
            ..original
        }),
    ] {
        let mut wrong = terminal.clone();
        wrong.binding = replacement;
        store.write_batch(&[WriteOp::put(NS, key.clone(), serde_json::to_vec(&wrong)?)])?;
        let error = reopen().err().context("substituted cleanup reopened")?;
        assert!(
            format!("{error:#}").contains("enrolled storage binding"),
            "{error:#}"
        );
    }
    store.write_batch(&[WriteOp::put(NS, key, serde_json::to_vec(&terminal)?)])?;
    reopen()?.shutdown().await?;
    store.shutdown().await?;
    node.shutdown().await?;
    Ok(())
}

/// Acquire the real Control commitment and issuer lease for a fresh, exact
/// materialization. The journal owns no application store or restore state.
fn writer_operation(
    f: &Fixture,
) -> Result<(
    crate::TargetOperation,
    kasumi_types::TargetRuntimeStep,
    String,
)> {
    use kasumi_serving::{
        AuthorityManifest, AuthorityPartition, LeasePurpose, LifecycleBoot, LifecycleGate,
        LifecycleLeaseClaims,
    };
    use kasumi_types::{
        Action, CredentialResource, RequestAuthorization, RequestContext, TargetRuntimeStep,
    };
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("fixture authority root generation failed"))?;
    let root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(pkcs8.as_ref())?;
    let manifest = AuthorityManifest {
        authority_id: Uuid::new_v4(),
        max_lease_ms: 60_000,
        clock_rate_error_ppm: 0,
        lifecycle_controls: std::collections::BTreeMap::from([(
            f.installed.root.control_incarnation,
            f.installed.root.public_key.clone(),
        )]),
        partitions: std::collections::BTreeMap::from([(
            0,
            AuthorityPartition {
                group: "writer-test".into(),
                public_key: root.public_key(),
            },
        )]),
    };
    let signer = root
        .install(manifest.clone(), 0)?
        .for_verifier(f.installed.node.verifier.clone())?;
    let partition = manifest.control_partition(0)?;
    let origin = crate::target_completion_machine::tests::origin();
    let mut intent = origin.materialization;
    let mut input = origin.input;
    let target = Uuid::new_v4();
    input.target_incarnation = target;
    let digest = input.digest()?;
    let observed = kasumi_clock::EpochClock::system()?.observe()?;
    let expires = observed.utc_ms() + 600_000;
    intent.control_incarnation = f.installed.root.control_incarnation;
    intent.accepted_at_ms = observed.utc_ms();
    intent.original_credential_expires_at_ms = expires;
    intent.request.command_id = Uuid::new_v4();
    intent.request.target_incarnation = target;
    intent.request.phase_input_sha256 = digest.clone();
    intent.request.authority_partition = partition.key();
    let node = intent
        .request
        .target_nodes
        .get_mut(&f.installed.node.node_id)
        .unwrap();
    node.principal = f.installed.node.principal.clone();
    node.verifier = f.installed.node.verifier.clone();
    node.certificate_sha256 = f.installed.node.certificate_sha256.clone();
    intent.request_sha256 = kasumi_types::staged_digest(&intent.request)?.0;
    input.validate(&intent)?;
    let context = RequestContext {
        tenant: "__kasumi_control".into(),
        principal: intent.original_principal.clone(),
        request_id: "journal-writer-original".into(),
        scopes: std::collections::BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::from_verified_credential(
            expires,
            &observed,
            CredentialResource::Control {
                incarnation: intent.control_incarnation,
            },
        )?,
    };
    let proof = f.sign_control_observation(kasumi_types::ControlIntentCommitment {
        root: f.installed.root.clone(),
        authority_partition: partition,
        partition_set_sha256: "bc".repeat(32),
        observed_policy_epoch: intent.request.expected_policy_epoch,
        observed_revision: intent.revision,
        observed_term: 1,
        intent,
    })?;
    let boot = LifecycleBoot::new(signer.trust, f.installed.node.clone())?;
    let attempt = boot.begin(&proof)?;
    let lease = attempt.verify(signer.signer.sign_lifecycle_lease(LifecycleLeaseClaims {
        request: attempt.request().clone(),
        commitment: proof.observation().clone(),
        authority_id: manifest.authority_id,
        partition: 0,
        authority_term: 1,
        authority_revision: 1,
        application_purpose: Some(LeasePurpose::RestorePreparation),
        lifetime_ms: manifest.max_lease_ms,
        credential_lifetime_ms: manifest.max_lease_ms,
    })?)?;
    let scope = crate::TargetOperationScope::new(crate::TargetLifecycleInvocation::from_verified(
        LifecycleGate::new(context, lease)?,
    )?)?;
    Ok((
        scope.begin_operation(60_000)?,
        TargetRuntimeStep::Materialize(input),
        digest,
    ))
}

#[tokio::test]
async fn journal_writer_fence_requires_the_original_signed_read_and_survives_reopen() -> Result<()>
{
    use kasumi_types::{
        BeginKeyRetirement, CompleteKeyRetirement, KeyIdentityRef, KeyRetentionScope,
        KeyRetirementState, RetireKeyVersionsRequest, SignedTargetWriterObservation,
        TargetWriterChallenge, TargetWriterObservation,
    };
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let before = f
        .store
        .get(NS, b"metadata")?
        .context("journal head missing")?;
    assert!(
        !serde_json::from_slice::<serde_json::Value>(&before)?
            .as_object()
            .unwrap()
            .contains_key("retirements")
    );
    let identity = KeyIdentityRef {
        provider: "historical".into(),
        key_ref: "source".into(),
    };
    let request = RetireKeyVersionsRequest {
        retirement_id: "1".into(),
        scope: KeyRetentionScope::TargetJournal {},
        identity: identity.clone(),
        retire_below_version: 3,
        expected_coverage_sha256: "aa".repeat(32),
    };
    let mut state = KeyRetirementState::default();
    state.begin(
        &BeginKeyRetirement {
            request: request.clone(),
            membership_epoch: 3,
            expected_dependency_sha256: "bb".repeat(32),
        },
        5,
    )?;
    let sign = |challenge: &TargetWriterChallenge,
                observed_revision,
                state: &KeyRetirementState|
     -> Result<SignedTargetWriterObservation> {
        let observation = TargetWriterObservation {
            challenge: challenge.clone(),
            observed_term: 1,
            observed_revision,
            membership_epoch: if state.is_empty() { 0 } else { 3 },
            observed_policy_epoch: if state.is_empty() { 0 } else { 2 },
            retirements: state.clone(),
        };
        let bytes = serde_json::to_vec(&("kasumi.target-journal-writer.v1", &observation))?;
        Ok(SignedTargetWriterObservation {
            observation,
            signature: hex::encode(f.control_key.sign(&bytes).as_ref()),
        })
    };
    let apply =
        |journal: &Arc<TargetJournal>, revision, state: &KeyRetirementState| -> Result<String> {
            let read = journal.begin_writer_read()?;
            let signed = sign(read.challenge(), revision, state)?;
            read.accept(&signed)
        };
    let check = |journal: &TargetJournal, version| {
        journal.metadata()?.retirements.admit_version(
            &identity.provider,
            &identity.key_ref,
            version,
        )
    };
    check(&journal, 1)?;
    let (existing, _, existing_digest) = writer_operation(&f)?;
    assert!(journal.prepare(&existing, &existing_digest).is_err());
    let read = journal.begin_writer_read()?;
    let initial = sign(read.challenge(), 2, &KeyRetirementState::default())?;
    let prior_writer = read.admit(&initial)?;
    let existing_intent = journal.prepare_observed(&existing, &existing_digest, &prior_writer)?;
    let original = journal.begin_writer_read()?;
    let physical = original.challenge().catalog_minimums.versions()[0].clone();
    let incompatible = RetireKeyVersionsRequest {
        identity: physical.identity(),
        retire_below_version: physical.version + 1,
        ..request.clone()
    };
    let mut retired = KeyRetirementState::default();
    retired.begin(
        &BeginKeyRetirement {
            request: incompatible.clone(),
            membership_epoch: 3,
            expected_dependency_sha256: "aa".repeat(32),
        },
        5,
    )?;
    retired.complete(
        &CompleteKeyRetirement {
            retirement_id: incompatible.retirement_id.clone(),
            request_sha256: incompatible.request_sha256()?,
            completed_coverage_sha256: "bb".repeat(32),
            expected_dependency_sha256: "cc".repeat(32),
        },
        6,
    )?;
    let enrollment = kasumi_types::TargetWriterRegistration::WithCatalog {
        participant: original.challenge().participant(),
        catalog_minimums: original.challenge().catalog_minimums.clone(),
    };
    assert!(enrollment.checked_participant(&retired).is_err());
    let blocked = sign(original.challenge(), 6, &retired)?;
    assert!(original.admit(&blocked).is_err());
    let before_signed = f
        .store
        .get(NS, b"metadata")?
        .context("original target was not admitted")?;
    let original = journal.begin_writer_read()?;
    let signed = sign(original.challenge(), 5, &state)?;
    assert!(journal.begin_writer_read()?.accept(&signed).is_err());
    let mut wrong = signed.clone();
    wrong.signature = "00".repeat(64);
    assert!(original.accept(&wrong).is_err());
    assert_eq!(f.store.get(NS, b"metadata")?.unwrap(), before_signed);
    let accepted = apply(&journal, 5, &state)?;
    assert_eq!(accepted, apply(&journal, 5, &state)?);
    assert!(check(&journal, 2).is_err());
    check(&journal, 3)?;
    assert_eq!(
        journal.prepare(&existing, &existing_digest)?,
        existing_intent
    );
    let (new, step, new_digest) = writer_operation(&f)?;
    let before_new = f
        .store
        .get(NS, b"metadata")?
        .context("fenced head missing")?;
    assert!(journal.prepare(&new, &new_digest).is_err());
    assert!(
        journal
            .prepare_observed(&new, &new_digest, &prior_writer)
            .is_err()
    );
    let read = journal.begin_writer_read()?;
    let signed = sign(read.challenge(), 5, &state)?;
    let fenced = read.admit(&signed)?;
    let (lifecycle, phase, packet) = signed_initial_dispatch(&f, true)?;
    let error = journal
        .reserve_observed_initial_dispatch(&f.installed.root, &phase, &lifecycle, &packet, &fenced)
        .err()
        .context("first dispatch bypassed the durable checkpoint fence")?;
    assert!(
        error
            .to_string()
            .contains("original locally admitted materialization")
    );

    let result = journal
        .prepare_runtime(
            &new,
            &step,
            &new_digest,
            || async {
                let read = journal.begin_writer_read()?;
                let signed = sign(read.challenge(), 5, &state)?;
                read.admit(&signed)
            },
            |_| anyhow::bail!("original backup unavailable"),
        )
        .await;
    assert!(matches!(result,Err(ref e) if e.to_string().contains("original backup unavailable")));
    assert_eq!(f.store.get(NS, b"metadata")?.unwrap(), before_new);
    drop((prior_writer, fenced));
    drop(journal);
    let reopened = f.reopen()?;
    assert!(check(&reopened, 1).is_err());
    let active = state.clone();
    state.complete(
        &CompleteKeyRetirement {
            retirement_id: request.retirement_id.clone(),
            request_sha256: request.request_sha256()?,
            completed_coverage_sha256: "cc".repeat(32),
            expected_dependency_sha256: "dd".repeat(32),
        },
        6,
    )?;
    apply(&reopened, 6, &state)?;
    assert!(apply(&reopened, 5, &active).is_err());
    assert!(apply(&reopened, 7, &KeyRetirementState::default()).is_err());
    drop(reopened);
    let final_journal = f.reopen()?;
    assert!(check(&final_journal, 2).is_err());
    check(&final_journal, 3)?;
    let mut revision = 6;
    for number in 2..=(2 + kasumi_types::MAX_KEY_RETIREMENT_ABORTS) {
        let next_request = RetireKeyVersionsRequest {
            retirement_id: number.to_string(),
            retire_below_version: 4,
            ..request.clone()
        };
        revision += 1;
        state.begin(
            &BeginKeyRetirement {
                request: next_request.clone(),
                membership_epoch: 3,
                expected_dependency_sha256: "bb".repeat(32),
            },
            revision,
        )?;
        if number == 2 {
            apply(&final_journal, revision, &state)?;
        }
        revision += 1;
        state.abort(
            &kasumi_types::AbortKeyRetirement {
                retirement_id: next_request.retirement_id.clone(),
                request_sha256: next_request.request_sha256()?,
            },
            revision,
        )?;
    }
    assert!(state.status("2").is_none());
    assert!(check(&final_journal, 3).is_err());
    drop(final_journal);
    let returned = f.reopen()?;
    apply(&returned, revision, &state)?;
    check(&returned, 3)?;
    assert!(check(&returned, 2).is_err());

    Ok(())
}
