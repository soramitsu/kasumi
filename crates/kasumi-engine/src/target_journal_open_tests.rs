use super::*;
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet, test_utils::LocalKeyProvider};
use ring::signature::KeyPair;

struct Fixture {
    storage: crate::test_utils::FixtureStorage,
    config: crate::admission::AdmissionConfig,
    id: Uuid,
    node: Arc<NodeStore>,
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    admission: Arc<crate::admission::NodeAdmission>,
    directory: tempfile::TempDir,
    control_key: ring::signature::Ed25519KeyPair,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let control_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[71; 32])
            .map_err(|_| anyhow::anyhow!("fixture Control signing key failed"))?;
        let installed = TargetJournalInstallation {
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
        let node = storage.create_new(directory.path().join("persistent/journal.kv"), id)?;
        let store = TenantStore::initialize_catalog(
            node.clone(),
            format!("kasumi.target.{}.1", installed.root.control_incarnation),
            Arc::new(LocalKeyProvider::new([39; 32])),
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
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", head.as_slice())])?;
    drop(journal);
    assert!(f.create().is_err());
    let journal = f.reopen()?;
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head));
    journal.shutdown().await.unwrap();
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
        f.store
            .write_batch(&[WriteOp::put(NS, b"metadata", bytes.as_slice())])?;
        assert!(f.reopen().is_err());
        assert!(f.create().is_err());
        assert_eq!(f.store.get(NS, b"metadata")?, Some(bytes));
    }
    f.store.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn current_head_requires_exact_current_json_bytes() -> Result<()> {
    let f = Fixture::new().await?;
    drop(f.create()?);
    let original = f.store.get(NS, b"metadata")?.unwrap();
    let mut alternate = original.clone();
    alternate.push(b' ');
    assert_eq!(
        serde_json::from_slice::<Metadata>(&alternate)?,
        serde_json::from_slice::<Metadata>(&original)?
    );
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", alternate.clone())])?;
    let error = f
        .reopen()
        .err()
        .expect("alternate format-3 head bytes must reject");
    assert!(
        format!("{error:#}").contains("noncanonical target journal record"),
        "{error:#}"
    );
    assert_eq!(f.store.get(NS, b"metadata")?, Some(alternate));
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original)])?;
    f.reopen()?.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn installed_empty_journal_reopens_only_its_exact_node_after_owner_drain() -> Result<()> {
    let f = Fixture::new().await?;
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
    let bytes = std::fs::read(&path)?;
    assert!(storage.open_existing(&path, Uuid::new_v4()).is_err());
    assert_eq!(std::fs::read(&path)?, bytes);
    let node = storage.open_existing(&path, id)?;
    let store = TenantStore::open_existing(
        node.clone(),
        format!("kasumi.target.{}.1", installed.root.control_incarnation),
        Arc::new(LocalKeyProvider::new([39; 32])),
        StorageAccess::target_journal(&installed.root, &installed.node)?,
    )
    .await?;
    let journal = TargetJournal::open_existing(
        store.clone(),
        installed,
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        admission,
    )?;
    assert_eq!(store.get(NS, b"metadata")?, Some(original));
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
    assert_eq!(f.store.get(NS, b"metadata")?, Some(original));
    first.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn journal_rejects_foreign_equal_policy_core_before_creating_or_reopening_head() -> Result<()>
{
    let f = Fixture::new().await?;
    f.node.drain_initializers().await?;
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
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head.clone()));
    for (admission, prior) in [(&f.admission, before), (&foreign, foreign_before)] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let exact = f.reopen()?;
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head));
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
        let Decision::NewlyAccepted(candidate) =
            journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
        else {
            anyhow::bail!("signed first dispatch returned no candidate")
        };
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
            journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
            Decision::ExistingStatusOnly
        ));
    }

    for wrong_phase in [false, true] {
        let f = Fixture::new().await?;
        let journal = f.create()?;
        let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
        let Decision::NewlyAccepted(candidate) =
            journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
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
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
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
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("signed first dispatch returned no one-use candidate")
    };
    let verified = candidate
        .verify_initial_membership(f.installed.node.node_id, LifecyclePhase::Initialize)?;
    let (stores, access) =
        target_prebind_stores(&f, &lifecycle, verified.bootstrap_sha256()).await?;
    assert_eq!(
        stores.custody().store().get("raft.meta", b"node_id")?,
        Some(serde_json::to_vec(&f.installed.node.node_id)?)
    );
    assert_eq!(
        stores.custody().store().get("raft.meta", b"group")?,
        Some(serde_json::to_vec(&format!(
            "{}/{}",
            lifecycle.request.tenant, lifecycle.request.target_incarnation
        ))?)
    );
    let materialized_identity = stores.custody().store().scan("raft.meta")?;
    let expected = verified.persist_target_raft_prebind(&journal, &stores)?;
    for (key, value) in materialized_identity {
        assert_eq!(
            stores.custody().store().get("raft.meta", &key)?,
            Some(value)
        );
    }
    assert_eq!(
        stores.custody().store().get("raft.meta", b"node_id")?,
        Some(serde_json::to_vec(&f.installed.node.node_id)?)
    );
    assert_eq!(
        stores.custody().store().get("raft.meta", b"group")?,
        Some(serde_json::to_vec(&expected.group)?)
    );
    assert_eq!(
        read_target_first_membership_prebind(&stores, &expected)?,
        expected
    );
    assert!(matches!(
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
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
    let Decision::NewlyAccepted(later) = journal.reserve_initial_dispatch(
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
    f.store
        .write_batch(&[WriteOp::put(NS, key.as_bytes(), substituted)])?;
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
    reopened.custody().store().write_batch(&[WriteOp::put(
        TARGET_PREBIND_NAMESPACE,
        TARGET_PREBIND_KEY,
        serde_json::to_vec(&local_substitution)?,
    )])?;
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
            journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
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
async fn historical_initial_membership_requires_exact_control_journal_and_applied_custody()
-> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("first dispatch returned no one-use candidate")
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
    )
    .await?;
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
    f.store
        .write_batch(&[WriteOp::put(NS, key.as_bytes(), substituted)])?;
    assert!(
        journal
            .resolve_initial_membership_history(&control, &phase, &identity, &request, &stores)
            .is_err(),
        "a different valid journal row cannot inherit the applied fact"
    );
    f.store
        .write_batch(&[WriteOp::put(NS, key.as_bytes(), original)])?;
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
async fn first_membership_terminal_requires_history_and_uses_original_reserved_capacity()
-> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("first dispatch returned no one-use candidate")
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
    assert_eq!(f.store.get(NS, b"metadata")?, Some(before.clone()));
    let first = kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
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
        f.store.get(NS, terminal_key.as_bytes())?,
        Some(terminal.clone())
    );
    assert_eq!(
        decode_current::<Metadata>(&f.store.get(NS, b"metadata")?.unwrap())?,
        after
    );
    assert!(matches!(
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));
    drop(journal);
    let journal = f.reopen()?;
    journal.record_initial_membership_history(&control, &phase, &identity, &request, &stores)?;
    assert_eq!(f.store.get(NS, terminal_key.as_bytes())?, Some(terminal));
    stores.shutdown().await?;
    journal.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn first_membership_terminal_rejects_substitution_missing_custody_and_torn_accounting()
-> Result<()> {
    use super::dispatch::InitialDispatchReservation as Decision;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = signed_initial_dispatch(&f, false)?;
    let control = f.verified_control(&lifecycle)?;
    let Decision::NewlyAccepted(candidate) =
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?
    else {
        anyhow::bail!("first dispatch returned no one-use candidate")
    };
    let identity = candidate.identity().clone();
    let candidate = candidate.verify_initial_membership(1, LifecyclePhase::Initialize)?;
    let (stores, _) = target_prebind_stores(&f, &lifecycle, candidate.bootstrap_sha256()).await?;
    let expected = candidate.persist_target_raft_prebind(&journal, &stores)?;
    kasumi_raft::historical_test_utils::publish_committed_first_membership(
        stores.clone(),
        &expected,
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
        f.store.get(NS, terminal_key.as_bytes())?,
        Some(original.clone())
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
        f.store.get(NS, terminal_key.as_bytes())?,
        Some(original.clone())
    );
    stores.custody().store().write_batch(&[WriteOp::put(
        "raft.meta",
        association_key,
        association,
    )])?;
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
        f.store
            .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), invalid.clone())])?;
        assert!(f.reopen().is_err(), "substituted terminal {field} reopened");
        assert_eq!(f.store.get(NS, terminal_key.as_bytes())?, Some(invalid));
        f.store
            .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), original.clone())])?;
    }
    let mut padded = original.clone();
    padded.push(b' ');
    f.store
        .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), padded)])?;
    assert!(f.reopen().is_err(), "noncanonical terminal reopened");
    f.store
        .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), original.clone())])?;

    // A canonical terminal digest is still only retained observation. Exact
    // live local history must detect substitution at the same log position.
    let mut invalid: serde_json::Value = serde_json::from_slice(&original)?;
    invalid["first_fact_sha256"] = serde_json::json!("33".repeat(32));
    let invalid: super::dispatch::InitialMembershipTerminal = serde_json::from_value(invalid)?;
    let invalid = serde_json::to_vec(&invalid)?;
    f.store
        .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), invalid.clone())])?;
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
    assert_eq!(f.store.get(NS, terminal_key.as_bytes())?, Some(invalid));
    drop(journal);
    f.store
        .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), original.clone())])?;

    f.store
        .write_batch(&[WriteOp::delete(NS, terminal_key.as_bytes())])?;
    assert!(
        f.reopen().is_err(),
        "missing terminal with counted publication reopened"
    );
    f.store
        .write_batch(&[WriteOp::put(NS, terminal_key.as_bytes(), original)])?;
    let mut invalid: Metadata = decode_current(&original_head)?;
    invalid.dispatch_terminals = 0;
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", serde_json::to_vec(&invalid)?)])?;
    assert!(
        f.reopen().is_err(),
        "terminal without counted publication reopened"
    );
    invalid.format = 2;
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", serde_json::to_vec(&invalid)?)])?;
    assert!(
        f.reopen().is_err(),
        "retired format cannot be upgraded during reopen"
    );
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original_head)])?;
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
    let f = Fixture::new().await?;
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
    f.store.write_batch(&[
        WriteOp::put(NS, intent_key.clone(), intent_bytes.clone()),
        WriteOp::put(NS, generation_key.clone(), generation_bytes.clone()),
        WriteOp::put(NS, b"metadata", head_bytes.clone()),
    ])?;
    drop(journal);
    drop(f.reopen()?);

    for (key, original) in [
        (intent_key, intent_bytes),
        (generation_key, generation_bytes),
    ] {
        let mut alternate = original.clone();
        alternate.push(b' ');
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&alternate)?,
            serde_json::from_slice::<serde_json::Value>(&original)?
        );
        let mut alternate_head = head.clone();
        alternate_head.charged_bytes += 1;
        f.store.write_batch(&[
            WriteOp::put(NS, key.clone(), alternate.clone()),
            WriteOp::put(NS, b"metadata", serde_json::to_vec(&alternate_head)?),
        ])?;
        let error = f.reopen().err().expect("alternate journal row must reject");
        assert!(
            format!("{error:#}").contains("noncanonical target journal record"),
            "{error:#}"
        );
        assert_eq!(f.store.get(NS, &key)?, Some(alternate));
        f.store.write_batch(&[
            WriteOp::put(NS, key, original),
            WriteOp::put(NS, b"metadata", head_bytes.clone()),
        ])?;
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
    f.store
        .write_batch(&[WriteOp::put(NS, key, alternate.clone())])?;
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
    assert_eq!(f.store.get(NS, key)?, Some(alternate));
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
    let first =
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?;
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
    f.store.write_batch(&[WriteOp::put(
        NS,
        b"metadata",
        serde_json::to_vec(&damaged_head)?,
    )])?;
    assert!(
        journal
            .read_initial_dispatch_status(&f.installed.root, &identity, &request)
            .is_err()
    );
    assert!(
        journal
            .reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)
            .is_err()
    );
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", metadata_before.clone())])?;
    assert!(matches!(
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    ));
    assert_eq!(f.store.get(NS, b"metadata")?, Some(metadata_before.clone()));
    let mut changed = phase.clone();
    changed
        .effect_attempts
        .get_mut(&RecoveryEffect::TargetCommand)
        .unwrap()
        .attempt_id = Uuid::new_v4();
    changed.validate()?;
    assert!(
        journal
            .reserve_initial_dispatch(&f.installed.root, &changed, &lifecycle, &request)
            .is_err()
    );
    let mut wrong_root = f.installed.root.clone();
    wrong_root.public_key = "ff".repeat(32);
    assert!(
        journal
            .reserve_initial_dispatch(&wrong_root, &phase, &lifecycle, &request)
            .is_err()
    );
    let (initialize_lifecycle, initialize_phase, initialize_request) = initial_dispatch(&f, true)?;
    let stopped_key = stop_key(
        &initialize_lifecycle.request.tenant,
        initialize_lifecycle.request.target_incarnation,
    );
    f.store
        .write_batch(&[WriteOp::put(NS, stopped_key.clone(), b"{}".to_vec())])?;
    assert!(
        journal
            .reserve_initial_dispatch(
                &f.installed.root,
                &initialize_phase,
                &initialize_lifecycle,
                &initialize_request
            )
            .is_err()
    );
    f.store.write_batch(&[WriteOp::delete(NS, stopped_key)])?;
    assert!(matches!(
        journal.reserve_initial_dispatch(
            &f.installed.root,
            &initialize_phase,
            &initialize_lifecycle,
            &initialize_request
        )?,
        Decision::NewlyAccepted(_)
    ));
    let metadata: Metadata = serde_json::from_slice(&f.store.get(NS, b"metadata")?.unwrap())?;
    assert_eq!(metadata.format, 4);
    assert_eq!(metadata.dispatches, 2);
    assert_eq!(metadata.dispatch_terminals, 0);
    assert_eq!(metadata.dispatch_starts, 0);
    assert_eq!(metadata.dispatch_initializes, 0);
    assert!(metadata.charged_bytes >= MAX_RECORD as u64 + 2 * DISPATCH_TERMINAL_RESERVE);
    drop(journal);
    let reopened = f.reopen()?;
    assert!(matches!(
        reopened.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
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
    journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?;
    drop(journal);
    let original_head = f.store.get(NS, b"metadata")?.unwrap();
    let key = format!("dispatch/{}/{}", phase.operation_id, phase.phase_id).into_bytes();
    let original_row = f.store.get(NS, &key)?.unwrap();
    for format in 1..4 {
        let mut old: Metadata = serde_json::from_slice(&original_head)?;
        old.format = format;
        f.store
            .write_batch(&[WriteOp::put(NS, b"metadata", serde_json::to_vec(&old)?)])?;
        assert!(
            f.reopen().is_err(),
            "retired journal format {format} reopened"
        );
    }
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original_head.clone())])?;
    let mut missing_field: serde_json::Value = serde_json::from_slice(&original_head)?;
    missing_field.as_object_mut().unwrap().remove("dispatches");
    f.store.write_batch(&[WriteOp::put(
        NS,
        b"metadata",
        serde_json::to_vec(&missing_field)?,
    )])?;
    assert!(f.reopen().is_err());
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original_head.clone())])?;
    let mut wrong_count: Metadata = serde_json::from_slice(&original_head)?;
    wrong_count.dispatches = 0;
    f.store.write_batch(&[WriteOp::put(
        NS,
        b"metadata",
        serde_json::to_vec(&wrong_count)?,
    )])?;
    assert!(f.reopen().is_err());
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original_head.clone())])?;
    let mut wrong_bytes: Metadata = serde_json::from_slice(&original_head)?;
    wrong_bytes.charged_bytes -= 1;
    f.store.write_batch(&[WriteOp::put(
        NS,
        b"metadata",
        serde_json::to_vec(&wrong_bytes)?,
    )])?;
    assert!(f.reopen().is_err());
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", original_head.clone())])?;
    let mut noncanonical = original_row.clone();
    noncanonical.push(b' ');
    f.store
        .write_batch(&[WriteOp::put(NS, key.clone(), noncanonical)])?;
    assert!(f.reopen().is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&original_row)?;
    altered["phase"]["effect_attempts"]["target_command"]["input_sha256"] =
        serde_json::Value::String("ff".repeat(32));
    f.store
        .write_batch(&[WriteOp::put(NS, key.clone(), serde_json::to_vec(&altered)?)])?;
    assert!(f.reopen().is_err());
    f.store.write_batch(&[
        WriteOp::delete(NS, key.clone()),
        WriteOp::put(NS, b"dispatch/foreign/phase", original_row.clone()),
    ])?;
    assert!(f.reopen().is_err());
    f.store.write_batch(&[
        WriteOp::delete(NS, b"dispatch/foreign/phase"),
        WriteOp::put(NS, key, original_row),
    ])?;
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
        journal
            .reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)
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
