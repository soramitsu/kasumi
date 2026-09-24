use super::*;
use kasumi_store::{NodeStore, StorageAccess, test_utils::LocalKeyProvider};

struct Fixture {
    storage: crate::test_utils::FixtureStorage,
    config: crate::admission::AdmissionConfig,
    id: Uuid,
    node: Arc<NodeStore>,
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    admission: Arc<crate::admission::NodeAdmission>,
    directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let installed = TargetJournalInstallation {
            root: ControlSigningRoot {
                control_incarnation: Uuid::new_v4(),
                public_key: "11".repeat(32),
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
async fn format_two_head_requires_exact_current_json_bytes() -> Result<()> {
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
        .expect("alternate format-2 head bytes must reject");
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
    } = f;
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
        sequence: 1,
        phase: RecoveryPhase::Initialize,
        completion_scope: None,
        previous_phase: None,
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

#[tokio::test]
async fn format_two_intent_and_generation_require_current_writer_bytes_on_reopen() -> Result<()> {
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
    use kasumi_types::RecoveryEffect;
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = initial_dispatch(&f, false)?;
    let attempt_id = phase
        .effect_attempts
        .get(&RecoveryEffect::TargetCommand)
        .unwrap()
        .attempt_id;
    assert_eq!(
        journal.read_initial_dispatch_status(
            &f.installed.root,
            phase.operation_id,
            phase.phase_id,
            attempt_id,
            &phase.input_sha256,
            &request
        )?,
        Status::NoLocalRecord
    );
    assert!(
        journal
            .read_initial_dispatch_status(
                &f.installed.root,
                phase.operation_id,
                phase.phase_id,
                attempt_id,
                &"ff".repeat(32),
                &request
            )
            .is_err()
    );
    assert_eq!(
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
        Decision::NewlyAccepted
    );
    assert_eq!(
        journal.read_initial_dispatch_status(
            &f.installed.root,
            phase.operation_id,
            phase.phase_id,
            attempt_id,
            &phase.input_sha256,
            &request
        )?,
        Status::AcceptedOnly
    );
    assert!(
        journal
            .read_initial_dispatch_status(
                &f.installed.root,
                phase.operation_id,
                phase.phase_id,
                Uuid::new_v4(),
                &phase.input_sha256,
                &request
            )
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
            .read_initial_dispatch_status(
                &f.installed.root,
                phase.operation_id,
                phase.phase_id,
                attempt_id,
                &phase.input_sha256,
                &request
            )
            .is_err()
    );
    assert!(
        journal
            .reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)
            .is_err()
    );
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", metadata_before.clone())])?;
    assert_eq!(
        journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    );
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
    assert_eq!(
        journal.reserve_initial_dispatch(
            &f.installed.root,
            &initialize_phase,
            &initialize_lifecycle,
            &initialize_request
        )?,
        Decision::NewlyAccepted
    );
    let metadata: Metadata = serde_json::from_slice(&f.store.get(NS, b"metadata")?.unwrap())?;
    assert_eq!(metadata.format, 2);
    assert_eq!(metadata.dispatches, 2);
    assert!(metadata.charged_bytes >= MAX_RECORD as u64 + 2 * DISPATCH_TERMINAL_RESERVE);
    drop(journal);
    let reopened = f.reopen()?;
    assert_eq!(
        reopened.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?,
        Decision::ExistingStatusOnly
    );
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn format_one_and_corrupt_dispatch_or_accounting_fail_closed_on_reopen() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let (lifecycle, phase, request) = initial_dispatch(&f, false)?;
    journal.reserve_initial_dispatch(&f.installed.root, &phase, &lifecycle, &request)?;
    drop(journal);
    let original_head = f.store.get(NS, b"metadata")?.unwrap();
    let key = format!("dispatch/{}/{}", phase.operation_id, phase.phase_id).into_bytes();
    let original_row = f.store.get(NS, &key)?.unwrap();
    let mut old: Metadata = serde_json::from_slice(&original_head)?;
    old.format = 1;
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", serde_json::to_vec(&old)?)])?;
    assert!(f.reopen().is_err());
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
