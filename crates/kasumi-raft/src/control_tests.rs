use super::*;
use crate::{LogStore, RaftCommand, RetirementReplayState};
use anyhow::Result;
use kasumi_store::{
    NodeStore, StorageAccess, TenantStorageSet,
    test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
};
use kasumi_types::*;
use openraft::RaftLogReader;
use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
use std::collections::BTreeSet;

#[test]
fn target_first_membership_prebind_rejects_substitution_and_noncanonical_bytes() -> Result<()> {
    let target_incarnation = uuid::Uuid::new_v4();
    let record = TargetFirstMembershipPrebind {
        format: 1,
        control_root: ControlSigningRoot {
            control_incarnation: uuid::Uuid::new_v4(),
            public_key: "11".repeat(32),
        },
        node: NodeIdentity {
            node_id: 1,
            verifier: TrustVerifierIdentity {
                installation_id: uuid::Uuid::new_v4(),
                node_id: 1,
            },
            principal: "target-node".into(),
            certificate_sha256: "22".repeat(32),
        },
        tenant: "tenant".into(),
        target_incarnation,
        group: format!("tenant/{target_incarnation}"),
        dispatch: TargetInitialDispatchIdentity {
            operation_id: uuid::Uuid::new_v4(),
            phase_id: uuid::Uuid::new_v4(),
            attempt_id: uuid::Uuid::new_v4(),
            input_sha256: "33".repeat(32),
        },
        journal_row_sha256: "44".repeat(32),
        voters: [
            (1, "https://target-1:7400".into()),
            (2, "https://target-2:7400".into()),
            (3, "https://target-3:7400".into()),
        ]
        .into(),
        bootstrap_sha256: "55".repeat(32),
    };
    record.validate()?;
    let canonical = serde_json::to_vec(&record)?;
    assert_eq!(
        crate::control::decode_canonical::<TargetFirstMembershipPrebind>(&canonical)?,
        record
    );
    let mut padded = canonical.clone();
    padded.push(b' ');
    assert!(crate::control::decode_canonical::<TargetFirstMembershipPrebind>(&padded).is_err());

    let mut changed = record.clone();
    changed.group = "tenant/other".into();
    assert!(changed.validate().is_err());
    let mut changed = record.clone();
    changed.voters.remove(&2);
    assert!(changed.validate().is_err());
    let mut changed = record.clone();
    changed.node.verifier.node_id = 2;
    assert!(changed.validate().is_err());
    let mut changed = record.clone();
    changed.dispatch.attempt_id = uuid::Uuid::nil();
    assert!(changed.validate().is_err());
    let mut changed = record;
    changed.journal_row_sha256 = "not-a-digest".into();
    assert!(changed.validate().is_err());
    Ok(())
}

const INCARNATION: &str = "f38b3bea-9d6e-4ecb-9eab-9c5e4cb412d6";
pub(crate) fn group() -> String {
    format!("tenant/{INCARNATION}")
}
pub(crate) fn id(index: u64) -> LogId<u64> {
    LogId::new(openraft::CommittedLeaderId::new(3, 1), index)
}

// This fixture is log metadata, not a verified full backup or successful source
// retirement. The engine's retirement integration exercises its actual producer.
pub(crate) fn seed() -> Result<(Command, RetirementLogSeed)> {
    let context = RequestContext {
        tenant: "tenant".into(),
        principal: "owner".into(),
        request_id: "retire-one".into(),
        scopes: BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::service_identity(),
    };
    let command = Command {
        context,
        timestamp_ms: 123,
        operation: Operation::RetireSource(PreparedRetirement {
            request: RetireSourceRequest {
                retirement_id: "retire-one".into(),
                expected_source_incarnation: INCARNATION.into(),
                target_incarnation: "feb9b646-a733-4315-8216-2c2c7f28b9c4".into(),
                checkpoint: FullBackupCheckpoint {
                    tenant: "tenant".into(),
                    source_incarnation: INCARNATION.into(),
                    revision: 0,
                    resident_sha256: "1".repeat(64),
                    backup_id: uuid::Uuid::new_v4(),
                    manifest_ciphertext_sha256: "2".repeat(64),
                    key_lineage_digest: "3".repeat(64),
                },
                destination: "installed".into(),
                not_after_ms: 1000,
            },
            verified_closure_digest: "4".repeat(64),
            observation: Some(RetirementObservation {
                revision: 0,
                closure_digest: "4".repeat(64),
            }),
        }),
    };
    let state = RetirementReplayState {
        tenant: "tenant".into(),
        incarnation: INCARNATION.into(),
        previous_revision: 0,
        revision_base: 0,
        policy_epoch: 1,
        administrators: BTreeSet::from(["owner".into()]),
        suspended: true,
        retired: false,
        pending_restore: false,
        existing_identity: None,
        retirement_bytes: 0,
        max_retirement_bytes: 64 << 20,
        audit_hot_bytes: 0,
        max_audit_hot_bytes: 1 << 20,
        snapshot_bytes: 1024,
        max_snapshot_bytes: 1 << 20,
        staged_outcome_headroom: 0,
    };
    let seed = RetirementLogSeed::prepare(&command, state)?;
    Ok((command, seed))
}
pub(crate) fn retirement_entry() -> Result<Entry<TypeConfig>> {
    let (command, seed) = seed()?;
    Ok(Entry {
        log_id: id(1),
        payload: EntryPayload::Normal(RaftCommand::retirement(
            serde_json::to_vec(&command)?,
            seed,
        )?),
    })
}

#[test]
fn retirement_reserves_full_width_audit_bytes_before_commitment() -> Result<()> {
    let (command, seed) = seed()?;
    let mut state = seed.source().clone();
    state.audit_hot_bytes = state.max_audit_hot_bytes;
    let full = RetirementLogSeed::prepare(&command, state.clone())?;
    assert_eq!(
        full.reserve_success_capacity().unwrap_err().code,
        ErrorCode::AuditUnavailable
    );
    state.max_audit_hot_bytes += MAX_AUDIT_EVENT_BYTES as u64;
    RetirementLogSeed::prepare(&command, state)?.reserve_success_capacity()?;
    Ok(())
}

#[test]
fn retirement_reserves_permanent_bytes_before_a_positive_seed_can_commit() -> Result<()> {
    let (command, seed) = seed()?;
    let mut state = seed.source().clone();
    let required = StoredRetirement::reservation_bytes("owner", seed.request())?;
    state.retirement_bytes = 3 << 30;
    state.max_retirement_bytes = state.retirement_bytes + required - 1;
    let full = RetirementLogSeed::prepare(&command, state.clone())?;
    assert_eq!(
        full.reserve_success_capacity().unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    state.max_retirement_bytes += 1;
    RetirementLogSeed::prepare(&command, state.clone())?.reserve_success_capacity()?;
    state.retirement_bytes = u64::MAX - 1;
    state.max_retirement_bytes = u64::MAX;
    assert_eq!(
        RetirementLogSeed::prepare(&command, state)?
            .reserve_success_capacity()
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let mut incompatible = serde_json::to_value(seed.source())?;
    incompatible["max_retirements"] = serde_json::json!(4096);
    assert!(serde_json::from_value::<RetirementReplayState>(incompatible).is_err());
    Ok(())
}
pub(crate) fn ordinary(index: u64) -> Entry<TypeConfig> {
    Entry {
        log_id: id(index),
        payload: EntryPayload::Normal(RaftCommand::application(
            b"municipal-sensitive-payload".to_vec(),
        )),
    }
}
pub(crate) async fn fixture(
    disk: FaultBackend,
    create: bool,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
) -> Result<(
    Arc<TenantStorageSet>,
    Arc<LocalKeyProvider>,
    Arc<LocalKeyProvider>,
    LogStore,
)> {
    fixture_for_node(disk, create, fixture_scratch, 1).await
}

pub(crate) async fn fixture_for_node(
    disk: FaultBackend,
    create: bool,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    node_id: u64,
) -> Result<(
    Arc<TenantStorageSet>,
    Arc<LocalKeyProvider>,
    Arc<LocalKeyProvider>,
    LogStore,
)> {
    let node = NodeStore::open_with_backend(
        disk,
        kasumi_store::test_utils::storage_admission(),
        fixture_scratch.clone(),
    )?;
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let app = (if create {
        TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            app_provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
    } else {
        TenantStore::open_existing_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            app_provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
    })?;
    let custody = (if create {
        TenantStore::initialize_catalog_fixture_with_clock(
            node,
            CustodyStore::catalog_name("tenant"),
            custody_provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
    } else {
        TenantStore::open_existing_fixture_with_clock(
            node,
            CustodyStore::catalog_name("tenant"),
            custody_provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
    })?;
    let stores = if create {
        kasumi_store::test_utils::with_domains(app, custody)?
    } else {
        let pair =
            kasumi_store::test_utils::open_existing_custody_fixture(app, custody_provider.clone())
                .await?;
        ensure!(
            Arc::ptr_eq(pair.custody().store(), &custody),
            "strict reopen changed original custody owner"
        );
        pair
    };
    if create {
        let digest = "0".repeat(64);
        let manifest = format!(r#"{{"format":2,"bytes":1,"chunks":1,"digest":"{digest}"}}"#);
        let [node_identity, group_id] = initial_storage_identity(node_id, &group())?;
        stores.write_batch(
            &[WriteOp::put(
                "engine.bootstrap",
                b"manifest",
                manifest.as_bytes(),
            )],
            &[
                WriteOp::put(
                    META,
                    b"application_bootstrap_sha256",
                    serde_json::to_vec(&digest)?,
                ),
                node_identity,
                group_id,
            ],
        )?;
    } else {
        ensure!(
            stores
                .custody()
                .store()
                .get(META, b"application_bootstrap_sha256")?
                .as_deref()
                == Some(serde_json::to_vec(&"0".repeat(64))?.as_slice()),
            "existing fixture lost bootstrap commitment"
        );
    }
    let log = LogStore::open(stores.clone(), node_id).await?;
    log.bind_group(group()).await?;
    Ok((stores, app_provider, custody_provider, log))
}

fn signed_target_serving_access(prebind: &TargetFirstMembershipPrebind) -> Result<StorageAccess> {
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("target serving fixture key generation failed"))?;
    let root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(pkcs8.as_ref())?;
    let manifest = kasumi_serving::AuthorityManifest {
        lifecycle_controls: Default::default(),
        authority_id: uuid::Uuid::new_v4(),
        max_lease_ms: 60_000,
        clock_rate_error_ppm: 0,
        partitions: std::collections::BTreeMap::from([(
            0,
            kasumi_serving::AuthorityPartition {
                group: "target-history-fixture-issuer".into(),
                public_key: root.public_key(),
            },
        )]),
    };
    let signing = root
        .install(manifest.clone(), 0)?
        .for_verifier(prebind.node.verifier.clone())?;
    let signer = signing.signer.clone();
    let boot = kasumi_serving::ServingBoot::new(
        signing.trust,
        kasumi_serving::ServingIdentity {
            tenant: prebind.tenant.clone(),
            incarnation: prebind.target_incarnation,
            authority_epoch: 1,
            node: prebind.node.clone(),
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
        recovery_checkpoint: None,
    })?)?;
    StorageAccess::serving(kasumi_serving::ServingGate::new(lease)?)
}

async fn target_serving_fixture(
    disk: FaultBackend,
    create: bool,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    prebind: &TargetFirstMembershipPrebind,
    access: StorageAccess,
    app_provider: Arc<LocalKeyProvider>,
    custody_provider: Arc<LocalKeyProvider>,
) -> Result<(Arc<TenantStorageSet>, LogStore)> {
    let node = NodeStore::open_with_backend(
        disk,
        kasumi_store::test_utils::storage_admission(),
        fixture_scratch,
    )?;
    let stores = if create {
        TenantStorageSet::initialize_catalogs(
            node,
            prebind.tenant.clone(),
            app_provider,
            custody_provider,
            access,
        )
        .await?
    } else {
        TenantStorageSet::open_existing(
            node,
            prebind.tenant.clone(),
            app_provider,
            custody_provider,
            access,
        )
        .await?
    };
    if create {
        let mut identity = initial_storage_identity(prebind.node.node_id, &prebind.group)?
            .into_iter()
            .collect::<Vec<_>>();
        identity.push(WriteOp::put(
            META,
            b"application_bootstrap_sha256",
            serde_json::to_vec(&prebind.bootstrap_sha256)?,
        ));
        stores.initialize_state(
            &[WriteOp::put(
                "engine.bootstrap",
                b"manifest",
                serde_json::to_vec(&serde_json::json!({
                    "format": 2,
                    "bytes": 0,
                    "chunks": 0,
                    "digest": prebind.bootstrap_sha256,
                }))?,
            )],
            &identity,
        )?;
    }
    let log = LogStore::open(stores.clone(), prebind.node.node_id).await?;
    log.bind_group(prebind.group.clone()).await?;
    Ok((stores, log))
}

fn replace_with_alternate_json(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
) -> Result<Vec<u8>> {
    let original = store
        .get(namespace, key)?
        .context("expected current Raft metadata row")?;
    let mut alternate = Vec::with_capacity(original.len() + 1);
    alternate.push(b' ');
    alternate.extend_from_slice(&original);
    ensure!(
        serde_json::from_slice::<serde_json::Value>(&original)?
            == serde_json::from_slice::<serde_json::Value>(&alternate)?,
        "alternate JSON changed the record value"
    );
    store.write_batch(&[WriteOp::put(namespace, key, alternate)])?;
    Ok(original)
}

fn restore_json(store: &TenantStore, namespace: &str, key: &[u8], original: Vec<u8>) -> Result<()> {
    store.write_batch(&[WriteOp::put(namespace, key, original)])
}

fn assert_alternate_initial_identity_rejected(store: &TenantStore, key: &[u8]) -> Result<()> {
    let original = store
        .get(META, key)?
        .context("expected installed Raft identity")?;
    let mut alternate = vec![b' '];
    alternate.extend_from_slice(&original);
    ensure!(
        serde_json::from_slice::<serde_json::Value>(&original)?
            == serde_json::from_slice::<serde_json::Value>(&alternate)?,
        "alternate JSON changed Raft identity"
    );
    assert!(
        store
            .write_batch(&[WriteOp::put(META, key, alternate)])
            .is_err()
    );
    assert_eq!(store.get(META, key)?, Some(original));
    Ok(())
}

#[tokio::test]
async fn raft_control_metadata_requires_current_writer_bytes_on_every_live_read() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    log.save_vote(&openraft::Vote::new_committed(3, 1)).await?;
    log.save_committed(Some(id(1))).await?;
    let store = stores.custody().store();
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert_eq!(view.committed()?, Some(id(1)));
    assert!(view.retirement_seed(1)?.is_some());
    assert_eq!(log.try_get_log_entries(0..=1).await?.len(), 2);

    assert_alternate_initial_identity_rejected(store, b"node_id")?;
    LogStore::open(stores.clone(), 1).await?;
    ControlLog::installed(stores.custody().clone())?.context("restored control identity absent")?;

    assert_alternate_initial_identity_rejected(store, b"group")?;
    log.bind_group(group()).await?;

    let original = replace_with_alternate_json(store, META, b"vote")?;
    assert!(log.read_vote().await.is_err());
    assert!(view.read_vote().is_err());
    restore_json(store, META, b"vote", original)?;
    assert_eq!(
        log.read_vote().await?,
        Some(openraft::Vote::new_committed(3, 1))
    );

    let original = replace_with_alternate_json(store, META, b"committed")?;
    assert!(log.read_committed().await.is_err());
    assert!(view.committed().is_err());
    restore_json(store, META, b"committed", original)?;
    assert_eq!(log.read_committed().await?, Some(id(1)));

    // This row is first-installed with the application manifest and cannot be
    // rewritten through a live TenantStore, even to equivalent JSON bytes.
    let original = store
        .get(META, b"application_bootstrap_sha256")?
        .context("bootstrap commitment absent")?;
    assert!(replace_with_alternate_json(store, META, b"application_bootstrap_sha256").is_err());
    assert_eq!(
        store.get(META, b"application_bootstrap_sha256")?,
        Some(original)
    );
    assert!(view.retirement_seed(1)?.is_some());

    let key = 1u64.to_be_bytes();
    let original = replace_with_alternate_json(store, SEEDS, &key)?;
    assert!(view.retirement_seed(1).is_err());
    restore_json(store, SEEDS, &key, original)?;
    assert!(view.retirement_seed(1)?.is_some());

    let original = replace_with_alternate_json(store, HEADERS, &key)?;
    assert!(LogStore::open(stores.clone(), 1).await.is_err());
    assert!(log.try_get_log_entries(0..=1).await.is_err());
    restore_json(store, HEADERS, &key, original)?;
    LogStore::open(stores.clone(), 1).await?;
    assert_eq!(log.try_get_log_entries(0..=1).await?.len(), 2);

    log.purge(id(1)).await?;
    let original = replace_with_alternate_json(store, META, b"purged")?;
    assert!(log.get_log_state().await.is_err());
    assert!(view.retirement_seed(1).is_err());
    restore_json(store, META, b"purged", original)?;
    assert_eq!(log.get_log_state().await?.last_purged_log_id, Some(id(1)));
    assert!(view.retirement_seed(1)?.is_some());
    Ok(())
}

#[tokio::test]
async fn noncanonical_recovery_scan_header_cannot_publish_retirement() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    log.blocking_append([membership(0), retirement_entry()?])
        .await?;
    log.save_committed(Some(id(1))).await?;
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    let store = stores.custody().store();
    let key = 0u64.to_be_bytes();
    let original = replace_with_alternate_json(store, HEADERS, &key)?;
    assert!(view.recover_retired().is_err());
    assert!(store.get(META, b"applied")?.is_none());
    assert!(store.get(META, b"retired_boundary")?.is_none());
    restore_json(store, HEADERS, &key, original)?;
    assert!(view.recover_retired()?);
    assert!(store.get(META, b"applied")?.is_some());
    assert!(store.get(META, b"retired_boundary")?.is_some());

    let original = replace_with_alternate_json(store, META, b"applied")?;
    assert!(crate::custody_machine::applied(stores.custody()).is_err());
    restore_json(store, META, b"applied", original)?;
    assert!(crate::custody_machine::applied(stores.custody()).is_ok());

    let original = replace_with_alternate_json(store, META, b"retired_boundary")?;
    assert!(retired_boundary(stores.custody()).is_err());
    restore_json(store, META, b"retired_boundary", original)?;
    assert!(retired_boundary(stores.custody())?.is_some());
    Ok(())
}

#[tokio::test]
async fn committed_seed_reopens_before_any_projection_without_application_key_access() -> Result<()>
{
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, app_provider, custody_provider, mut log) =
        fixture(disk.clone(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(
        view.retirement_seed(1)?.is_none(),
        "append is not commitment"
    );
    assert!(load::<AppliedCursor>(stores.custody().store(), META, b"applied")?.is_none());
    log.save_committed(Some(id(1))).await?;
    let original = view.retirement_seed(1)?.unwrap().seed().encoded()?;
    let crash = disk.crash();
    app_provider.revoke();
    assert!(stores.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    drop(view);
    drop(log);
    drop(stores);
    // No source state machine, application provider or payload decoder is opened.
    let control = CustodyStore::open(
        NodeStore::open_with_backend(
            crash,
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "tenant".into(),
        custody_provider,
    )
    .await?;
    let recovered = ControlLog::open(control.clone(), 1, group())?;
    assert_eq!(
        recovered.retirement_seed(1)?.unwrap().seed().encoded()?,
        original
    );
    assert_eq!(app_provider.probe_count(), probes);
    assert!(load::<AppliedCursor>(control.store(), META, b"applied")?.is_none());
    for (_, bytes) in control.store().scan(HEADERS)? {
        assert!(!String::from_utf8_lossy(&bytes).contains("municipal-sensitive-payload"));
    }
    control.store().shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn truncation_permanently_removes_uncommitted_seed_before_overwrite_and_restart() -> Result<()>
{
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, _, provider, mut log) =
        fixture(disk.clone(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    log.save_committed(Some(id(0))).await?;
    log.truncate(id(1)).await?;
    assert!(
        stores
            .custody()
            .store()
            .get(SEEDS, &1u64.to_be_bytes())?
            .is_none()
    );
    log.blocking_append([ordinary(1)]).await?;
    log.save_committed(Some(id(1))).await?;
    assert!(
        log.truncate(id(1)).await.is_err(),
        "committed source prefix cannot be truncated"
    );
    let crash = disk.crash();
    drop(log);
    drop(stores);
    let control = CustodyStore::open(
        NodeStore::open_with_backend(
            crash,
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "tenant".into(),
        provider,
    )
    .await?;
    assert!(
        ControlLog::open(control.clone(), 1, group())?
            .retirement_seed(1)?
            .is_none()
    );
    control.store().shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn interrupted_raft_append_never_persists_seed_without_matching_body_and_header() -> Result<()>
{
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let seed_disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(seed_disk.clone(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0)]).await?;
    log.save_committed(Some(id(0))).await?;
    let baseline = seed_disk.crash();
    drop(log);
    drop(stores);
    let mut failed = 0;
    let mut succeeded = 0;
    for failure in 0..40 {
        let disk = baseline.crash();
        let (stores, _, _, mut log) = fixture(disk.clone(), false, fixture_scratch.clone()).await?;
        disk.fail_after(failure);
        let appended = log.blocking_append([retirement_entry()?]).await;
        let crash = disk.crash();
        disk.disarm();
        drop(log);
        drop(stores);
        let (reopened, _, _, _) = fixture(crash, false, fixture_scratch.clone()).await?;
        let control = reopened.custody().store();
        let body = reopened
            .application()
            .get("raft.log", &1u64.to_be_bytes())?;
        let header = control.get(HEADERS, &1u64.to_be_bytes())?;
        let seed = control.get(SEEDS, &1u64.to_be_bytes())?;
        assert_eq!(body.is_some(), header.is_some());
        assert_eq!(body.is_some(), seed.is_some());
        assert!(
            ControlLog::open(reopened.custody().clone(), 1, group())?
                .retirement_seed(1)?
                .is_none()
        );
        if appended.is_ok() {
            succeeded += 1;
            assert!(body.is_some());
        } else {
            failed += 1;
        }
    }
    assert!(failed > 0 && succeeded > 0);
    Ok(())
}

#[tokio::test]
async fn substituted_seed_bootstrap_or_command_and_uncovered_commit_fail_closed() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    assert!(log.save_committed(Some(id(9))).await.is_err());
    log.save_committed(Some(id(1))).await?;
    assert!(log.save_committed(Some(id(0))).await.is_err());
    let view = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(view.retirement_seed(1)?.is_some());
    let mut saved: RetainedSeed =
        load(stores.custody().store(), SEEDS, &1u64.to_be_bytes())?.unwrap();
    saved.bootstrap_sha256 = "f".repeat(64);
    stores.custody().store().write_batch(&[WriteOp::put(
        SEEDS,
        1u64.to_be_bytes(),
        serde_json::to_vec(&saved)?,
    )])?;
    assert!(view.retirement_seed(1).is_err());
    let (mut command, seed) = seed()?;
    command.operation = Operation::Suspend(false);
    assert!(RaftCommand::retirement(serde_json::to_vec(&command)?, seed.clone()).is_err());
    let mut value = serde_json::to_value(&seed)?;
    value["source"]["documents"] = serde_json::json!({"payload":"forbidden"});
    assert!(RetirementLogSeed::decode(&serde_json::to_vec(&value)?).is_err());
    assert!(ControlLog::open(stores.custody().clone(), 2, group()).is_err());
    Ok(())
}

#[tokio::test]
async fn ordinary_purge_deletes_bodies_and_nonretirement_overwrite_cannot_leave_a_seed()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    log.blocking_append([ordinary(0), retirement_entry()?])
        .await?;
    log.save_committed(Some(id(0))).await?;
    // Storage's own contract clears an overwritten uncommitted seed even if an
    // embedding omitted OpenRaft's normal preceding truncate call.
    log.blocking_append([ordinary(1)]).await?;
    log.save_committed(Some(id(1))).await?;
    assert!(
        stores
            .custody()
            .store()
            .get(SEEDS, &1u64.to_be_bytes())?
            .is_none()
    );
    log.purge(id(1)).await?;
    assert!(
        stores
            .application()
            .get("raft.log", &1u64.to_be_bytes())?
            .is_none()
    );
    assert!(
        ControlLog::open(stores.custody().clone(), 1, group())?
            .retirement_seed(1)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn accepted_boundary_and_exact_applied_position_publish_atomically_before_retained_purge()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let seed_disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(seed_disk.clone(), true, fixture_scratch.clone()).await?;
    let entry = retirement_entry()?;
    let EntryPayload::Normal(command) = &entry.payload else {
        unreachable!()
    };
    let seed = command.seed()?.unwrap();
    let context = AppliedEntryContext {
        log_id: id(1),
        previous: Some(id(0)),
        membership: StoredMembership::default(),
        command_sha256: seed.command_sha256().into(),
        retirement_seed: Some(seed.clone()),
    };
    let receipt = RetirementReceipt {
        tenant: "tenant".into(),
        principal: "owner".into(),
        retirement_id: seed.request().retirement_id.clone(),
        request_digest: seed.request().reference()?.request_digest,
        source_incarnation: INCARNATION.into(),
        target_incarnation: seed.request().target_incarnation.clone(),
        revision: 1,
        policy_epoch: 2,
        admitted_at_ms: 123,
        checkpoint: seed.request().checkpoint.clone(),
        closure_digest: "4".repeat(64),
    };
    log.blocking_append([ordinary(0), entry]).await?;
    log.save_committed(Some(id(1))).await?;
    let baseline = seed_disk.crash();
    drop(log);
    drop(stores);
    let mut successes = 0;
    for failure in 0..40 {
        let disk = baseline.crash();
        let (stores, _, _, _) = fixture(disk.clone(), false, fixture_scratch.clone()).await?;
        disk.fail_after(failure);
        let result = persist_applied(&stores, &context, Some(receipt.clone()));
        let crash = disk.crash();
        disk.disarm();
        drop(stores);
        let (reopened, _, _, mut log) = fixture(crash, false, fixture_scratch.clone()).await?;
        let applied: Option<AppliedCursor> = load(reopened.custody().store(), META, b"applied")?;
        let boundary = retired_boundary(reopened.custody())?;
        assert_eq!(
            applied.is_some(),
            boundary.is_some(),
            "torn source transition {failure}"
        );
        if let Some(boundary) = boundary {
            assert_eq!(applied.unwrap(), AppliedCursor::Entry(context.record()));
            assert_eq!(boundary.receipt, receipt);
            log.purge(id(1)).await?;
            assert!(
                reopened
                    .application()
                    .get("raft.log", &1u64.to_be_bytes())?
                    .is_some()
            );
            assert!(
                ControlLog::open(reopened.custody().clone(), 1, group())?
                    .retirement_seed(1)?
                    .is_some()
            );
        }
        if result.is_ok() {
            successes += 1;
        }
    }
    assert!(successes > 0);
    Ok(())
}

fn membership(index: u64) -> Entry<TypeConfig> {
    membership_with_address(index, "local")
}

fn membership_with_address(index: u64, address: &str) -> Entry<TypeConfig> {
    Entry {
        log_id: id(index),
        payload: EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1])],
            [(1, BasicNode::new(address))]
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>(),
        )),
    }
}

fn membership_context(
    entry: &Entry<TypeConfig>,
    previous: Option<LogId<u64>>,
) -> Result<AppliedEntryContext> {
    let EntryPayload::Membership(membership) = &entry.payload else {
        anyhow::bail!("membership fixture entry required")
    };
    Ok(AppliedEntryContext {
        log_id: entry.log_id,
        previous,
        membership: StoredMembership::new(Some(entry.log_id), membership.clone()),
        command_sha256: crate::command::sha256(&crate::storage::encode_entry(entry)?),
        retirement_seed: None,
    })
}

#[tokio::test]
async fn first_applied_membership_and_cursor_survive_every_atomic_write_boundary() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let seed_disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(seed_disk.clone(), true, fixture_scratch.clone()).await?;
    let entry = membership(0);
    let context = membership_context(&entry, None)?;
    let (header, _) = LogHeader::build(&entry, &crate::storage::encode_entry(&entry)?)?;
    log.blocking_append([entry]).await?;
    log.save_committed(Some(id(0))).await?;
    let baseline = seed_disk.crash();
    drop(log);
    drop(stores);

    let mut successes = 0;
    for failure in 0..40 {
        let disk = baseline.crash();
        let (stores, _, _, _) = fixture(disk.clone(), false, fixture_scratch.clone()).await?;
        disk.fail_after(failure);
        let result = persist_applied(&stores, &context, None);
        let crash = disk.crash();
        disk.disarm();
        drop(stores);
        let (reopened, _, _, _) = fixture(crash, false, fixture_scratch.clone()).await?;
        let applied: Option<AppliedCursor> = load(reopened.custody().store(), META, b"applied")?;
        let first = first_applied_membership(reopened.custody().store())?;
        assert_eq!(
            applied.is_some(),
            first.is_some(),
            "torn first-membership capture at write boundary {failure}"
        );
        if let Some(first) = first {
            assert_eq!(applied, Some(AppliedCursor::Entry(context.record())));
            assert_eq!(first.header, header);
        }
        if result.is_ok() {
            successes += 1;
        }
    }
    assert!(successes > 0);
    Ok(())
}

#[tokio::test]
async fn first_applied_membership_survives_later_membership_purge_and_reopen() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk.clone(), true, fixture_scratch.clone()).await?;
    let first = membership(0);
    let later = membership_with_address(1, "later-local");
    let first_context = membership_context(&first, None)?;
    let later_context = membership_context(&later, Some(id(0)))?;
    log.blocking_append([first, later]).await?;
    log.save_committed(Some(id(1))).await?;
    persist_applied(&stores, &first_context, None)?;
    let fact = first_applied_membership(stores.custody().store())?
        .context("first applied membership fact missing")?;
    persist_applied(&stores, &later_context, None)?;
    assert_eq!(
        first_applied_membership(stores.custody().store())?,
        Some(fact.clone())
    );
    log.purge(id(1)).await?;
    assert!(
        stores
            .custody()
            .store()
            .get(HEADERS, &0u64.to_be_bytes())?
            .is_none()
    );
    let crash = disk.crash();
    drop(log);
    drop(stores);
    let (reopened, _, _, _) = fixture(crash, false, fixture_scratch).await?;
    assert_eq!(
        first_applied_membership(reopened.custody().store())?,
        Some(fact.clone())
    );
    assert_eq!(
        load::<AppliedCursor>(reopened.custody().store(), META, b"applied")?,
        Some(AppliedCursor::Entry(later_context.record()))
    );
    let snapshot_meta = openraft::SnapshotMeta {
        last_log_id: Some(id(1)),
        last_membership: later_context.membership,
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    assert_eq!(
        first_membership_for_snapshot(reopened.custody(), &snapshot_meta)?,
        Some(fact)
    );
    Ok(())
}

#[tokio::test]
async fn prebound_first_membership_association_survives_later_apply_purge_and_reopen() -> Result<()>
{
    use std::collections::BTreeMap;
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let voters = (1..=3)
        .map(|node| (node, format!("https://target-{node}:7400")))
        .collect::<BTreeMap<_, _>>();
    let prebind = TargetFirstMembershipPrebind {
        format: 1,
        control_root: ControlSigningRoot {
            control_incarnation: uuid::Uuid::new_v4(),
            public_key: "11".repeat(32),
        },
        node: NodeIdentity {
            node_id: 1,
            verifier: TrustVerifierIdentity {
                installation_id: uuid::Uuid::new_v4(),
                node_id: 1,
            },
            principal: "target-node".into(),
            certificate_sha256: "22".repeat(32),
        },
        tenant: "tenant".into(),
        target_incarnation: uuid::Uuid::parse_str(INCARNATION)?,
        group: group(),
        dispatch: TargetInitialDispatchIdentity {
            operation_id: uuid::Uuid::new_v4(),
            phase_id: uuid::Uuid::new_v4(),
            attempt_id: uuid::Uuid::new_v4(),
            input_sha256: "33".repeat(32),
        },
        journal_row_sha256: "44".repeat(32),
        voters: voters.clone(),
        bootstrap_sha256: "0".repeat(64),
    };
    let access = signed_target_serving_access(&prebind)?;
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let (stores, mut log) = target_serving_fixture(
        disk.clone(),
        true,
        fixture_scratch.clone(),
        &prebind,
        access.clone(),
        app_provider.clone(),
        custody_provider.clone(),
    )
    .await?;
    stores.custody().store().write_batch(&[WriteOp::put(
        META,
        TARGET_PREBIND_KEY,
        serde_json::to_vec(&prebind)?,
    )])?;
    let first = Entry {
        log_id: id(0),
        payload: EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2, 3])],
            voters
                .iter()
                .map(|(node, endpoint)| (*node, BasicNode::new(endpoint)))
                .collect::<BTreeMap<_, _>>(),
        )),
    };
    let later = membership_with_address(1, "later-local");
    let first_context = membership_context(&first, None)?;
    let later_context = membership_context(&later, Some(id(0)))?;
    log.blocking_append([first, later]).await?;
    log.save_committed(Some(id(1))).await?;
    let mut wrong_voters = prebind.clone();
    wrong_voters
        .voters
        .insert(2, "https://substituted:7400".into());
    stores.custody().store().write_batch(&[WriteOp::put(
        META,
        TARGET_PREBIND_KEY,
        serde_json::to_vec(&wrong_voters)?,
    )])?;
    assert!(persist_applied(&stores, &first_context, None).is_err());
    assert!(first_applied_membership(stores.custody().store())?.is_none());
    assert!(load::<AppliedCursor>(stores.custody().store(), META, b"applied")?.is_none());
    assert!(
        load::<LocalFirstMembershipAssociation>(
            stores.custody().store(),
            META,
            LOCAL_FIRST_ASSOCIATION_KEY,
        )?
        .is_none()
    );
    stores.custody().store().write_batch(&[WriteOp::put(
        META,
        TARGET_PREBIND_KEY,
        serde_json::to_vec(&prebind)?,
    )])?;
    persist_applied(&stores, &first_context, None)?;
    let original_fact = first_applied_membership(stores.custody().store())?
        .context("prebound first membership absent")?;
    let association: LocalFirstMembershipAssociation =
        load(stores.custody().store(), META, LOCAL_FIRST_ASSOCIATION_KEY)?
            .context("atomic local association absent")?;
    persist_applied(&stores, &later_context, None)?;
    assert_eq!(
        read_target_first_membership_history(&stores, &prebind)?.first_log_id(),
        id(0)
    );
    let original_header = stores
        .custody()
        .store()
        .get(HEADERS, &0u64.to_be_bytes())?
        .context("retained first log header absent")?;
    let mut substituted_header: LogHeader = serde_json::from_slice(&original_header)?;
    substituted_header.entry_sha256 = "aa".repeat(32);
    stores.custody().store().write_batch(&[WriteOp::put(
        HEADERS,
        0u64.to_be_bytes(),
        serde_json::to_vec(&substituted_header)?,
    )])?;
    assert!(read_target_first_membership_history(&stores, &prebind).is_err());
    stores.custody().store().write_batch(&[WriteOp::put(
        HEADERS,
        0u64.to_be_bytes(),
        original_header,
    )])?;
    log.purge(id(1)).await?;
    let crash = disk.crash();
    drop(log);
    drop(stores);
    let (reopened, _) = target_serving_fixture(
        crash,
        false,
        fixture_scratch,
        &prebind,
        access,
        app_provider,
        custody_provider,
    )
    .await?;
    assert_eq!(
        first_applied_membership(reopened.custody().store())?,
        Some(original_fact.clone())
    );
    assert_eq!(
        load::<LocalFirstMembershipAssociation>(
            reopened.custody().store(),
            META,
            LOCAL_FIRST_ASSOCIATION_KEY,
        )?,
        Some(association.clone())
    );
    let history = read_target_first_membership_history(&reopened, &prebind)?;
    assert_eq!(history.first_log_id(), id(0));
    assert_eq!(history.applied_log_id(), id(1));
    assert_eq!(history.committed_log_id(), id(1));
    let snapshot_meta = openraft::SnapshotMeta {
        last_log_id: Some(id(1)),
        last_membership: later_context.membership,
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    assert_eq!(
        first_membership_for_snapshot(reopened.custody(), &snapshot_meta)?,
        Some(original_fact)
    );
    let incomplete_coverage = crate::storage::SnapshotCoverage {
        kind: crate::storage::SnapshotKind::Application,
        manifest_id: uuid::Uuid::new_v4().to_string(),
        snapshot_sha256: "aa".repeat(32),
        backend_sha256: "bb".repeat(32),
        meta: snapshot_meta.clone(),
    };
    reopened.custody().store().write_batch(&[WriteOp::put(
        META,
        b"snapshot_coverage",
        serde_json::to_vec(&incomplete_coverage)?,
    )])?;
    assert!(
        read_target_first_membership_history(&reopened, &prebind).is_err(),
        "snapshot control coverage without its published image must fail"
    );
    reopened
        .custody()
        .store()
        .write_batch(&[WriteOp::delete(META, b"snapshot_coverage")])?;
    reopened
        .custody()
        .store()
        .write_batch(&[WriteOp::delete(META, LOCAL_FIRST_ASSOCIATION_KEY)])?;
    assert!(first_membership_for_snapshot(reopened.custody(), &snapshot_meta).is_err());
    assert!(read_target_first_membership_history(&reopened, &prebind).is_err());
    reopened.custody().store().write_batch(&[WriteOp::put(
        META,
        LOCAL_FIRST_ASSOCIATION_KEY,
        serde_json::to_vec(&association)?,
    )])?;
    reopened.custody().store().write_batch(&[WriteOp::put(
        META,
        b"committed",
        serde_json::to_vec(&Some(id(0)))?,
    )])?;
    assert!(read_target_first_membership_history(&reopened, &prebind).is_err());
    reopened.custody().store().write_batch(&[WriteOp::put(
        META,
        b"committed",
        serde_json::to_vec(&Some(id(1)))?,
    )])?;
    let mut substituted = prebind.clone();
    substituted.dispatch.attempt_id = uuid::Uuid::new_v4();
    reopened.custody().store().write_batch(&[WriteOp::put(
        META,
        TARGET_PREBIND_KEY,
        serde_json::to_vec(&substituted)?,
    )])?;
    assert!(first_membership_for_snapshot(reopened.custody(), &snapshot_meta).is_err());
    assert!(read_target_first_membership_history(&reopened, &prebind).is_err());
    reopened.custody().store().write_batch(&[
        WriteOp::delete(META, TARGET_PREBIND_KEY),
        WriteOp::delete(META, LOCAL_FIRST_ASSOCIATION_KEY),
    ])?;
    assert!(read_target_first_membership_history(&reopened, &prebind).is_err());
    Ok(())
}

#[tokio::test]
async fn reserved_committed_retirement_recovers_atomic_custody_after_crash_without_app_key()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, app_provider, custody_provider, mut log) =
        fixture(disk.clone(), true, fixture_scratch.clone()).await?;
    log.blocking_append([membership(0), retirement_entry()?])
        .await?;
    let reader = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(
        !reader.recover_retired()?,
        "uncommitted append cannot select retired mode"
    );
    log.save_committed(Some(id(1))).await?;
    let crash = disk.crash();
    app_provider.revoke();
    assert!(stores.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    drop(reader);
    drop(log);
    drop(stores);
    let custody = CustodyStore::open(
        NodeStore::open_with_backend(
            crash.clone(),
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "tenant".into(),
        custody_provider.clone(),
    )
    .await?;
    let reader = ControlLog::open(custody.clone(), 1, group())?;
    assert!(reader.recover_retired()?);
    let saved = custody_state(&custody)?;
    assert_eq!(saved.origin.receipt.revision, 1);
    assert_eq!(saved.origin.receipt.policy_epoch, 2);
    assert_eq!(saved.policy_epoch, 1);
    assert_eq!(app_provider.probe_count(), probes);
    let restarted = crash.crash();
    drop(reader);
    drop(custody);
    let custody = CustodyStore::open(
        NodeStore::open_with_backend(
            restarted,
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "tenant".into(),
        custody_provider,
    )
    .await?;
    assert!(ControlLog::open(custody.clone(), 1, group())?.recover_retired()?);
    assert_eq!(custody_state(&custody)?, saved);
    custody.store().shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn retirement_recovery_crosses_former_seed_count_ceiling_without_promoting_a_tail()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    log.blocking_append([membership(0), retirement_entry()?])
        .await?;
    // These authenticated physical rows are outside committed coverage. Their
    // payloads must never become recovery evidence, regardless of their count.
    // Keep fixture construction bounded too: one small batch at a time.
    let store = stores.custody().store();
    let mut batch = Vec::with_capacity(128);
    for index in 2u64..=100_001 {
        batch.push(WriteOp::put(
            SEEDS,
            index.to_be_bytes(),
            b"uncommitted physical tail",
        ));
        if batch.len() == 128 {
            store.write_batch(&batch)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        store.write_batch(&batch)?;
    }
    let reader = ControlLog::open(stores.custody().clone(), 1, group())?;
    assert!(!reader.recover_retired()?);
    assert!(retired_boundary(stores.custody())?.is_none());
    log.save_committed(Some(id(1))).await?;
    assert!(reader.recover_retired()?);
    let boundary = retired_boundary(stores.custody())?.unwrap();
    assert_eq!(boundary.position.log_id, id(1));
    assert_eq!(boundary.receipt.revision, 1);
    assert!(reader.retirement_seed(100_001)?.is_none());
    stores.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn retirement_recovery_never_selects_between_multiple_committed_successes() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let (stores, _, _, mut log) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    let mut second = retirement_entry()?;
    second.log_id = id(2);
    log.blocking_append([membership(0), retirement_entry()?, second])
        .await?;
    log.save_committed(Some(id(2))).await?;
    let reader = ControlLog::open(stores.custody().clone(), 1, group())?;
    for index in [1, 2] {
        let committed = reader.retirement_seed(index)?.unwrap();
        assert!(committed.seed.recovered_success(index)?.is_some());
    }
    let error = reader.recover_retired().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("multiple successful retirement candidates"),
        "unexpected recovery rejection: {error:#}"
    );
    assert!(retired_boundary(stores.custody())?.is_none());
    assert!(load::<AppliedCursor>(stores.custody().store(), META, b"applied")?.is_none());
    stores.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn exhausted_seed_completion_budget_cannot_promote_a_committed_candidate() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk, true, fixture_scratch.clone()).await?;
    let (command, prior) = seed()?;
    let mut source = prior.source().clone();
    source.max_snapshot_bytes = source.snapshot_bytes + 100;
    let seed = RetirementLogSeed::prepare(&command, source)?;
    assert_eq!(
        seed.reserve_success_capacity().unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    log.blocking_append([
        membership(0),
        Entry {
            log_id: id(1),
            payload: EntryPayload::Normal(RaftCommand::retirement(
                serde_json::to_vec(&command)?,
                seed,
            )?),
        },
    ])
    .await?;
    log.save_committed(Some(id(1))).await?;
    assert!(
        ControlLog::open(stores.custody().clone(), 1, group())?
            .recover_retired()
            .is_err()
    );
    assert!(retired_boundary(stores.custody())?.is_none());
    assert!(load::<AppliedCursor>(stores.custody().store(), META, b"applied")?.is_none());
    Ok(())
}

#[tokio::test]
async fn failed_or_already_applied_without_boundary_cannot_be_reinterpreted_as_retired()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk, true, fixture_scratch.clone()).await?;
    let (mut command, prior) = seed()?;
    command.timestamp_ms = 1001;
    let seed = RetirementLogSeed::prepare(&command, prior.source().clone())?;
    log.blocking_append([
        membership(0),
        Entry {
            log_id: id(1),
            payload: EntryPayload::Normal(RaftCommand::retirement(
                serde_json::to_vec(&command)?,
                seed,
            )?),
        },
    ])
    .await?;
    log.save_committed(Some(id(1))).await?;
    assert!(!ControlLog::open(stores.custody().clone(), 1, group())?.recover_retired()?);
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk, true, fixture_scratch.clone()).await?;
    let entry = retirement_entry()?;
    let digest = match &entry.payload {
        EntryPayload::Normal(command) => sha256(command.bytes()),
        _ => unreachable!(),
    };
    log.blocking_append([membership(0), entry]).await?;
    log.save_committed(Some(id(1))).await?;
    stores.custody().store().write_batch(&[WriteOp::put(
        META,
        b"applied",
        serde_json::to_vec(&AppliedCursor::Entry(AppliedPosition {
            log_id: id(1),
            previous: Some(id(0)),
            membership: StoredMembership::default(),
            command_sha256: digest,
        }))?,
    )])?;
    assert!(
        ControlLog::open(stores.custody().clone(), 1, group())?
            .recover_retired()
            .is_err()
    );
    assert!(retired_boundary(stores.custody())?.is_none());
    Ok(())
}
