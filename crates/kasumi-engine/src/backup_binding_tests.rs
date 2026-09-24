use super::*;
use crate::staged_terminal::{AppliedIdentity, AppliedOrigin};
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use kasumi_types::{Action, BackupBindingClaim, BackupNamespaceBinding, Grant, Limits, Policy};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};

fn state() -> TenantState {
    let incarnation = uuid::Uuid::from_u128(99).to_string();
    let mut state = crate::TenantEngine::new(
        crate::control::CONTROL_TENANT.into(),
        incarnation.clone(),
        Policy {
            grants: vec![Grant {
                principal: "operator".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    let partition = kasumi_types::ControlAuthorityPartition {
        authority_id: uuid::Uuid::from_u128(7),
        manifest_sha256: "12".repeat(32),
        partition: 0,
        signing_public_key: "34".repeat(32),
        maximum_lifetime_ms: 1000,
        drain_ms: 1000,
    };
    let installation = kasumi_types::LifecycleInstallation {
        root: kasumi_types::ControlSigningRoot {
            control_incarnation: uuid::Uuid::parse_str(&incarnation).unwrap(),
            public_key: "56".repeat(32),
        },
        generation: 1,
        partitions: BTreeMap::from([(partition.key(), partition)]),
        max_intents: 100,
        max_changes: 10,
        max_state_bytes: 8 << 20,
    };
    installation.validate().unwrap();
    state.lifecycle_control = Some(kasumi_types::LifecycleControlState {
        installation,
        installation_command_id: uuid::Uuid::from_u128(8),
        installation_revision: 0,
        installation_policy_epoch: 0,
        installation_policy: state.policy.clone(),
        retired: false,
        pending_change: None,
        intents: Default::default(),
        changes: Default::default(),
    });
    state
}
fn row(state: &TenantState, bytes: &[u8], session_id: uuid::Uuid) -> Row {
    let claim = BackupBindingClaim {
        session_id,
        tenant: "tenant-a".into(),
        source_incarnation: "source-a".into(),
        revision: 7,
        source_purpose_sha256: "ab".repeat(32),
        namespace_binding: BackupNamespaceBinding::Filesystem {
            installation_id: uuid::Uuid::from_u128(1),
            origin_node_id: 1,
            namespace_id: uuid::Uuid::from_u128(2),
            device: 4,
            inode: 9,
        },
        destination_alias: Some("alias-a".into()),
        binding_nonce: uuid::Uuid::from_u128(3),
        intent_ciphertext_sha256: format!("{:x}", sha2::Sha256::digest(bytes)),
        principal: "operator".into(),
        request_id: "request-a".into(),
        command_id: uuid::Uuid::from_u128(4),
        intent_ciphertext: bytes.into(),
    };
    Row {
        ordinal: 1,
        key: session_id.to_string(),
        previous_sha256: state.backup_binding_head.sha256.clone(),
        applied: AppliedIdentity {
            incarnation: state.incarnation.clone(),
            revision: 1,
            timestamp_ms: 1000,
            command_sha256: "cd".repeat(32),
            origin: AppliedOrigin::Raft {
                term: 1,
                leader: 1,
                index: 1,
                context_sha256: "ef".repeat(32),
            },
        },
        record: BackupBindingRecord {
            claim,
            position: kasumi_types::BackupBindingPosition {
                term: 1,
                index: 1,
                command_sha256: "cd".repeat(32),
            },
        },
    }
}
async fn durable() -> (tempfile::TempDir, Arc<TenantStore>, TenantState, View) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
    kasumi_store::private_files::create_directory(&directory.path().join("persistent")).unwrap();
    let disk = ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
    let node = NodeStore::create_new_fixture(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        memory,
        disk,
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node,
        crate::control::CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await
    .unwrap();
    let state = state();
    let empty = View::empty(&state.incarnation).unwrap();
    let install = empty
        .prepare_install(&store, &state, &"10".repeat(32), false)
        .unwrap();
    store
        .replace_namespaces(&install.replacements(), install.writes())
        .unwrap();
    (directory, store, state, install.view)
}

#[tokio::test]
async fn selected_physical_rows_require_current_writer_bytes_without_repair() -> Result<()> {
    let (_directory, store, initial, old) = durable().await;
    let session_id = uuid::Uuid::from_u128(50);
    let mut state = initial.clone();
    state.revision = 1;
    let pending = Pending::prepare(
        &old,
        &state,
        row(&initial, b"selected-writer-bytes", session_id),
    )?;
    state.backup_binding_head = pending.head().clone();
    let selected = pending.persist()?;
    let checkpoint = "51".repeat(32);
    store.write_batch(&selected.checkpoint_writes(&state, &checkpoint)?)?;
    let point_key = id_key(&session_id.to_string());
    let namespace = match selected.source.as_deref() {
        Some(Source::Durable(rows)) => rows.binding.namespace(),
        _ => panic!("fixture requires durable selected rows"),
    };
    let ordinal_key = ordinal_key(1);
    let canonical_ordinal = store
        .get_bounded(&namespace, &ordinal_key, MAX_ROW_BYTES)?
        .expect("current writer must persist selected ordinal");
    let canonical_point = store
        .get_bounded(&namespace, &point_key, MAX_ROW_BYTES)?
        .expect("current writer must persist selected point");
    assert_eq!(
        serde_json::to_vec(&serde_json::from_slice::<Ordinal>(&canonical_ordinal)?)?,
        canonical_ordinal
    );
    assert_eq!(
        serde_json::to_vec(&serde_json::from_slice::<Row>(&canonical_point)?)?,
        canonical_point
    );
    let _ = selected.row(1)?;

    let mut alternate_ordinal = canonical_ordinal.clone();
    alternate_ordinal.push(b' ');
    assert!(serde_json::from_slice::<Ordinal>(&alternate_ordinal).is_ok());
    store.write_batch(&[WriteOp::put(
        &namespace,
        ordinal_key.as_slice(),
        alternate_ordinal.as_slice(),
    )])?;
    let Err(error) = selected.row(1) else {
        panic!("selected ordinal accepted alternate writer bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical backup binding ordinal"),
        "{error:#}"
    );
    assert_eq!(
        store.get_bounded(&namespace, &ordinal_key, MAX_ROW_BYTES)?,
        Some(alternate_ordinal),
        "failed selected read repaired ordinal bytes"
    );
    store.write_batch(&[WriteOp::put(
        &namespace,
        ordinal_key.as_slice(),
        canonical_ordinal.as_slice(),
    )])?;
    let _ = selected.row(1)?;

    let mut alternate_point = canonical_point.clone();
    alternate_point.push(b' ');
    assert!(serde_json::from_slice::<Row>(&alternate_point).is_ok());
    store.write_batch(&[WriteOp::put(
        &namespace,
        point_key.as_slice(),
        alternate_point.as_slice(),
    )])?;
    // The same physical row is still ahead of the old view's applied cursor.
    assert!(old.get(session_id)?.is_none());
    let Err(error) = selected.get(session_id) else {
        panic!("selected point accepted alternate writer bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical backup binding point"),
        "{error:#}"
    );
    assert_eq!(
        store.get_bounded(&namespace, &point_key, MAX_ROW_BYTES)?,
        Some(alternate_point),
        "failed selected read repaired point bytes"
    );
    store.write_batch(&[WriteOp::put(
        &namespace,
        point_key.as_slice(),
        canonical_point.as_slice(),
    )])?;
    assert_eq!(
        selected
            .get(session_id)?
            .unwrap()
            .record
            .claim
            .intent_ciphertext,
        b"selected-writer-bytes"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn checkpoint_catalog_requires_current_writer_bytes_without_repair() -> Result<()> {
    let (_directory, store, state, selected) = durable().await;
    let checkpoint = "10".repeat(32);
    let canonical = store
        .get_bounded(CATALOG, checkpoint.as_bytes(), 64 << 10)?
        .expect("current writer must install checkpoint binding");
    let binding: NamespaceBinding = serde_json::from_slice(&canonical)?;
    assert_eq!(serde_json::to_vec(&binding)?, canonical);
    assert!(View::checkpoint_exists(&store, &checkpoint)?);
    selected.prepare_install(&store, &state, &checkpoint, true)?;

    let mut alternate = canonical.clone();
    alternate.push(b' ');
    assert!(serde_json::from_slice::<NamespaceBinding>(&alternate).is_ok());
    store.write_batch(&[WriteOp::put(
        CATALOG,
        checkpoint.as_bytes(),
        alternate.as_slice(),
    )])?;
    assert!(View::checkpoint_exists(&store, &checkpoint)?);
    let error = selected
        .prepare_install(&store, &state, &checkpoint, true)
        .err()
        .expect("alternate checkpoint binding accepted");
    assert!(
        format!("{error:#}").contains("noncanonical backup binding checkpoint binding"),
        "{error:#}"
    );
    assert_eq!(
        store.get_bounded(CATALOG, checkpoint.as_bytes(), 64 << 10)?,
        Some(alternate),
        "failed installation repaired the checkpoint binding"
    );

    store.write_batch(&[WriteOp::put(
        CATALOG,
        checkpoint.as_bytes(),
        canonical.as_slice(),
    )])?;
    let restored = selected.prepare_install(&store, &state, &checkpoint, true)?;
    assert!(restored.replacements().is_empty());
    assert_eq!(restored.view.head(), selected.head());
    store.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn committed_point_before_applied_cursor_is_invisible_and_exact_replay_survives() {
    let (_directory, store, initial, old) = durable().await;
    let session_id = uuid::Uuid::from_u128(5);
    let mut next = initial.clone();
    next.revision = 1;
    let pending = Pending::prepare(
        &old,
        &next,
        row(&initial, b"encrypted-intent-a", session_id),
    )
    .unwrap();
    next.backup_binding_head = pending.head().clone();
    let committed = pending.persist().unwrap();
    assert!(old.get(session_id).unwrap().is_none());
    assert_eq!(
        committed
            .get(session_id)
            .unwrap()
            .unwrap()
            .record
            .claim
            .intent_ciphertext,
        b"encrypted-intent-a"
    );
    assert_eq!(
        committed.get(session_id).unwrap().unwrap().record.position,
        kasumi_types::BackupBindingPosition {
            term: 1,
            index: 1,
            command_sha256: "cd".repeat(32),
        }
    );
    let mut replay_state = initial.clone();
    replay_state.revision = 1;
    let replay = Pending::prepare(
        &old,
        &replay_state,
        row(&initial, b"encrypted-intent-a", session_id),
    )
    .unwrap();
    assert_eq!(replay.persist().unwrap().head(), committed.head());
    let altered = Pending::prepare(
        &old,
        &replay_state,
        row(&initial, b"encrypted-intent-b", session_id),
    )
    .unwrap();
    assert!(
        altered
            .persist()
            .unwrap_err()
            .to_string()
            .contains("exact command replay")
    );
    assert!(old.get(session_id).unwrap().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn selected_checkpoint_reopens_exact_row_and_rejects_changed_head() {
    let (_directory, store, initial, old) = durable().await;
    let session_id = uuid::Uuid::from_u128(6);
    let mut selected_state = initial.clone();
    selected_state.revision = 1;
    let pending = Pending::prepare(
        &old,
        &selected_state,
        row(&initial, b"retained-encrypted-intent", session_id),
    )
    .unwrap();
    selected_state.backup_binding_head = pending.head().clone();
    let selected = pending.persist().unwrap();
    let checkpoint = "11".repeat(32);
    store
        .write_batch(
            &selected
                .checkpoint_writes(&selected_state, &checkpoint)
                .unwrap(),
        )
        .unwrap();
    let reopened = selected
        .prepare_install(&store, &selected_state, &checkpoint, true)
        .unwrap()
        .view;
    assert_eq!(
        reopened
            .get(session_id)
            .unwrap()
            .unwrap()
            .record
            .claim
            .intent_ciphertext,
        b"retained-encrypted-intent"
    );
    let receipts =
        crate::mutation_receipt::View::empty(&selected_state.tenant, &selected_state.incarnation)
            .unwrap();
    let terminals =
        crate::staged_terminal::View::empty(&selected_state.tenant, &selected_state.incarnation)
            .unwrap();
    let resolutions =
        crate::target_resolution::View::empty(&selected_state.tenant, &selected_state.incarnation)
            .unwrap();
    let mut snapshot = Vec::new();
    crate::snapshot_codec::write(
        &selected_state,
        &receipts,
        &selected,
        &terminals,
        &resolutions,
        &mut snapshot,
    )
    .unwrap();
    let decoded =
        crate::snapshot_codec::read(store.scratch_disk(), &mut snapshot.as_slice()).unwrap();
    assert_eq!(
        decoded
            .backup_bindings
            .get(session_id)
            .unwrap()
            .unwrap()
            .record
            .claim
            .intent_ciphertext,
        b"retained-encrypted-intent"
    );
    let mut changed = selected_state.clone();
    changed.backup_binding_head.sha256 = "ff".repeat(32);
    assert!(
        selected
            .prepare_install(&store, &changed, &checkpoint, true)
            .is_err()
    );
    store.shutdown().await.unwrap();
}

#[test]
fn row_admission_binds_exact_control_position_and_intent_size() {
    let mut state = state();
    state.revision = 1;
    let session_id = uuid::Uuid::from_u128(7);
    let row = row(
        &state,
        &vec![0xff; kasumi_types::MAX_BACKUP_BINDING_INTENT_BYTES],
        session_id,
    );
    row.validate(&state).unwrap();
    let charged = row.framed_bytes().unwrap();
    assert!(charged <= state.limits.max_backup_binding_bytes);
    let empty = View::empty(&state.incarnation).unwrap();
    let mut one_below = state.clone();
    one_below.limits.max_backup_binding_bytes = charged - 1;
    assert!(Pending::prepare(&empty, &one_below, row.clone()).is_err());
    let mut exact = state.clone();
    exact.limits.max_backup_binding_bytes = charged;
    assert!(Pending::prepare(&empty, &exact, row.clone()).is_ok());

    let mut changed = row.clone();
    changed.record.position.index = 2;
    assert!(changed.validate(&state).is_err());

    let mut oversized = row;
    oversized.record.claim.intent_ciphertext.push(0xff);
    oversized.record.claim.intent_ciphertext_sha256 = format!(
        "{:x}",
        sha2::Sha256::digest(&oversized.record.claim.intent_ciphertext)
    );
    assert!(oversized.validate(&state).is_err());
}

#[test]
fn application_snapshot_has_no_control_binding_catalog() {
    let mut state = state();
    state.tenant = "application".into();
    state.lifecycle_control = None;
    let empty = View::empty(&state.incarnation).unwrap();
    empty.validate_state(&state).unwrap();
    assert!(
        empty
            .checkpoint_writes(&state, &"12".repeat(32))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn encrypted_restart_keeps_future_binding_invisible_until_exact_replay() {
    let (directory, store, initial, old) = durable().await;
    let disk = store.scratch_disk().clone();
    let session_id = uuid::Uuid::from_u128(8);
    let mut replay_state = initial.clone();
    replay_state.revision = 1;
    let future = Pending::prepare(
        &old,
        &replay_state,
        row(&initial, b"future-encrypted-intent", session_id),
    )
    .unwrap();
    let expected_head = future.head().clone();
    let future = future.persist().unwrap();
    assert!(old.get(session_id).unwrap().is_none());
    assert_eq!(future.head(), &expected_head);
    drop(future);
    drop(old);
    store.shutdown().await.unwrap();
    drop(store);

    let node = NodeStore::open_existing_fixture(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        disk.memory().clone(),
        disk,
    )
    .unwrap();
    let store = TenantStore::open_existing_fixture(
        node,
        crate::control::CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await
    .unwrap();
    let empty = View::empty(&initial.incarnation).unwrap();
    let reopened = empty
        .prepare_install(&store, &initial, &"10".repeat(32), true)
        .unwrap()
        .view;
    assert!(reopened.get(session_id).unwrap().is_none());
    let exact = Pending::prepare(
        &reopened,
        &replay_state,
        row(&initial, b"future-encrypted-intent", session_id),
    )
    .unwrap();
    assert_eq!(exact.head(), &expected_head);
    let committed = exact.persist().unwrap();
    assert_eq!(committed.head(), &expected_head);
    assert_eq!(
        committed
            .get(session_id)
            .unwrap()
            .unwrap()
            .record
            .claim
            .intent_ciphertext,
        b"future-encrypted-intent"
    );
    let altered = Pending::prepare(
        &reopened,
        &replay_state,
        row(&initial, b"different-encrypted-intent", session_id),
    )
    .unwrap();
    assert!(
        altered
            .persist()
            .unwrap_err()
            .to_string()
            .contains("exact command replay")
    );
    assert!(reopened.get(session_id).unwrap().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_bootstrap_rejects_missing_catalog_point_and_corrupt_index_after_restart() {
    for fault in ["catalog", "point", "index", "alternate-index"] {
        let (directory, store, initial, old) = durable().await;
        let disk = store.scratch_disk().clone();
        let session_id = uuid::Uuid::from_u128(9);
        let mut selected_state = initial.clone();
        selected_state.revision = 1;
        let pending = Pending::prepare(
            &old,
            &selected_state,
            row(&initial, b"selected-encrypted-intent", session_id),
        )
        .unwrap();
        selected_state.backup_binding_head = pending.head().clone();
        let selected = pending.persist().unwrap();
        let checkpoint = "13".repeat(32);
        store
            .write_batch(
                &selected
                    .checkpoint_writes(&selected_state, &checkpoint)
                    .unwrap(),
            )
            .unwrap();
        let namespace = match selected.source.as_deref() {
            Some(Source::Durable(rows)) => rows.binding.namespace(),
            _ => panic!("fixture requires durable binding rows"),
        };
        let receipts = crate::mutation_receipt::View::empty(
            &selected_state.tenant,
            &selected_state.incarnation,
        )
        .unwrap();
        let terminals = crate::staged_terminal::View::empty(
            &selected_state.tenant,
            &selected_state.incarnation,
        )
        .unwrap();
        let resolutions = crate::target_resolution::View::empty(
            &selected_state.tenant,
            &selected_state.incarnation,
        )
        .unwrap();
        let mut snapshot = Vec::new();
        crate::snapshot_codec::write(
            &selected_state,
            &receipts,
            &selected,
            &terminals,
            &resolutions,
            &mut snapshot,
        )
        .unwrap();
        let staged = crate::snapshot_codec::read(&disk, &mut snapshot.as_slice())
            .unwrap()
            .backup_bindings;
        assert!(staged.get(session_id).unwrap().is_some());

        drop(selected);
        drop(old);
        store.shutdown().await.unwrap();
        drop(store);
        let node = NodeStore::open_existing_fixture(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            disk.memory().clone(),
            disk.clone(),
        )
        .unwrap();
        let store = TenantStore::open_existing_fixture(
            node,
            crate::control::CONTROL_TENANT.into(),
            Arc::new(LocalKeyProvider::new([89; 32])),
        )
        .await
        .unwrap();
        let healthy = staged
            .prepare_install(&store, &selected_state, &checkpoint, true)
            .unwrap()
            .view;
        assert_eq!(
            healthy
                .get(session_id)
                .unwrap()
                .unwrap()
                .record
                .claim
                .intent_ciphertext,
            b"selected-encrypted-intent"
        );
        drop(healthy);

        let damage = match fault {
            "catalog" => WriteOp::delete(CATALOG, checkpoint.as_bytes()),
            "point" => WriteOp::delete(&namespace, id_key(&session_id.to_string())),
            "index" => WriteOp::put(&namespace, ordinal_key(1), b"not-json".to_vec()),
            "alternate-index" => {
                let mut bytes = store
                    .get_bounded(&namespace, &ordinal_key(1), MAX_ROW_BYTES)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    serde_json::to_vec(&serde_json::from_slice::<Ordinal>(&bytes).unwrap())
                        .unwrap(),
                    bytes
                );
                bytes.push(b' ');
                WriteOp::put(&namespace, ordinal_key(1), bytes)
            }
            _ => unreachable!(),
        };
        store.write_batch(&[damage]).unwrap();
        match fault {
            "catalog" => assert!(
                store
                    .get_bounded(CATALOG, checkpoint.as_bytes(), 64 << 10)
                    .unwrap()
                    .is_none()
            ),
            "point" => assert!(
                store
                    .get_bounded(&namespace, &id_key(&session_id.to_string()), MAX_ROW_BYTES)
                    .unwrap()
                    .is_none()
            ),
            "index" => assert_eq!(
                store
                    .get_bounded(&namespace, &ordinal_key(1), MAX_ROW_BYTES)
                    .unwrap()
                    .as_deref(),
                Some(b"not-json".as_slice())
            ),
            "alternate-index" => {
                let bytes = store
                    .get_bounded(&namespace, &ordinal_key(1), MAX_ROW_BYTES)
                    .unwrap()
                    .unwrap();
                assert_eq!(bytes.last(), Some(&b' '));
                assert!(serde_json::from_slice::<Ordinal>(&bytes).is_ok());
            }
            _ => unreachable!(),
        }
        store.shutdown().await.unwrap();
        drop(store);
        let node = NodeStore::open_existing_fixture(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            disk.memory().clone(),
            disk,
        )
        .unwrap();
        let store = TenantStore::open_existing_fixture(
            node,
            crate::control::CONTROL_TENANT.into(),
            Arc::new(LocalKeyProvider::new([89; 32])),
        )
        .await
        .unwrap();
        let error = staged
            .prepare_install(&store, &selected_state, &checkpoint, true)
            .err()
            .expect("snapshot bootstrap accepted damaged checkpoint");
        match fault {
            "catalog" => assert!(
                error
                    .to_string()
                    .contains("authoritative backup binding checkpoint missing"),
                "{error:#}"
            ),
            "point" => assert!(
                error
                    .to_string()
                    .contains("backup binding checkpoint row missing"),
                "{error:#}"
            ),
            "index" => assert!(
                error.downcast_ref::<serde_json::Error>().is_some(),
                "{error:#}"
            ),
            "alternate-index" => {
                assert!(
                    format!("{error:#}").contains("noncanonical backup binding ordinal"),
                    "{error:#}"
                );
                assert_eq!(
                    store
                        .get_bounded(&namespace, &ordinal_key(1), MAX_ROW_BYTES)
                        .unwrap()
                        .unwrap()
                        .last(),
                    Some(&b' '),
                    "failed restart repaired alternate ordinal bytes"
                );
            }
            _ => unreachable!(),
        }
        store.shutdown().await.unwrap();
    }
}

#[test]
fn application_snapshot_validator_rejects_nonempty_control_binding_head_and_row() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let control = state();
    let application = crate::TenantEngine::new(
        "application".into(),
        control.incarnation.clone(),
        control.policy.clone(),
        control.limits.clone(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    let receipts =
        crate::mutation_receipt::View::empty(&application.tenant, &application.incarnation)
            .unwrap();
    let bindings = View::empty(&application.incarnation).unwrap();
    let terminals =
        crate::staged_terminal::View::empty(&application.tenant, &application.incarnation).unwrap();
    let resolutions =
        crate::target_resolution::View::empty(&application.tenant, &application.incarnation)
            .unwrap();
    let mut baseline = Vec::new();
    crate::snapshot_codec::write(
        &application,
        &receipts,
        &bindings,
        &terminals,
        &resolutions,
        &mut baseline,
    )
    .unwrap();
    let baseline = kasumi_store::SnapshotImage::from_bytes(&scratch.disk, &baseline).unwrap();
    crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
        baseline,
        128 << 20,
        || Ok(()),
    )
    .unwrap();

    let binding_row = row(
        &control,
        b"forbidden-control-intent",
        uuid::Uuid::from_u128(10),
    );
    let mut forged = application;
    forged.revision = 1;
    advance(&mut forged.backup_binding_head, &binding_row).unwrap();
    let encode = |with_row: bool| {
        let mut bytes = Vec::new();
        let mut encoder = crate::snapshot_codec::Encoder::new(&mut bytes).unwrap();
        for kind in 0..21 {
            for record in crate::snapshot_codec::records(&forged, kind, None).unwrap() {
                encoder.record(record.unwrap()).unwrap();
            }
        }
        for record in crate::snapshot_codec::records(&forged, 23, None).unwrap() {
            encoder.record(record.unwrap()).unwrap();
        }
        if with_row {
            encoder
                .record(crate::snapshot_codec::Record::BackupBinding(Box::new(
                    binding_row.clone(),
                )))
                .unwrap();
        }
        encoder.finish().unwrap();
        bytes
    };
    let image = kasumi_store::SnapshotImage::from_bytes(&scratch.disk, &encode(false)).unwrap();
    let error = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
        image,
        128 << 20,
        || Ok(()),
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("Control state cannot be an application backup"),
        "{error}"
    );
    let image = kasumi_store::SnapshotImage::from_bytes(&scratch.disk, &encode(true)).unwrap();
    let error = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
        image,
        128 << 20,
        || Ok(()),
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("backup binding point row requires installed Control"),
        "{error}"
    );
}
