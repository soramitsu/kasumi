use super::*;
use crate::staged_terminal::{AppliedIdentity, AppliedOrigin};
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use kasumi_types::{Action, BackupBindingClaim, BackupNamespaceBinding, Grant, Limits, Policy};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn state() -> TenantState {
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
    state.lifecycle_control = Some(std::sync::Arc::new(kasumi_types::LifecycleControlState {
        installation,
        installation_command_id: uuid::Uuid::from_u128(8),
        installation_revision: 0,
        installation_policy_epoch: 0,
        installation_policy: Policy::clone(&state.policy),
        retired: false,
        pending_change: None,
        intent_head: None,
        intent_source: Default::default(),
        pending_intent: None,
        intents: Default::default(),
        changes: Default::default(),
    }));
    state
}
pub(crate) fn row(state: &TenantState, bytes: &[u8], session_id: uuid::Uuid) -> Row {
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
        terminal: None,
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
async fn durable() -> (
    tempfile::TempDir,
    NodeStore,
    Arc<TenantStore>,
    TenantState,
    View,
) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    // Snapshot decoding holds all four staging tables and their native workspaces.
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64);
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
        node.clone(),
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
    install.stage().unwrap();
    store.write_batch(install.writes()).unwrap();
    (directory, node, store, state, install.view)
}

#[tokio::test]
async fn selected_physical_rows_require_current_writer_bytes_without_repair() -> Result<()> {
    let (_directory, _node, store, initial, old) = durable().await;
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

    let alternate_ordinal = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
        &store,
        canonical_ordinal.as_bytes(),
        b" ",
    )?;
    assert!(serde_json::from_slice::<Ordinal>(&alternate_ordinal).is_ok());
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        &namespace,
        ordinal_key.as_slice(),
        alternate_ordinal.as_bytes(),
    )?;
    let Err(error) = selected.row(1) else {
        panic!("selected ordinal accepted alternate writer bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical backup binding ordinal"),
        "{error:#}"
    );
    let observed_ordinal = store.get_bounded(&namespace, &ordinal_key, MAX_ROW_BYTES)?;
    assert_eq!(
        observed_ordinal.as_deref(),
        Some(alternate_ordinal.as_bytes()),
        "failed selected read repaired ordinal bytes"
    );
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        &namespace,
        ordinal_key.as_slice(),
        canonical_ordinal.as_bytes(),
    )?;
    let _ = selected.row(1)?;

    let alternate_point = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
        &store,
        canonical_point.as_bytes(),
        b" ",
    )?;
    assert!(serde_json::from_slice::<Row>(&alternate_point).is_ok());
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        &namespace,
        point_key.as_slice(),
        alternate_point.as_bytes(),
    )?;
    // The same physical row is still ahead of the old view's applied cursor.
    assert!(old.get(session_id)?.is_none());
    let Err(error) = selected.get(session_id) else {
        panic!("selected point accepted alternate writer bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical backup binding point"),
        "{error:#}"
    );
    let observed_point = store.get_bounded(&namespace, &point_key, MAX_ROW_BYTES)?;
    assert_eq!(
        observed_point.as_deref(),
        Some(alternate_point.as_bytes()),
        "failed selected read repaired point bytes"
    );
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        &namespace,
        point_key.as_slice(),
        canonical_point.as_bytes(),
    )?;
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
    let (_directory, _node, store, state, selected) = durable().await;
    let checkpoint = "10".repeat(32);
    let canonical = store
        .get_bounded(CATALOG, checkpoint.as_bytes(), 64 << 10)?
        .expect("current writer must install checkpoint binding");
    let binding: NamespaceBinding = serde_json::from_slice(&canonical)?;
    assert_eq!(serde_json::to_vec(&binding)?, canonical);
    assert!(View::checkpoint_exists(&store, &checkpoint)?);
    selected.prepare_install(&store, &state, &checkpoint, true)?;

    let alternate = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
        &store,
        canonical.as_bytes(),
        b" ",
    )?;
    assert!(serde_json::from_slice::<NamespaceBinding>(&alternate).is_ok());
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        CATALOG,
        checkpoint.as_bytes(),
        alternate.as_bytes(),
    )?;
    assert!(View::checkpoint_exists(&store, &checkpoint)?);
    let error = selected
        .prepare_install(&store, &state, &checkpoint, true)
        .err()
        .expect("alternate checkpoint binding accepted");
    assert!(
        format!("{error:#}").contains("noncanonical backup binding checkpoint binding"),
        "{error:#}"
    );
    let observed_catalog = store.get_bounded(CATALOG, checkpoint.as_bytes(), 64 << 10)?;
    assert_eq!(
        observed_catalog.as_deref(),
        Some(alternate.as_bytes()),
        "failed installation repaired the checkpoint binding"
    );

    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        &store,
        CATALOG,
        checkpoint.as_bytes(),
        canonical.as_bytes(),
    )?;
    let restored = selected.prepare_install(&store, &state, &checkpoint, true)?;
    assert!(restored.writes().is_empty());
    assert_eq!(restored.view.head(), selected.head());
    store.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn committed_point_before_applied_cursor_is_invisible_and_exact_replay_survives() {
    let (_directory, _node, store, initial, old) = durable().await;
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
    let (_directory, _node, store, initial, old) = durable().await;
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
    assert_eq!(reopened.sessions, selected.sessions);
    assert_eq!(reopened.sessions.claimed_without_terminal, 1);
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
    let (directory, node, store, initial, old) = durable().await;
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
    node.shutdown().await.unwrap();
    drop(store);
    assert!(node.retire().is_retired());

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
        let (directory, node, store, initial, old) = durable().await;
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
        node.shutdown().await.unwrap();
        drop(store);
        assert!(node.retire().is_retired());
        let node = NodeStore::open_existing_fixture(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            disk.memory().clone(),
            disk.clone(),
        )
        .unwrap();
        let store = TenantStore::open_existing_fixture(
            node.clone(),
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
            "catalog" => kasumi_store::test_utils::FixtureWriteBatch::prepare(
                &store,
                &[kasumi_store::test_utils::FixtureWrite::Delete(
                    CATALOG,
                    checkpoint.as_bytes(),
                )],
            )
            .unwrap(),
            "point" => kasumi_store::test_utils::FixtureWriteBatch::prepare(
                &store,
                &[kasumi_store::test_utils::FixtureWrite::Delete(
                    &namespace,
                    &id_key(&session_id.to_string()),
                )],
            )
            .unwrap(),
            "index" => kasumi_store::test_utils::FixtureWriteBatch::prepare(
                &store,
                &[kasumi_store::test_utils::FixtureWrite::Put(
                    &namespace,
                    &ordinal_key(1),
                    b"not-json",
                )],
            )
            .unwrap(),
            "alternate-index" => {
                let bytes = store
                    .get_bounded(&namespace, &ordinal_key(1), MAX_ROW_BYTES)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    serde_json::to_vec(&serde_json::from_slice::<Ordinal>(&bytes).unwrap())
                        .unwrap(),
                    bytes
                );
                let alternate = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
                    &store,
                    bytes.as_bytes(),
                    b" ",
                )
                .unwrap();
                kasumi_store::test_utils::FixtureWriteBatch::prepare(
                    &store,
                    &[kasumi_store::test_utils::FixtureWrite::Put(
                        &namespace,
                        &ordinal_key(1),
                        alternate.as_bytes(),
                    )],
                )
                .unwrap()
            }
            _ => unreachable!(),
        };
        damage.write(&store).unwrap();
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
        node.shutdown().await.unwrap();
        drop(store);
        assert!(node.retire().is_retired());
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
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
    )
    .unwrap();
    let control = state();
    let application = crate::TenantEngine::new(
        "application".into(),
        control.incarnation.clone(),
        Policy::clone(&control.policy),
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

async fn exercise_lifecycle_intent_history(count: u64) -> Result<()> {
    use kasumi_types::{
        Command, CommitLifecycleIntent, CredentialResource, LifecycleControlCommand, Operation,
        RequestAuthorization, RequestContext,
    };
    use std::io::{Seek, SeekFrom};
    let (directory, node, store, mut state, installed) = durable().await;
    state.revision = 1;
    state.policy_epoch = 1;
    if count == 3 {
        // An empty backup cohort cannot spend, or overflow, its unrelated cap.
        state.limits.max_backup_binding_bytes = u64::MAX;
    }
    let control = Arc::make_mut(state.lifecycle_control.as_mut().unwrap());
    control.installation_revision = 1;
    control.installation_policy_epoch = 1;
    control.installation.max_intents = 1;
    let mut input = crate::target_completion_machine::tests::origin()
        .materialization
        .request;
    input.authority_partition = control
        .installation
        .partitions
        .keys()
        .next()
        .unwrap()
        .clone();
    input.installation_sha256 = kasumi_types::staged_digest(&control.installation)?.0;
    input.expected_policy_epoch = 1;
    let incarnation = control.installation.root.control_incarnation;
    let time = kasumi_clock::EpochClock::system()?.observe()?;
    let context = RequestContext {
        tenant: state.tenant.clone(),
        principal: "operator".into(),
        request_id: "lifecycle-history".into(),
        scopes: BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::from_verified_credential(
            time.utc_ms() + 86_400_000,
            &time,
            CredentialResource::Control { incarnation },
        )?,
    };
    let commit = |state: &mut TenantState,
                  req: &CommitLifecycleIntent,
                  revision|
     -> Result<kasumi_types::WriteReceipt> {
        state.revision = revision;
        let operation = LifecycleControlCommand::CommitIntent(Box::new(req.clone()));
        let command = Command {
            context: context.clone(),
            timestamp_ms: time.utc_ms(),
            operation: Operation::LifecycleControl(operation.clone()),
        };
        let applied = crate::state::lifecycle::apply(state, &command, &operation, revision)?.0?;
        if let Some((row, head)) =
            super::intents::take_candidate(state, &staged_digest(&command)?.0)?
        {
            ensure!(head.encoded_bytes <= state.limits.max_lifecycle_intent_bytes);
            installed.persist_intent(&row)?;
            Arc::make_mut(state.lifecycle_control.as_mut().unwrap()).intent_head = Some(head);
        }
        Ok(applied)
    };
    // A deployed checkpoint carries original inline kind-15 records. Continue
    // writing after installing its single bounded entry and retain its identity.
    let legacy_id = uuid::Uuid::from_u128(9_999);
    input.command_id = legacy_id;
    let legacy = commit(&mut state, &input, 2)?;
    ensure!(legacy.revision == 2);
    installed.bind_intents(&mut state);
    let first_id = uuid::Uuid::from_u128(10_001);
    let mut previous_generation = None;
    for ordinal in 1..=count {
        input.command_id = uuid::Uuid::from_u128(10_000 + u128::from(ordinal));
        let receipt = commit(&mut state, &input, ordinal + 2)?;
        if count == 3 && ordinal == 1 {
            previous_generation = Some(state.clone());
        }
        ensure!(
            receipt.revision == ordinal + 2
                && state.lifecycle_control.as_ref().unwrap().intents.len() == 1
        );
    }
    if let Some(old) = previous_generation {
        ensure!(
            old.lifecycle_intent(input.command_id)?.is_none()
                && old.lifecycle_intent(first_id)?.is_some(),
            "unselected future command became visible to an older generation"
        );
    }
    let last = state
        .lifecycle_intent(input.command_id)?
        .context("missing last lifecycle command")?
        .clone();
    let first = state
        .lifecycle_intent(first_id)?
        .context("missing original command")?
        .clone();
    ensure!(first.revision == 3 && last.revision == count + 2);
    let control = state.lifecycle_control.as_ref().unwrap();
    let head = control.intent_head.clone().unwrap();
    ensure!(head.count == count && head.encoded_bytes > 0 && control.installation.max_intents == 1);
    let replay = commit(&mut state, &first.request, count + 3)?;
    ensure!(
        replay.revision == first.revision
            && state
                .lifecycle_control
                .as_ref()
                .unwrap()
                .intent_head
                .as_ref()
                == Some(&head)
    );
    let mut changed = first.request.clone();
    changed.phase_input_sha256 = "ab".repeat(32);
    ensure!(commit(&mut state, &changed, count + 4).is_err());
    let mut image = tempfile::tempfile_in(directory.path())?;
    crate::snapshot_codec::write(
        &state,
        &crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)?,
        &installed,
        &crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
        &crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
        &mut image,
    )?;
    let disk = store.scratch_disk().clone();
    image.seek(SeekFrom::Start(0))?;
    let decoded = crate::snapshot_codec::read(&disk, &mut image)
        .expect("valid mixed-version snapshot must decode");
    ensure!(
        decoded.state.lifecycle_intent(first_id)?.as_deref() == Some(&first)
            && decoded.state.lifecycle_intent(input.command_id)?.as_deref() == Some(&last)
    );
    // Keep an actual missing chunk fatal to both ordered reducers. The public
    // wire error remains bounded while the private owner retains its native cause.
    if count == 3 {
        let namespace = match installed.source.as_deref().unwrap() {
            Source::Durable(rows) => rows.binding.namespace(),
            _ => unreachable!(),
        };
        let chunk = [
            b"lifecycle/chunk/".as_slice(),
            first_id.as_bytes(),
            &0u64.to_be_bytes(),
        ]
        .concat();
        let saved = store
            .get_bounded(&namespace, &chunk, 256 << 10)?
            .context("original lifecycle chunk")?;
        store.write_batch(&[WriteOp::delete(&namespace, chunk.as_slice())])?;
        let failure = state
            .lifecycle_intent(first_id)
            .err()
            .context("missing lifecycle chunk was not fatal")?;
        ensure!(
            failure.has_physical_source() && failure.code == kasumi_types::ErrorCode::Corruption
        );
        let fatal = crate::state::recovery::ordered_recovery_outcome::<()>(Err(
            kasumi_query::ReadFailure::Query(failure.clone()),
        ))
        .unwrap_err();
        ensure!(fatal.chain().any(|cause| {
            cause
                .to_string()
                .contains("selected lifecycle intent chunk missing")
        }));
        ensure!(!serde_json::to_string(&failure)?.contains("chunk missing"));
        store.write_batch(&[WriteOp::put(&namespace, chunk, saved.as_bytes())])?;
        drop(saved);
        let ordinal_key = [b"lifecycle/ordinal/".as_slice(), &1u64.to_be_bytes()].concat();
        let saved = store
            .get_bounded(&namespace, &ordinal_key, 512)?
            .context("original selected ordinal")?;
        let redirected = serde_json::to_vec(
            &serde_json::json!({"id":input.command_id,"sha256":"cd".repeat(32)}),
        )?;
        store.write_batch(&[WriteOp::put(&namespace, ordinal_key.clone(), redirected)])?;
        let failure = state
            .lifecycle_intent(first_id)
            .err()
            .context("redirected historical ordinal accepted")?;
        ensure!(failure.has_physical_source());
        store.write_batch(&[WriteOp::put(&namespace, ordinal_key, saved.as_bytes())])?;
        drop(saved);
        let point_key = [b"lifecycle/id/".as_slice(), first_id.as_bytes()].concat();
        let saved = store
            .get_bounded(&namespace, &point_key, 512)?
            .context("original point descriptor")?;
        store.write_batch(&[WriteOp::delete(&namespace, point_key.as_slice())])?;
        ensure!(
            state
                .lifecycle_intent(first_id)
                .err()
                .is_some_and(|e| e.has_physical_source()),
            "selected payload without a descriptor became an unseen command"
        );
        store.write_batch(&[WriteOp::put(&namespace, point_key, saved.as_bytes())])?;
        drop(saved);
        let mut duplicate = state.clone();
        Arc::make_mut(duplicate.lifecycle_control.as_mut().unwrap())
            .intents
            .insert(first_id, first.clone());
        ensure!(
            duplicate
                .lifecycle_intent(first_id)
                .err()
                .is_some_and(|e| e.has_physical_source())
        );
        Arc::make_mut(duplicate.lifecycle_control.as_mut().unwrap())
            .intents
            .remove(&legacy_id);
        let mut invalid = tempfile::tempfile_in(directory.path())?;
        crate::snapshot_codec::write(
            &duplicate,
            &crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)?,
            &installed,
            &crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
            &crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
            &mut invalid,
        )?;
        invalid.seek(SeekFrom::Start(0))?;
        ensure!(
            crate::snapshot_codec::read(&disk, &mut invalid).is_err(),
            "mixed legacy and new duplicate was restored"
        );
    }
    ensure!(
        decoded
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .intents
            .len()
            == 1
            && decoded.state.lifecycle_intent(legacy_id)?.unwrap().revision == legacy.revision
    );
    let checkpoint = "51".repeat(32);
    store.write_batch(&installed.checkpoint_writes(&state, &checkpoint)?)?;
    if count == 3 {
        store.seal();
        let physical = state
            .lifecycle_intent(first_id)
            .err()
            .context("sealed owner was accepted")?;
        ensure!(physical.has_physical_source());
        let private = crate::state::recovery::ordered_recovery_outcome::<()>(Err(
            kasumi_query::ReadFailure::Query(physical),
        ))
        .unwrap_err();
        ensure!(private.chain().any(|cause| {
            cause
                .downcast_ref::<kasumi_store::KeyAccessDenied>()
                .is_some()
        }));
    }
    drop(state);
    drop(installed);
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    ensure!(node.retire().is_retired());
    let node = NodeStore::open_existing_fixture(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        disk.memory().clone(),
        disk,
    )
    .expect("original node store must reopen");
    let store = TenantStore::open_existing_fixture(
        node.clone(),
        crate::control::CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await?;
    let reopen =
        decoded
            .backup_bindings
            .prepare_install(&store, &decoded.state, &checkpoint, true)?;
    let mut restored = decoded.state;
    reopen.view.bind_intents(&mut restored);
    ensure!(
        restored.lifecycle_intent(first_id)?.as_deref() == Some(&first)
            && restored.lifecycle_intent(input.command_id)?.as_deref() == Some(&last)
    );
    drop(restored);
    drop(reopen);
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    ensure!(node.retire().is_retired());
    println!(
        "KASUMI_LIFECYCLE_HISTORY {}",
        serde_json::json!({"selected_intents":count,"resident_legacy_intents":1,"previous_max_intents":10000,"installed_max_intents":1,
        "bytes":head.encoded_bytes,"sha256":head.sha256,"replayed_first_revision":replay.revision,"fresh_store_reopen":true,"both_stores_drained":true})
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_intent_prefix_survives_snapshot_and_store_reopen() -> Result<()> {
    exercise_lifecycle_intent_history(3).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit permanent lifecycle capacity cohort; applies 10,001 original Control commands"]
async fn lifecycle_history_crosses_ten_thousand_ordered_control_intents() -> Result<()> {
    exercise_lifecycle_intent_history(10_001).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_row_exceeding_one_scratch_batch_stages_and_preserves_owner_refusal() -> Result<()>
{
    use kasumi_types::{LifecycleIntentHead, LifecycleIntentRow, LifecycleIntentRows};
    let (_directory, node, store, mut state, initial) = durable().await;
    // This lower-layer fixture intentionally exceeds the semantic principal-name
    // limit to exercise the full permitted physical frame, independent of commands.
    let mut intent = crate::target_completion_machine::tests::origin().materialization;
    let control = Arc::make_mut(state.lifecycle_control.as_mut().unwrap());
    intent.control_incarnation = control.installation.root.control_incarnation;
    intent.original_principal = "a".repeat(kasumi_store::EncryptedTableBatch::MAX_BYTES + 1);
    intent.revision = 2;
    let id = intent.request.command_id;
    let max = control.installation.max_state_bytes;
    let genesis = LifecycleIntentHead::empty(intent.control_incarnation)?;
    let row = LifecycleIntentRow {
        ordinal: 1,
        previous_sha256: genesis.sha256.clone(),
        command_sha256: "ab".repeat(32),
        intent,
    };
    let head = super::intents::advance(&genesis, &row)?;
    control.intent_head = Some(head.clone());
    let mut builder = Builder::new(
        store.scratch_disk(),
        super::scratch_limit(head.encoded_bytes)?,
        &state.backup_binding_head.origin_incarnation,
    )
    .expect("physical fixture needs an encrypted scratch table");
    ensure!(
        builder
            .push_intent(&row, control, head.encoded_bytes - 1)
            .is_err()
    );
    builder.push_intent(&row, control, head.encoded_bytes)?;
    let staged = builder.finish(&state.backup_binding_head)?;
    let install = staged.prepare_install(&store, &state, &"51".repeat(32), false)?;
    install.stage()?;
    store.write_batch(install.writes())?;
    let durable = install.view.source.as_ref().unwrap();
    for source in [staged.source.as_ref().unwrap(), durable] {
        let too_small = source
            .point(&head, id, 8192)
            .err()
            .context("over-limit point was accepted")?;
        ensure!(anyhow::Error::from(too_small).chain().any(|cause| {
            cause
                .to_string()
                .contains("invalid lifecycle point descriptor")
        }));
        let denied = source
            .point(&head, id, max)
            .err()
            .context("over-budget decode was accepted")?;
        ensure!(denied.has_physical_source());
        ensure!(anyhow::Error::from(denied).chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::OutOfMemory)
        }));
    }
    drop(install);
    drop(initial);
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    ensure!(node.retire().is_retired());
    println!(
        "KASUMI_LIFECYCLE_CHUNKS {}",
        serde_json::json!({"canonical_row_bytes":crate::accounting::encoded_len(&row)?,"selected_bytes":head.encoded_bytes,"backup_rows":state.backup_binding_head.count,"staged_and_durable":true,"retained_owner_refusal":true,"drained":true})
    );
    Ok(())
}
