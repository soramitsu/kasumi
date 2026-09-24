use super::*;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::collections::{BTreeMap, BTreeSet};

fn state() -> TenantState {
    crate::TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
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
    .clone()
}
fn active(id: &str) -> StagedTransaction {
    let manifest = StagedManifest::from_chunks(&[StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Delete {
            collection: "docs".into(),
            id: "row".into(),
            expected: Precondition::Any,
        }],
    }])
    .unwrap();
    StagedTransaction {
        scope: StagedTransactionScope {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            principal: "owner".into(),
        },
        transaction_id: id.into(),
        manifest_digest: staged_digest(&manifest).unwrap().0,
        manifest,
        chunks: Default::default(),
        stored_chunk_bytes: 0,
        uploaded_payload_bytes: 0,
        uploaded_operations: 0,
        uploaded_read_assertions: 0,
        expires_at_ms: Some(60000),
        ttl_ms: 60000,
        outcome: StagedOutcome::Uploading,
    }
}
fn applied(revision: u64) -> AppliedIdentity {
    AppliedIdentity {
        incarnation: "incarnation".into(),
        revision,
        timestamp_ms: 1000,
        command_sha256: "ab".repeat(32),
        origin: AppliedOrigin::Raft {
            term: 1,
            leader: 1,
            index: revision,
            context_sha256: "cd".repeat(32),
        },
    }
}
fn stop(
    previous: &TenantState,
    view: &View,
    id: &str,
    applied: &AppliedIdentity,
) -> (TenantState, Pending) {
    let mut next = previous.clone();
    next.revision = applied.revision;
    let key = crate::state::staging::identity("owner", id).unwrap();
    let mut stage = active(id);
    stage.expires_at_ms = None;
    stage.outcome = StagedOutcome::Aborted {
        receipt: WriteReceipt {
            revision: applied.revision,
            versions: BTreeMap::new(),
        },
    };
    crate::state::staging::replace_record(&mut next, key, stage).unwrap();
    let pending = Pending::prepare(view, previous, &mut next, applied).unwrap();
    (next, pending)
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
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await
    .unwrap();
    let state = state();
    let empty = View::empty(&state.tenant, &state.incarnation).unwrap();
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
    let key = crate::state::staging::identity("owner", "selected-writer-bytes")?;
    let (state, pending) = stop(&initial, &old, "selected-writer-bytes", &applied(1));
    let selected = pending.persist()?;
    let checkpoint = "51".repeat(32);
    store.write_batch(&selected.checkpoint_writes(&state, &checkpoint)?)?;
    let point_key = id_key(&key);
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
        format!("{error:#}").contains("noncanonical staged terminal ordinal"),
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
    assert!(old.get(&key)?.is_none());
    let Err(error) = selected.get(&key) else {
        panic!("selected point accepted alternate writer bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical staged terminal point"),
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
        selected.get(&key)?.unwrap().stage.transaction_id,
        "selected-writer-bytes"
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
        format!("{error:#}").contains("noncanonical terminal checkpoint binding"),
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
async fn durable_future_row_is_invisible_and_only_exact_original_replay_can_reuse_it() {
    let (_directory, _store, state, old) = durable().await;
    let key = crate::state::staging::identity("owner", "first").unwrap();
    let identity = applied(1);
    let (next, pending) = stop(&state, &old, "first", &identity);
    // Storage has committed, but the caller has not published the new Generation
    // or its applied cursor. The old logical view still observes absence.
    let committed_rows = pending.persist().unwrap();
    assert!(old.get(&key).unwrap().is_none());
    assert!(next.staged_transactions.is_empty());
    assert_eq!(committed_rows.head().count, 1);
    let (_, replay) = stop(&state, &old, "first", &identity);
    let exact = replay.persist().unwrap();
    assert_eq!(exact.head(), committed_rows.head());
    assert_eq!(exact.get(&key).unwrap().unwrap().applied, identity);
    let mut changed = identity.clone();
    changed.command_sha256 = "ef".repeat(32);
    let (_, substituted) = stop(&state, &old, "first", &changed);
    assert!(
        substituted
            .persist()
            .unwrap_err()
            .to_string()
            .contains("exact original command replay")
    );
    assert_eq!(committed_rows.get(&key).unwrap().unwrap().applied, identity);
    assert!(old.get(&key).unwrap().is_none());
}

#[tokio::test]
async fn encrypted_reopen_keeps_unapplied_terminal_rows_hidden_until_exact_replay() {
    let (directory, store, initial, old) = durable().await;
    let disk = store.scratch_disk().clone();
    let identity = applied(1);
    let key = crate::state::staging::identity("owner", "unapplied").unwrap();
    let (_, pending) = stop(&initial, &old, "unapplied", &identity);
    let durable_future = pending.persist().unwrap();
    let expected = durable_future.row(1).unwrap().sha256().unwrap();
    assert!(old.get(&key).unwrap().is_none());
    drop(durable_future);
    drop(old);
    store.shutdown().await.unwrap();
    drop(store);

    let reopened_node = NodeStore::open_existing_fixture(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        disk.memory().clone(),
        disk,
    )
    .unwrap();
    let reopened_store = TenantStore::open_existing_fixture(
        reopened_node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await
    .unwrap();
    let empty = View::empty(&initial.tenant, &initial.incarnation).unwrap();
    let reopened = empty
        .prepare_install(&reopened_store, &initial, &"10".repeat(32), true)
        .unwrap();
    assert!(reopened.replacements().is_empty());
    assert!(reopened.view.get(&key).unwrap().is_none());

    let mut conflicting = identity.clone();
    conflicting.command_sha256 = "ef".repeat(32);
    let (_, wrong) = stop(&initial, &reopened.view, "unapplied", &conflicting);
    assert!(wrong.persist().is_err());
    assert!(reopened.view.get(&key).unwrap().is_none());
    let (_, exact) = stop(&initial, &reopened.view, "unapplied", &identity);
    let selected = exact.persist().unwrap();
    assert_eq!(
        selected.get(&key).unwrap().unwrap().sha256().unwrap(),
        expected
    );
    assert!(reopened.view.get(&key).unwrap().is_none());
    drop(selected);
    drop(reopened);
    reopened_store.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_namespace_binding_selects_exact_prefix_and_preserves_older_live_views() {
    let (_directory, store, initial, old) = durable().await;
    let (first_state, first) = stop(&initial, &old, "first", &applied(1));
    let first = first.persist().unwrap();
    let (second_state, second) = stop(&first_state, &first, "second", &applied(2));
    let second = second.persist().unwrap();
    let checkpoint = "20".repeat(32);
    store
        .write_batch(&first.checkpoint_writes(&first_state, &checkpoint).unwrap())
        .unwrap();
    let mut staged = Builder::new(store.scratch_disk(), 64 << 20, "tenant", "incarnation").unwrap();
    staged.push(&first.row(1).unwrap(), &first_state).unwrap();
    let staged = staged.finish(first.head()).unwrap();
    let reopened = staged
        .prepare_install(&store, &first_state, &checkpoint, true)
        .unwrap();
    assert!(reopened.replacements().is_empty());
    assert_eq!(reopened.view.head().count, 1);
    assert!(
        reopened
            .view
            .get(&crate::state::staging::identity("owner", "second").unwrap())
            .unwrap()
            .is_none()
    );
    let (_, replay) = stop(&first_state, &reopened.view, "second", &applied(2));
    assert_eq!(replay.persist().unwrap().head(), second.head());
    let replaced = staged
        .prepare_install(&store, &first_state, &"30".repeat(32), false)
        .unwrap();
    store
        .replace_namespaces(&replaced.replacements(), replaced.writes())
        .unwrap();
    assert_eq!(replaced.view.head(), first.head());
    assert_eq!(second.head(), &second_state.staged_terminal_head);
    assert_eq!(second.row(2).unwrap().stage.transaction_id, "second");
    // A mapping for a different applied prefix cannot be repurposed on reopen.
    assert!(
        staged
            .prepare_install(&store, &first_state, &"40".repeat(32), true)
            .is_err()
    );
}

#[test]
fn terminal_applied_provenance_cannot_be_relabelled_across_two_restore_geneses() {
    fn link(source: &str, target: &str, revision: u64) -> RestoreLineageLink {
        RestoreLineageLink {
            checkpoint: FullBackupCheckpoint {
                tenant: "tenant".into(),
                source_incarnation: source.into(),
                revision,
                resident_sha256: "01".repeat(32),
                backup_id: uuid::Uuid::new_v4(),
                manifest_ciphertext_sha256: "02".repeat(32),
                key_lineage_digest: "03".repeat(32),
            },
            target_incarnation: target.into(),
        }
    }
    let initial = state();
    let empty = View::empty(&initial.tenant, &initial.incarnation).unwrap();
    let (_, pending) = stop(&initial, &empty, "original", &applied(1));
    let original = pending.rows[0].clone();
    let mut restored = initial;
    restored.incarnation = "current".into();
    restored.revision_base = 21;
    restored.revision = 25;
    restored.restore_lineage = vec![
        link("incarnation", "middle", 10),
        link("middle", "current", 20),
    ];
    restored.restored_from = Some(restored.restore_lineage[1].checkpoint.clone());
    validate_restore_lineage(
        &restored.tenant,
        &restored.incarnation,
        restored.revision,
        restored.restored_from.as_ref(),
        &restored.restore_lineage,
    )
    .unwrap();
    original.validate(&restored).unwrap();
    for incarnation in ["middle", "current"] {
        let mut substituted = original.clone();
        substituted.applied.incarnation = incarnation.into();
        assert!(
            substituted
                .validate(&restored)
                .unwrap_err()
                .to_string()
                .contains("outside its original incarnation")
        );
    }
    // A retained old upload can legitimately be stopped in either successor.
    // Its original request scope stays unchanged; the actual applying position
    // must use that successor's own Raft index and genesis revision.
    for (incarnation, revision) in [("middle", 12), ("current", 22)] {
        let mut stopped = original.clone();
        stopped.applied.incarnation = incarnation.into();
        stopped.applied.revision = revision;
        stopped.stage.outcome = StagedOutcome::Aborted {
            receipt: WriteReceipt {
                revision,
                versions: BTreeMap::new(),
            },
        };
        stopped.validate(&restored).unwrap();
        assert_eq!(stopped.stage.scope.incarnation, "incarnation");
        if let AppliedOrigin::Raft { index, .. } = &mut stopped.applied.origin {
            *index = 2;
        }
        assert!(
            stopped
                .validate(&restored)
                .unwrap_err()
                .to_string()
                .contains("Raft position differs")
        );
    }
}

#[test]
fn point_admission_precedes_decoding_even_for_an_unpublished_row() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let table = Arc::new(EncryptedTable::new(disk, 64 << 20).unwrap());
    let key = "12".repeat(32);
    let invalid = b"this is deliberately not a terminal row";
    table.insert(&id_key(&key), invalid).unwrap();
    let view = View {
        source: Some(Arc::new(Source::Staged(table))),
        head: StagedTerminalHead::empty("tenant", "incarnation").unwrap(),
    };
    let mut measured = None;
    let error = view
        .get_charged(&key, |bytes| {
            measured = Some(bytes);
            Err(Error::new(ErrorCode::ResourceExhausted, "read capacity rejected").into())
        })
        .unwrap_err();
    assert_eq!(measured, Some(invalid.len()));
    assert_eq!(
        error.downcast_ref::<Error>().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    // Allowing the reservation reaches the parser; the failed charge above did
    // not decode or accidentally turn the unpublished physical row into absence.
    assert!(view.get(&key).unwrap_err().is::<serde_json::Error>());
}

#[test]
fn original_begin_reservation_covers_maximum_terminal_envelope_and_counter_widths() {
    let stage = active("\"".repeat(256).as_str());
    let key = crate::state::staging::identity("owner", &stage.transaction_id).unwrap();
    let (used, reserved) = crate::state::staging::permanent_charge(&key, &stage).unwrap();
    for code in [
        ErrorCode::InvalidArgument,
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::AlreadyExists,
        ErrorCode::Conflict,
        ErrorCode::SchemaViolation,
        ErrorCode::QuotaExceeded,
        ErrorCode::ResourceExhausted,
        ErrorCode::IndexRequired,
        ErrorCode::CursorExpired,
        ErrorCode::Unavailable,
        ErrorCode::UnknownOutcome,
        ErrorCode::Corruption,
        ErrorCode::Sealed,
        ErrorCode::AuditUnavailable,
    ] {
        let mut terminal = stage.clone();
        terminal.outcome = StagedOutcome::Finished {
            outcome: Err(Error::new(code, "\0".repeat(Error::MAX_MESSAGE_BYTES))),
        };
        let row = Row {
            ordinal: u64::MAX,
            key: key.clone(),
            previous_sha256: "ff".repeat(32),
            stage: terminal,
            applied: AppliedIdentity {
                incarnation: "\"".repeat(256),
                revision: u64::MAX,
                timestamp_ms: u64::MAX,
                command_sha256: "ff".repeat(32),
                origin: AppliedOrigin::Raft {
                    term: u64::MAX,
                    leader: u64::MAX,
                    index: u64::MAX,
                    context_sha256: "ff".repeat(32),
                },
            },
        };
        assert!(row.framed_bytes().unwrap() <= used + reserved);
    }
}

#[test]
fn failed_terminal_ordinal_insert_aborts_uncommitted_batch_and_head() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let initial = state();
    let empty = View::empty(&initial.tenant, &initial.incarnation).unwrap();
    let (next, pending) = stop(&initial, &empty, "partial", &applied(1));
    let row = &pending.rows[0];
    let mut builder = Builder::new(
        disk,
        scratch_limit(next.limits.max_snapshot_bytes).unwrap(),
        &next.tenant,
        &next.incarnation,
    )
    .unwrap();
    // The real second insert fails after the identity entered the private
    // transaction. Neither partial row may become a verified view.
    let table = builder.table.clone();
    builder
        .batch
        .as_mut()
        .unwrap()
        .insert(&ordinal_key(row.ordinal), b"occupied ordinal")
        .unwrap();
    let error = builder.push(row, &next).unwrap_err();
    assert!(error.to_string().contains("duplicate staged key"));
    assert!(table.get(&id_key(&row.key)).unwrap().is_none());
    assert_eq!(builder.head, next.staged_terminal_head);
    assert!(builder.push(row, &next).is_err());
    assert!(builder.finish(&next.staged_terminal_head).is_err());
    assert!(table.get(&id_key(&row.key)).unwrap().is_none());
    assert!(table.get(&ordinal_key(row.ordinal)).unwrap().is_none());
}

#[test]
fn rejected_terminal_row_permanently_disqualifies_valid_prefix() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let initial = state();
    let empty = View::empty(&initial.tenant, &initial.incarnation).unwrap();
    let (next, pending) = stop(&initial, &empty, "prefix", &applied(1));
    let row = &pending.rows[0];
    let mut builder = Builder::new(
        disk,
        scratch_limit(next.limits.max_snapshot_bytes).unwrap(),
        &next.tenant,
        &next.incarnation,
    )
    .unwrap();
    builder.push(row, &next).unwrap();
    let mut invalid = row.clone();
    invalid.ordinal = 0;
    assert!(builder.push(&invalid, &next).is_err());
    assert_eq!(builder.head, next.staged_terminal_head);
    assert!(builder.finish(&next.staged_terminal_head).is_err());
}
