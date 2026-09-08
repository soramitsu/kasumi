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
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::open(directory.path().join("node.redb"), ScratchDisk::fixture()).unwrap();
    let store = TenantStore::open_fixture(
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
