use super::*;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::collections::BTreeSet;
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
fn identity(principal: &str, key: &str) -> kasumi_types::Result<String> {
    Ok(staged_digest(&(principal, key))?.0)
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
fn commit(
    previous: &TenantState,
    view: &View,
    key: &str,
    applied: &AppliedIdentity,
) -> (TenantState, Pending) {
    let mut next = previous.clone();
    next.revision = applied.revision;
    let receipt = StoredReceipt {
        scope: MutationReceiptScope {
            tenant: next.tenant.clone(),
            incarnation: next.incarnation.clone(),
            principal: "owner".into(),
        },
        idempotency_key: key.into(),
        recorded_revision: applied.revision,
        request_digest: "ef".repeat(32),
        collections: vec!["docs".into()],
        outcome: Err(Error::new(
            ErrorCode::QuotaExceeded,
            "original permanent failure",
        )),
    };
    let pending = Pending::prepare(view, &next, Some(receipt), applied).unwrap();
    next.mutation_receipt_head = pending.head().clone();
    (next, pending)
}
async fn durable() -> (tempfile::TempDir, Arc<TenantStore>, TenantState, View) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let node = NodeStore::create_new_fixture(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
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
async fn durable_future_row_is_invisible_and_only_exact_original_replay_can_reuse_it() {
    let (_directory, store, state, old) = durable().await;
    let key = self::identity("owner", "first").unwrap();
    let identity = applied(1);
    let (next, pending) = commit(&state, &old, "first", &identity);
    // Storage has committed, but the caller has not published the new Generation
    // or its applied cursor. The old logical view still observes absence.
    let committed_rows = pending.persist().unwrap();
    assert!(old.get(&key).unwrap().is_none());
    assert_eq!(next.mutation_receipt_head.count, 1);
    assert_eq!(committed_rows.head().count, 1);
    let (_, replay) = commit(&state, &old, "first", &identity);
    let exact = replay.persist().unwrap();
    assert_eq!(exact.head(), committed_rows.head());
    assert_eq!(exact.get(&key).unwrap().unwrap().applied, identity);
    let mut changed = identity.clone();
    changed.command_sha256 = "ef".repeat(32);
    let (_, substituted) = commit(&state, &old, "first", &changed);
    assert!(
        substituted
            .persist()
            .unwrap_err()
            .to_string()
            .contains("exact original command replay")
    );
    assert_eq!(committed_rows.get(&key).unwrap().unwrap().applied, identity);
    assert!(old.get(&key).unwrap().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn encrypted_reopen_keeps_unapplied_receipt_rows_hidden_until_exact_replay() {
    let (directory, store, initial, old) = durable().await;
    let disk = store.scratch_disk().clone();
    let identity = applied(1);
    let key = self::identity("owner", "unapplied").unwrap();
    let (_, pending) = commit(&initial, &old, "unapplied", &identity);
    let durable_future = pending.persist().unwrap();
    let expected = durable_future.row(1).unwrap().sha256().unwrap();
    assert!(old.get(&key).unwrap().is_none());
    drop(durable_future);
    drop(old);
    store.shutdown().await.unwrap();
    drop(store);

    let reopened_node = NodeStore::open_existing_fixture(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
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
    let (_, wrong) = commit(&initial, &reopened.view, "unapplied", &conflicting);
    assert!(wrong.persist().is_err());
    assert!(reopened.view.get(&key).unwrap().is_none());
    let (_, exact) = commit(&initial, &reopened.view, "unapplied", &identity);
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
    let (first_state, first) = commit(&initial, &old, "first", &applied(1));
    let first = first.persist().unwrap();
    let (second_state, second) = commit(&first_state, &first, "second", &applied(2));
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
            .get(&self::identity("owner", "second").unwrap())
            .unwrap()
            .is_none()
    );
    let (_, replay) = commit(&first_state, &reopened.view, "second", &applied(2));
    assert_eq!(replay.persist().unwrap().head(), second.head());
    let replaced = staged
        .prepare_install(&store, &first_state, &"30".repeat(32), false)
        .unwrap();
    store
        .replace_namespaces(&replaced.replacements(), replaced.writes())
        .unwrap();
    assert_eq!(replaced.view.head(), first.head());
    assert_eq!(second.head(), &second_state.mutation_receipt_head);
    assert_eq!(second.row(2).unwrap().receipt.idempotency_key, "second");
    // A mapping for a different applied prefix cannot be repurposed on reopen.
    assert!(
        staged
            .prepare_install(&store, &first_state, &"40".repeat(32), true)
            .is_err()
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn point_decode_admission_precedes_even_future_row_allocation() {
    let (_directory, store, initial, old) = durable().await;
    let (_, pending) = commit(&initial, &old, "future", &applied(1));
    let _future = pending.persist().unwrap();
    let mut called = false;
    let error = old
        .get_charged(&identity("owner", "future").unwrap(), |bytes| {
            called = true;
            let peak = crate::snapshot_codec::inspect_external_json_work(bytes, &mut || Ok(()))?;
            ensure!(
                peak > bytes.len() as u64,
                "structural peak must include DTO allocation"
            );
            anyhow::bail!("injected admission denial before row DTO")
        })
        .unwrap_err();
    assert!(called);
    assert!(error.to_string().contains("injected admission denial"));
    assert_eq!(old.head().count, 0);
    store.shutdown().await.unwrap();
}
