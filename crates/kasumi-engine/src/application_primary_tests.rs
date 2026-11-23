use super::*;
use kasumi_store::test_utils::LocalKeyProvider;
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionState, CollectionWriteMode,
    DocumentSlot, Limits, Policy, StoredDocument,
};

// These low-level fixtures supply synthetic log positions. The replicated
// database case separately exercises the actual pinned consensus boundary.
fn prepare_publication(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    prepare_publication_at(
        owner,
        store,
        previous,
        candidate,
        None,
        changed,
        applied,
        |_| Ok(true),
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    _storage: crate::test_utils::FixtureStorage,
    node: kasumi_store::NodeStore,
    store: Arc<TenantStore>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent, scratch) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let config = crate::test_utils::admission_config_with_bookkeeping(
            crate::admission::AdmissionConfig {
                max_inflight_bytes: Some(512 << 20),
                ..Default::default()
            },
        )
        .unwrap();
        let storage =
            crate::test_utils::FixtureStorage::open(&persistent, &scratch, config).unwrap();
        let node = storage
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([57; 32])),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            _storage: storage,
            node,
            store,
        }
    }

    fn publish(&self, publication: Option<PrimaryPublication>) {
        let mut publication = publication.expect("primary writes");
        self.store.write_batch(&publication.take_writes()).unwrap();
    }

    fn current(&self) -> PrimaryManifest {
        PrimaryManifest::load(&self.store)
            .unwrap()
            .expect("primary directory")
    }

    fn verify(&self, state: &TenantState) {
        let manifest = self.current();
        assert!(manifest.is_current());
        verify_rows(
            &*self.store,
            &manifest,
            state,
            None,
            self.store.plaintext_memory_owner(),
        )
        .unwrap();
    }

    async fn close(self) {
        self.store.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

fn genesis() -> TenantState {
    crate::TenantEngine::new(
        "tenant".into(),
        uuid::Uuid::from_u128(5).to_string(),
        Policy {
            grants: vec![kasumi_types::Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([
                    kasumi_types::Action::Admin,
                    kasumi_types::Action::Read,
                    kasumi_types::Action::Write,
                ]),
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

fn definition(name: &str, schema: serde_json::Value) -> Arc<CollectionDefinition> {
    Arc::new(CollectionDefinition {
        name: name.into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema,
        indexes: vec![],
        strict_read_audit: false,
    })
}

fn descriptor(id: &str, version: u64) -> Arc<DocumentSlot> {
    Arc::new(DocumentSlot::stored_descriptor(StoredDocument {
        id: id.into(),
        version,
        body_bytes: 10 + version,
        document_bytes: 64 + version,
        body_sha256: [version as u8; 32],
        body_object: [0x40 | version as u8; 32],
        body_object_bytes: 96 + version,
        body_decode_work: 1,
        body_manifest_work: 1,
    }))
}

/// `previous` at `revision` with `put` documents upserted and `remove`
/// documents deleted in `collection`, and the exact producer delta.
fn next(
    previous: &TenantState,
    revision: u64,
    collection: &str,
    put: &[&str],
    remove: &[&str],
) -> (TenantState, ChangedIds) {
    let mut state = previous.clone();
    state.revision = revision;
    let mut target = state
        .collections
        .get(collection)
        .cloned()
        .unwrap_or_else(|| CollectionState {
            definition: definition(collection, serde_json::json!({"type": "object"})),
            data_epoch: 0,
            documents: Default::default(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        });
    let mut changed = ChangedIds::new();
    for id in put {
        target
            .documents
            .insert((*id).into(), descriptor(id, revision - state.revision_base));
        changed
            .entry(collection.into())
            .or_default()
            .insert((*id).into());
    }
    for id in remove {
        target.documents.remove(*id);
        changed
            .entry(collection.into())
            .or_default()
            .insert((*id).into());
    }
    target.data_epoch = revision;
    state.collections.insert(collection.into(), target);
    state.document_count = state
        .collections
        .values()
        .map(|collection| collection.documents.len() as u64)
        .sum();
    state.logical_bytes = state.document_count * 100;
    (state, changed)
}

#[test]
fn cold_compaction_only_shares_a_feed_after_image_with_the_same_complete_descriptor() {
    let empty = genesis();
    let names: Vec<_> = (0..145).map(|i| format!("doc-{i:03}")).collect();
    let ids: Vec<_> = names.iter().map(String::as_str).collect();
    let (mut state, _) = next(&empty, empty.revision_base + 1, "docs", &ids, &[]);
    let slot = &state.collections["docs"].documents["doc-000"];
    let mut other = slot.stored().unwrap().clone();
    other.body_sha256 = [0xB1; 32];
    other.body_object = [0xA2; 32];
    let different = Arc::new(DocumentSlot::stored_descriptor(other.clone()));
    let equal = state.collections["docs"].documents["doc-001"].clone();
    let make_record = |id: &str, document| kasumi_types::ChangeRecord {
        collection: "docs".into(),
        id: id.into(),
        document: Some(document),
    };
    state.change_feed.commits.insert(
        1,
        Arc::new(kasumi_types::ChangeCommit {
            revision: state.revision,
            first_sequence: 1,
            record_bytes: 0,
            records: vec![
                make_record("doc-000", different.clone()),
                make_record("doc-001", equal),
            ],
        }),
    );
    assert_eq!(
        crate::document_store::compact_reopened(&mut state),
        ids.len()
    );
    let records = &state.change_feed.commits[&1].records;
    assert_eq!(
        records[0].document.as_ref().unwrap().stored().unwrap(),
        &other
    );
    assert!(Arc::ptr_eq(
        records[0].document.as_ref().unwrap(),
        &different
    ));
    assert!(Arc::ptr_eq(
        records[1].document.as_ref().unwrap(),
        &state.collections["docs"].documents["doc-001"]
    ));
    assert!(
        state.collections["docs"]
            .documents
            .values()
            .all(|slot| matches!(slot.as_ref(), DocumentSlot::Located(_)))
    );
}

fn applied(state: &TenantState, term: u8) -> Option<PrimaryApplied> {
    let index = state.revision - state.revision_base;
    Some(PrimaryApplied {
        index,
        log_sha256: [term; 32],
        command_sha256: Some([index as u8; 32]),
    })
}

fn snapshot_meta(state: &TenantState) -> kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode> {
    kasumi_raft::SnapshotMeta {
        last_log_id: Some(kasumi_raft::LogId {
            index: state.revision - state.revision_base,
            ..Default::default()
        }),
        last_membership: Default::default(),
        snapshot_id: "primary-test".into(),
    }
}

#[test]
fn the_directory_step_follows_the_exact_predecessor_and_skips_covered_replay() {
    let s0 = genesis();
    let (s1, _) = next(&s0, s0.revision + 1, "docs", &["a"], &[]);
    let (s2, _) = next(&s1, s1.revision + 1, "docs", &["b"], &[]);
    let (s3, _) = next(&s2, s2.revision + 1, "docs", &["c"], &[]);
    // A pristine store starts its first tree. A populated deployed store can rebuild.
    assert_eq!(step(None, &s0, &s1), Step::Edit);
    assert_eq!(step(None, &s1, &s2), Step::Replace);
    let at = |state: &TenantState| {
        PrimaryManifest::new(
            &state.tenant,
            &state.incarnation,
            state.revision_base,
            state.revision,
            applied(state, 1),
            primary::INITIAL_SPACE[0],
            TreeRoot::new_tree(),
            state.document_count,
            state.logical_bytes,
        )
    };
    let m2 = at(&s2);
    assert_eq!(step(Some(&m2), &s0, &s1), Step::Covered);
    assert_eq!(step(Some(&m2), &s1, &s2), Step::Boundary);
    assert_eq!(step(Some(&m2), &s2, &s3), Step::Edit);
    // A replayed group whose members straddle the directory cannot be edited.
    assert!(matches!(step(Some(&m2), &s1, &s3), Step::Stale(_)));
    assert_eq!(
        step(Some(&m2.stale(s3.revision, None)), &s2, &s3),
        Step::Nothing
    );
    assert_eq!(
        step(Some(&m2.stale(s2.revision, None)), &s2, &s3),
        Step::Replace
    );
    let foreign = PrimaryManifest {
        incarnation: uuid::Uuid::from_u128(6).to_string(),
        ..m2
    };
    assert!(matches!(step(Some(&foreign), &s2, &s3), Step::Stale(_)));
    assert!(matches!(
        step(Some(&foreign.stale(s2.revision, None)), &s2, &s3),
        Step::Stale(_)
    ));
}

fn changed_ids(
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
) -> Result<ChangedIds> {
    let mut observed = ChangedIds::new();
    visit_changed_ids(previous, candidate, changed, |collection, id| {
        assert!(
            observed
                .entry(collection.into())
                .or_default()
                .insert(id.into())
        );
        Ok(())
    })?;
    Ok(observed)
}

#[test]
fn the_edit_set_uses_the_producer_delta_and_whole_changed_collections() {
    let s0 = genesis();
    let (s1, _) = next(&s0, s0.revision + 1, "docs", &["a", "b"], &[]);
    // A new collection contributes all of its IDs beyond the delta.
    let ids = changed_ids(&s0, &s1, &ChangedIds::new()).unwrap();
    assert_eq!(ids["docs"], BTreeSet::from(["a".into(), "b".into()]));
    let (s2, changed) = next(&s1, s1.revision + 1, "docs", &["c"], &["a"]);
    // A same-definition collection is exactly its producer delta.
    assert_eq!(
        changed_ids(&s1, &s2, &changed).unwrap()["docs"],
        BTreeSet::from(["a".into(), "c".into()])
    );
    // Redefinition with unchanged maps changes no primary row; with changed
    // maps every ID of the collection is rewritten.
    let mut redefined = s2.clone();
    redefined.collections.get_mut("docs").unwrap().definition =
        definition("docs", serde_json::json!({"type": "object", "title": "v2"}));
    assert!(
        changed_ids(&s2, &redefined, &ChangedIds::new())
            .unwrap()
            .is_empty()
    );
    redefined
        .collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert("d".into(), descriptor("d", 3));
    assert_eq!(
        changed_ids(&s2, &redefined, &ChangedIds::new()).unwrap()["docs"],
        BTreeSet::from(["b".into(), "c".into(), "d".into()])
    );
    // A removed collection deletes the rows of every ID it held.
    let mut removed = s2.clone();
    removed.collections.remove("docs");
    assert_eq!(
        changed_ids(&s2, &removed, &ChangedIds::new()).unwrap()["docs"],
        BTreeSet::from(["b".into(), "c".into()])
    );
    // Beyond the bound the directory cannot be edited in place.
    let many: Vec<String> = (0..=MAX_REBUILD_IDS)
        .map(|n| format!("id-{n:05}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let (large, changed) = next(&s2, s2.revision + 1, "docs", &many, &[]);
    assert_eq!(changed_ids(&s2, &large, &changed).unwrap(), changed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_publications_edit_one_tree_and_replay_cannot_move_it() {
    let fixture = Fixture::new().await;
    let owner = PrimaryOwner::default();
    let store = &fixture.store;
    let s0 = genesis();
    assert_eq!(
        prepare_publication(&owner, store, &s0, &s0, &ChangedIds::new(), None)
            .unwrap()
            .map(|_| ()),
        Some(()),
        "a pristine store records its first directory"
    );
    let (s1, changed) = next(&s0, s0.revision + 1, "docs", &["a", "b", "c"], &[]);
    fixture
        .publish(prepare_publication(&owner, store, &s0, &s1, &changed, applied(&s1, 1)).unwrap());
    fixture.verify(&s1);
    let tree = fixture.current().records.tree;
    let (s2, changed) = next(&s1, s1.revision + 1, "docs", &["a", "d"], &["b"]);
    fixture
        .publish(prepare_publication(&owner, store, &s1, &s2, &changed, applied(&s2, 1)).unwrap());
    fixture.verify(&s2);
    assert_eq!(fixture.current().records.tree, tree);
    let pinned = store.read_view().unwrap();
    let (s3, changed) = next(&s2, s2.revision + 1, "other", &["x"], &[]);
    fixture
        .publish(prepare_publication(&owner, store, &s2, &s3, &changed, applied(&s3, 1)).unwrap());
    fixture.verify(&s3);
    // The root pinned before the edit still reads its own revision.
    let old = PrimaryManifest::load_at(&pinned).unwrap().unwrap();
    assert_eq!(old.revision, s2.revision);
    verify_rows(&pinned, &old, &s2, None, store.plaintext_memory_owner()).unwrap();
    pinned.close().unwrap();

    // Replay below the directory publishes nothing; replay reaching it
    // checks its boundary and rows and publishes nothing.
    assert!(
        prepare_publication(&owner, store, &s1, &s2, &changed, applied(&s2, 1))
            .unwrap()
            .is_none()
    );
    assert!(
        prepare_publication(&owner, store, &s2, &s3, &changed, applied(&s3, 1))
            .unwrap()
            .is_none()
    );
    // Store itself refuses a backward manifest.
    let backward = fixture.current().advance(
        s2.revision,
        applied(&s2, 1),
        fixture.current().records,
        0,
        0,
    );
    assert!(store.write_batch(&[backward.write().unwrap()]).is_err());
    fixture.verify(&s3);

    let before_replacement = store.read_view().unwrap();
    // A replayed boundary from another history goes stale at its revision.
    fixture
        .publish(prepare_publication(&owner, store, &s2, &s3, &changed, applied(&s3, 9)).unwrap());
    let stale = fixture.current();
    assert!(!stale.is_current() && stale.revision == s3.revision);
    let (s4, changed) = next(&s3, s3.revision + 1, "docs", &["e"], &[]);
    // Covered replay cannot replace the stale later position. Preparing a
    // replacement without publishing it never changes the selected root.
    assert!(
        prepare_publication(&owner, store, &s1, &s2, &changed, applied(&s2, 1))
            .unwrap()
            .is_none()
    );
    let mut boundary = snapshot_applied(&snapshot_meta(&s4)).unwrap().unwrap();
    boundary.command_sha256 = Some([4; 32]);
    let abandoned = prepare_publication(&owner, store, &s3, &s4, &changed, Some(boundary.clone()))
        .unwrap()
        .expect("small ordinary candidate can replace a stale directory");
    drop(abandoned);
    assert_eq!(fixture.current(), stale);
    fixture
        .publish(prepare_publication(&owner, store, &s3, &s4, &changed, Some(boundary)).unwrap());
    fixture.verify(&s4);
    assert_ne!(fixture.current().records.tree, tree);
    assert_ne!(fixture.current().page_space, primary::INITIAL_SPACE[0]);
    // Reopen keeps a current directory at or ahead of its snapshot.
    let mut writes = Vec::new();
    prepare_restore(&owner, store, &s4, &snapshot_meta(&s4), true, &mut writes).unwrap();
    assert!(writes.is_empty());
    prepare_restore(&owner, store, &s3, &snapshot_meta(&s3), true, &mut writes).unwrap();
    assert!(writes.is_empty());
    // An installation always rebuilds from its snapshot.
    prepare_restore(&owner, store, &s4, &snapshot_meta(&s4), false, &mut writes).unwrap();
    assert!(!writes.is_empty());
    drop(writes);
    // The replaced space is reclaimed at the next restore.
    let mut writes = Vec::new();
    prepare_restore(&owner, store, &s4, &snapshot_meta(&s4), true, &mut writes).unwrap();
    assert!(writes.is_empty());
    let view = store.read_view().unwrap();
    let mut initial = 0;
    view.visit(primary::INITIAL_SPACE[0], 64 << 10, |_, _| {
        initial += 1;
        Ok(())
    })
    .unwrap();
    view.close().unwrap();
    assert_eq!(initial, 0);
    let retained = PrimaryManifest::load_at(&before_replacement)
        .unwrap()
        .unwrap();
    assert_eq!(retained.revision, s3.revision);
    verify_rows(
        &before_replacement,
        &retained,
        &s3,
        None,
        store.plaintext_memory_owner(),
    )
    .unwrap();
    before_replacement.close().unwrap();

    // A delta larger than the entire synchronous rebuild allowance streams
    // through one bounded journal. Subsequent writes retain the same tree.
    let (s5, changed) = next(&s4, s4.revision + 1, "docs", &["f"], &["a"]);
    fixture
        .publish(prepare_publication(&owner, store, &s4, &s5, &changed, applied(&s5, 1)).unwrap());
    fixture.verify(&s5);
    let many: Vec<String> = (0..=MAX_REBUILD_IDS)
        .map(|n| format!("bulk-{n:05}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let (s6, changed) = next(&s5, s5.revision + 1, "docs", &many, &[]);
    fixture
        .publish(prepare_publication(&owner, store, &s5, &s6, &changed, applied(&s6, 1)).unwrap());
    fixture.verify(&s6);
    let large_root = fixture.current();
    let (s7, changed) = next(
        &s6,
        s6.revision + 1,
        "docs",
        &["bulk-00300"],
        &["bulk-00001"],
    );
    fixture
        .publish(prepare_publication(&owner, store, &s6, &s7, &changed, applied(&s7, 1)).unwrap());
    fixture.verify(&s7);
    assert_eq!(fixture.current().records.tree, large_root.records.tree);

    // Covered replay at the same genuine boundary must not synchronously
    // verify this whole directory. An already selected reader keeps its
    // complete authenticated root while the new selection is withdrawn.
    let pinned = store.read_view().unwrap();
    let original = fixture.current();
    fixture
        .publish(prepare_publication(&owner, store, &s6, &s7, &changed, applied(&s7, 1)).unwrap());
    let stale = fixture.current();
    assert_eq!(stale, original.stale(s7.revision, applied(&s7, 1)));
    assert_eq!(
        PrimaryManifest::load_at(&pinned).unwrap().unwrap(),
        original
    );
    verify_rows(
        &pinned,
        &original,
        &s7,
        None,
        store.plaintext_memory_owner(),
    )
    .unwrap();
    pinned.close().unwrap();
    let (s8, changed) = next(&s7, s7.revision + 1, "docs", &["another"], &[]);
    fixture
        .publish(prepare_publication(&owner, store, &s7, &s8, &changed, applied(&s8, 1)).unwrap());
    let seed = fixture.current();
    let captured = applied(&s8, 1).unwrap();
    assert_eq!(seed.rebuild().unwrap().captured, captured);
    assert_eq!(seed.rebuild().unwrap().cursor, None);
    assert_eq!(seed.records.count(), 0);
    assert_ne!(seed.page_space, stale.page_space);
    // Dropping a prepared window never commits its cursor. Recovery retains
    // the physical checkpoint even when reopen starts from an older snapshot.
    let (s9, delta) = next(
        &s8,
        s8.revision + 1,
        "docs",
        &["000-before", "new-after"],
        &["bulk-04000"],
    );
    drop(
        prepare_publication(&owner, store, &s8, &s9, &delta, applied(&s9, 1))
            .unwrap()
            .unwrap(),
    );
    assert_eq!(fixture.current(), seed);
    drop(owner);
    let owner = PrimaryOwner::default();
    let mut writes = Vec::new();
    prepare_restore(&owner, store, &s7, &snapshot_meta(&s7), true, &mut writes).unwrap();
    assert!(writes.is_empty());
    fixture.publish(prepare_publication(&owner, store, &s8, &s9, &delta, applied(&s9, 1)).unwrap());
    let advanced = fixture.current();
    assert_eq!(advanced.rebuild().unwrap().captured, captured);
    assert!(advanced.rebuild().unwrap().cursor.is_some());
    assert!(advanced.records.count() <= 2 * (WINDOW_IDS as u64 + 2));
    let partial = store.read_view().unwrap();

    // Change keys on both sides of the cursor while continually inserting
    // more than one scan window of fresh IDs ahead of the original end.
    let mut state = s9;
    for round in 0..4 {
        let cursor = fixture.current().rebuild().unwrap().cursor.clone().unwrap();
        let id = cursor.after_document.unwrap();
        let extra: Vec<_> = (0..90)
            .map(|n| format!("{id}-extra-{round}-{n:03}"))
            .collect();
        let mut put: Vec<_> = extra.iter().map(String::as_str).collect();
        put.push("000-before");
        let (candidate, delta) = next(&state, state.revision + 1, "docs", &put, &["bulk-04096"]);
        fixture.publish(
            prepare_publication(
                &owner,
                store,
                &state,
                &candidate,
                &delta,
                applied(&candidate, 1),
            )
            .unwrap(),
        );
        assert!(
            fixture
                .current()
                .rebuild()
                .unwrap()
                .cursor
                .as_ref()
                .unwrap()
                .after_document
                .as_ref()
                .unwrap()
                > extra.last().unwrap(),
            "newly inserted keys starved captured originals"
        );
        state = candidate;
    }
    // With no later log entry the idle worker must finish, at that same
    // authenticated position, in independently durable, bounded transactions.
    let final_applied = applied(&state, 1).unwrap();
    for _ in 0..(MAX_REBUILD_IDS / WINDOW_IDS + 20) {
        if maintain(&owner, store, &state, None, &final_applied).unwrap() {
            break;
        }
    }
    fixture.verify(&state);
    assert_eq!(fixture.current().applied, Some(final_applied));
    assert_eq!(
        PrimaryManifest::load_at(&partial).unwrap().unwrap(),
        advanced
    );
    partial.close().unwrap();

    // Installing an authenticated snapshot still replaces a completed directory.
    let mut writes = Vec::new();
    prepare_restore(
        &owner,
        store,
        &state,
        &snapshot_meta(&state),
        false,
        &mut writes,
    )
    .unwrap();
    store.write_batch(&writes).unwrap();
    fixture.verify(&state);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_primary_edit_is_recovered_when_its_publication_never_commits() {
    let fixture = Fixture::new().await;
    let owner = PrimaryOwner::default();
    let store = &fixture.store;
    let s0 = genesis();
    let ids: Vec<String> = (0..600).map(|n| format!("doc-{n:04}")).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (s1, changed) = next(&s0, s0.revision + 1, "docs", &ids, &[]);
    fixture
        .publish(prepare_publication(&owner, store, &s0, &s1, &changed, applied(&s1, 1)).unwrap());
    fixture.verify(&s1);
    let rows = |store: &Arc<TenantStore>| {
        let view = store.read_view().unwrap();
        let mut rows = 0u64;
        view.visit(primary::INITIAL_SPACE[0], 64 << 10, |_, _| {
            rows += 1;
            Ok(())
        })
        .unwrap();
        view.close().unwrap();
        rows
    };
    let settled = rows(store);
    // A large edit stages journaled batches; its publication is dropped.
    let (s2, changed) = next(&s1, s1.revision + 1, "docs", &ids[..400], &[]);
    let abandoned =
        prepare_publication(&owner, store, &s1, &s2, &changed, applied(&s2, 1)).unwrap();
    drop(abandoned);
    assert!(rows(store) > settled);
    // The next edit first abandons those rows, then edits the selected tree.
    let (s2b, changed) = next(&s1, s1.revision + 1, "docs", &["late"], &[]);
    fixture.publish(
        prepare_publication(&owner, store, &s1, &s2b, &changed, applied(&s2b, 1)).unwrap(),
    );
    fixture.verify(&s2b);
    let manifest = fixture.current();
    let view = store.read_view().unwrap();
    let reachable = TreeReader::new(&view, &manifest.page_space, manifest.records, None)
        .unwrap()
        .verify()
        .unwrap();
    view.close().unwrap();
    // Only the published tree's pages remain once its own journal settles.
    ordered_pages::recover_abandoned_edits_in(store, primary::FAMILY).unwrap();
    assert_eq!(rows(store), reachable);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_document_edit_rewrites_only_its_paths() {
    let fixture = Fixture::new().await;
    let owner = PrimaryOwner::default();
    let store = &fixture.store;
    let s0 = genesis();
    let ids: Vec<String> = (0..4000).map(|n| format!("doc-{n:05}")).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (s1, changed) = next(&s0, s0.revision + 1, "docs", &ids, &[]);
    // A pristine directory's first large edit goes through restore instead.
    let mut writes = Vec::new();
    prepare_restore(&owner, store, &s1, &snapshot_meta(&s1), true, &mut writes).unwrap();
    store.write_batch(&writes).unwrap();
    drop((writes, changed));
    fixture.verify(&s1);
    let height = fixture.current().records.height();
    let (s2, changed) = next(&s1, s1.revision + 1, "docs", &["doc-02000"], &[]);
    let mut publication = prepare_publication(&owner, store, &s1, &s2, &changed, applied(&s2, 1))
        .unwrap()
        .unwrap();
    let writes = publication.take_writes();
    let manifest = fixture.current();
    let (mut puts, mut deletes, mut bytes) = (0usize, 0usize, 0usize);
    for write in &writes {
        match write {
            WriteOp::Put {
                namespace, value, ..
            } if *namespace == manifest.page_space => {
                puts += 1;
                bytes += value.len();
            }
            WriteOp::Delete { namespace, .. } if *namespace == manifest.page_space => deletes += 1,
            _ => {}
        }
    }
    eprintln!(
        "primary single-document edit over 4000 documents: height {height}, \
         {puts} page puts ({bytes} bytes), {deletes} displaced pages, {} writes",
        writes.len()
    );
    // The live and header rows sit in two leaves; each path is rewritten once.
    assert!(
        puts <= 2 * height && deletes == puts,
        "{puts} puts, {deletes} deletes"
    );
    assert!(bytes <= 2 * height * ordered_pages::MAX_PAGE_BYTES);
    store.write_batch(&writes).unwrap();
    fixture.verify(&s2);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_service_rebuilds_a_directory_that_missed_its_last_log_entry() {
    let fixture = Fixture::new().await;
    let store = &fixture.store;
    let owner = PrimaryOwner::default();
    let s0 = genesis();
    let (s1, delta) = next(&s0, s0.revision + 1, "docs", &["gone", "old"], &[]);
    fixture.publish(prepare_publication(&owner, store, &s0, &s1, &delta, applied(&s1, 1)).unwrap());
    let (s2, _) = next(&s1, s1.revision + 1, "docs", &["new"], &["gone"]);
    let selected = applied(&s2, 1).unwrap();
    for _ in 0..8 {
        if maintain(&owner, store, &s2, None, &selected).unwrap() {
            break;
        }
    }
    fixture.verify(&s2);
    fixture.close().await;
}
