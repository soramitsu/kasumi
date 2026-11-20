use super::*;
use kasumi_query::{QueryCancellation, search_text_shards};
use kasumi_store::test_utils::LocalKeyProvider;
use kasumi_types::{
    Analyzer, CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, IndexDefinition,
    IndexField, Limits, Policy, ScalarType, StoredDocument, TextIndex, TextSearch,
};
use serde_json::json;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: crate::test_utils::FixtureStorage,
    node: kasumi_store::NodeStore,
    store: Arc<TenantStore>,
    owner: TextOwner,
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
            Arc::new(LocalKeyProvider::new([73; 32])),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            storage,
            node,
            store,
            owner: TextOwner::default(),
        }
    }

    /// Prepare `candidate` after `previous` and publish it as the paired
    /// application transaction would; `None` when nothing was written.
    fn publish(
        &self,
        previous: &TenantState,
        candidate: &TenantState,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Option<TextManifest> {
        let mut publication = prepare_publication(
            &self.owner,
            &self.store,
            previous,
            candidate,
            changed,
            &ResolverBodies(None),
        )
        .unwrap()?;
        let manifest = publication.manifest().clone();
        self.store.write_batch(&publication.take_writes()).unwrap();
        Some(manifest)
    }

    fn current(&self) -> TextManifest {
        TextManifest::load(&self.store)
            .unwrap()
            .expect("text directory")
    }

    fn descriptor(&self, collection: &str) -> CollectionDescriptor {
        let manifest = self.current();
        let tree =
            TreeReader::new(&*self.store, &manifest.page_space, manifest.records, None).unwrap();
        read(&tree, &collection_key(collection)).unwrap().unwrap()
    }

    fn search(&self, state: &TenantState, query: &str) -> Vec<String> {
        let view = self.store.read_view().unwrap();
        let hits = search_at(&self.storage.admission, &view, state, query);
        view.close().unwrap();
        hits
    }

    async fn close(self) {
        self.store.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

/// Search "docs" through the directory a pinned view selects, at `state`.
fn search_at(
    admission: &Arc<NodeAdmission>,
    view: &kasumi_store::TenantReadView,
    state: &TenantState,
    query: &str,
) -> Vec<String> {
    let manifest = TextManifest::load_at(view)
        .unwrap()
        .expect("text directory");
    assert!(manifest.is_current());
    let tree = TreeReader::new(view, &manifest.page_space, manifest.records, None).unwrap();
    search_collection(
        &tree,
        view,
        &manifest,
        "docs",
        &state.collections["docs"],
        admission,
        |shards| {
            search_text_shards(
                shards,
                &TextSearch::new("text", query),
                1000,
                &QueryCancellation::default(),
            )
        },
    )
    .unwrap()
    .unwrap()
    .into_keys()
    .collect()
}

fn genesis() -> TenantState {
    crate::TenantEngine::new(
        "tenant".into(),
        uuid::Uuid::from_u128(7).to_string(),
        Policy {
            grants: vec![kasumi_types::Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([kasumi_types::Action::Admin]),
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

fn definition(path: &str) -> Arc<CollectionDefinition> {
    Arc::new(CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type": "object"}),
        indexes: vec![IndexDefinition {
            name: "text".into(),
            fields: vec![IndexField {
                path: path.into(),
                kind: ScalarType::String,
            }],
            unique: false,
            text: Some(TextIndex {
                analyzer: Analyzer::UnicodeV1,
            }),
        }],
        strict_read_audit: false,
    })
}

type Changed = BTreeMap<String, BTreeSet<String>>;

/// The next revision of `previous` with `put` bodies upserted and `remove`
/// documents deleted in "docs", and its exact delta.
fn next(previous: &TenantState, put: &[(&str, &str)], remove: &[&str]) -> (TenantState, Changed) {
    let mut state = previous.clone();
    state.revision += 1;
    let version = state.revision - state.revision_base;
    let collection = state
        .collections
        .entry("docs".into())
        .or_insert_with(|| CollectionState {
            definition: definition("/title"),
            data_epoch: 0,
            documents: Default::default(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        });
    let mut changed = Changed::new();
    for (id, title) in put {
        collection.documents.insert(
            (*id).into(),
            Arc::new(DocumentSlot::Pending(Arc::new(Document {
                id: (*id).into(),
                version,
                body: json!({"title": title}),
            }))),
        );
        changed
            .entry("docs".into())
            .or_default()
            .insert((*id).into());
    }
    for id in remove {
        collection.documents.remove(*id);
        changed
            .entry("docs".into())
            .or_default()
            .insert((*id).into());
    }
    (state, changed)
}

fn stored(id: &str, version: u64) -> Arc<DocumentSlot> {
    Arc::new(DocumentSlot::Stored(StoredDocument {
        id: id.into(),
        version,
        body_bytes: 10,
        document_bytes: 64,
        body_sha256: [1; 32],
        body_object: [2; 32],
        body_object_bytes: 96,
        body_decode_work: 1,
        body_manifest_work: 1,
    }))
}

#[tokio::test]
async fn publications_index_supersede_merge_and_drop_documents() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    // A tenant without text indexes never writes a directory.
    let (mut plain, _) = next(&s0, &[], &[]);
    plain.collections.clear();
    assert!(fixture.publish(&s0, &plain, &Changed::new()).is_none());

    // Creating a text collection stages the first generation.
    let (s1, _) = next(&s0, &[], &[]);
    let first = fixture.publish(&s0, &s1, &Changed::new()).unwrap();
    assert!(first.is_current() && first.revision == s1.revision);
    assert_ne!(first.page_space, INITIAL_SPACE[0]);
    assert_eq!((first.collections, first.shards), (1, 0));

    let (s2, changed) = next(&s1, &[("a", "alpha shared"), ("b", "beta shared")], &[]);
    let edited = fixture.publish(&s1, &s2, &changed).unwrap();
    assert_eq!(edited.page_space, first.page_space);
    assert_eq!(edited.records.tree, first.records.tree);
    assert_eq!(fixture.search(&s2, "shared"), ["a", "b"]);

    // An update supersedes the old row; a delete leaves no current row.
    let (s3, changed) = next(&s2, &[("a", "gamma shared")], &["b"]);
    fixture.publish(&s2, &s3, &changed).unwrap();
    assert!(fixture.search(&s3, "alpha").is_empty());
    assert!(fixture.search(&s3, "beta").is_empty());
    assert_eq!(fixture.search(&s3, "gamma"), ["a"]);
    assert_eq!(fixture.search(&s3, "shared"), ["a"]);
    assert_eq!(fixture.descriptor("docs").documents, 3);

    // A replayed entry the directory already covers writes nothing.
    assert!(fixture.publish(&s2, &s3, &changed).is_none());
    assert!(fixture.publish(&s1, &s2, &Changed::new()).is_none());

    // Single-document publications merge eight at a time, dropping
    // superseded rows; the shard count stays bounded.
    let mut state = s3;
    for round in 0..40 {
        let id = format!("d{}", round % 5);
        let title = format!("round{round} shared");
        let (following, changed) = next(&state, &[(id.as_str(), title.as_str())], &[]);
        fixture.publish(&state, &following, &changed).unwrap();
        state = following;
        let descriptor = fixture.descriptor("docs");
        assert!(descriptor.shards <= 2 * FANIN as u64, "{descriptor:?}");
    }
    // Without merges 43 rows would remain; merges dropped superseded ones.
    let descriptor = fixture.descriptor("docs");
    assert!(descriptor.documents < 43, "{descriptor:?}");
    let mut expected: Vec<String> = (0..5).map(|i| format!("d{i}")).collect();
    expected.insert(0, "a".into());
    assert_eq!(fixture.search(&state, "shared"), expected);
    assert_eq!(fixture.search(&state, "round39"), ["d4"]);
    assert!(fixture.search(&state, "round0").is_empty());
    let manifest = fixture.current();
    assert_eq!(manifest.shards, descriptor.shards);
    assert_eq!(manifest.shard_bytes, descriptor.bytes);

    // Dropping the collection deletes every row it owned.
    let mut dropped = state.clone();
    dropped.revision += 1;
    dropped.collections.remove("docs");
    let after = fixture.publish(&state, &dropped, &Changed::new()).unwrap();
    assert_eq!(
        (after.collections, after.shards, after.shard_bytes),
        (0, 0, 0)
    );
    let tree = TreeReader::new(&*fixture.store, &after.page_space, after.records, None).unwrap();
    assert!(collection_keys(&tree, "docs").unwrap().is_empty());
    drop(tree);
    fixture.close().await;
}

#[tokio::test]
async fn compaction_rewrites_a_sealed_shard_dominated_by_superseded_rows() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    let titles: Vec<(String, String)> = (0..5000)
        .map(|i| (format!("{i:05}"), format!("word{} common", i % 97)))
        .collect();
    let put: Vec<(&str, &str)> = titles
        .iter()
        .map(|(id, title)| (id.as_str(), title.as_str()))
        .collect();
    let (s1, _) = next(&s0, &put, &[]);
    // A first directory over existing rows is a staged rebuild.
    fixture.publish(&s0, &s1, &Changed::new()).unwrap();
    let built = fixture.descriptor("docs");
    assert_eq!((built.shards, built.documents), (1, 5000));
    let levels = {
        let manifest = fixture.current();
        let tree = TreeReader::new(
            &*fixture.store,
            &manifest.page_space,
            manifest.records,
            None,
        )
        .unwrap();
        shard_levels(&tree, "docs").unwrap()
    };
    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0].0, SEALED);

    let removed: Vec<&str> = titles[..4000].iter().map(|(id, _)| id.as_str()).collect();
    let (s2, changed) = next(&s1, &[], &removed);
    fixture.publish(&s1, &s2, &changed).unwrap();
    let compacted = fixture.descriptor("docs");
    assert_eq!((compacted.shards, compacted.documents), (1, 1000));
    assert!(compacted.bytes < built.bytes);
    let hits = fixture.search(&s2, "word5");
    assert!(!hits.is_empty() && hits.iter().all(|id| id.as_str() >= "04000"));
    fixture.close().await;
}

#[tokio::test]
async fn a_failed_edit_goes_stale_and_the_next_publication_rebuilds() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    let (s1, changed) = next(&s0, &[("a", "alpha")], &[]);
    fixture.publish(&s0, &s1, &changed).unwrap();
    // A stored body this publication cannot read fails the edit.
    let (mut s2, changed) = next(&s1, &[("b", "beta")], &[]);
    let version = s2.revision - s2.revision_base;
    s2.collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert("b".into(), stored("b", version));
    let stale = fixture.publish(&s1, &s2, &changed).unwrap();
    assert!(!stale.is_current());
    assert_eq!(stale.revision, s2.revision);
    // Readers never use a stale directory.
    assert!(!fixture.current().is_current());

    let (s3, changed) = next(&s2, &[("b", "beta again")], &[]);
    let rebuilt = fixture.publish(&s2, &s3, &changed).unwrap();
    assert!(rebuilt.is_current());
    assert_ne!(rebuilt.page_space, stale.page_space);
    assert_eq!(fixture.search(&s3, "alpha"), ["a"]);
    assert_eq!(fixture.search(&s3, "beta"), ["b"]);
    // The replaced generation retired with the switch and is reclaimed by
    // the next publication's settlement.
    let (s4, changed) = next(&s3, &[("c", "gamma")], &[]);
    fixture.publish(&s3, &s4, &changed).unwrap();
    let view = fixture.store.read_view().unwrap();
    let mut leftover = 0;
    view.visit(&stale.page_space, 1 << 20, |_, _| {
        leftover += 1;
        Ok(())
    })
    .unwrap();
    view.close().unwrap();
    assert_eq!(leftover, 0);
    fixture.close().await;
}

#[tokio::test]
async fn a_changed_text_definition_over_live_rows_rebuilds_a_new_generation() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    let (s1, changed) = next(&s0, &[("a", "alpha")], &[]);
    let first = fixture.publish(&s0, &s1, &changed).unwrap();
    let mut s2 = s1.clone();
    s2.revision += 1;
    s2.collections.get_mut("docs").unwrap().definition = definition("/missing");
    let rebuilt = fixture.publish(&s1, &s2, &Changed::new()).unwrap();
    assert_ne!(rebuilt.page_space, first.page_space);
    assert_ne!(rebuilt.records.tree, first.records.tree);
    assert!(fixture.search(&s2, "alpha").is_empty());
    assert_eq!(fixture.descriptor("docs").documents, 1);
    fixture.close().await;
}

#[tokio::test]
async fn retained_readers_keep_their_generation_and_the_cache_obeys_its_budget() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    let (s1, changed) = next(&s0, &[("a", "alpha"), ("b", "beta")], &[]);
    fixture.publish(&s0, &s1, &changed).unwrap();
    let pinned = fixture.store.read_view().unwrap();
    assert_eq!(
        search_at(&fixture.storage.admission, &pinned, &s1, "alpha"),
        ["a"]
    );

    // Later edits merge away the shards the pinned reader uses, then a
    // definition change replaces the whole generation and it is reclaimed.
    let mut state = s1.clone();
    for round in 0..(FANIN * 2) {
        let title = format!("later{round}");
        let (following, changed) = next(&state, &[("a", title.as_str())], &[]);
        fixture.publish(&state, &following, &changed).unwrap();
        state = following;
    }
    let mut redefined = state.clone();
    redefined.revision += 1;
    redefined.collections.get_mut("docs").unwrap().definition = definition("/other");
    fixture
        .publish(&state, &redefined, &Changed::new())
        .unwrap();
    let (following, changed) = next(&redefined, &[("z", "zulu")], &[]);
    fixture.publish(&redefined, &following, &changed).unwrap();

    {
        let mut cache = fixture.storage.admission.text_shards.lock().unwrap();
        cache.budget = 0;
        cache.evict(0);
    }
    // The pinned root still reads its own revision's shards.
    assert_eq!(
        search_at(&fixture.storage.admission, &pinned, &s1, "alpha"),
        ["a"]
    );
    assert_eq!(
        search_at(&fixture.storage.admission, &pinned, &s1, "beta"),
        ["b"]
    );
    assert!(
        fixture
            .storage
            .admission
            .text_shards
            .lock()
            .unwrap()
            .entries
            .is_empty()
    );
    pinned.close().unwrap();

    fixture.storage.admission.text_shards.lock().unwrap().budget = DEFAULT_SHARD_CACHE_BYTES;
    assert!(fixture.search(&following, "alpha").is_empty());
    let (entries, bytes) = {
        let cache = fixture.storage.admission.text_shards.lock().unwrap();
        (cache.entries.len(), cache.bytes)
    };
    assert!(entries > 0 && bytes <= DEFAULT_SHARD_CACHE_BYTES);
    fixture.close().await;
}

#[tokio::test]
async fn restore_keeps_a_covering_directory_and_rebuilds_anything_else() {
    let fixture = Fixture::new().await;
    let s0 = genesis();
    let (s1, changed) = next(&s0, &[("a", "alpha")], &[]);
    fixture.publish(&s0, &s1, &changed).unwrap();
    let (s2, changed) = next(&s1, &[("b", "beta")], &[]);
    let ahead = fixture.publish(&s1, &s2, &changed).unwrap();

    // Reopening at the older snapshot keeps the directory: later entries
    // replay as covered publications.
    let mut writes = Vec::new();
    prepare_restore(&fixture.owner, &fixture.store, &s1, None, true, &mut writes).unwrap();
    assert!(writes.is_empty());
    assert!(fixture.publish(&s1, &s2, &changed).is_none());

    // Installing a snapshot always rebuilds from it.
    prepare_restore(
        &fixture.owner,
        &fixture.store,
        &s1,
        None,
        false,
        &mut writes,
    )
    .unwrap();
    fixture.store.write_batch(&writes).unwrap();
    let installed = fixture.current();
    assert!(installed.is_current());
    assert_eq!(installed.revision, s1.revision);
    assert_ne!(installed.page_space, ahead.page_space);
    assert_eq!(fixture.search(&s1, "alpha"), ["a"]);
    assert!(fixture.search(&s1, "beta").is_empty());

    // A rebuild that cannot read its bodies selects a stale empty generation
    // rather than keeping another history's directory.
    let mut unreadable = s2.clone();
    unreadable
        .collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert("a".into(), stored("a", 1));
    let mut writes = Vec::new();
    prepare_restore(
        &fixture.owner,
        &fixture.store,
        &unreadable,
        None,
        false,
        &mut writes,
    )
    .unwrap();
    fixture.store.write_batch(&writes).unwrap();
    let failed = fixture.current();
    assert!(!failed.is_current());
    assert_eq!(failed.revision, unreadable.revision);
    assert_eq!(failed.shards, 0);
    fixture.close().await;
}
