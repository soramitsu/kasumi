use super::*;
use kasumi_store::test_utils::LocalKeyProvider;
use kasumi_types::{
    Action, CollectionDefinition, CollectionRetentionClass, CollectionState, CollectionWriteMode,
    Document, DocumentSlot, Grant, IndexDefinition, IndexField, Limits, Policy, ScalarType,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

// These storage component fixtures supply their own synthetic apply history.
fn prepare_publication(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    previous: &TenantState,
    previous_indexes: &QueryIndexes,
    candidate: &TenantState,
    candidate_indexes: &QueryIndexes,
    applied: Option<StructuredApplied>,
) -> Result<Option<StructuredPublication>> {
    prepare_publication_at(
        owner,
        store,
        (previous, previous_indexes),
        (candidate, candidate_indexes),
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
            Arc::new(LocalKeyProvider::new([58; 32])),
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

    fn manifest(&self) -> StructuredManifest {
        StructuredManifest::load(&self.store)
            .unwrap()
            .expect("structured directory")
    }

    /// Prepare one candidate publication and commit whatever it writes.
    fn publish(&self, owner: &StructuredOwner, previous: &Model, next: &Model, term: u64) -> bool {
        let publication = prepare_publication(
            owner,
            &self.store,
            &previous.state,
            &previous.indexes,
            &next.state,
            &next.indexes,
            Some(applied(&next.state, term)),
        )
        .unwrap();
        match publication {
            Some(mut publication) => {
                self.store.write_batch(&publication.take_writes()).unwrap();
                true
            }
            None => false,
        }
    }

    fn verify(&self, model: &Model) {
        let manifest = self.manifest();
        assert!(manifest.is_current());
        verify_rows(&*self.store, &manifest, &model.state, &model.indexes).unwrap();
    }

    fn space_rows(&self, space: &str) -> u64 {
        let view = self.store.read_view().unwrap();
        let mut rows = 0u64;
        view.visit(space, 64 << 10, |_, _| {
            rows += 1;
            Ok(())
        })
        .unwrap();
        view.close().unwrap();
        rows
    }

    /// Pages and overflow chunks reachable from the selected root.
    fn reachable(&self) -> u64 {
        let manifest = self.manifest();
        let reader =
            TreeReader::new(&*self.store, &manifest.page_space, manifest.records, None).unwrap();
        let mut rows = reader.verify().unwrap();
        reader
            .scan(Bound::Unbounded, Direction::Forward, &mut |_, value| {
                rows += value.len().div_ceil(64 << 10) * u64::from(value.len() > 2048);
                Ok(true)
            })
            .unwrap();
        rows
    }

    fn ids(&self, collection: &str, field: usize, predicate: FieldPredicate<'_>) -> Vec<String> {
        let manifest = self.manifest();
        assert!(manifest.is_current());
        let reader =
            TreeReader::new(&*self.store, &manifest.page_space, manifest.records, None).unwrap();
        let mut ids = Vec::new();
        visit_posting(
            &reader,
            collection,
            field,
            predicate,
            || Ok(()),
            |id| {
                ids.push(id.to_owned());
                Ok(true)
            },
        )
        .unwrap();
        ids
    }

    async fn close(self) {
        self.store.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

/// One generation's state, its resident indexes and the bodies behind them.
struct Model {
    state: TenantState,
    indexes: Arc<QueryIndexes>,
    documents: BTreeMap<String, Value>,
}

const FIELDS: [(&str, ScalarType); 5] = [
    ("/amount", ScalarType::Decimal),
    ("/flag", ScalarType::Boolean),
    ("/n", ScalarType::Number),
    ("/status", ScalarType::String),
    ("/tags", ScalarType::StringArray),
];

fn definition(fields: &[(&str, ScalarType)]) -> Arc<CollectionDefinition> {
    Arc::new(CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type": "object"}),
        indexes: fields
            .iter()
            .map(|(path, kind)| IndexDefinition {
                name: path.trim_start_matches('/').into(),
                fields: vec![IndexField {
                    path: (*path).into(),
                    kind: *kind,
                }],
                unique: false,
                text: None,
            })
            .collect(),
        strict_read_audit: false,
    })
}

fn genesis() -> Model {
    let state = crate::TenantEngine::new(
        "tenant".into(),
        uuid::Uuid::from_u128(6).to_string(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
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
    let indexes = crate::index_source::build(&state)
        .map_err(crate::index_source::into_anyhow)
        .unwrap();
    Model {
        state,
        indexes: Arc::new(indexes),
        documents: BTreeMap::new(),
    }
}

impl Model {
    /// The successor at the next revision: `put` documents upserted, `remove`
    /// documents deleted, optionally under a new collection definition
    /// (`Some(None)` drops the collection).
    fn next(
        &self,
        put: Vec<(String, Value)>,
        remove: &[&str],
        redefine: Option<Option<Arc<CollectionDefinition>>>,
    ) -> Self {
        let mut state = self.state.clone();
        state.revision += 1;
        let revision = state.revision;
        let mut documents = self.documents.clone();
        let mut changed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        if let Some(None) = redefine {
            state.collections.remove("docs");
            documents.clear();
        } else {
            let mut target =
                state
                    .collections
                    .get("docs")
                    .cloned()
                    .unwrap_or_else(|| CollectionState {
                        definition: definition(&FIELDS),
                        data_epoch: 0,
                        documents: Default::default(),
                        archived_documents: Default::default(),
                        archived_document_bytes: 0,
                    });
            if let Some(Some(definition)) = redefine {
                target.definition = definition;
            }
            for (id, body) in put {
                target.documents.insert(
                    id.clone(),
                    Arc::new(DocumentSlot::Pending(Arc::new(Document {
                        id: id.clone(),
                        version: revision,
                        body: body.clone(),
                    }))),
                );
                documents.insert(id.clone(), body);
                changed.entry("docs".into()).or_default().insert(id);
            }
            for id in remove {
                target.documents.remove(*id);
                documents.remove(*id);
                changed
                    .entry("docs".into())
                    .or_default()
                    .insert((*id).into());
            }
            target.data_epoch = revision;
            state.collections.insert("docs".into(), target);
        }
        let indexes = crate::index_source::update(&self.indexes, &self.state, &state, &changed)
            .map_err(crate::index_source::into_anyhow)
            .unwrap();
        Self {
            state,
            indexes: Arc::new(indexes),
            documents,
        }
    }

    /// The same indexes at the next revision: a metadata or denied entry.
    fn metadata(&self) -> Self {
        let mut state = self.state.clone();
        state.revision += 1;
        Self {
            state,
            indexes: self.indexes.clone(),
            documents: self.documents.clone(),
        }
    }
}

fn log_id(state: &TenantState, term: u64) -> kasumi_raft::LogId<u64> {
    openraft::LogId::new(
        openraft::CommittedLeaderId::new(term, 1),
        state.revision - state.revision_base,
    )
}

fn applied(state: &TenantState, term: u64) -> StructuredApplied {
    let index = state.revision - state.revision_base;
    StructuredApplied {
        index,
        log_sha256: log_sha256(&log_id(state, term)).unwrap(),
        command_sha256: Some([index as u8; 32]),
    }
}

fn snapshot_meta(
    state: &TenantState,
    term: u64,
) -> kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode> {
    kasumi_raft::SnapshotMeta {
        last_log_id: Some(log_id(state, term)),
        last_membership: Default::default(),
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    }
}

fn long(suffix: &str) -> String {
    format!("{}{suffix}", "x".repeat(230))
}

/// Statuses around the ordered-key bound: two scalars exactly at it, long
/// scalars sharing their first bytes, and ordinary short ones.
fn statuses() -> Vec<String> {
    vec![
        "closed".into(),
        "new".into(),
        "open".into(),
        "x".repeat(INLINE_VALUE),
        "x".repeat(INLINE_VALUE - 1),
        long("a"),
        long("b"),
        long("bb"),
        format!("{}y", "x".repeat(INLINE_VALUE)),
        "zeta\u{0}nul".into(),
    ]
}

fn body(n: usize) -> Value {
    let statuses = statuses();
    let mut body = serde_json::Map::new();
    match n % 7 {
        0 => {}
        1 => {
            body.insert("status".into(), Value::Null);
        }
        _ => {
            body.insert("status".into(), json!(statuses[n % statuses.len()]));
        }
    }
    if !n.is_multiple_of(5) {
        let number: Value = serde_json::from_str(&format!("{}.25", n as i64 - 20)).unwrap();
        body.insert("n".into(), number);
        body.insert(
            "amount".into(),
            json!(format!("{}.50", (n as i64 - 15) * 3)),
        );
    }
    match n % 4 {
        0 => {
            body.insert("flag".into(), json!(true));
        }
        1 => {
            body.insert("flag".into(), json!(false));
        }
        2 => {
            body.insert("flag".into(), Value::Null);
        }
        _ => {}
    }
    match n % 6 {
        0 => {}
        1 => {
            body.insert("tags".into(), json!([]));
        }
        _ => {
            body.insert(
                "tags".into(),
                json!([format!("t{}", n % 3), format!("u{}", n % 4), long("tag")]),
            );
        }
    }
    Value::Object(body)
}

fn decimal(value: &Value) -> f64 {
    match value {
        Value::Number(number) => number.as_str().parse().unwrap(),
        Value::String(text) => text.parse().unwrap(),
        _ => panic!("not numeric"),
    }
}

/// Order two non-null scalars of one field as the index does.
fn order(kind: ScalarType, left: &Value, right: &Value) -> std::cmp::Ordering {
    match kind {
        ScalarType::Number | ScalarType::Decimal => decimal(left).total_cmp(&decimal(right)),
        ScalarType::Boolean => left.as_bool().cmp(&right.as_bool()),
        _ => left
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right.as_str().unwrap().as_bytes()),
    }
}

/// Evaluate a predicate over the model's bodies without any index.
fn expected(model: &Model, path: &str, predicate: FieldPredicate<'_>) -> BTreeSet<String> {
    model
        .documents
        .iter()
        .filter(|(_, body)| {
            let actual = body.pointer(path);
            match predicate {
                FieldPredicate::Exists(present) => actual.is_some() == present,
                FieldPredicate::Equals { value, kind: k } => match actual {
                    None => false,
                    Some(Value::Null) => value.is_null(),
                    Some(Value::Array(elements)) => elements
                        .iter()
                        .any(|element| order(k, element, value).is_eq()),
                    Some(actual) => !value.is_null() && order(k, actual, value).is_eq(),
                },
                FieldPredicate::In { values, kind: k } => match actual {
                    None | Some(Value::Null) => false,
                    Some(actual) => values.iter().any(|value| order(k, actual, value).is_eq()),
                },
                FieldPredicate::Range {
                    lower,
                    upper,
                    kind: k,
                } => match actual {
                    None | Some(Value::Null) => false,
                    Some(actual) => {
                        (match lower {
                            Bound::Unbounded => true,
                            Bound::Included(value) => order(k, actual, value).is_ge(),
                            Bound::Excluded(value) => order(k, actual, value).is_gt(),
                        }) && (match upper {
                            Bound::Unbounded => true,
                            Bound::Included(value) => order(k, actual, value).is_le(),
                            Bound::Excluded(value) => order(k, actual, value).is_lt(),
                        })
                    }
                },
            }
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn bound(value: Option<&Value>, inclusive: bool) -> Bound<&Value> {
    match value {
        None => Bound::Unbounded,
        Some(value) if inclusive => Bound::Included(value),
        Some(value) => Bound::Excluded(value),
    }
}

/// Every predicate family over every field, against the brute-force model.
fn check_predicates(fixture: &Fixture, model: &Model, fields: &[(&str, ScalarType)]) {
    let mut sorted: Vec<_> = fields.to_vec();
    sorted.sort_by_key(|(path, _)| *path);
    let statuses = statuses();
    let mut probes = 0;
    for (ordinal, (path, kind)) in sorted.iter().enumerate() {
        let mut check = |predicate: FieldPredicate<'_>, id_ordered: bool| {
            let found = fixture.ids("docs", ordinal, predicate);
            let unique: BTreeSet<String> = found.iter().cloned().collect();
            assert_eq!(unique.len(), found.len(), "{path}: an ID was visited twice");
            if id_ordered {
                assert!(found.windows(2).all(|pair| pair[0] < pair[1]), "{path}");
            }
            assert_eq!(unique, expected(model, path, predicate), "{path}");
            probes += 1;
        };
        check(FieldPredicate::Exists(true), true);
        check(FieldPredicate::Exists(false), true);
        let null = Value::Null;
        if !matches!(kind, ScalarType::StringArray | ScalarType::NumberArray) {
            check(
                FieldPredicate::Equals {
                    value: &null,
                    kind: *kind,
                },
                true,
            );
        }
        let values: Vec<Value> = match kind {
            ScalarType::String => statuses
                .iter()
                .map(|status| json!(status))
                .chain([json!("absent"), json!(long("absent")), json!(long("a!"))])
                .collect(),
            ScalarType::StringArray => {
                vec![json!("t0"), json!("u3"), json!(long("tag")), json!("")]
            }
            ScalarType::Boolean => vec![json!(true), json!(false)],
            ScalarType::Number => [-20.75, -3.75, 0.25, 4.25, 11.25, 99.0]
                .iter()
                .map(|n| serde_json::from_str(&format!("{n}")).unwrap())
                .collect(),
            ScalarType::Decimal => ["-45.50", "-3.5", "0", "13.500", "58.50"]
                .iter()
                .map(|text| json!(text))
                .collect(),
            ScalarType::NumberArray => unreachable!(),
        };
        for value in &values {
            check(FieldPredicate::Equals { value, kind: *kind }, true);
        }
        if matches!(kind, ScalarType::StringArray) {
            continue;
        }
        check(
            FieldPredicate::In {
                values: &values,
                kind: *kind,
            },
            false,
        );
        if matches!(kind, ScalarType::Boolean) {
            continue;
        }
        for low in values.iter().map(Some).chain([None]) {
            for high in values.iter().map(Some).chain([None]) {
                for (low_inclusive, high_inclusive) in
                    [(true, true), (true, false), (false, true), (false, false)]
                {
                    if low.is_none() && high.is_none() {
                        continue;
                    }
                    check(
                        FieldPredicate::Range {
                            lower: bound(low, low_inclusive),
                            upper: bound(high, high_inclusive),
                            kind: *kind,
                        },
                        false,
                    );
                }
            }
        }
    }
    assert!(probes > 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_writes_keep_every_posting_current_for_each_predicate() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    assert!(StructuredManifest::load(&fixture.store).unwrap().is_none());

    // A pristine store starts its directory in the initial space.
    let first = genesis.next(
        (0..60).map(|n| (format!("d{n:03}"), body(n))).collect(),
        &[],
        None,
    );
    assert!(fixture.publish(&owner, &genesis, &first, 1));
    let manifest = fixture.manifest();
    assert_eq!(manifest.page_space, structured::INITIAL_SPACE[0]);
    assert_eq!(manifest.revision, first.state.revision);
    assert_eq!(manifest.applied, Some(applied(&first.state, 1)));
    fixture.verify(&first);
    check_predicates(&fixture, &first, &FIELDS);

    // Updates move postings between scalars, deletions remove them and new
    // documents add them; only the changed rows are edited.
    let second = first.next(
        (0..20)
            .map(|n| (format!("d{:03}", n * 3), body(n * 3 + 11)))
            .chain((60..75).map(|n| (format!("d{n:03}"), body(n))))
            .collect(),
        &["d001", "d004", "d007", "d058"],
        None,
    );
    let before = fixture.manifest().records;
    assert!(fixture.publish(&owner, &first, &second, 1));
    assert_eq!(fixture.manifest().records.tree, before.tree);
    fixture.verify(&second);
    check_predicates(&fixture, &second, &FIELDS);

    // A metadata entry moves only the boundary.
    let third = second.metadata();
    let before = fixture.manifest();
    assert!(fixture.publish(&owner, &second, &third, 1));
    let after = fixture.manifest();
    assert_eq!(after.records, before.records);
    assert_eq!(after.revision, third.state.revision);
    fixture.verify(&third);

    // A changed definition renumbers the fields: its rows are replaced.
    let redefined = [
        ("/aaa", ScalarType::String),
        ("/n", ScalarType::Number),
        ("/status", ScalarType::String),
        ("/tags", ScalarType::StringArray),
    ];
    let fourth = third.next(
        vec![("d900".into(), json!({"aaa": "first", "status": "open"}))],
        &[],
        Some(Some(definition(&redefined))),
    );
    assert!(fixture.publish(&owner, &third, &fourth, 1));
    assert_ne!(fixture.manifest().layout_sha256, after.layout_sha256);
    fixture.verify(&fourth);
    check_predicates(&fixture, &fourth, &redefined);

    // Deleting every document, then the collection, empties the tree.
    let ids: Vec<String> = fourth.documents.keys().cloned().collect();
    let removed: Vec<&str> = ids.iter().map(String::as_str).collect();
    let fifth = fourth.next(vec![], &removed, None);
    assert!(fixture.publish(&owner, &fourth, &fifth, 1));
    fixture.verify(&fifth);
    assert_eq!(fixture.manifest().records.count(), 0);
    let sixth = fifth.next(vec![], &[], Some(None));
    assert!(fixture.publish(&owner, &fifth, &sixth, 1));
    fixture.verify(&sixth);
    // Edits left no unreachable page behind.
    ordered_pages::recover_abandoned_edits_in(&fixture.store, structured::FAMILY).unwrap();
    assert_eq!(fixture.space_rows(structured::INITIAL_SPACE[0]), 0);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn structured_edits_borrow_overflow_values_until_the_producer_fits() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    let first = genesis.next(vec![("original".into(), small(1))], &[], None);
    assert!(fixture.publish(&owner, &genesis, &first, 1));
    let selected = fixture.manifest();

    let scalar = "x".repeat(MAX_EDIT_BYTES + 1);
    let value = FieldValue {
        tag: 5,
        bytes: std::borrow::Cow::Borrowed(scalar.as_bytes()),
    };
    let (_, borrowed) = encode_row(
        "docs",
        StructuredRow::Value {
            field: 0,
            value: &value,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(borrowed.as_ptr(), scalar.as_ptr());

    let next = first.next(vec![("large".into(), json!({"status":scalar}))], &[], None);
    let before = crate::test_utils::reserved_payload_bytes(&fixture._storage.admission);
    assert!(
        edit(
            &owner,
            &fixture.store,
            &selected,
            &first.indexes,
            &next.state,
            &next.indexes,
            Some(applied(&next.state, 1)),
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&fixture._storage.admission),
        before
    );
    assert_eq!(fixture.manifest(), selected);
    fixture.verify(&first);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_compound_unique_proof_resolves_swaps_sparse_values_and_preserves_failures() {
    let fixture = Fixture::new().await;
    let genesis = genesis();
    let mut definition = (*definition(&[])).clone();
    definition.indexes.push(IndexDefinition {
        name: "group_serial".into(),
        unique: true,
        text: None,
        fields: vec![
            IndexField {
                path: "/group".into(),
                kind: ScalarType::String,
            },
            IndexField {
                path: "/serial".into(),
                kind: ScalarType::Number,
            },
        ],
    });
    // Reverse declaration order relative to the canonical unique-name order.
    let mut reversed = definition.indexes.last().unwrap().clone();
    reversed.name = "aaa_serial_group".into();
    reversed.fields.reverse();
    definition.indexes.push(reversed);
    let group = "business-group-".repeat(30);
    let body = |n: usize| json!({"group": group, "serial": n});
    let first = genesis.next(
        (0..40).map(|n| (format!("d{n:03}"), body(n))).collect(),
        &[],
        Some(Some(Arc::new(definition))),
    );
    assert!(fixture.publish(&StructuredOwner::default(), &genesis, &first, 1));
    let manifest = fixture.manifest();
    let view = fixture.store.read_view().unwrap();
    let reader = TreeReader::new(&view, &manifest.page_space, manifest.records, None).unwrap();
    let read = |lower, upper, descending| {
        ordered_unique_window(&reader, "docs", 0, lower, upper, descending, || true).unwrap()
    };
    let page = read(Bound::Unbounded, Bound::Unbounded, false);
    assert_eq!(
        page.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
        (0..16).map(|n| format!("d{n:03}")).collect::<Vec<_>>()
    );
    let end = &page.last().unwrap().0;
    let next = read(Bound::Excluded(end.as_slice()), Bound::Unbounded, false);
    assert_eq!(
        (
            next.first().unwrap().1.as_str(),
            next.last().unwrap().1.as_str()
        ),
        ("d016", "d031")
    );
    let reverse = read(
        Bound::Excluded(page[12].0.as_slice()),
        Bound::Included(next[1].0.as_slice()),
        true,
    );
    assert_eq!(
        reverse
            .iter()
            .map(|(_, id)| id.as_str())
            .collect::<Vec<_>>(),
        ["d017", "d016", "d015", "d014", "d013"]
    );
    let mut visits = 0;
    let canceled = ordered_unique_window(
        &reader,
        "docs",
        0,
        Bound::Unbounded,
        Bound::Unbounded,
        false,
        || {
            visits += 1;
            visits <= 2
        },
    )
    .unwrap();
    assert_eq!((visits, canceled.len()), (3, 2));
    let candidate = |rows: Vec<(&str, Value)>| {
        let mut next = first.state.clone();
        next.revision += 1;
        let collection = next.collections.get_mut("docs").unwrap();
        collection.data_epoch = next.revision;
        let mut ids = BTreeSet::new();
        for (id, body) in rows {
            ids.insert(id.to_owned());
            collection.documents.insert(
                id.to_owned(),
                Arc::new(DocumentSlot::Pending(Arc::new(Document {
                    id: id.to_owned(),
                    version: next.revision,
                    body,
                }))),
            );
        }
        (next, BTreeMap::from([("docs".to_owned(), ids)]))
    };
    let check = |rows, expected, accepts| {
        let (next, changed) = candidate(rows);
        assert_eq!(
            unique::prove(&reader, &first.indexes, &first.state, &next, &changed, None).unwrap(),
            if expected {
                unique::Decision::Accepted
            } else {
                unique::Decision::Conflict("aaa_serial_group".into())
            }
        );
        let actual =
            crate::index_source::validate_changes(&first.indexes, &first.state, &next, &changed);
        if accepts {
            actual.unwrap();
        } else {
            assert!(
                matches!(actual,Err(kasumi_query::ReadFailure::Query(ref e)) if e == &kasumi_query::unique_conflict("aaa_serial_group"))
            );
        }
    };
    // The first component alone has forty rows, above the sixteen-ID anchor
    // bound. Its second native prefix resolves each owner and the opposite
    // original document is explicitly released by the same batch.
    check(vec![("d000", body(1)), ("d001", body(0))], true, true);
    check(vec![("new", body(1))], false, false);
    check(vec![("new1", body(70)), ("new2", body(70))], false, false);
    check(
        vec![
            ("sparse-a", json!({"group":group})),
            ("sparse-b", json!({"group":group})),
        ],
        true,
        true,
    );
    check(
        vec![
            ("nil-a", json!({"group":null,"serial":12})),
            ("nil-b", json!({"group":null,"serial":12})),
        ],
        false,
        false,
    );

    // A matching digest for oversized tuples forces canonical comparison.
    let long = "x".repeat(kasumi_query::MAX_ORDERED_TUPLE_BYTES + 1);
    let over = json!({"group":long,"serial":100});
    let (next, changed) = candidate(vec![("aa", over.clone()), ("zz", over)]);
    assert_eq!(
        unique::prove(&reader, &first.indexes, &first.state, &next, &changed, None).unwrap(),
        unique::Decision::Inconclusive
    );
    assert!(
        matches!(crate::index_source::validate_changes(&first.indexes,&first.state,&next,&changed),
        Err(kasumi_query::ReadFailure::Query(ref e)) if e==&kasumi_query::unique_conflict("aaa_serial_group"))
    );

    struct Failing<'a>(&'a kasumi_store::TenantReadView);
    impl PageSource for Failing<'_> {
        fn check_access(&self) -> Result<()> {
            Ok(())
        }
        fn read_row(&self, _: &str, _: &[u8], _: usize) -> Result<Option<ordered_pages::PageRow>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "original unique page read",
            )
            .into())
        }
        fn memory(&self) -> Arc<dyn kasumi_store::NodeDiskMemoryAdmission> {
            self.0.memory()
        }
        fn domain(&self) -> &str {
            self.0.domain()
        }
    }
    let failed = Failing(&view);
    let broken = TreeReader::new(&failed, &manifest.page_space, manifest.records, None).unwrap();
    let page_error = ordered_unique_window(
        &broken,
        "docs",
        0,
        Bound::Unbounded,
        Bound::Unbounded,
        false,
        || false,
    )
    .unwrap_err();
    assert_eq!(
        page_error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let (next, changed) = candidate(vec![("same", body(1))]);
    let error =
        unique::prove(&broken, &first.indexes, &first.state, &next, &changed, None).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(error.to_string(), "original unique page read");
    drop(broken);
    drop(reader);
    view.close().unwrap();
    fixture.close().await;
}

fn small(n: usize) -> Value {
    json!({"status": format!("s{:04}", n % 97), "n": n})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_change_rebuilds_a_small_directory_and_resumes_a_large_one() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    // 1,200 documents change 8,400 rows: more than one edit may touch, but
    // the whole index is small enough to rebuild inside the publication.
    let first = genesis.next(
        (0..1200).map(|n| (format!("d{n:06}"), small(n))).collect(),
        &[],
        None,
    );
    assert!(fixture.publish(&owner, &genesis, &first, 1));
    let rebuilt = fixture.manifest();
    assert!(rebuilt.page_space.starts_with("kasumi.app.structured@"));
    fixture.verify(&first);
    let second = first.next(vec![("d000007".into(), small(5000))], &["d000009"], None);
    assert!(fixture.publish(&owner, &first, &second, 1));
    assert_eq!(fixture.manifest().page_space, rebuilt.page_space);
    fixture.verify(&second);

    // An oversized complete replacement starts as an empty non-serving tree.
    let third = second.next(
        (2000..11_000)
            .map(|n| (format!("d{n:06}"), small(n)))
            .collect(),
        &[],
        None,
    );
    assert!(!third.indexes.structured_rows_within(MAX_REBUILD_ROWS));
    let before = fixture.manifest();
    assert!(fixture.publish(&owner, &second, &third, 1));
    let rebuilding = fixture.manifest();
    assert!(rebuilding.rebuild().is_some());
    assert_ne!(rebuilding.page_space, before.page_space);
    assert_eq!(rebuilding.records.count(), 0);
    for _ in 0..3 {
        assert!(
            !maintain(
                &owner,
                &fixture.store,
                &third.state,
                &third.indexes,
                None,
                Some(&applied(&third.state, 1))
            )
            .unwrap()
        );
    }
    let partial = fixture.manifest();
    assert!(partial.rebuild().unwrap().cursor.is_some());
    assert!(partial.records.count() <= 3 * 256);
    // Change and delete rows already scanned, alongside later rows. The
    // retained cursor stays fixed while the original ordinary delta commits.
    let fourth = third.next(
        vec![
            ("d000011".into(), small(6000)),
            ("d010998".into(), small(9000)),
        ],
        &[],
        None,
    );
    assert!(fixture.publish(&owner, &third, &fourth, 1));
    assert_eq!(fixture.manifest().rebuild(), partial.rebuild());
    let restarted = StructuredOwner::default();
    let mut writes = Vec::new();
    prepare_restore(
        &restarted,
        &fixture.store,
        &fourth.state,
        &fourth.indexes,
        &snapshot_meta(&fourth.state, 1),
        true,
        &mut writes,
    )
    .unwrap();
    assert!(writes.is_empty());
    assert_eq!(fixture.manifest().rebuild(), partial.rebuild());
    let mut steps = 0;
    while !maintain(
        &restarted,
        &fixture.store,
        &fourth.state,
        &fourth.indexes,
        None,
        Some(&applied(&fourth.state, 1)),
    )
    .unwrap()
    {
        steps += 1;
        assert!(steps < 2000);
    }
    let restored = fixture.manifest();
    assert_eq!(restored.page_space, rebuilding.page_space);
    // Two presence rows and five postings (three of them absences) each.
    assert_eq!(restored.records.count(), 7 * 10_199);
    fixture.verify(&fourth);
    let fifth = fourth.next(vec![("d000012".into(), small(7000))], &["d010999"], None);
    assert!(fixture.publish(&restarted, &fourth, &fifth, 1));
    fixture.verify(&fifth);
    let ids = fixture.ids(
        "docs",
        3,
        FieldPredicate::Equals {
            value: &json!("s0016"),
            kind: ScalarType::String,
        },
    );
    assert_eq!(
        ids.into_iter().collect::<BTreeSet<_>>(),
        expected(
            &fifth,
            "/status",
            FieldPredicate::Equals {
                value: &json!("s0016"),
                kind: ScalarType::String,
            }
        )
    );
    // The replaced generations are reclaimed in bounded batches.
    NamespaceStage::reclaim_family(&fixture.store, structured::FAMILY).unwrap();
    assert_eq!(fixture.space_rows(&before.page_space), 0);
    assert_eq!(fixture.space_rows(structured::INITIAL_SPACE[0]), 0);
    // Covered ordinary replay reaches the installed 71,393-row boundary.
    // Its current read lease remains valid while the new selection explicitly
    // withdraws the unbounded proof and the registered owner seeds it again.
    let pinned = fixture.store.read_view().unwrap();
    let original = fixture.manifest();
    assert!(fixture.publish(&restarted, &fifth, &fifth, 1));
    let stale = fixture.manifest();
    assert_eq!(stale.status, structured::StructuredStatus::Stale);
    assert_eq!(stale.records, original.records);
    assert_eq!(
        StructuredManifest::load_at(&pinned).unwrap().unwrap(),
        original
    );
    assert!(
        !maintain(
            &restarted,
            &fixture.store,
            &fifth.state,
            &fifth.indexes,
            None,
            Some(&applied(&fifth.state, 1))
        )
        .unwrap()
    );
    let replacement = fixture.manifest();
    assert!(replacement.rebuild().is_some());
    assert_eq!(replacement.records.count(), 0);
    pinned.close().unwrap();
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_structured_array_resumes_by_row_key_across_reordering_and_deletion() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    let prefix = "long-prefix".repeat(24);
    let mut array: Vec<String> = (0..400).map(|i| format!("{prefix}{i:05}")).collect();
    let first = genesis.next(
        vec![("a".into(), json!({"tags":array})), ("z".into(), small(2))],
        &[],
        None,
    );
    let mut seeded = incremental::seed(
        &owner,
        &fixture.store,
        &first.state,
        &first.indexes,
        Some(&applied(&first.state, 1)),
    )
    .unwrap();
    fixture.store.write_batch(&seeded.take_writes()).unwrap();
    assert!(
        !maintain(
            &owner,
            &fixture.store,
            &first.state,
            &first.indexes,
            None,
            Some(&applied(&first.state, 1))
        )
        .unwrap()
    );
    let partial = fixture.manifest();
    let progress = partial.rebuild().unwrap();
    assert!(progress.cursor.as_ref().unwrap().field.is_some());
    let mut forged = partial.clone();
    forged.status = structured::StructuredStatus::Current;
    assert!(
        fixture
            .store
            .write_batch(&[forged.write().unwrap()])
            .is_err()
    );
    let retained = fixture.store.read_view().unwrap();
    array.reverse();
    array.pop();
    array.push(format!("{prefix}additional"));
    let second = first.next(
        vec![
            ("a".into(), json!({"tags":array})),
            ("mid".into(), small(3)),
        ],
        &["z"],
        None,
    );
    assert!(fixture.publish(&owner, &first, &second, 1));
    let mut steps = 0;
    while !maintain(
        &owner,
        &fixture.store,
        &second.state,
        &second.indexes,
        None,
        Some(&applied(&second.state, 1)),
    )
    .unwrap()
    {
        steps += 1;
        assert!(steps < 30);
    }
    fixture.verify(&second);
    assert_eq!(
        StructuredManifest::load_at(&retained).unwrap().unwrap(),
        partial
    );
    retained.close().unwrap();
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bootstrap_partial_binds_its_original_genesis_and_promotes_only_its_exhausted_root() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let mut model = genesis().next(vec![("row".into(), small(7))], &[], None);
    model.state.revision_base = model.state.revision;
    let mut seed =
        incremental::seed(&owner, &fixture.store, &model.state, &model.indexes, None).unwrap();
    fixture.store.write_batch(&seed.take_writes()).unwrap();
    assert!(fixture.publish(&owner, &model, &model, 1));
    let bound = fixture.manifest();
    assert_eq!(bound.applied, Some(applied(&model.state, 1)));
    assert!(bound.rebuild().unwrap().captured.is_none());
    while !fixture.manifest().rebuild().unwrap().finished() {
        assert!(
            !maintain(
                &owner,
                &fixture.store,
                &model.state,
                &model.indexes,
                None,
                bound.applied.as_ref()
            )
            .unwrap()
        );
    }
    let exhausted = fixture.manifest();
    let mut forged = exhausted.clone();
    forged.status = structured::StructuredStatus::Current;
    forged.revision += 1;
    forged.applied.as_mut().unwrap().index += 1;
    assert!(
        fixture
            .store
            .write_batch(&[forged.write().unwrap()])
            .is_err()
    );
    assert_eq!(fixture.manifest(), exhausted);
    assert!(
        maintain(
            &owner,
            &fixture.store,
            &model.state,
            &model.indexes,
            None,
            bound.applied.as_ref()
        )
        .unwrap()
    );
    fixture.verify(&model);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_keeps_a_current_directory_and_replay_must_reproduce_its_boundary() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    let mut models = vec![genesis];
    for step in 0..4usize {
        let previous = models.last().unwrap();
        let next = previous.next(
            (0..30)
                .map(|n| (format!("d{:03}", step * 20 + n), body(step * 7 + n)))
                .collect(),
            &[],
            None,
        );
        assert!(fixture.publish(&owner, previous, &next, 1));
        models.push(next);
    }
    fixture.verify(&models[4]);
    let selected = fixture.manifest();

    // Restart: the snapshot is older than the directory, which is kept. The
    // replayed entries below it publish nothing, and the entry that reaches
    // it reproduces its boundary and rows.
    let restarted = StructuredOwner::default();
    let mut writes = Vec::new();
    prepare_restore(
        &restarted,
        &fixture.store,
        &models[2].state,
        &models[2].indexes,
        &snapshot_meta(&models[2].state, 1),
        true,
        &mut writes,
    )
    .unwrap();
    assert!(writes.is_empty());
    assert!(!fixture.publish(&restarted, &models[2], &models[3], 1));
    assert!(!fixture.publish(&restarted, &models[3], &models[4], 1));
    assert_eq!(fixture.manifest(), selected);
    // The unapplied tail edits forward from it.
    let fifth = models[4].next(vec![("tail".into(), body(3))], &["d000"], None);
    assert!(fixture.publish(&restarted, &models[4], &fifth, 1));
    fixture.verify(&fifth);
    let selected = fixture.manifest();

    // A snapshot at exactly the directory's position keeps it only when the
    // log position and every row agree.
    let mut writes = Vec::new();
    prepare_restore(
        &StructuredOwner::default(),
        &fixture.store,
        &fifth.state,
        &fifth.indexes,
        &snapshot_meta(&fifth.state, 1),
        true,
        &mut writes,
    )
    .unwrap();
    assert!(writes.is_empty());
    for (state, indexes, term) in [
        // Another leader's entry at the same index.
        (&fifth.state, &fifth.indexes, 2),
        // The same position with other rows.
        (&fifth.state, &models[4].indexes, 1),
    ] {
        let mut writes = Vec::new();
        prepare_restore(
            &StructuredOwner::default(),
            &fixture.store,
            state,
            indexes,
            &snapshot_meta(state, term),
            true,
            &mut writes,
        )
        .unwrap();
        assert!(!writes.is_empty(), "a differing boundary must be rebuilt");
    }
    // An installed snapshot always replaces the directory.
    let mut writes = Vec::new();
    prepare_restore(
        &StructuredOwner::default(),
        &fixture.store,
        &fifth.state,
        &fifth.indexes,
        &snapshot_meta(&fifth.state, 1),
        false,
        &mut writes,
    )
    .unwrap();
    assert!(!writes.is_empty());
    // None of those unpublished generations moved the selected directory.
    assert_eq!(fixture.manifest(), selected);

    // A replayed entry that reaches the directory with other rows, or as
    // another command, cannot be vouched for: the directory goes stale at
    // that revision instead of serving rows that differ from the state.
    let restarted = StructuredOwner::default();
    let other = models[4].next(vec![("other".into(), body(9))], &[], None);
    assert_eq!(other.state.revision, fifth.state.revision);
    assert!(fixture.publish(&restarted, &models[4], &other, 1));
    let stale = fixture.manifest();
    assert!(!stale.is_current());
    assert_eq!(stale.revision, other.state.revision);
    assert_eq!(stale.records, selected.records);
    // The next publication replaces the small stale directory.
    let sixth = other.next(vec![("after".into(), body(4))], &[], None);
    assert!(fixture.publish(&restarted, &other, &sixth, 1));
    assert!(
        fixture
            .manifest()
            .page_space
            .starts_with("kasumi.app.structured@")
    );
    fixture.verify(&sixth);
    check_predicates(&fixture, &sixth, &FIELDS);

    // A covered replay under another command identity is refused the same way.
    let seventh = sixth.next(vec![("seven".into(), body(5))], &[], None);
    assert!(fixture.publish(&restarted, &sixth, &seventh, 1));
    let restarted = StructuredOwner::default();
    assert!(fixture.publish(&restarted, &sixth, &seventh, 2));
    assert!(!fixture.manifest().is_current());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_publication_leaves_the_selected_directory_and_no_orphan_rows() {
    let fixture = Fixture::new().await;
    let owner = StructuredOwner::default();
    let genesis = genesis();
    let first = genesis.next(
        (0..5000).map(|n| (format!("d{n:06}"), small(n))).collect(),
        &[],
        None,
    );
    assert!(fixture.publish(&owner, &genesis, &first, 1));
    fixture.verify(&first);
    let selected = fixture.manifest();
    let settled = fixture.space_rows(&selected.page_space);
    assert_eq!(settled, fixture.reachable());

    // 250 updates spread over the collection change 1,000 rows on most
    // leaves: within the edit bound but too many pages for the publication
    // itself, so the edit journals batches first.
    let second = first.next(
        (0..250)
            .map(|n| (format!("d{:06}", n * 20), small(n * 20 + 100_000)))
            .collect(),
        &[],
        None,
    );
    let prepare = |owner: &StructuredOwner| {
        prepare_publication(
            owner,
            &fixture.store,
            &first.state,
            &first.indexes,
            &second.state,
            &second.indexes,
            Some(applied(&second.state, 1)),
        )
        .unwrap()
        .expect("staged edit")
    };
    // The process stops after staging and before the publication commits.
    drop(prepare(&owner));
    assert!(fixture.space_rows(&selected.page_space) > settled);
    assert_eq!(fixture.manifest(), selected);
    fixture.verify(&first);

    // The next process abandons those rows before it edits, then publishes.
    let restarted = StructuredOwner::default();
    let mut publication = prepare(&restarted);
    fixture
        .store
        .write_batch(&publication.take_writes())
        .unwrap();
    drop(publication);
    fixture.verify(&second);
    let third = second.next(vec![("d000001".into(), small(900))], &[], None);
    assert!(fixture.publish(&restarted, &second, &third, 1));
    fixture.verify(&third);
    ordered_pages::recover_abandoned_edits_in(&fixture.store, structured::FAMILY).unwrap();
    assert_eq!(
        fixture.space_rows(&selected.page_space),
        fixture.reachable()
    );

    // An interrupted replacement stays sealed and unselected. Its running
    // owner may reclaim four batches per tick. A process which reopens the
    // older snapshot must recover its durable stages before replaying.
    let fourth = third.next(
        (1000..2500)
            .map(|n| (format!("d{n:06}"), small(n + 7)))
            .collect(),
        &[],
        None,
    );
    let replace = |owner: &StructuredOwner| {
        prepare_publication(
            owner,
            &fixture.store,
            &third.state,
            &third.indexes,
            &fourth.state,
            &fourth.indexes,
            Some(applied(&fourth.state, 1)),
        )
        .unwrap()
        .expect("replacement generation")
    };
    let page_space = |writes: &[WriteOp]| {
        writes
            .iter()
            .find_map(|write| match write {
                WriteOp::Put {
                    namespace, value, ..
                } if namespace == structured::MANIFESTS => Some(
                    serde_json::from_slice::<StructuredManifest>(value)
                        .unwrap()
                        .page_space,
                ),
                _ => None,
            })
            .expect("manifest write")
    };
    let abandoned = page_space(&replace(&restarted).take_writes());
    let staged_rows = fixture.space_rows(&abandoned);
    assert!(staged_rows > 60);
    assert_eq!(fixture.manifest().revision, third.state.revision);
    fixture.verify(&third);
    assert!(
        !restarted
            .finish_replacement_for_test(&fixture.store)
            .unwrap()
    );
    let remaining = fixture.space_rows(&abandoned);
    assert!(remaining < staged_rows && staged_rows - remaining <= 60);
    assert!(remaining > 0);

    let restarted = StructuredOwner::default();
    let mut recovered = Vec::new();
    prepare_restore(
        &restarted,
        &fixture.store,
        &first.state,
        &first.indexes,
        &snapshot_meta(&first.state, 1),
        true,
        &mut recovered,
    )
    .unwrap();
    assert!(recovered.is_empty());
    assert_eq!(fixture.space_rows(&abandoned), 0);
    fixture.verify(&third);
    let writes = replace(&restarted).take_writes();
    let replacement = page_space(&writes);
    assert_ne!(replacement, abandoned);
    assert_eq!(fixture.space_rows(&abandoned), 0);
    fixture.store.write_batch(&writes).unwrap();
    assert_eq!(fixture.manifest().page_space, replacement);
    fixture.verify(&fourth);
    NamespaceStage::reclaim_family(&fixture.store, structured::FAMILY).unwrap();
    assert_eq!(fixture.space_rows(&selected.page_space), 0);
    assert_eq!(fixture.space_rows(&replacement), fixture.reachable());
    fixture.close().await;
}
