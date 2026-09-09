use super::*;
use crate::admission::AdmissionConfig;
use kasumi_query::QueryCancellation;
use serde_json::json;
use std::sync::atomic::AtomicU64;

#[derive(Default)]
struct Clock(AtomicU64);
impl LeaseClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Acquire))
    }
}
fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "lease-test".into(),
    }
}
fn node() -> Arc<NodeAdmission> {
    // These unit tests isolate lease ownership. They install no production
    // maintenance lanes and do not establish a production capacity gate.
    NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            max_inflight_bytes: Some(512 << 20),
            ..Default::default()
        },
        8 << 30,
        0,
    )
    .unwrap()
}
fn fixture(count: usize, body_bytes: usize, budget: usize) -> TenantEngine {
    let policy = Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context().scopes,
        }],
        strict_read_audit: false,
    };
    let mut limits = Limits::default();
    limits.atomic.max_snapshot_lease_bytes = budget;
    let engine = TenantEngine::new("tenant".into(), "incarnation".into(), policy, limits).unwrap();
    let mut state = engine.generation().unwrap().state.clone();
    state.revision = 1;
    state.schema_epoch = 1;
    let definition = CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
    };
    let documents: imbl::OrdMap<String, Arc<Document>> = (0..count)
        .map(|id| {
            let id = format!("d{id:04}");
            (
                id.clone(),
                Arc::new(Document {
                    id,
                    version: 1,
                    body: json!({"value":"x".repeat(body_bytes)}),
                }),
            )
        })
        .collect();
    state.document_count = count as u64;
    state.logical_bytes = documents
        .values()
        .map(|doc| crate::accounting::encoded_len(&doc.body).unwrap() as u64)
        .sum();
    state.collections.insert(
        "docs".into(),
        CollectionState {
            definition,
            data_epoch: 1,
            documents,
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        },
    );
    install(&engine, state);
    engine
}
fn install(engine: &TenantEngine, state: TenantState) {
    let indexes = Arc::new(QueryIndexes::build(&state.collections).unwrap());
    let snapshot_accounting = SnapshotAccounting::rebuild(&state).unwrap();
    engine.publish_generation(Some(Arc::new(Generation {
        terminals: engine.generation().unwrap().terminals.clone(),
        target_resolutions: engine.generation().unwrap().target_resolutions.clone(),
        state,
        indexes,
        receipt_expiry: Default::default(),
        snapshot_accounting,
        _read_reservations: vec![],
    })));
}
fn write(engine: &TenantEngine, mutation: Mutation) -> WriteReceipt {
    let revision = engine.generation().unwrap().state.revision + 1;
    engine
        .apply_command(
            revision,
            Command {
                context: context(),
                timestamp_ms: revision,
                operation: Operation::Mutate(MutationBatch {
                    idempotency_key: format!("write-{revision}"),
                    read_set: vec![],
                    operations: vec![mutation],
                }),
            },
        )
        .unwrap()
        .unwrap()
}
fn put(id: &str, body_bytes: usize) -> Mutation {
    Mutation::Put {
        collection: "docs".into(),
        id: id.into(),
        expected: Precondition::Any,
        body: json!({"value":"y".repeat(body_bytes)}),
    }
}
fn open(engine: &TenantEngine, node: &Arc<NodeAdmission>, clock: &Arc<Clock>) -> Arc<LeaseHandle> {
    clock.0.fetch_add(1, Ordering::AcqRel);
    engine
        .leases
        .open(engine, &context(), 60_000, clock.clone(), 1, node)
        .unwrap()
}
fn select(
    engine: &TenantEngine,
    node: &Arc<NodeAdmission>,
    lease: &LeaseHandle,
    id: &str,
) -> SelectedSnapshot {
    engine
        .leases
        .select(
            engine,
            &lease.header.lease_id,
            PageSelection::Points(vec![DocumentKey {
                collection: "docs".into(),
                id: id.into(),
            }]),
            PageAccess {
                context: &context(),
                term: 1,
                node,
                cancellation: &QueryCancellation::default(),
            },
        )
        .unwrap()
}

#[test]
fn publication_expires_full_roots_while_two_inflight_selections_keep_only_bounded_pages() {
    let engine = fixture(64, 64 << 10, 64 << 10);
    let node = node();
    let clock = Arc::new(Clock::default());
    let lease = open(&engine, &node, &clock);
    let root_bytes = node.snapshot().reserved_bytes;
    assert!(root_bytes < 64 << 10);
    let unselected =
        Arc::downgrade(&engine.generation().unwrap().state.collections["docs"].documents["d0063"]);
    let page_one = select(&engine, &node, &lease, "d0000");
    let page_two = select(&engine, &node, &lease, "d0001");
    assert_eq!(
        page_one.generation.state.collections["docs"]
            .documents
            .len(),
        1
    );
    assert_eq!(
        page_two.generation.state.collections["docs"]
            .documents
            .len(),
        1
    );
    let charged = node.snapshot().reserved_bytes;
    let committed = write(&engine, put("d0063", 64 << 10));
    assert_eq!(committed.revision, 2);
    // No monitor tick or subsequent read is needed to revoke either page.
    assert!(!page_one.handle.live());
    assert!(!page_two.handle.live());
    assert!(engine.leases.entries.lock().unwrap().is_empty());
    assert!(
        unselected.upgrade().is_none(),
        "an in-flight page retained the whole old document root"
    );
    assert_eq!(page_one.generation.state.revision, lease.header.revision);
    assert_eq!(
        page_one.generation.state.collections["docs"].documents["d0000"].body["value"]
            .as_str()
            .unwrap()
            .as_bytes()[0],
        b'x'
    );
    assert_eq!(
        engine.generation().unwrap().state.collections["docs"].documents["d0063"].body["value"]
            .as_str()
            .unwrap()
            .as_bytes()[0],
        b'y'
    );
    assert!(node.snapshot().reserved_bytes < charged);
    assert!(
        node.snapshot().reserved_bytes > root_bytes,
        "live page buffers lost their reservation"
    );
    assert_eq!(
        engine
            .leases
            .checked_handle(&engine, &context(), &lease.header.lease_id, 1)
            .err()
            .unwrap()
            .code,
        ErrorCode::CursorExpired
    );
    drop(page_one);
    drop(page_two);
    assert_eq!(node.snapshot().reserved_bytes, LEASE_HANDLE_BYTES as u64);
    drop(lease);
    assert_eq!(node.snapshot().reserved_bytes, 0);
}

#[test]
fn publication_enforces_aggregate_retention_before_another_page_or_monitor_tick() {
    let engine = fixture(128, 32, 256 << 10);
    let node = node();
    let clock = Arc::new(Clock::default());
    let first = open(&engine, &node, &clock);
    let second = open(&engine, &node, &clock);
    let third = open(&engine, &node, &clock);
    let base = engine
        .leases
        .entries
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .bytes
        + LEASE_HANDLE_BYTES;
    let old = engine.generation().unwrap().state.collections["docs"].documents["d0000"].clone();
    let delta =
        document_heap(&old, usize::MAX).unwrap() + RETAINED_ENTRY_BYTES + path_bytes(128, 1);
    let mut state = engine.generation().unwrap().state.clone();
    state.limits.atomic.max_snapshot_lease_bytes = base * 3 + delta * 2 - 1;
    install(&engine, state);
    write(&engine, put("d0000", 32));
    assert!(!first.live());
    assert!(second.live() && third.live());
    let entries = engine.leases.entries.lock().unwrap();
    let total: usize = entries
        .values()
        .map(|root| root.bytes + LEASE_HANDLE_BYTES)
        .sum();
    assert_eq!(entries.len(), 2);
    assert!(
        total
            <= engine
                .generation()
                .unwrap()
                .state
                .limits
                .atomic
                .max_snapshot_lease_bytes
    );
    assert_eq!(
        entries[&second.header.lease_id].generation.state.revision,
        1
    );
}

#[test]
fn primary_id_paths_stay_charged_after_temporary_insert_and_delete() {
    let engine = fixture(128, 32, 1 << 20);
    let node = node();
    let clock = Arc::new(Clock::default());
    let lease = open(&engine, &node, &clock);
    write(&engine, put("temporary", 32));
    write(
        &engine,
        Mutation::Delete {
            collection: "docs".into(),
            id: "temporary".into(),
            expected: Precondition::Any,
        },
    );
    let entries = engine.leases.entries.lock().unwrap();
    let root = &entries[&lease.header.lease_id];
    assert_eq!(root.paths["docs"].ids, 2);
    assert!(root.bytes >= root.metadata_bytes + path_bytes(128, 2) * 2);
    assert!(root.handle.live());
    assert_eq!(root.generation.state.revision, 1);
    assert_eq!(
        root.ids
            .document_ids_after("docs", None, 129)
            .unwrap()
            .len(),
        128
    );
}

#[test]
fn metadata_allocation_is_charged_before_opening_and_snapshot_replace_invalidates_handles() {
    let engine = fixture(1, 0, 32 << 10);
    let node = node();
    let clock = Arc::new(Clock::default());
    let lease = open(&engine, &node, &clock);
    let current = engine.generation().unwrap();
    engine.leases.replace(&engine.current, current);
    assert!(!lease.live());
    drop(lease);
    assert_eq!(node.snapshot().reserved_bytes, 0);
    let mut state = engine.generation().unwrap().state.clone();
    state.collections.get_mut("docs").unwrap().definition.schema =
        json!({"type":"object","description":"large schema".repeat(5000)});
    install(&engine, state);
    let result = engine
        .leases
        .open(&engine, &context(), 60_000, clock, 1, &node);
    assert_eq!(result.err().unwrap().code, ErrorCode::ResourceExhausted);
    assert_eq!(node.snapshot().reserved_bytes, 0);
}

#[test]
fn archive_leaf_clones_share_unchanged_large_values_and_manifest_payloads() {
    let engine = fixture(0, 0, 64 << 10);
    let node = node();
    let clock = Arc::new(Clock::default());
    let mut state = engine.generation().unwrap().state.clone();
    let collection = state.collections.get_mut("docs").unwrap();
    for id in ["first", "neighbor"] {
        collection.archived_documents.insert(
            id.into(),
            Arc::new(ArchivedDocument {
                version: 1,
                archive_id: "archive".into(),
                chunk_index: 0,
                document_sha256: "12".repeat(32),
                document_bytes: 128,
                indexed_fields: BTreeMap::from([(
                    "/value".into(),
                    json!(if id == "neighbor" {
                        "x".repeat(256 << 10)
                    } else {
                        "small".into()
                    }),
                )]),
            }),
        );
    }
    let archive = Arc::new(RetainedHistoryArchive {
        storage_destination: "local".into(),
        storage_backup_session: None,
        manifest: HistoryArchiveManifest {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: "archive".into(),
            tenant: "tenant".into(),
            source_incarnation: "incarnation".into(),
            collection: "docs".into(),
            cutoff_revision: 1,
            source_schema_epoch: 1,
            destination: "local".into(),
            document_count: 2,
            chunks: (0..1024)
                .map(|index| ArchiveChunkDescriptor {
                    object_id: format!("object-{index}"),
                    ciphertext_sha256: "56".repeat(32),
                    plaintext_sha256: "78".repeat(32),
                    plaintext_bytes: 128,
                    document_count: 1,
                    first_id: format!("id{index:04}"),
                    last_id: format!("id{index:04}"),
                })
                .collect(),
        },
        manifest_object_id: "object".into(),
        manifest_ciphertext_sha256: "34".repeat(32),
        published_revision: 1,
    });
    let mut first_archive = archive.as_ref().clone();
    first_archive.manifest.chunks = Vec::new();
    state
        .history_archives
        .insert("first-archive".into(), Arc::new(first_archive));
    state
        .history_archives
        .insert("archive".into(), archive.clone());
    install(&engine, state);
    let lease = open(&engine, &node, &clock);
    let mut state = engine.generation().unwrap().state.clone();
    let first = state
        .collections
        .get_mut("docs")
        .unwrap()
        .archived_documents
        .get_mut("first")
        .unwrap();
    Arc::make_mut(first).version = 2;
    Arc::make_mut(state.history_archives.get_mut("first-archive").unwrap()).published_revision = 2;
    state.revision = 2;
    install(&engine, state);
    let entries = engine.leases.entries.lock().unwrap();
    let retained = &entries[&lease.header.lease_id];
    let current = engine.generation().unwrap();
    assert!(lease.live());
    assert!(Arc::ptr_eq(
        &retained.generation.state.collections["docs"].archived_documents["neighbor"],
        &current.state.collections["docs"].archived_documents["neighbor"]
    ));
    assert!(Arc::ptr_eq(
        &retained.generation.state.history_archives["archive"],
        &current.state.history_archives["archive"]
    ));
    assert!(retained.bytes < 64 << 10);
    assert_eq!(
        retained.generation.state.collections["docs"].archived_documents["first"].version,
        1
    );
}
