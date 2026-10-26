fn point_memory_document() -> Arc<Document> {
    Arc::new(Document {
        id: "point".into(),
        version: 7,
        body: serde_json::Value::Object(
            (0..256).map(|i| (format!("field-{i}"), json!(i))).collect(),
        ),
    })
}

#[test]
fn point_memory_clone_denial_and_cancellation_keep_source_and_charge_together() {
    let document = point_memory_document();
    let quote = kasumi_query::document_clone_bytes(&document).unwrap();
    assert!(quote > crate::accounting::encoded_len(document.as_ref()).unwrap() as u64 * 3);
    let node = query_memory_node(quote + OUTPUT_CHARGE_BYTES - 1);
    let baseline = node.snapshot();
    let cancellation = QueryCancellation::default();
    let mut read =
        point_read::PointRead::new(node.reserve(64, Some(cancellation.clone())).unwrap());
    read.document = Some(OwnedDocument::Pending(document.clone()));
    let held = node.snapshot();
    let references = Arc::strong_count(&document);
    assert_eq!(read.owned().unwrap_err().code, ErrorCode::ResourceExhausted);
    assert_eq!(Arc::strong_count(&document), references);
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    cancellation.cancel();
    assert_eq!(
        read.shared().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    assert_eq!(read.document.as_ref().unwrap().body["field-255"], 255);
    drop(read);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn point_memory_shared_clones_keep_one_charge_until_cross_thread_last_drop() {
    let node = query_memory_node(2 << 20);
    let baseline = node.snapshot();
    let document = point_memory_document();
    let weak = Arc::downgrade(&document);
    let mut read = point_read::PointRead::new(node.reserve(64, None).unwrap());
    read.document = Some(OwnedDocument::Pending(document.clone()));
    let shared = read.shared().unwrap();
    assert!(std::ptr::eq(shared.as_ref(), document.as_ref()));
    let held = node.snapshot();
    let last = shared.clone();
    assert!(std::ptr::eq(shared.as_ref(), last.as_ref()));
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, held.live_reservations);
    assert_eq!(held.inflight_operations, baseline.inflight_operations);
    drop((read, document, shared));
    assert!(weak.upgrade().is_some());
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    std::thread::spawn(move || {
        assert_eq!(last.body["field-255"], 255);
        drop(last);
    })
    .join()
    .unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn point_memory_small_rows_do_not_retain_the_tenant_document_limit_per_reader() {
    const READERS: usize = 32;
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("small"))
        .await
        .unwrap();
    let limit = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .limits
        .max_document_bytes;
    assert_eq!(limit, 1 << 20);
    // Warm the selected native pages before comparing concurrent output grants.
    drop(
        fixture
            .db
            .get(&fixture.context, "docs", "small")
            .await
            .unwrap(),
    );
    let node = fixture.db.admission().clone();
    let before = {
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        node.snapshot()
    };
    let start = Arc::new(tokio::sync::Barrier::new(READERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..READERS {
        let db = fixture.db.clone();
        let context = fixture.context.clone();
        let start = start.clone();
        tasks.spawn(async move {
            start.wait().await;
            db.get(&context, "docs", "small").await.unwrap().unwrap()
        });
    }
    start.wait().await;
    let mut outputs = Vec::with_capacity(READERS);
    while let Some(joined) = tasks.join_next().await {
        outputs.push(joined.unwrap());
    }
    assert_eq!(outputs.len(), READERS);
    assert!(
        outputs
            .iter()
            .all(|document| document.body == json!({"value": 7}))
    );
    // Reap completed audit jobs and pause maintenance so only these outputs
    // change the ledger between the held and released census.
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let held = node.snapshot();
    assert_eq!(held.inflight_operations, before.inflight_operations);
    assert!(
        held.reserved_bytes.saturating_sub(before.reserved_bytes) < READERS as u64 * (64 << 10),
        "small outputs retained the 1 MiB tenant maximum instead of actual cloned data: before={before:?}, held={held:?}"
    );
    drop(outputs);
    let released = node.snapshot();
    assert!(released.reserved_bytes < held.reserved_bytes);
    assert_eq!(released.live_reservations + READERS, held.live_reservations);
    drop(quiescent);
    fixture.close().await;
}

#[tokio::test]
async fn point_memory_public_hot_outputs_release_strict_slots_and_outlive_shutdown() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("a"))
        .await
        .unwrap();
    let generation = fixture.db.engine().generation().unwrap();
    let weak_generation = Arc::downgrade(&generation);
    let earlier = fixture
        .db
        .get_shared(&fixture.context, "docs", "a")
        .await
        .unwrap()
        .expect("document exists");
    let stored = generation.state.collections["docs"].documents["a"]
        .stored()
        .unwrap();
    assert_eq!(earlier.id, stored.id);
    assert_eq!(earlier.version, stored.version);
    assert_eq!(earlier.body, json!({"value": 7}));
    let mut definition = generation.state.collections["docs"].definition.clone();
    definition.strict_read_audit = true;
    drop(generation);
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::ReplaceCollection(definition),
        )
        .await
        .unwrap();
    assert!(
        weak_generation.upgrade().is_none(),
        "a hot handle must not pin its complete Generation"
    );
    let node = fixture.db.admission().clone();
    let blockers: Vec<_> = (0..AdmissionConfig::default().max_inflight_operations - 1)
        .map(|_| node.reserve(1, None).unwrap())
        .collect();
    let (revision, audit_count) = {
        let generation = fixture.db.engine().generation().unwrap();
        (generation.state.revision, generation.state.audits.len())
    };
    let owned = fixture
        .db
        .get(&fixture.context, "docs", "a")
        .await
        .unwrap()
        .expect("document exists");
    {
        let generation = fixture.db.engine().generation().unwrap();
        let event = generation.state.audits.back().unwrap();
        assert_eq!(event.data_revision, Some(revision));
        assert_eq!(event.action, "read");
        assert_eq!(event.outcome, "authorized_release");
    }
    let shared = fixture
        .db
        .get_shared(&fixture.context, "docs", "a")
        .await
        .unwrap()
        .expect("document exists");
    assert_eq!(
        fixture.db.engine().generation().unwrap().state.audits.len(),
        audit_count + 2
    );
    assert_eq!(node.snapshot().inflight_operations, blockers.len());
    let clone = shared.clone();
    drop((blockers, earlier, shared));
    fixture.close().await;
    assert_eq!(owned.body["value"], 7);
    assert_eq!(clone.body["value"], 7);
    let held = node.snapshot();
    drop(owned);
    let shared_only = node.snapshot();
    assert_eq!(shared_only.live_reservations + 1, held.live_reservations);
    assert!(shared_only.reserved_bytes < held.reserved_bytes);
    drop(clone);
    assert_eq!(
        node.snapshot().live_reservations + 1,
        shared_only.live_reservations
    );
    assert!(node.snapshot().reserved_bytes < shared_only.reserved_bytes);
}

#[tokio::test]
async fn point_memory_cold_shared_clone_keeps_archive_charge_after_shutdown() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "history".into(),
                write_mode: CollectionWriteMode::AppendOnly,
                retention_class: CollectionRetentionClass::ArchivableHistory,
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut batch = credential_batch("cold");
    let Mutation::Put {
        collection, body, ..
    } = &mut batch.operations[0]
    else {
        unreachable!()
    };
    *collection = "history".into();
    *body = json!({"text":"archived point ".repeat(1024)});
    let version = fixture
        .db
        .mutate(fixture.context.clone(), batch)
        .await
        .unwrap()
        .revision;
    fixture
        .db
        .install_archive_destination(
            "cold".into(),
            Arc::new(
                kasumi_store::FilesystemBackupDestination::new(
                    fixture._directory.path().join("persistent/point-history"),
                    16 << 20,
                    fixture.storage.persistent.clone(),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    fixture
        .db
        .archive_history(
            fixture.context.clone(),
            ArchiveHistory {
                archive_id: "point-archive".into(),
                collection: "history".into(),
                cutoff_revision: version,
                destination: "cold".into(),
            },
        )
        .await
        .unwrap();
    assert!(
        fixture.db.engine().generation().unwrap().state.collections["history"]
            .documents
            .is_empty()
    );
    let node = fixture.db.admission().clone();
    let shared = fixture
        .db
        .get_shared(&fixture.context, "history", "cold")
        .await
        .unwrap()
        .expect("document exists");
    let last = shared.clone();
    assert!(std::ptr::eq(shared.as_ref(), last.as_ref()));
    assert_eq!(shared.version, version);
    fixture.close().await;
    let held = node.snapshot();
    drop(shared);
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, held.live_reservations);
    assert_eq!(
        last.body["text"].as_str().unwrap().len(),
        "archived point ".len() * 1024
    );
    drop(last);
    let released = node.snapshot();
    assert_eq!(
        released.live_reservations + 2,
        held.live_reservations,
        "the point owner and decoded archive chunk retire only at final handle disposal"
    );
    assert!(released.reserved_bytes < held.reserved_bytes);
    assert_eq!(released.inflight_operations, 0);
}

#[test]
fn point_memory_shared_owner_backing_denial_leaves_selected_source_owned() {
    let document = point_memory_document();
    let pilot = query_memory_node(2 << 20);
    let mut read = point_read::PointRead::new(pilot.reserve(64, None).unwrap());
    read.document = Some(OwnedDocument::Pending(document.clone()));
    let output = read.shared().unwrap();
    let required = crate::test_utils::reserved_payload_bytes(&pilot);
    assert!(required > 64);
    drop((output, read));
    let node = query_memory_node(required - 1);
    let baseline = node.snapshot();
    let mut read = point_read::PointRead::new(node.reserve(64, None).unwrap());
    read.document = Some(OwnedDocument::Pending(document.clone()));
    let held = node.snapshot();
    assert_eq!(
        read.shared().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert!(std::ptr::eq(
        read.document.as_ref().unwrap().as_ref(),
        document.as_ref()
    ));
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, held.live_reservations);
    drop(read);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn point_memory_cancelled_public_outputs_retain_admitted_audit_until_completion() {
    fn without_cache(fixture: &CredentialFixture) -> (u64, u64) {
        let cache = fixture.node.cache_stats().unwrap();
        let cache_charge = cache
            .admitted_credit_bytes
            .checked_add(cache.provider_overhead_bytes)
            .unwrap();
        let usage = fixture.db.admission().snapshot();
        (
            usage.reserved_bytes.checked_sub(cache_charge).unwrap(),
            usage
                .resident_reserved_bytes
                .checked_sub(cache_charge)
                .unwrap(),
        )
    }
    fn operation_bytes(usage: &crate::admission::AdmissionSnapshot) -> u64 {
        usage
            .reserved_bytes
            .checked_sub(usage.bookkeeping_bytes)
            .unwrap()
            .checked_sub(usage.resident_reserved_bytes)
            .unwrap()
    }
    for shared in [false, true] {
        let fixture = CredentialFixture::new().await;
        let mut definition = fixture.db.engine().generation().unwrap().state.collections["docs"]
            .definition
            .clone();
        definition.strict_read_audit = true;
        fixture
            .db
            .administer(
                fixture.context.clone(),
                Operation::ReplaceCollection(definition),
            )
            .await
            .unwrap();
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch("a"))
            .await
            .unwrap();
        // Warm this exact public point variant and its actual strict proposal
        // path. Neither a result nor a cursor survives into the isolated census.
        if shared {
            drop(
                fixture
                    .db
                    .get_shared(&fixture.context, "docs", "a")
                    .await
                    .unwrap()
                    .expect("document exists"),
            );
        } else {
            drop(
                fixture
                    .db
                    .get(&fixture.context, "docs", "a")
                    .await
                    .unwrap()
                    .expect("document exists"),
            );
        }
        let node = fixture.db.admission().clone();
        fixture.db.proposals.prepare(&node).unwrap();
        let quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let baseline = node.snapshot();
        let baseline_bytes = without_cache(&fixture);
        assert_eq!(baseline.inflight_operations, 0);
        assert_eq!(operation_bytes(&baseline), 0);
        let (revision, audit_count) = {
            let generation = fixture.db.engine().generation().unwrap();
            (generation.state.revision, generation.state.audits.len())
        };
        let gate = fixture.db.proposal_gate.lock().await;
        let mut pending = Box::pin(async {
            if shared {
                drop(fixture.db.get_shared(&fixture.context, "docs", "a").await?);
            } else {
                drop(fixture.db.get(&fixture.context, "docs", "a").await?);
            }
            Ok::<(), Error>(())
        });
        // Observe the newly registered strict audit child. The selected point
        // output is already fully admitted before submit reaches this boundary.
        fixture
            .db
            .proposals
            .wait_for_admission(pending.as_mut())
            .await;
        let held = node.snapshot();
        let held_cache = fixture.node.cache_stats().unwrap();
        assert_eq!(fixture.db.fixture_running_proposals(), 1);
        assert_eq!(
            held.inflight_operations, 1,
            "only the point read's audit is executing"
        );
        let audit_bytes = operation_bytes(&held);
        assert!(audit_bytes > 0);
        assert!(without_cache(&fixture).1 > baseline_bytes.1);

        drop(pending);
        let cancelled = node.snapshot();
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(fixture.db.fixture_running_proposals(), 1);
        assert_eq!(cancelled.inflight_operations, 1);
        assert_eq!(operation_bytes(&cancelled), audit_bytes);
        assert_eq!(
            cancelled
                .live_reservations
                .checked_add(if shared { 4 } else { 3 })
                .unwrap(),
            held.live_reservations,
            "point workspace, any shared native body and two boxed release futures retire, while the audit child remains"
        );
        assert_eq!(without_cache(&fixture).1, baseline_bytes.1);
        assert_eq!(
            without_cache(&fixture).0,
            baseline_bytes.0.checked_add(audit_bytes).unwrap(),
            "only the admitted audit's bytes remain beyond baseline"
        );
        let mut draining = Box::pin(fixture.db.work.drain());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
                .await
                .is_pending(),
            "cancelled point waiter must not complete its admitted child"
        );
        drop(quiescent);
        drop(gate);
        draining.await;
        // Join/acknowledge the original child and retire its fixed registry
        // budget, independently of the now-destroyed read waiter.
        fixture.db.proposals.drain().await.unwrap();
        let quiescent = fixture.audit.quiescent_jobs_for_test().await;
        assert_eq!(fixture.db.fixture_running_proposals(), 0);
        assert_eq!(node.snapshot().inflight_operations, 0);
        assert_eq!(
            without_cache(&fixture).0,
            baseline_bytes
                .0
                .checked_sub(Database::fixture_proposal_metadata_bytes().unwrap())
                .unwrap(),
            "point output, both release futures, audit child and registry retire exactly"
        );
        let generation = fixture.db.engine().generation().unwrap();
        assert_eq!(generation.state.audits.len(), audit_count + 1);
        let event = generation.state.audits.back().unwrap();
        assert_eq!(event.action, "read");
        assert_eq!(event.data_revision, Some(revision));
        assert_eq!(event.outcome, "authorized_release");
        drop(generation);
        drop(quiescent);
        fixture.close().await;
    }
}

#[tokio::test]
async fn point_memory_native_worker_keeps_source_and_charge_after_cancellation() {
    struct PausedNativeDocument {
        original: Arc<dyn DocumentResolver>,
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        released: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl DocumentResolver for PausedNativeDocument {
        fn load(&self, descriptor: &StoredDocument) -> anyhow::Result<SharedDocument> {
            let document = self.original.load(descriptor)?;
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
                // Bounds the old inline implementation independently of this
                // current-thread Tokio runtime, which it would otherwise block.
                self.released
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| anyhow::anyhow!("native point pause expired"))?;
            }
            Ok(document)
        }
    }
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("point"))
        .await
        .unwrap();
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let mut selected = fixture.db.engine().generation().unwrap().lease_view();
    let slot = selected.state.collections["docs"].documents["point"].clone();
    assert!(matches!(slot.as_ref(), DocumentSlot::Stored(_)));
    let original = selected.document_sources.take().unwrap();
    assert!(
        selected
            .document_sources
            .set(Arc::new(PausedNativeDocument {
                original,
                entered: Mutex::new(Some(entered)),
                released: Mutex::new(released),
            }))
            .is_ok()
    );
    let selected = Arc::new(selected);
    let selected_owner = Arc::downgrade(&selected);
    let node = fixture.db.admission().clone();
    let baseline_decode = node
        .snapshot()
        .resident_reserved_bytes_by_origin
        .document_source;
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let mut read =
        point_read::PointRead::new(node.reserve(4096, Some(cancellation.clone())).unwrap());
    read.generation = Some(selected);
    read.registration = Some(Arc::new(fence.begin(cancellation.clone()).unwrap()));
    let registration = Arc::downgrade(read.registration.as_ref().unwrap());
    let held = fixture
        .db
        .query_slots
        .clone()
        .acquire_many_owned(3)
        .await
        .unwrap();
    let permit = fixture
        .db
        .query_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let waiter = tokio::spawn(async move {
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        read.read_native(slot, permit, &cancellation, point_read::PointRead::owned)
            .await
            .map(|_| ())
    });
    tokio::time::timeout(Duration::from_secs(2), entry)
        .await
        .expect("native point worker must yield the async runtime")
        .unwrap();
    assert!(!waiter.is_finished());
    tokio::time::sleep(Duration::from_millis(1)).await;
    let charged = node
        .snapshot()
        .resident_reserved_bytes_by_origin
        .document_source;
    assert!(charged > baseline_decode);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(fixture.db.query_slots.available_permits(), 0);
    assert!(selected_owner.upgrade().is_some());
    assert!(registration.upgrade().is_some());
    assert_eq!(
        node.snapshot()
            .resident_reserved_bytes_by_origin
            .document_source,
        charged
    );
    let mut draining = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        draining.await;
        while selected_owner.upgrade().is_some()
            || registration.upgrade().is_some()
            || fixture.db.query_slots.available_permits() != 1
            || node
                .snapshot()
                .resident_reserved_bytes_by_origin
                .document_source
                != baseline_decode
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(held);
    assert_eq!(fixture.db.query_slots.available_permits(), 4);
    fixture.close().await;
}

#[tokio::test]
async fn point_memory_queued_request_takes_no_active_slot_before_worker_admission() {
    let fixture = CredentialFixture::new().await;
    let node = fixture.db.admission().clone();
    let held = fixture
        .db
        .query_slots
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    let blockers: Vec<_> = (0..node.policy().max_inflight_operations)
        .map(|_| node.reserve(1, None).unwrap())
        .collect();
    let baseline = node.snapshot();
    let mut waiting = Box::pin(fixture.db.get(&fixture.context, "docs", "absent"));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let queued = node.snapshot();
    assert_eq!(queued.inflight_operations, baseline.inflight_operations);
    assert_eq!(queued.live_reservations, baseline.live_reservations + 1);
    assert!(queued.reserved_bytes > baseline.reserved_bytes);
    drop(waiting);
    assert_eq!(
        node.snapshot().inflight_operations,
        baseline.inflight_operations
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    drop(blockers);
    drop(held);
    fixture.close().await;
}

#[tokio::test]
async fn point_memory_queued_wait_does_not_consume_native_read_timeout() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("queued"))
        .await
        .unwrap();
    let held = fixture
        .db
        .query_slots
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    let mut waiting = Box::pin(fixture.db.get(&fixture.context, "docs", "queued"));
    assert!(
        tokio::time::timeout(
            kasumi_store::NATIVE_READ_TIMEOUT + Duration::from_millis(50),
            waiting.as_mut(),
        )
        .await
        .is_err(),
        "queued point read inherited the native operation deadline"
    );
    assert_eq!(fixture.db.query_slots.available_permits(), 0);
    drop(held);
    let document = tokio::time::timeout(kasumi_store::NATIVE_READ_TIMEOUT, waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(document.body, json!({"value": 7}));
    drop(document);
    assert_eq!(fixture.db.query_slots.available_permits(), 4);
    fixture.close().await;
}
