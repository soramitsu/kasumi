fn feed_memory_fixture() -> (Arc<crate::Generation>, RequestContext, ReadChangeFeed) {
    let mut generation = query_memory_generation();
    let document = Arc::new(Document {
        id: "a".into(),
        version: 7,
        body: serde_json::Value::Object(
            (0..256).map(|i| (format!("field-{i}"), json!(i))).collect(),
        ),
    });
    let records = vec![ChangeRecord {
        collection: "docs".into(),
        id: "a".into(),
        document: Some(document),
    }];
    let record_bytes = records
        .iter()
        .try_fold(0usize, |bytes, record| {
            bytes.checked_add(crate::accounting::encoded_len(record).unwrap())
        })
        .unwrap();
    let commit = Arc::new(ChangeCommit {
        revision: 7,
        first_sequence: 1,
        records,
        record_bytes,
    });
    let encoded_commit_bytes = crate::change_feed_state::entry_bytes(1, &commit).unwrap();
    Arc::get_mut(&mut generation).unwrap().state.change_feed = ChangeFeedState {
        next_sequence: 2,
        commits: [(1u64, commit)].into_iter().collect(),
        event_count: 1,
        encoded_commit_bytes,
    };
    crate::change_feed_state::validate_restored(&generation.state).unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: generation.state.tenant.clone(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read]),
        request_id: "feed-memory".into(),
    };
    let request = ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: ChangeFeedStart::Beginning,
        limit: 1,
    };
    (generation, context, request)
}

#[test]
fn feed_memory_after_image_denial_preserves_admitted_prefix_and_drains() {
    let (generation, context, request) = feed_memory_fixture();
    let record = &generation.state.change_feed.commits[&1].records[0];
    let page_bytes = kasumi_query::change_feed_page_workspace_bytes(
        &context.tenant,
        &generation.state.incarnation,
        &context.principal,
        &request.collections,
        1,
    )
    .unwrap();
    let event_bytes = kasumi_query::change_event_clone_bytes(record).unwrap();
    assert!(event_bytes > crate::accounting::encoded_len(record).unwrap() as u64 * 3);
    let node = query_memory_node(page_bytes + event_bytes - 1);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let mut memory = QueryMemory::empty(node.reserve(512, Some(cancellation.clone())).unwrap());
    assert_eq!(
        change_feed::build_change_feed_page(
            &generation.state,
            &context,
            &request,
            &cancellation,
            &mut memory,
        )
        .unwrap_err()
        .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(memory.live_bytes(), 0);
    assert_eq!(memory.peak_bytes(), page_bytes);
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), page_bytes);
    assert_eq!(record.document.as_ref().unwrap().body["field-255"], 255);
    drop(memory);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn feed_memory_owned_after_image_outlives_source_and_final_owner_drains() {
    let (generation, context, request) = feed_memory_fixture();
    let source = Arc::downgrade(
        generation.state.change_feed.commits[&1].records[0]
            .document
            .as_ref()
            .unwrap(),
    );
    let node = query_memory_node(2 << 20);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let mut memory = QueryMemory::empty(node.reserve(512, Some(cancellation.clone())).unwrap());
    let page = change_feed::build_change_feed_page(
        &generation.state,
        &context,
        &request,
        &cancellation,
        &mut memory,
    )
    .unwrap();
    memory.reserve(OUTPUT_CHARGE_BYTES).unwrap();
    let mut reservation = memory.into_workspace();
    reservation.retain_workspace();
    let output = AdmittedOutput::new(page, Arc::new(reservation));
    drop(generation);
    assert!(
        source.upgrade().is_none(),
        "public after-image must not retain an internal Arc"
    );
    cancellation.cancel();
    let ChangeFeedPage::Events { events, .. } = output.as_ref() else {
        panic!("expected events");
    };
    assert_eq!(events[0].document.as_ref().unwrap().body["field-255"], 255);
    assert_eq!(
        node.snapshot().inflight_operations,
        before.inflight_operations
    );
    assert!(node.snapshot().reserved_bytes > before.reserved_bytes);
    drop(output);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[tokio::test]
async fn feed_memory_public_strict_page_releases_slot_and_outlives_shutdown() {
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
    let node = fixture.db.admission().clone();
    let blockers: Vec<_> = (0..AdmissionConfig::default().max_inflight_operations - 1)
        .map(|_| node.reserve(1, None).unwrap())
        .collect();
    let (revision, audit_count) = {
        let generation = fixture.db.engine().generation().unwrap();
        (generation.state.revision, generation.state.audits.len())
    };
    let output = fixture
        .db
        .read_change_feed(
            &fixture.context,
            ReadChangeFeed {
                collections: BTreeSet::from(["docs".into()]),
                start: ChangeFeedStart::Beginning,
                limit: 1,
            },
        )
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, .. } = output.as_ref() else {
        panic!("expected events");
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].document.as_ref().unwrap().body["value"], 7);
    let generation = fixture.db.engine().generation().unwrap();
    assert_eq!(generation.state.audits.len(), audit_count + 1);
    let event = generation.state.audits.back().unwrap();
    assert_eq!(event.action, "change_feed");
    assert_eq!(event.data_revision, Some(revision));
    assert_eq!(event.outcome, "authorized_release");
    assert_eq!(node.snapshot().inflight_operations, blockers.len());
    drop(generation);
    drop(blockers);
    fixture.close().await;
    assert_eq!(events[0].document.as_ref().unwrap().body["value"], 7);
    let held = node.snapshot();
    drop(output);
    assert_eq!(
        node.snapshot().live_reservations + 1,
        held.live_reservations
    );
    assert!(node.snapshot().reserved_bytes < held.reserved_bytes);
}

#[tokio::test]
async fn feed_memory_cancelled_public_read_retains_admitted_audit_until_completion() {
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
    let request = || ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: ChangeFeedStart::Beginning,
        limit: 1,
    };
    // Warm this exact source and the real strict proposal path before measuring
    // the next request. No cursor or output from warmup remains alive.
    drop(
        fixture
            .db
            .read_change_feed(&fixture.context, request())
            .await
            .unwrap(),
    );
    let node = fixture.db.admission().clone();
    fixture.db.proposals.prepare(&node).unwrap();
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    let baseline_bytes = without_cache(&fixture);
    assert_eq!(baseline.inflight_operations, 0);
    assert_eq!(operation_bytes(&baseline), 0);
    let permits = fixture.db.query_slots.available_permits();
    let (revision, audit_count) = {
        let generation = fixture.db.engine().generation().unwrap();
        (generation.state.revision, generation.state.audits.len())
    };
    let gate = fixture.db.proposal_gate.lock().await;
    let mut pending = Box::pin(fixture.db.read_change_feed(&fixture.context, request()));
    // This observes an actual newly owned proposal child, not the first Pending
    // poll. The feed page must already exist before its strict audit is queued.
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
        "only the strict audit is still executing"
    );
    assert_eq!(fixture.db.query_slots.available_permits(), permits - 1);
    let audit_bytes = operation_bytes(&held);
    assert!(audit_bytes > 0);
    assert!(without_cache(&fixture).1 > baseline_bytes.1);

    drop(pending);
    let cancelled = node.snapshot();
    assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
    assert_eq!(fixture.db.query_slots.available_permits(), permits);
    assert_eq!(fixture.db.fixture_running_proposals(), 1);
    assert_eq!(cancelled.inflight_operations, 1);
    assert_eq!(operation_bytes(&cancelled), audit_bytes);
    assert_eq!(
        cancelled.live_reservations.checked_add(2).unwrap(),
        held.live_reservations,
        "cancelled feed source and its boxed release future retire; audit child does not"
    );
    assert_eq!(without_cache(&fixture).1, baseline_bytes.1);
    assert_eq!(
        without_cache(&fixture).0,
        baseline_bytes.0.checked_add(audit_bytes).unwrap(),
        "exactly the admitted audit's bytes remain beyond baseline"
    );
    let mut draining = Box::pin(fixture.db.work.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending(),
        "cancelled waiter must not complete the admitted child"
    );
    drop(quiescent);
    drop(gate);
    draining.await;
    // Explicitly acknowledge the real worker and retire the fixed registry's
    // separately measured metadata reservation; no sleep-based reaping.
    fixture.db.proposals.drain().await.unwrap();
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    assert_eq!(fixture.db.fixture_running_proposals(), 0);
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert_eq!(fixture.db.query_slots.available_permits(), permits);
    assert_eq!(
        without_cache(&fixture).0,
        baseline_bytes
            .0
            .checked_sub(Database::fixture_proposal_metadata_bytes().unwrap())
            .unwrap(),
        "source, release future, audit child and acknowledged registry all retire exactly"
    );
    let generation = fixture.db.engine().generation().unwrap();
    assert_eq!(generation.state.audits.len(), audit_count + 1);
    let event = generation.state.audits.back().unwrap();
    assert_eq!(event.action, "change_feed");
    assert_eq!(event.data_revision, Some(revision));
    assert_eq!(event.outcome, "authorized_release");
    drop(generation);
    drop(quiescent);
    fixture.close().await;
}
