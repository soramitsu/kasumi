fn pagination_memory_response() -> QueryResponse {
    QueryResponse {
        revision: 7,
        rows: (0..3)
            .map(|id| QueryRow {
                id: format!("row-{id}"),
                version: 7,
                body: json!({"nested": vec![json!({}); 128], "label": "value"}),
                score: None,
            })
            .collect(),
        aggregates: vec![json!({"groups": vec![json!({"count": 1}); 64]})],
        cursor: None,
    }
}

fn pagination_fresh_owner(
    node: &Arc<NodeAdmission>,
    cancellation: &QueryCancellation,
) -> (QueryResultOwner, Arc<WorkFence>, u64) {
    let response = pagination_memory_response();
    let request = query_memory_request();
    let initial = query_input_workspace(&request, 3)
        .unwrap()
        .checked_add(
            kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap(),
        )
        .unwrap();
    let fence = Arc::new(WorkFence::default());
    let mut owner = QueryResultOwner {
        request,
        response: Arc::new(response),
        memory: Some(QueryMemory::empty(
            node.reserve(512, Some(cancellation.clone())).unwrap(),
        )),
        reservation: None,
        page_charge: None,
        _registration: Arc::new(fence.begin(cancellation.clone()).unwrap()),
    };
    owner.memory.as_mut().unwrap().reserve(initial).unwrap();
    (owner, fence, initial)
}

fn pagination_continuation_owner(
    node: &Arc<NodeAdmission>,
    cursor: &Cursor,
    cancellation: &QueryCancellation,
) -> QueryResultOwner {
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let initial = query_input_workspace(&request, 3).unwrap();
    let fence = Arc::new(WorkFence::default());
    let mut owner = QueryResultOwner {
        request,
        response: cursor.response.clone(),
        memory: Some(QueryMemory::empty(
            node.reserve(512, Some(cancellation.clone())).unwrap(),
        )),
        reservation: Some(cursor.reservation.clone()),
        page_charge: None,
        _registration: Arc::new(fence.begin(cancellation.clone()).unwrap()),
    };
    owner.memory.as_mut().unwrap().reserve(initial).unwrap();
    owner
}

#[test]
fn pagination_memory_fresh_clone_admits_full_response_and_page_before_cursor_handoff() {
    let response = pagination_memory_response();
    let initial = query_input_workspace(&query_memory_request(), 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap();
    let page_bytes = kasumi_query::query_response_clone_bytes(&response, 0..1).unwrap();
    // Tiny JSON nodes make wire bytes an insufficient replacement for the
    // actual row/aggregate clone claim used by the service.
    assert!(page_bytes > crate::accounting::encoded_len(&response).unwrap() as u64 * 3);
    let cancellation = QueryCancellation::default();
    let node = query_memory_node(initial + page_bytes + OUTPUT_CHARGE_BYTES);
    let before = node.snapshot();
    let (mut owner, _, observed_initial) = pagination_fresh_owner(&node, &cancellation);
    assert_eq!(observed_initial, initial);
    let admitted = node.snapshot();
    let page = owner.clone_page(0..1, &cancellation).unwrap();
    assert_eq!(page.rows, response.rows[..1]);
    assert_eq!(page.aggregates, response.aggregates);
    assert_eq!(
        owner.memory.as_ref().unwrap().live_bytes(),
        initial + page_bytes
    );
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        initial + page_bytes
    );
    assert_eq!(
        node.snapshot().live_reservations,
        admitted.live_reservations
    );
    assert_eq!(
        node.snapshot().inflight_operations,
        admitted.inflight_operations
    );
    let cursor_charge = owner.cursor_reservation().unwrap();
    assert!(owner.memory.is_none());
    assert!(Arc::ptr_eq(
        owner.reservation.as_ref().unwrap(),
        &cursor_charge
    ));
    drop(page);
    drop(owner);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        initial + page_bytes + OUTPUT_CHARGE_BYTES
    );
    drop(cursor_charge);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);

    let node = query_memory_node(initial + page_bytes - 1);
    let before = node.snapshot();
    let (mut owner, _, _) = pagination_fresh_owner(&node, &cancellation);
    let admitted = node.snapshot();
    assert_eq!(
        owner.clone_page(0..1, &cancellation).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(owner.memory.as_ref().unwrap().live_bytes(), initial);
    assert_eq!(owner.memory.as_ref().unwrap().peak_bytes(), initial);
    assert_eq!(node.snapshot().reserved_bytes, admitted.reserved_bytes);
    assert_eq!(owner.response.as_ref(), &response);
    drop(owner);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
}

#[test]
fn pagination_memory_output_charge_denial_keeps_the_completed_payload_owned() {
    let response = pagination_memory_response();
    let initial = query_input_workspace(&query_memory_request(), 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap();
    let page_bytes = kasumi_query::query_response_clone_bytes(&response, 0..1).unwrap();
    let node = query_memory_node(initial + page_bytes);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, _, _) = pagination_fresh_owner(&node, &cancellation);
    let page = owner.clone_page(0..1, &cancellation).unwrap();
    let admitted = node.snapshot();
    assert_eq!(
        owner.prepare_page_handoff().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert!(owner.reservation.is_none());
    assert_eq!(
        owner.memory.as_ref().unwrap().live_bytes(),
        initial + page_bytes
    );
    assert_eq!(owner.response.as_ref(), &response);
    assert_eq!(page.rows, response.rows[..1]);
    assert_eq!(node.snapshot().reserved_bytes, admitted.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        admitted.live_reservations
    );
    assert_eq!(
        node.snapshot().inflight_operations,
        admitted.inflight_operations
    );
    drop(page);
    drop(owner);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn pagination_memory_concurrent_continuations_use_independent_page_charges() {
    let response = pagination_memory_response();
    let full_bytes = query_input_workspace(&query_memory_request(), 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap()
        + OUTPUT_CHARGE_BYTES;
    let page_bytes = kasumi_query::query_response_clone_bytes(&response, 0..1).unwrap();
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let input_bytes = query_input_workspace(&request, 3).unwrap();
    let node = query_memory_node(full_bytes + input_bytes * 2 + page_bytes * 2 - 1);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, _, _) = pagination_fresh_owner(&node, &cancellation);
    let charge = owner.cursor_reservation().unwrap();
    let cursor = Cursor {
        principal: "owner".into(),
        query_digest: "digest".into(),
        incarnation: "incarnation".into(),
        policy_epoch: 0,
        created: Duration::ZERO,
        ttl: Duration::from_secs(5),
        response: owner.response.clone(),
        reservation: charge,
        offset: 0,
        bytes: crate::accounting::encoded_len(owner.response.as_ref()).unwrap(),
        term: 1,
    };
    drop(owner);
    let mut first = pagination_continuation_owner(&node, &cursor, &cancellation);
    let mut second = pagination_continuation_owner(&node, &cursor, &cancellation);
    let first_page = first.clone_page(0..1, &cancellation).unwrap();
    let admitted = node.snapshot();
    assert_eq!(
        second.clone_page(0..1, &cancellation).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(second.memory.as_ref().unwrap().live_bytes(), input_bytes);
    assert_eq!(second.memory.as_ref().unwrap().peak_bytes(), input_bytes);
    assert_eq!(node.snapshot().reserved_bytes, admitted.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        before.live_reservations + 3
    );
    assert_eq!(
        node.snapshot().inflight_operations,
        before.inflight_operations + 2
    );
    assert!(Arc::ptr_eq(
        first.reservation.as_ref().unwrap(),
        &cursor.reservation
    ));
    assert!(Arc::ptr_eq(
        second.reservation.as_ref().unwrap(),
        &cursor.reservation
    ));
    drop(first_page);
    drop(first);
    let second_page = second.clone_page(0..1, &cancellation).unwrap();
    assert_eq!(second_page.rows, response.rows[..1]);
    assert_eq!(second_page.aggregates, response.aggregates);
    drop(cursor);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        full_bytes + input_bytes + page_bytes
    );
    drop(second_page);
    drop(second);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[tokio::test]
async fn pagination_memory_await_cancellation_and_unwind_drain_payload_before_charge() {
    let node = query_memory_node(1 << 20);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, fence, _) = pagination_fresh_owner(&node, &cancellation);
    let weak = Arc::downgrade(&owner.response);
    let mut pending = Box::pin(async move {
        let page = owner.clone_page(0..1, &cancellation).unwrap();
        std::future::pending::<()>().await;
        drop(page);
        drop(owner);
    });
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert!(node.snapshot().reserved_bytes > before.reserved_bytes);
    fence.seal();
    let mut draining = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(pending);
    draining.await;
    assert!(weak.upgrade().is_none());
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);

    let cancellation = QueryCancellation::default();
    let (mut owner, fence, _) = pagination_fresh_owner(&node, &cancellation);
    let weak = Arc::downgrade(&owner.response);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _page = owner.clone_page(0..1, &cancellation).unwrap();
        panic!("injected pagination release panic");
    }));
    assert!(unwind.is_err());
    fence.drain().await;
    assert!(weak.upgrade().is_none());
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn pagination_memory_completed_pages_release_only_their_operation_slots() {
    let response = pagination_memory_response();
    let initial = query_input_workspace(&query_memory_request(), 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap();
    let page_bytes = kasumi_query::query_response_clone_bytes(&response, 0..1).unwrap();
    let audit_bytes = ((Limits::default().max_batch_bytes + (64 << 10)) * 3) as u64;
    let node = NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            // Enough for the retained full/page output and the same ordinary
            // command allowance that strict release needs; only slots deny it.
            max_inflight_bytes: Some(initial + page_bytes + OUTPUT_CHARGE_BYTES + audit_bytes),
            max_inflight_operations: 1,
            max_reservations: 64,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            ..Default::default()
        })
        .unwrap(),
        8 << 30,
        0,
    )
    .unwrap();
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, _, _) = pagination_fresh_owner(&node, &cancellation);
    let page = owner.clone_page(0..1, &cancellation).unwrap();
    let pending = node.snapshot();
    assert_eq!(pending.inflight_operations, 1);
    assert_eq!(
        node.reserve(audit_bytes, None).err().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    drop(owner.cursor_reservation().unwrap());
    let completed = node.snapshot();
    assert_eq!(completed.inflight_operations, 0);
    assert_eq!(
        completed.reserved_bytes,
        pending.reserved_bytes + OUTPUT_CHARGE_BYTES
    );
    assert_eq!(completed.live_reservations, pending.live_reservations);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        initial + page_bytes + OUTPUT_CHARGE_BYTES
    );
    let audit = node.reserve(audit_bytes, None).unwrap();
    assert_eq!(node.snapshot().inflight_operations, 1);
    assert_eq!(owner.response.as_ref(), &response);
    assert_eq!(page.rows, response.rows[..1]);
    drop(audit);
    let cursor = Cursor {
        principal: "owner".into(),
        query_digest: "digest".into(),
        incarnation: "incarnation".into(),
        policy_epoch: 0,
        created: Duration::ZERO,
        ttl: Duration::from_secs(5),
        response: owner.response.clone(),
        reservation: owner.cursor_reservation().unwrap(),
        offset: 1,
        bytes: crate::accounting::encoded_len(owner.response.as_ref()).unwrap(),
        term: 1,
    };
    drop(page);
    drop(owner);
    let mut continuation = pagination_continuation_owner(&node, &cursor, &cancellation);
    let next_page = continuation.clone_page(1..2, &cancellation).unwrap();
    let pending = node.snapshot();
    continuation.prepare_page_handoff().unwrap();
    let retained = node.snapshot();
    assert_eq!(retained.inflight_operations, 0);
    assert_eq!(
        retained.reserved_bytes,
        pending.reserved_bytes + OUTPUT_CHARGE_BYTES
    );
    assert_eq!(retained.live_reservations, pending.live_reservations);
    assert!(continuation.memory.is_none());
    assert!(!Arc::ptr_eq(
        continuation.page_charge.as_ref().unwrap(),
        &cursor.reservation,
    ));
    // Preparing twice neither allocates another Arc backing nor changes bytes.
    continuation.prepare_page_handoff().unwrap();
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    let audit = node.reserve(1, None).unwrap();
    assert_eq!(node.snapshot().inflight_operations, 1);
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes + 1);
    assert_eq!(next_page.rows, response.rows[1..2]);
    drop(audit);
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    drop(next_page);
    drop(continuation);
    drop(cursor);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    assert_eq!(
        node.snapshot().inflight_operations,
        before.inflight_operations
    );
}

#[test]
fn pagination_memory_continuation_release_error_keeps_its_request_charged() {
    fn reject_page(_output: AdmittedOutput<QueryResponse>) -> Result<()> {
        Err(Error::new(
            ErrorCode::Sealed,
            "injected final release denial",
        ))
    }

    let response = pagination_memory_response();
    let full_bytes = query_input_workspace(&query_memory_request(), 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 0..response.rows.len()).unwrap()
        + OUTPUT_CHARGE_BYTES;
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let page_bytes = query_input_workspace(&request, 3).unwrap()
        + kasumi_query::query_response_clone_bytes(&response, 1..2).unwrap()
        + OUTPUT_CHARGE_BYTES;
    let node = query_memory_node(full_bytes + page_bytes);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut original, _, _) = pagination_fresh_owner(&node, &cancellation);
    let cursor = Cursor {
        principal: "owner".into(),
        query_digest: "digest".into(),
        incarnation: "incarnation".into(),
        policy_epoch: 0,
        created: Duration::ZERO,
        ttl: Duration::from_secs(5),
        response: original.response.clone(),
        reservation: original.cursor_reservation().unwrap(),
        offset: 1,
        bytes: crate::accounting::encoded_len(original.response.as_ref()).unwrap(),
        term: 1,
    };
    drop(original);
    let mut full = pagination_continuation_owner(&node, &cursor, &cancellation);
    let page = full.clone_page(1..2, &cancellation).unwrap();
    full.prepare_page_handoff().unwrap();
    let page_charge = Arc::downgrade(full.page_charge.as_ref().unwrap());
    let retained = node.snapshot();
    assert_eq!(retained.inflight_operations, 0);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        full_bytes + page_bytes
    );
    // Model a final authorization error after constructing the outgoing owner.
    // It drops that output before the still-live query owner and request.
    let denied = reject_page(AdmittedOutput::new(page, full.take_page_charge()));
    assert_eq!(denied.unwrap_err().code, ErrorCode::Sealed);
    assert_eq!(full.request.cursor.as_deref(), Some("old-cursor"));
    assert!(page_charge.upgrade().is_some());
    assert_eq!(node.snapshot().reserved_bytes, retained.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        retained.live_reservations
    );
    drop(full);
    assert!(page_charge.upgrade().is_none());
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), full_bytes);
    drop(cursor);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    assert_eq!(
        node.snapshot().inflight_operations,
        before.inflight_operations
    );
}

#[tokio::test]
async fn pagination_memory_strict_pages_release_the_completed_operation_slot() {
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
    for id in ["a", "b"] {
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch(id))
            .await
            .unwrap();
    }
    let node = fixture.db.admission().clone();
    assert_eq!(node.snapshot().inflight_operations, 0);
    // Keep the fixture's original byte/slot limits. One operation slot remains
    // for the query worker and then its durable strict-read audit proposal.
    let blockers: Vec<_> = (0..AdmissionConfig::default().max_inflight_operations - 1)
        .map(|_| node.reserve(1, None).unwrap())
        .collect();
    assert_eq!(blockers.len(), 63);
    assert_eq!(node.snapshot().inflight_operations, blockers.len());
    for limit in [1, 2] {
        let context = RequestContext {
            request_id: format!("strict-fresh-page-{limit}"),
            ..fixture.context.clone()
        };
        let mut request = query_memory_request();
        request.limit = limit;
        assert!(request.cursor.is_none());
        let (revision, audit_count) = {
            let generation = fixture.db.engine().generation().unwrap();
            (generation.state.revision, generation.state.audits.len())
        };
        let page = fixture.db.query(&context, request).await.unwrap();
        assert_eq!(page.revision, revision);
        assert_eq!(page.rows.len(), limit);
        assert_eq!(page.cursor.is_some(), limit == 1);
        let generation = fixture.db.engine().generation().unwrap();
        assert_eq!(generation.state.audits.len(), audit_count + 1);
        let event = generation.state.audits.back().unwrap();
        assert_eq!(event.action, "read");
        assert_eq!(event.request_id, context.request_id);
        assert_eq!(event.collection.as_deref(), Some("docs"));
        assert_eq!(event.data_revision, Some(page.revision));
        assert_eq!(event.outcome, "authorized_release");
        assert!(generation.state.revision > page.revision);
        assert_eq!(node.snapshot().inflight_operations, blockers.len());
        let next_audit_count = generation.state.audits.len();
        drop(generation);
        if let Some(cursor) = &page.cursor {
            let context = RequestContext {
                request_id: format!("strict-continuation-page-{limit}"),
                ..fixture.context.clone()
            };
            // Keep every normalized field equal to the original query.
            let mut continuation = query_memory_request();
            continuation.limit = limit;
            continuation.cursor = Some(cursor.clone());
            let next = fixture.db.query(&context, continuation).await.unwrap();
            assert_eq!(next.revision, page.revision);
            assert_eq!(next.rows.len(), 1);
            assert!(next.cursor.is_none());
            let generation = fixture.db.engine().generation().unwrap();
            assert_eq!(generation.state.audits.len(), next_audit_count + 1);
            let event = generation.state.audits.back().unwrap();
            assert_eq!(event.action, "read");
            assert_eq!(event.request_id, context.request_id);
            assert_eq!(event.collection.as_deref(), Some("docs"));
            assert_eq!(event.data_revision, Some(next.revision));
            assert_eq!(event.outcome, "authorized_release");
            assert_eq!(node.snapshot().inflight_operations, blockers.len());
        }
    }
    // Snapshot workers likewise finish before their collection's strict audit.
    // All three canonical snapshot outputs must relinquish the operation slot
    // while retaining their admitted payload through that audit.
    let context = RequestContext {
        request_id: "strict-completed-snapshot".into(),
        ..fixture.context.clone()
    };
    let key = DocumentKey {
        collection: "docs".into(),
        id: "a".into(),
    };
    let assert_audit = |revision: u64, previous_count: usize| {
        let generation = fixture.db.engine().generation().unwrap();
        assert_eq!(generation.state.audits.len(), previous_count + 1);
        let event = generation.state.audits.back().unwrap();
        assert_eq!(event.action, "read");
        assert_eq!(event.request_id, context.request_id);
        assert_eq!(event.collection.as_deref(), Some("docs"));
        assert_eq!(event.data_revision, Some(revision));
        assert_eq!(event.outcome, "authorized_release");
        assert_eq!(node.snapshot().inflight_operations, blockers.len());
    };
    let count = fixture.db.engine().generation().unwrap().state.audits.len();
    let snapshot = fixture
        .db
        .read_snapshot(
            &context,
            ReadSnapshotRequest {
                documents: vec![key.clone()],
                queries: vec![],
                time_bounds: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(snapshot.documents[0].document.as_ref().unwrap().id, "a");
    assert_audit(snapshot.revision, count);
    drop(snapshot);
    let lease = fixture
        .db
        .open_snapshot_lease(&context, OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let count = fixture.db.engine().generation().unwrap().state.audits.len();
    let point = fixture
        .db
        .read_snapshot_page(
            &context,
            ReadSnapshotPage {
                lease_id: lease.lease_id.clone(),
                documents: vec![key],
            },
        )
        .await
        .unwrap();
    assert_eq!(point.documents[0].document.as_ref().unwrap().id, "a");
    assert_audit(point.revision, count);
    drop(point);
    let count = fixture.db.engine().generation().unwrap().state.audits.len();
    let scan = fixture
        .db
        .scan_snapshot_page(
            &context,
            ScanSnapshotPage {
                lease_id: lease.lease_id.clone(),
                collection: "docs".into(),
                after_id: None,
                limit: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(scan.documents.len(), 1);
    assert_audit(scan.snapshot.revision, count);
    drop(scan);
    fixture
        .db
        .close_snapshot_lease(&context, &lease.lease_id)
        .await
        .unwrap();
    drop(blockers);
    assert_eq!(node.snapshot().inflight_operations, 0);
    fixture.close().await;
}

fn admitted_read_output_drops_one_charge<T>(node: &NodeAdmission, output: AdmittedOutput<T>) {
    let retained = node.snapshot();
    drop(output);
    let released = node.snapshot();
    assert!(released.reserved_bytes < retained.reserved_bytes);
    assert_eq!(released.live_reservations + 1, retained.live_reservations);
    assert_eq!(released.inflight_operations, retained.inflight_operations);
}

#[tokio::test]
async fn pagination_memory_public_read_outputs_outlive_shutdown_and_release_independently() {
    let fixture = CredentialFixture::new().await;
    for id in ["a", "b"] {
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch(id))
            .await
            .unwrap();
    }
    let node = fixture.db.admission().clone();
    let mut request = query_memory_request();
    let first = fixture
        .db
        .query(&fixture.context, request.clone())
        .await
        .unwrap();
    request.cursor = first.cursor.clone();
    assert!(request.cursor.is_some());
    let last = fixture.db.query(&fixture.context, request).await.unwrap();
    assert!(last.cursor.is_none());
    let key = DocumentKey {
        collection: "docs".into(),
        id: "a".into(),
    };
    let mut query = query_memory_request();
    query.limit = 2;
    let snapshot = fixture
        .db
        .read_snapshot(
            &fixture.context,
            ReadSnapshotRequest {
                documents: vec![key.clone()],
                queries: vec![query],
                time_bounds: None,
            },
        )
        .await
        .unwrap();
    let lease = fixture
        .db
        .open_snapshot_lease(&fixture.context, OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let point = fixture
        .db
        .read_snapshot_page(
            &fixture.context,
            ReadSnapshotPage {
                lease_id: lease.lease_id.clone(),
                documents: vec![key],
            },
        )
        .await
        .unwrap();
    let scan = fixture
        .db
        .scan_snapshot_page(
            &fixture.context,
            ScanSnapshotPage {
                lease_id: lease.lease_id.clone(),
                collection: "docs".into(),
                after_id: None,
                limit: 1,
            },
        )
        .await
        .unwrap();
    fixture
        .db
        .close_snapshot_lease(&fixture.context, &lease.lease_id)
        .await
        .unwrap();
    assert_eq!(node.snapshot().inflight_operations, 0);
    // Returned plaintext holds only admission, not a work registration or a
    // storage owner: shutdown completes while all five results remain alive.
    fixture.close().await;
    assert_eq!(first.rows.len(), 1);
    assert_eq!(last.rows.len(), 1);
    assert_eq!(
        snapshot.documents[0].document.as_ref().unwrap().body,
        json!({"value":7})
    );
    assert_eq!(snapshot.queries[0].rows.len(), 2);
    assert_eq!(point.documents[0].document.as_ref().unwrap().id, "a");
    assert_eq!(scan.documents.len(), 1);
    assert!(scan.next_after_id.is_some());
    // The old cursor was consumed, so its first-page charge and the independent
    // continuation, coherent snapshot, point page and scan charges each drain.
    admitted_read_output_drops_one_charge(&node, first);
    admitted_read_output_drops_one_charge(&node, last);
    admitted_read_output_drops_one_charge(&node, snapshot);
    admitted_read_output_drops_one_charge(&node, point);
    admitted_read_output_drops_one_charge(&node, scan);
}
