fn pagination_memory_rows() -> PinnedRows {
    let rows: Vec<_> = (0..3)
        .map(|id| PinnedRow {
            document: Arc::new(Document {
                id: format!("row-{id}"),
                version: 7,
                body: json!({"nested": vec![json!({}); 128], "label": "value"}),
            }),
            score: None,
        })
        .collect();
    let bytes = kasumi_query::vec_bytes::<PinnedRow>(rows.len()).unwrap() as usize
        + rows
            .iter()
            .map(|row| crate::retained_document_bytes(&row.document).unwrap())
            .sum::<usize>();
    PinnedRows { rows, bytes }
}

fn pagination_page(rows: &PinnedRows, range: std::ops::Range<usize>) -> QueryResponse {
    QueryResponse {
        revision: 7,
        rows: rows.rows[range]
            .iter()
            .map(|row| QueryRow {
                id: row.document.id.clone(),
                version: row.document.version,
                body: row.document.body.clone(),
                score: row.score,
            })
            .collect(),
        aggregates: vec![],
        cursor: None,
    }
}

/// What copying these rows into a page admits.
fn pagination_page_bytes(rows: &PinnedRows, range: std::ops::Range<usize>) -> u64 {
    let page = pagination_page(rows, range);
    kasumi_query::query_response_clone_bytes(&page, 0..page.rows.len()).unwrap()
}

/// What pinning these rows for a cursor admits.
fn pagination_pin_bytes(rows: &PinnedRows) -> u64 {
    rows.bytes as u64
}

/// A fresh query's output: its request, first page and the pinned rows after it.
fn pagination_fresh_owner(
    node: &Arc<NodeAdmission>,
    cancellation: &QueryCancellation,
) -> (QueryResultOwner, QueryResponse, Arc<WorkFence>, u64) {
    let rows = pagination_memory_rows();
    let request = query_memory_request();
    let page = pagination_page(&rows, 0..1);
    let initial = query_input_workspace(&request, 3).unwrap()
        + pagination_page_bytes(&rows, 0..1)
        + pagination_pin_bytes(&rows);
    let fence = Arc::new(WorkFence::default());
    let mut owner = QueryResultOwner {
        request,
        rows: Arc::new(rows),
        memory: Some(QueryMemory::empty(
            node.reserve(512, Some(cancellation.clone())).unwrap(),
        )),
        reservation: None,
        page_charge: None,
        _registration: Arc::new(fence.begin(cancellation.clone()).unwrap()),
    };
    owner.memory.as_mut().unwrap().reserve(initial).unwrap();
    (owner, page, fence, initial)
}

fn pagination_cursor(owner: &mut QueryResultOwner, offset: usize) -> Cursor {
    Cursor {
        principal: "owner".into(),
        query_digest: "digest".into(),
        incarnation: "incarnation".into(),
        policy_epoch: 0,
        created: Duration::ZERO,
        ttl: Duration::from_secs(5),
        rows: owner.rows.clone(),
        revision: 7,
        reservation: owner.cursor_reservation().unwrap(),
        offset,
        term: 1,
    }
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
        rows: cursor.rows.clone(),
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
fn pagination_memory_continuation_copy_admits_its_page_before_cursor_handoff() {
    let rows = pagination_memory_rows();
    let page_bytes = pagination_page_bytes(&rows, 1..2);
    // Tiny JSON nodes make wire bytes an insufficient replacement for the
    // actual row clone claim used by the service.
    assert!(
        page_bytes
            > crate::accounting::encoded_len(&pagination_page(&rows, 1..2)).unwrap() as u64 * 3
    );
    // Pins are charged as whole documents, never as wire bytes.
    assert!(rows.bytes > crate::accounting::encoded_len(&pagination_page(&rows, 0..3)).unwrap());
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let input = query_input_workspace(&request, 3).unwrap();
    let cancellation = QueryCancellation::default();
    let node = query_memory_node(1 << 20);
    let before = node.snapshot();
    let (mut fresh, first_page, _, initial) = pagination_fresh_owner(&node, &cancellation);
    let cursor = pagination_cursor(&mut fresh, 1);
    assert!(fresh.memory.is_none());
    assert!(Arc::ptr_eq(fresh.reservation.as_ref().unwrap(), &cursor.reservation));
    drop((fresh, first_page));
    let full = initial + OUTPUT_CHARGE_BYTES;
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), full);
    let mut continuation = pagination_continuation_owner(&node, &cursor, &cancellation);
    let admitted = node.snapshot();
    let page = continuation
        .copy_page(1, 7, usize::MAX, &cancellation)
        .unwrap();
    assert_eq!(page, pagination_page(&rows, 1..2));
    assert_eq!(
        continuation.memory.as_ref().unwrap().live_bytes(),
        input + page_bytes
    );
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        full + input + page_bytes
    );
    assert_eq!(node.snapshot().live_reservations, admitted.live_reservations);
    assert_eq!(
        node.snapshot().inflight_operations,
        admitted.inflight_operations
    );
    drop(page);
    drop(continuation);
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), full);
    drop(cursor);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);

    // A denied copy leaves the continuation's ledger at its request.
    let node = query_memory_node(full + input);
    let before = node.snapshot();
    let (mut fresh, first_page, _, _) = pagination_fresh_owner(&node, &cancellation);
    let cursor = pagination_cursor(&mut fresh, 1);
    drop((fresh, first_page));
    let mut continuation = pagination_continuation_owner(&node, &cursor, &cancellation);
    let admitted = node.snapshot();
    assert_eq!(
        continuation
            .copy_page(1, 7, usize::MAX, &cancellation)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(continuation.memory.as_ref().unwrap().live_bytes(), input);
    assert_eq!(continuation.memory.as_ref().unwrap().peak_bytes(), input);
    assert_eq!(node.snapshot().reserved_bytes, admitted.reserved_bytes);
    assert_eq!(continuation.rows.rows.len(), 3);
    drop(continuation);
    drop(cursor);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
}

#[test]
fn pagination_memory_output_charge_denial_keeps_the_completed_payload_owned() {
    let node = query_memory_node(
        query_input_workspace(&query_memory_request(), 3).unwrap()
            + pagination_page_bytes(&pagination_memory_rows(), 0..1)
            + pagination_pin_bytes(&pagination_memory_rows()),
    );
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, page, _, initial) = pagination_fresh_owner(&node, &cancellation);
    let admitted = node.snapshot();
    assert_eq!(
        owner.prepare_page_handoff().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert!(owner.reservation.is_none());
    assert_eq!(owner.memory.as_ref().unwrap().live_bytes(), initial);
    assert_eq!(owner.rows.rows.len(), 3);
    assert_eq!(page.rows.len(), 1);
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
    let rows = pagination_memory_rows();
    let full_bytes = query_input_workspace(&query_memory_request(), 3).unwrap()
        + pagination_page_bytes(&rows, 0..1)
        + pagination_pin_bytes(&rows)
        + OUTPUT_CHARGE_BYTES;
    let page_bytes = pagination_page_bytes(&rows, 1..2);
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let input_bytes = query_input_workspace(&request, 3).unwrap();
    // Room for both requests but only one copied page.
    let node = query_memory_node(full_bytes + input_bytes * 2 + page_bytes);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut owner, first_page, _, _) = pagination_fresh_owner(&node, &cancellation);
    let cursor = pagination_cursor(&mut owner, 1);
    drop((owner, first_page));
    let mut first = pagination_continuation_owner(&node, &cursor, &cancellation);
    let mut second = pagination_continuation_owner(&node, &cursor, &cancellation);
    let first_page = first.copy_page(1, 7, usize::MAX, &cancellation).unwrap();
    assert_eq!(
        second
            .copy_page(1, 7, usize::MAX, &cancellation)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(second.memory.as_ref().unwrap().live_bytes(), input_bytes);
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
    let second_page = second.copy_page(1, 7, usize::MAX, &cancellation).unwrap();
    assert_eq!(second_page, pagination_page(&rows, 1..2));
    drop(cursor);
    assert!(
        crate::test_utils::reserved_payload_bytes(&node) >= full_bytes + input_bytes + page_bytes
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
    let (mut owner, first_page, fence, _) = pagination_fresh_owner(&node, &cancellation);
    let weak = Arc::downgrade(&owner.rows);
    let mut pending = Box::pin(async move {
        let page = owner.copy_page(1, 7, usize::MAX, &cancellation).unwrap();
        std::future::pending::<()>().await;
        drop((page, first_page));
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
    let (mut owner, first_page, fence, _) = pagination_fresh_owner(&node, &cancellation);
    let weak = Arc::downgrade(&owner.rows);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _first_page = first_page;
        let _page = owner.copy_page(1, 7, usize::MAX, &cancellation).unwrap();
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
    let rows = pagination_memory_rows();
    let initial = query_input_workspace(&query_memory_request(), 3).unwrap()
        + pagination_page_bytes(&rows, 0..1)
        + pagination_pin_bytes(&rows);
    let page_bytes = pagination_page_bytes(&rows, 1..2);
    let audit_bytes = ((Limits::default().max_batch_bytes + (64 << 10)) * 3) as u64;
    let node = NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            // Enough for the retained output, a continuation page and the same
            // ordinary command allowance that strict release needs; only slots
            // deny it.
            max_inflight_bytes: Some(
                initial + OUTPUT_CHARGE_BYTES * 2 + (64 << 10) + page_bytes + audit_bytes,
            ),
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
    let (mut owner, page, _, _) = pagination_fresh_owner(&node, &cancellation);
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
        initial + OUTPUT_CHARGE_BYTES
    );
    let audit = node.reserve(audit_bytes, None).unwrap();
    assert_eq!(node.snapshot().inflight_operations, 1);
    assert_eq!(owner.rows.rows.len(), 3);
    assert_eq!(page, pagination_page(&rows, 0..1));
    drop(audit);
    let cursor = pagination_cursor(&mut owner, 1);
    drop(page);
    drop(owner);
    let mut continuation = pagination_continuation_owner(&node, &cursor, &cancellation);
    let next_page = continuation
        .copy_page(cursor.offset, cursor.revision, usize::MAX, &cancellation)
        .unwrap();
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
    assert_eq!(next_page, pagination_page(&rows, 1..2));
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

    let rows = pagination_memory_rows();
    let full_bytes = query_input_workspace(&query_memory_request(), 3).unwrap()
        + pagination_page_bytes(&rows, 0..1)
        + pagination_pin_bytes(&rows)
        + OUTPUT_CHARGE_BYTES;
    let mut request = query_memory_request();
    request.cursor = Some("old-cursor".into());
    let page_bytes = query_input_workspace(&request, 3).unwrap()
        + pagination_page_bytes(&rows, 1..2)
        + OUTPUT_CHARGE_BYTES;
    let node = query_memory_node(full_bytes + page_bytes);
    let before = node.snapshot();
    let cancellation = QueryCancellation::default();
    let (mut original, first_page, _, _) = pagination_fresh_owner(&node, &cancellation);
    let cursor = pagination_cursor(&mut original, 1);
    drop((original, first_page));
    let mut full = pagination_continuation_owner(&node, &cursor, &cancellation);
    let page = full.copy_page(1, 7, usize::MAX, &cancellation).unwrap();
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
        request.limit = Some(limit);
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
            continuation.limit = Some(limit);
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
    query.limit = Some(2);
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
