fn query_memory_node(payload_bytes: u64) -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            max_inflight_bytes: Some(payload_bytes),
            max_reservations: 64,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            ..Default::default()
        })
        .unwrap(),
        8 << 30,
        0,
    )
    .unwrap()
}

fn query_memory_generation() -> Arc<crate::Generation> {
    let engine = TenantEngine::new(
        "query-memory".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Read, Action::Admin]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let collection = CollectionState {
        definition: CollectionDefinition {
            name: "docs".into(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: json!({"type": "object"}),
            indexes: vec![],
            strict_read_audit: false,
        },
        data_epoch: 7,
        documents: [(
            "a".to_owned(),
            Arc::new(Document {
                id: "a".into(),
                version: 7,
                body: json!({"value": "x".repeat(1024)}),
            }),
        )]
        .into_iter()
        .collect(),
        archived_documents: Default::default(),
        archived_document_bytes: 0,
    };
    let mut generation = engine
        .generation()
        .unwrap()
        .read_view(BTreeMap::from([("docs".into(), collection)]), vec![]);
    generation.state.revision = 7;
    generation.state.limits.max_result_bytes = 16 << 10;
    generation.state.limits.max_query_candidates = 4;
    generation.state.limits.max_query_groups = 4;
    generation.indexes = Arc::new(crate::index_source::build(&generation.state).unwrap());
    Arc::new(generation)
}

fn query_memory_request() -> QueryRequest {
    serde_json::from_value(json!({"collection": "docs", "allow_scan": true, "limit": 1})).unwrap()
}

fn query_memory_snapshot_work(
    node: &Arc<NodeAdmission>,
    generation: Arc<crate::Generation>,
    request: ReadSnapshotRequest,
) -> (SnapshotWork, Arc<WorkFence>, Arc<tokio::sync::Semaphore>) {
    let cancellation = QueryCancellation::default();
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(cancellation.clone()).unwrap());
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let mut work = SnapshotWork {
        generation,
        request,
        cancellation: cancellation.clone(),
        _permit: slots.clone().try_acquire_owned().unwrap(),
        memory: QueryMemory::empty(node.reserve(512, Some(cancellation)).unwrap()),
        registration,
    };
    work.memory
        .reserve(query_input_workspace(&work.request, 1).unwrap())
        .unwrap();
    (work, fence, slots)
}

#[test]
fn query_memory_reuses_prepaid_slot_and_preserves_growth_on_denial_and_cancellation() {
    let node = query_memory_node(4096);
    let baseline = node.snapshot();
    let cancellation = QueryCancellation::default();
    let mut memory = QueryMemory::empty(node.reserve(1024, Some(cancellation.clone())).unwrap());
    let prepaid = node.snapshot();
    memory.reserve(64).unwrap();
    assert_eq!(node.snapshot().reserved_bytes, prepaid.reserved_bytes);
    memory.reserve(2048).unwrap();
    let grown = node.snapshot();
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 2112);
    assert_eq!(grown.live_reservations, prepaid.live_reservations);
    assert_eq!(grown.inflight_operations, prepaid.inflight_operations);
    assert_eq!(
        memory.reserve(2048).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!((memory.live_bytes(), memory.peak_bytes()), (2112, 2112));
    assert_eq!(node.snapshot().reserved_bytes, grown.reserved_bytes);
    memory.release(2048).unwrap();
    let provider = memory.into_workspace();
    let mut memory = QueryMemory::empty(provider);
    cancellation.cancel();
    assert_eq!(
        memory.reserve(64).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(memory.live_bytes(), 0);
    assert_eq!(node.snapshot().reserved_bytes, grown.reserved_bytes);
    drop(memory);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn snapshot_query_memory_keeps_points_and_prior_results_live_and_denies_second_peak() {
    let request = ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "a".into(),
        }],
        queries: vec![query_memory_request(), query_memory_request()],
        time_bounds: None,
    };
    let generation = query_memory_generation();
    let expected_document = generation.state.collections["docs"].documents["a"]
        .as_ref()
        .clone();
    let metadata = 512
        + generation.state.incarnation.len() as u64
        + request
            .queries
            .iter()
            .map(|query| query.collection.len() as u64 + 256)
            .sum::<u64>();
    let point = snapshot_point_workspace(&request.documents[0], Some(&expected_document)).unwrap();
    let initial = query_input_workspace(&request, 1).unwrap();
    // A same-size invalid second query stops before its allocations, exposing
    // the completed first query's peak without duplicating planner internals.
    let mut prefix = request.clone();
    prefix.queries[1].limit = 0;
    assert_eq!(query_input_workspace(&prefix, 1).unwrap(), initial);
    let prefix_node = query_memory_node(1 << 20);
    let (prefix_work, _, _) =
        query_memory_snapshot_work(&prefix_node, query_memory_generation(), prefix);
    let prefix_output = prefix_work.run();
    assert_eq!(
        prefix_output.response.as_ref().unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let first_peak = prefix_output.memory.peak_bytes();
    assert!(first_peak > initial + metadata + point);
    drop(prefix_output);
    assert_eq!(crate::test_utils::reserved_payload_bytes(&prefix_node), 0);
    let node = query_memory_node(1 << 20);
    let before = node.snapshot();
    let (work, fence, slots) = query_memory_snapshot_work(&node, generation, request.clone());
    let output = work.run();
    let response = output.response.as_ref().unwrap();
    assert_eq!(
        response.documents[0].document.as_ref(),
        Some(&expected_document)
    );
    assert_eq!(response.queries.len(), 2);
    let retained_query = kasumi_query::query_response_clone_bytes(
        &response.queries[0],
        0..response.queries[0].rows.len(),
    )
    .unwrap();
    assert_eq!(response.queries[0], response.queries[1]);
    let second_peak = output.memory.peak_bytes();
    assert!(second_peak > first_peak);
    assert_eq!(
        output.memory.live_bytes(),
        initial + metadata + point + retained_query * 2
    );
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        second_peak
    );
    assert_eq!(slots.available_permits(), 1);
    fence.seal();
    let mut draining = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(output);
    draining.await;
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);

    // Both evaluations fit individually. Only the second query's overlap with
    // the already retained point and first response exceeds this fixed budget.
    let node = query_memory_node(second_peak - 1);
    let before = node.snapshot();
    let (work, fence, slots) =
        query_memory_snapshot_work(&node, query_memory_generation(), request);
    let output = work.run();
    assert_eq!(
        output.response.as_ref().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(output.memory.live_bytes(), initial);
    assert!(output.memory.peak_bytes() >= first_peak);
    assert!(output.memory.peak_bytes() < second_peak);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&node),
        output.memory.peak_bytes()
    );
    assert_eq!(
        node.snapshot().live_reservations,
        before.live_reservations + 1
    );
    assert_eq!(slots.available_permits(), 1);
    fence.seal();
    let mut draining = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(output);
    draining.await;
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[tokio::test]
async fn query_memory_success_and_source_error_outputs_hold_custody_until_abandoned() {
    for missing in [false, true] {
        let node = query_memory_node(1 << 20);
        let before = node.snapshot();
        let generation = query_memory_generation();
        let weak = Arc::downgrade(&generation);
        let mut request = query_memory_request();
        if missing {
            request.collection = "missing".into();
        }
        let initial = query_input_workspace(&request, 1).unwrap();
        let cancellation = QueryCancellation::default();
        let fence = Arc::new(WorkFence::default());
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let mut work = QueryWork {
            generation,
            request,
            cancellation: cancellation.clone(),
            _permit: slots.clone().try_acquire_owned().unwrap(),
            memory: QueryMemory::empty(node.reserve(512, Some(cancellation.clone())).unwrap()),
            registration: Arc::new(fence.begin(cancellation).unwrap()),
        };
        work.memory.reserve(initial).unwrap();
        let output = tokio::task::spawn_blocking(move || work.run())
            .await
            .unwrap();
        if missing {
            assert_eq!(
                output.response.as_ref().unwrap_err(),
                &Error::new(ErrorCode::NotFound, "collection not found")
            );
            assert_eq!(output.memory.live_bytes(), initial);
        } else {
            assert_eq!(output.response.as_ref().unwrap().rows.len(), 1);
            assert!(output.memory.live_bytes() > initial);
        }
        assert!(weak.upgrade().is_none());
        assert_eq!(slots.available_permits(), 1);
        assert!(crate::test_utils::reserved_payload_bytes(&node) >= output.memory.peak_bytes());
        fence.seal();
        let mut draining = Box::pin(fence.drain());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(output);
        draining.await;
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
        assert_eq!(
            node.snapshot().inflight_operations,
            before.inflight_operations
        );
    }
}
