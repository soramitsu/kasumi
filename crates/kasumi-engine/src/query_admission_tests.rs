use super::*;
use std::task::Poll;

fn node() -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(crate::admission::AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            max_inflight_bytes: Some(64 << 20),
            ..Default::default()
        })
        .unwrap(),
        8 << 30,
        0,
    )
    .unwrap()
}

#[tokio::test]
async fn queued_query_keeps_request_capacity_without_execution_and_wakes_on_shutdown() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let mut request = QueryRequest::new("docs");
    request.collection.reserve(1 << 20);
    request
        .filter
        .fields
        .insert("/owner".into(), Condition::default());
    request.filter.fields.clear(); // An empty BTree may still retain its root.
    let minimum = request.collection.capacity() as u64;
    let queued = WaitingQuery::admit(&node, &fence, request, &cancellation).unwrap();
    assert!(queued.bytes >= minimum);
    assert_eq!(
        node.snapshot().inflight_operations,
        baseline.inflight_operations
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let mut waiting = Box::pin(permit(
        &slots,
        &cancellation,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    fence.seal();
    assert!(waiting.await.is_err());
    assert_eq!(slots.available_permits(), 0);
    drop(queued);
    fence.drain().await;
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    drop(held);
    assert_eq!(slots.available_permits(), 4);
}

#[tokio::test]
async fn queued_query_wait_uses_original_deadline_and_releases_cancelled_waiter() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let queued =
        WaitingQuery::admit(&node, &fence, QueryRequest::new("docs"), &cancellation).unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
    assert_eq!(
        permit(&slots, &cancellation, deadline)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(slots.available_permits(), 0);
    drop(queued);
    fence.drain().await;
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    drop(held);
    // Expiry is checked even when a permit becomes immediately available.
    assert!(permit(&slots, &cancellation, deadline).await.is_err());
    assert_eq!(slots.available_permits(), 4);
}

#[tokio::test]
async fn queued_query_dispatch_transfers_input_to_one_active_grant_without_extra_workers() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let mut request = QueryRequest::new("docs");
    request.select = Vec::with_capacity(4096);
    let pointer = request.select.as_ptr();
    let queued = WaitingQuery::admit(&node, &fence, request, &cancellation).unwrap();
    let retained = queued.bytes;
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let mut waiting = Box::pin(permit(
        &slots,
        &cancellation,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(held);
    let permit = waiting.await.unwrap();
    assert_eq!(slots.available_permits(), 3);
    let (mut input, registration) = queued.into_input(&node, 1 << 20, &cancellation).unwrap();
    assert_eq!(input.request.select.as_ptr(), pointer);
    assert_eq!(input.memory.live_bytes(), retained);
    let prepaid = node.snapshot().reserved_bytes;
    input.memory.reserve(1 << 20).unwrap();
    assert_eq!(input.memory.live_bytes(), retained + (1 << 20));
    assert_eq!(node.snapshot().reserved_bytes, prepaid);
    assert_eq!(
        node.snapshot().inflight_operations,
        baseline.inflight_operations + 1
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    drop(input);
    drop(registration);
    drop(permit);
    fence.drain().await;
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(slots.available_permits(), 4);
}

#[test]
fn queued_query_quotes_spare_vectors_nested_values_and_retained_empty_trees() {
    let mut request = QueryRequest::new("docs");
    let compact = request_bytes(&request).unwrap();
    request.select = Vec::with_capacity(4096);
    assert!(
        request_bytes(&request).unwrap()
            >= compact + kasumi_query::vec_bytes::<String>(4096).unwrap()
    );
    let mut value = String::with_capacity(1 << 20);
    value.push('x');
    let capacity = value.capacity();
    request.filter = Filter::new().eq("/proof", value);
    assert!(request_bytes(&request).unwrap() >= capacity as u64);
    let mut empty = Filter::default();
    empty.fields.insert("/deleted".into(), Condition::default());
    empty.fields.clear();
    assert!(filter_bytes(&empty, 0).unwrap() >= tree::<String, Condition>(1).unwrap());
}

#[tokio::test]
async fn queued_query_admits_under_operation_saturation_but_dispatch_needs_its_own_slot() {
    let node = node();
    let baseline = node.snapshot();
    let mut active = (0..node.policy().max_inflight_operations)
        .map(|_| node.reserve(0, None).unwrap())
        .collect::<Vec<_>>();
    assert!(node.reserve(0, None).is_err());
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let queued =
        WaitingQuery::admit(&node, &fence, QueryRequest::new("docs"), &cancellation).unwrap();
    assert_eq!(node.snapshot().inflight_operations, active.len());
    assert_eq!(
        queued
            .into_input(&node, 1 << 20, &cancellation)
            .err()
            .unwrap()
            .code,
        ErrorCode::ResourceExhausted
    );
    fence.drain().await;
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + active.len()
    );

    let queued =
        WaitingQuery::admit(&node, &fence, QueryRequest::new("docs"), &cancellation).unwrap();
    drop(active.pop());
    let (input, registration) = queued.into_input(&node, 1 << 20, &cancellation).unwrap();
    assert_eq!(
        node.snapshot().inflight_operations,
        node.policy().max_inflight_operations
    );
    drop(input);
    drop(registration);
    fence.drain().await;
    drop(active);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(node.snapshot().inflight_operations, 0);
}

fn snapshot_request() -> ReadSnapshotRequest {
    ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "a".into(),
        }],
        queries: vec![],
        time_bounds: None,
    }
}

#[tokio::test]
async fn queued_snapshot_retains_spare_input_capacity_and_transfers_one_execution_grant() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let mut request = snapshot_request();
    request.documents.reserve(4096);
    request.documents[0].id.reserve(1 << 20);
    request.queries = Vec::with_capacity(64);
    let mut query = QueryRequest::new("docs");
    query.select = Vec::with_capacity(4096);
    request.queries.push(query);
    let documents = request.documents.as_ptr();
    let queries = request.queries.as_ptr();
    let minimum = kasumi_query::vec_bytes::<DocumentKey>(request.documents.capacity()).unwrap()
        + request.documents[0].id.capacity() as u64
        + kasumi_query::vec_bytes::<QueryRequest>(request.queries.capacity()).unwrap()
        + kasumi_query::vec_bytes::<String>(request.queries[0].select.capacity()).unwrap();
    let queued = WaitingSnapshot::admit(
        &node,
        &fence,
        request,
        BTreeSet::from(["docs".into()]),
        &cancellation,
    )
    .unwrap();
    let retained = queued.bytes;
    assert!(retained >= minimum);
    assert_eq!(
        node.snapshot().inflight_operations,
        baseline.inflight_operations
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    let (mut input, registration, collections) =
        queued.into_input(&node, 1 << 20, &cancellation).unwrap();
    assert_eq!(input.request.documents.as_ptr(), documents);
    assert_eq!(input.request.queries.as_ptr(), queries);
    assert_eq!(input.memory.live_bytes(), retained);
    assert_eq!(collections, BTreeSet::from(["docs".into()]));
    assert_eq!(
        node.snapshot().inflight_operations,
        baseline.inflight_operations + 1
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    let prepaid = node.snapshot().reserved_bytes;
    input.memory.reserve(1 << 20).unwrap();
    assert_eq!(node.snapshot().reserved_bytes, prepaid);
    drop(collections);
    drop(input);
    drop(registration);
    fence.drain().await;
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[tokio::test]
async fn queued_snapshot_fifo_progress_survives_cancelled_middle_waiter() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let first = QueryCancellation::default();
    let middle = QueryCancellation::default();
    let last = QueryCancellation::default();
    let mut inputs = Vec::new();
    for cancellation in [&first, &middle, &last] {
        inputs.push(
            WaitingSnapshot::admit(
                &node,
                &fence,
                snapshot_request(),
                BTreeSet::from(["docs".into()]),
                cancellation,
            )
            .unwrap(),
        );
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(slots.clone().acquire_owned().await.unwrap());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut first_wait = Box::pin(permit(&slots, &first, deadline));
    let mut middle_wait = Box::pin(permit(&slots, &middle, deadline));
    let mut last_wait = Box::pin(permit(&slots, &last, deadline));
    std::future::poll_fn(|cx| {
        assert!(first_wait.as_mut().poll(cx).is_pending());
        assert!(middle_wait.as_mut().poll(cx).is_pending());
        assert!(last_wait.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    middle.cancel();
    assert!(middle_wait.await.is_err());
    drop(held.pop());
    std::future::poll_fn(|cx| {
        assert!(
            last_wait.as_mut().poll(cx).is_pending(),
            "FIFO predecessor owns the released slot"
        );
        Poll::Ready(())
    })
    .await;
    let admitted = first_wait.await.unwrap();
    assert_eq!(slots.available_permits(), 0);
    drop(admitted);
    let admitted = last_wait.await.unwrap();
    assert_eq!(slots.available_permits(), 0);
    drop(admitted);
    drop(held);
    drop(inputs);
    fence.drain().await;
    assert_eq!(slots.available_permits(), 4);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[tokio::test]
async fn queued_snapshot_dispatch_refusal_releases_input_and_work_registration() {
    let node = node();
    let baseline = node.snapshot();
    let fence = Arc::new(WorkFence::default());
    let cancellation = QueryCancellation::default();
    let active: Vec<_> = (0..node.policy().max_inflight_operations)
        .map(|_| node.reserve(0, None).unwrap())
        .collect();
    let queued = WaitingSnapshot::admit(
        &node,
        &fence,
        snapshot_request(),
        BTreeSet::from(["docs".into()]),
        &cancellation,
    )
    .unwrap();
    assert_eq!(node.snapshot().inflight_operations, active.len());
    assert_eq!(
        queued
            .into_input(&node, 1 << 20, &cancellation)
            .err()
            .unwrap()
            .code,
        ErrorCode::ResourceExhausted
    );
    fence.drain().await;
    drop(active);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}
