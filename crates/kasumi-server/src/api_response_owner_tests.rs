fn admitted_query_context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "person".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read]),
        request_id: "owned-output".into(),
    }
}

async fn seed_admitted_output(fixture: &Fixture) -> Value {
    let body = json!({"n":7,"text":"owned output ".repeat(1024),"nested":{"active":true}});
    let mut context = admitted_query_context();
    context.scopes.insert(Action::Write);
    fixture
        .db
        .mutate(
            context,
            serde_json::from_value(json!({
                "read_set":[],"idempotency_key":"owned-output-seed",
                "operations":[{"op":"put","collection":"docs","id":"one","body":body,
                "expected":{"kind":"absent"}}]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    body
}

// The native page/value cache shares this governor with the durable service
// audit. Authentication may grow that fitting cache; only its measured provider
// charge is excluded here, never the query source or adapter reservations.
fn admitted_non_cache_bytes(fixture: &Fixture) -> u64 {
    let cache = fixture.node.cache_stats().unwrap();
    let cache_charge = cache
        .admitted_credit_bytes
        .checked_add(cache.provider_overhead_bytes)
        .expect("native cache provider charge fits u64");
    fixture
        .physical
        .admission
        .snapshot()
        .reserved_bytes
        .checked_sub(cache_charge)
        .expect("native cache charge belongs to the exact fixture governor")
}

#[tokio::test]
async fn admitted_native_output_survives_unpolled_body_and_last_frame_clone() {
    use http_body_util::BodyExt;
    let fixture = Fixture::new().await;
    let expected = seed_admitted_output(&fixture).await;
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let query = json!({"collection":"docs","limit":1});
    // Warm the exact query's source before measuring adapter-only ownership.
    drop(
        fixture
            .db
            .query(
                &admitted_query_context(),
                serde_json::from_value(query.clone()).unwrap(),
            )
            .await
            .unwrap(),
    );
    let node = &fixture.physical.admission;
    // HTTP authentication has real durable audit jobs; reap their retained
    // handles and pause maintenance while establishing this isolated census.
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = admitted_non_cache_bytes(&fixture);
    drop(quiescent);
    let request = proto::QueryRequest {
        query_json: serde_json::to_vec(&query).unwrap(),
    }
    .encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
    framed.extend_from_slice(&request);
    let router = tonic::service::Routes::new(crate::rpc::native_data_service(
        fixture.registry.clone(),
        fixture.auth.clone(),
    ))
    .into_axum_router();
    for retain_parts in [false, true] {
        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/kasumi.v1.KasumiData/Query")
                    .version(axum::http::Version::HTTP_2)
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .header("authorization", &token)
                    .body(Body::from(framed.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The response owns source, bytes and fences across this await. Reap
        // only completed audit jobs; hold off maintenance through disposal.
        // This guard ends before the next HTTP request or fixture shutdown.
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let held = node.snapshot();
        assert_eq!(held.inflight_operations, 0);
        let held_cache = fixture.node.cache_stats().unwrap();
        assert!(admitted_non_cache_bytes(&fixture) > baseline_bytes);
        let (parts, mut body) = response.into_parts();
        let mut parts = Some(parts);
        if !retain_parts {
            drop(parts.take());
        }
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(
            u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
            bytes.len() - 5
        );
        let decoded = proto::QueryResponse::decode(&bytes[5..]).unwrap();
        assert_eq!(decoded.rows.len(), 1);
        let document = decoded.rows[0].document.as_ref().unwrap();
        assert_eq!(document.id, "one");
        assert_eq!(
            serde_json::from_slice::<Value>(&document.body_json).unwrap(),
            expected
        );
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        assert_eq!(
            node.snapshot().inflight_operations,
            baseline.inflight_operations
        );
        drop(clone);
        if retain_parts {
            assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
            assert_eq!(node.snapshot().live_reservations, held.live_reservations);
            assert_eq!(
                node.snapshot().reserved_bytes,
                held.reserved_bytes,
                "detached HTTP parts retain their shared custody after the final frame"
            );
            drop(parts.take());
        }
        // Authentication durably appends to the shared native store. Its
        // fitting cache may grow during the request, but disposal below has
        // no storage work and must retire exactly the source and adapter slots.
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(admitted_non_cache_bytes(&fixture), baseline_bytes);
        let released = node.snapshot();
        assert_eq!(
            released.live_reservations,
            held.live_reservations.checked_sub(2).unwrap(),
            "source and adapter reservations retire only after the final owner"
        );
        assert_eq!(released.inflight_operations, baseline.inflight_operations);
    }
    fixture.close().await;
}

#[tokio::test]
async fn admitted_mcp_output_survives_http_handoff_and_last_frame_clone() {
    use http_body_util::BodyExt;
    let fixture = Fixture::new().await;
    let expected = seed_admitted_output(&fixture).await;
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let query = json!({"collection":"docs","limit":1});
    drop(
        fixture
            .db
            .query(
                &admitted_query_context(),
                serde_json::from_value(query.clone()).unwrap(),
            )
            .await
            .unwrap(),
    );
    let node = &fixture.physical.admission;
    // HTTP authentication has real durable audit jobs; reap their retained
    // handles and pause maintenance while establishing this isolated census.
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = admitted_non_cache_bytes(&fixture);
    drop(quiescent);
    let request = mcp_body(
        "tools/call",
        json!({"name":"kasumi_query","arguments":query}),
    );
    for retain_parts in [false, true] {
        let response = fixture
            .router()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "kasumi.example")
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "tools/call")
                    .header("mcp-name", "kasumi_query")
                    .header("authorization", &token)
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The response owns source, bytes and fences across this await. Reap
        // only completed audit jobs; hold off maintenance through disposal.
        // This guard ends before the next HTTP request or fixture shutdown.
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let held = node.snapshot();
        assert_eq!(held.inflight_operations, 0);
        let held_cache = fixture.node.cache_stats().unwrap();
        assert!(admitted_non_cache_bytes(&fixture) > baseline_bytes);
        let (parts, mut body) = response.into_parts();
        let mut parts = Some(parts);
        if !retain_parts {
            drop(parts.take());
        }
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        let rows = result["result"]["structuredContent"]["rows"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "one");
        assert_eq!(rows[0]["body"], expected);
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        drop(clone);
        if retain_parts {
            assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
            assert_eq!(node.snapshot().live_reservations, held.live_reservations);
            assert_eq!(
                node.snapshot().reserved_bytes,
                held.reserved_bytes,
                "detached HTTP parts retain their shared custody after the final frame"
            );
            drop(parts.take());
        }
        // Authentication durably appends to the shared native store. Its
        // fitting cache may grow during the request, but disposal below has
        // no storage work and must retire exactly the source and adapter slots.
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(admitted_non_cache_bytes(&fixture), baseline_bytes);
        let released = node.snapshot();
        assert_eq!(
            released.live_reservations,
            held.live_reservations.checked_sub(2).unwrap(),
            "source and adapter reservations retire only after the final owner"
        );
        assert_eq!(released.inflight_operations, baseline.inflight_operations);
    }
    fixture.close().await;
}

#[tokio::test]
async fn admitted_adapter_growth_denial_destroys_source_before_releasing_custody() {
    let fixture = Fixture::new().await;
    let context = admitted_query_context();
    let query = || serde_json::from_value(json!({"collection":"docs","limit":1})).unwrap();
    drop(fixture.db.query(&context, query()).await.unwrap());
    let node = &fixture.physical.admission;
    let baseline = node.snapshot();
    let source = fixture.db.query(&context, query()).await.unwrap();
    let fence = fixture.db.owned_response_fence(&context).unwrap();
    assert!(node.snapshot().reserved_bytes > baseline.reserved_bytes);
    let failed = response_owner::PendingReply::new(source, fence).convert::<()>(|_, fence| {
        fence.retain_response_bytes(u64::MAX)?;
        panic!("denied conversion must not run its allocator")
    });
    assert!(matches!(
        failed,
        Err(Error {
            code: ErrorCode::ResourceExhausted,
            ..
        })
    ));
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    fixture.close().await;
}

#[tokio::test]
async fn admitted_native_feed_survives_unpolled_body_and_last_frame_clone() {
    use http_body_util::BodyExt;
    let fixture = Fixture::new().await;
    let expected = seed_admitted_output(&fixture).await;
    let expected_version = fixture.db.engine().generation().unwrap().state.collections["docs"]
        .documents["one"]
        .version;
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let feed = kasumi_types::ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start: kasumi_types::ChangeFeedStart::Beginning,
        limit: 1,
    };
    // Exercise the exact nonempty source before the isolated ownership census.
    // A feed has no server-side cursor owner to retain after this warmup.
    drop(
        fixture
            .db
            .read_change_feed(&admitted_query_context(), feed.clone())
            .await
            .unwrap(),
    );
    let node = &fixture.physical.admission;
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = admitted_non_cache_bytes(&fixture);
    drop(quiescent);
    let request = proto::ReadChangeFeedRequest {
        request_json: serde_json::to_vec(&feed).unwrap(),
    }
    .encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(request.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&request);
    let router = tonic::service::Routes::new(crate::rpc::native_data_service(
        fixture.registry.clone(),
        fixture.auth.clone(),
    ))
    .into_axum_router();
    for retain_parts in [false, true] {
        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/kasumi.v1.KasumiData/ReadChangeFeed")
                    .version(axum::http::Version::HTTP_2)
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .header("authorization", &token)
                    .body(Body::from(framed.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Reap completed durable authentication jobs and exclude only measured
        // native cache provider bytes. Source/adapter owners stay in the census.
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let held = node.snapshot();
        assert_eq!(held.inflight_operations, 0);
        let held_cache = fixture.node.cache_stats().unwrap();
        assert!(admitted_non_cache_bytes(&fixture) > baseline_bytes);
        let (parts, mut body) = response.into_parts();
        let mut parts = Some(parts);
        if !retain_parts {
            drop(parts.take());
        }
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let decoded = decode_grpc::<proto::ReadChangeFeedResponse>(&bytes);
        let page: kasumi_types::ChangeFeedPage =
            serde_json::from_slice(&decoded.response_json).unwrap();
        let kasumi_types::ChangeFeedPage::Events {
            revision,
            first_available_sequence,
            head_sequence,
            events,
            next,
            caught_up,
        } = page
        else {
            panic!("the seeded feed must return its after-image, not a retention gap")
        };
        assert_eq!(revision, expected_version);
        assert_eq!(first_available_sequence, 1);
        assert_eq!(head_sequence, 1);
        assert!(caught_up);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.sequence, 1);
        assert_eq!(event.revision, expected_version);
        assert_eq!(event.ordinal, 0);
        assert_eq!(event.commit_event_count, 1);
        assert_eq!(event.collection, "docs");
        assert_eq!(event.id, "one");
        let document = event.document.as_ref().unwrap();
        assert_eq!(document.id, "one");
        assert_eq!(document.version, expected_version);
        assert_eq!(document.body, expected);
        assert_eq!(next.tenant, "tenant-a");
        assert_eq!(next.incarnation, fixture.incarnation.to_string());
        assert_eq!(next.principal, "person");
        assert_eq!(next.collections, feed.collections);
        assert_eq!(next.after_sequence, 1);
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        assert_eq!(
            node.snapshot().inflight_operations,
            baseline.inflight_operations
        );
        drop(clone);
        if retain_parts {
            assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
            assert_eq!(node.snapshot().live_reservations, held.live_reservations);
            assert_eq!(
                node.snapshot().reserved_bytes,
                held.reserved_bytes,
                "detached HTTP parts retain feed custody after the final frame"
            );
            drop(parts.take());
        }
        // Nothing in owner disposal touches storage. Both the after-image
        // source and adapter reservations must retire at exactly the final
        // frame/parts owner, while the complete fitting native cache stays hot.
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(admitted_non_cache_bytes(&fixture), baseline_bytes);
        let released = node.snapshot();
        assert_eq!(
            released.live_reservations,
            held.live_reservations.checked_sub(2).unwrap(),
            "feed source and adapter reservations retire together at final disposal"
        );
        assert_eq!(released.inflight_operations, baseline.inflight_operations);
    }
    fixture.close().await;
}

#[tokio::test]
async fn admitted_native_point_survives_unpolled_body_and_last_frame_clone() {
    use http_body_util::BodyExt;
    let fixture = Fixture::new().await;
    let expected = seed_admitted_output(&fixture).await;
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    // Warm the exact point source, then release it before the ownership census.
    let warm = fixture
        .db
        .get(&admitted_query_context(), "docs", "one")
        .await
        .unwrap();
    let expected_version = warm.version;
    drop(warm);
    let node = &fixture.physical.admission;
    // HTTP authentication has real durable audit jobs; reap their retained
    // handles and pause maintenance while establishing this isolated census.
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = admitted_non_cache_bytes(&fixture);
    drop(quiescent);
    let request = proto::GetRequest {
        collection: "docs".into(),
        id: "one".into(),
    }
    .encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(request.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&request);
    let router = tonic::service::Routes::new(crate::rpc::native_data_service(
        fixture.registry.clone(),
        fixture.auth.clone(),
    ))
    .into_axum_router();
    for retain_parts in [false, true] {
        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/kasumi.v1.KasumiData/Get")
                    .version(axum::http::Version::HTTP_2)
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .header("authorization", &token)
                    .body(Body::from(framed.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The response owns source, bytes and fences across this await. Reap
        // only completed audit jobs; hold off maintenance through disposal.
        // This guard ends before the next HTTP request or fixture shutdown.
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let held = node.snapshot();
        assert_eq!(held.inflight_operations, 0);
        let held_cache = fixture.node.cache_stats().unwrap();
        assert!(admitted_non_cache_bytes(&fixture) > baseline_bytes);
        let (parts, mut body) = response.into_parts();
        let mut parts = Some(parts);
        if !retain_parts {
            drop(parts.take());
        }
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(
            u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
            bytes.len() - 5
        );
        let document = proto::Document::decode(&bytes[5..]).unwrap();
        assert_eq!(document.id, "one");
        assert_eq!(document.version, expected_version);
        assert_eq!(
            serde_json::from_slice::<Value>(&document.body_json).unwrap(),
            expected
        );
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        assert_eq!(
            node.snapshot().inflight_operations,
            baseline.inflight_operations
        );
        drop(clone);
        if retain_parts {
            assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
            assert_eq!(node.snapshot().live_reservations, held.live_reservations);
            assert_eq!(
                node.snapshot().reserved_bytes,
                held.reserved_bytes,
                "detached HTTP parts retain their shared custody after the final frame"
            );
            drop(parts.take());
        }
        // Authentication durably appends to the shared native store. Its
        // fitting cache may grow during the request, but disposal below has
        // no storage work and must retire exactly the source and adapter slots.
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(admitted_non_cache_bytes(&fixture), baseline_bytes);
        let released = node.snapshot();
        assert_eq!(
            released.live_reservations,
            held.live_reservations.checked_sub(2).unwrap(),
            "point source and adapter reservations retire only after the final owner"
        );
        assert_eq!(released.inflight_operations, baseline.inflight_operations);
    }
    fixture.close().await;
}

#[tokio::test]
async fn admitted_mcp_point_survives_http_handoff_and_last_frame_clone() {
    use http_body_util::BodyExt;
    let fixture = Fixture::new().await;
    let expected = seed_admitted_output(&fixture).await;
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let warm = fixture
        .db
        .get(&admitted_query_context(), "docs", "one")
        .await
        .unwrap();
    let expected_version = warm.version;
    drop(warm);
    let node = &fixture.physical.admission;
    // HTTP authentication has real durable audit jobs; reap their retained
    // handles and pause maintenance while establishing this isolated census.
    let quiescent = fixture.audit.quiescent_jobs_for_test().await;
    let baseline = node.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = admitted_non_cache_bytes(&fixture);
    drop(quiescent);
    let request = mcp_body(
        "tools/call",
        json!({"name":"kasumi_get","arguments":{"collection":"docs","id":"one"}}),
    );
    for retain_parts in [false, true] {
        let response = fixture
            .router()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "kasumi.example")
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "tools/call")
                    .header("mcp-name", "kasumi_get")
                    .header("authorization", &token)
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The response owns source, bytes and fences across this await. Reap
        // only completed audit jobs; hold off maintenance through disposal.
        // This guard ends before the next HTTP request or fixture shutdown.
        let _quiescent = fixture.audit.quiescent_jobs_for_test().await;
        let held = node.snapshot();
        assert_eq!(held.inflight_operations, 0);
        let held_cache = fixture.node.cache_stats().unwrap();
        assert!(admitted_non_cache_bytes(&fixture) > baseline_bytes);
        let (parts, mut body) = response.into_parts();
        let mut parts = Some(parts);
        if !retain_parts {
            drop(parts.take());
        }
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        let document = &result["result"]["structuredContent"];
        assert_eq!(document["id"], "one");
        assert_eq!(document["version"], expected_version);
        assert_eq!(document["body"], expected);
        let clone = bytes.clone();
        drop(body);
        drop(bytes);
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, held.live_reservations);
        drop(clone);
        if retain_parts {
            assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
            assert_eq!(node.snapshot().live_reservations, held.live_reservations);
            assert_eq!(
                node.snapshot().reserved_bytes,
                held.reserved_bytes,
                "detached HTTP parts retain their shared custody after the final frame"
            );
            drop(parts.take());
        }
        // Authentication durably appends to the shared native store. Its
        // fitting cache may grow during the request, but disposal below has
        // no storage work and must retire exactly the source and adapter slots.
        assert_eq!(fixture.node.cache_stats().unwrap(), held_cache);
        assert_eq!(admitted_non_cache_bytes(&fixture), baseline_bytes);
        let released = node.snapshot();
        assert_eq!(
            released.live_reservations,
            held.live_reservations.checked_sub(2).unwrap(),
            "point source and adapter reservations retire only after the final owner"
        );
        assert_eq!(released.inflight_operations, baseline.inflight_operations);
    }
    fixture.close().await;
}
