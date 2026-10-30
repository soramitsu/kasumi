#[tokio::test]
async fn private_evidence_snapshot_retry_funds_original_and_replacement_owners() {
    use kasumi_private_evidence::{CustodyBackend, KasumiBackend};
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Duration,
    };

    let fail_next = Arc::new(AtomicBool::new(true));
    let reads = Arc::new(AtomicUsize::new(0));
    let transport = private_evidence_transport_fixture_with_router({
        let fail_next = fail_next.clone();
        let reads = reads.clone();
        move |router| {
            router.layer(axum::middleware::from_fn(
                move |request: HttpRequest<Body>, next: axum::middleware::Next| {
                    let fail_next = fail_next.clone();
                    let reads = reads.clone();
                    async move {
                        let snapshot = request.uri().path() == "/kasumi.v1.KasumiData/ReadSnapshot";
                        let fail = snapshot && fail_next.swap(false, Ordering::SeqCst);
                        if snapshot {
                            reads.fetch_add(1, Ordering::SeqCst);
                        }
                        let response = next.run(request).await;
                        if !fail {
                            return response;
                        }
                        // Finish the actual authenticated RPC before replacing
                        // its reply. The next attempt must coexist with the
                        // pool's retained original request admission even when
                        // the first transport has finished normally.
                        axum::body::to_bytes(response.into_body(), 8 << 20)
                            .await
                            .unwrap();
                        axum::http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "14")
                            .body(Body::empty())
                            .unwrap()
                    }
                },
            ))
        }
    })
    .await;
    let mut backend =
        KasumiBackend::from_installed_profile(&transport.profile_path, &transport.binding).unwrap();
    let ids = vec!["retry-budget-missing".to_owned()];
    for operation in 1..=2 {
        fail_next.store(true, Ordering::SeqCst);
        let records = backend
            .read_records(
                &transport.binding.manifest_collection,
                &ids,
                Duration::from_secs(30),
            )
            .await
            .expect("a retry must fit beside the retained original snapshot admission");
        assert_eq!(records, vec![None]);
        assert_eq!(reads.load(Ordering::SeqCst), operation * 2);
        assert!(!fail_next.load(Ordering::SeqCst));
        // Repeating the forced retry on the same backend also requires both
        // reservations from the previous operation to have been released.
    }
    drop(backend);
    transport.close().await;
}
