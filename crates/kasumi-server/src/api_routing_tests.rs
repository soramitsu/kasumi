#[tokio::test]
async fn native_pool_replays_uncertain_batches_and_never_moves_historical_pages() {
    use kasumi_client::{KasumiClientConfig, KasumiClientPool};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    let fixture = Fixture::new().await;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&key).unwrap().pem().into_bytes();
    let issuer = rcgen::Issuer::new(params, key);
    let identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let client = identity();
    let first_requests = Arc::new(AtomicUsize::new(0));
    let mut endpoints = std::collections::BTreeMap::new();
    let mut tasks = Vec::new();
    let mut stops = Vec::new();
    for member in 1..=2 {
        let server = identity();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        endpoints.insert(
            member,
            KasumiClientConfig {
                endpoint: format!(
                    "https://localhost:{}",
                    listener.local_addr().unwrap().port()
                ),
                identity: client.clone(),
                trusted_ca_pem: ca.clone(),
                server_certificate_pins: BTreeSet::from([server.certificate_pin()]),
            },
        );
        let router = tonic::service::Routes::new(fixture.data().service()).into_axum_router();
        let router = if member == 1 {
            let requests = first_requests.clone();
            router
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    |axum::extract::State(first): axum::extract::State<
                        Arc<std::sync::atomic::AtomicBool>,
                    >,
                     request: HttpRequest<Body>,
                     next: axum::middleware::Next| async move {
                        let response = next.run(request).await;
                        if first.swap(false, Ordering::SeqCst) {
                            let _ = axum::body::to_bytes(response.into_body(), 32 << 20)
                                .await
                                .unwrap();
                            axum::http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .header("grpc-status", "14")
                                .body(Body::empty())
                                .unwrap()
                        } else {
                            response
                        }
                    },
                ))
                .layer(axum::middleware::from_fn(
                    move |request: HttpRequest<Body>, next: axum::middleware::Next| {
                        let requests = requests.clone();
                        async move {
                            requests.fetch_add(1, Ordering::SeqCst);
                            next.run(request).await
                        }
                    },
                ))
        } else {
            router
        };
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        stops.push(stop);
        tasks.push(tokio::spawn(crate::tls::serve_tls(
            listener,
            kasumi_transport::server_config(
                &server,
                ClientAuthentication::Required {
                    trusted_ca_pem: &ca,
                },
            )
            .unwrap(),
            router,
            crate::tls::ListenerLimits::default(),
            fixture.audit.clone(),
            shutdown,
        )));
    }
    let token = fixture
        .token("person", "tenant-a", "kasumi:read kasumi:write")
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let current_token = Arc::new(std::sync::RwLock::new(token.clone()));
    let credential_loads = Arc::new(AtomicUsize::new(0));
    let selected = current_token.clone();
    let loads = credential_loads.clone();
    let source: Arc<dyn kasumi_transport::credentials::CredentialSource> = Arc::new(move || {
        let snapshot = selected.read().unwrap().clone();
        if loads.fetch_add(1, Ordering::SeqCst) == 0 {
            *selected.write().unwrap() = "invalid-replacement".into();
        }
        Ok(zeroize::Zeroizing::new(snapshot))
    });
    let mut pool = KasumiClientPool::new(endpoints.clone(), source.clone()).unwrap();
    let mut body = batch();
    for id in ["two", "three"] {
        let mut operation = body["operations"][0].clone();
        operation["id"] = json!(id);
        body["operations"].as_array_mut().unwrap().push(operation);
    }
    let original: kasumi_types::MutationBatch = serde_json::from_value(body).unwrap();
    let receipt = pool
        .mutate(&original, Duration::from_secs(4))
        .await
        .unwrap();
    assert_eq!(
        first_requests.load(Ordering::SeqCst),
        1,
        "first member committed but lost its response"
    );
    assert_eq!(credential_loads.load(Ordering::SeqCst), 1, "ambiguous mutation retries retain the original credential snapshot");
    assert!(pool.mutate(&original, Duration::from_secs(4)).await.is_err());
    assert_eq!(credential_loads.load(Ordering::SeqCst), 2, "the next operation reads the replacement once");
    *current_token.write().unwrap() = token;
    let replay = pool
        .mutate(&original, Duration::from_secs(4))
        .await
        .unwrap();
    assert_eq!(receipt.revision, replay.revision);
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .document_count,
        3
    );
    let mut conflicting = original.clone();
    conflicting.operations.clear();
    conflicting.operations.push(kasumi_types::Mutation::Put {
        collection: "docs".into(),
        id: "other".into(),
        body: json!({}),
        expected: kasumi_types::Precondition::Absent,
    });
    assert!(
        pool.mutate(&conflicting, Duration::from_secs(4))
            .await
            .is_err()
    );
    assert_eq!(
        first_requests.load(Ordering::SeqCst),
        1,
        "conflicts are never failover signals"
    );
    let query = serde_json::from_value(
        json!({"collection":"docs", "filter":{"op":"all"}, "limit":1, "allow_scan":true}),
    )
    .unwrap();
    let page = pool.query(&query, Duration::from_secs(4)).await.unwrap();
    assert_eq!(page.member(), 2);
    assert!(page.response().cursor.is_some());
    let lease = pool
        .open_snapshot_lease(
            &kasumi_types::OpenSnapshotLease { ttl_ms: 5000 },
            Duration::from_secs(4),
        )
        .await
        .unwrap();
    assert_eq!(lease.member(), 2);
    let mut other_pool = KasumiClientPool::new(endpoints, source).unwrap();
    assert!(
        other_pool
            .next_query_page(&page, Duration::from_secs(1))
            .await
            .is_err()
    );
    stops[1].send(true).unwrap();
    tasks.pop().unwrap().await.unwrap().unwrap();
    assert!(
        pool.next_query_page(&page, Duration::from_millis(150))
            .await
            .is_err()
    );
    assert!(
        pool.scan_snapshot_page(&lease, "docs", None, 1, Duration::from_millis(150))
            .await
            .is_err()
    );
    assert_eq!(
        first_requests.load(Ordering::SeqCst),
        1,
        "historical operations must not move to the healthy first member"
    );
    // An explicitly new query can select an available installed member.
    assert_eq!(
        pool.query(&query, Duration::from_secs(2))
            .await
            .unwrap()
            .member(),
        1
    );
    stops[0].send(true).unwrap();
    tasks.pop().unwrap().await.unwrap().unwrap();
    fixture.close().await;
}
