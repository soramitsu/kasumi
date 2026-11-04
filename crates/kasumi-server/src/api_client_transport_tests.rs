#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_client_reads_progress_while_its_mutation_connection_is_full() {
    use kasumi_client::{KasumiClientConfig, prelude::*};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    let fixture = Fixture::new().await;
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem().into_bytes();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let server_identity = identity();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = KasumiClientConfig {
        endpoint: format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ),
        identity: identity(),
        trusted_ca_pem: ca_pem.clone(),
        server_certificate_pins: BTreeSet::from([server_identity.certificate_pin()]),
    };
    let armed = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let router = tonic::service::Routes::new(fixture.data().service())
        .into_axum_router()
        .layer(axum::middleware::from_fn({
            let armed = armed.clone();
            let entered = entered.clone();
            let release = release.clone();
            move |request: HttpRequest<Body>, next: axum::middleware::Next| {
                let armed = armed.clone();
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    if request.uri().path() == "/kasumi.v1.KasumiData/Mutate"
                        && armed.swap(false, Ordering::SeqCst)
                    {
                        // Hold the HTTP/2 stream before application admission:
                        // no pending consensus write should block the read barrier.
                        entered.notify_one();
                        release.notified().await;
                    }
                    next.run(request).await
                }
            }
        }));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        kasumi_transport::server_config(
            &server_identity,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap(),
        router,
        crate::tls::ListenerLimits {
            max_connections: 2,
            max_http2_streams: 1,
            ..Default::default()
        },
        fixture.audit.clone(),
        shutdown,
    ));
    let bearer = fixture
        .token("person", "tenant-a", "kasumi:read kasumi:write")
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let credential = bearer.clone();
    let db = Kasumi::connect(&config, move || {
        Ok(zeroize::Zeroizing::new(credential.clone()))
    })
    .await
    .unwrap()
    .with_timeout(Duration::from_secs(10));
    let initial_batch = MutationBatch::new().insert("docs", "existing", json!({"n": 1}));
    let initial = db.mutate(&initial_batch).await.unwrap();
    let scope = kasumi_types::MutationReceiptScope {
        tenant: "tenant-a".into(),
        incarnation: fixture.incarnation.to_string(),
        principal: "person".into(),
    };

    armed.store(true, Ordering::SeqCst);
    let writer = db.clone();
    let mut mutation = tokio::spawn(async move {
        writer
            .mutate(&MutationBatch::new().insert("docs", "pending", json!({"n": 2})))
            .await
    });
    let entered = tokio::time::timeout(Duration::from_secs(10), entered.notified()).await;
    let (read, resolved) = if entered.is_ok() {
        let mut client = db.client();
        let (read, resolved) = tokio::join!(
            db.get("docs", "existing"),
            client.resolve_mutation(&bearer, &scope, &initial_batch, Duration::from_secs(10)),
        );
        (Some(read), Some(resolved))
    } else {
        (None, None)
    };
    let mutation_still_waiting = !mutation.is_finished();

    // Always release and join the writer before asserting read progress, even
    // when a shared-connection regression makes either read hit its deadline.
    release.notify_one();
    let written = tokio::time::timeout(Duration::from_secs(10), &mut mutation).await;
    if written.is_err() {
        mutation.abort();
        let _ = mutation.await;
    }
    drop(db);
    stop.send_replace(true);
    let served = serving.await;
    fixture.close().await;

    entered.expect("mutation did not enter its held HTTP/2 stream");
    let document = read
        .expect("read was attempted")
        .expect("Get must not queue behind the held mutation")
        .expect("pre-existing document remains visible");
    assert_eq!(document.body, json!({"n": 1}));
    assert_eq!(document.version, initial.revision);
    let resolved = resolved
        .expect("receipt read was attempted")
        .expect("receipt resolution must not queue behind the held mutation")
        .expect("initial committed receipt remains available");
    assert_eq!(resolved.scope, scope);
    assert_eq!(resolved.request_digest, initial_batch.digest().unwrap());
    assert_eq!(resolved.outcome.unwrap(), initial);
    assert!(
        mutation_still_waiting,
        "read finished only after mutation exited"
    );
    written
        .expect("released mutation did not finish")
        .expect("mutation task panicked")
        .expect("released mutation failed");
    served.unwrap().unwrap();
}
