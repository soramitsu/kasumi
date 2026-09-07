#[tokio::test]
async fn guarded_stop_secure_sdk_preserves_exact_identity_and_native_authority() {
    use kasumi_client::{KasumiClient, KasumiClientConfig};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use kasumi_types::{
        BeginStagedTransaction, Mutation, Precondition, ReadAssertion, ReadSnapshotRequest,
        StagedChunk, StagedManifest, StagedOutcome, StopStagedTransaction,
    };
    let fixture = Fixture::new().await;
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let current = fixture.db.engine().generation().unwrap();
    let original = BeginStagedTransaction {
        transaction_id: "native-never-started".into(),
        ttl_ms: 60_000,
        manifest: StagedManifest::from_chunks(&[StagedChunk {
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "result".into(),
                expected: Precondition::Absent,
                body: json!({"value":1}),
            }],
        }])
        .unwrap(),
    };
    let request = StopStagedTransaction {
        original: original.clone(),
        admission: vec![
            ReadAssertion::Snapshot {
                incarnation: current.state.incarnation.clone(),
                policy_epoch: current.state.policy_epoch,
                schema_epoch: current.state.schema_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: kasumi_clock::EpochClock::system()
                    .unwrap()
                    .now_ms()
                    .unwrap()
                    + 60_000,
            },
        ],
    };
    drop(current);
    let data = fixture.data();
    let wire = |value: &Value| proto::StopStagedTransactionRequest {
        request_json: serde_json::to_vec(value).unwrap(),
    };
    let body = serde_json::to_value(&request).unwrap();
    for invalid in [
        json!({"original":original}),
        json!({"original":original,"admission":[],"tenant":"substitute"}),
        json!({"original":original,"admission":[]}),
    ] {
        assert!(
            data.stop_staged_transaction(native(wire(&invalid), &token))
                .await
                .is_err()
        );
    }
    let write_only = fixture.token("person", "tenant-a", "kasumi:write");
    let mut read_guard = request.clone();
    read_guard.admission.push(ReadAssertion::Collection {
        collection: "docs".into(),
        data_epoch: fixture.db.engine().generation().unwrap().state.collections["docs"].data_epoch,
    });
    assert_eq!(
        data.stop_staged_transaction(native(
            wire(&serde_json::to_value(&read_guard).unwrap()),
            &write_only
        ))
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        data.stop_staged_transaction(native(
            wire(&body),
            &fixture.token("person", "tenant-a", "kasumi:read")
        ))
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert!(
        data.stop_staged_transaction(native(
            wire(&body),
            &fixture.token("person", "other-tenant", "kasumi:read kasumi:write")
        ))
        .await
        .is_err()
    );
    assert!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .staged_transactions
            .is_empty()
    );

    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = ca.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::new(ca, key);
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
    let server = identity();
    let config_identity = identity();
    let pin = server.certificate_pin();
    let trusted = certificate.pem().into_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = KasumiClientConfig {
        endpoint: format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ),
        identity: config_identity,
        trusted_ca_pem: trusted.clone(),
        server_certificate_pins: BTreeSet::from([pin]),
    };
    let tls = kasumi_transport::server_config(
        &server,
        ClientAuthentication::Required {
            trusted_ca_pem: &trusted,
        },
    )
    .unwrap();
    let router = tonic::service::Routes::new(data.service()).into_axum_router();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        tls,
        router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let mut client = KasumiClient::connect(&config).await.unwrap();
    let bearer = token.strip_prefix("Bearer ").unwrap();
    let accepted = client
        .stop_staged_transaction(bearer, &request)
        .await
        .unwrap();
    assert!(matches!(accepted.outcome, StagedOutcome::Aborted { .. }));
    assert_eq!(accepted.expires_at_ms, None);
    let snapshot = client
        .read_snapshot(
            bearer,
            &ReadSnapshotRequest {
                documents: vec![kasumi_types::DocumentKey {
                    collection: "docs".into(),
                    id: "result".into(),
                }],
                queries: vec![],
            },
        )
        .await
        .unwrap();
    assert!(snapshot.documents[0].document.is_none());
    let mut fresh = request;
    fresh.admission = snapshot.read_assertions();
    fresh.admission.push(ReadAssertion::Before {
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60_000,
    });
    assert_eq!(
        client
            .stop_staged_transaction(bearer, &fresh)
            .await
            .unwrap()
            .outcome,
        accepted.outcome
    );
    assert!(
        client
            .begin_staged_transaction(bearer, &original)
            .await
            .is_err()
    );
    assert!(
        client
            .finalize_staged_transaction(bearer, &original.reference().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        client
            .staged_transaction_status(bearer, &original.reference().unwrap())
            .await
            .unwrap()
            .outcome,
        accepted.outcome
    );
    drop(client);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    fixture.close().await;
}
