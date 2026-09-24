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
        scope: kasumi_types::StagedTransactionScope {
            tenant: "tenant-a".into(),
            principal: "person".into(),
            incarnation: fixture.incarnation.to_string(),
        },
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
    let snapshot_resources = kasumi_client::ClientResources::new(16 << 20, 8).unwrap();
    let snapshot_options = |duration| kasumi_client::SnapshotReadOptions {
        resources: snapshot_resources.clone(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 64 << 10,
            max_json_bytes: 64 << 10,
            max_decoded_bytes: 2 << 20,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + duration,
        expected_incarnation: fixture.incarnation,
    };
    let snapshot = client
        .read_snapshot(
            bearer,
            &ReadSnapshotRequest {
                documents: vec![kasumi_types::DocumentKey {
                    collection: "docs".into(),
                    id: "result".into(),
                }],
                queries: vec![],
                time_bounds: None,
            },
            &snapshot_options(std::time::Duration::from_secs(4)),
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

#[tokio::test]
async fn native_staged_original_scope_cannot_be_reinterpreted_by_another_authorized_principal() {
    use kasumi_types::{
        AppendStagedChunk, BeginStagedTransaction, Mutation, Precondition, ReadAssertion,
        StagedChunk, StagedManifest, StagedOutcome, StagedTransactionStatus, StopStagedTransaction,
    };
    let fixture = Fixture::new().await;
    let mut policy = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .policy
        .clone();
    policy.grants.push(Grant {
        principal: "replacement".into(),
        collection: None,
        actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
    });
    fixture
        .db
        .administer(
            RequestContext {
                authorization: kasumi_types::RequestAuthorization::service_identity(),
                principal: "person".into(),
                tenant: "tenant-a".into(),
                request_id: "grant-second-writer".into(),
                scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            },
            Operation::SetPolicy(policy),
        )
        .await
        .unwrap();
    let a = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let b = fixture.token("replacement", "tenant-a", "kasumi:read kasumi:write");
    let data = fixture.data();
    let chunk = StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "scope-result".into(),
            expected: Precondition::Absent,
            body: json!({"owner":"person"}),
        }],
    };
    let original = BeginStagedTransaction {
        scope: kasumi_types::StagedTransactionScope {
            tenant: "tenant-a".into(),
            principal: "person".into(),
            incarnation: fixture.incarnation.to_string(),
        },
        transaction_id: "original-identity".into(),
        manifest: StagedManifest::from_chunks(std::slice::from_ref(&chunk)).unwrap(),
        ttl_ms: 60_000,
    };
    let reference = original.reference().unwrap();
    data.begin_staged_transaction(native(
        proto::BeginStagedTransactionRequest {
            request_json: serde_json::to_vec(&original).unwrap(),
        },
        &a,
    ))
    .await
    .unwrap();
    let current = fixture.db.engine().generation().unwrap();
    let stop = StopStagedTransaction {
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
    let foreign_stop = data
        .stop_staged_transaction(native(
            proto::StopStagedTransactionRequest {
                request_json: serde_json::to_vec(&stop).unwrap(),
            },
            &b,
        ))
        .await;
    // Every operation must retain A's original scope; B has independent write
    // and administrator grants, so these are scope failures, not missing RBAC.
    for field in 0..4 {
        let mut changed = original.clone();
        let bearer = if field == 0 { &b } else { &a };
        match field {
            0 => {}
            1 => changed.scope.principal = "replacement".into(),
            2 => changed.scope.tenant = "another-tenant".into(),
            _ => changed.scope.incarnation = uuid::Uuid::new_v4().to_string(),
        }
        let reference = changed.reference().unwrap();
        assert!(
            data.begin_staged_transaction(native(
                proto::BeginStagedTransactionRequest {
                    request_json: serde_json::to_vec(&changed).unwrap(),
                },
                bearer
            ))
            .await
            .is_err()
        );
        assert!(
            data.append_staged_chunk(native(
                proto::AppendStagedChunkRequest {
                    request_json: serde_json::to_vec(&AppendStagedChunk {
                        transaction: reference.clone(),
                        index: 0,
                        chunk: chunk.clone()
                    })
                    .unwrap(),
                },
                bearer
            ))
            .await
            .is_err()
        );
        assert!(
            data.finalize_staged_transaction(native(
                proto::StagedTransactionReference {
                    request_json: serde_json::to_vec(&reference).unwrap(),
                },
                bearer
            ))
            .await
            .is_err()
        );
        assert!(
            data.staged_transaction_status(native(
                proto::StagedTransactionReference {
                    request_json: serde_json::to_vec(&reference).unwrap(),
                },
                bearer
            ))
            .await
            .is_err()
        );
        assert!(
            data.stop_staged_transaction(native(
                proto::StopStagedTransactionRequest {
                    request_json: serde_json::to_vec(&StopStagedTransaction {
                        original: changed,
                        admission: stop.admission.clone()
                    })
                    .unwrap(),
                },
                bearer
            ))
            .await
            .is_err()
        );
    }
    let mut missing = serde_json::to_value(&original).unwrap();
    missing.as_object_mut().unwrap().remove("scope");
    assert_eq!(
        data.begin_staged_transaction(native(
            proto::BeginStagedTransactionRequest {
                request_json: serde_json::to_vec(&missing).unwrap(),
            },
            &a
        ))
        .await
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .staged_transactions
            .len(),
        1
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-key".into());
    header.typ = Some("at+jwt".into());
    let renewed = format!("Bearer {}", jsonwebtoken::encode(&header, &json!({
        "sub":"person", "tenant":"tenant-a", "scope":"kasumi:read kasumi:write",
        "iss":"https://issuer.example", "aud":"https://kasumi.example/mcp", "exp":now+600,
        "jti":"renewed-original-principal", "kasumi_resource":{"kind":"database","incarnation":fixture.incarnation},
    }), &fixture.key).unwrap());
    assert_ne!(a, renewed);
    let observed = data
        .staged_transaction_status(native(
            proto::StagedTransactionReference {
                request_json: serde_json::to_vec(&reference).unwrap(),
            },
            &a,
        ))
        .await
        .unwrap()
        .into_inner();
    let observed: StagedTransactionStatus =
        serde_json::from_slice(&observed.response_json).unwrap();
    assert_eq!(observed.transaction, reference);
    assert!(matches!(observed.outcome, StagedOutcome::Uploading));
    data.append_staged_chunk(native(
        proto::AppendStagedChunkRequest {
            request_json: serde_json::to_vec(&AppendStagedChunk {
                transaction: reference.clone(),
                index: 0,
                chunk,
            })
            .unwrap(),
        },
        &renewed,
    ))
    .await
    .unwrap();
    data.finalize_staged_transaction(native(
        proto::StagedTransactionReference {
            request_json: serde_json::to_vec(&reference).unwrap(),
        },
        &renewed,
    ))
    .await
    .unwrap();
    assert!(
        fixture.db.engine().generation().unwrap().state.collections["docs"]
            .documents
            .contains_key("scope-result")
    );
    fixture.close().await;
    assert!(
        foreign_stop.is_err(),
        "foreign authorized principal acknowledged a stop while the original writer still committed: {foreign_stop:?}"
    );
}
