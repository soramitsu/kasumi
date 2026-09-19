// Included in api::tests to reuse the actual encrypted database and identity
// fixture. Transport assertions use the real pinned mTLS listener and SDK.
fn ordered_rpc_definition() -> CollectionDefinition {
    CollectionDefinition {
        name: "ordered".into(),
        schema: json!({"type":"object"}),
        indexes: vec![IndexDefinition {
            name: "scope_at_id".into(),
            fields: vec![
                IndexField {
                    path: "/scope".into(),
                    kind: ScalarType::String,
                },
                IndexField {
                    path: "/at".into(),
                    kind: ScalarType::Number,
                },
                IndexField {
                    path: "/literalId".into(),
                    kind: ScalarType::String,
                },
            ],
            unique: true,
            text: None,
        }],
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        strict_read_audit: true,
    }
}
fn ordered_rpc_request() -> kasumi_types::OrderedSeekRequest {
    kasumi_types::OrderedSeekRequest {
        collection: "ordered".into(),
        index: "scope_at_id".into(),
        prefix: vec![json!("employee")],
        lower: None,
        upper: None,
        direction: kasumi_types::Direction::Asc,
        limit: 2,
        continuation: None,
    }
}
fn ordered_rpc_installer() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "person".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "ordered-rpc-installation".into(),
    }
}
fn ordered_rpc_error_code(error: kasumi_client::ClientError) -> Code {
    match error {
        kasumi_client::ClientError::Transport(status) => status.code(),
        kasumi_client::ClientError::DecodeRejected { code, .. } => code,
        other => panic!("unexpected ordered seek failure: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_tls_ordered_seek_preserves_literals_epochs_and_owned_continuation() {
    use kasumi_client::{
        ClientDecodeLimits, ClientResources, JsonReadOptions, KasumiClient, KasumiClientConfig,
        KasumiClientPool, decode_mutation_json,
    };
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use kasumi_types::Precondition;
    use std::{collections::BTreeMap, time::Duration};

    async fn drained(resources: &Arc<ClientResources>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while resources.usage().live_owners != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resources.usage().accounted_bytes, 0);
    }
    let fixture = Fixture::new().await;
    fixture
        .db
        .administer(
            ordered_rpc_installer(),
            Operation::CreateCollection(ordered_rpc_definition()),
        )
        .await
        .unwrap();
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
    let server = identity();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = KasumiClientConfig {
        endpoint: format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ),
        identity: identity(),
        trusted_ca_pem: ca_pem.clone(),
        server_certificate_pins: BTreeSet::from([server.certificate_pin()]),
    };
    let router = tonic::service::Routes::new(fixture.data().service()).into_axum_router();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        kasumi_transport::server_config(
            &server,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap(),
        router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let mut data = tokio::time::timeout(Duration::from_secs(10), KasumiClient::connect(&config))
        .await
        .unwrap()
        .unwrap();
    let authorization = fixture.token(
        "person",
        "tenant-a",
        "kasumi:read kasumi:write kasumi:admin",
    );
    let bearer = authorization.strip_prefix("Bearer ").unwrap();
    let current = Arc::new(std::sync::RwLock::new(bearer.to_owned()));
    let selected = current.clone();
    let credential: Arc<dyn kasumi_transport::credentials::CredentialSource> =
        Arc::new(move || Ok(zeroize::Zeroizing::new(selected.read().unwrap().clone())));
    let endpoints = BTreeMap::from([(7, config)]);
    let mut pool = KasumiClientPool::new(endpoints.clone(), credential.clone()).unwrap();
    let resources = ClientResources::new(128 << 20, 8).unwrap();
    let options = || JsonReadOptions {
        resources: resources.clone(),
        limits: ClientDecodeLimits {
            max_request_bytes: 128 << 10,
            max_wire_bytes: 128 << 10,
            max_json_bytes: 128 << 10,
            max_depth: 32,
            max_nodes: 4096,
            max_string_bytes: 4096,
            max_number_bytes: 512,
            max_rows: 16,
            max_decoded_bytes: 4 << 20,
        },
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
    };
    // Construct literal JSON values without stock Value deserialization first.
    let at = "340282366920938463463374607431768211456"
        .parse::<serde_json::Number>()
        .unwrap();
    let payload = json!({
        "number_marker":{"$serde_json::private::Number":"literal-number"},
        "raw_marker":{"$serde_json::private::RawValue":"not JSON"},
        "decimal":"90071992547409931234567890.123456789".parse::<serde_json::Number>().unwrap(),
        "exponent":"1e400".parse::<serde_json::Number>().unwrap(),
    });
    let batch = MutationBatch {
        idempotency_key: "ordered-rpc-literals".into(),
        read_set: vec![],
        operations: ["a", "a-longer", "b", "c", "other"]
            .map(|id| Mutation::Put {
                collection: "ordered".into(),
                id: id.into(),
                expected: Precondition::Absent,
                body: json!({"scope":if id == "other" { "another-employee" } else { "employee" },
                    "at":at, "literalId":id, "payload":payload}),
            })
            .into(),
    };
    let bytes = String::from_utf8(serde_json::to_vec(&batch).unwrap())
        .unwrap()
        .replace('$', "\\u0024");
    let write_options = options();
    let admitted = decode_mutation_json(bytes.as_bytes(), &write_options)
        .await
        .unwrap();
    let receipt = pool
        .mutate(&admitted, Duration::from_secs(10))
        .await
        .unwrap();
    drop(admitted);
    drained(&resources).await;

    let request = ordered_rpc_request();
    let first = pool.ordered_seek(&request, &options()).await.unwrap();
    assert_eq!(first.member(), 7);
    let response = first.response();
    assert_eq!(response.tenant, "tenant-a");
    assert_eq!(response.incarnation, fixture.incarnation.to_string());
    assert_eq!(response.collection_epoch, receipt.revision);
    assert_eq!(response.revision, response.observed_revision);
    assert_eq!(response.index_entries_visited, 3);
    assert_eq!(
        response
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "a-longer"]
    );
    for row in &response.rows {
        assert_eq!(row.body["payload"], payload);
        assert_eq!(row.body["at"].to_string(), at.to_string());
        assert_eq!(row.version, receipt.revision);
    }
    let continuation = response.continuation.clone().unwrap();
    assert_eq!(
        continuation.after_key,
        vec![json!("employee"), json!(at), json!("a-longer")]
    );
    assert_eq!(continuation.collection_epoch, response.collection_epoch);
    assert_eq!(continuation.policy_epoch, response.policy_epoch);
    assert_eq!(continuation.schema_epoch, response.schema_epoch);
    assert_eq!(continuation.index_sha256, response.index_sha256);
    assert_eq!(continuation.request_sha256, response.request_sha256);
    let original_revision = response.revision;
    let held = first.clone();
    drop(first);
    assert!(resources.usage().accounted_bytes > 0);

    let second = pool
        .next_ordered_seek_page(&held, &options())
        .await
        .unwrap();
    assert_eq!(second.member(), held.member());
    assert_eq!(second.response().revision, original_revision);
    assert!(
        second.response().observed_revision > original_revision,
        "strict read audit advances global revision without changing source data"
    );
    assert_eq!(
        second.response().collection_epoch,
        held.response().collection_epoch
    );
    assert_eq!(
        second
            .response()
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["b", "c"]
    );
    assert_eq!(second.response().index_entries_visited, 2);
    assert!(second.response().continuation.is_none());
    drop(second);
    let mut foreign = KasumiClientPool::new(endpoints, credential).unwrap();
    assert_eq!(
        ordered_rpc_error_code(
            foreign
                .next_ordered_seek_page(&held, &options())
                .await
                .err()
                .unwrap()
        ),
        Code::InvalidArgument
    );
    drop(foreign);

    // A continuation is checked against both original request and current source.
    for mutate in 0..6 {
        let mut changed = request.clone();
        let mut cursor = continuation.clone();
        match mutate {
            0 => cursor.tenant = "tenant-other".into(),
            1 => cursor.incarnation = uuid::Uuid::new_v4().to_string(),
            2 => cursor.collection_epoch += 1,
            3 => cursor.policy_epoch += 1,
            4 => cursor.schema_epoch += 1,
            _ => cursor.index_sha256 = "0".repeat(64),
        }
        changed.continuation = Some(cursor);
        assert_eq!(
            ordered_rpc_error_code(
                data.ordered_seek(bearer, &changed, &options())
                    .await
                    .err()
                    .unwrap()
            ),
            Code::Aborted
        );
    }
    let mut changed_request = request.clone();
    changed_request.continuation = Some(continuation.clone());
    changed_request.prefix = vec![json!("another-employee")];
    // The SDK can reject an altered request before dispatch. This is a caller
    // validation failure, distinct from the server's changed-source conflict.
    assert_eq!(
        ordered_rpc_error_code(
            data.ordered_seek(bearer, &changed_request, &options())
                .await
                .err()
                .unwrap()
        ),
        Code::InvalidArgument
    );
    drop(changed_request);
    drop(continuation);
    drop(held);
    drained(&resources).await;

    let mut small = options();
    small.limits.max_number_bytes = 8; // Request is small; returned body/tuple is not.
    assert_eq!(
        ordered_rpc_error_code(
            data.ordered_seek(bearer, &request, &small)
                .await
                .err()
                .unwrap()
        ),
        Code::ResourceExhausted
    );
    drained(&resources).await;
    let mut expired = options();
    expired.deadline = tokio::time::Instant::now();
    assert_eq!(
        ordered_rpc_error_code(
            data.ordered_seek(bearer, &request, &expired)
                .await
                .err()
                .unwrap()
        ),
        Code::DeadlineExceeded
    );
    drained(&resources).await;
    let reader = fixture.token("reader", "tenant-a", "kasumi:read");
    assert_eq!(
        ordered_rpc_error_code(
            data.ordered_seek(
                reader.strip_prefix("Bearer ").unwrap(),
                &request,
                &options()
            )
            .await
            .err()
            .unwrap()
        ),
        Code::PermissionDenied
    );
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-key".into());
    header.typ = Some("at+jwt".into());
    let expired_token = encode(
        &header,
        &json!({"sub":"person","tenant":"tenant-a","scope":"kasumi:read",
        "iss":"https://issuer.example","aud":"https://kasumi.example/mcp","exp":1,
        "kasumi_resource":{"kind":"database","incarnation":fixture.incarnation}}),
        &fixture.key,
    )
    .unwrap();
    *current.write().unwrap() = expired_token;
    assert_eq!(
        ordered_rpc_error_code(pool.ordered_seek(&request, &options()).await.err().unwrap()),
        Code::Unauthenticated
    );
    drained(&resources).await;
    *current.write().unwrap() = bearer.to_owned();

    let page = pool.ordered_seek(&request, &options()).await.unwrap();
    let later = MutationBatch {
        idempotency_key: "ordered-rpc-source-change".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "ordered".into(),
            id: "later".into(),
            expected: Precondition::Absent,
            body: json!({"scope":"employee","at":at,"literalId":"later"}),
        }],
    };
    fixture
        .db
        .mutate(ordered_rpc_installer(), later)
        .await
        .unwrap();
    assert_eq!(
        ordered_rpc_error_code(
            pool.next_ordered_seek_page(&page, &options())
                .await
                .err()
                .unwrap()
        ),
        Code::Aborted
    );
    drop(page);
    drained(&resources).await;
    let page = pool.ordered_seek(&request, &options()).await.unwrap();
    fixture
        .db
        .administer(
            ordered_rpc_installer(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "person".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Read, Action::Admin, Action::Write]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        ordered_rpc_error_code(
            pool.next_ordered_seek_page(&page, &options())
                .await
                .err()
                .unwrap()
        ),
        Code::Aborted,
        "a changed current policy cannot refresh the original source"
    );
    drop(page);
    drained(&resources).await;
    let page = pool.ordered_seek(&request, &options()).await.unwrap();
    fixture
        .db
        .administer(
            ordered_rpc_installer(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "person".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin, Action::Write]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        ordered_rpc_error_code(
            pool.next_ordered_seek_page(&page, &options())
                .await
                .err()
                .unwrap()
        ),
        Code::PermissionDenied
    );
    drop(page);
    drained(&resources).await;
    drop(pool);
    drop(data);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn native_ordered_seek_encoded_release_rechecks_original_credential_deadline() {
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock(AtomicU64);
    impl kasumi_clock::LeaseClock for Clock {
        fn now(&self) -> std::time::Duration {
            std::time::Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    let fixture = Fixture::new().await;
    fixture
        .db
        .administer(
            ordered_rpc_installer(),
            Operation::CreateCollection(ordered_rpc_definition()),
        )
        .await
        .unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let epoch =
        kasumi_clock::EpochClock::new(clock.clone(), Arc::new(kasumi_clock::SystemWallClock))
            .unwrap();
    let observation = epoch.observe().unwrap();
    let mut context = ordered_rpc_installer();
    context.request_id = "ordered-seek-encoded-expiry".into();
    context.authorization = kasumi_types::RequestAuthorization::from_verified_credential(
        observation.utc_ms() + 1000,
        &observation,
        kasumi_types::CredentialResource::Database {
            incarnation: fixture.incarnation,
        },
    )
    .unwrap();
    let fence = fixture.db.response_fence(&context).unwrap();
    let result = fixture
        .db
        .ordered_seek(&context, ordered_rpc_request())
        .await
        .unwrap();
    let encoded = proto::OrderedSeekResponse {
        response_json: encode_json(&result).unwrap(),
    };
    assert!(!encoded.response_json.is_empty());
    // Exercise the actual shared final-release boundary deterministically after
    // encoding. This is separate from the real TLS transport test above.
    clock.0.store(1000, Ordering::SeqCst);
    let error = release_response(&fixture.auth, &context, fence, encoded, false)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(
        fixture
            .audit_store
            .scan("security.audit")
            .unwrap()
            .iter()
            .any(|(_, bytes)| {
                let event: Value = serde_json::from_slice(bytes).unwrap();
                event["event"]["kind"] == "access_denied"
                    && event["event"]["request_id"] == context.request_id
            })
    );
    fixture.close().await;
}
