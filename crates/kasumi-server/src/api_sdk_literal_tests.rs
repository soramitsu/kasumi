#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_sdk_query_feed_schema_preserve_literal_values_and_admission() {
    use kasumi_client::{
        ClientDecodeLimits, ClientError, ClientResources, JsonReadOptions, KasumiAdminClient,
        KasumiClient, KasumiClientConfig, KasumiClientPool, decode_mutation_json,
        decode_schema_change_json,
    };
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use kasumi_types::{
        AggregateFunction, Aggregation, ChangeFeedPage, ChangeFeedStart, CollectionRetentionClass,
        CollectionWriteMode, Precondition, Predicate, QueryRequest, ReadAssertion, ReadChangeFeed,
        ReadSchema, SchemaChange, SchemaChangeSet,
    };
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
    fn exhausted(error: ClientError) {
        assert!(
            matches!(
                error,
                ClientError::DecodeRejected {
                    code: Code::ResourceExhausted,
                    ..
                }
            ),
            "expected admitted decode exhaustion: {error}"
        );
    }

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
    let client_identity = identity();
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let routers = [
        tonic::service::Routes::new(fixture.data().service()).into_axum_router(),
        tonic::service::Routes::new(admin.service()).into_axum_router(),
    ];
    let mut configs = Vec::new();
    let mut listeners = Vec::new();
    for router in routers {
        let server_identity = identity();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configs.push(KasumiClientConfig {
            endpoint: format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ),
            identity: client_identity.clone(),
            trusted_ca_pem: ca_pem.clone(),
            server_certificate_pins: BTreeSet::from([server_identity.certificate_pin()]),
        });
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
            crate::tls::ListenerLimits::default(),
            fixture.audit.clone(),
            shutdown,
        ));
        listeners.push((stop, serving));
    }
    let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut data = tokio::time::timeout_at(connect_deadline, KasumiClient::connect(&configs[0]))
        .await
        .unwrap()
        .unwrap();
    let mut admin =
        tokio::time::timeout_at(connect_deadline, KasumiAdminClient::connect(&configs[1]))
            .await
            .unwrap()
            .unwrap();
    let token = fixture.token(
        "person",
        "tenant-a",
        "kasumi:read kasumi:write kasumi:admin",
    );
    let bearer = token.strip_prefix("Bearer ").unwrap();
    let owned_bearer = bearer.to_owned();
    let source: Arc<dyn kasumi_transport::credentials::CredentialSource> =
        Arc::new(move || Ok(zeroize::Zeroizing::new(owned_bearer.clone())));
    let mut pool =
        KasumiClientPool::new(BTreeMap::from([(1, configs[0].clone())]), source).unwrap();
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

    let policy_limits = admin
        .read_policy_limits(
            bearer,
            &kasumi_types::ReadPolicyLimits {
                tenant: "tenant-a".into(),
                expected_incarnation: fixture.incarnation.to_string(),
            },
            &options(),
        )
        .await
        .unwrap();
    assert_eq!(policy_limits.tenant, "tenant-a");
    assert_eq!(policy_limits.incarnation, fixture.incarnation.to_string());
    assert_eq!(policy_limits.limits.max_document_bytes, 1 << 20);
    drop(policy_limits);

    // Construct literal objects directly. No stock Value decoder is allowed to
    // pre-transform the expected payload before the SDK's byte boundary.
    let payload = json!({
        "number_marker":{"$serde_json::private::Number":"literal-number"},
        "raw_marker":{"$serde_json::private::RawValue":"not JSON"},
        "both":{"$serde_json::private::Number":"literal", "$serde_json::private::RawValue":"[1,2]"},
        "integer":"340282366920938463463374607431768211456".parse::<serde_json::Number>().unwrap(),
        "decimal":"90071992547409931234567890.123456789".parse::<serde_json::Number>().unwrap(),
        "exponent":"1e400".parse::<serde_json::Number>().unwrap()
    });
    assert!(payload["number_marker"].is_object());
    assert!(payload["raw_marker"].is_object());
    assert_eq!(
        payload["integer"].to_string(),
        "340282366920938463463374607431768211456"
    );
    assert_eq!(
        payload["decimal"].to_string(),
        "90071992547409931234567890.123456789"
    );
    // Number parsing canonicalizes the exponent sign without losing precision.
    assert_eq!(payload["exponent"].to_string(), "1e+400");
    let schema = json!({"type":"object","properties":{"payload":{"const":payload}},
        "required":["payload","n"]});
    let schema_request = ReadSchema {
        collections: BTreeSet::from(["literal".into()]),
    };
    let before = admin
        .read_schema(bearer, &schema_request, &options())
        .await
        .unwrap();
    assert!(before.collections["literal"].is_none());
    let schema_options = options();
    let schema_deadline_ms = kasumi_clock::EpochClock::system()
        .unwrap()
        .now_ms()
        .unwrap()
        + 10_000;
    let change = SchemaChangeSet {
        activation_id: "native-literal-schema".into(),
        expected_incarnation: before.incarnation.clone(),
        expected_schema_epoch: before.schema_epoch,
        read_set: vec![
            ReadAssertion::Snapshot {
                incarnation: before.incarnation.clone(),
                policy_epoch: before.policy_epoch,
                schema_epoch: before.schema_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: schema_deadline_ms,
            },
        ],
        changes: vec![SchemaChange::Create {
            definition: CollectionDefinition {
                name: "literal".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: schema.clone(),
                indexes: vec![],
                strict_read_audit: false,
            },
        }],
    };
    drop(before);
    let schema_bytes = String::from_utf8(serde_json::to_vec(&change).unwrap())
        .unwrap()
        .replace('$', "\\u0024");
    let admitted_change = decode_schema_change_json(schema_bytes.as_bytes(), &schema_options)
        .await
        .unwrap();
    assert_eq!(
        admitted_change.reference().unwrap().request_digest,
        change.reference().unwrap().request_digest
    );
    let activation = tokio::time::timeout_at(
        schema_options.deadline,
        admin.activate_schema(bearer, &admitted_change),
    )
    .await
    .unwrap()
    .unwrap();
    drop(admitted_change);
    let installed = admin
        .read_schema(bearer, &schema_request, &options())
        .await
        .unwrap();
    assert!(installed.revision >= activation.revision);
    assert_eq!(installed.incarnation, fixture.incarnation.to_string());
    assert_eq!(
        installed.collections["literal"]
            .as_ref()
            .unwrap()
            .definition
            .schema,
        schema
    );
    drop(installed);
    drained(&resources).await;

    let batch = MutationBatch {
        idempotency_key: "native-literal-two".into(),
        read_set: vec![],
        operations: ["a", "b"]
            .map(|id| Mutation::Put {
                collection: "literal".into(),
                id: id.into(),
                expected: Precondition::Absent,
                body: json!({"payload":payload,"n":7}),
            })
            .into(),
    };
    let batch_bytes = String::from_utf8(serde_json::to_vec(&batch).unwrap())
        .unwrap()
        .replace('$', "\\u0024");
    let mutation_options = options();
    let admitted_batch = decode_mutation_json(batch_bytes.as_bytes(), &mutation_options)
        .await
        .unwrap();
    assert_eq!(admitted_batch.digest().unwrap(), batch.digest().unwrap());
    let receipt = pool
        .mutate(
            &admitted_batch,
            mutation_options
                .deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
        .unwrap();
    drop(admitted_batch);
    drained(&resources).await;

    let query = QueryRequest {
        collection: "literal".into(),
        filter: Predicate::All,
        sort: vec![],
        projection: vec![],
        aggregates: vec![],
        group_by: vec![],
        text: None,
        limit: 1,
        cursor: None,
        allow_scan: true,
    };
    let first = pool.query(&query, &options()).await.unwrap();
    let original_query_revision = first.response().revision;
    let original_cursor = first.response().cursor.clone().unwrap();
    assert_eq!(first.response().rows[0].id, "a");
    assert_eq!(first.response().rows[0].version, receipt.revision);
    assert_eq!(first.response().rows[0].body["payload"], payload);
    let retained = first.clone();
    drop(first);
    assert!(resources.usage().accounted_bytes > 0);
    let later = MutationBatch {
        idempotency_key: "native-literal-later".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "literal".into(),
            id: "c".into(),
            expected: Precondition::Absent,
            body: json!({"payload":payload,"n":9}),
        }],
    };
    let later_bytes = serde_json::to_vec(&later).unwrap();
    let later_options = options();
    let admitted_later = decode_mutation_json(&later_bytes, &later_options)
        .await
        .unwrap();
    let later_receipt = pool
        .mutate(
            &admitted_later,
            later_options
                .deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
        .unwrap();
    drop(admitted_later);
    assert!(later_receipt.revision > original_query_revision);
    let second = pool.next_query_page(&retained, &options()).await.unwrap();
    assert_eq!(
        retained.response().cursor.as_deref(),
        Some(original_cursor.as_str())
    );
    assert_eq!(second.response().revision, original_query_revision);
    assert_eq!(second.response().rows.len(), 1);
    assert_eq!(second.response().rows[0].id, "b");
    assert_eq!(second.response().rows[0].body["payload"], payload);
    assert!(second.response().cursor.is_none());
    drop(second);
    drop(retained);
    drained(&resources).await;

    let mut aggregate = query.clone();
    aggregate.limit = 16;
    aggregate.aggregates = [
        "$serde_json::private::Number",
        "$serde_json::private::RawValue",
    ]
    .map(|alias| Aggregation {
        alias: alias.into(),
        function: AggregateFunction::Count,
        field: None,
        scale: None,
    })
    .into();
    let result = data.query(bearer, &aggregate, &options()).await.unwrap();
    assert_eq!(result.rows.len(), 3);
    assert_eq!(result.aggregates.len(), 1);
    assert_eq!(
        result.aggregates[0]["values"],
        json!({
            "$serde_json::private::Number":3, "$serde_json::private::RawValue":3
        })
    );
    let shared_result = result.clone();
    drop(result);
    assert!(resources.usage().live_owners > 0);
    drop(shared_result);
    drained(&resources).await;

    let feed_request = ReadChangeFeed {
        collections: BTreeSet::from(["literal".into()]),
        start: ChangeFeedStart::Beginning,
        limit: 1,
    };
    let feed = data
        .read_change_feed(bearer, &feed_request, &options())
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, next, .. } = &*feed else {
        panic!("unexpected retention gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].revision, receipt.revision);
    assert_eq!(
        events[0].document.as_ref().unwrap().body["payload"],
        payload
    );
    let original_feed_cursor = next.clone();
    drop(feed);
    let continue_feed = ReadChangeFeed {
        start: ChangeFeedStart::After {
            cursor: original_feed_cursor.clone(),
        },
        ..feed_request.clone()
    };
    let feed = data
        .read_change_feed(bearer, &continue_feed, &options())
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, next, .. } = &*feed else {
        panic!("unexpected retention gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "b");
    assert_eq!(events[0].revision, receipt.revision);
    assert_eq!(
        events[0].document.as_ref().unwrap().body["payload"],
        payload
    );
    assert_eq!(next.tenant, original_feed_cursor.tenant);
    assert_eq!(next.principal, original_feed_cursor.principal);
    assert_eq!(next.incarnation, original_feed_cursor.incarnation);
    assert_eq!(next.collections, original_feed_cursor.collections);
    assert!(next.after_sequence > original_feed_cursor.after_sequence);
    drop(feed);
    drained(&resources).await;

    // Small response numeric budget leaves the requests admissible but rejects
    // actual returned literal bodies. Failure must not leak a worker reservation
    // or alter committed writes, and the same original cursor remains usable.
    let mut small = options();
    small.limits.max_number_bytes = 8;
    exhausted(data.query(bearer, &query, &small).await.unwrap_err());
    exhausted(
        data.read_change_feed(bearer, &continue_feed, &small)
            .await
            .unwrap_err(),
    );
    exhausted(
        admin
            .read_schema(bearer, &schema_request, &small)
            .await
            .unwrap_err(),
    );
    drained(&resources).await;
    let feed = data
        .read_change_feed(bearer, &continue_feed, &options())
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, .. } = &*feed else {
        panic!("unexpected retention gap")
    };
    assert_eq!(events[0].id, "b");
    assert_eq!(events[0].revision, receipt.revision);
    drop(feed);
    let mut expired = options();
    expired.deadline = tokio::time::Instant::now();
    assert!(matches!(
        data.query(bearer, &query, &expired).await.unwrap_err(),
        ClientError::DecodeRejected {
            code: Code::DeadlineExceeded,
            ..
        }
    ));
    drained(&resources).await;
    let installed = admin
        .read_schema(bearer, &schema_request, &options())
        .await
        .unwrap();
    assert_eq!(
        installed.collections["literal"]
            .as_ref()
            .unwrap()
            .definition
            .schema,
        schema
    );
    assert_eq!(
        installed.collections["literal"]
            .as_ref()
            .unwrap()
            .data_epoch,
        later_receipt.revision
    );
    drop(installed);
    drained(&resources).await;

    drop(pool);
    drop(data);
    drop(admin);
    for (stop, serving) in listeners {
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    fixture.close().await;
}
