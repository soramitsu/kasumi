#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_level_client_reads_writes_pages_and_reports_database_codes() {
    use kasumi_client::{KasumiClientConfig, prelude::*};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

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
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let reject_next = Arc::new(AtomicBool::new(false));
    let reject = reject_next.clone();
    let service = tonic::service::interceptor::InterceptedService::new(
        fixture.data().service(),
        move |request: tonic::Request<()>| {
            if reject.swap(false, Ordering::SeqCst) {
                return Err(tonic::Status::unavailable("retry this operation"));
            }
            Ok(request)
        },
    );
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        kasumi_transport::server_config(
            &server_identity,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap(),
        tonic::service::Routes::new(service).into_axum_router(),
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let bearer = token.strip_prefix("Bearer ").unwrap().to_owned();
    let credential_reads = Arc::new(AtomicUsize::new(0));
    let reads = credential_reads.clone();
    let db = tokio::time::timeout(
        Duration::from_secs(10),
        Kasumi::connect(&config, move || {
            reads.fetch_add(1, Ordering::SeqCst);
            Ok(zeroize::Zeroizing::new(bearer.clone()))
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .with_timeout(Duration::from_secs(10));

    assert_eq!(db.get("docs", "a").await.unwrap(), None);
    let missing = db.get("no-such-collection", "a").await.unwrap_err();
    assert_eq!(missing.code(), Some(ErrorCode::NotFound));

    let reads_before_retry = credential_reads.load(Ordering::SeqCst);
    reject_next.store(true, Ordering::SeqCst);
    let receipt = db
        .mutate(
            &MutationBatch::new()
                .insert("docs", "a", json!({"n": 1, "tag": "x"}))
                .insert("docs", "b", json!({"n": 2}))
                .insert("docs", "c", json!({"n": 3, "nested": {"k": "v", "other": true}})),
        )
        .await
        .unwrap();
    assert!(!reject_next.load(Ordering::SeqCst));
    assert_eq!(
        credential_reads.load(Ordering::SeqCst),
        reads_before_retry + 1,
        "one mutation keeps its original credential across transport retries"
    );
    let duplicate = db
        .mutate(&MutationBatch::new().insert("docs", "a", json!({"n": 9})))
        .await
        .unwrap_err();
    assert_eq!(duplicate.code(), Some(ErrorCode::Conflict));

    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Row {
        n: u64,
    }
    let typed = db.get_as::<Row>("docs", "a").await.unwrap().unwrap();
    assert_eq!((typed.body, typed.version), (Row { n: 1 }, receipt.revision));
    db.mutate(&MutationBatch::new().replace("docs", "a", json!({"n": 1, "tag": "y"}), typed.version))
        .await
        .unwrap();

    let query = QueryRequest::new("docs")
        .filter(Filter::new().gte("/n", 2))
        .sort_desc("/n")
        .limit(1);
    let first = db.query(&query).await.unwrap();
    assert_eq!(first.rows()[0].id, "c");
    assert!(first.has_more());
    let second = db.next_page(&first).await.unwrap().unwrap();
    assert_eq!(second.rows()[0].id, "b");
    assert_eq!(second.revision(), first.revision());
    assert!(db.next_page(&second).await.unwrap().is_none());
    let all = db.query_all(&query).await.unwrap();
    assert_eq!(
        all.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        ["c", "b"]
    );
    assert_eq!(
        first.decode::<Row>().unwrap()[0].body,
        Row { n: 3 }
    );

    let selected = db
        .query(
            &QueryRequest::new("docs")
                .filter(Filter::new().eq("/n", 3))
                .select(["/nested/k"]),
        )
        .await
        .unwrap();
    assert_eq!(selected.rows()[0].body, json!({"nested": {"k": "v"}}));

    let totals = db
        .query(
            &QueryRequest::new("docs")
                .aggregate("count", Aggregation::count())
                .aggregate("total", Aggregation::sum("/n")),
        )
        .await
        .unwrap();
    assert!(totals.rows().is_empty());
    assert_eq!(
        totals.aggregates(),
        [json!({"group": {}, "values": {"count": 3, "total": 6}})]
    );
    assert!(matches!(
        db.query_all(&QueryRequest::new("docs").aggregate("count", Aggregation::count()))
            .await,
        Err(kasumi_client::ClientError::DecodeRejected {
            code: tonic::Code::InvalidArgument,
            ..
        })
    ));

    let unindexed = db
        .query(&QueryRequest::new("docs").filter(Filter::new().eq("/tag", "y")))
        .await
        .unwrap_err();
    assert_eq!(unindexed.code(), Some(ErrorCode::IndexRequired));
    let scanned = db
        .query(
            &QueryRequest::new("docs")
                .filter(Filter::new().eq("/tag", "y"))
                .allow_scan(),
        )
        .await
        .unwrap();
    assert_eq!(scanned.rows()[0].id, "a");

    // Partial updates merge into the stored document.
    db.patch("docs", "c", json!({"nested": {"other": null, "added": 1}, "n": 4}))
        .await
        .unwrap();
    assert_eq!(
        db.get("docs", "c").await.unwrap().unwrap().body,
        json!({"n": 4, "nested": {"k": "v", "added": 1}})
    );
    let missing = db.patch("docs", "zzz", json!({"n": 1})).await.unwrap_err();
    assert_eq!(missing.code(), Some(ErrorCode::NotFound));
    let definitions = db.collections().await.unwrap();
    assert_eq!(
        definitions.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        ["docs"]
    );

    // The shell commands drive the same client and print one JSON per line.
    async fn cli(db: &Kasumi, command: &str) -> anyhow::Result<Vec<Value>> {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        let mut out = Vec::new();
        crate::data_cli::execute(crate::data_cli::parse(&arguments)?, db, &mut out).await?;
        Ok(String::from_utf8(out)?
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect())
    }
    let receipt = cli(&db, r#"put docs d {"n":5,"tag":"cli"} --if absent --key cli-put"#)
        .await
        .unwrap();
    assert!(receipt[0]["revision"].as_u64().unwrap() > 0);
    cli(&db, r#"patch docs d {"tag":null,"extra":true}"#)
        .await
        .unwrap();
    let document = cli(&db, "get docs d").await.unwrap();
    assert_eq!(document[0]["body"], json!({"n": 5, "extra": true}));
    let rows = cli(&db, r#"query docs {"/n":{"gte":3}} --sort -/n --limit 1 --all"#)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|row| row["id"].clone()).collect::<Vec<_>>(),
        [json!("d"), json!("c")]
    );
    let json_rows = cli(&db, r#"query --json {"collection":"docs","filter":{"/n":{"gte":3}},"sort":["-/n"],"limit":1} --all"#)
        .await
        .unwrap();
    assert_eq!(json_rows, rows);
    let groups = cli(&db, r#"query --json {"collection":"docs","aggregate":{"n":{"count":"*"}}}"#)
        .await
        .unwrap();
    assert_eq!(groups, [json!({"group": {}, "values": {"n": 4}})]);
    assert_eq!(cli(&db, "collections").await.unwrap()[0]["name"], json!("docs"));
    cli(&db, "delete docs d").await.unwrap();
    let error = cli(&db, "get docs d").await.unwrap_err();
    assert!(error.to_string().contains("docs/d not found"), "{error}");

    drop((db, first, second, selected, totals, scanned));
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.close().await;
}

#[test]
fn malformed_native_requests_explain_the_fix() {
    let error = crate::api::decode_json::<kasumi_types::QueryRequest>(
        br#"{"collection":"docs","sort":["amount"]}"#,
    )
    .unwrap_err();
    assert_eq!(error.code, kasumi_types::ErrorCode::InvalidArgument);
    assert!(error.message.contains("-/amount"), "{}", error.message);
}
