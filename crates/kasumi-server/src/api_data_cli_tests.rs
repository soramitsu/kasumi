#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_cli_runs_a_command_journal_through_an_installed_profile() {
    use kasumi_client::{ClientProfile, ProfileAuthorityEndpoint, ProfileTlsFiles};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::Duration};

    let fixture = Fixture::new().await;
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "person".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "journal-schema".into(),
    };
    for (name, write_mode) in [
        ("intents", kasumi_types::CollectionWriteMode::AppendOnly),
        ("claims", kasumi_types::CollectionWriteMode::Mutable),
        ("receipts", kasumi_types::CollectionWriteMode::AppendOnly),
    ] {
        fixture
            .db
            .administer(
                context.clone(),
                Operation::CreateCollection(CollectionDefinition {
                    name: name.into(),
                    write_mode,
                    retention_class: kasumi_types::CollectionRetentionClass::Operational,
                    schema: json!({"type": "object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                }),
            )
            .await
            .unwrap();
    }

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
        (certificate.pem(), key.serialize_pem())
    };
    let (server_certificate, server_key) = identity();
    let server =
        TlsIdentity::from_pem(server_certificate.as_bytes(), server_key.as_bytes()).unwrap();
    let (client_certificate, client_key) = identity();
    let trusted = certificate.pem().into_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let pin = hex::encode(server.certificate_pin());
    let write_private = |name: &str, bytes: &[u8]| {
        let path = fixture._dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let family_id = uuid::Uuid::new_v4();
    let profile = ClientProfile {
        format: 2,
        family_id,
        tenant: "tenant-a".into(),
        principal: "person".into(),
        resource: kasumi_types::CredentialResource::Database {
            incarnation: fixture.incarnation,
        },
        native_endpoint: endpoint.clone(),
        administrative_members: BTreeMap::from([(
            1,
            ProfileAuthorityEndpoint {
                endpoint: endpoint.clone(),
                certificate_pins: BTreeSet::from([pin.clone()]),
            },
        )]),
        mcp_endpoint: format!("{endpoint}/mcp"),
        identity: ProfileTlsFiles {
            certificate: write_private("client.crt", client_certificate.as_bytes()),
            private_key: write_private("client.key", client_key.as_bytes()),
        },
        server_ca: write_private("ca.crt", &trusted),
        native_certificate_pin: pin,
        bearer_file: write_private("bearer", token.strip_prefix("Bearer ").unwrap().as_bytes()),
    };
    let bytes = serde_json::to_vec(&profile).unwrap();
    let profile_path = write_private("profile.json", &bytes);
    let profile_path = profile_path.to_str().unwrap();
    let tls = kasumi_transport::server_config(
        &server,
        ClientAuthentication::Required {
            trusted_ca_pem: &trusted,
        },
    )
    .unwrap();
    let router = tonic::service::Routes::new(fixture.data().service()).into_axum_router();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        tls,
        router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));

    // Every invocation pins the profile digest and its database binding.
    let digest = hex::encode(Sha256::digest(&bytes));
    let incarnation = fixture.incarnation.to_string();
    let family = family_id.to_string();
    let pins = [
        "--profile",
        profile_path,
        "--expect-profile-sha256",
        &digest,
        "--expect-tenant",
        "tenant-a",
        "--expect-incarnation",
        &incarnation,
        "--expect-principal",
        "person",
        "--expect-family-id",
        &family,
        "--timeout-ms",
        "30000",
    ];
    let cli = |words: Vec<String>| async move {
        let arguments = pins
            .iter()
            .map(|word| word.to_string())
            .chain(words)
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        let arguments = arguments.into_iter().map(Into::into).collect();
        let status = crate::data_cli::run(arguments, &mut out).await;
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches('\n').count(), 1, "one document: {text}");
        (status, serde_json::from_str::<Value>(&text).unwrap(), text)
    };
    let mutate = |batch: &str| cli(vec!["mutate".into(), batch.into()]);
    let resolve = |batch: &str| cli(vec!["resolve-mutation".into(), batch.into()]);

    // An intent is created once under its caller-supplied key. The identical
    // batch resolves to the original receipt instead of writing again.
    let intent = r#"{"idempotency_key":"is/run-1/op-1/intent","operations":[{"op":"put","collection":"intents","id":"op-1","body":{"fingerprint":"f1","amount":10.50},"expected":"absent"}]}"#;
    let (status, first, _) = mutate(intent).await;
    assert_eq!(status, 0, "{first}");
    let revision = first["result"]["receipt"]["revision"].as_u64().unwrap();
    assert_eq!(
        first["result"]["receipt"]["versions"],
        json!({"/intents/op-1": revision})
    );
    assert_eq!(
        first["result"]["request_digest"],
        json!(
            serde_json::from_str::<MutationBatch>(intent)
                .unwrap()
                .digest()
                .unwrap()
        )
    );
    let (status, again, _) = mutate(intent).await;
    assert_eq!((status, &again), (0, &first));
    let (status, stored, text) = cli(vec!["get".into(), "intents".into(), "op-1".into()]).await;
    assert_eq!(status, 0);
    assert_eq!(stored["result"]["document"]["version"], json!(revision));
    assert!(
        text.contains(r#""amount":10.50"#),
        "exact number text: {text}"
    );

    // The same key with a different payload is a conflict, not a replay.
    let changed = intent.replace(r#""fingerprint":"f1""#, r#""fingerprint":"f2""#);
    let (status, conflict, _) = mutate(&changed).await;
    assert_eq!(status, 6, "{conflict}");
    assert_eq!(
        conflict["error"],
        json!({"class": "conflict", "code": "CONFLICT",
               "message": "idempotency key reused for different input",
               "idempotency_key": "is/run-1/op-1/intent"})
    );
    let (status, other, _) = resolve(&changed).await;
    assert_eq!((status, &other["error"]["class"]), (6, &json!("conflict")));
    // Outcomes are looked up under the profile's own tenant and principal, so
    // a scope naming another principal is refused rather than reported unknown.
    let (status, foreign, _) = cli(vec![
        "resolve-mutation".into(),
        intent.into(),
        "--scope".into(),
        json!({"tenant": "tenant-a", "incarnation": fixture.incarnation.to_string(),
               "principal": "someone-else"})
        .to_string(),
    ])
    .await;
    assert_eq!(status, 2, "{foreign}");
    assert_eq!(foreign["error"]["class"], json!("invalid_request"));
    assert_eq!(
        foreign["error"]["idempotency_key"],
        json!("is/run-1/op-1/intent")
    );

    // A claim is compare-and-set: create when absent, update at the observed
    // version, and a stale version is a retained precondition failure.
    let claim = |key: &str, owner: &str, expected: Value| {
        json!({"idempotency_key": key, "operations": [{"op": "put", "collection": "claims",
            "id": "op-1", "body": {"owner": owner}, "expected": expected}]})
        .to_string()
    };
    let (status, created, _) = mutate(&claim("is/run-1/op-1/claim-1", "a", json!("absent"))).await;
    assert_eq!(status, 0, "{created}");
    let created = created["result"]["receipt"]["revision"].as_u64().unwrap();
    let (status, updated, _) = mutate(&claim(
        "is/run-1/op-1/claim-2",
        "b",
        json!({"version": created}),
    ))
    .await;
    assert_eq!(status, 0, "{updated}");
    let updated = updated["result"]["receipt"]["revision"].as_u64().unwrap();
    let stale = claim("is/run-1/op-1/claim-3", "c", json!({"version": created}));
    let (status, refused, _) = mutate(&stale).await;
    assert_eq!(status, 7, "{refused}");
    assert_eq!(refused["error"]["class"], json!("precondition_failed"));
    assert_eq!(refused["error"]["code"], json!("CONFLICT"));
    let (status, retained, _) = resolve(&stale).await;
    assert_eq!(status, 0);
    assert_eq!(retained["result"]["outcome"], json!("rejected"));
    assert_eq!(
        retained["result"]["error"],
        json!({"class": "precondition_failed", "code": "CONFLICT",
               "message": "document precondition failed"})
    );

    // One coherent snapshot proves each version and the receipt's absence.
    let (status, snapshot, _) = cli(vec![
        "read-snapshot".into(),
        json!({"documents": [
            {"collection": "intents", "id": "op-1"},
            {"collection": "claims", "id": "op-1"},
            {"collection": "receipts", "id": "op-1"}],
            "queries": [], "time_bounds": null})
        .to_string(),
    ])
    .await;
    assert_eq!(status, 0, "{snapshot}");
    let read = &snapshot["result"]["snapshot"];
    assert_eq!(read["incarnation"], json!(incarnation));
    assert_eq!(read["documents"][0]["document"]["version"], json!(revision));
    assert_eq!(read["documents"][1]["document"]["version"], json!(updated));
    assert_eq!(
        read["documents"][1]["document"]["body"],
        json!({"owner": "b"})
    );
    assert_eq!(
        read["documents"][2],
        json!({"key": {"collection": "receipts", "id": "op-1"}, "document": null})
    );
    let fence = snapshot["result"]["read_assertions"].clone();
    assert_eq!(fence[0]["kind"], json!("snapshot"));
    assert_eq!(fence[3]["expected"], json!("absent"));

    // Finishing the claim and writing the permanent receipt is one batch fenced
    // on the snapshot; resolving it returns the original committed receipt.
    let finish = json!({"idempotency_key": "is/run-1/op-1/finish", "read_set": fence,
        "operations": [
            {"op": "put", "collection": "claims", "id": "op-1", "body": {"owner": "b", "done": true},
             "expected": {"version": updated}},
            {"op": "put", "collection": "receipts", "id": "op-1", "body": {"ledger": "committed"},
             "expected": "absent"}]})
    .to_string();
    let (status, finished, _) = mutate(&finish).await;
    assert_eq!(status, 0, "{finished}");
    let (status, resolved, _) = resolve(&finish).await;
    assert_eq!(status, 0);
    assert_eq!(resolved["result"]["outcome"], json!("committed"));
    assert_eq!(resolved["result"]["receipt"], finished["result"]["receipt"]);
    assert_eq!(
        resolved["result"]["scope"],
        json!({"tenant": "tenant-a", "incarnation": incarnation, "principal": "person"})
    );
    let late = finish.replace("is/run-1/op-1/finish", "is/run-1/op-1/finish-late");
    let (status, late, _) = mutate(&late).await;
    assert_eq!(status, 7, "{late}");

    // A key that was never used has no retained outcome. That is unknown,
    // never evidence that the batch did not happen.
    let never = r#"{"idempotency_key":"is/run-1/op-9/intent","operations":[{"op":"put","collection":"intents","id":"op-9","body":{},"expected":"absent"}]}"#;
    let (status, unknown, _) = resolve(never).await;
    assert_eq!(status, 0);
    assert_eq!(unknown["result"]["outcome"], json!("unknown"));
    assert!(unknown["result"].get("receipt").is_none());

    // Two concurrent claims at the same observed version: exactly one wins.
    // The loser is precondition_failed once its receipt check finishes within
    // the deadline, else conflict; either way its retained outcome is the
    // failed precondition and the winner's claim is the stored one.
    let current = updated.max(finished["result"]["receipt"]["revision"].as_u64().unwrap());
    let race = |key: &str, owner: &str| claim(key, owner, json!({"version": current}));
    let racers = [
        ("a", race("is/run-1/op-1/race-a", "a")),
        ("b", race("is/run-1/op-1/race-b", "b")),
    ];
    let (left, right) = tokio::join!(mutate(&racers[0].1), mutate(&racers[1].1));
    let (winner, (lost, loser), losing) = match (left.0, right.0) {
        (0, _) => (racers[0].0, (right.0, &right.1), &racers[1].1),
        (_, 0) => (racers[1].0, (left.0, &left.1), &racers[0].1),
        _ => panic!("no claim won: {} {}", left.1, right.1),
    };
    assert!(matches!(lost, 6 | 7), "{loser}");
    assert_eq!(loser["error"]["code"], json!("CONFLICT"), "{loser}");
    let (status, retained, _) = resolve(losing).await;
    assert_eq!(status, 0, "{retained}");
    assert_eq!(retained["result"]["outcome"], json!("rejected"));
    assert_eq!(
        retained["result"]["error"]["class"],
        json!("precondition_failed")
    );
    let (_, stored, _) = cli(vec!["get".into(), "claims".into(), "op-1".into()]).await;
    assert_eq!(
        stored["result"]["document"]["body"],
        json!({"owner": winner})
    );

    // An append-only create over an existing ID fails its absent precondition,
    // so a lost intent race is a retained precondition failure, as is the same
    // create fenced by a document read assertion. Overwriting stays forbidden.
    let duplicate = r#"{"idempotency_key":"is/run-1/op-1/intent-again","operations":[{"op":"put","collection":"intents","id":"op-1","body":{},"expected":"absent"}]}"#;
    let (status, lost, _) = mutate(duplicate).await;
    assert_eq!(status, 7, "{lost}");
    assert_eq!(
        lost["error"],
        json!({"class": "precondition_failed", "code": "CONFLICT",
               "message": "document precondition failed",
               "idempotency_key": "is/run-1/op-1/intent-again"})
    );
    let fenced = r#"{"idempotency_key":"is/run-1/op-1/intent-fenced","read_set":[{"kind":"document","collection":"intents","id":"op-1","expected":"absent"}],"operations":[{"op":"put","collection":"intents","id":"op-1","body":{},"expected":"absent"}]}"#;
    let (status, fenced, _) = mutate(fenced).await;
    assert_eq!(status, 7, "{fenced}");
    let overwrite = r#"{"idempotency_key":"is/run-1/op-1/intent-overwrite","operations":[{"op":"put","collection":"intents","id":"op-1","body":{},"expected":"any"}]}"#;
    let (status, forbidden, _) = mutate(overwrite).await;
    assert_eq!(status, 4, "{forbidden}");
    assert_eq!(forbidden["error"]["code"], json!("FORBIDDEN"));

    // A profile that differs from its independent pin never connects.
    let mut out = Vec::new();
    let status = crate::data_cli::run(
        vec![
            "--profile".into(),
            profile_path.into(),
            "--expect-profile-sha256".into(),
            "0".repeat(64).into(),
            "collections".into(),
        ],
        &mut out,
    )
    .await;
    assert_eq!(status, 3);

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.close().await;
}
