#[tokio::test]
async fn private_evidence_four_full_chunks_roundtrip_through_secure_native_transport() {
    use kasumi_client::{ClientProfile, ProfileAuthorityEndpoint, ProfileTlsFiles};
    use kasumi_private_evidence::{
        AppendOutcome, CHUNK_BYTES, EvidenceIdentity, InstalledProfileBinding,
        PrivateEvidenceCustody, collection_definition_sha256, collection_definitions,
        verify_installed_collection_definitions,
    };
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::Duration};

    let fixture = Fixture::new().await;
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "person".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "private-evidence-schema".into(),
    };
    for definition in collection_definitions("evidence_manifests", "evidence_chunks").unwrap() {
        fixture
            .db
            .administer(context.clone(), Operation::CreateCollection(definition))
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
    let bearer = token.strip_prefix("Bearer ").unwrap();
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
        bearer_file: write_private("bearer", bearer.as_bytes()),
    };
    let bytes = serde_json::to_vec(&profile).unwrap();
    let profile_path = write_private("profile.json", &bytes);
    let [manifest_definition_sha256, chunk_definition_sha256] =
        collection_definition_sha256("evidence_manifests", "evidence_chunks").unwrap();
    let binding = InstalledProfileBinding {
        profile_sha256: hex::encode(Sha256::digest(&bytes)),
        tenant: profile.tenant.clone(),
        incarnation: fixture.incarnation,
        principal: profile.principal.clone(),
        family_id,
        manifest_collection: "evidence_manifests".into(),
        chunk_collection: "evidence_chunks".into(),
        manifest_definition_sha256,
        chunk_definition_sha256,
        max_component_bytes: 4 * CHUNK_BYTES,
    };
    let schema = fixture
        .db
        .read_schema(
            &context,
            kasumi_types::ReadSchema::Named {
                collections: BTreeSet::from([
                    binding.manifest_collection.clone(),
                    binding.chunk_collection.clone(),
                ]),
            },
        )
        .await
        .unwrap();
    verify_installed_collection_definitions(&schema, &binding).unwrap();
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

    let payload = (0..4 * CHUNK_BYTES)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let evidence = EvidenceIdentity::new(
        kasumi_types::MutationReceiptScope {
            tenant: binding.tenant.clone(),
            incarnation: binding.incarnation.to_string(),
            principal: binding.principal.clone(),
        },
        hex::encode(Sha256::digest(b"secure native full read-group boundary")),
        "native_boundary".into(),
    )
    .unwrap();
    let mut custody =
        PrivateEvidenceCustody::from_installed_profile(&profile_path, &binding).unwrap();
    let timeout = Duration::from_secs(60);
    assert_eq!(
        custody.append(&evidence, &payload, timeout).await.unwrap(),
        AppendOutcome::Committed
    );
    let retained = custody.read(&evidence, timeout).await.unwrap().unwrap();
    assert_eq!(retained.identity, evidence);
    assert_eq!(retained.sha256, hex::encode(Sha256::digest(&payload)));
    assert_eq!(retained.bytes, payload);
    assert_eq!(
        custody.append(&evidence, &payload, timeout).await.unwrap(),
        AppendOutcome::AlreadyPresent
    );

    // The original 12 MiB budget rejects these exact native rows, demonstrating
    // that this test exercises the real decoder capacity rather than a mock.
    let mut client = kasumi_client::KasumiClient::connect(&profile.connection(false).unwrap())
        .await
        .unwrap();
    let request = kasumi_types::ReadSnapshotRequest {
        documents: (0..4)
            .map(|index| kasumi_types::DocumentKey {
                collection: binding.chunk_collection.clone(),
                id: format!("private-evidence/{}/chunk-{index:04}", evidence.evidence_id),
            })
            .collect(),
        queries: vec![],
        time_bounds: None,
    };
    let options = kasumi_client::SnapshotReadOptions {
        resources: kasumi_client::ClientResources::new(128 << 20, 2).unwrap(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 128 << 10,
            max_wire_bytes: 8 << 20,
            max_json_bytes: 8 << 20,
            max_depth: 32,
            max_nodes: 100_000,
            max_string_bytes: 1 << 20,
            max_number_bytes: 128,
            max_rows: 4,
            max_decoded_bytes: 12 << 20,
        },
        deadline: tokio::time::Instant::now() + timeout,
        expected_incarnation: fixture.incarnation,
    };
    assert!(matches!(
        client.read_snapshot(bearer, &request, &options).await,
        Err(kasumi_client::ClientError::DecodeRejected {
            code: Code::ResourceExhausted,
            ..
        })
    ));
    drop(client);
    drop(custody);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    fixture.close().await;
}
