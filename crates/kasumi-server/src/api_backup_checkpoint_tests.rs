#[tokio::test]
async fn native_backup_proof_is_admin_only_configured_and_verified_through_secure_sdk() {
    use kasumi_client::{KasumiAdminClient, KasumiClientConfig};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    let fixture = Fixture::new().await;
    let destination = Arc::new(kasumi_store::FilesystemBackupDestination::new(fixture._dir.path().join("backup"), 16 << 20).unwrap());
    fixture.db.install_archive_destination("approved".into(), destination).unwrap();
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let token = fixture.token("person", "tenant-a", "kasumi:admin");
    let read_only = fixture.token("person", "tenant-a", "kasumi:read");
    let wire = || proto::CreateBackupCheckpointRequest { request_json: serde_json::to_vec(&kasumi_types::CreateBackupCheckpoint { destination: "approved".into() }).unwrap() };
    assert_eq!(admin.create_backup_checkpoint(native(wire(), &read_only)).await.unwrap_err().code(), Code::PermissionDenied);
    assert!(admin.create_backup_checkpoint(native(wire(), &fixture.token("person", "other", "kasumi:admin"))).await.is_err());
    for body in [json!({"destination":"/tmp/user-controlled"}), json!({"destination":"approved","tenant":"other"})] {
        assert!(admin.create_backup_checkpoint(native(proto::CreateBackupCheckpointRequest { request_json: serde_json::to_vec(&body).unwrap() }, &token)).await.is_err());
    }
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign, rcgen::KeyUsagePurpose::DigitalSignature];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);
    let identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth, rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let server_identity = identity();
    let client_identity = identity();
    let server_pin = server_identity.certificate_pin();
    let ca_pem = ca_cert.pem().into_bytes();
    let tls = kasumi_transport::server_config(&server_identity, ClientAuthentication::Required { trusted_ca_pem: &ca_pem }).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", listener.local_addr().unwrap().port());
    let router = tonic::service::Routes::new(admin.service()).into_axum_router();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(listener, tls, router, crate::tls::ListenerLimits::default(), fixture.audit.clone(), shutdown));
    let config = KasumiClientConfig { endpoint, identity: client_identity, trusted_ca_pem: ca_pem, server_certificate_pins: BTreeSet::from([server_pin]) };
    let mut client = KasumiAdminClient::connect(&config).await.unwrap();
    let bearer = token.strip_prefix("Bearer ").unwrap();
    let proof = client.create_backup_checkpoint(bearer, &kasumi_types::CreateBackupCheckpoint { destination: "approved".into() }).await.unwrap();
    assert_eq!(proof.tenant(), "tenant-a");
    assert_eq!(proof.source_incarnation(), "incarnation-a");
    assert_eq!(proof.resident_sha256().len(), 64);
    assert_eq!(proof.manifest_ciphertext_sha256().len(), 64);
    assert_eq!(proof.key_lineage_digest().len(), 64);
    let request = kasumi_types::VerifyBackupCheckpoint { destination: "approved".into(), backup_id: proof.backup_id() };
    let readback = client.verify_backup_checkpoint(bearer, &request).await.unwrap();
    assert_eq!(proof.checkpoint(), readback.checkpoint());
    assert!(client.verify_backup_checkpoint(read_only.strip_prefix("Bearer ").unwrap(), &request).await.is_err());
    let retirement = kasumi_types::RetireSourceRequest {
        retirement_id: "native-retirement".into(), expected_source_incarnation: proof.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(), checkpoint: proof.checkpoint().clone(),
        destination: "approved".into(), not_after_ms: u64::MAX,
    };
    let reference = retirement.reference().unwrap();
    assert!(client.retire_source(read_only.strip_prefix("Bearer ").unwrap(), &retirement).await.is_err());
    let mut stopped_request = retirement.clone(); stopped_request.retirement_id = "native-stopped".into();
    let kasumi_client::VerifiedRetirementResolution::Stopped(stopped) = client.abort_retirement(bearer, &stopped_request).await.unwrap() else { panic!("stop must be definitive") };
    assert_eq!(stopped.reference(), &stopped_request.reference().unwrap());
    assert!(client.retire_source(bearer, &stopped_request).await.is_err());
    let retired = client.retire_source(bearer, &retirement).await.unwrap();
    let kasumi_client::VerifiedRetirementResolution::Retired(resolved) = client.abort_retirement(bearer, &retirement).await.unwrap() else { panic!("retirement cannot be stopped after commit") };
    assert_eq!(resolved.receipt(), retired.receipt());
    assert_eq!(retired.checkpoint(), proof.checkpoint());
    assert_eq!(retired.target_incarnation(), retirement.target_incarnation);
    assert_eq!(client.verify_retirement_receipt(bearer, &reference).await.unwrap().receipt(), retired.receipt());
    assert_eq!(client.retirement_status(bearer, &reference).await.unwrap().unwrap().outcome.unwrap(), *retired.receipt());
    assert_eq!(client.retire_source(bearer, &retirement).await.unwrap().receipt(), retired.receipt());
    let mut mismatched = reference.clone(); mismatched.source_incarnation = "unconfigured-source".into();
    assert!(client.verify_retirement_receipt(bearer, &mismatched).await.is_err());
    assert!(client.retirement_status(read_only.strip_prefix("Bearer ").unwrap(), &reference).await.is_err());
    let mut invalid_pin = config;
    invalid_pin.server_certificate_pins = BTreeSet::from([[0x53; 32]]);
    assert!(KasumiAdminClient::connect(&invalid_pin).await.is_err());
    drop(client); stop.send(true).unwrap(); serving.await.unwrap().unwrap();
    fixture.close().await;
}
