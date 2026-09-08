#[tokio::test]
async fn native_backup_proof_is_admin_only_configured_and_verified_through_secure_sdk() {
    use kasumi_client::{KasumiAdminClient, KasumiClientConfig};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    let fixture = Fixture::new().await;
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._dir.path().join("backup"),
            16 << 20,
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination("approved".into(), destination)
        .unwrap();
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let token = fixture.token("person", "tenant-a", "kasumi:admin");
    let read_only = fixture.token("person", "tenant-a", "kasumi:read");
    let wire = || proto::CreateBackupCheckpointRequest {
        request_json: serde_json::to_vec(&kasumi_types::CreateBackupCheckpoint {
            session_id: uuid::Uuid::new_v4(),
            destination: "approved".into(),
        })
        .unwrap(),
    };
    assert_eq!(
        admin
            .create_backup_checkpoint(native(wire(), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        admin
            .create_backup_checkpoint(native(
                wire(),
                &fixture.token("person", "other", "kasumi:admin")
            ))
            .await
            .is_err()
    );
    for body in [
        json!({"destination":"/tmp/user-controlled"}),
        json!({"destination":"approved","tenant":"other"}),
    ] {
        assert!(
            admin
                .create_backup_checkpoint(native(
                    proto::CreateBackupCheckpointRequest {
                        request_json: serde_json::to_vec(&body).unwrap()
                    },
                    &token
                ))
                .await
                .is_err()
        );
    }
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);
    let identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let server_identity = identity();
    let client_identity = identity();
    let server_pin = server_identity.certificate_pin();
    let ca_pem = ca_cert.pem().into_bytes();
    let tls = kasumi_transport::server_config(
        &server_identity,
        ClientAuthentication::Required {
            trusted_ca_pem: &ca_pem,
        },
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let router = tonic::service::Routes::new(admin.service())
        .add_service(fixture.data().service())
        .into_axum_router();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        tls,
        router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let config = KasumiClientConfig {
        endpoint,
        identity: client_identity,
        trusted_ca_pem: ca_pem,
        server_certificate_pins: BTreeSet::from([server_pin]),
    };
    let mut client = KasumiAdminClient::connect(&config).await.unwrap();
    let mut data_client = kasumi_client::KasumiClient::connect(&config).await.unwrap();
    let reader_token = fixture.token("reader", "tenant-a", "kasumi:read");
    let lineage = data_client
        .read_restore_lineage(
            reader_token.strip_prefix("Bearer ").unwrap(),
            &kasumi_types::ReadRestoreLineage {
                expected_incarnation: fixture.incarnation.to_string(),
                collection: "docs".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(lineage.tenant(), "tenant-a");
    assert!(lineage.links().is_empty());
    assert!(
        data_client
            .read_restore_lineage(
                reader_token.strip_prefix("Bearer ").unwrap(),
                &kasumi_types::ReadRestoreLineage {
                    expected_incarnation: fixture.incarnation.to_string(),
                    collection: "private".into()
                }
            )
            .await
            .is_err()
    );

    let bearer = token.strip_prefix("Bearer ").unwrap();
    let proof = client
        .create_backup_checkpoint(
            bearer,
            &kasumi_types::CreateBackupCheckpoint {
                session_id: uuid::Uuid::new_v4(),
                destination: "approved".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(proof.tenant(), "tenant-a");
    assert_eq!(
        proof.source_incarnation(),
        fixture.db.engine().generation().unwrap().state.incarnation
    );
    assert_eq!(proof.resident_sha256().len(), 64);
    assert_eq!(proof.manifest_ciphertext_sha256().len(), 64);
    assert_eq!(proof.key_lineage_digest().len(), 64);
    let request = kasumi_types::VerifyBackupCheckpoint {
        destination: "approved".into(),
        backup_id: proof.backup_id(),
    };
    let readback = client
        .verify_backup_checkpoint(bearer, &request)
        .await
        .unwrap();
    assert_eq!(proof.checkpoint(), readback.checkpoint());
    assert!(
        client
            .verify_backup_checkpoint(read_only.strip_prefix("Bearer ").unwrap(), &request)
            .await
            .is_err()
    );
    let session_request = kasumi_types::BackupSessionRequest {
        destination: "approved".into(),
        session_id: proof.backup_id(),
    };
    let session_status = client
        .backup_session_status(bearer, &session_request)
        .await
        .unwrap();
    assert!(
        matches!(session_status.outcome, Some(kasumi_types::BackupSessionOutcome::Complete { checkpoint, .. }) if checkpoint == *proof.checkpoint())
    );
    assert!(
        client
            .backup_session_status(read_only.strip_prefix("Bearer ").unwrap(), &session_request)
            .await
            .is_err()
    );
    let terminal = client
        .abort_backup_session(
            bearer,
            &kasumi_types::AbortBackupSession {
                destination: "approved".into(),
                session_id: proof.backup_id(),
                reason: "confirm durable outcome".into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        Some(kasumi_types::BackupSessionOutcome::Complete { .. })
    ));
    assert!(
        client
            .cleanup_backup_session(
                bearer,
                &kasumi_types::CleanupBackupSession {
                    destination: "approved".into(),
                    session_id: proof.backup_id(),
                    max_objects: 256,
                }
            )
            .await
            .is_err()
    );
    let retirement = kasumi_types::RetireSourceRequest {
        retirement_id: "native-retirement".into(),
        expected_source_incarnation: proof.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: proof.checkpoint().clone(),
        destination: "approved".into(),
        not_after_ms: u64::MAX,
    };
    let reference = retirement.reference().unwrap();
    assert!(
        client
            .retire_source(read_only.strip_prefix("Bearer ").unwrap(), &retirement)
            .await
            .is_err()
    );
    let mut stopped_request = retirement.clone();
    stopped_request.retirement_id = "native-stopped".into();
    let kasumi_client::VerifiedRetirementResolution::Stopped(stopped) = client
        .abort_retirement(bearer, &stopped_request)
        .await
        .unwrap()
    else {
        panic!("stop must be definitive")
    };
    assert_eq!(stopped.reference(), &stopped_request.reference().unwrap());
    assert!(
        client
            .retire_source(bearer, &stopped_request)
            .await
            .is_err()
    );
    let retired = client.retire_source(bearer, &retirement).await.unwrap();
    assert!(
        client
            .verify_retirement_receipt(bearer, &reference)
            .await
            .is_err(),
        "a fresh database invocation cannot become custody authority"
    );
    let custody_token = fixture.custody_token("person");
    let bearer = custody_token.strip_prefix("Bearer ").unwrap();
    let kasumi_client::VerifiedRetirementResolution::Retired(resolved) =
        client.abort_retirement(bearer, &retirement).await.unwrap()
    else {
        panic!("retirement cannot be stopped after commit")
    };
    assert_eq!(resolved.receipt(), retired.receipt());
    assert_eq!(retired.checkpoint(), proof.checkpoint());
    assert_eq!(retired.target_incarnation(), retirement.target_incarnation);
    assert_eq!(
        client
            .verify_retirement_receipt(bearer, &reference)
            .await
            .unwrap()
            .receipt(),
        retired.receipt()
    );
    assert_eq!(
        client
            .retirement_status(bearer, &reference)
            .await
            .unwrap()
            .unwrap()
            .outcome
            .unwrap(),
        *retired.receipt()
    );
    assert_eq!(
        client
            .retire_source(bearer, &retirement)
            .await
            .unwrap()
            .receipt(),
        retired.receipt()
    );
    let mut mismatched = reference.clone();
    mismatched.source_incarnation = "unconfigured-source".into();
    assert!(
        client
            .verify_retirement_receipt(bearer, &mismatched)
            .await
            .is_err()
    );
    assert!(
        client
            .retirement_status(read_only.strip_prefix("Bearer ").unwrap(), &reference)
            .await
            .is_err()
    );
    let initial_custody = client.read_custody(bearer, &reference).await.unwrap();
    assert_eq!(initial_custody.policy_epoch, 1);
    let rotation = kasumi_types::CustodyRequest {
        retirement: reference.clone(),
        command_id: "native-custody-rotation".into(),
        expected_policy_epoch: initial_custody.policy_epoch,
        not_after_ms: u64::MAX,
        action: kasumi_types::CustodyAction::ReplaceAdministrators(BTreeSet::from([
            "custodian".into()
        ])),
    };
    let kasumi_client::ClientError::Transport(error) =
        client.execute_custody(bearer, &rotation).await.unwrap_err()
    else {
        panic!("native status expected")
    };
    let detail: Error = serde_json::from_slice(error.details()).unwrap();
    assert_eq!(detail.code, ErrorCode::UnknownOutcome);
    assert!(
        client
            .verify_retirement_receipt(bearer, &reference)
            .await
            .is_err()
    );
    let custodian_token = fixture.custody_token("custodian");
    let custodian_bearer = custodian_token.strip_prefix("Bearer ").unwrap();
    let replay = client
        .execute_custody(custodian_bearer, &rotation)
        .await
        .unwrap();
    assert_eq!(replay.principal, "person");
    replay.outcome.unwrap();
    assert_eq!(
        client
            .read_custody(custodian_bearer, &reference)
            .await
            .unwrap()
            .policy_epoch,
        2
    );
    let store = fixture.db.detach_retired_custody().await.unwrap();
    let control = kasumi_raft::ControlLog::installed(store.clone())
        .unwrap()
        .unwrap();
    let node_id = control.node_id();
    let group = control.group().to_owned();
    let peer_router = Arc::new(kasumi_raft::InProcessRouter::default());
    let custody = kasumi_engine::RetiredCustody::open_replicated(
        store,
        node_id,
        group.clone(),
        peer_router.clone(),
        kasumi_raft::Config::default(),
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        fixture.audit.clone(),
    )
    .await
    .unwrap();
    peer_router.register(group, node_id, custody.raft_group().unwrap().raft().clone());
    custody
        .raft_group()
        .unwrap()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(node_id, "native custody leader")
        .await
        .unwrap();
    fixture.registry.remove("tenant-a").unwrap();
    fixture
        .registry
        .install_retirement_source(kasumi_engine::InstalledRetirementSource::RetiredCustody(
            custody.clone(),
        ))
        .unwrap();
    // The same authenticated SDK now resolves through an installed key-free
    // source route. The old application Database and store are permanently sealed.
    fixture.db.shutdown().await.unwrap();
    assert!(fixture.db.engine().generation().is_err());
    assert_eq!(
        client
            .verify_retirement_receipt(custodian_bearer, &reference)
            .await
            .unwrap()
            .receipt(),
        retired.receipt()
    );
    assert!(
        client
            .abort_retirement(custodian_bearer, &stopped_request)
            .await
            .is_err(),
        "nonretired stop proof cannot be released after another retirement won"
    );
    let mut invalid_pin = config;
    invalid_pin.server_certificate_pins = BTreeSet::from([[0x53; 32]]);
    assert!(KasumiAdminClient::connect(&invalid_pin).await.is_err());
    drop(client);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    custody.shutdown().await.unwrap();
    fixture.close().await;
}
