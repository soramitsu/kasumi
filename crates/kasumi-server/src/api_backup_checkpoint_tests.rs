#[tokio::test]
async fn committed_source_marker_with_absent_status_never_calls_mutation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let beginnings = AtomicUsize::new(0);
    let sends = AtomicUsize::new(0);
    let error = crate::recovery_runtime::retire_after_absent_status(
        true,
        async {
            beginnings.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        async {
            sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<kasumi_types::Error>()
            .map(|error| error.code),
        Some(kasumi_types::ErrorCode::UnknownOutcome)
    );
    assert_eq!(beginnings.load(Ordering::SeqCst), 0);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_backup_proof_is_admin_only_configured_and_verified_through_secure_sdk() {
    use kasumi_client::{KasumiAdminClient, KasumiClientConfig};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    let fixture = Fixture::new().await;
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._dir.path().join("persistent/backup"),
            16 << 20,
            fixture.physical.persistent.clone(),
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
    let custody_token = fixture.custody_token("person");
    let custody_bearer = custody_token.strip_prefix("Bearer ").unwrap();
    let mut absent = retirement.clone();
    absent.retirement_id = "native-marker-unknown".into();
    let absent_reference = absent.reference().unwrap();
    assert!(
        client
            .retirement_status(bearer, &absent_reference)
            .await
            .unwrap()
            .is_none()
    );
    let unresolved = crate::recovery_runtime::dispatch_planned_retirement(
        || {
            Ok((
                std::collections::BTreeMap::from([(1, config.clone())]),
                zeroize::Zeroizing::new(bearer.to_owned()),
            ))
        },
        &std::collections::BTreeMap::from([(1, config.clone())]),
        custody_bearer,
        &absent,
        true,
        std::time::Duration::from_secs(30),
        async { panic!("a committed marker cannot begin another retirement") },
    )
    .await
    .unwrap_err();
    assert_eq!(
        unresolved
            .downcast_ref::<kasumi_types::Error>()
            .map(|error| error.code),
        Some(kasumi_types::ErrorCode::UnknownOutcome)
    );
    assert!(
        client
            .retirement_status(bearer, &absent_reference)
            .await
            .unwrap()
            .is_none(),
        "an absent status after a marker must not cause a new retirement"
    );
    let admitted = std::sync::atomic::AtomicBool::new(false);
    let retired = crate::recovery_runtime::dispatch_planned_retirement(
        || {
            Ok((
                std::collections::BTreeMap::from([(1, config.clone())]),
                zeroize::Zeroizing::new(bearer.to_owned()),
            ))
        },
        &std::collections::BTreeMap::from([(1, config.clone())]),
        custody_bearer,
        &retirement,
        false,
        std::time::Duration::from_secs(30),
        async {
            admitted.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(admitted.load(std::sync::atomic::Ordering::Acquire));
    let retained = crate::recovery_runtime::dispatch_planned_retirement(
        || panic!("accepted retirement must recover without the application credential"),
        &std::collections::BTreeMap::from([(1, config.clone())]),
        custody_bearer,
        &retirement,
        true,
        std::time::Duration::from_secs(30),
        async { panic!("accepted retirement must not dispatch another effect") },
    )
    .await
    .unwrap();
    assert_eq!(retained.receipt(), retired.receipt());
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
    assert!(
        client
            .read_custody_receipt(bearer, &rotation)
            .await
            .unwrap()
            .is_none()
    );
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
    assert!(
        client
            .read_custody_receipt(bearer, &rotation)
            .await
            .is_err()
    );
    let before_receipt = client
        .read_custody(custodian_bearer, &reference)
        .await
        .unwrap();
    let observed_receipt = client
        .read_custody_receipt(custodian_bearer, &rotation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .read_custody(custodian_bearer, &reference)
            .await
            .unwrap()
            .revision,
        before_receipt.revision
    );
    let mut substituted = rotation.clone();
    substituted.not_after_ms -= 1;
    assert!(
        client
            .read_custody_receipt(custodian_bearer, &substituted)
            .await
            .is_err()
    );
    let replay = client
        .execute_custody(custodian_bearer, &rotation)
        .await
        .unwrap();
    assert_eq!(replay, observed_receipt);
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
        kasumi_raft::RaftGroupConfig::default(),
        fixture.audit.admission().clone(),
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
            .read_custody_receipt(custodian_bearer, &rotation)
            .await
            .unwrap(),
        Some(observed_receipt),
    );
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
#[tokio::test]
async fn retirement_pool_lost_committed_reply_never_dispatches_to_second_installed_route() {
    use kasumi_client::{KasumiClientConfig, KasumiRetirementPool};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let fixture = Fixture::new().await;
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture
                ._dir
                .path()
                .join("persistent/retirement-pool-backup"),
            16 << 20,
            fixture.physical.persistent.clone(),
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination("approved".into(), destination.clone())
        .unwrap();
    let application_token = fixture.token("person", "tenant-a", "kasumi:admin");
    let context = fixture.auth.authenticate(&application_token).await.unwrap();
    let checkpoint = fixture
        .db
        .backup_checkpoint(context, destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let request = kasumi_types::RetireSourceRequest {
        retirement_id: "pool-lost-reply".into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: "approved".into(),
        not_after_ms: u64::MAX,
    };
    let reference = request.reference().unwrap();

    let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = parameters.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(parameters, ca_key);
    let identity = || {
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        parameters.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let server_identity = identity();
    let client_identity = identity();
    let server_pin = server_identity.certificate_pin();
    let ca_pem = ca.pem().into_bytes();
    let first_effects = Arc::new(AtomicUsize::new(0));
    let first_body_consumed = Arc::new(AtomicBool::new(false));
    let first_successful_reply: Arc<std::sync::Mutex<Option<kasumi_types::RetirementReceipt>>> =
        Arc::new(std::sync::Mutex::new(None));
    let first_status_unavailable = Arc::new(AtomicBool::new(true));
    let first_status_reads = Arc::new(AtomicUsize::new(0));
    let second_effects = Arc::new(AtomicUsize::new(0));
    let second_status_reads = Arc::new(AtomicUsize::new(0));

    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_endpoint = format!("https://localhost:{}", first.local_addr().unwrap().port());
    let first_router = tonic::service::Routes::new(
        NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone()).service(),
    )
    .into_axum_router()
    .layer(axum::middleware::from_fn({
        let effects = first_effects.clone();
        let consumed = first_body_consumed.clone();
        let successful_reply = first_successful_reply.clone();
        let expected_retirement = request.clone();
        let unavailable = first_status_unavailable.clone();
        let reads = first_status_reads.clone();
        move |request: HttpRequest<Body>, next: axum::middleware::Next| {
            let effects = effects.clone();
            let consumed = consumed.clone();
            let successful_reply = successful_reply.clone();
            let expected_retirement = expected_retirement.clone();
            let unavailable = unavailable.clone();
            let reads = reads.clone();
            async move {
                let path = request.uri().path();
                if path == "/kasumi.v1.KasumiAdmin/RetirementStatus" {
                    reads.fetch_add(1, Ordering::SeqCst);
                    if unavailable.swap(false, Ordering::SeqCst) {
                        return axum::http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "14")
                            .body(Body::empty())
                            .unwrap();
                    }
                }
                if path != "/kasumi.v1.KasumiAdmin/RetireSource" {
                    return next.run(request).await;
                }
                effects.fetch_add(1, Ordering::SeqCst);
                let response = next.run(request).await;
                assert_eq!(response.status(), StatusCode::OK);
                // Drive and verify the real handler's complete successful reply
                // before losing it at this deterministic delivery boundary.
                let collected = http_body_util::Limited::new(response.into_body(), 1 << 20)
                    .collect()
                    .await
                    .unwrap();
                assert_eq!(
                    collected
                        .trailers()
                        .and_then(|trailers| trailers.get("grpc-status"))
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    "0"
                );
                let bytes = collected.to_bytes();
                assert!(bytes.len() >= 5, "successful gRPC reply lacks a frame");
                assert_eq!(bytes[0], 0, "retirement reply must be uncompressed");
                let frame_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                assert_eq!(frame_len, bytes.len() - 5);
                let reply = proto::RetirementReceiptResponse::decode(&bytes[5..]).unwrap();
                let receipt: kasumi_types::RetirementReceipt =
                    serde_json::from_slice(&reply.response_json).unwrap();
                receipt.validate().unwrap();
                let reference = expected_retirement.reference().unwrap();
                assert_eq!(receipt.source_incarnation, reference.source_incarnation);
                assert_eq!(receipt.retirement_id, reference.retirement_id);
                assert_eq!(receipt.request_digest, reference.request_digest);
                assert_eq!(receipt.checkpoint, expected_retirement.checkpoint);
                assert_eq!(receipt.target_incarnation, expected_retirement.target_incarnation);
                assert!(receipt.admitted_at_ms <= expected_retirement.not_after_ms);
                *successful_reply.lock().unwrap() = Some(receipt);
                consumed.store(true, Ordering::SeqCst);
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "14")
                    .body(Body::empty())
                    .unwrap()
            }
        }
    }));
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_endpoint = format!("https://localhost:{}", second.local_addr().unwrap().port());
    let second_router = tonic::service::Routes::new(
        NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone()).service(),
    )
    .into_axum_router()
    .layer(axum::middleware::from_fn({
        let effects = second_effects.clone();
        let reads = second_status_reads.clone();
        move |request: HttpRequest<Body>, next: axum::middleware::Next| {
            let effects = effects.clone();
            let reads = reads.clone();
            async move {
                match request.uri().path() {
                    "/kasumi.v1.KasumiAdmin/RetireSource" => {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    "/kasumi.v1.KasumiAdmin/RetirementStatus" => {
                        reads.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                next.run(request).await
            }
        }
    }));
    let tls = || {
        kasumi_transport::server_config(
            &server_identity,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap()
    };
    let (first_stop, first_shutdown) = tokio::sync::watch::channel(false);
    let first_task = tokio::spawn(crate::tls::serve_tls(
        first,
        tls(),
        first_router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        first_shutdown,
    ));
    let (second_stop, second_shutdown) = tokio::sync::watch::channel(false);
    let second_task = tokio::spawn(crate::tls::serve_tls(
        second,
        tls(),
        second_router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        second_shutdown,
    ));
    let config = |endpoint| KasumiClientConfig {
        endpoint,
        identity: client_identity.clone(),
        trusted_ca_pem: ca_pem.clone(),
        server_certificate_pins: BTreeSet::from([server_pin]),
    };
    let current_bearer = Arc::new(std::sync::RwLock::new(
        application_token
            .strip_prefix("Bearer ")
            .unwrap()
            .to_owned(),
    ));
    let source = current_bearer.clone();
    let mut pool = KasumiRetirementPool::new(
        BTreeMap::from([(1, config(first_endpoint)), (2, config(second_endpoint))]),
        Arc::new(move || Ok(zeroize::Zeroizing::new(source.read().unwrap().clone()))),
    )
    .unwrap();
    let ambiguous = pool
        .retire_source(&request, std::time::Duration::from_secs(60))
        .await;
    assert!(
        matches!(ambiguous, Err(kasumi_client::ClientError::Transport(ref status)) if status.code() == Code::Unavailable),
        "the consumed source response must be lost as a retryable transport error: {ambiguous:?}"
    );
    assert!(first_body_consumed.load(Ordering::SeqCst));
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    assert_eq!(second_effects.load(Ordering::SeqCst), 0);

    *current_bearer.write().unwrap() = fixture
        .custody_token("person")
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let status = pool
        .retirement_status(&reference, std::time::Duration::from_secs(30))
        .await
        .unwrap()
        .expect("the exact committed retirement must be observable");
    let receipt = status.outcome.unwrap();
    assert_eq!(
        first_successful_reply.lock().unwrap().clone(),
        Some(receipt.clone()),
        "the exact server receipt was committed before its reply was lost"
    );
    assert_eq!(status.reference, reference);
    assert_eq!(receipt.request_digest, reference.request_digest);
    assert_eq!(receipt.checkpoint, request.checkpoint);
    assert_eq!(first_status_reads.load(Ordering::SeqCst), 1);
    assert!(second_status_reads.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        pool.verify_retirement_receipt(&reference, std::time::Duration::from_secs(30))
            .await
            .unwrap()
            .receipt(),
        &receipt,
    );
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    assert_eq!(second_effects.load(Ordering::SeqCst), 0);

    drop(pool);
    first_stop.send(true).unwrap();
    second_stop.send(true).unwrap();
    first_task.await.unwrap().unwrap();
    second_task.await.unwrap().unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn retirement_pool_lost_abort_reply_never_dispatches_to_second_installed_route() {
    use http_body_util::BodyExt;
    use kasumi_client::{KasumiClientConfig, KasumiRetirementPool};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let fixture = Fixture::new().await;
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture
                ._dir
                .path()
                .join("persistent/retirement-pool-abort-backup"),
            16 << 20,
            fixture.physical.persistent.clone(),
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination("approved".into(), destination.clone())
        .unwrap();
    let application_token = fixture.token("person", "tenant-a", "kasumi:admin");
    let context = fixture.auth.authenticate(&application_token).await.unwrap();
    let checkpoint = fixture
        .db
        .backup_checkpoint(context, destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let request = kasumi_types::RetireSourceRequest {
        retirement_id: "pool-abort-lost-reply".into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: "approved".into(),
        not_after_ms: u64::MAX,
    };
    let reference = request.reference().unwrap();

    let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = parameters.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(parameters, ca_key);
    let identity = || {
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        parameters.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    let server_identity = identity();
    let client_identity = identity();
    let server_pin = server_identity.certificate_pin();
    let ca_pem = ca.pem().into_bytes();
    let first_effects = Arc::new(AtomicUsize::new(0));
    let first_body_consumed = Arc::new(AtomicBool::new(false));
    let first_successful_reply: Arc<std::sync::Mutex<Option<kasumi_types::RetirementStatus>>> =
        Arc::new(std::sync::Mutex::new(None));
    let first_status_unavailable = Arc::new(AtomicBool::new(true));
    let status_reads_blocked = Arc::new(AtomicBool::new(false));
    let first_status_reads = Arc::new(AtomicUsize::new(0));
    let second_effects = Arc::new(AtomicUsize::new(0));
    let second_status_reads = Arc::new(AtomicUsize::new(0));

    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_endpoint = format!("https://localhost:{}", first.local_addr().unwrap().port());
    let first_router = tonic::service::Routes::new(
        NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone()).service(),
    )
    .into_axum_router()
    .layer(axum::middleware::from_fn({
        let effects = first_effects.clone();
        let consumed = first_body_consumed.clone();
        let successful_reply = first_successful_reply.clone();
        let expected_retirement = request.clone();
        let unavailable = first_status_unavailable.clone();
        let blocked = status_reads_blocked.clone();
        let reads = first_status_reads.clone();
        move |request: HttpRequest<Body>, next: axum::middleware::Next| {
            let effects = effects.clone();
            let consumed = consumed.clone();
            let successful_reply = successful_reply.clone();
            let expected_retirement = expected_retirement.clone();
            let unavailable = unavailable.clone();
            let blocked = blocked.clone();
            let reads = reads.clone();
            async move {
                let path = request.uri().path();
                if path == "/kasumi.v1.KasumiAdmin/RetirementStatus" {
                    reads.fetch_add(1, Ordering::SeqCst);
                    if blocked.load(Ordering::SeqCst)
                        || unavailable.swap(false, Ordering::SeqCst)
                    {
                        return axum::http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "14")
                            .body(Body::empty())
                            .unwrap();
                    }
                }
                if path != "/kasumi.v1.KasumiAdmin/AbortRetirement" {
                    return next.run(request).await;
                }
                effects.fetch_add(1, Ordering::SeqCst);
                let response = next.run(request).await;
                assert_eq!(response.status(), StatusCode::OK);
                // Observe the real handler's complete, successful stopped reply
                // before replacing only its delivery to the original client.
                let collected = http_body_util::Limited::new(response.into_body(), 1 << 20)
                    .collect()
                    .await
                    .unwrap();
                assert_eq!(
                    collected
                        .trailers()
                        .and_then(|trailers| trailers.get("grpc-status"))
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    "0"
                );
                let bytes = collected.to_bytes();
                assert!(bytes.len() >= 5, "successful gRPC reply lacks a frame");
                assert_eq!(bytes[0], 0, "retirement stop reply must be uncompressed");
                let frame_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                assert_eq!(frame_len, bytes.len() - 5);
                let reply = proto::RetirementStatusResponse::decode(&bytes[5..]).unwrap();
                let status: kasumi_types::RetirementStatus = serde_json::from_slice::<
                    Option<kasumi_types::RetirementStatus>,
                >(&reply.response_json)
                .unwrap()
                .expect("the accepted stop has a permanent status");
                let reference = expected_retirement.reference().unwrap();
                assert_eq!(status.reference, reference);
                assert_eq!(status.tenant, expected_retirement.checkpoint.tenant);
                assert_eq!(status.principal, "person");
                assert!(status.accepted_revision > expected_retirement.checkpoint.revision);
                assert_eq!(
                    status.outcome.as_ref().unwrap_err().code,
                    ErrorCode::Conflict
                );
                *successful_reply.lock().unwrap() = Some(status);
                consumed.store(true, Ordering::SeqCst);
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "14")
                    .body(Body::empty())
                    .unwrap()
            }
        }
    }));
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_endpoint = format!("https://localhost:{}", second.local_addr().unwrap().port());
    let second_router = tonic::service::Routes::new(
        NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone()).service(),
    )
    .into_axum_router()
    .layer(axum::middleware::from_fn({
        let effects = second_effects.clone();
        let reads = second_status_reads.clone();
        let blocked = status_reads_blocked.clone();
        move |request: HttpRequest<Body>, next: axum::middleware::Next| {
            let effects = effects.clone();
            let reads = reads.clone();
            let blocked = blocked.clone();
            async move {
                match request.uri().path() {
                    "/kasumi.v1.KasumiAdmin/AbortRetirement" => {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    "/kasumi.v1.KasumiAdmin/RetirementStatus" => {
                        reads.fetch_add(1, Ordering::SeqCst);
                        if blocked.load(Ordering::SeqCst) {
                            return axum::http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .header("grpc-status", "14")
                                .body(Body::empty())
                                .unwrap();
                        }
                    }
                    _ => {}
                }
                next.run(request).await
            }
        }
    }));
    let tls = || {
        kasumi_transport::server_config(
            &server_identity,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap()
    };
    let (first_stop, first_shutdown) = tokio::sync::watch::channel(false);
    let first_task = tokio::spawn(crate::tls::serve_tls(
        first,
        tls(),
        first_router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        first_shutdown,
    ));
    let (second_stop, second_shutdown) = tokio::sync::watch::channel(false);
    let second_task = tokio::spawn(crate::tls::serve_tls(
        second,
        tls(),
        second_router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        second_shutdown,
    ));
    let config = |endpoint| KasumiClientConfig {
        endpoint,
        identity: client_identity.clone(),
        trusted_ca_pem: ca_pem.clone(),
        server_certificate_pins: BTreeSet::from([server_pin]),
    };
    let bearer = application_token
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let endpoints = BTreeMap::from([
        (1, config(first_endpoint)),
        (2, config(second_endpoint)),
    ]);
    let new_pool = || {
        let bearer = bearer.clone();
        KasumiRetirementPool::new(
            endpoints.clone(),
            Arc::new(move || Ok(zeroize::Zeroizing::new(bearer.clone()))),
        )
        .unwrap()
    };
    let mut pool = new_pool();
    let ambiguous = pool
        .abort_retirement(&request, std::time::Duration::from_secs(60))
        .await;
    assert!(
        matches!(ambiguous, Err(kasumi_client::ClientError::Transport(ref status)) if status.code() == Code::Unavailable),
        "the consumed stop response must be lost as a retryable transport error: {ambiguous:?}"
    );
    assert!(first_body_consumed.load(Ordering::SeqCst));
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    assert_eq!(second_effects.load(Ordering::SeqCst), 0);

    // Retain the exact original request across invocations. A new pool has no
    // memory of the effect dispatch and must still perform status-only recovery.
    let saved_request = serde_json::to_vec(&request).unwrap();
    drop(pool);
    let restored_request: kasumi_types::RetireSourceRequest =
        serde_json::from_slice(&saved_request).unwrap();
    assert_eq!(restored_request.reference().unwrap(), reference);

    status_reads_blocked.store(true, Ordering::SeqCst);
    let mut unavailable_pool = new_pool();
    let unavailable = unavailable_pool
        .retirement_status(&reference, std::time::Duration::from_secs(2))
        .await;
    assert!(
        matches!(&unavailable, Err(kasumi_client::ClientError::Transport(status))
            if matches!(status.code(), Code::Unavailable | Code::DeadlineExceeded)),
        "unavailable exact status must remain unresolved: {unavailable:?}"
    );
    assert!(first_status_reads.load(Ordering::SeqCst) > 0);
    assert!(second_status_reads.load(Ordering::SeqCst) > 0);
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    assert_eq!(second_effects.load(Ordering::SeqCst), 0);
    drop(unavailable_pool);

    status_reads_blocked.store(false, Ordering::SeqCst);
    let mut recovery_pool = new_pool();
    let status = recovery_pool
        .retirement_status(
            &restored_request.reference().unwrap(),
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap()
        .expect("the exact committed stop must remain observable");
    assert_eq!(
        first_successful_reply.lock().unwrap().clone(),
        Some(status.clone()),
        "the exact permanent stop was committed before its reply was lost"
    );
    assert_eq!(status.reference, reference);
    assert_eq!(
        status.outcome.as_ref().unwrap_err().code,
        ErrorCode::Conflict
    );
    assert!(first_status_reads.load(Ordering::SeqCst) >= 2);
    assert!(second_status_reads.load(Ordering::SeqCst) >= 2);
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    assert_eq!(second_effects.load(Ordering::SeqCst), 0);

    drop(recovery_pool);
    first_stop.send(true).unwrap();
    second_stop.send(true).unwrap();
    first_task.await.unwrap().unwrap();
    second_task.await.unwrap().unwrap();
    fixture.close().await;
}
