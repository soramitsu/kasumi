#[tokio::test]
async fn native_listener_reloads_complete_tls_and_rejects_invalid_replacement() {
    use crate::{
        runtime::{MutualTlsEndpoint, TlsFiles},
        tls_reload::{ListenerSource, RuntimeTlsReload},
    };
    use kasumi_client::{KasumiClient, KasumiClientConfig};
    use kasumi_transport::{ClientAuthentication, ReloadableServerConfig, TlsIdentity};
    let fixture = Fixture::new().await;
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&key).unwrap().pem().into_bytes();
    let issuer = rcgen::Issuer::new(ca, key);
    let make_identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap().pem().into_bytes();
        let key = key.serialize_pem().into_bytes();
        (TlsIdentity::from_pem(&cert, &key).unwrap(), cert, key)
    };
    let (first, first_cert, first_key) = make_identity();
    let (second, second_cert, second_key) = make_identity();
    let (client, _, _) = make_identity();
    let files = TlsFiles {
        certificate: fixture._dir.path().join("tls.pem"),
        private_key: fixture._dir.path().join("tls-key.pem"),
    };
    let ca_path = fixture._dir.path().join("ca.pem");
    std::fs::write(&files.certificate, &first_cert).unwrap();
    std::fs::write(&files.private_key, &first_key).unwrap();
    std::fs::write(&ca_path, &ca_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&files.private_key, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = ReloadableServerConfig::new(
        kasumi_transport::server_config(
            &first,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca_pem,
            },
        )
        .unwrap(),
    );
    let reload = RuntimeTlsReload::new(
        vec![(
            ListenerSource::Mutual(MutualTlsEndpoint {
                listen: address,
                tls: files.clone(),
                client_ca: ca_path,
                client_certificate_pins: None,
            }),
            target.clone(),
        )],
        None,
        fixture.audit.clone(),
    );
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        target,
        tonic::service::Routes::new(fixture.data().service()).into_axum_router(),
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let config = KasumiClientConfig {
        endpoint: format!("https://localhost:{}", address.port()),
        identity: client,
        trusted_ca_pem: ca_pem,
        server_certificate_pins: BTreeSet::from([first.certificate_pin()]),
    };
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let token = token.strip_prefix("Bearer ").unwrap();
    let query = serde_json::from_value(
        json!({"collection":"docs", "allow_scan":true}),
    )
    .unwrap();
    let decode_resources = kasumi_client::ClientResources::new(64 << 20, 4).unwrap();
    let decode_options = || kasumi_client::JsonReadOptions {
        resources: decode_resources.clone(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 1 << 20,
            max_json_bytes: 1 << 20,
            max_decoded_bytes: 4 << 20,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
    };
    KasumiClient::connect(&config)
        .await
        .unwrap()
        .query(token, &query, &decode_options())
        .await
        .unwrap();
    // A new certificate paired with an old private key cannot publish any part.
    std::fs::write(&files.certificate, &second_cert).unwrap();
    assert!(reload.reload().await.is_err());
    assert_eq!(reload.generations().unwrap(), vec![1]);
    KasumiClient::connect(&config)
        .await
        .unwrap()
        .query(token, &query, &decode_options())
        .await
        .unwrap();
    std::fs::write(&files.private_key, &second_key).unwrap();
    assert_eq!(reload.reload().await.unwrap(), vec![2]);
    assert!(
        KasumiClient::connect(&config).await.is_err(),
        "retired server pin must fail a fresh connection"
    );
    let mut new_config = config;
    new_config.server_certificate_pins = BTreeSet::from([second.certificate_pin()]);
    KasumiClient::connect(&new_config)
        .await
        .unwrap()
        .query(token, &query, &decode_options())
        .await
        .unwrap();
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn native_listener_admits_only_allowlisted_clients_across_reloads() {
    use crate::{
        client_pins::ClientPins,
        runtime::{MutualTlsEndpoint, TlsFiles},
        tls_reload::{ListenerSource, RuntimeTlsReload},
    };
    use kasumi_client::{KasumiClient, KasumiClientConfig};
    use kasumi_transport::{CertificatePin, ReloadableServerConfig, TlsIdentity};
    let fixture = Fixture::new().await;
    let authority = |name: &str| {
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.distinguished_name.push(rcgen::DnType::CommonName, name);
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = ca.self_signed(&key).unwrap().pem().into_bytes();
        (pem, rcgen::Issuer::new(ca, key))
    };
    let (ca_pem, issuer) = authority("installation");
    let (_, foreign_issuer) = authority("foreign");
    let identity = |issuer: &rcgen::Issuer<'_, rcgen::KeyPair>, client: bool| {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![if client {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        }];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, issuer).unwrap().pem().into_bytes();
        let key = key.serialize_pem().into_bytes();
        (TlsIdentity::from_pem(&cert, &key).unwrap(), cert, key)
    };
    let (server, server_cert, server_key) = identity(&issuer, false);
    let (alice, _, _) = identity(&issuer, true);
    let (bob, _, _) = identity(&issuer, true);
    let (carol, _, _) = identity(&issuer, true);
    let (foreign, _, _) = identity(&foreign_issuer, true);
    let directory = fixture._dir.path();
    let files = TlsFiles {
        certificate: directory.join("tls.pem"),
        private_key: directory.join("tls-key.pem"),
    };
    let ca_path = directory.join("ca.pem");
    let pins_path = directory.join("client-pins.json");
    let write = |path: &std::path::Path, bytes: &[u8]| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    write(&files.certificate, &server_cert);
    write(&files.private_key, &server_key);
    write(&ca_path, &ca_pem);
    let allow = |admitted: &[(&TlsIdentity, &str)]| {
        let mut pins = ClientPins::default();
        for (identity, name) in admitted {
            pins.enroll(identity.certificate_pin(), name).unwrap();
        }
        write(&pins_path, &serde_json::to_vec_pretty(&pins).unwrap());
    };
    allow(&[(&alice, "alice"), (&bob, "bob"), (&foreign, "foreign")]);
    let endpoint = MutualTlsEndpoint {
        listen: "127.0.0.1:1".parse().unwrap(),
        tls: files.clone(),
        client_ca: ca_path.clone(),
        client_certificate_pins: Some(pins_path.clone()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Startup loads the allowlist exactly as a reload does.
    let target = ReloadableServerConfig::new(endpoint.load().unwrap());
    let reload = RuntimeTlsReload::new(
        vec![(ListenerSource::Mutual(endpoint.clone()), target.clone())],
        None,
        fixture.audit.clone(),
    );
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        target,
        tonic::service::Routes::new(fixture.data().service()).into_axum_router(),
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let token = token.strip_prefix("Bearer ").unwrap().to_owned();
    let server_pin: CertificatePin = server.certificate_pin();
    let decode_resources = kasumi_client::ClientResources::new(64 << 20, 4).unwrap();
    // Whether `client` completes a handshake and a request: TLS 1.3 clients
    // may finish before the server refuses their certificate.
    let admitted = |client: &TlsIdentity| {
        let config = KasumiClientConfig {
            endpoint: format!("https://localhost:{}", address.port()),
            identity: client.clone(),
            trusted_ca_pem: ca_pem.clone(),
            server_certificate_pins: BTreeSet::from([server_pin]),
        };
        let token = token.clone();
        let resources = decode_resources.clone();
        async move {
            let query =
                serde_json::from_value(json!({"collection":"docs", "allow_scan":true})).unwrap();
            let options = kasumi_client::JsonReadOptions {
                resources,
                limits: kasumi_client::ClientDecodeLimits {
                    max_request_bytes: 64 << 10,
                    max_wire_bytes: 1 << 20,
                    max_json_bytes: 1 << 20,
                    max_decoded_bytes: 4 << 20,
                    ..Default::default()
                },
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            };
            match KasumiClient::connect(&config).await {
                Ok(mut client) => client.query(&token, &query, &options).await.is_ok(),
                Err(_) => false,
            }
        }
    };
    assert!(admitted(&alice).await && admitted(&bob).await);
    // An unlisted leaf of the trusted CA is refused at the handshake, and a
    // listed pin does not admit another authority's certificate.
    assert!(!admitted(&carol).await);
    assert!(!admitted(&foreign).await);
    // Removing bob's pin refuses bob's next handshake once the listener reloads.
    allow(&[(&alice, "alice"), (&carol, "carol")]);
    assert!(
        admitted(&bob).await,
        "the file alone changes nothing before a reload"
    );
    assert_eq!(reload.reload().await.unwrap(), vec![2]);
    assert!(!admitted(&bob).await);
    assert!(admitted(&alice).await && admitted(&carol).await);
    // A malformed or missing allowlist is refused and keeps the generation
    // before it: carol stays admitted and bob refused.
    write(
        &pins_path,
        br#"{"format":1,"certificates":[{"pin":"not-a-pin","name":"x"}]}"#,
    );
    assert!(reload.reload().await.is_err());
    std::fs::remove_file(&pins_path).unwrap();
    assert!(reload.reload().await.is_err());
    assert!(endpoint.load().is_err(), "startup refuses it too");
    assert_eq!(reload.generations().unwrap(), vec![2]);
    assert!(admitted(&carol).await && !admitted(&bob).await);
    // An explicitly empty allowlist admits no one.
    allow(&[]);
    assert_eq!(reload.reload().await.unwrap(), vec![3]);
    assert!(!admitted(&alice).await && !admitted(&carol).await);
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    fixture.close().await;
}
