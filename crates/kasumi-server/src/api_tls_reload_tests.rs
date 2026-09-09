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
        json!({"collection":"docs", "filter":{"op":"all"}, "allow_scan":true}),
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
