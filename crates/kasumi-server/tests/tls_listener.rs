mod tls_support;

use anyhow::Result;
use axum::{Router, routing::get};
use kasumi_server::tls::{ListenerLimits, serve_tls};
use kasumi_transport::{ClientAuthentication, grpc_channel, peer_client_config, server_config};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tls_support::{Authority, client};

#[tokio::test]
async fn native_grpc_channel_uses_pinned_tls13_and_http2_with_no_plaintext_fallback() -> Result<()>
{
    use kasumi_server::{
        api::DatabaseRegistry,
        auth::{AuthConfig, Authenticator},
        rpc::{
            NativeData,
            proto::{CollectionsRequest, kasumi_data_client::KasumiDataClient},
        },
    };
    let ca = Authority::new()?;
    let server = ca.issue("127.0.0.1")?;
    let caller = ca.issue("service.example")?;
    let auth = Authenticator::new(AuthConfig {
        issuer: "https://issuer.example".into(),
        audience: "https://kasumi.example".into(),
        source: kasumi_server::auth::AuthKeySource::ExternalOAuth {
            jwks_uri: "https://issuer.example/keys".into(),
            trusted_ca_pem: None,
        },
        algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_token_types: BTreeSet::from(["at+jwt".into()]),
    })?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}", listener.local_addr()?);
    let service = NativeData::new(DatabaseRegistry::default(), auth).service();
    let router = tonic::service::Routes::new(service).into_axum_router();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(serve_tls(
        listener,
        server_config(
            &server.tls()?,
            ClientAuthentication::Required {
                trusted_ca_pem: ca.pem.as_bytes(),
            },
        )?,
        router,
        ListenerLimits::default(),
        tls_support::audit(),
        stopped,
    ));
    let pins = BTreeSet::from([server.tls()?.certificate_pin()]);
    let channel = grpc_channel(&endpoint, &caller.tls()?, ca.pem.as_bytes(), pins.clone()).await?;
    // A real gRPC request crosses the pinned TLS channel and reaches per-request
    // auth; lack of bearer token returns the service's expected gRPC status.
    let error = KasumiDataClient::new(channel)
        .collections(CollectionsRequest {})
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    let mut client_config = kasumi_client::KasumiClientConfig {
        endpoint: endpoint.clone(),
        identity: caller.tls()?,
        trusted_ca_pem: ca.pem.as_bytes().to_vec(),
        server_certificate_pins: pins.clone(),
    };
    let mut typed = kasumi_client::KasumiClient::connect(&client_config).await?;
    let snapshot_resources = kasumi_client::ClientResources::new(16 << 20, 8).unwrap();
    let snapshot_options = |duration| kasumi_client::SnapshotReadOptions {
        resources: snapshot_resources.clone(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 64 << 10,
            max_json_bytes: 64 << 10,
            max_decoded_bytes: 2 << 20,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + duration,
        expected_incarnation: uuid::Uuid::from_u128(1),
    };
    let error = typed
        .read_snapshot(
            "invalid",
            &kasumi_types::ReadSnapshotRequest {
                documents: vec![kasumi_types::DocumentKey {
                    collection: "docs".into(),
                    id: "a".into(),
                }],
                queries: vec![],
            },
            &snapshot_options(std::time::Duration::from_secs(4)),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        kasumi_client::ClientError::DecodeRejected {
            code: tonic::Code::Unauthenticated,
            ..
        }
    ));
    drop(typed);
    client_config.server_certificate_pins.clear();
    assert!(
        kasumi_client::KasumiClient::connect(&client_config)
            .await
            .is_err()
    );
    client_config.server_certificate_pins = BTreeSet::from([[0; 32]]);
    assert!(
        kasumi_client::KasumiClient::connect(&client_config)
            .await
            .is_err()
    );
    client_config.server_certificate_pins = pins.clone();
    client_config.endpoint = endpoint.replacen("https:", "http:", 1);
    assert!(
        kasumi_client::KasumiClient::connect(&client_config)
            .await
            .is_err()
    );
    assert!(
        grpc_channel(
            &endpoint,
            &caller.tls()?,
            ca.pem.as_bytes(),
            BTreeSet::from([[0; 32]])
        )
        .await
        .is_err()
    );
    assert!(
        grpc_channel(
            &endpoint.replacen("https:", "http:", 1),
            &caller.tls()?,
            ca.pem.as_bytes(),
            pins
        )
        .await
        .is_err()
    );
    stop.send(true)?;
    task.await??;
    Ok(())
}
use tokio::{net::TcpListener, sync::watch};

#[tokio::test]
async fn mutual_tls_requires_trusted_client_and_rejects_tls12() -> Result<()> {
    let ca = Authority::new()?;
    let server = ca.issue("127.0.0.1")?;
    let service = ca.issue("service.example")?;
    let outsider_ca = Authority::new()?;
    let outsider = outsider_ca.issue("outsider.example")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}/ready", listener.local_addr()?);
    let (stop, stopped) = watch::channel(false);
    let audit = tls_support::audit();
    let task = tokio::spawn(serve_tls(
        listener,
        server_config(
            &server.tls()?,
            ClientAuthentication::Required {
                trusted_ca_pem: ca.pem.as_bytes(),
            },
        )?,
        Router::new().route("/ready", get(|| async { "ready" })),
        ListenerLimits::default(),
        audit.clone(),
        stopped,
    ));
    assert_eq!(
        client(&ca, Some(&service))?
            .get(&endpoint)
            .send()
            .await?
            .text()
            .await?,
        "ready"
    );
    assert!(client(&ca, None)?.get(&endpoint).send().await.is_err());
    assert!(
        client(&ca, Some(&outsider))?
            .get(&endpoint)
            .send()
            .await
            .is_err()
    );
    let legacy = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem.as_bytes())?)
        .identity(service.reqwest()?)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()?;
    assert!(legacy.get(&endpoint).send().await.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if audit
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.outcome == kasumi_server::tls::TlsHandshakeOutcome::Rejected)
                .count()
                >= 3
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await?;
    let events = audit.events.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.outcome == kasumi_server::tls::TlsHandshakeOutcome::Accepted)
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .all(|event| event.timestamp_ms > 0 && !event.connection_id.is_empty())
    );
    stop.send(true)?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn authentication_audit_failure_or_timeout_never_releases_http_requests() -> Result<()> {
    use kasumi_server::tls::{TlsHandshakeAudit, TlsHandshakeEvent};
    struct Stalled;
    #[async_trait::async_trait]
    impl TlsHandshakeAudit for Stalled {
        async fn record(&self, _: &TlsHandshakeEvent) -> Result<()> {
            std::future::pending().await
        }
    }
    let ca = Authority::new()?;
    let server = ca.issue("127.0.0.1")?;
    let failure = tls_support::audit();
    failure.fail.store(true, Ordering::Release);
    for audit in [failure as Arc<dyn TlsHandshakeAudit>, Arc::new(Stalled)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://{}/ready", listener.local_addr()?);
        let (stop, stopped) = watch::channel(false);
        let limits = ListenerLimits {
            handshake_timeout: std::time::Duration::from_millis(100),
            ..ListenerLimits::default()
        };
        let task = tokio::spawn(serve_tls(
            listener,
            server_config(&server.tls()?, ClientAuthentication::OAuth)?,
            Router::new().route(
                "/ready",
                get(move || {
                    let calls = observed.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        "ready"
                    }
                }),
            ),
            limits,
            audit,
            stopped,
        ));
        assert!(client(&ca, None)?.get(&endpoint).send().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        stop.send(true)?;
        task.await??;
    }
    Ok(())
}

#[tokio::test]
async fn oauth_listener_allows_tls_without_client_cert_but_peer_pins_fail_before_http() -> Result<()>
{
    let ca = Authority::new()?;
    let server = ca.issue("127.0.0.1")?;
    let alternate_server = ca.issue("127.0.0.1")?;
    let caller = ca.issue("client.example")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}/ready", listener.local_addr()?);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(serve_tls(
        listener,
        server_config(&server.tls()?, ClientAuthentication::OAuth)?,
        Router::new().route(
            "/ready",
            get(move || {
                let calls = observed.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    "ready"
                }
            }),
        ),
        ListenerLimits::default(),
        tls_support::audit(),
        stopped,
    ));
    let pin_mismatch = peer_client_config(
        &caller.tls()?,
        ca.pem.as_bytes(),
        BTreeSet::from([alternate_server.tls()?.certificate_pin()]),
    )?;
    let mismatched = reqwest::Client::builder()
        .no_proxy()
        .use_preconfigured_tls(pin_mismatch)
        .build()?;
    assert!(mismatched.get(&endpoint).send().await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "HTTP must not start before node-specific pin verification"
    );
    assert_eq!(
        client(&ca, None)?
            .get(&endpoint)
            .send()
            .await?
            .text()
            .await?,
        "ready"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(true)?;
    task.await??;
    Ok(())
}
