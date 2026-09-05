//! TLS 1.3-only HTTP listeners shared by native RPC, MCP, and cluster traffic.
use std::{collections::BTreeSet, future::Future, io::Cursor, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

pub type CertificatePin = [u8; 32];

/// Private key material is deliberately neither Debug nor serializable.
pub struct TlsIdentity {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    pub fn from_pem(certificates: &[u8], private_key: &[u8]) -> Result<Self> {
        let certificates = certificates_from_pem(certificates)?;
        let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key))?
            .context("TLS private key missing")?;
        Ok(Self {
            certificates,
            private_key,
        })
    }
    pub fn certificate_pin(&self) -> CertificatePin {
        certificate_digest(&self.certificates[0])
    }
}

fn certificates_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certificates.is_empty(), "TLS certificates missing");
    Ok(certificates)
}

pub fn certificate_pin(pem: &[u8]) -> Result<CertificatePin> {
    Ok(certificate_digest(&certificates_from_pem(pem)?[0]))
}

fn certificate_digest(certificate: &CertificateDer<'_>) -> CertificatePin {
    Sha256::digest(certificate.as_ref()).into()
}

fn roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates_from_pem(pem)? {
        roots.add(certificate)?;
    }
    Ok(roots)
}

/// Use Required for native data/admin and cluster listeners. MCP authenticates
/// each HTTP request with OAuth and uses OAuth at this transport boundary.
pub enum ClientAuthentication<'a> {
    Required { trusted_ca_pem: &'a [u8] },
    OAuth,
}

pub fn server_config(
    identity: &TlsIdentity,
    authentication: ClientAuthentication<'_>,
) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let builder = match authentication {
        ClientAuthentication::Required { trusted_ca_pem } => {
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(trusted_ca_pem)?),
                provider,
            )
            .build()?;
            builder.with_client_cert_verifier(verifier)
        }
        ClientAuthentication::OAuth => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(
        identity.certificates.clone(),
        identity.private_key.clone_key(),
    )?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinnedServerVerifier {
    trusted: Arc<WebPkiServerVerifier>,
    pins: BTreeSet<CertificatePin>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified =
            self.trusted
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        if !self.pins.contains(&certificate_digest(end_entity)) {
            return Err(rustls::Error::General(
                "configured peer certificate does not match".into(),
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.trusted
            .verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.trusted
            .verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.trusted.supported_verify_schemes()
    }
}

/// CA chain, DNS/IP name, certificate validity, and the configured node-specific
/// leaf pin are all checked during the TLS handshake, before any request bytes.
pub fn peer_client_config(
    identity: &TlsIdentity,
    trusted_ca_pem: &[u8],
    pins: BTreeSet<CertificatePin>,
) -> Result<ClientConfig> {
    ensure!(!pins.is_empty(), "peer certificate pins missing");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let trusted = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots(trusted_ca_pem)?),
        provider.clone(),
    )
    .build()?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier { trusted, pins }))
        .with_client_auth_cert(
            identity.certificates.clone(),
            identity.private_key.clone_key(),
        )?;
    config.enable_early_data = false;
    Ok(config)
}

/// Native gRPC channel using the same TLS 1.3, mutual-authentication and pin
/// verifier as peers. The connector always encrypts its TCP stream. Tonic's
/// internal connector URI uses http solely to avoid wrapping that TLS stream a
/// second time; the HTTP/2 request origin remains the configured HTTPS origin.
pub async fn grpc_channel(
    endpoint: &str,
    identity: &TlsIdentity,
    trusted_ca_pem: &[u8],
    pins: BTreeSet<CertificatePin>,
) -> Result<tonic::transport::Channel> {
    let endpoint = reqwest::Url::parse(endpoint)?;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && matches!(endpoint.path(), "" | "/"),
        "native RPC endpoint must be an HTTPS origin"
    );
    let host = endpoint
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = endpoint
        .port_or_known_default()
        .context("RPC endpoint port missing")?;
    let name = ServerName::try_from(host.clone()).context("invalid RPC server name")?;
    let origin: axum::http::Uri = endpoint.as_str().parse()?;
    let mut transport_endpoint = endpoint.clone();
    transport_endpoint
        .set_scheme("http")
        .map_err(|_| anyhow::anyhow!("invalid RPC transport origin"))?;
    let mut config = peer_client_config(identity, trusted_ca_pem, pins)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let channel = tonic::transport::Endpoint::from_shared(transport_endpoint.to_string())?
        .origin(origin)
        .connect_timeout(Duration::from_secs(5))
        .concurrency_limit(64)
        .buffer_size(64)
        .connect_with_connector(tower::service_fn(move |_uri: axum::http::Uri| {
            let host = host.clone();
            let name = name.clone();
            let connector = connector.clone();
            async move {
                let socket = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                socket.set_nodelay(true)?;
                let stream = connector.connect(name, socket).await?;
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(std::io::Error::other("RPC peer did not negotiate HTTP/2"));
                }
                Ok(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(channel)
}

/// Derived from the completed TLS handshake, never HTTP headers. The Option is
/// None only on a listener configured for OAuth rather than mutual TLS.
#[derive(Clone, Debug)]
pub struct AuthenticatedTlsPeer {
    certificate_pin: Option<CertificatePin>,
}

impl AuthenticatedTlsPeer {
    pub fn certificate_pin(&self) -> Option<CertificatePin> {
        self.certificate_pin
    }
}

#[derive(Clone, Debug)]
pub struct ListenerLimits {
    pub max_connections: usize,
    pub max_http2_streams: u32,
    pub handshake_timeout: Duration,
    pub drain_timeout: Duration,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsHandshakeOutcome {
    Accepted,
    Rejected,
    TimedOut,
}

/// Connection metadata only. No token, certificate body, document, or query
/// content enters authentication audit records.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TlsHandshakeEvent {
    pub connection_id: String,
    pub peer_address: std::net::SocketAddr,
    pub certificate_pin: Option<CertificatePin>,
    pub outcome: TlsHandshakeOutcome,
    pub timestamp_ms: u64,
}

#[async_trait]
pub trait TlsHandshakeAudit: Send + Sync + 'static {
    /// Return success only after the event is durably persisted under the
    /// operator's security-audit key, independently of customer tenant keys.
    /// Authentication success is never released to HTTP before this succeeds.
    async fn record(&self, event: &TlsHandshakeEvent) -> Result<()>;
}

async fn audit_handshake(
    audit: &dyn TlsHandshakeAudit,
    peer_address: std::net::SocketAddr,
    pin: Option<CertificatePin>,
    outcome: TlsHandshakeOutcome,
    timeout: Duration,
) -> Result<()> {
    let event = TlsHandshakeEvent {
        connection_id: uuid::Uuid::new_v4().to_string(),
        peer_address,
        certificate_pin: pin,
        outcome,
        timestamp_ms: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?,
    };
    tokio::time::timeout(timeout, audit.record(&event))
        .await
        .context("TLS authentication audit timed out")?
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_http2_streams: 32,
            handshake_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(10),
        }
    }
}

/// Serves an Axum router over strict TLS. Stops accepting on shutdown, requests
/// graceful connection shutdown, then bounds draining before aborting leftovers.
pub async fn serve_tls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: Router,
    limits: ListenerLimits,
    audit: Arc<dyn TlsHandshakeAudit>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    serve_tls_source(
        listener,
        config,
        router,
        limits,
        audit,
        shutdown,
        |socket| socket.set_nodelay(true),
    )
    .await
}

trait ConnectionSource: Send {
    fn accept(
        &mut self,
    ) -> impl Future<Output = std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>> + Send;
}

impl ConnectionSource for TcpListener {
    async fn accept(&mut self) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
        TcpListener::accept(self).await
    }
}

async fn serve_tls_source(
    mut listener: impl ConnectionSource,
    config: Arc<ServerConfig>,
    router: Router,
    limits: ListenerLimits,
    audit: Arc<dyn TlsHandshakeAudit>,
    mut shutdown: watch::Receiver<bool>,
    configure_socket: impl Fn(&tokio::net::TcpStream) -> std::io::Result<()>
    + Clone
    + Send
    + Sync
    + 'static,
) -> Result<()> {
    ensure!(
        limits.max_connections > 0
            && limits.max_http2_streams > 0
            && !limits.handshake_timeout.is_zero()
            && !limits.drain_timeout.is_zero(),
        "invalid TLS listener limits"
    );
    let acceptor = TlsAcceptor::from(config);
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();
    let (connection_stop, connection_shutdown) = watch::channel(false);
    let mut outcome = Ok(());
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            connection = listener.accept() => {
                let (socket, address) = match connection {
                    Ok(connection) => connection,
                    Err(error) => { outcome = Err(error.into()); break; },
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else { drop(socket); continue; };
                let acceptor = acceptor.clone();
                let configure_socket = configure_socket.clone();
                let router = router.clone();
                let limits = limits.clone();
                let audit = audit.clone();
                let mut shutdown = connection_shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    // A peer can reset while queued before the listener starts.
                    // On macOS even TCP_NODELAY then returns EINVAL. This closes
                    // and audits that connection; it must not stop the listener.
                    if configure_socket(&socket).is_err() {
                        drop(socket);
                        let _ = audit_handshake(audit.as_ref(), address, None, TlsHandshakeOutcome::Rejected, limits.handshake_timeout).await;
                        return;
                    }
                    let stream = match tokio::time::timeout(limits.handshake_timeout, acceptor.accept(socket)).await {
                        Ok(Ok(stream)) => stream,
                        outcome => {
                            let outcome = if outcome.is_err() { TlsHandshakeOutcome::TimedOut } else { TlsHandshakeOutcome::Rejected };
                            let _ = audit_handshake(audit.as_ref(), address, None, outcome, limits.handshake_timeout).await;
                            return;
                        },
                    };
                    if *shutdown.borrow() { return; }
                    let peer = AuthenticatedTlsPeer { certificate_pin: stream.get_ref().1.peer_certificates().and_then(|certificates| certificates.first()).map(certificate_digest) };
                    if audit_handshake(audit.as_ref(), address, peer.certificate_pin, TlsHandshakeOutcome::Accepted, limits.handshake_timeout).await.is_err() {
                        return;
                    }
                    let service = TowerToHyperService::new(router.layer(Extension(peer)));
                    let mut builder = Builder::new(TokioExecutor::new());
                    builder.http1().max_buf_size(32 * 1024).timer(TokioTimer::new()).header_read_timeout(limits.handshake_timeout);
                    builder.http2().max_concurrent_streams(limits.max_http2_streams);
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = shutdown.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(limits.drain_timeout, connection).await;
                        }
                    }
                });
            }
        }
    }
    // A listener I/O error also requests graceful connection shutdown. Always
    // join the nested owners before returning its original error to the runtime.
    connection_stop.send_replace(true);
    drop(listener);
    if tokio::time::timeout(limits.drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    outcome
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use axum::{extract::State, routing::post};
    use kasumi_store::NodeStore;
    use std::sync::Mutex;

    struct FailingSource {
        listener: TcpListener,
        failure: tokio::sync::oneshot::Receiver<std::io::Error>,
        failed: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl ConnectionSource for FailingSource {
        async fn accept(
            &mut self,
        ) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
            tokio::select! {
                failure = &mut self.failure => {
                    let _ = self.failed.take().unwrap().send(());
                    Err(failure.unwrap())
                },
                connection = self.listener.accept() => connection,
            }
        }
    }
    struct Audit;
    #[async_trait]
    impl TlsHandshakeAudit for Audit {
        async fn record(&self, _: &TlsHandshakeEvent) -> Result<()> {
            Ok(())
        }
    }
    struct RequestState {
        node: Arc<NodeStore>,
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<tokio::sync::Notify>,
    }
    async fn request(State(state): State<Arc<RequestState>>) -> &'static str {
        state
            .entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        state.release.notified().await;
        assert!(Arc::strong_count(&state.node) > 0);
        "completed before listener returned"
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_io_failure_drains_active_tls_request_before_releasing_node() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accept-error.redb");
        let node = NodeStore::open(&path).unwrap();
        let weak = Arc::downgrade(&node);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let identity = TlsIdentity::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/request",
            socket.local_addr().unwrap().port()
        );
        let (entered, ready) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let router = Router::new()
            .route("/request", post(request))
            .with_state(Arc::new(RequestState {
                node,
                entered: Mutex::new(Some(entered)),
                release: release.clone(),
            }));
        let (inject, failure) = tokio::sync::oneshot::channel();
        let (failed, failure_observed) = tokio::sync::oneshot::channel();
        let (_stop, shutdown) = watch::channel(false);
        let mut server = tokio::spawn(serve_tls_source(
            FailingSource {
                listener: socket,
                failure,
                failed: Some(failed),
            },
            server_config(&identity, ClientAuthentication::OAuth).unwrap(),
            router,
            ListenerLimits::default(),
            Arc::new(Audit),
            shutdown,
            |socket| socket.set_nodelay(true),
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
            .build()
            .unwrap();
        let response = tokio::spawn(async move {
            client
                .post(endpoint)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(10), ready)
            .await
            .unwrap()
            .unwrap();
        inject
            .send(std::io::Error::other("injected listener accept failure"))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), failure_observed)
            .await
            .unwrap()
            .unwrap();
        // The accepted request is deliberately paused: an I/O error must not
        // finish the parent listener by abandoning that nested request task.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err()
        );
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected listener accept failure")
        );
        assert_eq!(
            response.await.unwrap(),
            "completed before listener returned"
        );
        assert!(weak.upgrade().is_none());
        drop(NodeStore::open(&path).unwrap());
    }

    struct RecordingAudit(tokio::sync::mpsc::UnboundedSender<TlsHandshakeEvent>);
    #[async_trait]
    impl TlsHandshakeAudit for RecordingAudit {
        async fn record(&self, event: &TlsHandshakeEvent) -> Result<()> {
            self.0.send(event.clone()).unwrap();
            Ok(())
        }
    }

    struct QueuedSource {
        listener: TcpListener,
        wait_for_first_reset: bool,
    }
    impl ConnectionSource for QueuedSource {
        async fn accept(
            &mut self,
        ) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
            let (socket, address) = self.listener.accept().await?;
            if std::mem::take(&mut self.wait_for_first_reset) {
                // Observe the kernel's reset state before socket configuration,
                // without a sleep or timing assumption about packet delivery.
                loop {
                    socket.readable().await?;
                    match socket.try_read(&mut [0]) {
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                        Ok(0) => break,
                        outcome => panic!("queued client did not reset: {outcome:?}"),
                    }
                }
            }
            Ok((socket, address))
        }
    }

    async fn rejected_setup_keeps_listener_available(reset: bool) {
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let identity = TlsIdentity::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let queued = tokio::net::TcpStream::connect(address).await.unwrap();
        let peer = queued.local_addr().unwrap();
        let queued = if reset {
            // Send RST while the connection is queued and no listener task is
            // accepting, as happens when startup outlasts a client's deadline.
            #[allow(deprecated)]
            queued.set_linger(Some(Duration::ZERO)).unwrap();
            drop(queued);
            None
        } else {
            Some(queued)
        };
        let (events, mut records) = tokio::sync::mpsc::unbounded_channel();
        let (stop, shutdown) = watch::channel(false);
        let first_setup = Arc::new(AtomicBool::new(true));
        let first_errno = Arc::new(AtomicI32::new(0));
        let observed_errno = first_errno.clone();
        let server = tokio::spawn(serve_tls_source(
            QueuedSource {
                listener,
                wait_for_first_reset: reset,
            },
            server_config(&identity, ClientAuthentication::OAuth).unwrap(),
            Router::new().route("/request", post(|| async { "listener remains available" })),
            ListenerLimits::default(),
            Arc::new(RecordingAudit(events)),
            shutdown,
            move |socket| {
                let first = first_setup.swap(false, Ordering::SeqCst);
                let result = if first && !reset {
                    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
                } else {
                    socket.set_nodelay(true)
                };
                if first && let Err(error) = &result {
                    observed_errno.store(error.raw_os_error().unwrap_or(-1), Ordering::SeqCst);
                }
                result
            },
        ));
        let denied = tokio::time::timeout(Duration::from_secs(10), records.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(denied.peer_address, peer);
        assert_eq!(denied.outcome, TlsHandshakeOutcome::Rejected);
        assert_eq!(denied.certificate_pin, None);
        assert!(!server.is_finished());
        if !reset {
            assert_eq!(first_errno.load(Ordering::SeqCst), -1);
        }
        #[cfg(target_os = "macos")]
        if reset {
            assert_eq!(first_errno.load(Ordering::SeqCst), 22);
        }
        drop(queued);
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let response = client
            .post(format!("https://localhost:{}/request", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "listener remains available");
        let accepted = records.recv().await.unwrap();
        assert_eq!(accepted.outcome, TlsHandshakeOutcome::Accepted);
        assert!(!server.is_finished());
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_setup_failure_is_audited_and_does_not_stop_listener() {
        rejected_setup_keeps_listener_available(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_queued_before_listener_start_is_audited_and_next_tls_request_succeeds() {
        rejected_setup_keeps_listener_available(true).await;
    }
}
