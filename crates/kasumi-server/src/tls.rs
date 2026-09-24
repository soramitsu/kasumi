//! TLS 1.3-only HTTP listeners shared by native RPC, MCP, and cluster traffic.
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use kasumi_transport::{CertificatePin, certificate_digest};
#[cfg(test)]
use kasumi_transport::{ClientAuthentication, TlsIdentity, server_config};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};
use tokio_rustls::TlsAcceptor;

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
pub fn serve_tls(
    listener: TcpListener,
    config: impl Into<kasumi_transport::ReloadableServerConfig>,
    router: Router,
    limits: ListenerLimits,
    audit: Arc<dyn TlsHandshakeAudit>,
    shutdown: watch::Receiver<bool>,
) -> ServingListener {
    let config = config.into();
    let inventory = Arc::new(ListenerInventory::new(limits));
    ServingListener {
        inventory: inventory.clone(),
        running: Box::pin(serve_tls_source(
            listener,
            config,
            router,
            audit,
            shutdown,
            |socket| socket.set_nodelay(true),
            inventory,
        )),
    }
}

/// The runtime retains `inventory` separately from this future's task handle.
/// An externally aborted listener cannot destroy its nested connection census.
pub struct ServingListener {
    inventory: Arc<ListenerInventory>,
    running: std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send>>,
}
impl Future for ServingListener {
    type Output = Result<()>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.running.as_mut().poll(cx)
    }
}
impl ServingListener {
    pub(crate) fn inventory(&self) -> Arc<ListenerInventory> {
        self.inventory.clone()
    }
}
pub(crate) struct ListenerInventory {
    connections: crate::tls_tasks::Tasks,
    streams: crate::tls_tasks::Tasks,
    stop: watch::Sender<bool>,
    limits: ListenerLimits,
    report: tokio::sync::Mutex<kasumi_types::drain::DrainReport>,
}
impl ListenerInventory {
    fn new(limits: ListenerLimits) -> Self {
        Self {
            connections: crate::tls_tasks::Tasks::new(limits.max_connections),
            // Invalid/overflowing settings fail before accepting any socket.
            // Hyper 1.11.1 dispatches H2Stream and, for a successful
            // CONNECT, UpgradedSendStreamTask before that H2Stream exits.
            // Account for both concurrently, including the transition overlap.
            streams: crate::tls_tasks::Tasks::new(
                limits
                    .max_connections
                    .checked_mul(limits.max_http2_streams as usize)
                    .and_then(|streams| streams.checked_mul(2))
                    .unwrap_or(0),
            ),
            stop: watch::channel(false).0,
            limits,
            report: Default::default(),
        }
    }
    pub(crate) async fn drain(&self) -> kasumi_types::drain::DrainResult {
        self.stop.send_replace(true);
        let mut report = self.report.lock().await;
        if let Err(failure) = self.connections.drain(self.limits.drain_timeout).await {
            report.merge(&failure);
        }
        // Connections have stopped dispatching new streams. Seal and join the
        // exact Hyper executor task inventory before declaring listener drain.
        if let Err(failure) = self.streams.drain(self.limits.drain_timeout).await {
            report.merge(&failure);
        }
        report.complete()
    }
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
    config: impl Into<kasumi_transport::ReloadableServerConfig>,
    router: Router,
    audit: Arc<dyn TlsHandshakeAudit>,
    mut shutdown: watch::Receiver<bool>,
    configure_socket: impl Fn(&tokio::net::TcpStream) -> std::io::Result<()>
    + Clone
    + Send
    + Sync
    + 'static,
    inventory: Arc<ListenerInventory>,
) -> Result<()> {
    let limits = inventory.limits.clone();
    ensure!(
        limits.max_connections > 0
            && limits.max_connections <= Semaphore::MAX_PERMITS
            && limits.max_http2_streams > 0
            && !limits.handshake_timeout.is_zero()
            && !limits.drain_timeout.is_zero()
            && limits
                .max_connections
                .checked_mul(limits.max_http2_streams as usize)
                .and_then(|streams| streams.checked_mul(2))
                .is_some(),
        "invalid TLS listener limits"
    );
    let config = config.into();
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let tasks = inventory.connections.clone();
    let connection_shutdown = inventory.stop.subscribe();
    let mut task_failure = tasks.failure();
    let mut stream_failure = inventory.streams.failure();
    let outcome = crate::startup_preparation::capture("TLS listener", async {
    let mut outcome = Ok(());
    loop {
        if *shutdown.borrow() || *task_failure.borrow() || *stream_failure.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = task_failure.changed() => break,
            _ = stream_failure.changed() => break,
            _ = tasks.next(), if !tasks.is_empty() => {},
            _ = inventory.streams.next(), if !inventory.streams.is_empty() => {},
            connection = listener.accept() => {
                let (socket, address) = match connection {
                    Ok(connection) => connection,
                    Err(error) => { outcome = Err(error.into()); break; },
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else { drop(socket); continue; };
                let mut generation_change = config.subscribe();
                let (generation, current) = config.snapshot_generation()?;
                let acceptor = TlsAcceptor::from(current);
                let configure_socket = configure_socket.clone();
                let router = router.clone();
                let limits = limits.clone();
                let audit = audit.clone();
                let mut shutdown = connection_shutdown.clone();
                let executor = inventory.streams.clone();
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
                    if *shutdown.borrow() || *generation_change.borrow() != generation { return; }
                    let peer = AuthenticatedTlsPeer { certificate_pin: stream.get_ref().1.peer_certificates().and_then(|certificates| certificates.first()).map(certificate_digest) };
                    if audit_handshake(audit.as_ref(), address, peer.certificate_pin, TlsHandshakeOutcome::Accepted, limits.handshake_timeout).await.is_err() {
                        return;
                    }
                    let service = TowerToHyperService::new(router.layer(Extension(peer)));
                    let mut builder = Builder::new(executor);
                    builder.http1().max_buf_size(32 * 1024).timer(TokioTimer::new()).header_read_timeout(limits.handshake_timeout);
                    builder.http2().max_concurrent_streams(limits.max_http2_streams);
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = generation_change.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(limits.drain_timeout, connection).await;
                        },
                        _ = shutdown.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(limits.drain_timeout, connection).await;
                        }
                    }
                });
            }
        }
    }
    outcome
    }).await;
    // The inventory lives outside the caught accept loop and is also held by
    // the outer serving owner. Poll panic, I/O error and snapshot errors all use
    // the same positive nested-task drain before returning their original cause.
    drop(listener);
    let drain = inventory.drain().await.map_err(Into::into);
    crate::runtime_drain::combine(outcome, drain)
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
    #[tokio::test]
    async fn unsupported_listener_capacity_returns_error_without_spawning_owners() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let identity = TlsIdentity::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        for (connections, streams) in [
            (Semaphore::MAX_PERMITS + 1, 1),
            (Semaphore::MAX_PERMITS, u32::MAX),
        ] {
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (_stop, shutdown) = watch::channel(false);
            let listener = serve_tls(
                socket,
                server_config(&identity, ClientAuthentication::OAuth).unwrap(),
                Router::new(),
                ListenerLimits {
                    max_connections: connections,
                    max_http2_streams: streams,
                    ..Default::default()
                },
                Arc::new(Audit),
                shutdown,
            );
            let inventory = listener.inventory();
            let error = tokio::time::timeout(Duration::from_secs(5), listener)
                .await
                .unwrap()
                .unwrap_err();
            assert!(error.to_string().contains("invalid TLS listener limits"));
            assert!(inventory.connections.is_empty());
            assert!(inventory.streams.is_empty());
            inventory.drain().await.unwrap();
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
        state.node.shutdown().await.unwrap();
        "completed before listener returned"
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_io_failure_drains_active_tls_request_before_releasing_node() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                .unwrap();
        let path = directory.path().join("persistent/accept-error.kv");
        let node = physical
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
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
            Arc::new(Audit),
            shutdown,
            |socket| socket.set_nodelay(true),
            Arc::new(ListenerInventory::new(ListenerLimits::default())),
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
        let reopened = physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        reopened.shutdown().await.unwrap();
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
            Arc::new(ListenerInventory::new(ListenerLimits::default())),
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
