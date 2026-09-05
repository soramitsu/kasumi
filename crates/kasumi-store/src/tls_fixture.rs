//! TLS-only compatibility fixture. No external service or insecure client bypass.
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use std::sync::Arc;

pub(crate) struct TlsFixture {
    pub endpoint: String,
    pub ca_pem: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TlsFixture {
    pub async fn spawn(router: axum::Router) -> Self {
        Self::with_versions(router, &[&rustls::version::TLS13]).await
    }
    pub async fn with_versions(
        router: axum::Router,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let ca_pem = cert.pem().into_bytes();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((tcp, _)) = incoming else { break };
                        let tls = tls.clone(); let router = router.clone();
                        connections.spawn(async move {
                            let Ok(tls) = tls.accept(tcp).await else { return };
                            let service = TowerToHyperService::new(router);
                            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(TokioIo::new(tls), service).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            endpoint,
            ca_pem,
            task,
        }
    }
}
