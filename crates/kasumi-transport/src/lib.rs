//! Shared TLS 1.3, mutual authentication and certificate pinning for Kasumi.
pub mod credentials;
mod reload;
use anyhow::{Context, Result, ensure};
use hyper_util::rt::TokioIo;
pub use reload::ReloadableServerConfig;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

pub type CertificatePin = [u8; 32];

/// Private key material is deliberately neither Debug nor serializable.
pub struct TlsIdentity {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl Clone for TlsIdentity {
    fn clone(&self) -> Self {
        Self {
            certificates: self.certificates.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl TlsIdentity {
    pub fn from_pem(certificates: &[u8], private_key: &[u8]) -> Result<Self> {
        let certificates = certificates_from_pem(certificates)?;
        let private_key = PrivateKeyDer::from_pem_slice(private_key)
            .context("TLS private key missing or malformed")?;
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
    let certificates = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
    ensure!(!certificates.is_empty(), "TLS certificates missing");
    Ok(certificates)
}

pub fn certificate_pin(pem: &[u8]) -> Result<CertificatePin> {
    Ok(certificate_digest(&certificates_from_pem(pem)?[0]))
}

pub fn certificate_digest(certificate: &CertificateDer<'_>) -> CertificatePin {
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
    // This config is shared by pinned cluster HTTP and native gRPC peers.
    // Require HTTP/2 for authenticated, multiplexed peer traffic.
    config.alpn_protocols = vec![b"h2".to_vec()];
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
    let endpoint = url::Url::parse(endpoint)?;
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
    let origin: http::Uri = endpoint.as_str().parse()?;
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
        .connect_with_connector(tower::service_fn(move |_uri: http::Uri| {
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
