//! Shared TLS 1.3, mutual authentication and certificate pinning for Kasumi.
pub mod credentials;
mod reload;
use anyhow::{Context, Result, ensure};
use hyper_util::rt::TokioIo;
pub use reload::ReloadableServerConfig;
use rustls::{
    ClientConfig, DistinguishedName, RootCertStore, ServerConfig,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::danger::{ClientCertVerified, ClientCertVerifier},
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

impl Drop for TlsIdentity {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key);
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

    /// Identity of the loaded leaf certificate's public key. Reissued
    /// certificates with the same key have different certificate pins but the
    /// same SubjectPublicKeyInfo pin. No private key bytes are exposed.
    pub fn public_key_pin(&self) -> Result<CertificatePin> {
        let encoded = self.certificates[0].as_ref();
        let (remaining, certificate) = x509_parser::parse_x509_certificate(encoded)
            .map_err(|_| anyhow::anyhow!("TLS leaf certificate is invalid"))?;
        ensure!(
            remaining.is_empty(),
            "TLS leaf certificate has trailing bytes"
        );
        Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
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

#[cfg(test)]
mod identity_pin_tests {
    use super::*;

    #[test]
    fn reissued_leaf_cannot_hide_reused_tls_public_key() {
        let shared_key = rcgen::KeyPair::generate().unwrap();
        let first = rcgen::CertificateParams::new(vec!["data.local".into()])
            .unwrap()
            .self_signed(&shared_key)
            .unwrap();
        let reissued = rcgen::CertificateParams::new(vec!["admin.local".into()])
            .unwrap()
            .self_signed(&shared_key)
            .unwrap();
        let separate_key = rcgen::KeyPair::generate().unwrap();
        let separate = rcgen::CertificateParams::new(vec!["separate.local".into()])
            .unwrap()
            .self_signed(&separate_key)
            .unwrap();
        let identity = |certificate: &rcgen::Certificate, key: &rcgen::KeyPair| {
            TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes())
                .unwrap()
        };
        let first = identity(&first, &shared_key);
        let reissued = identity(&reissued, &shared_key);
        let separate = identity(&separate, &separate_key);
        assert_ne!(first.certificate_pin(), reissued.certificate_pin());
        assert_eq!(
            first.public_key_pin().unwrap(),
            reissued.public_key_pin().unwrap()
        );
        assert_ne!(
            first.public_key_pin().unwrap(),
            separate.public_key_pin().unwrap()
        );
    }
}

#[cfg(test)]
mod admitted_client_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    struct Authority {
        pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn authority(name: &str) -> Authority {
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let pem = parameters.self_signed(&key).unwrap().pem();
        Authority {
            pem,
            issuer: Issuer::new(parameters, key),
        }
    }

    fn leaf(authority: &Authority, name: &str, client: bool) -> TlsIdentity {
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::new(vec!["localhost".into()]).unwrap();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        parameters.extended_key_usages = vec![if client {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        let certificate = parameters.signed_by(&key, &authority.issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    }

    /// One complete TLS 1.3 handshake over an in-memory stream; the server's
    /// result, since a client finishes before the server has verified it.
    async fn handshake(
        server: Arc<ServerConfig>,
        server_pin: CertificatePin,
        authority: &Authority,
        client: Option<&TlsIdentity>,
    ) -> std::result::Result<(), String> {
        let (client_stream, server_stream) = tokio::io::duplex(64 << 10);
        let mut roots = RootCertStore::empty();
        roots
            .add(certificates_from_pem(authority.pem.as_bytes()).unwrap()[0].clone())
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedServerVerifier {
            trusted: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .unwrap(),
            pins: BTreeSet::from([server_pin]),
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let config = match client {
            Some(identity) => builder
                .with_client_auth_cert(
                    identity.certificates.clone(),
                    identity.private_key.clone_key(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let acceptor = tokio_rustls::TlsAcceptor::from(server);
        let name = ServerName::try_from("localhost").unwrap();
        let (_, accepted) = tokio::join!(
            async {
                // The client may finish before the server refuses it; keep its
                // side open until the server has decided.
                let connected = connector.connect(name, client_stream).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                connected
            },
            acceptor.accept(server_stream)
        );
        accepted.map(drop).map_err(|error| error.to_string())
    }

    #[tokio::test]
    async fn only_admitted_leaves_of_the_trusted_authority_complete_a_handshake() {
        let installation = authority("installation");
        let other = authority("other");
        let server = leaf(&installation, "server", false);
        let listed = leaf(&installation, "listed", true);
        let unlisted = leaf(&installation, "unlisted", true);
        let foreign = leaf(&other, "foreign", true);
        let server_only = leaf(&installation, "server-usage", false);
        let admitted = BTreeSet::from([
            listed.certificate_pin(),
            foreign.certificate_pin(),
            server_only.certificate_pin(),
        ]);
        let config = |admitted: &BTreeSet<CertificatePin>| {
            server_config(
                &server,
                ClientAuthentication::Admitted {
                    trusted_ca_pem: installation.pem.as_bytes(),
                    admitted,
                },
            )
            .unwrap()
        };
        let pin = server.certificate_pin();
        handshake(config(&admitted), pin, &installation, Some(&listed))
            .await
            .unwrap();
        // An unlisted certificate of the trusted authority is refused.
        let refused = handshake(config(&admitted), pin, &installation, Some(&unlisted))
            .await
            .unwrap_err();
        assert!(
            refused.contains("ApplicationVerificationFailure"),
            "{refused}"
        );
        // A listed pin admits nothing the CA-only checks refuse: another
        // authority's leaf, a server-only leaf, or no certificate at all.
        for client in [Some(&foreign), Some(&server_only), None] {
            let refused = handshake(config(&admitted), pin, &installation, client)
                .await
                .unwrap_err();
            assert!(
                !refused.contains("ApplicationVerificationFailure"),
                "{refused}"
            );
        }
        // An empty allowlist admits no one.
        assert!(
            handshake(config(&BTreeSet::new()), pin, &installation, Some(&listed))
                .await
                .is_err()
        );
        // Without an allowlist, CA-only verification admits the unlisted leaf.
        let ca_only = server_config(
            &server,
            ClientAuthentication::Required {
                trusted_ca_pem: installation.pem.as_bytes(),
            },
        )
        .unwrap();
        handshake(ca_only, pin, &installation, Some(&unlisted))
            .await
            .unwrap();
    }

    #[test]
    fn enrollment_pins_only_client_certificates_of_the_trusted_authority() {
        let installation = authority("installation");
        let other = authority("other");
        let pem = |authority: &Authority, client: bool| {
            let key = KeyPair::generate().unwrap();
            let mut parameters = CertificateParams::new(vec!["localhost".into()]).unwrap();
            parameters.extended_key_usages = vec![if client {
                ExtendedKeyUsagePurpose::ClientAuth
            } else {
                ExtendedKeyUsagePurpose::ServerAuth
            }];
            parameters.signed_by(&key, &authority.issuer).unwrap().pem()
        };
        let client = pem(&installation, true);
        assert_eq!(
            admissible_client_pin(installation.pem.as_bytes(), client.as_bytes()).unwrap(),
            certificate_pin(client.as_bytes()).unwrap()
        );
        for refused in [pem(&other, true), pem(&installation, false)] {
            assert!(
                admissible_client_pin(installation.pem.as_bytes(), refused.as_bytes()).is_err()
            );
        }
        assert!(admissible_client_pin(installation.pem.as_bytes(), b"not a certificate").is_err());
    }
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
    Required {
        trusted_ca_pem: &'a [u8],
    },
    /// As `Required`, and the leaf certificate's SHA-256 pin must also be one
    /// of `admitted`. An empty set admits no client.
    Admitted {
        trusted_ca_pem: &'a [u8],
        admitted: &'a BTreeSet<CertificatePin>,
    },
    OAuth,
}

fn client_verifier(
    trusted_ca_pem: &[u8],
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>> {
    Ok(rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(trusted_ca_pem)?),
        provider,
    )
    .build()?)
}

/// WebPKI client verification (CA chain, validity, client-authentication
/// usage and the handshake signature), and then the leaf certificate's pin
/// must be admitted. The pin is checked only after the chain verifies.
#[derive(Debug)]
struct AdmittedClientVerifier {
    trusted: Arc<dyn ClientCertVerifier>,
    admitted: BTreeSet<CertificatePin>,
}

impl ClientCertVerifier for AdmittedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.trusted.offer_client_auth()
    }
    fn client_auth_mandatory(&self) -> bool {
        self.trusted.client_auth_mandatory()
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.trusted.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .trusted
            .verify_client_cert(end_entity, intermediates, now)?;
        if !self.admitted.contains(&certificate_digest(end_entity)) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
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
    fn requires_raw_public_keys(&self) -> bool {
        self.trusted.requires_raw_public_keys()
    }
}

/// The pin of `certificate_pem`'s leaf, after checking it as a listener that
/// requires client certificates from `trusted_ca_pem` would: its chain,
/// validity now and client-authentication usage.
pub fn admissible_client_pin(
    trusted_ca_pem: &[u8],
    certificate_pem: &[u8],
) -> Result<CertificatePin> {
    let verifier = client_verifier(
        trusted_ca_pem,
        Arc::new(rustls::crypto::ring::default_provider()),
    )?;
    let certificates = certificates_from_pem(certificate_pem)?;
    verifier
        .verify_client_cert(&certificates[0], &certificates[1..], UnixTime::now())
        .map_err(|error| anyhow::anyhow!("the client certificate is not admissible: {error}"))?;
    Ok(certificate_digest(&certificates[0]))
}

pub fn server_config(
    identity: &TlsIdentity,
    authentication: ClientAuthentication<'_>,
) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    // Each configuration has its own session cache and issues no tickets, so
    // a session never resumes under a later admission generation.
    let builder = match authentication {
        ClientAuthentication::Required { trusted_ca_pem } => {
            builder.with_client_cert_verifier(client_verifier(trusted_ca_pem, provider)?)
        }
        ClientAuthentication::Admitted {
            trusted_ca_pem,
            admitted,
        } => builder.with_client_cert_verifier(Arc::new(AdmittedClientVerifier {
            trusted: client_verifier(trusted_ca_pem, provider)?,
            admitted: admitted.clone(),
        })),
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
