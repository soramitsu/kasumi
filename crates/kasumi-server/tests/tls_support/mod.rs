#![allow(dead_code)]
use anyhow::Result;
use kasumi_server::tls::{TlsHandshakeAudit, TlsHandshakeEvent, TlsIdentity};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

pub struct Authority {
    pub pem: String,
    issuer: Issuer<'static, KeyPair>,
}
pub struct Identity {
    pub cert: String,
    pub key: String,
}

#[derive(Default)]
pub struct TestAudit {
    pub events: std::sync::Mutex<Vec<TlsHandshakeEvent>>,
    pub fail: std::sync::atomic::AtomicBool,
    pub requests: std::sync::Mutex<Vec<kasumi_server::auth::RequestAuditEvent>>,
}

#[async_trait::async_trait]
impl kasumi_server::auth::RequestAuditSink for TestAudit {
    async fn record(
        &self,
        event: kasumi_server::auth::RequestAuditEvent,
    ) -> kasumi_types::Result<()> {
        if self.fail.load(std::sync::atomic::Ordering::Acquire) {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::AuditUnavailable,
                "injected audit failure",
            ));
        }
        self.requests.lock().unwrap().push(event);
        Ok(())
    }
}

#[async_trait::async_trait]
impl TlsHandshakeAudit for TestAudit {
    async fn record(&self, event: &TlsHandshakeEvent) -> Result<()> {
        anyhow::ensure!(
            !self.fail.load(std::sync::atomic::Ordering::Acquire),
            "injected security audit storage failure"
        );
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

pub fn audit() -> std::sync::Arc<TestAudit> {
    std::sync::Arc::new(TestAudit::default())
}

impl Authority {
    pub fn new() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Self {
            pem: cert.pem(),
            issuer: Issuer::new(params, key),
        })
    }
    pub fn issue(&self, hostname: &str) -> Result<Identity> {
        let mut params = CertificateParams::new(vec![hostname.into()])?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(Identity {
            cert: cert.pem(),
            key: key.serialize_pem(),
        })
    }
}

impl Identity {
    pub fn tls(&self) -> Result<TlsIdentity> {
        TlsIdentity::from_pem(self.cert.as_bytes(), self.key.as_bytes())
    }
    pub fn reqwest(&self) -> Result<reqwest::Identity> {
        Ok(reqwest::Identity::from_pem(
            format!("{}{}", self.cert, self.key).as_bytes(),
        )?)
    }
}

pub fn client(ca: &Authority, identity: Option<&Identity>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem.as_bytes())?);
    if let Some(identity) = identity {
        builder = builder.identity(identity.reqwest()?);
    }
    Ok(builder.build()?)
}
