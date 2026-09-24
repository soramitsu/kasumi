use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// An owned fixed-size key. Deliberately not Clone, Debug, or Serialize.
pub struct SecretKey(Box<Zeroizing<[u8; 32]>>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(Zeroizing::new(bytes)))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn random() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        Ok(Self::from_bytes(*bytes))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub provider: String,
    pub key_ref: String,
    pub ciphertext: String,
    pub version: u64,
    pub context: Option<String>,
}

/// The fixed security properties of one installed historical wrapping source.
/// Credentials and local file paths are deliberately absent: they may refresh
/// without redirecting the accepted key resource or changing its TLS trust.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalSourceSecurityDescriptor {
    File {
        key_ref: String,
    },
    Transit {
        key_ref: String,
        canonical_origin: String,
        namespace: Option<String>,
        mount: String,
        key_name: String,
        derived: bool,
        ca_trust_sha256: [u8; 32],
    },
    #[cfg(test)]
    Fixture {
        key_ref: String,
    },
}

impl HistoricalSourceSecurityDescriptor {
    /// Bind a file source to the identity read from its opened keyring, not its
    /// installation path. A subsequent unwrap still checks that identity.
    pub fn file(provider: &crate::FileKeyProvider) -> Self {
        Self::File {
            key_ref: provider.key_ref().to_owned(),
        }
    }

    /// Construct from the exact opened Transit client and its snapshotted CA.
    /// System roots have no pinned trust content and cannot be accepted as a
    /// historical source in the first release.
    pub fn transit(provider: &TransitKeyProvider) -> Result<Self> {
        Ok(Self::Transit {
            key_ref: provider.key_ref.clone(),
            canonical_origin: provider.endpoint.origin().ascii_serialization(),
            namespace: provider.namespace.clone(),
            mount: provider.mount.clone(),
            key_name: provider.key_name.clone(),
            derived: provider.derived,
            ca_trust_sha256: provider
                .pinned_ca_sha256
                .context("historical Transit source requires a pinned CA certificate")?,
        })
    }

    pub fn dispatch_identity(&self) -> (&'static str, &str) {
        match self {
            Self::File { key_ref } => ("file", key_ref),
            Self::Transit { key_ref, .. } => ("transit", key_ref),
            #[cfg(test)]
            Self::Fixture { key_ref } => ("test-only", key_ref),
        }
    }
}

pub struct GeneratedKey {
    pub plaintext: SecretKey,
    pub wrapped: WrappedKey,
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey>;
    /// Must make a fresh authenticated key-service request; never use a plaintext cache.
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey>;
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey>;
}

/// Credentials are runtime-only. This configuration intentionally cannot be serialized.
pub struct TransitConfig {
    pub endpoint: String,
    pub mount: String,
    pub key_name: String,
    pub credential: std::sync::Arc<dyn kasumi_transport::credentials::CredentialSource>,
    pub namespace: Option<String>,
    pub ca_pem: Option<Vec<u8>>,
    /// Set only for Transit keys created with `derived=true`.
    pub derived: bool,
}

impl fmt::Debug for TransitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitConfig")
            .field("endpoint", &self.endpoint)
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

pub struct TransitKeyProvider {
    client: Client,
    endpoint: Url,
    mount: String,
    key_name: String,
    key_ref: String,
    namespace: Option<String>,
    derived: bool,
    pinned_ca_sha256: Option<[u8; 32]>,
    credential: std::sync::Arc<dyn kasumi_transport::credentials::CredentialSource>,
}

impl TransitKeyProvider {
    pub fn new(config: TransitConfig) -> Result<Self> {
        let endpoint = Url::parse(&config.endpoint).context("invalid Transit endpoint")?;
        ensure!(endpoint.scheme() == "https", "Transit requires HTTPS");
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "invalid Transit endpoint"
        );
        ensure!(
            endpoint.path() == "/" || endpoint.path().is_empty(),
            "Transit endpoint must be an origin"
        );
        validate_path(&config.mount)?;
        ensure!(
            !config.key_name.contains('/'),
            "Transit key name must be one path segment"
        );
        validate_path(&config.key_name)?;
        let mut headers = HeaderMap::new();
        if let Some(namespace) = &config.namespace {
            validate_path(namespace)?;
            headers.insert("X-Vault-Namespace", HeaderValue::from_str(namespace)?);
        }
        let mut builder = Client::builder()
            .no_proxy()
            .default_headers(headers)
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5));
        let pinned_ca_sha256 = if let Some(ca) = config.ca_pem {
            ensure!(
                !ca.is_empty() && ca.len() <= 1 << 20,
                "Transit CA certificate outside first-release bounds"
            );
            let certificates = reqwest::Certificate::from_pem_bundle(&ca)?;
            ensure!(
                !certificates.is_empty(),
                "Transit CA bundle contains no certificates"
            );
            builder = builder.tls_built_in_root_certs(false);
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
            Some(Sha256::digest(&ca).into())
        } else {
            None
        };
        let key_ref = format!(
            "{}|{}|{}|{}",
            endpoint,
            config.namespace.as_deref().unwrap_or(""),
            config.mount,
            config.key_name
        );
        Ok(Self {
            client: builder.build()?,
            endpoint,
            mount: config.mount,
            key_name: config.key_name,
            key_ref,
            namespace: config.namespace,
            derived: config.derived,
            pinned_ca_sha256,
            credential: config.credential,
        })
    }

    fn context(&self, tenant: &str) -> Option<String> {
        self.derived
            .then(|| STANDARD.encode(format!("kasumi/tenant/{tenant}")))
    }

    async fn request(&self, operation: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let url = self
            .endpoint
            .join(&format!("v1/{}/{operation}/{}", self.mount, self.key_name))?;
        let secret = kasumi_transport::credentials::token(self.credential.as_ref())?;
        let mut token = HeaderValue::from_str(&secret).context("invalid Transit token")?;
        token.set_sensitive(true);
        let mut response = self
            .client
            .post(url)
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Transit request failed"))?;
        let status = response.status();
        // Do not copy arbitrary provider error bodies into logs: they may contain secrets.
        ensure!(
            status.is_success(),
            "Transit rejected request (HTTP {})",
            status.as_u16()
        );
        ensure!(
            response.content_length().is_none_or(|n| n <= 65536),
            "Transit response too large"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.context("reading Transit response")? {
            ensure!(
                chunk.len() <= 65536usize.saturating_sub(bytes.len()),
                "Transit response too large"
            );
            bytes.extend(chunk);
        }
        serde_json::from_slice(&bytes).context("invalid Transit response")
    }

    fn validate_wrapped(&self, tenant: &str, wrapped: &WrappedKey) -> Result<()> {
        ensure!(
            wrapped.provider == "transit" && wrapped.key_ref == self.key_ref,
            "wrapped key does not belong to configured Transit key"
        );
        ensure!(
            wrapped.context == self.context(tenant),
            "wrapped key context mismatch"
        );
        ensure!(
            version(&wrapped.ciphertext)? == wrapped.version,
            "wrapped key version mismatch"
        );
        Ok(())
    }

    fn decode_key(response: &mut serde_json::Value) -> Result<SecretKey> {
        let mut encoded = match response
            .pointer_mut("/data/plaintext")
            .map(serde_json::Value::take)
        {
            Some(serde_json::Value::String(s)) => Zeroizing::new(s),
            _ => bail!("Transit did not return plaintext key"),
        };
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .context("invalid Transit key encoding")?,
        );
        encoded.zeroize();
        ensure!(bytes.len() == 32, "Transit returned a non-256-bit data key");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(SecretKey::from_bytes(*key))
    }

    fn wrapped(&self, tenant: &str, response: &serde_json::Value) -> Result<WrappedKey> {
        let ciphertext = response
            .pointer("/data/ciphertext")
            .and_then(|v| v.as_str())
            .context("Transit did not return wrapped key")?
            .to_owned();
        Ok(WrappedKey {
            version: version(&ciphertext)?,
            ciphertext,
            provider: "transit".into(),
            key_ref: self.key_ref.clone(),
            context: self.context(tenant),
        })
    }
}

#[async_trait]
impl KeyProvider for TransitKeyProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        let mut body = serde_json::json!({"bits": 256});
        if let Some(ctx) = self.context(tenant) {
            body["context"] = ctx.into();
        }
        let mut response = self.request("datakey/plaintext", body).await?;
        let plaintext = Self::decode_key(&mut response)?;
        Ok(GeneratedKey {
            wrapped: self.wrapped(tenant, &response)?,
            plaintext,
        })
    }

    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.validate_wrapped(tenant, wrapped)?;
        let mut body = serde_json::json!({"ciphertext": wrapped.ciphertext});
        if let Some(ctx) = &wrapped.context {
            body["context"] = ctx.clone().into();
        }
        Self::decode_key(&mut self.request("decrypt", body).await?)
    }

    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.validate_wrapped(tenant, wrapped)?;
        let mut body = serde_json::json!({"ciphertext": wrapped.ciphertext});
        if let Some(ctx) = &wrapped.context {
            body["context"] = ctx.clone().into();
        }
        self.wrapped(tenant, &self.request("rewrap", body).await?)
    }
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.split('/').all(|p| !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
        "invalid Transit path"
    );
    Ok(())
}

fn version(ciphertext: &str) -> Result<u64> {
    let Some(rest) = ciphertext.strip_prefix("vault:v") else {
        bail!("invalid Transit ciphertext prefix")
    };
    let Some((version, payload)) = rest.split_once(':') else {
        bail!("invalid Transit ciphertext")
    };
    ensure!(!payload.is_empty(), "empty Transit ciphertext");
    let version = version
        .parse::<u64>()
        .context("invalid Transit key version")?;
    ensure!(version > 0, "invalid Transit key version");
    Ok(version)
}

/// The canonical wrapping resource reported by a constructed provider. The
/// version and tenant context remain exact fields of each wrapped key, while
/// one installed resource is responsible for all of its retained versions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WrappingIdentity {
    provider: String,
    key_ref: String,
}

impl WrappingIdentity {
    fn constructed(provider: &str, key_ref: &str) -> Result<Self> {
        ensure!(
            !provider.is_empty()
                && provider.len() <= 16
                && !key_ref.is_empty()
                && key_ref.len() <= 2048,
            "wrapping identity outside first-release bounds"
        );
        Ok(Self {
            provider: provider.into(),
            key_ref: key_ref.into(),
        })
    }

    fn wrapped(key: &WrappedKey) -> Result<Self> {
        ensure!(key.version > 0, "invalid historical wrapping version");
        Self::constructed(&key.provider, &key.key_ref)
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }
}

#[async_trait]
trait HistoricalUnwrapper: Send + Sync {
    async fn unwrap_historical(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey>;
}

#[async_trait]
impl<T: KeyProvider> HistoricalUnwrapper for T {
    async fn unwrap_historical(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        KeyProvider::unwrap_key(self, tenant, wrapped).await
    }
}

/// A historical binding can only be made from a constructed provider. The
/// erased capability exposes only unwrap, never generation or rewrap.
pub struct HistoricalKeySource {
    identity: WrappingIdentity,
    descriptor: HistoricalSourceSecurityDescriptor,
    provider: std::sync::Arc<dyn HistoricalUnwrapper>,
}

impl HistoricalKeySource {
    fn constructed(
        descriptor: HistoricalSourceSecurityDescriptor,
        provider: std::sync::Arc<dyn HistoricalUnwrapper>,
    ) -> Result<Self> {
        let (kind, key_ref) = descriptor.dispatch_identity();
        let identity = WrappingIdentity::constructed(kind, key_ref)?;
        Ok(Self {
            identity,
            descriptor,
            provider,
        })
    }

    pub fn file(provider: std::sync::Arc<crate::FileKeyProvider>) -> Result<Self> {
        Self::constructed(
            HistoricalSourceSecurityDescriptor::file(&provider),
            provider,
        )
    }

    pub fn transit(provider: std::sync::Arc<TransitKeyProvider>) -> Result<Self> {
        Self::constructed(
            HistoricalSourceSecurityDescriptor::transit(&provider)?,
            provider,
        )
    }

    #[cfg(test)]
    fn fixture(provider: std::sync::Arc<crate::test_utils::LocalKeyProvider>) -> Self {
        Self::constructed(
            HistoricalSourceSecurityDescriptor::Fixture {
                key_ref: provider.key_ref().to_owned(),
            },
            provider,
        )
        .expect("bounded test fixture identity")
    }

    pub fn identity(&self) -> &WrappingIdentity {
        &self.identity
    }

    pub fn descriptor(&self) -> &HistoricalSourceSecurityDescriptor {
        &self.descriptor
    }
}

/// Immutable, exact unwrap dispatch for installed historical providers.
/// A missing identity or a failed selected provider is terminal: no current
/// primary fallback and no decryption trials against other providers occur.
pub struct HistoricalKeyResolver {
    sources: std::collections::BTreeMap<WrappingIdentity, std::sync::Arc<dyn HistoricalUnwrapper>>,
    descriptors: std::collections::BTreeSet<HistoricalSourceSecurityDescriptor>,
}

impl HistoricalKeyResolver {
    /// First-release installed source-set bound, separate from retention page size.
    pub const MAX_SOURCES: usize = 64;

    pub fn new(sources: Vec<HistoricalKeySource>) -> Result<Self> {
        ensure!(
            (1..=Self::MAX_SOURCES).contains(&sources.len()),
            "historical wrapping source count outside first-release bounds"
        );
        let mut installed = std::collections::BTreeMap::new();
        let mut descriptors = std::collections::BTreeSet::new();
        for source in sources {
            ensure!(
                !installed.contains_key(&source.identity),
                "duplicate or ambiguous historical wrapping identity"
            );
            ensure!(
                descriptors.insert(source.descriptor),
                "duplicate historical source security descriptor"
            );
            installed.insert(source.identity, source.provider);
        }
        Ok(Self {
            sources: installed,
            descriptors,
        })
    }

    pub fn identities(&self) -> impl Iterator<Item = &WrappingIdentity> {
        self.sources.keys()
    }

    pub fn descriptors(&self) -> impl Iterator<Item = &HistoricalSourceSecurityDescriptor> {
        self.descriptors.iter()
    }

    pub async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        let identity = WrappingIdentity::wrapped(wrapped)?;
        let source = self
            .sources
            .get(&identity)
            .context("historical wrapping identity is not installed")?;
        source.unwrap_historical(tenant, wrapped).await
    }
}

/// Generation and rewrap are denied; an unwrap result remains a key capability.
/// Callers must still separate historical reads from primary-backed writes.
#[async_trait]
impl KeyProvider for HistoricalKeyResolver {
    async fn generate_key(&self, _tenant: &str) -> Result<GeneratedKey> {
        bail!("historical wrapping resolver cannot generate keys")
    }

    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        HistoricalKeyResolver::unwrap_key(self, tenant, wrapped).await
    }

    async fn rewrap_key(&self, _tenant: &str, _wrapped: &WrappedKey) -> Result<WrappedKey> {
        bail!("historical wrapping resolver cannot rewrap keys")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NodeStore, TenantStore, WriteOp,
        test_utils::{LocalKeyProvider, ManualClock},
        tls_fixture::TlsFixture,
    };
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };

    struct Service {
        wrapping: LocalKeyProvider,
        response_mode: AtomicU8,
        expected_token: parking_lot::Mutex<String>,
        requests: parking_lot::Mutex<Vec<(String, serde_json::Value)>>,
    }
    impl Service {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wrapping: LocalKeyProvider::new([64; 32]),
                response_mode: AtomicU8::new(0),
                expected_token: parking_lot::Mutex::new("test-runtime-secret".into()),
                requests: parking_lot::Mutex::new(Vec::new()),
            })
        }
    }
    fn local(provider: &LocalKeyProvider, wrapped: &str) -> WrappedKey {
        let version = version(wrapped).unwrap();
        WrappedKey {
            provider: "test-only".into(),
            key_ref: provider.key_ref().into(),
            version,
            ciphertext: wrapped.splitn(3, ':').nth(2).unwrap().into(),
            context: Some("tenant".into()),
        }
    }
    fn vault(wrapped: &WrappedKey) -> String {
        format!("vault:v{}:{}", wrapped.version, wrapped.ciphertext)
    }
    async fn request(
        State(state): State<Arc<Service>>,
        Path(operation): Path<String>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        if headers
            .get("x-vault-token")
            .is_none_or(|v| v != state.expected_token.lock().as_str())
            || headers
                .get("x-vault-namespace")
                .is_none_or(|v| v != "teams")
        {
            return (
                StatusCode::FORBIDDEN,
                "sensitive upstream error must never be logged",
            )
                .into_response();
        }
        state
            .requests
            .lock()
            .push((operation.clone(), body.clone()));
        match state.response_mode.load(Ordering::SeqCst) {
            1 => {
                return (
                    StatusCode::FORBIDDEN,
                    "sensitive upstream error must never be logged",
                )
                    .into_response();
            }
            2 => {
                return Json(serde_json::json!({"data":{"plaintext":STANDARD.encode([1; 31])}}))
                    .into_response();
            }
            3 => return (StatusCode::OK, "x".repeat(70000)).into_response(),
            4 => {
                return (
                    StatusCode::TEMPORARY_REDIRECT,
                    [("location", "https://example.invalid/steal")],
                )
                    .into_response();
            }
            5 => {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
            _ => {}
        }
        if body.get("context").and_then(|v| v.as_str())
            != Some(STANDARD.encode("kasumi/tenant/tenant").as_str())
        {
            return (StatusCode::BAD_REQUEST, "wrong derivation context").into_response();
        }
        match operation.as_str() {
            "datakey/plaintext/tenant-key" => {
                if body["bits"] != 256 {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                let generated = state.wrapping.generate_key("tenant").await.unwrap();
                Json(serde_json::json!({"data":{"plaintext":STANDARD.encode(generated.plaintext.as_bytes()), "ciphertext":vault(&generated.wrapped)}})).into_response()
            }
            "decrypt/tenant-key" => {
                let key = match state
                    .wrapping
                    .unwrap_key(
                        "tenant",
                        &local(&state.wrapping, body["ciphertext"].as_str().unwrap()),
                    )
                    .await
                {
                    Ok(key) => key,
                    Err(_) => return StatusCode::FORBIDDEN.into_response(),
                };
                Json(serde_json::json!({"data":{"plaintext":STANDARD.encode(key.as_bytes())}}))
                    .into_response()
            }
            "rewrap/tenant-key" => {
                let key = state
                    .wrapping
                    .rewrap_key(
                        "tenant",
                        &local(&state.wrapping, body["ciphertext"].as_str().unwrap()),
                    )
                    .await
                    .unwrap();
                Json(serde_json::json!({"data":{"ciphertext":vault(&key)}})).into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
    fn router(state: Arc<Service>) -> Router {
        Router::new()
            .route("/v1/teams/transit/{*operation}", post(request))
            .with_state(state)
    }
    fn config(fixture: &TlsFixture) -> TransitConfig {
        TransitConfig {
            endpoint: fixture.endpoint.clone(),
            mount: "teams/transit".into(),
            key_name: "tenant-key".into(),
            credential: Arc::new(|| Ok(Zeroizing::new("test-runtime-secret".into()))),
            namespace: Some("teams".into()),
            ca_pem: Some(fixture.ca_pem.clone()),
            derived: true,
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn transit_reads_replaced_token_for_every_request_and_never_caches_failure() {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let dir = crate::test_utils::private_tempdir().unwrap();
        let path = dir.path().join("token");
        let publish = |value: &str| {
            let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
            file.write_all(value.as_bytes()).unwrap();
            file.persist(&path).unwrap();
        };
        publish("test-runtime-secret");
        let mut settings = config(&fixture);
        settings.credential =
            Arc::new(kasumi_transport::credentials::FileCredentialSource::new(&path).unwrap());
        let provider = TransitKeyProvider::new(settings).unwrap();
        let key = provider.generate_key("tenant").await.unwrap();
        *state.expected_token.lock() = "rotated-runtime-secret".into();
        assert!(provider.unwrap_key("tenant", &key.wrapped).await.is_err());
        publish("rotated-runtime-secret");
        let restored = provider.unwrap_key("tenant", &key.wrapped).await.unwrap();
        assert_eq!(restored.as_bytes(), key.plaintext.as_bytes());
        publish("bad\nheader");
        assert!(provider.unwrap_key("tenant", &key.wrapped).await.is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(provider.unwrap_key("tenant", &key.wrapped).await.is_err());
    }

    #[tokio::test]
    async fn transit_tls_generation_fresh_decrypt_rewrap_context_and_revocation() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let provider = Arc::new(TransitKeyProvider::new(config(&fixture)).unwrap());
        let dir = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant".into(),
            provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .requests
                .lock()
                .iter()
                .map(|(operation, _)| operation.as_str())
                .collect::<Vec<_>>(),
            [
                "datakey/plaintext/tenant-key",
                "datakey/plaintext/tenant-key",
                "decrypt/tenant-key",
                "decrypt/tenant-key"
            ]
        );
        store
            .write_batch(&[WriteOp::put("docs", b"a", b"plaintext document")])
            .unwrap();
        state.wrapping.rotate();
        store.rewrap_keys().await.unwrap();
        state.wrapping.set_minimum_version(2);
        store.refresh_lease().await.unwrap();
        assert_eq!(
            store.get("docs", b"a").unwrap(),
            Some(b"plaintext document".to_vec())
        );
        let generated = provider.generate_key("tenant").await.unwrap();
        let previous = state.requests.lock().len();
        assert!(
            provider
                .unwrap_key("wrong-tenant", &generated.wrapped)
                .await
                .is_err()
        );
        assert_eq!(state.requests.lock().len(), previous); // rejects binding before network
        state.response_mode.store(1, Ordering::SeqCst);
        let failure = store.refresh_lease().await.unwrap_err();
        assert!(!format!("{failure:#}").contains("sensitive upstream"));
        assert!(store.get("docs", b"a").is_err());
        assert!(store.state.read().keys.is_empty());
    }

    #[tokio::test]
    async fn transit_rejects_missing_trust_tls12_redirects_malformed_and_oversized_responses() {
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let mut untrusted = config(&fixture);
        untrusted.ca_pem = None;
        assert!(
            TransitKeyProvider::new(untrusted)
                .unwrap()
                .generate_key("tenant")
                .await
                .is_err()
        );
        let provider = TransitKeyProvider::new(config(&fixture)).unwrap();
        for response in [2, 3, 4] {
            state.response_mode.store(response, Ordering::SeqCst);
            assert!(
                provider.generate_key("tenant").await.is_err(),
                "accepted invalid response {response}"
            );
        }
        let old =
            TlsFixture::with_versions(router(Service::new()), &[&rustls::version::TLS12]).await;
        assert!(
            TransitKeyProvider::new(config(&old))
                .unwrap()
                .generate_key("tenant")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn transit_timeout_is_bounded_and_seals_existing_plaintext() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let provider = Arc::new(TransitKeyProvider::new(config(&fixture)).unwrap());
        let dir = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant".into(),
            provider,
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        state.response_mode.store(5, Ordering::SeqCst);
        let start = std::time::Instant::now();
        assert!(store.refresh_lease().await.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(7));
        assert!(store.check_access().is_err());
        assert!(store.state.read().keys.is_empty());
    }

    #[test]
    fn transit_origin_path_and_wrapped_version_validation() {
        for bad in [
            "http://localhost:8200",
            "https://user:password@localhost",
            "https://localhost/v1",
            "https://localhost?token=secret",
        ] {
            let config = TransitConfig {
                endpoint: bad.into(),
                mount: "transit".into(),
                key_name: "key".into(),
                credential: Arc::new(|| Ok(Zeroizing::new("secret".into()))),
                namespace: None,
                ca_pem: None,
                derived: false,
            };
            assert!(TransitKeyProvider::new(config).is_err());
        }
        for bad in [
            "",
            "/transit",
            "../transit",
            "transit//key",
            "transit?secret",
            "transit%2fother",
        ] {
            assert!(validate_path(bad).is_err());
        }
        for bad in [
            "other:v1:abc",
            "vault:v0:abc",
            "vault:v1:",
            "vault:vx:abc",
            "vault:v18446744073709551616:abc",
        ] {
            assert!(version(bad).is_err());
        }
    }
}

#[cfg(test)]
mod historical_resolver_tests {
    use super::*;
    use crate::{file_keys::FileKeyProvider, private_files, test_utils::LocalKeyProvider};
    use std::sync::Arc;

    #[tokio::test]
    async fn exact_source_only_and_no_missing_or_failed_source_fallback() {
        let first = Arc::new(LocalKeyProvider::new([61; 32]));
        let second = Arc::new(LocalKeyProvider::new([62; 32]));
        let absent = Arc::new(LocalKeyProvider::new([63; 32]));
        let first_key = first.generate_key("tenant").await.unwrap();
        let second_key = second.generate_key("tenant").await.unwrap();
        let absent_key = absent.generate_key("tenant").await.unwrap();
        let resolver = HistoricalKeyResolver::new(vec![
            HistoricalKeySource::fixture(first.clone()),
            HistoricalKeySource::fixture(second.clone()),
        ])
        .unwrap();

        let read_only: &dyn KeyProvider = &resolver;
        assert!(read_only.generate_key("tenant").await.is_err());
        assert!(
            read_only
                .rewrap_key("tenant", &first_key.wrapped)
                .await
                .is_err()
        );
        assert_eq!(first.probe_count(), 0);
        assert_eq!(second.probe_count(), 0);

        assert_eq!(
            resolver
                .unwrap_key("tenant", &first_key.wrapped)
                .await
                .unwrap()
                .as_bytes(),
            first_key.plaintext.as_bytes()
        );
        assert_eq!(first.probe_count(), 1);
        assert_eq!(second.probe_count(), 0);

        let mut unbounded = first_key.wrapped.clone();
        unbounded.key_ref = "x".repeat(2049);
        assert!(resolver.unwrap_key("tenant", &unbounded).await.is_err());
        assert_eq!(first.probe_count(), 1);
        assert_eq!(second.probe_count(), 0);
        assert!(
            resolver
                .unwrap_key("tenant", &absent_key.wrapped)
                .await
                .is_err()
        );
        assert_eq!(first.probe_count(), 1);
        assert_eq!(second.probe_count(), 0);

        let mut wrong_context = first_key.wrapped.clone();
        wrong_context.context = Some("another-tenant".into());
        assert!(resolver.unwrap_key("tenant", &wrong_context).await.is_err());
        assert_eq!(first.probe_count(), 2);
        assert_eq!(second.probe_count(), 0);

        let mut invalid_version = first_key.wrapped.clone();
        invalid_version.version = 0;
        assert!(
            resolver
                .unwrap_key("tenant", &invalid_version)
                .await
                .is_err()
        );
        assert_eq!(first.probe_count(), 2);

        first.revoke();
        assert!(
            resolver
                .unwrap_key("tenant", &first_key.wrapped)
                .await
                .is_err()
        );
        assert_eq!(first.probe_count(), 3);
        assert_eq!(second.probe_count(), 0);
        assert_eq!(
            resolver
                .unwrap_key("tenant", &second_key.wrapped)
                .await
                .unwrap()
                .as_bytes(),
            second_key.plaintext.as_bytes()
        );
        assert_eq!(second.probe_count(), 1);
    }

    #[test]
    fn duplicate_identity_is_rejected_even_when_providers_are_distinct_objects() {
        let first = Arc::new(LocalKeyProvider::new([64; 32]));
        let duplicate = Arc::new(LocalKeyProvider::new([64; 32]));
        assert!(
            HistoricalKeyResolver::new(vec![
                HistoricalKeySource::fixture(first),
                HistoricalKeySource::fixture(duplicate),
            ])
            .is_err()
        );
    }

    #[test]
    fn installed_descriptor_set_is_unique_and_order_independent() {
        let first = Arc::new(LocalKeyProvider::new([65; 32]));
        let second = Arc::new(LocalKeyProvider::new([66; 32]));
        let forward = HistoricalKeyResolver::new(vec![
            HistoricalKeySource::fixture(first.clone()),
            HistoricalKeySource::fixture(second.clone()),
        ])
        .unwrap();
        let reverse = HistoricalKeyResolver::new(vec![
            HistoricalKeySource::fixture(second),
            HistoricalKeySource::fixture(first),
        ])
        .unwrap();
        let descriptors = forward.descriptors().cloned().collect::<Vec<_>>();
        assert_eq!(descriptors.len(), 2);
        assert_eq!(
            descriptors,
            reverse.descriptors().cloned().collect::<Vec<_>>()
        );
        assert_eq!(forward.identities().count(), descriptors.len());
    }

    #[test]
    fn historical_set_must_be_present_and_bounded() {
        assert!(HistoricalKeyResolver::new(Vec::new()).is_err());
        let oversized = (0..=HistoricalKeyResolver::MAX_SOURCES)
            .map(|n| HistoricalKeySource::fixture(Arc::new(LocalKeyProvider::new([n as u8; 32]))))
            .collect();
        assert!(HistoricalKeyResolver::new(oversized).is_err());
    }

    #[test]
    fn file_source_identity_comes_from_installed_keyring_not_path() {
        let root = crate::test_utils::private_tempdir().unwrap();
        let directory = root.path().join("keys");
        private_files::create_directory(&directory).unwrap();
        let path = directory.join("app.json");
        let first = Arc::new(FileKeyProvider::initialize(&path, "application").unwrap());
        let reopened = Arc::new(FileKeyProvider::open(&path).unwrap());
        let same = HistoricalKeySource::file(reopened).unwrap();
        assert_eq!(
            HistoricalKeySource::file(first.clone()).unwrap().identity(),
            same.identity()
        );
        assert!(
            HistoricalKeyResolver::new(vec![HistoricalKeySource::file(first).unwrap(), same])
                .is_err()
        );
        let other_path = directory.join("replacement.json");
        let other = Arc::new(FileKeyProvider::initialize(&other_path, "application").unwrap());
        assert_ne!(
            HistoricalKeySource::file(Arc::new(FileKeyProvider::open(&path).unwrap()))
                .unwrap()
                .identity(),
            HistoricalKeySource::file(other).unwrap().identity()
        );
    }

    #[test]
    fn transit_identity_ignores_credential_rotation_but_not_key_resource() {
        let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes();
        let config = |key_name: &str, token: &str, derived: bool| TransitConfig {
            endpoint: "https://EXAMPLE.com:443".into(),
            mount: "transit".into(),
            key_name: key_name.into(),
            credential: Arc::new({
                let token = token.to_owned();
                move || Ok(Zeroizing::new(token.clone()))
            }),
            namespace: Some("team".into()),
            ca_pem: Some(ca.clone()),
            derived,
        };
        let original = HistoricalKeySource::transit(Arc::new(
            TransitKeyProvider::new(config("archive", "old-token", true)).unwrap(),
        ))
        .unwrap();
        let rotated = HistoricalKeySource::transit(Arc::new(
            TransitKeyProvider::new(config("archive", "new-token", true)).unwrap(),
        ))
        .unwrap();
        let ambiguous = HistoricalKeySource::transit(Arc::new(
            TransitKeyProvider::new(config("archive", "new-token", false)).unwrap(),
        ))
        .unwrap();
        let different = HistoricalKeySource::transit(Arc::new(
            TransitKeyProvider::new(config("other", "new-token", true)).unwrap(),
        ))
        .unwrap();
        let mut changed_trust = config("archive", "new-token", true);
        changed_trust.ca_pem = Some(
            rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .unwrap()
                .cert
                .pem()
                .into_bytes(),
        );
        let changed_trust =
            HistoricalKeySource::transit(Arc::new(TransitKeyProvider::new(changed_trust).unwrap()))
                .unwrap();
        assert_eq!(original.identity(), rotated.identity());
        assert_eq!(original.descriptor(), rotated.descriptor());
        assert_eq!(original.identity(), ambiguous.identity());
        assert_ne!(original.descriptor(), ambiguous.descriptor());
        assert_eq!(original.identity(), changed_trust.identity());
        assert_ne!(original.descriptor(), changed_trust.descriptor());
        assert_ne!(original.identity(), different.identity());
        assert!(HistoricalKeyResolver::new(vec![original, rotated]).is_err());
        assert!(
            HistoricalKeyResolver::new(vec![
                ambiguous,
                HistoricalKeySource::transit(Arc::new(
                    TransitKeyProvider::new(config("archive", "old-token", true)).unwrap()
                ))
                .unwrap()
            ])
            .is_err()
        );
        assert!(
            HistoricalKeyResolver::new(vec![
                changed_trust,
                HistoricalKeySource::transit(Arc::new(
                    TransitKeyProvider::new(config("archive", "old-token", true)).unwrap()
                ))
                .unwrap()
            ])
            .is_err()
        );
        let mut unpinned = config("archive", "token", true);
        unpinned.ca_pem = None;
        assert!(
            HistoricalKeySource::transit(Arc::new(TransitKeyProvider::new(unpinned).unwrap()))
                .is_err()
        );
    }
}

#[cfg(test)]
mod historical_source_descriptor_tests {
    use super::*;
    use crate::{FileKeyProvider, private_files};
    use std::sync::Arc;

    fn ca_pem() -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes()
    }

    fn config(ca: Option<Vec<u8>>, token: &str) -> TransitConfig {
        let token = token.to_owned();
        TransitConfig {
            endpoint: "https://EXAMPLE.com:443".into(),
            mount: "teams/transit".into(),
            key_name: "archive".into(),
            credential: Arc::new(move || Ok(Zeroizing::new(token.clone()))),
            namespace: Some("team".into()),
            ca_pem: ca,
            derived: true,
        }
    }

    fn transit(config: TransitConfig) -> (String, HistoricalSourceSecurityDescriptor) {
        let provider = TransitKeyProvider::new(config).unwrap();
        (
            provider.key_ref.clone(),
            HistoricalSourceSecurityDescriptor::transit(&provider).unwrap(),
        )
    }

    #[test]
    fn transit_descriptor_tracks_exact_resource_mode_and_pinned_trust() {
        let ca = ca_pem();
        let (key_ref, original) = transit(config(Some(ca.clone()), "old-token"));
        let mut rotated = config(Some(ca.clone()), "new-token");
        rotated.endpoint = "https://example.com".into();
        assert_eq!(original, transit(rotated).1);
        assert_eq!(original.dispatch_identity(), ("transit", key_ref.as_str()));
        let HistoricalSourceSecurityDescriptor::Transit {
            canonical_origin,
            ca_trust_sha256,
            ..
        } = &original
        else {
            panic!("Transit provider produced a non-Transit descriptor")
        };
        assert_eq!(canonical_origin, "https://example.com");
        let expected: [u8; 32] = Sha256::digest(&ca).into();
        assert_eq!(ca_trust_sha256, &expected);

        let mut changed = config(Some(ca.clone()), "new-token");
        changed.derived = false;
        assert_eq!(key_ref, transit(changed).0);
        assert_ne!(
            original,
            transit(config_with_change(&ca, |c| c.derived = false)).1
        );
        assert_ne!(
            original,
            transit(config_with_change(&ca, |c| c.namespace = Some("other".into()))).1
        );
        assert_ne!(
            original,
            transit(config_with_change(&ca, |c| c.mount = "other".into())).1
        );
        assert_ne!(
            original,
            transit(config_with_change(&ca, |c| c.key_name = "other".into())).1
        );
        assert_ne!(
            original,
            transit(config_with_change(&ca, |c| c.endpoint = "https://other.example".into())).1
        );
        let replacement_ca = ca_pem();
        let (same_key_ref, changed_trust) = transit(config(Some(replacement_ca), "new-token"));
        assert_eq!(key_ref, same_key_ref);
        assert_ne!(original, changed_trust);

        let encoded = serde_json::to_vec(&original).unwrap();
        assert_eq!(
            serde_json::from_slice::<HistoricalSourceSecurityDescriptor>(&encoded).unwrap(),
            original
        );
        let mut incomplete: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("ca_trust_sha256");
        assert!(serde_json::from_value::<HistoricalSourceSecurityDescriptor>(incomplete).is_err());
    }

    fn config_with_change(ca: &[u8], change: impl FnOnce(&mut TransitConfig)) -> TransitConfig {
        let mut config = config(Some(ca.to_vec()), "new-token");
        change(&mut config);
        config
    }

    #[test]
    fn unpinned_transit_source_cannot_get_historical_descriptor() {
        let provider = TransitKeyProvider::new(config(None, "token")).unwrap();
        assert!(HistoricalSourceSecurityDescriptor::transit(&provider).is_err());
        assert!(TransitKeyProvider::new(config(Some(Vec::new()), "token")).is_err());
        assert!(
            TransitKeyProvider::new(config(Some(b"garbage but nonempty".to_vec()), "token"))
                .is_err()
        );
        assert!(
            TransitKeyProvider::new(config(
                Some(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec()),
                "token"
            ))
            .is_err()
        );
    }

    #[test]
    fn file_descriptor_comes_from_opened_keyring_identity_not_path_or_generation() {
        let root = crate::test_utils::private_tempdir().unwrap();
        let directory = root.path().join("keys");
        private_files::create_directory(&directory).unwrap();
        let first_path = directory.join("first.json");
        let first = FileKeyProvider::initialize(&first_path, "application").unwrap();
        let original = HistoricalSourceSecurityDescriptor::file(&first);
        assert_eq!(original.dispatch_identity(), ("file", first.key_ref()));
        first.rotate().unwrap();
        assert_eq!(
            original,
            HistoricalSourceSecurityDescriptor::file(&FileKeyProvider::open(&first_path).unwrap())
        );
        let alias = directory.join("same-keyring.json");
        private_files::create(&alias, &private_files::read(&first_path, 1 << 20).unwrap()).unwrap();
        assert_eq!(
            original,
            HistoricalSourceSecurityDescriptor::file(&FileKeyProvider::open(alias).unwrap())
        );
        let other =
            FileKeyProvider::initialize(&directory.join("other.json"), "application").unwrap();
        assert_ne!(original, HistoricalSourceSecurityDescriptor::file(&other));
    }
}
