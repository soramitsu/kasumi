use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

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
    /// Every Transit client uses pinned trust, including the writable primary.
    pub fn transit(provider: &TransitKeyProvider) -> Result<Self> {
        Ok(Self::Transit {
            key_ref: provider.key_ref.clone(),
            canonical_origin: provider.endpoint.origin().ascii_serialization(),
            namespace: provider.namespace.clone(),
            mount: provider.mount.clone(),
            key_name: provider.key_name.clone(),
            derived: provider.derived,
            ca_trust_sha256: provider.pinned_ca_sha256,
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
    /// Required pinned CA bundle. System trust is never a fallback.
    pub ca_pem: Vec<u8>,
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
    pinned_ca_sha256: [u8; 32],
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
        let ca = config.ca_pem;
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
        let pinned_ca_sha256 = Sha256::digest(&ca).into();
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
    /// Names a wrapping resource and grants no key access. Resolver entries
    /// are still made only from constructed providers.
    pub fn new(provider: &str, key_ref: &str) -> Result<Self> {
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
        Self::new(&key.provider, &key.key_ref)
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
        let identity = WrappingIdentity::new(kind, key_ref)?;
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

const HISTORICAL_SOURCE_SET_DOMAIN: &[u8] = b"kasumi.historical-source-set.v1\0";

/// Canonical digest of a committed historical source set, computable from
/// configuration or a journal without opening any provider. A count prefix is
/// followed by each descriptor's exact JSON encoding, length framed, in set
/// order, so installation order cannot change it. Credentials and paths are
/// not descriptor fields: a token refresh or keyring move keeps the digest,
/// while a key resource, origin, namespace, mount, derivation or pinned CA
/// change alters it.
pub fn source_set_sha256_of(
    descriptors: &BTreeSet<HistoricalSourceSecurityDescriptor>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HISTORICAL_SOURCE_SET_DOMAIN);
    digest.update((descriptors.len() as u64).to_be_bytes());
    for descriptor in descriptors {
        // Strings, options, booleans and fixed arrays always encode.
        let encoded = serde_json::to_vec(descriptor).expect("historical source descriptor JSON");
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(&encoded);
    }
    digest.finalize().into()
}

/// Immutable, exact unwrap dispatch for installed historical providers.
/// A missing identity or a failed selected provider is terminal: no current
/// primary fallback and no decryption trials against other providers occur.
/// An installed primary is one more exact entry, selected only for ciphertext
/// wrapped under its own identity.
pub struct HistoricalKeyResolver {
    sources: BTreeMap<WrappingIdentity, std::sync::Arc<dyn HistoricalUnwrapper>>,
    primary: Option<HistoricalSourceSecurityDescriptor>,
    historical: BTreeSet<HistoricalSourceSecurityDescriptor>,
}

impl HistoricalKeyResolver {
    /// First-release installed source-set bound, separate from retention page
    /// size. An installed primary counts toward it.
    pub const MAX_SOURCES: usize = 64;

    /// Historical sources only, such as the committed source set of a recovery.
    pub fn new(sources: Vec<HistoricalKeySource>) -> Result<Self> {
        Self::install(None, sources)
    }

    /// Installs the writable primary's read-only unwrap capability beside the
    /// historical sources, for the store's own persisted ciphertext. It is not
    /// a fallback for other identities, and a historical source equal to it is
    /// rejected rather than merged. The historical list may be empty.
    pub fn with_primary(
        primary: HistoricalKeySource,
        historical: Vec<HistoricalKeySource>,
    ) -> Result<Self> {
        Self::install(Some(primary), historical)
    }

    fn install(
        primary: Option<HistoricalKeySource>,
        historical: Vec<HistoricalKeySource>,
    ) -> Result<Self> {
        ensure!(
            (1..=Self::MAX_SOURCES).contains(&(historical.len() + usize::from(primary.is_some()))),
            "historical wrapping source count outside first-release bounds"
        );
        let mut sources = BTreeMap::new();
        let primary = primary.map(|source| {
            sources.insert(source.identity.clone(), source.provider);
            (source.identity, source.descriptor)
        });
        let mut installed = BTreeSet::new();
        for source in historical {
            if let Some((identity, descriptor)) = &primary {
                ensure!(
                    source.identity != *identity && source.descriptor != *descriptor,
                    "historical wrapping source duplicates the installed primary"
                );
            }
            ensure!(
                !sources.contains_key(&source.identity),
                "duplicate or ambiguous historical wrapping identity"
            );
            ensure!(
                installed.insert(source.descriptor),
                "duplicate historical source security descriptor"
            );
            sources.insert(source.identity, source.provider);
        }
        Ok(Self {
            sources,
            primary: primary.map(|(_, descriptor)| descriptor),
            historical: installed,
        })
    }

    /// Every dispatchable identity, including an installed primary.
    pub fn identities(&self) -> impl Iterator<Item = &WrappingIdentity> {
        self.sources.keys()
    }

    /// Every installed descriptor: the primary, if any, then the historical set.
    pub fn descriptors(&self) -> impl Iterator<Item = &HistoricalSourceSecurityDescriptor> {
        self.primary.iter().chain(&self.historical)
    }

    pub fn primary_descriptor(&self) -> Option<&HistoricalSourceSecurityDescriptor> {
        self.primary.as_ref()
    }

    /// The historical source set, excluding any installed primary.
    pub fn historical_descriptors(&self) -> &BTreeSet<HistoricalSourceSecurityDescriptor> {
        &self.historical
    }

    /// Digest of the historical source set; an installed primary is excluded.
    pub fn source_set_sha256(&self) -> [u8; 32] {
        source_set_sha256_of(&self.historical)
    }

    /// Requires the historical source set to equal a committed set exactly.
    /// A subset, superset or changed descriptor is a binding failure; an
    /// installed primary is not part of the comparison.
    pub fn require_descriptors(
        &self,
        expected: &BTreeSet<HistoricalSourceSecurityDescriptor>,
    ) -> Result<()> {
        ensure!(
            self.historical == *expected,
            "installed historical wrapping sources differ from the committed source set"
        );
        Ok(())
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
            ca_pem: fixture.ca_pem.clone(),
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
            store.get("docs", b"a").unwrap().as_deref(),
            Some(b"plaintext document".as_slice())
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
        untrusted.ca_pem.clear();
        assert!(TransitKeyProvider::new(untrusted).is_err());
        let mut wrong_trust = config(&fixture);
        wrong_trust.ca_pem = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes();
        assert!(
            TransitKeyProvider::new(wrong_trust)
                .unwrap()
                .generate_key("tenant")
                .await
                .is_err()
        );
        assert!(state.requests.lock().is_empty());
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
                ca_pem: Vec::new(),
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
            ca_pem: ca.clone(),
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
        changed_trust.ca_pem = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes();
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
        unpinned.ca_pem.clear();
        assert!(TransitKeyProvider::new(unpinned).is_err());
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

    fn config(ca: Vec<u8>, token: &str) -> TransitConfig {
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
        let (key_ref, original) = transit(config(ca.clone(), "old-token"));
        let mut rotated = config(ca.clone(), "new-token");
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

        let mut changed = config(ca.clone(), "new-token");
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
        let (same_key_ref, changed_trust) = transit(config(replacement_ca, "new-token"));
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
        let mut config = config(ca.to_vec(), "new-token");
        change(&mut config);
        config
    }

    #[test]
    fn transit_constructor_rejects_empty_invalid_and_oversized_pinned_trust() {
        assert!(TransitKeyProvider::new(config(Vec::new(), "token")).is_err());
        assert!(
            TransitKeyProvider::new(config(b"garbage but nonempty".to_vec(), "token")).is_err()
        );
        assert!(
            TransitKeyProvider::new(config(
                b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec(),
                "token"
            ))
            .is_err()
        );
        assert!(TransitKeyProvider::new(config(vec![b' '; (1 << 20) + 1], "token")).is_err());
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

#[cfg(test)]
mod historical_source_set_tests {
    use super::*;
    use crate::{FileKeyProvider, private_files, test_utils::LocalKeyProvider};
    use kasumi_transport::credentials::FileCredentialSource;
    use std::sync::Arc;

    fn fixture(seed: u8) -> Arc<LocalKeyProvider> {
        Arc::new(LocalKeyProvider::new([seed; 32]))
    }

    fn source(provider: &Arc<LocalKeyProvider>) -> HistoricalKeySource {
        HistoricalKeySource::fixture(provider.clone())
    }

    fn must_fail<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("accepted a rejected historical source set"),
            Err(error) => format!("{error:#}"),
        }
    }

    fn ca_pem() -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .cert
            .pem()
            .into_bytes()
    }

    type ConfigChange = fn(&mut TransitConfig);

    fn transit_config(ca: &[u8], token: &std::path::Path) -> TransitConfig {
        TransitConfig {
            endpoint: "https://EXAMPLE.com:443".into(),
            mount: "teams/transit".into(),
            key_name: "archive".into(),
            credential: Arc::new(FileCredentialSource::new(token).unwrap()),
            namespace: Some("team".into()),
            ca_pem: ca.to_vec(),
            derived: true,
        }
    }

    fn transit_source(config: TransitConfig) -> HistoricalKeySource {
        HistoricalKeySource::transit(Arc::new(TransitKeyProvider::new(config).unwrap())).unwrap()
    }

    fn transit_set_sha256(config: TransitConfig) -> [u8; 32] {
        HistoricalKeyResolver::new(vec![transit_source(config)])
            .unwrap()
            .source_set_sha256()
    }

    #[test]
    fn source_set_digest_is_domain_separated_count_prefixed_and_framed() {
        let file = HistoricalSourceSecurityDescriptor::File {
            key_ref: "keyring-a".into(),
        };
        let transit = HistoricalSourceSecurityDescriptor::Transit {
            key_ref: "https://example.com/|team|transit|archive".into(),
            canonical_origin: "https://example.com".into(),
            namespace: None,
            mount: "transit".into(),
            key_name: "archive".into(),
            derived: true,
            ca_trust_sha256: [7; 32],
        };
        // Written independently of the Serialize derive: variant tags, field
        // order, the null namespace and the numeric CA array are the format.
        let literals = [
            r#"{"kind":"file","key_ref":"keyring-a"}"#.to_owned(),
            format!(
                concat!(
                    r#"{{"kind":"transit","key_ref":"https://example.com/|team|transit|archive","#,
                    r#""canonical_origin":"https://example.com","namespace":null,"#,
                    r#""mount":"transit","key_name":"archive","derived":true,"#,
                    r#""ca_trust_sha256":[{}]}}"#
                ),
                ["7"; 32].join(",")
            ),
        ];
        let mut expected = Sha256::new();
        expected.update(b"kasumi.historical-source-set.v1\0");
        expected.update(2u64.to_be_bytes());
        for literal in &literals {
            expected.update((literal.len() as u64).to_be_bytes());
            expected.update(literal.as_bytes());
        }
        let expected: [u8; 32] = expected.finalize().into();
        // Set order, never argument order.
        assert_eq!(
            source_set_sha256_of(&BTreeSet::from([transit.clone(), file.clone()])),
            expected
        );
        assert_eq!(
            source_set_sha256_of(&BTreeSet::from([file.clone(), transit.clone()])),
            expected
        );

        let mut empty = Sha256::new();
        empty.update(b"kasumi.historical-source-set.v1\0");
        empty.update(0u64.to_be_bytes());
        let empty: [u8; 32] = empty.finalize().into();
        assert_eq!(source_set_sha256_of(&BTreeSet::new()), empty);

        // Neither the empty set, a member alone nor the pair collide.
        let digests = BTreeSet::from([
            expected,
            empty,
            source_set_sha256_of(&BTreeSet::from([file])),
            source_set_sha256_of(&BTreeSet::from([transit])),
        ]);
        assert_eq!(digests.len(), 4);
    }

    #[test]
    fn resolver_digest_is_order_independent_and_excludes_the_primary() {
        let (primary, first, second) = (fixture(71), fixture(72), fixture(73));
        let forward = HistoricalKeyResolver::new(vec![source(&first), source(&second)]).unwrap();
        let reverse = HistoricalKeyResolver::new(vec![source(&second), source(&first)]).unwrap();
        let committed = forward.historical_descriptors().clone();
        assert_eq!(committed.len(), 2);
        assert_eq!(forward.source_set_sha256(), reverse.source_set_sha256());
        assert_eq!(
            forward.source_set_sha256(),
            source_set_sha256_of(&committed)
        );
        assert!(forward.primary_descriptor().is_none());
        assert_eq!(
            forward.descriptors().cloned().collect::<BTreeSet<_>>(),
            committed
        );
        reverse.require_descriptors(&committed).unwrap();

        let installed = HistoricalKeyResolver::with_primary(
            source(&primary),
            vec![source(&second), source(&first)],
        )
        .unwrap();
        let primary_descriptor = source(&primary).descriptor().clone();
        assert_eq!(installed.source_set_sha256(), forward.source_set_sha256());
        installed.require_descriptors(&committed).unwrap();
        assert_eq!(installed.primary_descriptor(), Some(&primary_descriptor));
        assert!(
            !installed
                .historical_descriptors()
                .contains(&primary_descriptor)
        );
        assert_eq!(installed.descriptors().next(), Some(&primary_descriptor));
        assert_eq!(installed.descriptors().count(), 3);
        assert_eq!(installed.identities().count(), 3);

        // The same sources with the primary listed as historical are a
        // different committed set.
        let promoted =
            HistoricalKeyResolver::new(vec![source(&primary), source(&first), source(&second)])
                .unwrap();
        assert_ne!(promoted.source_set_sha256(), installed.source_set_sha256());
        assert!(
            installed
                .require_descriptors(promoted.historical_descriptors())
                .is_err()
        );
        assert!(promoted.require_descriptors(&committed).is_err());

        // A primary alone commits the empty historical set.
        let alone = HistoricalKeyResolver::with_primary(source(&primary), Vec::new()).unwrap();
        assert_eq!(
            alone.source_set_sha256(),
            source_set_sha256_of(&BTreeSet::new())
        );
        alone.require_descriptors(&BTreeSet::new()).unwrap();
        assert!(alone.require_descriptors(&committed).is_err());

        // Exact equality: a subset or a superset is a binding failure.
        let subset = BTreeSet::from([source(&first).descriptor().clone()]);
        let error = must_fail(installed.require_descriptors(&subset));
        assert!(error.contains("committed source set"), "{error}");
        let mut superset = committed.clone();
        superset.insert(source(&fixture(74)).descriptor().clone());
        assert!(installed.require_descriptors(&superset).is_err());
    }

    #[test]
    fn source_set_digest_tracks_every_security_descriptor_field() {
        let descriptor =
            |key_ref: &str,
             origin: &str,
             namespace: Option<&str>,
             mount: &str,
             key_name: &str,
             derived: bool,
             ca: u8| HistoricalSourceSecurityDescriptor::Transit {
                key_ref: key_ref.into(),
                canonical_origin: origin.into(),
                namespace: namespace.map(Into::into),
                mount: mount.into(),
                key_name: key_name.into(),
                derived,
                ca_trust_sha256: [ca; 32],
            };
        let origin = "https://example.com";
        let base = descriptor("resource", origin, Some("team"), "transit", "key", true, 1);
        let changed = [
            descriptor("changed", origin, Some("team"), "transit", "key", true, 1),
            descriptor(
                "resource",
                "https://other",
                Some("team"),
                "transit",
                "key",
                true,
                1,
            ),
            descriptor("resource", origin, Some("other"), "transit", "key", true, 1),
            descriptor("resource", origin, None, "transit", "key", true, 1),
            descriptor("resource", origin, Some("team"), "other", "key", true, 1),
            descriptor(
                "resource",
                origin,
                Some("team"),
                "transit",
                "other",
                true,
                1,
            ),
            descriptor("resource", origin, Some("team"), "transit", "key", false, 1),
            descriptor("resource", origin, Some("team"), "transit", "key", true, 2),
            HistoricalSourceSecurityDescriptor::File {
                key_ref: "resource".into(),
            },
        ];
        let neighbour = HistoricalSourceSecurityDescriptor::File {
            key_ref: "neighbour".into(),
        };
        let alone = |d: &HistoricalSourceSecurityDescriptor| {
            source_set_sha256_of(&BTreeSet::from([d.clone()]))
        };
        let beside = |d: &HistoricalSourceSecurityDescriptor| {
            source_set_sha256_of(&BTreeSet::from([neighbour.clone(), d.clone()]))
        };
        assert_eq!(alone(&base), alone(&base.clone()));
        let mut digests = BTreeSet::from([alone(&base), beside(&base)]);
        for change in &changed {
            assert!(digests.insert(alone(change)), "{change:?} kept the digest");
            assert!(digests.insert(beside(change)), "{change:?} kept the digest");
        }
    }

    #[test]
    fn transit_source_set_ignores_credentials_but_tracks_resource_and_trust() {
        let root = crate::test_utils::private_tempdir().unwrap();
        let token = root.path().join("token");
        std::fs::write(&token, "old-token").unwrap();
        let ca = ca_pem();
        let original = transit_set_sha256(transit_config(&ca, &token));

        // Token file content and location, and the origin's spelling, are
        // not security properties of the source.
        std::fs::write(&token, "new-token").unwrap();
        assert_eq!(transit_set_sha256(transit_config(&ca, &token)), original);
        let moved = root.path().join("moved-token");
        std::fs::write(&moved, "moved-token").unwrap();
        let mut respelled = transit_config(&ca, &moved);
        respelled.endpoint = "https://example.com".into();
        assert_eq!(transit_set_sha256(respelled), original);

        let changes: [(&str, ConfigChange); 6] = [
            ("origin", |c| c.endpoint = "https://other.example".into()),
            ("port", |c| c.endpoint = "https://example.com:8200".into()),
            ("namespace", |c| c.namespace = None),
            ("mount", |c| c.mount = "transit".into()),
            ("key name", |c| c.key_name = "other".into()),
            ("derivation", |c| c.derived = false),
        ];
        for (field, change) in changes {
            let mut config = transit_config(&ca, &token);
            change(&mut config);
            assert_ne!(
                transit_set_sha256(config),
                original,
                "{field} kept the digest"
            );
        }
        assert_ne!(
            transit_set_sha256(transit_config(&ca_pem(), &token)),
            original,
            "pinned CA change kept the digest"
        );
    }

    #[tokio::test]
    async fn file_source_set_survives_restart_move_and_rotation_but_not_replacement() {
        let root = crate::test_utils::private_tempdir().unwrap();
        let directory = root.path().join("keys");
        private_files::create_directory(&directory).unwrap();
        let primary_path = directory.join("primary.json");
        let archive_path = directory.join("archive.json");
        let primary = Arc::new(FileKeyProvider::initialize(&primary_path, "application").unwrap());
        let archive = Arc::new(FileKeyProvider::initialize(&archive_path, "application").unwrap());
        let current = primary.generate_key("tenant").await.unwrap();
        let old = archive.generate_key("tenant").await.unwrap();
        let installed = HistoricalKeyResolver::with_primary(
            HistoricalKeySource::file(primary).unwrap(),
            vec![HistoricalKeySource::file(archive).unwrap()],
        )
        .unwrap();
        let committed = installed.historical_descriptors().clone();
        let digest = installed.source_set_sha256();
        drop(installed);

        // Restart after the archive keyring moved and the primary rotated.
        let moved_path = directory.join("moved-archive.json");
        std::fs::rename(&archive_path, &moved_path).unwrap();
        let primary = Arc::new(FileKeyProvider::open(&primary_path).unwrap());
        assert_eq!(primary.rotate().unwrap(), 2);
        let archive = Arc::new(FileKeyProvider::open(&moved_path).unwrap());
        let reopened = HistoricalKeyResolver::with_primary(
            HistoricalKeySource::file(primary.clone()).unwrap(),
            vec![HistoricalKeySource::file(archive.clone()).unwrap()],
        )
        .unwrap();
        assert_eq!(reopened.source_set_sha256(), digest);
        reopened.require_descriptors(&committed).unwrap();
        for key in [&current, &old] {
            assert_eq!(
                reopened
                    .unwrap_key("tenant", &key.wrapped)
                    .await
                    .unwrap()
                    .as_bytes(),
                key.plaintext.as_bytes()
            );
        }

        // A replacement keyring at the original path is another source.
        let replacement =
            Arc::new(FileKeyProvider::initialize(&archive_path, "application").unwrap());
        let replaced = HistoricalKeyResolver::with_primary(
            HistoricalKeySource::file(primary.clone()).unwrap(),
            vec![HistoricalKeySource::file(replacement).unwrap()],
        )
        .unwrap();
        assert_ne!(replaced.source_set_sha256(), digest);
        assert!(replaced.require_descriptors(&committed).is_err());
        let error = must_fail(replaced.unwrap_key("tenant", &old.wrapped).await);
        assert!(error.contains("not installed"), "{error}");

        // Swapping the primary and historical roles changes the committed set.
        let swapped = HistoricalKeyResolver::with_primary(
            HistoricalKeySource::file(archive).unwrap(),
            vec![HistoricalKeySource::file(primary).unwrap()],
        )
        .unwrap();
        assert_ne!(swapped.source_set_sha256(), digest);
        assert!(swapped.require_descriptors(&committed).is_err());
    }

    #[test]
    fn with_primary_rejects_a_historical_source_equal_to_the_primary() {
        let primary = fixture(81);
        let historical = fixture(82);
        for duplicate in [primary.clone(), fixture(81)] {
            let error = must_fail(HistoricalKeyResolver::with_primary(
                source(&primary),
                vec![source(&historical), HistoricalKeySource::fixture(duplicate)],
            ));
            assert!(error.contains("installed primary"), "{error}");
        }
        assert!(
            HistoricalKeyResolver::with_primary(
                source(&primary),
                vec![source(&historical), source(&fixture(82))],
            )
            .is_err()
        );

        let root = crate::test_utils::private_tempdir().unwrap();
        let directory = root.path().join("keys");
        private_files::create_directory(&directory).unwrap();
        let path = directory.join("application.json");
        let keyring = Arc::new(FileKeyProvider::initialize(&path, "application").unwrap());
        let alias = directory.join("alias.json");
        private_files::create(&alias, &private_files::read(&path, 1 << 20).unwrap()).unwrap();
        for duplicate in [path, alias] {
            let error = must_fail(HistoricalKeyResolver::with_primary(
                HistoricalKeySource::file(keyring.clone()).unwrap(),
                vec![
                    HistoricalKeySource::file(Arc::new(FileKeyProvider::open(duplicate).unwrap()))
                        .unwrap(),
                ],
            ));
            assert!(error.contains("installed primary"), "{error}");
        }

        // The same Transit resource is ambiguous with the primary even under
        // another derivation mode, pinned CA or credential.
        let token = root.path().join("token");
        std::fs::write(&token, "token").unwrap();
        let ca = ca_pem();
        let changes: [ConfigChange; 3] = [|_| {}, |c| c.derived = false, |c| c.ca_pem = ca_pem()];
        for change in changes {
            let mut config = transit_config(&ca, &token);
            change(&mut config);
            let error = must_fail(HistoricalKeyResolver::with_primary(
                transit_source(transit_config(&ca, &token)),
                vec![transit_source(config)],
            ));
            assert!(error.contains("installed primary"), "{error}");
        }
        let mut other = transit_config(&ca, &token);
        other.key_name = "other".into();
        let resolver = HistoricalKeyResolver::with_primary(
            transit_source(transit_config(&ca, &token)),
            vec![transit_source(other)],
        )
        .unwrap();
        assert_eq!(resolver.identities().count(), 2);
    }

    #[tokio::test]
    async fn primary_entry_is_exact_dispatch_with_one_probe_per_identity() {
        let (primary, first, second, absent) = (fixture(91), fixture(92), fixture(93), fixture(94));
        let current = primary.generate_key("tenant").await.unwrap();
        let first_key = first.generate_key("tenant").await.unwrap();
        let second_key = second.generate_key("tenant").await.unwrap();
        let absent_key = absent.generate_key("tenant").await.unwrap();
        let resolver = HistoricalKeyResolver::with_primary(
            source(&primary),
            vec![source(&first), source(&second)],
        )
        .unwrap();
        let probes = || {
            [
                primary.probe_count(),
                first.probe_count(),
                second.probe_count(),
                absent.probe_count(),
            ]
        };

        let read_only: &dyn KeyProvider = &resolver;
        assert!(read_only.generate_key("tenant").await.is_err());
        assert!(
            read_only
                .rewrap_key("tenant", &current.wrapped)
                .await
                .is_err()
        );
        assert_eq!(probes(), [0, 0, 0, 0]);

        for (key, expected) in [
            (&current, [1, 0, 0, 0]),
            (&first_key, [1, 1, 0, 0]),
            (&second_key, [1, 1, 1, 0]),
        ] {
            assert_eq!(
                resolver
                    .unwrap_key("tenant", &key.wrapped)
                    .await
                    .unwrap()
                    .as_bytes(),
                key.plaintext.as_bytes()
            );
            assert_eq!(probes(), expected);
        }

        // An uninstalled identity probes nothing, not even the primary.
        let error = must_fail(resolver.unwrap_key("tenant", &absent_key.wrapped).await);
        assert!(error.contains("not installed"), "{error}");
        assert_eq!(probes(), [1, 1, 1, 0]);

        // A failed primary is terminal for its own ciphertext.
        primary.revoke();
        assert!(
            resolver
                .unwrap_key("tenant", &current.wrapped)
                .await
                .is_err()
        );
        assert_eq!(probes(), [2, 1, 1, 0]);

        // A failed historical source never falls back to the primary.
        primary.allow();
        first.revoke();
        assert!(
            resolver
                .unwrap_key("tenant", &first_key.wrapped)
                .await
                .is_err()
        );
        assert_eq!(probes(), [2, 2, 1, 0]);

        // A context mismatch under the primary identity reaches only it.
        assert!(
            resolver
                .unwrap_key("other-tenant", &current.wrapped)
                .await
                .is_err()
        );
        assert_eq!(probes(), [3, 2, 1, 0]);
        assert_eq!(
            resolver
                .unwrap_key("tenant", &current.wrapped)
                .await
                .unwrap()
                .as_bytes(),
            current.plaintext.as_bytes()
        );
        assert_eq!(probes(), [4, 2, 1, 0]);
    }

    #[test]
    fn source_cap_counts_the_primary() {
        let max = HistoricalKeyResolver::MAX_SOURCES;
        let providers = (0..=max).map(|n| fixture(n as u8)).collect::<Vec<_>>();
        let sources =
            |range: std::ops::Range<usize>| providers[range].iter().map(source).collect::<Vec<_>>();
        assert_eq!(
            HistoricalKeyResolver::new(sources(0..max))
                .unwrap()
                .identities()
                .count(),
            max
        );
        let full =
            HistoricalKeyResolver::with_primary(source(&providers[max]), sources(0..max - 1))
                .unwrap();
        assert_eq!(full.identities().count(), max);
        assert_eq!(full.historical_descriptors().len(), max - 1);
        let error = must_fail(HistoricalKeyResolver::with_primary(
            source(&providers[max]),
            sources(0..max),
        ));
        assert!(error.contains("count outside"), "{error}");
        assert!(HistoricalKeyResolver::new(sources(0..max + 1)).is_err());
        assert!(HistoricalKeyResolver::new(Vec::new()).is_err());
        HistoricalKeyResolver::with_primary(source(&providers[0]), Vec::new()).unwrap();
    }

    #[test]
    fn public_wrapping_identity_keeps_first_release_bounds() {
        let provider = fixture(95);
        assert_eq!(
            &WrappingIdentity::new("test-only", provider.key_ref()).unwrap(),
            source(&provider).identity()
        );
        let identity = WrappingIdentity::new(&"p".repeat(16), &"k".repeat(2048)).unwrap();
        assert_eq!(identity.provider().len(), 16);
        assert_eq!(identity.key_ref().len(), 2048);
        let (long_provider, long_key_ref) = ("p".repeat(17), "k".repeat(2049));
        for (provider, key_ref) in [
            ("", "key"),
            (long_provider.as_str(), "key"),
            ("file", ""),
            ("file", long_key_ref.as_str()),
        ] {
            assert!(WrappingIdentity::new(provider, key_ref).is_err());
        }
    }
}
