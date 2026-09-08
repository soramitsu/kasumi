use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
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
    derived: bool,
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
        if let Some(ca) = config.ca_pem {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca)?);
        }
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
            derived: config.derived,
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
        let dir = tempfile::tempdir().unwrap();
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
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let provider = Arc::new(TransitKeyProvider::new(config(&fixture)).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let store = TenantStore::open_fixture_with_clock(
            NodeStore::open(dir.path().join("db")).unwrap(),
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
        let state = Service::new();
        let fixture = TlsFixture::spawn(router(state.clone())).await;
        let provider = Arc::new(TransitKeyProvider::new(config(&fixture)).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let store = TenantStore::open_fixture_with_clock(
            NodeStore::open(dir.path().join("db")).unwrap(),
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
