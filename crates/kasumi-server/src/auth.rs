//! OAuth resource-server authentication. Token-provided URLs are never fetched.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use kasumi_clock::EpochClock;
use kasumi_types::{Action, Error, ErrorCode, RequestAuthorization, RequestContext, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestAuditKind {
    AuthenticationSucceeded,
    AuthenticationDenied,
    AccessDenied,
    TenantSealed,
}

/// Failed tokens never contribute claimed identity fields. This closed metadata
/// type cannot carry token strings, query values or document bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAuditEvent {
    pub kind: RequestAuditKind,
    pub principal: Option<String>,
    pub tenant: Option<String>,
    pub request_id: String,
}

#[async_trait::async_trait]
pub trait RequestAuditSink: Send + Sync {
    async fn record(&self, event: RequestAuditEvent) -> Result<()>;
}

const MAX_TOKEN_BYTES: usize = 16 << 10;
const MAX_JWKS_BYTES: usize = 256 << 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
    /// Only configured asymmetric signature algorithms are accepted.
    pub algorithms: Vec<Algorithm>,
    /// Default deployment uses RFC 9068 "at+jwt"; issuer-specific profiles must
    /// configure this explicitly and use a dedicated resource audience.
    pub access_token_types: BTreeSet<String>,
    /// Optional dedicated trust anchor for a private issuer's HTTPS JWKS. This
    /// public PEM is configured by the operator, never supplied by a token.
    #[serde(default)]
    pub jwks_trusted_ca_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    tenant: String,
    scope: String,
    exp: u64,
    kasumi_resource: kasumi_types::CredentialResource,
    #[serde(default)]
    token_use: Option<String>,
}

struct CachedKeys {
    keys: JwkSet,
    fetched: Duration,
}

pub struct Authenticator {
    config: AuthConfig,
    clock: Arc<EpochClock>,
    client: reqwest::Client,
    cache: RwLock<Option<CachedKeys>>,
    refresh: tokio::sync::Mutex<()>,
    audit: std::sync::OnceLock<Arc<dyn RequestAuditSink>>,
}

impl Authenticator {
    pub fn new(config: AuthConfig) -> anyhow::Result<Arc<Self>> {
        Self::new_with_clock(config, EpochClock::system()?)
    }

    fn new_with_clock(config: AuthConfig, clock: Arc<EpochClock>) -> anyhow::Result<Arc<Self>> {
        for (name, text) in [
            ("issuer", &config.issuer),
            ("audience", &config.audience),
            ("jwks_uri", &config.jwks_uri),
        ] {
            let url = reqwest::Url::parse(text)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "{name} must be an HTTPS URL without credentials or fragment"
            );
        }
        anyhow::ensure!(
            !config.algorithms.is_empty()
                && config.algorithms.iter().all(|a| matches!(
                    a,
                    Algorithm::RS256
                        | Algorithm::RS384
                        | Algorithm::RS512
                        | Algorithm::PS256
                        | Algorithm::PS384
                        | Algorithm::PS512
                        | Algorithm::ES256
                        | Algorithm::ES384
                        | Algorithm::EdDSA
                )),
            "only asymmetric access-token algorithms are allowed"
        );
        anyhow::ensure!(
            !config.access_token_types.is_empty()
                && !config.access_token_types.iter().any(|t| t.is_empty()),
            "access token types must be explicit"
        );
        let mut client = reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5));
        if let Some(pem) = &config.jwks_trusted_ca_pem {
            anyhow::ensure!(pem.len() <= 256 << 10, "JWKS CA PEM exceeds limit");
            client = client
                .tls_built_in_root_certs(false)
                .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
        }
        let client = client.build()?;
        Ok(Arc::new(Self {
            config,
            clock,
            client,
            cache: RwLock::new(None),
            refresh: tokio::sync::Mutex::new(()),
            audit: std::sync::OnceLock::new(),
        }))
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Must be installed before serving. A missing or failing sink never permits
    /// successful authentication, and cannot be replaced at runtime.
    pub fn install_audit(&self, sink: Arc<dyn RequestAuditSink>) -> anyhow::Result<()> {
        self.audit
            .set(sink)
            .map_err(|_| anyhow::anyhow!("request audit sink already installed"))
    }

    async fn record(&self, event: RequestAuditEvent) -> Result<()> {
        self.audit
            .get()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::AuditUnavailable,
                    "required request audit sink unavailable",
                )
            })?
            .record(event)
            .await
            .map_err(|_| {
                Error::new(
                    ErrorCode::AuditUnavailable,
                    "required request audit storage unavailable",
                )
            })
    }

    /// Record adapter-originated authorization and sealed-tenant rejections in
    /// independently protected service storage. Database request methods audit
    /// their own results; the private error marker prevents duplicate attempts
    /// when a nested request's error reaches another boundary. The original
    /// denial still wins on audit failure.
    pub(crate) async fn audit_result<T>(
        &self,
        context: &RequestContext,
        mut result: Result<T>,
    ) -> Result<T> {
        if let Err(error) = &mut result {
            if error.denial_audit_attempted() {
                return result;
            }
            let kind = match error.code {
                ErrorCode::Forbidden | ErrorCode::Unauthorized => {
                    Some(RequestAuditKind::AccessDenied)
                }
                ErrorCode::Sealed => Some(RequestAuditKind::TenantSealed),
                _ => None,
            };
            if let Some(kind) = kind {
                let _ = self
                    .record(RequestAuditEvent {
                        kind,
                        principal: Some(context.principal.clone()),
                        tenant: Some(context.tenant.clone()),
                        request_id: context.request_id.clone(),
                    })
                    .await;
                error.mark_denial_audit_attempted();
            }
        }
        result
    }

    pub(crate) async fn anonymous_denial(&self) {
        let _ = self
            .record(RequestAuditEvent {
                kind: RequestAuditKind::AccessDenied,
                principal: None,
                tenant: None,
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn with_test_keys(config: AuthConfig, keys: JwkSet) -> Arc<Self> {
        let authenticator = Self::new(config).expect("valid test authenticator config");
        *authenticator.cache.write().await = Some(CachedKeys {
            keys,
            fetched: authenticator.clock.elapsed_clock().now(),
        });
        authenticator
    }

    /// Fetched only from operator configuration, never token jku/x5u/issuer input.
    async fn refresh_keys(&self, requested_kid: &str) -> Result<()> {
        let _guard = self.refresh.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache.as_ref() {
                if self
                    .clock
                    .elapsed_clock()
                    .now()
                    .checked_sub(cache.fetched)
                    .ok_or_else(unauthorized)?
                    < Duration::from_secs(300)
                    && cache.keys.find(requested_kid).is_some()
                {
                    return Ok(());
                }
                // Unknown-kid floods cannot turn verification into an unbounded JWKS fetcher.
                if self
                    .clock
                    .elapsed_clock()
                    .now()
                    .checked_sub(cache.fetched)
                    .ok_or_else(unauthorized)?
                    < Duration::from_secs(5)
                {
                    return Err(unauthorized());
                }
            }
        }
        let mut response = self
            .client
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|_| unavailable())?
            .error_for_status()
            .map_err(|_| unavailable())?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        let keys: JwkSet = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        if keys.keys.is_empty() || keys.keys.len() > 128 {
            return Err(unavailable());
        }
        let mut ids = BTreeSet::new();
        for key in &keys.keys {
            if key
                .common
                .key_id
                .as_ref()
                .is_none_or(|id| !ids.insert(id.clone()))
            {
                return Err(unavailable());
            }
        }
        *self.cache.write().await = Some(CachedKeys {
            keys,
            fetched: self.clock.elapsed_clock().now(),
        });
        Ok(())
    }

    pub async fn authenticate(&self, authorization: &str) -> Result<RequestContext> {
        match self.verify(authorization).await {
            Ok(context) => {
                self.record(RequestAuditEvent {
                    kind: RequestAuditKind::AuthenticationSucceeded,
                    principal: Some(context.principal.clone()),
                    tenant: Some(context.tenant.clone()),
                    request_id: context.request_id.clone(),
                })
                .await?;
                self.audit_result(&context, context.authorization.check_live())
                    .await?;
                Ok(context)
            }
            Err(error) => {
                let _ = self
                    .record(RequestAuditEvent {
                        kind: RequestAuditKind::AuthenticationDenied,
                        principal: None,
                        tenant: None,
                        request_id: uuid::Uuid::new_v4().to_string(),
                    })
                    .await;
                Err(error)
            }
        }
    }

    async fn verify(&self, authorization: &str) -> Result<RequestContext> {
        // Capture before JWKS/signature work. Delayed verification cannot renew
        // the absolute token lifetime or ignore time spent suspended.
        let observation = self.clock.observe().map_err(|_| unauthorized())?;
        let token = authorization
            .strip_prefix("Bearer ")
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= MAX_TOKEN_BYTES
                    && !value.contains(char::is_whitespace)
            })
            .ok_or_else(unauthorized)?;
        let header = decode_header(token).map_err(|_| unauthorized())?;
        if !self.config.algorithms.contains(&header.alg)
            || header
                .typ
                .as_ref()
                .is_none_or(|typ| !self.config.access_token_types.contains(typ))
        {
            return Err(unauthorized());
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty() && kid.len() <= 256)
            .ok_or_else(unauthorized)?;
        self.refresh_keys(kid).await?;
        let cache = self.cache.read().await;
        let keys = &cache.as_ref().ok_or_else(unavailable)?.keys;
        let jwk = keys.find(kid).ok_or_else(unauthorized)?;
        if jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| *usage != jsonwebtoken::jwk::PublicKeyUse::Signature)
        {
            return Err(unauthorized());
        }
        if jwk
            .common
            .key_algorithm
            .is_some_and(|algorithm| algorithm.to_string() != format!("{:?}", header.alg))
            || jwk
                .common
                .key_operations
                .as_ref()
                .is_some_and(|operations| {
                    !operations.contains(&jsonwebtoken::jwk::KeyOperations::Verify)
                })
        {
            return Err(unauthorized());
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|_| unauthorized())?;
        let mut validation = Validation::new(header.alg);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| unauthorized())?
            .claims;
        if claims
            .token_use
            .as_deref()
            .is_some_and(|usage| usage != "access")
            || claims.exp == 0
        {
            return Err(unauthorized());
        }
        kasumi_types::validate_name(&claims.sub).map_err(|_| unauthorized())?;
        kasumi_types::validate_name(&claims.tenant).map_err(|_| unauthorized())?;
        if claims.scope.len() > 4096 {
            return Err(unauthorized());
        }
        let scopes = claims
            .scope
            .split_ascii_whitespace()
            .filter_map(|scope| match scope {
                "kasumi:read" => Some(Action::Read),
                "kasumi:write" => Some(Action::Write),
                "kasumi:admin" => Some(Action::Admin),
                "kasumi:audit" => Some(Action::Audit),
                _ => None,
            })
            .collect();
        let authorization = RequestAuthorization::from_verified_credential(
            claims.exp.checked_mul(1000).ok_or_else(unauthorized)?,
            &observation,
            claims.kasumi_resource,
        )?;
        Ok(RequestContext {
            authorization,
            principal: claims.sub,
            tenant: claims.tenant,
            scopes,
            request_id: uuid::Uuid::new_v4().to_string(),
        })
    }

    pub fn protected_resource_metadata(&self, mcp_resource: &str) -> serde_json::Value {
        serde_json::json!({"resource":mcp_resource,"authorization_servers":[self.config.issuer],"scopes_supported":["kasumi:read","kasumi:write"],"bearer_methods_supported":["header"]})
    }
}

fn unauthorized() -> Error {
    Error::new(ErrorCode::Unauthorized, "invalid or missing access token")
}
fn unavailable() -> Error {
    Error::new(
        ErrorCode::Unavailable,
        "trusted authorization keys unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};

    #[derive(Default)]
    struct TestAudit(std::sync::Mutex<Vec<RequestAuditEvent>>);
    #[async_trait::async_trait]
    impl RequestAuditSink for TestAudit {
        async fn record(&self, event: RequestAuditEvent) -> Result<()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn config() -> AuthConfig {
        AuthConfig {
            issuer: "https://issuer.example".into(),
            audience: "https://kasumi.example/mcp".into(),
            jwks_uri: "https://issuer.example/keys".into(),
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
            jwks_trusted_ca_pem: None,
        }
    }

    async fn fixture() -> (Arc<Authenticator>, EncodingKey) {
        fixture_with_clock(EpochClock::system().unwrap()).await
    }

    async fn fixture_with_clock(clock: Arc<EpochClock>) -> (Arc<Authenticator>, EncodingKey) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let keys: JwkSet = serde_json::from_value(serde_json::json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"key-1","x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}]})).unwrap();
        let auth = Authenticator::new_with_clock(config(), clock).unwrap();
        auth.install_audit(Arc::new(TestAudit::default())).unwrap();
        *auth.cache.write().await = Some(CachedKeys {
            keys,
            fetched: auth.clock.elapsed_clock().now(),
        });
        (
            auth,
            EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap(),
        )
    }

    fn claims() -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        serde_json::json!({"iss":"https://issuer.example","aud":"https://kasumi.example/mcp","sub":"person","tenant":"tenant-a","kasumi_resource":{"kind":"database","incarnation":"00000000-0000-0000-0000-000000000001"},"scope":"kasumi:read kasumi:write unrelated","exp":now+300,"nbf":now-1,"token_use":"access"})
    }
    fn bearer(key: &EncodingKey, claims: &serde_json::Value, typ: &str) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("key-1".into());
        header.typ = Some(typ.into());
        format!("Bearer {}", encode(&header, claims, key).unwrap())
    }

    #[tokio::test]
    async fn identity_and_tenant_come_only_from_verified_access_token() {
        let (auth, key) = fixture().await;
        let context = auth
            .authenticate(&bearer(&key, &claims(), "at+jwt"))
            .await
            .unwrap();
        assert_eq!(context.principal, "person");
        assert_eq!(context.tenant, "tenant-a");
        assert_eq!(
            context.scopes,
            BTreeSet::from([Action::Read, Action::Write])
        );
        assert!(!context.request_id.is_empty());
    }

    #[tokio::test]
    async fn missing_audit_sink_blocks_valid_tokens_and_cannot_be_reconfigured() {
        let (source, key) = fixture().await;
        let auth = Authenticator::new(config()).unwrap();
        let cache = source.cache.read().await;
        *auth.cache.write().await = Some(CachedKeys {
            keys: cache.as_ref().unwrap().keys.clone(),
            fetched: auth.clock.elapsed_clock().now(),
        });
        assert_eq!(
            auth.authenticate(&bearer(&key, &claims(), "at+jwt"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        auth.install_audit(Arc::new(TestAudit::default())).unwrap();
        assert!(auth.install_audit(Arc::new(TestAudit::default())).is_err());
        assert!(
            auth.authenticate(&bearer(&key, &claims(), "at+jwt"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_wrong_audience_issuer_expiry_not_before_and_id_tokens() {
        let (auth, key) = fixture().await;
        let original = claims();
        for (field, value) in [
            ("aud", serde_json::json!("https://different.example")),
            ("iss", serde_json::json!("https://attacker.example")),
            ("exp", serde_json::json!(1)),
            ("nbf", serde_json::json!(u64::MAX)),
            ("token_use", serde_json::json!("id")),
            ("sub", serde_json::json!("")),
            ("tenant", serde_json::json!("")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert_eq!(
                auth.authenticate(&bearer(&key, &changed, "at+jwt"))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Unauthorized,
                "{field}"
            );
        }
        assert_eq!(
            auth.authenticate(&bearer(&key, &original, "JWT"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
    }

    #[tokio::test]
    async fn untrusted_signatures_and_unknown_keys_never_gain_access() {
        let (auth, _) = fixture().await;
        let (_, other_key) = fixture().await;
        assert!(
            auth.authenticate(&bearer(&other_key, &claims(), "at+jwt"))
                .await
                .is_err()
        );
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("at+jwt".into());
        header.kid = Some("unknown".into());
        let token = format!("Bearer {}", encode(&header, &claims(), &other_key).unwrap());
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert!(
            auth.authenticate(&format!("Bearer {}", "x".repeat(MAX_TOKEN_BYTES + 1)))
                .await
                .is_err()
        );
    }

    #[test]
    fn config_rejects_cleartext_credentials_and_symmetric_algorithms() {
        let mut bad = config();
        bad.jwks_uri = "http://issuer.example/keys".into();
        assert!(Authenticator::new(bad).is_err());
        let mut bad = config();
        bad.jwks_uri = "https://secret:password@issuer.example/keys".into();
        assert!(Authenticator::new(bad).is_err());
        let mut bad = config();
        bad.algorithms = vec![Algorithm::HS256];
        assert!(Authenticator::new(bad).is_err());
    }
    struct ManualElapsed(std::sync::atomic::AtomicU64);
    impl kasumi_clock::LeaseClock for ManualElapsed {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }
    struct ManualWall(std::sync::atomic::AtomicU64);
    impl kasumi_clock::WallClock for ManualWall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }
    #[tokio::test]
    async fn verified_credential_expiry_survives_suspend_wall_rollback_and_injected_origin() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut claims = claims();
        let base = claims["exp"].as_u64().unwrap() - 300;
        claims["exp"] = serde_json::json!(base + 10);
        claims["authorization"] = serde_json::json!({"kind":"service_identity"});
        let elapsed = Arc::new(ManualElapsed(AtomicU64::new(0)));
        let wall = Arc::new(ManualWall(AtomicU64::new(base * 1000)));
        let clock = Arc::new(EpochClock::new(elapsed.clone(), wall.clone()).unwrap());
        let (auth, key) = fixture_with_clock(clock).await;
        let token = bearer(&key, &claims, "at+jwt");
        let context = auth.authenticate(&token).await.unwrap();
        assert_eq!(
            context.authorization.expires_at_ms(),
            Some((base + 10) * 1000)
        );
        elapsed.0.store(9999, Ordering::SeqCst);
        wall.0.store(1, Ordering::SeqCst);
        let delayed_clone = context.clone();
        delayed_clone.authorization.check_live().unwrap();
        // Suspend advances the kernel elapsed clock even when UTC moves back.
        elapsed.0.store(10_000, Ordering::SeqCst);
        assert_eq!(
            context.authorization.check_live().unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            delayed_clone.authorization.check_live().unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
        // A clone cannot recover even if a faulty injected clock goes backwards.
        elapsed.0.store(1, Ordering::SeqCst);
        assert!(delayed_clone.authorization.check_live().is_err());
    }
    struct ExpiringAudit {
        clock: Arc<ManualElapsed>,
        events: std::sync::Mutex<Vec<RequestAuditKind>>,
    }
    #[async_trait::async_trait]
    impl RequestAuditSink for ExpiringAudit {
        async fn record(&self, event: RequestAuditEvent) -> Result<()> {
            if event.kind == RequestAuditKind::AuthenticationSucceeded {
                self.clock
                    .0
                    .store(10_000, std::sync::atomic::Ordering::SeqCst);
            }
            self.events.lock().unwrap().push(event.kind);
            Ok(())
        }
    }
    #[tokio::test]
    async fn credential_expiring_during_required_authentication_audit_is_never_released() {
        use std::sync::atomic::AtomicU64;
        let mut claims = claims();
        let base = claims["exp"].as_u64().unwrap() - 300;
        claims["exp"] = serde_json::json!(base + 10);
        let elapsed = Arc::new(ManualElapsed(AtomicU64::new(0)));
        let clock = Arc::new(
            EpochClock::new(
                elapsed.clone(),
                Arc::new(ManualWall(AtomicU64::new(base * 1000))),
            )
            .unwrap(),
        );
        let (source, key) = fixture().await;
        let auth = Authenticator::new_with_clock(config(), clock).unwrap();
        let cache = source.cache.read().await;
        *auth.cache.write().await = Some(CachedKeys {
            keys: cache.as_ref().unwrap().keys.clone(),
            fetched: Duration::ZERO,
        });
        let audit = Arc::new(ExpiringAudit {
            clock: elapsed,
            events: std::sync::Mutex::new(vec![]),
        });
        auth.install_audit(audit.clone()).unwrap();
        assert_eq!(
            auth.authenticate(&bearer(&key, &claims, "at+jwt"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            *audit.events.lock().unwrap(),
            vec![
                RequestAuditKind::AuthenticationSucceeded,
                RequestAuditKind::AccessDenied
            ]
        );
    }
}
