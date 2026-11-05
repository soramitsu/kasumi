//! OAuth resource-server authentication. Token-provided URLs are never fetched.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use kasumi_clock::EpochClock;
use kasumi_types::{Action, Error, ErrorCode, RequestAuthorization, RequestContext, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestAuditKind {
    AuthenticationSucceeded,
    /// Later successes on one connection with the token whose recorded
    /// success has this event's `request_id` (see `authenticate_on`).
    AuthenticationRepeated {
        requests: u64,
    },
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
    pub source: AuthKeySource,
    /// Only configured asymmetric signature algorithms are accepted.
    pub algorithms: Vec<Algorithm>,
    /// Default deployment uses RFC 9068 "at+jwt"; issuer-specific profiles must
    /// configure this explicitly and use a dedicated resource audience.
    pub access_token_types: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthKeySource {
    #[serde(rename = "external_oauth")]
    ExternalOAuth {
        jwks_uri: String,
        trusted_ca_pem: Option<String>,
    },
    Local {
        signer_file: std::path::PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: String,
    tenant: String,
    scope: String,
    exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
    kasumi_resource: kasumi_types::CredentialResource,
    #[serde(default)]
    token_use: Option<String>,
    #[serde(default)]
    kasumi_family: Option<uuid::Uuid>,
}

/// Tokens whose signed claims one key set has verified, at most this many.
/// A full cache is emptied; its tokens are verified again on their next use.
const MAX_VERIFIED_TOKENS: usize = 1024;

type TokenDigest = [u8; 32];

struct CachedKeys {
    keys: JwkSet,
    fetched: Duration,
    /// Claims of tokens these exact keys verified, by token SHA-256. Owned by
    /// the key set, so every reload or JWKS refresh starts empty. Only
    /// successfully verified tokens enter; failures are never remembered.
    verified: std::sync::Mutex<std::collections::HashMap<TokenDigest, Claims>>,
}

impl CachedKeys {
    fn new(keys: JwkSet, fetched: Duration) -> Self {
        Self {
            keys,
            fetched,
            verified: Default::default(),
        }
    }

    fn verified(&self, digest: &TokenDigest) -> Option<Claims> {
        self.verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .cloned()
    }

    fn remember(&self, digest: TokenDigest, claims: &Claims) {
        let mut verified = self
            .verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if verified.len() >= MAX_VERIFIED_TOKENS {
            verified.clear();
        }
        verified.insert(digest, claims.clone());
    }
}

/// The bearer token whose successful authentication one client connection
/// has durably recorded, and how many later requests it authenticated there.
/// The connection's serving task owns it and closes it when the connection
/// ends; its requests share it through a request extension.
#[derive(Default)]
pub(crate) struct ConnectionAuthentications {
    current: tokio::sync::Mutex<Option<RecordedToken>>,
}

impl ConnectionAuthentications {
    /// Durably record how many requests the current token authenticated
    /// after its recorded success. A connection that ends without this, such
    /// as one aborted at shutdown, loses only that count: each of its tokens'
    /// first success is already durable.
    pub(crate) async fn close(&self) -> Result<()> {
        match self.current.lock().await.take() {
            Some(mut token) => token.settle().await,
            None => Ok(()),
        }
    }
}

struct RecordedToken {
    auth: Arc<Authenticator>,
    digest: TokenDigest,
    principal: String,
    tenant: String,
    /// The request whose `AuthenticationSucceeded` record covers this token.
    request_id: String,
    /// Later successes counted instead of recorded.
    repeated: u64,
}

impl RecordedToken {
    /// Durably record the successes counted since the last record, if any.
    /// A failed record keeps the count; a cancelled one may lose it but
    /// never records it twice.
    async fn settle(&mut self) -> Result<()> {
        let requests = std::mem::take(&mut self.repeated);
        if requests == 0 {
            return Ok(());
        }
        let recorded = self
            .auth
            .record(RequestAuditEvent {
                kind: RequestAuditKind::AuthenticationRepeated { requests },
                principal: Some(self.principal.clone()),
                tenant: Some(self.tenant.clone()),
                request_id: self.request_id.clone(),
            })
            .await;
        if recorded.is_err() {
            self.repeated = self.repeated.saturating_add(requests);
        }
        recorded
    }
}

fn succeeded(context: &RequestContext) -> RequestAuditEvent {
    RequestAuditEvent {
        kind: RequestAuditKind::AuthenticationSucceeded,
        principal: Some(context.principal.clone()),
        tenant: Some(context.tenant.clone()),
        request_id: context.request_id.clone(),
    }
}

/// The physical identity of the local signer file a reload read. Rotation
/// atomically replaces the file, so an unchanged identity has the same keys.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SignerFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified: Option<std::time::SystemTime>,
}

impl SignerFileIdentity {
    fn observe(path: &std::path::Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).ok()?;
        Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// Whether a reload of the local signer could ever trust `kid`. Its kids are
/// `{signer}.{generation}`, and rotation only appends a higher generation to
/// the same signer, so a malformed kid or an older generation of a cached
/// signer stays unknown however often the file is reloaded. A kid of another
/// signer may appear only if the file is replaced; the caller's file-identity
/// gate bounds those reloads. With no cached keys yet, every kid may appear.
fn local_kid_may_appear(cached: Option<&JwkSet>, kid: &str) -> bool {
    let split = |kid: &str| -> Option<(String, u64)> {
        let (signer, generation) = kid.rsplit_once('.')?;
        Some((signer.to_owned(), generation.parse().ok()?))
    };
    let Some(cached) = cached.filter(|keys| !keys.keys.is_empty()) else {
        return true;
    };
    let Some((signer, generation)) = split(kid) else {
        return false;
    };
    cached
        .keys
        .iter()
        .filter_map(|key| key.common.key_id.as_deref().and_then(split))
        .filter(|(cached_signer, _)| *cached_signer == signer)
        .map(|(_, cached_generation)| cached_generation)
        .max()
        .is_none_or(|highest| generation > highest)
}

/// What the last refresh established, held while refreshing.
#[derive(Default)]
struct RefreshState {
    /// Number of the local signer reload that produced the cache.
    loaded: u64,
    /// The signer file that reload read, successfully or not. A kid that may
    /// still appear is reloaded only after this identity changes.
    signer: Option<SignerFileIdentity>,
}

pub struct Authenticator {
    config: AuthConfig,
    clock: Arc<EpochClock>,
    client: reqwest::Client,
    cache: RwLock<Option<CachedKeys>>,
    /// Serializes refreshes; requests whose key is cached never wait on it.
    refresh: tokio::sync::Mutex<RefreshState>,
    /// Local signer reloads begun, numbered while holding `refresh`.
    reloads: AtomicU64,
    audit: std::sync::OnceLock<Arc<dyn RequestAuditSink>>,
    /// Whether the latest audit write failed. Connections then record every
    /// success again instead of counting it, so an audit outage refuses
    /// their requests as it refuses everyone else's.
    audit_failed: AtomicBool,
    local_credentials: std::sync::OnceLock<Arc<crate::local_auth::LocalCredentials>>,
}

impl Authenticator {
    pub(crate) fn signer_admission_deadline(
        &self,
        not_after_ms: u64,
    ) -> anyhow::Result<kasumi_clock::ElapsedDeadline> {
        self.clock.observe()?.until(not_after_ms)
    }
    pub fn new(config: AuthConfig) -> anyhow::Result<Arc<Self>> {
        Self::new_with_clock(config, EpochClock::system()?)
    }

    fn new_with_clock(config: AuthConfig, clock: Arc<EpochClock>) -> anyhow::Result<Arc<Self>> {
        let mut urls = vec![("issuer", &config.issuer), ("audience", &config.audience)];
        match &config.source {
            AuthKeySource::ExternalOAuth { jwks_uri, .. } => urls.push(("jwks_uri", jwks_uri)),
            AuthKeySource::Local { signer_file } => {
                anyhow::ensure!(
                    signer_file.is_absolute(),
                    "local signer path must be absolute"
                );
                anyhow::ensure!(
                    config.algorithms == [Algorithm::EdDSA]
                        && config.access_token_types == BTreeSet::from(["at+jwt".into()]),
                    "local issuer requires EdDSA access tokens"
                );
            }
        }
        for (name, text) in urls {
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
        if let AuthKeySource::ExternalOAuth {
            trusted_ca_pem: Some(pem),
            ..
        } = &config.source
        {
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
            refresh: tokio::sync::Mutex::new(RefreshState::default()),
            reloads: AtomicU64::new(0),
            audit: std::sync::OnceLock::new(),
            audit_failed: AtomicBool::new(false),
            local_credentials: std::sync::OnceLock::new(),
        }))
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn install_local_credentials(
        &self,
        credentials: Arc<crate::local_auth::LocalCredentials>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(self.config.source, AuthKeySource::Local { .. }),
            "external OAuth cannot install a local credential issuer"
        );
        self.local_credentials
            .set(credentials)
            .map_err(|_| anyhow::anyhow!("local credential issuer already installed"))
    }

    pub(crate) fn local_credentials(&self) -> Result<&Arc<crate::local_auth::LocalCredentials>> {
        self.local_credentials.get().ok_or_else(unavailable)
    }

    /// Must be installed before serving. A missing or failing sink never permits
    /// successful authentication, and cannot be replaced at runtime.
    pub fn install_audit(&self, sink: Arc<dyn RequestAuditSink>) -> anyhow::Result<()> {
        self.audit
            .set(sink)
            .map_err(|_| anyhow::anyhow!("request audit sink already installed"))
    }

    async fn record(&self, event: RequestAuditEvent) -> Result<()> {
        let recorded = match self.audit.get() {
            Some(sink) => sink.record(event).await.map_err(|_| {
                Error::new(
                    ErrorCode::AuditUnavailable,
                    "required request audit storage unavailable",
                )
            }),
            None => Err(Error::new(
                ErrorCode::AuditUnavailable,
                "required request audit sink unavailable",
            )),
        };
        self.audit_failed
            .store(recorded.is_err(), Ordering::Release);
        recorded
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
    pub(crate) fn with_test_clock(
        config: AuthConfig,
        clock: Arc<EpochClock>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_clock(config, clock)
    }

    #[cfg(test)]
    pub(crate) async fn with_test_keys(config: AuthConfig, keys: JwkSet) -> Arc<Self> {
        let authenticator = Self::new(config).expect("valid test authenticator config");
        *authenticator.cache.write().await = Some(CachedKeys::new(
            keys,
            authenticator.clock.elapsed_clock().now(),
        ));
        authenticator
    }

    /// Whether the cache already trusts `kid` without a refresh: the local
    /// signer's keys until a reload, an external JWKS for its lifetime.
    async fn cached(&self, kid: &str) -> Result<bool> {
        let cache = self.cache.read().await;
        let Some(cache) = cache
            .as_ref()
            .filter(|cache| cache.keys.find(kid).is_some())
        else {
            return Ok(false);
        };
        Ok(match self.config.source {
            AuthKeySource::Local { .. } => true,
            AuthKeySource::ExternalOAuth { .. } => {
                self.clock
                    .elapsed_clock()
                    .now()
                    .checked_sub(cache.fetched)
                    .ok_or_else(unauthorized)?
                    < Duration::from_secs(300)
            }
        })
    }

    /// Fetched only from operator configuration, never token jku/x5u/issuer input.
    async fn refresh_keys(&self, requested_kid: &str) -> Result<()> {
        // A cached key never waits behind a JWKS fetch or a signer reload.
        if self.cached(requested_kid).await? {
            return Ok(());
        }
        let begun = self.reloads.load(Ordering::Acquire);
        let mut state = self.refresh.lock().await;
        if self.cached(requested_kid).await? {
            return Ok(());
        }
        let jwks_uri = match &self.config.source {
            AuthKeySource::Local { signer_file } => {
                // Rotation only appends generations, and a kid is issued only
                // after its generation is written. A reload begun while this
                // request waited has read it, so the kid is unknown.
                if state.loaded > begun {
                    return Err(unauthorized());
                }
                // Unauthenticated headers choose the kid. Read the private
                // signer file only for a kid that could still appear, and
                // only once per replacement of that file, so a flood of
                // unknown kids neither rereads it nor drops verified tokens.
                let identity = SignerFileIdentity::observe(signer_file);
                {
                    let cache = self.cache.read().await;
                    let cached = cache.as_ref().map(|cached| &cached.keys);
                    if !local_kid_may_appear(cached, requested_kid)
                        || (cached.is_some() && identity.is_some() && state.signer == identity)
                    {
                        return Err(unauthorized());
                    }
                }
                let reload = self.reloads.fetch_add(1, Ordering::AcqRel) + 1;
                state.signer = identity;
                let signer_file = signer_file.clone();
                let keys = tokio::task::spawn_blocking(move || {
                    crate::local_auth::trusted_keys(&signer_file)
                })
                .await
                .map_err(|_| unavailable())?
                .map_err(|_| unavailable())?;
                let mut cache = self.cache.write().await;
                let now = self.clock.elapsed_clock().now();
                match cache.as_mut() {
                    // The same keys keep the tokens they already verified.
                    Some(current) if current.keys == keys => current.fetched = now,
                    _ => *cache = Some(CachedKeys::new(keys, now)),
                }
                state.loaded = reload;
                return Ok(());
            }
            AuthKeySource::ExternalOAuth { jwks_uri, .. } => jwks_uri,
        };
        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache.as_ref() {
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
            .get(jwks_uri)
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
        *self.cache.write().await = Some(CachedKeys::new(keys, self.clock.elapsed_clock().now()));
        Ok(())
    }

    /// Authenticate one request, durably recording its success or refusal.
    pub async fn authenticate(&self, authorization: &str) -> Result<RequestContext> {
        let context = match self.verify(authorization).await {
            Ok((context, _)) => context,
            Err(error) => return Err(self.refuse(error).await),
        };
        self.record(succeeded(&context)).await?;
        self.audit_result(&context, context.authorization.check_live())
            .await?;
        Ok(context)
    }

    /// Authenticate a request received on `connection`. Each request is
    /// verified in full: signature (through the verified-token cache), signed
    /// times, token use, scopes and credential liveness. The first success of
    /// a token on the connection is durably recorded before that request
    /// proceeds, like every success of `authenticate`; later successes with
    /// the same token are counted instead, and the count is recorded once,
    /// when the connection presents another token or closes. While audit
    /// writes fail, each success is recorded again, so the outage refuses
    /// these requests too. Every refusal is recorded.
    pub(crate) async fn authenticate_on(
        self: &Arc<Self>,
        authorization: &str,
        connection: &ConnectionAuthentications,
    ) -> Result<RequestContext> {
        let (context, digest) = match self.verify(authorization).await {
            Ok(verified) => verified,
            Err(error) => return Err(self.refuse(error).await),
        };
        // Held across a first success's durable record: concurrent first
        // requests on one connection record one success, and none of them
        // proceeds before it is durable.
        let mut current = connection.current.lock().await;
        let recorded = current
            .as_ref()
            .is_some_and(|token| token.digest == digest && Arc::ptr_eq(&token.auth, self));
        if recorded && !self.audit_failed.load(Ordering::Acquire) {
            if let Some(token) = current.as_mut() {
                token.repeated = token.repeated.saturating_add(1);
            }
            drop(current);
        } else if recorded {
            drop(current);
            self.record(succeeded(&context)).await?;
        } else {
            if let Some(previous) = current.as_mut() {
                previous.settle().await?;
            }
            self.record(succeeded(&context)).await?;
            *current = Some(RecordedToken {
                auth: self.clone(),
                digest,
                principal: context.principal.clone(),
                tenant: context.tenant.clone(),
                request_id: context.request_id.clone(),
                repeated: 0,
            });
            drop(current);
        }
        self.audit_result(&context, context.authorization.check_live())
            .await?;
        Ok(context)
    }

    /// Record a refused bearer without any claimed identity. The refusal
    /// stands even if its record fails.
    async fn refuse(&self, error: Error) -> Error {
        let _ = self
            .record(RequestAuditEvent {
                kind: RequestAuditKind::AuthenticationDenied,
                principal: None,
                tenant: None,
                request_id: uuid::Uuid::new_v4().to_string(),
            })
            .await;
        error
    }

    /// The signed claims of `token` under `keys`, without any time check.
    fn verify_signature(
        &self,
        keys: &JwkSet,
        token: &str,
        header: &jsonwebtoken::Header,
        kid: &str,
    ) -> Result<Claims> {
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
        // JWT verifies signed claims and identity. The process-wide trusted
        // epoch observation is the sole time authority, including after wall
        // clock rollback; elapsed authorization retains the original expiry.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        Ok(decode::<Claims>(token, &key, &validation)
            .map_err(|_| unauthorized())?
            .claims)
    }

    /// The request context `authorization` grants, with the digest of its
    /// token bytes.
    async fn verify(&self, authorization: &str) -> Result<(RequestContext, TokenDigest)> {
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
        let digest: TokenDigest = Sha256::digest(token.as_bytes()).into();
        let claims = {
            let cache = self.cache.read().await;
            let cached = cache.as_ref().ok_or_else(unavailable)?;
            // Signature, issuer, audience and required-claim checks depend
            // only on these exact token bytes and this key set, so a token
            // this key set already verified skips them. Everything below
            // (signed times against the trusted epoch, token use, scopes and
            // credential liveness) runs every request.
            match cached.verified(&digest) {
                Some(claims) => claims,
                None => {
                    let claims = self.verify_signature(&cached.keys, token, &header, kid)?;
                    cached.remember(digest, &claims);
                    claims
                }
            }
        };
        if let Some(not_before) = claims.nbf {
            let not_before_ms = not_before.checked_mul(1000).ok_or_else(unauthorized)?;
            if observation.utc_ms() < not_before_ms {
                return Err(unauthorized());
            }
        }
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
        let expires_at = claims.exp.checked_mul(1000).ok_or_else(unauthorized)?;
        let authorization = match &self.config.source {
            AuthKeySource::Local { .. } => {
                if claims.token_use.as_deref() != Some("access") {
                    return Err(unauthorized());
                }
                let family = claims.kasumi_family.ok_or_else(unauthorized)?;
                let guard = self.local_credentials()?.guard(
                    family,
                    &claims.sub,
                    &claims.tenant,
                    &claims.scope,
                    &claims.kasumi_resource,
                )?;
                RequestAuthorization::from_verified_credential_with_liveness(
                    expires_at,
                    &observation,
                    claims.kasumi_resource,
                    guard,
                )?
            }
            AuthKeySource::ExternalOAuth { .. } => RequestAuthorization::from_verified_credential(
                expires_at,
                &observation,
                claims.kasumi_resource,
            )?,
        };
        Ok((
            RequestContext {
                authorization,
                principal: claims.sub,
                tenant: claims.tenant,
                scopes,
                request_id: uuid::Uuid::new_v4().to_string(),
            },
            digest,
        ))
    }

    /// Only an installed external authorization provider advertises discovery.
    pub fn protected_resource_metadata(&self, mcp_resource: &str) -> Option<serde_json::Value> {
        match &self.config.source {
            AuthKeySource::ExternalOAuth { .. } => Some(serde_json::json!({
                "resource": mcp_resource,
                "authorization_servers": [self.config.issuer],
                "scopes_supported": ["kasumi:read", "kasumi:write"],
                "bearer_methods_supported": ["header"]
            })),
            AuthKeySource::Local { .. } => None,
        }
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
            source: AuthKeySource::ExternalOAuth {
                jwks_uri: "https://issuer.example/keys".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
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
        *auth.cache.write().await = Some(CachedKeys::new(keys, auth.clock.elapsed_clock().now()));
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
        *auth.cache.write().await = Some(CachedKeys::new(
            cache.as_ref().unwrap().keys.clone(),
            auth.clock.elapsed_clock().now(),
        ));
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
        bad.source = AuthKeySource::ExternalOAuth {
            jwks_uri: "http://issuer.example/keys".into(),
            trusted_ca_pem: None,
        };
        assert!(Authenticator::new(bad).is_err());
        let mut bad = config();
        bad.source = AuthKeySource::ExternalOAuth {
            jwks_uri: "https://secret:password@issuer.example/keys".into(),
            trusted_ca_pem: None,
        };
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
    #[tokio::test]
    async fn signed_claim_times_use_only_trusted_native_epoch_with_exact_boundaries() {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Exercise trusted UTC on both sides of system time; real UTC must
        // never replace the native epoch or decide its four-second proof.
        for base_seconds in [1_000_000, 4_000_000_000] {
            let elapsed = Arc::new(ManualElapsed(AtomicU64::new(0)));
            let wall = Arc::new(ManualWall(AtomicU64::new(base_seconds * 1000)));
            let clock = Arc::new(EpochClock::new(elapsed.clone(), wall.clone()).unwrap());
            let (auth, key) = fixture_with_clock(clock).await;
            let mut value = claims();
            value["nbf"] = serde_json::json!(base_seconds);
            value["exp"] = serde_json::json!(base_seconds + 4);
            let token = bearer(&key, &value, "at+jwt");
            let original = auth.authenticate(&token).await.unwrap();
            assert_eq!(
                original.authorization.expires_at_ms(),
                Some((base_seconds + 4) * 1000)
            );
            // A missing optional nbf preserves the existing claim contract.
            let mut no_nbf = value.clone();
            no_nbf.as_object_mut().unwrap().remove("nbf");
            auth.authenticate(&bearer(&key, &no_nbf, "at+jwt"))
                .await
                .unwrap();
            for (name, changed) in [
                ("nbf", serde_json::json!(base_seconds + 1)),
                ("nbf", serde_json::json!(u64::MAX)),
                ("nbf", serde_json::json!("1000000")),
                ("nbf", serde_json::json!(-1)),
                ("nbf", serde_json::json!(1.5)),
                ("exp", serde_json::json!(u64::MAX)),
                ("exp", serde_json::json!(base_seconds)),
                ("exp", serde_json::json!("1000004")),
            ] {
                let mut invalid = value.clone();
                invalid[name] = changed;
                assert_eq!(
                    auth.authenticate(&bearer(&key, &invalid, "at+jwt"))
                        .await
                        .unwrap_err()
                        .code,
                    ErrorCode::Unauthorized,
                    "{name}={}",
                    invalid[name]
                );
            }
            // Exact nbf equality passes, the millisecond before it does not.
            let mut future = value.clone();
            future["nbf"] = serde_json::json!(base_seconds + 1);
            let future = bearer(&key, &future, "at+jwt");
            elapsed.0.store(999, Ordering::SeqCst);
            wall.0.store(1, Ordering::SeqCst);
            assert_eq!(
                auth.authenticate(&future).await.unwrap_err().code,
                ErrorCode::Unauthorized
            );
            elapsed.0.store(1000, Ordering::SeqCst);
            auth.authenticate(&future).await.unwrap();
            elapsed.0.store(3999, Ordering::SeqCst);
            original.authorization.check_live().unwrap();
            auth.authenticate(&token).await.unwrap();
            elapsed.0.store(4000, Ordering::SeqCst);
            assert_eq!(
                original.authorization.check_live().unwrap_err().code,
                ErrorCode::Unauthorized
            );
            assert_eq!(
                auth.authenticate(&token).await.unwrap_err().code,
                ErrorCode::Unauthorized
            );
        }
    }

    async fn verified_tokens(auth: &Authenticator) -> usize {
        auth.cache
            .read()
            .await
            .as_ref()
            .map_or(0, |cached| cached.verified.lock().unwrap().len())
    }

    #[tokio::test]
    async fn verified_tokens_skip_only_signature_work_and_end_with_their_key_set() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let base = 2_000_000_000;
        let elapsed = Arc::new(ManualElapsed(AtomicU64::new(0)));
        let wall = Arc::new(ManualWall(AtomicU64::new(base * 1000)));
        let clock = Arc::new(EpochClock::new(elapsed.clone(), wall).unwrap());
        let (auth, key) = fixture_with_clock(clock).await;
        let mut value = claims();
        value["nbf"] = serde_json::json!(base);
        value["exp"] = serde_json::json!(base + 4);
        let token = bearer(&key, &value, "at+jwt");
        auth.authenticate(&token).await.unwrap();
        assert_eq!(verified_tokens(&auth).await, 1);
        // A repeat uses the verified claims and yields the same identity, a
        // fresh request ID and the same absolute expiry.
        let first = auth.authenticate(&token).await.unwrap();
        let second = auth.authenticate(&token).await.unwrap();
        assert_eq!(verified_tokens(&auth).await, 1);
        assert_eq!(
            (&first.principal, &first.tenant),
            (&second.principal, &second.tenant)
        );
        assert_ne!(first.request_id, second.request_id);
        assert_eq!(
            second.authorization.expires_at_ms(),
            Some((base + 4) * 1000)
        );
        // Changed signature bytes and another key's signature over identical
        // claims are separate tokens, verified on their own and refused.
        let signature_at = token.rfind('.').unwrap() + 10;
        let mut forged = token.clone().into_bytes();
        forged[signature_at] = if forged[signature_at] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let forged = String::from_utf8(forged).unwrap();
        assert_eq!(
            auth.authenticate(&forged).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
        let (_, other) = fixture().await;
        assert_eq!(
            auth.authenticate(&bearer(&other, &value, "at+jwt"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert_eq!(verified_tokens(&auth).await, 1);
        // A replaced key set starts without verified tokens; one without the
        // token's key refuses it even though it was verified before.
        let keys = auth.cache.read().await.as_ref().unwrap().keys.clone();
        let empty: JwkSet = serde_json::from_value(serde_json::json!({"keys": []})).unwrap();
        *auth.cache.write().await = Some(CachedKeys::new(empty, Duration::ZERO));
        assert_eq!(verified_tokens(&auth).await, 0);
        // An unknown kid is refreshed for external issuers; the fixture's JWKS
        // endpoint is unreachable, so the token cannot be accepted.
        assert!(auth.authenticate(&token).await.is_err());
        *auth.cache.write().await = Some(CachedKeys::new(keys, auth.clock.elapsed_clock().now()));
        auth.authenticate(&token).await.unwrap();
        assert_eq!(verified_tokens(&auth).await, 1);
        // Signed times still apply to a verified token on every request.
        elapsed.0.store(4000, Ordering::SeqCst);
        assert_eq!(
            auth.authenticate(&token).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }

    #[test]
    fn verified_token_cache_is_bounded() {
        let empty: JwkSet = serde_json::from_value(serde_json::json!({"keys": []})).unwrap();
        let cached = CachedKeys::new(empty, Duration::ZERO);
        let claims: Claims = serde_json::from_value(claims()).unwrap();
        for index in 0..=MAX_VERIFIED_TOKENS {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
            cached.remember(digest, &claims);
            assert!(cached.verified.lock().unwrap().len() <= MAX_VERIFIED_TOKENS);
        }
        assert!(cached.verified(&[0; 32]).is_none());
    }

    /// Keeps every event it accepts and refuses every write while `failing`.
    /// Each write yields first, so concurrent requests interleave.
    #[derive(Default)]
    struct SwitchedAudit {
        events: std::sync::Mutex<Vec<RequestAuditEvent>>,
        failing: AtomicBool,
    }
    #[async_trait::async_trait]
    impl RequestAuditSink for SwitchedAudit {
        async fn record(&self, event: RequestAuditEvent) -> Result<()> {
            tokio::task::yield_now().await;
            if self.failing.load(Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::AuditUnavailable,
                    "test audit failing",
                ));
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }
    impl SwitchedAudit {
        fn fail(&self, failing: bool) {
            self.failing.store(failing, Ordering::SeqCst);
        }
        /// Each kept event's kind with the request it names.
        fn recorded(&self) -> Vec<(RequestAuditKind, String)> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|event| (event.kind.clone(), event.request_id.clone()))
                .collect()
        }
    }

    async fn connection_fixture() -> (Arc<Authenticator>, Arc<SwitchedAudit>, EncodingKey) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let keys: JwkSet = serde_json::from_value(serde_json::json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"key-1","x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}]})).unwrap();
        let auth = Authenticator::new(config()).unwrap();
        let audit = Arc::new(SwitchedAudit::default());
        auth.install_audit(audit.clone()).unwrap();
        *auth.cache.write().await = Some(CachedKeys::new(keys, auth.clock.elapsed_clock().now()));
        (
            auth,
            audit,
            EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap(),
        )
    }

    fn renewed(key: &EncodingKey) -> String {
        let mut renewed = claims();
        renewed["exp"] = serde_json::json!(renewed["exp"].as_u64().unwrap() + 1);
        bearer(key, &renewed, "at+jwt")
    }

    fn repeated(requests: u64) -> RequestAuditKind {
        RequestAuditKind::AuthenticationRepeated { requests }
    }

    #[tokio::test]
    async fn a_connection_records_each_tokens_first_success_and_counts_the_rest() {
        use RequestAuditKind::{
            AuthenticationDenied as Denied, AuthenticationSucceeded as Succeeded,
        };
        let (auth, audit, key) = connection_fixture().await;
        let token = bearer(&key, &claims(), "at+jwt");
        let renewed = renewed(&key);
        let mut expired = claims();
        expired["exp"] = serde_json::json!(1);
        let expired = bearer(&key, &expired, "at+jwt");
        let connection = ConnectionAuthentications::default();
        let first = auth.authenticate_on(&token, &connection).await.unwrap();
        for _ in 0..2 {
            let later = auth.authenticate_on(&token, &connection).await.unwrap();
            assert_ne!(later.request_id, first.request_id);
            assert_eq!(later.principal, "person");
        }
        assert_eq!(audit.recorded(), [(Succeeded, first.request_id.clone())]);
        // Another token closes the first one's account before its own first
        // success is recorded.
        let second = auth.authenticate_on(&renewed, &connection).await.unwrap();
        auth.authenticate_on(&renewed, &connection).await.unwrap();
        // Refusals are recorded one by one and leave the account alone.
        for _ in 0..2 {
            assert_eq!(
                auth.authenticate_on(&expired, &connection)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Unauthorized
            );
        }
        connection.close().await.unwrap();
        connection.close().await.unwrap();
        let recorded = audit.recorded();
        assert_eq!(
            recorded[..4],
            [
                (Succeeded, first.request_id.clone()),
                (repeated(2), first.request_id.clone()),
                (Succeeded, second.request_id.clone()),
                (Denied, recorded[3].1.clone()),
            ]
        );
        assert_eq!(recorded[4].0, Denied);
        assert_eq!(recorded[5..], [(repeated(1), second.request_id.clone())]);
        let count = audit.events.lock().unwrap()[1].clone();
        assert_eq!(
            (count.principal.as_deref(), count.tenant.as_deref()),
            (Some("person"), Some("tenant-a"))
        );
        // The same token on another connection, and every request without a
        // connection, record their own successes.
        audit.events.lock().unwrap().clear();
        let other = ConnectionAuthentications::default();
        auth.authenticate_on(&token, &other).await.unwrap();
        auth.authenticate(&token).await.unwrap();
        auth.authenticate(&token).await.unwrap();
        assert!(audit.recorded().iter().all(|(kind, _)| *kind == Succeeded));
        assert_eq!(audit.recorded().len(), 3);
        // A connection whose token made one request closes without a count.
        other.close().await.unwrap();
        assert_eq!(audit.recorded().len(), 3);
    }

    #[tokio::test]
    async fn a_connection_records_every_success_again_while_audit_writes_fail() {
        use RequestAuditKind::AuthenticationSucceeded as Succeeded;
        let (auth, audit, key) = connection_fixture().await;
        let token = bearer(&key, &claims(), "at+jwt");
        let connection = ConnectionAuthentications::default();
        // A first success that cannot be recorded is refused and not counted.
        audit.fail(true);
        assert_eq!(
            auth.authenticate_on(&token, &connection)
                .await
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        audit.fail(false);
        let first = auth.authenticate_on(&token, &connection).await.unwrap();
        auth.authenticate_on(&token, &connection).await.unwrap();
        // Any failed write, here a refusal's, stops the counting: the
        // connection's next success must be recorded, so the outage refuses it.
        audit.fail(true);
        assert_eq!(
            auth.authenticate_on("Bearer invalid", &connection)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            auth.authenticate_on(&token, &connection)
                .await
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        // Another token must first record the counted successes; that fails
        // too, and the count is kept.
        assert_eq!(
            auth.authenticate_on(&renewed(&key), &connection)
                .await
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        audit.fail(false);
        // The first success after the outage is recorded and resumes counting.
        let recovered = auth.authenticate_on(&token, &connection).await.unwrap();
        auth.authenticate_on(&token, &connection).await.unwrap();
        connection.close().await.unwrap();
        assert_eq!(
            audit.recorded(),
            [
                (Succeeded, first.request_id.clone()),
                (Succeeded, recovered.request_id),
                (repeated(2), first.request_id),
            ]
        );
        // A count that cannot be recorded at close is lost, not retried.
        let closing = ConnectionAuthentications::default();
        auth.authenticate_on(&token, &closing).await.unwrap();
        auth.authenticate_on(&token, &closing).await.unwrap();
        audit.fail(true);
        assert_eq!(
            closing.close().await.unwrap_err().code,
            ErrorCode::AuditUnavailable
        );
        audit.fail(false);
        closing.close().await.unwrap();
        assert_eq!(audit.recorded().len(), 4);
    }

    #[tokio::test]
    async fn concurrent_first_requests_on_a_connection_record_one_success() {
        use RequestAuditKind::AuthenticationSucceeded as Succeeded;
        let (auth, audit, key) = connection_fixture().await;
        let token = bearer(&key, &claims(), "at+jwt");
        let connection = ConnectionAuthentications::default();
        let (first, second, third) = tokio::join!(
            auth.authenticate_on(&token, &connection),
            auth.authenticate_on(&token, &connection),
            auth.authenticate_on(&token, &connection),
        );
        let ids =
            [first.unwrap(), second.unwrap(), third.unwrap()].map(|context| context.request_id);
        connection.close().await.unwrap();
        let recorded = audit.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].0, Succeeded);
        assert!(ids.contains(&recorded[0].1));
        assert_eq!(recorded[1], (repeated(2), recorded[0].1.clone()));
    }

    #[tokio::test]
    async fn a_connection_counts_only_successes_of_the_authenticator_that_recorded_them() {
        use RequestAuditKind::AuthenticationSucceeded as Succeeded;
        let (auth, audit, key) = connection_fixture().await;
        let other = Authenticator::new(config()).unwrap();
        let other_audit = Arc::new(SwitchedAudit::default());
        other.install_audit(other_audit.clone()).unwrap();
        let keys = auth.cache.read().await.as_ref().unwrap().keys.clone();
        *other.cache.write().await = Some(CachedKeys::new(keys, other.clock.elapsed_clock().now()));
        let token = bearer(&key, &claims(), "at+jwt");
        let connection = ConnectionAuthentications::default();
        let first = auth.authenticate_on(&token, &connection).await.unwrap();
        auth.authenticate_on(&token, &connection).await.unwrap();
        // The same token through another authenticator is recorded in that
        // authenticator's audit, after this one's count.
        let elsewhere = other.authenticate_on(&token, &connection).await.unwrap();
        connection.close().await.unwrap();
        assert_eq!(
            audit.recorded(),
            [
                (Succeeded, first.request_id.clone()),
                (repeated(1), first.request_id),
            ]
        );
        assert_eq!(other_audit.recorded(), [(Succeeded, elsewhere.request_id)]);
    }

    #[tokio::test]
    async fn a_connection_refuses_its_recorded_token_once_it_expires() {
        use RequestAuditKind::{
            AuthenticationDenied as Denied, AuthenticationSucceeded as Succeeded,
        };
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
        let keys = source.cache.read().await.as_ref().unwrap().keys.clone();
        *auth.cache.write().await = Some(CachedKeys::new(keys, Duration::ZERO));
        let audit = Arc::new(SwitchedAudit::default());
        auth.install_audit(audit.clone()).unwrap();
        let token = bearer(&key, &claims, "at+jwt");
        let connection = ConnectionAuthentications::default();
        let first = auth.authenticate_on(&token, &connection).await.unwrap();
        auth.authenticate_on(&token, &connection).await.unwrap();
        // The token's success is recorded on this connection, yet each later
        // request checks its expiry again and is refused, and recorded, alone.
        elapsed.0.store(10_000, Ordering::SeqCst);
        for _ in 0..2 {
            assert_eq!(
                auth.authenticate_on(&token, &connection)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Unauthorized
            );
        }
        connection.close().await.unwrap();
        let recorded = audit.recorded();
        assert_eq!(recorded.len(), 4);
        assert_eq!(recorded[0], (Succeeded, first.request_id.clone()));
        assert_eq!((&recorded[1].0, &recorded[2].0), (&Denied, &Denied));
        assert_eq!(recorded[3], (repeated(1), first.request_id));
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
        *auth.cache.write().await = Some(CachedKeys::new(
            cache.as_ref().unwrap().keys.clone(),
            Duration::ZERO,
        ));
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

    #[tokio::test]
    async fn cached_external_key_verifies_without_waiting_for_a_refresh() {
        let (auth, key) = fixture().await;
        // A JWKS fetch holds this lock for up to its whole HTTP timeout.
        let refreshing = auth.refresh.lock().await;
        let context = tokio::time::timeout(
            Duration::from_secs(5),
            auth.authenticate(&bearer(&key, &claims(), "at+jwt")),
        )
        .await
        .expect("a cached key waited behind a refresh")
        .unwrap();
        assert_eq!(context.principal, "person");
        drop(refreshing);
    }

    #[tokio::test]
    async fn local_signer_is_reloaded_only_for_an_unknown_kid() {
        use kasumi_store::private_files;
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        crate::local_auth::initialize_signer(&signer).unwrap();
        let auth = Authenticator::new(AuthConfig {
            issuer: "https://localhost/local".into(),
            audience: "https://localhost/kasumi".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        })
        .unwrap();
        let kid = |generation: usize| {
            crate::local_auth::trusted_keys(&signer).unwrap().keys[generation]
                .common
                .key_id
                .clone()
                .unwrap()
        };
        let first = kid(0);
        let begun = |auth: &Authenticator| auth.reloads.load(Ordering::Acquire);
        auth.refresh_keys(&first).await.unwrap();
        assert_eq!(begun(&auth), 1);
        // Only the next generation of the same signer could be added later.
        let (signer_id, _) = first.rsplit_once('.').unwrap();
        let next = format!("{signer_id}.2");

        // Kids that no rotation can add are refused without a reload: other
        // text and generations below the cached one of this signer.
        assert_eq!(first, format!("{signer_id}.1"));
        for impossible in [
            "unknown".to_owned(),
            format!("{signer_id}.0"),
            format!("{signer_id}.x"),
        ] {
            assert_eq!(
                auth.refresh_keys(&impossible).await.unwrap_err().code,
                ErrorCode::Unauthorized,
                "{impossible}"
            );
        }
        assert_eq!(begun(&auth), 1);
        // A kid a rotation or a replaced signer file could add is not reread
        // while the signer file is unchanged.
        for possible in [next.clone(), format!("{}.9", uuid::Uuid::new_v4())] {
            assert_eq!(
                auth.refresh_keys(&possible).await.unwrap_err().code,
                ErrorCode::Unauthorized,
                "{possible}"
            );
        }
        assert_eq!(begun(&auth), 1);

        // A known kid neither reads the signer file nor waits on a reload.
        let installed = private_files::read(&signer, 1 << 20).unwrap();
        private_files::replace(&signer, b"unreadable signer").unwrap();
        let reloading = auth.refresh.lock().await;
        tokio::time::timeout(Duration::from_secs(5), auth.refresh_keys(&first))
            .await
            .expect("a cached key waited behind a reload")
            .unwrap();
        drop(reloading);
        assert_eq!(begun(&auth), 1);
        // A replaced file is reloaded for a possible kid; a failed reload
        // keeps the trusted keys and is not retried for the same file.
        assert_eq!(
            auth.refresh_keys(&next).await.unwrap_err().code,
            ErrorCode::Unavailable
        );
        assert_eq!(begun(&auth), 2);
        assert_eq!(
            auth.refresh_keys(&next).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(begun(&auth), 2);
        auth.refresh_keys(&first).await.unwrap();
        private_files::replace(&signer, &installed).unwrap();
        // Verified tokens survive a reload that finds the same keys.
        let verified: Claims = serde_json::from_value(claims()).unwrap();
        auth.cache
            .read()
            .await
            .as_ref()
            .unwrap()
            .remember([7; 32], &verified);

        // Requests that waited behind one reload share it instead of rereading.
        let reloading = auth.refresh.lock().await;
        let waiting = [(); 2].map(|()| {
            let auth = auth.clone();
            let next = next.clone();
            tokio::spawn(async move { auth.refresh_keys(&next).await })
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        drop(reloading);
        let mut outcomes = Vec::new();
        for task in waiting {
            outcomes.push(task.await.unwrap().map_err(|error| error.code));
        }
        assert_eq!(outcomes, [Ok(()), Err(ErrorCode::Unauthorized)]);
        assert_eq!(begun(&auth), 3);
        assert!(
            auth.cache
                .read()
                .await
                .as_ref()
                .unwrap()
                .verified(&[7; 32])
                .is_some()
        );
        assert_eq!(
            auth.refresh_keys(&next).await.unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(begun(&auth), 3);

        // A rotated generation is trusted on its first use.
        crate::local_auth::rotate_signer(&signer).unwrap();
        let second = kid(1);
        assert_eq!(second, next);
        auth.refresh_keys(&second).await.unwrap();
        assert_eq!(begun(&auth), 4);
        assert!(auth.cached(&first).await.unwrap() && auth.cached(&second).await.unwrap());
    }
}
