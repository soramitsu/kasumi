//! Local Ed25519 issuer and encrypted permanent credential-family records.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
use kasumi_clock::EpochClock;
use kasumi_store::{NamespaceEpoch, TenantStore, WriteOp, private_files};
use kasumi_types::{
    Action, CreateCredential, CredentialAudience, CredentialLiveness, CredentialStatus, Error,
    ErrorCode, IssuedCredential, RenewCredential, exact_json::decode_exact,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const FAMILIES: &str = "local-credential-families";
const ISSUANCES: &str = "local-credential-issuances";
const EVENTS: &str = "local-credential-events";
/// Each family's most recent issuance, written with it. Only that issuance's
/// token can recover the family online once it has expired.
const LATEST: &str = "local-credential-latest-issuances";
const MAX_SIGNERS: usize = 1 << 20;
const MAX_RECORD: usize = 16 << 10;

#[derive(Debug)]
struct InvalidFamilyRecord;
impl std::fmt::Display for InvalidFamilyRecord {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("invalid permanent credential family record")
    }
}
impl std::error::Error for InvalidFamilyRecord {}

/// Fixed classes only: never format the storage error, row, family, or key.
fn family_status_error(error: &anyhow::Error, key_lease_class: Option<&'static str>) -> Error {
    if error
        .downcast_ref::<Error>()
        .is_some_and(|error| error.code == ErrorCode::NotFound)
    {
        return Error::new(ErrorCode::Unauthorized, "credential family is missing");
    }
    let (class, code, stage, retirement) = if error.is::<InvalidFamilyRecord>() {
        ("invalid_family_record", ErrorCode::Corruption, None, None)
    } else if let Some(failure) = error.downcast_ref::<kasumi_store::TenantPointReadFailure>() {
        (
            "point_read_failed",
            ErrorCode::Unavailable,
            Some(failure.stage()),
            None,
        )
    } else if let Some(failure) = error.downcast_ref::<kasumi_store::TenantPointReadRetirement>() {
        (
            "point_read_retirement_pending",
            ErrorCode::Unavailable,
            None,
            Some(failure.disposition()),
        )
    } else if error.is::<kasumi_store::KeyAccessDenied>() {
        ("key_access_unavailable", ErrorCode::Unavailable, None, None)
    } else if error.is::<std::io::Error>() {
        ("storage_io_unavailable", ErrorCode::Unavailable, None, None)
    } else {
        ("storage_unavailable", ErrorCode::Unavailable, None, None)
    };
    let io_kind = error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind);
    tracing::warn!(
        failure_class = class,
        read_stage = stage,
        retirement = ?retirement,
        io_error_kind = ?io_kind,
        key_lease_failure_class = key_lease_class,
        "native credential family status unavailable"
    );
    Error::new(
        code,
        format!("credential family status unavailable: {class}"),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signers {
    format: u32,
    id: Uuid,
    active: u64,
    keys: BTreeMap<u64, String>,
}
impl Drop for Signers {
    fn drop(&mut self) {
        for pem in self.keys.values_mut() {
            pem.zeroize();
        }
    }
}
impl Signers {
    fn read(path: &Path) -> Result<Self> {
        // Only the current writer's exact bytes select signing material; an
        // equivalent respelling is refused rather than rewritten by rotation.
        let signers: Self = decode_exact(
            &private_files::read(path, MAX_SIGNERS)?,
            MAX_SIGNERS,
            "local signing installation",
        )?;
        ensure!(
            signers.format == 1
                && !signers.id.is_nil()
                && signers.active > 0
                && signers.keys.contains_key(&signers.active),
            "unsupported or invalid local signing installation"
        );
        for (generation, pem) in &signers.keys {
            ensure!(
                *generation > 0 && *generation <= signers.active,
                "invalid signing generation"
            );
            let key = rcgen::KeyPair::from_pem(pem)?;
            ensure!(
                key.algorithm() == &rcgen::PKCS_ED25519,
                "local signer must use Ed25519"
            );
        }
        Ok(signers)
    }
    fn kid(&self, generation: u64) -> String {
        format!("{}.{}", self.id, generation)
    }
}
pub fn initialize_signer(path: &Path) -> Result<()> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let signers = Signers {
        format: 1,
        id: Uuid::new_v4(),
        active: 1,
        keys: BTreeMap::from([(1, key.serialize_pem())]),
    };
    private_files::create(path, &Zeroizing::new(serde_json::to_vec(&signers)?))
}
pub fn rotate_signer(path: &Path) -> Result<u64> {
    let _lock = private_files::ExclusiveLock::acquire(&path.with_extension("lock"))?;
    let mut signers = Signers::read(path)?;
    signers.active = signers
        .active
        .checked_add(1)
        .context("signing generation exhausted")?;
    signers.keys.insert(
        signers.active,
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?.serialize_pem(),
    );
    let encoded = Zeroizing::new(serde_json::to_vec(&signers)?);
    ensure!(
        encoded.len() <= MAX_SIGNERS,
        "signing storage budget exceeded"
    );
    private_files::replace(path, &encoded)?;
    Ok(signers.active)
}
pub(crate) fn trusted_keys(path: &Path) -> Result<JwkSet> {
    let signers = Signers::read(path)?;
    let keys = signers.keys.iter().map(|(generation,pem)| {
        let key = rcgen::KeyPair::from_pem(pem)?;
        Ok(serde_json::json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","key_ops":["verify"],"kid":signers.kid(*generation),"x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}))
    }).collect::<Result<Vec<_>>>()?;
    Ok(serde_json::from_value(serde_json::json!({"keys":keys}))?)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issuance {
    family_id: Uuid,
    issuance_id: Uuid,
    issued_at: u64,
    expires_at: u64,
    signer: u64,
}
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    tenant: &'a str,
    kasumi_resource: &'a kasumi_types::CredentialResource,
    scope: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: Uuid,
    kasumi_family: Uuid,
    token_use: &'static str,
    /// RFC 8705 confirmation of a certificate-bound family's client certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<Confirmation>,
}
#[derive(Serialize)]
struct Confirmation {
    /// Base64url SHA-256 of the client certificate's DER.
    #[serde(rename = "x5t#S256")]
    x5t_s256: String,
}
#[derive(Serialize)]
struct CredentialEvent<'a> {
    operation: &'static str,
    actor: &'a str,
    family_id: Uuid,
    at_ms: u64,
}
/// The ledger row of an online recovery: which expired issuance renewed the
/// family, into which issuance, and over which client certificate.
#[derive(Serialize)]
struct RecoveryEvent<'a> {
    operation: &'static str,
    actor: &'a str,
    family_id: Uuid,
    at_ms: u64,
    renewal_id: Uuid,
    recovered_issuance_id: Uuid,
    recovered_expires_at_ms: u64,
    client_certificate_sha256: String,
}
/// The issuance a family's latest creation, renewal or recovery wrote.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LatestIssuance {
    issuance_id: Uuid,
    expires_at: u64,
}

/// An expired local access token presented to recover its own family. The
/// authenticator verified its signature, issuer, audience, type, token use
/// and family claims, and that the family is unrevoked with exactly these
/// claims; the issuer checks the rest under its writer lock.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryProof {
    pub(crate) family_id: Uuid,
    /// The token's `jti`: the issuance it was signed for.
    pub(crate) issuance_id: Uuid,
    pub(crate) expires_at_ms: u64,
    /// SHA-256 of the client certificate of the connection presenting it.
    pub(crate) client_certificate: [u8; 32],
}

/// Whether a credential that expires at `expires_at_ms` may recover its family
/// at `now_ms`: only after it has expired, and only within the fixed window.
pub(crate) fn check_recovery_window(expires_at_ms: u64, now_ms: u64) -> kasumi_types::Result<()> {
    if now_ms < expires_at_ms {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "credential has not expired; renew it instead of recovering it",
        ));
    }
    let closes_at_ms = expires_at_ms
        .saturating_add(kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS * 1000);
    if now_ms >= closes_at_ms {
        return Err(Error::new(
            ErrorCode::Unauthorized,
            format!(
                "credential expired more than {} hours ago; its online recovery window has closed",
                kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS / 3600
            ),
        ));
    }
    Ok(())
}

pub struct LocalCredentials {
    store: Arc<TenantStore>,
    signer_file: PathBuf,
    issuer: String,
    /// The audience of native families' tokens.
    audience: String,
    /// The audience of MCP families' tokens, when the installation separates
    /// them (`AuthConfig::mcp_audience`).
    mcp_audience: Option<String>,
    clock: Arc<EpochClock>,
    mutation: Mutex<()>,
    statuses: StatusCache,
}

/// Decoded family statuses for the authorization and liveness checks that
/// every request repeats. A status is tagged with the store's FAMILIES write
/// epoch sampled before its read and is served only while that epoch is still
/// equal and even, so it is exactly the committed row; any write of the
/// namespace by any writer of this store retires it. A hit still requires the
/// store's current key access.
struct StatusCache {
    families: NamespaceEpoch,
    rows: Mutex<HashMap<Uuid, (u64, CredentialStatus)>>,
}
const MAX_CACHED_STATUSES: usize = 1024;
impl StatusCache {
    /// The epoch a store read is tagged with, and the current cached status.
    fn get(&self, family: Uuid) -> (u64, Option<CredentialStatus>) {
        let epoch = self.families.current();
        if !epoch.is_multiple_of(2) {
            return (epoch, None);
        }
        let rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        let status = rows
            .get(&family)
            .filter(|(at, _)| *at == epoch)
            .map(|(_, status)| status.clone());
        (epoch, status)
    }
    /// Retain a status read since `epoch` was sampled, unless a write began.
    fn insert(&self, epoch: u64, family: Uuid, status: &CredentialStatus) {
        if !epoch.is_multiple_of(2) || self.families.current() != epoch {
            return;
        }
        let mut rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        if rows.len() >= MAX_CACHED_STATUSES {
            rows.retain(|_, (at, _)| *at == epoch);
            if rows.len() >= MAX_CACHED_STATUSES {
                rows.clear();
            }
        }
        rows.insert(family, (epoch, status.clone()));
    }
}
impl LocalCredentials {
    #[cfg(test)]
    pub(crate) fn with_test_clock(
        store: Arc<TenantStore>,
        signer_file: PathBuf,
        issuer: String,
        audience: String,
        clock: Arc<EpochClock>,
    ) -> Result<Arc<Self>> {
        let mut credentials = Self::open(store, signer_file, issuer, audience)?;
        Arc::get_mut(&mut credentials)
            .context("new test credential manager was shared")?
            .clock = clock;
        Ok(credentials)
    }

    pub fn open(
        store: Arc<TenantStore>,
        signer_file: PathBuf,
        issuer: String,
        audience: String,
    ) -> Result<Arc<Self>> {
        ensure!(
            store.tenant() == kasumi_engine::SECURITY_TENANT,
            "credential records require separate security storage"
        );
        Signers::read(&signer_file)?;
        let statuses = StatusCache {
            families: store.namespace_epoch(FAMILIES)?,
            rows: Mutex::default(),
        };
        Ok(Arc::new(Self {
            store,
            signer_file,
            issuer,
            audience,
            mcp_audience: None,
            clock: EpochClock::system()?,
            mutation: Mutex::new(()),
            statuses,
        }))
    }

    /// Issue MCP families' tokens for `audience`. Without one, an MCP family
    /// cannot be created or issued.
    pub fn with_mcp_audience(mut self: Arc<Self>, audience: Option<String>) -> Result<Arc<Self>> {
        Arc::get_mut(&mut self)
            .context("new credential manager was shared")?
            .mcp_audience = audience;
        Ok(self)
    }
    pub fn status(&self, family: Uuid) -> Result<CredentialStatus> {
        let (epoch, cached) = self.statuses.get(family);
        if let Some(status) = cached {
            self.store.check_access()?;
            return Ok(status);
        }
        let bytes = self
            .store
            .get_bounded(FAMILIES, family.as_bytes(), MAX_RECORD)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "credential family not found"))?;
        let status = Self::family(&bytes).context(InvalidFamilyRecord)?;
        self.statuses.insert(epoch, family, &status);
        Ok(status)
    }
    fn authorization_status(&self, family: Uuid) -> kasumi_types::Result<CredentialStatus> {
        self.status(family)
            .map_err(|error| family_status_error(&error, self.store.key_lease_failure_class()))
    }
    /// Permanent credential rows are admitted only as the current writer's exact
    /// bytes. An equivalent or default-omitting spelling fails closed.
    fn family(bytes: &[u8]) -> Result<CredentialStatus> {
        decode_exact(bytes, MAX_RECORD, "credential family record")
    }
    fn issuance_key(family: Uuid, issuance: Uuid) -> Vec<u8> {
        [family.as_bytes().as_slice(), issuance.as_bytes().as_slice()].concat()
    }
    fn issuance(bytes: &[u8]) -> Result<Issuance> {
        decode_exact(bytes, MAX_RECORD, "credential issuance record")
    }
    fn token(&self, status: &CredentialStatus, issuance: &Issuance) -> Result<IssuedCredential> {
        ensure!(
            status.revoked_at_ms.is_none(),
            Error::new(ErrorCode::Unauthorized, "credential family revoked")
        );
        let signers = Signers::read(&self.signer_file)?;
        let key = EncodingKey::from_ed_pem(
            signers
                .keys
                .get(&issuance.signer)
                .context("issuance signer unavailable")?
                .as_bytes(),
        )?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(signers.kid(issuance.signer));
        header.typ = Some("at+jwt".into());
        let specification = &status.specification;
        // Audience and binding come from the family, so every creation,
        // renewal, recovery and replay issues them unchanged.
        let audience = match specification.audience {
            CredentialAudience::Native => self.audience.as_str(),
            CredentialAudience::Mcp => self.mcp_audience.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "this installation has no MCP audience for MCP credentials",
                )
            })?,
        };
        let claims = Claims {
            iss: &self.issuer,
            aud: audience,
            sub: &specification.principal,
            tenant: &specification.tenant,
            kasumi_resource: &specification.resource,
            scope: scopes(&specification.scopes),
            exp: issuance.expires_at,
            nbf: issuance.issued_at,
            iat: issuance.issued_at,
            jti: issuance.issuance_id,
            kasumi_family: specification.family_id,
            token_use: "access",
            cnf: specification.certificate_binding().map(|pin| Confirmation {
                x5t_s256: URL_SAFE_NO_PAD.encode(pin),
            }),
        };
        Ok(IssuedCredential {
            family_id: specification.family_id,
            token: encode(&header, &claims, &key)?,
            expires_at_ms: issuance
                .expires_at
                .checked_mul(1000)
                .context("credential time overflow")?,
        })
    }
    /// The native adapter requires current Control administrator authority. The
    /// initializer calls this only while holding exclusive installation ownership.
    pub fn create(&self, specification: CreateCredential, actor: &str) -> Result<IssuedCredential> {
        specification.validate()?;
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("credential writer poisoned"))?;
        if let Some(bytes) =
            self.store
                .get_bounded(FAMILIES, specification.family_id.as_bytes(), MAX_RECORD)?
        {
            let status = Self::family(&bytes)?;
            ensure!(
                status.specification == specification,
                Error::new(
                    ErrorCode::Conflict,
                    "credential identity conflicts with original specification"
                )
            );
            let issuance = self
                .store
                .get_bounded(
                    ISSUANCES,
                    &Self::issuance_key(specification.family_id, specification.family_id),
                    MAX_RECORD,
                )?
                .context("credential issuance missing")?;
            return self.token(&status, &Self::issuance(&issuance)?);
        }
        let now = self.clock.now_ms()?;
        let issued_at = now / 1000;
        let issuance = Issuance {
            family_id: specification.family_id,
            issuance_id: specification.family_id,
            issued_at,
            expires_at: issued_at
                .checked_add(specification.lifetime_seconds)
                .context("credential time overflow")?,
            signer: Signers::read(&self.signer_file)?.active,
        };
        let status = CredentialStatus {
            specification,
            created_at_ms: now,
            revoked_at_ms: None,
        };
        let token = self.token(&status, &issuance)?;
        let event = CredentialEvent {
            operation: "create",
            actor,
            family_id: status.specification.family_id,
            at_ms: now,
        };
        self.store.write_batch(&[
            WriteOp::put(
                FAMILIES,
                status.specification.family_id.as_bytes(),
                encoded(&status)?,
            ),
            WriteOp::put(
                ISSUANCES,
                Self::issuance_key(issuance.family_id, issuance.issuance_id),
                encoded(&issuance)?,
            ),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
            Self::latest(&issuance)?,
        ])?;
        Ok(token)
    }
    /// Record `issuance` as its family's latest, in the batch that writes it.
    fn latest(issuance: &Issuance) -> Result<WriteOp> {
        Ok(WriteOp::put(
            LATEST,
            issuance.family_id.as_bytes(),
            encoded(&LatestIssuance {
                issuance_id: issuance.issuance_id,
                expires_at: issuance.expires_at,
            })?,
        ))
    }
    /// The family's next issuance, signed by the active key from `now_ms`.
    fn next_issuance(
        &self,
        status: &CredentialStatus,
        issuance_id: Uuid,
        now_ms: u64,
    ) -> Result<Issuance> {
        let issued_at = now_ms / 1000;
        Ok(Issuance {
            family_id: status.specification.family_id,
            issuance_id,
            issued_at,
            expires_at: issued_at
                .checked_add(status.specification.lifetime_seconds)
                .context("credential time overflow")?,
            signer: Signers::read(&self.signer_file)?.active,
        })
    }
    pub fn renew(&self, request: &RenewCredential, actor: &str) -> Result<IssuedCredential> {
        ensure!(
            !request.renewal_id.is_nil() && request.renewal_id != request.family_id,
            Error::new(
                ErrorCode::InvalidArgument,
                "renewal requires a distinct identity"
            )
        );
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("credential writer poisoned"))?;
        let status = self.status(request.family_id)?;
        ensure!(
            status.revoked_at_ms.is_none(),
            Error::new(ErrorCode::Unauthorized, "credential family revoked")
        );
        let key = Self::issuance_key(request.family_id, request.renewal_id);
        if let Some(bytes) = self.store.get_bounded(ISSUANCES, &key, MAX_RECORD)? {
            // A retained renewal is replayed only from its exact original row;
            // an alternate spelling is refused and never replaced by a new issuance.
            return self.token(&status, &Self::issuance(&bytes)?);
        }
        let now = self.clock.now_ms()?;
        let issuance = self.next_issuance(&status, request.renewal_id, now)?;
        let token = self.token(&status, &issuance)?;
        let event = CredentialEvent {
            operation: "renew",
            actor,
            family_id: request.family_id,
            at_ms: now,
        };
        self.store.write_batch(&[
            WriteOp::put(ISSUANCES, key, encoded(&issuance)?),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
            Self::latest(&issuance)?,
        ])?;
        Ok(token)
    }
    /// Renew a family from its expired credential through the native
    /// recovery method (docs/credential-lifetime.md). Under the writer lock
    /// the family must be unrevoked and the credential expired within the
    /// fixed window. A request naming an issuance that already exists replays
    /// it exactly, as renewal does after a lost reply. Otherwise only the
    /// family's latest issuance can recover it: a superseded credential, or a
    /// family whose latest issuance this build never recorded, is refused.
    pub(crate) fn recover(
        &self,
        proof: &RecoveryProof,
        request: &RenewCredential,
        actor: &str,
    ) -> Result<IssuedCredential> {
        ensure!(
            !request.renewal_id.is_nil() && request.renewal_id != request.family_id,
            Error::new(
                ErrorCode::InvalidArgument,
                "renewal requires a distinct identity"
            )
        );
        ensure!(
            request.family_id == proof.family_id,
            Error::new(
                ErrorCode::Forbidden,
                "recovery requires the expired credential's own family"
            )
        );
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("credential writer poisoned"))?;
        let status = self.status(request.family_id)?;
        ensure!(
            status.revoked_at_ms.is_none(),
            Error::new(ErrorCode::Unauthorized, "credential family revoked")
        );
        let now = self.clock.now_ms()?;
        check_recovery_window(proof.expires_at_ms, now)?;
        let key = Self::issuance_key(request.family_id, request.renewal_id);
        if let Some(bytes) = self.store.get_bounded(ISSUANCES, &key, MAX_RECORD)? {
            return self.token(&status, &Self::issuance(&bytes)?);
        }
        let latest = self
            .store
            .get_bounded(LATEST, request.family_id.as_bytes(), MAX_RECORD)?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unauthorized,
                    "credential family has no recorded latest issuance; recover it with the stopped installation",
                )
            })?;
        let latest: LatestIssuance =
            decode_exact(&latest, MAX_RECORD, "latest credential issuance record")?;
        ensure!(
            latest.issuance_id == proof.issuance_id
                && latest.expires_at.checked_mul(1000) == Some(proof.expires_at_ms),
            Error::new(
                ErrorCode::Unauthorized,
                "credential was superseded by a later issuance of its family; only the latest can recover it"
            )
        );
        let issuance = self.next_issuance(&status, request.renewal_id, now)?;
        let token = self.token(&status, &issuance)?;
        let event = RecoveryEvent {
            operation: "recover",
            actor,
            family_id: request.family_id,
            at_ms: now,
            renewal_id: request.renewal_id,
            recovered_issuance_id: proof.issuance_id,
            recovered_expires_at_ms: proof.expires_at_ms,
            client_certificate_sha256: hex::encode(proof.client_certificate),
        };
        self.store.write_batch(&[
            WriteOp::put(ISSUANCES, key, encoded(&issuance)?),
            WriteOp::put(EVENTS, Uuid::new_v4().as_bytes(), encoded(&event)?),
            Self::latest(&issuance)?,
        ])?;
        Ok(token)
    }
    pub fn revoke(&self, family: Uuid, actor: &str) -> Result<CredentialStatus> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("credential writer poisoned"))?;
        let mut status = self.status(family)?;
        if status.revoked_at_ms.is_some() {
            return Ok(status);
        }
        let now = self.clock.now_ms()?;
        status.revoked_at_ms = Some(now);
        let event = CredentialEvent {
            operation: "revoke",
            actor,
            family_id: family,
            at_ms: now,
        };
        self.store.write_batch(&[
            WriteOp::put(FAMILIES, family.as_bytes(), encoded(&status)?),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
        ])?;
        Ok(status)
    }
    /// The family's liveness, if its record has exactly these signed claims:
    /// `binding` is the token's confirmed client certificate and `audience`
    /// the listener audience that verified it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn guard(
        self: &Arc<Self>,
        family: Uuid,
        principal: &str,
        tenant: &str,
        scope: &str,
        resource: &kasumi_types::CredentialResource,
        binding: Option<[u8; 32]>,
        audience: CredentialAudience,
    ) -> kasumi_types::Result<Arc<dyn CredentialLiveness>> {
        let status = self.authorization_status(family)?;
        let specification = &status.specification;
        if !(status.revoked_at_ms.is_none()
            && specification.principal == principal
            && specification.tenant == tenant
            && &specification.resource == resource
            && scopes(&specification.scopes) == scope
            && specification.certificate_binding() == binding
            && specification.audience == audience)
        {
            return Err(Error::new(
                ErrorCode::Unauthorized,
                "credential family claims mismatch or revoked",
            ));
        }
        Ok(Arc::new(FamilyGuard {
            credentials: self.clone(),
            family,
        }))
    }
}
struct FamilyGuard {
    credentials: Arc<LocalCredentials>,
    family: Uuid,
}
impl CredentialLiveness for FamilyGuard {
    fn check(&self) -> kasumi_types::Result<()> {
        match self.credentials.authorization_status(self.family)? {
            status if status.revoked_at_ms.is_none() => Ok(()),
            _ => Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unauthorized,
                "credential family revoked",
            )),
        }
    }
    fn family_id(&self) -> Option<Uuid> {
        Some(self.family)
    }
}
/// Never commit a credential row that its exact reader would refuse.
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_RECORD,
        "credential record exceeds its work limit"
    );
    Ok(bytes)
}
fn scopes(scopes: &std::collections::BTreeSet<Action>) -> String {
    scopes
        .iter()
        .map(|scope| match scope {
            Action::Read => "kasumi:read",
            Action::Write => "kasumi:write",
            Action::Admin => "kasumi:admin",
            Action::Audit => "kasumi:audit",
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthConfig, AuthKeySource, Authenticator, RequestAuditEvent, RequestAuditSink,
    };
    use kasumi_store::{FileKeyProvider, StorageAccess};
    use std::collections::BTreeSet;
    struct Audit;
    #[async_trait::async_trait]
    impl RequestAuditSink for Audit {
        async fn record(&self, _: RequestAuditEvent) -> kasumi_types::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn family_status_taxonomy_never_exposes_underlying_record_or_provider_errors() {
        let private = "secret-provider-or-record-content";
        let unavailable = family_status_error(&anyhow::anyhow!(private), Some("provider_timeout"));
        assert_eq!(unavailable.code, ErrorCode::Unavailable);
        assert!(!unavailable.message.contains(private));
        let io_failure =
            anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::WouldBlock, private));
        let classified_io = family_status_error(&io_failure, None);
        assert_eq!(classified_io.code, ErrorCode::Unavailable);
        assert_eq!(
            classified_io.message,
            "credential family status unavailable: storage_io_unavailable"
        );
        assert!(!classified_io.message.contains(private));
        let invalid = anyhow::anyhow!(private).context(InvalidFamilyRecord);
        let corrupt = family_status_error(&invalid, None);
        assert_eq!(corrupt.code, ErrorCode::Corruption);
        assert!(!corrupt.message.contains(private));
        let missing = anyhow::Error::new(Error::new(ErrorCode::NotFound, private));
        assert_eq!(
            family_status_error(&missing, None).code,
            ErrorCode::Unauthorized
        );
    }
    #[tokio::test]
    async fn local_issuer_renewal_preserves_deadlines_and_revocation_fences_existing_requests() {
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let physical =
            crate::runtime_storage_fixtures::physical(root.path(), Default::default()).unwrap();
        let node = physical
            .create_new(
                root.path().join("persistent/database"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys,
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let config = AuthConfig {
            issuer: "https://localhost/local".into(),
            audience: "https://localhost/kasumi".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
            mcp_audience: None,
            require_certificate_binding: false,
        };
        let manager = LocalCredentials::open(
            store.clone(),
            signer.clone(),
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap();
        let auth = Authenticator::new(config.clone()).unwrap();
        auth.install_audit(Arc::new(Audit)).unwrap();
        auth.install_local_credentials(manager.clone()).unwrap();
        let specification = CreateCredential {
            family_id: Uuid::new_v4(),
            principal: "administrator".into(),
            tenant: "tenant-a".into(),
            resource: kasumi_types::CredentialResource::Database {
                incarnation: Uuid::new_v4(),
            },
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            lifetime_seconds: 3600,
            client_certificate_sha256: None,
            audience: Default::default(),
        };
        let issued = manager
            .create(specification.clone(), "initializer")
            .unwrap();
        assert_eq!(
            manager
                .create(specification.clone(), "initializer")
                .unwrap()
                .token,
            issued.token
        );
        let context = auth
            .authenticate(&format!("Bearer {}", issued.token))
            .await
            .unwrap();
        let payload = issued.token.split('.').nth(1).unwrap();
        let mut without_use: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        without_use.as_object_mut().unwrap().remove("token_use");
        let signers = Signers::read(&signer).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(signers.kid(signers.active));
        header.typ = Some("at+jwt".into());
        let without_use = encode(
            &header,
            &without_use,
            &EncodingKey::from_ed_pem(signers.keys.get(&signers.active).unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
        drop(signers);
        assert_eq!(
            auth.authenticate(&format!("Bearer {without_use}"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        let captured_deadline = context.authorization.expires_at_ms();
        assert_eq!(
            context.authorization.credential_family(),
            Some(specification.family_id)
        );
        rotate_signer(&signer).unwrap();
        let renewal = RenewCredential {
            family_id: issued.family_id,
            renewal_id: Uuid::new_v4(),
        };
        let renewed = manager.renew(&renewal, "administrator").unwrap();
        assert_eq!(
            manager.renew(&renewal, "administrator").unwrap().token,
            renewed.token
        );
        let new_context = auth
            .authenticate(&format!("Bearer {}", renewed.token))
            .await
            .unwrap();
        context.authorization.check_live().unwrap();
        assert_eq!(context.authorization.expires_at_ms(), captured_deadline);
        // A real sealed credential store is an availability failure at BOTH
        // initial authentication and an already issued live invocation. It
        // cannot masquerade as revoked credentials or authorize a request.
        store.seal();
        assert_eq!(
            context.authorization.check_live().unwrap_err().code,
            ErrorCode::Unavailable
        );
        assert_eq!(
            auth.authenticate(&format!("Bearer {}", renewed.token))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unavailable
        );
        // Explicit native key-lease recovery restores only storage access;
        // the original credential deadline and subsequent revocation remain.
        store.refresh_lease().await.unwrap();
        context.authorization.check_live().unwrap();
        assert_eq!(context.authorization.expires_at_ms(), captured_deadline);
        assert!(
            !context
                .authorization
                .same_live_invocation(&new_context.authorization)
        );
        assert!(
            auth.protected_resource_metadata("https://localhost/mcp")
                .is_none()
        );
        let revoked = manager.revoke(issued.family_id, "administrator").unwrap();
        assert!(revoked.revoked_at_ms.is_some());
        assert_eq!(
            context.authorization.check_live().unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            new_context.authorization.check_live().unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            auth.authenticate(&format!("Bearer {}", renewed.token))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert!(
            manager
                .renew(
                    &RenewCredential {
                        family_id: issued.family_id,
                        renewal_id: Uuid::new_v4()
                    },
                    "administrator"
                )
                .is_err()
        );
        let reopened =
            LocalCredentials::open(store, signer, config.issuer, config.audience).unwrap();
        assert_eq!(reopened.status(issued.family_id).unwrap(), revoked);
        assert!(reopened.create(specification, "initializer").is_err());
        node.shutdown().await.unwrap();
    }

    #[derive(Default)]
    struct RecordingAudit(std::sync::Mutex<Vec<crate::auth::RequestAuditKind>>);
    #[async_trait::async_trait]
    impl RequestAuditSink for RecordingAudit {
        async fn record(&self, event: RequestAuditEvent) -> kasumi_types::Result<()> {
            self.0.lock().unwrap().push(event.kind);
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_connection_refuses_its_recorded_token_once_revoked() {
        use crate::auth::RequestAuditKind::{
            AuthenticationDenied as Denied, AuthenticationRepeated as Repeated,
            AuthenticationSucceeded as Succeeded,
        };
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let physical =
            crate::runtime_storage_fixtures::physical(root.path(), Default::default()).unwrap();
        let node = physical
            .create_new(
                root.path().join("persistent/database"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys,
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let config = AuthConfig {
            issuer: "https://localhost/local".into(),
            audience: "https://localhost/kasumi".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
            mcp_audience: None,
            require_certificate_binding: false,
        };
        let manager = LocalCredentials::open(
            store,
            signer,
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap();
        let auth = Authenticator::new(config).unwrap();
        let audit = Arc::new(RecordingAudit::default());
        auth.install_audit(audit.clone()).unwrap();
        auth.install_local_credentials(manager.clone()).unwrap();
        let issued = manager
            .create(
                CreateCredential {
                    family_id: Uuid::new_v4(),
                    principal: "reader".into(),
                    tenant: "tenant-a".into(),
                    resource: kasumi_types::CredentialResource::Database {
                        incarnation: Uuid::new_v4(),
                    },
                    scopes: BTreeSet::from([Action::Read]),
                    lifetime_seconds: 3600,
                    client_certificate_sha256: None,
                    audience: Default::default(),
                },
                "initializer",
            )
            .unwrap();
        let bearer = format!("Bearer {}", issued.token);
        let connection = crate::auth::ConnectionAuthentications::default();
        auth.authenticate_on(&bearer, &connection, None)
            .await
            .unwrap();
        auth.authenticate_on(&bearer, &connection, None)
            .await
            .unwrap();
        // Revocation reaches the next request on the same connection: its
        // token is checked again, refused, and the refusal recorded alone.
        manager.revoke(issued.family_id, "administrator").unwrap();
        for _ in 0..2 {
            assert_eq!(
                auth.authenticate_on(&bearer, &connection, None)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Unauthorized
            );
        }
        connection.close().await.unwrap();
        assert_eq!(
            *audit.0.lock().unwrap(),
            [Succeeded, Denied, Denied, Repeated { requests: 1 }]
        );
        node.shutdown().await.unwrap();
    }

    struct ManualWall(std::sync::atomic::AtomicU64);
    impl kasumi_clock::WallClock for ManualWall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct RecordingEvents(std::sync::Mutex<Vec<RequestAuditEvent>>);
    #[async_trait::async_trait]
    impl RequestAuditSink for RecordingEvents {
        async fn record(&self, event: RequestAuditEvent) -> kasumi_types::Result<()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[test]
    fn the_recovery_window_opens_at_expiry_and_closes_exactly_24_hours_later() {
        let expiry = 1_800_000_000_000;
        let window = kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS * 1000;
        assert_eq!(window, 86_400_000);
        assert_eq!(
            check_recovery_window(expiry, expiry - 1).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        check_recovery_window(expiry, expiry).unwrap();
        check_recovery_window(expiry, expiry + window - 1).unwrap();
        let closed = check_recovery_window(expiry, expiry + window).unwrap_err();
        assert_eq!(closed.code, ErrorCode::Unauthorized);
        assert!(closed.message.contains("24 hours"), "{}", closed.message);
    }

    /// The refusal of a recovery that must not issue a credential, which
    /// is never formatted.
    fn refusal(result: anyhow::Result<IssuedCredential>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("recovery issued a credential it must refuse"),
            Err(error) => error,
        }
    }

    /// Online recovery renews only an unrevoked family's latest credential,
    /// after it expired and within the window, replays a lost reply exactly,
    /// and every refusal of a verified credential is recorded with its
    /// identity while unverifiable ones identify nobody.
    #[tokio::test]
    async fn only_the_latest_expired_credential_recovers_within_its_window() {
        use crate::auth::RequestAuditKind::{
            AuthenticationDenied, AuthenticationSucceeded, CredentialRecovery,
        };
        use kasumi_types::SecurityOutcome;
        use std::sync::atomic::Ordering::SeqCst;
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let physical =
            crate::runtime_storage_fixtures::physical(root.path(), Default::default()).unwrap();
        let node = physical
            .create_new(
                root.path().join("persistent/database"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys,
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let config = AuthConfig {
            issuer: "https://localhost/local".into(),
            audience: "https://localhost/kasumi".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
            mcp_audience: None,
            require_certificate_binding: false,
        };
        let start = EpochClock::system().unwrap().now_ms().unwrap();
        let wall = Arc::new(ManualWall(std::sync::atomic::AtomicU64::new(start)));
        let clock = Arc::new(
            EpochClock::new(Arc::new(kasumi_clock::SystemLeaseClock), wall.clone()).unwrap(),
        );
        let manager = LocalCredentials::with_test_clock(
            store.clone(),
            signer,
            config.issuer.clone(),
            config.audience.clone(),
            clock.clone(),
        )
        .unwrap();
        let auth = Authenticator::with_test_clock(config, clock).unwrap();
        let audit = Arc::new(RecordingEvents::default());
        auth.install_audit(audit.clone()).unwrap();
        auth.install_local_credentials(manager.clone()).unwrap();
        let specification = |principal: &str| CreateCredential {
            family_id: Uuid::new_v4(),
            principal: principal.into(),
            tenant: "tenant-a".into(),
            resource: kasumi_types::CredentialResource::Database {
                incarnation: Uuid::new_v4(),
            },
            scopes: BTreeSet::from([Action::Read, Action::Write]),
            lifetime_seconds: 3600,
            client_certificate_sha256: None,
            audience: Default::default(),
        };
        let bearer = |token: &str| format!("Bearer {token}");
        let pin = Some([7u8; 32]);
        let renewal = |family_id| RenewCredential {
            family_id,
            renewal_id: Uuid::new_v4(),
        };
        let created = manager
            .create(specification("writer"), "initializer")
            .unwrap();
        let family = created.family_id;
        // A live credential renews instead; without a client certificate
        // nothing is verified at all.
        assert_eq!(
            auth.verify_recovery(&bearer(&created.token), pin)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            auth.verify_recovery(&bearer(&created.token), None)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        // Renewal halfway through supersedes the created credential.
        wall.0.store(start + 1_800_000, SeqCst);
        let renewed = manager.renew(&renewal(family), "writer").unwrap();
        // Both have expired an hour later. The created one still verifies as
        // an expired credential of the family, but cannot recover it.
        wall.0.store(renewed.expires_at_ms + 3_600_000, SeqCst);
        let superseded = auth
            .verify_recovery(&bearer(&created.token), pin)
            .await
            .unwrap();
        let recovery = renewal(family);
        let refused = refusal(manager.recover(&superseded.proof, &recovery, "writer"));
        assert_eq!(
            refused.downcast_ref::<Error>().unwrap().code,
            ErrorCode::Unauthorized
        );
        assert!(refused.to_string().contains("superseded"), "{refused}");
        let latest = auth
            .verify_recovery(&bearer(&renewed.token), pin)
            .await
            .unwrap();
        assert_eq!(latest.context.principal, "writer");
        assert_eq!(latest.context.tenant, "tenant-a");
        assert_eq!(
            latest.context.scopes,
            BTreeSet::from([Action::Read, Action::Write])
        );
        assert_eq!(latest.proof.family_id, family);
        assert_eq!(latest.proof.expires_at_ms, renewed.expires_at_ms);
        latest.context.authorization.check_live().unwrap();
        assert_eq!(
            latest.context.authorization.credential_family(),
            Some(family)
        );
        let recovered = manager.recover(&latest.proof, &recovery, "writer").unwrap();
        assert_eq!(recovered.family_id, family);
        // A full lifetime from the recovery, not from the expired credential.
        let recovered_from = wall.0.load(SeqCst);
        assert!(
            (recovered_from + 3_599_000..recovered_from + 3_660_000)
                .contains(&recovered.expires_at_ms)
        );
        let context = auth.authenticate(&bearer(&recovered.token)).await.unwrap();
        assert_eq!(context.authorization.credential_family(), Some(family));
        // A lost reply replays exactly; any other recovery from the same
        // expired credential is refused, as the recovery superseded it.
        assert_eq!(
            manager
                .recover(&latest.proof, &recovery, "writer")
                .unwrap()
                .token,
            recovered.token
        );
        assert!(
            refusal(manager.recover(&latest.proof, &renewal(family), "writer"))
                .to_string()
                .contains("superseded")
        );
        // A proof is valid only for its own family and a distinct identity.
        let other = manager
            .create(specification("other"), "initializer")
            .unwrap();
        for request in [
            renewal(other.family_id),
            RenewCredential {
                family_id: family,
                renewal_id: family,
            },
            RenewCredential {
                family_id: family,
                renewal_id: Uuid::nil(),
            },
        ] {
            assert!(manager.recover(&latest.proof, &request, "writer").is_err());
        }
        // A family whose latest issuance no build recorded cannot recover:
        // the latest credential is unknown.
        let unrecorded = manager
            .create(specification("unrecorded"), "initializer")
            .unwrap();
        store
            .write_batch(&[WriteOp::delete(LATEST, unrecorded.family_id.as_bytes())])
            .unwrap();
        // Revocation refuses at verification, and under the writer lock for
        // a credential verified before the revocation.
        let revoked = manager
            .create(specification("revoked"), "initializer")
            .unwrap();
        let raced = manager
            .create(specification("raced"), "initializer")
            .unwrap();
        let all_expired = [&recovered, &unrecorded, &revoked, &raced]
            .iter()
            .map(|credential| credential.expires_at_ms)
            .max()
            .unwrap();
        wall.0.store(all_expired + 1, SeqCst);
        let unrecorded_proof = auth
            .verify_recovery(&bearer(&unrecorded.token), pin)
            .await
            .unwrap();
        assert!(
            refusal(manager.recover(
                &unrecorded_proof.proof,
                &renewal(unrecorded.family_id),
                "unrecorded"
            ))
            .to_string()
            .contains("no recorded latest issuance")
        );
        let raced_proof = auth
            .verify_recovery(&bearer(&raced.token), pin)
            .await
            .unwrap();
        manager.revoke(revoked.family_id, "administrator").unwrap();
        manager.revoke(raced.family_id, "administrator").unwrap();
        assert_eq!(
            auth.verify_recovery(&bearer(&revoked.token), pin)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert!(
            refusal(manager.recover(&raced_proof.proof, &renewal(raced.family_id), "raced"))
                .to_string()
                .contains("revoked")
        );
        assert_eq!(
            raced_proof
                .context
                .authorization
                .check_live()
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        // The window closes 24 hours after expiry, for good.
        wall.0.store(
            recovered.expires_at_ms
                + kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS * 1000,
            SeqCst,
        );
        let closed = auth
            .verify_recovery(&bearer(&recovered.token), pin)
            .await
            .unwrap_err();
        assert_eq!(closed.code, ErrorCode::Unauthorized);
        assert!(
            closed.message.contains("window has closed"),
            "{}",
            closed.message
        );
        // A token this issuer never signed is refused as any bearer is.
        let (signed, _) = recovered.token.rsplit_once('.').unwrap();
        let (_, signature) = created.token.rsplit_once('.').unwrap();
        let forged = format!("{signed}.{signature}");
        assert_eq!(
            auth.verify_recovery(&bearer(&forged), pin)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        let events = audit
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|event| (event.kind.clone(), event.principal.clone()))
            .collect::<Vec<_>>();
        let denied = CredentialRecovery {
            outcome: SecurityOutcome::Denied,
        };
        assert_eq!(
            events,
            [
                (denied.clone(), Some("writer".to_owned())),
                (AuthenticationDenied, None),
                (AuthenticationSucceeded, Some("writer".to_owned())),
                (denied.clone(), Some("revoked".to_owned())),
                (denied, Some("writer".to_owned())),
                (AuthenticationDenied, None),
            ]
        );
        node.shutdown().await.unwrap();
    }

    /// Equivalent spellings the current writer never produces. Serde alone
    /// admits each of them as the original value.
    fn respelled(current: &[u8]) -> [Vec<u8>; 2] {
        let spaced = std::str::from_utf8(current)
            .unwrap()
            .replacen(':', ": ", 1)
            .into_bytes();
        let reordered =
            serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(current).unwrap())
                .unwrap();
        assert_ne!(reordered, current);
        [spaced, reordered]
    }

    type Rows = Vec<(Vec<u8>, Vec<u8>)>;
    fn rows(store: &TenantStore) -> [Rows; 3] {
        [FAMILIES, ISSUANCES, EVENTS].map(|namespace| {
            let mut rows = Vec::new();
            store
                .visit(namespace, MAX_RECORD, |key, value| {
                    rows.push((key.to_vec(), value.to_vec()));
                    Ok(())
                })
                .unwrap();
            rows
        })
    }

    fn refused(error: anyhow::Error, name: &str) {
        assert!(
            format!("{error:#}").contains(&format!("noncanonical {name}")),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn noncanonical_credential_rows_and_signers_fail_closed_across_restart() {
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let physical =
            crate::runtime_storage_fixtures::physical(root.path(), Default::default()).unwrap();
        let database = root.path().join("persistent/database");
        let node = physical
            .create_new(&database, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys.clone(),
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let open = |store: &Arc<TenantStore>| {
            LocalCredentials::open(
                store.clone(),
                signer.clone(),
                "https://localhost/local".into(),
                "https://localhost/kasumi".into(),
            )
        };
        let manager = open(&store).unwrap();
        let specification = CreateCredential {
            family_id: Uuid::new_v4(),
            principal: "administrator".into(),
            tenant: "tenant-a".into(),
            resource: kasumi_types::CredentialResource::Database {
                incarnation: Uuid::new_v4(),
            },
            scopes: BTreeSet::from([Action::Read, Action::Admin]),
            lifetime_seconds: 3600,
            client_certificate_sha256: None,
            audience: Default::default(),
        };
        let family = specification.family_id;
        let issued = manager
            .create(specification.clone(), "initializer")
            .unwrap();
        let renewal = RenewCredential {
            family_id: family,
            renewal_id: Uuid::new_v4(),
        };
        let renewed = manager.renew(&renewal, "administrator").unwrap();
        let fresh = || RenewCredential {
            family_id: family,
            renewal_id: Uuid::new_v4(),
        };

        // A retained Issuance row replays only from its exact original bytes. An
        // alternate row is refused and never replaced by another issuance.
        for (key, retry) in [
            (LocalCredentials::issuance_key(family, family), None),
            (
                LocalCredentials::issuance_key(family, renewal.renewal_id),
                Some(&renewal),
            ),
        ] {
            let current = store.get(ISSUANCES, &key).unwrap().unwrap();
            for alternate in respelled(&current) {
                let admitted: Issuance = serde_json::from_slice(&alternate).unwrap();
                assert_eq!(serde_json::to_vec(&admitted).unwrap(), current);
                store
                    .write_batch(&[WriteOp::put(ISSUANCES, key.clone(), alternate.clone())])
                    .unwrap();
                let before = rows(&store);
                let error = match retry {
                    Some(renewal) => manager.renew(renewal, "administrator").err().unwrap(),
                    None => manager
                        .create(specification.clone(), "initializer")
                        .err()
                        .unwrap(),
                };
                refused(error, "credential issuance record");
                assert_eq!(rows(&store), before);
                assert_eq!(store.get(ISSUANCES, &key).unwrap().unwrap(), alternate);
            }
            store
                .write_batch(&[WriteOp::put(ISSUANCES, key, current.as_bytes())])
                .unwrap();
        }
        assert_eq!(
            manager.renew(&renewal, "administrator").unwrap().token,
            renewed.token
        );
        assert_eq!(
            manager
                .create(specification.clone(), "initializer")
                .unwrap()
                .token,
            issued.token
        );

        // Serde's default would silently restore the omitted lifetime. The row
        // fails every reader closed, including across a node restart.
        let current = store.get(FAMILIES, family.as_bytes()).unwrap().unwrap();
        let text = std::str::from_utf8(&current).unwrap();
        let omitted = text
            .replacen(",\"lifetime_seconds\":3600", "", 1)
            .into_bytes();
        assert_ne!(omitted, current);
        let status = manager.status(family).unwrap();
        assert_eq!(
            serde_json::from_slice::<CredentialStatus>(&omitted).unwrap(),
            status
        );
        let resource = status.specification.resource.clone();
        let mut alternates = respelled(&current).to_vec();
        alternates.push(omitted.clone());
        for alternate in alternates {
            store
                .write_batch(&[WriteOp::put(FAMILIES, family.as_bytes(), alternate)])
                .unwrap();
            let before = rows(&store);
            refused(
                manager.status(family).unwrap_err(),
                "credential family record",
            );
            refused(
                manager.renew(&fresh(), "administrator").err().unwrap(),
                "credential family record",
            );
            refused(
                manager
                    .create(specification.clone(), "initializer")
                    .err()
                    .unwrap(),
                "credential family record",
            );
            refused(
                manager.revoke(family, "administrator").unwrap_err(),
                "credential family record",
            );
            assert!(
                manager
                    .guard(
                        family,
                        "administrator",
                        "tenant-a",
                        "kasumi:read kasumi:admin",
                        &resource,
                        None,
                        CredentialAudience::Native,
                    )
                    .is_err()
            );
            assert_eq!(rows(&store), before);
        }
        drop(manager);
        store.shutdown().await.unwrap();
        drop(store);
        node.shutdown().await.unwrap();
        drop(node);
        let node = physical
            .open_existing(&database, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let store = TenantStore::open_existing(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys.clone(),
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let manager = open(&store).unwrap();
        let before = rows(&store);
        refused(
            manager.status(family).unwrap_err(),
            "credential family record",
        );
        refused(
            manager.renew(&fresh(), "administrator").err().unwrap(),
            "credential family record",
        );
        assert_eq!(rows(&store), before);
        assert_eq!(
            store.get(FAMILIES, family.as_bytes()).unwrap().unwrap(),
            omitted
        );
        store
            .write_batch(&[WriteOp::put(
                FAMILIES,
                family.as_bytes(),
                current.as_bytes(),
            )])
            .unwrap();
        assert_eq!(manager.status(family).unwrap(), status);
        assert_eq!(
            manager.renew(&renewal, "administrator").unwrap().token,
            renewed.token
        );

        // An alternate signing installation neither starts the issuer, signs a
        // renewal, publishes verification keys, nor is rewritten by rotation.
        let current = private_files::read(&signer, MAX_SIGNERS).unwrap();
        for alternate in respelled(&current) {
            private_files::replace(&signer, &alternate).unwrap();
            let before = rows(&store);
            refused(open(&store).err().unwrap(), "local signing installation");
            refused(
                manager.renew(&fresh(), "administrator").err().unwrap(),
                "local signing installation",
            );
            refused(
                trusted_keys(&signer).unwrap_err(),
                "local signing installation",
            );
            refused(
                rotate_signer(&signer).unwrap_err(),
                "local signing installation",
            );
            assert_eq!(rows(&store), before);
            assert_eq!(
                private_files::read(&signer, MAX_SIGNERS)
                    .unwrap()
                    .as_slice(),
                alternate.as_slice()
            );
        }
        private_files::replace(&signer, &current).unwrap();
        drop(open(&store).unwrap());
        assert_eq!(rotate_signer(&signer).unwrap(), 2);
        manager.renew(&fresh(), "administrator").unwrap();
        drop(manager);
        store.shutdown().await.unwrap();
        drop(store);
        node.shutdown().await.unwrap();
    }

    /// A security store, signer and issuer under `root`, with an MCP audience
    /// when `mcp` is set.
    async fn binding_fixture(
        root: &Path,
        mcp: bool,
    ) -> (
        kasumi_store::NodeStore,
        Arc<TenantStore>,
        PathBuf,
        AuthConfig,
    ) {
        let private = root.join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let physical = crate::runtime_storage_fixtures::physical(root, Default::default()).unwrap();
        let node = physical
            .create_new(
                root.join("persistent/database"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            keys,
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let config = AuthConfig {
            issuer: "https://localhost/local".into(),
            audience: "https://localhost/kasumi/api".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
            mcp_audience: mcp.then(|| "https://localhost/kasumi/mcp".into()),
            require_certificate_binding: mcp,
        };
        (node, store, signer, config)
    }

    fn token_claims(token: &str) -> serde_json::Value {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn bound_and_mcp_families_keep_audience_and_binding_through_every_issuance() {
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let (node, store, signer, config) = binding_fixture(root.path(), true).await;
        let manager = LocalCredentials::open(
            store.clone(),
            signer.clone(),
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap()
        .with_mcp_audience(config.mcp_audience.clone())
        .unwrap();
        let native = Authenticator::new(config.clone()).unwrap();
        let mcp = Authenticator::mcp(config.clone()).unwrap();
        for auth in [&native, &mcp] {
            auth.install_audit(Arc::new(Audit)).unwrap();
            auth.install_local_credentials(manager.clone()).unwrap();
        }
        let (mine, other) = ([7; 32], [8; 32]);
        let bound = CreateCredential {
            family_id: Uuid::new_v4(),
            principal: "application".into(),
            tenant: "tenant-a".into(),
            resource: kasumi_types::CredentialResource::Database {
                incarnation: Uuid::new_v4(),
            },
            scopes: BTreeSet::from([Action::Read, Action::Write]),
            lifetime_seconds: 3600,
            client_certificate_sha256: Some(hex::encode(mine)),
            audience: CredentialAudience::Native,
        };
        let created = manager.create(bound.clone(), "initializer").unwrap();
        let renewal = RenewCredential {
            family_id: bound.family_id,
            renewal_id: Uuid::new_v4(),
        };
        let renewed = manager.renew(&renewal, "application").unwrap();
        // Creation, renewal and their replays all confirm the same certificate
        // for the native audience.
        for token in [
            &created.token,
            &renewed.token,
            &manager.create(bound.clone(), "initializer").unwrap().token,
            &manager.renew(&renewal, "application").unwrap().token,
        ] {
            let claims = token_claims(token);
            assert_eq!(claims["aud"], serde_json::json!(config.audience));
            assert_eq!(
                claims["cnf"],
                serde_json::json!({"x5t#S256": URL_SAFE_NO_PAD.encode(mine)})
            );
            let bearer = format!("Bearer {token}");
            native
                .authenticate_presented(&bearer, Some(mine))
                .await
                .unwrap();
            assert!(
                native
                    .authenticate_presented(&bearer, Some(other))
                    .await
                    .is_err()
            );
            assert!(mcp.authenticate_presented(&bearer, None).await.is_err());
        }
        // A family whose record differs from the token's confirmation is
        // refused even when the presented certificate matches the token.
        assert!(
            manager
                .guard(
                    bound.family_id,
                    &bound.principal,
                    &bound.tenant,
                    "kasumi:read kasumi:write",
                    &bound.resource,
                    None,
                    CredentialAudience::Native,
                )
                .is_err()
        );
        // An MCP family is unbound and for the MCP audience only.
        let mcp_family = CreateCredential {
            family_id: Uuid::new_v4(),
            client_certificate_sha256: None,
            audience: CredentialAudience::Mcp,
            ..bound.clone()
        };
        let issued = manager.create(mcp_family.clone(), "initializer").unwrap();
        let renewed = manager
            .renew(
                &RenewCredential {
                    family_id: mcp_family.family_id,
                    renewal_id: Uuid::new_v4(),
                },
                "administrator",
            )
            .unwrap();
        for token in [&issued.token, &renewed.token] {
            let claims = token_claims(token);
            assert_eq!(claims["aud"], serde_json::json!(config.mcp_audience));
            assert!(claims.get("cnf").is_none());
            let bearer = format!("Bearer {token}");
            mcp.authenticate_presented(&bearer, None).await.unwrap();
            for presented in [None, Some(mine)] {
                assert!(
                    native
                        .authenticate_presented(&bearer, presented)
                        .await
                        .is_err()
                );
            }
        }
        // MCP families are never bound, and need an installation MCP audience.
        assert!(
            CreateCredential {
                client_certificate_sha256: Some(hex::encode(mine)),
                ..mcp_family.clone()
            }
            .validate()
            .is_err()
        );
        let without_mcp = LocalCredentials::open(
            store.clone(),
            signer.clone(),
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap();
        let orphan = CreateCredential {
            family_id: Uuid::new_v4(),
            ..mcp_family
        };
        assert!(without_mcp.create(orphan.clone(), "initializer").is_err());
        assert!(without_mcp.status(orphan.family_id).is_err());
        drop((native, mcp, manager, without_mcp));
        drop(store);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_expired_bound_credential_recovers_only_from_its_own_certificate() {
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let (node, store, signer, config) = binding_fixture(root.path(), true).await;
        let now = EpochClock::system().unwrap().now_ms().unwrap();
        let past = LocalCredentials::with_test_clock(
            store.clone(),
            signer.clone(),
            config.issuer.clone(),
            config.audience.clone(),
            Arc::new(
                EpochClock::new(
                    Arc::new(kasumi_clock::SystemLeaseClock),
                    Arc::new(PastClock(now - 7_200_000)),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let (mine, other) = ([7; 32], [8; 32]);
        let specification = CreateCredential {
            family_id: Uuid::new_v4(),
            principal: "application".into(),
            tenant: "tenant-a".into(),
            resource: kasumi_types::CredentialResource::Database {
                incarnation: Uuid::new_v4(),
            },
            scopes: BTreeSet::from([Action::Read]),
            lifetime_seconds: 3600,
            client_certificate_sha256: Some(hex::encode(mine)),
            audience: CredentialAudience::Native,
        };
        let expired = format!(
            "Bearer {}",
            past.create(specification.clone(), "initializer")
                .unwrap()
                .token
        );
        drop(past);
        let manager = LocalCredentials::open(
            store.clone(),
            signer,
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap()
        .with_mcp_audience(config.mcp_audience.clone())
        .unwrap();
        let auth = Authenticator::new(config.clone()).unwrap();
        auth.install_audit(Arc::new(Audit)).unwrap();
        auth.install_local_credentials(manager.clone()).unwrap();
        assert!(auth.verify_recovery(&expired, Some(other)).await.is_err());
        let verified = auth.verify_recovery(&expired, Some(mine)).await.unwrap();
        let recovered = manager
            .recover(
                &verified.proof,
                &RenewCredential {
                    family_id: specification.family_id,
                    renewal_id: Uuid::new_v4(),
                },
                "application",
            )
            .unwrap();
        assert_eq!(
            token_claims(&recovered.token)["cnf"],
            serde_json::json!({"x5t#S256": URL_SAFE_NO_PAD.encode(mine)})
        );
        auth.authenticate_presented(&format!("Bearer {}", recovered.token), Some(mine))
            .await
            .unwrap();
        drop((auth, manager));
        drop(store);
        node.shutdown().await.unwrap();
    }

    struct PastClock(u64);
    impl kasumi_clock::WallClock for PastClock {
        fn now_ms(&self) -> Result<u64> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn a_family_written_before_binding_keeps_its_exact_record_and_renews_unbound() {
        let root = kasumi_store::test_utils::private_tempdir().unwrap();
        let (node, store, signer, config) = binding_fixture(root.path(), false).await;
        let manager = LocalCredentials::open(
            store.clone(),
            signer.clone(),
            config.issuer.clone(),
            config.audience.clone(),
        )
        .unwrap();
        let auth = Authenticator::new(config.clone()).unwrap();
        auth.install_audit(Arc::new(Audit)).unwrap();
        auth.install_local_credentials(manager.clone()).unwrap();
        // The bytes the writer before certificate binding committed: no
        // binding and no audience member.
        let family = Uuid::new_v4();
        let incarnation = Uuid::new_v4();
        let issued_at = EpochClock::system().unwrap().now_ms().unwrap() / 1000;
        let signer_generation = Signers::read(&signer).unwrap().active;
        let legacy = format!(
            r#"{{"specification":{{"family_id":"{family}","principal":"administrator","tenant":"tenant-a","resource":{{"kind":"database","incarnation":"{incarnation}"}},"scopes":["read","write","admin","audit"],"lifetime_seconds":3600}},"created_at_ms":{},"revoked_at_ms":null}}"#,
            issued_at * 1000
        );
        let issuance = format!(
            r#"{{"family_id":"{family}","issuance_id":"{family}","issued_at":{issued_at},"expires_at":{},"signer":{signer_generation}}}"#,
            issued_at + 3600
        );
        store
            .write_batch(&[
                WriteOp::put(FAMILIES, family.as_bytes(), legacy.as_bytes().to_vec()),
                WriteOp::put(
                    ISSUANCES,
                    LocalCredentials::issuance_key(family, family),
                    issuance.as_bytes().to_vec(),
                ),
            ])
            .unwrap();
        let status = manager.status(family).unwrap();
        assert_eq!(status.specification.client_certificate_sha256, None);
        assert_eq!(status.specification.audience, CredentialAudience::Native);
        assert_eq!(encoded(&status).unwrap(), legacy.as_bytes());
        // Its replayed creation and its renewal stay unbound and native.
        let replayed = manager
            .create(status.specification.clone(), "initializer")
            .unwrap();
        let renewed = manager
            .renew(
                &RenewCredential {
                    family_id: family,
                    renewal_id: Uuid::new_v4(),
                },
                "administrator",
            )
            .unwrap();
        for token in [&replayed.token, &renewed.token] {
            let claims = token_claims(token);
            assert!(claims.get("cnf").is_none());
            assert_eq!(claims["aud"], serde_json::json!(config.audience));
            let bearer = format!("Bearer {token}");
            auth.authenticate_presented(&bearer, Some([9; 32]))
                .await
                .unwrap();
            auth.authenticate(&bearer).await.unwrap();
        }
        // An equivalent spelling that names the defaults is not the writer's.
        let family_bytes = |text: String| {
            store
                .write_batch(&[WriteOp::put(FAMILIES, family.as_bytes(), text.into_bytes())])
                .unwrap();
            LocalCredentials::open(
                store.clone(),
                signer.clone(),
                config.issuer.clone(),
                config.audience.clone(),
            )
            .unwrap()
            .status(family)
        };
        for respelled in [
            legacy.replace(
                r#""lifetime_seconds":3600"#,
                r#""lifetime_seconds":3600,"audience":"native""#,
            ),
            legacy.replace(
                r#""lifetime_seconds":3600"#,
                r#""lifetime_seconds":3600,"client_certificate_sha256":null"#,
            ),
        ] {
            assert!(family_bytes(respelled).is_err());
        }
        assert!(family_bytes(legacy).is_ok());
        drop((auth, manager));
        drop(store);
        node.shutdown().await.unwrap();
    }
}
