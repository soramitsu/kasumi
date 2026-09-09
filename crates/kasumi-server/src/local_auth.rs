//! Local Ed25519 issuer and encrypted permanent credential-family records.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
use kasumi_clock::EpochClock;
use kasumi_store::{TenantStore, WriteOp, private_files};
use kasumi_types::{
    Action, CreateCredential, CredentialLiveness, CredentialStatus, Error, ErrorCode,
    IssuedCredential, RenewCredential,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const FAMILIES: &str = "local-credential-families";
const ISSUANCES: &str = "local-credential-issuances";
const EVENTS: &str = "local-credential-events";
const MAX_SIGNERS: usize = 1 << 20;

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
        let signers: Self = serde_json::from_slice(&private_files::read(path, MAX_SIGNERS)?)?;
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
}
#[derive(Serialize)]
struct CredentialEvent<'a> {
    operation: &'static str,
    actor: &'a str,
    family_id: Uuid,
    at_ms: u64,
}

pub struct LocalCredentials {
    store: Arc<TenantStore>,
    signer_file: PathBuf,
    issuer: String,
    audience: String,
    clock: Arc<EpochClock>,
    mutation: Mutex<()>,
}
impl LocalCredentials {
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
        Ok(Arc::new(Self {
            store,
            signer_file,
            issuer,
            audience,
            clock: EpochClock::system()?,
            mutation: Mutex::new(()),
        }))
    }
    pub fn status(&self, family: Uuid) -> Result<CredentialStatus> {
        let bytes = self
            .store
            .get(FAMILIES, family.as_bytes())?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "credential family not found"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn issuance_key(family: Uuid, issuance: Uuid) -> Vec<u8> {
        [family.as_bytes().as_slice(), issuance.as_bytes().as_slice()].concat()
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
        let claims = Claims {
            iss: &self.issuer,
            aud: &self.audience,
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
        if let Some(bytes) = self
            .store
            .get(FAMILIES, specification.family_id.as_bytes())?
        {
            let status: CredentialStatus = serde_json::from_slice(&bytes)?;
            ensure!(
                status.specification == specification,
                Error::new(
                    ErrorCode::Conflict,
                    "credential identity conflicts with original specification"
                )
            );
            let issuance = self
                .store
                .get(
                    ISSUANCES,
                    &Self::issuance_key(specification.family_id, specification.family_id),
                )?
                .context("credential issuance missing")?;
            return self.token(&status, &serde_json::from_slice(&issuance)?);
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
                serde_json::to_vec(&status)?,
            ),
            WriteOp::put(
                ISSUANCES,
                Self::issuance_key(issuance.family_id, issuance.issuance_id),
                serde_json::to_vec(&issuance)?,
            ),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
        ])?;
        Ok(token)
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
        if let Some(bytes) = self.store.get(ISSUANCES, &key)? {
            return self.token(&status, &serde_json::from_slice(&bytes)?);
        }
        let now = self.clock.now_ms()?;
        let issued_at = now / 1000;
        let issuance = Issuance {
            family_id: request.family_id,
            issuance_id: request.renewal_id,
            issued_at,
            expires_at: issued_at
                .checked_add(status.specification.lifetime_seconds)
                .context("credential time overflow")?,
            signer: Signers::read(&self.signer_file)?.active,
        };
        let token = self.token(&status, &issuance)?;
        let event = CredentialEvent {
            operation: "renew",
            actor,
            family_id: request.family_id,
            at_ms: now,
        };
        self.store.write_batch(&[
            WriteOp::put(ISSUANCES, key, serde_json::to_vec(&issuance)?),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
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
            WriteOp::put(FAMILIES, family.as_bytes(), serde_json::to_vec(&status)?),
            WriteOp::put(
                EVENTS,
                Uuid::new_v4().as_bytes(),
                serde_json::to_vec(&event)?,
            ),
        ])?;
        Ok(status)
    }
    pub(crate) fn guard(
        self: &Arc<Self>,
        family: Uuid,
        principal: &str,
        tenant: &str,
        scope: &str,
        resource: &kasumi_types::CredentialResource,
    ) -> Result<Arc<dyn CredentialLiveness>> {
        let status = self.status(family)?;
        let specification = &status.specification;
        ensure!(
            status.revoked_at_ms.is_none()
                && specification.principal == principal
                && specification.tenant == tenant
                && &specification.resource == resource
                && scopes(&specification.scopes) == scope,
            "credential family claims mismatch or revoked"
        );
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
        match self.credentials.status(self.family) {
            Ok(status) if status.revoked_at_ms.is_none() => Ok(()),
            _ => Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unauthorized,
                "credential family revoked or unavailable",
            )),
        }
    }
    fn family_id(&self) -> Option<Uuid> {
        Some(self.family)
    }
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
    use kasumi_store::{FileKeyProvider, NodeStore, StorageAccess};
    use std::collections::BTreeSet;
    struct Audit;
    #[async_trait::async_trait]
    impl RequestAuditSink for Audit {
        async fn record(&self, _: RequestAuditEvent) -> kasumi_types::Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn local_issuer_renewal_preserves_deadlines_and_revocation_fences_existing_requests() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("operator");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let keys = Arc::new(
            FileKeyProvider::initialize(&private.join("security.json"), "security").unwrap(),
        );
        let store = TenantStore::open(
            NodeStore::create_new(
                root.path().join("database"),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
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
        assert!(
            !context
                .authorization
                .same_live_invocation(&new_context.authorization)
        );
        assert!(
            auth.protected_resource_metadata("https://localhost/mcp")
                .get("authorization_servers")
                .is_none()
        );
        let revoked = manager.revoke(issued.family_id, "administrator").unwrap();
        assert!(revoked.revoked_at_ms.is_some());
        assert!(context.authorization.check_live().is_err());
        assert!(new_context.authorization.check_live().is_err());
        assert!(
            auth.authenticate(&format!("Bearer {}", renewed.token))
                .await
                .is_err()
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
    }
}
