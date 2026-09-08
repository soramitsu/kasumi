//! Explicitly initialized, separately encrypted local signer-verifier state.
//! Runtime opening never bootstraps trust from a certificate received on a wire.
use crate::{
    runtime::{KeyProviderSettings, file_secret, read_bounded, read_private_file},
    serving_runtime::CredentialSource,
};
use anyhow::{Context, Result, ensure};
use kasumi_serving::*;
use kasumi_store::{NodeStore, StorageAccess, TenantStore, WriteOp, private_files};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
const NS: &str = "live.signer.installation";
#[path = "signer_runtime_authorization.rs"]
mod authorization;
use authorization::{CurrentSignerInvocation, ScopedSignerAdministrator};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierConfig {
    pub identity: TrustVerifierIdentity,
    pub database_path: PathBuf,
    pub keys: KeyProviderSettings,
}
impl SignerVerifierConfig {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        ensure!(
            self.database_path.is_absolute(),
            "verifier storage requires an installed absolute path"
        );
        self.keys.validate()?;
        Ok(())
    }
    async fn store(
        &self,
        credential: CredentialSource,
        initialize: bool,
    ) -> Result<Arc<TenantStore>> {
        self.validate()?;
        private_files::check_directory(
            self.database_path
                .parent()
                .context("verifier directory missing")?,
        )?;
        let node = if initialize {
            NodeStore::open(&self.database_path)?
        } else {
            NodeStore::open_existing(&self.database_path)?
        };
        let provider = self.keys.provider(credential)?;
        let access = StorageAccess::live_signer_trust(self.identity.clone())?;
        if initialize {
            TenantStore::open(node, self.identity.tenant(), provider, access).await
        } else {
            TenantStore::open_existing(node, self.identity.tenant(), provider, access).await
        }
    }
    pub(crate) async fn open(
        &self,
        domains: BTreeMap<String, SigningDomain>,
        credential: CredentialSource,
    ) -> Result<Arc<InstalledSignerVerifier>> {
        ensure!(
            self.database_path.is_file(),
            "signer verifier must be explicitly initialized before runtime startup"
        );
        let store = self.store(credential, false).await?;
        let administrator = Arc::new(ScopedSignerAdministrator::default());
        let result = (|| -> Result<BTreeMap<String, Arc<LiveSignerTrust>>> {
            let installed: VerifierInstallation = serde_json::from_slice(
                &store
                    .get_bounded(NS, b"installation", 256 << 10)?
                    .context("signer verifier initialization is incomplete")?,
            )?;
            installed.validate()?;
            ensure!(
                installed.identity == self.identity && installed.domains.keys().eq(domains.keys()),
                "exact installed verifier domain set differs"
            );
            let mut owners = BTreeMap::new();
            for (digest, domain) in domains {
                ensure!(digest == domain.digest()?, "noncanonical verifier domain");
                let owner =
                    store.open_live_signer_trust(&self.identity, domain, administrator.clone())?;
                let current = owner.current()?;
                ensure!(
                    current.revision != 0 || current.active.digest()? == installed.domains[&digest],
                    "initial verifier head differs from completed installation"
                );
                owners.insert(digest, owner);
            }
            Ok(owners)
        })();
        let owners = match result {
            Ok(owners) => owners,
            Err(error) => {
                store.shutdown().await;
                return Err(error);
            }
        };
        Ok(Arc::new(InstalledSignerVerifier {
            store,
            owners,
            administrator,
        }))
    }
}
pub(crate) struct InstalledSignerVerifier {
    store: Arc<TenantStore>,
    owners: BTreeMap<String, Arc<LiveSignerTrust>>,
    administrator: Arc<ScopedSignerAdministrator>,
}
impl InstalledSignerVerifier {
    pub(crate) async fn authorize(
        &self,
        request: &SignerVerifierRequest,
        fence: Arc<kasumi_authority::AuthorityAdministrativeFence>,
        domain: &SigningDomain,
    ) -> Result<(Arc<LiveSignerTrust>, CurrentSignerInvocation)> {
        request.validate()?;
        ensure!(
            *domain == fence.signing_domain()?,
            "current administrative authority cannot address another signing domain"
        );
        ensure!(
            request.verifier.node_id == fence.local_node_id(),
            "signer request is not for this authority member"
        );
        ensure!(
            request.domain_sha256 == domain.digest()?,
            "signer request belongs to another authority domain"
        );
        let owner = self.owner(domain)?;
        ensure!(
            owner.current()?.verifier == request.verifier,
            "signer request targets another physical verifier"
        );
        let scope = self.administrator.bind(fence).await?;
        scope.check()?;
        Ok((owner, scope))
    }
    pub(crate) fn trust(&self, manifest: AuthorityManifest) -> Result<AuthorityTrust> {
        let mut live = BTreeMap::new();
        for partition in manifest.partitions.keys() {
            let domain = manifest.signing_domain(*partition)?;
            live.insert(
                *partition,
                self.owners
                    .get(&domain.digest()?)
                    .context("authority verifier domain absent")?
                    .clone(),
            );
        }
        AuthorityTrust::install(manifest)?.with_live_verifiers(live)
    }
    pub(crate) fn owner(&self, domain: &SigningDomain) -> Result<Arc<LiveSignerTrust>> {
        self.owners
            .get(&domain.digest()?)
            .cloned()
            .context("installed signer domain absent")
    }
    pub(crate) async fn shutdown(&self) {
        for owner in self.owners.values() {
            owner.close();
        }
        self.store.shutdown().await;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSignerConfig {
    pub certificate: SigningCertificate,
    pub key_file: PathBuf,
}
impl OperationalSignerConfig {
    pub fn validate(&self, domain: &SigningDomain) -> Result<()> {
        ensure!(
            self.key_file.is_absolute(),
            "operational signer requires an installed absolute key path"
        );
        self.certificate.verify(domain)
    }
    pub(crate) fn open(&self, verifier: &InstalledSignerVerifier) -> Result<Arc<AuthoritySigner>> {
        let signer = GenerationSigner::from_pkcs8(
            self.certificate.clone(),
            &read_private_file(&self.key_file, 64 << 10)?,
        )?;
        Ok(Arc::new(AuthoritySigner::new(
            LiveGenerationSigner::install(
                signer,
                verifier.owner(&self.certificate.identity.domain)?,
            )?,
        )))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct VerifierInstallation {
    format: u32,
    identity: TrustVerifierIdentity,
    domains: BTreeMap<String, String>,
}
impl VerifierInstallation {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && !self.domains.is_empty() && self.domains.len() <= 1024,
            "unsupported verifier installation"
        );
        self.identity.validate()?;
        for (domain, certificate) in &self.domains {
            kasumi_types::validate_sha256(domain)?;
            kasumi_types::validate_sha256(certificate)?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeSignerVerifier {
    pub verifier: SignerVerifierConfig,
    pub initial_certificates: Vec<SigningCertificate>,
}
impl InitializeSignerVerifier {
    pub async fn initialize(&self) -> Result<()> {
        self.verifier.validate()?;
        ensure!(
            !self.initial_certificates.is_empty() && self.initial_certificates.len() <= 1024,
            "verifier requires a bounded explicit domain set"
        );
        let mut domains = BTreeMap::new();
        for certificate in &self.initial_certificates {
            certificate.verify(&certificate.identity.domain)?;
            ensure!(
                certificate.identity.generation == 1,
                "new verifier requires initial generation one"
            );
            ensure!(
                domains
                    .insert(certificate.identity.domain.digest()?, certificate.digest()?)
                    .is_none(),
                "duplicate verifier domain"
            );
        }
        let installed = VerifierInstallation {
            format: 1,
            identity: self.verifier.identity.clone(),
            domains,
        };
        installed.validate()?;
        let parent = self
            .verifier
            .database_path
            .parent()
            .context("verifier directory missing")?;
        if !parent.exists() {
            private_files::create_directory(parent)?;
        }
        let store = self.verifier.store(Arc::new(file_secret), true).await?;
        let result = (|| -> Result<()> {
            if let Some(previous) = store.get_bounded(NS, b"installation", 256 << 10)? {
                ensure!(
                    serde_json::from_slice::<VerifierInstallation>(&previous)? == installed,
                    "verifier installation already differs"
                );
                let administrator: Arc<dyn LiveTrustAdministrator> =
                    Arc::new(ScopedSignerAdministrator::default());
                for certificate in &self.initial_certificates {
                    let owner = store.open_live_signer_trust(
                        &self.verifier.identity,
                        certificate.identity.domain.clone(),
                        administrator.clone(),
                    )?;
                    let current = owner.current()?;
                    ensure!(
                        current.revision != 0 || current.active == *certificate,
                        "initial verifier head differs from completed installation"
                    );
                }
            } else {
                let administrator: Arc<dyn LiveTrustAdministrator> =
                    Arc::new(ScopedSignerAdministrator::default());
                for certificate in &self.initial_certificates {
                    if store.has_live_signer_trust(
                        &self.verifier.identity,
                        &certificate.identity.domain,
                    )? {
                        let owner = store.open_live_signer_trust(
                            &self.verifier.identity,
                            certificate.identity.domain.clone(),
                            administrator.clone(),
                        )?;
                        ensure!(
                            owner.current()?
                                == LocalSignerTrustRecord::initial(
                                    self.verifier.identity.clone(),
                                    certificate.clone()
                                )?,
                            "partial verifier initialization differs"
                        );
                    } else {
                        store.initialize_live_signer_trust(
                            &self.verifier.identity,
                            certificate.clone(),
                            administrator.clone(),
                        )?;
                    }
                }
                store.write_batch(&[WriteOp::put(
                    NS,
                    b"installation",
                    serde_json::to_vec(&installed)?,
                )])?;
            }
            Ok(())
        })();
        store.shutdown().await;
        result
    }
}
pub async fn initialize_from_file(path: &Path) -> Result<()> {
    let input: InitializeSignerVerifier = serde_json::from_slice(&read_bounded(path, 2 << 20)?)?;
    input.initialize().await
}

#[cfg(test)]
#[path = "signer_runtime_tests.rs"]
mod tests;
