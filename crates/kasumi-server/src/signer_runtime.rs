//! Explicitly initialized, separately encrypted local signer-verifier state.
//! Runtime opening never bootstraps trust from a certificate received on a wire.
use crate::{
    runtime::{KeyProviderSettings, file_secret, read_bounded},
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
pub(crate) mod authorization;
use authorization::{CurrentSignerInvocation, ScopedSignerAdministrator};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierConfig {
    pub identity: TrustVerifierIdentity,
    pub database_path: PathBuf,
    pub keys: KeyProviderSettings,
    pub max_background_workers: usize,
}
impl SignerVerifierConfig {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        BackgroundWorkBudget::required_bytes(self.max_background_workers, 1)?;
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
        persistent_disk: Arc<kasumi_store::NodeDisk>,
        scratch_disk: Arc<kasumi_store::ScratchDisk>,
    ) -> Result<(Arc<NodeStore>, Arc<TenantStore>)> {
        self.validate()?;
        private_files::check_directory(
            self.database_path
                .parent()
                .context("verifier directory missing")?,
        )?;
        let database_id = kasumi_store::node_store_ids::signer_verifier(&self.identity)?;
        // Preparation is called only inside a retained startup/installation
        // owner. Keep acquired scopes outside the caught future until cleanup
        // has actually joined every initializer and worker.
        let mut pending = crate::startup_resources::Resources::default();
        let prepared = crate::startup_preparation::capture("signer verifier storage", async {
            let provider = self.keys.provider(credential)?;
            let access = StorageAccess::live_signer_trust(self.identity.clone())?;
            let node = if initialize {
                NodeStore::create_new(
                    &self.database_path,
                    database_id,
                    persistent_disk.clone(),
                    scratch_disk.clone(),
                )?
            } else {
                NodeStore::open_existing(
                    &self.database_path,
                    database_id,
                    persistent_disk.clone(),
                    scratch_disk.clone(),
                )?
            };
            pending.owned_nodes.push(node.clone());
            #[cfg(test)]
            crate::startup_preparation::checkpoint(database_id, "verifier-storage-node");
            let store = if initialize {
                TenantStore::initialize_catalog(
                    node.clone(),
                    self.identity.tenant(),
                    provider,
                    access,
                )
                .await?
            } else {
                TenantStore::open_existing(node.clone(), self.identity.tenant(), provider, access)
                    .await?
            };
            pending.stores.push(store.clone());
            #[cfg(test)]
            crate::startup_preparation::checkpoint(database_id, "verifier-storage-catalog");
            node.drain_initializers().await?;
            Ok((node, store))
        })
        .await;
        match prepared {
            Ok(store) => Ok(store),
            Err(error) => {
                #[cfg(test)]
                crate::startup_preparation::failure_checkpoint(database_id).await;
                match crate::startup_owner::finish(&mut pending).await {
                    Ok(()) => Err(error),
                    Err(drain) => Err(error.context(drain)),
                }
            }
        }
    }

    pub(crate) async fn open(
        &self,
        domains: BTreeMap<String, SigningDomain>,
        credential: CredentialSource,
        persistent_disk: Arc<kasumi_store::NodeDisk>,
        scratch_disk: Arc<kasumi_store::ScratchDisk>,
        admission: Arc<kasumi_engine::admission::NodeAdmission>,
    ) -> Result<Arc<InstalledSignerVerifier>> {
        ensure!(
            self.database_path.is_file(),
            "signer verifier must be explicitly initialized before runtime startup"
        );
        self.validate()?;
        let bytes =
            BackgroundWorkBudget::required_bytes(self.max_background_workers, domains.len())?;
        let mut reserved = admission.reserve(bytes, None)?;
        reserved.retain(bytes);
        let charge: Arc<dyn Send + Sync> = Arc::new(reserved);
        let (node, store) = self
            .store(credential, false, persistent_disk, scratch_disk)
            .await?;
        let administrator = Arc::new(ScopedSignerAdministrator::default());
        let result = (|| -> Result<(TrustVerifierIdentity, BTreeMap<String, Arc<LiveSignerTrust>>)> {
            let installed_bytes = store
                .get_bounded(NS, b"installation", 256 << 10)?
                .context("signer verifier initialization is incomplete")?;
            let installed = VerifierInstallation::decode_current(&installed_bytes)?;
            ensure!(
                installed.identity == self.identity && installed.domains.keys().eq(domains.keys()),
                "exact installed verifier domain set differs"
            );
            let mut owners = BTreeMap::new();
            for (digest, domain) in domains {
                ensure!(digest == domain.digest()?, "noncanonical verifier domain");
                let owner = store.open_live_signer_trust(
                    &self.identity,
                    domain,
                    administrator.clone(),
                    BackgroundWorkBudget::new(self.max_background_workers, charge.clone())?,
                )?;
                let current = owner.current()?;
                ensure!(
                    current.revision != 0 || current.active.digest()? == installed.domains[&digest],
                    "initial verifier head differs from completed installation"
                );
                owners.insert(digest, owner);
            }
            Ok((installed.identity, owners))
        })();
        let (installed_identity, owners) = match result {
            Ok(verified) => verified,
            Err(error) => {
                let mut pending = crate::startup_resources::Resources::default();
                pending.owned_nodes.push(node);
                pending.stores.push(store);
                return Err(match crate::startup_owner::finish(&mut pending).await {
                    Ok(()) => error,
                    Err(failure) => error.context(failure),
                });
            }
        };
        Ok(Arc::new(InstalledSignerVerifier {
            node,
            store,
            installed_identity,
            owners,
            administrator,
            drain_report: Default::default(),
        }))
    }
}
pub(crate) struct InstalledSignerVerifier {
    node: Arc<NodeStore>,
    store: Arc<TenantStore>,
    // Captured from the checked encrypted installation record, never config.
    #[allow(dead_code, reason = "retained for G05 installed destination handoff")]
    installed_identity: TrustVerifierIdentity,
    owners: BTreeMap<String, Arc<LiveSignerTrust>>,
    administrator: Arc<ScopedSignerAdministrator>,
    drain_report: std::sync::Mutex<kasumi_types::drain::DrainReport>,
}
impl InstalledSignerVerifier {
    /// Only the live verifier on this exact installed disk may supply the
    /// replicated physical owner to destination opening.
    #[allow(dead_code, reason = "retained for G05 installed destination handoff")]
    pub(crate) fn identity_for(
        &self,
        disk: &Arc<kasumi_store::NodeDisk>,
    ) -> Result<TrustVerifierIdentity> {
        ensure!(
            Arc::ptr_eq(self.node.persistent_disk(), disk),
            "installed verifier belongs to another persistent disk"
        );
        self.store.check_access()?;
        Ok(self.installed_identity.clone())
    }

    pub(crate) async fn authorize_control(
        &self,
        request: &ControlSignerRequest,
        fence: Arc<kasumi_engine::ControlAdministrativeFence>,
        issuer: kasumi_client::CurrentControlSignerObservation,
        domain: &SigningDomain,
    ) -> Result<(Arc<LiveSignerTrust>, CurrentSignerInvocation)> {
        request.digest()?;
        issuer.check()?;
        let observation = issuer.observation();
        ensure!(
            observation.request_sha256 == request.digest()?
                && observation.observation_id == request.observation_id
                && observation.admission.root == fence.installation().root
                && observation.admission.partition == *fence.partition()
                && observation
                    .admission
                    .nodes
                    .iter()
                    .map(|node| node.node_id)
                    .collect::<std::collections::BTreeSet<_>>()
                    == fence.members().collect()
                && request.directive.node.node_id == fence.local_node_id()
                && observation.head.active.identity.domain == *domain
                && request.directive.domain_sha256 == domain.digest()?,
            "current physical Control registry, quorum or issuer differs"
        );
        let owner = self.owner(domain)?;
        ensure!(
            owner.current()?.verifier == request.directive.node.verifier,
            "remote signer request addresses another physical verifier owner"
        );
        let scope = self.administrator.bind_control(fence, issuer).await?;
        scope.check()?;
        Ok((owner, scope))
    }
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
    pub(crate) async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        use kasumi_types::drain::DrainCompletion;
        for owner in self.owners.values() {
            owner.close();
        }
        let mut retained = None;
        for owner in self.owners.values() {
            if let Err(error) = owner.drain_background_work().await {
                self.drain_report
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .merge(&error);
                if error.completion() == DrainCompletion::Retained {
                    retained = Some(error);
                }
            }
        }
        if retained.is_none()
            && let Err(error) = self.store.shutdown().await
        {
            self.drain_report
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .merge(&error);
            if error.completion() == DrainCompletion::Retained {
                retained = Some(error);
            }
        }
        if retained.is_none()
            && let Err(error) = self.node.shutdown().await
        {
            self.drain_report
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .merge(&error);
            if error.completion() == DrainCompletion::Retained {
                retained = Some(error);
            }
        }
        self.drain_report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .outcome(retained)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSignerConfig {
    pub certificate: SigningCertificate,
    pub key_file: PathBuf,
}
impl OperationalSignerConfig {
    /// Read one bounded private descriptor snapshot. Its installed path is never
    /// chosen by a network request, and a changed key must match its certificate.
    pub(crate) fn load(path: &Path, domain: &SigningDomain) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "operational signer descriptor requires an absolute path"
        );
        let config: Self = serde_json::from_slice(&private_files::read(path, 128 << 10)?)?;
        config.validate(domain)?;
        Ok(config)
    }

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
            &private_files::read(&self.key_file, 64 << 10)?,
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
    fn decode_current(bytes: &[u8]) -> Result<Self> {
        let installed: Self = serde_json::from_slice(bytes)?;
        installed.validate()?;
        struct Exact<'a> {
            original: &'a [u8],
            offset: usize,
        }
        impl std::io::Write for Exact<'_> {
            fn write(&mut self, encoded: &[u8]) -> std::io::Result<usize> {
                let end = self.offset.checked_add(encoded.len()).ok_or_else(|| {
                    std::io::Error::other("noncanonical signer verifier installation")
                })?;
                if self.original.get(self.offset..end) != Some(encoded) {
                    return Err(std::io::Error::other(
                        "noncanonical signer verifier installation",
                    ));
                }
                self.offset = end;
                Ok(encoded.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut exact = Exact {
            original: bytes,
            offset: 0,
        };
        serde_json::to_writer(&mut exact, &installed)
            .context("noncanonical signer verifier installation")?;
        ensure!(
            exact.offset == bytes.len(),
            "noncanonical signer verifier installation"
        );
        Ok(installed)
    }
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeSignerVerifier {
    pub admission: kasumi_engine::admission::AdmissionConfig,
    pub persistent_disk: kasumi_store::NodeDiskConfig,
    pub scratch_disk: kasumi_store::ScratchDiskConfig,
    pub verifier: SignerVerifierConfig,
    pub initial_certificates: Vec<SigningCertificate>,
}
// Only a drained result crosses the acknowledged startup handoff. Abandoned
// errors remain observable through the retained initialization registry.
struct InitializedVerifier;
impl crate::startup_owner::Runtime for InitializedVerifier {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}
impl InitializeSignerVerifier {
    pub async fn initialize(&self) -> Result<()> {
        let storage = crate::runtime_memory::RuntimeStorage::installed(&self.admission)?;
        self.initialize_with_storage(storage).await
    }

    pub(crate) async fn initialize_with_storage(
        &self,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<()> {
        storage.require_policy(&self.admission)?;
        crate::startup_owner::open(
            crate::startup_owner::Kind::SignerVerifier,
            self.clone().initialize_owned(storage),
        )
        .await?;
        Ok(())
    }
    /// Stop admitting new initializations before joining abandoned operations.
    /// Cancellation retains the exact pending task and its original failure.
    pub async fn drain_initializations() -> Result<()> {
        crate::startup_owner::drain(crate::startup_owner::Kind::SignerVerifier).await
    }
    async fn initialize_owned(
        self,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<InitializedVerifier> {
        self.verifier.validate()?;
        crate::persistent_disk::validate(
            &self.persistent_disk,
            &self.scratch_disk,
            [self.verifier.database_path.as_path()],
        )?;
        let admission = storage.facade(&self.admission)?;
        let mut pending = crate::startup_resources::Resources::default();
        pending.owned_admissions.push(admission.clone());
        let bytes = BackgroundWorkBudget::required_bytes(
            self.verifier.max_background_workers,
            self.initial_certificates.len(),
        )?;
        let mut reserved = admission.reserve(bytes, None)?;
        reserved.retain(bytes);
        let charge: Arc<dyn Send + Sync> = Arc::new(reserved);
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
        #[cfg(test)]
        let database_id = kasumi_store::node_store_ids::signer_verifier(&self.verifier.identity)?;
        let result = crate::startup_preparation::capture("signer verifier installation", async {
            let (node, store) = self
                .verifier
                .store(
                    Arc::new(file_secret),
                    true,
                    crate::persistent_disk::open(&self.persistent_disk, &storage)?,
                    storage.open_scratch(&self.scratch_disk)?,
                )
                .await?;
            pending.owned_nodes.push(node);
            pending.stores.push(store.clone());
            #[cfg(test)]
            crate::startup_preparation::checkpoint(database_id, "verifier-installation-store");
            ensure!(
                store.get_bounded(NS, b"installation", 256 << 10)?.is_none(),
                "fresh verifier unexpectedly contains an installation"
            );
            let administrator: Arc<dyn LiveTrustAdministrator> =
                Arc::new(ScopedSignerAdministrator::default());
            for certificate in &self.initial_certificates {
                // This operation exclusively created the physical file. Neither
                // a previous head nor partial trust is a resumable installation.
                store.initialize_live_signer_trust(
                    &self.verifier.identity,
                    certificate.clone(),
                    administrator.clone(),
                    BackgroundWorkBudget::new(
                        self.verifier.max_background_workers,
                        charge.clone(),
                    )?,
                )?;
            }
            #[cfg(test)]
            crate::startup_preparation::checkpoint(database_id, "verifier-installation-domains");
            store.write_batch(&[WriteOp::put(
                NS,
                b"installation",
                serde_json::to_vec(&installed)?,
            )])?;
            #[cfg(test)]
            crate::startup_preparation::checkpoint(database_id, "verifier-installation-complete");
            Ok(())
        })
        .await;
        #[cfg(test)]
        if result.is_err() {
            crate::startup_preparation::failure_checkpoint(database_id).await;
        }
        let drained = crate::startup_owner::finish(&mut pending).await;
        match (result, drained) {
            (Ok(()), Ok(())) => Ok(InitializedVerifier),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(drain)) => Err(drain.into()),
            (Err(error), Err(drain)) => Err(error.context(drain)),
        }
    }
}

pub async fn initialize_from_file(path: &Path) -> Result<()> {
    let input: InitializeSignerVerifier = serde_json::from_slice(&read_bounded(path, 2 << 20)?)?;
    input.initialize().await
}

#[cfg(test)]
#[path = "signer_runtime_tests.rs"]
mod tests;
