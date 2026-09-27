//! Explicit filesystem destination enrollment and installed-owner handoff.
//! Runtime opening never enrolls or repairs a destination. Configured identity
//! values select an original marker; only retained installed owners authorize it.
use crate::{administration::DestinationConfig, runtime::RuntimeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::{BackupDestination, FilesystemBackupDestination, NodeDisk, private_files};
use kasumi_types::{BackupNamespaceBinding, TrustVerifierIdentity};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub(crate) enum InstalledOwner<'a> {
    Standalone(&'a crate::standalone::InstalledStandaloneOwner),
    Replicated(&'a crate::signer_runtime::InstalledSignerVerifier),
}
impl InstalledOwner<'_> {
    fn identity_for(&self, disk: &Arc<NodeDisk>) -> Result<TrustVerifierIdentity> {
        match self {
            Self::Standalone(owner) => owner.identity_for(disk),
            Self::Replicated(owner) => owner.identity_for(disk),
        }
    }
    pub(crate) fn require_binding(
        &self,
        disk: &Arc<NodeDisk>,
        binding: &BackupNamespaceBinding,
    ) -> Result<()> {
        binding.validate()?;
        let identity = self.identity_for(disk)?;
        ensure!(
            matches!(binding, BackupNamespaceBinding::Filesystem { installation_id, origin_node_id, .. }
            if *installation_id == identity.installation_id && *origin_node_id == identity.node_id),
            "backup namespace differs from the retained installed owner"
        );
        Ok(())
    }
}

pub(crate) fn open_destinations(
    configured: &BTreeMap<String, DestinationConfig>,
    disk: Arc<NodeDisk>,
    standalone: Option<&crate::standalone::InstalledStandaloneOwner>,
    verifier: Option<&crate::signer_runtime::InstalledSignerVerifier>,
) -> Result<BTreeMap<String, Arc<dyn BackupDestination>>> {
    ensure!(
        standalone.is_none() || verifier.is_none(),
        "ambiguous installed backup owner"
    );
    let owner = standalone
        .map(InstalledOwner::Standalone)
        .or_else(|| verifier.map(InstalledOwner::Replicated));
    configured
        .iter()
        .map(|(alias, destination)| {
            Ok((
                alias.clone(),
                destination.open(disk.clone(), owner.as_ref())?,
            ))
        })
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub format: u32,
    pub destination: String,
    pub directory: PathBuf,
    pub max_bytes: usize,
    /// Stable caller-selected identity, retained for an uncertain retry.
    pub namespace_id: Uuid,
}
impl EnrollmentRequest {
    fn validate(&self, config: &RuntimeConfig) -> Result<()> {
        ensure!(
            self.format == 1 && !self.namespace_id.is_nil(),
            "invalid backup enrollment request"
        );
        kasumi_types::validate_name(&self.destination)?;
        crate::administration::validate_filesystem_location(&self.directory)?;
        crate::administration::bounded(self.max_bytes)?;
        ensure!(
            !config.backup_destinations.contains_key(&self.destination),
            "backup destination alias is already installed"
        );
        // Validate location without creating even a parent or opening a marker.
        config
            .persistent_disk
            .binding(&self.directory.join("kasumi-backup.marker"))?;
        for destination in config.backup_destinations.values() {
            if let DestinationConfig::Filesystem { directory, .. } = destination {
                ensure!(
                    !self.directory.starts_with(directory)
                        && !directory.starts_with(&self.directory),
                    "backup enrollment overlaps an installed destination"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReceipt {
    pub format: u32,
    pub destination: String,
    /// Exact observed marker binding, never a caller-supplied inode/device.
    pub configuration: DestinationConfig,
}
struct Completed(EnrollmentReceipt);
impl crate::startup_owner::Runtime for Completed {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

#[inline(never)]
pub(crate) fn enroll_with_storage(
    config: RuntimeConfig,
    request: EnrollmentRequest,
    storage: crate::runtime_memory::RuntimeStorage,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<EnrollmentReceipt>> + Send>> {
    Box::pin(async move {
        config.validate()?;
        request.validate(&config)?;
        storage.require_policy(&config.admission)?;
        Ok(
            crate::startup_owner::open(crate::startup_owner::Kind::LocalOperator, async move {
                let mut pending = crate::startup_resources::Resources::default();
                let outcome =
                    crate::startup_preparation::capture("backup destination enrollment", async {
                        let admission = storage.facade(&config.admission)?;
                        pending.owned_admissions.push(admission.clone());
                        let disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
                        pending.standalone_owner = crate::standalone::claim(&config, &disk)?;
                        if let Some(configured) = &config.signer_verifier {
                            let mut domains = BTreeMap::new();
                            for authority in config.serving_authorities.values() {
                                for partition in authority.manifest.partitions.keys() {
                                    let domain = authority.manifest.signing_domain(*partition)?;
                                    domains.insert(domain.digest()?, domain);
                                }
                            }
                            let verifier = configured
                                .open(
                                    domains,
                                    Arc::new(crate::runtime::file_secret),
                                    disk.clone(),
                                    storage.open_scratch(&config.scratch_disk)?,
                                    admission,
                                )
                                .await?;
                            pending.verifiers.push(verifier);
                        }
                        ensure!(
                            pending.standalone_owner.is_none() || pending.verifiers.is_empty(),
                            "ambiguous installed backup owner"
                        );
                        let owner = if let Some(owner) = &pending.standalone_owner {
                            InstalledOwner::Standalone(owner)
                        } else {
                            InstalledOwner::Replicated(pending.verifiers.first().context(
                                "backup enrollment requires an original installed owner",
                            )?)
                        };
                        let identity = owner.identity_for(&disk)?;
                        let destination = FilesystemBackupDestination::enroll(
                            &request.directory,
                            request.max_bytes,
                            disk.clone(),
                            &identity,
                            request.namespace_id,
                        )?;
                        let namespace_binding = destination.namespace_binding()?;
                        owner.require_binding(&disk, &namespace_binding)?;
                        Ok(EnrollmentReceipt {
                            format: 1,
                            destination: request.destination,
                            configuration: DestinationConfig::Filesystem {
                                directory: request.directory,
                                max_bytes: request.max_bytes,
                                namespace_binding,
                            },
                        })
                    })
                    .await;
                let drained = crate::startup_owner::finish(&mut pending).await;
                match (outcome, drained) {
                    (Ok(receipt), Ok(())) => Ok(Completed(receipt)),
                    (Err(error), Ok(())) => Err(error),
                    (Ok(_), Err(drain)) => Err(drain.into()),
                    (Err(error), Err(drain)) => Err(error.context(drain)),
                }
            })
            .await?
            .0,
        )
    })
}

pub(crate) async fn command(config: &Path, request: &Path, output: &Path) -> Result<()> {
    ensure!(
        output.is_absolute(),
        "backup enrollment receipt must be absolute"
    );
    private_files::check_directory(output.parent().context("receipt parent is absent")?)?;
    match std::fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => anyhow::bail!("backup enrollment receipt already exists or is inaccessible"),
    }
    let config = RuntimeConfig::load(config)?;
    // An operator receipt is separate from managed runtime storage. Writing it
    // beneath a NodeDisk root would bypass that root's admitted file creation.
    let selected = std::fs::canonicalize(output.parent().context("receipt parent is absent")?)?
        .join(output.file_name().context("receipt filename is absent")?);
    for root in config
        .persistent_disk
        .roots
        .values()
        .chain(std::iter::once(&config.scratch_disk.directory))
    {
        ensure!(
            !selected.starts_with(std::fs::canonicalize(root)?),
            "backup enrollment receipt must be outside managed storage roots"
        );
    }
    let request: EnrollmentRequest =
        serde_json::from_slice(&crate::runtime::read_bounded(request, 64 << 10)?)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    let receipt = enroll_with_storage(config, request, storage).await?;
    // No configuration is rewritten. If output publication fails, the actual
    // enrolled root remains; the same stable request may capture it again.
    private_files::create(output, &serde_json::to_vec(&receipt)?)?;
    Ok(())
}

#[cfg(test)]
#[path = "backup_destination_installation_tests.rs"]
mod tests;
