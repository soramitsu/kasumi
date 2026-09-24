//! Explicit isolated storage policy for server installation fixtures.
use crate::{runtime::RuntimeConfig, runtime_memory::RuntimeStorage};
use anyhow::{Context, Result, ensure};
use kasumi_engine::admission::AdmissionConfig;
use kasumi_store::{NodeDiskConfig, ScratchDiskConfig};
use std::{collections::BTreeMap, path::Path};

/// Existing test policies already include bookkeeping. Add only the exact new
/// metadata owners, once, before creating either physical fixture disk.
pub(crate) fn configure(config: &mut RuntimeConfig) -> Result<RuntimeStorage> {
    let storage = RuntimeStorage::isolated_fixture(
        config.admission.clone(),
        &config.persistent_disk,
        &config.scratch_disk,
    )?;
    config.admission = storage.policy().clone();
    Ok(storage)
}

pub(crate) fn standalone_disks(directory: &Path) -> Result<(NodeDiskConfig, ScratchDiskConfig)> {
    ensure!(
        directory.is_absolute(),
        "fixture installation path must be absolute"
    );
    let parent = directory
        .parent()
        .context("fixture installation parent missing")?;
    let name = directory
        .file_name()
        .context("fixture installation name missing")?;
    let directory = std::fs::canonicalize(parent)?.join(name);
    let persistent = RuntimeStorage::fixture_installation_disk_config(BTreeMap::from([
        ("data".into(), directory.join("data")),
        ("backups".into(), directory.join("backups")),
    ]));
    let scratch = ScratchDiskConfig {
        directory: directory.join("scratch"),
        ..crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture())
            .unwrap()
            .scratch_disk
    };
    Ok((persistent, scratch))
}

pub(crate) fn standalone_storage(
    directory: &Path,
    policy: AdmissionConfig,
) -> Result<RuntimeStorage> {
    let (persistent, scratch) = standalone_disks(directory)?;
    RuntimeStorage::isolated_fixture(policy, &persistent, &scratch)
}

pub(crate) async fn initialize_standalone(
    directory: &Path,
    tenant: &str,
) -> Result<(crate::standalone::InitializedInstallation, RuntimeStorage)> {
    // These fixtures historically used the default total, not the newly
    // generated production installation's explicit 2 GiB policy.
    let storage = standalone_storage(directory, AdmissionConfig::default())?;
    let installed = crate::standalone::initialize_with_storage(
        directory,
        tenant,
        kasumi_store::DirectoryPolicy::fixture(),
        storage.clone(),
    )
    .await?;
    Ok((installed, storage))
}

/// A low-level fixture owns its TempDir in the calling scope. Physical and
/// scratch roots are explicit siblings; the existing total receives only the
/// new installed metadata charges. The facade is admitted before either disk.
pub(crate) fn physical(
    directory: &Path,
    policy: AdmissionConfig,
) -> Result<kasumi_engine::test_utils::FixtureStorage> {
    let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(directory)?;
    kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, policy)
}
