//! Explicit first installation of an independently encrypted target journal.
//! A partially created installation is never adopted by normal daemon startup.
use crate::{
    runtime::{RuntimeConfig, file_secret},
    target_runtime_config::TargetRecoveryConfig,
};
use anyhow::{Context, Result};
use kasumi_engine::{TargetJournal, TargetJournalInstallation};
use kasumi_store::{NodeStore, StorageAccess, TenantStore, node_store_ids};
use std::{path::Path, sync::Arc};

pub async fn initialize_from_file(path: &Path) -> Result<()> {
    initialize(RuntimeConfig::load(path)?).await
}

/// The owned initializer retains its actual file/store owners through drain if
/// its caller is cancelled. Existing, partial or uncertain files are not reset.
pub async fn initialize(config: RuntimeConfig) -> Result<()> {
    config.validate()?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    initialize_with_storage(config, storage).await
}

pub(crate) async fn initialize_with_storage(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    config.validate()?;
    storage.require_policy(&config.admission)?;
    crate::startup_owner::open(
        crate::startup_owner::Kind::TargetJournal,
        initialize_owned(config, storage),
    )
    .await?;
    Ok(())
}

/// Join cancelled installation attempts and preserve their original failures.
pub async fn drain_initializations() -> Result<()> {
    crate::startup_owner::drain(crate::startup_owner::Kind::TargetJournal).await
}

struct Initialized;
impl crate::startup_owner::Runtime for Initialized {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

async fn initialize_owned(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Initialized> {
    let installed: &TargetRecoveryConfig = config
        .target_recovery
        .as_ref()
        .context("target recovery is not configured")?;
    let admission = storage.facade(&config.admission)?;
    let mut pending = crate::startup_resources::Resources::default();
    pending.owned_admissions.push(admission.clone());
    let scratch = storage.open_scratch(&config.scratch_disk)?;
    let id = node_store_ids::target_journal(
        installed.control_root.control_incarnation,
        &installed.node.verifier,
    )?;
    let prepared = crate::startup_preparation::capture("target journal installation", async {
        let node = NodeStore::create_new(
            &installed.journal_path,
            id,
            crate::persistent_disk::open(&config.persistent_disk, &storage)?,
            scratch,
        )?;
        pending.owned_nodes.push(node.clone());
        let store = TenantStore::initialize_catalog(
            node.clone(),
            format!(
                "kasumi.target.{}.{}",
                installed.control_root.control_incarnation, installed.node.node_id
            ),
            installed.journal_keys.provider(Arc::new(file_secret))?,
            StorageAccess::target_journal(&installed.control_root, &installed.node)?,
        )
        .await?;
        pending.stores.push(store.clone());
        node.drain_initializers().await?;
        let journal = TargetJournal::create_new(
            store,
            TargetJournalInstallation {
                root: installed.control_root.clone(),
                node: installed.node.clone(),
            },
            installed.limits.journal.clone(),
            admission,
        )?;
        pending.journals.push(journal);
        Ok(())
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    match (prepared, drained) {
        (Ok(()), Ok(())) => Ok(Initialized),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
}
