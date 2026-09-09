//! Explicit first installation of an independently encrypted target journal.
//! A partially created installation is never adopted by normal daemon startup.
use crate::{
    runtime::{RuntimeConfig, file_secret},
    target_runtime_config::TargetRecoveryConfig,
};
use anyhow::{Context, Result};
use kasumi_engine::{TargetJournal, TargetJournalInstallation, admission::NodeAdmission};
use kasumi_store::{NodeStore, ScratchDisk, StorageAccess, TenantStore, node_store_ids};
use std::{path::Path, sync::Arc};

pub async fn initialize_from_file(path: &Path) -> Result<()> {
    initialize(RuntimeConfig::load(path)?).await
}

/// The owned initializer retains its actual file/store owners through drain if
/// its caller is cancelled. Existing, partial or uncertain files are not reset.
pub async fn initialize(config: RuntimeConfig) -> Result<()> {
    config.validate()?;
    tokio::spawn(async move { initialize_owned(config).await }).await?
}

async fn initialize_owned(config: RuntimeConfig) -> Result<()> {
    let installed: &TargetRecoveryConfig = config
        .target_recovery
        .as_ref()
        .context("target recovery is not configured")?;
    let admission = NodeAdmission::new(config.admission.clone())?;
    let scratch = ScratchDisk::open(config.scratch_disk.clone())?;
    let id = node_store_ids::target_journal(
        installed.control_root.control_incarnation,
        &installed.node.verifier,
    )?;
    let node = NodeStore::create_new(&installed.journal_path, id, scratch)?;
    let prepared = TenantStore::initialize_catalog(
        node.clone(),
        format!(
            "kasumi.target.{}.{}",
            installed.control_root.control_incarnation, installed.node.node_id
        ),
        installed.journal_keys.provider(Arc::new(file_secret))?,
        StorageAccess::target_journal(&installed.control_root, &installed.node)?,
    )
    .await;
    let drained = node.drain_initializers().await;
    let store = match (prepared, drained) {
        (Ok(store), Ok(())) => store,
        (Ok(store), Err(error)) => {
            store.shutdown().await;
            return Err(error);
        }
        (Err(error), Ok(())) => return Err(error),
        (Err(error), Err(drain)) => {
            return Err(error.context(format!("singleton drain failed: {drain:#}")));
        }
    };
    let result = TargetJournal::create_new(
        store.clone(),
        TargetJournalInstallation {
            root: installed.control_root.clone(),
            node: installed.node.clone(),
        },
        installed.limits.journal.clone(),
        admission,
    );
    if let Ok(journal) = &result {
        journal.shutdown().await;
    }
    store.shutdown().await;
    drop(store);
    drop(node);
    result.map(|_| ())
}
