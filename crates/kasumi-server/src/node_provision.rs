//! Explicit first-enrollment file creation. This establishes only the node-file
//! envelope and encrypted-storage tables, not HA tenant/catalog/bootstrap state.
use anyhow::{Context, Result};
use kasumi_store::{NodeStore, ScratchDisk, ScratchDiskConfig, private_files};
use std::path::Path;
use uuid::Uuid;

pub(crate) fn create(path: &Path, database_id: Uuid, scratch: &ScratchDiskConfig) -> Result<()> {
    private_files::check_directory(path.parent().context("node database directory is absent")?)?;
    let disk = ScratchDisk::open(scratch.clone())?;
    let node = NodeStore::create_new(path, database_id, disk)?;
    // No worker or tenant is started. Drop closes the actual redb descriptor
    // before this synchronous operator command reports completion.
    drop(node);
    Ok(())
}
