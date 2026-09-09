//! Explicit first enrollment of a node file and its service audit. Application,
//! Control and authority catalogs/bootstrap require their own installation.
use anyhow::{Context, Result};
use kasumi_store::{
    NodeStore, ScratchDisk, ScratchDiskConfig, StorageAccess, TenantStore, private_files,
};
use std::{path::Path, sync::Arc};
use uuid::Uuid;

pub(crate) async fn create(
    path: &Path,
    database_id: Uuid,
    scratch: &ScratchDiskConfig,
    security: &crate::runtime::SecurityAuditConfig,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Result<()> {
    private_files::check_directory(path.parent().context("node database directory is absent")?)?;
    security.validate()?;
    let provider = security
        .keys
        .provider(Arc::new(crate::runtime::file_secret))?;
    let disk = ScratchDisk::open(scratch.clone())?;
    let node = NodeStore::create_new(path, database_id, disk)?;
    let store = TenantStore::open(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        provider,
        StorageAccess::security_audit(),
    )
    .await?;
    let opened = security.initialize(store.clone(), admission);
    if let Ok(audit) = &opened {
        audit.shutdown().await;
    }
    store.shutdown().await;
    opened?;
    drop(store);
    drop(node);
    Ok(())
}
