//! Exclusive first enrollment of a node file and its service audit. The caller
//! retains this same physical owner through application/Control/authority genesis.
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
) -> Result<(Arc<NodeStore>, Arc<kasumi_engine::SecurityAudit>)> {
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
    match security.initialize(store.clone(), admission) {
        Ok(audit) => Ok((node, audit)),
        Err(error) => {
            store.shutdown().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn enrollment_retains_one_exclusive_node_owner_until_audit_and_node_drain() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let keys = directory.path().join("security.json");
        kasumi_store::FileKeyProvider::initialize(&keys, "security")?;
        let security = crate::runtime::SecurityAuditConfig {
            keys: crate::runtime::KeyProviderSettings::File { path: keys },
            retention: Default::default(),
            archive: None,
        };
        let scratch = ScratchDiskConfig {
            directory: directory.path().join("scratch"),
            max_bytes: 64 << 20,
            min_free_bytes: 0,
        };
        let path = directory.path().join("node.redb");
        let database_id = Uuid::new_v4();
        let admission = kasumi_engine::admission::NodeAdmission::new(Default::default())?;
        let (node, audit) =
            create(&path, database_id, &scratch, &security, admission.clone()).await?;
        audit.store().write_batch(&[kasumi_store::WriteOp::put(
            "enrollment-test",
            b"retained",
            b"original owner".to_vec(),
        )])?;
        assert!(
            NodeStore::open_existing(&path, database_id, ScratchDisk::open(scratch.clone())?)
                .is_err()
        );
        assert!(
            create(&path, database_id, &scratch, &security, admission.clone())
                .await
                .is_err()
        );
        audit.shutdown().await;
        drop(audit);
        // Audit shutdown cannot release the independently retained physical node.
        assert!(
            NodeStore::open_existing(&path, database_id, ScratchDisk::open(scratch.clone())?)
                .is_err()
        );
        drop(node);
        let node = NodeStore::open_existing(&path, database_id, ScratchDisk::open(scratch)?)?;
        let store = TenantStore::open_existing(
            node,
            kasumi_engine::SECURITY_TENANT.into(),
            security
                .keys
                .provider(Arc::new(crate::runtime::file_secret))?,
            StorageAccess::security_audit(),
        )
        .await?;
        let audit = security.open(store.clone(), admission)?;
        assert_eq!(
            store.get("enrollment-test", b"retained")?,
            Some(b"original owner".to_vec())
        );
        audit.shutdown().await;
        Ok(())
    }
}
