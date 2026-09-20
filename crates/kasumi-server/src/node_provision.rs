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
    persistent: &kasumi_store::NodeDiskConfig,
    scratch: &ScratchDiskConfig,
    security: &crate::runtime::SecurityAuditConfig,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Result<(Arc<NodeStore>, Arc<kasumi_engine::SecurityAudit>)> {
    let mut pending = crate::startup_resources::Resources::default();
    let outcome = crate::startup_preparation::capture("node provisioning", async {
        private_files::check_directory(
            path.parent().context("node database directory is absent")?,
        )?;
        security.validate()?;
        let provider = security
            .keys
            .provider(Arc::new(crate::runtime::file_secret))?;
        let disk = ScratchDisk::open(scratch.clone())?;
        crate::persistent_disk::validate(persistent, scratch, [path])?;
        let node = NodeStore::create_new(
            path,
            database_id,
            crate::persistent_disk::open(persistent)?,
            disk,
        )?;
        pending.owned_nodes.push(node.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(database_id, "node-provision-node");
        let store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            provider,
            StorageAccess::security_audit(),
        )
        .await?;
        pending.stores.push(store.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(database_id, "node-provision-store");
        node.drain_initializers().await?;
        let audit = security.initialize(store, admission)?;
        pending.audits.push(audit.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(database_id, "node-provision-audit");
        Ok((node, audit))
    })
    .await;
    match outcome {
        Ok(owners) => Ok(owners),
        Err(error) => match crate::startup_owner::finish(&mut pending).await {
            Ok(()) => Err(error),
            Err(drain) => Err(error.context(drain)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn enrollment_retains_one_exclusive_node_owner_until_audit_and_node_drain() -> Result<()>
    {
        let directory = kasumi_store::test_utils::private_tempdir()?;
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
        let persistent = crate::persistent_disk::fixture_config(&directory.path().join("data"));
        let path = directory.path().join("data/node.redb");
        let database_id = Uuid::new_v4();
        let admission = kasumi_engine::admission::NodeAdmission::new(Default::default())?;
        let (node, audit) = create(
            &path,
            database_id,
            &persistent,
            &scratch,
            &security,
            admission.clone(),
        )
        .await?;
        audit.store().write_batch(&[kasumi_store::WriteOp::put(
            "enrollment-test",
            b"retained",
            b"original owner".to_vec(),
        )])?;
        assert!(
            NodeStore::open_existing_fixture(
                &path,
                database_id,
                ScratchDisk::open(scratch.clone())?
            )
            .is_err()
        );
        assert!(
            create(
                &path,
                database_id,
                &persistent,
                &scratch,
                &security,
                admission.clone()
            )
            .await
            .is_err()
        );
        audit.shutdown().await.unwrap();
        drop(audit);
        // Audit shutdown cannot release the independently retained physical node.
        assert!(
            NodeStore::open_existing_fixture(
                &path,
                database_id,
                ScratchDisk::open(scratch.clone())?
            )
            .is_err()
        );
        node.shutdown().await?;
        node.shutdown().await?;
        drop(node);
        let node =
            NodeStore::open_existing_fixture(&path, database_id, ScratchDisk::open(scratch)?)?;
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
        audit.shutdown().await.unwrap();
        Ok(())
    }
}
