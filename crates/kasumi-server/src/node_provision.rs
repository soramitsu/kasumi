//! Exclusive first enrollment of a node file and its service audit. The caller
//! retains this same physical owner through application/Control/authority genesis.
use anyhow::{Context, Result};
use kasumi_store::{NodeStore, ScratchDiskConfig, StorageAccess, TenantStore, private_files};
use std::{path::Path, sync::Arc};
use uuid::Uuid;

#[allow(
    clippy::result_large_err,
    reason = "the native constructor returns whole inline custody into the same preadmitted inventory before any foreign marker; boxing the error would allocate outside that boundary"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "the original initial inventory is mandatory alongside the physical policies and successful-owner staging; no fallback donor may be substituted"
)]
pub(crate) async fn create(
    path: &Path,
    database_id: Uuid,
    persistent: &kasumi_store::NodeDiskConfig,
    scratch: &ScratchDiskConfig,
    security: &crate::runtime::SecurityAuditConfig,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    storage: &crate::runtime_memory::RuntimeStorage,
    original_recoveries: &crate::administration::OriginalRecoveries,
) -> Result<(NodeStore, Arc<kasumi_engine::SecurityAudit>)> {
    storage.require_admission(&admission)?;
    let mut pending = crate::startup_resources::Resources::default();
    pending.original_recoveries = Some(original_recoveries.clone());
    let outcome = crate::startup_preparation::capture("node provisioning", async {
        private_files::check_directory(
            path.parent().context("node database directory is absent")?,
        )?;
        security.validate()?;
        let provider = security
            .keys
            .provider(Arc::new(crate::runtime::file_secret))?;
        let disk = storage.open_scratch(scratch)?;
        crate::persistent_disk::validate(persistent, scratch, [path])?;
        let persistent_disk = crate::persistent_disk::open(persistent, storage)?;
        let node = {
            let mut constructor = original_recoveries.claim(0).await;
            constructor
                .begin_node()
                .map_err(|observed| observed.foreign_error())?
                .run_node(|| {
                    NodeStore::create_new(
                        path,
                        database_id,
                        persistent_disk.clone(),
                        disk.clone(),
                        persistent_disk.native_storage_config(),
                    )
                })
                .map_err(|observed| observed.foreign_error())?
        };
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
        node.drain_initializers()
            .await
            .map_err(|failure| failure.observation())?;
        let audit = security.initialize(store, admission)?;
        pending.audits.push(audit.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(database_id, "node-provision-audit");
        Ok((node, audit))
    })
    .await;
    match outcome {
        Ok(owners) => Ok(owners),
        Err(error)
            if pending.owned_nodes.is_empty()
                && pending.stores.is_empty()
                && pending.audits.is_empty()
                && original_recoveries.retained().await =>
        {
            // No successful physical owner entered this scope. The caller
            // retains the same installed seat and census originals; returning
            // the paid foreign observation claims no disposal or refund.
            Err(error)
        }
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
            native_cache_bytes: 8 << 20,
        };
        let persistent = crate::persistent_disk::fixture_config(&directory.path().join("data"));
        let path = directory.path().join("data/node.kv");
        let database_id = Uuid::new_v4();
        let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(
            Default::default(),
            &persistent,
            &scratch,
        )?;
        let admission = storage.facade(storage.policy())?;
        let original_recoveries = crate::administration::OriginalRecoveries::new(
            &admission,
            crate::administration::OriginalRecoveryParticipants::one(
                crate::runtime::CONTROL_TENANT,
            ),
        )?;
        let (node, audit) = create(
            &path,
            database_id,
            &persistent,
            &scratch,
            &security,
            admission.clone(),
            &storage,
            &original_recoveries,
        )
        .await?;
        audit.store().write_batch(&[kasumi_store::WriteOp::put(
            "enrollment-test",
            b"retained",
            b"original owner".to_vec(),
        )])?;
        assert!(
            {
                let native_arg_0 = &path;
                let native_arg_1 = database_id;
                let native_arg_2 = storage.open_persistent(&persistent)?;
                let native_arg_3 = storage.open_scratch(&scratch)?;
                NodeStore::open_existing(
                    native_arg_0,
                    native_arg_1,
                    native_arg_2.clone(),
                    native_arg_3,
                    native_arg_2.native_storage_config(),
                )
            }
            .is_err()
        );
        let duplicate = create(
            &path,
            database_id,
            &persistent,
            &scratch,
            &security,
            admission.clone(),
            &storage,
            &original_recoveries,
        )
        .await
        .err()
        .expect("the existing original node must reject duplicate creation");
        let identity = |original: &kasumi_store::NodeStoreStartFailure| {
            let kasumi_store::NodeStoreStartFailure::Opening(original) = original else {
                panic!("the actual duplicate keeps its opening carrier: {original:?}");
            };
            let report = original.custody().opening().report();
            let kasumi_store::TerminalObservation::Returned(Err(error)) = report.acquisition()
            else {
                panic!("duplicate creation must retain its actual acquisition error");
            };
            let outer: &(dyn std::error::Error + Send + Sync + 'static) = error.as_ref();
            (
                original as *const kasumi_store::NodeStoreOpeningFailure as usize,
                original.opening_id(),
                outer as *const _ as *const () as usize,
            )
        };
        let original_identity = original_recoveries
            .with_node_start_failure(0, identity)
            .await
            .expect("the whole original is resident before its foreign diagnostic");
        drop(duplicate);
        let alias = original_recoveries.clone();
        for _ in 0..3 {
            assert_eq!(
                alias.with_node_start_failure(0, identity).await,
                Some(original_identity)
            );
        }
        assert!(alias.retained().await);
        audit.shutdown().await.unwrap();
        drop(audit);
        // Audit shutdown cannot release the independently retained physical node.
        assert!(
            {
                let native_arg_0 = &path;
                let native_arg_1 = database_id;
                let native_arg_2 = storage.open_persistent(&persistent)?;
                let native_arg_3 = storage.open_scratch(&scratch)?;
                NodeStore::open_existing(
                    native_arg_0,
                    native_arg_1,
                    native_arg_2.clone(),
                    native_arg_3,
                    native_arg_2.native_storage_config(),
                )
            }
            .is_err()
        );
        node.shutdown().await?;
        node.shutdown().await?;
        drop(node);
        {
            let mut constructor = original_recoveries.claim(0).await;
            assert!(!constructor.is_empty());
            let refusal = match constructor.begin_node() {
                Ok(_) => panic!(
                    "actual node drain cannot erase the independent duplicate-start original"
                ),
                Err(refusal) => refusal,
            };
            assert_eq!(refusal.index, 0);
            assert_eq!(refusal.stage, "native_node_start");
        }
        assert_eq!(
            original_recoveries
                .with_node_start_failure(0, identity)
                .await,
            Some(original_identity)
        );
        let node = {
            let native_arg_0 = &path;
            let native_arg_1 = database_id;
            let native_arg_2 = storage.open_persistent(&persistent)?;
            let native_arg_3 = storage.open_scratch(&scratch)?;
            NodeStore::open_existing(
                native_arg_0,
                native_arg_1,
                native_arg_2.clone(),
                native_arg_3,
                native_arg_2.native_storage_config(),
            )
        }
        .expect("the original physical owner has actually drained before this typed reopen");
        let store = TenantStore::open_existing(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            security
                .keys
                .provider(Arc::new(crate::runtime::file_secret))?,
            StorageAccess::security_audit(),
        )
        .await?;
        let audit = security.open(store.clone(), admission)?;
        assert_eq!(
            store.get("enrollment-test", b"retained")?.as_deref(),
            Some(b"original owner".as_slice())
        );
        audit.shutdown().await.unwrap();
        node.shutdown().await?;
        assert_eq!(
            alias.with_node_start_failure(0, identity).await,
            Some(original_identity)
        );
        Ok(())
    }
}
