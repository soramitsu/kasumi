//! Installed archive locations. The canonical segment bound is always 8 MiB;
//! expandable retained-byte capacity belongs to the audit retention budget.
use crate::administration::DestinationConfig;
use anyhow::Result;
use kasumi_store::{AuditArchiveDestination, FilesystemAuditArchive, S3AuditArchive};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditDestinationConfig {
    Filesystem {
        directory: PathBuf,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        credentials_file: PathBuf,
        ca_certificate: Option<PathBuf>,
    },
}
impl AuditDestinationConfig {
    fn bounded_destination(&self) -> DestinationConfig {
        let max_bytes = kasumi_types::MAX_AUDIT_SEGMENT_BYTES;
        match self {
            Self::Filesystem { directory } => DestinationConfig::Filesystem {
                directory: directory.clone(),
                max_bytes,
            },
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
            } => DestinationConfig::S3 {
                endpoint: endpoint.clone(),
                region: region.clone(),
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                credentials_file: credentials_file.clone(),
                ca_certificate: ca_certificate.clone(),
                max_bytes,
            },
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.bounded_destination().validate()
    }
    pub(crate) fn open(
        &self,
        persistent_disk: Arc<kasumi_store::NodeDisk>,
    ) -> Result<Arc<dyn AuditArchiveDestination>> {
        self.validate()?;
        Ok(match self {
            Self::Filesystem { directory } => {
                Arc::new(FilesystemAuditArchive::open(directory, persistent_disk)?)
            }
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
            } => Arc::new(S3AuditArchive::new(Arc::new(
                kasumi_store::S3BackupDestination::new(kasumi_store::S3BackupConfig {
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    bucket: bucket.clone(),
                    prefix: prefix.clone(),
                    credential: Arc::new(kasumi_transport::credentials::FileCredentialSource::new(
                        credentials_file,
                    )?),
                    ca_pem: ca_certificate
                        .as_ref()
                        .map(|path| crate::runtime::read_bounded(path, 1 << 20))
                        .transpose()?,
                    max_bytes: kasumi_types::MAX_AUDIT_SEGMENT_BYTES,
                })?,
            ))),
        })
    }
}

impl crate::runtime::RuntimeConfig {
    /// Install before bootstrap publication or any Raft replay. The encrypted
    /// placement binding rejects a missing/replaced external destination on
    /// restart; this helper never falls back after an S3 publication failure.
    /// Recovery may supply an exclusively owned cache with a durable publication
    /// observer while retaining the same installed external destination.
    pub(crate) fn install_tenant_audit_archive(
        &self,
        store: &Arc<kasumi_store::TenantStore>,
        cache: Option<Arc<FilesystemAuditArchive>>,
    ) -> Result<()> {
        let cache = match cache {
            Some(cache) => cache,
            None => Arc::new(FilesystemAuditArchive::open(
                store.durable_directory()?.join("tenant-audit-archives"),
                store.persistent_disk().clone(),
            )?),
        };
        let destination = match self.tenant_audit_archives.get(store.tenant()) {
            Some(destination) => destination.open(store.persistent_disk().clone())?,
            None => cache.clone() as Arc<dyn AuditArchiveDestination>,
        };
        store.install_tenant_audit_archive(cache, destination)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};

    #[test]
    fn archive_installation_map_is_an_explicit_first_release_field() {
        let mut encoded = serde_json::to_value(crate::runtime::example_config()).unwrap();
        serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded.clone()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("tenant_audit_archives");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded).is_err());
    }

    #[tokio::test]
    async fn restart_requires_the_exact_installed_external_archive_and_supplied_cache() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("node.redb");
        let provider = Arc::new(LocalKeyProvider::new([73; 32]));
        let node = NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let cache = Arc::new(
            FilesystemAuditArchive::open_fixture(directory.path().join("owned-cache")).unwrap(),
        );
        let mut installed = crate::runtime::example_config();
        installed.tenant_audit_archives.insert(
            "tenant".into(),
            AuditDestinationConfig::Filesystem {
                directory: directory.path().join("external-archive"),
            },
        );
        installed
            .install_tenant_audit_archive(&store, Some(cache.clone()))
            .unwrap();
        assert_eq!(
            store.tenant_audit_archive().unwrap().cache().identity(),
            cache.identity()
        );
        store.shutdown().await.unwrap();
        drop(store);
        drop(node);
        let node = NodeStore::open_existing_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let reopened = TenantStore::open_existing_fixture(node, "tenant".into(), provider)
            .await
            .unwrap();
        let empty = crate::runtime::example_config();
        assert!(
            empty
                .install_tenant_audit_archive(&reopened, Some(cache.clone()))
                .is_err()
        );
        assert!(
            installed
                .install_tenant_audit_archive(&reopened, None)
                .is_err()
        );
        installed
            .install_tenant_audit_archive(&reopened, Some(cache))
            .unwrap();
        assert!(reopened.tenant_audit_archive().is_ok());
        reopened.shutdown().await.unwrap();
    }
}
