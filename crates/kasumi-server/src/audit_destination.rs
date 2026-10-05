//! Installed archive locations. The canonical segment bound is always 8 MiB;
//! expandable retained-byte capacity belongs to the audit retention budget.
use anyhow::{Context, Result, ensure};
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
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Filesystem { directory } => {
                crate::administration::validate_filesystem_location(directory)
            }
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
            } => crate::administration::validate_s3_location(
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate.as_deref(),
            ),
        }
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

/// Every installed tenant chooses a policy explicitly. The external form owns
/// an independent destination while retaining a private dependency cache.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantAuditPlacementConfig {
    LocalReplicaOnly,
    External { destination: AuditDestinationConfig },
}

impl<'de> Deserialize<'de> for TenantAuditPlacementConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Serde's internally tagged unit visitor ignores extra fields. Decode
        // local placement as a closed empty struct so every choice is strict.
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum InstalledChoice {
            LocalReplicaOnly {},
            External { destination: AuditDestinationConfig },
        }
        Ok(match InstalledChoice::deserialize(deserializer)? {
            InstalledChoice::LocalReplicaOnly {} => Self::LocalReplicaOnly,
            InstalledChoice::External { destination } => Self::External { destination },
        })
    }
}

pub(crate) fn deserialize_tenant_audit_placements<'de, D>(
    deserializer: D,
) -> std::result::Result<std::collections::BTreeMap<String, TenantAuditPlacementConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Placements;
    impl<'de> serde::de::Visitor<'de> for Placements {
        type Value = std::collections::BTreeMap<String, TenantAuditPlacementConfig>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an explicit tenant audit placement map without duplicate rows")
        }
        fn visit_map<M>(self, mut entries: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut placements = std::collections::BTreeMap::new();
            while let Some((tenant, placement)) =
                entries.next_entry::<String, TenantAuditPlacementConfig>()?
            {
                if placements.len() == 10_001 || placements.insert(tenant, placement).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive tenant audit placement rows",
                    ));
                }
            }
            Ok(placements)
        }
    }
    deserializer.deserialize_map(Placements)
}

impl TenantAuditPlacementConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::LocalReplicaOnly => Ok(()),
            Self::External { destination } => destination.validate(),
        }
    }

    /// Bind the exact installed choice before a recovery operation can open
    /// its cache or publish externally. Credential contents are deliberately
    /// outside this configuration identity and may be refreshed in place.
    pub(crate) fn canonical_binding(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"kasumi.tenant-audit-placement.v1\0");
        digest.update(serde_json::to_vec(self)?);
        Ok(hex::encode(digest.finalize()))
    }

    pub(crate) fn install(
        &self,
        store: &Arc<kasumi_store::TenantStore>,
        cache: Option<Arc<FilesystemAuditArchive>>,
    ) -> Result<()> {
        self.validate()?;
        let cache = match cache {
            Some(cache) => cache,
            None => Arc::new(FilesystemAuditArchive::open(
                store.durable_directory()?.join("tenant-audit-archives"),
                store.persistent_disk().clone(),
            )?),
        };
        cache.validate_cache_custody(store.persistent_disk())?;
        let destination: Arc<dyn AuditArchiveDestination> = match self {
            Self::LocalReplicaOnly => cache.clone(),
            Self::External { destination } => {
                let destination: Arc<dyn AuditArchiveDestination> = match destination {
                    AuditDestinationConfig::Filesystem { directory } => {
                        let destination = Arc::new(FilesystemAuditArchive::open(
                            directory,
                            store.persistent_disk().clone(),
                        )?);
                        cache.validate_external_destination(&destination)?;
                        destination
                    }
                    AuditDestinationConfig::S3 { .. } => {
                        destination.open(store.persistent_disk().clone())?
                    }
                };
                ensure!(
                    destination.identity() != cache.identity(),
                    "external tenant audit destination is the local replica cache"
                );
                destination
            }
        };
        store.install_tenant_audit_archive(cache, destination)?;
        Ok(())
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
        // Resolve before creating even the local cache or reading a credential.
        self.tenant_audit_placement(store.tenant())?
            .install(store, cache)
    }

    pub(crate) fn tenant_audit_placement(
        &self,
        tenant: &str,
    ) -> Result<&TenantAuditPlacementConfig> {
        let placement = self
            .tenant_audit_placements
            .get(tenant)
            .context("tenant audit placement must be explicitly installed")?;
        placement.validate()?;
        Ok(placement)
    }

    pub(crate) fn validate_tenant_audit_placements(&self) -> Result<()> {
        let expected: std::collections::BTreeSet<_> =
            std::iter::once(crate::runtime::CONTROL_TENANT)
                .chain(self.tenants.iter().map(|tenant| tenant.tenant.as_str()))
                .collect();
        ensure!(
            expected.len() == self.tenants.len() + 1
                && self.tenant_audit_placements.len() == expected.len()
                && expected
                    .iter()
                    .all(|tenant| self.tenant_audit_placements.contains_key(*tenant)),
            "tenant audit placements must cover exactly Control and configured tenants"
        );
        for placement in self.tenant_audit_placements.values() {
            placement.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};

    #[test]
    fn archive_installation_map_is_an_explicit_first_release_field() {
        let mut encoded = serde_json::to_value(
            crate::runtime::example_config(
                kasumi_store::DirectoryPolicy::fixture(),
                kasumi_store::FileAllocationPolicy::fixture(),
            )
            .unwrap(),
        )
        .unwrap();
        serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded.clone()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("tenant_audit_placements");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded).is_err());
    }

    #[test]
    fn placement_shapes_reject_missing_legacy_and_extra_choices() {
        let local = serde_json::json!({"kind": "local_replica_only"});
        let filesystem = serde_json::json!({
            "kind": "external",
            "destination": {"kind": "filesystem", "directory": "/var/lib/kasumi/archives/acme"}
        });
        let s3 = serde_json::json!({
            "kind": "external",
            "destination": {
                "kind": "s3", "endpoint": "https://minio.example", "region": "local",
                "bucket": "audit", "prefix": "acme", "credentials_file": "/etc/kasumi/s3.json",
                "ca_certificate": null
            }
        });
        for choice in [&local, &filesystem, &s3] {
            let decoded: TenantAuditPlacementConfig =
                serde_json::from_value(choice.clone()).unwrap();
            decoded.validate().unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), *choice);
        }
        for unsupported in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"kind": "filesystem", "directory": "/var/lib/kasumi/archives/acme"}),
            serde_json::json!({"kind": "external"}),
            serde_json::json!({"kind": "external", "destination": null}),
            serde_json::json!({"kind": "local_replica_only", "destination": null}),
            serde_json::json!({"kind": "local_replica_only", "unknown": true}),
            serde_json::json!({"kind": "external", "destination": filesystem["destination"], "unknown": true}),
            serde_json::json!({"kind": "local"}),
        ] {
            assert!(
                serde_json::from_value::<TenantAuditPlacementConfig>(unsupported.clone()).is_err(),
                "{unsupported}"
            );
        }
        let local: TenantAuditPlacementConfig = serde_json::from_value(local).unwrap();
        let external: TenantAuditPlacementConfig = serde_json::from_value(filesystem).unwrap();
        assert_ne!(
            local.canonical_binding().unwrap(),
            external.canonical_binding().unwrap()
        );
    }

    #[test]
    fn runtime_load_requires_exact_complete_placement_rows() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let path = directory.path().join("kasumi.json");
        let config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )?;
        let original = serde_json::to_value(&config)?;
        std::fs::write(&path, serde_json::to_vec(&original)?)?;
        crate::runtime::RuntimeConfig::load(&path)?;
        for replacement in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"acme": {"kind": "local_replica_only"}}),
            serde_json::json!({"__kasumi_control": {"kind": "local_replica_only"}}),
            serde_json::json!({
                "__kasumi_control": {"kind": "local_replica_only"},
                "acme": {"kind": "filesystem", "directory": "/var/lib/kasumi/archives/acme"}
            }),
        ] {
            let mut encoded = original.clone();
            encoded["tenant_audit_placements"] = replacement;
            std::fs::write(&path, serde_json::to_vec(&encoded)?)?;
            assert!(crate::runtime::RuntimeConfig::load(&path).is_err());
        }
        for extra in [
            "unknown",
            crate::runtime::SECURITY_TENANT,
            "kasumi.custody/acme",
        ] {
            let mut encoded = original.clone();
            encoded["tenant_audit_placements"][extra] =
                serde_json::json!({"kind": "local_replica_only"});
            std::fs::write(&path, serde_json::to_vec(&encoded)?)?;
            assert!(
                crate::runtime::RuntimeConfig::load(&path).is_err(),
                "{extra}"
            );
        }
        let mut old = original.clone();
        let placements = old
            .as_object_mut()
            .unwrap()
            .remove("tenant_audit_placements")
            .unwrap();
        old["tenant_audit_archives"] = placements;
        std::fs::write(&path, serde_json::to_vec(&old)?)?;
        assert!(crate::runtime::RuntimeConfig::load(&path).is_err());

        let mut external = original.clone();
        external["tenant_audit_placements"]["acme"] = serde_json::json!({
            "kind": "external", "destination": {
                "kind": "filesystem", "directory": "/var/lib/kasumi/archives/acme"
            }
        });
        std::fs::write(&path, serde_json::to_vec(&external)?)?;
        crate::runtime::RuntimeConfig::load(&path)?;

        let serialized = serde_json::to_string(&original)?;
        let field = format!(
            "\"tenant_audit_placements\":{}",
            serde_json::to_string(&original["tenant_audit_placements"])?
        );
        let duplicate = serialized.replacen(&field, "\"tenant_audit_placements\":{\"__kasumi_control\":{\"kind\":\"local_replica_only\"},\"acme\":{\"kind\":\"local_replica_only\"},\"acme\":{\"kind\":\"local_replica_only\"}}", 1);
        assert_ne!(serialized, duplicate);
        std::fs::write(&path, duplicate)?;
        let error = crate::runtime::RuntimeConfig::load(&path).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate"));
        Ok(())
    }

    #[test]
    fn target_template_requires_its_own_explicit_choice() {
        let config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        let template = crate::target_runtime_config::TargetTenantTemplate {
            authority: "storage-fence".into(),
            audit_placement: TenantAuditPlacementConfig::LocalReplicaOnly,
            application_keys: config.tenants[0].keys.clone(),
            custody_keys: config.tenants[0].custody_keys.clone(),
            source_backups: Default::default(),
        };
        let original = serde_json::to_value(template).unwrap();
        for omitted in [None, Some(serde_json::Value::Null)] {
            let mut encoded = original.clone();
            match omitted {
                None => {
                    encoded.as_object_mut().unwrap().remove("audit_placement");
                }
                Some(value) => encoded["audit_placement"] = value,
            }
            assert!(
                serde_json::from_value::<crate::target_runtime_config::TargetTenantTemplate>(
                    encoded
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn missing_placement_rejects_before_cache_creation_and_binding() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())?;
        let node = physical
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .expect("audit placement fixture must create its installed native node");
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([74; 32])),
        )
        .await?;
        let cache = store.durable_directory()?.join("tenant-audit-archives");
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )?;
        assert!(!cache.try_exists()?);
        assert!(config.install_tenant_audit_archive(&store, None).is_err());
        assert!(!cache.try_exists()?);
        assert!(store.tenant_audit_archive().is_err());
        config.tenant_audit_placements.insert(
            "tenant".into(),
            TenantAuditPlacementConfig::LocalReplicaOnly,
        );
        config.install_tenant_audit_archive(&store, None)?;
        assert!(cache.is_dir());
        assert_eq!(
            store.tenant_audit_archive()?.cache().identity(),
            store.tenant_audit_archive()?.destination_identity()
        );
        store.shutdown().await?;
        drop(store);
        node.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn external_choice_cannot_publish_a_supplied_cache_as_external_history() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())?;
        let node = physical
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .expect("external audit placement fixture must create its installed native node");
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([75; 32])),
        )
        .await?;
        let cache_path = directory.path().join("persistent/owned-cache");
        let cache = Arc::new(FilesystemAuditArchive::open(
            &cache_path,
            physical.persistent.clone(),
        )?);
        let external = TenantAuditPlacementConfig::External {
            destination: AuditDestinationConfig::Filesystem {
                directory: cache_path.join("."),
            },
        };
        assert!(external.install(&store, Some(cache.clone())).is_err());
        assert!(store.tenant_audit_archive().is_err());
        TenantAuditPlacementConfig::LocalReplicaOnly.install(&store, Some(cache.clone()))?;
        assert_eq!(
            store.tenant_audit_archive()?.cache().identity(),
            cache.identity()
        );
        store.shutdown().await?;
        drop(store);
        node.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn restart_requires_the_exact_installed_external_archive_and_supplied_cache() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                .unwrap();
        let path = directory.path().join("persistent/node.kv");
        let provider = Arc::new(LocalKeyProvider::new([73; 32]));
        let node = physical
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant".into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let cache = Arc::new(
            FilesystemAuditArchive::open(
                directory.path().join("persistent/owned-cache"),
                physical.persistent.clone(),
            )
            .unwrap(),
        );
        let mut installed = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        installed.tenant_audit_placements.insert(
            "tenant".into(),
            TenantAuditPlacementConfig::External {
                destination: AuditDestinationConfig::Filesystem {
                    directory: directory.path().join("persistent/external-archive"),
                },
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
        node.shutdown().await.unwrap();
        drop(node);
        let node = physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let reopened = TenantStore::open_existing_fixture(node.clone(), "tenant".into(), provider)
            .await
            .unwrap();
        let empty = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
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
        node.shutdown().await.unwrap();
    }
}
