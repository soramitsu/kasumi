//! Explicit installed persistent roots. Configuration validation is read-only;
//! opening never invents a root from a database path or scratch directory.
//! Roots may be on different filesystems; each root is one filesystem.
use anyhow::{Result, ensure};
use kasumi_store::{
    DiskWork, NodeDisk, NodeDiskConfig, NodeDiskDirectory, NodeDiskPhase, ScratchDiskConfig,
};
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) fn validate<'a>(
    config: &NodeDiskConfig,
    scratch: &ScratchDiskConfig,
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<()> {
    config.validate()?;
    scratch.validate()?;
    let installed_path = |path: &Path| {
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
    };
    ensure!(
        installed_path(&scratch.directory),
        "scratch path {} contains parent traversal",
        scratch.directory.display()
    );
    for (name, root) in &config.roots {
        ensure!(
            installed_path(root),
            "persistent root {name} ({}) contains parent traversal",
            root.display()
        );
        ensure!(
            !root.starts_with(&scratch.directory) && !scratch.directory.starts_with(root),
            "persistent root {name} ({}) and the scratch directory {} overlap; give scratch its \
             own directory outside every persistent root",
            root.display(),
            scratch.directory.display()
        );
        for (other_name, other) in &config.roots {
            ensure!(
                name == other_name || !root.starts_with(other),
                "persistent root {name} ({}) is inside persistent root {other_name} ({}). Roots \
                 may not nest, even when the inner directory is a mount point of another \
                 filesystem. Mount the other filesystem outside every persistent root, install \
                 that directory as its own root, and place tenant_audit_cache or backup \
                 destination directories beneath it",
                root.display(),
                other.display()
            );
        }
    }
    for path in paths {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "persistent path {} must be an absolute installed path without parent traversal",
            path.display()
        );
        ensure!(
            config.roots.values().any(|root| path.starts_with(root)),
            "persistent path {} is outside the explicitly installed roots; install a root that \
             contains it",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn open(
    config: &NodeDiskConfig,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<Arc<NodeDisk>> {
    storage.open_persistent(config)
}

/// Create a configured directory only through the installed NodeDisk's
/// enrolled namespace. The disk may already have inventoried this root; a raw
/// mkdir after its census would leave parent extents and child identity unknown.
pub(crate) fn open_or_create_directory(
    config: &NodeDiskConfig,
    disk: &Arc<NodeDisk>,
    path: &Path,
) -> Result<NodeDiskDirectory> {
    // A configured root itself is already enrolled by the census. `binding`
    // intentionally requires a child path, so open that exact root directly.
    if let Some((root, _)) = config
        .roots
        .iter()
        .find(|(_, installed)| installed.as_path() == path)
    {
        return Ok(disk.open_directory(root, Path::new(""))?);
    }
    let (root, relative) = config.binding(path)?;
    let mut directory = disk.open_directory(root, Path::new(""))?;
    for part in relative.iter() {
        // binding accepted only normal components under one installed root.
        let name = CString::new(part.as_bytes())?;
        let child = match directory.open_child(&name) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = disk.snapshot();
                if state.phase != NodeDiskPhase::Open || !state.filesystem_admission_ready {
                    return Err(error.into());
                }
                directory.create_child(&name, DiskWork::Foreground)?
            }
            Err(error) => return Err(error.into()),
        };
        directory = child;
    }
    Ok(directory)
}

/// Values written into a new installation/example, never deserialization
/// defaults or an enrollment fallback for an existing configuration.
pub(crate) fn initial_config(
    roots: BTreeMap<String, PathBuf>,
    directory_policy: kasumi_store::DirectoryPolicy,
    file_allocation_policy: kasumi_store::FileAllocationPolicy,
) -> Result<NodeDiskConfig> {
    directory_policy.validate()?;
    file_allocation_policy.validate()?;
    // Admission charges installed metadata for every namespace and handle slot
    // (about 0.5 KB per file or subdirectory, 67 KB per open file and 53 KB
    // per open directory), so these caps size the generated admission total.
    // Installations hold about ten files and directories and a few dozen
    // descriptors; one million of each and 4,096 handles quoted 1.51 GB.
    Ok(NodeDiskConfig {
        native_storage: kasumi_store::NodeStorageConfig::new(1 << 30, 64),
        roots,
        max_bytes: 128 << 30,
        maintenance_reserve_bytes: 1 << 30,
        min_free_bytes: 256 << 20,
        max_open_files: 1024,
        max_open_directories: 256,
        directory_policy,
        file_allocation_policy,
        max_persistent_files: 100_000,
        max_persistent_subdirectories: 10_000,
        census_work_per_step: 1_000_000,
        max_depth: 64,
        max_name_bytes: 255,
    })
}

impl crate::runtime::RuntimeConfig {
    pub(crate) fn validate_persistent_disk(&self) -> Result<()> {
        let mut paths = vec![self.database_path.as_path()];
        if let Some(verifier) = &self.signer_verifier {
            paths.push(&verifier.database_path);
        }
        if let Some(target) = &self.target_recovery {
            paths.extend([
                target.journal_path.as_path(),
                target.generation_root.as_path(),
            ]);
        }
        if let Some(crate::audit_destination::AuditDestinationConfig::Filesystem { directory }) =
            &self.security_audit.archive
        {
            paths.push(directory);
        }
        for placement in
            self.tenant_audit_placements
                .values()
                .chain(self.target_recovery.iter().flat_map(|target| {
                    target
                        .tenants
                        .values()
                        .map(|template| &template.audit_placement)
                }))
        {
            if let crate::audit_destination::TenantAuditPlacementConfig::External {
                destination:
                    crate::audit_destination::AuditDestinationConfig::Filesystem { directory },
            } = placement
            {
                if let Some(target) = &self.target_recovery {
                    anyhow::ensure!(
                        !directory.starts_with(&target.generation_root),
                        "external tenant audit archive is inside the generation deletion root"
                    );
                }
                if self.mode == crate::runtime::DeploymentMode::Standalone {
                    let generations = self
                        .database_path
                        .parent()
                        .ok_or_else(|| anyhow::anyhow!("standalone data directory missing"))?
                        .join("generations");
                    anyhow::ensure!(
                        !directory.starts_with(&generations),
                        "external tenant audit archive is inside the local generation deletion root"
                    );
                }
                paths.push(directory);
            }
        }
        for destination in self.backup_destinations.values() {
            if let crate::administration::DestinationConfig::Filesystem { directory, .. } =
                destination
            {
                paths.push(directory);
            }
        }
        if let Some(cache) = &self.tenant_audit_cache {
            self.validate_tenant_audit_cache(cache, &paths)?;
            paths.push(cache);
        }
        validate(&self.persistent_disk, &self.scratch_disk, paths)
    }

    /// The configured cache is its own directory: normalized, outside every
    /// generation deletion root, and apart from every other installed
    /// destination, database and archive path.
    fn validate_tenant_audit_cache(&self, cache: &Path, others: &[&Path]) -> Result<()> {
        ensure!(
            cache.is_absolute()
                && cache.as_os_str() == cache.components().collect::<PathBuf>().as_os_str()
                && cache.components().all(|part| matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
            "tenant_audit_cache {} must be a normalized absolute path",
            cache.display()
        );
        let data = self
            .database_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed data directory missing"))?;
        let mut deletion_roots = vec![data.join("generations")];
        if let Some(target) = &self.target_recovery {
            deletion_roots.push(target.generation_root.clone());
        }
        for root in &deletion_roots {
            ensure!(
                !cache.starts_with(root),
                "tenant_audit_cache {} is inside the generation deletion root {}",
                cache.display(),
                root.display()
            );
        }
        ensure!(
            cache != data.join(crate::audit_destination::TENANT_AUDIT_CACHE),
            "tenant_audit_cache {} is the default location; omit it instead",
            cache.display()
        );
        ensure!(
            !self
                .persistent_disk
                .roots
                .values()
                .any(|root| root == cache),
            "tenant_audit_cache {} must be a directory inside a persistent root, not the root",
            cache.display()
        );
        for other in others {
            ensure!(
                !cache.starts_with(other) && !other.starts_with(cache),
                "tenant_audit_cache {} overlaps the installed path {}",
                cache.display(),
                other.display()
            );
        }
        Ok(())
    }
}

impl crate::authority_runtime::AuthorityRuntimeConfig {
    pub(crate) fn validate_persistent_disk(&self) -> Result<()> {
        let mut paths = vec![
            self.database_path.as_path(),
            self.signer_verifier.database_path.as_path(),
        ];
        if let Some(crate::audit_destination::AuditDestinationConfig::Filesystem { directory }) =
            &self.security_audit.archive
        {
            paths.push(directory);
        }
        validate(&self.persistent_disk, &self.scratch_disk, paths)
    }
}

/// Test installations still provide an explicit root and exercise the production
/// owner/configuration path. This constructor is absent from installed builds.
#[cfg(test)]
pub(crate) fn fixture_config(root: &Path) -> NodeDiskConfig {
    if !root.exists() {
        kasumi_store::private_files::create_directory(root).unwrap();
    }
    let mut config = initial_config(
        BTreeMap::from([("fixture".into(), root.to_path_buf())]),
        kasumi_store::DirectoryPolicy::fixture(),
        kasumi_store::FileAllocationPolicy::fixture(),
    )
    .unwrap();
    config.max_bytes = 256 << 30;
    config.min_free_bytes = 0;
    // A bounded test policy; the fixture's explicit RuntimeStorage installs its
    // isolated owners under the same admitted memory core before storage use.
    config.max_persistent_files = 16_384;
    config.max_persistent_subdirectories = 16_384;
    config.census_work_per_step = 16_384;
    config.max_open_files = 256;
    config.max_open_directories = 256;
    config
}

#[cfg(test)]
mod tests {
    #[test]
    fn installed_directory_creation_tracks_nested_target_root_and_reopen() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let config = super::fixture_config(&directory.path().join("persistent"));
        let storage = crate::runtime_memory::RuntimeStorage::isolated_persistent_fixture(
            kasumi_engine::admission::AdmissionConfig::default(),
            &config,
        )
        .unwrap();
        let disk = storage.open_persistent(&config).unwrap();
        let root = &config.roots["fixture"];
        let target = root.join("targets/generations");
        let before = disk.snapshot().persistent_directories;
        assert!(!target.exists());
        let owner = super::open_or_create_directory(&config, &disk, &target).unwrap();
        owner.sync_all().unwrap();
        assert!(target.is_dir());
        assert_eq!(disk.snapshot().persistent_directories, before + 2);
        drop(owner);
        let owner = super::open_or_create_directory(&config, &disk, &target).unwrap();
        owner.sync_all().unwrap();
        assert_eq!(disk.snapshot().persistent_directories, before + 2);
        drop(owner);
        assert!(super::open_or_create_directory(&config, &disk, &root.join("../escape")).is_err());
        assert!(!directory.path().join("escape").exists());
        assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
        disk.pause().unwrap();
    }

    #[test]
    fn installed_directory_opens_an_exact_dedicated_root_without_creating_a_child() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let mut config = super::fixture_config(&directory.path().join("persistent"));
        let target_root = directory.path().join("target-generations");
        // Roots exist before NodeDisk inventories them; this one can be used as
        // the generation root while journal/database paths use the other root.
        kasumi_store::private_files::create_directory(&target_root).unwrap();
        config.roots.insert("target".into(), target_root.clone());
        let storage = crate::runtime_memory::RuntimeStorage::isolated_persistent_fixture(
            kasumi_engine::admission::AdmissionConfig::default(),
            &config,
        )
        .unwrap();
        let disk = storage.open_persistent(&config).unwrap();
        let before = disk.snapshot().persistent_directories;
        assert!(config.binding(&target_root).is_err());
        let owner = super::open_or_create_directory(&config, &disk, &target_root).unwrap();
        owner.sync_all().unwrap();
        assert_eq!(disk.snapshot().persistent_directories, before);
        drop(owner);
        assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
        disk.pause().unwrap();
    }

    #[test]
    fn persistent_config_is_mandatory_and_does_not_infer_database_parent() {
        let mut value = serde_json::to_value(
            crate::runtime::example_config(
                kasumi_store::DirectoryPolicy::fixture(),
                kasumi_store::FileAllocationPolicy::fixture(),
            )
            .unwrap(),
        )
        .unwrap();
        value.as_object_mut().unwrap().remove("persistent_disk");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(value).is_err());
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config.database_path = "/different/node.kv".into();
        assert!(config.validate_persistent_disk().is_err());
    }
    #[test]
    fn persistent_namespace_limits_are_required_without_legacy_fields() {
        let config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        let limits = [
            "max_persistent_files",
            "max_persistent_subdirectories",
            "census_work_per_step",
        ];
        for (name, generated) in limits.into_iter().zip([100_000, 10_000, 1_000_000]) {
            assert_eq!(encoded["persistent_disk"][name], generated);
            let mut missing = encoded.clone();
            missing["persistent_disk"]
                .as_object_mut()
                .unwrap()
                .remove(name);
            assert!(
                serde_json::from_value::<crate::runtime::RuntimeConfig>(missing).is_err(),
                "missing required limit {name} was accepted"
            );
        }
        let decoded =
            serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded.clone()).unwrap();
        assert_eq!(decoded.persistent_disk, config.persistent_disk);
        let mut legacy = encoded.clone();
        let policy = legacy["persistent_disk"].as_object_mut().unwrap();
        for name in limits {
            policy.remove(name);
        }
        policy.insert("max_census_entries".into(), 1_000_000.into());
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(legacy).is_err());
        let mut mixed = encoded;
        mixed["persistent_disk"]["max_census_entries"] = 1_000_000.into();
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(mixed).is_err());
    }
    #[test]
    fn persistent_file_allowance_is_required_and_preserves_the_selected_value() {
        let policy = kasumi_store::FileAllocationPolicy::new(12345).unwrap();
        let config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture(), policy)
                .unwrap();
        assert_eq!(config.persistent_disk.file_allocation_policy, policy);
        let mut encoded = serde_json::to_value(&config).unwrap();
        let decoded: crate::runtime::RuntimeConfig =
            serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.persistent_disk.file_allocation_policy, policy);
        encoded["persistent_disk"]
            .as_object_mut()
            .unwrap()
            .remove("file_allocation_policy");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(encoded).is_err());
    }
    #[test]
    fn persistent_roots_cannot_overlap_each_other_or_scratch() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config
            .persistent_disk
            .roots
            .insert("overlap".into(), "/var/lib/kasumi".into());
        assert!(config.validate_persistent_disk().is_err());
        config.persistent_disk.roots.remove("overlap");
        config.scratch_disk.directory = "/var/lib/kasumi/data/scratch".into();
        assert!(config.validate_persistent_disk().is_err());
    }
    #[test]
    fn auxiliary_filesystem_destinations_require_explicit_roots() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config.validate_persistent_disk().unwrap();
        config.backup_destinations.insert(
            "outside".into(),
            crate::administration::DestinationConfig::Filesystem {
                directory: "/uninstalled/backups".into(),
                max_bytes: 1 << 20,
                // Shape-only negative fixture; never an enrolled namespace.
                namespace_binding: kasumi_types::BackupNamespaceBinding::Filesystem {
                    installation_id: uuid::Uuid::nil(),
                    origin_node_id: 0,
                    namespace_id: uuid::Uuid::nil(),
                    device: 0,
                    inode: 0,
                },
            },
        );
        assert!(config.validate_persistent_disk().is_err());
        config.backup_destinations.clear();
        config.tenant_audit_placements.insert(
            "acme".into(),
            crate::audit_destination::TenantAuditPlacementConfig::External {
                destination: crate::audit_destination::AuditDestinationConfig::Filesystem {
                    directory: "/uninstalled/archives".into(),
                },
            },
        );
        assert!(config.validate_persistent_disk().is_err());
        config.tenant_audit_placements.insert(
            "acme".into(),
            crate::audit_destination::TenantAuditPlacementConfig::LocalReplicaOnly,
        );
        config.signer_verifier.as_mut().unwrap().database_path = "/uninstalled/trust.kv".into();
        assert!(config.validate_persistent_disk().is_err());
    }

    #[test]
    fn external_tenant_history_cannot_be_owned_by_local_generation_cleanup() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config.mode = crate::runtime::DeploymentMode::Standalone;
        config.tenant_audit_placements.insert(
            "acme".into(),
            crate::audit_destination::TenantAuditPlacementConfig::External {
                destination: crate::audit_destination::AuditDestinationConfig::Filesystem {
                    directory: config
                        .database_path
                        .parent()
                        .unwrap()
                        .join("generations/target/history"),
                },
            },
        );
        let error = config.validate_persistent_disk().unwrap_err();
        assert!(error.to_string().contains("local generation deletion root"));
        config.tenant_audit_placements.insert(
            "acme".into(),
            crate::audit_destination::TenantAuditPlacementConfig::External {
                destination: crate::audit_destination::AuditDestinationConfig::Filesystem {
                    directory: "/var/lib/kasumi/archives/acme".into(),
                },
            },
        );
        config.validate_persistent_disk().unwrap();
    }

    #[test]
    fn nested_roots_name_both_roots_and_the_supported_layout() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        // The bind mount the operators tried: a second filesystem mounted
        // inside the data root, installed as its own root.
        config.persistent_disk.roots.insert(
            "audit".into(),
            "/var/lib/kasumi/data/tenant-audit-archives".into(),
        );
        let error = config.validate_persistent_disk().unwrap_err().to_string();
        for expected in [
            "persistent root audit (/var/lib/kasumi/data/tenant-audit-archives)",
            "inside persistent root data (/var/lib/kasumi/data)",
            "may not nest",
            "install that directory as its own root",
            "tenant_audit_cache",
        ] {
            assert!(error.contains(expected), "{error}");
        }
        // The supported layout: the other filesystem is its own root, and the
        // cache and backups are directories beneath it.
        config.persistent_disk.roots.remove("audit");
        config
            .persistent_disk
            .roots
            .insert("volume".into(), "/data/kasumi".into());
        config.tenant_audit_cache = Some("/data/kasumi/tenant-audit-archives".into());
        config.validate_persistent_disk().unwrap();
        let outside = "/mnt/elsewhere/backups";
        config.backup_destinations.insert(
            "outside".into(),
            crate::administration::DestinationConfig::Filesystem {
                directory: outside.into(),
                max_bytes: 1 << 20,
                // Shape-only negative fixture; never an enrolled namespace.
                namespace_binding: kasumi_types::BackupNamespaceBinding::Filesystem {
                    installation_id: uuid::Uuid::nil(),
                    origin_node_id: 0,
                    namespace_id: uuid::Uuid::nil(),
                    device: 0,
                    inode: 0,
                },
            },
        );
        let error = config.validate_persistent_disk().unwrap_err().to_string();
        assert!(error.contains(outside), "{error}");
        assert!(error.contains("install a root that contains it"), "{error}");
    }

    #[test]
    fn tenant_audit_cache_is_its_own_directory_inside_an_installed_root() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert!(encoded.get("tenant_audit_cache").is_none());
        let cache = std::path::PathBuf::from("/var/lib/kasumi/archives/tenant-audit-cache");
        config.tenant_audit_cache = Some(cache.clone());
        config.validate_persistent_disk().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(encoded["tenant_audit_cache"], cache.display().to_string());
        let decoded: crate::runtime::RuntimeConfig = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.tenant_audit_cache, Some(cache));
        for (cache, reason) in [
            (
                "/mnt/data/tenant-audit-cache",
                "outside the explicitly installed roots",
            ),
            (
                "/var/lib/kasumi/data/tenant-audit-archives",
                "default location",
            ),
            ("/var/lib/kasumi/archives", "not the root"),
            (
                "/var/lib/kasumi/data/generations/cache",
                "generation deletion root",
            ),
            (
                "/var/lib/kasumi/archives/cache/",
                "normalized absolute path",
            ),
            (
                "/var/lib/kasumi/archives/./cache",
                "normalized absolute path",
            ),
            ("relative/cache", "normalized absolute path"),
            ("/var/lib/kasumi/verifier/trust.kv/cache", "overlaps"),
        ] {
            config.tenant_audit_cache = Some(cache.into());
            let error = config.validate_persistent_disk().unwrap_err().to_string();
            assert!(error.contains(reason), "{cache}: {error}");
        }
        config.tenant_audit_cache = Some("/var/lib/kasumi/archives/acme/cache".into());
        config.tenant_audit_placements.insert(
            "acme".into(),
            crate::audit_destination::TenantAuditPlacementConfig::External {
                destination: crate::audit_destination::AuditDestinationConfig::Filesystem {
                    directory: "/var/lib/kasumi/archives/acme".into(),
                },
            },
        );
        let error = config.validate_persistent_disk().unwrap_err().to_string();
        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn parent_traversal_cannot_bypass_root_overlap_checks() {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config
            .persistent_disk
            .roots
            .insert("traversal".into(), "/var/lib/kasumi/data/../scratch".into());
        assert!(config.validate_persistent_disk().is_err());
        config.persistent_disk.roots.remove("traversal");
        config.scratch_disk.directory = "/var/lib/kasumi/elsewhere/../data".into();
        assert!(config.validate_persistent_disk().is_err());
    }
}
