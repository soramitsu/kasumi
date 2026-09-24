//! Explicit installed persistent roots. Configuration validation is read-only;
//! opening never invents a root from a database path or scratch directory.
use anyhow::{Result, ensure};
use kasumi_store::{NodeDisk, NodeDiskConfig, ScratchDiskConfig};
use std::{
    collections::BTreeMap,
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
        "scratch path contains parent traversal"
    );
    for (name, root) in &config.roots {
        ensure!(
            installed_path(root),
            "persistent root contains parent traversal"
        );
        ensure!(
            !root.starts_with(&scratch.directory) && !scratch.directory.starts_with(root),
            "persistent and scratch roots overlap"
        );
        for (other_name, other) in &config.roots {
            if name != other_name {
                ensure!(!root.starts_with(other), "persistent roots overlap");
            }
        }
    }
    for path in paths {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "persistent path must be an absolute installed path without parent traversal"
        );
        ensure!(
            config.roots.values().any(|root| path.starts_with(root)),
            "persistent path is outside the explicitly installed roots"
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

/// Values written into a new installation/example, never deserialization
/// defaults or an enrollment fallback for an existing configuration.
pub(crate) fn initial_config(
    roots: BTreeMap<String, PathBuf>,
    directory_policy: kasumi_store::DirectoryPolicy,
) -> Result<NodeDiskConfig> {
    directory_policy.validate()?;
    Ok(NodeDiskConfig {
        roots,
        max_bytes: 128 << 30,
        maintenance_reserve_bytes: 1 << 30,
        min_free_bytes: 256 << 20,
        max_open_files: 4096,
        max_open_directories: 4096,
        directory_policy,
        max_persistent_files: 1_000_000,
        max_persistent_subdirectories: 1_000_000,
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
        for archive in self.tenant_audit_archives.values() {
            if let crate::audit_destination::AuditDestinationConfig::Filesystem { directory } =
                archive
            {
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
        validate(&self.persistent_disk, &self.scratch_disk, paths)
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
    fn persistent_config_is_mandatory_and_does_not_infer_database_parent() {
        let mut value = serde_json::to_value(
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap(),
        )
        .unwrap();
        value.as_object_mut().unwrap().remove("persistent_disk");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(value).is_err());
        let mut config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        config.database_path = "/different/node.redb".into();
        assert!(config.validate_persistent_disk().is_err());
    }
    #[test]
    fn persistent_namespace_limits_are_required_without_legacy_fields() {
        let config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        let limits = [
            "max_persistent_files",
            "max_persistent_subdirectories",
            "census_work_per_step",
        ];
        for name in limits {
            assert_eq!(encoded["persistent_disk"][name], 1_000_000);
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
    fn persistent_roots_cannot_overlap_each_other_or_scratch() {
        let mut config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
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
        let mut config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        config.validate_persistent_disk().unwrap();
        config.backup_destinations.insert(
            "outside".into(),
            crate::administration::DestinationConfig::Filesystem {
                directory: "/uninstalled/backups".into(),
                max_bytes: 1 << 20,
            },
        );
        assert!(config.validate_persistent_disk().is_err());
        config.backup_destinations.clear();
        config.tenant_audit_archives.insert(
            "acme".into(),
            crate::audit_destination::AuditDestinationConfig::Filesystem {
                directory: "/uninstalled/archives".into(),
            },
        );
        assert!(config.validate_persistent_disk().is_err());
        config.tenant_audit_archives.clear();
        config.signer_verifier.as_mut().unwrap().database_path = "/uninstalled/trust.redb".into();
        assert!(config.validate_persistent_disk().is_err());
    }

    #[test]
    fn parent_traversal_cannot_bypass_root_overlap_checks() {
        let mut config =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
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
