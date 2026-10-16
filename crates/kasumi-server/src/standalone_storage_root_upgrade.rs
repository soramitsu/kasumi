//! `kasumid maintenance upgrade-storage-root CONFIG SAVE_DIR`: the one-time,
//! offline, first-release upgrade of a stopped standalone installation's
//! group roots from `KASUMI-KVROOT003` to `KASUMI-KVROOT005` in place.
//!
//! It exists only for the BPNG installation created before ROOT005. Delete it,
//! `kasumi_store::StorageRootUpgrade` and `kasumi_kv::RootUpgradePlan` once
//! that installation is upgraded; the runtime keeps refusing ROOT003.
//!
//! Ownership is taken as by every offline operator: the operator registry,
//! the installed persistent disk with its exclusive root locks and census, and
//! the standalone installation claim. No encrypted store or kv group is opened
//! and no root is decoded by the runtime path. Every root is validated and
//! planned before anything is written; the original image of each root that
//! needs work is saved to SAVE_DIR (owner-only, synchronized) before its slots
//! are rewritten on the same inode. A rerun completes an interrupted upgrade
//! and reports `already ROOT005` once nothing is left to do.
use super::{claim, open_installed_file, operator};
use crate::runtime::{DeploymentMode, RuntimeConfig};
use anyhow::{Context, Result, bail, ensure};
use kasumi_store::{
    NodeDisk, NodeDiskFile, ROOT_FILE_NAME, RootSlot, STORAGE_ROOT_FILE_BYTES, StorageRootUpgrade,
    private_files,
};
use sha2::{Digest, Sha256};
use std::{
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

const SUMMARY_FORMAT: &str = "kasumi.storage-root-upgrade.v1";

pub async fn upgrade_storage_root(
    configuration: &Path,
    save_directory: &Path,
) -> Result<serde_json::Value> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    upgrade_storage_root_with_storage(configuration, save_directory, storage).await
}

pub(crate) async fn upgrade_storage_root_with_storage(
    configuration: &Path,
    save_directory: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<serde_json::Value> {
    let configuration = configuration.to_owned();
    let save_directory = save_directory.to_owned();
    operator::run(async move { upgrade_owned(&configuration, &save_directory, storage).await })
        .await
}

/// One installed group root and the node identity its envelope must carry.
struct InstalledRoot {
    path: PathBuf,
    /// The saved copy's file name, unique per root of the installation.
    saved_name: String,
    identity: Uuid,
}

enum SavedCopy {
    /// Nothing needs saving and no copy exists.
    Absent,
    /// This run saves the root as it found it.
    Write,
    /// An earlier run saved this root before the same upgrade.
    Matches,
    /// Nothing needs saving; the existing copy predates the current root.
    Stale,
}

enum Inspection {
    /// An interrupted creation left no envelope and no published root.
    Unpublished(Vec<u8>),
    Root {
        upgrade: Box<StorageRootUpgrade>,
        saved: SavedCopy,
    },
}

struct Planned {
    root: InstalledRoot,
    file: NodeDiskFile,
    inspection: Inspection,
}

async fn upgrade_owned(
    configuration: &Path,
    save_directory: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<serde_json::Value> {
    let config = RuntimeConfig::load(configuration)?;
    ensure!(
        config.mode == DeploymentMode::Standalone,
        "the storage root upgrade is for a stopped standalone installation"
    );
    let save = SaveDirectory::check(&config, save_directory)?;
    let disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
    let owner = claim(&config, &disk)?
        .context("the storage root upgrade requires the installed standalone owner")?;
    let installation = owner.identity_for(&disk)?.installation_id;
    let mut planned = Vec::new();
    for root in installed_roots(&config, &disk, installation)? {
        let file = open_installed_file(&config.persistent_disk, &disk, &root.path)
            .with_context(|| format!("opening {}", root.path.display()))?;
        let inspection = inspect(&file, &root, &save)
            .with_context(|| format!("refusing to upgrade {}", root.path.display()))?;
        planned.push(Planned {
            root,
            file,
            inspection,
        });
    }
    // Every root is planned; only now is anything written, originals first.
    let pending = |inspection: &Inspection| match inspection {
        Inspection::Root { upgrade, .. } => !upgrade.plan().is_current(),
        Inspection::Unpublished(_) => false,
    };
    if planned.iter().any(|root| pending(&root.inspection)) {
        save.create()?;
    }
    for root in &planned {
        if let Inspection::Root {
            upgrade,
            saved: SavedCopy::Write,
        } = &root.inspection
        {
            private_files::create(&save.copy(&root.root.saved_name), upgrade.before())
                .with_context(|| format!("saving the original of {}", root.root.path.display()))?;
        }
    }
    let mut roots = Vec::with_capacity(planned.len());
    for mut root in planned {
        let summary = match &root.inspection {
            Inspection::Unpublished(image) => serde_json::json!({
                "path": root.root.path,
                "outcome": "unpublished",
                "slots_changed": [],
                "generation": null,
                "sha256_before": hex::encode(Sha256::digest(image)),
                "sha256_after": hex::encode(Sha256::digest(image)),
                "saved_copy": null,
            }),
            Inspection::Root { upgrade, saved } => {
                let plan = upgrade.plan();
                let outcome = if plan.is_current() {
                    "already ROOT005"
                } else if plan.is_interrupted() {
                    "resumed"
                } else {
                    "upgraded"
                };
                let written = if plan.is_current() {
                    Vec::new()
                } else {
                    upgrade
                        .apply(&root.file)
                        .with_context(|| format!("upgrading {}", root.root.path.display()))?
                };
                let saved_copy = match saved {
                    SavedCopy::Absent => serde_json::Value::Null,
                    SavedCopy::Write => saved_copy(&save, &root.root, "written"),
                    SavedCopy::Matches => saved_copy(&save, &root.root, "matches"),
                    SavedCopy::Stale => saved_copy(&save, &root.root, "stale"),
                };
                serde_json::json!({
                    "path": root.root.path,
                    "outcome": outcome,
                    "envelope": upgrade.envelope().as_str(),
                    "slots": {
                        "A": plan.upgrade(RootSlot::A).as_str(),
                        "B": plan.upgrade(RootSlot::B).as_str(),
                    },
                    "slots_changed": written.iter().map(|slot| slot_name(*slot)).collect::<Vec<_>>(),
                    "generation": plan.generation(),
                    "selected_slot": plan.selected().map(|(slot, _)| slot_name(slot)),
                    "mirrored": plan.selected().map(|(_, mirrored)| mirrored),
                    "sha256_before": hex::encode(Sha256::digest(upgrade.before())),
                    "sha256_after": hex::encode(Sha256::digest(upgrade.after())),
                    "saved_copy": saved_copy,
                })
            }
        };
        root.file
            .close()
            .with_context(|| format!("closing {}", root.root.path.display()))?;
        roots.push(summary);
    }
    drop(owner);
    Ok(serde_json::json!({
        "format": SUMMARY_FORMAT,
        "save_directory": save.path,
        "roots": roots,
    }))
}

fn slot_name(slot: RootSlot) -> &'static str {
    match slot {
        RootSlot::A => "A",
        RootSlot::B => "B",
    }
}

fn saved_copy(save: &SaveDirectory, root: &InstalledRoot, state: &str) -> serde_json::Value {
    serde_json::json!({"path": save.copy(&root.saved_name), "state": state})
}

/// `data/node.kv/root.kvroot` and the root of every local generation group
/// under `data/generations`, each with the identity its envelope must carry.
fn installed_roots(
    config: &RuntimeConfig,
    disk: &Arc<NodeDisk>,
    installation: Uuid,
) -> Result<Vec<InstalledRoot>> {
    let data = config
        .database_path
        .parent()
        .context("standalone data directory missing")?;
    let mut roots = vec![InstalledRoot {
        path: config.database_path.join(ROOT_FILE_NAME),
        saved_name: format!("node.kv.{ROOT_FILE_NAME}"),
        identity: config.database_id,
    }];
    let generations = data.join("generations");
    let entries = match std::fs::read_dir(&generations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(roots),
        Err(error) => return Err(error).context("listing local generations"),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .ok()
            .context("local generations directory holds an unreadable name")?;
        let incarnation = Uuid::parse_str(&name)
            .ok()
            .filter(|incarnation| incarnation.to_string() == name)
            .with_context(|| format!("local generations directory holds {name:?}"))?;
        ensure!(
            entry.file_type()?.is_dir(),
            "local generation {name} is not a directory"
        );
        names.push((name, incarnation));
    }
    names.sort();
    for (name, incarnation) in names {
        let directory = generations.join(&name);
        let path = directory.join("node.kv").join(ROOT_FILE_NAME);
        match std::fs::symlink_metadata(&path) {
            // No group was created yet, or cleanup already removed its root.
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        roots.push(InstalledRoot {
            identity: crate::local_recovery::generation_node_id(
                config,
                disk,
                &directory,
                installation,
                incarnation,
            )
            .with_context(|| format!("binding local generation {name}"))?,
            saved_name: format!("generations.{name}.node.kv.{ROOT_FILE_NAME}"),
            path,
        });
    }
    Ok(roots)
}

/// Read and plan one root; nothing is written.
fn inspect(file: &NodeDiskFile, root: &InstalledRoot, save: &SaveDirectory) -> Result<Inspection> {
    let length = file.observed_len()?;
    ensure!(
        length == 0 || length == STORAGE_ROOT_FILE_BYTES as u64,
        "segment group root length is invalid"
    );
    let mut image = vec![0; length as usize];
    file.read_exact_at(&mut image, 0)?;
    if image.iter().all(|&byte| byte == 0) {
        // Group creation grows the root and writes its envelope before any
        // publication, so a zero image holds no root to upgrade.
        return Ok(Inspection::Unpublished(image));
    }
    let upgrade = Box::new(StorageRootUpgrade::from_image(&image, root.identity)?);
    let saved = match save.read(&root.saved_name)? {
        None if upgrade.plan().is_current() => SavedCopy::Absent,
        None => SavedCopy::Write,
        Some(copy) => {
            let same = StorageRootUpgrade::from_image(&copy, root.identity)
                .is_ok_and(|saved| saved.same_upgrade(&upgrade));
            if same {
                SavedCopy::Matches
            } else if upgrade.plan().is_current() {
                SavedCopy::Stale
            } else {
                bail!(
                    "the save directory holds a different copy at {}",
                    save.copy(&root.saved_name).display()
                );
            }
        }
    };
    Ok(Inspection::Root { upgrade, saved })
}

struct SaveDirectory {
    path: PathBuf,
}

impl SaveDirectory {
    /// An absolute owner-only directory outside every installed storage root,
    /// so the copies never enter the census of the disk they describe.
    fn check(config: &RuntimeConfig, path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "the save directory must be an absolute path without . or .. components"
        );
        let resolved = match std::fs::canonicalize(path) {
            Ok(resolved) => resolved,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                std::fs::canonicalize(path.parent().context("the save directory has no parent")?)?
                    .join(path.file_name().context("the save directory has no name")?)
            }
            Err(error) => return Err(error.into()),
        };
        for root in config
            .persistent_disk
            .roots
            .values()
            .chain([&config.scratch_disk.directory])
        {
            let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            ensure!(
                !resolved.starts_with(&root),
                "the save directory is inside installed storage {}",
                root.display()
            );
        }
        if std::fs::symlink_metadata(path).is_ok() {
            private_files::check_directory(path)?;
        }
        Ok(Self {
            path: path.to_owned(),
        })
    }

    fn copy(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn create(&self) -> Result<()> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => private_files::check_directory(&self.path),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                private_files::create_directory(&self.path)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.copy(name);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
            Ok(_) => Ok(Some(
                private_files::read(&path, STORAGE_ROOT_FILE_BYTES)?.to_vec(),
            )),
        }
    }
}

#[cfg(test)]
#[path = "standalone_storage_root_upgrade_tests.rs"]
pub(crate) mod tests;
