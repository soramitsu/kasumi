//! Exact deletion of one stopped target generation's storage.
//!
//! The original materialization binds the directory it created (installed
//! path, materialization stamp, directory device/inode and store identity)
//! before any catalog is initialized. Cleanup deletes only that exact
//! directory: it records `Deleting` before the first unlink and `Deleted`
//! only after the deletion and the parent directory sync are confirmed. A
//! replay after any interruption resumes from the recorded stage; a recorded
//! deletion is final and never deletes a later directory at the same path.
use super::{target_absence_from_installed_disk, target_file_exists};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{TargetCleanup, TargetCleanupStage, TargetFileBinding};
use std::{path::Path, sync::Arc};
use uuid::Uuid;

/// The durable records of one target generation's cleanup. Production uses
/// the target journal under the operation's StopLocal phase.
pub(super) trait CleanupLedger {
    fn binding(&self) -> Result<Option<TargetFileBinding>>;
    fn bind(&self, binding: &TargetFileBinding) -> Result<()>;
    fn cleanup(&self) -> Result<Option<TargetCleanup>>;
    fn record(&self, cleanup: &TargetCleanup) -> Result<()>;
    /// The operation fence, checked before the first unlink.
    fn check(&self) -> Result<()>;
}

/// The installed disk and enrolled generation directory holding the target.
pub(super) struct TargetStorage<'a> {
    pub(super) disk: &'a Arc<kasumi_store::NodeDisk>,
    pub(super) config: &'a kasumi_store::NodeDiskConfig,
    pub(super) parent: &'a kasumi_store::NodeDiskDirectory,
}

/// The identity of one target generation's storage.
pub(super) struct TargetFile<'a> {
    pub(super) tenant: &'a str,
    pub(super) target: Uuid,
    pub(super) path: &'a Path,
    pub(super) node_store_id: Uuid,
}
impl TargetFile<'_> {
    fn cleanup(
        &self,
        stage: TargetCleanupStage,
        binding: Option<TargetFileBinding>,
    ) -> TargetCleanup {
        TargetCleanup {
            tenant: self.tenant.to_owned(),
            target_incarnation: self.target,
            stage,
            binding,
        }
    }
    fn claim(&self, storage: &TargetStorage<'_>) -> Result<kasumi_store::NodeSegmentGroupCleanup> {
        kasumi_store::NodeStore::claim_cleanup(
            self.path,
            self.node_store_id,
            storage.disk.clone(),
            storage.disk.native_storage_config(),
        )
    }
}

/// Delete exactly the originally bound storage of `file`, or prove that none
/// was ever created, and record the terminal outcome. Idempotent.
pub(super) fn delete_exact(
    ledger: &dyn CleanupLedger,
    storage: &TargetStorage<'_>,
    file: &TargetFile<'_>,
) -> Result<()> {
    let (binding, claimed, stage) = match ledger.cleanup()? {
        Some(recorded) if recorded.stage == TargetCleanupStage::Deleted => {
            ensure!(
                !target_file_exists(file.path)?,
                "target path is occupied again after its recorded deletion"
            );
            target_absence_from_installed_disk(storage.config, storage.disk, file.path)?;
            return Ok(());
        }
        Some(recorded) => {
            let binding = recorded
                .binding
                .context("target cleanup in progress has no binding")?;
            let exists = target_file_exists(file.path)?;
            ensure!(
                !exists || recorded.stage == TargetCleanupStage::Deleting,
                "target path is occupied again after its recorded unlink"
            );
            let claimed = exists.then(|| file.claim(storage)).transpose()?;
            (binding, claimed, recorded.stage)
        }
        None => {
            let existing = ledger.binding()?;
            if !target_file_exists(file.path)? {
                ensure!(
                    existing.is_none(),
                    "bound target disappeared before cleanup"
                );
                target_absence_from_installed_disk(storage.config, storage.disk, file.path)?;
                storage.parent.sync_all()?;
                boundary(file.path, "synced")?;
                ledger.record(&file.cleanup(TargetCleanupStage::Deleted, None))?;
                return Ok(());
            }
            // An unbound materialization may have synced its stamped directory
            // before creating the root file. The creation journal validates the
            // stamp in bind(). Once bound, only Deleting explains a missing root.
            let claimed = file.claim(storage)?;
            let directory = if existing.is_some() {
                claimed.identity()?.directory
            } else {
                claimed.directory_identity()?
            };
            let binding = TargetFileBinding {
                tenant: file.tenant.to_owned(),
                target_incarnation: file.target,
                path: file.path.to_owned(),
                directory,
                directory_stamp: Some(claimed.target_directory_stamp()?.context(
                    "target cleanup requires the original materialization directory stamp",
                )?),
                node_store_id: file.node_store_id,
            };
            if let Some(existing) = existing {
                ensure!(
                    existing == binding,
                    "target storage is not its originally enrolled directory"
                );
            } else {
                ledger.bind(&binding)?;
            }
            ledger.record(&file.cleanup(TargetCleanupStage::Deleting, Some(binding.clone())))?;
            boundary(file.path, "deleting")?;
            (binding, Some(claimed), TargetCleanupStage::Deleting)
        }
    };
    ensure!(
        binding.tenant == file.tenant
            && binding.target_incarnation == file.target
            && binding.path == file.path
            && binding.node_store_id == file.node_store_id,
        "target cleanup binding names other storage"
    );
    if let Some(claimed) = claimed {
        ensure!(
            binding.directory_stamp.is_some()
                && claimed.target_directory_stamp()? == binding.directory_stamp
                && claimed.directory_identity()? == binding.directory
                && kasumi_store::private_files::directory_identity(file.path)? == binding.directory,
            "target storage at {} is not its originally enrolled directory",
            file.path.display()
        );
        ledger.check()?;
        claimed.delete()?;
    } else {
        // An interrupted earlier attempt may have finished the unlinks.
        target_absence_from_installed_disk(storage.config, storage.disk, file.path)?;
    }
    // Only the original deletion may explain absence. Record it before the
    // explicit parent sync, then retain the successful sync before finalization.
    if stage == TargetCleanupStage::Deleting {
        ledger.record(&file.cleanup(TargetCleanupStage::Unlinked, Some(binding.clone())))?;
        boundary(file.path, "unlinked")?;
    }
    if stage != TargetCleanupStage::ParentSynced {
        storage.parent.sync_all()?;
        ledger.record(&file.cleanup(TargetCleanupStage::ParentSynced, Some(binding.clone())))?;
        boundary(file.path, "synced")?;
    }
    ledger.record(&file.cleanup(TargetCleanupStage::Deleted, Some(binding)))
}

/// A named step boundary. Tests interrupt a cleanup at any of them.
fn boundary(path: &Path, name: &'static str) -> Result<()> {
    #[cfg(test)]
    interruption::reached(path, name)?;
    #[cfg(not(test))]
    let _ = (path, name);
    Ok(())
}

#[cfg(test)]
pub(super) mod interruption {
    use super::*;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };

    fn stops() -> &'static Mutex<BTreeMap<PathBuf, &'static str>> {
        static STOPS: OnceLock<Mutex<BTreeMap<PathBuf, &'static str>>> = OnceLock::new();
        STOPS.get_or_init(Default::default)
    }
    /// Fail the next cleanup of `path` right after `boundary`.
    pub(crate) fn stop_after(path: &Path, boundary: &'static str) {
        stops().lock().unwrap().insert(path.to_owned(), boundary);
    }
    pub(super) fn reached(path: &Path, name: &'static str) -> Result<()> {
        let mut stops = stops().lock().unwrap();
        if stops.get(path) == Some(&name) {
            stops.remove(path);
            anyhow::bail!("injected interruption after cleanup boundary {name}");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "target_cleanup_tests.rs"]
mod tests;
