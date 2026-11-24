//! Select the original backup destination and enrolled historical keys of an
//! already serving materialized target. This reader acquires no serving lease.
use super::*;
use kasumi_engine::{TargetCheckpointInventory, TargetCheckpointSource};
use std::sync::Weak;

pub(super) struct Installed {
    pub(super) runtime: Weak<TargetRecoveryRuntime>,
    pub(super) control: Weak<kasumi_engine::Database>,
}

impl TargetCheckpointInventory for Installed {
    fn stopped_absent(&self, tenant: &str, target: Uuid) -> Result<bool> {
        let Some(runtime) = self.runtime.upgrade() else {
            return Ok(false);
        };
        if runtime.closing.load(Ordering::Acquire) {
            return Ok(false);
        }
        let key = (tenant.to_owned(), target);
        let no_local_owner = || {
            runtime
                .generations
                .try_lock()
                .is_ok_and(|owners| !owners.contains_key(&key))
        };
        if !no_local_owner() {
            return Ok(false);
        }
        let path = runtime.path(&key)?;
        if target_file_exists(&path)? {
            return Ok(false);
        }
        target_absence_from_installed_disk(
            &runtime.config.persistent_disk,
            runtime.audit.store().persistent_disk(),
            &path,
        )?;
        Ok(no_local_owner() && !runtime.closing.load(Ordering::Acquire))
    }
    fn source(
        &self,
        target: Uuid,
        checkpoint: &FullBackupCheckpoint,
    ) -> Result<Option<TargetCheckpointSource>> {
        let Some(runtime) = self.runtime.upgrade() else {
            return Ok(None);
        };
        if runtime.closing.load(Ordering::Acquire) {
            return Ok(None);
        }
        // Target serving publishes this exact database through the registry
        // before recording its local worker state. The status monitor may hold
        // the generation mutex while checking the same healthy handle. The
        // journal authenticates its genesis, enrolled node, physical directory
        // and backing disk before and after visiting the checkpoint graph.
        let Some(database) = runtime
            .registry
            .installed_generation(&checkpoint.tenant, &target.to_string())?
        else {
            return Ok(None);
        };
        let source_id = Uuid::parse_str(&checkpoint.source_incarnation)?;
        let Some(source) = runtime
            .installed
            .tenants
            .get(&checkpoint.tenant)
            .and_then(|template| template.source_backups.get(&source_id))
        else {
            return Ok(None);
        };
        let Some(binding) = &source.read_key_binding else {
            return Ok(None);
        };
        let keys = match crate::local_recovery::keys::RecoveryKeys::open_with(
            &source.keys,
            &source.historical_keys,
            runtime.credential.clone(),
        )
        .and_then(|keys| keys.bound_digest(binding))
        {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(backup_id = %checkpoint.backup_id, %error, "target backup key roster unavailable");
                return Ok(None);
            }
        };
        let Some(destination) = runtime.destinations.get(&source.destination_alias) else {
            return Ok(None);
        };
        let Some(control) = self.control.upgrade() else {
            return Ok(None);
        };
        Ok(Some(TargetCheckpointSource {
            control,
            target: database,
            destination_alias: source.destination_alias.clone(),
            destination: destination.clone(),
            keys,
        }))
    }
}

#[cfg(test)]
impl TargetRecoveryRuntime {
    pub(crate) async fn check_checkpoint_route_under_generation_lock(
        self: &Arc<Self>,
        control: &Arc<kasumi_engine::Database>,
        target: Uuid,
        checkpoint: &FullBackupCheckpoint,
    ) -> Result<()> {
        let key = (checkpoint.tenant.clone(), target);
        let generation = self
            .generations
            .lock()
            .await
            .get(&key)
            .cloned()
            .context("installed target worker absent")?;
        let observed = generation.lock().await;
        let (_, registered) = observed
            .registered_data
            .as_ref()
            .filter(|(original, _)| original == &key)
            .context("target worker has no registered data route")?;
        let inventory = Installed {
            runtime: Arc::downgrade(self),
            control: Arc::downgrade(control),
        };
        let source = inventory
            .source(target, checkpoint)?
            .context("target checkpoint route vanished during a worker observation")?;
        anyhow::ensure!(
            Arc::ptr_eq(registered, &source.target),
            "checkpoint route differs from the worker's enrolled database"
        );
        Ok(())
    }
}
