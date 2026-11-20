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
        let key = (checkpoint.tenant.clone(), target);
        let generation = runtime
            .generations
            .try_lock()
            .ok()
            .and_then(|owners| owners.get(&key).cloned());
        let Some(database) = generation.and_then(|generation| {
            generation
                .try_lock()
                .ok()?
                .registered_data
                .as_ref()
                .filter(|(original, _)| original == &key)
                .map(|(_, db)| db.clone())
        }) else {
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
