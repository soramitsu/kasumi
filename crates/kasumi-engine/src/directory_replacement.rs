//! Bound physical retirement to one selected/unselected generation pair.
use anyhow::{Result, ensure};
use kasumi_store::{NamespaceStage, SelectedGeneration, TenantStore};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(crate) struct DirectoryReplacement {
    replacement: Mutex<Option<PendingReplacement>>,
}
struct PendingReplacement {
    previous: String,
    candidate: String,
    _workspace: kasumi_store::DiskMemoryLease,
}

impl DirectoryReplacement {
    fn replacement_slot(&self) -> Result<std::sync::MutexGuard<'_, Option<PendingReplacement>>> {
        self.replacement
            .lock()
            .map_err(|_| anyhow::anyhow!("directory replacement owner poisoned"))
    }

    /// A failed Native begin can have a durable outcome. Record the original
    /// proposed namespace before starting it and retain the two exact names.
    pub(crate) fn begin(
        &self,
        store: &Arc<TenantStore>,
        family: &str,
        previous: &str,
    ) -> Result<NamespaceStage> {
        let mut slot = self.replacement_slot()?;
        ensure!(
            slot.is_none(),
            "previous directory replacement still owns native pages"
        );
        let workspace = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(1024)?;
        let candidate = format!("{}@{}", family, uuid::Uuid::new_v4());
        *slot = Some(PendingReplacement {
            previous: previous.to_owned(),
            candidate,
            _workspace: workspace,
        });
        NamespaceStage::begin(
            store,
            &slot
                .as_ref()
                .expect("installed original replacement")
                .candidate,
        )
    }

    /// The paired selector determines whether the prior or proposed space is
    /// unselected. Four deletion commits bound one ordinary application.
    /// A process restart recovers the same durable native owners on reopen.
    pub(crate) fn advance(
        &self,
        store: &Arc<TenantStore>,
        family: &str,
        initial: &[&str],
    ) -> Result<bool> {
        let mut slot = self.replacement_slot()?;
        let Some(pending) = slot.as_ref() else {
            return Ok(true);
        };
        let selected = SelectedGeneration::load(store, family, initial)?;
        let unselected = if selected.namespace(0) == pending.candidate {
            &pending.previous
        } else {
            ensure!(
                selected.namespace(0) == pending.previous,
                "directory replacement selection changed"
            );
            &pending.candidate
        };
        for _ in 0..4 {
            if NamespaceStage::reclaim(store, unselected)? {
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn recovered(&self) -> Result<()> {
        *self.replacement_slot()? = None;
        Ok(())
    }
}
