//! Restore persistence owns its original gate, stores and request lifetime.
use super::*;
use crate::backup_verify::VerificationDeadline;
use kasumi_query::QueryCancellation;

pub(super) struct Publication {
    pub stores: Arc<TenantStorageSet>,
    pub audit: Arc<SecurityAudit>,
    pub contexts: Vec<RequestContext>,
    pub cancellation: QueryCancellation,
    pub deadline: VerificationDeadline,
}
impl Publication {
    fn check(&self) -> anyhow::Result<()> {
        self.deadline.check()?;
        self.cancellation.check()?;
        self.stores.check_access()?;
        self.audit.store().check_access()?;
        anyhow::ensure!(
            !self.contexts.is_empty() && self.contexts.len() <= 2,
            "restore publication requires bounded exact authorizations"
        );
        for context in &self.contexts {
            context.authorization.check_live()?;
            anyhow::ensure!(
                context.tenant == self.stores.application().tenant()
                    && context.scopes.contains(&Action::Admin),
                "restore publication authorization differs"
            );
        }
        Ok(())
    }
    pub async fn persist(
        self,
        restored: backup_restore::PreparedState,
        gate: tokio::sync::MutexGuard<'static, ()>,
        binding: Vec<u8>,
    ) -> anyhow::Result<(
        backup_restore::PreparedState,
        tokio::sync::MutexGuard<'static, ()>,
    )> {
        let workspace = restored.publication_workspace();
        let registration = restored.publication_registration();
        self.deadline
            .blocking(workspace, registration, move || {
                // Cancellation must not release either source/target ownership,
                // the bootstrap gate or workspace before this actual job drains.
                self.check()?;
                bind_deployment(&self.stores, &binding)?;
                self.check()?;
                persist_new_checked(&self.stores, &restored.bytes, || self.check())?;
                self.check()?;
                Ok((restored, gate))
            })
            .await
    }
}
