//! Restore persistence owns its original gate, stores and request lifetime.
use super::*;
use crate::backup_verify::{VerificationDeadline, VerificationPhase};
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
        identity: [WriteOp; 2],
    ) -> anyhow::Result<(
        backup_restore::PreparedState,
        tokio::sync::MutexGuard<'static, ()>,
    )> {
        let workspace = restored.publication_workspace();
        let registration = restored.publication_registration();
        let phase = VerificationPhase::start("restore.publication_wait", Some(self.deadline));
        let result = self
            .deadline
            .blocking(workspace, registration, move || {
                // Declare the serial guard first so error cleanup destroys stores
                // and prepared state before releasing bootstrap serialization.
                let serial = gate;
                let prepared = restored;
                let publication = self;
                publication.check()?;
                let phase = VerificationPhase::start(
                    "restore.deployment_binding",
                    Some(publication.deadline),
                );
                bind_deployment(&publication.stores, &binding)?;
                phase.complete();
                publication.check()?;
                let phase = VerificationPhase::start(
                    "restore.bootstrap_persistence",
                    Some(publication.deadline),
                );
                persist_new_checked(&publication.stores, &prepared.bytes, identity, || {
                    publication.check()
                })?;
                publication.check()?;
                phase.complete();
                Ok((prepared, serial))
            })
            .await?;
        phase.complete();
        Ok(result)
    }
}
