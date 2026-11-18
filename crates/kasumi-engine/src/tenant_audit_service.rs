//! Private observations of a tenant's retained audit stream at one quorum position.
use super::*;

impl Database {
    pub async fn tenant_audit_status(
        &self,
        context: &RequestContext,
    ) -> Result<AdmittedOutput<TenantAuditStatus>> {
        let result = self.tenant_audit_status_inner(context).await;
        self.audit_result(context, result).await
    }

    async fn tenant_audit_status_inner(
        &self,
        context: &RequestContext,
    ) -> Result<AdmittedOutput<TenantAuditStatus>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Audit)?;
        let mut reservation = self.admission().reserve(64 << 10, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        self.engine
            .authorize_release(context, None, Action::Audit, state.policy_epoch)?;
        let hot_tail_sha256 = state
            .audits
            .back()
            .map(|event| staged_digest(event).map(|(digest, _)| digest))
            .transpose()?;
        let status = TenantAuditStatus {
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            revision: state.revision,
            position: state.audit_retention.clone(),
            budget: state.limits.audit_retention.clone(),
            hot_tail_sha256,
        };
        status
            .validate()
            .map_err(|error| Error::new(ErrorCode::Corruption, error.message))?;
        let epoch = state.policy_epoch;
        let strict = state.policy.strict_read_audit;
        drop(generation);
        self.release_event(
            context,
            None,
            status.revision,
            strict,
            epoch,
            "tenant_audit_status",
        )
        .await?;
        self.engine
            .authorize_release(context, None, Action::Audit, epoch)?;
        self.access()?;
        reservation.retain_workspace();
        Ok(AdmittedOutput::new(status, Arc::new(reservation)))
    }
}
