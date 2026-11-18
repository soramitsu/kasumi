//! Private observations of a tenant's retained audit stream at one quorum position.
use super::*;
#[path = "tenant_audit_export.rs"]
mod export;
#[path = "tenant_audit_verify.rs"]
mod verification;

impl Database {
    pub async fn tenant_audit_status(
        &self,
        context: &RequestContext,
    ) -> Result<AdmittedOutput<TenantAuditStatus>> {
        let result = self.tenant_audit_status_inner(context).await;
        self.audit_result(context, result).await
    }

    pub async fn tenant_audit_capacity(
        &self,
        context: &RequestContext,
    ) -> Result<AdmittedOutput<TenantAuditCapacity>> {
        let result = self.tenant_audit_capacity_inner(context).await;
        self.audit_result(context, result).await
    }

    async fn tenant_audit_capacity_inner(
        &self,
        context: &RequestContext,
    ) -> Result<AdmittedOutput<TenantAuditCapacity>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Audit)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let mut reservation = self.admission().reserve(64 << 10, Some(token.clone()))?;
        self.barrier().await?;
        // The encrypted point read has its own Store admission. The worker
        // owns the decoded headers, registration and extra parsing workspace.
        reservation.reserve_additional(1 << 20)?;
        let engine = self.engine.clone();
        let caller = context.clone();
        let ((capacity, epoch, strict), mut reservation) = tokio::task::spawn_blocking(move || {
            let _registration = registration;
            token.check()?;
            let value = engine.audit_capacity_observation(&caller)?;
            Ok::<_, Error>((value, reservation))
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "tenant audit observation worker failed",
            )
        })??;
        self.finish_tenant_audit_read(
            context,
            capacity.revision,
            epoch,
            strict,
            "tenant_audit_capacity",
        )
        .await?;
        reservation.retain(64 << 10);
        Ok(AdmittedOutput::new(capacity, Arc::new(reservation)))
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
        self.finish_tenant_audit_read(
            context,
            status.revision,
            epoch,
            strict,
            "tenant_audit_status",
        )
        .await?;
        reservation.retain_workspace();
        Ok(AdmittedOutput::new(status, Arc::new(reservation)))
    }

    async fn finish_tenant_audit_read(
        &self,
        context: &RequestContext,
        revision: u64,
        epoch: u64,
        strict: bool,
        operation: &'static str,
    ) -> Result<()> {
        self.release_event(context, None, revision, strict, epoch, operation)
            .await?;
        self.engine
            .authorize_release(context, None, Action::Audit, epoch)?;
        self.access()
    }
}
