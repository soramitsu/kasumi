//! Protected observation of a stopped physical generation. Reading its journal
//! does not acquire a target operation, open the generation or replay cleanup.
use super::*;
use kasumi_client::{KasumiLifecyclePool, KasumiRecoveryPool};

pub(crate) struct TargetDeletionReply {
    pub(crate) status: TargetDeletionStatus,
    runtime: Arc<TargetRecoveryRuntime>,
    admission: TargetRequestAdmission,
    bearer: Zeroizing<String>,
    context: RequestContext,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl TargetDeletionReply {
    pub(crate) async fn release(&self) -> Result<()> {
        let latest = self
            .runtime
            .observe_deletion(
                &self.status.query,
                &self.context,
                &self.bearer,
                &self.admission,
            )
            .await?;
        ensure!(
            latest == self.status,
            "deletion progressed during response release"
        );
        Ok(())
    }
}

impl TargetRecoveryRuntime {
    pub(crate) async fn read_deletion_status(
        self: &Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        query: TargetDeletionQuery,
    ) -> Result<TargetDeletionReply> {
        query.validate()?;
        ensure!(
            query.node_id == self.installed.node.node_id,
            "deletion observation names another installed target"
        );
        let bearer = self.phase_observation_credential(bearer)?;
        let admission = TargetRequestAdmission::capture(
            context.clone(),
            self.installed.limits.operation_timeout_ms,
        )?;
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .context("target invocation capacity exhausted")?;
        let status = self
            .observe_deletion(&query, &context, &bearer, &admission)
            .await?;
        Ok(TargetDeletionReply {
            status,
            runtime: self.clone(),
            admission,
            bearer,
            context,
            _permit: permit,
        })
    }

    async fn observe_deletion(
        &self,
        query: &TargetDeletionQuery,
        context: &RequestContext,
        bearer: &Zeroizing<String>,
        admission: &TargetRequestAdmission,
    ) -> Result<TargetDeletionStatus> {
        admission.require_context(context)?;
        context
            .authorization
            .require_control(&self.installed.control_root.control_incarnation.to_string())?;
        ensure!(
            context.tenant == "__kasumi_control" && context.scopes.contains(&Action::Admin),
            "current Control Admin required"
        );
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let connections = self.installed.control_connections()?;
        let credential = bearer.clone();
        let mut recovery = KasumiRecoveryPool::new(
            connections.clone(),
            Arc::new(move || Ok(credential.clone())),
        )?;
        let phase = recovery
            .read_phase(
                &RecoveryPhaseRequest {
                    operation_id: query.operation_id,
                    phase_id: query.phase_id,
                },
                admission.remaining_response()?,
            )
            .await?;
        let RecoveryDispatch::Target { request, node_id } = &phase.input else {
            anyhow::bail!("deletion observation has no target dispatch");
        };
        ensure!(
            *node_id == query.node_id && matches!(request.step, TargetRuntimeStep::Stop(_)),
            "deletion observation is not this target's StopLocal"
        );
        // A completed StopLocal already carries the target and issuer signatures.
        // Read that history under the current observer's grant after cold restart.
        let original = if phase.outcome.is_some() {
            None
        } else {
            let credential = bearer.clone();
            let trust = kasumi_serving::ControlTrust::install(self.installed.control_root.clone())?;
            let mut control = KasumiLifecyclePool::new(
                connections,
                trust,
                Arc::new(move || Ok(credential.clone())),
            )?;
            Some(
                control
                    .observe_intent(request.command_id, admission.remaining_response()?)
                    .await?,
            )
        };
        admission.check()?;
        let status = self
            .journal
            .deletion_status(query, original.as_ref(), &phase)?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        admission.check()?;
        Ok(status)
    }
}
