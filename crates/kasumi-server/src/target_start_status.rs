//! A Start status response keeps its actual generation locked through encoding
//! and audit. Fresh Control reads and the original live child are required at
//! each release fence; stored rows never reopen a generation.
use super::*;

pub(crate) struct TargetInitialStartReply {
    pub(crate) status: TargetInitialStartStatus,
    runtime: Arc<TargetRecoveryRuntime>,
    generation: tokio::sync::OwnedMutexGuard<Generation>,
    query: TargetInitialStartRequest,
    context: RequestContext,
    bearer: Zeroizing<String>,
    admission: TargetRequestAdmission,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl TargetInitialStartReply {
    pub(crate) async fn release(&self) -> Result<()> {
        let current = self
            .runtime
            .check_initial_start_status(
                &self.generation,
                &self.query,
                &self.context,
                &self.bearer,
                &self.admission,
            )
            .await?;
        ensure!(
            current == self.status,
            "Start status changed before response release"
        );
        Ok(())
    }
}
impl TargetRecoveryRuntime {
    pub(crate) async fn read_initial_start(
        self: &Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        query: TargetInitialStartRequest,
    ) -> Result<TargetInitialStartReply> {
        query.validate_for_node(self.installed.node.node_id)?;
        let admission = TargetRequestAdmission::capture_until(
            context.clone(),
            self.installed.limits.operation_timeout_ms,
            query.request.not_after_ms,
        )?;
        context
            .authorization
            .require_control(&self.installed.control_root.control_incarnation.to_string())?;
        ensure!(
            context.tenant == "__kasumi_control" && context.scopes.contains(&Action::Admin),
            "target requires current Control Admin"
        );
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .context("target invocation capacity exhausted")?;
        let key = (query.request.tenant.clone(), query.target_incarnation);
        let owner = admission
            .run(async {
                self.generations
                    .lock()
                    .await
                    .get(&key)
                    .cloned()
                    .context("original Start generation is not owned")
            })
            .await?;
        let generation = admission
            .run(async { Ok(owner.lock_owned().await) })
            .await?;
        let status = self
            .check_initial_start_status(&generation, &query, &context, &bearer, &admission)
            .await?;
        Ok(TargetInitialStartReply {
            status,
            runtime: self.clone(),
            generation,
            query,
            context,
            bearer,
            admission,
            _permit: permit,
        })
    }

    pub(super) async fn check_initial_start_status(
        &self,
        generation: &Generation,
        query: &TargetInitialStartRequest,
        context: &RequestContext,
        bearer: &Zeroizing<String>,
        admission: &TargetRequestAdmission,
    ) -> Result<TargetInitialStartStatus> {
        query.validate_for_node(self.installed.node.node_id)?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let (original, marked) = observe_initial_dispatch_from_control(
            &self.installed,
            context,
            bearer,
            &query.request,
            &query.identity,
            query.target_incarnation,
            admission,
            #[cfg(test)]
            &self.marked_first_membership_reads,
        )
        .await?;
        let phase = generation
            .phase
            .as_ref()
            .context("original Start phase is not owned")?;
        ensure!(
            phase.original().observation().intent == original.observation().intent
                && phase.original().observation().root == original.observation().root,
            "Start child belongs to another installed Control phase"
        );
        phase.scope().invocation().check()?;
        ensure!(
            generation.registered_group.as_deref()
                == Some(&format!(
                    "{}/{}",
                    query.request.tenant, query.target_incarnation
                )),
            "original Start peer route is not owned"
        );
        let child = generation
            .replica
            .as_ref()
            .context("original Start child is not owned")?;
        self.journal
            .resolve_initial_start(&original, &marked, &query.identity, &query.request, child)?
            .check()?;
        let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input)) = &query.request.step
        else {
            anyhow::bail!("Start query input differs")
        };
        let status = TargetInitialStartStatus {
            contract: TargetInitialStartStatus::CONTRACT.into(),
            target_incarnation: query.target_incarnation,
            node_id: self.installed.node.node_id,
            identity: query.identity.clone(),
            origin_sha256: input.origin_sha256.clone(),
        };
        status.validate_for(query, self.installed.node.node_id)?;
        admission.check()?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        Ok(status)
    }
}
