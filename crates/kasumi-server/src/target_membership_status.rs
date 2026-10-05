//! A Membership status response keeps its actual generation locked through encoding
//! and audit. Fresh Control reads and the original live child are required at
//! each release fence; stored rows never reopen a generation.
use super::*;

pub(crate) struct TargetInitialMembershipReply {
    pub(crate) status: TargetInitialMembershipHistoryStatus,
    runtime: Arc<TargetRecoveryRuntime>,
    generation: tokio::sync::OwnedMutexGuard<Generation>,
    query: TargetInitialMembershipHistoryRequest,
    context: RequestContext,
    bearer: Zeroizing<String>,
    admission: TargetRequestAdmission,
    _permit: tokio::sync::OwnedSemaphorePermit,
    failure: TargetCallSeat,
}
impl TargetInitialMembershipReply {
    pub(crate) async fn release(&self) -> std::result::Result<(), TargetCallFailure> {
        self.failure
            .begin()?
            .run(self.release_inner())
            .await?
            .claim()?;
        Ok(())
    }
    async fn release_inner(&self) -> SnapshotResult<()> {
        let current = self
            .runtime
            .check_initial_membership_status(
                &self.generation,
                &self.query,
                &self.context,
                &self.bearer,
                &self.admission,
            )
            .await?;
        snapshot_ensure!(
            current.identity == self.status.identity
                && current.first_log_index == self.status.first_log_index
                && current.applied_log_index >= self.status.applied_log_index
                && current.committed_log_index >= self.status.committed_log_index,
            "Membership status changed before response release"
        );
        Ok(())
    }
}
impl TargetRecoveryRuntime {
    pub(crate) async fn read_initial_membership_history(
        self: &Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        query: TargetInitialMembershipHistoryRequest,
    ) -> std::result::Result<TargetInitialMembershipReply, TargetCallFailure> {
        let failure = self.call_jobs.acquire_failure()?;
        failure
            .begin()?
            .run(self.read_initial_membership_history_inner(
                context,
                bearer,
                query,
                failure.clone(),
            ))
            .await
            .and_then(|ticket| ticket.claim())
    }
    async fn read_initial_membership_history_inner(
        self: &Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        query: TargetInitialMembershipHistoryRequest,
        failure: TargetCallSeat,
    ) -> SnapshotResult<TargetInitialMembershipReply> {
        query.validate_for_node(self.installed.node.node_id)?;
        let admission = TargetRequestAdmission::capture_until(
            context.clone(),
            self.installed.limits.operation_timeout_ms,
            query.request.not_after_ms,
        )?;
        context
            .authorization
            .require_control(&self.installed.control_root.control_incarnation.to_string())?;
        snapshot_ensure!(
            context.tenant == "__kasumi_control" && context.scopes.contains(&Action::Admin),
            "target requires current Control Admin"
        );
        snapshot_ensure!(
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
            .run::<_, SnapshotFailure>(async {
                Ok(self
                    .generations
                    .lock()
                    .await
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| {
                        missing_target_owner("original Start generation is not owned")
                    })?)
            })
            .await?;
        let generation = admission
            .run::<_, SnapshotFailure>(async { Ok(owner.lock_owned().await) })
            .await?;
        let status = self
            .check_initial_membership_status(&generation, &query, &context, &bearer, &admission)
            .await?;
        Ok(TargetInitialMembershipReply {
            status,
            runtime: self.clone(),
            generation,
            query,
            context,
            bearer,
            admission,
            _permit: permit,
            failure,
        })
    }

    pub(super) async fn check_initial_membership_status(
        &self,
        generation: &Generation,
        query: &TargetInitialMembershipHistoryRequest,
        context: &RequestContext,
        bearer: &Zeroizing<String>,
        admission: &TargetRequestAdmission,
    ) -> SnapshotResult<TargetInitialMembershipHistoryStatus> {
        query.validate_for_node(self.installed.node.node_id)?;
        snapshot_ensure!(
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
            .ok_or_else(|| missing_target_owner("original Start phase is not owned"))?;
        snapshot_ensure!(
            phase.original().observation().intent == original.observation().intent
                && phase.original().observation().root == original.observation().root,
            "Start child belongs to another installed Control phase"
        );
        phase.scope().invocation().check()?;
        snapshot_ensure!(
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
            .ok_or_else(|| missing_target_owner("original Start child is not owned"))?;
        let stores = generation
            .stores
            .as_deref()
            .ok_or_else(|| missing_target_owner("original membership stores are not owned"))?;
        let history = self.journal.resolve_initial_membership_history(
            &original,
            &marked,
            &query.identity,
            &query.request,
            stores,
        )?;
        history.require_owner(child)?;
        let local = history.local();
        let status = TargetInitialMembershipHistoryStatus {
            contract: TargetInitialMembershipHistoryStatus::CONTRACT.into(),
            target_incarnation: query.target_incarnation,
            identity: history.identity().clone(),
            first_log_index: local.first_log_id().index,
            applied_log_index: local.applied_log_id().index,
            committed_log_index: local.committed_log_id().index,
        };
        status.validate_for(query)?;
        admission.check()?;
        snapshot_ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        Ok(status)
    }
}
