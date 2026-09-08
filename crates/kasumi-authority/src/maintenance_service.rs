use super::*;
use crate::state::maintenance_state::{MaintenanceTransition, PreparedMaintenance};

impl IndependentAuthority {
    pub fn install_maintenance_transport(
        &self,
        transport: Arc<dyn AuthorityMaintenanceTransport>,
    ) -> anyhow::Result<()> {
        self.maintenance_transport
            .set(transport)
            .map_err(|_| anyhow::anyhow!("authority maintenance transport already installed"))
    }
    /// Called only through a pinned peer connection. Durable acknowledgement
    /// prevents a restart with smaller resources from invalidating readiness
    /// already observed by a leader whose completion may still be uncertain.
    pub fn check_maintenance_ready(
        &self,
        bootstrap_sha256: &str,
        required_state_bytes: u64,
        command: &AuthorityMaintenanceCommand,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            bootstrap_sha256 == self.bootstrap_digest,
            "authority maintenance bootstrap differs"
        );
        command.validate()?;
        anyhow::ensure!(
            required_state_bytes <= self.settings.resource_budget_bytes,
            "authority member cannot fit required operational state"
        );
        self.group.check_access()?;
        self.validate_installed_maintenance(command)?;
        let required = match &command.action {
            AuthorityMaintenanceAction::SetCapacity { capacity } => {
                required_state_bytes.max(capacity.max_state_bytes)
            }
            _ => required_state_bytes,
        };
        self.backend.reserve_node_resources(required)?;
        Ok(())
    }
    async fn preflight_maintenance(&self, command: &AuthorityMaintenanceCommand) -> Result<()> {
        self.validate_installed_maintenance(command)?;
        if !matches!(
            command.action,
            AuthorityMaintenanceAction::EnrollLearner { .. }
                | AuthorityMaintenanceAction::SetCapacity { .. }
        ) {
            return Ok(());
        }
        let configuration = self
            .backend
            .operational_configuration()
            .map_err(unavailable)?;
        let mut members: std::collections::BTreeSet<_> =
            configuration.membership.members.keys().copied().collect();
        if let AuthorityMaintenanceAction::EnrollLearner { node_id, .. } = &command.action {
            members.insert(*node_id);
        }
        let transport = self
            .maintenance_transport
            .get()
            .ok_or_else(|| unavailable("authority maintenance transport unavailable"))?;
        tokio::time::timeout(Duration::from_secs(30), async {
            for node_id in members {
                transport
                    .check_ready(
                        node_id,
                        &self.bootstrap_digest,
                        configuration.capacity.max_state_bytes,
                        command,
                    )
                    .await
                    .map_err(unavailable)?;
            }
            Ok(())
        })
        .await
        .map_err(unavailable)?
    }

    /// Trusted transport callback. Approved endpoints alone do not override a
    /// member identity permanently revoked in applied operational state.
    pub fn peer_allowed(&self, node_id: u64) -> anyhow::Result<()> {
        let member = self.backend.peer_member(node_id)?;
        anyhow::ensure!(
            self.settings.installed_members.get(&node_id) == Some(&member),
            "installed peer trust differs from committed authority membership"
        );
        Ok(())
    }
    pub(super) fn check_installed_configuration(&self) -> anyhow::Result<()> {
        let current = self.backend.operational_configuration()?;
        anyhow::ensure!(
            current.capacity.max_state_bytes <= self.settings.resource_budget_bytes,
            "current authority capacity exceeds installed resources"
        );
        for (id, member) in &current.membership.members {
            anyhow::ensure!(
                self.settings.installed_members.get(id) == Some(member),
                "installed peer trust differs from committed authority membership"
            );
        }
        self.backend.peer_allowed(self.local_node_id)
    }
    pub async fn maintenance(
        self: &Arc<Self>,
        context: RequestContext,
        request: AuthorityMaintenanceRequest,
    ) -> Result<(AuthorityMaintenanceResponse, AuthorityResponseFence)> {
        request.validate().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid authority maintenance request",
            )
        })?;
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        match request {
            AuthorityMaintenanceRequest::Configuration => {
                let configuration = self
                    .backend
                    .operational_configuration()
                    .map_err(unavailable)?;
                return Ok((
                    AuthorityMaintenanceResponse::Configuration { configuration },
                    self.fence(signer.clone(), context, Some(epoch), None, term),
                ));
            }
            AuthorityMaintenanceRequest::Status { operation_id } => {
                let status = self
                    .backend
                    .maintenance_status(operation_id)
                    .map_err(unavailable)?
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::NotFound,
                            "authority maintenance operation is absent",
                        )
                    })?;
                return Ok((
                    AuthorityMaintenanceResponse::Operation { status },
                    self.fence(signer.clone(), context, Some(epoch), None, term),
                ));
            }
            _ => {}
        }
        let service = self.clone();
        // Own accepted work through cancellation and remote response loss. The
        // exact phase journal precedes every external membership operation.
        let job = tokio::spawn(async move {
            let _permit = permit;
            service.maintenance_owned(signer, context, request).await
        });
        tokio::time::timeout(Duration::from_secs(35), job)
            .await
            .map_err(unknown)?
            .map_err(unknown)?
    }
    async fn maintenance_owned(
        self: Arc<Self>,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        request: AuthorityMaintenanceRequest,
    ) -> Result<(AuthorityMaintenanceResponse, AuthorityResponseFence)> {
        let _serial = self.proposal.lock().await;
        let term = self.barrier(&context).await?;
        self.backend.authorize_admin(&context)?;
        let id = request
            .operation_id()
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "maintenance identity absent"))?;
        let mut status = match request {
            AuthorityMaintenanceRequest::Start { command } => {
                if let Some(status) = self.backend.maintenance_status(id).map_err(unavailable)? {
                    if status.command != command {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "permanent maintenance identity has different input",
                        ));
                    }
                    status
                } else {
                    self.preflight_maintenance(&command).await?;
                    self.maintenance_write(&context, term, MaintenanceTransition::Begin { command })
                        .await?
                }
            }
            AuthorityMaintenanceRequest::Resume { .. }
            | AuthorityMaintenanceRequest::Stop { .. } => {
                let status = self
                    .backend
                    .maintenance_status(id)
                    .map_err(unavailable)?
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::NotFound,
                            "authority maintenance operation is absent",
                        )
                    })?;
                if matches!(request, AuthorityMaintenanceRequest::Stop { .. }) {
                    let stopped = self
                        .maintenance_write(
                            &context,
                            term,
                            MaintenanceTransition::Stop { operation_id: id },
                        )
                        .await?;
                    return self
                        .release_maintenance(signer.clone(), context, stopped, term)
                        .await;
                }
                status
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "maintenance dispatch differs",
                ));
            }
        };
        if status.phase == AuthorityMaintenancePhase::Prepared {
            self.preflight_maintenance(&status.command).await?;
            status = self
                .maintenance_write(
                    &context,
                    term,
                    MaintenanceTransition::Dispatch { operation_id: id },
                )
                .await?;
        }
        if status.phase == AuthorityMaintenancePhase::Dispatched {
            self.validate_installed_maintenance(&status.command)?;
            self.barrier(&context).await?;
            match &status.command.action {
                AuthorityMaintenanceAction::EnrollLearner { node_id, member } => {
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        self.group
                            .add_learner(*node_id, BasicNode::new(member.endpoint.clone())),
                    )
                    .await
                    .map_err(unknown)?
                    .map_err(unknown)?;
                }
                AuthorityMaintenanceAction::ReplaceVoters { voters } => {
                    let metrics = self.group.raft().metrics().borrow().clone();
                    if !voters.iter().all(|id| {
                        metrics
                            .membership_config
                            .nodes()
                            .any(|(node, _)| node == id)
                    }) {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "all replacement authority voters must first complete learner catch-up",
                        ));
                    }
                    let committed: std::collections::BTreeSet<_> =
                        metrics.membership_config.voter_ids().collect();
                    if metrics
                        .membership_config
                        .membership()
                        .get_joint_config()
                        .len()
                        != 1
                        || committed != *voters
                    {
                        tokio::time::timeout(
                            Duration::from_secs(30),
                            self.group.change_membership(voters.clone()),
                        )
                        .await
                        .map_err(unknown)?
                        .map_err(unknown)?;
                    }
                }
                AuthorityMaintenanceAction::RevokeMember { node_id } => {
                    if self
                        .group
                        .raft()
                        .metrics()
                        .borrow()
                        .membership_config
                        .nodes()
                        .any(|(id, _)| id == node_id)
                    {
                        tokio::time::timeout(
                            Duration::from_secs(30),
                            self.group.remove_learner(*node_id),
                        )
                        .await
                        .map_err(unknown)?
                        .map_err(unknown)?;
                    }
                }
                AuthorityMaintenanceAction::EnrollSignerVerifier { .. }
                | AuthorityMaintenanceAction::AdmitControlVerifiers { .. }
                | AuthorityMaintenanceAction::StageSignerGeneration { .. }
                | AuthorityMaintenanceAction::ActivateSignerGeneration { .. }
                | AuthorityMaintenanceAction::SetCapacity { .. }
                | AuthorityMaintenanceAction::AuthorizeSignerTrust { .. } => {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "capacity operation unexpectedly dispatched",
                    ));
                }
            }
            status = self
                .maintenance_write(
                    &context,
                    term,
                    MaintenanceTransition::Finish { operation_id: id },
                )
                .await?;
        }
        if status.phase == AuthorityMaintenancePhase::Draining {
            let status_sha256 = digest(&("kasumi.authority-maintenance-status.v1", &status))
                .map_err(unavailable)?;
            // An incomplete drain is a durable phase, not a failed command. A
            // new leader restarts its private full-interval witness conservatively.
            if self.require_drain(&status_sha256, term).is_ok() {
                status = self
                    .maintenance_write(
                        &context,
                        term,
                        MaintenanceTransition::CompleteDrain {
                            operation_id: id,
                            status_sha256,
                        },
                    )
                    .await?;
            }
        }
        self.release_maintenance(signer.clone(), context, status, term)
            .await
    }
    fn validate_installed_maintenance(&self, command: &AuthorityMaintenanceCommand) -> Result<()> {
        match &command.action {
            AuthorityMaintenanceAction::EnrollLearner { node_id, member } => {
                if self.settings.installed_members.get(node_id) != Some(member) {
                    return Err(Error::new(
                        ErrorCode::Forbidden,
                        "authority learner differs from the installed transport pool",
                    ));
                }
            }
            AuthorityMaintenanceAction::SetCapacity { capacity }
                if capacity.max_state_bytes > self.settings.resource_budget_bytes =>
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "authority capacity exceeds this node's installed resource budget",
                ));
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) async fn maintenance_write(
        &self,
        context: &RequestContext,
        term: u64,
        transition: MaintenanceTransition,
    ) -> Result<AuthorityMaintenanceStatus> {
        if self.barrier(context).await? != term {
            return Err(unknown("authority maintenance leader changed"));
        }
        self.backend.authorize_admin(context)?;
        let admitted_at_ms = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        let prepared = PreparedOperation::Maintenance(Box::new(PreparedMaintenance {
            context: context.clone(),
            transition,
            admitted_at_ms,
            authority_term: term,
        }));
        let response = self
            .write_proposal(serde_json::to_vec(&prepared).map_err(unavailable)?, term)
            .await?;
        serde_json::from_slice(&response).map_err(unknown)?
    }
    async fn release_maintenance(
        self: &Arc<Self>,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        status: AuthorityMaintenanceStatus,
        term: u64,
    ) -> Result<(AuthorityMaintenanceResponse, AuthorityResponseFence)> {
        if self.barrier(&context).await? != term {
            return Err(unknown(
                "authority maintenance leader changed before release",
            ));
        }
        let epoch = self.backend.authorize_admin(&context)?;
        let fence = self.fence(signer.clone(), context, Some(epoch), None, term);
        fence.check()?;
        Ok((AuthorityMaintenanceResponse::Operation { status }, fence))
    }
}
