use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationalState {
    pub revision: u64,
    pub membership: AuthorityMembership,
    pub capacity: AuthorityCapacity,
    pub pending_operation: Option<Uuid>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokedMember {
    pub node_id: u64,
    pub member: AuthorityMember,
    pub operation_id: Uuid,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum MaintenanceTransition {
    Begin {
        command: AuthorityMaintenanceCommand,
    },
    Dispatch {
        operation_id: Uuid,
    },
    Finish {
        operation_id: Uuid,
    },
    CompleteDrain {
        operation_id: Uuid,
        status_sha256: String,
    },
    Stop {
        operation_id: Uuid,
    },
}
impl MaintenanceTransition {
    pub(crate) fn operation_id(&self) -> Uuid {
        match self {
            Self::Begin { command } => command.operation_id,
            Self::Dispatch { operation_id }
            | Self::Finish { operation_id }
            | Self::CompleteDrain { operation_id, .. }
            | Self::Stop { operation_id } => *operation_id,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedMaintenance {
    pub context: RequestContext,
    pub transition: MaintenanceTransition,
    pub admitted_at_ms: u64,
    pub authority_term: u64,
}
fn operation_key(id: Uuid) -> String {
    format!("maintenance/{id}")
}
fn revoked_key(id: u64) -> String {
    format!("revoked-member/{id:020}")
}

impl Backend {
    pub(crate) fn reserve_node_resources(&self, required: u64) -> Result<()> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        ensure!(
            required <= self.resource_budget_bytes,
            "authority resource acknowledgement exceeds installed budget"
        );
        let previous = self
            .store
            .get_bounded("authority.installation", b"resource-floor", 32)?
            .map(|bytes| serde_json::from_slice::<u64>(&bytes))
            .transpose()?
            .unwrap_or(0);
        if required > previous {
            self.store.write_batch(&[WriteOp::put(
                "authority.installation",
                b"resource-floor",
                serde_json::to_vec(&required)?,
            )])?;
        }
        Ok(())
    }

    pub(crate) fn maintenance_status(
        &self,
        id: Uuid,
    ) -> Result<Option<AuthorityMaintenanceStatus>> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        self.maintenance_status_unlocked(id)
    }
    fn maintenance_status_unlocked(&self, id: Uuid) -> Result<Option<AuthorityMaintenanceStatus>> {
        match self.record(&operation_key(id))? {
            None => Ok(None),
            Some(Record::Maintenance(status)) => Ok(Some(status)),
            _ => anyhow::bail!("authority maintenance record type differs"),
        }
    }
    pub(crate) fn operational_configuration(&self) -> Result<AuthorityOperationalConfiguration> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let meta = self.meta()?;
        Ok(AuthorityOperationalConfiguration {
            policy_epoch: meta.policy_epoch,
            revision: meta.operational.revision,
            membership: meta.operational.membership,
            capacity: meta.operational.capacity,
            pending_operation: meta.operational.pending_operation,
        })
    }
    pub(crate) fn peer_member(&self, node_id: u64) -> Result<AuthorityMember> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        ensure!(
            self.record(&revoked_key(node_id))?.is_none(),
            "authority member is permanently revoked"
        );
        self.meta()?
            .operational
            .membership
            .members
            .get(&node_id)
            .cloned()
            .context("authority member is not active")
    }
    pub(crate) fn peer_allowed(&self, node_id: u64) -> Result<()> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        ensure!(
            self.meta()?
                .operational
                .membership
                .members
                .contains_key(&node_id)
                && self.record(&revoked_key(node_id))?.is_none(),
            "authority member is not active"
        );
        Ok(())
    }
    pub(super) fn reduce_maintenance(
        &self,
        position: &AppliedEntryContext,
        prepared: PreparedMaintenance,
    ) -> Result<kasumi_types::Result<AuthorityMaintenanceStatus>> {
        let mut meta = self.meta()?;
        if let Err(error) = prepared
            .context
            .authorization
            .check_admitted_at(prepared.admitted_at_ms)
        {
            return Ok(Err(error));
        }
        if let Err(error) = self.authorize(&meta, &prepared.context) {
            return Ok(Err(error));
        }
        if prepared.authority_term != position.log_id.leader_id.term {
            return Ok(Err(conflict("maintenance proposal term changed")));
        }
        let id = prepared.transition.operation_id();
        let previous = self.maintenance_status_unlocked(id)?;
        let mut additions = Vec::new();
        let mut status = match &prepared.transition {
            MaintenanceTransition::Begin { command } => {
                if command.validate().is_err() {
                    return Ok(Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid authority maintenance command",
                    )));
                }
                if let Some(previous) = previous {
                    return Ok(if previous.command == *command {
                        Ok(previous)
                    } else {
                        Err(conflict(
                            "permanent maintenance identity has different input",
                        ))
                    });
                }
                if matches!(
                    command.action,
                    AuthorityMaintenanceAction::AuthorizeSignerTrust { .. }
                ) && !prepared
                    .context
                    .authorization
                    .expires_at_ms()
                    .is_some_and(|expiry| command.not_after_ms <= expiry)
                {
                    return Ok(Err(Error::new(
                        ErrorCode::Unauthorized,
                        "signer directive exceeds the original finite credential",
                    )));
                }
                if command.expected_policy_epoch != meta.policy_epoch
                    || prepared.admitted_at_ms > command.not_after_ms
                {
                    return Ok(Err(conflict(
                        "maintenance admission deadline or policy epoch changed",
                    )));
                }
                let mut status = AuthorityMaintenanceStatus {
                    command: command.clone(),
                    command_sha256: command.digest()?,
                    admitted_principal: prepared.context.principal.clone(),
                    admitted_revision: position.log_id.index,
                    progress_revision: position.log_id.index,
                    phase: AuthorityMaintenancePhase::Prepared,
                };
                let validation = self.validate_maintenance_start(&meta, command);
                if let Err(error) = validation {
                    status.phase = AuthorityMaintenancePhase::Rejected {
                        code: error.code,
                        message: error.message,
                    };
                } else if let AuthorityMaintenanceAction::SetCapacity { capacity } = &command.action
                {
                    meta.operational.capacity = capacity.clone();
                    status.phase = AuthorityMaintenancePhase::Completed;
                    meta.operational.revision = position.log_id.index;
                } else if matches!(
                    command.action,
                    AuthorityMaintenanceAction::AuthorizeSignerTrust { .. }
                ) {
                    status.phase = AuthorityMaintenancePhase::Completed;
                    meta.operational.revision = position.log_id.index;
                } else {
                    meta.operational.pending_operation = Some(id);
                    meta.operational.revision = position.log_id.index;
                }
                meta.maintenance_receipts = meta
                    .maintenance_receipts
                    .checked_add(1)
                    .context("maintenance receipt count exhausted")?;
                status
            }
            _ => {
                let Some(status) = previous else {
                    return Ok(Err(Error::new(
                        ErrorCode::NotFound,
                        "maintenance operation is absent",
                    )));
                };
                if status.phase.terminal() {
                    return Ok(Ok(status));
                }
                if meta.operational.pending_operation != Some(id) {
                    anyhow::bail!("pending maintenance identity differs");
                }
                status
            }
        };
        match &prepared.transition {
            MaintenanceTransition::Begin { .. } => {}
            MaintenanceTransition::Stop { .. } => {
                if status.phase != AuthorityMaintenancePhase::Prepared {
                    return Ok(Err(conflict("dispatched maintenance must resolve forward")));
                }
                status.phase = AuthorityMaintenancePhase::Stopped;
                meta.operational.pending_operation = None;
            }
            MaintenanceTransition::Dispatch { .. } => {
                if status.phase != AuthorityMaintenancePhase::Prepared {
                    return Ok(Ok(status));
                }
                if let AuthorityMaintenanceAction::EnrollLearner { node_id, member } =
                    &status.command.action
                {
                    meta.operational
                        .membership
                        .members
                        .insert(*node_id, member.clone());
                }
                status.phase = AuthorityMaintenancePhase::Dispatched;
            }
            MaintenanceTransition::Finish { .. } => {
                if status.phase != AuthorityMaintenancePhase::Dispatched {
                    return Ok(Ok(status));
                }
                let membership = position.membership.membership();
                let voters: BTreeSet<_> = membership.voter_ids().collect();
                match &status.command.action {
                    AuthorityMaintenanceAction::EnrollLearner { node_id, member } => {
                        if membership
                            .nodes()
                            .find(|(id, _)| *id == node_id)
                            .map(|(_, node)| &node.addr)
                            != Some(&member.endpoint)
                        {
                            return Ok(Err(conflict(
                                "learner membership has not committed its exact endpoint",
                            )));
                        }
                        status.phase = AuthorityMaintenancePhase::Completed;
                    }
                    AuthorityMaintenanceAction::ReplaceVoters { voters: desired } => {
                        if membership.get_joint_config().len() != 1 || voters != *desired {
                            return Ok(Err(conflict(
                                "requested final authority membership is not committed",
                            )));
                        }
                        meta.operational.membership.voters = desired.clone();
                        status.phase = AuthorityMaintenancePhase::Completed;
                    }
                    AuthorityMaintenanceAction::RevokeMember { node_id } => {
                        if membership.nodes().any(|(id, _)| id == node_id) {
                            return Ok(Err(conflict(
                                "member remains in committed Raft membership",
                            )));
                        }
                        let member = meta
                            .operational
                            .membership
                            .members
                            .remove(node_id)
                            .context("revoked member is absent")?;
                        additions.push((
                            revoked_key(*node_id),
                            Record::RevokedMember(RevokedMember {
                                node_id: *node_id,
                                member,
                                operation_id: id,
                                revision: position.log_id.index,
                            }),
                        ));
                        meta.member_revocations = meta
                            .member_revocations
                            .checked_add(1)
                            .context("member revocation count exhausted")?;
                        status.phase = AuthorityMaintenancePhase::Draining;
                    }
                    AuthorityMaintenanceAction::SetCapacity { .. }
                    | AuthorityMaintenanceAction::AuthorizeSignerTrust { .. } => {
                        anyhow::bail!("capacity maintenance requires no dispatch")
                    }
                }
                if status.phase.terminal() {
                    meta.operational.pending_operation = None;
                }
            }
            MaintenanceTransition::CompleteDrain { status_sha256, .. } => {
                if status.phase != AuthorityMaintenancePhase::Draining
                    || *status_sha256
                        != digest(&("kasumi.authority-maintenance-status.v1", &status))?
                {
                    return Ok(Err(conflict(
                        "complete issuer drain is not bound to current maintenance phase",
                    )));
                }
                status.phase = AuthorityMaintenancePhase::Completed;
                meta.operational.pending_operation = None;
            }
        }
        status.progress_revision = position.log_id.index;
        status.validate()?;
        meta.operational.revision = position.log_id.index;
        meta.operational.membership.validate()?;
        meta.operational.capacity.validate()?;
        additions.push((operation_key(id), Record::Maintenance(status.clone())));
        let mut writes = Vec::new();
        for (key, record) in additions {
            let bytes = serde_json::to_vec(&record)?;
            ensure!(
                bytes.len() <= MAX_RECORD_BYTES,
                "maintenance record exceeds its byte bound"
            );
            let previous = self
                .store
                .get_bounded(NS, key.as_bytes(), MAX_RECORD_BYTES)?;
            meta.state_bytes = meta
                .state_bytes
                .checked_sub(previous.as_ref().map_or(0, |bytes| bytes.len() as u64))
                .context("maintenance byte accounting underflow")?
                .checked_add(bytes.len() as u64)
                .context("maintenance byte accounting overflow")?;
            writes.push(WriteOp::put(NS, key.as_bytes(), bytes));
        }
        let reserved = Self::completion_reserve(&meta);
        if meta.state_bytes.saturating_add(reserved).saturating_add(
            if meta.operational.pending_operation.is_some() {
                MAX_RECORD_BYTES as u64
            } else {
                0
            },
        ) > meta.operational.capacity.max_state_bytes
        {
            return Ok(Err(Error::new(
                ErrorCode::ResourceExhausted,
                "authority maintenance byte capacity exhausted",
            )));
        }
        meta.revision = position.log_id.index;
        writes.push(WriteOp::put(NS, META, serde_json::to_vec(&meta)?));
        self.store.write_batch(&writes)?;
        Ok(Ok(status))
    }
    fn validate_maintenance_start(
        &self,
        meta: &Meta,
        command: &AuthorityMaintenanceCommand,
    ) -> kasumi_types::Result<()> {
        if meta.operational.revision != command.expected_operational_revision
            || meta.operational.pending_operation.is_some()
        {
            return Err(conflict(
                "authority operational revision changed or maintenance remains pending",
            ));
        }
        let mut next = meta.operational.membership.clone();
        match &command.action {
            AuthorityMaintenanceAction::AuthorizeSignerTrust {
                verifier,
                domain_sha256,
                command,
            } => {
                if next
                    .members
                    .get(&verifier.node_id)
                    .is_none_or(|member| member.verifier != *verifier)
                    || self
                        .record(&revoked_key(verifier.node_id))
                        .map_err(unavailable)?
                        .is_some()
                    || *domain_sha256
                        != self
                            .installation
                            .manifest
                            .signing_domain(self.installation.partition)
                            .map_err(unavailable)?
                            .digest()
                            .map_err(unavailable)?
                {
                    return Err(conflict(
                        "signer directive member or installed domain differs",
                    ));
                }
                if let SignerTrustAction::Stage { certificate } = &command.action {
                    certificate
                        .verify(
                            &self
                                .installation
                                .manifest
                                .signing_domain(self.installation.partition)
                                .map_err(unavailable)?,
                        )
                        .map_err(unavailable)?;
                }
            }
            AuthorityMaintenanceAction::EnrollLearner { node_id, member } => {
                if next.members.contains_key(node_id)
                    || self
                        .record(&revoked_key(*node_id))
                        .map_err(unavailable)?
                        .is_some()
                {
                    return Err(conflict(
                        "authority member identity is already allocated or permanently revoked",
                    ));
                }
                next.members.insert(*node_id, member.clone());
            }
            AuthorityMaintenanceAction::ReplaceVoters { voters } => next.voters = voters.clone(),
            AuthorityMaintenanceAction::RevokeMember { node_id } => {
                if next.voters.contains(node_id) || next.members.remove(node_id).is_none() {
                    return Err(conflict(
                        "replace an active voter before revoking its member identity",
                    ));
                }
            }
            AuthorityMaintenanceAction::SetCapacity { capacity } => {
                capacity.validate().map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid authority byte capacity",
                    )
                })?;
                if capacity.max_tenants < meta.tenants
                    || meta
                        .state_bytes
                        .saturating_add(Self::completion_reserve(meta))
                        .saturating_add(capacity.maintenance_reserve_bytes)
                        > capacity.max_state_bytes
                {
                    return Err(conflict(
                        "new authority capacity cannot fit durable records and reserved completions",
                    ));
                }
            }
        }
        next.validate().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "authority membership violates installed endpoint or failure-domain requirements",
            )
        })
    }
    pub(super) fn completion_reserve(meta: &Meta) -> u64 {
        meta.active_fences
            .saturating_mul(3 * MAX_RECORD_BYTES as u64)
            .saturating_add(
                meta.open_control_epochs
                    .saturating_mul(MAX_RECORD_BYTES as u64),
            )
    }
}

impl Backend {
    pub(super) fn validate_maintenance_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let state = &snapshot.meta.operational;
        state.membership.validate()?;
        state.capacity.validate()?;
        ensure!(
            state.revision <= snapshot.meta.revision,
            "authority operational revision exceeds applied state"
        );
        let (mut operations, mut revocations, mut pending) = (0u64, 0u64, None);
        snapshot.records.visit(|key, record| {
            match record {
                Record::Maintenance(status) => {
                    status.validate()?;
                    ensure!(key == operation_key(status.command.operation_id)
                        && status.progress_revision <= snapshot.meta.revision, "authority maintenance snapshot identity or position differs");
                    operations = operations.checked_add(1).context("maintenance count overflow")?;
                    if !status.phase.terminal() {
                        ensure!(pending.replace(status.command.operation_id).is_none(), "multiple unfinished authority maintenance operations");
                    }
                    if let AuthorityMaintenanceAction::AuthorizeSignerTrust { verifier, domain_sha256, command } = &status.command.action {
                        ensure!(matches!(status.phase, AuthorityMaintenancePhase::Completed | AuthorityMaintenancePhase::Rejected { .. }), "signer authorization has an impossible dispatched phase");
                        if status.phase == AuthorityMaintenancePhase::Completed {
                            let domain = self.installation.manifest.signing_domain(self.installation.partition)?;
                            ensure!(*domain_sha256 == domain.digest()?, "signer directive snapshot domain differs");
                            ensure!(state.membership.members.get(&verifier.node_id).is_some_and(|member| member.verifier == *verifier)
                                || matches!(snapshot.records.get(&revoked_key(verifier.node_id))?, Some(Record::RevokedMember(ref record)) if record.member.verifier == *verifier), "signer directive member lacks its permanent physical identity");
                            if let SignerTrustAction::Stage { certificate } = &command.action { certificate.verify(&domain)?; }
                        }
                    }
                    if let AuthorityMaintenanceAction::EnrollLearner { node_id, member } = &status.command.action
                        && matches!(status.phase, AuthorityMaintenancePhase::Dispatched | AuthorityMaintenancePhase::Completed) {
                        if let Some(current) = state.membership.members.get(node_id) {
                            ensure!(current == member, "enrolled authority member differs from its permanent command");
                        } else {
                            ensure!(matches!(snapshot.records.get(&revoked_key(*node_id))?, Some(Record::RevokedMember(ref revoked)) if revoked.member == *member), "enrolled authority member has neither live identity nor permanent revocation");
                        }
                    }
                }
                Record::RevokedMember(revoked) => {
                    revoked.member.validate()?;
                    ensure!(revoked.node_id == revoked.member.verifier.node_id && revoked.revision > 0 && revoked.revision <= snapshot.meta.revision
                        && key == revoked_key(revoked.node_id) && !state.membership.members.contains_key(&revoked.node_id),
                        "revoked authority member snapshot identity differs");
                    let Some(Record::Maintenance(status)) = snapshot.records.get(&operation_key(revoked.operation_id))? else {
                        anyhow::bail!("authority member revocation lacks permanent operation identity");
                    };
                    ensure!(matches!(status.command.action, AuthorityMaintenanceAction::RevokeMember { node_id } if node_id == revoked.node_id)
                        && matches!(status.phase, AuthorityMaintenancePhase::Draining | AuthorityMaintenancePhase::Completed)
                        && status.progress_revision >= revoked.revision, "authority member revocation outcome differs");
                    revocations = revocations.checked_add(1).context("revocation count overflow")?;
                }
                _ => {}
            }
            Ok(())
        })?;
        ensure!(
            operations == snapshot.meta.maintenance_receipts
                && revocations == snapshot.meta.member_revocations
                && pending == state.pending_operation,
            "authority maintenance snapshot accounting differs"
        );
        Ok(())
    }
}
