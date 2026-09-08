//! Replicated dispatch and coverage facts. Only the internal leader preparation
//! path accepts a current native observation; public DTOs cannot prepare an ack.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CoverageBinding {
    stage_operation_id: Uuid,
    verifier: TrustVerifierIdentity,
    dispatch_operation_id: Uuid,
    revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CoveragePermission {
    dispatch_operation_id: Uuid,
    permission_operation_id: Uuid,
    permission_sha256: String,
    permission_revision: u64,
    revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CoverageTransition {
    Begin {
        command: SignerCoverageCommand,
    },
    Acknowledge {
        operation_id: Uuid,
        dispatch_sha256: String,
        publication: SignerPublicationResponse,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedCoverage {
    pub context: RequestContext,
    pub admitted_at_ms: u64,
    pub authority_term: u64,
    pub transition: CoverageTransition,
}
fn dispatch_key(id: Uuid) -> String {
    format!("signer-dispatch/{id}")
}
fn acknowledgment_key(id: Uuid) -> String {
    format!("signer-coverage/{id}")
}
fn permission_key(id: Uuid) -> String {
    format!("signer-coverage-permission/{id}")
}
fn binding_key(stage: Uuid, verifier: &TrustVerifierIdentity) -> String {
    format!(
        "signer-dispatch-verifier/{stage}/{}/{:020}",
        verifier.installation_id, verifier.node_id
    )
}
impl Backend {
    pub(crate) fn signer_coverage_status(&self, id: Uuid) -> Result<Option<SignerCoverageStatus>> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        self.coverage_status_unlocked(id)
    }
    fn coverage_status_unlocked(&self, id: Uuid) -> Result<Option<SignerCoverageStatus>> {
        let Some(record) = self.record(&dispatch_key(id))? else {
            return Ok(None);
        };
        let Record::CoverageDispatch(dispatch) = record else {
            anyhow::bail!("coverage dispatch record differs");
        };
        let acknowledgment = match self.record(&acknowledgment_key(id))? {
            None => None,
            Some(Record::CoverageAcknowledgment(ack)) => Some(ack),
            _ => anyhow::bail!("coverage acknowledgment record differs"),
        };
        Ok(Some(SignerCoverageStatus {
            dispatch,
            acknowledgment,
        }))
    }
    fn coverage_dependencies(
        &self,
        dispatch: &SignerCoverageDispatch,
        read: impl Fn(&str) -> Result<Option<Record>>,
    ) -> Result<()> {
        dispatch.digest()?;
        let publication = &dispatch.command.publication;
        let Some(Record::SignerRoster(frozen)) =
            read(&signer_roster::roster_key(publication.global_stage()))?
        else {
            anyhow::bail!("coverage dispatch lacks its original frozen roster");
        };
        ensure!(
            frozen.operation_id == publication.global_stage()
                && frozen.roster == dispatch.frozen_roster
                && frozen.revision < dispatch.revision
                && dispatch.registration.revision <= frozen.revision,
            "coverage dispatch changed frozen registration or roster"
        );
        ensure!(
            matches!(read(&signer_roster::verifier_key(publication.verifier()))?,
            Some(Record::Verifier(ref registration)) if *registration == dispatch.registration),
            "coverage dispatch registration is not the permanent physical origin"
        );
        match publication {
            SignerPublicationRequest::Issuer { directive, .. } => {
                self.issuer_signer_dependencies(directive, dispatch.revision, &read)?;
            }
            SignerPublicationRequest::Control { request } => {
                self.control_signer_dependencies(&request.directive, dispatch.revision, &read)?;
            }
        }
        Ok(())
    }
    fn coverage_permission(
        &self,
        dispatch: &SignerCoverageDispatch,
        before: u64,
        read: impl Fn(&str) -> Result<Option<Record>>,
    ) -> Result<AuthorityMaintenanceStatus> {
        let publication = &dispatch.command.publication;
        let Some(Record::Maintenance(permission)) = read(&maintenance_state::operation_key(
            publication.command().operation_id,
        ))?
        else {
            anyhow::bail!("coverage acknowledgment lacks its original local effect permission");
        };
        ensure!(
            permission.phase == AuthorityMaintenancePhase::Completed
                && permission.progress_revision < before,
            "local effect permission did not precede coverage acknowledgment"
        );
        let Some(Record::CoveragePermission(marker)) =
            read(&permission_key(dispatch.command.operation_id))?
        else {
            anyhow::bail!("coverage source permission has no durable phase record");
        };
        ensure!(
            marker.dispatch_operation_id == dispatch.command.operation_id
                && marker.permission_operation_id == permission.command.operation_id
                && marker.permission_sha256 == permission.command_sha256
                && marker.permission_revision == permission.progress_revision
                && marker.revision >= dispatch.revision
                && marker.revision >= permission.progress_revision
                && marker.revision < before,
            "coverage source permission phase or causal position differs"
        );
        match (publication, &permission.command.action) {
            (
                SignerPublicationRequest::Issuer { directive, .. },
                AuthorityMaintenanceAction::AuthorizeSignerTrust { directive: actual },
            ) => {
                ensure!(
                    directive == actual,
                    "coverage substituted issuer publication permission"
                );
            }
            (
                SignerPublicationRequest::Control { request },
                AuthorityMaintenanceAction::AuthorizeControlSigner { directive },
            ) => {
                ensure!(
                    request.directive == **directive,
                    "coverage substituted Control publication permission"
                );
            }
            _ => anyhow::bail!("coverage publication permission kind differs"),
        }
        Ok(permission)
    }
    fn coverage_observation_dependencies(
        &self,
        dispatch: &SignerCoverageDispatch,
        publication: &SignerPublicationResponse,
        before: u64,
        read: impl Fn(&str) -> Result<Option<Record>>,
    ) -> Result<()> {
        let permission = self.coverage_permission(dispatch, before, &read)?;
        ensure!(
            *publication.authorization()? == permission,
            "coverage observation substituted the exact committed source permission"
        );
        if let (
            SignerPublicationRequest::Control { request },
            SignerPublicationResponse::Control(reply),
        ) = (&dispatch.command.publication, publication)
        {
            let (admission, registration) = self.control_signer_dependencies(
                &request.directive,
                permission.progress_revision,
                &read,
            )?;
            ensure!(
                reply.issuer.admission == admission
                    && reply.issuer.registration == registration
                    && reply.issuer.registration == dispatch.registration
                    && reply.issuer.operational_revision < before
                    && reply
                        .issuer
                        .head
                        .retirement
                        .as_ref()
                        .is_some_and(|winner| winner.roster == dispatch.frozen_roster),
                "coverage observation changed its exact Control admission, roster or causal position"
            );
        }
        Ok(())
    }
    fn retain_coverage_permission(
        meta: &mut Meta,
        dispatch: &SignerCoverageDispatch,
        permission: &AuthorityMaintenanceStatus,
        revision: u64,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        ensure!(
            permission.phase == AuthorityMaintenancePhase::Completed,
            "coverage permission is not complete"
        );
        let matches = match (&dispatch.command.publication, &permission.command.action) {
            (
                SignerPublicationRequest::Issuer { directive, .. },
                AuthorityMaintenanceAction::AuthorizeSignerTrust { directive: actual },
            ) => directive == actual,
            (
                SignerPublicationRequest::Control { request },
                AuthorityMaintenanceAction::AuthorizeControlSigner { directive },
            ) => request.directive == **directive,
            _ => false,
        };
        ensure!(
            matches,
            "coverage permission differs from original dispatch"
        );
        add_count(&mut meta.coverage_permissions, 1)?;
        additions.push((
            permission_key(dispatch.command.operation_id),
            Record::CoveragePermission(CoveragePermission {
                dispatch_operation_id: dispatch.command.operation_id,
                permission_operation_id: permission.command.operation_id,
                permission_sha256: permission.command_sha256.clone(),
                permission_revision: permission.progress_revision,
                revision,
            }),
        ));
        Ok(())
    }
    pub(super) fn coverage_permission_committed(
        &self,
        meta: &mut Meta,
        permission: &AuthorityMaintenanceStatus,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        if permission.phase != AuthorityMaintenancePhase::Completed {
            return Ok(());
        }
        let (stage, verifier) = match &permission.command.action {
            AuthorityMaintenanceAction::AuthorizeSignerTrust { directive } => {
                (directive.global_stage_operation_id, &directive.verifier)
            }
            AuthorityMaintenanceAction::AuthorizeControlSigner { directive } => (
                directive.global_stage_operation_id,
                &directive.node.verifier,
            ),
            _ => return Ok(()),
        };
        let Some(Record::CoverageBinding(binding)) = self.record(&binding_key(stage, verifier))?
        else {
            return Ok(());
        };
        if self
            .record(&permission_key(binding.dispatch_operation_id))?
            .is_some()
        {
            return Ok(());
        }
        let Some(Record::CoverageDispatch(dispatch)) =
            self.record(&dispatch_key(binding.dispatch_operation_id))?
        else {
            anyhow::bail!("coverage permission binding lacks its original dispatch");
        };
        // A different phase for this physical verifier must not consume the
        // original dispatch's reserved completion capacity.
        if dispatch.command.publication.command().operation_id != permission.command.operation_id {
            return Ok(());
        }
        Self::retain_coverage_permission(
            meta,
            &dispatch,
            permission,
            permission.progress_revision,
            additions,
        )
    }
    pub(super) fn reduce_coverage(
        &self,
        position: &AppliedEntryContext,
        prepared: PreparedCoverage,
    ) -> Result<kasumi_types::Result<SignerCoverageStatus>> {
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
            return Ok(Err(conflict("coverage proposal term changed")));
        }
        let revision = position.log_id.index;
        let mut additions = Vec::new();
        let status = match prepared.transition {
            CoverageTransition::Begin { command } => {
                command.digest()?;
                if let Some(previous) = self.coverage_status_unlocked(command.operation_id)? {
                    return Ok(if previous.dispatch.command == command {
                        Ok(previous)
                    } else {
                        Err(conflict("permanent coverage command differs"))
                    });
                }
                if command.expected_policy_epoch != meta.policy_epoch
                    || command.expected_operational_revision != meta.operational.revision
                    || prepared.admitted_at_ms >= command.not_after_ms
                    || !prepared
                        .context
                        .authorization
                        .expires_at_ms()
                        .is_some_and(|expiry| command.not_after_ms <= expiry)
                {
                    return Ok(Err(conflict(
                        "coverage original policy, revision or finite admission changed",
                    )));
                }
                if let Err(error) = command.publication.validate_for_head(&meta.signing) {
                    return Ok(Err(conflict(&error.to_string())));
                }
                let identity_key = binding_key(
                    command.publication.global_stage(),
                    command.publication.verifier(),
                );
                if self.record(&identity_key)?.is_some() {
                    return Ok(Err(conflict(
                        "physical verifier already has an exact coverage dispatch for this stage",
                    )));
                }
                let Some(Record::Verifier(registration)) =
                    self.record(&signer_roster::verifier_key(command.publication.verifier()))?
                else {
                    return Ok(Err(conflict("coverage receiver is not enrolled")));
                };
                let dispatch = SignerCoverageDispatch {
                    command_sha256: command.digest()?,
                    command,
                    registration,
                    frozen_roster: meta
                        .signing
                        .retirement
                        .as_ref()
                        .context("global winner absent")?
                        .roster
                        .clone(),
                    admitted_principal: prepared.context.principal.clone(),
                    revision,
                };
                if let Err(error) = self.coverage_dependencies(&dispatch, |key| self.record(key)) {
                    return Ok(Err(conflict(&error.to_string())));
                }
                additions.push((
                    identity_key,
                    Record::CoverageBinding(CoverageBinding {
                        stage_operation_id: dispatch.command.publication.global_stage(),
                        verifier: dispatch.command.publication.verifier().clone(),
                        dispatch_operation_id: dispatch.command.operation_id,
                        revision,
                    }),
                ));
                additions.push((
                    dispatch_key(dispatch.command.operation_id),
                    Record::CoverageDispatch(dispatch.clone()),
                ));
                add_count(&mut meta.coverage_dispatches, 1)?;
                if let Some(Record::Maintenance(permission)) =
                    self.record(&maintenance_state::operation_key(
                        dispatch.command.publication.command().operation_id,
                    ))?
                {
                    if let Err(error) = Self::retain_coverage_permission(
                        &mut meta,
                        &dispatch,
                        &permission,
                        revision,
                        &mut additions,
                    ) {
                        return Ok(Err(conflict(&error.to_string())));
                    }
                }
                SignerCoverageStatus {
                    dispatch,
                    acknowledgment: None,
                }
            }
            CoverageTransition::Acknowledge {
                operation_id,
                dispatch_sha256,
                publication,
            } => {
                let Some(mut status) = self.coverage_status_unlocked(operation_id)? else {
                    return Ok(Err(conflict("original coverage dispatch absent")));
                };
                if status.dispatch.digest()? != dispatch_sha256 {
                    return Ok(Err(conflict(
                        "coverage acknowledgment substituted its original dispatch",
                    )));
                }
                if let Err(error) = publication.validate_for(
                    &status.dispatch.command.publication,
                    &self.installation.manifest,
                ) {
                    return Ok(Err(conflict(&error.to_string())));
                }
                if status.acknowledgment.is_some() {
                    return Ok(Ok(status));
                }
                if let Err(error) = status
                    .dispatch
                    .command
                    .publication
                    .validate_for_head(&meta.signing)
                {
                    return Ok(Err(conflict(&error.to_string())));
                }
                self.coverage_dependencies(&status.dispatch, |key| self.record(key))?;
                self.coverage_observation_dependencies(
                    &status.dispatch,
                    &publication,
                    revision,
                    |key| self.record(key),
                )?;
                let ack = SignerCoverageAcknowledgment {
                    dispatch_operation_id: operation_id,
                    dispatch_sha256,
                    publication,
                    revision,
                };
                if let Err(error) = ack.validate_for(&status.dispatch, &self.installation.manifest)
                {
                    return Ok(Err(conflict(&error.to_string())));
                }
                additions.push((
                    acknowledgment_key(operation_id),
                    Record::CoverageAcknowledgment(ack.clone()),
                ));
                add_count(&mut meta.coverage_acknowledgments, 1)?;
                status.acknowledgment = Some(ack);
                status
            }
        };
        let mut writes = Vec::new();
        for (key, record) in additions {
            ensure!(
                self.record(&key)?.is_none(),
                "coverage permanent record cannot be overwritten"
            );
            let bytes = serde_json::to_vec(&record)?;
            ensure!(
                bytes.len() <= MAX_RECORD_BYTES,
                "coverage record exceeds its bounded format"
            );
            add_count(&mut meta.state_bytes, bytes.len() as u64)?;
            writes.push(WriteOp::put(NS, key.as_bytes(), bytes));
        }
        if meta
            .state_bytes
            .saturating_add(Self::completion_reserve(&meta))
            > meta.operational.capacity.max_state_bytes
        {
            return Ok(Err(Error::new(
                ErrorCode::ResourceExhausted,
                "coverage capacity cannot preserve its completion reserve",
            )));
        }
        meta.revision = revision;
        meta.operational.revision = revision;
        writes.push(WriteOp::put(NS, META, serde_json::to_vec(&meta)?));
        self.store.write_batch(&writes)?;
        Ok(Ok(status))
    }
    pub(super) fn validate_coverage_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let (mut dispatches, mut acknowledgments, mut bindings, mut permissions) = (0, 0, 0, 0);
        snapshot.records.visit(|key, record| {
            match record {
                Record::CoverageDispatch(dispatch) => {
                    add_count(&mut dispatches, 1)?;
                    ensure!(
                        key == dispatch_key(dispatch.command.operation_id)
                            && dispatch.revision <= snapshot.meta.revision,
                        "coverage dispatch snapshot identity or position differs"
                    );
                    self.coverage_dependencies(dispatch, |key| snapshot.records.get(key))?;
                    let Some(Record::CoverageBinding(binding)) =
                        snapshot.records.get(&binding_key(
                            dispatch.command.publication.global_stage(),
                            dispatch.command.publication.verifier(),
                        ))?
                    else {
                        anyhow::bail!("coverage dispatch lacks its permanent physical binding");
                    };
                    ensure!(
                        binding.dispatch_operation_id == dispatch.command.operation_id
                            && binding.revision == dispatch.revision,
                        "coverage dispatch physical identity differs"
                    );
                }
                Record::CoverageBinding(binding) => {
                    add_count(&mut bindings, 1)?;
                    ensure!(
                        key == binding_key(binding.stage_operation_id, &binding.verifier),
                        "coverage binding key differs"
                    );
                    let Some(Record::CoverageDispatch(dispatch)) = snapshot
                        .records
                        .get(&dispatch_key(binding.dispatch_operation_id))?
                    else {
                        anyhow::bail!("coverage binding lacks its original dispatch");
                    };
                    ensure!(
                        binding.stage_operation_id == dispatch.command.publication.global_stage()
                            && binding.verifier == *dispatch.command.publication.verifier()
                            && binding.revision == dispatch.revision,
                        "coverage binding substituted its original physical identity"
                    );
                }
                Record::CoverageAcknowledgment(ack) => {
                    add_count(&mut acknowledgments, 1)?;
                    ensure!(
                        key == acknowledgment_key(ack.dispatch_operation_id)
                            && ack.revision <= snapshot.meta.revision,
                        "coverage acknowledgment snapshot key or position differs"
                    );
                    let Some(Record::CoverageDispatch(dispatch)) = snapshot
                        .records
                        .get(&dispatch_key(ack.dispatch_operation_id))?
                    else {
                        anyhow::bail!("coverage acknowledgment lacks its original dispatch");
                    };
                    ack.validate_for(&dispatch, &self.installation.manifest)?;
                    self.coverage_observation_dependencies(
                        &dispatch,
                        &ack.publication,
                        ack.revision,
                        |key| snapshot.records.get(key),
                    )?;
                }
                Record::CoveragePermission(marker) => {
                    add_count(&mut permissions, 1)?;
                    ensure!(
                        key == permission_key(marker.dispatch_operation_id)
                            && marker.revision <= snapshot.meta.revision,
                        "coverage permission snapshot key or position differs"
                    );
                    let Some(Record::CoverageDispatch(dispatch)) = snapshot
                        .records
                        .get(&dispatch_key(marker.dispatch_operation_id))?
                    else {
                        anyhow::bail!("coverage permission lacks original dispatch");
                    };
                    self.coverage_permission(
                        &dispatch,
                        marker
                            .revision
                            .checked_add(1)
                            .context("coverage position exhausted")?,
                        |key| snapshot.records.get(key),
                    )?;
                }
                _ => {}
            }
            Ok(())
        })?;
        ensure!(
            dispatches == snapshot.meta.coverage_dispatches
                && bindings == dispatches
                && acknowledgments == snapshot.meta.coverage_acknowledgments
                && acknowledgments <= permissions
                && permissions == snapshot.meta.coverage_permissions
                && permissions <= dispatches,
            "coverage snapshot accounting differs"
        );
        Ok(())
    }
    pub(super) fn validate_coverage_history(&self, snapshot: &Snapshot) -> Result<()> {
        self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
            if key.starts_with(b"signer-dispatch/")
                || key.starts_with(b"signer-coverage/")
                || key.starts_with(b"signer-dispatch-verifier/")
                || key.starts_with(b"signer-coverage-permission/")
            {
                let key = std::str::from_utf8(key)?;
                let record = snapshot
                    .records
                    .get(key)?
                    .context("snapshot omits permanent signer coverage history")?;
                ensure!(
                    serde_json::to_vec(&record)? == bytes,
                    "snapshot changes permanent signer coverage history"
                );
            }
            Ok(())
        })
    }
}
