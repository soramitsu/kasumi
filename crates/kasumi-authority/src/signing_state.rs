use super::*;

impl Backend {
    pub fn signing_observation(&self) -> Result<(AuthoritySigningHead, u64, u64)> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let meta = self.meta()?;
        meta.signing.validate()?;
        ensure!(
            meta.signing.initial == self.initial_signer_certificate,
            "global signer observation differs from installed initial certificate"
        );
        Ok((meta.signing, meta.policy_epoch, meta.operational.revision))
    }
    pub fn signing_head(&self) -> Result<AuthoritySigningHead> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let head = self.meta()?.signing;
        head.validate()?;
        ensure!(
            head.initial == self.initial_signer_certificate,
            "global signer head differs from installed initial certificate"
        );
        Ok(head)
    }
    pub(super) fn validate_signing_transition(
        &self,
        meta: &Meta,
        command: &AuthorityMaintenanceCommand,
    ) -> Result<()> {
        let head = &meta.signing;
        head.validate()?;
        match &command.action {
            AuthorityMaintenanceAction::AuthorizeControlSigner { directive } => {
                return self.validate_control_signer_directive(meta, directive);
            }
            AuthorityMaintenanceAction::EnrollSignerVerifier { .. }
            | AuthorityMaintenanceAction::AdmitControlVerifiers { .. } => {
                return self.validate_roster_transition(meta, command);
            }
            AuthorityMaintenanceAction::StageSignerGeneration { certificate } => {
                self.freeze_signer_roster(meta)?;
                certificate.verify(&head.initial.identity.domain)?;
                ensure!(
                    head.staged.is_none()
                        && head.retirement.is_none()
                        && head.active.identity.generation.checked_add(1)
                            == Some(certificate.identity.generation)
                        && head.active.identity.public_key != certificate.identity.public_key,
                    "global signer stage requires an unoccupied exact successor and completed prior retirement"
                );
            }
            AuthorityMaintenanceAction::ActivateSignerGeneration {
                stage_operation_id,
                certificate_sha256,
            } => {
                let staged = head.staged.as_ref().context("global signer stage absent")?;
                ensure!(
                    staged.operation_id == *stage_operation_id
                        && staged.certificate.digest()? == *certificate_sha256,
                    "global activation differs from exact staged operation"
                );
            }
            _ => anyhow::bail!("not a global signer transition"),
        }
        Ok(())
    }
    pub(super) fn apply_signing_transition(
        &self,
        meta: &mut Meta,
        command: &AuthorityMaintenanceCommand,
        revision: u64,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        self.validate_signing_transition(meta, command)?;
        if matches!(
            &command.action,
            AuthorityMaintenanceAction::AuthorizeControlSigner { .. }
        ) {
            meta.operational.revision = revision;
            return Ok(());
        }
        if matches!(
            &command.action,
            AuthorityMaintenanceAction::EnrollSignerVerifier { .. }
                | AuthorityMaintenanceAction::AdmitControlVerifiers { .. }
        ) {
            return self.apply_roster_transition(meta, command, revision, additions);
        }
        let roster = self.freeze_signer_roster(meta)?;
        if matches!(
            command.action,
            AuthorityMaintenanceAction::StageSignerGeneration { .. }
        ) {
            Self::retain_signer_roster(meta, command.operation_id, revision, &roster, additions)?;
        }
        let head = &mut meta.signing;
        match &command.action {
            AuthorityMaintenanceAction::StageSignerGeneration { certificate } => {
                head.staged = Some(AuthoritySignerStage {
                    roster,
                    operation_id: command.operation_id,
                    revision,
                    certificate: certificate.clone(),
                });
            }
            AuthorityMaintenanceAction::ActivateSignerGeneration {
                stage_operation_id, ..
            } => {
                let staged = head.staged.take().context("global stage disappeared")?;
                head.retirement = Some(AuthoritySignerRetirement {
                    roster: staged.roster,
                    stage_operation_id: *stage_operation_id,
                    activation_operation_id: command.operation_id,
                    activation_revision: revision,
                    previous: head.active.clone(),
                });
                head.active = staged.certificate;
            }
            _ => anyhow::bail!("not a global signer transition"),
        }
        head.revision = revision;
        head.validate()
    }
    pub(super) fn validate_signing_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        self.validate_control_signer_snapshot(snapshot)?;
        let head = &snapshot.meta.signing;
        head.validate()?;
        ensure!(
            head.initial == self.initial_signer_certificate
                && head.revision <= snapshot.meta.revision,
            "global signer snapshot differs from immutable bootstrap or applied position"
        );
        let (mut latest_stage, mut latest_activation) = (None, None);
        snapshot.records.visit(|_, record| {
            if let Record::Maintenance(status) = record
                && status.phase == AuthorityMaintenancePhase::Completed
            {
                let selected = match &status.command.action {
                    AuthorityMaintenanceAction::StageSignerGeneration { certificate } => {
                        certificate.verify(&head.initial.identity.domain)?;
                        &mut latest_stage
                    }
                    AuthorityMaintenanceAction::ActivateSignerGeneration { .. } => {
                        &mut latest_activation
                    }
                    _ => return Ok(()),
                };
                if selected
                    .as_ref()
                    .is_none_or(|current: &AuthorityMaintenanceStatus| {
                        current.progress_revision < status.progress_revision
                    })
                {
                    *selected = Some(status.clone());
                }
            }
            Ok(())
        })?;
        match (
            &latest_stage,
            &latest_activation,
            &head.staged,
            &head.retirement,
        ) {
            (None, None, None, None) => ensure!(
                head.revision == 0 && head.active == head.initial,
                "initial global head lacks genesis identity"
            ),
            (Some(stage), None, Some(staged), None) => ensure!(
                stage.command.operation_id == staged.operation_id
                    && head.revision == staged.revision
                    && head.active == head.initial,
                "global staged head is not the latest committed signing state"
            ),
            (Some(stage), Some(activation), None, Some(retirement)) => ensure!(
                stage.command.operation_id == retirement.stage_operation_id
                    && activation.command.operation_id == retirement.activation_operation_id
                    && head.revision == retirement.activation_revision,
                "global active head is not the latest committed signing state"
            ),
            _ => anyhow::bail!("global signing head omits or regresses retained transitions"),
        }
        let stage = |id: Uuid,
                     certificate: &SigningCertificate|
         -> Result<AuthorityMaintenanceStatus> {
            let Some(Record::Maintenance(status)) = snapshot
                .records
                .get(&maintenance_state::operation_key(id))?
            else {
                anyhow::bail!("global signer stage lacks permanent consensus identity");
            };
            ensure!(
                status.phase == AuthorityMaintenancePhase::Completed
                    && matches!(&status.command.action, AuthorityMaintenanceAction::StageSignerGeneration { certificate: actual } if actual == certificate),
                "global signer stage receipt differs"
            );
            Ok(status)
        };
        if let Some(staged) = &head.staged {
            ensure!(
                stage(staged.operation_id, &staged.certificate)?.progress_revision
                    == staged.revision,
                "global signer stage position differs"
            );
        }
        if let Some(retirement) = &head.retirement {
            let staged = stage(retirement.stage_operation_id, &head.active)?;
            let Some(Record::Maintenance(activation)) = snapshot.records.get(
                &maintenance_state::operation_key(retirement.activation_operation_id),
            )?
            else {
                anyhow::bail!("global signer activation lacks permanent consensus identity");
            };
            ensure!(
                activation.phase == AuthorityMaintenancePhase::Completed
                    && activation.progress_revision == retirement.activation_revision
                    && staged.progress_revision < activation.progress_revision
                    && matches!(&activation.command.action, AuthorityMaintenanceAction::ActivateSignerGeneration { stage_operation_id, certificate_sha256 }
                    if *stage_operation_id == retirement.stage_operation_id && *certificate_sha256 == head.active.digest()?),
                "global signer activation receipt or causal position differs"
            );
        }
        Ok(())
    }
}
