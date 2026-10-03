use super::*;

// Created and consumed while the caller holds Backend::mutation. The private
// action carries the exact validated input and, for a stage, its complete
// frozen roster. It cannot be reused after the applied generation changes.
pub(super) struct PreparedSigningTransition<'a>(PreparedSigningAction<'a>);
enum PreparedSigningAction<'a> {
    AuthorizeControl,
    Roster(&'a AuthorityMaintenanceCommand),
    Stage {
        operation_id: Uuid,
        certificate: &'a SigningCertificate,
        roster: SignerVerifierRoster,
    },
    Activate {
        operation_id: Uuid,
        stage_operation_id: Uuid,
    },
}

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
    pub(super) fn prepare_signing_transition<'a>(
        &self,
        meta: &Meta,
        command: &'a AuthorityMaintenanceCommand,
    ) -> Result<PreparedSigningTransition<'a>> {
        let head = &meta.signing;
        head.validate()?;
        let action = match &command.action {
            AuthorityMaintenanceAction::AuthorizeControlSigner { directive } => {
                self.validate_control_signer_directive(meta, directive)?;
                PreparedSigningAction::AuthorizeControl
            }
            AuthorityMaintenanceAction::EnrollSignerVerifier { .. }
            | AuthorityMaintenanceAction::AdmitControlVerifiers { .. } => {
                self.validate_roster_transition(meta, command)?;
                PreparedSigningAction::Roster(command)
            }
            AuthorityMaintenanceAction::StageSignerGeneration { certificate } => {
                // Preserve the rejection order: physical coverage is checked
                // before the certificate's installed domain or successor.
                let roster = self.freeze_signer_roster(meta)?;
                certificate
                    .verify(&head.initial.identity.domain)
                    .map_err(reject_conflict)?;
                reject_unless!(
                    head.staged.is_none()
                        && head.retirement.is_none()
                        && head.active.identity.generation.checked_add(1)
                            == Some(certificate.identity.generation)
                        && head.active.identity.public_key != certificate.identity.public_key,
                    "global signer stage requires an unoccupied exact successor and completed prior retirement"
                );
                PreparedSigningAction::Stage {
                    operation_id: command.operation_id,
                    certificate,
                    roster,
                }
            }
            AuthorityMaintenanceAction::ActivateSignerGeneration {
                stage_operation_id,
                certificate_sha256,
            } => {
                let staged = head
                    .staged
                    .as_ref()
                    .ok_or_else(|| reject_conflict("global signer stage absent"))?;
                reject_unless!(
                    staged.operation_id == *stage_operation_id
                        && staged.certificate.digest()? == *certificate_sha256,
                    "global activation differs from exact staged operation"
                );
                PreparedSigningAction::Activate {
                    operation_id: command.operation_id,
                    stage_operation_id: *stage_operation_id,
                }
            }
            _ => reject_bail!("not a global signer transition"),
        };
        Ok(PreparedSigningTransition(action))
    }
    pub(super) fn apply_signing_transition(
        &self,
        meta: &mut Meta,
        prepared: PreparedSigningTransition<'_>,
        revision: u64,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        match prepared.0 {
            PreparedSigningAction::AuthorizeControl => {
                meta.operational.revision = revision;
                return Ok(());
            }
            PreparedSigningAction::Roster(command) => {
                return self.apply_roster_transition(meta, command, revision, additions);
            }
            PreparedSigningAction::Stage {
                operation_id,
                certificate,
                roster,
            } => {
                Self::retain_signer_roster(meta, operation_id, revision, &roster, additions)?;
                meta.signing.staged = Some(AuthoritySignerStage {
                    roster,
                    operation_id,
                    revision,
                    certificate: certificate.clone(),
                });
            }
            PreparedSigningAction::Activate {
                operation_id,
                stage_operation_id,
            } => {
                // Activation still checks current physical coverage at its
                // original apply boundary. A failure here is an outer error,
                // not a new permanent semantic rejection.
                self.freeze_signer_roster(meta)?;
                let head = &mut meta.signing;
                let staged = head.staged.take().context("global stage disappeared")?;
                head.retirement = Some(AuthoritySignerRetirement {
                    roster: staged.roster,
                    stage_operation_id,
                    activation_operation_id: operation_id,
                    activation_revision: revision,
                    previous: head.active.clone(),
                });
                head.active = staged.certificate;
            }
        }
        meta.signing.revision = revision;
        meta.signing.validate()
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
