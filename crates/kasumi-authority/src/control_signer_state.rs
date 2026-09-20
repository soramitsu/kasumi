use super::maintenance_state::operation_key;
use super::signer_roster::{control_key, verifier_key};
use super::*;

impl Backend {
    pub(super) fn control_signer_dependencies(
        &self,
        directive: &ControlSignerDirective,
        revision: u64,
        read: impl Fn(&str) -> Result<Option<Record>>,
    ) -> Result<(ControlVerifierAdmission, SignerVerifierRegistration)> {
        directive.validate()?;
        let domain = self
            .installation
            .manifest
            .signing_domain(self.installation.partition)?;
        ensure!(
            directive.domain_sha256 == domain.digest()?,
            "remote directive issuer domain differs"
        );
        let Some(Record::ControlVerifier(control)) =
            read(&control_key(directive.root.control_incarnation))?
        else {
            anyhow::bail!("physical Control admission absent");
        };
        ensure!(
            control.admission.root == directive.root
                && control.admission.partition
                    == self
                        .installation
                        .manifest
                        .control_partition(self.installation.partition)?
                && control.admission.nodes.contains(&directive.node)
                && control.revision < revision,
            "remote directive Control identity or admission position differs"
        );
        let Some(Record::Verifier(registration)) = read(&verifier_key(&directive.node.verifier))?
        else {
            anyhow::bail!("physical Control verifier registration absent");
        };
        ensure!(
            registration.enrollment.verifier == directive.node.verifier
                && registration.revision < revision,
            "remote physical verifier position differs"
        );
        let Some(Record::Maintenance(stage)) =
            read(&operation_key(directive.global_stage_operation_id))?
        else {
            anyhow::bail!("global signer stage outcome absent");
        };
        let AuthorityMaintenanceAction::StageSignerGeneration { certificate } =
            &stage.command.action
        else {
            anyhow::bail!("global stage identity belongs to another operation");
        };
        ensure!(
            stage.phase == AuthorityMaintenancePhase::Completed
                && stage.progress_revision < revision,
            "global stage did not precede remote permission"
        );
        match &directive.command.action {
            SignerTrustAction::Stage {
                certificate: requested,
            } => ensure!(
                requested == certificate,
                "remote certificate differs from committed global stage"
            ),
            SignerTrustAction::Activate {
                staged_operation_id,
                certificate_sha256,
            } => {
                let Some(Record::Maintenance(activation)) = read(&operation_key(
                    directive
                        .global_activation_operation_id
                        .context("global activation identity absent")?,
                ))?
                else {
                    anyhow::bail!("global activation outcome absent");
                };
                ensure!(
                    activation.phase == AuthorityMaintenancePhase::Completed
                        && activation.progress_revision < revision
                        && matches!(&activation.command.action, AuthorityMaintenanceAction::ActivateSignerGeneration {
                        stage_operation_id, certificate_sha256: hash } if *stage_operation_id == directive.global_stage_operation_id && hash == certificate_sha256)
                        && certificate.digest()? == *certificate_sha256,
                    "remote activation lacks the exact committed global winner"
                );
                let Some(Record::Maintenance(local)) = read(&operation_key(*staged_operation_id))?
                else {
                    anyhow::bail!("original local stage directive absent");
                };
                let AuthorityMaintenanceAction::AuthorizeControlSigner {
                    directive: previous,
                } = &local.command.action
                else {
                    anyhow::bail!("local stage belongs to another permission");
                };
                ensure!(
                    local.phase == AuthorityMaintenancePhase::Completed
                        && local.progress_revision < revision
                        && previous.root == directive.root
                        && previous.node == directive.node
                        && previous.domain_sha256 == directive.domain_sha256
                        && previous.global_stage_operation_id
                            == directive.global_stage_operation_id
                        && previous.command.expected_revision.checked_add(1)
                            == Some(directive.command.expected_revision)
                        && matches!(&previous.command.action, SignerTrustAction::Stage { certificate: actual } if actual == certificate),
                    "remote activation substituted its original physical local stage"
                );
            }
            _ => anyhow::bail!("unsupported remote signer effect"),
        }
        Ok((control.admission, registration))
    }
    pub(super) fn validate_control_signer_directive(
        &self,
        meta: &Meta,
        directive: &ControlSignerDirective,
    ) -> Result<()> {
        directive.validate_for_head(&meta.signing)?;
        self.control_signer_dependencies(
            directive,
            meta.revision
                .checked_add(1)
                .context("remote permission revision exhausted")?,
            |key| self.record(key),
        )?;
        Ok(())
    }
    pub(super) fn validate_control_signer_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        snapshot.records.visit(|_, record| {
            if let Record::Maintenance(status) = record
                && let AuthorityMaintenanceAction::AuthorizeControlSigner { directive } =
                    &status.command.action
            {
                ensure!(
                    matches!(
                        status.phase,
                        AuthorityMaintenancePhase::Completed
                            | AuthorityMaintenancePhase::Rejected { .. }
                    ),
                    "remote permission has an impossible dispatch phase"
                );
                if status.phase == AuthorityMaintenancePhase::Completed {
                    self.control_signer_dependencies(directive, status.progress_revision, |key| {
                        snapshot.records.get(key)
                    })?;
                }
            }
            Ok(())
        })
    }
    pub(crate) fn control_signer_observation(
        &self,
        request: &ControlSignerRequest,
    ) -> Result<ControlSignerObservation> {
        request.digest()?;
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let meta = self.meta()?;
        request.directive.validate_for_head(&meta.signing)?;
        let Some(Record::Maintenance(authorization)) =
            self.record(&operation_key(request.directive.command.operation_id))?
        else {
            anyhow::bail!("remote effect has no permanent source permission");
        };
        ensure!(
            authorization.phase == AuthorityMaintenancePhase::Completed
                && matches!(&authorization.command.action, AuthorityMaintenanceAction::AuthorizeControlSigner { directive } if **directive == request.directive),
            "remote source permission differs"
        );
        let (admission, registration) = self.control_signer_dependencies(
            &request.directive,
            authorization.progress_revision,
            |key| self.record(key),
        )?;
        let may_apply = authorization.command.expected_policy_epoch == meta.policy_epoch
            && meta
                .administrators
                .contains(&authorization.admitted_principal);
        Ok(ControlSignerObservation {
            observation_id: request.observation_id,
            request_sha256: request.digest()?,
            authorization,
            admission,
            registration,
            head: meta.signing,
            policy_epoch: meta.policy_epoch,
            operational_revision: meta.operational.revision,
            // The actual current service fills these after its quorum admission.
            authority_term: 0,
            lifetime_ms: 0,
            may_apply,
        })
    }
}
