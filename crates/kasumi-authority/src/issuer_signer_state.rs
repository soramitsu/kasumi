use super::maintenance_state::operation_key;
use super::*;

impl Backend {
    pub(super) fn issuer_signer_dependencies(
        &self,
        directive: &IssuerSignerDirective,
        before: u64,
        read: impl Fn(&str) -> Result<Option<Record>>,
    ) -> Result<()> {
        directive.validate()?;
        ensure!(
            directive.domain_sha256
                == self
                    .installation
                    .manifest
                    .signing_domain(self.installation.partition)?
                    .digest()?,
            "local signer directive issuer domain differs"
        );
        let completed = |id: Uuid| -> Result<AuthorityMaintenanceStatus> {
            let Some(Record::Maintenance(status)) = read(&operation_key(id))? else {
                anyhow::bail!(
                    "local signer directive lacks its permanent global/local prerequisite"
                );
            };
            ensure!(
                status.phase == AuthorityMaintenancePhase::Completed
                    && status.progress_revision < before,
                "signer prerequisite did not precede publication permission"
            );
            Ok(status)
        };
        let stage = completed(directive.global_stage_operation_id)?;
        let AuthorityMaintenanceAction::StageSignerGeneration { certificate } =
            &stage.command.action
        else {
            anyhow::bail!("local signer global stage identity differs");
        };
        if let SignerTrustAction::Stage {
            certificate: requested,
        } = &directive.command.action
        {
            ensure!(
                requested == certificate,
                "local signer certificate differs from global stage"
            );
            return Ok(());
        }
        let winner = completed(
            directive
                .global_activation_operation_id
                .context("global activation absent")?,
        )?;
        ensure!(
            matches!(&winner.command.action, AuthorityMaintenanceAction::ActivateSignerGeneration {
            stage_operation_id, certificate_sha256 } if *stage_operation_id == directive.global_stage_operation_id && *certificate_sha256 == certificate.digest()?),
            "local signer directive substituted the global activation winner"
        );
        let predecessor = match &directive.command.action {
            SignerTrustAction::Activate {
                staged_operation_id,
                certificate_sha256,
            } => {
                ensure!(
                    *certificate_sha256 == certificate.digest()?,
                    "local activation certificate differs"
                );
                completed(*staged_operation_id)?
            }
            SignerTrustAction::CompleteRetirement {
                activation_operation_id,
            } => completed(*activation_operation_id)?,
            _ => anyhow::bail!("local stage abort requires a committed global abort"),
        };
        let AuthorityMaintenanceAction::AuthorizeSignerTrust {
            directive: previous,
        } = &predecessor.command.action
        else {
            anyhow::bail!("local signer predecessor is another permission kind");
        };
        ensure!(
            previous.verifier == directive.verifier
                && previous.domain_sha256 == directive.domain_sha256
                && previous.global_stage_operation_id == directive.global_stage_operation_id
                && previous.command.expected_revision.checked_add(1)
                    == Some(directive.command.expected_revision),
            "local signer predecessor has another physical owner or revision"
        );
        match (&directive.command.action, &previous.command.action) {
            (
                SignerTrustAction::Activate { .. },
                SignerTrustAction::Stage {
                    certificate: actual,
                },
            ) => {
                ensure!(
                    actual == certificate && previous.global_activation_operation_id.is_none(),
                    "local original stage differs"
                );
            }
            (
                SignerTrustAction::CompleteRetirement { .. },
                SignerTrustAction::Activate {
                    certificate_sha256, ..
                },
            ) => {
                ensure!(
                    *certificate_sha256 == certificate.digest()?
                        && previous.global_activation_operation_id
                            == directive.global_activation_operation_id,
                    "local retirement substituted its original committed activation"
                );
            }
            _ => anyhow::bail!("local signer phase predecessor differs"),
        }
        Ok(())
    }
    pub(super) fn validate_issuer_signer_directive(
        &self,
        meta: &Meta,
        directive: &IssuerSignerDirective,
    ) -> Result<()> {
        directive.validate_for_head(&meta.signing)?;
        self.issuer_signer_dependencies(
            directive,
            meta.revision
                .checked_add(1)
                .context("signer publication revision exhausted")?,
            |key| self.record(key),
        )
    }
    pub(crate) fn check_current_issuer_directive(
        &self,
        context: &RequestContext,
        permission: &AuthorityMaintenanceStatus,
    ) -> Result<()> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let meta = self.meta()?;
        let epoch = self.authorize(&meta, context)?;
        ensure!(
            permission.phase == AuthorityMaintenancePhase::Completed
                && permission.command.expected_policy_epoch == epoch,
            "historical signer permission cannot grant a new local effect"
        );
        ensure!(
            matches!(self.record(&operation_key(permission.command.operation_id))?, Some(Record::Maintenance(ref current)) if current == permission),
            "current signer permission differs from its permanent identity"
        );
        let AuthorityMaintenanceAction::AuthorizeSignerTrust { directive } =
            &permission.command.action
        else {
            anyhow::bail!("current signer permission kind differs");
        };
        ensure!(
            meta.operational
                .membership
                .members
                .get(&directive.verifier.node_id)
                .is_some_and(|member| member.verifier == directive.verifier),
            "signer verifier is no longer an active issuer member"
        );
        directive.validate_for_head(&meta.signing)?;
        self.issuer_signer_dependencies(directive, permission.progress_revision, |key| {
            self.record(key)
        })
    }
}
