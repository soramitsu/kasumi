//! Exact global origin for a local issuer verifier publication. Root
//! certification alone does not authorize a new local stage or activation.
use crate::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerSignerDirective {
    pub verifier: TrustVerifierIdentity,
    pub domain_sha256: String,
    pub global_stage_operation_id: Uuid,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub global_activation_operation_id: Option<Uuid>,
    pub command: SignerTrustCommand,
}
impl IssuerSignerDirective {
    pub fn from_current_head(
        verifier: TrustVerifierIdentity,
        domain_sha256: String,
        command: SignerTrustCommand,
        head: &AuthoritySigningHead,
    ) -> Result<Self> {
        let (stage, activation) = match &command.action {
            SignerTrustAction::Stage { .. } => (
                head.staged
                    .as_ref()
                    .map(|stage| stage.operation_id)
                    .or_else(|| {
                        head.retirement
                            .as_ref()
                            .map(|retirement| retirement.stage_operation_id)
                    })
                    .context("global stage has not committed")?,
                None,
            ),
            SignerTrustAction::Activate { .. } | SignerTrustAction::CompleteRetirement { .. } => {
                let winner = head
                    .retirement
                    .as_ref()
                    .context("global activation has not committed")?;
                (
                    winner.stage_operation_id,
                    Some(winner.activation_operation_id),
                )
            }
            SignerTrustAction::StopStage { .. } => {
                anyhow::bail!("local stage abort requires a committed global abort protocol")
            }
        };
        let directive = Self {
            verifier,
            domain_sha256,
            global_stage_operation_id: stage,
            global_activation_operation_id: activation,
            command,
        };
        directive.validate_for_head(head)?;
        Ok(directive)
    }
    pub fn validate(&self) -> Result<()> {
        self.verifier.validate()?;
        kasumi_types::validate_sha256(&self.domain_sha256)?;
        ensure!(
            !self.global_stage_operation_id.is_nil(),
            "exact global stage required"
        );
        self.command.digest()?;
        match &self.command.action {
            SignerTrustAction::Stage { certificate } => {
                certificate.verify(&certificate.identity.domain)?;
                ensure!(
                    certificate.identity.domain.digest()? == self.domain_sha256
                        && self.global_activation_operation_id.is_none(),
                    "local stage issuer origin differs"
                );
            }
            SignerTrustAction::Activate {
                staged_operation_id,
                certificate_sha256,
            } => {
                kasumi_types::validate_sha256(certificate_sha256)?;
                ensure!(
                    !staged_operation_id.is_nil()
                        && self
                            .global_activation_operation_id
                            .is_some_and(|id| !id.is_nil()),
                    "local activation requires the original local stage and global winner"
                );
            }
            SignerTrustAction::CompleteRetirement {
                activation_operation_id,
            } => ensure!(
                !activation_operation_id.is_nil()
                    && self
                        .global_activation_operation_id
                        .is_some_and(|id| !id.is_nil()),
                "local retirement requires the original local activation and global winner"
            ),
            SignerTrustAction::StopStage { .. } => {
                anyhow::bail!("local stage abort requires a committed global abort protocol")
            }
        }
        Ok(())
    }
    pub fn validate_for_head(&self, head: &AuthoritySigningHead) -> Result<()> {
        self.validate()?;
        head.validate()?;
        ensure!(
            head.active.identity.domain.digest()? == self.domain_sha256,
            "local signer issuer domain differs"
        );
        match &self.command.action {
            SignerTrustAction::Stage { certificate } => ensure!(
                head.staged
                    .as_ref()
                    .is_some_and(|stage| stage.operation_id == self.global_stage_operation_id
                        && stage.certificate == *certificate)
                    || head
                        .retirement
                        .as_ref()
                        .is_some_and(|winner| winner.stage_operation_id
                            == self.global_stage_operation_id
                            && head.active == *certificate),
                "local stage differs from committed global successor"
            ),
            SignerTrustAction::Activate {
                certificate_sha256, ..
            } => {
                self.require_winner(head)?;
                ensure!(
                    head.active.digest()? == *certificate_sha256,
                    "local activation substituted the global winner"
                );
            }
            SignerTrustAction::CompleteRetirement { .. } => self.require_winner(head)?,
            SignerTrustAction::StopStage { .. } => {
                anyhow::bail!("local stage abort is unavailable")
            }
        }
        Ok(())
    }
    fn require_winner(&self, head: &AuthoritySigningHead) -> Result<()> {
        let winner = head
            .retirement
            .as_ref()
            .context("global activation has not committed")?;
        ensure!(
            winner.stage_operation_id == self.global_stage_operation_id
                && Some(winner.activation_operation_id) == self.global_activation_operation_id,
            "local directive differs from committed global winner"
        );
        Ok(())
    }
}
