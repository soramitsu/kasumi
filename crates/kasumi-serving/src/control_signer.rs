//! Exact issuer-to-Control signer directives. Wire records are historical data;
//! only a fresh pinned transport observation can authorize a receiver invocation.
use crate::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSignerDirective {
    pub root: kasumi_types::ControlSigningRoot,
    pub node: NodeIdentity,
    pub domain_sha256: String,
    pub global_stage_operation_id: Uuid,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub global_activation_operation_id: Option<Uuid>,
    pub command: SignerTrustCommand,
}
impl ControlSignerDirective {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        self.node.validate()?;
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
                    "remote stage domain or activation binding differs"
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
                    "remote activation requires local stage and committed global winner"
                );
            }
            SignerTrustAction::StopStage { .. } | SignerTrustAction::CompleteRetirement { .. } => {
                anyhow::bail!("remote stage abort and retirement completion are not available");
            }
        }
        Ok(())
    }
    pub fn validate_for_head(&self, head: &AuthoritySigningHead) -> Result<()> {
        self.validate()?;
        head.validate()?;
        ensure!(
            head.active.identity.domain.digest()? == self.domain_sha256,
            "remote directive belongs to another issuer domain"
        );
        match &self.command.action {
            SignerTrustAction::Stage { certificate } => {
                let matches_pending = head.staged.as_ref().is_some_and(|stage| {
                    stage.operation_id == self.global_stage_operation_id
                        && stage.certificate == *certificate
                });
                let matches_forward = head.retirement.as_ref().is_some_and(|retirement| {
                    retirement.stage_operation_id == self.global_stage_operation_id
                        && head.active == *certificate
                });
                ensure!(
                    matches_pending || matches_forward,
                    "remote stage is outside the committed global rotation"
                );
            }
            SignerTrustAction::Activate {
                certificate_sha256, ..
            } => {
                let retirement = head
                    .retirement
                    .as_ref()
                    .context("global activation has not committed")?;
                ensure!(
                    retirement.stage_operation_id == self.global_stage_operation_id
                        && Some(retirement.activation_operation_id)
                            == self.global_activation_operation_id
                        && head.active.digest()? == *certificate_sha256,
                    "remote activation differs from committed global winner"
                );
            }
            _ => anyhow::bail!("unsupported remote signer effect"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSignerRequest {
    pub observation_id: Uuid,
    pub directive: ControlSignerDirective,
}
impl ControlSignerRequest {
    pub fn digest(&self) -> Result<String> {
        ensure!(
            !self.observation_id.is_nil(),
            "fresh remote observation identity required"
        );
        self.directive.validate()?;
        crate::digest(&("kasumi.control-signer-request.v1", self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSignerObservation {
    pub observation_id: Uuid,
    pub request_sha256: String,
    pub authorization: AuthorityMaintenanceStatus,
    pub admission: ControlVerifierAdmission,
    pub registration: SignerVerifierRegistration,
    pub head: AuthoritySigningHead,
    pub policy_epoch: u64,
    pub operational_revision: u64,
    pub authority_term: u64,
    pub lifetime_ms: u64,
    pub may_apply: bool,
}
impl ControlSignerObservation {
    pub fn validate_for(
        &self,
        request: &ControlSignerRequest,
        manifest: &AuthorityManifest,
    ) -> Result<()> {
        request.digest()?;
        manifest.validate()?;
        self.admission.validate()?;
        self.registration.enrollment.validate()?;
        self.authorization.validate()?;
        request.directive.validate_for_head(&self.head)?;
        let domain = &self.head.active.identity.domain;
        ensure!(
            manifest.signing_domain(domain.partition)? == *domain
                && self.admission.partition == manifest.control_partition(domain.partition)?
                && manifest
                    .lifecycle_controls
                    .get(&request.directive.root.control_incarnation)
                    == Some(&request.directive.root.public_key),
            "current Control observation differs from installed issuer/root"
        );
        ensure!(
            self.observation_id == request.observation_id
                && self.request_sha256 == request.digest()?
                && self.admission.root == request.directive.root
                && self.admission.nodes.contains(&request.directive.node)
                && self.registration.enrollment.verifier == request.directive.node.verifier
                && self.registration.revision > 0
                && self.registration.revision <= self.operational_revision
                && !self.registration.operation_id.is_nil()
                && self.policy_epoch > 0
                && self.authority_term > 0
                && self.lifetime_ms > 0
                && self.lifetime_ms <= manifest.max_lease_ms,
            "current Control physical admission or finite observation differs"
        );
        ensure!(
            self.authorization.phase == AuthorityMaintenancePhase::Completed
                && self.authorization.command.operation_id
                    == request.directive.command.operation_id
                && self.authorization.progress_revision <= self.operational_revision
                && matches!(&self.authorization.command.action,
                AuthorityMaintenanceAction::AuthorizeControlSigner { directive } if **directive == request.directive),
            "remote effect lacks its exact current committed directive"
        );
        ensure!(
            !self.may_apply
                || self.authorization.command.expected_policy_epoch == self.policy_epoch,
            "remote first effect cannot use a retired source policy epoch"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSignerResponse {
    pub observation_id: Uuid,
    pub request_sha256: String,
    pub current: LocalSignerTrustRecord,
    pub receipt: SignerTrustReceipt,
    pub issuer: ControlSignerObservation,
}
impl ControlSignerResponse {
    pub fn validate_for(
        &self,
        request: &ControlSignerRequest,
        manifest: &AuthorityManifest,
    ) -> Result<()> {
        self.issuer.validate_for(request, manifest)?;
        self.current.validate()?;
        ensure!(
            self.observation_id == request.observation_id
                && self.request_sha256 == request.digest()?
                && self.current.verifier == request.directive.node.verifier
                && self.current.active.identity.domain.digest()? == request.directive.domain_sha256
                && self.receipt.command == request.directive.command
                && self.receipt.command_sha256 == request.directive.command.digest()?
                && !self.receipt.principal.is_empty()
                && request.directive.command.expected_revision.checked_add(1)
                    == Some(self.receipt.revision)
                && self.receipt.revision <= self.current.revision,
            "remote publication response differs from its exact physical directive"
        );
        kasumi_types::validate_sha256(&self.receipt.active_certificate_sha256)?;
        match &request.directive.command.action {
            SignerTrustAction::Stage { certificate } => ensure!(
                self.receipt.active_generation.checked_add(1)
                    == Some(certificate.identity.generation)
                    && !self.receipt.retirement_pending,
                "remote stage receipt reports another generation or retirement"
            ),
            SignerTrustAction::Activate {
                certificate_sha256, ..
            } => ensure!(
                self.receipt.active_generation == self.issuer.head.active.identity.generation
                    && self.receipt.active_certificate_sha256 == *certificate_sha256
                    && self.receipt.retirement_pending,
                "remote activation receipt does not publish the committed global winner"
            ),
            _ => anyhow::bail!("unsupported remote receipt"),
        }
        if self.current.revision == self.receipt.revision {
            ensure!(
                self.current.active.identity.generation == self.receipt.active_generation
                    && self.current.active.digest()? == self.receipt.active_certificate_sha256
                    && self.current.retirement.is_some() == self.receipt.retirement_pending,
                "current physical state contradicts its latest receipt"
            );
            match &request.directive.command.action {
                SignerTrustAction::Stage { certificate } => ensure!(
                    self.current
                        .staged
                        .as_ref()
                        .is_some_and(|stage| stage.operation_id
                            == self.receipt.command.operation_id
                            && stage.certificate == *certificate),
                    "latest remote stage is absent from the current physical state"
                ),
                SignerTrustAction::Activate { .. } => ensure!(
                    self.current
                        .retirement
                        .as_ref()
                        .is_some_and(|retirement| retirement.operation_id
                            == self.receipt.command.operation_id),
                    "latest remote activation lacks its exact pending local drain"
                ),
                _ => anyhow::bail!("unsupported remote receipt"),
            }
        }
        Ok(())
    }
}
