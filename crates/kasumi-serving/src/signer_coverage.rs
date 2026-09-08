//! Historical coverage records. Deserializing these records never creates a
//! current native observation or permission to mutate a physical verifier.
use crate::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerPublicationRequest {
    Issuer {
        observation_id: Uuid,
        directive: Box<IssuerSignerDirective>,
    },
    Control {
        request: Box<ControlSignerRequest>,
    },
}
impl SignerPublicationRequest {
    pub fn command(&self) -> &SignerTrustCommand {
        match self {
            Self::Issuer { directive, .. } => &directive.command,
            Self::Control { request } => &request.directive.command,
        }
    }
    pub fn verifier(&self) -> &TrustVerifierIdentity {
        match self {
            Self::Issuer { directive, .. } => &directive.verifier,
            Self::Control { request } => &request.directive.node.verifier,
        }
    }
    pub fn domain_sha256(&self) -> &str {
        match self {
            Self::Issuer { directive, .. } => &directive.domain_sha256,
            Self::Control { request } => &request.directive.domain_sha256,
        }
    }
    pub fn global_stage(&self) -> Uuid {
        match self {
            Self::Issuer { directive, .. } => directive.global_stage_operation_id,
            Self::Control { request } => request.directive.global_stage_operation_id,
        }
    }
    pub fn global_activation(&self) -> Result<Uuid> {
        match self {
            Self::Issuer { directive, .. } => directive.global_activation_operation_id,
            Self::Control { request } => request.directive.global_activation_operation_id,
        }
        .context("publication lacks its exact committed global winner")
    }
    pub fn issuer_request(&self) -> Result<SignerVerifierRequest> {
        let Self::Issuer {
            observation_id,
            directive,
        } = self
        else {
            anyhow::bail!("publication is not an issuer request");
        };
        Ok(SignerVerifierRequest {
            observation_id: *observation_id,
            verifier: directive.verifier.clone(),
            domain_sha256: directive.domain_sha256.clone(),
            action: SignerVerifierAction::Administer {
                command: directive.command.clone(),
            },
        })
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Issuer {
                observation_id,
                directive,
            } => {
                ensure!(
                    !observation_id.is_nil(),
                    "publication observation identity required"
                );
                directive.validate()?;
            }
            Self::Control { request } => {
                request.digest()?;
            }
        }
        ensure!(
            matches!(self.command().action, SignerTrustAction::Activate { .. }),
            "coverage requires the original activation, not a stage or retirement claim"
        );
        self.global_activation()?;
        Ok(())
    }
    pub fn validate_manifest(&self, manifest: &AuthorityManifest) -> Result<()> {
        self.validate()?;
        manifest.validate()?;
        let mut installed = false;
        for partition in manifest.partitions.keys() {
            if manifest.signing_domain(*partition)?.digest()? == self.domain_sha256() {
                installed = true;
            }
        }
        ensure!(
            installed,
            "publication signing domain is not independently installed"
        );
        if let Self::Control { request } = self {
            ensure!(
                manifest
                    .lifecycle_controls
                    .get(&request.directive.root.control_incarnation)
                    == Some(&request.directive.root.public_key),
                "publication Control root is not independently installed"
            );
        }
        Ok(())
    }
    pub fn validate_for_head(&self, head: &AuthoritySigningHead) -> Result<()> {
        self.validate()?;
        match self {
            Self::Issuer { directive, .. } => directive.validate_for_head(head),
            Self::Control { request } => request.directive.validate_for_head(head),
        }
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.signer-publication-request.v1", self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "response",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SignerPublicationResponse {
    Issuer(Box<SignerVerifierResponse>),
    Control(Box<ControlSignerResponse>),
}
impl SignerPublicationResponse {
    pub fn current(&self) -> &LocalSignerTrustRecord {
        match self {
            Self::Issuer(reply) => &reply.current,
            Self::Control(reply) => &reply.current,
        }
    }
    pub fn authorization(&self) -> Result<&AuthorityMaintenanceStatus> {
        match self {
            Self::Issuer(reply) => reply
                .authorization
                .as_ref()
                .context("source publication permission absent"),
            Self::Control(reply) => Ok(&reply.issuer.authorization),
        }
    }
    pub fn receipt(&self) -> Result<&SignerTrustReceipt> {
        match self {
            Self::Issuer(reply) => reply.receipt.as_ref().context("publication receipt absent"),
            Self::Control(reply) => Ok(&reply.receipt),
        }
    }
    pub fn validate_for(
        &self,
        request: &SignerPublicationRequest,
        manifest: &AuthorityManifest,
    ) -> Result<()> {
        request.validate_manifest(manifest)?;
        match (self, request) {
            (Self::Issuer(reply), SignerPublicationRequest::Issuer { directive, .. }) => {
                let domain = &reply.current.active.identity.domain;
                ensure!(
                    manifest.signing_domain(domain.partition)? == *domain,
                    "publication signing domain is not independently installed"
                );
                reply.validate_for(&request.issuer_request()?, domain)?;
                ensure!(
                    matches!(&reply.authorization.as_ref().context("source permission absent")?.command.action,
                    AuthorityMaintenanceAction::AuthorizeSignerTrust { directive: exact } if exact == directive),
                    "publication substituted its original global or local permission"
                );
            }
            (Self::Control(reply), SignerPublicationRequest::Control { request }) => {
                reply.validate_for(request, manifest)?;
            }
            _ => anyhow::bail!("publication response belongs to another receiver kind"),
        }
        let receipt = self.receipt()?;
        let SignerTrustAction::Activate {
            certificate_sha256, ..
        } = &request.command().action
        else {
            anyhow::bail!("publication is not an activation");
        };
        ensure!(
            receipt.command == *request.command()
                && request.command().expected_revision.checked_add(1) == Some(receipt.revision)
                && receipt.active_certificate_sha256 == *certificate_sha256
                && receipt.active_generation == self.current().active.identity.generation
                && self.current().active.digest()? == *certificate_sha256
                && self.current().verifier == *request.verifier(),
            "current publication does not cover the exact original activation"
        );
        if let Some(retirement) = &self.current().retirement {
            ensure!(
                retirement.operation_id == request.command().operation_id,
                "current publication has another local activation drain"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCoverageCommand {
    pub operation_id: Uuid,
    pub expected_policy_epoch: u64,
    pub expected_operational_revision: u64,
    pub not_after_ms: u64,
    pub publication: SignerPublicationRequest,
}
impl SignerCoverageCommand {
    pub fn digest(&self) -> Result<String> {
        ensure!(
            !self.operation_id.is_nil() && self.expected_policy_epoch > 0 && self.not_after_ms > 0,
            "coverage dispatch requires an exact finite admission"
        );
        self.publication.validate()?;
        ensure!(
            self.not_after_ms == self.publication.command().not_after_ms,
            "coverage dispatch must retain the exact original local activation admission"
        );
        crate::digest(&("kasumi.signer-coverage-command.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCoverageDispatch {
    pub command: SignerCoverageCommand,
    pub command_sha256: String,
    pub registration: SignerVerifierRegistration,
    pub frozen_roster: SignerVerifierRoster,
    pub admitted_principal: String,
    pub revision: u64,
}
impl SignerCoverageDispatch {
    pub fn digest(&self) -> Result<String> {
        ensure!(
            self.command.digest()? == self.command_sha256 && self.revision > 0,
            "coverage dispatch command or position differs"
        );
        self.registration.enrollment.validate()?;
        self.frozen_roster.validate()?;
        kasumi_types::validate_name(&self.admitted_principal)?;
        ensure!(
            !self.registration.operation_id.is_nil()
                && self.registration.enrollment.verifier == *self.command.publication.verifier()
                && self.registration.revision > 0
                && self.registration.revision < self.revision,
            "coverage dispatch physical registration differs"
        );
        crate::digest(&("kasumi.signer-coverage-dispatch.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCoverageAcknowledgment {
    pub dispatch_operation_id: Uuid,
    pub dispatch_sha256: String,
    pub publication: SignerPublicationResponse,
    pub revision: u64,
}
impl SignerCoverageAcknowledgment {
    pub fn validate_for(
        &self,
        dispatch: &SignerCoverageDispatch,
        manifest: &AuthorityManifest,
    ) -> Result<()> {
        ensure!(
            self.dispatch_operation_id == dispatch.command.operation_id
                && self.dispatch_sha256 == dispatch.digest()?
                && self.revision > dispatch.revision,
            "coverage acknowledgment lacks its original earlier dispatch"
        );
        self.publication
            .validate_for(&dispatch.command.publication, manifest)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCoverageStatus {
    pub dispatch: SignerCoverageDispatch,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub acknowledgment: Option<SignerCoverageAcknowledgment>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerCoverageRequest {
    Start { command: SignerCoverageCommand },
    Resume { operation_id: Uuid },
    Status { operation_id: Uuid },
}
impl SignerCoverageRequest {
    pub fn operation_id(&self) -> Uuid {
        match self {
            Self::Start { command } => command.operation_id,
            Self::Resume { operation_id } | Self::Status { operation_id } => *operation_id,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.operation_id().is_nil(),
            "exact coverage operation identity required"
        );
        if let Self::Start { command } = self {
            command.digest()?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.signer-coverage-request.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCoverageResponse {
    pub request_sha256: String,
    pub status: SignerCoverageStatus,
}
impl SignerCoverageResponse {
    pub fn validate_for(
        &self,
        request: &SignerCoverageRequest,
        manifest: &AuthorityManifest,
    ) -> Result<()> {
        ensure!(
            self.request_sha256 == request.digest()?
                && self.status.dispatch.command.operation_id == request.operation_id(),
            "coverage response differs from the original request"
        );
        self.status.dispatch.digest()?;
        self.status
            .dispatch
            .command
            .publication
            .validate_manifest(manifest)?;
        if let SignerCoverageRequest::Start { command } = request {
            ensure!(
                self.status.dispatch.command == *command,
                "coverage response changed the original dispatch"
            );
        }
        if let Some(ack) = &self.status.acknowledgment {
            ack.validate_for(&self.status.dispatch, manifest)?;
        }
        Ok(())
    }
}
