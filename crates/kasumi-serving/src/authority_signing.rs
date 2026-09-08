//! Replicated issuer-generation state. Historical roots certify keys; only this
//! current consensus head and the exact local verifier permit live issuance.
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySignerStage {
    pub operation_id: Uuid,
    pub revision: u64,
    pub certificate: SigningCertificate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySignerRetirement {
    pub stage_operation_id: Uuid,
    pub activation_operation_id: Uuid,
    pub activation_revision: u64,
    pub previous: SigningCertificate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySigningHead {
    pub initial: SigningCertificate,
    pub revision: u64,
    pub active: SigningCertificate,
    pub staged: Option<AuthoritySignerStage>,
    /// Global retirement cannot complete merely because one local verifier has
    /// waited. Every enrolled receiver and issuer still needs exact evidence.
    pub retirement: Option<AuthoritySignerRetirement>,
}
impl AuthoritySigningHead {
    pub fn initial(certificate: SigningCertificate) -> Result<Self> {
        let head = Self {
            initial: certificate.clone(),
            revision: 0,
            active: certificate,
            staged: None,
            retirement: None,
        };
        head.validate()?;
        Ok(head)
    }
    pub fn validate(&self) -> Result<()> {
        let domain = &self.initial.identity.domain;
        self.initial.verify(domain)?;
        ensure!(
            self.initial.identity.generation == 1,
            "initial issuer generation must be one"
        );
        self.active.verify(domain)?;
        ensure!(
            self.revision != 0
                || (self.active == self.initial
                    && self.staged.is_none()
                    && self.retirement.is_none()),
            "initial signing head contains an operational transition"
        );
        if self.active.identity.generation == 1 {
            ensure!(
                self.active == self.initial && self.retirement.is_none(),
                "generation-one head differs from its immutable initial key"
            );
        }
        ensure!(
            self.active.identity.generation == 1 || self.retirement.is_some(),
            "successor generation lacks its unresolved global retirement"
        );
        if let Some(staged) = &self.staged {
            staged.certificate.verify(domain)?;
            ensure!(
                self.retirement.is_none()
                    && !staged.operation_id.is_nil()
                    && staged.revision > 0
                    && staged.revision <= self.revision
                    && self.active.identity.generation.checked_add(1)
                        == Some(staged.certificate.identity.generation)
                    && self.active.identity.public_key != staged.certificate.identity.public_key,
                "staged authority signer differs from exact successor"
            );
        }
        if let Some(retirement) = &self.retirement {
            retirement.previous.verify(domain)?;
            ensure!(
                retirement.previous.identity.generation != 1 || retirement.previous == self.initial,
                "retired generation one differs from immutable bootstrap"
            );
            ensure!(
                !retirement.stage_operation_id.is_nil()
                    && !retirement.activation_operation_id.is_nil()
                    && retirement.activation_revision > 0
                    && retirement.activation_revision <= self.revision
                    && retirement.previous.identity.generation.checked_add(1)
                        == Some(self.active.identity.generation)
                    && retirement.previous.identity.public_key != self.active.identity.public_key,
                "global signer retirement identity differs"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoritySigningAction {
    Observe,
    Receipt {
        operation_id: Uuid,
    },
    Start {
        command: AuthorityMaintenanceCommand,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySigningRequest {
    pub observation_id: Uuid,
    pub domain_sha256: String,
    pub action: AuthoritySigningAction,
}
impl AuthoritySigningRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.observation_id.is_nil(),
            "fresh signing observation identity required"
        );
        kasumi_types::validate_sha256(&self.domain_sha256)?;
        match &self.action {
            AuthoritySigningAction::Observe => {}
            AuthoritySigningAction::Receipt { operation_id } => ensure!(
                !operation_id.is_nil(),
                "signing operation identity required"
            ),
            AuthoritySigningAction::Start { command } => {
                command.validate()?;
                ensure!(
                    command.action.is_signing_head_transition(),
                    "command is not a global signing transition"
                );
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.authority-signing-request.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySigningResponse {
    pub request_sha256: String,
    pub current: AuthoritySigningHead,
    pub policy_epoch: u64,
    pub operational_revision: u64,
    pub status: Option<AuthorityMaintenanceStatus>,
}
impl AuthoritySigningResponse {
    pub fn validate_for(
        &self,
        request: &AuthoritySigningRequest,
        domain: &SigningDomain,
    ) -> Result<()> {
        request.validate()?;
        self.current.validate()?;
        ensure!(
            self.policy_epoch > 0 && self.current.revision <= self.operational_revision,
            "signing observation positions differ"
        );
        ensure!(
            self.request_sha256 == request.digest()?
                && request.domain_sha256 == domain.digest()?
                && self.current.initial.identity.domain == *domain,
            "current authority signing response binding differs"
        );
        match (&request.action, &self.status) {
            (AuthoritySigningAction::Observe, None)
            | (AuthoritySigningAction::Receipt { .. }, None) => {}
            (AuthoritySigningAction::Receipt { operation_id }, Some(status)) => ensure!(
                status.command.operation_id == *operation_id,
                "signing receipt identity differs"
            ),
            (AuthoritySigningAction::Start { command }, Some(status)) => ensure!(
                status.command == *command,
                "signing transition input differs"
            ),
            _ => anyhow::bail!("authority signing response kind differs"),
        }
        if let Some(status) = &self.status {
            status.validate()?;
            ensure!(
                status.progress_revision <= self.operational_revision,
                "signing receipt exceeds current applied observation"
            );
            ensure!(
                status.command.action.is_signing_head_transition(),
                "receipt belongs to another maintenance operation"
            );
        }
        Ok(())
    }
}
