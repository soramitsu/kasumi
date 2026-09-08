//! Replicated issuer-generation state. Historical roots certify keys; only this
//! current consensus head and the exact local verifier permit live issuance.
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Installed native administrative origin for one durable physical verifier.
/// Credentials remain local renewable sources; they are never replicated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierEnrollment {
    pub verifier: TrustVerifierIdentity,
    pub endpoint: String,
    pub certificate_pins: std::collections::BTreeSet<String>,
}
impl SignerVerifierEnrollment {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            url::Url::parse(&self.endpoint)?.to_string() == self.endpoint,
            "verifier endpoint must be a canonical HTTPS origin"
        );
        AuthorityMember {
            verifier: self.verifier.clone(),
            endpoint: self.endpoint.clone(),
            failure_domain: "signer-verifier".into(),
            certificate_pins: self.certificate_pins.clone(),
        }
        .validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierRegistration {
    pub enrollment: SignerVerifierEnrollment,
    pub operation_id: Uuid,
    pub revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierPage {
    pub registrations: Vec<SignerVerifierRegistration>,
    pub next: Option<TrustVerifierIdentity>,
}

/// Current administrative admission of the exact Control receiver set for one
/// installed root and issuer partition. This is an enrollment fact, never an
/// acknowledgement that a remote verifier has published a trust transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlVerifierAdmission {
    pub root: kasumi_types::ControlSigningRoot,
    pub partition: kasumi_types::ControlAuthorityPartition,
    pub nodes: std::collections::BTreeSet<NodeIdentity>,
}
impl ControlVerifierAdmission {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        self.partition.validate()?;
        validate_nodes(&self.nodes)
    }
}

/// Digest of the complete point-addressed enrollment table at the atomic stage
/// and admission freeze. The table, not a caller-supplied list, defines coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierRoster {
    pub enrollment_count: u64,
    pub control_count: u64,
    pub sha256: String,
}
impl SignerVerifierRoster {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.enrollment_count >= 3,
            "signer roster omits issuer members"
        );
        kasumi_types::validate_sha256(&self.sha256).map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySignerStage {
    pub roster: SignerVerifierRoster,
    pub operation_id: Uuid,
    pub revision: u64,
    pub certificate: SigningCertificate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySignerRetirement {
    pub roster: SignerVerifierRoster,
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
            staged.roster.validate()?;
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
            retirement.roster.validate()?;
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
    Verifiers {
        expected_operational_revision: u64,
        after: Option<TrustVerifierIdentity>,
        limit: u16,
    },
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
            AuthoritySigningAction::Verifiers { after, limit, .. } => {
                ensure!(
                    (1..=64).contains(limit),
                    "verifier page limit outside bounded range"
                );
                if let Some(after) = after {
                    after.validate()?;
                }
            }
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
    pub verifier_page: Option<SignerVerifierPage>,
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
            | (AuthoritySigningAction::Verifiers { .. }, None)
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
        match (&request.action, &self.verifier_page) {
            (
                AuthoritySigningAction::Verifiers {
                    expected_operational_revision,
                    after,
                    limit,
                },
                Some(page),
            ) => {
                ensure!(
                    *expected_operational_revision == self.operational_revision
                        && page.registrations.len() <= usize::from(*limit),
                    "verifier pagination position or work bound differs"
                );
                let mut previous = after.as_ref();
                for registration in &page.registrations {
                    registration.enrollment.validate()?;
                    ensure!(!registration.operation_id.is_nil() && registration.revision > 0 && registration.revision <= self.operational_revision
                        && previous.is_none_or(|identity| *identity < registration.enrollment.verifier), "verifier page identity or ordering differs");
                    previous = Some(&registration.enrollment.verifier);
                }
                ensure!(
                    page.next.is_none()
                        || (!page.registrations.is_empty() && page.next.as_ref() == previous),
                    "verifier continuation does not retain the last exact identity"
                );
            }
            (AuthoritySigningAction::Verifiers { .. }, None) => {
                anyhow::bail!("verifier page absent")
            }
            (_, Some(_)) => anyhow::bail!("unexpected verifier page"),
            (_, None) => {}
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
