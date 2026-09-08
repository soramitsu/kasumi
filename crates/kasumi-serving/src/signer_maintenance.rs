//! Current authenticated local-verifier maintenance. These observations are not
//! signing-root proofs and never authorize another verifier's activation.
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerVerifierAction {
    Observe,
    /// Reopen the installed key source for this already activated durable head.
    /// This changes only the in-memory signer; it is not a trust transition or
    /// a permanent rotation completion receipt.
    ReloadOperationalSigner {
        expected_revision: u64,
        certificate_sha256: String,
        not_after_ms: u64,
    },
    Receipt {
        operation_id: Uuid,
    },
    Administer {
        command: SignerTrustCommand,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierRequest {
    /// Fresh request correlation; an immutable receipt is not a current reply.
    pub observation_id: Uuid,
    pub verifier: TrustVerifierIdentity,
    pub domain_sha256: String,
    pub action: SignerVerifierAction,
}
impl SignerVerifierRequest {
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.signer-verifier-request.v1", self))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.observation_id.is_nil(),
            "observation identity required"
        );
        self.verifier.validate()?;
        kasumi_types::validate_sha256(&self.domain_sha256)?;
        match &self.action {
            SignerVerifierAction::Observe => {}
            SignerVerifierAction::ReloadOperationalSigner {
                certificate_sha256,
                not_after_ms,
                ..
            } => {
                kasumi_types::validate_sha256(certificate_sha256)?;
                ensure!(*not_after_ms > 0, "reload admission deadline required");
            }
            SignerVerifierAction::Receipt { operation_id } => {
                ensure!(!operation_id.is_nil(), "receipt identity required")
            }
            SignerVerifierAction::Administer { command } => {
                command.digest()?;
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerVerifierResponse {
    pub observation_id: Uuid,
    pub request_sha256: String,
    pub domain_sha256: String,
    pub current: LocalSignerTrustRecord,
    pub receipt: Option<SignerTrustReceipt>,
    /// A current reload observation, never a historical authorization proof.
    pub loaded_certificate: Option<SigningCertificate>,
    /// Permanent consensus authorization. Local publication is evidenced only
    /// by `receipt`; this field alone does not complete rotation or local drain.
    pub authorization: Option<AuthorityMaintenanceStatus>,
}
impl SignerVerifierResponse {
    /// Validation requires the exact original request and independently installed
    /// signing domain. This checks a current native reply, never a live capability.
    pub fn validate_for(
        &self,
        request: &SignerVerifierRequest,
        domain: &SigningDomain,
    ) -> Result<()> {
        request.validate()?;
        self.current.validate()?;
        ensure!(
            self.observation_id == request.observation_id
                && self.request_sha256 == request.digest()?
                && self.domain_sha256 == request.domain_sha256
                && self.domain_sha256 == domain.digest()?
                && self.current.verifier == request.verifier
                && self.current.active.identity.domain == *domain,
            "current verifier response binding differs"
        );
        match (&request.action, &self.receipt) {
            (SignerVerifierAction::Observe, None)
            | (SignerVerifierAction::ReloadOperationalSigner { .. }, None)
            | (SignerVerifierAction::Receipt { .. }, None) => {}
            (SignerVerifierAction::Receipt { operation_id }, Some(receipt)) => ensure!(
                receipt.command.operation_id == *operation_id,
                "receipt identity differs"
            ),
            (SignerVerifierAction::Administer { command }, Some(receipt)) => ensure!(
                receipt.command == *command,
                "accepted signer command differs"
            ),
            _ => anyhow::bail!("verifier response kind differs"),
        }
        match (&request.action, &self.loaded_certificate) {
            (
                SignerVerifierAction::ReloadOperationalSigner {
                    expected_revision,
                    certificate_sha256,
                    ..
                },
                Some(certificate),
            ) => {
                certificate.verify(domain)?;
                ensure!(
                    *expected_revision == self.current.revision
                        && *certificate == self.current.active
                        && certificate.digest()? == *certificate_sha256,
                    "loaded signer differs from requested durable generation"
                );
            }
            (SignerVerifierAction::ReloadOperationalSigner { .. }, None) => {
                anyhow::bail!("reload observation lacks its loaded signer")
            }
            (_, None) => {}
            (_, Some(_)) => anyhow::bail!("unrequested signer reload observation"),
        }
        if let Some(authorization) = &self.authorization {
            authorization.validate()?;
            let AuthorityMaintenanceAction::AuthorizeSignerTrust {
                verifier,
                domain_sha256,
                command,
            } = &authorization.command.action
            else {
                anyhow::bail!("response has another maintenance authorization");
            };
            ensure!(
                *verifier == request.verifier && *domain_sha256 == request.domain_sha256,
                "consensus directive targets another verifier"
            );
            let requested_id = match &request.action {
                SignerVerifierAction::Observe
                | SignerVerifierAction::ReloadOperationalSigner { .. } => {
                    anyhow::bail!("observation cannot carry an unrelated directive")
                }
                SignerVerifierAction::Receipt { operation_id } => *operation_id,
                SignerVerifierAction::Administer { command } => command.operation_id,
            };
            ensure!(
                command.operation_id == requested_id,
                "consensus directive identity differs"
            );
            if let Some(receipt) = &self.receipt {
                ensure!(
                    authorization.phase == AuthorityMaintenancePhase::Completed
                        && **command == receipt.command,
                    "local publication has no matching committed directive"
                );
            }
        } else {
            ensure!(
                self.receipt.is_none(),
                "local receipt lacks its permanent consensus directive"
            );
        }
        if let Some(receipt) = &self.receipt {
            ensure!(
                receipt.command_sha256 == receipt.command.digest()?
                    && receipt.revision > 0
                    && receipt.revision <= self.current.revision
                    && receipt.active_generation > 0
                    && receipt.active_generation <= self.current.active.identity.generation,
                "permanent signer receipt differs"
            );
            kasumi_types::validate_name(&receipt.principal)?;
            kasumi_types::validate_sha256(&receipt.active_certificate_sha256)?;
            if receipt.revision == self.current.revision {
                ensure!(
                    receipt.active_generation == self.current.active.identity.generation
                        && receipt.active_certificate_sha256 == self.current.active.digest()?
                        && receipt.retirement_pending == self.current.retirement.is_some(),
                    "current signer head and receipt disagree"
                );
            }
        }
        Ok(())
    }
}
