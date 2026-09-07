//! A current authenticated observation of one permanent planned source fence.
//! The receipt is immutable evidence, not renewable serving authority.
use kasumi_types::{FullBackupCheckpoint, RetirementReceipt};

/// A definitive observation for one exact command, never a serving lease.
#[derive(Clone, Debug)]
pub enum VerifiedRetirementResolution {
    Retired(VerifiedRetirementReceipt),
    Stopped(VerifiedRetirementStop),
}

/// Created only from an accepted permanent failure/stop under current source
/// Admin. A missing command or expired caller lease cannot construct this proof.
///
/// ```compile_fail
/// let _: kasumi_engine::VerifiedRetirementStop = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedRetirementStop {
    status: kasumi_types::RetirementStatus,
}
impl VerifiedRetirementStop {
    pub(crate) fn new(status: kasumi_types::RetirementStatus) -> Self {
        Self { status }
    }
    pub fn reference(&self) -> &kasumi_types::RetirementRef {
        &self.status.reference
    }
    pub fn tenant(&self) -> &str {
        &self.status.tenant
    }
    pub fn source_incarnation(&self) -> &str {
        &self.status.reference.source_incarnation
    }
    pub fn retirement_id(&self) -> &str {
        &self.status.reference.retirement_id
    }
    pub fn request_digest(&self) -> &str {
        &self.status.reference.request_digest
    }
    pub fn revision(&self) -> u64 {
        self.status.accepted_revision
    }
    pub fn principal(&self) -> &str {
        &self.status.principal
    }
    pub fn failure(&self) -> &kasumi_types::Error {
        self.status.outcome.as_ref().unwrap_err()
    }
    pub fn status(&self) -> &kasumi_types::RetirementStatus {
        &self.status
    }
}

/// Constructed only after the authoritative source's permanent retirement
/// outcome and exact incarnation binding have been observed under current Admin.
/// Deserializing the wire record cannot create this type.
///
/// ```compile_fail
/// let _: kasumi_engine::VerifiedRetirementReceipt = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedRetirementReceipt {
    receipt: RetirementReceipt,
    invocation: Option<kasumi_types::RequestContext>,
}
impl VerifiedRetirementReceipt {
    pub(crate) fn new(receipt: RetirementReceipt) -> Self {
        Self {
            receipt,
            invocation: None,
        }
    }
    pub(crate) fn from_accepted_invocation(
        receipt: RetirementReceipt,
        context: &kasumi_types::RequestContext,
    ) -> Self {
        Self {
            receipt,
            invocation: Some(context.clone()),
        }
    }
    pub(crate) fn is_accepted_invocation(&self, context: &kasumi_types::RequestContext) -> bool {
        self.invocation.as_ref().is_some_and(|original| {
            original == context
                && original
                    .authorization
                    .same_live_invocation(&context.authorization)
        })
    }
    pub fn tenant(&self) -> &str {
        &self.receipt.tenant
    }
    pub fn source_incarnation(&self) -> &str {
        &self.receipt.source_incarnation
    }
    pub fn target_incarnation(&self) -> &str {
        &self.receipt.target_incarnation
    }
    pub fn retirement_id(&self) -> &str {
        &self.receipt.retirement_id
    }
    pub fn revision(&self) -> u64 {
        self.receipt.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.receipt.policy_epoch
    }
    pub fn checkpoint(&self) -> &FullBackupCheckpoint {
        &self.receipt.checkpoint
    }
    pub fn request_digest(&self) -> &str {
        &self.receipt.request_digest
    }
    pub fn receipt(&self) -> &RetirementReceipt {
        &self.receipt
    }
}
