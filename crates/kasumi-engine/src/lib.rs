//! Deterministic tenant state and the common authorized service layer.
mod retirement_closure;
mod retirement_proof;
mod retirement_source;
pub use retirement_proof::{
    VerifiedRetirementReceipt, VerifiedRetirementResolution, VerifiedRetirementStop,
};
pub use retirement_source::InstalledRetirementSource;
mod accounting;
pub mod admission;
mod backup_format;
mod backup_proof;
mod backup_verify;
pub use backup_proof::VerifiedBackupCheckpoint;
mod bootstrap;
pub mod control;
pub mod security_audit;
mod service;
mod state;
pub use bootstrap::{
    PreparedReplicaRestore, ReplicaPlacement, ReplicaRestoreConfig, ReplicatedBootstrap,
    RestoreSource, initialize_replicated, open_local, open_replicated, prepare_replicated_restore,
    recovery_workspace_bytes, restore_local, restore_local_with_incarnation,
    restore_local_with_incarnation_and_admission,
};
pub use security_audit::{
    SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome,
    TransportAuditMetadata,
};
pub use service::{
    CustodyResponseFence, Database, ResponseFence, RetiredCustody, RetirementResponseFence,
};
pub use state::{Generation, TenantEngine};
mod change_feed_state;

/// Adapters retain one of these fences through final response encoding.
pub trait EncodedResponseFence {
    fn check(&self) -> kasumi_types::Result<()>;
}
impl EncodedResponseFence for ResponseFence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        ResponseFence::check(self)
    }
}
impl EncodedResponseFence for CustodyResponseFence {
    fn check(&self) -> kasumi_types::Result<()> {
        CustodyResponseFence::check(self)
    }
}
impl EncodedResponseFence for RetirementResponseFence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        RetirementResponseFence::check(self)
    }
}
