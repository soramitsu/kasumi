//! Deterministic tenant state and the common authorized service layer.
pub use service::control_administration::ControlAdministrativeFence;
pub use service::lifecycle_service::{
    LifecycleSigner, VerifiedLifecycleChange, VerifiedLifecycleIntent,
};
pub use service::recovery_service::{VerifiedRecoveryPhase, VerifiedRecoveryStatus};
mod restore_lineage_proof;
mod retirement_closure;
mod retirement_proof;
pub use restore_lineage_proof::VerifiedRestoreLineage;
mod retirement_source;
pub use retirement_proof::{
    VerifiedRetirementReceipt, VerifiedRetirementResolution, VerifiedRetirementStop,
};
pub use retirement_source::InstalledRetirementSource;
mod accounting;
mod audit_source;
pub use audit_source::authorize_audit_source;
pub mod admission;
mod audit_maintenance;
pub use audit_maintenance::AuditMaintenanceStatus;
mod backup_format;
mod backup_proof;
mod backup_verify;
mod target_invocation;
mod target_signer;
pub use backup_proof::VerifiedBackupCheckpoint;
pub use service::target_activation_service::VerifiedTargetActivation;
pub use service::target_inspection_service::VerifiedTargetInspection;
pub use service::target_service::VerifiedTargetCompletion;
pub use target_invocation::{
    TargetLifecycleInvocation, TargetOperation, TargetOperationScope, TargetRequestAdmission,
};
pub use target_signer::TargetSigner;
mod bootstrap;
pub mod control;
pub mod security_audit;
mod service;
mod snapshot_codec;
mod snapshot_index;
mod state;
pub use bootstrap::{
    LocalRestoreRequest, MaterializedTargetReplica, PreparedReplicaRestore, ReplicaPlacement,
    ReplicaRestoreConfig, ReplicatedBootstrap, RestoreSource, TargetMaterializationConfig,
    TargetReplica, TargetReplicaConfig, VerifiedTargetMaterialization, initialize_replicated,
    materialize_target_replica, open_local, open_local_with_incarnation, open_replicated,
    open_target_replica, prepare_replicated_restore, recovery_workspace_bytes, restore_local,
    resume_target_materialization,
};
pub use security_audit::{
    SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome,
    TransportAuditMetadata,
};
pub use service::{
    CustodyResponseFence, Database, ResponseFence, RetiredCustody, RetirementResponseFence,
};
pub use state::{Generation, PreparedSnapshotRestore, TenantEngine};
mod change_feed_state;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

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

mod target_journal;
pub use target_journal::{
    TargetJournal, TargetJournalInstallation, TargetJournalIntent, VerifiedTargetServingProjection,
};

pub use bootstrap::target_serving::{TargetServingReplica, open_serving_target};

#[cfg(any(test, feature = "test-utils"))]
pub use bootstrap::open_fixture_with_epoch_clock;
