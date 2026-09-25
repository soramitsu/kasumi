//! Deterministic tenant state and the common authorized service layer.
pub use service::control_administration::ControlAdministrativeFence;
pub use service::lifecycle_service::{
    LifecycleSigner, VerifiedLifecycleChange, VerifiedLifecycleIntent,
};
pub use service::recovery_service::{
    RecoveryEffectDispatchTicket, VerifiedRecoveryPhase, VerifiedRecoveryStatus,
};
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
mod current_json;
pub use audit_source::authorize_audit_source;
pub mod admission;
mod audit_maintenance;
pub use audit_maintenance::AuditMaintenanceStatus;
mod backup_format;
mod backup_proof;
mod backup_verify;
mod target_completion_machine;
#[cfg(test)]
mod target_completion_status_tests;
mod target_initial_intent;
mod target_invocation;
mod target_signer;
pub use backup_proof::VerifiedBackupCheckpoint;
pub use service::target_activation_service::VerifiedTargetActivation;
pub use service::target_inspection_service::VerifiedTargetInspection;
pub use service::target_receiver_service::VerifiedTargetReceiver;
pub use service::target_service::VerifiedTargetCompletion;
pub use target_invocation::{
    TargetLifecycleInvocation, TargetOperation, TargetOperationScope, TargetRequestAdmission,
};
pub use target_signer::TargetSigner;
mod backup_binding;
mod bootstrap;
pub mod control;
mod mutation_receipt;
pub mod security_audit;
mod service;
mod snapshot_codec;
mod snapshot_index;
mod staged_terminal;
mod state;
mod target_resolution;
pub use bootstrap::{
    ControlGenesis, ControlLifecycleGenesis, LocalRestoreRequest, MaterializedTargetReplica,
    OpenedReplica, PreparedReplicaRestore, ReplicaPlacement, ReplicaRestoreConfig,
    ReplicatedBootstrap, ReplicatedGenesis, RestoreSource, TargetMaterializationConfig,
    TargetReplica, TargetReplicaConfig, VerifiedTargetMaterialization, initialize_replicated,
    materialize_target_replica, open_existing_local, open_existing_replicated, open_local,
    open_local_with_incarnation, open_replicated, open_target_replica, persisted_bootstrap_digest,
    persisted_bootstrap_digest_at, prepare_replicated_restore, recovery_workspace_bytes,
    restore_local, resume_target_materialization,
};
pub use security_audit::{
    SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome,
    TransportAuditMetadata,
};
pub use service::{
    CustodyResponseFence, Database, ResponseFence, RetiredCustody, RetirementResponseFence,
};
pub use state::{Generation, PreparedSnapshotRestore, TenantEngine};

/// Conservative resident charge for retaining one immutable document across
/// asynchronous work. Uses the same allocation accounting as coherent leases;
/// callers must reserve this amount before cloning the shared document handle.
pub fn retained_document_bytes(document: &kasumi_types::Document) -> kasumi_types::Result<usize> {
    state::lease_retention::document_heap(document, usize::MAX)
}
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
    MaterializationFile, MaterializationNode, TargetJournal, TargetJournalInstallation,
    TargetJournalIntent, VerifiedTargetServingProjection,
};

pub use bootstrap::target_serving::{TargetServingReplica, open_serving_target};

#[cfg(any(test, feature = "test-utils"))]
pub use bootstrap::open_fixture_with_epoch_clock;

#[cfg(test)]
mod codec_fixture;
