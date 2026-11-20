//! Deterministic tenant state and the common authorized service layer.
pub use service::control_administration::ControlAdministrativeFence;
pub use service::control_topology_service::VerifiedControlTopology;
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
mod output;
pub use output::AdmittedOutput;
mod application_checkpoint;
mod application_primary;
mod application_records;
mod application_sources;
mod application_structured;
mod application_text;
mod audit_source;
mod current_json;
mod document_encoding;
mod document_gc;
mod document_restore;
mod document_source;
mod document_store;
mod generation_metadata;
pub use generation_metadata::{CollectionMetadata, LifecycleInstallationMetadata};
mod index_source;
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
pub use service::target_initial_membership_service::VerifiedTargetInitialMembershipStatus;
pub use service::target_inspection_service::VerifiedTargetInspection;
pub use service::target_receiver_service::VerifiedTargetReceiver;
pub use service::target_service::VerifiedTargetCompletion;
pub use target_invocation::{
    TargetLifecycleInvocation, TargetOperation, TargetOperationScope, TargetRequestAdmission,
};
pub use target_signer::TargetSigner;
mod backup_binding;
pub use backup_binding::ControlBackupSessions;
pub use service::backup_session_pages::{
    ControlBackupSessionBinding, ControlBackupSessionCursor, ControlBackupSessionDecision,
    ControlBackupSessionEntry, ControlBackupSessionPage, MAX_CONTROL_BACKUP_SESSION_PAGE,
};
mod bootstrap;
pub mod control;
mod materialization_row;
mod mutation_receipt;
mod namespace_installation;
pub mod security_audit;
mod service;
mod snapshot_codec;
mod snapshot_index;
mod staged_terminal;
mod state;
mod target_resolution;
mod tenant_audit_directory;
pub use bootstrap::{
    ControlGenesis, ControlLifecycleGenesis, LocalRestoreRequest, MaterializedTargetReplica,
    OpenedReplica, ReplicaPlacement, ReplicatedBootstrap, ReplicatedGenesis, RestoreSource,
    TargetMaterializationConfig, TargetReplica, TargetReplicaConfig, TargetReplicaStartup,
    VerifiedTargetMaterialization, initialize_replicated, materialize_target_replica,
    open_existing_local, open_existing_replicated, open_local, open_local_with_incarnation,
    open_replicated, open_target_replica, persisted_bootstrap_digest,
    persisted_bootstrap_digest_at, recovery_workspace_bytes, restore_local,
    resume_target_materialization,
};
pub use security_audit::{
    ArchivePrune, SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind,
    SecurityOutcome, TransportAuditMetadata,
};
pub use service::{
    AuthoritySignerKeyInventory, AuthoritySignerKeys, BackupSourceCapability, CustodyResponseFence,
    Database, LocalRecoveryCheckpoint, LocalRecoveryKeyFinding, LocalRecoveryKeyInventory,
    LocalRecoveryKeyRead, RemoteBackupFuture, RemoteBackupSourceVerifier, RemoteBackupTransport,
    RemoteDataCatalogReader, ResponseFence, RetiredCustody, RetirementResponseFence, SignerCatalog,
    TargetCheckpointInventory, TargetCheckpointSource, TargetJournalExclusion,
    VerifiedBackupSource,
};
pub use state::{
    Generation, LocalSnapshotArchive, PreparedSnapshotRestore, TenantEngine,
    local_snapshot_archive, set_local_snapshot_archive, validate_genesis_inputs,
};
mod snapshot_failure;
pub use snapshot_failure::SnapshotFailure;
#[cfg(test)]
mod allocation_tests;
#[cfg(test)]
mod local_writer_capacity_tests;
#[cfg(test)]
mod test_fixture_failure;

/// Conservative resident charge for retaining one immutable document across
/// asynchronous work. Uses the same allocation accounting as coherent leases;
/// callers must reserve this amount before cloning the shared document handle.
pub fn retained_document_bytes(document: &kasumi_types::Document) -> kasumi_types::Result<usize> {
    state::lease_retention::document_heap(document, usize::MAX)
}
mod change_feed_state;

/// Daemon diagnostics carry only fixed drain inventory labels. Retained error
/// chains may hold provider, path or storage detail and stay in the owner.
pub(crate) fn drain_components(failure: &kasumi_types::drain::DrainFailure) -> String {
    let mut names = failure
        .issues()
        .iter()
        .map(|issue| issue.component())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names.join(",")
}
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
    AcceptedInitialDispatchPrebind, InitialDispatchReservation, InitialDispatchStatus,
    InitialInitializePermit, MaterializationFile, MaterializationNode,
    ResolvedInitialMembershipHistory, ResolvedInitialStart, TargetCleanup, TargetCleanupStage,
    TargetFileBinding, TargetJournal, TargetJournalInstallation, TargetJournalIntent,
    TargetOwnerDrain, TargetWriterRead, VerifiedInitialMembership,
    VerifiedTargetInitializationAssociation, VerifiedTargetServingProjection,
};

pub use bootstrap::target_serving::{TargetServingReplica, open_serving_target};

#[cfg(any(test, feature = "test-utils"))]
pub use bootstrap::open_fixture_with_epoch_clock;

#[cfg(test)]
mod codec_fixture;
