#[path = "accepted_apply.rs"]
mod accepted_apply;
use accepted_apply::{AcceptedGeneration, ApplyOwner, ChangedIds};
#[path = "validation_baseline.rs"]
mod validation_baseline;
use validation_baseline::{CapturedValidation, UninitializedEngine, ValidationBaseline};
#[path = "ordered_command.rs"]
mod ordered_command;
#[cfg(test)]
#[path = "validation_baseline_tests.rs"]
mod validation_baseline_tests;
use ordered_command::ByteBoundCommand;
#[cfg(test)]
use ordered_command::PreparedOrderedCommand;
#[path = "custody_snapshot.rs"]
mod custody_snapshot;
#[path = "mutation_apply.rs"]
mod mutation_apply;
#[path = "mutation_capacity.rs"]
mod mutation_capacity;
pub(crate) use mutation_capacity::admit_mutation_capacity;
#[cfg(test)]
#[path = "primary_projection.rs"]
pub(crate) mod primary_projection;
#[path = "snapshot_api.rs"]
mod snapshot_api;
#[path = "snapshot_bundle.rs"]
mod snapshot_bundle;
#[path = "snapshot_validation.rs"]
pub(crate) mod snapshot_validation;
use crate::SnapshotFailure;
use crate::accounting::{SnapshotAccounting, encoded_len};
use arc_swap::ArcSwapOption;
use kasumi_query::{QueryIndexes, check_unique, validate_collection};
use kasumi_types::*;
use sha2::{Digest, Sha256};
pub use snapshot_api::PreparedSnapshotRestore;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
#[path = "history_state.rs"]
pub(crate) mod history;
#[path = "lease_retention.rs"]
pub(crate) mod lease_retention;
#[path = "lifecycle_state.rs"]
pub(crate) mod lifecycle;
#[path = "recovery_state.rs"]
pub(crate) mod recovery;
#[path = "retirement_state.rs"]
pub(crate) mod retirement;
#[path = "schema_activation.rs"]
pub(crate) mod schema;
#[path = "staging.rs"]
pub(crate) mod staging;
#[path = "target_state.rs"]
pub(crate) mod target;
#[path = "tenant_audit.rs"]
pub(crate) mod tenant_audit;

pub struct Generation {
    pub state: TenantState,
    pub(crate) receipts: crate::mutation_receipt::View,
    pub(crate) backup_bindings: crate::backup_binding::View,
    pub(crate) terminals: crate::staged_terminal::View,
    pub(crate) target_resolutions: crate::target_resolution::View,
    pub(crate) indexes: Arc<QueryIndexes>,
    snapshot_accounting: SnapshotAccounting,
    pub(crate) application_selection:
        std::sync::OnceLock<crate::application_sources::SelectedApplication>,
    _read_reservations: Vec<crate::admission::Reservation>,
}
impl Generation {
    pub(crate) fn clone_application_selection(
        &self,
    ) -> std::sync::OnceLock<crate::application_sources::SelectedApplication> {
        match self.application_selection.get() {
            Some(selection) => std::sync::OnceLock::from(selection.clone()),
            None => std::sync::OnceLock::new(),
        }
    }

    /// Share persistent document roots and fixed point-history owners without
    /// retaining resident staging, audit history, or prior secondary/text indexes.
    pub(crate) fn lease_view(&self) -> Self {
        let mut state = crate::snapshot_codec::metadata(&self.state);
        state.collections = self.state.collections.clone();
        state.history_archives = self.state.history_archives.clone();
        Self {
            receipts: self.receipts.clone(),
            backup_bindings: self.backup_bindings.clone(),
            terminals: self.terminals.clone(),
            target_resolutions: self.target_resolutions.clone(),
            state,
            indexes: Arc::new(QueryIndexes::default()),
            snapshot_accounting: SnapshotAccounting::default(),
            application_selection: self.clone_application_selection(),
            _read_reservations: Vec::new(),
        }
    }

    pub(crate) fn read_view(
        &self,
        collections: BTreeMap<String, CollectionState>,
        reservations: Vec<crate::admission::Reservation>,
    ) -> Self {
        let mut state = self.state.clone();
        state.collections = collections;
        Self {
            receipts: self.receipts.clone(),
            backup_bindings: self.backup_bindings.clone(),
            terminals: self.terminals.clone(),
            target_resolutions: self.target_resolutions.clone(),
            state,
            indexes: self.indexes.clone(),
            snapshot_accounting: self.snapshot_accounting.clone(),
            application_selection: self.clone_application_selection(),
            _read_reservations: reservations,
        }
    }
    pub(crate) fn snapshot_bytes(&self) -> Result<usize> {
        self.snapshot_accounting.bytes(&self.state)
    }
}

/// A private candidate does not become visible until its response and custody
/// transition have crossed the adapter's durable publication barrier.
struct PreparedCommand {
    // None is the distinct permanently frozen result, not a new candidate.
    generation: Option<Arc<Generation>>,
    outcome: Result<WriteReceipt>,
    changed: ChangedIds,
}

/// Terminal state prepared for the current command, before budget acceptance.
struct PreparedTerminals<'a> {
    applied: &'a crate::staged_terminal::AppliedIdentity,
    pending: &'a crate::staged_terminal::Pending,
    owner: &'a crate::staged_terminal::View,
    scope: &'a ApplyScope,
}

/// Validate configuration with the same empty genesis metadata and snapshot
/// quota as the runtime constructor, without building indexes or publishing a
/// serving Generation. Inputs are checked before cloning their bounded policy
/// metadata; no existing TenantState, document body, or governor is copied.
pub fn validate_genesis_inputs(
    tenant: &str,
    incarnation: &str,
    policy: &Policy,
    limits: &Limits,
) -> Result<()> {
    validate_name(tenant)?;
    validate_name(incarnation)?;
    validate_limits(limits)?;
    validate_policy(policy, limits)?;
    let state = genesis_metadata(tenant, incarnation, policy.clone(), limits.clone())?;
    genesis_snapshot_accounting(&state).map(|_| ())
}

fn genesis_metadata(
    tenant: &str,
    incarnation: &str,
    policy: Policy,
    limits: Limits,
) -> Result<TenantState> {
    validate_name(tenant)?;
    validate_name(incarnation)?;
    validate_limits(&limits)?;
    validate_policy(&policy, &limits)?;
    let state = TenantState {
        tenant: tenant.to_owned(),
        incarnation: incarnation.to_owned(),
        revision: 0,
        revision_base: 0,
        policy_epoch: 0,
        schema_epoch: 0,
        suspended: false,
        retired: false,
        pending_restore: None,
        restored_from: None,
        restore_lineage: Vec::new(),
        lifecycle_control: None,
        target_lifecycle: Default::default(),
        recovery_control: Default::default(),
        document_count: 0,
        logical_bytes: 0,
        policy,
        limits,
        collections: BTreeMap::new(),
        mutation_receipt_head: MutationReceiptHead::empty(tenant, incarnation)?,
        backup_binding_head: BackupBindingHead::empty(incarnation)?,
        staged_transactions: imbl::OrdMap::new(),
        active_staged_transactions: BTreeSet::new(),
        permanent_staged_bytes: 0,
        reserved_staged_terminal_bytes: 0,
        staged_terminal_head: StagedTerminalHead::empty(tenant, incarnation)?,
        target_resolution_head: TargetResolutionPrefixHead::empty(tenant, incarnation)?,
        target_completion_head: None,
        change_feed: ChangeFeedState::empty(),
        history_archives: imbl::OrdMap::new(),
        history_archive_bytes: 0,
        schema_activations: imbl::OrdMap::new(),
        schema_activation_bytes: 0,
        retirements: imbl::OrdMap::new(),
        retirement_bytes: 0,
        audit_retention: AuditRetentionState::empty(uuid::Uuid::from_bytes(
            Sha256::digest(
                serde_json::to_vec(&("kasumi.audit-stream.v1", &tenant, &incarnation))
                    .expect("identity serializes"),
            )[..16]
                .try_into()
                .expect("digest width"),
        )),
        audits: imbl::Vector::new(),
    };
    Ok(state)
}

fn genesis_snapshot_accounting(state: &TenantState) -> Result<SnapshotAccounting> {
    let accounting = SnapshotAccounting::rebuild(state)?;
    if !accounting.fits(state)? {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "bootstrap exceeds snapshot byte budget",
        ));
    }
    Ok(accounting)
}

/// Only ordered consensus application may publish generations.
pub struct TenantEngine {
    current: ArcSwapOption<Generation>,
    #[cfg(any(test, feature = "test-utils"))]
    sealed_restore_observation: Mutex<Option<Option<kasumi_types::PendingRestore>>>,
    pub(crate) leases: lease_retention::LeaseManager,
    apply_lock: Mutex<()>,
    tenant: String,
    incarnation: String,
    revision_base: u64,
    restoration_identity: String,
    bootstrap_sha256: std::sync::OnceLock<String>,
    application_sources: std::sync::OnceLock<crate::application_sources::SourceRootsRef>,
    access: std::sync::OnceLock<kasumi_store::StorageAccess>,
    pub(crate) snapshot_store: std::sync::OnceLock<Arc<kasumi_store::TenantStore>>,
    pub(crate) audit_maintenance:
        Mutex<Option<Arc<crate::audit_maintenance::NodeAuditMaintenance>>>,
}

enum ApplyScope {
    Committed,
    #[cfg(any(test, feature = "test-utils"))]
    Fixture(Arc<kasumi_store::ScratchDisk>),
}
impl ApplyScope {
    fn stage_terminals(
        &self,
        pending: crate::staged_terminal::Pending,
        _previous_state: &TenantState,
    ) -> std::result::Result<crate::staged_terminal::View, kasumi_store::ScratchOperationFailure>
    {
        match self {
            Self::Committed => pending.stage().map_err(Into::into),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(disk) => pending.stage_fixture(disk, _previous_state),
        }
    }
}

/// Raft stores exact first-release command bytes. A decoded predecessor shape
/// must not acquire current defaults or discard fields during replay.
fn decode_canonical_json<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> anyhow::Result<T> {
    struct ExactJson<'a>(&'a [u8]);
    impl std::io::Write for ExactJson<'_> {
        fn write(&mut self, encoded: &[u8]) -> std::io::Result<usize> {
            if !self.0.starts_with(encoded) {
                return Err(std::io::Error::other("noncanonical committed command"));
            }
            self.0 = &self.0[encoded.len()..];
            Ok(encoded.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let command: T = serde_json::from_slice(bytes)?;
    let mut exact = ExactJson(bytes);
    serde_json::to_writer(&mut exact, &command)?;
    anyhow::ensure!(exact.0.is_empty(), "noncanonical committed command");
    Ok(command)
}

fn decode_committed_command(bytes: &[u8]) -> anyhow::Result<Command> {
    decode_canonical_json(bytes)
}

impl kasumi_raft::StateMachineBackend for TenantEngine {
    fn close_application(&self) {
        self.seal();
    }
    fn apply_with_publisher(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        input: kasumi_raft::AppliedInput<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        let bytes = match input {
            kasumi_raft::AppliedInput::Metadata => {
                return self
                    .publish_metadata(position, publisher)
                    .map_err(Into::into);
            }
            kasumi_raft::AppliedInput::Command(bytes) => bytes,
        };
        let input = ByteBoundCommand::check(position, bytes)?;
        let position = input.position();
        let bytes = input.bytes();
        if bytes.starts_with(recovery::PREFIX) {
            return self
                .apply_recovery(position, bytes, publisher)
                .map_err(Into::into);
        }
        if bytes.starts_with(target::PREFIX) {
            return self
                .apply_target(position, bytes, publisher)
                .map_err(Into::into);
        }
        if bytes.starts_with(tenant_audit::PREFIX) {
            return self
                .apply_audit_prune(position, bytes, publisher)
                .map_err(Into::into);
        }
        ordered_command::apply_ordinary(self, input, publisher)
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<kasumi_raft::CapturedSnapshot, kasumi_store::ScratchOperationFailure>
    {
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let generation = self.generation()?;
            let retirement = custody_snapshot::retired(&generation.state)?;
            let store = self
                .snapshot_store
                .get()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("snapshot storage not installed"))?;
            let checkpoint_generation = generation.clone();
            Ok(
                kasumi_raft::CapturedSnapshot::new(retirement, move |writer| {
                    snapshot_bundle::write(&generation, &store, writer).map_err(Into::into)
                })
                .with_checkpoint_writes(move |context| {
                    let mut writes = checkpoint_generation.receipts.checkpoint_writes(
                        &checkpoint_generation.state,
                        &context.checkpoint_sha256()?,
                    )?;
                    writes.extend(checkpoint_generation.backup_bindings.checkpoint_writes(
                        &checkpoint_generation.state,
                        &context.checkpoint_sha256()?,
                    )?);
                    writes.extend(checkpoint_generation.terminals.checkpoint_writes(
                        &checkpoint_generation.state,
                        &context.checkpoint_sha256()?,
                    )?);
                    writes.extend(checkpoint_generation.target_resolutions.checkpoint_writes(
                        &checkpoint_generation.state,
                        &context.checkpoint_sha256()?,
                    )?);
                    Ok(writes)
                }),
            )
        })
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<kasumi_raft::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        let prior = kasumi_store::ScratchOperationFailure::ordinary(|| {
            CapturedValidation::capture(self).map_err(Into::into)
        })?;
        let generation = snapshot_bundle::read(self, &prior.baseline(), bytes, None)?;
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            custody_snapshot::retired(&generation.state).map_err(Into::into)
        })
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        let (apply, selection) = kasumi_store::ScratchOperationFailure::ordinary(|| {
            let apply = ApplyOwner::lock(self, || anyhow::anyhow!("tenant apply lock poisoned"))?;
            let selection = self
                .application_sources
                .get()
                .map(|sources| {
                    sources
                        .prepare_restore(context, std::mem::size_of::<PreparedTenantRestore<'_>>())
                })
                .transpose()?;
            Ok((apply, selection))
        })?;
        let mut generation =
            snapshot_bundle::read(self, &ValidationBaseline::from_apply(&apply), bytes, None)?;
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let expected_revision = self
                .revision_base
                .checked_add(context.meta.last_log_id.map_or(0, |id| id.index))
                .ok_or_else(|| anyhow::anyhow!("snapshot applied revision overflow"))?;
            anyhow::ensure!(
                generation.state.revision == expected_revision,
                "snapshot logical and Raft applied positions differ"
            );
            let store = self
                .snapshot_store
                .get()
                .ok_or_else(|| anyhow::anyhow!("snapshot storage not installed"))?;
            let receipt_installation = generation.receipts.prepare_install(
                store,
                &generation.state,
                &context.checkpoint_sha256()?,
                context.mode == kasumi_raft::SnapshotRestoreMode::Reopen,
            )?;
            generation.receipts = receipt_installation.view.clone();
            let binding_installation = generation.backup_bindings.prepare_install(
                store,
                &generation.state,
                &context.checkpoint_sha256()?,
                context.mode == kasumi_raft::SnapshotRestoreMode::Reopen,
            )?;
            generation.backup_bindings = binding_installation.view.clone();
            let installation = generation.terminals.prepare_install(
                store,
                &generation.state,
                &context.checkpoint_sha256()?,
                context.mode == kasumi_raft::SnapshotRestoreMode::Reopen,
            )?;
            generation.terminals = installation.view.clone();
            let target_installation = generation.target_resolutions.prepare_install(
                store,
                &generation.state,
                &context.checkpoint_sha256()?,
                context.mode == kasumi_raft::SnapshotRestoreMode::Reopen,
            )?;
            generation.target_resolutions = target_installation.view.clone();
            let mut writes = receipt_installation.writes().to_vec();
            writes.extend_from_slice(binding_installation.writes());
            writes.extend_from_slice(installation.writes());
            writes.extend_from_slice(target_installation.writes());
            let retirement = custody_snapshot::retired(&generation.state)?;
            #[cfg(test)]
            let retirement_probe =
                validation_baseline_tests::restore_retirement_probe(self, &generation);
            Ok(Box::new(PreparedTenantRestore {
                engine: self,
                generation,
                selection,
                receipt_installation,
                binding_installation,
                installation,
                target_installation,
                writes,
                retirement,
                #[cfg(test)]
                _retirement_probe: retirement_probe,
                _apply: apply,
            })
                as Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>)
        })
    }
}

struct PreparedTenantRestore<'a> {
    engine: &'a TenantEngine,
    generation: Generation,
    selection: Option<crate::application_sources::RestoreSelection>,
    receipt_installation: crate::mutation_receipt::Installation,
    binding_installation: crate::backup_binding::Installation,
    installation: crate::staged_terminal::Installation,
    target_installation: crate::target_resolution::Installation,
    writes: Vec<kasumi_store::WriteOp>,
    retirement: Option<kasumi_raft::RetiredSnapshotState>,
    #[cfg(test)]
    _retirement_probe: Option<validation_baseline_tests::RestoreRetirementProbe<'a>>,
    _apply: ApplyOwner<'a>,
}
impl kasumi_raft::PreparedStateMachineRestore for PreparedTenantRestore<'_> {
    fn retirement(&self) -> Option<kasumi_raft::RetiredSnapshotState> {
        self.retirement.clone()
    }
    fn application_replacements(&self) -> Vec<kasumi_store::NamespaceReplacement<'_>> {
        let mut replacements = self.receipt_installation.replacements();
        replacements.extend(self.binding_installation.replacements());
        replacements.extend(self.installation.replacements());
        replacements.extend(self.target_installation.replacements());
        replacements
    }
    fn application_writes(&self) -> &[kasumi_store::WriteOp] {
        &self.writes
    }
    fn publish(self: Box<Self>) -> anyhow::Result<()> {
        let Self {
            engine,
            generation,
            selection,
            // Keep the owner in the partially moved box. On an error, moved
            // locals retire first, then installations/writes, then the owner.
            ..
        } = *self;
        engine
            .snapshot_store
            .get()
            .ok_or_else(|| anyhow::anyhow!("snapshot storage not installed"))?
            .check_access()?;
        if let Some(selection) = selection {
            let selected = selection.capture(generation.state.retired)?;
            generation
                .application_selection
                .set(selected)
                .map_err(|_| anyhow::anyhow!("restored application selection already installed"))?;
        }
        engine.leases.replace(&engine.current, Arc::new(generation));
        Ok(())
    }
}

impl TenantEngine {
    pub(crate) fn install_application_sources(
        &self,
        sources: crate::application_sources::SourceRootsRef,
        image: &kasumi_store::SnapshotImage,
    ) -> anyhow::Result<()> {
        // Source-installed production ordinary commands require the actual
        // paired completion binding before bootstrap can acquire a source.
        sources.completion()?;
        let apply = ApplyOwner::lock(self, || anyhow::anyhow!("tenant apply lock poisoned"))?;
        anyhow::ensure!(
            self.application_sources.get().is_none(),
            "application source already installed"
        );
        let generation = apply.current();
        anyhow::ensure!(
            generation.state.revision == generation.state.revision_base,
            "application source bootstrap must precede replay"
        );
        anyhow::ensure!(
            self.bootstrap_sha256.get().map(String::as_str) == Some(image.sha256()),
            "application source differs from authenticated bootstrap image"
        );
        let selection = sources.prepare_initial()?.capture(
            kasumi_raft::ApplicationBoundaryRef::Bootstrap(image),
            generation.state.retired,
        )?;
        generation
            .application_selection
            .set(selection)
            .map_err(|_| anyhow::anyhow!("bootstrap selection already installed"))?;
        self.application_sources
            .set(sources)
            .map_err(|_| anyhow::anyhow!("application source already installed"))?;
        Ok(())
    }
    pub(crate) fn seal_application_source_consumers(&self) {
        if let Some(sources) = self.application_sources.get() {
            kasumi_raft::ApplicationSourceCustody::seal_consumers(sources.as_ref());
        }
    }
    /// Preparation, response encoding, and immutable row staging precede the
    /// durable callback. The current Generation changes only after it succeeds.
    fn publish_prepared_generation(
        &self,
        accepted: AcceptedGeneration<'_>,
        response: kasumi_raft::AppliedResponse,
        position: Option<&kasumi_raft::AppliedEntryContext>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> anyhow::Result<()> {
        accepted.require_publication(self, position)?;
        let candidate = accepted.candidate();
        let sources = self.application_sources.get();
        anyhow::ensure!(
            sources.is_none() || position.is_some(),
            "runtime publication lacks actual applied position"
        );
        if let Some(sources) = sources {
            let expectation = sources.publication_expectation(
                position.expect("checked applied position"),
                &[],
                &response,
            )?;
            let mut prepared = sources.publication_preparation();
            let receipt = publisher.commit_with_selection(
                response,
                &[],
                &mut prepared,
                expectation.challenge()?,
            )?;
            let selection = prepared
                .finish_publication(&expectation, receipt)?
                .capture(
                    kasumi_raft::ApplicationBoundaryRef::Entry(
                        position.expect("checked applied position"),
                    ),
                    candidate.state.retired,
                )?;
            candidate
                .application_selection
                .set(selection)
                .map_err(|_| {
                    anyhow::anyhow!("candidate application selection already installed")
                })?;
        } else {
            publisher.commit(response, &[])?;
        }
        accepted.publish();
        Ok(())
    }

    fn publish_metadata(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> anyhow::Result<()> {
        let apply = ApplyOwner::lock(self, || anyhow::anyhow!("tenant apply lock poisoned"))?;
        let revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .ok_or_else(|| anyhow::anyhow!("consensus metadata revision overflow"))?;
        let previous = apply.current();
        let response = kasumi_raft::AppliedResponse::application(Vec::new());
        // Covered replay still crosses the adapter's publication barrier.
        if revision <= previous.state.revision {
            publisher.commit(response, &[])?;
            return Ok(());
        }
        let mut state = previous.state.clone();
        state.revision = revision;
        let candidate = Arc::new(Generation {
            state,
            receipts: previous.receipts.clone(),
            backup_bindings: previous.backup_bindings.clone(),
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            indexes: previous.indexes.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            application_selection: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        });
        self.publish_prepared_generation(
            apply.accept(candidate, ChangedIds::new())?,
            response,
            Some(position),
            publisher,
        )
    }

    fn publish_generation(&self, next: Option<Arc<Generation>>) {
        self.leases.publish(&self.current, next);
    }

    pub(crate) fn check_operation_access(&self, operation: &Operation) -> Result<()> {
        let generation = self.generation()?;
        self.check_operation_access_from(&generation.state, operation)
    }

    // Both service preflight and ordered apply evaluate one exact prior state.
    // The latter already validated its ApplyOwner; do not acquire a public
    // generation/history owner while that serialization guard is held.
    fn check_operation_access_from(
        &self,
        state: &TenantState,
        operation: &Operation,
    ) -> Result<()> {
        // The access grant may expire after ApplyOwner acquisition. Keep the
        // current access/presence check at this entry without cloning an owner.
        self.require_current_access()?;
        if state
            .target_lifecycle
            .get(&state.incarnation)
            .is_some_and(|target| target.activation.is_none())
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "native target activation must commit before tenant commands",
            ));
        }
        if let Some(access) = self.access.get() {
            access
                .check()
                .map_err(|_| Error::new(ErrorCode::Sealed, "independent access grant expired"))?;
            if access.check_serving().is_err() {
                self.require_current_access()?;
                if state.target_lifecycle.contains_key(&state.incarnation)
                    || !state.suspended
                    || !matches!(operation, Operation::MaintenanceAudit(event) if event.action == "restore" && event.outcome == "completed")
                {
                    return Err(Error::new(
                        ErrorCode::Forbidden,
                        "restore preparation permits only exact restore completion",
                    ));
                }
            }
        }
        Ok(())
    }
    /// Installed before Raft replay or native publication. Pure arithmetic
    /// engine fixtures have no store; a serving database retains this exact
    /// capability through generation reads and ordered state publication.
    pub(crate) fn install_storage_access(
        &self,
        store: &Arc<kasumi_store::TenantStore>,
    ) -> Result<()> {
        store
            .check_access()
            .map_err(|_| Error::new(ErrorCode::Sealed, "storage serving authority unavailable"))?;
        let access = store.storage_access().clone();
        // A missing S3 installation must fail before replay, never switch a
        // committed pruning transition to a filesystem-only policy.
        if !access.purpose().is_local_fixture() || store.durable_directory().is_ok() {
            store.tenant_audit_archive().map_err(|_| {
                Error::new(ErrorCode::Unavailable, "tenant audit placement unavailable")
            })?;
        }
        if let Some(gate) = access.serving_gate() {
            let generation = self.generation()?;
            if gate.identity().tenant != generation.state.tenant
                || gate.identity().incarnation.to_string() != generation.state.incarnation
                || gate
                    .recovery_checkpoint()
                    .map_err(|_| Error::new(ErrorCode::Sealed, "serving grant expired"))?
                    != generation.state.restored_from
            {
                self.seal();
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "serving authority incarnation or exact restored checkpoint differs",
                ));
            }
        }
        self.snapshot_store.set(store.clone()).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "engine storage owner already installed",
            )
        })?;
        self.access.set(access).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "engine storage authority already installed",
            )
        })?;
        self.install_terminal_bootstrap(store)?;
        if let Err(error) = self.require_current_access() {
            self.seal();
            return Err(error);
        }
        Ok(())
    }
    fn install_terminal_bootstrap(&self, store: &Arc<kasumi_store::TenantStore>) -> Result<()> {
        let apply = ApplyOwner::lock_validation(self)?;
        let previous = apply.current();
        if previous.state.revision != previous.state.revision_base {
            return Err(Error::new(
                ErrorCode::Conflict,
                "terminal bootstrap ownership must precede replay",
            ));
        }
        #[cfg(any(test, feature = "test-utils"))]
        if self.bootstrap_sha256.get().is_none()
            && store.storage_access().purpose().is_local_fixture()
        {
            let image = Self::logical_snapshot_of(previous, store.scratch_disk())?;
            self.bootstrap_sha256
                .set(image.sha256().into())
                .map_err(|_| {
                    Error::new(ErrorCode::Corruption, "duplicate fixture bootstrap digest")
                })?;
        }
        let digest = self.bootstrap_sha256.get().ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "authenticated bootstrap image identity missing",
            )
        })?;
        let checkpoint = staged_digest(&("kasumi.application-point-bootstrap.v1", digest))?.0;
        let reopen = crate::staged_terminal::View::checkpoint_exists(store, &checkpoint)
            .map_err(terminal_error)?;
        if crate::target_resolution::View::checkpoint_exists(store, &checkpoint)
            .map_err(terminal_error)?
            != reopen
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "joint terminal bootstrap catalogs differ",
            ));
        }
        let binding_catalog = crate::backup_binding::View::checkpoint_exists(store, &checkpoint)
            .map_err(terminal_error)?;
        if binding_catalog != (reopen && previous.state.tenant == crate::control::CONTROL_TENANT) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "joint backup binding bootstrap catalog differs",
            ));
        }
        if crate::mutation_receipt::View::checkpoint_exists(store, &checkpoint)
            .map_err(terminal_error)?
            != reopen
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "joint receipt bootstrap catalog differs",
            ));
        }
        let receipt_installation = previous
            .receipts
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let binding_installation = previous
            .backup_bindings
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let installation = previous
            .terminals
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let target_installation = previous
            .target_resolutions
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let mut replacements = receipt_installation.replacements();
        replacements.extend(binding_installation.replacements());
        replacements.extend(installation.replacements());
        replacements.extend(target_installation.replacements());
        let mut writes = receipt_installation.writes().to_vec();
        writes.extend_from_slice(binding_installation.writes());
        writes.extend_from_slice(installation.writes());
        writes.extend_from_slice(target_installation.writes());
        store
            .replace_namespaces(&replacements, &writes)
            .map_err(terminal_error)?;
        drop(replacements);
        self.publish_generation(Some(Arc::new(Generation {
            state: previous.state.clone(),
            receipts: receipt_installation.view,
            backup_bindings: binding_installation.view,
            terminals: installation.view,
            target_resolutions: target_installation.view,
            indexes: previous.indexes.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            application_selection: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        })));
        Ok(())
    }
    pub(crate) fn retirement_replay_state(
        &self,
        command: &Command,
    ) -> Result<kasumi_raft::RetirementReplayState> {
        if !matches!(&command.operation, Operation::RetireSource(_)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retirement replay state requires retirement",
            ));
        }
        let generation = self.generation()?;
        Self::retirement_replay_from(&generation, command)
    }

    fn retirement_replay_from(
        generation: &Generation,
        command: &Command,
    ) -> Result<kasumi_raft::RetirementReplayState> {
        let Operation::RetireSource(prepared) = &command.operation else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retirement replay state requires retirement",
            ));
        };
        let state = &generation.state;
        let existing_identity =
            retirement::lookup(state, &command.context, &prepared.request.reference()?)?.cloned();
        Ok(kasumi_raft::RetirementReplayState {
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            previous_revision: state.revision,
            revision_base: state.revision_base,
            policy_epoch: state.policy_epoch,
            administrators: state
                .policy
                .grants
                .iter()
                .filter(|grant| {
                    grant.collection.is_none() && grant.actions.contains(&Action::Admin)
                })
                .map(|grant| grant.principal.clone())
                .collect(),
            suspended: state.suspended,
            retired: state.retired,
            pending_restore: state.pending_restore.is_some(),
            existing_identity,
            retirement_bytes: state.retirement_bytes,
            max_retirement_bytes: state.limits.max_retirement_bytes,
            audit_hot_bytes: state.audit_retention.hot_bytes,
            max_audit_hot_bytes: state
                .limits
                .audit_retention
                .hot_bytes
                .checked_sub(crate::accounting::target_audit_reserve(state))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::Corruption,
                        "retained target audit reserve exceeds budget",
                    )
                })?,
            snapshot_bytes: generation.snapshot_bytes()? as u64,
            max_snapshot_bytes: state.limits.max_snapshot_bytes,
            staged_outcome_headroom: crate::accounting::snapshot_headroom(state)?,
        })
    }
    /// A tenant bootstrap is trusted control-plane input, identical on all replicas.
    pub fn new(
        tenant: String,
        incarnation: String,
        policy: Policy,
        limits: Limits,
    ) -> Result<Self> {
        Self::new_genesis(tenant, incarnation, policy, limits, None)
    }
    pub(crate) fn new_genesis(
        tenant: String,
        incarnation: String,
        policy: Policy,
        limits: Limits,
        control: Option<&crate::ControlGenesis>,
    ) -> Result<Self> {
        let mut state = genesis_metadata(&tenant, &incarnation, policy, limits)?;
        if let Some(control) = control {
            control.seed(&mut state)?;
            validate_metadata_budget(&state.collections, &state.limits)?;
            lifecycle::validate(&state)?;
        }
        let revision_base = state.revision_base;
        let indexes = Arc::new(crate::index_source::build(&state)?);
        let snapshot_accounting = genesis_snapshot_accounting(&state)?;
        let restoration_identity =
            staged_digest(&(&state.restored_from, &state.restore_lineage))?.0;
        Ok(Self {
            restoration_identity,
            bootstrap_sha256: std::sync::OnceLock::new(),
            application_sources: std::sync::OnceLock::new(),
            access: std::sync::OnceLock::new(),
            snapshot_store: std::sync::OnceLock::new(),
            audit_maintenance: Mutex::new(None),
            leases: lease_retention::LeaseManager::default(),
            current: ArcSwapOption::from_pointee(Generation {
                target_resolutions: crate::target_resolution::View::empty(
                    &state.tenant,
                    &state.incarnation,
                )
                .map_err(terminal_error)?,
                receipts: crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)
                    .map_err(terminal_error)?,
                backup_bindings: crate::backup_binding::View::empty(&state.incarnation)
                    .map_err(terminal_error)?,
                terminals: crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)
                    .map_err(terminal_error)?,
                state,
                indexes,
                snapshot_accounting,
                application_selection: std::sync::OnceLock::new(),
                _read_reservations: vec![],
            }),
            apply_lock: Mutex::new(()),
            #[cfg(any(test, feature = "test-utils"))]
            sealed_restore_observation: Mutex::new(None),
            tenant,
            incarnation,
            revision_base,
        })
    }

    pub(crate) fn from_bootstrap(
        expected_tenant: &str,
        bytes: &kasumi_store::SnapshotImage,
    ) -> std::result::Result<Self, SnapshotFailure> {
        let decoded = crate::snapshot_codec::read(bytes.disk(), &mut bytes.reader())
            .map_err(SnapshotFailure::from)?;
        let engine = Self::from_bootstrap_state(
            expected_tenant,
            decoded.state,
            decoded.receipts,
            decoded.backup_bindings,
            decoded.terminals,
            decoded.target_resolutions,
        )?;
        engine
            .bootstrap_sha256
            .set(bytes.sha256().into())
            .map_err(|_| Error::new(ErrorCode::Corruption, "duplicate bootstrap digest"))?;
        Ok(engine)
    }

    fn from_bootstrap_state(
        expected_tenant: &str,
        state: TenantState,
        receipts: crate::mutation_receipt::View,
        backup_bindings: crate::backup_binding::View,
        terminals: crate::staged_terminal::View,
        target_resolutions: crate::target_resolution::View,
    ) -> Result<Self> {
        if state.tenant != expected_tenant || state.revision != state.revision_base {
            return Err(Error::new(
                ErrorCode::Corruption,
                "tenant bootstrap identity or revision invalid",
            ));
        }
        let uninitialized = UninitializedEngine::new(&state)?;
        let engine = uninitialized.engine();
        let generation = engine.prepare_state(
            &uninitialized.baseline(),
            state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
        )?;
        Ok(uninitialized.finish(generation))
    }

    #[cfg(test)]
    pub(crate) fn restored_bootstrap(
        bytes: &kasumi_store::SnapshotImage,
        expected_tenant: &str,
        incarnation: String,
        checkpoint: FullBackupCheckpoint,
        target_origin: Option<TargetOrigin>,
    ) -> std::result::Result<kasumi_store::SnapshotImage, SnapshotFailure> {
        let crate::snapshot_codec::Decoded {
            mut state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
            ..
        } = crate::snapshot_codec::read(bytes.disk(), &mut bytes.reader())
            .map_err(SnapshotFailure::from)?;
        if state.tenant != expected_tenant {
            return Err(Error::new(ErrorCode::Forbidden, "backup tenant mismatch").into());
        }
        Self::verify_decoded_logical_state(
            &UninitializedEngine::new(&state)?,
            &state,
            &receipts,
            &backup_bindings,
            &terminals,
            &target_resolutions,
        )?;
        Self::rebind_restored_state(&mut state, incarnation, checkpoint, target_origin)?;
        kasumi_store::SnapshotImage::capture(
            bytes.disk(),
            crate::target_resolution::snapshot_limit(&state)
                .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))?,
            |writer| {
                crate::snapshot_codec::write(
                    &state,
                    &receipts,
                    &backup_bindings,
                    &terminals,
                    &target_resolutions,
                    writer,
                )
            },
        )
        .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()).into())
    }

    fn rebind_restored_state(
        state: &mut TenantState,
        incarnation: String,
        checkpoint: FullBackupCheckpoint,
        target_origin: Option<TargetOrigin>,
    ) -> Result<()> {
        validate_name(&incarnation)?;
        checkpoint.validate()?;
        if checkpoint.tenant != state.tenant
            || checkpoint.source_incarnation != state.incarnation
            || checkpoint.revision != state.revision
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "restored origin differs from verified snapshot",
            ));
        }
        state.restore_lineage.push(RestoreLineageLink {
            checkpoint: checkpoint.clone(),
            target_incarnation: incarnation.clone(),
        });
        state.restored_from = Some(checkpoint.clone());
        state.incarnation = incarnation;
        state.target_completion_head = None;
        if let Some(origin) = target_origin {
            origin.validate()?;
            if origin
                .materialization
                .request
                .target_incarnation
                .to_string()
                != state.incarnation
                || origin.materialization.request.checkpoint != checkpoint
                || state.target_lifecycle.contains_key(&state.incarnation)
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "target genesis origin differs or incarnation reused",
                ));
            }
            state.target_completion_head = Some(TargetCompletionHead::empty(
                &origin,
                state.limits.max_target_resolution_bytes,
            )?);
            state.target_lifecycle.insert(
                state.incarnation.clone(),
                TargetExecutionState {
                    origin,
                    completion: None,
                    activation: None,
                },
            );
        }
        state.pending_restore = Some(PendingRestore {
            backup_id: checkpoint.backup_id.to_string(),
            source_revision: state.revision,
        });
        state.suspended = true;
        state.retired = false;
        state.policy_epoch = state
            .policy_epoch
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "policy epoch exhausted"))?;
        state.revision_base = state
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "revision exhausted"))?;
        state.revision = state.revision_base;
        if !SnapshotAccounting::rebuild(state)?.fits(state)? {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "restore metadata exceeds snapshot quota; increase the source quota before making this backup",
            ));
        }
        Ok(())
    }

    pub(crate) fn materialize_verified_restore(
        source: snapshot_validation::ValidatedApplicationSnapshot,
        expected_tenant: &str,
        incarnation: String,
        checkpoint: FullBackupCheckpoint,
        target_origin: Option<TargetOrigin>,
        handoff_workspace: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<(kasumi_store::SnapshotImage, Self), SnapshotFailure> {
        if source.header().tenant != expected_tenant {
            return Err(Error::new(ErrorCode::Forbidden, "backup tenant mismatch").into());
        }
        use crate::backup_verify::VerificationPhase;
        let phase = VerificationPhase::start("restore.release_validation_indexes", None);
        let image = source.into_image();
        phase.complete();
        let phase = VerificationPhase::start("restore.materialization_admission", None);
        // Both encrypted point-table caches are now destroyed. Reserve the
        // actual target allocation before decoding, under the same owned job.
        handoff_workspace()?;
        phase.complete();
        let phase = VerificationPhase::start("restore.snapshot_decode", None);
        let scratch_disk = image.disk().clone();
        let crate::snapshot_codec::Decoded {
            mut state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
            ..
        } = crate::snapshot_codec::read(image.disk(), &mut image.reader())
            .map_err(SnapshotFailure::from)?;
        drop(image);
        phase.complete();
        let phase = VerificationPhase::start("restore.rebind", None);
        Self::rebind_restored_state(&mut state, incarnation, checkpoint, target_origin)?;
        phase.complete();
        let phase = VerificationPhase::start("restore.prepare_generation", None);
        let engine = Self::from_bootstrap_state(
            expected_tenant,
            state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
        )?;
        phase.complete();
        let phase = VerificationPhase::start("restore.genesis_snapshot", None);
        let image = engine.logical_snapshot(&scratch_disk)?;
        engine
            .bootstrap_sha256
            .set(image.sha256().into())
            .map_err(|_| Error::new(ErrorCode::Corruption, "duplicate target bootstrap digest"))?;
        phase.complete();
        Ok((image, engine))
    }

    /// Inspect only the committed restore marker in native recovery tests.
    /// This cannot open storage, expose a generation, renew a serving lease, or
    /// authorize an operation. Normal generation() remains access-fenced.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture_pending_restore(&self) -> Result<Option<kasumi_types::PendingRestore>> {
        self.current
            .load()
            .as_ref()
            .map(|generation| generation.state.pending_restore.clone())
            .ok_or_else(|| Error::new(ErrorCode::Sealed, "fixture engine state is closed"))
    }

    pub fn generation(&self) -> Result<Arc<Generation>> {
        #[cfg(test)]
        validation_baseline_tests::observe_public_generation()?;
        let generation = self.current_generation()?;
        if let Some(selection) = generation.application_selection.get() {
            selection
                .retain_public_history()
                .map_err(|error| Error::new(ErrorCode::ResourceExhausted, error.to_string()))?;
        }
        self.check_current_access()?;
        Ok(generation)
    }

    // Private apply acquisition bypasses no access checks and does not use a
    // future public history-escape API. Only ApplyOwner lends this owner.
    fn current_generation(&self) -> Result<Arc<Generation>> {
        self.check_current_access()?;
        self.current
            .load_full()
            .ok_or_else(|| Error::new(ErrorCode::Sealed, "tenant requires authorized recovery"))
    }

    fn require_current_access(&self) -> Result<()> {
        self.check_current_access()?;
        if self.current.load().is_none() {
            return Err(Error::new(
                ErrorCode::Sealed,
                "tenant requires authorized recovery",
            ));
        }
        Ok(())
    }

    fn check_current_access(&self) -> Result<()> {
        if let Some(store) = self.snapshot_store.get() {
            store.check_access().map_err(|_| {
                Error::new(
                    ErrorCode::Sealed,
                    "tenant key authorization expired; recovery required",
                )
            })?;
        }
        if let Some(access) = self.access.get() {
            access.check().map_err(|_| {
                Error::new(
                    ErrorCode::Sealed,
                    "independent serving authority unavailable",
                )
            })?;
        }
        Ok(())
    }

    /// A full logical backup can be captured at any committed revision. It is
    /// validated as a snapshot; only the later restored genesis must begin at
    /// its revision base.
    #[cfg(test)]
    pub(crate) fn verify_logical_snapshot(
        _bytes: &kasumi_store::SnapshotImage,
        state: &TenantState,
    ) -> std::result::Result<(), SnapshotFailure> {
        let uninitialized = UninitializedEngine::new(state)?;
        let decoded = crate::snapshot_codec::read(_bytes.disk(), &mut _bytes.reader())
            .map_err(SnapshotFailure::from)?;
        Self::verify_decoded_logical_state(
            &uninitialized,
            state,
            &decoded.receipts,
            &decoded.backup_bindings,
            &decoded.terminals,
            &decoded.target_resolutions,
        )
        .map_err(Into::into)
    }

    #[cfg(test)]
    fn verify_decoded_logical_state(
        uninitialized: &UninitializedEngine,
        state: &TenantState,
        receipts: &crate::mutation_receipt::View,
        backup_bindings: &crate::backup_binding::View,
        terminals: &crate::staged_terminal::View,
        target_resolutions: &crate::target_resolution::View,
    ) -> Result<()> {
        let verifier = uninitialized.engine();
        // These views retain the already authenticated decoded owners. Full
        // state validation needs no second decoding or duplicate scratch core.
        verifier.prepare_state(
            &uninitialized.baseline(),
            state.clone(),
            receipts.clone(),
            backup_bindings.clone(),
            terminals.clone(),
            target_resolutions.clone(),
        )?;
        Ok(())
    }

    /// Metadata captured from the actual committed generation under the seal
    /// apply fence. No storage, serving lease or generation handle is retained.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture_pending_restore_at_seal(&self) -> Result<Option<kasumi_types::PendingRestore>> {
        self.sealed_restore_observation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::Sealed, "no sealed restore observation"))
    }

    /// Drop resident state under the apply fence. Already returned client data cannot be recalled.
    pub fn seal(&self) {
        let _guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(generation) = self.current.load().as_ref() {
            *self
                .sealed_restore_observation
                .lock()
                .unwrap_or_else(|p| p.into_inner()) =
                Some(generation.state.pending_restore.clone());
        }
        self.publish_generation(None);
        self.audit_maintenance
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }

    pub fn authorize(
        &self,
        context: &RequestContext,
        collection: Option<&str>,
        action: Action,
    ) -> Result<()> {
        context.authorization.check_live()?;
        authorize_state(&self.generation()?.state, context, collection, action)
    }

    pub(crate) fn authorize_discovery(
        &self,
        context: &RequestContext,
        action: Action,
        epoch: Option<u64>,
    ) -> Result<()> {
        context.authorization.check_live()?;
        let generation = self.generation()?;
        authorize_discovery_state(&generation.state, context, action)?;
        if epoch.is_some_and(|epoch| epoch != generation.state.policy_epoch) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "access policy changed during discovery",
            ));
        }
        Ok(())
    }

    pub(crate) fn authorize_release(
        &self,
        context: &RequestContext,
        collection: Option<&str>,
        action: Action,
        policy_epoch: u64,
    ) -> Result<()> {
        context.authorization.check_live()?;
        let generation = self.generation()?;
        authorize_state(&generation.state, context, collection, action)?;
        if generation.state.policy_epoch != policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "access policy changed during read; retry the request",
            ));
        }
        Ok(())
    }

    /// Outer errors mean the replica cannot materialize committed state and must stop serving.
    /// Inner errors are deterministic command rejections and still advance the applied revision.
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(
        clippy::result_large_err,
        reason = "The fixture returns whole inline admitted publication custody without an error-path Box."
    )]
    pub fn apply_command(
        &self,
        disk: &Arc<kasumi_store::ScratchDisk>,
        revision: u64,
        command: Command,
    ) -> std::result::Result<Result<WriteReceipt>, kasumi_raft::TestPublicationFailure> {
        if self
            .snapshot_store
            .get()
            .is_some_and(|store| !store.storage_access().purpose().is_local_fixture())
        {
            return Err(kasumi_raft::TestPublicationFailure::Operation(
                Error::new(
                    ErrorCode::Forbidden,
                    "fixture application cannot mutate production storage",
                )
                .into(),
            ));
        }
        let applied = crate::staged_terminal::AppliedIdentity {
            incarnation: self.incarnation.clone(),
            revision,
            timestamp_ms: command.timestamp_ms,
            command_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&command)
                    .map_err(|_| {
                        Error::new(ErrorCode::Corruption, "fixture command encoding failed")
                    })
                    .map_err(anyhow::Error::from)?,
            )),
            origin: crate::staged_terminal::AppliedOrigin::Fixture,
        };
        let response = crate::test_utils::capture_application(|publisher| {
            self.apply_fixture_command(
                command,
                applied,
                ApplyScope::Fixture(disk.clone()),
                publisher,
            )
        })?;
        Ok(serde_json::from_slice(&response.data).map_err(anyhow::Error::from)?)
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn apply_fixture_command(
        &self,
        command: Command,
        applied: crate::staged_terminal::AppliedIdentity,
        scope: ApplyScope,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            anyhow::ensure!(
                matches!(&scope, ApplyScope::Fixture(_))
                    && matches!(
                        &applied.origin,
                        crate::staged_terminal::AppliedOrigin::Fixture
                    ),
                "fixture application requires its actual local origin"
            );
            Ok(())
        })?;
        let apply = ApplyOwner::lock(self, || anyhow::anyhow!("tenant apply lock poisoned"))?;
        let prepared = self.prepare_command_ordered(&apply, &command, &applied, &scope)?;
        let response = kasumi_raft::AppliedResponse::application(
            serde_json::to_vec(&prepared.outcome).map_err(anyhow::Error::from)?,
        );
        match prepared.generation {
            None => {
                let outcome = publisher.commit(response, &[]);
                drop(apply);
                outcome.map_err(Into::into)
            }
            Some(candidate) => self
                .publish_prepared_generation(
                    apply.accept(candidate, prepared.changed)?,
                    response,
                    None,
                    publisher,
                )
                .map_err(Into::into),
        }
    }

    fn prepare_command_ordered(
        &self,
        apply: &ApplyOwner<'_>,
        command: &Command,
        applied: &crate::staged_terminal::AppliedIdentity,
        scope: &ApplyScope,
    ) -> std::result::Result<PreparedCommand, kasumi_store::ScratchOperationFailure> {
        apply.require_engine(self)?;
        let previous = apply.current();
        let revision = applied.revision;
        self.check_operation_access_from(&previous.state, &command.operation)
            .map_err(anyhow::Error::from)?;
        if revision <= previous.state.revision {
            return Err(kasumi_store::ScratchOperationFailure::Operation(
                Error::new(ErrorCode::Corruption, "applied revision must increase").into(),
            ));
        }
        if previous.state.retired {
            return Ok(PreparedCommand {
                generation: None,
                changed: ChangedIds::new(),
                outcome: Err(Error::new(
                    ErrorCode::Sealed,
                    "application state is permanently frozen after retirement",
                )),
            });
        }
        if let Operation::Mutate(batch) = &command.operation {
            return self.prepare_mutation_ordered(apply, command, batch, applied, scope);
        }
        #[cfg(any(test, feature = "test-utils"))]
        if matches!(scope, ApplyScope::Fixture(_)) {
            previous.terminals.check_fixture_source()?;
        }
        // Reads and preparation use the selected history directly. A fixture
        // obtains append storage only after a nonempty terminal overlay passes
        // validation and budget checks.
        let terminal_owner = previous.terminals.clone();
        let mut next = previous.state.clone();
        next.revision = revision;
        let result = if command.context.tenant != next.tenant {
            Err(Error::new(ErrorCode::Forbidden, "tenant access denied"))
        } else if let Err(error) = command
            .context
            .authorization
            .check_admitted_at(command.timestamp_ms)
        {
            Err(error)
        } else if let Err(error) = authorize_resource(&next, &command.context) {
            Err(error)
        } else {
            if let Some(key) = staged_command_key(command).map_err(anyhow::Error::from)?
                && !next.staged_transactions.contains_key(&key)
                && let Some(row) = terminal_owner.get(&key)?
            {
                row.validate(&previous.state)?;
                next.staged_transactions.insert(key, row.stage);
            }
            apply_operation(
                &mut next,
                command,
                revision,
                previous.state.revision,
                &previous.indexes,
            )
        };
        let (outcome, changed_documents) = match result {
            // Invariant failures must leave the entire publication private,
            // including staged/schema outcomes and their audit/revision metadata.
            Ok((Err(error), _)) | Err(error) if error.code == ErrorCode::Corruption => {
                return Err(kasumi_store::ScratchOperationFailure::Operation(
                    error.into(),
                ));
            }
            Ok(value) => value,
            Err(error) => (Err(error), false),
        };
        // Audit events are part of the replicated result, never emitted as document-bearing logs.
        let action = match &command.operation {
            Operation::LifecycleControl(_) => "lifecycle_control",
            Operation::PublishHistoryArchive(_) => "archive",
            Operation::Mutate(_) => "mutation",
            Operation::BeginStaged(_)
            | Operation::AppendStaged(_)
            | Operation::FinalizeStaged(_)
            | Operation::StopStaged(_) => "staged_transaction",
            Operation::ActivateSchema(_)
            | Operation::CreateCollection(_)
            | Operation::ReplaceCollection(_) => "schema",
            Operation::SetPolicy(_) => "policy",
            Operation::SetLimits(_) => "quota",
            Operation::Suspend(_) => "suspend",
            Operation::RetireSource(_) => "retire",
            Operation::AbortRetirement(_) => "retire_stop",
            Operation::Audit(_) | Operation::MaintenanceAudit(_) => "audit",
        };
        if !matches!(
            command.operation,
            Operation::Audit(_) | Operation::MaintenanceAudit(_)
        ) {
            let event_id = format!("{}:{revision}", next.incarnation);
            append_audit(
                &mut next,
                AuditEvent {
                    event_id,
                    principal: command.context.principal.clone(),
                    action: action.into(),
                    request_id: command.context.request_id.clone(),
                    timestamp_ms: command.timestamp_ms,
                    data_revision: Some(revision),
                    outcome: if outcome.is_ok() {
                        "committed"
                    } else {
                        "rejected"
                    }
                    .into(),
                    collection: None,
                },
            )
            .map_err(anyhow::Error::from)?;
        }
        if !crate::accounting::audit_fits(&next) {
            let mut rejected = previous.state.clone();
            rejected.revision = revision;
            let candidate = Arc::new(Generation {
                receipts: previous.receipts.clone(),
                backup_bindings: previous.backup_bindings.clone(),
                terminals: previous.terminals.clone(),
                target_resolutions: previous.target_resolutions.clone(),
                state: rejected,
                indexes: previous.indexes.clone(),
                snapshot_accounting: previous.snapshot_accounting.clone(),
                application_selection: std::sync::OnceLock::new(),
                _read_reservations: vec![],
            });
            return Ok(PreparedCommand {
                generation: Some(candidate),
                changed: ChangedIds::new(),
                outcome: Err(Error::new(
                    ErrorCode::AuditUnavailable,
                    "hot audit byte budget exhausted",
                )),
            });
        }
        let terminal_pending = crate::staged_terminal::Pending::prepare(
            &terminal_owner,
            &previous.state,
            &mut next,
            applied,
        )?;
        let terminals = PreparedTerminals {
            applied,
            pending: &terminal_pending,
            owner: &terminal_owner,
            scope,
        };
        if let Err(error) = staging::validate_budget(&next, &next.limits) {
            return self.prepare_resource_rejection(
                previous,
                next,
                command,
                Some(error),
                &terminals,
            );
        }
        let changed = if changed_documents {
            operation_changes(&previous.state, command).map_err(anyhow::Error::from)?
        } else {
            BTreeMap::new()
        };
        if changed_documents
            && !matches!(command.operation, Operation::PublishHistoryArchive(_))
            && let Err(error) =
                crate::change_feed_state::append(&previous.state, &mut next, &changed)
        {
            return self.prepare_resource_rejection(
                previous,
                next,
                command,
                Some(error),
                &terminals,
            );
        }
        let snapshot_accounting = previous
            .snapshot_accounting
            .updated(
                &previous.state,
                &next,
                &changed,
                &staged_changes(&previous.state, command).map_err(anyhow::Error::from)?,
            )
            .map_err(anyhow::Error::from)?;
        if !snapshot_accounting
            .fits(&next)
            .map_err(anyhow::Error::from)?
            || !lifecycle::completion_fits(&next).map_err(anyhow::Error::from)?
        {
            return self.prepare_resource_rejection(previous, next, command, None, &terminals);
        }
        let indexes = if changed_documents
            && !matches!(command.operation, Operation::PublishHistoryArchive(_))
        {
            Arc::new(
                crate::index_source::update(&previous.indexes, &previous.state, &next, &changed)
                    .map_err(anyhow::Error::from)?,
            )
        } else {
            previous.indexes.clone()
        };
        let terminals = scope.stage_terminals(terminal_pending, &previous.state)?;
        let candidate = Arc::new(Generation {
            receipts: previous.receipts.clone(),
            backup_bindings: previous.backup_bindings.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            terminals,
            state: next,
            indexes,
            snapshot_accounting,
            application_selection: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        });
        Ok(PreparedCommand {
            generation: Some(candidate),
            changed,
            outcome,
        })
    }

    fn prepare_resource_rejection(
        &self,
        previous: &Generation,
        next: TenantState,
        command: &Command,
        failure: Option<Error>,
        terminals: &PreparedTerminals<'_>,
    ) -> std::result::Result<PreparedCommand, kasumi_store::ScratchOperationFailure> {
        let revision = next.revision;
        let error = failure.unwrap_or_else(|| {
            Error::new(
                ErrorCode::QuotaExceeded,
                "serialized tenant snapshot byte budget exhausted",
            )
        });
        let mut rejected = previous.state.clone();
        rejected.revision = revision;
        let ordinary = !matches!(
            command.operation,
            Operation::Audit(_) | Operation::MaintenanceAudit(_)
        );
        if ordinary {
            schema::reject_budget(&previous.state, &next, &mut rejected, command, &error)
                .map_err(anyhow::Error::from)?;
            retirement::reject_budget(&previous.state, &next, &mut rejected, command, &error)
                .map_err(anyhow::Error::from)?;
            if let Operation::FinalizeStaged(reference) = &command.operation {
                let key = staged_digest(&(&command.context.principal, &reference.transaction_id))
                    .map_err(anyhow::Error::from)?
                    .0;
                if previous
                    .state
                    .staged_transactions
                    .get(&key)
                    .is_some_and(StagedTransaction::is_active)
                    && let Some(completed) = terminals.pending.get(&key)?
                    && !completed.is_active()
                {
                    let mut completed = completed.clone();
                    completed.outcome = StagedOutcome::Finished {
                        outcome: Err(error.clone()),
                    };
                    staging::replace_record(&mut rejected, key, completed)
                        .map_err(anyhow::Error::from)?;
                }
            }
            let mut event = next
                .audits
                .back()
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "required audit missing"))
                .map_err(anyhow::Error::from)?
                .clone();
            event.outcome = "rejected".into();
            append_audit(&mut rejected, event).map_err(anyhow::Error::from)?;
            let rejected_terminals = crate::staged_terminal::Pending::prepare(
                terminals.owner,
                &previous.state,
                &mut rejected,
                terminals.applied,
            )?;
            let accounting = previous
                .snapshot_accounting
                .updated(
                    &previous.state,
                    &rejected,
                    &BTreeMap::new(),
                    &staged_changes(&previous.state, command).map_err(anyhow::Error::from)?,
                )
                .map_err(anyhow::Error::from)?;
            if rejected.audit_retention.hot_bytes <= rejected.limits.audit_retention.hot_bytes
                && accounting.fits(&rejected).map_err(anyhow::Error::from)?
                && lifecycle::completion_fits(&rejected).map_err(anyhow::Error::from)?
            {
                let terminals = terminals
                    .scope
                    .stage_terminals(rejected_terminals, &previous.state)?;
                let candidate = Arc::new(Generation {
                    receipts: previous.receipts.clone(),
                    backup_bindings: previous.backup_bindings.clone(),
                    target_resolutions: previous.target_resolutions.clone(),
                    terminals,
                    state: rejected,
                    indexes: previous.indexes.clone(),
                    snapshot_accounting: accounting,
                    application_selection: std::sync::OnceLock::new(),
                    _read_reservations: vec![],
                });
                return Ok(PreparedCommand {
                    generation: Some(candidate),
                    changed: ChangedIds::new(),
                    outcome: Err(error),
                });
            }
        }
        // Required audit/receipt storage is exhausted. Nothing from the command
        // takes effect. The revision-only cursor fits its pre-reserved headroom.
        let mut rejected = previous.state.clone();
        rejected.revision = revision;
        let candidate = Arc::new(Generation {
            receipts: previous.receipts.clone(),
            backup_bindings: previous.backup_bindings.clone(),
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            state: rejected,
            indexes: previous.indexes.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            application_selection: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        });
        Ok(PreparedCommand {
            generation: Some(candidate),
            changed: ChangedIds::new(),
            outcome: Err(Error::new(
                ErrorCode::AuditUnavailable,
                "required audit cannot fit serialized tenant budget",
            )),
        })
    }

    pub(crate) fn write_generation(
        generation: &Generation,
        writer: &mut dyn std::io::Write,
    ) -> Result<()> {
        if !generation.snapshot_accounting.fits(&generation.state)? {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot byte accounting mismatch",
            ));
        }
        crate::snapshot_codec::write(
            &generation.state,
            &generation.receipts,
            &generation.backup_bindings,
            &generation.terminals,
            &generation.target_resolutions,
            writer,
        )
        .map_err(|_| Error::new(ErrorCode::Corruption, "snapshot encoding failed"))
    }

    pub(crate) fn logical_snapshot(
        &self,
        scratch_disk: &Arc<kasumi_store::ScratchDisk>,
    ) -> Result<kasumi_store::SnapshotImage> {
        let generation = self.generation()?;
        Self::logical_snapshot_of(&generation, scratch_disk)
    }

    fn logical_snapshot_of(
        generation: &Generation,
        scratch_disk: &Arc<kasumi_store::ScratchDisk>,
    ) -> Result<kasumi_store::SnapshotImage> {
        kasumi_store::SnapshotImage::capture(
            scratch_disk,
            crate::target_resolution::snapshot_limit(&generation.state)
                .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))?,
            |writer| Ok(Self::write_generation(generation, writer)?),
        )
        .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))
    }

    pub fn snapshot_bytes(&self) -> Result<usize> {
        let generation = self.generation()?;
        generation.snapshot_accounting.bytes(&generation.state)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn restore_candidate(
        &self,
        bytes: &kasumi_store::SnapshotImage,
    ) -> std::result::Result<(), SnapshotFailure> {
        let apply = ApplyOwner::lock_validation(self)?;
        let generation = self.prepare_snapshot_reader(
            &ValidationBaseline::from_apply(&apply),
            bytes.disk(),
            &mut bytes.reader(),
            None,
        )?;
        if generation.state.audit_retention.archive_head.is_some() {
            let store = self.snapshot_store.get().ok_or_else(|| {
                Error::new(
                    ErrorCode::Corruption,
                    "logical snapshot audit dependencies not installed",
                )
            })?;
            snapshot_bundle::verify_local(&generation, store)
                .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))?;
        }
        self.leases.replace(&self.current, Arc::new(generation));
        Ok(())
    }

    fn prepare_snapshot_reader(
        &self,
        baseline: &ValidationBaseline<'_>,
        disk: &Arc<kasumi_store::ScratchDisk>,
        reader: &mut dyn std::io::Read,
        expected: Option<crate::snapshot_codec::StreamSummary>,
    ) -> std::result::Result<Generation, SnapshotFailure> {
        baseline.current_for(self)?;
        let crate::snapshot_codec::Decoded {
            state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
            summary,
        } = crate::snapshot_codec::read(disk, reader).map_err(SnapshotFailure::from)?;
        if expected.is_some_and(|expected| expected != summary) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot differs from admitted typed framing",
            )
            .into());
        }
        self.prepare_state(
            baseline,
            state,
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
        )
        .map_err(Into::into)
    }

    fn prepare_state(
        &self,
        baseline: &ValidationBaseline<'_>,
        state: TenantState,
        receipts: crate::mutation_receipt::View,
        backup_bindings: crate::backup_binding::View,
        terminals: crate::staged_terminal::View,
        target_resolutions: crate::target_resolution::View,
    ) -> Result<Generation> {
        let prior = baseline.current_for(self)?;
        if state.tenant != self.tenant
            || state.incarnation != self.incarnation
            || state.revision_base != self.revision_base
            || state.revision < state.revision_base
            || staged_digest(&(&state.restored_from, &state.restore_lineage))?.0
                != self.restoration_identity
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot tenant or incarnation mismatch",
            ));
        }
        validate_limits(&state.limits)?;
        validate_policy(&state.policy, &state.limits)?;
        lifecycle::validate(&state)?;
        recovery::validate(&state)?;
        if let Some(current) = prior {
            recovery::validate_successor(&current.state, &state)?;
        }
        validate_target_history(&state)?;
        for entry in state.target_lifecycle.values() {
            if let Some(completed) = &entry.completion {
                let expected = kasumi_serving::verify_target_materializations(
                    &entry.origin,
                    &completed.materialized,
                )
                .map_err(|_| {
                    Error::new(
                        ErrorCode::Corruption,
                        "snapshot target materialization signatures differ",
                    )
                })?;
                if expected != completed.bootstrap_sha256 {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot target bootstrap differs",
                    ));
                }
            }
        }
        if let Some(current) = prior {
            for (id, old) in &current.state.target_lifecycle {
                let new = state.target_lifecycle.get(id).ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "snapshot removed target history")
                })?;
                if new.origin != old.origin
                    || old
                        .completion
                        .as_ref()
                        .is_some_and(|fact| new.completion.as_ref() != Some(fact))
                    || old
                        .activation
                        .as_ref()
                        .is_some_and(|fact| new.activation.as_ref() != Some(fact))
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot substituted immutable target history",
                    ));
                }
            }
        }
        if let Some(current) = prior
            && let Some(installed) = &current.state.lifecycle_control
            && state.lifecycle_control.as_ref().is_none_or(|incoming| {
                incoming.installation != installed.installation
                    || incoming.installation_command_id != installed.installation_command_id
                    || incoming.installation_revision != installed.installation_revision
                    || incoming.installation_policy_epoch != installed.installation_policy_epoch
                    || staged_digest(&incoming.installation_policy).ok()
                        != staged_digest(&installed.installation_policy).ok()
            })
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot substituted the immutable control installation",
            ));
        }
        if let Some(current) = prior
            && let (Some(old), Some(incoming)) =
                (&current.state.lifecycle_control, &state.lifecycle_control)
        {
            for (id, intent) in &old.intents {
                if incoming.intents.get(id) != Some(intent) {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot substituted a permanent lifecycle intent",
                    ));
                }
            }
            for (id, change) in &old.changes {
                let Some(actual) = incoming.changes.get(id) else {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot removed a permanent control change",
                    ));
                };
                let mut expected = change.clone();
                if expected.completed_revision.is_none() {
                    expected.completed_revision = actual.completed_revision;
                    expected.completion_stops = actual.completion_stops.clone();
                }
                if staged_digest(&expected)? != staged_digest(actual)? {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot substituted permanent control history",
                    ));
                }
            }
        }
        validate_metadata_budget(&state.collections, &state.limits)?;
        if state.schema_epoch > state.policy_epoch
            || (!state.collections.is_empty() && state.schema_epoch == 0)
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "invalid snapshot schema epoch",
            ));
        }
        if state.retired && !state.suspended {
            return Err(Error::new(
                ErrorCode::Corruption,
                "retired incarnation must be suspended",
            ));
        }
        if state.pending_restore.as_ref().is_some_and(|pending| {
            !state.suspended
                || pending.source_revision >= state.revision_base
                || uuid::Uuid::parse_str(&pending.backup_id).is_err()
        }) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "invalid pending restore marker",
            ));
        }
        let mut count = 0u64;
        let mut logical_bytes = 0u64;
        for (name, collection) in &state.collections {
            count = count
                .checked_add(collection.archived_documents.len() as u64)
                .ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "archived document count overflow")
                })?;
            if collection.data_epoch > state.revision {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "invalid snapshot data/schema epoch",
                ));
            }
            if name != &collection.definition.name {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "snapshot collection identity mismatch",
                ));
            }
            let source = crate::index_source::StateCollection::new(&state, name, collection);
            validate_collection(&source).map_err(kasumi_query::ReadFailure::into_query_error)?;
            check_unique(&source).map_err(kasumi_query::ReadFailure::into_query_error)?;
            for (id, document) in &collection.documents {
                validate_name(id)?;
                if id != &document.id || document.version > collection.data_epoch {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "invalid document identity/version",
                    ));
                }
                count = count
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorCode::Corruption, "document count overflow"))?;
                let document_bytes = encoded_len(&document.body)?;
                if document_bytes > state.limits.max_document_bytes {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot document exceeds byte quota",
                    ));
                }
                logical_bytes = logical_bytes
                    .checked_add(document_bytes as u64)
                    .ok_or_else(|| {
                        Error::new(ErrorCode::Corruption, "document byte count overflow")
                    })?;
            }
        }
        if count != state.document_count
            || logical_bytes != state.logical_bytes
            || count > state.limits.max_documents
            || logical_bytes > state.limits.max_logical_bytes
            || state.mutation_receipt_head.encoded_bytes > state.limits.max_mutation_receipt_bytes
            || state.backup_binding_head.encoded_bytes > state.limits.max_backup_binding_bytes
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot logical accounting mismatch",
            ));
        }
        if !state.recovery_control.is_empty()
            && (state.tenant != crate::control::CONTROL_TENANT || state.lifecycle_control.is_none())
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "recovery coordinator requires installed Control state",
            ));
        }
        validate_audits(&state)?;
        let snapshot_accounting = SnapshotAccounting::rebuild(&state)?;
        terminals.validate_state(&state).map_err(terminal_error)?;
        if terminals.head() != &state.staged_terminal_head {
            return Err(Error::new(
                ErrorCode::Corruption,
                "terminal snapshot owner differs",
            ));
        }
        if let Some(current) = prior {
            let old = current.terminals.head();
            if old.origin_incarnation != state.staged_terminal_head.origin_incarnation
                || old.count > state.staged_terminal_head.count
                || (old.count > 0
                    && terminals
                        .row(old.count)
                        .map_err(terminal_error)?
                        .sha256()
                        .map_err(terminal_error)?
                        != old.sha256)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "snapshot removed or substituted terminal staged history",
                ));
            }
        }
        target_resolutions
            .validate_state(&state)
            .map_err(terminal_error)?;
        if !target::receiver::history_reserve_fits(&state)? {
            return Err(Error::new(
                ErrorCode::Corruption,
                "target history lost reserved completion capacity",
            ));
        }
        if let Some(current) = prior {
            if let Some(old_head) = &current.state.target_completion_head {
                let incoming = state.target_completion_head.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorCode::Corruption,
                        "snapshot removed current target completion head",
                    )
                })?;
                if old_head.initial_budget_bytes != incoming.initial_budget_bytes {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "snapshot substituted initial target budget",
                    ));
                }
                if let Some(active) = &old_head.active
                    && incoming.active.as_ref() != Some(active)
                {
                    let key = format!(
                        "completion/{}/{}",
                        state.incarnation, active.intent.request.command_id
                    );
                    let row = target_resolutions
                        .get(&key)
                        .map_err(terminal_error)?
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Corruption,
                                "snapshot replaced an unsealed original completion attempt",
                            )
                        })?;
                    if !matches!(row.record, TargetResolutionRecord::Completion(ref fact) if fact.input.attempt == *active)
                    {
                        return Err(Error::new(
                            ErrorCode::Corruption,
                            "snapshot terminal changed original active attempt",
                        ));
                    }
                }
            }
            let old = current.target_resolutions.head();
            if old.origin_incarnation != state.target_resolution_head.origin_incarnation
                || old.count > state.target_resolution_head.count
                || (old.count > 0
                    && target_resolutions
                        .row(old.count)
                        .map_err(terminal_error)?
                        .sha256()
                        .map_err(terminal_error)?
                        != old.sha256)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "snapshot removed or substituted permanent target terminal history",
                ));
            }
        }
        staging::validate_restored(&state)?;
        schema::validate_restored(&state)?;
        retirement::validate_restored(&state)?;
        validate_restore_lineage(
            &state.tenant,
            &state.incarnation,
            state.revision,
            state.restored_from.as_ref(),
            &state.restore_lineage,
        )
        .map_err(|_| Error::new(ErrorCode::Corruption, "invalid restore lineage"))?;
        backup_bindings
            .validate_state(&state)
            .map_err(terminal_error)?;
        for row in backup_bindings.records() {
            row.map_err(terminal_error)?
                .validate(&state)
                .map_err(terminal_error)?;
        }
        if let Some(current) = prior {
            let old = current.backup_bindings.head();
            if old.origin_incarnation != state.backup_binding_head.origin_incarnation
                || old.count > state.backup_binding_head.count
                || (old.count > 0
                    && backup_bindings
                        .row(old.count)
                        .map_err(terminal_error)?
                        .sha256()
                        .map_err(terminal_error)?
                        != old.sha256)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "snapshot removed or substituted permanent backup bindings",
                ));
            }
        }
        receipts.validate_state(&state).map_err(terminal_error)?;
        for row in receipts.records() {
            row.map_err(terminal_error)?
                .validate(&state)
                .map_err(terminal_error)?;
        }
        if let Some(current) = prior {
            let old = current.receipts.head();
            if old.origin_incarnation != state.mutation_receipt_head.origin_incarnation
                || old.count > state.mutation_receipt_head.count
                || (old.count > 0
                    && receipts
                        .row(old.count)
                        .map_err(terminal_error)?
                        .sha256()
                        .map_err(terminal_error)?
                        != old.sha256)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "snapshot removed or substituted permanent mutation receipts",
                ));
            }
        }
        if let Some(origin) = &state.restored_from {
            origin.validate()?;
            if origin.tenant != state.tenant
                || origin.source_incarnation == state.incarnation
                || origin.revision >= state.revision_base
                || state.pending_restore.as_ref().is_some_and(|pending| {
                    pending.backup_id != origin.backup_id.to_string()
                        || pending.source_revision != origin.revision
                })
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "restored origin binding differs",
                ));
            }
        } else if state.pending_restore.is_some() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "pending restore lacks authenticated origin",
            ));
        }

        history::validate_restored(&state)?;
        crate::change_feed_state::validate_restored(&state)?;
        if !snapshot_accounting.fits(&state)? {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot exceeds serialized byte quota",
            ));
        }
        let indexes = Arc::new(crate::index_source::build(&state)?);
        Ok(Generation {
            receipts,
            backup_bindings,
            terminals,
            target_resolutions,
            state,
            indexes,
            snapshot_accounting,
            application_selection: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        })
    }
}

fn authorize_state(
    state: &TenantState,
    context: &RequestContext,
    collection: Option<&str>,
    action: Action,
) -> Result<()> {
    authorize_resource(state, context)?;
    if context.tenant != state.tenant {
        return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
    }
    if !state.policy.allows(context, collection, action) {
        return Err(Error::new(ErrorCode::Forbidden, "operation access denied"));
    }
    if state.tenant.starts_with("__kasumi_")
        && action == Action::Write
        && !state.policy.allows(context, None, Action::Admin)
    {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "operator metadata requires administration permission",
        ));
    }
    if (state.suspended || state.retired) && action != Action::Admin {
        return Err(Error::new(ErrorCode::Sealed, "tenant is suspended"));
    }
    Ok(())
}

fn authorize_discovery_state(
    state: &TenantState,
    context: &RequestContext,
    action: Action,
) -> Result<()> {
    authorize_resource(state, context)?;
    if context.tenant != state.tenant
        || !context.scopes.contains(&action)
        || !state
            .policy
            .grants
            .iter()
            .any(|grant| grant.principal == context.principal && grant.actions.contains(&action))
    {
        return Err(Error::new(ErrorCode::Forbidden, "discovery access denied"));
    }
    if (state.suspended && action != Action::Admin) || state.retired {
        return Err(Error::new(
            ErrorCode::Sealed,
            "tenant is suspended or retired",
        ));
    }
    Ok(())
}

/// Native credentials bind their exact installed purpose and incarnation.
/// Replicas use this same immutable metadata without sampling local time.
pub(crate) fn authorize_resource(state: &TenantState, context: &RequestContext) -> Result<()> {
    if state.tenant == crate::control::CONTROL_TENANT {
        context.authorization.require_control(&state.incarnation)
    } else {
        context.authorization.require_database(&state.incarnation)
    }
}

fn apply_operation(
    state: &mut TenantState,
    command: &Command,
    revision: u64,
    previous_revision: u64,
    indexes: &QueryIndexes,
) -> Result<(Result<WriteReceipt>, bool)> {
    let receipt = || WriteReceipt {
        revision,
        versions: BTreeMap::new(),
    };
    if state.retired
        && !matches!(
            command.operation,
            Operation::MaintenanceAudit(_)
                | Operation::RetireSource(_)
                | Operation::AbortRetirement(_)
                | Operation::SetLimits(_)
                | Operation::SetPolicy(_)
        )
    {
        return Err(Error::new(
            ErrorCode::Sealed,
            "database incarnation is permanently retired",
        ));
    }
    lifecycle::guard(state, &command.operation)?;
    match &command.operation {
        Operation::LifecycleControl(request) => lifecycle::apply(state, command, request, revision),
        Operation::PublishHistoryArchive(request) => {
            history::publish(state, command, request, revision)
        }
        Operation::BeginStaged(_)
        | Operation::AppendStaged(_)
        | Operation::FinalizeStaged(_)
        | Operation::StopStaged(_) => staging::apply(state, command, revision, indexes),
        Operation::Mutate(_) => Err(Error::new(
            ErrorCode::Corruption,
            "ordinary mutation bypassed permanent receipt admission",
        )),
        Operation::ActivateSchema(request) => schema::apply(
            state,
            &command.context,
            request,
            revision,
            command.timestamp_ms,
        ),
        Operation::CreateCollection(definition) | Operation::ReplaceCollection(definition) => {
            authorize_state(
                state,
                &command.context,
                Some(&definition.name),
                Action::Admin,
            )?;
            let collection = schema::prepare_collection(
                state,
                state.collections.get(&definition.name),
                definition,
                matches!(command.operation, Operation::CreateCollection(_)),
            )?;
            let mut collections = state.collections.clone();
            collections.insert(definition.name.clone(), collection);
            validate_metadata_budget(&collections, &state.limits)?;
            let epoch = next_policy_epoch(state.policy_epoch)?;
            let schema_epoch = next_policy_epoch(state.schema_epoch)?;
            state.collections = collections;
            state.policy_epoch = epoch;
            state.schema_epoch = schema_epoch;
            Ok((Ok(receipt()), true))
        }
        Operation::SetPolicy(policy) => {
            authorize_state(state, &command.context, None, Action::Admin)?;
            validate_policy(policy, &state.limits)?;
            let epoch = next_policy_epoch(state.policy_epoch)?;
            state.policy = policy.clone();
            state.policy_epoch = epoch;
            Ok((Ok(receipt()), false))
        }
        Operation::SetLimits(limits) => {
            authorize_state(state, &command.context, None, Action::Admin)?;
            if limits.max_target_resolution_bytes != state.limits.max_target_resolution_bytes {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "target resolution budget requires exact current-Control maintenance",
                ));
            }
            validate_limits(limits)?;
            staging::validate_new_limits(state, limits)?;
            if state.schema_activation_bytes > limits.max_schema_activation_bytes
                || state.retirement_bytes > limits.max_retirement_bytes
            {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "new byte budget excludes retained permanent outcomes",
                ));
            }
            validate_policy(&state.policy, limits)?;
            validate_metadata_budget(&state.collections, limits)?;
            if limits.max_document_bytes < state.limits.max_document_bytes {
                for collection in state.collections.values() {
                    for document in collection.documents.values() {
                        if encoded_len(&document.body)? > limits.max_document_bytes {
                            return Err(Error::new(
                                ErrorCode::QuotaExceeded,
                                "new document limit is below retained state",
                            ));
                        }
                    }
                }
            }
            if state.document_count > limits.max_documents
                || state.logical_bytes > limits.max_logical_bytes
                || state.mutation_receipt_head.encoded_bytes > limits.max_mutation_receipt_bytes
                || state.backup_binding_head.encoded_bytes > limits.max_backup_binding_bytes
                || state.history_archives.len() > limits.history.max_archive_segments
                || state.audit_retention.hot_bytes > limits.audit_retention.hot_bytes
                || state.audit_retention.archive_bytes > limits.audit_retention.archive_bytes
            {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "new limits are below retained state",
                ));
            }
            let epoch = next_policy_epoch(state.policy_epoch)?;
            state.limits = limits.clone();
            state.policy_epoch = epoch;
            crate::change_feed_state::trim(&mut state.change_feed, &limits.history)?;
            Ok((Ok(receipt()), false))
        }
        Operation::Suspend(suspended) => {
            authorize_state(state, &command.context, None, Action::Admin)?;
            if !suspended && state.pending_restore.is_some() {
                return Err(Error::new(
                    ErrorCode::AuditUnavailable,
                    "restore must be durably finalized before activation",
                ));
            }
            let epoch = next_policy_epoch(state.policy_epoch)?;
            state.suspended = *suspended;
            state.policy_epoch = epoch;
            Ok((Ok(receipt()), false))
        }
        Operation::RetireSource(request) => {
            retirement::apply(state, command, request, previous_revision, revision)
        }
        Operation::AbortRetirement(request) => {
            retirement::abort(state, &command.context, request, revision)
        }
        Operation::Audit(event) => {
            let action = match event.action.as_str() {
                "read" | "discovery" | "change_feed" | "archive_receipt" | "restore_lineage" => {
                    Action::Read
                }
                "receipt" => Action::Write,
                "schema_activation_status" | "schema_read" | "policy_limits_read" => Action::Admin,
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid read audit action",
                    ));
                }
            };
            if event.collection.is_none() {
                authorize_discovery_state(state, &command.context, action)?;
            } else {
                authorize_state(state, &command.context, event.collection.as_deref(), action)?;
            }
            if event.principal != command.context.principal
                || event.request_id != command.context.request_id
                || event.outcome != "authorized_release"
                || event.data_revision.is_none_or(|r| r > revision)
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "invalid read audit event",
                ));
            }
            append_audit(state, event.clone())?;
            Ok((Ok(receipt()), false))
        }
        Operation::MaintenanceAudit(event) => {
            authorize_state(state, &command.context, None, Action::Admin)?;
            if event.principal != command.context.principal
                || event.request_id != command.context.request_id
                || !matches!(
                    event.action.as_str(),
                    "backup"
                        | "backup_verification"
                        | "restore"
                        | "archive"
                        | "key_rotation"
                        | "key_rewrap"
                        | "membership"
                        | "retirement_status"
                        | "retirement_receipt"
                        | "backup_abort"
                        | "backup_cleanup"
                )
                || !matches!(
                    event.outcome.as_str(),
                    "started" | "completed" | "failed" | "unknown"
                )
                || event.data_revision.is_none_or(|r| r > revision)
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "invalid maintenance audit event",
                ));
            }
            if event.action == "restore" && event.outcome == "completed" {
                let pending = state
                    .pending_restore
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::Conflict, "no restore is pending"))?;
                if event.data_revision != Some(pending.source_revision) {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "restore audit revision mismatch",
                    ));
                }
                state.pending_restore = None;
            }
            append_audit(state, event.clone())?;
            Ok((Ok(receipt()), false))
        }
    }
}

fn apply_batch(
    state: &mut TenantState,
    batch: &MutationBatch,
    revision: u64,
    evaluated_at_ms: u64,
    indexes: &QueryIndexes,
) -> Result<WriteReceipt> {
    if batch.operations.len() > state.limits.max_batch_operations
        || encoded_len(batch)? > state.limits.max_batch_bytes
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "mutation batch exceeds limits",
        ));
    }
    validate_read_assertions(
        state,
        &batch.read_set.iter().collect::<Vec<_>>(),
        evaluated_at_ms,
        512,
    )?;
    let patch_expansion_limit = state.limits.max_batch_bytes;
    apply_mutations(
        state,
        &batch.operations.iter().collect::<Vec<_>>(),
        revision,
        true,
        indexes,
        patch_expansion_limit,
    )
}

/// Extra workspace for copying patch source documents, independently of the
/// encoded patch input. The 1 MiB document ceiling is enforced by validate_limits.
/// Callers use immutable operation ceilings when admitting queued proposals;
/// ordered apply enforces the current, possibly narrower, byte limit.
pub(crate) fn merge_patch_workspace(patch_count: usize, expansion_limit: usize) -> usize {
    patch_count
        .saturating_mul(1 << 20)
        .min(expansion_limit)
        .saturating_mul(3)
}

fn validate_merge_patch_expansion(
    state: &TenantState,
    operations: &[&Mutation],
    expansion_limit: usize,
) -> Result<()> {
    let patch_count = operations
        .iter()
        .filter(|mutation| matches!(mutation, Mutation::Patch { .. }))
        .count();
    let workspace = merge_patch_workspace(patch_count, expansion_limit) as u64;
    let mut encoded = 0usize;
    let mut cloned = 0u64;
    for mutation in operations {
        let Mutation::Patch { collection, id, .. } = mutation else {
            continue;
        };
        let Some(document) = state
            .collections
            .get(collection)
            .and_then(|collection| collection.documents.get(id))
        else {
            // Preserve ordinary missing-document/precondition validation below.
            continue;
        };
        encoded = encoded
            .checked_add(encoded_len(&document.body)?)
            .filter(|bytes| *bytes <= expansion_limit)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "merge patch source documents exceed byte limit",
                )
            })?;
        // Encoded size alone cannot bound allocations for object-heavy JSON.
        // Quote all source clones before copying even the first document.
        cloned = cloned
            .checked_add(kasumi_query::document_clone_bytes(document)?)
            .filter(|bytes| *bytes <= workspace)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "merge patch source documents exceed workspace limit",
                )
            })?;
    }
    Ok(())
}

fn apply_mutations(
    state: &mut TenantState,
    operations: &[&Mutation],
    revision: u64,
    include_versions: bool,
    indexes: &QueryIndexes,
    patch_expansion_limit: usize,
) -> Result<WriteReceipt> {
    validate_merge_patch_expansion(state, operations, patch_expansion_limit)?;
    let mut targets = BTreeSet::new();
    let mut versions = BTreeMap::new();
    for &mutation in operations {
        let (name, id) = mutation.target();
        validate_name(id)?;
        if !targets.insert((name, id)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "duplicate batch target",
            ));
        }
        let collection = state
            .collections
            .get_mut(name)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
        if collection.archived_documents.contains_key(id) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "archived immutable identity cannot be overwritten or deleted",
            ));
        }
        let old = collection.documents.get(id);
        if collection.definition.write_mode == CollectionWriteMode::AppendOnly
            && !matches!(mutation, Mutation::Put { expected: Precondition::Absent, .. } if old.is_none())
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "append-only collections accept absent creates only",
            ));
        }
        match mutation.expected() {
            Precondition::Any => {}
            Precondition::Absent if old.is_none() => {}
            Precondition::Version(v) if old.is_some_and(|d| d.version == *v) => {}
            _ => {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "document precondition failed",
                ));
            }
        }
        let old_bytes = old.map(|d| encoded_len(&d.body)).transpose()?.unwrap_or(0) as u64;
        let replacement = match mutation {
            Mutation::Put { body, .. } => Some(std::borrow::Cow::Borrowed(body)),
            Mutation::Patch { patch, .. } => {
                let Some(old) = old else {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        "patch requires an existing document; use put to create it",
                    ));
                };
                let mut body = old.body.clone();
                kasumi_types::apply_merge_patch(&mut body, patch)?;
                Some(std::borrow::Cow::Owned(body))
            }
            Mutation::Delete { .. } => None,
        };
        match replacement {
            Some(body) => {
                let bytes = encoded_len(&*body)?;
                if bytes > state.limits.max_document_bytes {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "document exceeds byte limit",
                    ));
                }
                indexes.validate_document(&collection.definition, &body)?;
                if old.is_none() {
                    state.document_count += 1;
                }
                state.logical_bytes = state
                    .logical_bytes
                    .checked_sub(old_bytes)
                    .and_then(|n| n.checked_add(bytes as u64))
                    .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "logical size overflow"))?;
                collection.documents.insert(
                    id.to_owned(),
                    Arc::new(Document {
                        id: id.to_owned(),
                        version: revision,
                        body: body.into_owned(),
                    }),
                );
                collection.data_epoch = revision;
                if include_versions {
                    versions.insert(document_path(name, id), revision);
                }
            }
            None => {
                if collection.documents.remove(id).is_some() {
                    state.document_count -= 1;
                    state.logical_bytes -= old_bytes;
                    collection.data_epoch = revision;
                }
                if include_versions {
                    versions.insert(document_path(name, id), revision);
                }
            }
        }
    }
    if state.document_count > state.limits.max_documents
        || state.logical_bytes > state.limits.max_logical_bytes
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "tenant logical quota exceeded",
        ));
    }
    Ok(WriteReceipt { revision, versions })
}

pub(crate) fn validate_read_assertions(
    state: &TenantState,
    assertions: &[&ReadAssertion],
    evaluated_at_ms: u64,
    max_assertions: usize,
) -> Result<()> {
    if assertions.len() > max_assertions {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "read assertion limit exceeded",
        ));
    }
    let mut identities = BTreeSet::new();
    for &assertion in assertions {
        let identity =
            match assertion {
                ReadAssertion::Before { not_after_ms } => {
                    if evaluated_at_ms > *not_after_ms {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "transaction authorization deadline expired",
                        ));
                    }
                    (3, "", "")
                }
                ReadAssertion::NotBefore { not_before_ms } => {
                    if evaluated_at_ms < *not_before_ms {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "transaction admission time precedes required bound",
                        ));
                    }
                    (4, "", "")
                }
                ReadAssertion::Snapshot {
                    incarnation,
                    policy_epoch,
                    schema_epoch,
                } => {
                    validate_name(incarnation)?;
                    if incarnation != &state.incarnation
                        || *policy_epoch != state.policy_epoch
                        || *schema_epoch != state.schema_epoch
                    {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "snapshot identity or authority changed",
                        ));
                    }
                    (0, "", "")
                }
                ReadAssertion::Document {
                    collection,
                    id,
                    expected,
                } => {
                    validate_name(collection)?;
                    validate_name(id)?;
                    let collection_state = state.collections.get(collection).ok_or_else(|| {
                        Error::new(ErrorCode::NotFound, "read collection not found")
                    })?;
                    let version = collection_state
                        .documents
                        .get(id)
                        .map(|document| document.version)
                        .or_else(|| {
                            collection_state
                                .archived_documents
                                .get(id)
                                .map(|document| document.version)
                        });
                    let matches = match expected {
                        ReadPrecondition::Absent => version.is_none(),
                        ReadPrecondition::Version(expected) => version == Some(*expected),
                    };
                    if !matches {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "read document precondition failed",
                        ));
                    }
                    (1, collection.as_str(), id.as_str())
                }
                ReadAssertion::Collection {
                    collection,
                    data_epoch,
                } => {
                    validate_name(collection)?;
                    let current = state.collections.get(collection).ok_or_else(|| {
                        Error::new(ErrorCode::NotFound, "read collection not found")
                    })?;
                    if current.data_epoch != *data_epoch {
                        return Err(Error::new(ErrorCode::Conflict, "read collection changed"));
                    }
                    (2, collection.as_str(), "")
                }
            };
        if !identities.insert(identity) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "duplicate read assertion",
            ));
        }
    }
    Ok(())
}

fn batch_changes(batch: &MutationBatch) -> BTreeMap<String, BTreeSet<String>> {
    let mut changed = BTreeMap::<String, BTreeSet<String>>::new();
    for mutation in &batch.operations {
        let (collection, id) = mutation.target();
        changed
            .entry(collection.into())
            .or_default()
            .insert(id.into());
    }
    changed
}

fn operation_changes(
    state: &TenantState,
    command: &Command,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    match &command.operation {
        Operation::Mutate(batch) => Ok(batch_changes(batch)),
        Operation::PublishHistoryArchive(request) => Ok(history::changes(state, request)),
        Operation::FinalizeStaged(reference) => {
            let key = staged_digest(&(&command.context.principal, &reference.transaction_id))?.0;
            let stage = state.staged_transactions.get(&key).ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "finalized staged source missing")
            })?;
            Ok(staging::changes(stage))
        }
        _ => Ok(BTreeMap::new()),
    }
}

fn staged_changes(state: &TenantState, command: &Command) -> Result<BTreeSet<String>> {
    let transaction_id = match &command.operation {
        Operation::BeginStaged(request) => &request.transaction_id,
        Operation::AppendStaged(request) => &request.transaction.transaction_id,
        Operation::FinalizeStaged(reference) => &reference.transaction_id,
        Operation::StopStaged(request) => &request.original.transaction_id,
        _ => return Ok(BTreeSet::new()),
    };
    let mut changed = state.active_staged_transactions.clone();
    changed.insert(staged_digest(&(&command.context.principal, transaction_id))?.0);
    Ok(changed)
}

fn document_path(collection: &str, id: &str) -> String {
    let escape = |value: &str| value.replace('~', "~0").replace('/', "~1");
    format!("/{}/{}", escape(collection), escape(id))
}

pub(super) fn validate_limits(limits: &Limits) -> Result<()> {
    limits.audit_retention.validate()?;
    if limits.history.max_feed_events == 0
        || limits.history.max_feed_events > 1_000_000
        || limits.history.max_feed_bytes == 0
        || limits.history.max_feed_bytes > (512 << 20)
        || limits.history.max_archive_segments == 0
        || limits.history.max_archive_segments > 65_536
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid history resource limits",
        ));
    }
    let atomic = &limits.atomic;
    if atomic.max_operations == 0
        || atomic.max_operations > 100_000
        || atomic.max_read_assertions == 0
        || atomic.max_read_assertions > 100_000
        || atomic.max_transaction_bytes < limits.max_batch_bytes
        || atomic.max_transaction_bytes > (64 << 20)
        || atomic.max_active_transactions == 0
        || atomic.max_active_transactions > 64
        || atomic.max_reserved_staging_bytes < atomic.max_transaction_bytes
        || atomic.max_reserved_staging_bytes > (512 << 20)
        || atomic.max_permanent_staged_bytes == 0
        || atomic.max_snapshot_leases == 0
        || atomic.max_snapshot_leases > 128
        || atomic.max_snapshot_lease_bytes == 0
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid atomic resource limits",
        ));
    }
    if limits.max_document_bytes == 0
        || limits.max_document_bytes > (1 << 20)
        || limits.max_batch_operations == 0
        || limits.max_batch_operations > 256
        || limits.max_batch_bytes < limits.max_document_bytes
        || limits.max_batch_bytes > (8 << 20)
        || limits.max_page_size == 0
        || limits.max_page_size > 1000
        || limits.cursor_ttl_ms == 0
        || limits.cursor_ttl_ms > 60_000
        || limits.max_query_candidates == 0
        || limits.max_result_bytes == 0
        || limits.max_result_bytes > (8 << 20)
        || limits.max_mutation_receipt_bytes == 0
        || limits.max_backup_binding_bytes == 0
        || limits.max_documents == 0
        || limits.max_logical_bytes == 0
        || limits.max_snapshot_bytes < 4096
        || limits.max_query_groups == 0
        || limits.max_cursor_bytes == 0
        || limits.max_cursors == 0
        || limits.max_collections == 0
        || limits.max_schema_bytes == 0
        || limits.max_retirement_bytes == 0
        || limits.max_target_resolution_bytes < TARGET_COMPLETION_RESERVE_BYTES
        || limits.max_schema_activation_bytes == 0
        || limits.max_policy_grants == 0
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid resource limits",
        ));
    }
    Ok(())
}

fn next_policy_epoch(epoch: u64) -> Result<u64> {
    epoch
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "policy generation exhausted"))
}

pub(super) fn validate_policy(policy: &Policy, limits: &Limits) -> Result<()> {
    if policy.grants.len() > limits.max_policy_grants {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "policy grant quota exceeded",
        ));
    }
    if !policy
        .grants
        .iter()
        .any(|g| g.collection.is_none() && g.actions.contains(&Action::Admin))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "tenant needs an administrator",
        ));
    }
    for grant in &policy.grants {
        validate_name(&grant.principal)?;
        if let Some(collection) = &grant.collection {
            validate_name(collection)?;
        }
        if grant.actions.is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "empty policy grant"));
        }
    }
    Ok(())
}

fn validate_metadata_budget(
    collections: &BTreeMap<String, CollectionState>,
    limits: &Limits,
) -> Result<()> {
    if collections.len() > limits.max_collections {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "collection quota exceeded",
        ));
    }
    let bytes = collections
        .values()
        .try_fold(0usize, |total, collection| -> Result<usize> {
            total
                .checked_add(encoded_len(&collection.definition)?)
                .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "schema size overflow"))
        })?;
    if bytes > limits.max_schema_bytes {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "schema and index definition quota exceeded",
        ));
    }
    Ok(())
}

/// Appends a hot event with its permanent stream position and exact encoded budget.
pub(crate) fn append_audit(state: &mut TenantState, event: AuditEvent) -> Result<()> {
    let bytes = encoded_len(&event)?;
    if bytes > MAX_AUDIT_EVENT_BYTES {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "audit event exceeds record budget",
        ));
    }
    let next = state
        .audit_retention
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "audit sequence exhausted"))?;
    let hot = state
        .audit_retention
        .hot_bytes
        .checked_add(bytes as u64)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "audit byte count overflow"))?;
    state.audits.push_back(event);
    state.audit_retention.next_sequence = next;
    state.audit_retention.hot_bytes = hot;
    Ok(())
}
fn validate_audits(state: &TenantState) -> Result<()> {
    state.audit_retention.validate()?;
    if !crate::accounting::audit_fits(state)
        || state.audit_retention.archive_bytes > state.limits.audit_retention.archive_bytes
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "audit history exceeds configured byte budgets",
        ));
    }
    let hot = state.audits.iter().try_fold(0u64, |total, event| {
        let bytes = encoded_len(event)?;
        if bytes > MAX_AUDIT_EVENT_BYTES {
            return Err(Error::new(
                ErrorCode::Corruption,
                "audit event exceeds record budget",
            ));
        }
        total
            .checked_add(bytes as u64)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "audit byte count overflow"))
    })?;
    if state
        .audit_retention
        .next_sequence
        .checked_sub(state.audit_retention.pruned_before)
        != Some(state.audits.len() as u64)
        || hot != state.audit_retention.hot_bytes
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "audit retention accounting differs",
        ));
    }
    Ok(())
}

fn terminal_error(error: anyhow::Error) -> Error {
    error
        .downcast_ref::<Error>()
        .cloned()
        .unwrap_or_else(|| Error::new(ErrorCode::Corruption, error.to_string()))
}

fn staged_command_key(command: &Command) -> Result<Option<String>> {
    let id = match &command.operation {
        Operation::BeginStaged(request) => &request.transaction_id,
        Operation::AppendStaged(request) => &request.transaction.transaction_id,
        Operation::FinalizeStaged(reference) => &reference.transaction_id,
        Operation::StopStaged(request) => &request.original.transaction_id,
        _ => return Ok(None),
    };
    Ok(Some(staging::identity(&command.context.principal, id)?))
}

#[cfg(test)]
mod first_release_command_tests {
    use super::*;

    #[test]
    fn committed_command_rejects_defaulted_old_shape_and_discarded_fields() {
        let command = Command {
            context: RequestContext {
                authorization: kasumi_types::RequestAuthorization::service_identity(),
                principal: "owner".into(),
                tenant: "tenant".into(),
                scopes: BTreeSet::from([Action::Admin]),
                request_id: "request".into(),
            },
            timestamp_ms: 1,
            operation: Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        };
        let encoded = serde_json::to_vec(&command).unwrap();
        assert!(decode_committed_command(&encoded).is_ok());
        let current = String::from_utf8(encoded).unwrap();
        for old in [
            current.replacen(",\"indexes\":[]", "", 1),
            current.replacen(",\"strict_read_audit\":false", "", 1),
        ] {
            assert_ne!(old, current);
            assert!(serde_json::from_slice::<Command>(old.as_bytes()).is_ok());
            assert!(decode_committed_command(old.as_bytes()).is_err());
        }
        let with_unknown = format!("{},\"obsolete\":true}}", &current[..current.len() - 1]);
        assert!(serde_json::from_str::<Command>(&with_unknown).is_ok());
        assert!(decode_committed_command(with_unknown.as_bytes()).is_err());
        assert!(decode_committed_command(format!(" {current} ").as_bytes()).is_err());
    }

    #[test]
    fn prefixed_recovery_replay_requires_exact_current_writer_bytes() {
        let command = recovery::RecoveryCommand {
            authorization: recovery::RecoveryAuthorization {
                context: RequestContext {
                    authorization: RequestAuthorization::service_identity(),
                    principal: "owner".into(),
                    tenant: "__kasumi_control".into(),
                    scopes: BTreeSet::from([Action::Admin]),
                    request_id: "request".into(),
                },
                policy_epoch: 1,
                admitted_at_ms: 2,
                expires_at_ms: 3,
            },
            mutation: recovery::RecoveryMutation::Stop {
                operation_id: uuid::Uuid::from_u128(1),
                command_id: uuid::Uuid::from_u128(2),
            },
        };
        let encoded = command.encode().unwrap();
        let payload = &encoded[recovery::PREFIX.len()..];
        assert!(decode_canonical_json::<recovery::RecoveryCommand>(payload).is_ok());
        let canonical = std::str::from_utf8(payload).unwrap();
        let reordered = format!(
            "{{\"mutation\":{},\"authorization\":{}}}",
            serde_json::to_string(&command.mutation).unwrap(),
            serde_json::to_string(&command.authorization).unwrap(),
        );
        assert!(serde_json::from_str::<recovery::RecoveryCommand>(&reordered).is_ok());
        assert!(decode_canonical_json::<recovery::RecoveryCommand>(reordered.as_bytes()).is_err());
        assert!(
            decode_canonical_json::<recovery::RecoveryCommand>(format!(" {canonical} ").as_bytes())
                .is_err()
        );
        let context = serde_json::to_string(&command.authorization.context).unwrap();
        let obsolete_context = format!("{},\"obsolete\":true}}", &context[..context.len() - 1]);
        let obsolete = canonical.replacen(&context, &obsolete_context, 1);
        assert_ne!(obsolete, canonical);
        assert!(decode_canonical_json::<recovery::RecoveryCommand>(obsolete.as_bytes()).is_err());
    }

    #[test]
    fn noncanonical_target_envelope_is_rejected_before_state_change() {
        let origin = crate::target_completion_machine::tests::origin();
        let node = &origin.materialization.request.target_nodes[&1];
        let authority_id = uuid::Uuid::from_u128(42);
        let manifest_sha256 = "66".repeat(32);
        let root_public_key = "aa".repeat(32);
        let signature = GenerationSignature {
            certificate: SigningCertificate {
                identity: SigningGeneration {
                    domain: SigningDomain {
                        authority_id,
                        partition: 0,
                        manifest_sha256: manifest_sha256.clone(),
                        root_public_key: root_public_key.clone(),
                        retirement_drain_ms: 100,
                    },
                    generation: 1,
                    public_key: "bb".repeat(32),
                },
                root_signature: "cc".repeat(64),
            },
            signature: "dd".repeat(64),
        };
        // The signed record has a complete wire shape. Noncanonical input
        // stops at replay decoding; the canonical arm below reaches input
        // validation, before authority verification.
        let grant = kasumi_serving::SignedLifecycleLease {
            claims: kasumi_serving::LifecycleLeaseClaims {
                request: kasumi_serving::LifecycleLeaseRequest {
                    authority_manifest_sha256: manifest_sha256.clone(),
                    reference: LifecycleAuthorityReference {
                        control_incarnation: origin.materialization.control_incarnation,
                        control_policy_epoch: 1,
                        identity: LifecycleAuthorityIdentity::Intent(
                            origin.materialization.request.command_id,
                        ),
                    },
                    intent_sha256: "ee".repeat(32),
                    target_node: NodeIdentity {
                        node_id: node.node_id,
                        verifier: node.verifier.clone(),
                        principal: node.principal.clone(),
                        certificate_sha256: node.certificate_sha256.clone(),
                    },
                    boot_id: uuid::Uuid::from_u128(43),
                    attempt_id: uuid::Uuid::from_u128(44),
                },
                commitment: ControlIntentCommitment {
                    intent: origin.materialization.clone(),
                    root: ControlSigningRoot {
                        control_incarnation: origin.materialization.control_incarnation,
                        public_key: root_public_key.clone(),
                    },
                    authority_partition: ControlAuthorityPartition {
                        authority_id,
                        manifest_sha256: manifest_sha256.clone(),
                        partition: 0,
                        signing_public_key: root_public_key.clone(),
                        maximum_lifetime_ms: 100,
                        drain_ms: 100,
                    },
                    partition_set_sha256: "ff".repeat(32),
                    observed_policy_epoch: 1,
                    observed_revision: 1,
                    observed_term: 1,
                },
                authority_id,
                partition: 0,
                authority_term: 1,
                authority_revision: 1,
                application_purpose: None,
                lifetime_ms: 100,
                credential_lifetime_ms: 100,
            },
            signature,
        };
        let command = target::TargetCommand::MaintainBudget {
            authorization: crate::target_invocation::PreparedTargetAuthorization {
                context: RequestContext {
                    authorization: RequestAuthorization::service_identity(),
                    principal: "owner".into(),
                    tenant: "__kasumi_control".into(),
                    scopes: BTreeSet::from([Action::Admin]),
                    request_id: "target-command".into(),
                },
                grant,
                admitted_at_ms: 2,
                dispatch_not_after_ms: 3,
            },
            input: TargetResolutionBudgetInput {
                operation_id: uuid::Uuid::from_u128(45),
                origin_sha256: origin.digest().unwrap(),
                expected_bytes: 1,
                maximum_bytes: 2,
            },
        };
        let canonical = command.encode().unwrap();
        let payload = &canonical[target::PREFIX.len()..];
        assert!(decode_canonical_json::<target::TargetCommand>(payload).is_ok());
        let mut noncanonical = target::PREFIX.to_vec();
        noncanonical.push(b' ');
        noncanonical.extend_from_slice(payload);
        assert!(
            serde_json::from_slice::<target::TargetCommand>(&noncanonical[target::PREFIX.len()..])
                .is_ok()
        );

        let engine = TenantEngine::new(
            origin.materialization.request.tenant.clone(),
            origin.input.target_incarnation.to_string(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let before = engine.generation().unwrap();
        let position = kasumi_raft::AppliedEntryContext {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            previous: None,
            membership: Default::default(),
            command_sha256: hex::encode(Sha256::digest(&noncanonical)),
            retirement_seed: None,
        };
        let Err(failure) = kasumi_raft::StateMachineBackend::apply_with_publisher(
            &engine,
            &position,
            kasumi_raft::AppliedInput::Command(&noncanonical),
            &mut crate::test_utils::CaptureApplyPublisher::default(),
        ) else {
            panic!("noncanonical target command was applied");
        };
        assert!(format!("{failure:#}").contains("noncanonical committed command"));
        let after = engine.generation().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.state.revision, 0);

        // The matching canonical prefix reaches the real target producer.
        // Its one/two-byte budgets fail input validation before installed
        // authority is checked. That deterministic rejection is published;
        // this does not claim signed target activation.
        let position = kasumi_raft::AppliedEntryContext {
            command_sha256: hex::encode(Sha256::digest(&canonical)),
            ..position
        };
        let response = crate::test_utils::capture_application(|publisher| {
            kasumi_raft::StateMachineBackend::apply_with_publisher(
                &engine,
                &position,
                kasumi_raft::AppliedInput::Command(&canonical),
                publisher,
            )
        })
        .unwrap();
        assert!(response.retirement.is_none());
        let outcome: Result<target::TargetOutcome> =
            serde_json::from_slice(&response.data).unwrap();
        let rejection = outcome.unwrap_err();
        assert_eq!(rejection.code, ErrorCode::InvalidArgument);
        assert_eq!(
            rejection.message,
            "target metadata budget cannot preserve an attempt terminal reserve"
        );
        let current = engine.generation().unwrap();
        assert_eq!(current.state.revision, 1);
        assert_eq!(before.state.revision, 0);
        assert!(current.state.target_lifecycle.is_empty());
        let event = current.state.audits.back().unwrap();
        assert_eq!(event.action, "target_resolution_budget");
        assert_eq!(event.outcome, "rejected");
    }
}

#[cfg(test)]
mod restore_budget_tests {
    use super::*;
    #[test]
    fn restored_identity_metadata_is_validated_before_bootstrap_persistence() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
        )
        .unwrap();
        let disk = &scratch.disk;
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "owner".into(),
            tenant: "tenant".into(),
            scopes: BTreeSet::from([Action::Admin, Action::Write]),
            request_id: "request".into(),
        };
        let policy = Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: false,
        };
        let engine = TenantEngine::new(
            "tenant".into(),
            "incarnation".into(),
            policy,
            Limits::default(),
        )
        .unwrap();
        let before_collection = disk.snapshot();
        engine
            .apply_command(
                disk,
                1,
                Command {
                    context: context.clone(),
                    timestamp_ms: 1,
                    operation: Operation::CreateCollection(CollectionDefinition {
                        retention_class: kasumi_types::CollectionRetentionClass::Operational,
                        write_mode: kasumi_types::CollectionWriteMode::Mutable,
                        name: "docs".into(),
                        schema: serde_json::json!({"type":"object"}),
                        indexes: vec![],
                        strict_read_audit: false,
                    }),
                },
            )
            .unwrap()
            .unwrap();
        let after_collection = disk.snapshot();
        assert_eq!(after_collection.live_files, before_collection.live_files);
        assert_eq!(
            after_collection.charged_bytes,
            before_collection.charged_bytes
        );
        assert_eq!(engine.generation().unwrap().terminals.head().count, 0);
        engine
            .apply_command(
                disk,
                2,
                Command {
                    context,
                    timestamp_ms: 2,
                    operation: Operation::Mutate(MutationBatch {
                        read_set: Vec::new(),
                        idempotency_key: "key".into(),
                        operations: vec![Mutation::Put {
                            collection: "docs".into(),
                            id: "id".into(),
                            body: serde_json::json!({"data":"x".repeat(4096)}),
                            expected: Precondition::Absent,
                        }],
                    }),
                },
            )
            .unwrap()
            .unwrap();
        let current = engine.generation().unwrap();
        let mut state = current.state.clone();
        // Keep the original resident-state budget; permanent receipts have a
        // separate bound, but the recoverable image must include their owner.
        state.limits.max_snapshot_bytes =
            crate::test_utils::encode_snapshot_candidate(disk, &state, 64 << 20)
                .unwrap()
                .len() as u64
                + 20;
        let source = engine
            .prepare_state(
                &CapturedValidation::capture(&engine).unwrap().baseline(),
                state,
                current.receipts.clone(),
                current.backup_bindings.clone(),
                current.terminals.clone(),
                current.target_resolutions.clone(),
            )
            .unwrap();
        let bytes = crate::test_utils::encode_snapshot_candidate(disk, &source, 64 << 20).unwrap();
        let checkpoint = FullBackupCheckpoint {
            tenant: source.state.tenant.clone(),
            source_incarnation: source.state.incarnation.clone(),
            revision: source.state.revision,
            resident_sha256: bytes.sha256().to_owned(),
            backup_id: uuid::Uuid::new_v4(),
            manifest_ciphertext_sha256: "00".repeat(32),
            key_lineage_digest: "00".repeat(32),
        };
        engine.restore_candidate(&bytes).unwrap(); // Source itself is a valid recoverable snapshot.
        // Both original handles protect the old receipt table through restore.
        // Their fixture work is now complete; the engine owns the restored table.
        drop(source);
        drop(current);
        let outcome = TenantEngine::restored_bootstrap(
            &bytes,
            "tenant",
            uuid::Uuid::new_v4().to_string(),
            checkpoint,
            None,
        );
        let original = outcome.unwrap_err();
        assert!(original.creation().is_none());
        assert!(original.source_error().is_none());
        assert_eq!(
            original.operation_error().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(engine.logical_snapshot(bytes.disk()).unwrap(), bytes);
    }
}

// The prototype's authority is constructed in the owning state module. Private
// fields prevent a caller from substituting another mutex or source registry.
#[cfg(test)]
pub(crate) struct PrimaryApplyGuard<'engine> {
    roots: &'engine crate::application_sources::SourceRootsRef,
    scope: [u8; 32],
    bootstrap: [u8; 32],
    _guard: PrimaryApplyLock<'engine>,
}
#[cfg(test)]
enum PrimaryApplyLock<'engine> {
    Owned(std::sync::MutexGuard<'engine, ()>),
    Borrowed(&'engine std::sync::MutexGuard<'engine, ()>),
}
#[cfg(test)]
impl PrimaryApplyLock<'_> {
    fn held(&self) -> &() {
        match self {
            Self::Owned(guard) => guard,
            Self::Borrowed(guard) => guard,
        }
    }
}
#[cfg(test)]
impl PrimaryApplyGuard<'_> {
    pub(crate) fn roots(&self) -> &crate::application_sources::SourceRootsRef {
        let _held = self._guard.held();
        self.roots
    }
    pub(crate) fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub(crate) fn bootstrap(&self) -> [u8; 32] {
        self.bootstrap
    }
}
#[cfg(test)]
impl TenantEngine {
    pub(crate) fn lock_primary_apply(&self) -> anyhow::Result<PrimaryApplyGuard<'_>> {
        use crate::primary_tree::records;
        use anyhow::Context as _;
        let guard = self
            .apply_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("application apply lock poisoned"))?;
        let roots = self
            .application_sources
            .get()
            .context("application sources not installed")?;
        let bootstrap = self
            .bootstrap_sha256
            .get()
            .context("authenticated application bootstrap absent")?;
        let digest = records::boundary::raw_digest(bootstrap)
            .map_err(|error| anyhow::anyhow!("primary record invalid: {error:?}"))?;
        let scope = records::scope_hash(&self.tenant, &self.incarnation, digest)
            .map_err(|error| anyhow::anyhow!("primary record invalid: {error:?}"))?;
        roots.primary_installation().0.check_access()?;
        Ok(PrimaryApplyGuard {
            roots,
            scope,
            bootstrap: digest,
            _guard: PrimaryApplyLock::Owned(guard),
        })
    }
}

#[cfg(test)]
impl TenantEngine {
    pub(crate) fn application_guard_available_for_test(&self) -> bool {
        self.apply_lock.try_lock().is_ok()
    }
    /// Manufactured Frozen-branch fixture only; confers no retirement authority.
    /// Return the prior owner too so its actual retained reservations stay alive.
    pub(crate) fn freeze_current_for_completion_test(
        &self,
    ) -> anyhow::Result<(Arc<Generation>, Arc<Generation>)> {
        let old = self.generation()?;
        let apply = ApplyOwner::lock(self, || anyhow::anyhow!("tenant apply lock poisoned"))?;
        anyhow::ensure!(
            std::ptr::eq(old.as_ref(), apply.current()),
            "completion fixture current owner changed before serialization"
        );
        let mut state = old.state.clone();
        state.retired = true;
        let selected = std::sync::OnceLock::new();
        if let Some(source) = old.application_selection.get() {
            assert!(selected.set(source.clone()).is_ok());
        }
        let frozen = Arc::new(Generation {
            state,
            receipts: old.receipts.clone(),
            backup_bindings: old.backup_bindings.clone(),
            terminals: old.terminals.clone(),
            target_resolutions: old.target_resolutions.clone(),
            indexes: old.indexes.clone(),
            snapshot_accounting: old.snapshot_accounting.clone(),
            application_selection: selected,
            _read_reservations: vec![],
        });
        self.publish_generation(Some(frozen.clone()));
        Ok((old, frozen))
    }
}
