#[path = "custody_snapshot.rs"]
mod custody_snapshot;
#[path = "snapshot_api.rs"]
mod snapshot_api;
#[path = "snapshot_bundle.rs"]
mod snapshot_bundle;
#[path = "snapshot_validation.rs"]
pub(crate) mod snapshot_validation;
use crate::accounting::{SnapshotAccounting, encoded_len};
use arc_swap::ArcSwapOption;
use kasumi_query::{QueryIndexes, check_unique, validate_collection, validate_document};
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
    pub(crate) terminals: crate::staged_terminal::View,
    pub(crate) target_resolutions: crate::target_resolution::View,
    pub indexes: Arc<QueryIndexes>,
    // Derived from snapshotted receipts; each command removes only expired
    // buckets instead of traversing every retained receipt on every write.
    receipt_expiry: ReceiptExpiry,
    snapshot_accounting: SnapshotAccounting,
    _read_reservations: Vec<crate::admission::Reservation>,
}
impl Generation {
    /// Share persistent document roots without retaining receipts, staging,
    /// audit history, or the previous generation of secondary/text indexes.
    pub(crate) fn lease_view(&self) -> Self {
        let mut state = crate::snapshot_codec::metadata(&self.state);
        state.collections = self.state.collections.clone();
        state.history_archives = self.state.history_archives.clone();
        Self {
            terminals: self.terminals.clone(),
            target_resolutions: self.target_resolutions.clone(),
            state,
            indexes: Arc::new(QueryIndexes::default()),
            receipt_expiry: ReceiptExpiry::new(),
            snapshot_accounting: SnapshotAccounting::default(),
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
            terminals: self.terminals.clone(),
            target_resolutions: self.target_resolutions.clone(),
            state,
            indexes: self.indexes.clone(),
            receipt_expiry: self.receipt_expiry.clone(),
            snapshot_accounting: self.snapshot_accounting.clone(),
            _read_reservations: reservations,
        }
    }
    pub(crate) fn snapshot_bytes(&self) -> Result<usize> {
        self.snapshot_accounting.bytes(&self.state)
    }
}
type ReceiptExpiry = imbl::OrdMap<u64, imbl::Vector<String>>;

/// Only ordered consensus application may publish generations.
pub struct TenantEngine {
    current: ArcSwapOption<Generation>,
    pub(crate) leases: lease_retention::LeaseManager,
    apply_lock: Mutex<()>,
    tenant: String,
    incarnation: String,
    revision_base: u64,
    restoration_identity: String,
    bootstrap_sha256: std::sync::OnceLock<String>,
    access: std::sync::OnceLock<kasumi_store::StorageAccess>,
    pub(crate) snapshot_store: std::sync::OnceLock<Arc<kasumi_store::TenantStore>>,
    pub(crate) audit_maintenance:
        Mutex<Option<Arc<crate::audit_maintenance::NodeAuditMaintenance>>>,
}

impl kasumi_raft::StateMachineBackend for TenantEngine {
    fn close_application(&self) {
        self.seal();
    }
    fn apply(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
    ) -> anyhow::Result<kasumi_raft::AppliedResponse> {
        if bytes.starts_with(recovery::PREFIX) {
            return self.apply_recovery(position, bytes);
        }
        if bytes.starts_with(target::PREFIX) {
            return self.apply_target(position, bytes);
        }
        if bytes.starts_with(tenant_audit::PREFIX) {
            return self.apply_audit_prune(position, bytes);
        }
        let command: Command = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            !matches!(&command.operation, Operation::RetireSource(prepared) if prepared.observation.is_some())
                || position.retirement_seed.is_some(),
            "prepared retirement is missing its custody seed"
        );
        if let Some(seed) = &position.retirement_seed {
            seed.reserve_success_capacity()?;
            let expected = kasumi_raft::RetirementLogSeed::prepare(
                &command,
                self.retirement_replay_state(&command)?,
            )?;
            anyhow::ensure!(
                expected.encoded()? == seed.encoded()?,
                "committed retirement seed differs from ordered source state"
            );
        }
        let revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .ok_or_else(|| anyhow::anyhow!("logical revision exhausted"))?;
        let reference = position
            .retirement_seed
            .as_ref()
            .map(|seed| seed.request().reference())
            .transpose()?;
        let actor = command.context.clone();
        let applied = crate::staged_terminal::AppliedIdentity::ordered(
            &self.incarnation,
            revision,
            command.timestamp_ms,
            position,
        )?;
        let outcome = self.apply_command_ordered(revision, command, applied)?;
        let retirement = if outcome.is_ok() {
            if let Some(reference) = reference {
                let generation = self.generation()?;
                Some(
                    retirement::lookup(&generation.state, &actor, &reference)?
                        .ok_or_else(|| anyhow::anyhow!("successful retirement outcome missing"))?
                        .outcome
                        .clone()?,
                )
            } else {
                None
            }
        } else {
            None
        };
        Ok(kasumi_raft::AppliedResponse {
            data: serde_json::to_vec(&outcome)?,
            retirement,
        })
    }
    fn capture_snapshot(&self) -> anyhow::Result<kasumi_raft::CapturedSnapshot> {
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
                snapshot_bundle::write(&generation, &store, writer)
            })
            .with_checkpoint_writes(move |context| {
                let mut writes = checkpoint_generation.terminals.checkpoint_writes(
                    &checkpoint_generation.state,
                    &context.checkpoint_sha256()?,
                )?;
                writes.extend(checkpoint_generation.target_resolutions.checkpoint_writes(
                    &checkpoint_generation.state,
                    &context.checkpoint_sha256()?,
                )?);
                Ok(writes)
            }),
        )
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> anyhow::Result<Option<kasumi_raft::RetiredSnapshotState>> {
        let generation = snapshot_bundle::read(self, bytes)?;
        custody_snapshot::retired(&generation.state).map_err(Into::into)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> anyhow::Result<Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>> {
        let guard = self
            .apply_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("tenant apply lock poisoned"))?;
        let mut generation = snapshot_bundle::read(self, bytes)?;
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
        let mut writes = installation.writes().to_vec();
        writes.extend_from_slice(target_installation.writes());
        let retirement = custody_snapshot::retired(&generation.state)?;
        Ok(Box::new(PreparedTenantRestore {
            engine: self,
            generation,
            installation,
            target_installation,
            writes,
            retirement,
            _apply_guard: guard,
        }))
    }
}

struct PreparedTenantRestore<'a> {
    engine: &'a TenantEngine,
    generation: Generation,
    installation: crate::staged_terminal::Installation,
    target_installation: crate::target_resolution::Installation,
    writes: Vec<kasumi_store::WriteOp>,
    retirement: Option<kasumi_raft::RetiredSnapshotState>,
    _apply_guard: std::sync::MutexGuard<'a, ()>,
}
impl kasumi_raft::PreparedStateMachineRestore for PreparedTenantRestore<'_> {
    fn retirement(&self) -> Option<kasumi_raft::RetiredSnapshotState> {
        self.retirement.clone()
    }
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)> {
        let mut replacements = self.installation.replacements();
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
            _apply_guard,
            ..
        } = *self;
        engine
            .snapshot_store
            .get()
            .ok_or_else(|| anyhow::anyhow!("snapshot storage not installed"))?
            .check_access()?;
        engine.leases.replace(&engine.current, Arc::new(generation));
        Ok(())
    }
}

impl TenantEngine {
    fn publish_generation(&self, next: Option<Arc<Generation>>) {
        self.leases.publish(&self.current, next);
    }

    pub(crate) fn check_operation_access(&self, operation: &Operation) -> Result<()> {
        let generation = self.generation()?;
        if generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .is_some_and(|target| target.activation.is_none())
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "native target activation must commit before tenant commands",
            ));
        }
        drop(generation);
        if let Some(access) = self.access.get() {
            access
                .check()
                .map_err(|_| Error::new(ErrorCode::Sealed, "independent access grant expired"))?;
            if access.check_serving().is_err() {
                let generation = self.generation()?;
                if generation
                    .state
                    .target_lifecycle
                    .contains_key(&generation.state.incarnation)
                    || !generation.state.suspended
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
        if self.generation().is_err() {
            self.seal();
            return Err(Error::new(
                ErrorCode::Sealed,
                "serving authority expired during materialization",
            ));
        }
        Ok(())
    }
    fn install_terminal_bootstrap(&self, store: &Arc<kasumi_store::TenantStore>) -> Result<()> {
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant apply lock poisoned"))?;
        let previous = self.generation()?;
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
            let image = self.logical_snapshot(store.scratch_disk())?;
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
        let checkpoint = staged_digest(&("kasumi.staged-terminal-bootstrap.v1", digest))?.0;
        let reopen = crate::staged_terminal::View::checkpoint_exists(store, &checkpoint)
            .map_err(terminal_error)?;
        let installation = previous
            .terminals
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let target_installation = previous
            .target_resolutions
            .prepare_install(store, &previous.state, &checkpoint, reopen)
            .map_err(terminal_error)?;
        let mut replacements = installation.replacements();
        replacements.extend(target_installation.replacements());
        let mut writes = installation.writes().to_vec();
        writes.extend_from_slice(target_installation.writes());
        store
            .replace_namespaces(&replacements, &writes)
            .map_err(terminal_error)?;
        drop(replacements);
        self.publish_generation(Some(Arc::new(Generation {
            state: previous.state.clone(),
            terminals: installation.view,
            target_resolutions: target_installation.view,
            indexes: previous.indexes.clone(),
            receipt_expiry: previous.receipt_expiry.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            _read_reservations: vec![],
        })));
        Ok(())
    }
    pub(crate) fn retirement_replay_state(
        &self,
        command: &Command,
    ) -> Result<kasumi_raft::RetirementReplayState> {
        let Operation::RetireSource(prepared) = &command.operation else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retirement replay state requires retirement",
            ));
        };
        let generation = self.generation()?;
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
            max_audit_hot_bytes: state.limits.audit_retention.hot_bytes,
            snapshot_bytes: generation.snapshot_bytes()? as u64,
            max_snapshot_bytes: state.limits.max_snapshot_bytes,
            staged_outcome_headroom: crate::accounting::staged_headroom(state)?,
        })
    }
    /// A tenant bootstrap is trusted control-plane input, identical on all replicas.
    pub fn new(
        tenant: String,
        incarnation: String,
        policy: Policy,
        limits: Limits,
    ) -> Result<Self> {
        validate_name(&tenant)?;
        validate_name(&incarnation)?;
        validate_limits(&limits)?;
        validate_policy(&policy, &limits)?;
        let state = TenantState {
            tenant: tenant.clone(),
            incarnation: incarnation.clone(),
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
            receipts: imbl::OrdMap::new(),
            staged_transactions: imbl::OrdMap::new(),
            active_staged_transactions: BTreeSet::new(),
            permanent_staged_bytes: 0,
            reserved_staged_terminal_bytes: 0,
            staged_terminal_head: StagedTerminalHead::empty(&tenant, &incarnation)?,
            target_resolution_head: TargetResolutionPrefixHead::empty(&tenant, &incarnation)?,
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
        let indexes = Arc::new(QueryIndexes::build(&state.collections)?);
        let snapshot_accounting = SnapshotAccounting::rebuild(&state)?;
        if !snapshot_accounting.fits(&state)? {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "bootstrap exceeds snapshot byte budget",
            ));
        }
        let restoration_identity =
            staged_digest(&(&state.restored_from, &state.restore_lineage))?.0;
        Ok(Self {
            restoration_identity,
            bootstrap_sha256: std::sync::OnceLock::new(),
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
                terminals: crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)
                    .map_err(terminal_error)?,
                state,
                indexes,
                receipt_expiry: ReceiptExpiry::new(),
                snapshot_accounting,
                _read_reservations: vec![],
            }),
            apply_lock: Mutex::new(()),
            tenant,
            incarnation,
            revision_base: 0,
        })
    }

    pub(crate) fn from_bootstrap(
        expected_tenant: &str,
        bytes: &kasumi_store::SnapshotImage,
    ) -> Result<Self> {
        let decoded = crate::snapshot_codec::read(bytes.disk(), &mut bytes.reader())
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid tenant bootstrap"))?;
        let engine = Self::from_bootstrap_state(expected_tenant, decoded)?;
        engine
            .bootstrap_sha256
            .set(bytes.sha256().into())
            .map_err(|_| Error::new(ErrorCode::Corruption, "duplicate bootstrap digest"))?;
        Ok(engine)
    }

    fn from_bootstrap_state(
        expected_tenant: &str,
        decoded: crate::snapshot_codec::Decoded,
    ) -> Result<Self> {
        let crate::snapshot_codec::Decoded {
            state,
            terminals,
            target_resolutions,
        } = decoded;
        if state.tenant != expected_tenant || state.revision != state.revision_base {
            return Err(Error::new(
                ErrorCode::Corruption,
                "tenant bootstrap identity or revision invalid",
            ));
        }
        let engine = Self {
            access: std::sync::OnceLock::new(),
            snapshot_store: std::sync::OnceLock::new(),
            audit_maintenance: Mutex::new(None),
            leases: lease_retention::LeaseManager::default(),
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            revision_base: state.revision_base,
            restoration_identity: staged_digest(&(&state.restored_from, &state.restore_lineage))?.0,
            bootstrap_sha256: std::sync::OnceLock::new(),
            apply_lock: Mutex::new(()),
            current: ArcSwapOption::empty(),
        };
        let generation = engine.prepare_state(state, terminals, target_resolutions)?;
        engine.publish_generation(Some(Arc::new(generation)));
        Ok(engine)
    }

    #[cfg(test)]
    pub(crate) fn restored_bootstrap(
        bytes: &kasumi_store::SnapshotImage,
        expected_tenant: &str,
        incarnation: String,
        checkpoint: FullBackupCheckpoint,
        target_origin: Option<TargetOrigin>,
    ) -> Result<kasumi_store::SnapshotImage> {
        let crate::snapshot_codec::Decoded {
            mut state,
            terminals,
            target_resolutions,
        } = crate::snapshot_codec::read(bytes.disk(), &mut bytes.reader())
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid logical backup"))?;
        if state.tenant != expected_tenant {
            return Err(Error::new(ErrorCode::Forbidden, "backup tenant mismatch"));
        }
        Self::verify_logical_snapshot(bytes, &state)?;
        Self::rebind_restored_state(&mut state, incarnation, checkpoint, target_origin)?;
        kasumi_store::SnapshotImage::capture(
            bytes.disk(),
            crate::target_resolution::snapshot_limit(&state)
                .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))?,
            |writer| crate::snapshot_codec::write(&state, &terminals, &target_resolutions, writer),
        )
        .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))
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
            state.target_completion_head = Some(TargetCompletionHead::empty(&origin)?);
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
    ) -> Result<(kasumi_store::SnapshotImage, Self)> {
        if source.header().tenant != expected_tenant {
            return Err(Error::new(ErrorCode::Forbidden, "backup tenant mismatch"));
        }
        let image = source.into_image();
        // Both encrypted point-table caches are now destroyed. Reserve the
        // actual target allocation before decoding, under the same owned job.
        handoff_workspace()?;
        let scratch_disk = image.disk().clone();
        let crate::snapshot_codec::Decoded {
            mut state,
            terminals,
            target_resolutions,
        } = crate::snapshot_codec::read(image.disk(), &mut image.reader())
            .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))?;
        drop(image);
        Self::rebind_restored_state(&mut state, incarnation, checkpoint, target_origin)?;
        let engine = Self::from_bootstrap_state(
            expected_tenant,
            crate::snapshot_codec::Decoded {
                state,
                terminals,
                target_resolutions,
            },
        )?;
        let image = engine.logical_snapshot(&scratch_disk)?;
        engine
            .bootstrap_sha256
            .set(image.sha256().into())
            .map_err(|_| Error::new(ErrorCode::Corruption, "duplicate target bootstrap digest"))?;
        Ok((image, engine))
    }

    pub fn generation(&self) -> Result<Arc<Generation>> {
        if let Some(access) = self.access.get() {
            access.check().map_err(|_| {
                Error::new(
                    ErrorCode::Sealed,
                    "independent serving authority unavailable",
                )
            })?;
        }
        self.current
            .load_full()
            .ok_or_else(|| Error::new(ErrorCode::Sealed, "tenant requires authorized recovery"))
    }

    /// A full logical backup can be captured at any committed revision. It is
    /// validated as a snapshot; only the later restored genesis must begin at
    /// its revision base.
    #[cfg(test)]
    pub(crate) fn verify_logical_snapshot(
        _bytes: &kasumi_store::SnapshotImage,
        state: &TenantState,
    ) -> Result<()> {
        let verifier = Self {
            access: std::sync::OnceLock::new(),
            snapshot_store: std::sync::OnceLock::new(),
            audit_maintenance: Mutex::new(None),
            leases: lease_retention::LeaseManager::default(),
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            revision_base: state.revision_base,
            restoration_identity: staged_digest(&(&state.restored_from, &state.restore_lineage))?.0,
            bootstrap_sha256: std::sync::OnceLock::new(),
            apply_lock: Mutex::new(()),
            current: ArcSwapOption::empty(),
        };
        let decoded = crate::snapshot_codec::read(_bytes.disk(), &mut _bytes.reader())
            .map_err(terminal_error)?;
        verifier.prepare_state(state.clone(), decoded.terminals, decoded.target_resolutions)?;
        Ok(())
    }

    /// Drop resident state under the apply fence. Already returned client data cannot be recalled.
    pub fn seal(&self) {
        let _guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    pub fn apply_command(&self, revision: u64, command: Command) -> Result<Result<WriteReceipt>> {
        if self
            .snapshot_store
            .get()
            .is_some_and(|store| !store.storage_access().purpose().is_local_fixture())
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "fixture application cannot mutate production storage",
            ));
        }
        let applied = crate::staged_terminal::AppliedIdentity {
            incarnation: self.incarnation.clone(),
            revision,
            timestamp_ms: command.timestamp_ms,
            command_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&command).map_err(
                |_| Error::new(ErrorCode::Corruption, "fixture command encoding failed"),
            )?)),
            origin: crate::staged_terminal::AppliedOrigin::Fixture,
        };
        self.apply_command_ordered(revision, command, applied)
    }
    fn apply_command_ordered(
        &self,
        revision: u64,
        command: Command,
        applied: crate::staged_terminal::AppliedIdentity,
    ) -> Result<Result<WriteReceipt>> {
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant apply lock poisoned"))?;
        let previous = self.generation()?;
        self.check_operation_access(&command.operation)?;
        if revision <= previous.state.revision {
            return Err(Error::new(
                ErrorCode::Corruption,
                "applied revision must increase",
            ));
        }
        if previous.state.retired {
            return Ok(Err(Error::new(
                ErrorCode::Sealed,
                "application state is permanently frozen after retirement",
            )));
        }
        let terminal_owner = previous.terminals.clone();
        #[cfg(any(test, feature = "test-utils"))]
        let terminal_owner = if matches!(
            applied.origin,
            crate::staged_terminal::AppliedOrigin::Fixture
        ) {
            terminal_owner
                .fixture_owner(&previous.state)
                .map_err(terminal_error)?
        } else {
            terminal_owner
        };
        let mut next = previous.state.clone();
        let mut receipt_expiry = previous.receipt_expiry.clone();
        let mut changed_receipts = BTreeSet::new();
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
            if let Some(key) = staged_command_key(&command)?
                && !next.staged_transactions.contains_key(&key)
                && let Some(row) = terminal_owner.get(&key).map_err(terminal_error)?
            {
                row.validate(&previous.state).map_err(terminal_error)?;
                next.staged_transactions.insert(key, row.stage);
            }
            apply_operation(
                &mut next,
                &command,
                revision,
                previous.state.revision,
                &previous.indexes,
                &mut receipt_expiry,
                &mut changed_receipts,
            )
        };
        let (outcome, changed_documents) = match result {
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
            )?;
        }
        if next.audit_retention.hot_bytes > next.limits.audit_retention.hot_bytes {
            let mut rejected = previous.state.clone();
            rejected.revision = revision;
            self.publish_generation(Some(Arc::new(Generation {
                terminals: previous.terminals.clone(),
                target_resolutions: previous.target_resolutions.clone(),
                state: rejected,
                indexes: previous.indexes.clone(),
                receipt_expiry: previous.receipt_expiry.clone(),
                snapshot_accounting: previous.snapshot_accounting.clone(),
                _read_reservations: vec![],
            })));
            return Ok(Err(Error::new(
                ErrorCode::AuditUnavailable,
                "hot audit byte budget exhausted",
            )));
        }
        let terminal_pending = crate::staged_terminal::Pending::prepare(
            &terminal_owner,
            &previous.state,
            &mut next,
            &applied,
        )
        .map_err(terminal_error)?;
        if let Err(error) = staging::validate_budget(&next, &next.limits) {
            return self.reject_resource_budget(
                &previous,
                next,
                &command,
                receipt_expiry,
                &changed_receipts,
                Some(error),
                &applied,
                &terminal_pending,
                &terminal_owner,
            );
        }
        let changed = if changed_documents {
            operation_changes(&previous.state, &command)?
        } else {
            BTreeMap::new()
        };
        if changed_documents
            && !matches!(command.operation, Operation::PublishHistoryArchive(_))
            && let Err(error) =
                crate::change_feed_state::append(&previous.state, &mut next, &changed)
        {
            return self.reject_resource_budget(
                &previous,
                next,
                &command,
                receipt_expiry,
                &changed_receipts,
                Some(error),
                &applied,
                &terminal_pending,
                &terminal_owner,
            );
        }
        let snapshot_accounting = previous.snapshot_accounting.updated(
            &previous.state,
            &next,
            &changed,
            &changed_receipts,
            &staged_changes(&previous.state, &command)?,
        )?;
        if !snapshot_accounting.fits(&next)? || !lifecycle::completion_fits(&next)? {
            return self.reject_resource_budget(
                &previous,
                next,
                &command,
                receipt_expiry,
                &changed_receipts,
                None,
                &applied,
                &terminal_pending,
                &terminal_owner,
            );
        }
        let indexes = if changed_documents
            && !matches!(command.operation, Operation::PublishHistoryArchive(_))
        {
            Arc::new(previous.indexes.update(
                &previous.state.collections,
                &next.collections,
                &changed,
            )?)
        } else {
            previous.indexes.clone()
        };
        let terminals = terminal_pending.persist().map_err(terminal_error)?;
        self.publish_generation(Some(Arc::new(Generation {
            target_resolutions: previous.target_resolutions.clone(),
            terminals,
            state: next,
            indexes,
            receipt_expiry,
            snapshot_accounting,
            _read_reservations: vec![],
        })));
        Ok(outcome)
    }

    fn reject_resource_budget(
        &self,
        previous: &Generation,
        next: TenantState,
        command: &Command,
        receipt_expiry: ReceiptExpiry,
        changed_receipts: &BTreeSet<String>,
        failure: Option<Error>,
        applied: &crate::staged_terminal::AppliedIdentity,
        terminal_pending: &crate::staged_terminal::Pending,
        terminal_owner: &crate::staged_terminal::View,
    ) -> Result<Result<WriteReceipt>> {
        let revision = next.revision;
        let receipt_key = if let Operation::Mutate(batch) = &command.operation {
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&(&command.context.principal, &batch.idempotency_key)).map_err(
                    |_| Error::new(ErrorCode::Corruption, "receipt identity encoding failed"),
                )?,
            )))
        } else {
            None
        };
        let replay = receipt_key.as_ref().is_some_and(|key| {
            !changed_receipts.contains(key)
                && previous
                    .state
                    .receipts
                    .get(key)
                    .is_some_and(|receipt| receipt.expires_at_ms > command.timestamp_ms)
        });
        let error = failure.unwrap_or_else(|| {
            Error::new(
                if replay {
                    ErrorCode::AuditUnavailable
                } else {
                    ErrorCode::QuotaExceeded
                },
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
            schema::reject_budget(&previous.state, &next, &mut rejected, command, &error)?;
            retirement::reject_budget(&previous.state, &next, &mut rejected, command, &error)?;
            if let Operation::FinalizeStaged(reference) = &command.operation {
                let key =
                    staged_digest(&(&command.context.principal, &reference.transaction_id))?.0;
                if previous
                    .state
                    .staged_transactions
                    .get(&key)
                    .is_some_and(StagedTransaction::is_active)
                    && let Some(completed) = terminal_pending.get(&key).map_err(terminal_error)?
                    && !completed.is_active()
                {
                    let mut completed = completed.clone();
                    completed.outcome = StagedOutcome::Finished {
                        outcome: Err(error.clone()),
                    };
                    staging::replace_record(&mut rejected, key, completed)?;
                }
            }
            if let Some(key) = &receipt_key {
                // Preserve expiry cleanup and record this failed attempt when its
                // bounded receipt fits; never overwrite a prior idempotent result.
                rejected.receipts = next.receipts.clone();
                if changed_receipts.contains(key)
                    && let Some(receipt) = rejected.receipts.get_mut(key)
                {
                    receipt.outcome = Err(error.clone());
                }
            }
            let mut event = next
                .audits
                .back()
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "required audit missing"))?
                .clone();
            event.outcome = "rejected".into();
            append_audit(&mut rejected, event)?;
            let rejected_terminals = crate::staged_terminal::Pending::prepare(
                terminal_owner,
                &previous.state,
                &mut rejected,
                applied,
            )
            .map_err(terminal_error)?;
            let accounting = previous.snapshot_accounting.updated(
                &previous.state,
                &rejected,
                &BTreeMap::new(),
                changed_receipts,
                &staged_changes(&previous.state, command)?,
            )?;
            if rejected.audit_retention.hot_bytes <= rejected.limits.audit_retention.hot_bytes
                && accounting.fits(&rejected)?
                && lifecycle::completion_fits(&rejected)?
            {
                let terminals = rejected_terminals.persist().map_err(terminal_error)?;
                self.publish_generation(Some(Arc::new(Generation {
                    target_resolutions: previous.target_resolutions.clone(),
                    terminals,
                    state: rejected,
                    indexes: previous.indexes.clone(),
                    receipt_expiry,
                    snapshot_accounting: accounting,
                    _read_reservations: vec![],
                })));
                return Ok(Err(error));
            }
        }
        // Required audit/receipt storage is exhausted. Nothing from the command
        // takes effect. The revision-only cursor fits its pre-reserved headroom.
        let mut rejected = previous.state.clone();
        rejected.revision = revision;
        self.publish_generation(Some(Arc::new(Generation {
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            state: rejected,
            indexes: previous.indexes.clone(),
            receipt_expiry: previous.receipt_expiry.clone(),
            snapshot_accounting: previous.snapshot_accounting.clone(),
            _read_reservations: vec![],
        })));
        Ok(Err(Error::new(
            ErrorCode::AuditUnavailable,
            "required audit cannot fit serialized tenant budget",
        )))
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
        kasumi_store::SnapshotImage::capture(
            scratch_disk,
            crate::target_resolution::snapshot_limit(&generation.state)
                .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))?,
            |writer| Ok(Self::write_generation(&generation, writer)?),
        )
        .map_err(|e| Error::new(ErrorCode::Corruption, e.to_string()))
    }

    pub fn snapshot_bytes(&self) -> Result<usize> {
        let generation = self.generation()?;
        generation.snapshot_accounting.bytes(&generation.state)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn restore_candidate(&self, bytes: &kasumi_store::SnapshotImage) -> Result<()> {
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant apply lock poisoned"))?;
        let generation = self.prepare_snapshot_reader(bytes.disk(), &mut bytes.reader())?;
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
        disk: &Arc<kasumi_store::ScratchDisk>,
        reader: &mut dyn std::io::Read,
    ) -> Result<Generation> {
        let crate::snapshot_codec::Decoded {
            state,
            terminals,
            target_resolutions,
        } = crate::snapshot_codec::read(disk, reader)
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid tenant snapshot"))?;
        self.prepare_state(state, terminals, target_resolutions)
    }

    fn prepare_state(
        &self,
        state: TenantState,
        terminals: crate::staged_terminal::View,
        target_resolutions: crate::target_resolution::View,
    ) -> Result<Generation> {
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
        if let Ok(current) = self.generation() {
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
        if let Ok(current) = self.generation() {
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
        if let Ok(current) = self.generation()
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
        if let Ok(current) = self.generation()
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
            validate_collection(&collection.definition, &collection.documents)?;
            check_unique(collection)?;
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
            || state.receipts.len() > state.limits.max_receipts
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
        if let Ok(current) = self.generation() {
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
        if let Ok(current) = self.generation() {
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
        for (key, receipt) in &state.receipts {
            let maximum_revision = if receipt.scope.incarnation == state.incarnation {
                state.revision
            } else {
                state
                    .restore_lineage
                    .iter()
                    .find(|link| link.checkpoint.source_incarnation == receipt.scope.incarnation)
                    .map(|link| link.checkpoint.revision)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::Corruption,
                            "receipt original incarnation is absent from lineage",
                        )
                    })?
            };
            let genesis_revision = if receipt.scope.incarnation == state.incarnation {
                state.revision_base
            } else {
                state
                    .restore_lineage
                    .iter()
                    .find(|link| link.target_incarnation == receipt.scope.incarnation)
                    .map(|link| {
                        link.checkpoint.revision.checked_add(1).ok_or_else(|| {
                            Error::new(ErrorCode::Corruption, "receipt genesis revision overflow")
                        })
                    })
                    .transpose()?
                    .unwrap_or(0)
            };
            receipt.validate_identity(key, &state.tenant, genesis_revision, maximum_revision)?;
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
        let indexes = Arc::new(QueryIndexes::build(&state.collections)?);
        let mut receipt_expiry = ReceiptExpiry::new();
        for (key, receipt) in &state.receipts {
            receipt_expiry
                .entry(receipt.expires_at_ms)
                .or_default()
                .push_back(key.clone());
        }
        Ok(Generation {
            terminals,
            target_resolutions,
            state,
            indexes,
            receipt_expiry,
            snapshot_accounting,
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
    receipt_expiry: &mut ReceiptExpiry,
    changed_receipts: &mut BTreeSet<String>,
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
        Operation::Mutate(batch) => {
            for mutation in &batch.operations {
                authorize_state(
                    state,
                    &command.context,
                    Some(mutation.target().0),
                    Action::Write,
                )?;
            }
            for assertion in &batch.read_set {
                if let ReadAssertion::Document { collection, .. }
                | ReadAssertion::Collection { collection, .. } = assertion
                {
                    authorize_state(state, &command.context, Some(collection), Action::Read)?;
                }
            }
            if batch.operations.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "empty mutation batch",
                ));
            }
            validate_name(&batch.idempotency_key)?;
            let identity =
                serde_json::to_vec(&(&command.context.principal, &batch.idempotency_key)).map_err(
                    |_| Error::new(ErrorCode::InvalidArgument, "invalid receipt identity"),
                )?;
            let receipt_key = hex::encode(Sha256::digest(identity));
            let digest = batch.digest()?;
            if let Some(existing) = state
                .receipts
                .get(&receipt_key)
                .filter(|r| r.expires_at_ms > command.timestamp_ms)
            {
                if existing.request_digest != digest {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "idempotency key reused for different input",
                    ));
                }
                return Ok((existing.outcome.clone(), false));
            }
            while let Some(expires) = receipt_expiry.get_min().map(|(expires, _)| *expires) {
                if expires > command.timestamp_ms {
                    break;
                }
                let keys = receipt_expiry
                    .remove(&expires)
                    .expect("expiry bucket exists");
                for key in &keys {
                    if state
                        .receipts
                        .get(key)
                        .is_some_and(|receipt| receipt.expires_at_ms == expires)
                    {
                        state.receipts.remove(key);
                        changed_receipts.insert(key.clone());
                    }
                }
            }
            if state.receipts.len() >= state.limits.max_receipts {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "receipt retention budget exhausted",
                ));
            }
            let mut staged = state.clone();
            let outcome = apply_batch(&mut staged, batch, revision, command.timestamp_ms).and_then(
                |receipt| {
                    indexes.validate_unique_changes(
                        &state.collections,
                        &staged.collections,
                        &batch_changes(batch),
                    )?;
                    Ok(receipt)
                },
            );
            if outcome.is_ok() {
                *state = staged;
            }
            let expires_at_ms = command
                .timestamp_ms
                .saturating_add(state.limits.receipt_ttl_ms);
            receipt_expiry
                .entry(expires_at_ms)
                .or_default()
                .push_back(receipt_key.clone());
            changed_receipts.insert(receipt_key.clone());
            state.receipts.insert(
                receipt_key,
                StoredReceipt {
                    scope: MutationReceiptScope {
                        tenant: state.tenant.clone(),
                        incarnation: state.incarnation.clone(),
                        principal: command.context.principal.clone(),
                    },
                    idempotency_key: batch.idempotency_key.clone(),
                    recorded_revision: revision,
                    request_digest: digest,
                    expires_at_ms,
                    collections: batch
                        .operations
                        .iter()
                        .map(|op| op.target().0.to_owned())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    outcome: outcome.clone(),
                },
            );
            let changed = outcome.is_ok();
            Ok((outcome, changed))
        }
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
                || state.receipts.len() > limits.max_receipts
                || state.history_archives.len() > limits.history.max_archive_segments
                || state.audit_retention.hot_bytes > limits.audit_retention.hot_bytes
                || state.audit_retention.archive_bytes > limits.audit_retention.archive_bytes
            {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "new limits are below retained state",
                ));
            }
            state.limits = limits.clone();
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
                "schema_activation_status" | "schema_read" => Action::Admin,
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
    apply_mutations(
        state,
        &batch.operations.iter().collect::<Vec<_>>(),
        revision,
        true,
    )
}

fn apply_mutations(
    state: &mut TenantState,
    operations: &[&Mutation],
    revision: u64,
    include_versions: bool,
) -> Result<WriteReceipt> {
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
        match mutation {
            Mutation::Put { body, .. } => {
                let bytes = encoded_len(body)?;
                if bytes > state.limits.max_document_bytes {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "document exceeds byte limit",
                    ));
                }
                validate_document(&collection.definition, body)?;
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
                        body: body.clone(),
                    }),
                );
                collection.data_epoch = revision;
                if include_versions {
                    versions.insert(document_path(name, id), revision);
                }
            }
            Mutation::Delete { .. } => {
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

fn validate_read_assertions(
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

fn validate_limits(limits: &Limits) -> Result<()> {
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
        || limits.receipt_ttl_ms != 86_400_000
        || limits.max_query_candidates == 0
        || limits.max_result_bytes == 0
        || limits.max_result_bytes > (8 << 20)
        || limits.max_receipts == 0
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

fn validate_policy(policy: &Policy, limits: &Limits) -> Result<()> {
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
    if state.audit_retention.hot_bytes > state.limits.audit_retention.hot_bytes
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

#[cfg(test)]
mod restore_budget_tests {
    use super::*;
    #[test]
    fn restored_identity_metadata_is_validated_before_bootstrap_persistence() {
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
        engine
            .apply_command(
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
        engine
            .apply_command(
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
        let mut source = engine.generation().unwrap().state.clone();
        source.limits.max_snapshot_bytes =
            crate::test_utils::encode_snapshot_candidate(&source, 64 << 20)
                .unwrap()
                .len() as u64
                + 20;
        let bytes = crate::test_utils::encode_snapshot_candidate(&source, 64 << 20).unwrap();
        engine.restore_candidate(&bytes).unwrap(); // Source itself is a valid recoverable snapshot.
        let outcome = TenantEngine::restored_bootstrap(
            &bytes,
            "tenant",
            uuid::Uuid::new_v4().to_string(),
            FullBackupCheckpoint {
                tenant: source.tenant.clone(),
                source_incarnation: source.incarnation.clone(),
                revision: source.revision,
                resident_sha256: bytes.sha256().to_owned(),
                backup_id: uuid::Uuid::new_v4(),
                manifest_ciphertext_sha256: "00".repeat(32),
                key_lineage_digest: "00".repeat(32),
            },
            None,
        );
        assert_eq!(outcome.unwrap_err().code, ErrorCode::QuotaExceeded);
        assert_eq!(engine.logical_snapshot(bytes.disk()).unwrap(), bytes);
    }
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
