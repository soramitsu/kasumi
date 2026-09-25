//! Independently encrypted target metadata. A terminal stop is stored before
//! local owners are drained; it never claims that physical cleanup has finished.
use crate::TargetOperation;
use anyhow::{Context, Result, ensure};
use kasumi_serving::{NodeIdentity, VerifiedTargetStop};
use kasumi_store::{TenantStore, WriteOp};
use kasumi_types::TargetJournalLimits;
use kasumi_types::{
    ControlAuthorityPartition, ControlSigningRoot, LifecycleIntent, LifecyclePhase,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
const NS: &str = "target.journal";
#[cfg(test)]
#[path = "target_journal_open_tests.rs"]
mod open_tests;
const MAX_RECORD: usize = 256 << 10;
const COMPLETION_RESERVE: u64 = MAX_RECORD as u64;
// Each generation independently reserves a stop and an activation projection.
const GENERATION_RESERVE: u64 = COMPLETION_RESERVE * 2;
// Every accepted first-membership dispatch precharges one bounded future fact.
const DISPATCH_TERMINAL_RESERVE: u64 = MAX_RECORD as u64;
// One immutable Start observation or Initialize association and one membership observation share
// this original reservation. Neither may consume the other's half.
const DISPATCH_OBSERVATION_LIMIT: usize = MAX_RECORD / 2;
#[path = "target_journal_dispatch.rs"]
mod dispatch;
#[path = "target_journal_start.rs"]
mod initial_start;
pub use dispatch::{
    AcceptedInitialDispatchPrebind, InitialDispatchReservation, InitialDispatchStatus,
    InitialInitializePermit, ResolvedInitialMembershipHistory, VerifiedInitialMembership,
};
pub use initial_start::ResolvedInitialStart;
#[path = "target_projection.rs"]
mod projection;
pub use projection::VerifiedTargetServingProjection;

/// A format-4 journal record is the exact current writer's JSON bytes. This
/// streaming comparison avoids allocating another record during bounded reopen.
fn decode_current<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    struct Compare<'a>(&'a [u8]);
    impl Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.0.starts_with(bytes) {
                return Err(io::Error::other("noncanonical target journal record"));
            }
            self.0 = &self.0[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let value: T = serde_json::from_slice(bytes)?;
    let mut compare = Compare(bytes);
    serde_json::to_writer(&mut compare, &value)?;
    ensure!(compare.0.is_empty(), "noncanonical target journal record");
    Ok(value)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetJournalInstallation {
    pub root: ControlSigningRoot,
    pub node: NodeIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetJournalIntent {
    intent: LifecycleIntent,
    authority_partition: ControlAuthorityPartition,
    partition_set_sha256: String,
    node: NodeIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetJournalStop {
    intent: TargetJournalIntent,
    stopped: kasumi_serving::SignedTargetStop,
    authority: kasumi_serving::AuthorityManifest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationBinding {
    tenant: String,
    source_incarnation: Uuid,
    source_epoch: u64,
    target_incarnation: Uuid,
    checkpoint: kasumi_types::FullBackupCheckpoint,
    nodes: std::collections::BTreeMap<u64, kasumi_types::LifecycleNode>,
    control_incarnation: Uuid,
    partition: ControlAuthorityPartition,
}
impl GenerationBinding {
    fn from_intent(i: &TargetJournalIntent) -> Self {
        let r = &i.intent.request;
        Self {
            tenant: r.tenant.clone(),
            source_incarnation: r.source_incarnation,
            source_epoch: r.source_authority_epoch,
            target_incarnation: r.target_incarnation,
            checkpoint: r.checkpoint.clone(),
            nodes: r.target_nodes.clone(),
            control_incarnation: i.intent.control_incarnation,
            partition: i.authority_partition.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCreation {
    materialization_command_id: Uuid,
}

/// One journal-selected file operation. Only the first durably accepted
/// original materialization may create; replay always requires a ready file.
/// An uncertain commit or lost creation response never becomes a new creator.
pub struct MaterializationFile {
    operation: TargetOperation,
    persistent_disk: Arc<kasumi_store::NodeDisk>,
    node_store_id: Uuid,
    create: bool,
}
/// The catalog action follows this original journal decision, never a disk
/// existence probe. Replayed file reservations always return `Existing`.
pub enum MaterializationNode {
    Created(Arc<kasumi_store::NodeStore>),
    Existing(Arc<kasumi_store::NodeStore>),
}
impl MaterializationFile {
    pub fn open(
        self,
        path: &std::path::Path,
        scratch: Arc<kasumi_store::ScratchDisk>,
    ) -> Result<MaterializationNode> {
        self.operation.check()?;
        let node = if self.create {
            kasumi_store::NodeStore::create_new(
                path,
                self.node_store_id,
                self.persistent_disk.clone(),
                scratch,
            )
        } else {
            kasumi_store::NodeStore::open_existing(
                path,
                self.node_store_id,
                self.persistent_disk.clone(),
                scratch,
            )
        }
        .map_err(journal_unknown)?;
        // The runtime must first retain this physical owner, then recheck the
        // operation before starting catalog work. A failed post-open fence here
        // would discard the only explicit-close owner of the new file.
        Ok(if self.create {
            MaterializationNode::Created(node)
        } else {
            MaterializationNode::Existing(node)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: u32,
    installation: TargetJournalInstallation,
    intents: u64,
    generations: u64,
    dispatches: u64,
    dispatch_terminals: u64,
    dispatch_starts: u64,
    dispatch_initializes: u64,
    charged_bytes: u64,
}
/// The unique store catalog owns the mutation lock; runtime retains this one
/// journal handle. No application provider is constructed by opening it.
pub struct TargetJournal {
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    limits: TargetJournalLimits,
    admission: Arc<crate::admission::NodeAdmission>,
    mutation: Mutex<()>,
}
type JournalOwner = Arc<Mutex<std::sync::Weak<TargetJournal>>>;

impl TargetJournal {
    /// The installed runner must first close and drain its operations. Retained
    /// journal handles remain sealed after this store's own workers are joined.
    pub async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        self.store.shutdown().await
    }

    /// Explicit journal installation. Existing metadata or a live owner is an
    /// error; this operation cannot reset permanent target stops.
    pub fn create_new(
        store: Arc<TenantStore>,
        installed: TargetJournalInstallation,
        limits: TargetJournalLimits,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(store, installed, limits, admission, true)
    }

    /// Reopen only an authenticated installed journal, including an empty one.
    /// An absent head is corruption and never permission to create a new head.
    pub fn open_existing(
        store: Arc<TenantStore>,
        installed: TargetJournalInstallation,
        limits: TargetJournalLimits,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(store, installed, limits, admission, false)
    }

    fn open_inner(
        store: Arc<TenantStore>,
        installed: TargetJournalInstallation,
        limits: TargetJournalLimits,
        admission: Arc<crate::admission::NodeAdmission>,
        create: bool,
    ) -> Result<Arc<Self>> {
        admission.memory().require_store_memory(&store)?;
        let gate = Self::owner_gate(&store)?;
        Self::open_with_owner(store, installed, limits, admission, create, &gate)
    }

    fn owner_gate(store: &Arc<TenantStore>) -> Result<JournalOwner> {
        static OWNERS: std::sync::OnceLock<Mutex<std::collections::HashMap<usize, JournalOwner>>> =
            std::sync::OnceLock::new();
        let mut owners = OWNERS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal owner registry poisoned"))?;
        owners.retain(|_, owner| {
            // An opener owns its cloned gate before locking it. Pruning that
            // handoff would let another opener publish a second mutation lock.
            Arc::strong_count(owner) > 1
                || owner.try_lock().map_or(true, |old| old.strong_count() > 0)
        });
        Ok(owners
            .entry(Arc::as_ptr(store) as usize)
            .or_default()
            .clone())
    }

    fn open_with_owner(
        store: Arc<TenantStore>,
        installed: TargetJournalInstallation,
        limits: TargetJournalLimits,
        admission: Arc<crate::admission::NodeAdmission>,
        create: bool,
        gate: &JournalOwner,
    ) -> Result<Arc<Self>> {
        let mut owner = gate
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal owner poisoned"))?;
        if let Some(existing) = owner.upgrade() {
            ensure!(!create, "target journal is already installed");
            existing.metadata()?;
            ensure!(
                existing.installed == installed
                    && existing.limits == limits
                    && Arc::ptr_eq(&existing.admission, &admission),
                "live target journal installation differs"
            );
            existing.store.check_access()?;
            return Ok(existing);
        }
        let _workspace = admission.reserve((MAX_RECORD * 8) as u64, None)?;
        installed.root.validate()?;
        installed.node.validate()?;
        limits.validate()?;
        ensure!(
            matches!(store.storage_access().purpose(), kasumi_store::StoragePurpose::TargetJournal {control_root,node}
            if *control_root==installed.root && *node==installed.node),
            "independent target journal storage identity differs"
        );
        let journal = Arc::new(Self {
            store,
            installed,
            limits,
            admission,
            mutation: Mutex::new(()),
        });
        let installed_head = journal.store.get_bounded(NS, b"metadata", MAX_RECORD)?;
        if create {
            ensure!(
                installed_head.is_none(),
                "target journal is already installed"
            );
            // An absent head cannot initialize over retained records or an
            // unsupported journal. Reject before writing any replacement head.
            journal.store.visit(NS, MAX_RECORD, |_, _| {
                anyhow::bail!("target journal records exist without a canonical head")
            })?;
            let metadata = Metadata {
                format: 4,
                installation: journal.installed.clone(),
                intents: 0,
                generations: 0,
                dispatches: 0,
                dispatch_terminals: 0,
                dispatch_starts: 0,
                dispatch_initializes: 0,
                charged_bytes: MAX_RECORD as u64,
            };
            journal.store.write_batch(&[WriteOp::put(
                NS,
                b"metadata",
                serde_json::to_vec(&metadata)?,
            )])?;
        }
        let metadata = journal.metadata()?;
        // Streaming startup verification retains one bounded encrypted record at
        // a time. Permanent identities are never silently dropped or truncated.
        let mut intents = 0u64;
        let mut generations = 0u64;
        let mut dispatches = 0u64;
        let mut dispatch_terminals = 0u64;
        let mut dispatch_starts = 0u64;
        let mut dispatch_initializes = 0u64;
        let mut charged = MAX_RECORD as u64;
        journal.store.visit(NS, MAX_RECORD, |key, value| {
            if key.starts_with(b"intent/") {
                intents = intents.checked_add(1).context("journal count exhausted")?;
                let i: TargetJournalIntent = decode_current(value)?;
                journal.validate_intent(&i)?;
                ensure!(
                    key == intent_key(i.intent.request.command_id),
                    "journal intent key differs"
                );
                charged = charged
                    .checked_add(value.len() as u64 + COMPLETION_RESERVE)
                    .context("journal bytes exhausted")?;
            } else if key.starts_with(b"generation/") {
                generations = generations
                    .checked_add(1)
                    .context("journal count exhausted")?;
                let target: GenerationBinding = decode_current(value)?;
                ensure!(
                    key == generation_key(&target.tenant, target.target_incarnation),
                    "journal generation key differs"
                );
                charged = charged
                    .checked_add(value.len() as u64 + GENERATION_RESERVE)
                    .context("journal bytes exhausted")?;
            } else if key.starts_with(b"dispatch/") {
                dispatches = dispatches
                    .checked_add(1)
                    .context("journal dispatch count exhausted")?;
                journal.validate_dispatch_record(key, value)?;
                charged = charged
                    .checked_add(value.len() as u64 + DISPATCH_TERMINAL_RESERVE)
                    .context("journal dispatch bytes exhausted")?;
            } else if key.starts_with(b"file/") {
                let file: FileCreation = decode_current(value)?;
                journal.validate_file_creation(key, &file)?;
                charged = charged
                    .checked_add(value.len() as u64)
                    .context("journal file bytes exhausted")?;
            } else if key.starts_with(b"dispatch-terminal/") {
                dispatch_terminals = dispatch_terminals
                    .checked_add(1)
                    .context("journal dispatch terminal count exhausted")?;
                journal.validate_dispatch_terminal(key, value)?;
                // Its original dispatch already charged the full bounded
                // terminal reserve; publication never needs more capacity.
            } else if key.starts_with(b"dispatch-start/") {
                dispatch_starts = dispatch_starts
                    .checked_add(1)
                    .context("journal Start observation count exhausted")?;
                journal.validate_initial_start_record(key, value)?;
            } else if key.starts_with(b"dispatch-initialize/") {
                dispatch_initializes = dispatch_initializes
                    .checked_add(1)
                    .context("journal Initialize association count exhausted")?;
                journal.validate_initial_initialize_record(key, value)?;
            } else if key.starts_with(b"serving/") {
                journal.decode_serving_candidate(key, value)?;
            } else if key.starts_with(b"activation/") {
                journal.decode_projection_record(key, value)?;
            } else if key.starts_with(b"stop/") {
                let stop: TargetJournalStop = decode_current(value)?;
                journal.validate_stop(&stop)?;
                ensure!(
                    key == stop_key(
                        &stop.intent.intent.request.tenant,
                        stop.intent.intent.request.target_incarnation
                    ),
                    "journal stop key differs"
                );
            } else {
                ensure!(key == b"metadata", "unknown target journal record");
            }
            Ok(())
        })?;
        ensure!(
            metadata.intents == intents
                && metadata.generations == generations
                && metadata.dispatches == dispatches
                && metadata.dispatch_terminals == dispatch_terminals
                && metadata.dispatch_starts == dispatch_starts
                && metadata.dispatch_initializes == dispatch_initializes
                && metadata.charged_bytes == charged,
            "target journal accounting differs"
        );
        *owner = Arc::downgrade(&journal);
        Ok(journal)
    }
    fn metadata(&self) -> Result<Metadata> {
        let value = self
            .store
            .get_bounded(NS, b"metadata", MAX_RECORD)?
            .context("target journal metadata missing")?;
        let m: Metadata = decode_current(&value)?;
        ensure!(
            m.format == 4
                && m.installation == self.installed
                && m.dispatch_terminals <= m.dispatches
                && m.dispatch_starts
                    .checked_add(m.dispatch_initializes)
                    .is_some_and(|count| count <= m.dispatches)
                && m.charged_bytes <= self.limits.max_metadata_bytes,
            "target journal binding or capacity differs"
        );
        Ok(m)
    }
    fn validate_intent(&self, i: &TargetJournalIntent) -> Result<()> {
        i.intent.request.validate()?;
        ensure!(
            i.node == self.installed.node
                && i.intent.control_incarnation == self.installed.root.control_incarnation
                && i.intent.request.authority_partition == i.authority_partition.key()
                && i.intent.request_sha256 == kasumi_serving::digest(&i.intent.request)?
                && i.intent.accepted_at_ms < i.intent.original_credential_expires_at_ms,
            "journal original intent binding differs"
        );
        kasumi_types::validate_sha256(&i.partition_set_sha256)?;
        Ok(())
    }
    fn intent(&self, op: &TargetOperation) -> Result<TargetJournalIntent> {
        op.check()?;
        let lease = op.invocation().gate().current()?;
        let c = lease.commitment();
        ensure!(
            c.root == self.installed.root
                && lease.signed().claims.request.target_node == self.installed.node,
            "phase belongs to another installed journal"
        );
        let result = TargetJournalIntent {
            intent: c.intent.clone(),
            authority_partition: c.authority_partition.clone(),
            partition_set_sha256: c.partition_set_sha256.clone(),
            node: self.installed.node.clone(),
        };
        self.validate_intent(&result)?;
        Ok(result)
    }
    pub fn prepare(
        &self,
        op: &TargetOperation,
        exact_input_sha256: &str,
    ) -> Result<TargetJournalIntent> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        ensure!(
            intent.intent.request.phase != LifecyclePhase::StopLocal
                && intent.intent.request.phase_input_sha256 == exact_input_sha256,
            "target input differs from original control intent"
        );
        ensure!(
            self.store
                .get_bounded(
                    NS,
                    &stop_key(
                        &intent.intent.request.tenant,
                        intent.intent.request.target_incarnation
                    ),
                    MAX_RECORD
                )?
                .is_none(),
            "target incarnation permanently stopped locally"
        );
        if let Some(old) = self.store.get_bounded(
            NS,
            &intent_key(intent.intent.request.command_id),
            MAX_RECORD,
        )? {
            ensure!(
                decode_current::<TargetJournalIntent>(&old)? == intent,
                "target command identity already bound"
            );
            op.check()?;
            return Ok(intent);
        }
        let encoded = serde_json::to_vec(&intent)?;
        ensure!(
            encoded.len() <= MAX_RECORD,
            "target intent exceeds metadata bound"
        );
        let mut metadata = self.metadata()?;
        let target = intent.intent.request.target_incarnation;
        let binding = GenerationBinding::from_intent(&intent);
        let mut writes = vec![WriteOp::put(
            NS,
            intent_key(intent.intent.request.command_id),
            encoded.clone(),
        )];
        metadata.intents = metadata
            .intents
            .checked_add(1)
            .context("target journal count exhausted")?;
        metadata.charged_bytes = metadata
            .charged_bytes
            .checked_add(encoded.len() as u64 + COMPLETION_RESERVE)
            .context("journal bytes exhausted")?;
        if let Some(old) =
            self.store
                .get_bounded(NS, &generation_key(&binding.tenant, target), MAX_RECORD)?
        {
            ensure!(
                decode_current::<GenerationBinding>(&old)? == binding,
                "target generation binding differs"
            );
        } else {
            let encoded = serde_json::to_vec(&binding)?;
            metadata.generations = metadata
                .generations
                .checked_add(1)
                .context("target generation count exhausted")?;
            metadata.charged_bytes = metadata
                .charged_bytes
                .checked_add(encoded.len() as u64 + GENERATION_RESERVE)
                .context("journal bytes exhausted")?;
            writes.push(WriteOp::put(
                NS,
                generation_key(&binding.tenant, target),
                encoded,
            ));
        }
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "target journal permanent capacity exhausted"
        );
        writes.push(WriteOp::put(
            NS,
            b"metadata",
            serde_json::to_vec(&metadata)?,
        ));
        op.check()?;
        self.store.write_batch(&writes).map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)?;
        Ok(intent)
    }
    fn validate_file_creation(
        &self,
        key: &[u8],
        file: &FileCreation,
    ) -> Result<TargetJournalIntent> {
        let bytes = self
            .store
            .get_bounded(NS, &intent_key(file.materialization_command_id), MAX_RECORD)?
            .context("target file creation original intent missing")?;
        let intent: TargetJournalIntent = decode_current(&bytes)?;
        self.validate_intent(&intent)?;
        let request = &intent.intent.request;
        ensure!(
            request.command_id == file.materialization_command_id
                && request.phase == LifecyclePhase::Materialize
                && key == file_key(&request.tenant, request.target_incarnation),
            "target file creation identity differs"
        );
        let binding: GenerationBinding = decode_current(
            &self
                .store
                .get_bounded(
                    NS,
                    &generation_key(&request.tenant, request.target_incarnation),
                    MAX_RECORD,
                )?
                .context("target file creation generation binding missing")?,
        )?;
        ensure!(
            binding == GenerationBinding::from_intent(&intent),
            "target file creation generation differs"
        );
        Ok(intent)
    }

    /// Require the permanent causal creation intent before opening an existing
    /// target. The returned identifier is not a live serving authorization.
    pub fn materialization_file_id(&self, tenant: &str, target: Uuid) -> Result<Uuid> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        kasumi_types::validate_name(tenant)?;
        let key = file_key(tenant, target);
        let file: FileCreation = decode_current(
            &self
                .store
                .get_bounded(NS, &key, MAX_RECORD)?
                .context("target materialization file intent missing")?,
        )?;
        self.validate_file_creation(&key, &file)?;
        kasumi_store::node_store_ids::target_generation(
            self.installed.root.control_incarnation,
            tenant,
            target,
            &self.installed.node.verifier,
        )
    }

    /// Persist an exact original-materialization creation intent before any
    /// node file is touched. No path existence observation selects creation.
    pub fn reserve_materialization_file(
        &self,
        op: &TargetOperation,
    ) -> Result<MaterializationFile> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let request = &intent.intent.request;
        ensure!(
            request.phase == LifecyclePhase::Materialize,
            "only original materialization may create a target file"
        );
        ensure!(
            self.store
                .get_bounded(
                    NS,
                    &stop_key(&request.tenant, request.target_incarnation),
                    MAX_RECORD
                )?
                .is_none(),
            "target incarnation permanently stopped locally"
        );
        let file = FileCreation {
            materialization_command_id: request.command_id,
        };
        let key = file_key(&request.tenant, request.target_incarnation);
        ensure!(
            self.validate_file_creation(&key, &file)? == intent,
            "target file creation original intent differs"
        );
        let node_store_id = kasumi_store::node_store_ids::target_generation(
            self.installed.root.control_incarnation,
            &request.tenant,
            request.target_incarnation,
            &self.installed.node.verifier,
        )?;
        if let Some(old) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            ensure!(
                decode_current::<FileCreation>(&old)? == file,
                "target file already bound to another original materialization"
            );
            op.check()?;
            return Ok(MaterializationFile {
                operation: op.clone(),
                persistent_disk: self.store.persistent_disk().clone(),
                node_store_id,
                create: false,
            });
        }
        let bytes = serde_json::to_vec(&file)?;
        let mut metadata = self.metadata()?;
        metadata.charged_bytes = metadata
            .charged_bytes
            .checked_add(bytes.len() as u64)
            .context("journal file bytes exhausted")?;
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "target file intent exceeds permanent journal capacity"
        );
        op.check()?;
        self.store
            .write_batch(&[
                WriteOp::put(NS, key, bytes),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)?;
        Ok(MaterializationFile {
            operation: op.clone(),
            persistent_disk: self.store.persistent_disk().clone(),
            node_store_id,
            create: true,
        })
    }

    fn validate_stop(&self, stop: &TargetJournalStop) -> Result<()> {
        self.validate_intent(&stop.intent)?;
        let intent = &stop.intent.intent.request;
        let trust = kasumi_serving::AuthorityTrust::install(stop.authority.clone())?;
        ensure!(
            stop.authority
                .control_partition(stop.authority.partition(&intent.tenant)?)?
                == stop.intent.authority_partition
                && stop
                    .authority
                    .lifecycle_controls
                    .get(&self.installed.root.control_incarnation)
                    == Some(&self.installed.root.public_key),
            "target stop issuer differs from committed control partition"
        );
        let proof =
            trust.verify_target_stop(stop.stopped.clone(), &stop.stopped.observation.reference)?;
        let receipt = &proof.observation().stop;
        let kasumi_serving::AuthorityOutcome::TargetStopped {
            source_incarnation,
            source_epoch,
            target,
        } = &receipt.outcome
        else {
            anyhow::bail!("journal target stop is not a stopped outcome")
        };
        ensure!(
            intent.phase == LifecyclePhase::StopLocal
                && *source_incarnation == intent.source_incarnation
                && *source_epoch == intent.source_authority_epoch
                && target.incarnation == intent.target_incarnation
                && target.checkpoint == intent.checkpoint
                && target.nodes.len() == intent.target_nodes.len()
                && target.nodes.iter().all(|node| intent
                    .target_nodes
                    .get(&node.node_id)
                    .is_some_and(|expected| expected.verifier == node.verifier
                        && expected.principal == node.principal
                        && expected.certificate_sha256 == node.certificate_sha256))
                && intent.phase_input_sha256
                    == kasumi_serving::digest(&(
                        "kasumi.stop-local-target-input.v1",
                        proof.reference()
                    ))?,
            "drained target stop differs from exact original local phase"
        );
        Ok(())
    }
    /// Must precede local scope closure and any physical deletion. The returned
    /// value describes a permanent stop only, never completed local cleanup.
    pub fn stop(&self, op: &TargetOperation, proof: &VerifiedTargetStop) -> Result<()> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let lease = op.invocation().gate().current()?;
        let requested = TargetJournalStop {
            intent,
            stopped: proof.signed().clone(),
            authority: lease.authority().manifest().clone(),
        };
        self.validate_stop(&requested)?;
        let target = requested.intent.intent.request.target_incarnation;
        let binding = GenerationBinding::from_intent(&requested.intent);
        if let Some(bytes) =
            self.store
                .get_bounded(NS, &stop_key(&binding.tenant, target), MAX_RECORD)?
        {
            let old: TargetJournalStop = decode_current(&bytes)?;
            self.validate_stop(&old)?;
            ensure!(
                old.stopped.observation.stop.digest()?
                    == requested.stopped.observation.stop.digest()?,
                "target incarnation has another terminal stop"
            );
            op.check()?;
            return Ok(());
        }
        let encoded = serde_json::to_vec(&requested)?;
        ensure!(
            encoded.len() <= MAX_RECORD - 4096,
            "target stop exceeds reserved completion capacity"
        );
        let mut metadata = self.metadata()?;
        let mut writes = vec![WriteOp::put(NS, stop_key(&binding.tenant, target), encoded)];
        // Each generation reserves its terminal stop record, including the
        // original StopLocal identity. Stop consumes no normal phase slot or
        // extra capacity for an already reserved generation.
        if let Some(old) =
            self.store
                .get_bounded(NS, &generation_key(&binding.tenant, target), MAX_RECORD)?
        {
            ensure!(
                decode_current::<GenerationBinding>(&old)? == binding,
                "target generation binding differs"
            );
        } else {
            let encoded = serde_json::to_vec(&binding)?;
            metadata.generations = metadata
                .generations
                .checked_add(1)
                .context("journal count exhausted")?;
            metadata.charged_bytes = metadata
                .charged_bytes
                .checked_add(encoded.len() as u64 + GENERATION_RESERVE)
                .context("journal bytes exhausted")?;
            writes.push(WriteOp::put(
                NS,
                generation_key(&binding.tenant, target),
                encoded,
            ));
        }
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "permanent stop publication capacity exhausted"
        );
        writes.push(WriteOp::put(
            NS,
            b"metadata",
            serde_json::to_vec(&metadata)?,
        ));
        op.check()?;
        self.store.write_batch(&writes).map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)?;
        Ok(())
    }
}
fn intent_key(id: Uuid) -> Vec<u8> {
    format!("intent/{id}").into_bytes()
}
fn generation_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("generation/{tenant}/{id}").into_bytes()
}
fn file_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("file/{tenant}/{id}").into_bytes()
}
fn stop_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("stop/{tenant}/{id}").into_bytes()
}

impl TargetJournalIntent {
    /// Permanent accepted metadata, never proof of any physical target effect.
    pub fn intent(&self) -> &LifecycleIntent {
        &self.intent
    }
}

fn journal_unknown(_: impl std::fmt::Display) -> anyhow::Error {
    kasumi_types::Error::new(
        kasumi_types::ErrorCode::UnknownOutcome,
        "target journal publication unresolved; recover the exact identity",
    )
    .into()
}
