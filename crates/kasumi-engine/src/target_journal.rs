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
#[path = "target_journal_accounting.rs"]
mod accounting;
#[path = "target_journal_retirements.rs"]
mod retirements;
use retirements::JournalCheckpointPermit;
#[derive(Debug)]
pub struct MissingDispatchWriter;
impl std::fmt::Display for MissingDispatchWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("first dispatch requires its original journal writer observation")
    }
}
impl std::error::Error for MissingDispatchWriter {}
pub use retirements::{CurrentTargetJournalWriter, TargetWriterRead};
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
    VerifiedTargetInitializationAssociation,
};
pub use initial_start::ResolvedInitialStart;
#[path = "target_projection.rs"]
mod projection;
pub use projection::VerifiedTargetServingProjection;

/// A format-5 journal record is the exact current writer's JSON bytes. This
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
    /// Exact installed template choices, bound before any target cache or
    /// external archive is opened. These are configuration identities, not
    /// provider credential contents.
    pub audit_placement_bindings: std::collections::BTreeMap<String, String>,
    /// Absent in deployed journals. New installations with backup sources
    /// bind their complete tenant/incarnation/alias and provider roster here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_key_bindings_sha256: Option<String>,
}
impl TargetJournalInstallation {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        self.node.validate()?;
        if let Some(binding) = &self.source_key_bindings_sha256 {
            kasumi_types::validate_sha256(binding)?;
        }
        ensure!(
            (1..=10_000).contains(&self.audit_placement_bindings.len()),
            "target journal audit placement roster must be explicitly bounded"
        );
        for (tenant, binding) in &self.audit_placement_bindings {
            kasumi_types::validate_name(tenant)?;
            ensure!(
                !tenant.starts_with("__kasumi_") && !tenant.starts_with("kasumi."),
                "reserved target journal audit placement tenant"
            );
            kasumi_types::validate_sha256(binding)?;
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECORD / 2,
            "target journal audit placement roster exceeds its work limit"
        );
        Ok(())
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_drain: Option<TargetOwnerDrain>,
}

/// Bounded progress of the original target owners. A missing owner supplies
/// no start or completion observation. Higher marks never imply missed marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOwnerDrain {
    ClosingGates,
    GatesClosed,
    DrainingWorkers,
    WorkersDrained,
    DrainingStorage,
    StorageDrained,
}
impl From<TargetOwnerDrain> for kasumi_types::TargetDeletionProgress {
    fn from(value: TargetOwnerDrain) -> Self {
        match value {
            TargetOwnerDrain::ClosingGates => Self::ClosingGates,
            TargetOwnerDrain::GatesClosed => Self::GatesClosed,
            TargetOwnerDrain::DrainingWorkers => Self::DrainingWorkers,
            TargetOwnerDrain::WorkersDrained => Self::WorkersDrained,
            TargetOwnerDrain::DrainingStorage => Self::DrainingStorage,
            TargetOwnerDrain::StorageDrained => Self::StorageDrained,
        }
    }
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
    /// This generation identity was reserved solely by a terminal stop.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stop_before_prepare: bool,
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
            stop_before_prepare: false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCreation {
    materialization_command_id: Uuid,
}

/// The exact storage an original materialization created: its installed
/// path, the identity of the directory created there and the store identity
/// its root carries. Recorded before any catalog is initialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetFileBinding {
    pub tenant: String,
    pub target_incarnation: Uuid,
    pub path: std::path::PathBuf,
    pub directory: kasumi_store::private_files::DirectoryIdentity,
    pub node_store_id: Uuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCleanupStage {
    /// Exact deletion of the bound storage has begun.
    Deleting,
    /// The enrolled generation is absent after its original exact unlink.
    Unlinked,
    /// The enrolled parent was synchronized after the generation disappeared.
    ParentSynced,
    /// Deletion, or the absence of any storage, is confirmed after the
    /// parent directory sync. Terminal.
    Deleted,
}
impl TargetCleanupStage {
    pub fn permits_successor(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Deleting, Self::Unlinked)
                | (Self::Unlinked, Self::ParentSynced)
                | (Self::ParentSynced, Self::Deleted)
        )
    }
}
/// Durable local cleanup progress of one permanently stopped target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCleanup {
    pub tenant: String,
    pub target_incarnation: Uuid,
    pub stage: TargetCleanupStage,
    /// Absent only for a target that never had storage bound.
    pub binding: Option<TargetFileBinding>,
}
// One fixed charge covers a cleanup record, including all same-key progress rewrites.
const CLEANUP_RESERVE: usize = 4 << 10;

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
    Created(kasumi_store::NodeStore),
    Existing(kasumi_store::NodeStore),
}
impl MaterializationFile {
    #[allow(
        clippy::result_large_err,
        reason = "The journal returns whole inline admitted native startup custody without an error-path Box."
    )]
    pub fn open(
        self,
        path: &std::path::Path,
        scratch: Arc<kasumi_store::ScratchDisk>,
    ) -> std::result::Result<MaterializationNode, kasumi_store::NodeStoreStartFailure> {
        self.operation
            .check()
            .map_err(kasumi_store::NodeStoreStartFailure::Operation)?;
        let node = if self.create {
            kasumi_store::NodeStore::create_new(
                path,
                self.node_store_id,
                self.persistent_disk.clone(),
                scratch,
                self.persistent_disk.native_storage_config(),
            )
        } else {
            kasumi_store::NodeStore::open_existing(
                path,
                self.node_store_id,
                self.persistent_disk.clone(),
                scratch,
                self.persistent_disk.native_storage_config(),
            )
        }?;
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
    #[serde(
        default,
        skip_serializing_if = "retirements::WriterRetirements::is_empty"
    )]
    retirements: retirements::WriterRetirements,
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
    pub(crate) fn key_inventory_owner(&self) -> (&TargetJournalInstallation, &Arc<TenantStore>) {
        (&self.installed, &self.store)
    }

    /// Each encrypted row retains its observed wrapping version. The caller must
    /// obtain the independent external key graph for each permanent checkpoint.
    #[cfg(test)]
    pub(crate) fn visit_key_dependencies(
        &self,
        token: &kasumi_query::QueryCancellation,
        version: impl FnMut(kasumi_types::KeyRetentionEntry) -> Result<()>,
        mut checkpoint: impl FnMut(Uuid, &kasumi_types::FullBackupCheckpoint) -> Result<()>,
    ) -> Result<[u8; 32]> {
        self.visit_scoped_key_dependencies(
            token,
            version,
            |id, record, _| checkpoint(id, record),
            |_, _| Ok(false),
        )
    }

    pub(crate) fn visit_scoped_key_dependencies(
        &self,
        token: &kasumi_query::QueryCancellation,
        mut version: impl FnMut(kasumi_types::KeyRetentionEntry) -> Result<()>,
        mut checkpoint: impl FnMut(Uuid, &kasumi_types::FullBackupCheckpoint, bool) -> Result<()>,
        mut stopped_absent: impl FnMut(&str, Uuid) -> Result<bool>,
    ) -> Result<[u8; 32]> {
        use kasumi_types::{KeyCatalogDomain, KeyReference, KeyRetentionEntry, KeyVersionRef};
        use sha2::{Digest, Sha256};
        token.check()?;
        let _workspace = self
            .admission
            .reserve((MAX_RECORD * 8) as u64, Some(token.clone()))?;
        // Opening and inventory share the full accounting checks. Hold the writer
        // while the validators follow immutable links to their original records.
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let head = self.metadata()?;
        let node_id = self.installed.node.node_id;
        let mut entry = |reference: KeyReference, provider: &str, key_ref: &str, version_number| {
            token.check()?;
            ensure!(
                provider.len() <= kasumi_types::MAX_KEY_PROVIDER_BYTES
                    && key_ref.len() <= kasumi_types::MAX_KEY_REF_BYTES,
                "target journal wrapping identity exceeds its bound"
            );
            let row = KeyRetentionEntry {
                key: KeyVersionRef {
                    provider: provider.into(),
                    key_ref: key_ref.into(),
                    version: version_number,
                },
                reference,
            };
            row.validate()?;
            version(row)
        };
        let view = self.store.read_view()?;
        let result = (|| -> Result<[u8; 32]> {
            let physical = view.wrapping_inventory()?;
            let mut digest = Sha256::new();
            digest.update(b"kasumi.target-journal-key-inventory.v1\0");
            digest.update(
                physical.visit_catalog(|catalog_id, provider, key_ref, number| {
                    entry(
                        KeyReference::Catalog {
                            node_id,
                            catalog_id,
                            domain: KeyCatalogDomain::TargetJournal,
                        },
                        provider,
                        key_ref,
                        number,
                    )
                })?,
            );
            let mut accounting = accounting::JournalAccounting::new();
            physical.visit_records(NS, MAX_RECORD, |key, value, provider, key_ref, number| {
                token.check()?;
                let owner = accounting.observe(self, key, value, |row| {
                    ensure!(
                        row.control_incarnation == self.installed.root.control_incarnation
                            && row.checkpoint.tenant == row.tenant
                            && row.checkpoint.source_incarnation
                                == row.source_incarnation.to_string(),
                        "target journal generation differs from its checkpoint"
                    );
                    row.checkpoint.validate().map_err(Into::into)
                })?;
                if let Some(incarnation) = owner {
                    entry(
                        KeyReference::TargetJournal {
                            node_id,
                            incarnation,
                        },
                        provider,
                        key_ref,
                        number,
                    )?;
                } else {
                    ensure!(
                        decode_current::<Metadata>(value)? == head,
                        "target journal head changed during inventory"
                    );
                }
                serde_json::to_writer(&mut digest, &(provider, key_ref, number))?;
                for field in [key, value] {
                    digest.update((field.len() as u64).to_be_bytes());
                    digest.update(field);
                }
                Ok(())
            })?;
            accounting.verify(&head)?;
            // Keep the authenticated root pinned, but release the writer before
            // the visitor contacts a backup destination or a historical provider.
            drop(_guard);
            if head.generations != 0 || head.dispatches != 0 {
                view.visit(NS, MAX_RECORD, |key, value| {
                    token.check()?;
                    if key.starts_with(b"generation/") {
                        let row: GenerationBinding = decode_current(value)?;
                        if row.stop_before_prepare {
                            let stop: TargetJournalStop = decode_current(
                                &view
                                    .get(
                                        NS,
                                        &stop_key(&row.tenant, row.target_incarnation),
                                        MAX_RECORD,
                                    )?
                                    .context("stop-only generation lacks its terminal proof")?,
                            )?;
                            self.validate_stop(&stop)?;
                            let mut original = GenerationBinding::from_intent(&stop.intent);
                            original.stop_before_prepare = true;
                            ensure!(
                                original == row,
                                "stop-only generation differs from its original signed stop"
                            );
                            if let Some(bytes) = view.get(
                                NS,
                                &cleanup_key(&row.tenant, row.target_incarnation),
                                MAX_RECORD,
                            )? {
                                let cleanup: TargetCleanup = decode_current(&bytes)?;
                                self.validate_cleanup(&cleanup)?;
                                if cleanup.stage == TargetCleanupStage::Deleted
                                    && cleanup.binding.is_none()
                                    && view
                                        .get(
                                            NS,
                                            &file_key(&row.tenant, row.target_incarnation),
                                            MAX_RECORD,
                                        )?
                                        .is_none()
                                    && view
                                        .get(
                                            NS,
                                            &binding_key(&row.tenant, row.target_incarnation),
                                            MAX_RECORD,
                                        )?
                                        .is_none()
                                    && stopped_absent(&row.tenant, row.target_incarnation)?
                                {
                                    return Ok(());
                                }
                            }
                        }
                        checkpoint(
                            row.target_incarnation,
                            &row.checkpoint,
                            row.stop_before_prepare,
                        )?;
                    } else if key.starts_with(b"dispatch/") {
                        let row = self.validate_dispatch_record(key, value)?;
                        let request = &row.lifecycle.request;
                        let generation =
                            generation_key(&request.tenant, request.target_incarnation);
                        if let Some(bytes) = view.get(NS, &generation, MAX_RECORD)? {
                            let original: GenerationBinding = decode_current(&bytes)?;
                            ensure!(
                                original.checkpoint == request.checkpoint
                                    && original.source_incarnation == request.source_incarnation
                                    && original.source_epoch == request.source_authority_epoch
                                    && original.nodes == request.target_nodes,
                                "target dispatch differs from its retained generation"
                            );
                            if original.stop_before_prepare {
                                checkpoint(request.target_incarnation, &request.checkpoint, false)?;
                            }
                        } else {
                            // A lost initial dispatch can precede the first local
                            // prepare. Its immutable checkpoint is already retained.
                            checkpoint(request.target_incarnation, &request.checkpoint, false)?;
                        }
                    }
                    Ok(())
                })?;
            }
            token.check()?;
            physical.check_current()?;
            Ok(digest.finalize().into())
        })();
        match (result, view.close()) {
            (Ok(digest), Ok(())) => Ok(digest),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(close)) => Err(error.context(close)),
        }
    }

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
        installed.validate()?;
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
                format: 5,
                installation: journal.installed.clone(),
                intents: 0,
                generations: 0,
                dispatches: 0,
                dispatch_terminals: 0,
                dispatch_starts: 0,
                dispatch_initializes: 0,
                charged_bytes: MAX_RECORD as u64,
                retirements: Default::default(),
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
        let mut accounting = accounting::JournalAccounting::new();
        journal.store.visit(NS, MAX_RECORD, |key, value| {
            accounting.observe(&journal, key, value, |_| Ok(()))?;
            Ok(())
        })?;
        accounting.verify(&metadata)?;
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
            m.format == 5
                && m.installation == self.installed
                && m.dispatch_terminals <= m.dispatches
                && m.dispatch_starts
                    .checked_add(m.dispatch_initializes)
                    .is_some_and(|count| count <= m.dispatches)
                && m.charged_bytes <= self.limits.max_metadata_bytes,
            "target journal binding or capacity differs"
        );
        m.retirements.validate()?;
        Ok(m)
    }
    fn validate_intent(&self, i: &TargetJournalIntent) -> Result<()> {
        i.intent.request.validate()?;
        ensure!(
            self.installed
                .audit_placement_bindings
                .contains_key(&i.intent.request.tenant),
            "target journal tenant has no installed audit placement"
        );
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
        self.prepare_with_checkpoint_permit(op, exact_input_sha256, None, None)
    }
    fn prepare_with_checkpoint_permit(
        &self,
        op: &TargetOperation,
        exact_input_sha256: &str,
        permit: Option<&JournalCheckpointPermit>,
        writer: Option<&CurrentTargetJournalWriter>,
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
            writer
                .context(
                    "first target generation requires its registered Control writer observation",
                )?
                .require(self, &metadata.retirements)?;
            if metadata.retirements.requires_graph() {
                permit
                    .context(
                        "new target checkpoint requires verification at its durable writer fence",
                    )?
                    .require(self, &binding, &metadata.retirements)?;
            }
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

    /// Match the target database's genesis to the permanent command that
    /// created this physical directory. No writer or generation is opened.
    pub(crate) fn require_checkpoint_origin(
        &self,
        origin: &kasumi_types::TargetOrigin,
        target: &Arc<TenantStore>,
    ) -> Result<()> {
        origin.validate()?;
        let request = &origin.materialization.request;
        let key = file_key(&request.tenant, request.target_incarnation);
        let file = decode_current::<FileCreation>(
            &self
                .store
                .get_bounded(NS, &key, MAX_RECORD)?
                .context("target creation record missing")?,
        )?;
        let accepted = self.validate_file_creation(&key, &file)?;
        let binding = self
            .materialization_file_binding(&request.tenant, request.target_incarnation)?
            .context("target physical binding missing")?;
        ensure!(
            accepted.intent == origin.materialization
                && self.installed.source_key_bindings_sha256.is_some()
                && matches!(target.storage_access().purpose(), kasumi_store::StoragePurpose::Serving {identity, ..} if identity.tenant == request.tenant && identity.incarnation == request.target_incarnation && identity.node == self.installed.node)
                && Arc::ptr_eq(target.persistent_disk(), self.store.persistent_disk())
                && target.node_store().physical_identity()?.directory == binding.directory,
            "target genesis or physical owner differs from its journal"
        );
        target.check_access()
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

    fn validate_binding(&self, binding: &TargetFileBinding) -> Result<()> {
        kasumi_types::validate_name(&binding.tenant)?;
        let key = file_key(&binding.tenant, binding.target_incarnation);
        let file: FileCreation = decode_current(
            &self
                .store
                .get_bounded(NS, &key, MAX_RECORD)?
                .context("target file binding has no original creation")?,
        )?;
        self.validate_file_creation(&key, &file)?;
        ensure!(
            binding.path.is_absolute()
                && binding.node_store_id
                    == kasumi_store::node_store_ids::target_generation(
                        self.installed.root.control_incarnation,
                        &binding.tenant,
                        binding.target_incarnation,
                        &self.installed.node.verifier,
                    )?,
            "target file binding names another store"
        );
        Ok(())
    }
    fn validate_cleanup(&self, cleanup: &TargetCleanup) -> Result<()> {
        kasumi_types::validate_name(&cleanup.tenant)?;
        ensure!(
            self.store
                .get_bounded(
                    NS,
                    &stop_key(&cleanup.tenant, cleanup.target_incarnation),
                    MAX_RECORD,
                )?
                .is_some(),
            "target cleanup precedes its permanent stop"
        );
        ensure!(
            cleanup.binding
                == self
                    .materialization_file_binding(&cleanup.tenant, cleanup.target_incarnation)?,
            "target cleanup differs from the enrolled storage binding"
        );
        ensure!(
            cleanup.binding.is_some() || cleanup.stage == TargetCleanupStage::Deleted,
            "target deletion in progress has no binding"
        );
        Ok(())
    }

    /// Record the exact storage the original materialization created, before
    /// any catalog is initialized. Repeating it must name the same storage.
    pub fn bind_materialization_file(
        &self,
        op: &TargetOperation,
        binding: &TargetFileBinding,
    ) -> Result<()> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let request = &intent.intent.request;
        ensure!(
            request.tenant == binding.tenant
                && request.target_incarnation == binding.target_incarnation,
            "target file binding belongs to another phase"
        );
        self.validate_binding(binding)?;
        let key = binding_key(&binding.tenant, binding.target_incarnation);
        if let Some(old) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            ensure!(
                decode_current::<TargetFileBinding>(&old)? == *binding,
                "target file is bound to other storage"
            );
            op.check()?;
            return Ok(());
        }
        ensure!(
            self.target_cleanup(&binding.tenant, binding.target_incarnation)?
                .is_none(),
            "target cleanup already has a durable outcome"
        );
        let bytes = serde_json::to_vec(binding)?;
        let mut metadata = self.metadata()?;
        metadata.charged_bytes = metadata
            .charged_bytes
            .checked_add(bytes.len() as u64)
            .context("journal binding bytes exhausted")?;
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "target file binding exceeds permanent journal capacity"
        );
        op.check()?;
        self.store
            .write_batch(&[
                WriteOp::put(NS, key, bytes),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)
    }

    pub fn materialization_file_binding(
        &self,
        tenant: &str,
        target: Uuid,
    ) -> Result<Option<TargetFileBinding>> {
        kasumi_types::validate_name(tenant)?;
        let Some(bytes) = self
            .store
            .get_bounded(NS, &binding_key(tenant, target), MAX_RECORD)?
        else {
            return Ok(None);
        };
        let binding: TargetFileBinding = decode_current(&bytes)?;
        ensure!(
            binding.tenant == tenant && binding.target_incarnation == target,
            "journal file binding key differs"
        );
        self.validate_binding(&binding)?;
        Ok(Some(binding))
    }

    pub fn target_cleanup(&self, tenant: &str, target: Uuid) -> Result<Option<TargetCleanup>> {
        kasumi_types::validate_name(tenant)?;
        let Some(bytes) = self
            .store
            .get_bounded(NS, &cleanup_key(tenant, target), MAX_RECORD)?
        else {
            return Ok(None);
        };
        let cleanup: TargetCleanup = decode_current(&bytes)?;
        ensure!(
            cleanup.tenant == tenant && cleanup.target_incarnation == target,
            "journal cleanup key differs"
        );
        self.validate_cleanup(&cleanup)?;
        Ok(Some(cleanup))
    }

    /// Observe under the original journal lock. No generation opens and no
    /// cleanup command is admitted by this read. The two installed signers and
    /// the original physical binding are checked again before returning.
    pub fn deletion_status(
        &self,
        query: &kasumi_types::TargetDeletionQuery,
        original: &kasumi_serving::VerifiedControlIntent,
        marked: &kasumi_types::RecoveryPhaseRecord,
    ) -> Result<kasumi_types::TargetDeletionStatus> {
        use kasumi_types::{
            RecoveryDispatch, RecoveryEffect, RecoveryPhase, TargetDeletionProgress,
            TargetRuntimeStep,
        };
        query.validate()?;
        marked.validate()?;
        let observed = original.observation();
        let intent = &observed.intent;
        let RecoveryDispatch::Target { node_id, request } = &marked.input else {
            anyhow::bail!("deletion phase is not a target effect");
        };
        let TargetRuntimeStep::Stop(reference) = &request.step else {
            anyhow::bail!("deletion phase is not StopLocal");
        };
        let attempt = marked
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .context("deletion effect has not begun")?;
        ensure!(
            marked.operation_id == query.operation_id
                && marked.phase_id == query.phase_id
                && marked.phase == RecoveryPhase::Cleanup
                && *node_id == query.node_id
                && query.node_id == self.installed.node.node_id
                && observed.root == self.installed.root
                && intent.control_incarnation == observed.root.control_incarnation
                && request.command_id == intent.request.command_id
                && request.tenant == intent.request.tenant
                && intent.request.target_incarnation == query.target_incarnation
                && intent.request.phase == LifecyclePhase::StopLocal
                && attempt.input_sha256 == marked.input_sha256,
            "original Control deletion dispatch differs"
        );
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let bytes = self
            .store
            .get_bounded(
                NS,
                &stop_key(&request.tenant, query.target_incarnation),
                MAX_RECORD,
            )?
            .context("local permanent stop has not been recorded")?;
        let stop: TargetJournalStop = decode_current(&bytes)?;
        self.validate_stop(&stop)?;
        ensure!(
            &stop.intent.intent == intent
                && stop.intent.partition_set_sha256 == observed.partition_set_sha256
                && stop.intent.authority_partition == observed.authority_partition
                && stop.stopped.observation.reference == *reference,
            "local signed stop differs from original Control effect"
        );
        let binding =
            self.materialization_file_binding(&request.tenant, query.target_incarnation)?;
        let progress = match self
            .target_cleanup(&request.tenant, query.target_incarnation)?
            .map(|record| record.stage)
        {
            None => stop
                .owner_drain
                .map(Into::into)
                .unwrap_or(TargetDeletionProgress::StopRecorded),
            Some(TargetCleanupStage::Deleting) => TargetDeletionProgress::Deleting,
            Some(TargetCleanupStage::Unlinked) => TargetDeletionProgress::Unlinked,
            Some(TargetCleanupStage::ParentSynced) => TargetDeletionProgress::ParentSynced,
            Some(TargetCleanupStage::Deleted) => TargetDeletionProgress::Deleted,
        };
        let result = kasumi_types::TargetDeletionStatus {
            query: query.clone(),
            intent_id: request.command_id,
            attempt_id: attempt.attempt_id,
            stop_receipt_sha256: stop.stopped.observation.stop.digest()?,
            binding_sha256: binding.as_ref().map(kasumi_serving::digest).transpose()?,
            progress,
        };
        result.validate_for(query)?;
        Ok(result)
    }

    /// The StopLocal operation must present the same verified Authority stop.
    /// A retried drain never regresses the durable point or fills historical
    /// gaps from the mere absence of a previous process.
    pub fn record_owner_drain(
        &self,
        op: &TargetOperation,
        proof: &VerifiedTargetStop,
        stage: TargetOwnerDrain,
    ) -> Result<()> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let installed = self.intent(op)?;
        let requested = &installed.intent.request;
        ensure!(
            requested.phase == LifecyclePhase::StopLocal,
            "target drain requires StopLocal"
        );
        let key = stop_key(&requested.tenant, requested.target_incarnation);
        let bytes = self
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("target drain precedes permanent stop")?;
        let mut stop: TargetJournalStop = decode_current(&bytes)?;
        self.validate_stop(&stop)?;
        ensure!(
            GenerationBinding::from_intent(&stop.intent)
                == GenerationBinding::from_intent(&installed)
                && stop.stopped.observation.stop.digest()? == proof.observation().stop.digest()?,
            "target drain differs from the original permanent stop"
        );
        op.check()?;
        // Another correctly authorized StopLocal can retire this same generation,
        // but its resource drain never supplies evidence for the first command.
        if installed != stop.intent
            || stop.owner_drain.is_some_and(|old| old >= stage)
            || self
                .store
                .get_bounded(
                    NS,
                    &cleanup_key(&requested.tenant, requested.target_incarnation),
                    MAX_RECORD,
                )?
                .is_some()
        {
            return Ok(());
        }
        stop.owner_drain = Some(stage);
        let next = serde_json::to_vec(&stop)?;
        ensure!(
            next.len() <= MAX_RECORD,
            "drain progress exceeds original stop reserve"
        );
        op.check()?;
        self.store
            .write_batch(&[WriteOp::put(NS, key, next)])
            .map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)
    }

    /// Advance the local cleanup of a permanently stopped target. Only a first
    /// record, an exact replay, or the immediate next stage of the same
    /// binding is accepted. The terminal outcome never changes.
    pub fn record_target_cleanup(
        &self,
        op: &TargetOperation,
        cleanup: &TargetCleanup,
    ) -> Result<()> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let request = &intent.intent.request;
        ensure!(
            request.phase == LifecyclePhase::StopLocal
                && request.tenant == cleanup.tenant
                && request.target_incarnation == cleanup.target_incarnation,
            "target cleanup belongs to another phase"
        );
        self.validate_cleanup(cleanup)?;
        let bytes = serde_json::to_vec(cleanup)?;
        ensure!(
            bytes.len() <= CLEANUP_RESERVE,
            "target cleanup record exceeds its reserve"
        );
        let key = cleanup_key(&cleanup.tenant, cleanup.target_incarnation);
        let mut writes = vec![WriteOp::put(NS, key.clone(), bytes)];
        match self.store.get_bounded(NS, &key, MAX_RECORD)? {
            Some(old) => {
                let old: TargetCleanup = decode_current(&old)?;
                if old == *cleanup {
                    op.check()?;
                    return Ok(());
                }
                ensure!(
                    old.stage.permits_successor(cleanup.stage) && old.binding == cleanup.binding,
                    "target cleanup outcome differs"
                );
            }
            None => {
                ensure!(
                    cleanup.binding.is_none() || cleanup.stage == TargetCleanupStage::Deleting,
                    "bound storage must record deletion in progress before completion"
                );
                let mut metadata = self.metadata()?;
                metadata.charged_bytes = metadata
                    .charged_bytes
                    .checked_add(CLEANUP_RESERVE as u64)
                    .context("journal cleanup bytes exhausted")?;
                ensure!(
                    metadata.charged_bytes <= self.limits.max_metadata_bytes,
                    "target cleanup exceeds permanent journal capacity"
                );
                writes.push(WriteOp::put(
                    NS,
                    b"metadata",
                    serde_json::to_vec(&metadata)?,
                ));
            }
        }
        op.check()?;
        self.store.write_batch(&writes).map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)
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
            owner_drain: None,
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
            let mut binding = binding;
            binding.stop_before_prepare = true;
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
fn binding_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("binding/{tenant}/{id}").into_bytes()
}
fn cleanup_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("cleanup/{tenant}/{id}").into_bytes()
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
