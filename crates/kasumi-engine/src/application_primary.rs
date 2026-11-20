//! Ordinary primary directory publication and reopen.
//!
//! Every candidate publication that keeps the directory current edits the
//! live, archived and header rows of its changed documents copy-on-write in
//! the selected primary page space. The fixed-size manifest names the new
//! root at the candidate's exact revision and applied boundary. Both join the
//! existing paired application/custody transaction with the applied cursor,
//! so the directory and the cursor never disagree after a crash.
//!
//! Reopen restores the older authenticated snapshot and replays the retained
//! log. Replayed entries at or below the directory's revision are covered:
//! they publish nothing here (Store also refuses a backward manifest), and the
//! entry that reaches the directory's revision must carry its exact boundary
//! and reproduce its rows. Entries beyond it, including any unapplied tail,
//! edit forward from it. A store without a current directory (deployed
//! revisions, or a directory that went stale) rebuilds one from the restored
//! snapshot in a fresh generation that the restore publication selects.
//!
//! Ordinary edits are bounded. A candidate whose delta exceeds the bound, or
//! whose edit cannot be prepared, publishes a stale manifest instead of
//! fencing the replica. A later ordinary publication can replace an absent or
//! stale directory by streaming a bounded candidate into a new generation.
//! Staged edit batches written before a publication that
//! never commits are journaled and recovered under the same apply owner.
use crate::application_records;
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    NamespaceStage, NodeDiskMemoryAdmission, SelectedGeneration, TenantStore, WriteOp,
    ordered_pages::{self, Direction, Edit, PageSource, TreeReader, TreeRoot},
    primary_manifest::{self as primary, PrimaryApplied, PrimaryManifest, PrimaryStatus},
};
use kasumi_types::TenantState;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

#[path = "application_primary_rebuild.rs"]
mod incremental;

/// Changed document IDs by collection, as the accepted producer supplies them.
pub(crate) type ChangedIds = BTreeMap<String, BTreeSet<String>>;

/// Maximum population for a synchronous rebuild of an absent or stale root.
pub(crate) const MAX_REBUILD_IDS: usize = 4096;
/// Producer keys and descriptors held during an ordinary edit.
const WINDOW_IDS: usize = 64;
/// Each staged native transaction owns at most fourteen page/chunk dispositions.
const MAX_EDIT_BATCHES: u32 = 256;
/// Encoded key and value bytes of those documents' rows.
pub(crate) const MAX_EDIT_BYTES: usize = 16 << 20;
/// Period between attempts after a staged replacement exhausts its byte budget
/// or encounters an error. An oversized document count requires no I/O.
const REBUILD_RETRY_REVISIONS: u64 = 4096;

/// Per-engine edit journal custody. Only the apply owner reads or changes it.
pub(crate) struct PrimaryOwner {
    recovery_pending: AtomicBool,
    rebuild_after: AtomicU64,
    prefer_incremental: AtomicBool,
    maintenance_due: AtomicBool,
    replacement: Mutex<Option<PendingReplacement>>,
}

struct PendingReplacement {
    previous: String,
    candidate: String,
    _workspace: kasumi_store::DiskMemoryLease,
}

impl Default for PrimaryOwner {
    fn default() -> Self {
        // A process starts without knowing whether a previous one left
        // journaled batches behind.
        Self {
            recovery_pending: AtomicBool::new(true),
            rebuild_after: AtomicU64::new(0),
            prefer_incremental: AtomicBool::new(false),
            maintenance_due: AtomicBool::new(true),
            replacement: Mutex::new(None),
        }
    }
}

impl PrimaryOwner {
    /// Finish displaced-row reclamation of published edits and abandon the
    /// rows of unpublished ones before the next edit begins.
    fn recover(&self, store: &Arc<TenantStore>) -> Result<()> {
        if self.recovery_pending.load(Ordering::Acquire) {
            ordered_pages::recover_abandoned_edits_in(store, primary::FAMILY)?;
            self.recovery_pending.store(false, Ordering::Release);
        }
        Ok(())
    }
    pub(crate) fn needs_maintenance(&self) -> bool {
        self.maintenance_due.load(Ordering::Acquire)
    }
    pub(crate) fn caught_up(&self) {
        self.maintenance_due.store(false, Ordering::Release);
    }
    fn replacement_slot(&self) -> Result<std::sync::MutexGuard<'_, Option<PendingReplacement>>> {
        self.replacement
            .lock()
            .map_err(|_| anyhow::anyhow!("primary replacement owner poisoned"))
    }

    /// A failed Native begin can have a durable outcome. Record the original
    /// proposed namespace before starting it and retain the two exact names.
    fn begin_replacement(
        &self,
        store: &Arc<TenantStore>,
        previous: &str,
    ) -> Result<NamespaceStage> {
        let mut slot = self.replacement_slot()?;
        ensure!(
            slot.is_none(),
            "previous primary replacement still owns native pages"
        );
        let workspace = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(1024)?;
        let candidate = format!("{}@{}", primary::FAMILY, uuid::Uuid::new_v4());
        *slot = Some(PendingReplacement {
            previous: previous.to_owned(),
            candidate,
            _workspace: workspace,
        });
        NamespaceStage::begin(
            store,
            &slot
                .as_ref()
                .expect("installed original replacement")
                .candidate,
        )
    }

    /// The paired selector determines whether the prior or proposed space is
    /// unselected. Four deletion commits bound one ordinary application.
    /// A process restart recovers the same durable native owners on reopen.
    fn advance_replacement_cleanup(&self, store: &Arc<TenantStore>) -> Result<bool> {
        let mut slot = self.replacement_slot()?;
        let Some(pending) = slot.as_ref() else {
            return Ok(true);
        };
        let selected = SelectedGeneration::load(store, primary::FAMILY, &primary::INITIAL_SPACE)?;
        let unselected = if selected.namespace(0) == pending.candidate {
            &pending.previous
        } else {
            ensure!(
                selected.namespace(0) == pending.previous,
                "primary replacement selection changed"
            );
            &pending.candidate
        };
        for _ in 0..4 {
            if NamespaceStage::reclaim(store, unselected)? {
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn pending(&self) {
        self.recovery_pending.store(true, Ordering::Release);
    }
    fn settled(&self) {
        self.recovery_pending.store(false, Ordering::Release);
    }
}

fn log_sha256(log_id: &kasumi_raft::LogId<u64>) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    serde_json::to_writer(&mut hash, &("kasumi.primary.log.v1", log_id))?;
    Ok(hash.finalize().into())
}

/// The boundary of one ordinary or metadata entry.
pub(crate) fn entry_applied(position: &kasumi_raft::AppliedEntryContext) -> Result<PrimaryApplied> {
    entry_identity(&position.log_id, &position.command_sha256)
}

pub(crate) fn entry_identity(
    log: &kasumi_raft::LogId<u64>,
    digest: &str,
) -> Result<PrimaryApplied> {
    let mut command = [0u8; 32];
    hex::decode_to_slice(digest, &mut command).context("applied command digest is not SHA-256")?;
    log_applied(log, Some(command))
}

pub(crate) fn log_applied(
    log: &kasumi_raft::LogId<u64>,
    command_sha256: Option<[u8; 32]>,
) -> Result<PrimaryApplied> {
    Ok(PrimaryApplied {
        index: log.index,
        log_sha256: log_sha256(log)?,
        command_sha256,
    })
}

/// A snapshot boundary carries its log position but no command.
pub(crate) fn snapshot_applied(
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
) -> Result<Option<PrimaryApplied>> {
    meta.last_log_id
        .map(|log_id| log_applied(&log_id, None))
        .transpose()
}

fn record_digest(hash: &mut Sha256, key: &[u8], length: u64, value_sha256: [u8; 32]) {
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
    hash.update(length.to_be_bytes());
    hash.update(value_sha256);
}

/// Stream the directory's tree and the resident rows of `state` and compare
/// them exactly, including counts and logical bytes.
pub(crate) fn verify_rows(
    source: &dyn PageSource,
    manifest: &PrimaryManifest,
    state: &TenantState,
    memory: &Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<()> {
    ensure!(
        manifest.tenant == state.tenant
            && manifest.incarnation == state.incarnation
            && manifest.revision_base == state.revision_base
            && manifest.revision == state.revision
            && manifest.document_count == state.document_count
            && manifest.logical_bytes == state.logical_bytes,
        "primary directory scope or totals differ from the selected state"
    );
    // The authenticated root describes every key and value byte. A damaged
    // or foreign directory cannot make us hash more resident rows than it
    // could possibly contain.
    let mut remaining_rows = manifest.records.count();
    let mut remaining_bytes = manifest.records.bytes();
    let mut expected = Sha256::new();
    application_records::visit_primary(state, memory, |key, value| {
        remaining_rows = remaining_rows
            .checked_sub(1)
            .context("primary directory row count differs")?;
        remaining_bytes = remaining_bytes
            .checked_sub(key.len() as u64)
            .and_then(|left| left.checked_sub(value.len() as u64))
            .context("primary directory byte count differs")?;
        record_digest(
            &mut expected,
            key,
            value.len() as u64,
            Sha256::digest(value).into(),
        );
        Ok(())
    })?;
    ensure!(
        remaining_rows == 0 && remaining_bytes == 0,
        "primary directory row or byte count differs"
    );
    let reader = TreeReader::new(source, &manifest.page_space, manifest.records, None)?;
    let mut selected = Sha256::new();
    reader.scan(Bound::Unbounded, Direction::Forward, &mut |key, value| {
        record_digest(
            &mut selected,
            key,
            value.len(),
            reader.value_sha256(&value)?,
        );
        Ok(true)
    })?;
    ensure!(
        expected.finalize() == selected.finalize(),
        "primary directory rows differ from the selected state"
    );
    Ok(())
}

#[derive(Debug)]
struct RebuildByteBudget;
impl std::fmt::Display for RebuildByteBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("primary directory exceeds the replacement byte budget")
    }
}
impl std::error::Error for RebuildByteBudget {}

/// Bulk-build `state`'s rows into a fresh staged generation. The returned
/// writes select it with its manifest and retire the replaced space; they
/// must join the publication that selects `state`.
fn rebuild(
    store: &Arc<TenantStore>,
    state: &TenantState,
    applied: Option<PrimaryApplied>,
    mut byte_budget: usize,
    ordinary_owner: Option<&PrimaryOwner>,
) -> Result<Vec<WriteOp>> {
    let family = SelectedGeneration::adopt(store, primary::FAMILY, &primary::INITIAL_SPACE)?;
    let stage = match ordinary_owner {
        Some(owner) => owner.begin_replacement(store, family.namespace(0))?,
        None => NamespaceStage::begin_generation(store, primary::FAMILY)?,
    };
    let memory = store.plaintext_memory_owner().clone();
    let records = ordered_pages::stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        application_records::visit_primary(state, &memory, |key, value| {
            byte_budget = byte_budget
                .checked_sub(key.len())
                .and_then(|remaining| remaining.checked_sub(value.len()))
                .ok_or(RebuildByteBudget)?;
            builder.push(key, value)
        })
    })?;
    let manifest = PrimaryManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision_base,
        state.revision,
        applied,
        stage.namespace(),
        records,
        state.document_count,
        state.logical_bytes,
    );
    let mut writes = family.switch_writes(store, &[&stage])?;
    writes.push(manifest.write()?);
    Ok(writes)
}

/// Under the restore's apply owner, before its publication. Reopen keeps a
/// current directory at or ahead of the snapshot; replay reaches it. Any
/// other case, and every installation, selects a rebuilt generation.
pub(crate) fn prepare_restore(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
    reopen: bool,
    writes: &mut Vec<WriteOp>,
) -> Result<()> {
    ordered_pages::recover_abandoned_edits_in(store, primary::FAMILY)?;
    owner.settled();
    NamespaceStage::reclaim_family(store, primary::FAMILY)?;
    *owner.replacement_slot()? = None;
    owner.prefer_incremental.store(false, Ordering::Release);
    owner.maintenance_due.store(true, Ordering::Release);
    let applied = snapshot_applied(meta)?;
    if reopen
        && let Some(Some(manifest)) = load_or_skip(store)?
        && (manifest.is_current() || manifest.rebuild().is_some())
        && manifest.tenant == state.tenant
        && manifest.incarnation == state.incarnation
        && manifest.revision_base == state.revision_base
    {
        if manifest.revision > state.revision {
            return Ok(());
        }
        if manifest.revision == state.revision
            && manifest
                .applied
                .as_ref()
                .zip(applied.as_ref())
                .is_some_and(|(selected, snapshot)| selected.same_position(snapshot))
            && (manifest.rebuild().is_some()
                || verify_rows(&**store, &manifest, state, store.plaintext_memory_owner()).is_ok())
        {
            return Ok(());
        }
    }
    writes.extend(rebuild(store, state, applied, usize::MAX, None)?);
    Ok(())
}

/// The selected manifest. `Some(None)` when there is none; `None` when it
/// cannot be decoded or disagrees with its selection while access holds: the
/// directory is then neither edited nor trusted, and the next restore replaces
/// it with a rebuilt generation (that switch never decodes its predecessor).
fn load_or_skip(store: &Arc<TenantStore>) -> Result<Option<Option<PrimaryManifest>>> {
    match PrimaryManifest::load(store) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => {
            if let Err(access) = store.check_access() {
                return Err(error.context(access));
            }
            tracing::error!(

                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "unreadable primary directory is ignored until the next restore"
            );
            Ok(None)
        }
    }
}

/// Fixed writes for one candidate publication, and the workspace funding
/// their page rows until the publication returns.
pub(crate) struct PrimaryPublication {
    writes: Vec<WriteOp>,
    _workspace: Option<ordered_pages::EditWorkspace>,
}

impl PrimaryPublication {
    pub(crate) fn take_writes(&mut self) -> Vec<WriteOp> {
        std::mem::take(&mut self.writes)
    }
    fn only(writes: Vec<WriteOp>) -> Self {
        Self {
            writes,
            _workspace: None,
        }
    }
}

/// What the directory must do for one candidate.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// A stale directory ahead of the predecessor must survive covered replay.
    Nothing,
    /// The candidate can start a new page space for an absent or stale directory.
    Replace,
    /// A covered replay below the directory's revision.
    Covered,
    /// A covered replay reaching the directory's revision.
    Boundary,
    /// Edit from the current directory (or from an empty pristine tree).
    Edit,
    /// The directory cannot follow this candidate.
    Stale(&'static str),
}

fn step(
    manifest: Option<&PrimaryManifest>,
    previous: &TenantState,
    candidate: &TenantState,
) -> Step {
    let Some(manifest) = manifest else {
        return if pristine(previous) {
            Step::Edit
        } else {
            Step::Replace
        };
    };
    if manifest.tenant != candidate.tenant
        || manifest.incarnation != candidate.incarnation
        || manifest.revision_base != candidate.revision_base
    {
        return Step::Stale("primary directory scope differs from the candidate");
    }
    if !manifest.is_current() && manifest.rebuild().is_none() {
        return if manifest.revision <= previous.revision {
            Step::Replace
        } else {
            Step::Nothing
        };
    }
    if candidate.revision < manifest.revision {
        return Step::Covered;
    }
    if candidate.revision == manifest.revision {
        return Step::Boundary;
    }
    if manifest.revision != previous.revision {
        // A replayed group can straddle the directory's revision, and no
        // other publication may leave a revision unrecorded.
        return Step::Stale("primary directory revision differs from the predecessor");
    }
    Step::Edit
}

/// A state with no live or archived document: a pristine store's first
/// directory starts from an empty tree in the selected space.
fn pristine(state: &TenantState) -> bool {
    state.collections.values().all(|collection| {
        collection.documents.is_empty() && collection.archived_documents.is_empty()
    })
}

/// Emit the producer's exact delta without copying its ID set. A new,
/// removed or redefined collection also contributes IDs from either side.
fn visit_changed_ids(
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
    mut visit: impl FnMut(&str, &str) -> Result<()>,
) -> Result<()> {
    for (name, ids) in changed {
        for id in ids {
            visit(name, id)?;
        }
    }
    let names = previous.collections.keys().chain(
        candidate
            .collections
            .keys()
            .filter(|name| !previous.collections.contains_key(*name)),
    );
    for name in names {
        let old = previous.collections.get(name);
        let new = candidate.collections.get(name);
        if let (Some(old), Some(new)) = (old, new)
            && (Arc::ptr_eq(&old.definition, &new.definition)
                || (old.documents.ptr_eq(&new.documents)
                    && old.archived_documents.ptr_eq(&new.archived_documents))
                || old.definition == new.definition)
        {
            continue;
        }
        let supplied = |id: &str| changed.get(name).is_some_and(|ids| ids.contains(id));
        if let Some(old) = old {
            for id in crate::index_source::resident_ids_after(old, None) {
                if !supplied(id) {
                    visit(name, id)?;
                }
            }
        }
        if let Some(new) = new {
            for id in crate::index_source::resident_ids_after(new, None) {
                if !supplied(id)
                    && !old.is_some_and(|c| {
                        c.documents.contains_key(id) || c.archived_documents.contains_key(id)
                    })
                {
                    visit(name, id)?;
                }
            }
        }
    }
    Ok(())
}

/// Under the apply owner, after the candidate's after-images are stored.
/// `None` publishes nothing here: there is no current directory to keep, or a
/// covered replay is below it. A bounded candidate may replace an absent or
/// stale directory. Every other failure to follow the candidate,
/// including a replayed boundary that differs, publishes a stale manifest;
/// errors are reserved for failing to read the selected manifest itself.
pub(crate) fn prepare_publication_at(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
    applied: Option<PrimaryApplied>,
    matches_predecessor: impl FnOnce(&PrimaryManifest) -> Result<bool>,
) -> Result<Option<PrimaryPublication>> {
    // A budget refusal may have staged earlier windows before leaving the
    // root stale. Reclaim its original journal even while the root is stale.
    owner.recover(store)?;
    let may_replace = owner.advance_replacement_cleanup(store)?;
    let Some(manifest) = load_or_skip(store)? else {
        return Ok(None);
    };
    if manifest
        .as_ref()
        .is_none_or(|manifest| !manifest.is_current())
    {
        owner.maintenance_due.store(true, Ordering::Release);
    }
    let base = match step(manifest.as_ref(), previous, candidate) {
        Step::Nothing | Step::Covered => return Ok(None),
        Step::Replace if may_replace => return replace(owner, store, candidate, applied),
        Step::Replace => return Ok(None),
        Step::Boundary => {
            let manifest = manifest.expect("boundary directory");
            let same = manifest.matches_applied(applied.as_ref());
            let verified = if same && manifest.rebuild().is_some() {
                Ok(())
            } else if same
                && (manifest.records.count() > 2 * MAX_REBUILD_IDS as u64
                    || manifest.records.bytes() > MAX_EDIT_BYTES as u64)
            {
                // An ordinary Raft replay must not verify the whole population
                // inline. Keep prior readers on their root, withdraw this root
                // from the new selection and repair it under the writer's
                // existing bounded cursor at the committed position.
                owner.prefer_incremental.store(true, Ordering::Release);
                Err(anyhow::anyhow!(
                    "primary boundary exceeds the ordinary verification budget"
                ))
            } else if same {
                verify_rows(
                    &**store,
                    &manifest,
                    candidate,
                    store.plaintext_memory_owner(),
                )
            } else {
                Err(anyhow::anyhow!(
                    "replayed entry differs from the primary directory boundary"
                ))
            };
            return match verified {
                Ok(()) => Ok(None),
                Err(error) => {
                    owner.maintenance_due.store(true, Ordering::Release);
                    stale(
                        &manifest,
                        candidate,
                        applied,
                        error.context("replayed primary directory differs"),
                    )
                }
            };
        }
        Step::Stale(reason) => {
            owner.maintenance_due.store(true, Ordering::Release);
            let manifest = manifest.expect("stale directory");
            return stale(&manifest, candidate, applied, anyhow::anyhow!(reason));
        }
        Step::Edit => match manifest {
            Some(manifest) if !matches_predecessor(&manifest)? => {
                owner.maintenance_due.store(true, Ordering::Release);
                return stale(
                    &manifest,
                    candidate,
                    applied,
                    anyhow::anyhow!("primary predecessor differs from the selected Raft boundary"),
                );
            }
            Some(manifest) => manifest,
            None => {
                let selected =
                    SelectedGeneration::load(store, primary::FAMILY, &primary::INITIAL_SPACE)?;
                PrimaryManifest::new(
                    &candidate.tenant,
                    &candidate.incarnation,
                    candidate.revision_base,
                    previous.revision,
                    None,
                    selected.namespace(0),
                    TreeRoot::new_tree(),
                    0,
                    0,
                )
            }
        },
    };
    let prepare = |advance_cursor| {
        edit(
            owner,
            store,
            &base,
            candidate,
            (previous, changed),
            applied.clone(),
            advance_cursor,
        )
    };
    let publication = match prepare(true) {
        Err(error) if base.rebuild().is_some() && store.check_access().is_ok() => {
            // If the optional scan used the last grant, keep the complete
            // producer delta on the same partial root. The monitor can move
            // its cursor later under its own budget.
            owner.recover(store)?;
            prepare(false).map_err(|retry| retry.context(error))
        }
        result => result,
    };
    match publication {
        Ok(publication) => Ok(Some(publication)),
        Err(error) => {
            owner.maintenance_due.store(true, Ordering::Release);
            stale(&base, candidate, applied, error)
        }
    }
}

/// One scheduled step at the committed serving position. Its native
/// transactions can neither move Raft nor join a proposed command.
pub(crate) fn maintain(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    applied: &PrimaryApplied,
) -> Result<bool> {
    ensure!(
        state.revision_base.checked_add(applied.index) == Some(state.revision),
        "primary maintenance reached a different revision"
    );
    owner.recover(store)?;
    let may_replace = owner.advance_replacement_cleanup(store)?;
    let Some(manifest) = load_or_skip(store)? else {
        return Ok(false);
    };
    let publication = match manifest {
        Some(m)
            if m.tenant != state.tenant
                || m.incarnation != state.incarnation
                || m.revision_base != state.revision_base
                || m.revision > state.revision =>
        {
            return Ok(false);
        }
        Some(m)
            if m.is_current()
                && m.revision == state.revision
                && m.matches_applied(Some(applied)) =>
        {
            return Ok(may_replace);
        }
        Some(m)
            if m.rebuild().is_some()
                && m.revision == state.revision
                && m.applied.as_ref() == Some(applied) =>
        {
            Some(edit(
                owner,
                store,
                &m,
                state,
                (state, &ChangedIds::new()),
                Some(applied.clone()),
                true,
            )?)
        }
        _ if may_replace => {
            if pristine(state) {
                Some(PrimaryPublication::only(rebuild(
                    store,
                    state,
                    Some(applied.clone()),
                    MAX_EDIT_BYTES,
                    Some(owner),
                )?))
            } else {
                incremental::seed(owner, store, state, Some(applied.clone()))?
            }
        }
        _ => None,
    };
    if let Some(mut publication) = publication {
        store.write_batch(&publication.take_writes())?;
    }
    Ok(false)
}

/// A fresh stage can be selected only by the candidate's paired publication.
/// A lost publication leaves a sealed, unselected stage for family recovery.
/// Count the actual live and archive rows. The tenant's logical document
/// counter alone cannot bound both passes over the primary directory.
fn replace(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    candidate: &TenantState,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    if candidate.revision < owner.rebuild_after.load(Ordering::Acquire) {
        return Ok(None);
    }
    if owner.prefer_incremental.load(Ordering::Acquire) && !pristine(candidate) {
        return try_seed(owner, store, candidate, applied);
    }
    let mut remaining = MAX_REBUILD_IDS;
    for collection in candidate.collections.values() {
        let Some(count) = remaining
            .checked_sub(collection.documents.len())
            .and_then(|n| n.checked_sub(collection.archived_documents.len()))
        else {
            return try_seed(owner, store, candidate, applied);
        };
        remaining = count;
    }
    match rebuild(store, candidate, applied, MAX_EDIT_BYTES, Some(owner)) {
        Ok(writes) => Ok(Some(PrimaryPublication::only(writes))),
        Err(error) => {
            if let Err(access) = store.check_access() {
                return Err(error.context(access));
            }
            if error.is::<RebuildByteBudget>() {
                owner.prefer_incremental.store(true, Ordering::Release);
                return Ok(None);
            }
            owner.rebuild_after.store(
                candidate.revision.saturating_add(REBUILD_RETRY_REVISIONS),
                Ordering::Release,
            );
            tracing::warn!(
                revision = candidate.revision,
                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "bounded primary directory replacement did not complete"
            );
            Ok(None)
        }
    }
}

fn try_seed(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    match incremental::seed(owner, store, state, applied) {
        Ok(publication) => Ok(publication),
        Err(error) => {
            if let Err(access) = store.check_access() {
                return Err(error.context(access));
            }
            tracing::warn!(revision=state.revision,
                io_kind=?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "primary rebuild seed deferred");
            Ok(None)
        }
    }
}

fn stale(
    manifest: &PrimaryManifest,
    candidate: &TenantState,
    applied: Option<PrimaryApplied>,
    reason: anyhow::Error,
) -> Result<Option<PrimaryPublication>> {
    tracing::warn!(

        revision = candidate.revision,
        io_kind = ?reason.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
        "primary directory stops following ordinary apply until it is replaced"
    );
    // A replayed boundary that differs goes stale at its own revision.
    if candidate.revision < manifest.revision
        || (!manifest.is_current() && manifest.rebuild().is_none())
    {
        return Ok(None);
    }
    let applied = if manifest.revision == candidate.revision {
        manifest.applied.clone()
    } else {
        applied
    };
    Ok(Some(PrimaryPublication::only(vec![
        manifest.stale(candidate.revision, applied).write()?,
    ])))
}

fn edit(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    base: &PrimaryManifest,
    candidate: &TenantState,
    delta: (&TenantState, &ChangedIds),
    applied: Option<PrimaryApplied>,
    advance_cursor: bool,
) -> Result<PrimaryPublication> {
    let (previous, changed) = delta;
    let memory = store.plaintext_memory_owner();
    let mut status = base.status.clone();
    // A single decision covers pages created and then displaced in this same
    // edit. Failed or lost publications retain the original recovery journal.
    owner.pending();
    let edit = ordered_pages::edit_tree_staged_batches(
        store,
        &base.page_space,
        &base.records,
        MAX_EDIT_BATCHES,
        |apply| {
            let lease_count = 3 * WINDOW_IDS;
            let _lease_table = memory.clone().reserve_installed(u64::try_from(
                lease_count * std::mem::size_of::<kasumi_store::DiskMemoryLease>(),
            )?)?;
            let mut leases = Vec::new();
            leases.try_reserve_exact(lease_count)?;
            let mut rows = BTreeMap::new();
            let mut window_ids = 0;
            let mut input_bytes = 0usize;
            let mut flush = |rows: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>| -> Result<()> {
                let edits: Vec<_> = rows
                    .iter()
                    .map(|(key, value)| match value {
                        Some(value) => Edit::Put(key, value),
                        None => Edit::Delete(key),
                    })
                    .collect();
                apply(&edits)?;
                drop(edits);
                rows.clear();
                Ok(())
            };
            let mut add = |name: &str, id: &str| -> Result<()> {
                // Three tuple keys, their spare capacity, tree/Vec entries,
                // header value, and borrowed edit descriptors. Each encoded
                // primary value retains its separately measured original grant.
                let framing = 12 * (name.len() + id.len() + 8) + 3 * 256;
                let framing_lease = memory.clone().reserve_installed(u64::try_from(framing)?)?;
                leases.push(framing_lease);
                let added = application_records::primary_rows(
                    name,
                    candidate.collections.get(name),
                    id,
                    candidate.revision,
                    memory,
                    &mut rows,
                    &mut leases,
                )?;
                input_bytes = input_bytes
                    .checked_add(added + 3 * 96)
                    .context("primary edit byte total overflow")?;
                ensure!(
                    input_bytes <= MAX_EDIT_BYTES,
                    "primary edit exceeds its input work budget"
                );
                window_ids += 1;
                if window_ids == WINDOW_IDS {
                    flush(&mut rows)?;
                    leases.clear();
                    window_ids = 0;
                }
                Ok(())
            };
            let mut delta = 0usize;
            visit_changed_ids(previous, candidate, changed, |name, id| {
                add(name, id)?;
                delta += 1;
                Ok(())
            })?;
            if advance_cursor && let Some(progress) = base.rebuild() {
                let _cursor_workspace = memory.clone().reserve_installed(16 << 10)?;
                let reader = TreeReader::new(&**store, &base.page_space, base.records, None)?;
                status = incremental::advance(candidate, progress, delta, |name, id| {
                    if delta > 0
                        && (changed.get(name).is_some_and(|ids| ids.contains(id))
                            || application_records::has_primary_header(&reader, name, id)?)
                    {
                        // Every mutation after capture already edits this
                        // partial tree, wherever the cursor is.
                        return Ok(false);
                    }
                    add(name, id)?;
                    Ok(true)
                })?;
            }

            if !rows.is_empty() {
                flush(&mut rows)?;
            }
            Ok(())
        },
    )?;
    let staged = edit.staged_batches() > 0;
    let (root, mut writes, workspace) = edit.into_parts();
    if !staged {
        owner.settled();
    }
    let mut manifest = base.advance(
        candidate.revision,
        applied,
        root,
        candidate.document_count,
        candidate.logical_bytes,
    );
    if base.rebuild().is_some() && status == PrimaryStatus::Current {
        ensure!(
            manifest.document_count.checked_mul(2) == Some(root.count()),
            "completed primary rebuild row count differs"
        );
    }
    manifest.status = status;
    writes.push(manifest.write()?);
    Ok(PrimaryPublication {
        writes,
        _workspace: Some(workspace),
    })
}

#[cfg(test)]
#[path = "application_primary_tests.rs"]
mod tests;
