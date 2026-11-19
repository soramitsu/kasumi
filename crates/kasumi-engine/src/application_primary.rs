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
//! fencing the replica; nothing edits a stale directory until the next
//! restore replaces it. Staged edit batches written before a publication that
//! never commits are journaled and recovered under the same apply owner.
use crate::application_records;
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    NamespaceStage, NodeDiskMemoryAdmission, SelectedGeneration, TenantStore, WriteOp,
    ordered_pages::{self, Direction, Edit, PageSource, TreeReader, TreeRoot},
    primary_manifest::{self as primary, PrimaryApplied, PrimaryManifest},
};
use kasumi_types::{CollectionState, TenantState};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Changed document IDs by collection, as the accepted producer supplies them.
pub(crate) type ChangedIds = BTreeMap<String, BTreeSet<String>>;

/// Documents one ordinary publication may edit in place.
pub(crate) const MAX_EDIT_IDS: usize = 4096;
/// Encoded key and value bytes of those documents' rows.
pub(crate) const MAX_EDIT_BYTES: usize = 16 << 20;

/// Per-engine edit journal custody. Only the apply owner reads or changes it.
pub(crate) struct PrimaryOwner {
    recovery_pending: AtomicBool,
}

impl Default for PrimaryOwner {
    fn default() -> Self {
        // A process starts without knowing whether a previous one left
        // journaled batches behind.
        Self {
            recovery_pending: AtomicBool::new(true),
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
    let mut command = [0u8; 32];
    hex::decode_to_slice(&position.command_sha256, &mut command)
        .context("applied command digest is not SHA-256")?;
    Ok(PrimaryApplied {
        index: position.log_id.index,
        log_sha256: log_sha256(&position.log_id)?,
        command_sha256: Some(command),
    })
}

/// A snapshot boundary carries its log position but no command.
pub(crate) fn snapshot_applied(
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
) -> Result<Option<PrimaryApplied>> {
    meta.last_log_id
        .map(|log_id| {
            Ok(PrimaryApplied {
                index: log_id.index,
                log_sha256: log_sha256(&log_id)?,
                command_sha256: None,
            })
        })
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
    let mut expected = Sha256::new();
    application_records::visit_primary(state, memory, |key, value| {
        record_digest(
            &mut expected,
            key,
            value.len() as u64,
            Sha256::digest(value).into(),
        );
        Ok(())
    })?;
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

/// Bulk-build `state`'s rows into a fresh staged generation. The returned
/// writes select it with its manifest and retire the replaced space; they
/// must join the publication that selects `state`.
fn rebuild(
    store: &Arc<TenantStore>,
    state: &TenantState,
    applied: Option<PrimaryApplied>,
) -> Result<Vec<WriteOp>> {
    let family = SelectedGeneration::adopt(store, primary::FAMILY, &primary::INITIAL_SPACE)?;
    let stage = NamespaceStage::begin_generation(store, primary::FAMILY)?;
    let memory = store.plaintext_memory_owner().clone();
    let records = ordered_pages::stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        application_records::visit_primary(state, &memory, |key, value| builder.push(key, value))
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
    let applied = snapshot_applied(meta)?;
    if reopen
        && let Some(Some(manifest)) = load_or_skip(store)?
        && manifest.is_current()
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
            && verify_rows(&**store, &manifest, state, store.plaintext_memory_owner()).is_ok()
        {
            return Ok(());
        }
    }
    writes.extend(rebuild(store, state, applied)?);
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
            store.check_access()?;
            tracing::error!(
                tenant = %store.tenant(),
                error = %format!("{error:#}"),
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
    _rows: Option<kasumi_store::DiskMemoryLease>,
}

impl PrimaryPublication {
    pub(crate) fn take_writes(&mut self) -> Vec<WriteOp> {
        std::mem::take(&mut self.writes)
    }
    fn only(writes: Vec<WriteOp>) -> Self {
        Self {
            writes,
            _workspace: None,
            _rows: None,
        }
    }
}

/// What the directory must do for one candidate.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// No current directory to keep (absent and not pristine, or stale).
    Nothing,
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
            Step::Nothing
        };
    };
    if !manifest.is_current() {
        return Step::Nothing;
    }
    if manifest.tenant != candidate.tenant
        || manifest.incarnation != candidate.incarnation
        || manifest.revision_base != candidate.revision_base
    {
        return Step::Stale("primary directory scope differs from the candidate");
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

/// The document IDs whose rows can differ between the two states, or `None`
/// beyond the edit bound. Same-definition collections are covered by the
/// producer's exact delta (Accepted rejects a changed map without one); a new,
/// removed or redefined collection contributes every ID whose maps differ.
fn changed_ids(
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    let mut ids = changed.clone();
    let mut count: usize = ids.values().map(BTreeSet::len).sum();
    if count > MAX_EDIT_IDS {
        return None;
    }
    let names: BTreeSet<&String> = previous
        .collections
        .keys()
        .chain(candidate.collections.keys())
        .collect();
    let same = |old: &CollectionState, new: &CollectionState| {
        old.documents.ptr_eq(&new.documents)
            && old.archived_documents.ptr_eq(&new.archived_documents)
    };
    for name in names {
        let old = previous.collections.get(name);
        let new = candidate.collections.get(name);
        match (old, new) {
            (Some(old), Some(new))
                if Arc::ptr_eq(&old.definition, &new.definition)
                    || same(old, new)
                    || old.definition == new.definition =>
            {
                continue;
            }
            _ => {}
        }
        let entry = ids.entry(name.clone()).or_default();
        for collection in [old, new].into_iter().flatten() {
            for id in crate::index_source::resident_ids_after(collection, None) {
                if entry.insert(id.clone()) {
                    count += 1;
                    if count > MAX_EDIT_IDS {
                        return None;
                    }
                }
            }
        }
        if entry.is_empty() {
            ids.remove(name);
        }
    }
    Some(ids)
}

/// Under the apply owner, after the candidate's after-images are stored.
/// `None` publishes nothing here: there is no current directory to keep, or a
/// covered replay is below it. Every other failure to follow the candidate,
/// including a replayed boundary that differs, publishes a stale manifest;
/// errors are reserved for failing to read the selected manifest itself.
pub(crate) fn prepare_publication(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    let Some(manifest) = load_or_skip(store)? else {
        return Ok(None);
    };
    let base = match step(manifest.as_ref(), previous, candidate) {
        Step::Nothing | Step::Covered => return Ok(None),
        Step::Boundary => {
            let manifest = manifest.expect("boundary directory");
            let same = manifest.applied.as_ref().zip(applied.as_ref()).map_or(
                manifest.applied.is_none() && applied.is_none(),
                |(selected, replayed)| selected.same_position(replayed),
            );
            let verified = if same {
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
                Err(error) => stale(
                    &manifest,
                    candidate,
                    applied,
                    error.context("replayed primary directory differs"),
                ),
            };
        }
        Step::Stale(reason) => {
            let manifest = manifest.expect("stale directory");
            return stale(&manifest, candidate, applied, anyhow::anyhow!(reason));
        }
        Step::Edit => match manifest {
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
    match edit(
        owner,
        store,
        &base,
        previous,
        candidate,
        changed,
        applied.clone(),
    ) {
        Ok(Some(publication)) => Ok(Some(publication)),
        Ok(None) => stale(
            &base,
            candidate,
            applied,
            anyhow::anyhow!("primary edit exceeds its ordinary bound"),
        ),
        Err(error) => stale(&base, candidate, applied, error),
    }
}

fn stale(
    manifest: &PrimaryManifest,
    candidate: &TenantState,
    applied: Option<PrimaryApplied>,
    reason: anyhow::Error,
) -> Result<Option<PrimaryPublication>> {
    tracing::warn!(
        tenant = %candidate.tenant,
        revision = candidate.revision,
        error = %format!("{reason:#}"),
        "primary directory stops following ordinary apply until the next restore"
    );
    // A replayed boundary that differs goes stale at its own revision.
    if candidate.revision < manifest.revision || !manifest.is_current() {
        return Ok(None);
    }
    Ok(Some(PrimaryPublication::only(vec![
        manifest.stale(candidate.revision, applied).write()?,
    ])))
}

fn edit(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    base: &PrimaryManifest,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &ChangedIds,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    owner.recover(store)?;
    let Some(ids) = changed_ids(previous, candidate, changed) else {
        return Ok(None);
    };
    let memory = store.plaintext_memory_owner();
    let mut rows = BTreeMap::new();
    let mut bytes = 0usize;
    for (name, set) in &ids {
        let collection = candidate.collections.get(name);
        for id in set {
            bytes = bytes.saturating_add(application_records::primary_rows(
                name,
                collection,
                id,
                candidate.revision,
                memory,
                &mut rows,
            )?);
            if bytes > MAX_EDIT_BYTES {
                return Ok(None);
            }
        }
    }
    let rows_lease = memory
        .clone()
        .reserve_installed(u64::try_from(bytes)? + 96 * rows.len() as u64)?;
    let edits: Vec<Edit<'_>> = rows
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    // A staged edit writes journaled batches before its publication.
    owner.pending();
    let edit = ordered_pages::edit_tree_staged(store, &base.page_space, &base.records, &edits)?;
    let staged = edit.staged_batches() > 0;
    let (root, mut writes, workspace) = edit.into_parts();
    drop(edits);
    if !staged {
        owner.settled();
    }
    writes.push(
        base.advance(
            candidate.revision,
            applied,
            root,
            candidate.document_count,
            candidate.logical_bytes,
        )
        .write()?,
    );
    Ok(Some(PrimaryPublication {
        writes,
        _workspace: Some(workspace),
        _rows: Some(rows_lease),
    }))
}

#[cfg(test)]
#[path = "application_primary_tests.rs"]
mod tests;
