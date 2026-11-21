//! Ordinary structured index publication, reopen and reads.
//!
//! The directory is one ordered tree in its own page family. A row names a
//! collection, a field by its ordinal among the collection's indexed paths,
//! and then:
//!
//! - `P`: a document with a value at the path (null and arrays included);
//! - `V`: one posting, ordered by the canonical scalar and then the document
//!   ID, so equality is a prefix and a range is one ordered walk. A missing
//!   path is the scalar with tag zero, which answers absence;
//! - `D`: the complete bytes of a scalar too long for an ordered key. Its
//!   postings sort by the scalar's first bytes and then by its digest, and a
//!   range bound inside such a bucket compares these bytes.
//!
//! Every candidate publication that keeps the directory current edits exactly
//! the rows that differ between the previous and candidate indexes, which the
//! persistent index maps yield without opening a document. The fixed-size
//! manifest names the new root at the candidate's exact revision and applied
//! boundary, and both join the paired application/custody transaction with
//! the applied cursor. A small edit rides inside that transaction; a larger
//! one journals bounded batches first and publishes one owner decision.
//!
//! Reopen restores the older authenticated snapshot and replays the retained
//! log. Replayed entries below the directory's revision are covered and
//! publish nothing; the entry that reaches it must carry its exact boundary
//! and reproduce its rows. Entries beyond it edit forward. A store without a
//! current directory rebuilds one from the restored indexes in a fresh
//! generation that the restore publication selects.
//!
//! Small replacements use a bounded bulk build. An oversized replacement
//! selects an empty non-serving space and persists its captured producer and
//! document high key. The idle worker advances the native field-row cursor
//! under the apply gate. Ordinary accepted deltas immediately update the
//! partial tree, including keys behind the cursor. Readers use their selected
//! fallback until every captured field has been visited and the final native
//! promotion has committed. Superseded read views keep their original roots.
#[path = "application_structured_rebuild.rs"]
mod incremental;
pub(crate) use incremental::maintain;
#[cfg(test)]
pub(crate) use incremental::seed as seed_for_test;

#[path = "application_unique.rs"]
pub(crate) mod unique;

use anyhow::{Context, Result, ensure};
use kasumi_query::{FieldPredicate, FieldValue, QueryIndexes, StructuredRow};
use kasumi_store::{
    NamespaceStage, SelectedGeneration, TenantStore, WriteOp,
    ordered_pages::{
        self, Direction, Edit, MAX_KEY_BYTES, MAX_VALUE_BYTES, PageSource, TreeReader, TreeRoot,
    },
    structured_manifest::{self as structured, StructuredApplied, StructuredManifest},
};
use kasumi_types::TenantState;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Rows one ordinary publication may add and remove in place.
pub(crate) const MAX_EDIT_ROWS: usize = 2048;
/// Encoded key and value bytes of those rows.
pub(crate) const MAX_EDIT_BYTES: usize = 4 << 20;
/// Page rows and bytes an edit may carry inside the publication itself.
/// Larger edits journal bounded batches ahead of it.
const INLINE_EDIT_WRITES: usize = 32;
const INLINE_EDIT_BYTES: u64 = 512 << 10;
/// Presence and posting rows a publication may rebuild into a replacement
/// generation when the directory cannot follow it.
pub(crate) const MAX_REBUILD_ROWS: usize = 65_536;
const MAX_REBUILD_BYTES: usize = 16 << 20;
/// Revisions to wait before checking again whether an oversized index has
/// become small enough to rebuild.
const REBUILD_RETRY_REVISIONS: u64 = 4096;

const LONG: u8 = b'D';
const PRESENT: u8 = b'P';
const COMPOUND: u8 = b'U';
const POSTING: u8 = b'V';
/// Scalar bytes kept in an ordered key. Longer scalars order by this prefix
/// and their digest. Numbers always fit.
const INLINE_VALUE: usize = 224;
const DIGEST: usize = 32;

/// Per-installation custody of the directory's edit journal and replaced
/// generations. Only the apply owner reads or changes it.
pub(crate) struct StructuredOwner {
    recovery_pending: AtomicBool,
    rebuild_after: AtomicU64,
    pub(super) maintenance_due: AtomicBool,
    replacement: crate::directory_replacement::DirectoryReplacement,
}

impl Default for StructuredOwner {
    fn default() -> Self {
        // A process starts without knowing whether a previous one left
        // journaled batches behind.
        Self {
            recovery_pending: AtomicBool::new(true),
            rebuild_after: AtomicU64::new(0),
            maintenance_due: AtomicBool::new(true),
            replacement: Default::default(),
        }
    }
}

impl StructuredOwner {
    #[cfg(test)]
    pub(crate) fn finish_replacement_for_test(&self, store: &Arc<TenantStore>) -> Result<bool> {
        self.replacement
            .advance(store, structured::FAMILY, &structured::INITIAL_SPACE)
    }
    /// Finish displaced-row reclamation of published edits and abandon the
    /// rows of unpublished ones before the next edit begins.
    fn recover(&self, store: &Arc<TenantStore>) -> Result<()> {
        if self.recovery_pending.load(Ordering::Acquire) {
            ordered_pages::recover_abandoned_edits_in(store, structured::FAMILY)?;
            self.recovery_pending.store(false, Ordering::Release);
        }
        Ok(())
    }
}

fn log_sha256(log_id: &kasumi_raft::LogId<u64>) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    serde_json::to_writer(&mut hash, &("kasumi.structured.log.v1", log_id))?;
    Ok(hash.finalize().into())
}

/// The boundary of one ordinary or metadata entry. A command identity that
/// is not a SHA-256 digest is bound by its own digest instead of failing the
/// apply that carries it.
pub(crate) fn entry_applied(
    position: &kasumi_raft::AppliedEntryContext,
) -> Result<StructuredApplied> {
    entry_identity(&position.log_id, &position.command_sha256)
}

pub(crate) fn entry_identity(
    log: &kasumi_raft::LogId<u64>,
    digest: &str,
) -> Result<StructuredApplied> {
    let mut command = [0u8; 32];
    if hex::decode_to_slice(digest, &mut command).is_err() {
        command = Sha256::digest(digest.as_bytes()).into();
    }
    log_applied(log, Some(command))
}

pub(crate) fn log_applied(
    log: &kasumi_raft::LogId<u64>,
    command_sha256: Option<[u8; 32]>,
) -> Result<StructuredApplied> {
    Ok(StructuredApplied {
        index: log.index,
        log_sha256: log_sha256(log)?,
        command_sha256,
    })
}

/// A snapshot boundary carries its log position but no command.
pub(crate) fn snapshot_applied(
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
) -> Result<Option<StructuredApplied>> {
    meta.last_log_id
        .map(|log_id| log_applied(&log_id, None))
        .transpose()
}

/// Escape 0x00 as 0x00 0xFF so that a 0x00 0x01 or 0x00 0x02 terminator sorts
/// a shorter component before its extensions.
fn escape(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        out.push(*byte);
        if *byte == 0 {
            out.push(0xff);
        }
    }
}

fn field_prefix(kind: u8, collection: &str, field: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(collection.len() + 16);
    key.push(kind);
    escape(&mut key, collection.as_bytes());
    key.extend_from_slice(&[0, 1]);
    key.extend_from_slice(&(field as u64).to_be_bytes());
    key
}

/// Append the ordered scalar component: the type tag, then for numbers and
/// strings the escaped bytes and a terminator. Returns whether the scalar is
/// long: its component then ends with the digest of its complete bytes.
fn push_value(key: &mut Vec<u8>, value: &FieldValue<'_>) -> Result<bool> {
    ensure!(value.tag <= 5, "unknown structured scalar tag");
    key.push(value.tag);
    if value.tag < 4 {
        ensure!(
            value.bytes.is_empty(),
            "structured scalar carries a payload"
        );
        return Ok(false);
    }
    let bytes: &[u8] = &value.bytes;
    if bytes.len() <= INLINE_VALUE {
        escape(key, bytes);
        key.extend_from_slice(&[0, 1]);
        return Ok(false);
    }
    escape(key, &bytes[..INLINE_VALUE]);
    key.extend_from_slice(&[0, 2]);
    key.extend_from_slice(&Sha256::digest(bytes));
    Ok(true)
}

/// The length of the scalar component at the start of `rest`, and whether it
/// is a long scalar.
fn value_len(rest: &[u8]) -> Result<(usize, bool)> {
    let tag = *rest.first().context("truncated structured posting")?;
    ensure!(tag <= 5, "unknown structured scalar tag");
    if tag < 4 {
        return Ok((1, false));
    }
    let mut at = 1;
    loop {
        let byte = *rest.get(at).context("truncated structured scalar")?;
        if byte != 0 {
            at += 1;
            continue;
        }
        match rest.get(at + 1) {
            Some(0xff) => at += 2,
            Some(1) => return Ok((at + 2, false)),
            Some(2) => {
                ensure!(
                    rest.len() >= at + 2 + DIGEST,
                    "truncated structured scalar digest"
                );
                return Ok((at + 2 + DIGEST, true));
            }
            _ => anyhow::bail!("invalid structured scalar escape"),
        }
    }
}

/// The first key after every key that starts with `key`.
fn successor(mut key: Vec<u8>) -> Option<Vec<u8>> {
    while let Some(last) = key.pop() {
        if last != 0xff {
            key.push(last + 1);
            return Some(key);
        }
    }
    None
}

fn checked_key(key: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(
        key.len() <= MAX_KEY_BYTES,
        "structured row key exceeds the ordered key bound"
    );
    Ok(key)
}

/// Only the bounded native key is allocated. A long scalar remains borrowed
/// from the immutable input until the entire edit has storage admission.
fn encode_row<'a>(collection: &str, row: StructuredRow<'a>) -> Result<Option<(Vec<u8>, &'a [u8])>> {
    Ok(Some(match row {
        StructuredRow::Compound { index, key, id } => {
            let mut native = field_prefix(COMPOUND, collection, index);
            native.extend_from_slice(key);
            (checked_key(native)?, id.as_bytes())
        }
        StructuredRow::Present { field, id } => {
            let mut key = field_prefix(PRESENT, collection, field);
            key.extend_from_slice(id.as_bytes());
            (checked_key(key)?, &[][..])
        }
        StructuredRow::Posting { field, value, id } => {
            let mut key = field_prefix(POSTING, collection, field);
            push_value(&mut key, value)?;
            key.extend_from_slice(id.as_bytes());
            (checked_key(key)?, &[][..])
        }
        StructuredRow::Value { field, value } => {
            let mut key = field_prefix(LONG, collection, field);
            if !push_value(&mut key, value)? {
                return Ok(None);
            }
            ensure!(
                value.bytes.len() <= MAX_VALUE_BYTES,
                "structured scalar exceeds the ordered value bound"
            );
            (checked_key(key)?, value.bytes.as_ref())
        }
    }))
}

type Run<'a> = Vec<(Vec<u8>, kasumi_query::StructuredPostings<'a>)>;
type ValueVisitor<'v, 'a> =
    dyn FnMut(&[u8], bool, &kasumi_query::StructuredPostings<'a>) -> Result<()> + 'v;

fn flush_run<'a>(run: &mut Run<'a>, visit: &mut ValueVisitor<'_, 'a>) -> Result<()> {
    run.sort_by(|left, right| left.0.cmp(&right.0));
    for pair in run.windows(2) {
        ensure!(
            pair[0].0 != pair[1].0,
            "distinct long scalars share one digest"
        );
    }
    for (component, postings) in run.drain(..) {
        visit(&component, true, &postings)?;
    }
    Ok(())
}

/// A field's distinct scalars in key order. Resident order is canonical
/// scalar order, which is key order except inside a run of long scalars that
/// share their first bytes: those sort by digest. Such a run is contiguous,
/// so it is gathered, sorted and passed on before the next scalar.
fn ordered_values<'a>(
    field: &kasumi_query::StructuredField<'a>,
    mut visit: impl FnMut(&[u8], bool, &kasumi_query::StructuredPostings<'a>) -> Result<()>,
) -> Result<()> {
    let mut run: Run<'a> = Vec::new();
    for postings in field.values() {
        let mut component = Vec::new();
        if push_value(&mut component, &postings.value)? {
            let bucket = component.len() - DIGEST;
            if run
                .first()
                .is_some_and(|(first, _)| first[..first.len() - DIGEST] != component[..bucket])
            {
                flush_run(&mut run, &mut visit)?;
            }
            run.push((component, postings));
        } else {
            flush_run(&mut run, &mut visit)?;
            visit(&component, false, &postings)?;
        }
    }
    flush_run(&mut run, &mut visit)
}

/// This family has identical physical keys in the applied directory and a
/// verified immutable snapshot. Values are the complete owner IDs.
pub(crate) fn visit_compound_rows(
    indexes: &QueryIndexes,
    emit: &mut impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    indexes.visit_compound_rows(|name, index, key, id| -> Result<bool> {
        let mut native = field_prefix(COMPOUND, name, index);
        native.extend_from_slice(key);
        emit(&checked_key(native)?, id.as_bytes())?;
        Ok(true)
    })?;
    Ok(())
}

/// Every row of `indexes` in strictly increasing key order.
pub(crate) fn visit_rows(
    indexes: &QueryIndexes,
    mut emit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    for (name, fields) in indexes.structured_collections() {
        for (ordinal, field) in fields.enumerate() {
            let prefix = field_prefix(LONG, name, ordinal);
            ordered_values(&field, |component, long, postings| {
                if !long {
                    return Ok(());
                }
                ensure!(
                    postings.value.bytes.len() <= MAX_VALUE_BYTES,
                    "structured scalar exceeds the ordered value bound"
                );
                let mut key = prefix.clone();
                key.extend_from_slice(component);
                emit(&checked_key(key)?, &postings.value.bytes)
            })?;
        }
    }
    for (name, fields) in indexes.structured_collections() {
        for (ordinal, field) in fields.enumerate() {
            let mut key = field_prefix(PRESENT, name, ordinal);
            let prefix = key.len();
            for id in field.present() {
                key.truncate(prefix);
                key.extend_from_slice(id.as_bytes());
                ensure!(
                    key.len() <= MAX_KEY_BYTES,
                    "structured row key exceeds the ordered key bound"
                );
                emit(&key, &[])?;
            }
        }
    }
    visit_compound_rows(indexes, &mut emit)?;
    for (name, fields) in indexes.structured_collections() {
        for (ordinal, field) in fields.enumerate() {
            let prefix = field_prefix(POSTING, name, ordinal);
            ordered_values(&field, |component, _, postings| {
                let mut key = prefix.clone();
                key.extend_from_slice(component);
                let scalar = key.len();
                for id in postings.ids() {
                    key.truncate(scalar);
                    key.extend_from_slice(id.as_bytes());
                    ensure!(
                        key.len() <= MAX_KEY_BYTES,
                        "structured row key exceeds the ordered key bound"
                    );
                    emit(&key, &[])?;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

fn record_digest(hash: &mut Sha256, key: &[u8], length: u64, value_sha256: [u8; 32]) {
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
    hash.update(length.to_be_bytes());
    hash.update(value_sha256);
}

/// Stream the directory's tree and the rows of `indexes` and compare them
/// exactly, including the layout the row ordinals were written under.
pub(crate) fn verify_rows(
    source: &dyn PageSource,
    manifest: &StructuredManifest,
    state: &TenantState,
    indexes: &QueryIndexes,
) -> Result<()> {
    ensure!(
        manifest.tenant == state.tenant
            && manifest.incarnation == state.incarnation
            && manifest.revision_base == state.revision_base
            && manifest.revision == state.revision
            && manifest.layout_sha256 == indexes.structured_layout_sha256(),
        "structured directory scope or layout differs from the selected state"
    );
    let mut expected = Sha256::new();
    let mut remaining_rows = manifest.records.count();
    let mut remaining_bytes = manifest.records.bytes();
    visit_rows(indexes, |key, value| {
        remaining_rows = remaining_rows
            .checked_sub(1)
            .context("structured directory row count differs from the selected state")?;
        remaining_bytes = remaining_bytes
            .checked_sub(key.len() as u64)
            .and_then(|n| n.checked_sub(value.len() as u64))
            .context("structured directory byte count differs from the selected state")?;
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
        "structured directory row or byte count differs from the selected state"
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
        "structured directory rows differ from the selected state"
    );
    Ok(())
}

/// Count encoded native rows and bytes before synchronous build or proof. The
/// first refused row ends the visit. Only long strings can join a sort run.
fn bulk_workspace(indexes: &QueryIndexes) -> Option<u64> {
    if !indexes.structured_rows_within(MAX_REBUILD_ROWS) {
        return None;
    }
    let mut rows = 0usize;
    let mut bytes = 0usize;
    let mut charge = |size: usize| -> Option<()> {
        rows = rows.checked_add(1)?;
        bytes = bytes.checked_add(size)?;
        (rows <= MAX_REBUILD_ROWS && bytes <= MAX_REBUILD_BYTES).then_some(())
    };
    if !indexes
        .visit_compound_rows(|name, ordinal, key, id| -> Result<bool> {
            Ok(
                charge(field_prefix(COMPOUND, name, ordinal).len() + key.len() + id.len())
                    .is_some(),
            )
        })
        .ok()?
    {
        return None;
    }
    let mut largest = 0usize;
    for (collection, fields) in indexes.structured_collections() {
        for (ordinal, field) in fields.enumerate() {
            let prefix = field_prefix(PRESENT, collection, ordinal).len();
            for id in field.present() {
                charge(prefix + id.len())?;
            }
            let mut long = 0usize;
            for postings in field.values() {
                let mut component = Vec::new();
                if push_value(&mut component, &postings.value).ok()? {
                    charge(prefix + component.len() + postings.value.bytes.len())?;
                    long += 1;
                }
                for id in postings.ids() {
                    charge(prefix + component.len() + id.len())?;
                }
            }
            largest = largest.max(long);
        }
    }
    // Vec growth can retain twice the used capacity. Escaped prefixes can
    // double in size, and their temporary scalar components can also grow.
    Some(
        4096 + (largest as u64)
            * (4 * (INLINE_VALUE + DIGEST + 16)
                + 2 * std::mem::size_of::<(Vec<u8>, kasumi_query::StructuredPostings<'_>)>())
                as u64,
    )
}

/// Covered replay can only select rows it actually proved. Large trees move
/// to the recoverable non-serving path, including when a false small root
/// understates the selected resident input.
fn verify_bounded(
    source: &dyn PageSource,
    manifest: &StructuredManifest,
    state: &TenantState,
    indexes: &QueryIndexes,
) -> Result<()> {
    ensure!(
        manifest.records.count() <= MAX_REBUILD_ROWS as u64
            && manifest.records.bytes() <= MAX_REBUILD_BYTES as u64,
        "structured root exceeds the ordinary verification budget"
    );
    let cost = bulk_workspace(indexes)
        .context("structured input exceeds the ordinary verification budget")?;
    let _sort = source.memory().reserve_installed(cost)?;
    verify_rows(source, manifest, state, indexes)
}

/// Bulk-build the rows of `indexes` into a fresh staged generation. The
/// returned writes select it with its manifest and retire the replaced space;
/// they must join the publication that selects `state`.
fn rebuild(
    store: &Arc<TenantStore>,
    state: &TenantState,
    indexes: &QueryIndexes,
    applied: Option<StructuredApplied>,
    owner: Option<&StructuredOwner>,
    cost: u64,
) -> Result<Vec<WriteOp>> {
    let _sort = store
        .plaintext_memory_owner()
        .clone()
        .reserve_installed(cost)?;
    let family = SelectedGeneration::adopt(store, structured::FAMILY, &structured::INITIAL_SPACE)?;
    let stage = match owner {
        Some(owner) => owner
            .replacement
            .begin(store, structured::FAMILY, family.namespace(0))?,
        None => NamespaceStage::begin_generation(store, structured::FAMILY)?,
    };
    let records = ordered_pages::stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        visit_rows(indexes, |key, value| builder.push(key, value))
    })?;
    let manifest = StructuredManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision_base,
        state.revision,
        applied,
        indexes.structured_layout_sha256(),
        stage.namespace(),
        records,
    );
    let mut writes = family.switch_writes(store, &[&stage])?;
    writes.push(manifest.write()?);
    Ok(writes)
}

/// Under the restore's apply owner, before its publication. Reopen keeps a
/// current directory at or ahead of the snapshot; replay reaches it. Any
/// other case, and every installation, selects a rebuilt generation.
pub(crate) fn prepare_restore(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    indexes: &QueryIndexes,
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
    reopen: bool,
    writes: &mut Vec<WriteOp>,
) -> Result<()> {
    ordered_pages::recover_abandoned_edits_in(store, structured::FAMILY)?;
    owner.recovery_pending.store(false, Ordering::Release);
    NamespaceStage::reclaim_family(store, structured::FAMILY)?;
    owner.replacement.recovered()?;
    owner.maintenance_due.store(true, Ordering::Release);
    owner.rebuild_after.store(0, Ordering::Release);
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
            && manifest.matches_applied(applied.as_ref())
            && (manifest.rebuild().is_some()
                || verify_bounded(&**store, &manifest, state, indexes).is_ok())
        {
            return Ok(());
        }
    }
    // The replaced generation retires when this publication commits; the
    // next restore or replacement reclaims it in bounded batches.
    match bulk_workspace(indexes) {
        Some(cost) => writes.extend(rebuild(store, state, indexes, applied, None, cost)?),
        None => writes.extend(
            incremental::seed(owner, store, state, indexes, applied.as_ref())?.take_writes(),
        ),
    }
    Ok(())
}

/// The selected manifest. `Some(None)` when there is none; `None` when it
/// cannot be decoded or disagrees with its selection while access holds: the
/// directory is then neither edited nor trusted, and the next replacement
/// generation supersedes it (that switch never decodes its predecessor).
fn load_or_skip(store: &Arc<TenantStore>) -> Result<Option<Option<StructuredManifest>>> {
    match StructuredManifest::load(store) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => {
            if let Err(access) = store.check_access() {
                return Err(error.context(access));
            }
            tracing::error!(

                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "unreadable structured directory is ignored until it is replaced"
            );
            Ok(None)
        }
    }
}

/// Fixed writes for one candidate publication, and the workspace funding
/// their page rows until the publication returns.
pub(crate) struct StructuredPublication {
    writes: Vec<WriteOp>,
    _workspace: Option<ordered_pages::EditWorkspace>,
    _rows: Option<kasumi_store::DiskMemoryLease>,
}

impl StructuredPublication {
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
    /// No directory to follow, and none this candidate may start.
    Nothing,
    /// No current directory at or below the predecessor: a candidate may
    /// replace it with a rebuilt generation.
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
    manifest: Option<&StructuredManifest>,
    previous: &TenantState,
    previous_indexes: &QueryIndexes,
    candidate: &TenantState,
) -> Step {
    let Some(manifest) = manifest else {
        return if previous_indexes.structured_is_empty() {
            Step::Edit
        } else {
            Step::Replace
        };
    };
    if !manifest.is_current() && manifest.rebuild().is_none() {
        // A stale directory ahead of this candidate belongs to a later
        // position: covered replay must not move it.
        return if manifest.revision <= previous.revision {
            Step::Replace
        } else {
            Step::Nothing
        };
    }
    if manifest.tenant != candidate.tenant
        || manifest.incarnation != candidate.incarnation
        || manifest.revision_base != candidate.revision_base
    {
        return Step::Stale("structured directory scope differs from the candidate");
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
        return Step::Stale("structured directory revision differs from the predecessor");
    }
    Step::Edit
}

/// Under the apply owner, for every candidate publication. `None` publishes
/// nothing here: there is no directory to keep, or a covered replay is below
/// it. Every other failure to follow the candidate, including a replayed
/// boundary that differs, replaces a small directory or publishes a stale
/// manifest. The directory never fences a replica: an error is returned only
/// when access to the store itself is lost, which fails the apply's own
/// writes as well. Any other failure publishes nothing, and the next
/// candidate finds the directory behind its predecessor.
pub(crate) fn prepare_publication_at(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    previous: (&TenantState, &QueryIndexes),
    candidate: (&TenantState, &QueryIndexes),
    applied: Option<StructuredApplied>,
    matches_predecessor: impl FnOnce(&StructuredManifest) -> Result<bool>,
) -> Result<Option<StructuredPublication>> {
    match follow(
        owner,
        store,
        previous,
        candidate,
        applied,
        matches_predecessor,
    ) {
        Ok(publication) => Ok(publication),
        Err(error) => {
            owner.maintenance_due.store(true, Ordering::Release);
            if let Err(access) = store.check_access() {
                return Err(error.context(access));
            }
            tracing::error!(

                revision = candidate.0.revision,
                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "structured directory publication is skipped"
            );
            Ok(None)
        }
    }
}

fn follow(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    previous: (&TenantState, &QueryIndexes),
    candidate: (&TenantState, &QueryIndexes),
    applied: Option<StructuredApplied>,
    matches_predecessor: impl FnOnce(&StructuredManifest) -> Result<bool>,
) -> Result<Option<StructuredPublication>> {
    let (previous, previous_indexes) = previous;
    let (candidate, candidate_indexes) = candidate;
    if !owner
        .replacement
        .advance(store, structured::FAMILY, &structured::INITIAL_SPACE)?
    {
        owner.maintenance_due.store(true, Ordering::Release);
    }
    let Some(manifest) = load_or_skip(store)? else {
        return Ok(None);
    };
    let base = match step(manifest.as_ref(), previous, previous_indexes, candidate) {
        Step::Nothing | Step::Covered => return Ok(None),
        Step::Replace => {
            owner.maintenance_due.store(true, Ordering::Release);
            return Ok(replace(owner, store, candidate, candidate_indexes, applied));
        }
        Step::Boundary => {
            let manifest = manifest.expect("boundary directory");
            let binds_genesis = manifest.applied.is_none()
                && manifest.revision == manifest.revision_base
                && applied
                    .as_ref()
                    .is_some_and(|p| p.index == 0 && p.command_sha256.is_some());
            if manifest.rebuild().is_some() {
                if binds_genesis {
                    let mut bound = manifest;
                    bound.applied = applied;
                    return Ok(Some(StructuredPublication::only(vec![bound.write()?])));
                }
                if manifest.matches_applied(applied.as_ref()) {
                    return Ok(None);
                }
                owner.maintenance_due.store(true, Ordering::Release);
                return stale(
                    &manifest,
                    candidate,
                    applied,
                    anyhow::anyhow!("covered structured rebuild differs from its producer"),
                );
            }
            let same = binds_genesis || manifest.matches_applied(applied.as_ref());
            let verified = if same {
                verify_bounded(&**store, &manifest, candidate, candidate_indexes)
            } else {
                Err(anyhow::anyhow!(
                    "replayed entry differs from the structured directory boundary"
                ))
            };
            return match verified {
                Ok(()) if binds_genesis => {
                    let mut bound = manifest;
                    bound.applied = applied;
                    Ok(Some(StructuredPublication::only(vec![bound.write()?])))
                }
                Ok(()) => Ok(None),
                Err(error) => {
                    owner.maintenance_due.store(true, Ordering::Release);
                    store.check_access()?;
                    stale(
                        &manifest,
                        candidate,
                        applied,
                        error.context("replayed structured directory differs"),
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
                    anyhow::anyhow!("structured predecessor differs from selected Raft boundary"),
                );
            }
            Some(manifest) => manifest,
            None => {
                let selected = SelectedGeneration::load(
                    store,
                    structured::FAMILY,
                    &structured::INITIAL_SPACE,
                )?;
                StructuredManifest::new(
                    &candidate.tenant,
                    &candidate.incarnation,
                    candidate.revision_base,
                    previous.revision,
                    None,
                    previous_indexes.structured_layout_sha256(),
                    selected.namespace(0),
                    TreeRoot::new_tree(),
                )
            }
        },
    };
    let reason = match edit(
        owner,
        store,
        &base,
        previous_indexes,
        candidate,
        candidate_indexes,
        applied.clone(),
    ) {
        Ok(Some(publication)) => return Ok(Some(publication)),
        Ok(None) => anyhow::anyhow!("structured edit exceeds its ordinary bound"),
        Err(error) => error,
    };
    store.check_access()?;
    owner.maintenance_due.store(true, Ordering::Release);
    if base.rebuild().is_some() {
        return stale(&base, candidate, applied, reason);
    }
    if let Some(publication) = replace(owner, store, candidate, candidate_indexes, applied.clone())
    {
        tracing::info!(

            revision = candidate.revision,
            reason = %format!("{reason:#}"),
            "structured directory is rebuilt instead of edited"
        );
        return Ok(Some(publication));
    }
    stale(&base, candidate, applied, reason)
}

/// A rebuilt replacement generation for this candidate, when its whole index
/// is small enough to build inside one publication. A refused or failed build
/// leaves the directory as it is.
fn replace(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    candidate: &TenantState,
    indexes: &QueryIndexes,
    applied: Option<StructuredApplied>,
) -> Option<StructuredPublication> {
    if candidate.revision < owner.rebuild_after.load(Ordering::Acquire) {
        return None;
    }
    let retry = || {
        owner.rebuild_after.store(
            candidate.revision.saturating_add(REBUILD_RETRY_REVISIONS),
            Ordering::Release,
        )
    };
    let Some(cost) = bulk_workspace(indexes) else {
        owner.maintenance_due.store(true, Ordering::Release);
        let applied = applied.as_ref();
        return match incremental::seed(owner, store, candidate, indexes, applied) {
            Ok(publication) => Some(publication),
            Err(error) => {
                tracing::warn!(revision=candidate.revision, io_kind=?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind), "structured rebuild seed deferred");
                None
            }
        };
    };
    let built = (|| {
        // An earlier attempt whose publication never committed left a sealed
        // stage; a committed one left the generation it replaced.
        owner.recover(store)?;
        rebuild(store, candidate, indexes, applied, Some(owner), cost)
    })();
    match built {
        Ok(writes) => Some(StructuredPublication::only(writes)),
        Err(error) => {
            retry();
            tracing::warn!(

                revision = candidate.revision,
                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "structured directory could not be rebuilt in this publication"
            );
            None
        }
    }
}

fn stale(
    manifest: &StructuredManifest,
    candidate: &TenantState,
    applied: Option<StructuredApplied>,
    reason: anyhow::Error,
) -> Result<Option<StructuredPublication>> {
    tracing::warn!(

        revision = candidate.revision,
        io_kind = ?reason.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
        "structured directory stops following ordinary apply until it is replaced"
    );
    // A replayed boundary that differs goes stale at its own revision.
    if candidate.revision < manifest.revision
        || (!manifest.is_current() && manifest.rebuild().is_none())
    {
        return Ok(None);
    }
    Ok(Some(StructuredPublication::only(vec![
        manifest.stale(candidate.revision, applied).write()?,
    ])))
}

fn edit(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    base: &StructuredManifest,
    previous_indexes: &QueryIndexes,
    candidate: &TenantState,
    candidate_indexes: &QueryIndexes,
    applied: Option<StructuredApplied>,
) -> Result<Option<StructuredPublication>> {
    owner.recover(store)?;
    let layout = candidate_indexes.structured_layout_sha256();
    if base.format < structured::ORDERED_TUPLE_FORMAT {
        return Ok(None);
    }
    if base.rebuild().is_some() && layout != base.layout_sha256 {
        return Ok(None);
    }
    let memory = store.plaintext_memory_owner();
    let mut key_workspace = None;
    let mut operations = 0usize;
    let mut bytes = 0usize;
    let mut allocations = 0usize;
    // Both generations are immutable. Quote the producer stream without
    // retaining rows, before any map node, edit array or payload is allocated.
    let within = candidate_indexes.visit_structured_changes(
        previous_indexes,
        |collection, added, row| -> Result<bool> {
            if let StructuredRow::Value { value, .. } = row {
                if value.bytes.len() <= INLINE_VALUE {
                    return Ok(true);
                }
                if value.bytes.len() > MAX_EDIT_BYTES {
                    return Ok(false);
                }
            }
            if key_workspace.is_none() {
                key_workspace = Some(
                    memory
                        .clone()
                        .reserve_installed((4 * MAX_KEY_BYTES) as u64)?,
                );
            }
            let Some((key, value)) = encode_row(collection, row)? else {
                return Ok(true);
            };
            operations += 1;
            bytes += key.len() + value.len();
            allocations += key.capacity() + if added { value.len() } else { 0 };
            // A row appears at most once in each generation: a removal and
            // then an insertion may map to the same native key.
            Ok(bytes <= MAX_EDIT_BYTES && operations <= 2 * MAX_EDIT_ROWS)
        },
    )?;
    if !within {
        return Ok(None);
    }
    let mut next = base.advance(candidate.revision, applied, layout, base.records);
    next.status = base.status.clone();
    if operations == 0 {
        return Ok(Some(StructuredPublication::only(vec![next.write()?])));
    }
    // The fixed allowance funds a partially filled B-tree root. Per-row
    // framing includes both a map slot and its borrowed Edit descriptor.
    let retained = allocations + 2048 + 256 * operations.min(MAX_EDIT_ROWS + 1);
    let rows_lease = memory.clone().reserve_installed(retained.try_into()?)?;
    let mut rows = BTreeMap::new();
    let within = candidate_indexes.visit_structured_changes(
        previous_indexes,
        |collection, added, row| -> Result<bool> {
            if let Some((key, value)) = encode_row(collection, row)? {
                rows.insert(key, added.then(|| value.to_vec()));
            }
            Ok(rows.len() <= MAX_EDIT_ROWS)
        },
    )?;
    if !within {
        return Ok(None);
    }
    let edits: Vec<Edit<'_>> = rows
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    // Most writes change a few leaves: their pages ride in the publication.
    let inline = ordered_pages::edit_tree(&**store, &base.page_space, &base.records, &edits)?;
    let edit =
        if inline.writes().len() <= INLINE_EDIT_WRITES && inline.put_bytes() <= INLINE_EDIT_BYTES {
            inline
        } else {
            drop(inline);
            // A staged edit writes journaled batches before its publication.
            owner.recovery_pending.store(true, Ordering::Release);
            ordered_pages::edit_tree_staged_batches(
                store,
                &base.page_space,
                &base.records,
                incremental::MAX_BATCHES,
                |apply| apply(&edits),
            )?
        };
    let (root, mut writes, workspace) = edit.into_parts();
    drop(edits);
    next.records = root;
    writes.push(next.write()?);
    Ok(Some(StructuredPublication {
        writes,
        _workspace: Some(workspace),
        _rows: Some(rows_lease),
    }))
}

pub(crate) fn ordered_unique_window(
    reader: &TreeReader<'_>,
    collection: &str,
    index: usize,
    lower: Bound<&[u8]>,
    upper: Bound<&[u8]>,
    descending: bool,
    mut keep_reading: impl FnMut() -> bool,
) -> Result<kasumi_query::OrderedTupleWindow> {
    let prefix = field_prefix(COMPOUND, collection, index);
    let mut start_key = prefix.clone();
    let bound = if descending { upper } else { lower };
    let start = match bound {
        Bound::Included(key) | Bound::Excluded(key) => {
            ensure!(
                key.len() <= kasumi_query::MAX_ORDERED_TUPLE_BYTES,
                "ordered tuple range exceeds native bound"
            );
            start_key.extend_from_slice(key);
            if matches!(bound, Bound::Included(_)) {
                Bound::Included(start_key.as_slice())
            } else {
                Bound::Excluded(start_key.as_slice())
            }
        }
        Bound::Unbounded if descending => {
            start_key = successor(start_key).context("compound prefix successor absent")?;
            Bound::Excluded(start_key.as_slice())
        }
        Bound::Unbounded => Bound::Included(start_key.as_slice()),
    };
    let mut rows = Vec::with_capacity(kasumi_query::ORDERED_TUPLE_WINDOW);
    let direction = if descending {
        Direction::Reverse
    } else {
        Direction::Forward
    };
    reader.scan(start, direction, &mut |key, value| {
        if !keep_reading() {
            return Ok(false);
        }
        let Some(key) = key.strip_prefix(prefix.as_slice()) else {
            return Ok(false);
        };
        if !RangeBounds::<[u8]>::contains(&(lower, upper), key) {
            return Ok(false);
        }
        ensure!(
            !key.is_empty() && key.len() <= kasumi_query::MAX_ORDERED_TUPLE_BYTES,
            "invalid selected compound key"
        );
        let ordered_pages::ValueRef::Inline(id) = value else {
            anyhow::bail!("compound owner exceeds inline bound")
        };
        let id = posting_id(id)?;
        rows.push((key.to_vec(), id.to_owned()));
        Ok(rows.len() < kasumi_query::ORDERED_TUPLE_WINDOW)
    })?;
    Ok(rows)
}

fn posting_id(id: &[u8]) -> Result<&str> {
    let id = std::str::from_utf8(id)?;
    kasumi_types::validate_name(id)?;
    Ok(id)
}

/// Visit the IDs under one exact key prefix in ID order. Returns whether the
/// visitor wants more.
fn scan_ids(
    reader: &TreeReader<'_>,
    prefix: &[u8],
    check: &mut dyn FnMut() -> Result<()>,
    visit: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    let mut more = true;
    reader.scan(
        Bound::Included(prefix),
        Direction::Forward,
        &mut |key, value| {
            let Some(id) = key.strip_prefix(prefix) else {
                return Ok(false);
            };
            check()?;
            ensure!(value.is_empty(), "structured posting carries a payload");
            more = visit(posting_id(id)?)?;
            Ok(more)
        },
    )?;
    Ok(more)
}

/// Compare a long scalar's stored bytes with `target`. `None` when the
/// directory holds no such scalar.
fn long_order(
    reader: &TreeReader<'_>,
    collection: &str,
    field: usize,
    component: &[u8],
    target: &[u8],
) -> Result<Option<std::cmp::Ordering>> {
    let mut key = field_prefix(LONG, collection, field);
    key.extend_from_slice(component);
    reader.compare_value_at(&key, target, MAX_VALUE_BYTES)
}

/// One range bound as key positions.
struct Edge<'a> {
    /// The scalar component, without the digest for a long scalar.
    component: Vec<u8>,
    /// A long scalar's complete bytes: postings in its bucket compare them.
    long: Option<std::borrow::Cow<'a, [u8]>>,
    inclusive: bool,
}

impl<'a> Edge<'a> {
    fn from_bound(
        bound: Bound<&'a serde_json::Value>,
        kind: kasumi_types::ScalarType,
    ) -> Result<Option<Self>> {
        match bound {
            Bound::Unbounded => Ok(None),
            Bound::Included(value) => Self::new(value, kind, true).map(Some),
            Bound::Excluded(value) => Self::new(value, kind, false).map(Some),
        }
    }
    fn new(
        value: &'a serde_json::Value,
        kind: kasumi_types::ScalarType,
        inclusive: bool,
    ) -> Result<Self> {
        let value = FieldValue::predicate(value, kind)?;
        ensure!(
            value.tag >= 2,
            "ordered comparison requires a non-null scalar"
        );
        let mut component = Vec::new();
        let long = push_value(&mut component, &value)?;
        if long {
            component.truncate(component.len() - DIGEST);
        }
        Ok(Self {
            component,
            long: long.then_some(value.bytes),
            inclusive,
        })
    }
}

/// The bound whose long scalar shares `bucket`, the first bytes of a row's.
fn in_bucket<'e, 'a>(edge: &'e Option<Edge<'a>>, bucket: &[u8]) -> Option<&'e Edge<'a>> {
    edge.as_ref()
        .filter(|edge| edge.long.is_some() && edge.component == bucket)
}

/// Visit the document IDs one field predicate selects, reading only the
/// postings it names. Equality, containment, presence and absence are one
/// ID-ordered prefix. Membership visits each distinct scalar's prefix once.
/// A range walks its scalars in key order, each scalar's IDs in ID order.
/// `check` runs before every row so the walk stays cancellable.
pub(crate) fn visit_posting(
    reader: &TreeReader<'_>,
    collection: &str,
    field: usize,
    predicate: FieldPredicate<'_>,
    mut check: impl FnMut() -> Result<()>,
    mut visit: impl FnMut(&str) -> Result<bool>,
) -> Result<()> {
    check()?;
    let base = field_prefix(POSTING, collection, field);
    // One scalar's postings, after confirming a long scalar's exact bytes.
    let scalar = |value: &FieldValue<'_>,
                  check: &mut dyn FnMut() -> Result<()>,
                  visit: &mut dyn FnMut(&str) -> Result<bool>|
     -> Result<bool> {
        let mut prefix = base.clone();
        if push_value(&mut prefix, value)? {
            check()?;
            match long_order(
                reader,
                collection,
                field,
                &prefix[base.len()..],
                &value.bytes,
            )? {
                None => return Ok(true),
                Some(std::cmp::Ordering::Equal) => {}
                Some(_) => anyhow::bail!("distinct long scalars share one digest"),
            }
        }
        scan_ids(reader, &prefix, check, visit)
    };
    match predicate {
        FieldPredicate::Exists(true) => {
            let prefix = field_prefix(PRESENT, collection, field);
            scan_ids(reader, &prefix, &mut check, &mut visit)?;
        }
        FieldPredicate::Exists(false) => {
            let mut prefix = base.clone();
            prefix.push(0);
            scan_ids(reader, &prefix, &mut check, &mut visit)?;
        }
        FieldPredicate::Equals { value, kind } => {
            scalar(&FieldValue::predicate(value, kind)?, &mut check, &mut visit)?;
        }
        FieldPredicate::In { values, kind } => {
            ensure!(
                values.len() <= kasumi_types::MAX_FILTER_IN_VALUES,
                "too many indexed membership values"
            );
            // Equal scalars, including decimal spellings that normalize
            // alike, name one posting: read it once, in scalar order.
            let mut distinct = BTreeMap::new();
            for value in values {
                let value = FieldValue::predicate(value, kind)?;
                let mut component = Vec::new();
                push_value(&mut component, &value)?;
                distinct.insert(component, value);
            }
            for value in distinct.values() {
                if !scalar(value, &mut check, &mut visit)? {
                    break;
                }
            }
        }
        FieldPredicate::Range { lower, upper, kind } => {
            let (lower, upper) = (
                Edge::from_bound(lower, kind)?,
                Edge::from_bound(upper, kind)?,
            );
            let key = |component: &[u8]| {
                let mut key = base.clone();
                key.extend_from_slice(component);
                key
            };
            // Missing and null sort ahead of every comparable scalar.
            let start = match &lower {
                None => key(&[2]),
                Some(edge) if edge.long.is_some() || edge.inclusive => key(&edge.component),
                Some(edge) => match successor(key(&edge.component)) {
                    Some(start) => start,
                    None => return Ok(()),
                },
            };
            let end = match &upper {
                None => None,
                Some(edge) if edge.long.is_some() || edge.inclusive => {
                    successor(key(&edge.component))
                }
                Some(edge) => Some(key(&edge.component)),
            };
            if end.as_ref().is_some_and(|end| *end <= start) {
                return Ok(());
            }
            // The last long scalar decided, so each is compared once.
            let mut decided: Option<(Vec<u8>, bool)> = None;
            reader.scan(
                Bound::Included(&start),
                Direction::Forward,
                &mut |row, value| {
                    let Some(rest) = row.strip_prefix(base.as_slice()) else {
                        return Ok(false);
                    };
                    if end.as_ref().is_some_and(|end| row >= end.as_slice()) {
                        return Ok(false);
                    }
                    check()?;
                    ensure!(value.is_empty(), "structured posting carries a payload");
                    let (length, long) = value_len(rest)?;
                    let (component, id) = rest.split_at(length);
                    if long {
                        let bucket = &component[..length - DIGEST];
                        let (low, high) = (in_bucket(&lower, bucket), in_bucket(&upper, bucket));
                        if low.is_some() || high.is_some() {
                            let known = decided
                                .as_ref()
                                .filter(|(known, _)| known.as_slice() == component)
                                .map(|(_, keep)| *keep);
                            let keep = match known {
                                Some(keep) => keep,
                                None => {
                                    let mut keep = true;
                                    for (edge, below) in [(low, true), (high, false)] {
                                        let Some(edge) = edge else { continue };
                                        let bound = edge.long.as_deref().expect("long bound");
                                        let order = long_order(
                                            reader, collection, field, component, bound,
                                        )?
                                        .context("long scalar lost its bytes")?;
                                        keep &= match order {
                                            std::cmp::Ordering::Equal => edge.inclusive,
                                            std::cmp::Ordering::Greater => below,
                                            std::cmp::Ordering::Less => !below,
                                        };
                                    }
                                    decided = Some((component.to_vec(), keep));
                                    keep
                                }
                            };
                            if !keep {
                                return Ok(true);
                            }
                        }
                    }
                    visit(posting_id(id)?)
                },
            )?;
        }
    }
    check()
}

#[cfg(test)]
#[path = "application_structured_tests.rs"]
mod tests;
