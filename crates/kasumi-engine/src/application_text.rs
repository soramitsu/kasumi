//! The persisted text directory: bounded Tantivy shards of every text-indexed
//! collection, kept in the `kasumi.app.text` family's ordered tree.
//!
//! Every ordinary publication edits the tree for its changed documents and
//! advances the [`TextManifest`] in the same native transaction as the applied
//! cursor, so a selection's pinned root holds the directory of exactly its
//! revision. A rebuild (first directory, changed text definition with live
//! rows, stale directory, snapshot install) stages a fresh generation in
//! bounded batches and selects it with that publication. Readers search the
//! directory their selection pinned; replaced generations stay readable to
//! them through the native root and are reclaimed in bounded batches.
//!
//! Tree layout, per collection name `c` (names hold no NUL):
//!
//! | key                             | value                       |
//! |---------------------------------|-----------------------------|
//! | `c 0x00 0x01 seq 0x00 file`     | one shard file              |
//! | `c 0x00 0x01 seq 0x01`          | shard descriptor            |
//! | `c 0x00 0x02 level seq`         | level index entry (empty)   |
//! | `c 0x00 0x03`                   | collection descriptor       |
//!
//! A shard never changes. A changed live document is indexed again in a new
//! shard; readers keep a row only while its stored version is the selected
//! live version. Shards merge in groups of [`FANIN`] at one level, dropping
//! superseded rows, at most [`MAX_MERGES_PER_PUBLICATION`] per publication.
//! Full shards are sealed; a bounded compaction step rewrites one sealed shard
//! per publication while superseded rows dominate the collection.
use crate::admission::{NodeAdmission, Reservation};
use anyhow::{Context, Result, ensure};
use kasumi_query::{
    BuiltTextShard, MAX_SHARD_BYTES, MAX_SHARD_DOCUMENTS, TextShard, TextShardLayout, TextShardSet,
    TextShardWriter, merge_text_shards,
};
use kasumi_store::{
    NamespaceStage, NodeDiskMemoryAdmission, SelectedGeneration, TenantStore, WriteOp,
    ordered_pages::{
        self, Direction, Edit, EditWorkspace, PageSource, TreeReader, TreeRoot, ValueRef,
    },
    text_manifest::{FAMILY, INITIAL_SPACE, TextManifest, TextStatus},
};
use kasumi_types::{CollectionState, Document, DocumentResolver, DocumentSlot, TenantState};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Shards merged together at one level.
pub(crate) const FANIN: usize = 8;
/// Merges one publication performs; later publications continue.
pub(crate) const MAX_MERGES_PER_PUBLICATION: usize = 2;
/// A new shard is cut once its rows carry this much normalized text.
pub(crate) const CUT_TEXT_BYTES: u64 = 4 << 20;
/// Level of a shard that no longer merges: compaction alone rewrites it.
const SEALED: u8 = u8::MAX;
/// Compaction runs while superseded rows exceed live rows plus this slack.
const COMPACTION_SLACK: u64 = 1024;
/// Publications skipped after a failed rebuild before the next attempt.
const REBUILD_BACKOFF: u64 = 128;
const MAX_DESCRIPTOR_BYTES: usize = 64 << 10;

const SHARD: u8 = 1;
const LEVEL: u8 = 2;
const COLLECTION: u8 = 3;

/// Level by row count: a merge of [`FANIN`] shards of one level fits the next.
fn level(documents: u32) -> u8 {
    match documents {
        0..=1 => 0,
        2..=8 => 1,
        9..=64 => 2,
        65..=512 => 3,
        513..=4096 => 4,
        _ => SEALED,
    }
}

fn prefix(collection: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(collection.len() + 16);
    key.extend_from_slice(collection.as_bytes());
    key.push(0);
    key
}
fn shard_prefix(collection: &str, seq: u64) -> Vec<u8> {
    let mut key = prefix(collection);
    key.push(SHARD);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}
fn file_key(collection: &str, seq: u64, name: &str) -> Vec<u8> {
    let mut key = shard_prefix(collection, seq);
    key.push(0);
    key.extend_from_slice(name.as_bytes());
    key
}
fn shard_key(collection: &str, seq: u64) -> Vec<u8> {
    let mut key = shard_prefix(collection, seq);
    key.push(1);
    key
}
fn level_key(collection: &str, level: u8, seq: u64) -> Vec<u8> {
    let mut key = prefix(collection);
    key.extend_from_slice(&[LEVEL, level]);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}
fn collection_key(collection: &str) -> Vec<u8> {
    let mut key = prefix(collection);
    key.push(COLLECTION);
    key
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectionDescriptor {
    /// Identity of the indexed paths, analyzers and shard format.
    pub(crate) layout: [u8; 32],
    pub(crate) next_shard: u64,
    pub(crate) shards: u64,
    /// Rows of every shard, superseded rows included (BM25 `max_doc`).
    pub(crate) documents: u64,
    pub(crate) bytes: u64,
    /// Tokens per schema field over every shard.
    pub(crate) tokens: Vec<u64>,
    /// The next sealed shard the compaction step examines.
    pub(crate) compaction: u64,
}
impl CollectionDescriptor {
    fn empty(layout: &TextShardLayout) -> Self {
        Self {
            layout: layout.sha256(),
            next_shard: 0,
            shards: 0,
            documents: 0,
            bytes: 0,
            tokens: vec![0; layout.field_count()],
            compaction: 0,
        }
    }
    fn add(&mut self, documents: u32, bytes: u64, tokens: &[u64]) -> Result<()> {
        ensure!(
            tokens.len() == self.tokens.len(),
            "text token statistics differ"
        );
        self.shards = self
            .shards
            .checked_add(1)
            .context("text shard count overflow")?;
        self.documents = self
            .documents
            .checked_add(u64::from(documents))
            .context("text row count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("text bytes overflow")?;
        for (total, tokens) in self.tokens.iter_mut().zip(tokens) {
            *total = total.checked_add(*tokens).context("text token overflow")?;
        }
        Ok(())
    }
    fn remove(&mut self, documents: u32, bytes: u64, tokens: &[u64]) -> Result<()> {
        ensure!(
            tokens.len() == self.tokens.len(),
            "text token statistics differ"
        );
        self.shards = self
            .shards
            .checked_sub(1)
            .context("text shard count underflow")?;
        self.documents = self
            .documents
            .checked_sub(u64::from(documents))
            .context("text row count underflow")?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .context("text bytes underflow")?;
        for (total, tokens) in self.tokens.iter_mut().zip(tokens) {
            *total = total.checked_sub(*tokens).context("text token underflow")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShardDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contents_sha256: Option<[u8; 32]>,
    pub(crate) layout: [u8; 32],
    pub(crate) documents: u32,
    pub(crate) tokens: Vec<u64>,
    /// `(name, length)` in name order.
    pub(crate) files: Vec<(String, u64)>,
}
fn shard_contents(files: &[(String, Vec<u8>)]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"kasumi.text-shard.files.v1");
    for (name, bytes) in files {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

impl ShardDescriptor {
    fn of(layout: &TextShardLayout, built: &BuiltTextShard) -> Self {
        Self {
            layout: layout.sha256(),
            contents_sha256: Some(shard_contents(&built.files)),
            documents: built.documents,
            tokens: built.tokens.clone(),
            files: built
                .files
                .iter()
                .map(|(name, bytes)| (name.clone(), bytes.len() as u64))
                .collect(),
        }
    }
    fn bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |total, (_, length)| total.saturating_add(*length))
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_DESCRIPTOR_BYTES,
        "text descriptor exceeds its bound"
    );
    Ok(bytes)
}
fn decode<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_DESCRIPTOR_BYTES,
        "text descriptor exceeds its bound"
    );
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "noncanonical text descriptor"
    );
    Ok(value)
}

fn read<T: Serialize + for<'de> Deserialize<'de>>(
    tree: &TreeReader<'_>,
    key: &[u8],
) -> Result<Option<T>> {
    tree.with_value(key, MAX_DESCRIPTOR_BYTES, |value| {
        value.map(decode::<T>).transpose()
    })
}

/// Traverse the authenticated level index from an inclusive lower bound.
fn visit_levels(
    tree: &TreeReader<'_>,
    collection: &str,
    from: (u8, u64),
    mut visit: impl FnMut(u8, u64) -> Result<bool>,
) -> Result<()> {
    let mut family = prefix(collection);
    family.push(LEVEL);
    tree.scan(
        Bound::Included(&level_key(collection, from.0, from.1)),
        Direction::Forward,
        &mut |key, value| {
            let Some(rest) = key.strip_prefix(family.as_slice()) else {
                return Ok(false);
            };
            ensure!(
                rest.len() == 9 && value.is_empty() && (rest[0] <= 4 || rest[0] == SEALED),
                "invalid text level entry"
            );
            visit(rest[0], u64::from_be_bytes(rest[1..].try_into()?))
        },
    )?;
    Ok(())
}

#[cfg(test)]
fn shard_levels(tree: &TreeReader<'_>, name: &str) -> Result<Vec<(u8, u64)>> {
    let mut found = Vec::new();
    visit_levels(tree, name, (0, 0), |level, seq| {
        found.push((level, seq));
        Ok(true)
    })?;
    Ok(found)
}

// Larger collection removals select a replacement generation, streaming its rows.
const MAX_REMOVAL_ROWS: usize = 256;

fn collection_keys(tree: &TreeReader<'_>, collection: &str) -> Result<Vec<Vec<u8>>> {
    let start = prefix(collection);
    let mut keys = Vec::new();
    tree.scan(
        Bound::Included(start.as_slice()),
        Direction::Forward,
        &mut |key, _: ValueRef<'_>| {
            if !key.starts_with(&start) {
                return Ok(false);
            }
            keys.push(key.to_vec());
            Ok(keys.len() <= MAX_REMOVAL_ROWS)
        },
    )?;
    Ok(keys)
}

fn open_shard(
    tree: &TreeReader<'_>,
    layout: &TextShardLayout,
    collection: &str,
    seq: u64,
    descriptor: &ShardDescriptor,
) -> Result<TextShard> {
    ensure!(
        descriptor.layout == layout.sha256(),
        "text shard belongs to another layout"
    );
    ensure!(
        descriptor.bytes() <= MAX_SHARD_BYTES,
        "text shard exceeds its file bound"
    );
    let mut files = Vec::with_capacity(descriptor.files.len());
    for (name, length) in &descriptor.files {
        let expected = usize::try_from(*length)?;
        let bytes = tree.with_value(&file_key(collection, seq, name), expected, |value| {
            let bytes = value.context("text shard file missing")?;
            ensure!(bytes.len() == expected, "text shard file length differs");
            Ok(bytes.to_vec())
        })?;
        files.push((name.clone(), bytes));
    }
    if let Some(expected) = descriptor.contents_sha256 {
        ensure!(
            shard_contents(&files) == expected,
            "text shard file digest differs"
        );
    }
    Ok(TextShard::open(layout, files, descriptor.documents)?)
}

/// The selected live version of `id`: hydrated archives were never indexed.
pub(crate) fn live_version(collection: &CollectionState, id: &str) -> Option<u64> {
    if collection.archived_documents.contains_key(id) {
        return None;
    }
    collection.documents.get(id).map(|slot| slot.version())
}

fn live_documents(collection: &CollectionState) -> u64 {
    collection
        .documents
        .keys()
        .filter(|id| !collection.archived_documents.contains_key(*id))
        .count() as u64
}

fn has_text(state: &TenantState) -> bool {
    state
        .collections
        .values()
        .any(|collection| TextShardLayout::for_definition(&collection.definition).is_some())
}

/// Lends live bodies for indexing.
pub(crate) trait TextBodies {
    fn with_body(
        &self,
        slot: &DocumentSlot,
        visit: &mut dyn FnMut(&Document) -> Result<()>,
    ) -> Result<()>;
}

/// Pending after-images directly; stored bodies through a selected resolver.
pub(crate) struct ResolverBodies<'a>(pub(crate) Option<&'a dyn DocumentResolver>);
impl TextBodies for ResolverBodies<'_> {
    fn with_body(
        &self,
        slot: &DocumentSlot,
        visit: &mut dyn FnMut(&Document) -> Result<()>,
    ) -> Result<()> {
        let loan = crate::state::loan_document(slot, self.0)?;
        visit(loan.as_ref())
    }
}

/// Build a collection's shards from `rows` in ID order, cutting at the shard
/// row and text bounds. `emit` receives each finished shard.
fn build_shards<'a>(
    memory: &Arc<dyn NodeDiskMemoryAdmission>,
    layout: &TextShardLayout,
    rows: impl Iterator<Item = (&'a str, &'a DocumentSlot)>,
    bodies: &dyn TextBodies,
    mut emit: impl FnMut(BuiltTextShard) -> Result<()>,
) -> Result<()> {
    let mut rows = rows.peekable();
    while rows.peek().is_some() {
        // The index writer destroys its workers before the actual arena grant
        // is released on success, a failed body read, or a publication unwind.
        let _arena = memory
            .clone()
            .reserve_document_decode(TextShardWriter::ARENA_BYTES as u64)?;
        let mut writer = TextShardWriter::new(layout)?;
        for (id, slot) in rows.by_ref() {
            bodies.with_body(slot, &mut |document| {
                ensure!(document.id == id, "text body identity differs");
                Ok(writer.add(id, document.version, &document.body)?)
            })?;
            if writer.documents() >= MAX_SHARD_DOCUMENTS || writer.text_bytes() >= CUT_TEXT_BYTES {
                break;
            }
        }
        if let Some(built) = writer.finish()? {
            emit(built)?;
        }
    }
    Ok(())
}

/// Custody of the directory's journaled edits and replaced generations.
pub(crate) struct TextOwner {
    // Journaled edit batches or a replaced generation may await cleanup.
    dirty: AtomicBool,
    // No rebuild is attempted before this revision after one failed.
    rebuild_after: AtomicU64,
}
impl Default for TextOwner {
    fn default() -> Self {
        Self {
            // A new engine cannot know what an earlier process left behind.
            dirty: AtomicBool::new(true),
            rebuild_after: AtomicU64::new(0),
        }
    }
}
impl TextOwner {
    /// Quote the same arena used by the writer before the local proposer can
    /// commit. A healthy directory builds only for new live rows or a schema
    /// rebuild. An eligible stale directory may rebuild on any publication.
    pub(crate) fn writer_quote(
        &self,
        store: &TenantStore,
        state: &TenantState,
        command: &kasumi_types::Command,
    ) -> Result<u64> {
        use kasumi_types::{CollectionDefinition, Mutation, Operation};
        let indexed = |definition: &CollectionDefinition| {
            definition.indexes.iter().any(|index| index.text.is_some())
        };
        let writes_text = |mutation: &Mutation| {
            !matches!(mutation, Mutation::Delete { .. })
                && state
                    .collections
                    .get(mutation.target().0)
                    .is_some_and(|c| indexed(&c.definition))
        };
        let creates_over_rows = |definition: &CollectionDefinition| {
            indexed(definition)
                && state
                    .collections
                    .get(&definition.name)
                    .is_some_and(|c| !c.documents.is_empty())
        };
        let builds = match &command.operation {
            Operation::Mutate(batch) => batch.operations.iter().any(writes_text),
            Operation::FinalizeStaged(reference) => {
                let key = crate::state::staging::identity(
                    &command.context.principal,
                    &reference.transaction_id,
                )?;
                state.staged_transactions.get(&key).is_some_and(|stage| {
                    stage
                        .chunks
                        .values()
                        .flat_map(|chunk| &chunk.operations)
                        .any(writes_text)
                })
            }
            Operation::ReplaceCollection(definition) => creates_over_rows(definition),
            Operation::ActivateSchema(set) => set
                .changes
                .iter()
                .any(|change| creates_over_rows(change.definition())),
            _ => false,
        };
        if !builds {
            if state.revision.saturating_add(1) < self.rebuild_after.load(Ordering::Acquire)
                || !state
                    .collections
                    .values()
                    .any(|c| !c.documents.is_empty() && indexed(&c.definition))
            {
                return Ok(0);
            }
            let schema_change = matches!(
                command.operation,
                Operation::ReplaceCollection(_) | Operation::ActivateSchema(_)
            );
            if !schema_change
                && TextManifest::load(store)?.is_some_and(|manifest| {
                    manifest.is_current()
                        && manifest.incarnation == state.incarnation
                        && manifest.revision_base == state.revision_base
                        && manifest.revision >= state.revision
                })
            {
                return Ok(0);
            }
        }
        Ok(store
            .plaintext_memory_owner()
            .quote_installed(TextShardWriter::ARENA_BYTES as u64)?)
    }

    /// Finish published journals, abandon unpublished ones and reclaim
    /// unselected or replaced generations. Under the apply gate.
    fn settle(&self, store: &Arc<TenantStore>) -> Result<()> {
        if self.dirty.load(Ordering::Acquire) {
            ordered_pages::recover_abandoned_edits_in(store, FAMILY)?;
            NamespaceStage::reclaim_family(store, FAMILY)?;
            self.dirty.store(false, Ordering::Release);
        }
        Ok(())
    }
}

/// The directory writes of one publication and the workspace funding them.
pub(crate) struct TextPublication {
    writes: Vec<WriteOp>,
    #[cfg_attr(not(test), expect(dead_code, reason = "inspected by tests"))]
    manifest: TextManifest,
    _workspace: Option<EditWorkspace>,
}
impl TextPublication {
    pub(crate) fn take_writes(&mut self) -> Vec<WriteOp> {
        std::mem::take(&mut self.writes)
    }
    #[cfg_attr(not(test), expect(dead_code, reason = "inspected by tests"))]
    pub(crate) fn manifest(&self) -> &TextManifest {
        &self.manifest
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Nothing,
    Edit,
    Rebuild,
}

fn plan(manifest: Option<&TextManifest>, previous: &TenantState, candidate: &TenantState) -> Plan {
    let Some(manifest) = manifest else {
        return if has_text(candidate) {
            Plan::Rebuild
        } else {
            Plan::Nothing
        };
    };
    if manifest.incarnation != candidate.incarnation
        || manifest.revision_base != candidate.revision_base
        || !manifest.is_current()
    {
        return Plan::Rebuild;
    }
    if manifest.revision >= candidate.revision {
        // Covered replay after reopen: the directory already indexes it.
        Plan::Nothing
    } else if manifest.revision == previous.revision {
        Plan::Edit
    } else {
        Plan::Rebuild
    }
}

/// The directory step of one candidate publication: `None` when nothing is
/// written. A failure to maintain the directory never fails the publication:
/// it marks the directory stale, so text searches report it unavailable
/// until a later publication or restore rebuilds it.
pub(crate) fn prepare_publication(
    owner: &TextOwner,
    store: &Arc<TenantStore>,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
    bodies: &dyn TextBodies,
) -> Result<Option<TextPublication>> {
    owner.settle(store)?;
    let manifest = TextManifest::load(store)?;
    let step = plan(manifest.as_ref(), previous, candidate);
    let rebuild_allowed = candidate.revision >= owner.rebuild_after.load(Ordering::Acquire);
    let outcome = match step {
        Plan::Nothing => return Ok(None),
        Plan::Edit => {
            let manifest = manifest.as_ref().expect("edit has a current manifest");
            match edit(store, manifest, previous, candidate, changed, bodies) {
                Ok(Some(publication)) => {
                    if publication.writes.iter().any(journal_write) {
                        owner.dirty.store(true, Ordering::Release);
                    }
                    return Ok(Some(publication));
                }
                Ok(None) if rebuild_allowed => rebuild_publication(owner, store, candidate, bodies),
                // A failed rebuild backs off: the directory stays stale quietly.
                Ok(None) => return Ok(stale(Some(manifest), candidate)),
                Err(error) => Err(error),
            }
        }
        Plan::Rebuild if rebuild_allowed => rebuild_publication(owner, store, candidate, bodies),
        Plan::Rebuild => return Ok(stale(manifest.as_ref(), candidate)),
    };
    match outcome {
        Ok(publication) => Ok(publication),
        Err(error) => {
            tracing::warn!(
                event = "text_directory_stale",
                revision = candidate.revision,
                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "text directory could not follow a publication"
            );
            Ok(stale(manifest.as_ref(), candidate))
        }
    }
}

fn journal_write(write: &WriteOp) -> bool {
    matches!(write, WriteOp::Put { namespace, .. } if namespace.starts_with("kasumi.app.edit-"))
}

/// Mark a current directory stale at `candidate`'s revision, if it can be.
fn stale(manifest: Option<&TextManifest>, candidate: &TenantState) -> Option<TextPublication> {
    let manifest = manifest.filter(|manifest| {
        manifest.is_current()
            && manifest.revision < candidate.revision
            && manifest.incarnation == candidate.incarnation
            && manifest.revision_base == candidate.revision_base
    })?;
    let stale = manifest.stale_at(candidate.revision);
    let write = stale.write().ok()?;
    Some(TextPublication {
        writes: vec![write],
        manifest: stale,
        _workspace: None,
    })
}

fn rebuild_publication(
    owner: &TextOwner,
    store: &Arc<TenantStore>,
    candidate: &TenantState,
    bodies: &dyn TextBodies,
) -> Result<Option<TextPublication>> {
    let rebuilt = rebuild(store, candidate, bodies);
    // Either way an unselected or soon replaced generation may remain.
    owner.dirty.store(true, Ordering::Release);
    if rebuilt.is_err() {
        owner.rebuild_after.store(
            candidate.revision.saturating_add(REBUILD_BACKOFF),
            Ordering::Release,
        );
    }
    rebuilt.map(Some)
}

/// Stage a complete directory of `state` in a fresh generation: one shard
/// build and one tree path at a time. The returned writes select it.
pub(crate) fn rebuild(
    store: &Arc<TenantStore>,
    state: &TenantState,
    bodies: &dyn TextBodies,
) -> Result<TextPublication> {
    stage_generation(store, state, Some(bodies), TextStatus::Current)
}

fn stage_generation(
    store: &Arc<TenantStore>,
    state: &TenantState,
    bodies: Option<&dyn TextBodies>,
    status: TextStatus,
) -> Result<TextPublication> {
    NamespaceStage::reclaim_family(store, FAMILY)?;
    let family = SelectedGeneration::adopt(store, FAMILY, &INITIAL_SPACE)?;
    let stage = NamespaceStage::begin_generation(store, FAMILY)?;
    let mut totals = (0u64, 0u64, 0u64);
    let root = ordered_pages::stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        let Some(bodies) = bodies else {
            return Ok(());
        };
        for (name, collection) in &state.collections {
            let Some(layout) = TextShardLayout::for_definition(&collection.definition) else {
                continue;
            };
            let mut descriptor = CollectionDescriptor::empty(&layout);
            let mut last_level = None;
            let rows = collection
                .documents
                .iter()
                .filter(|(id, _)| !collection.archived_documents.contains_key(*id))
                .map(|(id, slot)| (id.as_str(), slot.as_ref()));
            build_shards(
                store.plaintext_memory_owner(),
                &layout,
                rows,
                bodies,
                |built| {
                    let seq = descriptor.next_shard;
                    descriptor.next_shard += 1;
                    for (file, bytes) in &built.files {
                        builder.push(&file_key(name, seq, file), bytes)?;
                    }
                    let shard = ShardDescriptor::of(&layout, &built);
                    builder.push(&shard_key(name, seq), &encode(&shard)?)?;
                    descriptor.add(built.documents, built.bytes(), &built.tokens)?;
                    last_level = Some((level(built.documents), seq));
                    Ok(())
                },
            )?;
            // All full rebuild shards are already packed. Keep only the last
            // partial shard at its natural merge level, followed by sealed rows.
            if let Some((last, seq)) = last_level {
                if last != SEALED {
                    builder.push(&level_key(name, last, seq), &[])?;
                }
                let sealed = if last == SEALED {
                    descriptor.next_shard
                } else {
                    seq
                };
                for id in 0..sealed {
                    builder.push(&level_key(name, SEALED, id), &[])?;
                }
            }
            builder.push(&collection_key(name), &encode(&descriptor)?)?;
            totals.0 += 1;
            totals.1 += descriptor.shards;
            totals.2 += descriptor.bytes;
        }
        Ok(())
    })?;
    let mut writes = family.switch_writes(store, &[&stage])?;
    let manifest = TextManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision_base,
        state.revision,
        status,
        stage.namespace(),
        root,
        totals.0,
        totals.1,
        totals.2,
    );
    writes.push(manifest.write()?);
    Ok(TextPublication {
        writes,
        manifest,
        _workspace: None,
    })
}

/// Pending edits in key order; `None` deletes.
type Edits = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

struct Totals {
    collections: u64,
    shards: u64,
    bytes: u64,
}

/// Edit the selected tree forward to `candidate`. `Ok(None)` when the change
/// needs a rebuild instead (a changed text layout over live rows).
fn edit(
    store: &Arc<TenantStore>,
    manifest: &TextManifest,
    previous: &TenantState,
    candidate: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
    bodies: &dyn TextBodies,
) -> Result<Option<TextPublication>> {
    let tree = TreeReader::new(&**store, &manifest.page_space, manifest.records, None)?;
    let mut names: BTreeSet<&str> = changed.keys().map(String::as_str).collect();
    for (name, collection) in &candidate.collections {
        if previous.collections.get(name).is_none_or(|old| {
            !Arc::ptr_eq(&old.definition, &collection.definition)
                && old.definition != collection.definition
        }) {
            names.insert(name);
        }
    }
    names.extend(
        previous
            .collections
            .keys()
            .filter(|name| !candidate.collections.contains_key(*name))
            .map(String::as_str),
    );
    let mut edits = Edits::new();
    let mut totals = Totals {
        collections: manifest.collections,
        shards: manifest.shards,
        bytes: manifest.shard_bytes,
    };
    for name in names {
        let collection = candidate.collections.get(name);
        let layout = collection
            .and_then(|collection| TextShardLayout::for_definition(&collection.definition));
        let existing: Option<CollectionDescriptor> = read(&tree, &collection_key(name))?;
        match (layout, existing) {
            (None, None) => {}
            (None, Some(old)) => {
                if !delete_collection(&tree, name, &old, &mut edits, &mut totals)? {
                    return Ok(None);
                }
            }
            (Some(layout), existing)
                if existing
                    .as_ref()
                    .is_none_or(|old| old.layout != layout.sha256()) =>
            {
                // A new text collection, or a changed text definition.
                if live_documents(collection.expect("layout has a collection")) > 0 {
                    return Ok(None);
                }
                if let Some(old) = &existing
                    && !delete_collection(&tree, name, old, &mut edits, &mut totals)?
                {
                    return Ok(None);
                }
                edits.insert(
                    collection_key(name),
                    Some(encode(&CollectionDescriptor::empty(&layout))?),
                );
                totals.collections += 1;
            }
            (Some(_), None) => unreachable!("an absent descriptor is a new layout"),
            (Some(layout), Some(descriptor)) => {
                let collection = collection.expect("layout has a collection");
                ensure!(
                    previous.collections.contains_key(name),
                    "indexed text collection lacks its predecessor"
                );
                let ids = changed.get(name);
                CollectionEdit {
                    memory: store.plaintext_memory_owner(),
                    tree: &tree,
                    name,
                    layout: &layout,
                    collection,
                    edits: &mut edits,
                    totals: &mut totals,
                }
                .apply(descriptor, ids, bodies)?;
            }
        }
    }
    let rows: Vec<Edit<'_>> = edits
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    let (records, mut writes, workspace) = if rows.is_empty() {
        (manifest.records, Vec::new(), None)
    } else {
        let edit =
            ordered_pages::edit_tree_staged(store, &manifest.page_space, &manifest.records, &rows)?;
        let (root, writes, workspace) = edit.into_parts();
        (root, writes, Some(workspace))
    };
    drop(rows);
    drop(edits);
    let next = TextManifest::new(
        &candidate.tenant,
        &candidate.incarnation,
        candidate.revision_base,
        candidate.revision,
        TextStatus::Current,
        &manifest.page_space,
        records,
        totals.collections,
        totals.shards,
        totals.bytes,
    );
    writes.push(next.write()?);
    Ok(Some(TextPublication {
        writes,
        manifest: next,
        _workspace: workspace,
    }))
}

fn delete_collection(
    tree: &TreeReader<'_>,
    name: &str,
    old: &CollectionDescriptor,
    edits: &mut Edits,
    totals: &mut Totals,
) -> Result<bool> {
    let keys = collection_keys(tree, name)?;
    if keys.len() > MAX_REMOVAL_ROWS {
        return Ok(false);
    }
    for key in keys {
        edits.insert(key, None);
    }
    totals.collections = totals.collections.checked_sub(1).context("text totals")?;
    totals.shards = totals
        .shards
        .checked_sub(old.shards)
        .context("text totals")?;
    totals.bytes = totals.bytes.checked_sub(old.bytes).context("text totals")?;
    Ok(true)
}

enum Member {
    Stored(ShardDescriptor),
    Pending(BuiltTextShard),
}
impl Member {
    fn documents(&self) -> u32 {
        match self {
            Self::Stored(descriptor) => descriptor.documents,
            Self::Pending(built) => built.documents,
        }
    }
    fn bytes(&self) -> u64 {
        match self {
            Self::Stored(descriptor) => descriptor.bytes(),
            Self::Pending(built) => built.bytes(),
        }
    }
    fn tokens(&self) -> &[u64] {
        match self {
            Self::Stored(descriptor) => &descriptor.tokens,
            Self::Pending(built) => &built.tokens,
        }
    }
}

struct CollectionEdit<'e, 't> {
    memory: &'e Arc<dyn NodeDiskMemoryAdmission>,
    tree: &'e TreeReader<'t>,
    name: &'e str,
    layout: &'e TextShardLayout,
    collection: &'e CollectionState,
    edits: &'e mut Edits,
    totals: &'e mut Totals,
}

impl CollectionEdit<'_, '_> {
    fn apply(
        mut self,
        mut descriptor: CollectionDescriptor,
        ids: Option<&BTreeSet<String>>,
        bodies: &dyn TextBodies,
    ) -> Result<()> {
        let start = (descriptor.shards, descriptor.bytes);
        // Shards are addressed by (level, seq); stored ones keep their files.
        let mut members: BTreeMap<u64, (u8, Member)> = BTreeMap::new();
        let mut stored_levels: BTreeMap<u64, u8> = BTreeMap::new();
        // Two merge rounds can consume at most this many existing members per level.
        for candidate in 0..=4 {
            let mut count = 0;
            visit_levels(self.tree, self.name, (candidate, 0), |level, seq| {
                if level != candidate {
                    return Ok(false);
                }
                stored_levels.insert(seq, level);
                count += 1;
                Ok(count < FANIN * MAX_MERGES_PER_PUBLICATION)
            })?;
        }
        for from in [descriptor.compaction, 0] {
            let mut found = false;
            visit_levels(self.tree, self.name, (SEALED, from), |level, seq| {
                stored_levels.insert(seq, level);
                found = true;
                Ok(false)
            })?;
            if found || from == 0 {
                break;
            }
        }
        // Index every changed live version in new shards.
        if let Some(ids) = ids {
            let rows = ids.iter().filter_map(|id| {
                live_version(self.collection, id)?;
                Some((id.as_str(), self.collection.documents.get(id)?.as_ref()))
            });
            build_shards(self.memory, self.layout, rows, bodies, |shard| {
                let seq = descriptor.next_shard;
                descriptor.next_shard += 1;
                descriptor.add(shard.documents, shard.bytes(), &shard.tokens)?;
                members.insert(seq, (level(shard.documents), Member::Pending(shard)));
                Ok(())
            })?;
        }
        let keep = |id: &str, version: u64| -> kasumi_types::Result<bool> {
            Ok(live_version(self.collection, id) == Some(version))
        };
        // Bounded merges, lowest level first.
        for _ in 0..MAX_MERGES_PER_PUBLICATION {
            let mut by_level: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
            for (seq, level) in &stored_levels {
                by_level.entry(*level).or_default().push(*seq);
            }
            for (seq, (level, _)) in &members {
                by_level.entry(*level).or_default().push(*seq);
            }
            let Some((_, group)) = by_level
                .into_iter()
                .find(|(level, seqs)| *level != SEALED && seqs.len() >= FANIN)
            else {
                break;
            };
            let mut group: Vec<u64> = group;
            group.sort_unstable();
            group.truncate(FANIN);
            let opened = group
                .iter()
                .map(|seq| self.open(*seq, &members))
                .collect::<Result<Vec<_>>>()?;
            let mut survivors = 0u64;
            let mut bytes = 0u64;
            for (shard, seq) in opened.iter().zip(&group) {
                shard.visit_rows(|id, version| {
                    survivors += u64::from(keep(id, version)?);
                    Ok(true)
                })?;
                bytes += self.member_bytes(*seq, &members)?;
            }
            if survivors <= u64::from(MAX_SHARD_DOCUMENTS) && bytes <= MAX_SHARD_BYTES {
                let merged =
                    merge_text_shards(self.layout, &opened.iter().collect::<Vec<_>>(), keep)?;
                drop(opened);
                for seq in &group {
                    self.retire(*seq, &mut descriptor, &mut members, &mut stored_levels)?;
                }
                if let Some(merged) = merged {
                    let seq = descriptor.next_shard;
                    descriptor.next_shard += 1;
                    descriptor.add(merged.documents, merged.bytes(), &merged.tokens)?;
                    members.insert(seq, (level(merged.documents), Member::Pending(merged)));
                }
            } else {
                // Too large to merge: these shards stop merging.
                for seq in &group {
                    if let Some((level, _)) = members.get_mut(seq) {
                        *level = SEALED;
                    } else if let Some(level) = stored_levels.get_mut(seq) {
                        self.edits.insert(level_key(self.name, *level, *seq), None);
                        self.edits
                            .insert(level_key(self.name, SEALED, *seq), Some(Vec::new()));
                        *level = SEALED;
                    }
                }
            }
        }
        // One bounded compaction step while superseded rows dominate.
        let live = live_documents(self.collection);
        if descriptor.documents > live.saturating_mul(2).saturating_add(COMPACTION_SLACK) {
            let sealed: Vec<u64> = stored_levels
                .iter()
                .filter(|(_, level)| **level == SEALED)
                .map(|(seq, _)| *seq)
                .collect();
            let next = sealed
                .iter()
                .find(|seq| **seq >= descriptor.compaction)
                .or_else(|| sealed.first())
                .copied();
            if let Some(seq) = next {
                descriptor.compaction = seq + 1;
                let shard = self.open(seq, &members)?;
                let mut survivors = 0u32;
                shard.visit_rows(|id, version| {
                    survivors += u32::from(keep(id, version)?);
                    Ok(true)
                })?;
                if u64::from(survivors) * 4 < u64::from(shard.documents()) * 3 {
                    let merged = merge_text_shards(self.layout, &[&shard], keep)?;
                    drop(shard);
                    self.retire(seq, &mut descriptor, &mut members, &mut stored_levels)?;
                    if let Some(merged) = merged {
                        let seq = descriptor.next_shard;
                        descriptor.next_shard += 1;
                        descriptor.add(merged.documents, merged.bytes(), &merged.tokens)?;
                        members.insert(seq, (level(merged.documents), Member::Pending(merged)));
                    }
                }
            }
        }
        // Write the surviving new shards.
        for (seq, (level, member)) in members {
            let Member::Pending(built) = member else {
                unreachable!("only new shards are members")
            };
            let descriptor = encode(&ShardDescriptor::of(self.layout, &built))?;
            for (file, bytes) in built.files {
                self.edits
                    .insert(file_key(self.name, seq, &file), Some(bytes));
            }
            self.edits
                .insert(shard_key(self.name, seq), Some(descriptor));
            self.edits
                .insert(level_key(self.name, level, seq), Some(Vec::new()));
        }
        self.edits
            .insert(collection_key(self.name), Some(encode(&descriptor)?));
        self.totals.shards = (self.totals.shards + descriptor.shards)
            .checked_sub(start.0)
            .context("text totals")?;
        self.totals.bytes = (self.totals.bytes + descriptor.bytes)
            .checked_sub(start.1)
            .context("text totals")?;
        Ok(())
    }

    fn open(&self, seq: u64, members: &BTreeMap<u64, (u8, Member)>) -> Result<TextShard> {
        match members.get(&seq) {
            Some((_, Member::Pending(built))) => Ok(TextShard::open(
                self.layout,
                built.files.clone(),
                built.documents,
            )?),
            Some((_, Member::Stored(_))) => unreachable!("stored shards are not members"),
            None => {
                let descriptor: ShardDescriptor = read(self.tree, &shard_key(self.name, seq))?
                    .context("text shard descriptor missing")?;
                open_shard(self.tree, self.layout, self.name, seq, &descriptor)
            }
        }
    }

    fn member_bytes(&self, seq: u64, members: &BTreeMap<u64, (u8, Member)>) -> Result<u64> {
        Ok(match members.get(&seq) {
            Some((_, member)) => member.bytes(),
            None => read::<ShardDescriptor>(self.tree, &shard_key(self.name, seq))?
                .context("text shard descriptor missing")?
                .bytes(),
        })
    }

    /// Remove one shard: a new one is dropped, a stored one deleted.
    fn retire(
        &mut self,
        seq: u64,
        descriptor: &mut CollectionDescriptor,
        members: &mut BTreeMap<u64, (u8, Member)>,
        stored_levels: &mut BTreeMap<u64, u8>,
    ) -> Result<()> {
        if let Some((_, member)) = members.remove(&seq) {
            return descriptor.remove(member.documents(), member.bytes(), member.tokens());
        }
        let level = stored_levels
            .remove(&seq)
            .context("retired text shard is not indexed")?;
        let stored: ShardDescriptor = read(self.tree, &shard_key(self.name, seq))?
            .context("text shard descriptor missing")?;
        for (file, _) in &stored.files {
            self.edits.insert(file_key(self.name, seq, file), None);
        }
        self.edits.insert(shard_key(self.name, seq), None);
        self.edits.insert(level_key(self.name, level, seq), None);
        let member = Member::Stored(stored);
        descriptor.remove(member.documents(), member.bytes(), member.tokens())
    }
}

/// Bring the directory to a restored generation. A reopened replica keeps a
/// current directory at or ahead of its snapshot (later entries replay as
/// covered); anything else selects a rebuilt generation. If even the rebuild
/// fails, a stale empty generation replaces whatever another history left.
pub(crate) fn prepare_restore(
    owner: &TextOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    resolver: Option<&dyn DocumentResolver>,
    reopen: bool,
    writes: &mut Vec<WriteOp>,
) -> Result<()> {
    owner.dirty.store(true, Ordering::Release);
    owner.settle(store)?;
    owner.rebuild_after.store(0, Ordering::Release);
    let manifest = TextManifest::load(store)?;
    if reopen
        && let Some(manifest) = &manifest
        && manifest.is_current()
        && manifest.incarnation == state.incarnation
        && manifest.revision_base == state.revision_base
        && manifest.revision >= state.revision
    {
        return Ok(());
    }
    if manifest.is_none() && !has_text(state) {
        return Ok(());
    }
    let publication = match rebuild(store, state, &ResolverBodies(resolver)) {
        Ok(publication) => publication,
        Err(error) => {
            tracing::warn!(
                event = "text_directory_stale",
                revision = state.revision,
                io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                "text directory could not be rebuilt at restore"
            );
            stage_generation(store, state, None, TextStatus::Stale)?
        }
    };
    owner.dirty.store(true, Ordering::Release);
    writes.extend(publication.writes);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reads

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ShardAddress {
    tenant: String,
    tree: [u8; 16],
    collection: String,
    seq: u64,
    layout: [u8; 32],
}

type CacheKey = (ShardAddress, [u8; 32]);

struct OpenShard {
    shard: TextShard,
    charged_bytes: u64,
    // Every reader keeps the reservation until it releases the Tantivy reader.
    _lease: Reservation,
}

struct Cached {
    shard: Arc<OpenShard>,
    used: u64,
}

#[derive(Default)]
pub(crate) struct ShardCache {
    evictions: u64,
    clock: u64,
    entries: BTreeMap<CacheKey, Cached>,
}

impl ShardCache {
    fn next_in_tree(
        &self,
        tenant: &str,
        tree: [u8; 16],
        after: Option<&CacheKey>,
    ) -> Option<CacheKey> {
        let first = (
            ShardAddress {
                tenant: tenant.into(),
                tree,
                collection: String::new(),
                seq: 0,
                layout: [0; 32],
            },
            [0; 32],
        );
        let from = after.map_or(Bound::Included(&first), Bound::Excluded);
        self.entries
            .range((from, Bound::Unbounded))
            .next()
            .map(|(key, _)| key)
            .filter(|key| key.0.tenant == tenant && key.0.tree == tree)
            .cloned()
    }

    fn get(&mut self, key: &CacheKey) -> Option<Arc<OpenShard>> {
        self.clock = self.clock.saturating_add(1);
        let clock = self.clock;
        self.entries.get_mut(key).map(|entry| {
            entry.used = clock;
            entry.shard.clone()
        })
    }
    /// A demand miss can reclaim an idle reader. Removing a pinned reader
    /// would strand its charge and force the next search to open it again.
    fn evict_oldest_idle(&mut self) -> Option<u64> {
        let oldest = self
            .entries
            .iter()
            .filter(|(_, entry)| Arc::strong_count(&entry.shard) == 1)
            .min_by_key(|(_, entry)| entry.used)
            .map(|(key, _)| key.clone())?;
        self.evictions = self.evictions.saturating_add(1);
        self.entries
            .remove(&oldest)
            .map(|entry| entry.shard.charged_bytes)
    }

    /// Concurrent misses may open the same immutable reader. Only the winner
    /// remains resident, and the later caller shares that reader's grant.
    fn insert(&mut self, key: CacheKey, shard: Arc<OpenShard>) -> Arc<OpenShard> {
        if let Some(existing) = self.get(&key) {
            return existing;
        }
        self.entries.insert(
            key,
            Cached {
                shard: shard.clone(),
                used: self.clock,
            },
        );
        shard
    }
}

/// One collection's shards at the selected directory: a [`TextShardSet`]
/// whose storage failures keep their original owner for the caller.
struct DirectoryShards<'r, 't> {
    tree: &'r TreeReader<'t>,
    source: &'r dyn PageSource,
    tenant: String,
    tree_id: [u8; 16],
    name: &'r str,
    layout: TextShardLayout,
    descriptor: CollectionDescriptor,
    shard_count: usize,
    // Last visited (ordinal, level, sequence) on this immutable selected view.
    cursor: std::cell::Cell<Option<(usize, u8, u64)>>,
    collection: &'r CollectionState,
    admission: &'r Arc<NodeAdmission>,
    failure: RefCell<Option<anyhow::Error>>,
}

impl DirectoryShards<'_, '_> {
    fn fail(&self, error: anyhow::Error) -> kasumi_types::Error {
        self.failure.borrow_mut().get_or_insert(error);
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::Unavailable,
            "text directory unavailable",
        )
    }
    fn sequence(&self, wanted: usize) -> Result<u64> {
        ensure!(wanted < self.shard_count, "text shard ordinal out of range");
        let (mut ordinal, from) = match self.cursor.get() {
            Some((ordinal, _, seq)) if ordinal == wanted => return Ok(seq),
            Some((ordinal, level, seq)) if ordinal < wanted => (ordinal, (level, seq)),
            _ => (0, (0, 0)),
        };
        let mut found = None;
        visit_levels(self.tree, self.name, from, |level, seq| {
            if ordinal == wanted {
                found = Some((wanted, level, seq));
                return Ok(false);
            }
            ordinal += 1;
            Ok(true)
        })?;
        let position = found.context("text directory shard count differs")?;
        self.cursor.set(Some(position));
        Ok(position.2)
    }

    fn load(&self, seq: u64) -> Result<Arc<OpenShard>> {
        let key = ShardAddress {
            tenant: self.tenant.clone(),
            tree: self.tree_id,
            collection: self.name.to_owned(),
            seq,
            layout: self.layout.sha256(),
        };
        match load_selected_shard(
            self.tree,
            self.source,
            key,
            &self.layout,
            self.admission,
            true,
        )? {
            ShardLoad::Open(shard) => Ok(shard),
            ShardLoad::Capacity(_) => {
                unreachable!("a demand read obtains its own grant or an error")
            }
        }
    }
}

enum ShardLoad {
    Open(Arc<OpenShard>),
    Capacity(u64),
}

fn load_selected_shard(
    tree: &TreeReader<'_>,
    source: &dyn PageSource,
    address: ShardAddress,
    layout: &TextShardLayout,
    admission: &Arc<NodeAdmission>,
    demand: bool,
) -> Result<ShardLoad> {
    // A cache hit still requires access to this immutable selected source.
    source.check_access()?;
    let descriptor: ShardDescriptor = read(tree, &shard_key(&address.collection, address.seq))?
        .context("text shard descriptor missing")?;
    ensure!(
        descriptor.layout == layout.sha256(),
        "selected text shard layout differs"
    );
    // An empty collection can be dropped and recreated in the same physical
    // tree with the same layout and sequence. Legacy descriptors have no
    // content commitment and can share a reader only within their exact root.
    let digest = descriptor
        .contents_sha256
        .or_else(|| tree.root().root.map(|page| page.sha256))
        .context("text shard has no authenticated root")?;
    let key = (address, digest);
    if let Some(shard) = admission.text_shards.lock().unwrap().get(&key) {
        return Ok(ShardLoad::Open(shard));
    }
    // Admit the file bytes before reading them; the lease then funds the
    // retained shard, or ends with this search.
    let file_bytes = descriptor.bytes();
    ensure!(
        file_bytes <= MAX_SHARD_BYTES,
        "text shard exceeds its byte bound"
    );
    let charged_bytes = file_bytes * 2 + MAX_DESCRIPTOR_BYTES as u64;
    let optional = admission.try_reserve_text_shard(charged_bytes)?;
    let retain = optional.is_some();
    let lease = match optional {
        Some(lease) => lease,
        None if !demand => return Ok(ShardLoad::Capacity(charged_bytes)),
        None => {
            // A cold scan that fits the transient budget leaves the hot set
            // alone. Required reads still respect installed audit protection.
            let mut cache = admission.text_shards.lock().unwrap();
            if let Some(existing) = cache.get(&key) {
                return Ok(ShardLoad::Open(existing));
            }
            let mut reclaimed = 0;
            loop {
                match admission.reserve_waiting(charged_bytes, None) {
                    Ok(lease) => break lease,
                    Err(error) => {
                        if error.code == kasumi_types::ErrorCode::ResourceExhausted
                            && reclaimed < charged_bytes
                            && let Some(bytes) = cache.evict_oldest_idle()
                        {
                            reclaimed += bytes;
                        } else {
                            return Err(error.into());
                        }
                    }
                }
            }
        }
    };
    let shard = Arc::new(OpenShard {
        shard: open_shard(tree, layout, &key.0.collection, key.0.seq, &descriptor)?,
        charged_bytes,
        _lease: lease,
    });
    source.check_access()?;
    let shard = if retain {
        admission.text_shards.lock().unwrap().insert(key, shard)
    } else {
        shard
    };
    Ok(ShardLoad::Open(shard))
}

#[path = "application_text_warmup.rs"]
mod warmup;
pub(crate) use warmup::Warmup;
pub use warmup::{TextWarmupState, TextWarmupStatus};

impl TextShardSet for DirectoryShards<'_, '_> {
    fn layout(&self) -> &TextShardLayout {
        &self.layout
    }
    fn shard_count(&self) -> usize {
        self.shard_count
    }
    fn with_shard(
        &self,
        shard: usize,
        visit: &mut dyn FnMut(&TextShard) -> kasumi_types::Result<()>,
    ) -> kasumi_types::Result<()> {
        let seq = self.sequence(shard).map_err(|error| self.fail(error))?;
        let opened = self.load(seq).map_err(|error| self.fail(error))?;
        visit(&opened.shard)
    }
    fn indexed_documents(&self) -> u64 {
        self.descriptor.documents
    }
    fn total_tokens(&self, field: usize) -> u64 {
        self.descriptor.tokens.get(field).copied().unwrap_or(0)
    }
    fn current(&self, id: &str, version: u64) -> kasumi_types::Result<bool> {
        Ok(live_version(self.collection, id) == Some(version))
    }
}

/// Search one collection of the directory `manifest` names through `tree`.
/// The outer error is a storage failure with its original owner; the inner
/// one is the search's own query error.
pub(crate) fn search_collection<T>(
    tree: &TreeReader<'_>,
    source: &dyn PageSource,
    manifest: &TextManifest,
    name: &str,
    collection: &CollectionState,
    admission: &Arc<NodeAdmission>,
    search: impl FnOnce(&dyn TextShardSet) -> kasumi_types::Result<T>,
) -> Result<kasumi_types::Result<T>> {
    let layout = TextShardLayout::for_definition(&collection.definition)
        .context("searched collection has no text layout")?;
    let descriptor: CollectionDescriptor = read(tree, &collection_key(name))?
        .context("current text directory lacks an indexed collection")?;
    ensure!(
        descriptor.layout == layout.sha256(),
        "text directory layout differs from the selected definition"
    );
    let mut shard_count = 0usize;
    visit_levels(tree, name, (0, 0), |_, _| {
        shard_count = shard_count
            .checked_add(1)
            .context("text shard count overflow")?;
        Ok(true)
    })?;
    ensure!(
        shard_count as u64 == descriptor.shards,
        "text directory shard count differs"
    );
    let set = DirectoryShards {
        tree,
        source,
        tenant: manifest.tenant.clone(),
        tree_id: manifest.records.tree,
        name,
        layout,
        descriptor,
        shard_count,
        cursor: std::cell::Cell::new(None),
        collection,
        admission,
        failure: RefCell::new(None),
    };
    let result = search(&set);
    if let Some(error) = set.failure.into_inner() {
        return Err(error);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "application_text_tests.rs"]
mod tests;
