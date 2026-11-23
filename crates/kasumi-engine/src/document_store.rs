//! Encrypted immutable bodies and shared proof chunks. Preparation never writes
//! storage or changes a root: the apply owner commits these writes together with
//! its custody outcome before exposing descriptors. One resolver belongs to a
//! generation; individual descriptors never pin old native roots.
use crate::{
    admission::{DocumentWorkspace, RetainedWorkspace},
    application_sources::{DocumentReader, SelectedApplication, SourceRootsRef},
    document_encoding::{self, BodyLimits, BodyManifest},
};
use anyhow::{Context, Result, ensure};
use kasumi_query::QueryWorkspace;
use kasumi_store::{
    NodeDiskMemoryAdmission, TenantStorageReadView, WriteOp,
    ordered_pages::{MAX_PAGE_BYTES, PageCache, PageSource},
    primary_manifest::{MAX_MANIFEST_BYTES, PrimaryManifest},
};
use kasumi_types::{
    AdmittedDocumentOwner, Document, DocumentResolver, LocatedDocument, SharedDocument,
    StoredDocument,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

pub(crate) const BODIES: &str = "engine.document.bodies";
pub(crate) const BLOBS: &str = "engine.document.blobs";
const MAX_OBJECT_BYTES: usize = 32 << 20;
const FLOOR: u64 = 64 << 10;

pub(crate) fn limits(bytes: usize) -> Result<BodyLimits> {
    ensure!(
        bytes > 0 && bytes <= MAX_OBJECT_BYTES,
        "document body exceeds storage bound"
    );
    Ok(BodyLimits {
        canonical_bytes: bytes,
        manifest_bytes: bytes
            .checked_mul(2)
            .and_then(|v| v.checked_add(64 << 10))
            .context("document manifest bound overflow")?
            .min(MAX_OBJECT_BYTES),
        fragments: bytes / document_encoding::STRING_THRESHOLD * 2 + 3,
        blobs: bytes / document_encoding::STRING_THRESHOLD
            + bytes / document_encoding::BLOB_CHUNK_BYTES
            + 2,
        depth: 128,
    })
}

/// Measurements borrow the admitted input through encoding. One canonical
/// body pass supplies its size, work and independent hash. The authenticated
/// document's framing contributes its own size and work.
pub(crate) struct DocumentMeasurement<'a> {
    document: &'a Document,
    limits: BodyLimits,
    body_bytes: u64,
    body_work: u64,
    body_sha256: [u8; 32],
    document_bytes: u64,
    document_work: u64,
}
impl<'a> DocumentMeasurement<'a> {
    pub(crate) fn new(document: &'a Document) -> Result<Self> {
        let mut digest = Sha256::new();
        let ((body_bytes, body_work), (document_bytes, document_work)) =
            crate::snapshot_codec::measure_document_json(document, |bytes| digest.update(bytes))?;
        let limits = limits(usize::try_from(body_bytes)?)?;
        Ok(Self {
            document,
            limits,
            body_bytes,
            body_work,
            body_sha256: digest.finalize().into(),
            document_bytes,
            document_work,
        })
    }

    pub(crate) fn limits(&self) -> BodyLimits {
        self.limits
    }

    pub(crate) fn workspace(&self) -> Result<u64> {
        self.document_work
            .checked_add(
                self.body_bytes
                    .checked_mul(8)
                    .context("document preparation overflow")?,
            )
            .and_then(|bytes| bytes.checked_add(1 << 20))
            .context("document preparation overflow")
    }

    pub(crate) fn descriptor(
        &self,
        manifest: &BodyManifest,
        object: document_encoding::EncodedObject<'_>,
    ) -> Result<StoredDocument> {
        // encode_body independently hashes its emitted canonical spelling.
        // Never substitute a manifest's declared identity for input validation.
        ensure!(
            self.body_bytes == manifest.canonical_bytes
                && self.body_sha256 == manifest.canonical_sha256,
            "document encoding differs from canonical body"
        );
        let wire = object.bytes();
        let descriptor = StoredDocument {
            id: self.document.id.clone(),
            version: self.document.version,
            body_bytes: self.body_bytes,
            document_bytes: self.document_bytes,
            body_sha256: self.body_sha256,
            body_object: object.digest(),
            body_object_bytes: wire.len() as u64,
            body_decode_work: self.body_work,
            body_manifest_work: crate::snapshot_codec::inspect_external_json_work(
                wire,
                &mut || Ok(()),
            )?,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// The structural workspace of lending the source found under `id`. A
/// located slot keeps the exact charges of the descriptor it stands for.
pub(crate) fn source_workspace(id: &str, slot: &kasumi_types::DocumentSlot) -> Result<u64> {
    let (body, object, manifest, decode) = match slot {
        kasumi_types::DocumentSlot::Pending(document) => {
            return crate::snapshot_codec::inspect_typed_json_work(document);
        }
        kasumi_types::DocumentSlot::Stored(document) => {
            document.validate()?;
            ensure!(document.id == id, "document source identity differs");
            (
                document.body_bytes,
                document.body_object_bytes,
                document.body_manifest_work,
                document.body_decode_work,
            )
        }
        kasumi_types::DocumentSlot::Located(document) => (
            document.body_bytes(),
            document.body_object_bytes(),
            document.body_manifest_work(),
            document.body_decode_work(),
        ),
    };
    body.checked_mul(2)
        .and_then(|bytes| bytes.checked_add(object.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(manifest))
        .and_then(|bytes| bytes.checked_add(decode))
        .and_then(|bytes| bytes.checked_add((id.len() as u64).checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(FLOOR + 4096))
        .context("document source workspace overflow")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scope([u8; 32]);
impl Scope {
    pub(crate) fn new(tenant: &str, incarnation: &str) -> Result<Self> {
        kasumi_types::validate_name(tenant)?;
        kasumi_types::validate_name(incarnation)?;
        let mut hash = Sha256::new();
        hash.update(b"kasumi.document-scope.v1\0");
        hash.update((tenant.len() as u64).to_be_bytes());
        hash.update(tenant.as_bytes());
        hash.update((incarnation.len() as u64).to_be_bytes());
        hash.update(incarnation.as_bytes());
        Ok(Self(hash.finalize().into()))
    }
    pub(crate) fn key(self, digest: [u8; 32]) -> [u8; 64] {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&self.0);
        key[32..].copy_from_slice(&digest);
        key
    }
}

fn installed_scope(roots: &SourceRootsRef, tenant: &str, incarnation: &str) -> Result<Scope> {
    let application = roots.primary_installation().0.application();
    ensure!(
        application.tenant() == tenant,
        "document storage tenant differs"
    );
    kasumi_types::validate_name(incarnation)?;
    let purpose = application.storage_access().purpose();
    if !purpose.is_local_fixture() {
        match purpose {
            // NodeControl's incarnation is bound by the engine's authenticated
            // bootstrap/selected source; its storage purpose has no UUID field.
            kasumi_store::StoragePurpose::NodeControl => ensure!(
                tenant == crate::control::CONTROL_TENANT,
                "document Control storage tenant differs"
            ),
            _ => purpose.validate_application_identity(tenant, incarnation)?,
        }
    }
    Scope::new(tenant, incarnation)
}

/// Keep this owner alive through the joint application/custody publication.
/// Its reservation covers staged bytes even on a failed or uncertain commit.
pub(crate) struct PreparedDocuments {
    writes: Vec<WriteOp>,
    seen: BTreeMap<(bool, [u8; 32]), usize>,
    reader: DocumentReader,
    scope: Scope,
    retained: u64,
    reservation: DocumentWorkspace,
    // Fences presence checks and learns each staged manifest and its chunks.
    collector: Option<Arc<crate::document_gc::ObjectGc>>,
}
impl PreparedDocuments {
    pub(crate) fn new(
        roots: &SourceRootsRef,
        selected: &SelectedApplication,
        tenant: &str,
        incarnation: &str,
    ) -> Result<Self> {
        let scope = installed_scope(roots, tenant, incarnation)?;
        let reservation = DocumentWorkspace::new(roots.primary_installation().1, FLOOR)?;
        let reader = selected.open_document_reader(roots)?;
        Ok(Self {
            writes: vec![],
            seen: BTreeMap::new(),
            reader,
            scope,
            retained: FLOOR,
            reservation,
            collector: None,
        })
    }
    /// The engine's object collector. An object it deleted after the selection
    /// this owner reads is written again, and every after-image staged here
    /// is reported to it as live.
    pub(crate) fn collecting(mut self, collector: Arc<crate::document_gc::ObjectGc>) -> Self {
        self.collector = Some(collector);
        self
    }
    pub(crate) fn stage(&mut self, document: &Document) -> Result<StoredDocument> {
        let measured = DocumentMeasurement::new(document)?;
        let limits = measured.limits();
        let work = measured.workspace()?;
        self.reservation.ensure_peak(
            self.retained
                .checked_add(work)
                .context("document preparation overflow")?,
        )?;
        let collecting = self.collector.is_some();
        // At most `limits.blobs` digests, within this document's workspace.
        let mut blobs = Vec::new();
        let (manifest, wire) = document_encoding::encode_body(&document.body, limits, |object| {
            if collecting {
                blobs.try_reserve(1)?;
                blobs.push(object.digest());
            }
            self.put(false, object, work)
        })?;
        let object = document_encoding::EncodedObject::new(&wire);
        let descriptor = measured.descriptor(&manifest, object)?;
        self.put(true, object, work)?;
        drop(wire);
        drop(manifest);
        self.reservation.retain(self.retained);
        if let Some(collector) = &self.collector {
            blobs.sort_unstable();
            blobs.dedup();
            collector.staged(descriptor.body_object, blobs);
        }
        Ok(descriptor)
    }
    fn put(
        &mut self,
        body: bool,
        object: document_encoding::EncodedObject<'_>,
        work: u64,
    ) -> Result<()> {
        let digest = object.digest();
        let bytes = object.bytes();
        if let Some(index) = self.seen.get(&(body, digest)) {
            let WriteOp::Put { value, .. } = &self.writes[*index] else {
                unreachable!()
            };
            ensure!(
                value.as_slice() == bytes,
                "document content-address collision"
            );
            return Ok(());
        }
        let namespace = if body { BODIES } else { BLOBS };
        let key = self.scope.key(digest);
        let baseline = work
            .checked_add(self.retained)
            .context("document preparation overflow")?;
        // The selection read here predates a deletion the collector committed
        // after it: that row is absent from the root this write publishes to.
        let fenced = self
            .collector
            .as_ref()
            .is_some_and(|collector| collector.fenced(body, &digest));
        let exists = !fenced
            && self.reader.with_record(
                &mut self.reservation,
                baseline,
                namespace,
                &key,
                bytes.len(),
                |previous| {
                    if let Some(previous) = previous {
                        ensure!(
                            previous == bytes,
                            "existing document content-address differs"
                        );
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                },
            )?;
        if exists {
            return Ok(());
        }
        let retained = self
            .retained
            .checked_add(
                (bytes.len() as u64)
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(2048))
                    .context("document operation size overflow")?,
            )
            .context("document operation size overflow")?;
        self.reservation.ensure_peak(
            work.checked_add(retained)
                .context("document operation size overflow")?,
        )?;
        self.writes.try_reserve(1)?;
        let index = self.writes.len();
        self.writes.push(WriteOp::put(namespace, key, bytes));
        self.seen.insert((body, digest), index);
        self.retained = retained;
        Ok(())
    }
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
    pub(crate) fn take_writes(&mut self) -> Vec<WriteOp> {
        std::mem::take(&mut self.writes)
    }
}

/// A generation's stored-document resolver. One bounded read (a query page, a
/// snapshot read, a lease scan page) can load all of its documents through a
/// single source view instead of opening and retiring a view per document.
pub(crate) trait GenerationDocuments: DocumentResolver {
    /// `None`: this resolver opens no per-document source view to share.
    fn shared_read(&self) -> Result<Option<Box<dyn SharedRead>>> {
        Ok(None)
    }
    /// The primary rows this resolver locates compacted slots from.
    fn located_rows(&self) -> Option<Arc<LocatedRows>> {
        None
    }
}

/// One bounded read's loans through a single exact selected source view,
/// opened by its first load. Each load still admits its own decode workspace
/// and rechecks key access before lending its document. `finish` retires the
/// view and fails if the view failed or key access ended.
pub(crate) trait SharedRead: DocumentResolver {
    fn selected(&self) -> &SelectedRead;
    fn finish(self: Box<Self>) -> Result<()>;
}

/// The authenticated primary rows that a generation's located slots stand
/// for: a pinned selection whose primary directory, or exact base snapshot,
/// held every live descriptor of the boundary's state. A slot is compacted
/// only from such rows and stays located only while its document is
/// unchanged, so its row here is its exact descriptor at any later revision.
/// A later generation keeps these rows until its own selection serves a
/// current directory, which then holds the same rows; a stale directory never
/// strands a located slot.
pub(crate) struct LocatedRows {
    selection: SelectedApplication,
    boundary: crate::application_sources::SnapshotBoundary<String>,
}

impl LocatedRows {
    /// The rows of `selection` at `state`, when it serves a primary directory
    /// with document headers at exactly that revision.
    pub(crate) fn serving(
        selection: &SelectedApplication,
        state: &kasumi_types::TenantState,
    ) -> Result<Option<Arc<Self>>> {
        use kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT;
        let layout = selection.with_serving_primary(None, state, |_, _, layout| Ok(layout))?;
        Ok(layout
            .filter(|layout| *layout >= DOCUMENT_HEADERS_LAYOUT)
            .map(|_| {
                Arc::new(Self {
                    selection: selection.clone(),
                    boundary: state.into(),
                })
            }))
    }

    /// Whether these rows are the current directory of `state` itself.
    pub(crate) fn current_at(&self, state: &kasumi_types::TenantState) -> bool {
        self.boundary == crate::application_sources::SnapshotBoundary::<String>::from(state)
    }

    pub(crate) fn locate(
        &self,
        shared: Option<&SelectedRead>,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        // A shared read may lend its pages only for its own selection.
        let shared = shared.filter(|read| read.documents.selected.same_selection(&self.selection));
        let point = self
            .selection
            .with_primary_boundary(shared, &self.boundary, |tree, memory, _| {
                let (point, _decode, _) = crate::application_records::admitted_snapshot_point(
                    tree,
                    memory,
                    collection,
                    id,
                    self.boundary.revision,
                    || Ok(()),
                )?;
                Ok(point)
            })?
            .context("located document directory is no longer served")?;
        let crate::application_records::PrimaryPoint::Live(slot) = point else {
            anyhow::bail!("located document has no live primary row")
        };
        located.check(id, slot.stored()?.clone())
    }
}

/// The sequence key of the retained change commit at exactly `revision`.
/// Commit revisions increase with their keys, so a bisection over the key
/// range finds it in logarithmically many ordered lookups.
pub(crate) fn feed_commit_at(feed: &kasumi_types::ChangeFeedState, revision: u64) -> Option<u64> {
    let (last, newest) = feed.commits.get_max()?;
    if revision >= newest.revision {
        return (revision == newest.revision).then_some(*last);
    }
    let (first, commit) = feed.commits.get_min()?;
    if commit.revision > revision {
        return None;
    }
    // `low` is a key whose commit is at or before `revision`; `high` a key.
    let (mut low, mut high) = (*first, *last);
    while low < high {
        let middle = low + (high - low) / 2 + 1;
        let (&key, commit) = feed.commits.range(middle..=high).next()?;
        if commit.revision <= revision {
            low = key;
        } else {
            high = *feed.commits.range(low..key).next_back()?.0;
        }
    }
    (feed.commits.get(&low)?.revision == revision).then_some(low)
}

/// The record of `id` in `collection` within the retained commit at
/// `revision`, if it holds a slot that `matches`.
fn feed_record_mut<'a>(
    feed: &'a mut kasumi_types::ChangeFeedState,
    revision: u64,
    collection: &str,
    id: &str,
    matches: impl Fn(&Arc<kasumi_types::DocumentSlot>) -> bool,
) -> Option<&'a mut Option<Arc<kasumi_types::DocumentSlot>>> {
    let key = feed_commit_at(feed, revision)?;
    let commit = feed.commits.get(&key)?;
    let identity = (collection, id);
    let same_slot = |record: &kasumi_types::ChangeRecord| {
        (record.collection.as_str(), record.id.as_str()) == identity
            && record.document.as_ref().is_some_and(&matches)
    };
    // New commits append records in collection and document ID order. A
    // restored commit retains its original sequence even when its IDs are
    // unordered, so an unsuccessful ordered lookup still checks the record.
    let index = commit
        .records
        .binary_search_by(|record| (record.collection.as_str(), record.id.as_str()).cmp(&identity))
        .ok()
        .filter(|&index| same_slot(&commit.records[index]))
        .or_else(|| commit.records.iter().position(same_slot))?;
    let commit = Arc::make_mut(feed.commits.get_mut(&key)?);
    Some(&mut commit.records[index].document)
}

/// Compact newly published documents only. Unchanged IDs can still use their
/// complete descriptors when a previously stale primary first becomes current.
pub(crate) fn compact_changed(
    state: &mut kasumi_types::TenantState,
    changed: &crate::application_primary::ChangedIds,
) -> usize {
    use kasumi_types::DocumentSlot;
    let mut compacted = 0;
    for (name, ids) in changed {
        let Some(collection) = state.collections.get_mut(name) else {
            continue;
        };
        for id in ids {
            let Some(slot) = collection.documents.get_mut(id) else {
                continue;
            };
            let DocumentSlot::Stored(descriptor) = slot.as_ref() else {
                continue;
            };
            let Some(located) = LocatedDocument::of(descriptor) else {
                continue;
            };
            let complete = std::mem::replace(slot, Arc::new(DocumentSlot::Located(located)));
            if let Some(record) = feed_record_mut(
                &mut state.change_feed,
                complete.version(),
                name,
                id,
                |record| Arc::ptr_eq(record, &complete),
            ) {
                *record = Some(slot.clone());
            }
            compacted += 1;
        }
    }
    compacted
}

/// Compact a reopened generation whose primary covers this exact revision.
/// Compare both complete descriptors before sharing a live change record.
/// A historical record with different content keeps its own body reference.
pub(crate) fn compact_reopened(state: &mut kasumi_types::TenantState) -> usize {
    use kasumi_types::DocumentSlot;
    fn shared_location(
        collections: &BTreeMap<String, kasumi_types::CollectionState>,
        record: &kasumi_types::ChangeRecord,
    ) -> Option<LocatedDocument> {
        let current = collections
            .get(&record.collection)?
            .documents
            .get(&record.id)?;
        let saved = record.document.as_ref()?;
        match (current.as_ref(), saved.as_ref()) {
            (DocumentSlot::Stored(left), DocumentSlot::Stored(right))
                if Arc::ptr_eq(current, saved) || left == right =>
            {
                LocatedDocument::of(left)
            }
            _ => None,
        }
    }

    let mut compacted = 0;
    let collections = &mut state.collections;
    let commits = &mut state.change_feed.commits;
    let mut next = commits.get_min().map(|(key, _)| *key);
    while let Some(key) = next {
        next = key
            .checked_add(1)
            .and_then(|after| commits.get_next(&after).map(|(&key, _)| key));
        if commits.get(&key).is_none_or(|commit| {
            !commit
                .records
                .iter()
                .any(|record| shared_location(collections, record).is_some())
        }) {
            continue;
        }
        if let Some(commit) = commits.get_mut(&key) {
            for record in &mut Arc::make_mut(commit).records {
                if let Some(located) = shared_location(collections, record)
                    && let Some(slot) = collections
                        .get_mut(&record.collection)
                        .and_then(|c| c.documents.get_mut(&record.id))
                {
                    *slot = Arc::new(DocumentSlot::Located(located));
                    record.document = Some(slot.clone());
                    compacted += 1;
                }
            }
        }
    }
    for collection in collections.values_mut() {
        // Drop the borrowed root after each page, so copy-on-write never
        // pins a second complete document map during compaction.
        let mut after: Option<String> = None;
        loop {
            use std::ops::Bound::{Excluded, Unbounded};
            let before = collection.documents.clone();
            let lower = after.as_ref().map_or(Unbounded, Excluded);
            let mut last = None;
            for (id, original) in before.range::<_, String>((lower, Unbounded)).take(64) {
                if let DocumentSlot::Stored(descriptor) = original.as_ref()
                    && let Some(located) = LocatedDocument::of(descriptor)
                    && let Some(slot) = collection.documents.get_mut(id)
                {
                    *slot = Arc::new(DocumentSlot::Located(located));
                    compacted += 1;
                }
                last = Some(id);
            }
            let Some(last) = last else { break };
            after = Some(last.clone());
        }
    }
    compacted
}

/// Give each retained change record that still names the located slot a
/// change of `changed` supersedes its complete descriptor, read from the
/// `previous` generation's rows through `resolver`. A located record must
/// always name its document's current version, which a later directory row
/// resolves; this keeps a superseded after-image readable and collectable.
pub(crate) fn rehydrate_superseded(
    previous: &kasumi_types::TenantState,
    resolver: Option<&dyn DocumentResolver>,
    candidate: &mut kasumi_types::TenantState,
    changed: &crate::application_primary::ChangedIds,
) -> Result<usize> {
    use kasumi_types::DocumentSlot;
    let mut rehydrated = 0;
    for (name, ids) in changed {
        let Some(old) = previous.collections.get(name) else {
            continue;
        };
        for id in ids {
            let Some(slot) = old.documents.get(id) else {
                continue;
            };
            if !matches!(slot.as_ref(), DocumentSlot::Located(_)) {
                continue;
            }
            let Some(record) = feed_record_mut(
                &mut candidate.change_feed,
                slot.version(),
                name,
                id,
                |record| {
                    matches!(record.as_ref(), DocumentSlot::Located(_))
                        && record.version() == slot.version()
                },
            ) else {
                continue;
            };
            let descriptor = slot.descriptor(name, id, resolver)?.into_owned();
            *record = Some(Arc::new(DocumentSlot::stored_descriptor(descriptor)));
            rehydrated += 1;
        }
    }
    Ok(rehydrated)
}

/// Each operation borrows the exact selected native source. It never opens
/// latest and releases its native loan before returning an admitted body.
#[derive(Clone)]
pub(crate) struct SelectedDocuments {
    selected: SelectedApplication,
    roots: SourceRootsRef,
    scope: Scope,
    located: Option<Arc<LocatedRows>>,
}
impl SelectedDocuments {
    pub(crate) fn new(
        roots: SourceRootsRef,
        selected: SelectedApplication,
        tenant: &str,
        incarnation: &str,
    ) -> Result<Self> {
        selected.require_document_roots(&roots)?;
        let scope = installed_scope(&roots, tenant, incarnation)?;
        Ok(Self {
            selected,
            roots,
            scope,
            located: None,
        })
    }

    /// Resolve located slots from `rows`.
    pub(crate) fn locating(mut self, rows: Option<Arc<LocatedRows>>) -> Self {
        self.located = rows;
        self
    }

    pub(crate) fn located_rows(&self) -> Option<&Arc<LocatedRows>> {
        self.located.as_ref()
    }

    fn locate_with(
        &self,
        shared: Option<&SelectedRead>,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        self.located
            .as_ref()
            .context("located document has no selected primary rows")?
            .locate(shared, collection, id, located)
    }

    /// Bootstrap materialization remains governed by this generation's exact
    /// native custody and key access even when no native body lookup is needed.
    pub(crate) fn with_source<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        let reader = self.selected.open_document_reader(&self.roots)?;
        reader.check_access()?;
        let result = read();
        let result = checked_completion(result, reader.check_access());
        checked_completion(result, reader.close())
    }

    pub(crate) fn shared_reader(&self) -> SelectedRead {
        SelectedRead {
            documents: self.clone(),
            reader: Mutex::new(None),
            pages: OnceLock::new(),
            primary: OnceLock::new(),
        }
    }

    /// Validate the descriptor and admit its wire workspace before any read.
    fn prepare(&self, descriptor: &StoredDocument) -> Result<PreparedLoad> {
        descriptor.validate()?;
        let limits = limits(usize::try_from(descriptor.body_bytes)?)?;
        let manifest_bytes = usize::try_from(descriptor.body_object_bytes)?;
        ensure!(
            manifest_bytes > 0 && manifest_bytes <= limits.manifest_bytes,
            "document manifest length exceeds bound"
        );
        let wire_floor = FLOOR
            .checked_add(
                descriptor
                    .body_bytes
                    .checked_mul(2)
                    .context("document read workspace overflow")?,
            )
            .and_then(|v| v.checked_add(descriptor.body_object_bytes.checked_mul(2)?))
            .context("document read workspace overflow")?;
        let reservation = DocumentWorkspace::new(self.roots.primary_installation().1, wire_floor)?;
        Ok(PreparedLoad {
            limits,
            manifest_bytes,
            wire_floor,
            reservation,
        })
    }

    /// Read and decode one body through `reader`, which the caller closes or
    /// rechecks before lending the result.
    fn decode(
        &self,
        descriptor: &StoredDocument,
        prepared: PreparedLoad,
        reader: &mut DocumentReader,
    ) -> Result<Decoded> {
        let PreparedLoad {
            limits,
            manifest_bytes,
            wire_floor,
            mut reservation,
        } = prepared;
        let key = self.scope.key(descriptor.body_object);
        let manifest_wire = reader.with_record(
            &mut reservation,
            wire_floor,
            BODIES,
            &key,
            manifest_bytes,
            |wire| {
                let wire = wire.context("selected document manifest missing")?;
                ensure!(
                    wire.len() == manifest_bytes
                        && Sha256::digest(wire).as_slice() == descriptor.body_object,
                    "selected document manifest identity differs"
                );
                Ok(wire.to_vec())
            },
        )?;
        let manifest_work =
            crate::snapshot_codec::inspect_external_json_work(&manifest_wire, &mut || Ok(()))?;
        ensure!(
            manifest_work == descriptor.body_manifest_work,
            "document manifest workspace differs"
        );
        let baseline = wire_floor
            .checked_add(manifest_work)
            .context("document manifest workspace overflow")?;
        reservation.ensure_peak(baseline)?;
        let manifest = BodyManifest::from_bytes(&manifest_wire, limits)?;
        ensure!(
            manifest.canonical_bytes == descriptor.body_bytes
                && manifest.canonical_sha256 == descriptor.body_sha256,
            "selected document logical identity differs"
        );
        let canonical = document_encoding::reconstruct_body(&manifest, limits, |reference| {
            let key = self.scope.key(reference.sha256);
            reader.with_record(
                &mut reservation,
                baseline,
                BLOBS,
                &key,
                usize::try_from(reference.bytes)?,
                |bytes| {
                    Ok(bytes
                        .context("selected document proof chunk missing")?
                        .to_vec())
                },
            )
        })?;
        let body_work =
            crate::snapshot_codec::inspect_external_json_work(&canonical, &mut || Ok(()))?;
        ensure!(
            body_work == descriptor.body_decode_work,
            "document body workspace differs"
        );
        let decoded_work = body_work
            .checked_add(
                (descriptor.id.len() as u64)
                    .checked_mul(2)
                    .context("document identity workspace overflow")?,
            )
            .and_then(|bytes| bytes.checked_add(4096))
            .context("document decode workspace overflow")?;
        reservation.ensure_peak(
            baseline
                .checked_add(decoded_work)
                .context("document decode workspace overflow")?,
        )?;
        let body = serde_json::from_slice(&canonical)?;
        let document = Document {
            id: descriptor.id.clone(),
            version: descriptor.version,
            body,
        };
        drop(canonical);
        drop(manifest);
        drop(manifest_wire);
        Ok(Decoded {
            document,
            reservation,
            decoded_work,
        })
    }
}

fn checked_completion<T>(result: Result<T>, completion: Result<()>) -> Result<T> {
    match (result, completion) {
        (result, Ok(())) => result,
        (Ok(value), Err(error)) => {
            drop(value);
            Err(error)
        }
        // Keep both original owners if decoding and source retirement fail.
        (Err(original), Err(completion)) => Err(original.context(completion)),
    }
}

struct PreparedLoad {
    limits: BodyLimits,
    manifest_bytes: usize,
    wire_floor: u64,
    reservation: DocumentWorkspace,
}

struct Decoded {
    document: Document,
    // After the document: its backing dies before the admission is returned.
    reservation: DocumentWorkspace,
    decoded_work: u64,
}
impl Decoded {
    fn into_shared(self) -> SharedDocument {
        let Self {
            document,
            mut reservation,
            decoded_work,
        } = self;
        // The borrowed scan quotes serde's actual decode backing, including
        // parser capacities. This body's wire, manifest and native read work
        // has ended now.
        reservation.retain(decoded_work);
        SharedDocument::from_admitted_owner(Arc::new(DecodedOwner {
            document,
            _reservation: reservation,
        }))
    }
}

struct DecodedOwner {
    document: Document,
    // LAST: decoded backing dies before its actual admission is returned.
    _reservation: DocumentWorkspace,
}
impl AdmittedDocumentOwner for DecodedOwner {
    fn document(&self) -> &Document {
        &self.document
    }
}
impl DocumentResolver for SelectedDocuments {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        let prepared = self.prepare(descriptor)?;
        let mut reader = self.selected.open_document_reader(&self.roots)?;
        let decoded = self.decode(descriptor, prepared, &mut reader)?;
        reader.close()?;
        Ok(decoded.into_shared())
    }
    fn locate(
        &self,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        self.locate_with(None, collection, id, located)
    }
}
impl GenerationDocuments for SelectedDocuments {
    fn shared_read(&self) -> Result<Option<Box<dyn SharedRead>>> {
        Ok(Some(Box::new(self.shared_reader())))
    }
    fn located_rows(&self) -> Option<Arc<LocatedRows>> {
        self.located.clone()
    }
}

/// The selected source view one bounded read shares across its loads. It is
/// the same exact child reader a single load opens, opened at the first load.
/// A failed load drops it, as a per-document reader would have been dropped,
/// and the next load opens another.
pub(crate) struct SelectedRead {
    documents: SelectedDocuments,
    // Taken out while in use, so a failure or unwind never puts it back.
    reader: Mutex<Option<DocumentReader>>,
    // A page of query results may visit adjacent descriptors through many
    // short-lived tree readers. These hints die with this selected read.
    pages: OnceLock<Arc<PageCache>>,
    primary: OnceLock<(PrimaryManifest, kasumi_kv::CacheMemoryLease)>,
}
impl SelectedRead {
    pub(crate) fn directory_pages(&self, memory: &Arc<dyn NodeDiskMemoryAdmission>) -> &PageCache {
        // Keep a small ancestor path and its live and archive leaves. The LRU
        // charges decoded bytes to the node and falls back to disk on refusal.
        self.pages
            .get_or_init(|| PageCache::new(memory.clone(), 8 * MAX_PAGE_BYTES as u64))
    }

    /// The paired source is immutable for the lifetime of this selection.
    /// Callers must hold its directory loan and check the requested boundary.
    pub(crate) fn primary_manifest(
        &self,
        view: &TenantStorageReadView,
    ) -> Result<Option<std::borrow::Cow<'_, PrimaryManifest>>> {
        use std::borrow::Cow;
        view.check_access()?;
        if let Some((manifest, _)) = self.primary.get() {
            return Ok(Some(Cow::Borrowed(manifest)));
        }
        let Some(manifest) = PrimaryManifest::load_from_pair(view)? else {
            return Ok(None);
        };
        let credit = (MAX_MANIFEST_BYTES + std::mem::size_of::<PrimaryManifest>()) as u64;
        if manifest.is_current()
            && let Ok(lease) = view.memory().reserve_cache_memory(credit)
        {
            let (manifest, _) = self.primary.get_or_init(|| (manifest, lease));
            return Ok(Some(Cow::Borrowed(manifest)));
        }
        Ok(Some(Cow::Owned(manifest)))
    }

    fn with_reader<T>(&self, read: impl FnOnce(&mut DocumentReader) -> Result<T>) -> Result<T> {
        let idle = self.reader.lock().unwrap_or_else(|p| p.into_inner()).take();
        let mut reader = match idle {
            Some(reader) => reader,
            None => self
                .documents
                .selected
                .open_document_reader(&self.documents.roots)?,
        };
        let result = read(&mut reader);
        if result.is_ok() {
            self.reader
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_or_insert(reader);
        }
        result
    }

    pub(crate) fn with_directory_reader<T>(
        &self,
        selection: &SelectedApplication,
        read: impl FnOnce(&DocumentReader) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            self.documents.selected.same_selection(selection),
            "directory and body selected different native roots"
        );
        self.with_reader(|reader| read(reader))
    }

    /// `SelectedDocuments::with_source` through the shared view.
    pub(crate) fn with_source<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.with_reader(|reader| reader.check_access())?;
        let result = read();
        checked_completion(result, self.with_reader(|reader| reader.check_access()))
    }
}
impl SelectedRead {
    pub(crate) fn locate_shared(
        &self,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        self.documents
            .locate_with(Some(self), collection, id, located)
    }
}
impl DocumentResolver for SelectedRead {
    fn locate(
        &self,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        self.locate_shared(collection, id, located)
    }
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        let prepared = self.documents.prepare(descriptor)?;
        self.with_reader(|reader| {
            let decoded = self.documents.decode(descriptor, prepared, reader)?;
            // A single load's close makes this check: decryption and JSON
            // reconstruction may outlive a key lease.
            reader.check_access()?;
            Ok(decoded)
        })
        .map(Decoded::into_shared)
    }
}
impl SharedRead for SelectedRead {
    fn selected(&self) -> &SelectedRead {
        self
    }
    fn finish(self: Box<Self>) -> Result<()> {
        match self.reader.into_inner().unwrap_or_else(|p| p.into_inner()) {
            Some(reader) => reader.close(),
            None => Ok(()),
        }
    }
}
