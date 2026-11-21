//! One-row-at-a-time logical snapshot materialization into encrypted bodies.
//! Scratch tables are unpublished and private until the complete snapshot is
//! verified; its restore then brings both published object namespaces to the
//! snapshot's objects in bounded batches. A reopening replica's own snapshot
//! names objects its store already published: decoding compares each with
//! that row and stages only an object the store lacks or holds otherwise.
use crate::{
    document_encoding::{self, BLOB_CHUNK_BYTES, BodyManifest},
    document_store::{
        BLOBS, BODIES, DocumentMeasurement, GenerationDocuments, Scope, SelectedRead, SharedRead,
        limits,
    },
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    DiskMemoryLease, EncryptedTable, EncryptedTableBatch, NodeDiskMemoryAdmission, PlaintextValue,
    ScratchDisk, ScratchTableValue, TenantReadView, TenantStore, WriteOp,
};
use kasumi_types::{
    AdmittedDocumentOwner, Document, DocumentResolver, SharedDocument, StoredDocument,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const FLOOR: u64 = 64 << 10;
/// Operations and copied object bytes in one restore correction batch: one
/// ordinary store write, far below the native transaction staging cap.
#[cfg(not(test))]
const CORRECTION_ENTRIES: usize = 4096;
#[cfg(test)]
const CORRECTION_ENTRIES: usize = 3;
const CORRECTION_BYTES: usize = 8 << 20;
/// A published manifest never exceeds the staged table's own row cap; a chunk
/// never exceeds `BLOB_CHUNK_BYTES`. Each visited row reserves its full bound.
const MAX_OBJECT_BYTES: usize = 32 << 20;
/// Objects a reopening decode compared most recently: a chunk repeated within
/// nearby documents needs no second point read.
const RECENT: usize = 16;
/// Digests a reopened snapshot's name set first admits, then doubles.
const NAMES_GROWTH: usize = 4096;
// At most 8 MiB of digest vectors per namespace. Later distinct names share
// the same encrypted table and bounded native transaction as the staged objects.
const RESIDENT_NAMES: usize = 128 << 10;

/// Only read-side decode admission constructs this error. Keep its original
/// provider observation separate from native I/O and retirement failures.
#[derive(Debug)]
pub(crate) struct ReadAdmissionFailure {
    original: std::io::Error,
}
impl ReadAdmissionFailure {
    pub(crate) fn reserve(
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
        bytes: u64,
    ) -> Result<DiskMemoryLease> {
        memory
            .clone()
            .reserve_document_decode(bytes)
            .map_err(|original| anyhow::Error::new(Self { original }))
    }

    pub(crate) fn is_capacity_denied(&self) -> bool {
        self.original.kind() == std::io::ErrorKind::OutOfMemory
    }
}
impl std::fmt::Display for ReadAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("document decode admission failed")
    }
}
impl std::error::Error for ReadAdmissionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Peak document-only slice of a logical materialization. The input record is
/// already admitted separately. Pending object copies are bounded by two native
/// batches; their total does not depend on document count or aggregate bodies.
pub(crate) fn workspace(maximum_record_bytes: u64, maximum_record_work: u64) -> Result<u64> {
    if maximum_record_bytes == 0 {
        return Ok(0);
    }
    let body = maximum_record_bytes.min(32 << 20);
    let limits = limits(usize::try_from(body)?)?;
    let token = crate::admission::MemoryCore::required_installed_reservation_bytes(0)?;
    let pending = (EncryptedTableBatch::MAX_BYTES as u64)
        .checked_mul(4)
        .and_then(|bytes| {
            bytes.checked_add(
                (EncryptedTableBatch::MAX_ENTRIES as u64)
                    .checked_mul(2)?
                    .checked_mul(2048u64.checked_add(token)?)?,
            )
        })
        .context("document pending workspace overflow")?;
    let encoding = maximum_record_work
        .checked_add(
            body.checked_mul(8)
                .context("document encoding workspace overflow")?,
        )
        .and_then(|bytes| bytes.checked_add(1 << 20))
        .and_then(|bytes| bytes.checked_add(token))
        .and_then(|bytes| bytes.checked_add(pending))
        .context("document encoding workspace overflow")?;
    // A manifest has at most 64 root sites, 16 sites per fragment, and
    // 40 per blob (including all 32 digest scalars). Literal and scalar bytes
    // are bounded by the manifest wire limit. This follows its fixed schema,
    // rather than assuming JSON structure is proportional to logical body size.
    let sites = (limits.fragments as u64)
        .checked_mul(16)
        .and_then(|sites| sites.checked_add((limits.blobs as u64).checked_mul(40)?))
        .and_then(|sites| sites.checked_add(64))
        .context("document manifest shape overflow")?;
    let manifest = limits.manifest_bytes as u64;
    let manifest_work = crate::snapshot_codec::bounded_json_work(manifest, sites)?;
    // During restore validation and genesis streaming, the unpublished
    // generation resolves directly through StagedDocuments. No selected
    // application reader exists until later publication, so this phase owns
    // three decode leases and no document-reader cell credits.
    let reading = body
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(manifest.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(FLOOR))
        .and_then(|bytes| bytes.checked_add(manifest_work))
        .and_then(|bytes| bytes.checked_add(maximum_record_work))
        // The record meter includes the document's id and DTO framing. Keep
        // the explicit decoded-owner allowance used by StagedDocuments::load.
        .and_then(|bytes| bytes.checked_add(4096))
        .and_then(|bytes| bytes.checked_add(token.checked_mul(3)?))
        .context("document read workspace overflow")?;
    Ok(encoding.max(reading))
}

struct TableBacking {
    bodies: EncryptedTable,
    blobs: EncryptedTable,
}
struct Tables {
    // Empty authenticated snapshots need scope ownership, not two native
    // databases. A builder always installs both tables before accepting rows.
    backing: Option<TableBacking>,
    disk: Arc<ScratchDisk>,
    scope: Scope,
    // LAST: table handles and their backing retire before this owner's credit.
    _metadata: DiskMemoryLease,
}

/// Immutable after the builder has been consumed. Clones share encrypted
/// backing, never a map of decoded payloads. Only a reopened snapshot keeps
/// a bounded sorted prefix of object digests and encrypted overflow rows.
#[derive(Clone)]
pub(crate) struct StagedDocuments {
    tables: Arc<Tables>,
    // Established by the consumed builder; these private tables never gain
    // objects after finish. Empty bootstraps need no membership point reads.
    // Whether the snapshot names any body, staged or published.
    has_bodies: bool,
    // A reopened snapshot: the objects it names that were not staged are the
    // rows its store held with the same bytes when decoded.
    published: Option<Arc<Published>>,
}

pub(crate) struct Builder {
    bodies: ObjectBatch,
    blobs: ObjectBatch,
    has_bodies: bool,
    tables: Arc<Tables>,
    comparing: Option<Comparing>,
    failed: bool,
}

/// Digests of the objects a reopened snapshot names in one namespace, and of
/// those it staged because the store lacked them or held other bytes. Each
/// buffer grows only under an admitted grant; sealing sorts both.
#[derive(Default)]
struct Names {
    all: Vec<[u8; 32]>,
    staged: Vec<[u8; 32]>,
    limit: usize,
    // Once the resident prefix is sealed, count distinct keys in the private
    // table. Its 32-byte membership keys and 64-byte object keys are disjoint.
    spill: Option<NameCounts>,
    // LAST: the buffers retire before the credit that admitted them.
    grant: Option<DiskMemoryLease>,
}
#[derive(Default)]
struct NameCounts {
    held: usize,
    staged: usize,
}

impl Names {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    fn record(
        &mut self,
        table: &EncryptedTable,
        batch: &mut ObjectBatch,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
        digest: [u8; 32],
        staged: bool,
    ) -> Result<()> {
        if self.spill.is_none() && self.all.len() < self.limit {
            return self.push(memory, digest, staged);
        }
        if self.spill.is_none() {
            self.seal();
            self.spill = Some(NameCounts::default());
        }
        if self.all.binary_search(&digest).is_err() && batch.put_name(table, digest, staged)? {
            let counts = self.spill.as_mut().expect("sealed name prefix");
            let count = if staged {
                &mut counts.staged
            } else {
                &mut counts.held
            };
            *count = count
                .checked_add(1)
                .context("document name count overflow")?;
        }
        Ok(())
    }

    fn push(
        &mut self,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
        digest: [u8; 32],
        staged: bool,
    ) -> Result<()> {
        let grow_all = self.all.len() == self.all.capacity();
        let grow_staged = staged && self.staged.len() == self.staged.capacity();
        if grow_all || grow_staged {
            let all = if grow_all {
                self.all
                    .capacity()
                    .saturating_mul(2)
                    .max(NAMES_GROWTH)
                    .min(self.limit)
            } else {
                self.all.capacity()
            };
            let staged = if grow_staged {
                self.staged
                    .capacity()
                    .saturating_mul(2)
                    .max(16)
                    .min(self.limit)
            } else {
                self.staged.capacity()
            };
            let bytes = all
                .checked_add(staged)
                .and_then(|digests| digests.checked_mul(32))
                .context("document name set overflow")?;
            // The previous grant still covers each buffer a reallocation
            // copies from, until both have grown.
            let previous = self
                .grant
                .replace(memory.clone().reserve_installed(u64::try_from(bytes)?)?);
            self.all.try_reserve_exact(all - self.all.len())?;
            self.staged.try_reserve_exact(staged - self.staged.len())?;
            drop(previous);
        }
        self.all.push(digest);
        if staged {
            self.staged.push(digest);
        }
        Ok(())
    }
    fn seal(&mut self) {
        for digests in [&mut self.all, &mut self.staged] {
            digests.sort_unstable();
            digests.dedup();
        }
    }
    /// None means the snapshot does not name this object. A true value means
    /// its authenticated replacement is staged in this same private table.
    fn is_staged(&self, table: &EncryptedTable, digest: &[u8; 32]) -> Result<Option<bool>> {
        if self.all.binary_search(digest).is_ok() {
            return Ok(Some(self.staged.binary_search(digest).is_ok()));
        }
        if self.spill.is_none() {
            return Ok(None);
        }
        table
            .get(digest)?
            .map(|value| name_marker(value.as_bytes()))
            .transpose()
    }
    fn counts(&self) -> NameCounts {
        NameCounts {
            held: self.all.len() - self.staged.len() + self.spill.as_ref().map_or(0, |s| s.held),
            staged: self.staged.len() + self.spill.as_ref().map_or(0, |s| s.staged),
        }
    }
}

/// A reopened snapshot's objects in its own store: every object it names,
/// each of which that store held with the same bytes when decoded unless it
/// is staged instead.
struct Published {
    store: Arc<TenantStore>,
    bodies: Names,
    blobs: Names,
}
impl Published {
    fn names(&self, body: bool) -> &Names {
        if body { &self.bodies } else { &self.blobs }
    }
}

/// A reopening decode's comparison with the rows its store already published,
/// through one view held until the builder finishes.
struct Comparing {
    published: Published,
    view: TenantReadView,
    recent: [Option<(bool, [u8; 32])>; RECENT],
    next: usize,
}
impl Comparing {
    /// Compare an object absent from the recent held-object cache against
    /// the pinned view. A different row needs an authenticated staged copy.
    fn holds(
        &mut self,
        body: bool,
        digest: [u8; 32],
        key: &[u8; 64],
        bytes: &[u8],
    ) -> Result<bool> {
        let (namespace, bound) = if body {
            (BODIES, MAX_OBJECT_BYTES)
        } else {
            (BLOBS, BLOB_CHUNK_BYTES)
        };
        let held = self
            .view
            .get(namespace, key, bound)?
            .is_some_and(|published| published.as_bytes() == bytes);
        if held {
            self.recent[self.next] = Some((body, digest));
            self.next = (self.next + 1) % RECENT;
        }
        Ok(held)
    }
    fn finish(self) -> Result<Published> {
        let Self {
            mut published,
            view,
            ..
        } = self;
        view.close()?;
        published.bodies.seal();
        published.blobs.seal();
        Ok(published)
    }
}

/// One object's bytes: its staged copy, or the published row a reopened
/// snapshot names.
enum ObjectBytes {
    Staged(ScratchTableValue),
    Published(PlaintextValue),
}
impl AsRef<[u8]> for ObjectBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Staged(value) => value.as_bytes(),
            Self::Published(value) => value.as_bytes(),
        }
    }
}

/// The digest of a content-addressed row of `scope`, if it is one.
fn scoped_digest(scope: &[u8; 64], key: &[u8]) -> Option<[u8; 32]> {
    (key.len() == 64 && key[..32] == scope[..32])
        .then(|| key[32..].try_into().expect("checked object key width"))
}

fn name_marker(value: &[u8]) -> Result<bool> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => anyhow::bail!("invalid reopened document name marker"),
    }
}

fn visit_objects(
    table: &EncryptedTable,
    mut visit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    table.visit(|key, value| match key.len() {
        64 => visit(key, value),
        32 => name_marker(value).map(|_| ()),
        _ => anyhow::bail!("invalid private document key width"),
    })
}

struct KnownObject {
    key: [u8; 64],
    value: Vec<u8>,
    _memory: DiskMemoryLease,
}
struct ObjectBatch {
    batch: Option<EncryptedTableBatch>,
    // At most 16 exact originals, totaling at most 4 MiB per table. Keep them
    // across commits so repeated proof chunks need no encrypted point read.
    // The same grants cover their copies through commit/abort retirement.
    known: Vec<KnownObject>,
    bytes: usize,
}
impl ObjectBatch {
    fn new() -> Self {
        Self {
            batch: None,
            known: Vec::with_capacity(EncryptedTableBatch::MAX_ENTRIES),
            bytes: 0,
        }
    }
    fn put_name(&mut self, table: &EncryptedTable, digest: [u8; 32], staged: bool) -> Result<bool> {
        if self
            .batch
            .as_ref()
            .is_some_and(|batch| !batch.has_capacity_for(33))
        {
            self.flush()?;
        }
        if self.batch.is_none() {
            self.batch = Some(table.begin_index_batch()?);
        }
        self.batch
            .as_mut()
            .expect("opened name batch")
            .insert_content(&digest, &[u8::from(staged)])
    }
    fn put(
        &mut self,
        table: &EncryptedTable,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
        key: [u8; 64],
        bytes: &[u8],
    ) -> Result<()> {
        if let Some(previous) = self.known.iter().find(|row| row.key == key) {
            ensure!(
                previous.value.as_slice() == bytes,
                "known document content-address collision"
            );
            return Ok(());
        }
        let row_bytes = key
            .len()
            .checked_add(bytes.len())
            .context("document staging batch overflow")?;
        if let Some(batch) = &self.batch
            && !batch.has_capacity_for(row_bytes)
        {
            // Keep a full transaction private when the object is already in
            // its view. Only a genuinely new object needs the next writer.
            if batch.contains_exact(&key, bytes)? {
                return Ok(());
            }
            self.flush()?;
        }
        // A committed duplicate alone does not need another private writer.
        if self.batch.is_none()
            && let Some(previous) = table.get(&key)?
        {
            ensure!(
                previous.as_bytes() == bytes,
                "document restore content-address collision"
            );
            return Ok(());
        }
        // Keep the single-row corridor for large manifests.
        if row_bytes > EncryptedTableBatch::MAX_BYTES {
            return table.insert(&key, bytes);
        }
        if self.batch.is_none() {
            self.batch = Some(table.begin_index_batch()?);
        }
        if !self
            .batch
            .as_mut()
            .expect("opened object batch")
            .insert_content(&key, bytes)?
        {
            return Ok(());
        }
        if self.known.len() == EncryptedTableBatch::MAX_ENTRIES
            || self
                .bytes
                .checked_add(row_bytes)
                .is_none_or(|n| n > EncryptedTableBatch::MAX_BYTES)
        {
            // The native transaction owns and charges its pending row bytes.
            // Evicting these duplicate-read copies does not publish the batch.
            self.known.clear();
            self.bytes = 0;
        }
        let retained = (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|value| value.checked_add(2048))
            .context("document pending row overflow")?;
        let grant = memory.clone().reserve_document_decode(retained)?;
        self.known.push(KnownObject {
            key,
            value: bytes.to_vec(),
            _memory: grant,
        });
        self.bytes += row_bytes;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if let Some(batch) = self.batch.take() {
            batch.commit()?;
        }
        Ok(())
    }
}

impl Builder {
    /// `max_table_bytes` is each native table's physical cap. Both also consume
    /// the exact installed ScratchDisk's aggregate space/memory governor.
    pub(crate) fn new(
        disk: &Arc<ScratchDisk>,
        max_table_bytes: u64,
        tenant: &str,
        incarnation: &str,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        let scope = kasumi_store::ScratchOperationFailure::ordinary(|| {
            kasumi_types::validate_name(incarnation)?;
            Scope::new(tenant, incarnation)
        })?;
        // This is retained table/batch bookkeeping, not a decoded document
        // loan. Its ordinary resident charge must not demand another source
        // headroom reserve after the enclosing restore has admitted its work.
        let metadata = disk.memory().clone().reserve_installed(FLOOR)?;
        let bodies = EncryptedTable::new(disk, max_table_bytes, disk.native_cache_config())?;
        let blobs = EncryptedTable::new(disk, max_table_bytes, disk.native_cache_config())?;
        Ok(Self {
            bodies: ObjectBatch::new(),
            blobs: ObjectBatch::new(),
            has_bodies: false,
            tables: Arc::new(Tables {
                backing: Some(TableBacking { bodies, blobs }),
                disk: disk.clone(),
                scope,
                _metadata: metadata,
            }),
            comparing: None,
            failed: false,
        })
    }

    /// For a reopening replica's own snapshot only, before the first push:
    /// compare each object with the row `store` already published under its
    /// content address and stage only an object it lacks or holds otherwise.
    /// The restore must publish a store-backed resolver, so these objects are
    /// never read from this staging after their reconciliation.
    pub(crate) fn compare_published(
        &mut self,
        store: &Arc<TenantStore>,
        tenant: &str,
        incarnation: &str,
    ) -> Result<()> {
        ensure!(
            !self.failed && !self.has_bodies && self.comparing.is_none(),
            "document comparison must precede every object"
        );
        ensure!(
            store.tenant() == tenant && Scope::new(tenant, incarnation)? == self.tables.scope,
            "reopened document store scope differs"
        );
        self.comparing = Some(Comparing {
            published: Published {
                store: store.clone(),
                bodies: Names::new(RESIDENT_NAMES),
                blobs: Names::new(RESIDENT_NAMES),
            },
            view: store.read_view()?,
            recent: [None; RECENT],
            next: 0,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn limit_resident_names_for_test(&mut self, limit: usize) {
        let published = &mut self
            .comparing
            .as_mut()
            .expect("reopening builder")
            .published;
        published.bodies.limit = limit;
        published.blobs.limit = limit;
    }

    /// The caller already owns/admitted this single decoded snapshot record.
    /// A failed push permanently prevents this partial staging from finishing.
    pub(crate) fn push(&mut self, document: &Document) -> Result<StoredDocument> {
        ensure!(!self.failed, "document restore builder previously failed");
        self.failed = true;
        let measured = DocumentMeasurement::new(document)?;
        let limits = measured.limits();
        let work = measured.workspace()?;
        let _workspace = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(work)?;
        let (manifest, wire) = document_encoding::encode_body(&document.body, limits, |object| {
            self.put(false, object)
        })?;
        let object = document_encoding::EncodedObject::new(&wire);
        let descriptor = measured.descriptor(&manifest, object)?;
        self.put(true, object)?;
        self.failed = false;
        Ok(descriptor)
    }

    fn put(&mut self, body: bool, object: document_encoding::EncodedObject<'_>) -> Result<()> {
        let digest = object.digest();
        let bytes = object.bytes();
        let key = self.tables.scope.key(digest);
        let backing = self.tables.backing.as_ref().expect("builder table backing");
        let (table, batch) = if body {
            (&backing.bodies, &mut self.bodies)
        } else {
            (&backing.blobs, &mut self.blobs)
        };
        if let Some(comparing) = &mut self.comparing {
            if comparing.recent.contains(&Some((body, digest))) {
                return Ok(());
            }
            let held = comparing.holds(body, digest, &key, bytes)?;
            let names = if body {
                &mut comparing.published.bodies
            } else {
                &mut comparing.published.blobs
            };
            names.record(table, batch, self.tables.disk.memory(), digest, !held)?;
            if held {
                self.has_bodies |= body;
                return Ok(());
            }
        }
        batch.put(table, self.tables.disk.memory(), key, bytes)?;
        self.has_bodies |= body;
        Ok(())
    }

    /// Call only after the enclosing authenticated snapshot stream has passed
    /// its count, order, digest and EOF checks. This does not publish live rows.
    pub(crate) fn finish(mut self) -> Result<StagedDocuments> {
        ensure!(!self.failed, "document restore builder previously failed");
        self.failed = true;
        self.bodies.flush()?;
        self.blobs.flush()?;
        let published = self
            .comparing
            .take()
            .map(Comparing::finish)
            .transpose()?
            .map(Arc::new);
        Ok(StagedDocuments {
            tables: self.tables,
            has_bodies: self.has_bodies,
            published,
        })
    }
}

/// One bounded correction batch of a published object namespace. Its
/// operation buffer and copied objects are admitted before allocation.
struct Correction<'a> {
    store: &'a Arc<TenantStore>,
    memory: &'a Arc<dyn NodeDiskMemoryAdmission>,
    namespace: &'static str,
    operations: Vec<WriteOp>,
    bytes: usize,
    // LAST: the buffer and its copies retire before their credit.
    _grant: DiskMemoryLease,
}
impl<'a> Correction<'a> {
    fn new(
        store: &'a Arc<TenantStore>,
        memory: &'a Arc<dyn NodeDiskMemoryAdmission>,
        namespace: &'static str,
    ) -> Result<Self> {
        // Each operation owns its namespace and key copies besides its slot.
        let entry = std::mem::size_of::<WriteOp>() + namespace.len() + 64 + 128;
        let bytes = CORRECTION_ENTRIES
            .checked_mul(entry)
            .and_then(|bytes| bytes.checked_add(CORRECTION_BYTES))
            .context("document correction workspace overflow")?;
        let grant = memory.clone().reserve_installed(u64::try_from(bytes)?)?;
        let mut operations = Vec::new();
        operations.try_reserve_exact(CORRECTION_ENTRIES)?;
        Ok(Self {
            store,
            memory,
            namespace,
            operations,
            bytes: 0,
            _grant: grant,
        })
    }
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        if self.operations.len() == CORRECTION_ENTRIES {
            self.flush()?;
        }
        self.operations.push(WriteOp::delete(self.namespace, key));
        Ok(())
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if value.len() > CORRECTION_BYTES {
            // An object above the batch allowance is written alone.
            self.flush()?;
            let _copy = self.memory.clone().reserve_installed(
                u64::try_from(value.len())?
                    .checked_add(4096)
                    .context("document correction workspace overflow")?,
            )?;
            return self
                .store
                .write_batch(&[WriteOp::put(self.namespace, key, value)]);
        }
        if self.operations.len() == CORRECTION_ENTRIES
            || self.bytes + value.len() > CORRECTION_BYTES
        {
            self.flush()?;
        }
        self.operations
            .push(WriteOp::put(self.namespace, key, value));
        self.bytes += value.len();
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if !self.operations.is_empty() {
            self.store.write_batch(&self.operations)?;
            self.operations.clear();
            self.bytes = 0;
        }
        Ok(())
    }
    /// Write each object of `table` this namespace lacks or holds with other
    /// bytes: no reader names another row under an object's content address.
    /// Each lookup is bounded by the object's own length.
    fn write_missing(&mut self, table: &EncryptedTable) -> Result<()> {
        visit_objects(table, |key, value| {
            if self
                .store
                .get_bounded(self.namespace, key, value.len())?
                .is_none_or(|published| published.as_bytes() != value)
            {
                self.put(key, value)?;
            }
            Ok(())
        })?;
        self.flush()
    }
}

impl StagedDocuments {
    pub(crate) fn empty(disk: &Arc<ScratchDisk>, tenant: &str, incarnation: &str) -> Result<Self> {
        kasumi_types::validate_name(incarnation)?;
        let scope = Scope::new(tenant, incarnation)?;
        let metadata = disk.memory().clone().reserve_installed(FLOOR)?;
        Ok(Self {
            tables: Arc::new(Tables {
                backing: None,
                disk: disk.clone(),
                scope,
                _metadata: metadata,
            }),
            has_bodies: false,
            published: None,
        })
    }

    /// Whether this reopened snapshot reads the objects it did not stage from
    /// its store's published rows.
    pub(crate) fn reads_published(&self) -> bool {
        self.published.is_some()
    }

    /// One object this snapshot names: its staged copy, or the published row
    /// a reopened snapshot found with the same bytes. `None` if it names no
    /// such object. A published row is bounded by the object's own length.
    fn object(&self, body: bool, digest: [u8; 32], bytes: usize) -> Result<Option<ObjectBytes>> {
        let key = self.tables.scope.key(digest);
        let Some(backing) = &self.tables.backing else {
            return Ok(None);
        };
        let table = if body {
            &backing.bodies
        } else {
            &backing.blobs
        };
        if let Some(published) = &self.published {
            match published.names(body).is_staged(table, &digest)? {
                None => return Ok(None),
                Some(false) => {
                    let namespace = if body { BODIES } else { BLOBS };
                    return Ok(published
                        .store
                        .get_bounded(namespace, &key, bytes)?
                        .map(ObjectBytes::Published));
                }
                Some(true) => {}
            }
        }
        Ok(table.get(&key)?.map(ObjectBytes::Staged))
    }

    fn read_grant(&self, bytes: u64) -> Result<DiskMemoryLease> {
        ReadAdmissionFailure::reserve(self.tables.disk.memory(), bytes)
    }

    /// Explicit physical ownership in this immutable authenticated bootstrap
    /// materialization. Presence with malformed/different metadata is an error;
    /// only true absence may select another generation-owned backing.
    pub(crate) fn contains(&self, descriptor: &StoredDocument) -> Result<bool> {
        descriptor.validate()?;
        let limits = limits(usize::try_from(descriptor.body_bytes)?)?;
        let expected = usize::try_from(descriptor.body_object_bytes)?;
        ensure!(
            expected > 0 && expected <= limits.manifest_bytes,
            "staged document manifest exceeds bound"
        );
        if !self.has_bodies {
            return Ok(false);
        }
        let _lookup = self.read_grant(FLOOR)?;
        let Some(wire) = self.object(true, descriptor.body_object, expected)? else {
            return Ok(false);
        };
        let wire = wire.as_ref();
        ensure!(
            wire.len() == expected
                && <[u8; 32]>::from(Sha256::digest(wire)) == descriptor.body_object,
            "staged document membership manifest identity differs"
        );
        let work = crate::snapshot_codec::inspect_external_json_work(wire, &mut || Ok(()))?;
        ensure!(
            work == descriptor.body_manifest_work,
            "staged document manifest workspace differs"
        );
        let _decode = self.read_grant(work)?;
        let manifest = BodyManifest::from_bytes(wire, limits)?;
        ensure!(
            manifest.canonical_bytes == descriptor.body_bytes
                && manifest.canonical_sha256 == descriptor.body_sha256,
            "staged document membership logical identity differs"
        );
        Ok(true)
    }

    /// Each published object namespace, its staged table and its row bound.
    fn namespaces(&self) -> [(&'static str, Option<&EncryptedTable>, usize); 2] {
        [
            (
                BODIES,
                self.tables.backing.as_ref().map(|backing| &backing.bodies),
                MAX_OBJECT_BYTES,
            ),
            (
                BLOBS,
                self.tables.backing.as_ref().map(|backing| &backing.blobs),
                BLOB_CHUNK_BYTES,
            ),
        ]
    }

    /// Before an install publishes its snapshot, write each snapshot object
    /// the store lacks, in bounded batches, deleting nothing. Object rows are
    /// content-addressed: the generation still serving names none of the new
    /// rows and keeps every row it does name, so a failure before publication
    /// leaves the previous snapshot whole.
    pub(crate) fn write_missing(&self, store: &Arc<TenantStore>) -> Result<()> {
        for (namespace, table, _) in self.namespaces() {
            if let Some(table) = table {
                Correction::new(store, self.tables.disk.memory(), namespace)?
                    .write_missing(table)?;
            }
        }
        Ok(())
    }

    /// Bring each published namespace to the snapshot's exact object set in
    /// bounded batches, never in one complete replacement, whose staging grows
    /// with every object the tenant ever wrote until it exceeds the native
    /// transaction cap. Object rows are content-addressed, no apply deletes
    /// them and the online collector deletes none its selected snapshot
    /// names: a reopening replica holds every object its own snapshot names,
    /// plus objects that only later or superseded documents name; an
    /// installing one holds the snapshot's objects `write_missing` wrote and
    /// every object of the state it replaced. Rows the snapshot lacks are
    /// deleted (replay rewrites each object a later entry names), then missing
    /// objects are written. This must finish before any restore selection
    /// captures the store: replay and later applies check object presence
    /// against that selection.
    pub(crate) fn reconcile(&self, store: &Arc<TenantStore>) -> Result<()> {
        self.clear_chunk_owners(store)?;
        if let Some(published) = &self.published {
            return self.reconcile_published(store, published);
        }
        let memory = self.tables.disk.memory();
        for (namespace, table, max_bytes) in self.namespaces() {
            let mut correction = Correction::new(store, memory, namespace)?;
            let mut kept = 0u64;
            // The view keeps its selected root while earlier batches commit.
            let view = store.read_view()?;
            view.visit(namespace, max_bytes, |key, value| {
                if let Some(table) = table {
                    let _lookup = self.read_grant(FLOOR)?;
                    if table
                        .get(key)?
                        .is_some_and(|staged| staged.as_bytes() == value)
                    {
                        kept += 1;
                        return Ok(());
                    }
                }
                correction.delete(key)
            })?;
            view.close()?;
            correction.flush()?;
            let Some(table) = table else { continue };
            let mut staged = 0u64;
            visit_objects(table, |_, _| {
                staged += 1;
                Ok(())
            })?;
            // Every kept row is one distinct staged object.
            if kept != staged {
                correction.write_missing(table)?;
            }
        }
        Ok(())
    }

    /// The collector's chunk owner counts describe the object rows this
    /// restore replaces: none survives it. The collector counts the restored
    /// manifests again before it collects any chunk.
    fn clear_chunk_owners(&self, store: &Arc<TenantStore>) -> Result<()> {
        let mut correction =
            Correction::new(store, self.tables.disk.memory(), crate::document_gc::LINKS)?;
        crate::document_gc::clear_links(store, |key| correction.delete(key))?;
        correction.flush()
    }

    /// A reopened snapshot's reconciliation. Its store already holds every
    /// object it names with the same bytes, except the objects decoding
    /// staged: delete each row it does not name, then write the staged ones.
    /// A named row that changed since decoding fails instead of being kept.
    fn reconcile_published(&self, store: &Arc<TenantStore>, published: &Published) -> Result<()> {
        ensure!(
            Arc::ptr_eq(store, &published.store),
            "reopened documents belong to another store"
        );
        let memory = self.tables.disk.memory();
        let scope = self.tables.scope.key([0; 32]);
        for (namespace, table, max_bytes) in self.namespaces() {
            let names = published.names(namespace == BODIES);
            let counts = names.counts();
            let table = table.context("reopened document staging table missing")?;
            let mut correction = Correction::new(store, memory, namespace)?;
            let mut held = 0usize;
            let view = store.read_view()?;
            view.visit(namespace, max_bytes, |key, value| {
                if let Some(digest) = scoped_digest(&scope, key)
                    && let Some(staged) = names.is_staged(table, &digest)?
                {
                    if !staged {
                        ensure!(
                            <[u8; 32]>::from(Sha256::digest(value)) == digest,
                            "reopened document object changed after decoding"
                        );
                        held += 1;
                    }
                    return Ok(());
                }
                correction.delete(key)
            })?;
            view.close()?;
            // Every named object decoding did not stage is still published.
            ensure!(
                held == counts.held,
                "reopened document object disappeared after decoding"
            );
            correction.flush()?;
            // Rewrites a named row held with other bytes, and writes a
            // missing one.
            if counts.staged != 0 {
                correction.write_missing(table)?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn object_counts(&self) -> Result<(u64, u64)> {
        let Some(backing) = &self.tables.backing else {
            return Ok((0, 0));
        };
        let mut bodies = 0u64;
        visit_objects(&backing.bodies, |_, _| {
            bodies += 1;
            Ok(())
        })?;
        let mut blobs = 0u64;
        visit_objects(&backing.blobs, |_, _| {
            blobs += 1;
            Ok(())
        })?;
        Ok((bodies, blobs))
    }

    #[cfg(test)]
    pub(crate) fn object_value_bytes(&self) -> Result<(u64, u64)> {
        let Some(backing) = &self.tables.backing else {
            return Ok((0, 0));
        };
        let mut bodies = 0u64;
        visit_objects(&backing.bodies, |_, value| {
            bodies = bodies
                .checked_add(value.len() as u64)
                .context("body byte count overflow")?;
            Ok(())
        })?;
        let mut blobs = 0u64;
        visit_objects(&backing.blobs, |_, value| {
            blobs = blobs
                .checked_add(value.len() as u64)
                .context("blob byte count overflow")?;
            Ok(())
        })?;
        Ok((bodies, blobs))
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_blob_for_test(&self) -> Result<()> {
        let backing = self
            .tables
            .backing
            .as_ref()
            .context("staged fixture has no proof blob")?;
        let mut first = None;
        visit_objects(&backing.blobs, |key, value| {
            if first.is_none() {
                first = Some((key.to_vec(), value.to_vec()));
            }
            Ok(())
        })?;
        let (key, mut bytes) = first.context("staged fixture has no proof blob")?;
        bytes[0] ^= 1;
        backing.blobs.set(&key, &bytes)
    }
}

/// A generation's two explicit immutable backing owners during bootstrap
/// reconstruction. Authenticated bootstrap objects remain in encrypted scratch;
/// later committed objects live in this exact selected native generation.
/// This never retries corruption against another source or opens latest state.
pub(crate) struct BootstrapDocuments {
    bootstrap: StagedDocuments,
    selected: crate::document_store::SelectedDocuments,
}
impl BootstrapDocuments {
    pub(crate) fn new(
        bootstrap: StagedDocuments,
        roots: crate::application_sources::SourceRootsRef,
        selected: crate::application_sources::SelectedApplication,
        tenant: &str,
        incarnation: &str,
    ) -> Result<Self> {
        ensure!(
            bootstrap.tables.scope == Scope::new(tenant, incarnation)?,
            "bootstrap document scope differs from selected generation"
        );
        let actual: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            roots.primary_installation().1.memory().clone();
        ensure!(
            Arc::ptr_eq(bootstrap.tables.disk.memory(), &actual),
            "bootstrap documents and selected source memory owners differ"
        );
        Ok(Self {
            bootstrap,
            selected: crate::document_store::SelectedDocuments::new(
                roots,
                selected,
                tenant,
                incarnation,
            )?,
        })
    }
}
impl DocumentResolver for BootstrapDocuments {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        if !self.bootstrap.has_bodies {
            // The selected resolver already retains and checks its exact
            // source. An empty bootstrap contributes neither a body lookup
            // nor a second reader around that native load.
            return self.selected.load(descriptor);
        }
        self.selected.with_source(|| {
            if self.bootstrap.contains(descriptor)? {
                self.bootstrap.load(descriptor)
            } else {
                self.selected.load(descriptor)
            }
        })
    }
}
impl GenerationDocuments for BootstrapDocuments {
    fn shared_read(&self) -> Result<Option<Box<dyn SharedRead>>> {
        let selected = self.selected.shared_reader();
        Ok(Some(if self.bootstrap.has_bodies {
            Box::new(BootstrapRead {
                bootstrap: self.bootstrap.clone(),
                selected,
            })
        } else {
            Box::new(selected)
        }))
    }
}

/// `BootstrapDocuments` for one bounded read: both the native lookups and the
/// access checks around staged bootstrap bodies use one shared selected view.
struct BootstrapRead {
    bootstrap: StagedDocuments,
    selected: SelectedRead,
}
impl DocumentResolver for BootstrapRead {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        self.selected.with_source(|| {
            if self.bootstrap.contains(descriptor)? {
                self.bootstrap.load(descriptor)
            } else {
                self.selected.load(descriptor)
            }
        })
    }
}
impl SharedRead for BootstrapRead {
    fn selected(&self) -> &SelectedRead {
        &self.selected
    }
    fn finish(self: Box<Self>) -> Result<()> {
        SharedRead::finish(Box::new(self.selected))
    }
}

struct DecodedOwner {
    document: Document,
    _decode: DiskMemoryLease,
}
impl AdmittedDocumentOwner for DecodedOwner {
    fn document(&self) -> &Document {
        &self.document
    }
}

impl DocumentResolver for StagedDocuments {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        self.load_checked(descriptor, &|| Ok(()))
    }
}

/// Borrowed only by an unpublished verification pass. The callback never
/// becomes part of the installed generation or its committed apply path.
pub(crate) struct CheckedDocuments<'a> {
    documents: &'a StagedDocuments,
    check: &'a (dyn Fn() -> Result<()> + Send + Sync),
}
impl DocumentResolver for CheckedDocuments<'_> {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
        self.documents.load_checked(descriptor, self.check)
    }
}
impl StagedDocuments {
    pub(crate) fn checked<'a>(
        &'a self,
        check: &'a (dyn Fn() -> Result<()> + Send + Sync),
    ) -> CheckedDocuments<'a> {
        CheckedDocuments {
            documents: self,
            check,
        }
    }

    fn load_checked(
        &self,
        descriptor: &StoredDocument,
        check: &(dyn Fn() -> Result<()> + Send + Sync),
    ) -> Result<SharedDocument> {
        check()?;
        descriptor.validate()?;
        let limits = limits(usize::try_from(descriptor.body_bytes)?)?;
        let manifest_bytes = usize::try_from(descriptor.body_object_bytes)?;
        ensure!(
            manifest_bytes > 0 && manifest_bytes <= limits.manifest_bytes,
            "staged document manifest exceeds bound"
        );
        let wire_bytes = descriptor
            .body_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(descriptor.body_object_bytes.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(FLOOR))
            .context("staged document wire workspace overflow")?;
        let wire_grant = self.read_grant(wire_bytes)?;
        let manifest_wire = self
            .object(true, descriptor.body_object, manifest_bytes)?
            .context("staged document manifest missing")?;
        ensure!(
            manifest_wire.as_ref().len() == manifest_bytes
                && <[u8; 32]>::from(Sha256::digest(manifest_wire.as_ref()))
                    == descriptor.body_object,
            "staged document manifest identity differs"
        );
        let manifest_work =
            crate::snapshot_codec::inspect_external_json_work(manifest_wire.as_ref(), &mut || {
                check()
            })?;
        ensure!(
            manifest_work == descriptor.body_manifest_work,
            "staged document manifest workspace differs"
        );
        let manifest_grant = self.read_grant(manifest_work)?;
        let manifest = BodyManifest::from_bytes(manifest_wire.as_ref(), limits)?;
        ensure!(
            manifest.canonical_bytes == descriptor.body_bytes
                && manifest.canonical_sha256 == descriptor.body_sha256,
            "staged document logical identity differs"
        );
        let canonical = document_encoding::reconstruct_body(&manifest, limits, |reference| {
            check()?;
            let blob = self
                .object(false, reference.sha256, usize::try_from(reference.bytes)?)?
                .context("staged document proof chunk missing")?;
            check()?;
            Ok(blob)
        })?;
        let body_work =
            crate::snapshot_codec::inspect_external_json_work(&canonical, &mut || check())?;
        ensure!(
            body_work == descriptor.body_decode_work,
            "staged document body workspace differs"
        );
        let decoded_work = body_work
            .checked_add(
                (descriptor.id.len() as u64)
                    .checked_mul(2)
                    .context("staged document identity length overflow")?,
            )
            .and_then(|bytes| bytes.checked_add(4096))
            .context("staged document decode workspace overflow")?;
        let decode = self.read_grant(decoded_work)?;
        let document = Document {
            id: descriptor.id.clone(),
            version: descriptor.version,
            body: serde_json::from_slice(&canonical)?,
        };
        check()?;
        drop(canonical);
        drop(manifest);
        drop(manifest_wire);
        drop(manifest_grant);
        drop(wire_grant);
        Ok(SharedDocument::from_admitted_owner(Arc::new(
            DecodedOwner {
                document,
                _decode: decode,
            },
        )))
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;

    #[test]
    fn reopened_name_index_keeps_a_fixed_resident_prefix_across_native_batches() {
        let memory = kasumi_store::test_utils::TestDiskMemory::new(128 << 20, 4096);
        let scratch = crate::codec_fixture::ScratchScope::new(memory.clone()).unwrap();
        let table =
            EncryptedTable::new(&scratch.disk, 128 << 20, scratch.disk.native_cache_config())
                .unwrap();
        let mut batch = ObjectBatch::new();
        let mut names = Names::new(8);
        let digest = |id: usize| <[u8; 32]>::from(Sha256::digest(id.to_be_bytes()));
        let count = 2 * EncryptedTableBatch::MAX_INDEX_ENTRIES + 17;
        for i in 0..count {
            names
                .record(
                    &table,
                    &mut batch,
                    scratch.disk.memory(),
                    digest(i),
                    i % 2 == 0,
                )
                .unwrap();
        }
        batch.flush().unwrap();
        // Duplicate claims across committed transactions retain the original counts.
        for i in [0, 1, 7, 8, 512, count - 1] {
            names
                .record(
                    &table,
                    &mut batch,
                    scratch.disk.memory(),
                    digest(i),
                    i % 2 == 0,
                )
                .unwrap();
        }
        batch.flush().unwrap();
        assert_eq!(names.all.capacity(), 8);
        assert!(names.staged.capacity() <= 8);
        assert_eq!(names.counts().held, count / 2);
        assert_eq!(names.counts().staged, count.div_ceil(2));
        for i in 0..count {
            assert_eq!(
                names.is_staged(&table, &digest(i)).unwrap(),
                Some(i % 2 == 0)
            );
        }
        assert_eq!(names.is_staged(&table, &digest(count)).unwrap(), None);
        visit_objects(&table, |_, _| {
            anyhow::bail!("name reached object publication")
        })
        .unwrap();
        table.set(&digest(8), &[2]).unwrap();
        assert!(names.is_staged(&table, &digest(8)).is_err());
        assert!(visit_objects(&table, |_, _| Ok(())).is_err());
        drop(batch);
        drop(names);
        table.close().unwrap();
        drop(table);
        assert_eq!(scratch.disk.snapshot().live_files, 0);
    }

    #[test]
    fn restore_measurements_match_independent_descriptors_and_roundtrip_all_encodings() {
        use base64::Engine as _;

        let memory = kasumi_store::test_utils::TestDiskMemory::new(128 << 20, 128);
        let scratch = crate::codec_fixture::ScratchScope::new(memory).unwrap();
        let mut builder = Builder::new(&scratch.disk, 64 << 20, "tenant", "incarnation").unwrap();
        let bodies = [
            serde_json::Value::Null,
            serde_json::json!({
                "z": [null, true, false, -17, 1.25, {"quote\"": "雪\\\n\t"}],
                "a": {"nested": []},
            }),
            serde_json::json!({"proof": "a7".repeat(BLOB_CHUNK_BYTES + 1)}),
            serde_json::json!({"proof": "A7".repeat(BLOB_CHUNK_BYTES + 1)}),
            serde_json::json!({"proof": base64::engine::general_purpose::STANDARD.encode(
                (0..BLOB_CHUNK_BYTES + 1).map(|n| n as u8).collect::<Vec<_>>()
            )}),
            serde_json::json!({"text": "雪\"\\\n".repeat(16_384)}),
        ];
        let mut expected = Vec::new();
        for (ordinal, body) in bodies.into_iter().enumerate() {
            let document = Document {
                id: format!("identity-{ordinal}"),
                version: ordinal as u64 + 1,
                body,
            };
            let descriptor = builder.push(&document).unwrap();
            let canonical =
                serde_json::to_vec(&kasumi_types::CanonicalJsonValue(&document.body)).unwrap();
            let body_work =
                crate::snapshot_codec::inspect_external_json_work(&canonical, &mut || Ok(()))
                    .unwrap();
            let independent = StoredDocument::from_document(
                &document,
                descriptor.body_object,
                descriptor.body_object_bytes,
                body_work,
                descriptor.body_manifest_work,
            )
            .unwrap();
            assert_eq!(descriptor, independent, "body encoding {ordinal}");
            expected.push((descriptor, document));
        }
        let staged = builder.finish().unwrap();
        for (descriptor, document) in expected {
            assert_eq!(staged.load(&descriptor).unwrap().as_ref(), &document);
        }
        drop(staged);
        assert_eq!(scratch.disk.snapshot().live_files, 0);
    }

    #[test]
    fn empty_staged_membership_needs_no_table_read_or_workspace() {
        let memory = kasumi_store::test_utils::TestDiskMemory::new(128 << 20, 128);
        let scratch = crate::codec_fixture::ScratchScope::new(memory.clone()).unwrap();
        let before_empty = memory.snapshot();
        let files = scratch.disk.snapshot().live_files;
        let empty = StagedDocuments::empty(&scratch.disk, "tenant", "incarnation").unwrap();
        assert_eq!(scratch.disk.snapshot().live_files, files);
        assert_eq!(
            memory.snapshot().live_reservations,
            before_empty.live_reservations + 1,
            "only the scope/metadata owner is admitted"
        );
        assert_eq!(empty.object_counts().unwrap(), (0, 0));
        assert!(StagedDocuments::empty(&scratch.disk, "tenant", "").is_err());
        let mut builder = Builder::new(&scratch.disk, 64 << 20, "tenant", "incarnation").unwrap();
        let document = Document {
            id: "native-only".into(),
            version: 1,
            body: serde_json::json!({"value": 7}),
        };
        let descriptor = builder.push(&document).unwrap();
        let populated = builder.finish().unwrap();
        assert!(populated.has_bodies);
        assert!(populated.contains(&descriptor).unwrap());
        assert!(!empty.has_bodies);
        assert!(empty.load(&descriptor).is_err());
        let before = memory.snapshot();
        for _ in 0..1000 {
            assert!(!empty.contains(&descriptor).unwrap());
        }
        assert_eq!(memory.snapshot(), before, "not even a transient read grant");
        drop(populated);
        drop(empty);
        assert_eq!(scratch.disk.snapshot().live_files, 0);
    }

    #[test]
    fn cancelled_staged_load_stops_between_blob_reads_and_releases_its_work() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let memory = kasumi_store::test_utils::TestDiskMemory::new(128 << 20, 128);
        let scratch = crate::codec_fixture::ScratchScope::new(memory.clone()).unwrap();
        let mut builder = Builder::new(&scratch.disk, 64 << 20, "tenant", "incarnation").unwrap();
        let document = Document {
            id: "proof".into(),
            version: 1,
            body: serde_json::json!({"proof": "a7".repeat(4 * BLOB_CHUNK_BYTES)}),
        };
        let descriptor = builder.push(&document).unwrap();
        let staged = builder.finish().unwrap();
        assert_eq!(staged.load(&descriptor).unwrap().as_ref(), &document);
        let before = memory.snapshot();
        let token = kasumi_query::QueryCancellation::default();
        let checks = AtomicUsize::new(0);
        let check = || {
            // This small manifest occupies one meter slice: entry, manifest
            // slice/end, first blob before/after. Cancel with its actual read
            // loan still live, before reading any subsequent proof chunks.
            if checks.fetch_add(1, Ordering::Relaxed) == 4 {
                token.cancel();
            }
            token.check().map_err(Into::into)
        };
        let error = staged.checked(&check).load(&descriptor).err().unwrap();
        assert_eq!(checks.load(Ordering::Relaxed), 5);
        assert_eq!(
            error.downcast_ref::<kasumi_types::Error>().unwrap().code,
            kasumi_types::ErrorCode::ResourceExhausted
        );
        let after = memory.snapshot();
        assert_eq!(after.used_bytes, before.used_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
        assert_eq!(staged.load(&descriptor).unwrap().as_ref(), &document);
        drop(staged);
        assert_eq!(scratch.disk.snapshot().live_files, 0);
    }

    #[test]
    fn committed_object_dedup_keeps_exact_bytes_without_reopening_or_growing() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let memory = kasumi_store::test_utils::TestDiskMemory::new(128 << 20, 128);
        let disk = ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
        let table = EncryptedTable::new(&disk, 64 << 20, disk.native_cache_config()).unwrap();
        let mut batch = ObjectBatch::new();
        let first = [1; 64];
        let value = vec![41; BLOB_CHUNK_BYTES];
        batch.put(&table, disk.memory(), first, &value).unwrap();
        batch.flush().unwrap();
        assert_eq!(table.get(&first).unwrap().unwrap().as_bytes(), value);
        let before = memory.snapshot();
        for _ in 0..64 {
            batch.put(&table, disk.memory(), first, &value).unwrap();
            batch.flush().unwrap();
        }
        // Native point reads take their own memory leases, even when native
        // pages are cached. A repeated committed chunk takes neither a read
        // lease nor another retained copy; its first exact copy stays admitted.
        assert_eq!(memory.snapshot(), before);
        let mut collision = value.clone();
        collision[0] ^= 1;
        assert!(batch.put(&table, disk.memory(), first, &collision).is_err());
        assert_eq!(memory.snapshot(), before);

        for ordinal in 2..=EncryptedTableBatch::MAX_ENTRIES {
            batch
                .put(&table, disk.memory(), [ordinal as u8; 64], &value)
                .unwrap();
        }
        assert_eq!(batch.known.len(), EncryptedTableBatch::MAX_ENTRIES);
        assert!(batch.bytes <= EncryptedTableBatch::MAX_BYTES);
        // Evicting the duplicate-read cache keeps the transaction private.
        // Its own read view must still detect a duplicate or collision.
        batch.put(&table, disk.memory(), [99; 64], &value).unwrap();
        assert_eq!(batch.known.len(), 1);
        assert_eq!(batch.bytes, value.len() + first.len());
        assert!(table.get(&[2; 64]).unwrap().is_none());
        batch.put(&table, disk.memory(), [2; 64], &value).unwrap();
        assert!(
            batch
                .put(&table, disk.memory(), [2; 64], &collision)
                .is_err()
        );
        batch.flush().unwrap();
        for ordinal in 1..=EncryptedTableBatch::MAX_ENTRIES {
            assert_eq!(
                table.get(&[ordinal as u8; 64]).unwrap().unwrap().as_bytes(),
                value
            );
        }
        assert_eq!(table.get(&[99; 64]).unwrap().unwrap().as_bytes(), value);
        drop(batch);
        table.close().unwrap();
        assert_eq!(disk.snapshot().live_files, 0);
    }

    #[test]
    fn read_admission_failure_keeps_original_io_owner_and_exact_capacity_kind() {
        #[derive(Debug)]
        struct Original;
        impl std::fmt::Display for Original {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("original admission observation")
            }
        }
        impl std::error::Error for Original {}

        for kind in [
            std::io::ErrorKind::OutOfMemory,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Other,
        ] {
            let original = std::io::Error::new(kind, Original);
            let address = std::ptr::from_ref(
                original
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Original>()
                    .unwrap(),
            );
            let failure = ReadAdmissionFailure { original };
            assert_eq!(
                failure.is_capacity_denied(),
                kind == std::io::ErrorKind::OutOfMemory
            );
            let source = std::error::Error::source(&failure)
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(source.kind(), kind);
            assert_eq!(
                std::ptr::from_ref(
                    source
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<Original>()
                        .unwrap()
                ),
                address
            );
        }
    }

    #[test]
    fn read_admission_classification_survives_io_wrapping() {
        use kasumi_types::ErrorCode;

        for kind in [
            std::io::ErrorKind::OutOfMemory,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Other,
        ] {
            for wrapped in [false, true] {
                for classify in [
                    crate::service::document_load_error,
                    crate::state::snapshot_encoding_failure::encoding_error,
                ] {
                    let failure = ReadAdmissionFailure {
                        original: kind.into(),
                    };
                    let error = if wrapped {
                        anyhow::Error::new(std::io::Error::other(failure))
                    } else {
                        anyhow::Error::new(failure)
                    };
                    let expected = if kind == std::io::ErrorKind::OutOfMemory {
                        ErrorCode::ResourceExhausted
                    } else {
                        ErrorCode::Unavailable
                    };
                    assert_eq!(classify(error.context("staged body read")).code, expected);
                }
            }
        }
    }

    #[test]
    fn restore_slice_bounds_actual_manifest_and_dense_body_decode_work() {
        let bodies = [
            serde_json::Value::Null,
            serde_json::json!({"escaped": "line\"\\\n".repeat(8192)}),
            serde_json::json!({"sites": vec![0; 8192]}),
            serde_json::json!({"proof": "a7".repeat(256 << 10)}),
            serde_json::Value::Array(
                (0..64)
                    .map(|_| serde_json::json!("x".repeat(4096)))
                    .collect(),
            ),
        ];
        for body in bodies {
            let document = Document {
                id: "bounded-document".into(),
                version: 17,
                body,
            };
            let body_bytes =
                crate::accounting::encoded_len(&kasumi_types::CanonicalJsonValue(&document.body))
                    .unwrap();
            let limits = limits(body_bytes).unwrap();
            let (_, wire) =
                document_encoding::encode_body(&document.body, limits, |_| Ok(())).unwrap();
            let manifest_work =
                crate::snapshot_codec::inspect_external_json_work(&wire, &mut || Ok(())).unwrap();
            let body_work = crate::snapshot_codec::inspect_typed_json_work(
                &kasumi_types::CanonicalJsonValue(&document.body),
            )
            .unwrap();
            let token =
                crate::admission::MemoryCore::required_installed_reservation_bytes(0).unwrap();
            let actual_read = 2 * body_bytes as u64
                + 2 * wire.len() as u64
                + FLOOR
                + manifest_work
                + body_work
                + 2 * document.id.len() as u64
                + 4096
                + 3 * token;
            let record_bytes = crate::accounting::encoded_len(&document).unwrap() as u64;
            let record_work = crate::snapshot_codec::inspect_typed_json_work(&document).unwrap();
            assert!(workspace(record_bytes, record_work).unwrap() >= actual_read);
        }
    }
}
