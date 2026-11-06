//! One-row-at-a-time logical snapshot materialization into encrypted bodies.
//! Scratch tables are unpublished and private until the complete snapshot is
//! verified; its restore then brings both published object namespaces to the
//! snapshot's objects in bounded batches. A reopening replica's own snapshot
//! names objects its store already published: decoding compares each with
//! that row and stages only an object the store lacks or holds otherwise.
use crate::{
    document_encoding::{self, BLOB_CHUNK_BYTES, BodyManifest},
    document_store::{BLOBS, BODIES, DocumentMeasurement, Scope, limits},
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

/// Only read-side decode admission constructs this error. Keep its original
/// provider observation separate from native I/O and retirement failures.
#[derive(Debug)]
pub(crate) struct ReadAdmissionFailure {
    original: std::io::Error,
}
impl ReadAdmissionFailure {
    pub(crate) fn is_capacity_denied(&self) -> bool {
        self.original.kind() == std::io::ErrorKind::OutOfMemory
    }
}
impl std::fmt::Display for ReadAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("staged document read admission failed")
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
    max_table_bytes: u64,
    // LAST: table handles and their backing retire before this owner's credit.
    _metadata: DiskMemoryLease,
}

/// Immutable after the builder has been consumed. Clones share encrypted
/// backing, never a map of decoded payloads. Only a reopened snapshot keeps
/// the sorted digests of the objects it names, until its publication.
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
    documents_since_flush: usize,
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
    // LAST: the buffers retire before the credit that admitted them.
    grant: Option<DiskMemoryLease>,
}
impl Names {
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
                self.all.capacity().saturating_mul(2).max(NAMES_GROWTH)
            } else {
                self.all.capacity()
            };
            let staged = if grow_staged {
                self.staged.capacity().saturating_mul(2).max(16)
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
    fn names(&self, digest: &[u8; 32]) -> bool {
        self.all.binary_search(digest).is_ok()
    }
    fn staged(&self, digest: &[u8; 32]) -> bool {
        self.staged.binary_search(digest).is_ok()
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
    /// Record `digest` as named, and whether the store already holds exactly
    /// `bytes` under its key. A row with other bytes is replaced by the
    /// staged copy when the restore publishes.
    fn holds(
        &mut self,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
        body: bool,
        digest: [u8; 32],
        key: &[u8; 64],
        bytes: &[u8],
    ) -> Result<bool> {
        let held = if self.recent.contains(&Some((body, digest))) {
            true
        } else {
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
            held
        };
        let names = if body {
            &mut self.published.bodies
        } else {
            &mut self.published.blobs
        };
        names.push(memory, digest, !held)?;
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
        if let Some(previous) = table.get(&key)? {
            ensure!(
                previous.as_bytes() == bytes,
                "document restore content-address collision"
            );
            return Ok(());
        }
        let row_bytes = key
            .len()
            .checked_add(bytes.len())
            .context("document staging batch overflow")?;
        if self.known.len() == EncryptedTableBatch::MAX_ENTRIES
            || self
                .bytes
                .checked_add(row_bytes)
                .is_none_or(|total| total > EncryptedTableBatch::MAX_BYTES)
        {
            self.flush()?;
            // A cache eviction may include uncommitted originals. Publish the
            // complete native batch before releasing any of their backing.
            self.known.clear();
            self.bytes = 0;
        }
        // The existing native single-row corridor accepts large manifests up
        // to its 32 MiB row cap; do not increase the bounded batch cap for one.
        if row_bytes > EncryptedTableBatch::MAX_BYTES {
            return table.insert(&key, bytes);
        }
        let retained = (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|value| value.checked_add(2048))
            .context("document pending row overflow")?;
        let grant = memory.clone().reserve_document_decode(retained)?;
        if self.batch.is_none() {
            self.batch = Some(table.begin_batch()?);
        }
        self.batch
            .as_mut()
            .expect("opened object batch")
            .insert(&key, bytes)?;
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
            documents_since_flush: 0,
            has_bodies: false,
            tables: Arc::new(Tables {
                backing: Some(TableBacking { bodies, blobs }),
                disk: disk.clone(),
                scope,
                max_table_bytes,
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
                bodies: Names::default(),
                blobs: Names::default(),
            },
            view: store.read_view()?,
            recent: [None; RECENT],
            next: 0,
        });
        Ok(())
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
        let manifest =
            document_encoding::encode_body(&document.body, limits, |reference, bytes| {
                self.put(false, reference.sha256, bytes)
            })?;
        let wire = manifest.to_bytes(limits)?;
        let descriptor = measured.descriptor(&manifest, &wire)?;
        self.put(true, descriptor.body_object, &wire)?;
        self.documents_since_flush += 1;
        if self.documents_since_flush == EncryptedTableBatch::MAX_ENTRIES / 2 {
            self.bodies.flush()?;
            self.blobs.flush()?;
            self.documents_since_flush = 0;
        }
        self.failed = false;
        Ok(descriptor)
    }

    fn put(&mut self, body: bool, digest: [u8; 32], bytes: &[u8]) -> Result<()> {
        ensure!(
            <[u8; 32]>::from(Sha256::digest(bytes)) == digest,
            "document restore object digest differs"
        );
        let key = self.tables.scope.key(digest);
        if let Some(comparing) = &mut self.comparing
            && comparing.holds(self.tables.disk.memory(), body, digest, &key, bytes)?
        {
            self.has_bodies |= body;
            return Ok(());
        }
        let backing = self.tables.backing.as_ref().expect("builder table backing");
        let (table, batch) = if body {
            (&backing.bodies, &mut self.bodies)
        } else {
            (&backing.blobs, &mut self.blobs)
        };
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
        table.visit(|key, value| {
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
    pub(crate) fn empty(
        disk: &Arc<ScratchDisk>,
        max_table_bytes: u64,
        tenant: &str,
        incarnation: &str,
    ) -> Result<Self> {
        kasumi_types::validate_name(incarnation)?;
        let scope = Scope::new(tenant, incarnation)?;
        let metadata = disk.memory().clone().reserve_installed(FLOOR)?;
        Ok(Self {
            tables: Arc::new(Tables {
                backing: None,
                disk: disk.clone(),
                scope,
                max_table_bytes,
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
        if let Some(published) = &self.published {
            let names = published.names(body);
            if !names.names(&digest) {
                return Ok(None);
            }
            if !names.staged(&digest) {
                let namespace = if body { BODIES } else { BLOBS };
                return Ok(published
                    .store
                    .get_bounded(namespace, &key, bytes)?
                    .map(ObjectBytes::Published));
            }
        }
        let Some(backing) = &self.tables.backing else {
            return Ok(None);
        };
        let table = if body {
            &backing.bodies
        } else {
            &backing.blobs
        };
        Ok(table.get(&key)?.map(ObjectBytes::Staged))
    }

    fn read_grant(&self, bytes: u64) -> Result<DiskMemoryLease> {
        self.tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(bytes)
            .map_err(|original| anyhow::Error::new(ReadAdmissionFailure { original }))
    }

    /// Rebind a verified logical restore to its explicitly selected new
    /// incarnation. Copy authenticated immutable objects without decoding JSON,
    /// preserving the original per-table cap and exact disk/memory governor.
    pub(crate) fn rebind_scope(
        &self,
        tenant: &str,
        incarnation: &str,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        let target_scope =
            kasumi_store::ScratchOperationFailure::ordinary(|| Scope::new(tenant, incarnation))?;
        if target_scope == self.tables.scope {
            return Ok(self.clone());
        }
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            ensure!(
                self.published.is_none(),
                "a reopened snapshot keeps its own document scope"
            );
            Ok(())
        })?;
        let Some(backing) = &self.tables.backing else {
            return Ok(Self::empty(
                &self.tables.disk,
                self.tables.max_table_bytes,
                tenant,
                incarnation,
            )?);
        };
        let mut builder = Builder::new(
            &self.tables.disk,
            self.tables.max_table_bytes,
            tenant,
            incarnation,
        )?;
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let source_prefix = self.tables.scope.key([0; 32]);
            for (body, table) in [(true, &backing.bodies), (false, &backing.blobs)] {
                let mut since_flush = 0;
                table.visit(|key, value| {
                    ensure!(
                        key.len() == 64 && key[..32] == source_prefix[..32],
                        "restored document object scope differs"
                    );
                    let digest = key[32..].try_into().expect("checked object key width");
                    // put authenticates the exact original value against its digest
                    // and admits each bounded pending copy before allocation.
                    builder.put(body, digest, value)?;
                    since_flush += 1;
                    if since_flush == EncryptedTableBatch::MAX_ENTRIES / 2 {
                        if body {
                            builder.bodies.flush()?;
                        } else {
                            builder.blobs.flush()?;
                        }
                        since_flush = 0;
                    }
                    Ok(())
                })?;
            }
            builder.finish()
        })
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

    /// The one complete replacement of both namespaces that a restore once
    /// published with its snapshot commitment. Its staging grows with every
    /// object the tenant holds; tests show it exceeding the native cap.
    #[cfg(test)]
    pub(crate) fn complete_snapshot_replacements(
        &self,
    ) -> [kasumi_store::NamespaceReplacement<'_>; 2] {
        match &self.tables.backing {
            Some(backing) => [
                kasumi_store::NamespaceReplacement::from_table(BODIES, &backing.bodies),
                kasumi_store::NamespaceReplacement::from_table(BLOBS, &backing.blobs),
            ],
            None => [
                kasumi_store::NamespaceReplacement::empty(BODIES),
                kasumi_store::NamespaceReplacement::empty(BLOBS),
            ],
        }
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
    /// transaction cap. Object rows are content-addressed and no apply deletes
    /// them: a reopening replica holds every object its own snapshot names,
    /// plus objects that only later or superseded documents name; an
    /// installing one holds the snapshot's objects `write_missing` wrote and
    /// every object of the state it replaced. Rows the snapshot lacks are
    /// deleted (replay rewrites each object a later entry names), then missing
    /// objects are written. This must finish before any restore selection
    /// captures the store: replay and later applies check object presence
    /// against that selection.
    pub(crate) fn reconcile(&self, store: &Arc<TenantStore>) -> Result<()> {
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
            table.visit(|_, _| {
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
            let mut correction = Correction::new(store, memory, namespace)?;
            let mut held = 0usize;
            let view = store.read_view()?;
            view.visit(namespace, max_bytes, |key, value| {
                if let Some(digest) = scoped_digest(&scope, key)
                    && names.names(&digest)
                {
                    if !names.staged(&digest) {
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
                held == names.all.len() - names.staged.len(),
                "reopened document object disappeared after decoding"
            );
            correction.flush()?;
            // Rewrites a named row held with other bytes, and writes a
            // missing one.
            if !names.staged.is_empty()
                && let Some(table) = table
            {
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
        backing.bodies.visit(|_, _| {
            bodies += 1;
            Ok(())
        })?;
        let mut blobs = 0u64;
        backing.blobs.visit(|_, _| {
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
        backing.bodies.visit(|_, value| {
            bodies = bodies
                .checked_add(value.len() as u64)
                .context("body byte count overflow")?;
            Ok(())
        })?;
        let mut blobs = 0u64;
        backing.blobs.visit(|_, value| {
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
        backing.blobs.visit(|key, value| {
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
        let empty =
            StagedDocuments::empty(&scratch.disk, 64 << 20, "tenant", "incarnation").unwrap();
        assert_eq!(scratch.disk.snapshot().live_files, files);
        assert_eq!(
            memory.snapshot().live_reservations,
            before_empty.live_reservations + 1,
            "only the scope/metadata owner is admitted"
        );
        assert_eq!(empty.object_counts().unwrap(), (0, 0));
        let rebound_empty = empty.rebind_scope("tenant", "empty-rebound").unwrap();
        assert_eq!(scratch.disk.snapshot().live_files, files);
        assert_eq!(rebound_empty.object_counts().unwrap(), (0, 0));
        assert!(empty.rebind_scope("tenant", "").is_err());
        drop(rebound_empty);
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
        let rebound = populated.rebind_scope("tenant", "rebound").unwrap();
        assert!(rebound.has_bodies);
        assert!(rebound.contains(&descriptor).unwrap());
        drop(rebound);
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
        // The next row evicts the cache while the previous fifteen writes are
        // still pending. Every one must become durable before its copy drops.
        batch.put(&table, disk.memory(), [99; 64], &value).unwrap();
        assert_eq!(batch.known.len(), 1);
        assert_eq!(batch.bytes, value.len() + first.len());
        for ordinal in 1..=EncryptedTableBatch::MAX_ENTRIES {
            assert_eq!(
                table.get(&[ordinal as u8; 64]).unwrap().unwrap().as_bytes(),
                value
            );
        }
        batch.flush().unwrap();
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
            let manifest =
                document_encoding::encode_body(&document.body, limits, |_, _| Ok(())).unwrap();
            let wire = manifest.to_bytes(limits).unwrap();
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
