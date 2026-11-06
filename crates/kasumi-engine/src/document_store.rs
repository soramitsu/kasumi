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
use kasumi_store::WriteOp;
use kasumi_types::{
    AdmittedDocumentOwner, Document, DocumentResolver, SharedDocument, StoredDocument,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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
/// body pass supplies its size, work and independent hash; one document pass
/// supplies its complete size and work. Neither retains another payload copy.
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
        let (body_bytes, body_work) = crate::snapshot_codec::measure_typed_json(
            &kasumi_types::CanonicalJsonValue(&document.body),
            |bytes| digest.update(bytes),
        )?;
        let limits = limits(usize::try_from(body_bytes)?)?;
        let (document_bytes, document_work) =
            crate::snapshot_codec::measure_typed_json(document, |_| {})?;
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
        wire: &[u8],
    ) -> Result<StoredDocument> {
        // encode_body independently hashes its emitted canonical spelling.
        // Never substitute a manifest's declared identity for input validation.
        ensure!(
            self.body_bytes == manifest.canonical_bytes
                && self.body_sha256 == manifest.canonical_sha256,
            "document encoding differs from canonical body"
        );
        let descriptor = StoredDocument {
            id: self.document.id.clone(),
            version: self.document.version,
            body_bytes: self.body_bytes,
            document_bytes: self.document_bytes,
            body_sha256: self.body_sha256,
            body_object: Sha256::digest(wire).into(),
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

pub(crate) fn source_workspace(slot: &kasumi_types::DocumentSlot) -> Result<u64> {
    match slot {
        kasumi_types::DocumentSlot::Pending(document) => {
            crate::snapshot_codec::inspect_typed_json_work(document)
        }
        kasumi_types::DocumentSlot::Stored(document) => {
            document.validate()?;
            document
                .body_bytes
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(document.body_object_bytes.checked_mul(4)?))
                .and_then(|bytes| bytes.checked_add(document.body_manifest_work))
                .and_then(|bytes| bytes.checked_add(document.body_decode_work))
                .and_then(|bytes| bytes.checked_add((document.id.len() as u64).checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(FLOOR + 4096))
                .context("document source workspace overflow")
        }
    }
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
        })
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
        let manifest =
            document_encoding::encode_body(&document.body, limits, |reference, bytes| {
                self.put(false, reference.sha256, bytes, work)
            })?;
        let wire = manifest.to_bytes(limits)?;
        let descriptor = measured.descriptor(&manifest, &wire)?;
        self.put(true, descriptor.body_object, &wire, work)?;
        drop(wire);
        drop(manifest);
        self.reservation.retain(self.retained);
        Ok(descriptor)
    }
    fn put(&mut self, body: bool, digest: [u8; 32], bytes: &[u8], work: u64) -> Result<()> {
        ensure!(
            Sha256::digest(bytes).as_slice() == digest,
            "document object digest differs"
        );
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
        let exists = self.reader.with_record(
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
}

/// One bounded read's loans through a single exact selected source view,
/// opened by its first load. Each load still admits its own decode workspace
/// and rechecks key access before lending its document. `finish` retires the
/// view and fails if the view failed or key access ended.
pub(crate) trait SharedRead: DocumentResolver {
    fn finish(self: Box<Self>) -> Result<()>;
}

/// Each operation borrows the exact selected native source. It never opens
/// latest and releases its native loan before returning an admitted body.
#[derive(Clone)]
pub(crate) struct SelectedDocuments {
    selected: SelectedApplication,
    roots: SourceRootsRef,
    scope: Scope,
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
        })
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
}
impl GenerationDocuments for SelectedDocuments {
    fn shared_read(&self) -> Result<Option<Box<dyn SharedRead>>> {
        Ok(Some(Box::new(self.shared_reader())))
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
}
impl SelectedRead {
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

    /// `SelectedDocuments::with_source` through the shared view.
    pub(crate) fn with_source<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.with_reader(|reader| reader.check_access())?;
        let result = read();
        checked_completion(result, self.with_reader(|reader| reader.check_access()))
    }
}
impl DocumentResolver for SelectedRead {
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
    fn finish(self: Box<Self>) -> Result<()> {
        match self.reader.into_inner().unwrap_or_else(|p| p.into_inner()) {
            Some(reader) => reader.close(),
            None => Ok(()),
        }
    }
}
