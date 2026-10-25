//! One-row-at-a-time logical snapshot materialization into encrypted bodies.
//! Scratch tables are unpublished and private until the complete snapshot is
//! verified and its application/custody coordinator imports both namespaces.
use crate::{
    document_encoding::{self, BodyManifest},
    document_store::{BLOBS, BODIES, Scope, limits},
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    DiskMemoryLease, EncryptedTable, EncryptedTableBatch, NamespaceReplacement,
    NodeDiskMemoryAdmission, ScratchDisk,
};
use kasumi_types::{
    AdmittedDocumentOwner, Document, DocumentResolver, SharedDocument, StoredDocument,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const FLOOR: u64 = 64 << 10;

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

struct Tables {
    bodies: EncryptedTable,
    blobs: EncryptedTable,
    disk: Arc<ScratchDisk>,
    scope: Scope,
    max_table_bytes: u64,
    // LAST: table handles and their backing retire before this owner's credit.
    _metadata: DiskMemoryLease,
}

/// Immutable after the builder has been consumed. Clones share encrypted
/// backing, never a map of decoded payloads or a growing proof digest set.
#[derive(Clone)]
pub(crate) struct StagedDocuments {
    tables: Arc<Tables>,
}

pub(crate) struct Builder {
    bodies: ObjectBatch,
    blobs: ObjectBatch,
    documents_since_flush: usize,
    tables: Arc<Tables>,
    failed: bool,
}

struct PendingObject {
    key: [u8; 64],
    value: Vec<u8>,
    _memory: DiskMemoryLease,
}
struct ObjectBatch {
    batch: Option<EncryptedTableBatch>,
    // At most 16 exact pending originals, totaling at most 4 MiB per table.
    // Their copies have separate real charges through commit/abort retirement.
    pending: Vec<PendingObject>,
    bytes: usize,
}
impl ObjectBatch {
    fn new() -> Self {
        Self {
            batch: None,
            pending: Vec::with_capacity(EncryptedTableBatch::MAX_ENTRIES),
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
        if let Some(previous) = self.pending.iter().find(|row| row.key == key) {
            ensure!(
                previous.value.as_slice() == bytes,
                "pending document content-address collision"
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
        if self.pending.len() == EncryptedTableBatch::MAX_ENTRIES
            || self
                .bytes
                .checked_add(row_bytes)
                .is_none_or(|total| total > EncryptedTableBatch::MAX_BYTES)
        {
            self.flush()?;
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
        self.pending.push(PendingObject {
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
        self.pending.clear();
        self.bytes = 0;
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
            tables: Arc::new(Tables {
                bodies,
                blobs,
                disk: disk.clone(),
                scope,
                max_table_bytes,
                _metadata: metadata,
            }),
            failed: false,
        })
    }

    /// The caller already owns/admitted this single decoded snapshot record.
    /// A failed push permanently prevents this partial staging from finishing.
    pub(crate) fn push(&mut self, document: &Document) -> Result<StoredDocument> {
        ensure!(!self.failed, "document restore builder previously failed");
        self.failed = true;
        let bytes =
            crate::accounting::encoded_len(&kasumi_types::CanonicalJsonValue(&document.body))?;
        let limits = limits(bytes)?;
        let work = crate::snapshot_codec::inspect_typed_json_work(document)?
            .checked_add(
                (bytes as u64)
                    .checked_mul(8)
                    .context("document restore workspace overflow")?,
            )
            .and_then(|bytes| bytes.checked_add(1 << 20))
            .context("document restore workspace overflow")?;
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
        let object = Sha256::digest(&wire).into();
        self.put(true, object, &wire)?;
        let descriptor = StoredDocument::from_document(
            document,
            object,
            wire.len() as u64,
            crate::snapshot_codec::inspect_typed_json_work(&kasumi_types::CanonicalJsonValue(
                &document.body,
            ))?,
            crate::snapshot_codec::inspect_external_json_work(&wire, &mut || Ok(()))?,
        )?;
        ensure!(
            descriptor.body_bytes == manifest.canonical_bytes
                && descriptor.body_sha256 == manifest.canonical_sha256,
            "document restore canonical identity differs"
        );
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
        let (table, batch) = if body {
            (&self.tables.bodies, &mut self.bodies)
        } else {
            (&self.tables.blobs, &mut self.blobs)
        };
        let key = self.tables.scope.key(digest);
        batch.put(table, self.tables.disk.memory(), key, bytes)
    }

    /// Call only after the enclosing authenticated snapshot stream has passed
    /// its count, order, digest and EOF checks. This does not publish live rows.
    pub(crate) fn finish(mut self) -> Result<StagedDocuments> {
        ensure!(!self.failed, "document restore builder previously failed");
        self.failed = true;
        self.bodies.flush()?;
        self.blobs.flush()?;
        Ok(StagedDocuments {
            tables: self.tables,
        })
    }
}

impl StagedDocuments {
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
        let mut builder = Builder::new(
            &self.tables.disk,
            self.tables.max_table_bytes,
            tenant,
            incarnation,
        )?;
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let source_prefix = self.tables.scope.key([0; 32]);
            for (body, table) in [(true, &self.tables.bodies), (false, &self.tables.blobs)] {
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
        let _lookup = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(FLOOR)?;
        let Some(wire) = self
            .tables
            .bodies
            .get(&self.tables.scope.key(descriptor.body_object))?
        else {
            return Ok(false);
        };
        ensure!(
            wire.len() == expected
                && <[u8; 32]>::from(Sha256::digest(wire.as_bytes())) == descriptor.body_object,
            "staged document membership manifest identity differs"
        );
        let work =
            crate::snapshot_codec::inspect_external_json_work(wire.as_bytes(), &mut || Ok(()))?;
        ensure!(
            work == descriptor.body_manifest_work,
            "staged document manifest workspace differs"
        );
        let _decode = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(work)?;
        let manifest = BodyManifest::from_bytes(wire.as_bytes(), limits)?;
        ensure!(
            manifest.canonical_bytes == descriptor.body_bytes
                && manifest.canonical_sha256 == descriptor.body_sha256,
            "staged document membership logical identity differs"
        );
        Ok(true)
    }

    /// COMPLETE namespace replacements, never partial merge or garbage
    /// collection. The coordinator must include every logical current/feed
    /// descriptor from the verified snapshot, retain older selected views, and
    /// jointly publish these rows with the exact snapshot/custody commitment.
    pub(crate) fn complete_snapshot_replacements(&self) -> [NamespaceReplacement<'_>; 2] {
        [
            NamespaceReplacement::from_table(BODIES, &self.tables.bodies),
            NamespaceReplacement::from_table(BLOBS, &self.tables.blobs),
        ]
    }

    #[cfg(test)]
    pub(crate) fn object_counts(&self) -> Result<(u64, u64)> {
        let mut bodies = 0u64;
        self.tables.bodies.visit(|_, _| {
            bodies += 1;
            Ok(())
        })?;
        let mut blobs = 0u64;
        self.tables.blobs.visit(|_, _| {
            blobs += 1;
            Ok(())
        })?;
        Ok((bodies, blobs))
    }

    #[cfg(test)]
    pub(crate) fn object_value_bytes(&self) -> Result<(u64, u64)> {
        let mut bodies = 0u64;
        self.tables.bodies.visit(|_, value| {
            bodies = bodies
                .checked_add(value.len() as u64)
                .context("body byte count overflow")?;
            Ok(())
        })?;
        let mut blobs = 0u64;
        self.tables.blobs.visit(|_, value| {
            blobs = blobs
                .checked_add(value.len() as u64)
                .context("blob byte count overflow")?;
            Ok(())
        })?;
        Ok((bodies, blobs))
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_blob_for_test(&self) -> Result<()> {
        let mut first = None;
        self.tables.blobs.visit(|key, value| {
            if first.is_none() {
                first = Some((key.to_vec(), value.to_vec()));
            }
            Ok(())
        })?;
        let (key, mut bytes) = first.context("staged fixture has no proof blob")?;
        bytes[0] ^= 1;
        self.tables.blobs.set(&key, &bytes)
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
        let wire_grant = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(wire_bytes)?;
        let manifest_wire = self
            .tables
            .bodies
            .get(&self.tables.scope.key(descriptor.body_object))?
            .context("staged document manifest missing")?;
        ensure!(
            manifest_wire.len() == manifest_bytes
                && <[u8; 32]>::from(Sha256::digest(manifest_wire.as_bytes()))
                    == descriptor.body_object,
            "staged document manifest identity differs"
        );
        let manifest_work = crate::snapshot_codec::inspect_external_json_work(
            manifest_wire.as_bytes(),
            &mut || Ok(()),
        )?;
        ensure!(
            manifest_work == descriptor.body_manifest_work,
            "staged document manifest workspace differs"
        );
        let manifest_grant = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(manifest_work)?;
        let manifest = BodyManifest::from_bytes(manifest_wire.as_bytes(), limits)?;
        ensure!(
            manifest.canonical_bytes == descriptor.body_bytes
                && manifest.canonical_sha256 == descriptor.body_sha256,
            "staged document logical identity differs"
        );
        let canonical = document_encoding::reconstruct_body(&manifest, limits, |reference| {
            self.tables
                .blobs
                .get(&self.tables.scope.key(reference.sha256))?
                .context("staged document proof chunk missing")
        })?;
        let body_work =
            crate::snapshot_codec::inspect_external_json_work(&canonical, &mut || Ok(()))?;
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
        let decode = self
            .tables
            .disk
            .memory()
            .clone()
            .reserve_document_decode(decoded_work)?;
        let document = Document {
            id: descriptor.id.clone(),
            version: descriptor.version,
            body: serde_json::from_slice(&canonical)?,
        };
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
