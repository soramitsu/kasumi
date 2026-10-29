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
use std::{collections::BTreeMap, sync::Arc};

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
        let bytes =
            crate::accounting::encoded_len(&kasumi_types::CanonicalJsonValue(&document.body))?;
        let limits = limits(bytes)?;
        let work = crate::snapshot_codec::inspect_typed_json_work(document)?
            .checked_add(
                (bytes as u64)
                    .checked_mul(8)
                    .context("document preparation overflow")?,
            )
            .and_then(|v| v.checked_add(1 << 20))
            .context("document preparation overflow")?;
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
        let object = Sha256::digest(&wire).into();
        self.put(true, object, &wire, work)?;
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
            "document encoding differs from canonical body"
        );
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
}

/// Each operation borrows the exact selected native source. It never opens
/// latest and releases its native loan before returning an admitted body.
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
        let mut reservation =
            DocumentWorkspace::new(self.roots.primary_installation().1, wire_floor)?;
        let mut reader = self.selected.open_document_reader(&self.roots)?;
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
        reader.close()?;
        // The borrowed scan quotes serde's actual decode backing, including
        // parser capacities. Wire/manifest/native read work has retired now.
        reservation.retain(decoded_work);
        Ok(SharedDocument::from_admitted_owner(Arc::new(
            DecodedOwner {
                document,
                _reservation: reservation,
            },
        )))
    }
}
