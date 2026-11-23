//! Compact application-document identity and explicitly scoped body loans.
//!
//! A descriptor owns no decoded JSON, cache entry, or native snapshot pin. The
//! enclosing generation supplies one exact resolver; keeping a native read view
//! in every descriptor would let unchanged records pin old storage roots forever.
//! This is an internal storage descriptor, never the public `Document` wire DTO.

use crate::{CanonicalJsonValue, Document, SharedDocument, validate_name};
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::sync::Arc;

/// Immutable logical identity plus the content identity of its encoded body.
/// `body_object` addresses the storage encoding, whose representation can share
/// proof blobs; `body_sha256` authenticates the original canonical JSON body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredDocument {
    pub id: String,
    pub version: u64,
    pub body_bytes: u64,
    pub document_bytes: u64,
    pub body_sha256: [u8; 32],
    pub body_object: [u8; 32],
    pub body_object_bytes: u64,
    /// Allocation-free structural quotes measured from the exact canonical body
    /// and immutable manifest before this descriptor is published.
    pub body_decode_work: u64,
    pub body_manifest_work: u64,
}

/// One exact selected application view, supplied by the enclosing generation.
///
/// The implementation checks tenant/incarnation, current key access and source
/// liveness, admits bounded read/decode work before allocation, and transfers the
/// real decode reservation into the returned owner. It must never refresh to a
/// newer root or return absence for a referenced body. Storage and admission
/// failures are local failures, not deterministic replicated command rejections.
pub trait DocumentResolver: Send + Sync {
    fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument>;

    /// The canonical live descriptor that a [`LocatedDocument`] of `id` in
    /// `collection` stands for, read from the authenticated primary directory
    /// this resolver selected. A resolver without such a directory cannot
    /// lend located slots, and a miss there is corruption, never absence.
    fn locate(
        &self,
        collection: &str,
        id: &str,
        located: &LocatedDocument,
    ) -> Result<StoredDocument> {
        let _ = (collection, id, located);
        anyhow::bail!("located document has no selected primary directory")
    }
}

/// The resident remainder of a published descriptor whose canonical copy is
/// the live row of an authenticated primary directory the enclosing
/// generation selected. The ordered writer's preconditions, the logical,
/// document and snapshot byte charges and the structural source quotes need
/// only these fields. Anything that names the body (its object and digests)
/// resolves the row through the generation's resolver, which checks every
/// resident field against it. The document ID is the key of the slot's
/// collection map. Charges are narrowed to `u32`: a descriptor whose charges do
/// not fit has no located form and stays complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatedDocument {
    version: u64,
    body_bytes: u32,
    document_bytes: u32,
    body_object_bytes: u32,
    body_decode_work: u32,
    body_manifest_work: u32,
}

impl LocatedDocument {
    /// The located form of `descriptor`, if its charges fit.
    pub fn of(descriptor: &StoredDocument) -> Option<Self> {
        Some(Self {
            version: descriptor.version,
            body_bytes: descriptor.body_bytes.try_into().ok()?,
            document_bytes: descriptor.document_bytes.try_into().ok()?,
            body_object_bytes: descriptor.body_object_bytes.try_into().ok()?,
            body_decode_work: descriptor.body_decode_work.try_into().ok()?,
            body_manifest_work: descriptor.body_manifest_work.try_into().ok()?,
        })
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn body_bytes(&self) -> u64 {
        self.body_bytes.into()
    }
    pub fn document_bytes(&self) -> u64 {
        self.document_bytes.into()
    }
    pub fn body_object_bytes(&self) -> u64 {
        self.body_object_bytes.into()
    }
    pub fn body_decode_work(&self) -> u64 {
        self.body_decode_work.into()
    }
    pub fn body_manifest_work(&self) -> u64 {
        self.body_manifest_work.into()
    }

    /// Accept a resolved row only when it is the exact descriptor this slot
    /// was compacted from: the same identity, version and charges.
    pub fn check(&self, id: &str, descriptor: StoredDocument) -> Result<StoredDocument> {
        descriptor.validate()?;
        ensure!(
            descriptor.id == id && Self::of(&descriptor).as_ref() == Some(self),
            "located document row differs from its resident descriptor"
        );
        Ok(descriptor)
    }
}

/// An unpublished bounded mutation can still own a decoded after-image while
/// its indexes and durable body object are prepared. A published collection
/// contains only `Stored` and `Located` slots, and a retained feed only
/// `Stored` ones. A `Located` slot exists only in a generation whose resolver
/// selected a primary directory holding its exact row; resolving it needs the
/// collection name and the slot's map key. There is deliberately no
/// context-free serialization of stored bodies, `Deref`, or body-returning
/// convenience method. Portable snapshots and responses must explicitly select
/// and lend their DTO; deserialization produces unpublished pending input only.
///
/// The complete descriptor is boxed so that a located slot, the resident form
/// of every unchanged published document, stays a small allocation.
#[derive(Debug, Clone, PartialEq)]
pub enum DocumentSlot {
    Pending(Arc<Document>),
    Stored(Box<StoredDocument>),
    Located(LocatedDocument),
}

impl Serialize for DocumentSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Pending(document) => document.serialize(serializer),
            Self::Stored(_) | Self::Located(_) => Err(serde::ser::Error::custom(
                "stored document serialization requires its selected resolver",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for DocumentSlot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Document::deserialize(deserializer).map(|document| Self::Pending(Arc::new(document)))
    }
}

/// Exactly one admitted decoded body or a borrow of the bounded pending input.
/// Holding two loans permits old/new index validation without retaining either
/// body in the collection. Dropping a stored loan releases its output owner.
pub enum DocumentLoan<'a> {
    Pending(&'a Document),
    Stored(SharedDocument),
}

/// An owned semantic record that retains either unpublished input or the real
/// decoded-body admission. Portable snapshot iterators can carry this owner
/// without cloning the JSON after-image or exposing a storage descriptor.
#[derive(Clone, Debug)]
pub enum OwnedDocument {
    Pending(Arc<Document>),
    Stored(SharedDocument),
}

impl PartialEq for OwnedDocument {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl AsRef<Document> for OwnedDocument {
    fn as_ref(&self) -> &Document {
        match self {
            Self::Pending(document) => document,
            Self::Stored(document) => document.as_ref(),
        }
    }
}
impl std::ops::Deref for OwnedDocument {
    type Target = Document;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}
impl Serialize for OwnedDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.as_ref().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for OwnedDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Document::deserialize(deserializer).map(|document| Self::Pending(Arc::new(document)))
    }
}

impl AsRef<Document> for DocumentLoan<'_> {
    fn as_ref(&self) -> &Document {
        match self {
            Self::Pending(document) => document,
            Self::Stored(document) => document.as_ref(),
        }
    }
}

impl std::ops::Deref for DocumentLoan<'_> {
    type Target = Document;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DocumentSlot {
    /// A complete published descriptor.
    pub fn stored_descriptor(descriptor: StoredDocument) -> Self {
        Self::Stored(Box::new(descriptor))
    }

    /// The slot's own copy of its identity. A located slot has none: its ID is
    /// the key under which its collection map holds it.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Pending(document) => Some(&document.id),
            Self::Stored(document) => Some(&document.id),
            Self::Located(_) => None,
        }
    }

    /// Whether a slot found under map key `id` can belong to it.
    pub fn has_id(&self, id: &str) -> bool {
        self.id().is_none_or(|own| own == id)
    }

    pub fn version(&self) -> u64 {
        match self {
            Self::Pending(document) => document.version,
            Self::Stored(document) => document.version,
            Self::Located(located) => located.version(),
        }
    }

    /// The resident complete descriptor. A located slot fails closed: callers
    /// that can meet one resolve it with [`Self::descriptor`].
    pub fn stored(&self) -> Result<&StoredDocument> {
        match self {
            Self::Stored(document) => Ok(document),
            Self::Pending(_) => anyhow::bail!("published document still owns a decoded body"),
            Self::Located(_) => Err(unresolved_located()),
        }
    }

    /// The complete descriptor of a published slot found under `id` in
    /// `collection`, resolving a located slot through `resolver`.
    pub fn descriptor(
        &self,
        collection: &str,
        id: &str,
        resolver: Option<&dyn DocumentResolver>,
    ) -> Result<std::borrow::Cow<'_, StoredDocument>> {
        match self {
            Self::Located(located) => {
                let resolver = resolver
                    .ok_or_else(|| anyhow::anyhow!("located document has no selected resolver"))?;
                Ok(std::borrow::Cow::Owned(
                    located.check(id, resolver.locate(collection, id, located)?)?,
                ))
            }
            _ => self.stored().map(std::borrow::Cow::Borrowed),
        }
    }

    /// The located form of a complete descriptor, if it has one.
    pub fn located(&self) -> Option<LocatedDocument> {
        match self {
            Self::Stored(document) => LocatedDocument::of(document),
            Self::Located(located) => Some(*located),
            Self::Pending(_) => None,
        }
    }

    /// Whether two published slots of one document name the same descriptor.
    /// A version identifies exactly one after-image of a document, so a
    /// located slot equals any complete descriptor of its version.
    pub fn same_descriptor(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Pending(left), Self::Pending(right)) => Arc::ptr_eq(left, right),
            (Self::Pending(_), _) | (_, Self::Pending(_)) => false,
            (Self::Stored(left), Self::Stored(right)) => left == right,
            (left, right) => left.located().is_some() && left.located() == right.located(),
        }
    }

    pub fn with_document<T>(
        &self,
        resolver: &dyn DocumentResolver,
        lend: impl for<'a> FnOnce(&'a Document) -> T,
    ) -> Result<T> {
        let document = self.load(resolver)?;
        Ok(lend(document.as_ref()))
    }

    pub fn load<'a>(&'a self, resolver: &dyn DocumentResolver) -> Result<DocumentLoan<'a>> {
        match self {
            Self::Pending(document) => Ok(DocumentLoan::Pending(document)),
            Self::Stored(document) => Ok(DocumentLoan::Stored(document.load(resolver)?)),
            Self::Located(_) => Err(unresolved_located()),
        }
    }

    /// [`Self::load`] for a slot found under `id` in `collection`, which may
    /// be located.
    pub fn load_at<'a>(
        &'a self,
        collection: &str,
        id: &str,
        resolver: &dyn DocumentResolver,
    ) -> Result<DocumentLoan<'a>> {
        match self {
            Self::Located(_) => Ok(DocumentLoan::Stored(
                self.descriptor(collection, id, Some(resolver))?
                    .load(resolver)?,
            )),
            _ => self.load(resolver),
        }
    }

    pub fn load_owned(&self, resolver: Option<&dyn DocumentResolver>) -> Result<OwnedDocument> {
        match self {
            Self::Pending(document) => Ok(OwnedDocument::Pending(document.clone())),
            Self::Stored(document) => {
                let resolver = resolver
                    .ok_or_else(|| anyhow::anyhow!("stored document has no selected resolver"))?;
                Ok(OwnedDocument::Stored(document.load(resolver)?))
            }
            Self::Located(_) => Err(unresolved_located()),
        }
    }

    /// [`Self::load_owned`] for a slot found under `id` in `collection`.
    pub fn load_owned_at(
        &self,
        collection: &str,
        id: &str,
        resolver: Option<&dyn DocumentResolver>,
    ) -> Result<OwnedDocument> {
        match self {
            Self::Located(_) => {
                let descriptor = self.descriptor(collection, id, resolver)?;
                let resolver = resolver
                    .ok_or_else(|| anyhow::anyhow!("stored document has no selected resolver"))?;
                Ok(OwnedDocument::Stored(descriptor.load(resolver)?))
            }
            _ => self.load_owned(resolver),
        }
    }

    /// Canonical body charge, independent of physical deduplication savings.
    pub fn body_bytes(&self) -> Result<u64> {
        match self {
            Self::Pending(document) => canonical_len(&CanonicalJsonValue(&document.body)),
            Self::Stored(document) => Ok(document.body_bytes),
            Self::Located(located) => Ok(located.body_bytes()),
        }
    }

    pub fn document_bytes(&self) -> Result<u64> {
        match self {
            Self::Pending(document) => canonical_len(document.as_ref()),
            Self::Stored(document) => Ok(document.document_bytes),
            Self::Located(located) => Ok(located.document_bytes()),
        }
    }
}

fn unresolved_located() -> anyhow::Error {
    anyhow::anyhow!("located document descriptor requires its selected primary directory")
}

impl StoredDocument {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.id)?;
        ensure!(self.body_bytes > 0, "stored document body length is zero");
        ensure!(
            self.body_object_bytes > 0,
            "stored document object length is zero"
        );
        ensure!(
            self.body_decode_work >= self.body_bytes
                && self.body_manifest_work >= self.body_object_bytes
                && self
                    .body_decode_work
                    .checked_add(self.body_manifest_work)
                    .is_some(),
            "stored document decode workspace differs"
        );
        ensure!(
            self.document_bytes > self.body_bytes,
            "stored document framing length differs"
        );
        Ok(())
    }

    /// Resolve only against the caller's selected view and verify the complete
    /// logical after-image before exposing it. The returned owner keeps all body
    /// allocations admitted until its last consumer releases them.
    pub fn load(&self, resolver: &dyn DocumentResolver) -> Result<SharedDocument> {
        self.validate()?;
        let document = resolver.load(self)?;
        ensure!(
            document.id == self.id && document.version == self.version,
            "stored document identity/version differs"
        );
        let (body_bytes, body_sha256) = fingerprint(&CanonicalJsonValue(&document.body))?;
        ensure!(
            body_bytes == self.body_bytes && body_sha256 == self.body_sha256,
            "stored document canonical body differs"
        );
        ensure!(
            framed_document_bytes(&document, body_bytes)? == self.document_bytes,
            "stored document canonical framing differs"
        );
        Ok(document)
    }

    /// The body loan ends before its admitted owner is released. A callback
    /// returning owned data must acquire its separate output reservation first.
    pub fn with_document<T>(
        &self,
        resolver: &dyn DocumentResolver,
        lend: impl for<'a> FnOnce(&'a Document) -> T,
    ) -> Result<T> {
        let document = self.load(resolver)?;
        Ok(lend(document.as_ref()))
    }

    /// Measure canonical semantic bytes without making a serialized body copy.
    /// The caller has already admitted the input and owns body-object durability.
    pub fn from_document(
        document: &Document,
        body_object: [u8; 32],
        body_object_bytes: u64,
        body_decode_work: u64,
        body_manifest_work: u64,
    ) -> Result<Self> {
        let (body_bytes, body_sha256) = fingerprint(&CanonicalJsonValue(&document.body))?;
        let descriptor = Self {
            id: document.id.clone(),
            version: document.version,
            body_bytes,
            document_bytes: framed_document_bytes(document, body_bytes)?,
            body_sha256,
            body_object,
            body_object_bytes,
            body_decode_work,
            body_manifest_work,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

fn fingerprint(value: &impl Serialize) -> Result<(u64, [u8; 32])> {
    struct Fingerprint {
        bytes: u64,
        digest: Sha256,
    }
    impl Write for Fingerprint {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("document byte length overflow"))?;
            self.digest.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Fingerprint {
        bytes: 0,
        digest: Sha256::new(),
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok((writer.bytes, writer.digest.finalize().into()))
}

/// The serialized length that [`fingerprint`] reports, without its digest.
/// Framing and charge checks compare lengths only; hashing the same bytes to
/// discard the result would add a SHA-256 pass to every load and every put.
/// The ordinary Document serializer contributes the exact escaped ID, version,
/// keys and delimiters. Substitute the measured body for its four-byte null
/// placeholder without traversing the authenticated payload a second time.
fn framed_document_bytes(document: &Document, measured_body_bytes: u64) -> Result<u64> {
    let framing = Document {
        id: document.id.clone(),
        version: document.version,
        body: serde_json::Value::Null,
    };
    canonical_len(&framing)?
        .checked_sub(4)
        .and_then(|n| n.checked_add(measured_body_bytes))
        .ok_or_else(|| anyhow::anyhow!("canonical document length overflow"))
}

fn canonical_len(value: &impl Serialize) -> Result<u64> {
    struct Length(u64);
    impl Write for Length {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("document byte length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Length(0);
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AdmittedDocumentOwner;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Owner {
        document: Document,
        alive: Arc<AtomicUsize>,
    }
    impl AdmittedDocumentOwner for Owner {
        fn document(&self) -> &Document {
            &self.document
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.alive.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct Resolver {
        document: Document,
        alive: Arc<AtomicUsize>,
    }
    impl DocumentResolver for Resolver {
        fn load(&self, _: &StoredDocument) -> Result<SharedDocument> {
            self.alive.fetch_add(1, Ordering::SeqCst);
            Ok(SharedDocument::from_admitted_owner(Arc::new(Owner {
                document: self.document.clone(),
                alive: self.alive.clone(),
            })))
        }
    }
    fn fixture() -> (StoredDocument, Resolver) {
        let document = Document {
            id: "proof".into(),
            version: 3,
            body: serde_json::json!({"proof": "x".repeat(8192), "amount": 11}),
        };
        (
            StoredDocument::from_document(&document, [9; 32], 256, 1 << 20, 4096).unwrap(),
            Resolver {
                document,
                alive: Arc::new(AtomicUsize::new(0)),
            },
        )
    }
    #[test]
    fn framing_uses_exact_id_version_and_measured_canonical_payload() {
        for id in ["quotes\"and\\slashes", "長い識別子"] {
            for body in [
                serde_json::Value::Null,
                serde_json::json!("\n\u{001f}"),
                serde_json::json!({"b": true, "a": [7, "x".repeat(32768)]}),
            ] {
                let doc = Document {
                    id: id.into(),
                    version: u64::MAX,
                    body,
                };
                let bytes = canonical_len(&CanonicalJsonValue(&doc.body)).unwrap();
                assert_eq!(
                    framed_document_bytes(&doc, bytes).unwrap(),
                    canonical_len(&doc).unwrap()
                );
                assert!(framed_document_bytes(&doc, u64::MAX).is_err());
            }
        }
    }

    #[test]
    fn descriptor_has_no_body_and_each_loan_releases_its_owner() {
        let (descriptor, resolver) = fixture();
        let encoded = serde_json::to_vec(&descriptor).unwrap();
        assert!(encoded.len() < 1024);
        for _ in 0..3 {
            let version = descriptor
                .with_document(&resolver, |document| {
                    assert_eq!(resolver.alive.load(Ordering::SeqCst), 1);
                    document.version
                })
                .unwrap();
            assert_eq!(version, 3);
            assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn length_only_measurement_matches_the_fingerprinted_length() {
        let (descriptor, resolver) = fixture();
        let document = &resolver.document;
        let body = CanonicalJsonValue(&document.body);
        assert_eq!(
            canonical_len(document).unwrap(),
            fingerprint(document).unwrap().0
        );
        assert_eq!(canonical_len(&body).unwrap(), fingerprint(&body).unwrap().0);
        assert_eq!(
            canonical_len(document).unwrap(),
            serde_json::to_vec(document).unwrap().len() as u64
        );
        // Descriptors and pending slots report those same lengths.
        assert_eq!(descriptor.document_bytes, canonical_len(document).unwrap());
        let pending = DocumentSlot::Pending(Arc::new(document.clone()));
        assert_eq!(pending.document_bytes().unwrap(), descriptor.document_bytes);
        assert_eq!(pending.body_bytes().unwrap(), descriptor.body_bytes);
    }

    #[test]
    fn a_framing_length_difference_fails_closed_without_a_body_difference() {
        // Identity and body match; only the recorded framing length differs.
        let (mut descriptor, resolver) = fixture();
        descriptor.document_bytes += 1;
        let error = descriptor.load(&resolver).unwrap_err();
        assert_eq!(
            error.to_string(),
            "stored document canonical framing differs"
        );
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrong_version_and_same_length_body_corruption_fail_closed() {
        let (descriptor, mut resolver) = fixture();
        resolver.document.version += 1;
        assert!(descriptor.load(&resolver).is_err());
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
        resolver.document.version -= 1;
        resolver.document.body["amount"] = serde_json::json!(12);
        assert!(descriptor.load(&resolver).is_err());
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn returned_handle_retains_owner_until_final_consumer() {
        let (descriptor, resolver) = fixture();
        let first = descriptor.load(&resolver).unwrap();
        let second = first.clone();
        drop(first);
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 1);
        drop(second);
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pending_slots_cannot_be_treated_as_published_storage() {
        let (descriptor, resolver) = fixture();
        let slot = DocumentSlot::Pending(Arc::new(resolver.document.clone()));
        assert_eq!(slot.id(), Some(descriptor.id.as_str()));
        assert_eq!(slot.version(), descriptor.version);
        assert_eq!(slot.body_bytes().unwrap(), descriptor.body_bytes);
        assert!(slot.stored().is_err());
        slot.with_document(&resolver, |document| {
            assert_eq!(document.version, descriptor.version);
            assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
        })
        .unwrap();
        let slot = DocumentSlot::stored_descriptor(descriptor.clone());
        assert_eq!(slot.stored().unwrap(), &descriptor);
    }

    #[test]
    fn wire_round_trip_is_pending_and_stored_requires_selected_serialization() {
        let (descriptor, resolver) = fixture();
        let pending = DocumentSlot::Pending(Arc::new(resolver.document.clone()));
        let bytes = serde_json::to_vec(&pending).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&resolver.document).unwrap());
        let decoded: DocumentSlot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, pending);
        assert!(decoded.stored().is_err());
        assert!(serde_json::to_vec(&DocumentSlot::stored_descriptor(descriptor.clone())).is_err());
        let located = DocumentSlot::Located(LocatedDocument::of(&descriptor).unwrap());
        assert!(serde_json::to_vec(&located).is_err());
    }

    #[test]
    fn owned_wire_record_retains_charge_without_cloning_body() {
        let (descriptor, resolver) = fixture();
        let slot = DocumentSlot::stored_descriptor(descriptor);
        let first = slot.load_owned(Some(&resolver)).unwrap();
        let second = first.clone();
        assert!(std::ptr::eq(first.as_ref(), second.as_ref()));
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&resolver.document).unwrap()
        );
        let restored: OwnedDocument =
            serde_json::from_slice(&serde_json::to_vec(&first).unwrap()).unwrap();
        assert!(matches!(restored, OwnedDocument::Pending(_)));
        drop(first);
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 1);
        drop(second);
        assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
    }

    /// A directory resolver over one canonical row.
    struct Directory {
        inner: Resolver,
        collection: &'static str,
        row: StoredDocument,
        located: AtomicUsize,
    }
    impl DocumentResolver for Directory {
        fn load(&self, descriptor: &StoredDocument) -> Result<SharedDocument> {
            self.inner.load(descriptor)
        }
        fn locate(
            &self,
            collection: &str,
            id: &str,
            _: &LocatedDocument,
        ) -> Result<StoredDocument> {
            self.located.fetch_add(1, Ordering::SeqCst);
            ensure!(
                collection == self.collection && id == self.row.id,
                "row absent"
            );
            Ok(self.row.clone())
        }
    }

    #[test]
    fn located_slots_keep_charges_and_resolve_only_their_exact_row() {
        let (descriptor, inner) = fixture();
        let compact = LocatedDocument::of(&descriptor).unwrap();
        let slot = DocumentSlot::Located(compact);
        // A located slot and its two Arc counters fit one 64-byte allocation.
        assert!(std::mem::size_of::<DocumentSlot>() + 16 <= 64);
        assert_eq!(slot.id(), None);
        assert!(slot.has_id("anything"));
        assert_eq!(slot.version(), descriptor.version);
        assert_eq!(slot.body_bytes().unwrap(), descriptor.body_bytes);
        assert_eq!(slot.document_bytes().unwrap(), descriptor.document_bytes);
        assert_eq!(slot.located(), Some(compact));
        // Without the selected directory every body-naming use fails closed.
        assert!(slot.stored().is_err());
        assert!(slot.load(&inner).is_err());
        assert!(slot.load_owned(Some(&inner)).is_err());
        assert!(slot.descriptor("docs", "proof", None).is_err());
        assert!(slot.load_at("docs", "proof", &inner).is_err());

        let directory = Directory {
            inner,
            collection: "docs",
            row: descriptor.clone(),
            located: AtomicUsize::new(0),
        };
        assert_eq!(
            slot.descriptor("docs", "proof", Some(&directory))
                .unwrap()
                .as_ref(),
            &descriptor
        );
        let loan = slot.load_at("docs", "proof", &directory).unwrap();
        assert_eq!(loan.version, descriptor.version);
        drop(loan);
        let owned = slot
            .load_owned_at("docs", "proof", Some(&directory))
            .unwrap();
        assert_eq!(owned.id, "proof");
        drop(owned);
        assert_eq!(directory.inner.alive.load(Ordering::SeqCst), 0);
        assert_eq!(directory.located.load(Ordering::SeqCst), 3);
        // Another document's row, or a row of another version, is corruption.
        assert!(slot.descriptor("other", "proof", Some(&directory)).is_err());
        let newer = DocumentSlot::Located(
            LocatedDocument::of(&StoredDocument {
                version: descriptor.version + 1,
                ..descriptor.clone()
            })
            .unwrap(),
        );
        assert!(newer.descriptor("docs", "proof", Some(&directory)).is_err());
        // One version names one after-image, however it is held.
        let stored = DocumentSlot::stored_descriptor(descriptor.clone());
        assert!(slot.same_descriptor(&stored) && stored.same_descriptor(&slot));
        assert!(!newer.same_descriptor(&stored));
        let pending = DocumentSlot::Pending(Arc::new(directory.inner.document.clone()));
        assert!(!pending.same_descriptor(&slot));
        // Charges beyond the narrowed range keep the complete descriptor.
        let wide = StoredDocument {
            body_decode_work: u64::from(u32::MAX) + 1,
            ..descriptor
        };
        assert!(LocatedDocument::of(&wide).is_none());
        assert_eq!(DocumentSlot::stored_descriptor(wide).located(), None);
    }
}
