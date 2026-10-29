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
}

/// An unpublished bounded mutation can still own a decoded after-image while
/// its indexes and durable body object are prepared. A published collection or
/// retained feed must contain only `Stored` slots. There is deliberately no
/// context-free serialization of stored bodies, `Deref`, or body-returning
/// convenience method. Portable snapshots and responses must explicitly select
/// and lend their DTO; deserialization produces unpublished pending input only.
#[derive(Debug, Clone, PartialEq)]
pub enum DocumentSlot {
    Pending(Arc<Document>),
    Stored(StoredDocument),
}

impl Serialize for DocumentSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Pending(document) => document.serialize(serializer),
            Self::Stored(_) => Err(serde::ser::Error::custom(
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
    pub fn id(&self) -> &str {
        match self {
            Self::Pending(document) => &document.id,
            Self::Stored(document) => &document.id,
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            Self::Pending(document) => document.version,
            Self::Stored(document) => document.version,
        }
    }

    pub fn stored(&self) -> Result<&StoredDocument> {
        match self {
            Self::Stored(document) => Ok(document),
            Self::Pending(_) => anyhow::bail!("published document still owns a decoded body"),
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
        }
    }

    /// Canonical body charge, independent of physical deduplication savings.
    pub fn body_bytes(&self) -> Result<u64> {
        match self {
            Self::Pending(document) => Ok(fingerprint(&CanonicalJsonValue(&document.body))?.0),
            Self::Stored(document) => Ok(document.body_bytes),
        }
    }

    pub fn document_bytes(&self) -> Result<u64> {
        match self {
            Self::Pending(document) => Ok(fingerprint(document.as_ref())?.0),
            Self::Stored(document) => Ok(document.document_bytes),
        }
    }
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
            fingerprint(document.as_ref())?.0 == self.document_bytes,
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
            document_bytes: fingerprint(document)?.0,
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
        assert_eq!(slot.id(), descriptor.id);
        assert_eq!(slot.version(), descriptor.version);
        assert_eq!(slot.body_bytes().unwrap(), descriptor.body_bytes);
        assert!(slot.stored().is_err());
        slot.with_document(&resolver, |document| {
            assert_eq!(document.version, descriptor.version);
            assert_eq!(resolver.alive.load(Ordering::SeqCst), 0);
        })
        .unwrap();
        let slot = DocumentSlot::Stored(descriptor.clone());
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
        assert!(serde_json::to_vec(&DocumentSlot::Stored(descriptor)).is_err());
    }

    #[test]
    fn owned_wire_record_retains_charge_without_cloning_body() {
        let (descriptor, resolver) = fixture();
        let slot = DocumentSlot::Stored(descriptor);
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
}
