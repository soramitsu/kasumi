//! Immutable document sharing across admitted Engine and SDK output boundaries.
use crate::Document;
use serde::{Serialize, Serializer};
use std::{fmt, ops::Deref, sync::Arc};

/// A trusted producer's immutable document and its real retained admission.
///
/// Implementors must own a stable document and keep every required admission
/// owner alive through the payload's destruction. `document()` must always
/// borrow that same document. The sized owner and its Arc backing must be
/// admitted before allocation; shared source allocations must retain their
/// original custody rather than treating a borrowed view as a memory charge.
///
/// This is an accounting contract for providers, not proof of arbitrary
/// downstream implementations. A production implementation must not use an
/// empty, optional or no-op charge. Engine and SDK providers keep their concrete
/// admission types private; this crate has no dependency on either provider.
/// Retention does not renew authorization, key access or response deadlines.
pub trait AdmittedDocumentOwner: Send + Sync + 'static {
    fn document(&self) -> &Document;
}

/// A previously released document whose clones retain the same admitted owner.
///
/// Borrowing and serialization expose the document, never its raw Arc or its
/// admission owner. A deliberate deep copy through `Document::clone` is a new
/// caller allocation outside this handle's custody. Serialization also requires
/// separate admission for any newly allocated representation.
///
/// A raw document Arc cannot be extracted by dereference:
///
/// ```compile_fail
/// use kasumi_types::{Document, SharedDocument};
/// use std::sync::Arc;
/// fn extract(document: &SharedDocument) -> Arc<Document> {
///     Arc::clone(document)
/// }
/// ```
///
/// The released document is immutable:
///
/// ```compile_fail
/// use kasumi_types::SharedDocument;
/// fn mutate(document: &mut SharedDocument) {
///     document.version = 0;
/// }
/// ```
///
/// Decoding requires a real admitted provider; there is no ownerless decoder:
///
/// ```compile_fail
/// use kasumi_types::SharedDocument;
/// let document: SharedDocument = serde_json::from_str(
///     r#"{"id":"one","version":1,"body":{}}"#,
/// ).unwrap();
/// ```
pub struct SharedDocument {
    inner: Arc<dyn AdmittedDocumentOwner>,
}

impl SharedDocument {
    /// Transfer an already-admitted immutable owner without allocating or
    /// cloning its document. The provider must satisfy `AdmittedDocumentOwner`'s
    /// custody contract before this call; this method neither admits bytes nor
    /// converts an uncharged Document into an admitted result.
    pub fn from_admitted_owner<O: AdmittedDocumentOwner>(owner: Arc<O>) -> Self {
        Self { inner: owner }
    }
}

impl Clone for SharedDocument {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Deref for SharedDocument {
    type Target = Document;

    fn deref(&self) -> &Self::Target {
        self.inner.document()
    }
}

impl AsRef<Document> for SharedDocument {
    fn as_ref(&self) -> &Document {
        self.inner.document()
    }
}

impl fmt::Debug for SharedDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SharedDocument")
            .field(self.inner.document())
            .finish()
    }
}

impl Serialize for SharedDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.document().serialize(serializer)
    }
}
