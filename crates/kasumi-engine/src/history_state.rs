//! Consensus validation of verified history publication. Replicas validate the
//! complete manifest against their own immutable source rows before discarding
//! any hot bodies; external history remains explicitly required on later reads.
use super::*;

fn source_failure(
    error: anyhow::Error,
) -> kasumi_query::ReadFailure<crate::index_source::DocumentSourceFailure> {
    kasumi_query::ReadFailure::Source(crate::index_source::DocumentSourceFailure(error))
}

/// The original archive wire fields, with one admitted body loan per element.
/// No decoded source collection or complete chunk remains resident here.
#[derive(serde::Serialize)]
struct SourceChunk<'a> {
    kind: HistoryArchiveKind,
    archive_id: &'a str,
    source_incarnation: &'a str,
    collection: &'a str,
    index: usize,
    documents: SourceDocuments<'a>,
}
struct SourceDocuments<'a> {
    documents: &'a [Arc<DocumentSlot>],
    resolver: Option<&'a dyn DocumentResolver>,
    failure: &'a std::cell::RefCell<Option<anyhow::Error>>,
}
impl serde::Serialize for SourceDocuments<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error as _, SerializeSeq};
        let mut sequence = serializer.serialize_seq(Some(self.documents.len()))?;
        for slot in self.documents {
            let document = slot.load_owned(self.resolver).map_err(|error| {
                *self.failure.borrow_mut() = Some(error);
                S::Error::custom("archive source document unavailable")
            })?;
            sequence.serialize_element(document.as_ref())?;
        }
        sequence.end()
    }
}

pub(crate) fn metadata_entry(id: &str, value: &impl serde::Serialize) -> Result<usize> {
    encoded_len(&id)?
        .checked_add(1)
        .and_then(|bytes| {
            encoded_len(value)
                .ok()
                .and_then(|value| bytes.checked_add(value))
        })
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "history metadata byte overflow"))
}

pub(crate) fn index_fields(
    definition: &CollectionDefinition,
    document: &Document,
) -> BTreeMap<String, serde_json::Value> {
    definition
        .indexes
        .iter()
        .flat_map(|index| &index.fields)
        .filter_map(|field| {
            document
                .body
                .pointer(&field.path)
                .map(|value| (field.path.clone(), value.clone()))
        })
        .collect()
}

pub(crate) fn validate_manifest(manifest: &HistoryArchiveManifest) -> Result<()> {
    for name in [
        &manifest.archive_id,
        &manifest.tenant,
        &manifest.source_incarnation,
        &manifest.collection,
        &manifest.destination,
    ] {
        validate_name(name)?;
    }
    if manifest.chunks.is_empty()
        || manifest.chunks.len() > MAX_ARCHIVE_CHUNKS
        || manifest.document_count == 0
        || manifest.document_count > MAX_ARCHIVE_DOCUMENTS
        || encoded_len(manifest)? > MAX_ARCHIVE_MANIFEST_BYTES
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "archive manifest outside bounds",
        ));
    }
    let mut previous: Option<&str> = None;
    let mut count = 0usize;
    let mut object_ids = BTreeSet::new();
    for chunk in &manifest.chunks {
        uuid::Uuid::parse_str(&chunk.object_id).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid archive object identity",
            )
        })?;
        validate_sha256(&chunk.ciphertext_sha256)?;
        validate_sha256(&chunk.plaintext_sha256)?;
        validate_name(&chunk.first_id)?;
        validate_name(&chunk.last_id)?;
        if chunk.first_id > chunk.last_id
            || previous.is_some_and(|id| id >= chunk.first_id.as_str())
            || chunk.document_count == 0
            || chunk.plaintext_bytes == 0
            || chunk.plaintext_bytes > MAX_ARCHIVE_CHUNK_BYTES
            || !object_ids.insert(&chunk.object_id)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid archive chunk bounds",
            ));
        }
        previous = Some(&chunk.last_id);
        count = count
            .checked_add(chunk.document_count)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "archive count overflow"))?;
    }
    if count != manifest.document_count {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "archive count differs from manifest",
        ));
    }
    Ok(())
}

pub(crate) fn publish(
    state: &mut TenantState,
    command: &Command,
    request: &PublishHistoryArchive,
    revision: u64,
    resolver: Option<&dyn DocumentResolver>,
) -> crate::index_source::SourceResult<(Result<WriteReceipt>, bool)> {
    authorize_state(state, &command.context, None, Action::Admin)?;
    let manifest = &request.manifest;
    authorize_state(
        state,
        &command.context,
        Some(&manifest.collection),
        Action::Admin,
    )?;
    authorize_state(
        state,
        &command.context,
        Some(&manifest.collection),
        Action::Read,
    )?;
    validate_manifest(manifest)?;
    validate_sha256(&request.manifest_ciphertext_sha256)?;
    uuid::Uuid::parse_str(&request.manifest_object_id).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "invalid archive manifest object",
        )
    })?;
    if let Some(existing) = state.history_archives.get(&manifest.archive_id) {
        if existing.manifest != *manifest
            || existing.manifest_object_id != request.manifest_object_id
            || existing.manifest_ciphertext_sha256 != request.manifest_ciphertext_sha256
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "archive identity reused for different history",
            )
            .into());
        }
        return Ok((
            Ok(WriteReceipt {
                revision: existing.published_revision,
                versions: BTreeMap::new(),
            }),
            false,
        ));
    }
    if manifest.tenant != state.tenant
        || manifest.source_incarnation != state.incarnation
        || manifest.source_schema_epoch != state.schema_epoch
        || request.expected_policy_epoch != state.policy_epoch
        || manifest.cutoff_revision > state.revision
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "archive source or authority fence changed",
        )
        .into());
    }
    if state.history_archives.len() >= state.limits.history.max_archive_segments {
        return Err(
            Error::new(ErrorCode::QuotaExceeded, "archive manifest quota exhausted").into(),
        );
    }
    let collection = state
        .collections
        .get(&manifest.collection)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "archive collection missing"))?;
    if collection.definition.retention_class != CollectionRetentionClass::ArchivableHistory
        || collection.definition.write_mode != CollectionWriteMode::AppendOnly
    {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "collection is not eligible for history archival",
        )
        .into());
    }
    if collection
        .definition
        .indexes
        .iter()
        .any(|index| index.text.is_some())
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "text-indexed history requires a supported cold text index",
        )
        .into());
    }
    let eligible: BTreeMap<_, _> = collection
        .documents
        .iter()
        .filter(|(_, document)| document.version() <= manifest.cutoff_revision)
        .map(|(id, document)| (id.clone(), document.clone()))
        .collect();
    if eligible.len() != manifest.document_count {
        return Err(Error::new(ErrorCode::Conflict, "archive source count changed").into());
    }
    let mut source_bytes = 0usize;
    for document in eligible.values() {
        let bytes = document.body_bytes().map_err(source_failure)?;
        source_bytes = source_bytes
            .checked_add(usize::try_from(bytes).map_err(|_| {
                Error::new(ErrorCode::QuotaExceeded, "archive source size overflow")
            })?)
            .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "archive source size overflow"))?;
    }
    if source_bytes > MAX_ARCHIVE_SOURCE_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "archive prefix exceeds source byte bound",
        )
        .into());
    }
    let mut moved = Vec::with_capacity(eligible.len());
    for (index, descriptor) in manifest.chunks.iter().enumerate() {
        let documents: Vec<_> = eligible
            .range(descriptor.first_id.clone()..=descriptor.last_id.clone())
            .map(|(_, document)| document.clone())
            .collect();
        if documents.len() != descriptor.document_count
            || documents
                .first()
                .is_none_or(|doc| doc.id() != descriptor.first_id)
            || documents
                .last()
                .is_none_or(|doc| doc.id() != descriptor.last_id)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "archive chunk does not cover its source interval",
            )
            .into());
        }
        let failure = std::cell::RefCell::new(None);
        let chunk = SourceChunk {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: &manifest.archive_id,
            source_incarnation: &manifest.source_incarnation,
            collection: &manifest.collection,
            index,
            documents: SourceDocuments {
                documents: &documents,
                resolver,
                failure: &failure,
            },
        };
        let measured = staged_digest(&chunk);
        if let Some(error) = failure.into_inner() {
            return Err(source_failure(error));
        }
        let (digest, bytes) = measured?;
        if digest != descriptor.plaintext_sha256 || bytes != descriptor.plaintext_bytes {
            return Err(Error::new(
                ErrorCode::Conflict,
                "archive source bytes differ from verified chunk",
            )
            .into());
        }
        for slot in documents {
            let document = slot.load_owned(resolver).map_err(source_failure)?;
            let reference = ArchivedDocument {
                version: document.version,
                archive_id: manifest.archive_id.clone(),
                chunk_index: index,
                document_sha256: staged_digest(&document)?.0,
                document_bytes: encoded_len(&document)?,
                indexed_fields: index_fields(&collection.definition, document.as_ref()),
            };
            moved.push((
                document.id.clone(),
                reference,
                encoded_len(&document.body)? as u64,
            ));
        }
    }
    if moved.len() != eligible.len() {
        return Err(Error::new(ErrorCode::Conflict, "archive intervals omit source rows").into());
    }
    let mut staged = state.clone();
    let collection = staged
        .collections
        .get_mut(&manifest.collection)
        .expect("validated collection");
    for (id, reference, body_bytes) in moved {
        if collection.archived_documents.contains_key(&id) {
            return Err(
                Error::new(ErrorCode::Corruption, "history identity already archived").into(),
            );
        }
        collection.archived_document_bytes = collection
            .archived_document_bytes
            .checked_add(metadata_entry(&id, &reference)?)
            .ok_or_else(|| {
                Error::new(ErrorCode::QuotaExceeded, "archive reference size overflow")
            })?;
        collection
            .archived_documents
            .insert(id.clone(), Arc::new(reference));
        collection.documents.remove(&id);
        staged.logical_bytes = staged
            .logical_bytes
            .checked_sub(body_bytes)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "archive logical byte underflow"))?;
    }
    let retained = RetainedHistoryArchive {
        storage_destination: manifest.destination.clone(),
        storage_backup_session: None,
        manifest: manifest.clone(),
        manifest_object_id: request.manifest_object_id.clone(),
        manifest_ciphertext_sha256: request.manifest_ciphertext_sha256.clone(),
        published_revision: revision,
    };
    staged.history_archive_bytes = staged
        .history_archive_bytes
        .checked_add(metadata_entry(&manifest.archive_id, &retained)?)
        .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "archive catalog byte overflow"))?;
    staged
        .history_archives
        .insert(manifest.archive_id.clone(), Arc::new(retained));
    // Archival changes storage placement, never logical identity or data epoch.
    *state = staged;
    Ok((
        Ok(WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        }),
        true,
    ))
}

pub(crate) fn changes(
    state: &TenantState,
    request: &PublishHistoryArchive,
) -> BTreeMap<String, BTreeSet<String>> {
    let manifest = &request.manifest;
    let ids = state
        .collections
        .get(&manifest.collection)
        .map(|collection| {
            collection
                .documents
                .iter()
                .filter(|(_, document)| document.version() <= manifest.cutoff_revision)
                .map(|(id, _)| id.clone())
                .collect()
        })
        .unwrap_or_default();
    BTreeMap::from([(manifest.collection.clone(), ids)])
}

pub(crate) fn validate_restored(state: &TenantState) -> Result<()> {
    if state.history_archives.len() > state.limits.history.max_archive_segments {
        return Err(Error::new(
            ErrorCode::Corruption,
            "archive catalog exceeds quota",
        ));
    }
    let mut archive_bytes = 0usize;
    let mut chunks: BTreeMap<(&str, usize), Vec<&str>> = BTreeMap::new();
    for (name, collection) in &state.collections {
        if !collection.archived_documents.is_empty()
            && (collection.definition.retention_class
                != CollectionRetentionClass::ArchivableHistory
                || collection.definition.write_mode != CollectionWriteMode::AppendOnly
                || collection
                    .definition
                    .indexes
                    .iter()
                    .any(|index| index.text.is_some()))
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "ineligible collection has archived history",
            ));
        }
        let fields: BTreeSet<_> = collection
            .definition
            .indexes
            .iter()
            .flat_map(|index| &index.fields)
            .map(|field| &field.path)
            .collect();
        let mut reference_bytes = 0usize;
        for (id, reference) in &collection.archived_documents {
            validate_name(id)?;
            validate_sha256(&reference.document_sha256)?;
            let archive = state
                .history_archives
                .get(&reference.archive_id)
                .ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "archived identity has no manifest")
                })?;
            let descriptor = archive
                .manifest
                .chunks
                .get(reference.chunk_index)
                .ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "archived identity has no chunk")
                })?;
            if archive.manifest.collection != *name
                || reference.version > archive.manifest.cutoff_revision
                || reference.version > collection.data_epoch
                || collection.documents.contains_key(id)
                || id < &descriptor.first_id
                || id > &descriptor.last_id
                || reference.document_bytes == 0
                || reference.document_bytes > (1 << 20) + 4096
                || reference
                    .indexed_fields
                    .keys()
                    .any(|field| !fields.contains(field))
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "invalid archived identity or index metadata",
                ));
            }
            reference_bytes = reference_bytes
                .checked_add(metadata_entry(id, reference)?)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "archive metadata overflow"))?;
            chunks
                .entry((&reference.archive_id, reference.chunk_index))
                .or_default()
                .push(id);
        }
        if reference_bytes != collection.archived_document_bytes {
            return Err(Error::new(
                ErrorCode::Corruption,
                "archive reference byte accounting mismatch",
            ));
        }
    }
    for (id, archive) in &state.history_archives {
        validate_name(&archive.storage_destination)?;
        validate_manifest(&archive.manifest)?;
        validate_sha256(&archive.manifest_ciphertext_sha256)?;
        uuid::Uuid::parse_str(&archive.manifest_object_id)
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid archive manifest object"))?;
        if id != &archive.manifest.archive_id
            || archive.manifest.tenant != state.tenant
            || archive.storage_backup_session.is_some_and(|id| id.is_nil())
            || archive.published_revision > state.revision
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "invalid archive manifest identity",
            ));
        }
        for (index, descriptor) in archive.manifest.chunks.iter().enumerate() {
            let mut ids = chunks.remove(&(id.as_str(), index)).ok_or_else(|| {
                Error::new(
                    ErrorCode::Corruption,
                    "archive manifest has no referenced rows",
                )
            })?;
            ids.sort_unstable();
            if ids.len() != descriptor.document_count
                || ids.first().copied() != Some(descriptor.first_id.as_str())
                || ids.last().copied() != Some(descriptor.last_id.as_str())
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "archive referenced interval mismatch",
                ));
            }
        }
        archive_bytes = archive_bytes
            .checked_add(metadata_entry(id, archive)?)
            .ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "archive catalog accounting overflow")
            })?;
    }
    if !chunks.is_empty() || archive_bytes != state.history_archive_bytes {
        return Err(Error::new(
            ErrorCode::Corruption,
            "archive catalog accounting mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod source_chunk_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Owner {
        document: Document,
        active: Arc<AtomicUsize>,
    }
    impl AdmittedDocumentOwner for Owner {
        fn document(&self) -> &Document {
            &self.document
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            assert_eq!(self.active.fetch_sub(1, Ordering::SeqCst), 1);
        }
    }
    struct Resolver {
        documents: Vec<Arc<Document>>,
        active: Arc<AtomicUsize>,
        fail: bool,
    }
    impl DocumentResolver for Resolver {
        fn load(&self, descriptor: &StoredDocument) -> anyhow::Result<SharedDocument> {
            anyhow::ensure!(
                !self.fail || descriptor.id != "b",
                "original history source failure"
            );
            assert_eq!(
                self.active.fetch_add(1, Ordering::SeqCst),
                0,
                "archive verification retained another decoded source"
            );
            let document = self
                .documents
                .iter()
                .find(|document| document.id == descriptor.id)
                .unwrap();
            Ok(SharedDocument::from_admitted_owner(Arc::new(Owner {
                document: document.as_ref().clone(),
                active: self.active.clone(),
            })))
        }
    }
    fn fixture(fail: bool) -> (Resolver, Vec<Arc<DocumentSlot>>) {
        let documents: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|id| {
                Arc::new(Document {
                    id: id.into(),
                    version: 7,
                    body: serde_json::json!({"proof": "ab".repeat(4096), "id": id}),
                })
            })
            .collect();
        let slots = documents
            .iter()
            .map(|document| {
                Arc::new(DocumentSlot::Stored(
                    StoredDocument::from_document(document, [17; 32], 4096, 1 << 20, 4096).unwrap(),
                ))
            })
            .collect();
        (
            Resolver {
                documents,
                active: Arc::new(AtomicUsize::new(0)),
                fail,
            },
            slots,
        )
    }
    #[test]
    fn source_chunk_preserves_archive_wire_and_releases_each_decoded_loan() {
        let (resolver, slots) = fixture(false);
        let expected = HistoryArchiveChunk {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: "archive".into(),
            source_incarnation: "incarnation".into(),
            collection: "docs".into(),
            index: 3,
            documents: resolver.documents.clone(),
        };
        let failure = std::cell::RefCell::new(None);
        let source = SourceChunk {
            kind: expected.kind,
            archive_id: &expected.archive_id,
            source_incarnation: &expected.source_incarnation,
            collection: &expected.collection,
            index: expected.index,
            documents: SourceDocuments {
                documents: &slots,
                resolver: Some(&resolver),
                failure: &failure,
            },
        };
        assert_eq!(
            staged_digest(&source).unwrap(),
            staged_digest(&expected).unwrap()
        );
        assert!(failure.borrow().is_none());
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn source_chunk_retains_original_load_failure_outside_serialization_error() {
        let (resolver, slots) = fixture(true);
        let failure = std::cell::RefCell::new(None);
        let source = SourceChunk {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: "archive",
            source_incarnation: "incarnation",
            collection: "docs",
            index: 0,
            documents: SourceDocuments {
                documents: &slots,
                resolver: Some(&resolver),
                failure: &failure,
            },
        };
        assert!(staged_digest(&source).is_err());
        assert_eq!(
            failure.borrow().as_ref().unwrap().to_string(),
            "original history source failure"
        );
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
    }
}
