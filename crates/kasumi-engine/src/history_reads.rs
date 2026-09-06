//! Verified, bounded cold-body resolution for ordinary point/query/snapshot
//! reads. A missing destination, object, key or digest never becomes absence.
use super::*;

pub(super) struct HistoryReadCache {
    chunks: HashMap<(String, usize), Arc<HistoryArchiveChunk>>,
    manifests: BTreeSet<String>,
    bytes: usize,
    reservations: Vec<Reservation>,
}
impl HistoryReadCache {
    pub(super) fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            manifests: BTreeSet::new(),
            bytes: 0,
            reservations: vec![],
        }
    }
}

impl Database {
    /// Operator-only dependency installation; data requests select only an
    /// already installed alias. A duplicate alias can never change its target.
    pub fn install_archive_destination(
        &self,
        alias: String,
        destination: Arc<dyn BackupDestination>,
    ) -> Result<()> {
        validate_name(&alias)?;
        let mut destinations = self.archive_destinations.lock().map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "archive destination registry unavailable",
            )
        })?;
        if let Some(existing) = destinations.get(&alias) {
            if Arc::ptr_eq(existing, &destination) {
                return Ok(());
            }
            return Err(Error::new(
                ErrorCode::Conflict,
                "archive destination alias already installed",
            ));
        }
        destinations.insert(alias, destination);
        Ok(())
    }

    pub(super) fn archive_destination(&self, alias: &str) -> Result<Arc<dyn BackupDestination>> {
        self.archive_destinations
            .lock()
            .map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "archive destination registry unavailable",
                )
            })?
            .get(alias)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    "required history destination is unavailable",
                )
            })
    }

    pub(super) async fn history_document(
        &self,
        generation: &crate::Generation,
        collection_name: &str,
        id: &str,
        cancellation: &QueryCancellation,
        cache: &mut HistoryReadCache,
    ) -> Result<Option<Arc<Document>>> {
        cancellation.check()?;
        self.access()?;
        let collection = generation
            .state
            .collections
            .get(collection_name)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "history collection missing"))?;
        if let Some(document) = collection.documents.get(id) {
            return Ok(Some(document.clone()));
        }
        let Some(reference) = collection.archived_documents.get(id) else {
            return Ok(None);
        };
        let archive = generation
            .state
            .history_archives
            .get(&reference.archive_id)
            .ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "history manifest reference missing")
            })?;
        let destination = self.archive_destination(&archive.storage_destination)?;
        if !cache.manifests.contains(&reference.archive_id) {
            // A manifest can be much larger than the requested point document.
            // Charge encrypted framing, authenticated plaintext and decoding
            // before the destination allocates any of those buffers.
            let _manifest_workspace = self.admission().reserve(
                (MAX_ARCHIVE_MANIFEST_BYTES * 6 + (4 << 20)) as u64,
                Some(cancellation.clone()),
            )?;
            let plaintext = self
                .verified_history_object(
                    destination.as_ref(),
                    &archive.manifest_object_id,
                    &archive.manifest_ciphertext_sha256,
                    MAX_ARCHIVE_MANIFEST_BYTES,
                    cancellation,
                )
                .await?;
            let manifest: HistoryArchiveManifest = serde_json::from_slice(&plaintext.snapshot)
                .map_err(|_| {
                    Error::new(ErrorCode::Corruption, "history manifest JSON is corrupt")
                })?;
            if manifest != archive.manifest {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "history manifest differs from committed catalog",
                ));
            }
            cache.manifests.insert(reference.archive_id.clone());
        }
        let key = (reference.archive_id.clone(), reference.chunk_index);
        if !cache.chunks.contains_key(&key) {
            let descriptor = archive
                .manifest
                .chunks
                .get(reference.chunk_index)
                .ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "history chunk reference missing")
                })?;
            let total = cache
                .bytes
                .checked_add(descriptor.plaintext_bytes)
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "history read byte overflow")
                })?;
            if total > generation.state.limits.max_cursor_bytes {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "history read exceeds bounded materialization budget",
                ));
            }
            let mut reservation = self.admission().reserve(
                (descriptor.plaintext_bytes.saturating_mul(3) + (4 << 20)) as u64,
                Some(cancellation.clone()),
            )?;
            let plaintext = self
                .verified_history_object(
                    destination.as_ref(),
                    &descriptor.object_id,
                    &descriptor.ciphertext_sha256,
                    descriptor.plaintext_bytes,
                    cancellation,
                )
                .await?;
            if plaintext.snapshot.len() != descriptor.plaintext_bytes
                || hex::encode(Sha256::digest(&plaintext.snapshot)) != descriptor.plaintext_sha256
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "history plaintext digest or byte count differs",
                ));
            }
            let chunk: HistoryArchiveChunk = serde_json::from_slice(&plaintext.snapshot)
                .map_err(|_| Error::new(ErrorCode::Corruption, "history chunk JSON is corrupt"))?;
            if chunk.archive_id != reference.archive_id
                || chunk.collection != collection_name
                || chunk.source_incarnation != archive.manifest.source_incarnation
                || chunk.index != reference.chunk_index
                || chunk.documents.len() != descriptor.document_count
                || chunk
                    .documents
                    .first()
                    .is_none_or(|document| document.id != descriptor.first_id)
                || chunk
                    .documents
                    .last()
                    .is_none_or(|document| document.id != descriptor.last_id)
                || chunk
                    .documents
                    .windows(2)
                    .any(|pair| pair[0].id >= pair[1].id)
                || chunk
                    .documents
                    .iter()
                    .any(|document| document.version > archive.manifest.cutoff_revision)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "history chunk identity or interval differs",
                ));
            }
            cache.chunks.insert(key.clone(), Arc::new(chunk));
            cache.bytes = total;
            reservation.retain_workspace();
            cache.reservations.push(reservation);
        }
        let chunk = &cache.chunks[&key];
        let position = chunk
            .documents
            .binary_search_by(|document| document.id.as_str().cmp(id))
            .map_err(|_| {
                Error::new(
                    ErrorCode::Corruption,
                    "archived document is missing from its chunk",
                )
            })?;
        let document = &chunk.documents[position];
        if document.version != reference.version
            || staged_digest(document)?.0 != reference.document_sha256
            || crate::accounting::encoded_len(document)? != reference.document_bytes
            || crate::state::history::index_fields(&collection.definition, document)
                != reference.indexed_fields
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "archived document identity/hash/index differs",
            ));
        }
        cancellation.check()?;
        self.access()?;
        Ok(Some(document.clone()))
    }

    pub(super) async fn verified_history_object(
        &self,
        destination: &dyn BackupDestination,
        object_id: &str,
        ciphertext_sha256: &str,
        max_plaintext_bytes: usize,
        cancellation: &QueryCancellation,
    ) -> Result<kasumi_store::BackupContents> {
        let object_id = uuid::Uuid::parse_str(object_id)
            .map_err(|_| Error::new(ErrorCode::Corruption, "history object identity is corrupt"))?;
        let limit = max_plaintext_bytes.saturating_add((2 << 20) + 84);
        let bytes = tokio::select! {
            result = destination.get(object_id, limit) => result.map_err(|_| Error::new(ErrorCode::Unavailable, "required history object is missing or unavailable"))?,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        if hex::encode(Sha256::digest(&bytes)) != ciphertext_sha256 {
            return Err(Error::new(
                ErrorCode::Corruption,
                "history ciphertext digest differs",
            ));
        }
        let contents = tokio::select! {
            result = self.store.decrypt_backup_object(&bytes, object_id, max_plaintext_bytes) => result.map_err(|_| Error::new(ErrorCode::Unavailable, "history authentication or historical key authorization failed"))?,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        self.access()?;
        Ok(contents)
    }

    pub(super) async fn hydrate_history(
        &self,
        generation: Arc<crate::Generation>,
        keys: &[DocumentKey],
        queries: &[QueryRequest],
        cancellation: &QueryCancellation,
    ) -> Result<Arc<crate::Generation>> {
        let mut targets: BTreeSet<(String, String)> = keys
            .iter()
            .map(|key| (key.collection.clone(), key.id.clone()))
            .collect();
        for query in queries {
            let collection = generation
                .state
                .collections
                .get(&query.collection)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "query collection missing"))?;
            if collection.archived_documents.is_empty() {
                continue;
            }
            match generation.indexes.indexed_candidate_ids(
                &generation.state.collections,
                query,
                &generation.state.limits,
                cancellation,
            ) {
                Ok(ids) => targets.extend(ids.into_iter().map(|id| (query.collection.clone(), id))),
                Err(error)
                    if error.code == ErrorCode::IndexRequired
                        && query.allow_scan
                        && query.text.is_none() =>
                {
                    if collection
                        .documents
                        .len()
                        .saturating_add(collection.archived_documents.len())
                        > generation.state.limits.max_query_candidates
                    {
                        return Err(Error::new(
                            ErrorCode::ResourceExhausted,
                            "historical scan candidate budget exceeded",
                        ));
                    }
                    targets.extend(
                        collection
                            .archived_documents
                            .keys()
                            .map(|id| (query.collection.clone(), id.clone())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        if !targets.iter().any(|(name, id)| {
            generation
                .state
                .collections
                .get(name)
                .is_some_and(|collection| collection.archived_documents.contains_key(id))
        }) {
            return Ok(generation);
        }
        let mut collections = generation.state.collections.clone();
        let mut cache = HistoryReadCache::new();
        for (name, id) in targets {
            if generation
                .state
                .collections
                .get(&name)
                .is_some_and(|collection| collection.archived_documents.contains_key(&id))
                && let Some(document) = self
                    .history_document(&generation, &name, &id, cancellation, &mut cache)
                    .await?
            {
                collections
                    .get_mut(&name)
                    .expect("validated collection")
                    .documents
                    .insert(id, document);
            }
        }
        Ok(Arc::new(
            generation.read_view(collections, cache.reservations),
        ))
    }
}
