//! Verified, bounded cold-body resolution for ordinary point/query/snapshot
//! reads. A missing destination, object, key or digest never becomes absence.
use super::*;

/// An independently owned decoded loan, never a copy made merely to cross an
/// await boundary. Archive loans retain their chunk charge in HistoryReadCache.
pub(super) type ReadDocument = OwnedDocument;

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

    pub(super) async fn archived_document(
        &self,
        generation: &crate::Generation,
        collection_name: &str,
        id: &str,
        reference: &ArchivedDocument,
        cancellation: &QueryCancellation,
        cache: &mut HistoryReadCache,
    ) -> Result<ReadDocument> {
        cancellation.check()?;
        self.access()?;
        let collection = generation
            .state
            .collections
            .get(collection_name)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "history collection missing"))?;
        let archive = generation
            .state
            .history_archives
            .get(&reference.archive_id)
            .ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "history manifest reference missing")
            })?;
        let destination = self.archive_destination(&archive.storage_destination)?;
        let scoped = archive
            .storage_backup_session
            .map(|id| kasumi_store::BackupSessionObjects::new(destination.as_ref(), id))
            .transpose()
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid history backup session"))?;
        let destination: &dyn BackupDestination =
            scoped.as_ref().map_or(destination.as_ref(), |view| view);
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
                    destination,
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
                    destination,
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
        Ok(ReadDocument::Pending(document.clone()))
    }

    pub(super) async fn verified_history_object(
        &self,
        destination: &dyn BackupDestination,
        object_id: &str,
        ciphertext_sha256: &str,
        max_plaintext_bytes: usize,
        cancellation: &QueryCancellation,
    ) -> Result<kasumi_store::BackupContents> {
        let (object_id, bytes) = self
            .history_ciphertext(
                destination,
                object_id,
                ciphertext_sha256,
                max_plaintext_bytes,
                cancellation,
            )
            .await?;
        let contents = tokio::select! {
            result = self.store.decrypt_backup_object(&bytes, object_id, max_plaintext_bytes) => result.map_err(|_| Error::new(ErrorCode::Unavailable, "history authentication or historical key authorization failed"))?,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        self.access()?;
        Ok(contents)
    }

    pub(super) async fn history_ciphertext(
        &self,
        destination: &dyn BackupDestination,
        object_id: &str,
        ciphertext_sha256: &str,
        max_plaintext_bytes: usize,
        cancellation: &QueryCancellation,
    ) -> Result<(uuid::Uuid, Vec<u8>)> {
        cancellation.check()?;
        self.access()?;
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
        Ok((object_id, bytes))
    }

    /// The blocking selection owns the same admission, concurrency permit and
    /// registration as the enclosing operation, including after cancellation.
    pub(super) async fn hydrate_history<W: Send + 'static>(
        &self,
        mut work: W,
        cancellation: &QueryCancellation,
        inputs: fn(&mut W) -> HistoryInputs<'_>,
    ) -> Result<W> {
        cancellation.check()?;
        if !inputs(&mut work).needs_history()? {
            return Ok(work);
        }
        let mut selected = self
            .admission()
            .memory()
            .read_child(
                cancellation.clone(),
                Some(DocumentReads::deadline_error),
                move |token| {
                    let targets = inputs(&mut work).read_targets(token)?;
                    Ok(HistorySelection { targets, work })
                },
            )
            .await?;
        if selected.targets.rows.is_empty() {
            return Ok(selected.work);
        }
        let input = inputs(&mut selected.work);
        input
            .memory
            .reserve(history_view_workspace(&input.generation.state)?)?;
        let mut collections = input.generation.state.collections.clone();
        let mut cache = HistoryReadCache::new();
        for (name, id, reference) in selected.targets.rows.drain(..) {
            let document = self
                .archived_document(
                    input.generation,
                    &name,
                    &id,
                    &reference,
                    cancellation,
                    &mut cache,
                )
                .await?;
            let ReadDocument::Pending(document) = document else {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "archive-only read selected a live body",
                ));
            };
            collections
                .get_mut(&name)
                .expect("validated collection")
                .documents
                .insert(id, Arc::new(DocumentSlot::Pending(document)));
        }
        let temporary_bytes = selected.targets.temporary_bytes;
        drop(selected.targets);
        input.memory.release(temporary_bytes)?;
        *input.generation = Arc::new(input.generation.read_view(collections, cache.reservations));
        Ok(selected.work)
    }
}

pub(super) enum HistoryKeys<'a> {
    Points(&'a [DocumentKey]),
    Scan(&'a str, &'a [String]),
}

impl HistoryKeys<'_> {
    fn visit(&self, mut visit: impl FnMut(&str, &str) -> Result<()>) -> Result<()> {
        match self {
            Self::Points(keys) => keys
                .iter()
                .try_for_each(|key| visit(&key.collection, &key.id)),
            Self::Scan(collection, ids) => ids.iter().try_for_each(|id| visit(collection, id)),
        }
    }
}

pub(super) struct HistoryInputs<'a> {
    pub(super) generation: &'a mut Arc<crate::Generation>,
    pub(super) keys: HistoryKeys<'a>,
    pub(super) queries: &'a [QueryRequest],
    pub(super) memory: &'a mut QueryMemory<Reservation>,
    pub(super) deadline: std::time::Instant,
    pub(super) scan_reader: Option<&'a mut Option<Box<dyn crate::document_store::SharedRead>>>,
}

// Drop decoded references before the workspace and registration funding them.
struct HistorySelection<W> {
    targets: HistoryTargets,
    work: W,
}

struct HistoryTargets {
    rows: Vec<(String, String, Arc<ArchivedDocument>)>,
    temporary_bytes: u64,
}

impl HistoryInputs<'_> {
    fn needs_history(&self) -> Result<bool> {
        let mut needed = false;
        let mut inspect =
            |name: &str| {
                let collection =
                    self.generation.state.collections.get(name).ok_or_else(|| {
                        Error::new(ErrorCode::NotFound, "history collection missing")
                    })?;
                // The restored collection header verifies this against the sum of
                // the encoded archive entries. Every such entry has nonzero size.
                needed |= collection.archived_document_bytes != 0;
                Ok(())
            };
        self.keys.visit(|name, _| inspect(name))?;
        for query in self.queries {
            inspect(&query.collection)?;
        }
        Ok(needed)
    }

    fn read_targets(&mut self, cancellation: &QueryCancellation) -> Result<HistoryTargets> {
        let shared = self.scan_reader.as_deref_mut().and_then(Option::take);
        if let Some(shared) = shared {
            // The lease selected its IDs under this registered reader. Keep
            // that same reader for the later page evaluation after hydration.
            let reads = DocumentReads::from_shared(self.generation, self.deadline, Some(shared));
            let targets = self.select(&reads, cancellation);
            if targets.is_ok() {
                *self
                    .scan_reader
                    .as_deref_mut()
                    .expect("supplied scan reader") = reads.into_shared();
                return targets;
            }
            return finish_document_read(reads, |_| targets);
        }
        with_document_reads(&self.generation.clone(), self.deadline, |reads| {
            self.select(reads, cancellation)
        })
    }

    fn select(
        &mut self,
        reads: &DocumentReads,
        cancellation: &QueryCancellation,
    ) -> Result<HistoryTargets> {
        reads.check_deadline()?;
        let baseline = self.memory.live_bytes();
        let mut ids = BTreeSet::new();
        let collection_has_history =
            |name: &str| self.generation.state.collections[name].archived_document_bytes != 0;
        self.keys.visit(|name, id| {
            cancellation.check()?;
            if collection_has_history(name) {
                self.memory.reserve(history_target_workspace(name, id)?)?;
                ids.insert((name.to_owned(), id.to_owned()));
            }
            Ok(())
        })?;
        for query in self.queries {
            if !collection_has_history(&query.collection) {
                continue;
            }
            let source = reads.source(&query.collection)?;
            let limits = &self.generation.state.limits;
            let candidate_baseline = self.memory.live_bytes();
            let candidates = self
                .generation
                .indexes
                .indexed_candidate_ids(&source, query, limits, cancellation, self.memory)
                .map_err(source_read_error);
            match candidates {
                Ok(candidates) => {
                    let candidate_bytes = self.memory.live_bytes() - candidate_baseline;
                    for id in candidates {
                        cancellation.check()?;
                        self.memory
                            .reserve(history_target_workspace(&query.collection, &id)?)?;
                        ids.insert((query.collection.clone(), id));
                    }
                    self.memory.release(candidate_bytes)?;
                }
                Err(error)
                    if error.code == ErrorCode::IndexRequired
                        && query.allow_scan
                        && query.search.is_none() =>
                {
                    let mut count = 0usize;
                    source
                        .visit_history_scan(cancellation, |id, archived| {
                            if count == limits.max_query_candidates {
                                return Err(Error::new(
                                    ErrorCode::ResourceExhausted,
                                    "historical scan candidate budget exceeded",
                                ));
                            }
                            count += 1;
                            if archived {
                                self.memory
                                    .reserve(history_target_workspace(&query.collection, id)?)?;
                                ids.insert((query.collection.clone(), id.to_owned()));
                            }
                            Ok(())
                        })
                        .map_err(source_read_error)?;
                }
                Err(error) => return Err(error),
            }
        }
        let id_bytes = self.memory.live_bytes() - baseline;
        let mut retained_keys = 0;
        let mut rows = Vec::new();
        let before_rows = self.memory.live_bytes();
        for (name, id) in ids {
            let source = reads.source(&name)?;
            if let Some(reference) = source
                .history_reference(&id, cancellation, |bytes| {
                    // Account for the decoded reference and geometric Vec growth
                    // while the selected reader still funds its decode.
                    self.memory.reserve(
                        bytes
                            .checked_add(
                                2 * std::mem::size_of::<(String, String, Arc<ArchivedDocument>)>()
                                    as u64,
                            )
                            .ok_or_else(query_workspace_overflow)?,
                    )
                })
                .map_err(source_read_error)?
            {
                retained_keys += history_target_workspace(&name, &id)?;
                rows.push((name, id, reference));
            }
        }
        let temporary_bytes = self.memory.live_bytes() - before_rows;
        self.memory.release(id_bytes - retained_keys)?;
        reads.check_deadline()?;
        cancellation.check()?;
        Ok(HistoryTargets {
            rows,
            temporary_bytes,
        })
    }
}

impl QueryWork {
    pub(super) fn history_inputs(&mut self) -> HistoryInputs<'_> {
        HistoryInputs {
            generation: &mut self.generation,
            keys: HistoryKeys::Points(&[]),
            queries: std::slice::from_ref(&self.request),
            memory: &mut self.memory,
            deadline: self.deadline,
            scan_reader: None,
        }
    }
}

impl SnapshotWork {
    pub(super) fn history_inputs(&mut self) -> HistoryInputs<'_> {
        HistoryInputs {
            generation: &mut self.generation,
            keys: HistoryKeys::Points(&self.request.documents),
            queries: &self.request.queries,
            memory: &mut self.memory,
            deadline: self.deadline,
            scan_reader: None,
        }
    }
}

fn history_target_workspace(collection: &str, id: &str) -> Result<u64> {
    (collection.len() as u64)
        .checked_add(id.len() as u64)
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or_else(query_workspace_overflow)
}

fn history_view_workspace(state: &TenantState) -> Result<u64> {
    // An explicit provisional allowance for cloned headers and collection
    // definitions, without serializing independently owned document/archive
    // bodies. This does not claim complete persistent-tree allocation coverage.
    let mut bytes = query_input_workspace(
        &(
            &state.tenant,
            &state.incarnation,
            &state.policy,
            &state.pending_restore,
            &state.restored_from,
            &state.restore_lineage,
            &state.lifecycle_control,
            &state.recovery_control,
            &state.active_staged_transactions,
            &state.audit_retention,
        ),
        2,
    )?;
    for (name, collection) in &state.collections {
        bytes = bytes
            .checked_add(query_input_workspace(&collection.definition, 2)?)
            .and_then(|bytes| bytes.checked_add(name.len() as u64))
            .and_then(|bytes| bytes.checked_add(1024))
            .ok_or_else(query_workspace_overflow)?;
    }
    Ok(bytes)
}
