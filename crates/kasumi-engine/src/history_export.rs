//! Administrative prefix export with chunk-by-chunk authenticated verification
//! before one replicated publication removes any resident source bodies.
use super::*;

pub(super) struct PublishedObject {
    pub id: uuid::Uuid,
    pub ciphertext_sha256: String,
}

/// Stable object names bind the logical request and its lineage, never a body
/// digest. All replicas derive the same names; create-only publication chooses
/// one encrypted representation, whose plaintext every adopter authenticates.
struct ArchiveObjectIds(Sha256);

impl ArchiveObjectIds {
    fn new(state: &TenantState, request: &ArchiveHistory) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"kasumi-history-archive-objects-v1");
        for value in [
            &state.tenant,
            &state.incarnation,
            &request.archive_id,
            &request.collection,
            &request.destination,
        ] {
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(request.cutoff_revision.to_le_bytes());
        Self(digest)
    }

    fn object(&self, chunk: Option<usize>) -> uuid::Uuid {
        let mut digest = self.0.clone();
        match chunk {
            Some(index) => {
                digest.update(b"chunk");
                digest.update((index as u64).to_le_bytes());
            }
            None => digest.update(b"manifest"),
        }
        let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("digest prefix");
        // RFC 9562 custom UUID (version 8), with 122 bits of request identity.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(bytes)
    }
}

/// Archive identities that requests of this node are exporting or publishing.
/// A publication proposal outlives a caller whose write deadline expires and
/// may still commit. An identical request meanwhile waits for it instead of
/// exporting a second object set, which publication would reject and nothing
/// would reclaim. A different request for the identity is rejected, as it is
/// once the archive applies.
#[derive(Default)]
pub(super) struct ArchiveFlights {
    flights: Mutex<BTreeMap<String, Arc<ArchiveFlight>>>,
    #[cfg(test)]
    test: ArchiveFlightTest,
}

/// One archive identity claimed by a request of this node.
struct ArchiveFlight {
    collection: String,
    cutoff_revision: u64,
    destination: String,
    /// The claiming request has not returned.
    claimed: AtomicBool,
    /// Its publication proposal, once admitted.
    publication: std::sync::OnceLock<proposal_jobs::Admitted>,
    notify: tokio::sync::Notify,
}

enum ArchiveClaim<'a> {
    Owner(ArchiveFlightOwner<'a>),
    InFlight(Arc<ArchiveFlight>),
}

/// The claiming request's hold on its flight, released when it returns or is
/// cancelled. An admitted publication keeps the flight until it terminates.
struct ArchiveFlightOwner<'a> {
    flights: &'a ArchiveFlights,
    archive_id: String,
    flight: Arc<ArchiveFlight>,
}

#[cfg(test)]
#[derive(Default)]
struct ArchiveFlightTest {
    wait_budget: Mutex<Option<Duration>>,
    waits: AtomicU64,
}

impl ArchiveFlights {
    fn claim(&self, request: &ArchiveHistory) -> Result<ArchiveClaim<'_>> {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        // Retire flights that can no longer change their identity. The rest
        // are running claims and unfinished publications, both bounded.
        flights.retain(|_, flight| !flight.settled());
        if let Some(flight) = flights.get(&request.archive_id) {
            if flight.collection != request.collection
                || flight.cutoff_revision != request.cutoff_revision
                || flight.destination != request.destination
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "archive identity reused for different request",
                ));
            }
            return Ok(ArchiveClaim::InFlight(flight.clone()));
        }
        let flight = Arc::new(ArchiveFlight {
            collection: request.collection.clone(),
            cutoff_revision: request.cutoff_revision,
            destination: request.destination.clone(),
            claimed: AtomicBool::new(true),
            publication: std::sync::OnceLock::new(),
            notify: tokio::sync::Notify::new(),
        });
        flights.insert(request.archive_id.clone(), flight.clone());
        Ok(ArchiveClaim::Owner(ArchiveFlightOwner {
            flights: self,
            archive_id: request.archive_id.clone(),
            flight,
        }))
    }

    /// Wait for `flight` to change, for at most the write deadline that an
    /// identical request has. Its expiry is the same uncertain outcome.
    async fn wait(
        &self,
        flight: &ArchiveFlight,
        deadline: tokio::time::Instant,
        cancellation: &QueryCancellation,
    ) -> Result<()> {
        #[cfg(test)]
        self.test.waits.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            () = flight.changed() => Ok(()),
            () = tokio::time::sleep_until(deadline) => Err(Error::new(
                ErrorCode::UnknownOutcome,
                "write deadline exceeded; resolve or retry with the same idempotency key",
            )),
            () = cancelled(cancellation) => Err(cancelled_error()),
        }
    }

    fn wait_budget(&self) -> Duration {
        #[cfg(test)]
        if let Some(budget) = *self
            .test
            .wait_budget
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            return budget;
        }
        kasumi_store::NATIVE_WRITE_TIMEOUT
    }
}

impl ArchiveFlight {
    /// Neither the claiming request nor its publication can still change the
    /// archive identity.
    fn settled(&self) -> bool {
        !self.claimed.load(Ordering::Acquire)
            && self
                .publication
                .get()
                .is_none_or(proposal_jobs::Admitted::finished)
    }

    /// Return once this flight may have changed: its claiming request returned,
    /// its publication was admitted, or that publication terminated.
    async fn changed(&self) {
        // Created before reading the state, so no later notification is lost.
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        match self.publication.get() {
            // Nothing notifies when a publication that outlived its claiming
            // request terminates.
            Some(publication) if !publication.finished() => tokio::select! {
                () = &mut notified => {}
                () = publication.finish() => {}
            },
            // The claiming request notifies when it records its publication
            // and when it returns. Once it has returned, nothing can change.
            _ if self.claimed.load(Ordering::Acquire) => notified.await,
            _ => {}
        }
    }
}

impl ArchiveFlightOwner<'_> {
    fn published(&self, publication: proposal_jobs::Admitted) {
        let _ = self.flight.publication.set(publication);
        self.flight.notify.notify_waiters();
    }
}

impl Drop for ArchiveFlightOwner<'_> {
    fn drop(&mut self) {
        self.flight.claimed.store(false, Ordering::Release);
        if self.flight.settled() {
            let mut flights = self
                .flights
                .flights
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if flights
                .get(&self.archive_id)
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
            {
                flights.remove(&self.archive_id);
            }
        }
        self.flight.notify.notify_waiters();
    }
}

#[cfg(test)]
impl ArchiveFlights {
    pub(super) fn set_wait_budget_for_test(&self, budget: Duration) {
        *self
            .test
            .wait_budget
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(budget);
    }

    /// Drive `request` until it waits for an in-flight archive of this node.
    pub(super) async fn wait_for_waiter_for_test<F: Future>(
        &self,
        mut request: std::pin::Pin<&mut F>,
    ) {
        let before = self.test.waits.load(Ordering::SeqCst);
        std::future::poll_fn(|cx| {
            assert!(
                request.as_mut().poll(cx).is_pending(),
                "request completed before waiting for the in-flight archive"
            );
            if self.test.waits.load(Ordering::SeqCst) > before {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
    }

    /// Whether `archive_id` has an admitted publication that has not finished.
    pub(super) fn publishing_for_test(&self, archive_id: &str) -> bool {
        self.flights
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(archive_id)
            .and_then(|flight| flight.publication.get())
            .is_some_and(|publication| !publication.finished())
    }
}

fn bundle_output_error(error: anyhow::Error) -> Error {
    if let Some(admission) = error.downcast_ref::<kasumi_store::BackupBundleAdmissionError>()
        && admission.kind() != std::io::ErrorKind::OutOfMemory
    {
        return Error::new(
            ErrorCode::Unavailable,
            "history bundle memory owner unavailable",
        );
    }
    Error::new(
        ErrorCode::ResourceExhausted,
        "history object exceeds encoding bound",
    )
}

impl Database {
    pub async fn archive_history(
        &self,
        context: RequestContext,
        request: ArchiveHistory,
    ) -> Result<WriteReceipt> {
        let result = self.archive_history_inner(&context, request).await;
        self.audit_write_result(&context, result).await
    }

    async fn archive_history_inner(
        &self,
        context: &RequestContext,
        request: ArchiveHistory,
    ) -> Result<WriteReceipt> {
        for name in [
            &request.archive_id,
            &request.collection,
            &request.destination,
        ] {
            validate_name(name)?;
        }
        self.engine.authorize(context, None, Action::Admin)?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Admin)?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        self.access()?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let _registration = self.work.begin(cancellation.clone())?;
        let mut wait_deadline = None;
        let (generation, flight) = loop {
            tokio::select! {
                result = self.barrier() => result?,
                _ = cancelled(&cancellation) => return Err(cancelled_error()),
            }
            let generation = self.engine.generation()?;
            let state = &generation.state;
            self.engine
                .authorize_release(context, None, Action::Admin, state.policy_epoch)?;
            if let Some(existing) = state.history_archives.get(&request.archive_id) {
                let manifest = &existing.manifest;
                if manifest.collection != request.collection
                    || manifest.cutoff_revision != request.cutoff_revision
                    || manifest.destination != request.destination
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "archive identity reused for different request",
                    ));
                }
                self.release_event(
                    context,
                    Some(&request.collection),
                    state.revision,
                    state.policy.strict_read_audit
                        || state.collections[&request.collection]
                            .definition
                            .strict_read_audit,
                    state.policy_epoch,
                    "archive_receipt",
                )
                .await?;
                self.engine.authorize_release(
                    context,
                    Some(&request.collection),
                    Action::Admin,
                    state.policy_epoch,
                )?;
                self.access()?;
                return Ok(WriteReceipt {
                    revision: existing.published_revision,
                    versions: BTreeMap::new(),
                });
            }
            match self.archive_flights.claim(&request)? {
                ArchiveClaim::Owner(flight) => {
                    // A publication that settled after `generation` was read
                    // is visible now: replay or reject it as above.
                    if self
                        .engine
                        .generation()?
                        .state
                        .history_archives
                        .contains_key(&request.archive_id)
                    {
                        continue;
                    }
                    break (generation, flight);
                }
                // An identical request is exporting or publishing this archive.
                // Its outcome decides this one; never export a second copy.
                ArchiveClaim::InFlight(in_flight) => {
                    drop(generation);
                    let deadline = *wait_deadline.get_or_insert_with(|| {
                        tokio::time::Instant::now() + self.archive_flights.wait_budget()
                    });
                    self.archive_flights
                        .wait(&in_flight, deadline, &cancellation)
                        .await?;
                }
            }
        };
        let state = &generation.state;
        // Only the claiming request holds an export slot, never a waiter.
        let _slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "archive export concurrency limit reached",
            )
        })?;
        if request.cutoff_revision > state.revision
            || state.history_archives.len() >= state.limits.history.max_archive_segments
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "archive cutoff or catalog capacity outside bounds",
            ));
        }
        let collection = state
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "archive collection missing"))?;
        if collection.definition.retention_class != CollectionRetentionClass::ArchivableHistory
            || collection.definition.write_mode != CollectionWriteMode::AppendOnly
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "collection is not eligible for archival",
            ));
        }
        if collection
            .definition
            .indexes
            .iter()
            .any(|index| index.text.is_some())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "text-indexed history needs supported cold text storage",
            ));
        }
        // Validate the immutable prefix while borrowing its existing owners.
        // The export workspace is not live during the ordered start audit.
        let mut selected_count = 0usize;
        let mut source_bytes = 0usize;
        for document in collection.documents.values() {
            cancellation.check()?;
            if document.version() > request.cutoff_revision {
                continue;
            }
            source_bytes = source_bytes
                .checked_add(
                    usize::try_from(document.body_bytes().map_err(document_load_error)?)
                        .map_err(|_| query_workspace_overflow())?,
                )
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "archive source size overflow")
                })?;
            if source_bytes > MAX_ARCHIVE_SOURCE_BYTES || selected_count >= MAX_ARCHIVE_DOCUMENTS {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "archive prefix exceeds bounded export capacity; choose an earlier cutoff",
                ));
            }
            selected_count += 1;
        }
        if selected_count == 0 {
            return Err(Error::new(
                ErrorCode::NotFound,
                "archive prefix has no hot source documents",
            ));
        }
        let destination = self.archive_destination(&request.destination)?;
        self.maintenance_audit_inner(context.clone(), "archive", "started", state.revision)
            .await?;
        let export_floor = (MAX_ARCHIVE_SOURCE_BYTES * 3) as u64;
        let mut reservation = self
            .admission()
            .reserve(export_floor, Some(cancellation.clone()))?;
        let mut selected = BTreeMap::new();
        for (id, document) in &collection.documents {
            cancellation.check()?;
            if document.version() <= request.cutoff_revision {
                selected.insert(id.clone(), document.clone());
            }
        }
        let object_ids = ArchiveObjectIds::new(state, &request);
        let mut manifest = HistoryArchiveManifest {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: request.archive_id.clone(),
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            collection: request.collection.clone(),
            cutoff_revision: request.cutoff_revision,
            destination: request.destination,
            document_count: selected.len(),
            chunks: vec![],
        };
        let mut chunk = HistoryArchiveChunk {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: request.archive_id,
            source_incarnation: state.incarnation.clone(),
            collection: request.collection.clone(),
            index: 0,
            documents: vec![],
        };
        let mut chunk_bytes = crate::accounting::encoded_len(&chunk)?.saturating_add(16);
        let mut chunk_clone_bytes = 0u64;
        for document in selected.into_values() {
            cancellation.check()?;
            let bytes = usize::try_from(document.document_bytes().map_err(document_load_error)?)
                .map_err(|_| query_workspace_overflow())?
                .saturating_add(1);
            if chunk_bytes.saturating_add(bytes) > MAX_ARCHIVE_CHUNK_BYTES
                && !chunk.documents.is_empty()
            {
                manifest.chunks.push(
                    self.export_history_chunk(
                        context,
                        state.policy_epoch,
                        &chunk,
                        object_ids.object(Some(chunk.index)),
                        destination.as_ref(),
                        &cancellation,
                    )
                    .await?,
                );
                chunk.documents.clear();
                // Keep the operation's admitted peak and slot until export
                // completes; a smaller following chunk reuses that workspace.
                chunk_clone_bytes = 0;
                chunk.index += 1;
                chunk_bytes = crate::accounting::encoded_len(&chunk)?.saturating_add(16);
            }
            if chunk_bytes.saturating_add(bytes) > MAX_ARCHIVE_CHUNK_BYTES {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "history document exceeds chunk limit",
                ));
            }
            chunk_bytes += bytes;
            match document.as_ref() {
                DocumentSlot::Pending(document) => chunk.documents.push(document.clone()),
                DocumentSlot::Stored(_) => {
                    let document = generation
                        .load_document(&document)
                        .map_err(document_load_error)?;
                    cancellation.check()?;
                    chunk_clone_bytes = chunk_clone_bytes
                        .checked_add(
                            kasumi_query::document_clone_bytes(&document)?
                                .checked_add(point_read::point_arc_bytes::<Document>()?)
                                .ok_or_else(query_workspace_overflow)?,
                        )
                        .ok_or_else(query_workspace_overflow)?;
                    kasumi_query::QueryWorkspace::ensure_peak(
                        &mut reservation,
                        export_floor
                            .checked_add(chunk_clone_bytes)
                            .ok_or_else(query_workspace_overflow)?,
                    )?;
                    chunk.documents.push(Arc::new(document.as_ref().clone()));
                }
            }
        }
        if !chunk.documents.is_empty() {
            manifest.chunks.push(
                self.export_history_chunk(
                    context,
                    state.policy_epoch,
                    &chunk,
                    object_ids.object(Some(chunk.index)),
                    destination.as_ref(),
                    &cancellation,
                )
                .await?,
            );
        }
        crate::state::history::validate_manifest(&manifest)?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|_| Error::new(ErrorCode::Corruption, "archive manifest encoding failed"))?;
        let published = self
            .publish_history_object_inner(
                context,
                state.policy_epoch,
                state.revision,
                object_ids.object(None),
                true,
                bytes,
                destination.as_ref(),
                &cancellation,
            )
            .await?;
        // The selection iterator is exhausted and publication returned. Destroy
        // the final chunk's actual vector and aliases before releasing their
        // workspace. The manifest stays covered by this original grant until
        // submit installs its independently admitted command owner.
        drop(chunk);
        reservation.handoff_workspace(self.admission(), manifest_workspace(&manifest)?)?;
        self.engine
            .authorize_release(context, None, Action::Admin, state.policy_epoch)?;
        // The flight keeps the admitted publication after this caller's write
        // deadline, until it commits or fails.
        self.submit_input_observed(
            context.clone(),
            proposal_input::OperationInput::ordinary(Operation::PublishHistoryArchive(
                PublishHistoryArchive {
                    manifest,
                    manifest_object_id: published.id.to_string(),
                    manifest_ciphertext_sha256: published.ciphertext_sha256,
                    expected_policy_epoch: state.policy_epoch,
                    expected_schema_epoch: state.schema_epoch,
                },
            )),
            |publication| flight.published(publication),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn export_history_chunk(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        chunk: &HistoryArchiveChunk,
        id: uuid::Uuid,
        destination: &dyn BackupDestination,
        cancellation: &QueryCancellation,
    ) -> Result<ArchiveChunkDescriptor> {
        let bytes = serde_json::to_vec(chunk)
            .map_err(|_| Error::new(ErrorCode::Corruption, "archive chunk encoding failed"))?;
        if bytes.len() > MAX_ARCHIVE_CHUNK_BYTES {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "archive chunk exceeds encoding bound",
            ));
        }
        let plaintext_bytes = bytes.len();
        let plaintext_sha256 = hex::encode(Sha256::digest(&bytes));
        let revision = chunk
            .documents
            .iter()
            .map(|document| document.version)
            .max()
            .unwrap_or(0);
        let published = self
            .publish_history_object_inner(
                context,
                policy_epoch,
                revision,
                id,
                true,
                bytes,
                destination,
                cancellation,
            )
            .await?;
        Ok(ArchiveChunkDescriptor {
            object_id: published.id.to_string(),
            ciphertext_sha256: published.ciphertext_sha256,
            plaintext_sha256,
            plaintext_bytes,
            document_count: chunk.documents.len(),
            first_id: chunk.documents.first().expect("nonempty chunk").id.clone(),
            last_id: chunk.documents.last().expect("nonempty chunk").id.clone(),
        })
    }

    pub(super) async fn publish_history_object(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        revision: u64,
        plaintext: Vec<u8>,
        destination: &dyn BackupDestination,
        cancellation: &QueryCancellation,
    ) -> Result<PublishedObject> {
        self.publish_history_object_named(
            context,
            policy_epoch,
            revision,
            uuid::Uuid::new_v4(),
            plaintext,
            destination,
            cancellation,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn publish_history_object_named(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        revision: u64,
        id: uuid::Uuid,
        plaintext: Vec<u8>,
        destination: &dyn BackupDestination,
        cancellation: &QueryCancellation,
    ) -> Result<PublishedObject> {
        self.publish_history_object_inner(
            context,
            policy_epoch,
            revision,
            id,
            false,
            plaintext,
            destination,
            cancellation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_history_object_inner(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        revision: u64,
        id: uuid::Uuid,
        adopt_identical: bool,
        plaintext: Vec<u8>,
        destination: &dyn BackupDestination,
        cancellation: &QueryCancellation,
    ) -> Result<PublishedObject> {
        cancellation.check()?;
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        let expected_plaintext = hex::encode(Sha256::digest(&plaintext));
        let max_plaintext_bytes = plaintext.len();
        let encrypted = self
            .store
            .encrypt_backup_with_id(id, revision, &plaintext)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "history encryption failed"))?;
        drop(plaintext);
        let id = encrypted.id();
        let bytes = encrypted.to_bytes().map_err(bundle_output_error)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        // A transport failure may follow a durable create. Verify the same
        // immutable object before deciding whether publication can proceed.
        let _put_result = tokio::select! {
            result = destination.put(id, bytes.into()) => result,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        cancellation.check()?;
        let verified = if adopt_identical {
            // A competing replica encrypts with a fresh nonce, so its ciphertext
            // cannot match ours. Authenticate the immutable winner first, then
            // compare its complete plaintext with the locally selected prefix.
            // A filesystem .pending file is never adopted or overwritten: get
            // cannot see it and reports a retryable unavailable outcome.
            let limit = max_plaintext_bytes.saturating_add((2 << 20) + 84);
            let bytes = tokio::select! {
                result = destination.get(id, limit) => result.map_err(|_| Error::new(
                    ErrorCode::Unavailable, "required history object is missing or unavailable"))?,
                _ = cancelled(cancellation) => return Err(cancelled_error()),
            };
            let contents = tokio::select! {
                result = self.store.decrypt_backup_object(&bytes, id, max_plaintext_bytes) => result.map_err(|_| Error::new(
                    ErrorCode::Unavailable, "history authentication or historical key authorization failed"))?,
                _ = cancelled(cancellation) => return Err(cancelled_error()),
            };
            self.access()?;
            contents
        } else {
            self.verified_history_object(
                destination,
                &id.to_string(),
                &digest,
                max_plaintext_bytes,
                cancellation,
            )
            .await?
        };
        if hex::encode(Sha256::digest(&verified.snapshot)) != expected_plaintext {
            return Err(Error::new(
                if adopt_identical {
                    ErrorCode::Conflict
                } else {
                    ErrorCode::Corruption
                },
                "published history plaintext differs",
            ));
        }
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        Ok(PublishedObject {
            id,
            ciphertext_sha256: verified.ciphertext_sha256,
        })
    }
}

fn manifest_workspace(manifest: &HistoryArchiveManifest) -> Result<u64> {
    fn overflow() -> Error {
        Error::new(
            ErrorCode::ResourceExhausted,
            "archive manifest workspace overflow",
        )
    }
    fn backing(bytes: usize) -> Result<u64> {
        if bytes == 0 {
            return Ok(0);
        }
        bytes
            .checked_next_power_of_two()
            .and_then(|bytes| bytes.checked_add(4096))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)
    }
    fn add(total: &mut u64, bytes: usize) -> Result<()> {
        *total = total.checked_add(backing(bytes)?).ok_or_else(overflow)?;
        Ok(())
    }
    // Actual live capacities, with allocation rounding and per-allocation
    // allowance. Fixed local custody and bounded publication identities remain
    // covered until the command has taken ownership.
    let mut total = 64 << 10;
    add(
        &mut total,
        manifest
            .chunks
            .capacity()
            .checked_mul(std::mem::size_of::<ArchiveChunkDescriptor>())
            .ok_or_else(overflow)?,
    )?;
    for value in [
        &manifest.archive_id,
        &manifest.tenant,
        &manifest.source_incarnation,
        &manifest.collection,
        &manifest.destination,
    ] {
        add(&mut total, value.capacity())?;
    }
    for chunk in &manifest.chunks {
        for value in [
            &chunk.object_id,
            &chunk.ciphertext_sha256,
            &chunk.plaintext_sha256,
            &chunk.first_id,
            &chunk.last_id,
        ] {
            add(&mut total, value.capacity())?;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod flight_tests {
    use super::*;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn archive_object_names_bind_request_and_lineage_without_live_epoch_or_revision() {
        let engine = TenantEngine::new(
            "tenant".into(),
            "incarnation".into(),
            Policy {
                grants: vec![kasumi_types::Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Admin].into_iter().collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let generation = engine.generation().unwrap();
        let mut state = generation.state.clone();
        let request = ArchiveHistory {
            archive_id: "period".into(),
            collection: "history".into(),
            cutoff_revision: 7,
            destination: "cold".into(),
        };
        let ids = ArchiveObjectIds::new(&state, &request);
        let first = ids.object(Some(0));
        let manifest = ids.object(None);
        assert_ne!(first, manifest);
        assert_ne!(first, ids.object(Some(1)));
        state.revision += 1;
        state.schema_epoch += 1;
        assert_eq!(
            first,
            ArchiveObjectIds::new(&state, &request).object(Some(0))
        );
        assert_eq!(
            manifest,
            ArchiveObjectIds::new(&state, &request).object(None)
        );
        for field in 0..4 {
            let mut other = request.clone();
            match field {
                0 => other.archive_id.push('x'),
                1 => other.collection.push('x'),
                2 => other.destination.push('x'),
                _ => other.cutoff_revision += 1,
            }
            assert_ne!(first, ArchiveObjectIds::new(&state, &other).object(Some(0)));
        }
        state.tenant.push('x');
        assert_ne!(
            first,
            ArchiveObjectIds::new(&state, &request).object(Some(0))
        );
        state.tenant.pop();
        state.incarnation.push('x');
        assert_ne!(
            first,
            ArchiveObjectIds::new(&state, &request).object(Some(0))
        );
    }

    fn flight(claimed: bool, publication: Option<proposal_jobs::Admitted>) -> ArchiveFlight {
        let flight = ArchiveFlight {
            collection: "history".into(),
            cutoff_revision: 1,
            destination: "cold".into(),
            claimed: AtomicBool::new(claimed),
            publication: std::sync::OnceLock::new(),
            notify: tokio::sync::Notify::new(),
        };
        if let Some(publication) = publication {
            assert!(flight.publication.set(publication).is_ok());
        }
        flight
    }

    fn poll_once(changed: std::pin::Pin<&mut impl Future<Output = ()>>) -> Poll<()> {
        changed.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn a_waiter_returns_at_once_when_nothing_can_change_the_flight() {
        // The claiming request returned, and it admitted no publication or its
        // publication has finished, even while this waiter was setting up.
        for publication in [None, Some(proposal_jobs::Admitted::dropped_for_test())] {
            let flight = flight(false, publication);
            assert!(flight.settled());
            assert_eq!(poll_once(std::pin::pin!(flight.changed())), Poll::Ready(()));
        }
    }

    #[test]
    fn a_waiter_waits_for_the_claiming_request_after_its_publication_finished() {
        let flight = flight(true, Some(proposal_jobs::Admitted::dropped_for_test()));
        assert!(!flight.settled());
        let mut changed = std::pin::pin!(flight.changed());
        assert_eq!(poll_once(changed.as_mut()), Poll::Pending);
        // What the claiming request's guard does when it returns.
        flight.claimed.store(false, Ordering::Release);
        flight.notify.notify_waiters();
        assert_eq!(poll_once(changed.as_mut()), Poll::Ready(()));
        assert!(flight.settled());
    }
}

#[cfg(test)]
mod bundle_output_tests {
    use super::*;

    #[test]
    fn non_capacity_bundle_owner_failure_is_unavailable() {
        let owner_failure = kasumi_store::BackupBundleAdmissionError::from(std::io::Error::other(
            "installed owner failed",
        ));
        let error = bundle_output_error(owner_failure.into());
        assert_eq!(error.code, ErrorCode::Unavailable);

        let capacity = kasumi_store::BackupBundleAdmissionError::from(std::io::Error::from(
            std::io::ErrorKind::OutOfMemory,
        ));
        let error = bundle_output_error(capacity.into());
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }
}
