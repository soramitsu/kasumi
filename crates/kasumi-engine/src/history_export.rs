//! Administrative prefix export with chunk-by-chunk authenticated verification
//! before one replicated publication removes any resident source bodies.
use super::*;

impl Database {
    pub async fn archive_history(
        &self,
        context: RequestContext,
        request: ArchiveHistory,
    ) -> Result<WriteReceipt> {
        let result = self.archive_history_inner(&context, request).await;
        self.audit_result(&context, result).await
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
        let _slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "archive export concurrency limit reached",
            )
        })?;
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
        let _reservation = self.admission().reserve(
            (MAX_ARCHIVE_SOURCE_BYTES * 3) as u64,
            Some(cancellation.clone()),
        )?;
        let mut selected = BTreeMap::new();
        let mut source_bytes = 0usize;
        for (id, document) in &collection.documents {
            cancellation.check()?;
            if document.version > request.cutoff_revision {
                continue;
            }
            source_bytes = source_bytes
                .checked_add(crate::accounting::encoded_len(&document.body)?)
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "archive source size overflow")
                })?;
            if source_bytes > MAX_ARCHIVE_SOURCE_BYTES || selected.len() >= MAX_ARCHIVE_DOCUMENTS {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "archive prefix exceeds bounded export capacity; choose an earlier cutoff",
                ));
            }
            selected.insert(id.clone(), document.clone());
        }
        if selected.is_empty() {
            return Err(Error::new(
                ErrorCode::NotFound,
                "archive prefix has no hot source documents",
            ));
        }
        let destination = self.archive_destination(&request.destination)?;
        self.maintenance_audit_inner(context.clone(), "archive", "started", state.revision)
            .await?;
        let mut manifest = HistoryArchiveManifest {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: request.archive_id.clone(),
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            collection: request.collection.clone(),
            cutoff_revision: request.cutoff_revision,
            source_schema_epoch: state.schema_epoch,
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
        for document in selected.into_values() {
            cancellation.check()?;
            let bytes = crate::accounting::encoded_len(&document)?.saturating_add(1);
            if chunk_bytes.saturating_add(bytes) > MAX_ARCHIVE_CHUNK_BYTES
                && !chunk.documents.is_empty()
            {
                manifest.chunks.push(
                    self.export_history_chunk(
                        context,
                        state.policy_epoch,
                        &chunk,
                        destination.as_ref(),
                        &cancellation,
                    )
                    .await?,
                );
                chunk.documents.clear();
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
            chunk.documents.push(document);
        }
        if !chunk.documents.is_empty() {
            manifest.chunks.push(
                self.export_history_chunk(
                    context,
                    state.policy_epoch,
                    &chunk,
                    destination.as_ref(),
                    &cancellation,
                )
                .await?,
            );
        }
        crate::state::history::validate_manifest(&manifest)?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|_| Error::new(ErrorCode::Corruption, "archive manifest encoding failed"))?;
        let (manifest_object_id, manifest_ciphertext_sha256) = self
            .publish_history_object(
                context,
                state.policy_epoch,
                state.revision,
                bytes,
                destination.as_ref(),
                &cancellation,
            )
            .await?;
        self.engine
            .authorize_release(context, None, Action::Admin, state.policy_epoch)?;
        self.submit(
            context.clone(),
            Operation::PublishHistoryArchive(PublishHistoryArchive {
                manifest,
                manifest_object_id,
                manifest_ciphertext_sha256,
                expected_policy_epoch: state.policy_epoch,
            }),
        )
        .await
    }

    async fn export_history_chunk(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        chunk: &HistoryArchiveChunk,
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
        let (object_id, ciphertext_sha256) = self
            .publish_history_object(
                context,
                policy_epoch,
                revision,
                bytes,
                destination,
                cancellation,
            )
            .await?;
        Ok(ArchiveChunkDescriptor {
            object_id,
            ciphertext_sha256,
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
    ) -> Result<(String, String)> {
        cancellation.check()?;
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        let expected_plaintext = hex::encode(Sha256::digest(&plaintext));
        let max_plaintext_bytes = plaintext.len();
        let encrypted = self
            .store
            .encrypt_backup(revision, &plaintext)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "history encryption failed"))?;
        drop(plaintext);
        let id = encrypted.id();
        let bytes = encrypted.to_bytes().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "history object exceeds encoding bound",
            )
        })?;
        let digest = hex::encode(Sha256::digest(&bytes));
        // A transport failure may follow a durable create. Verify the same
        // immutable object before deciding whether publication can proceed.
        let _put_result = tokio::select! {
            result = destination.put(id, bytes) => result,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        cancellation.check()?;
        let verified = self
            .verified_history_object(
                destination,
                &id.to_string(),
                &digest,
                max_plaintext_bytes,
                cancellation,
            )
            .await?;
        if hex::encode(Sha256::digest(&verified.snapshot)) != expected_plaintext {
            return Err(Error::new(
                ErrorCode::Corruption,
                "published history plaintext differs",
            ));
        }
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        Ok((id.to_string(), digest))
    }
}
