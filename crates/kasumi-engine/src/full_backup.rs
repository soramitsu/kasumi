//! Stream one coherent resident generation, verify transitive cold objects,
//! then publish the authenticated full manifest last.
use super::*;
use crate::backup_format::*;
use std::io::Write;

/// Publication identity has no verification proof or key lineage. Only the
/// complete authenticated graph readback can construct a checkpoint.
pub(super) struct PublishedRoot {
    tenant: String,
    source_incarnation: String,
    revision: u64,
    resident_sha256: String,
    backup_id: uuid::Uuid,
    manifest_ciphertext_sha256: String,
}
impl PublishedRoot {
    pub(super) fn matches(&self, checkpoint: &FullBackupCheckpoint) -> bool {
        self.tenant == checkpoint.tenant
            && self.source_incarnation == checkpoint.source_incarnation
            && self.revision == checkpoint.revision
            && self.resident_sha256 == checkpoint.resident_sha256
            && self.backup_id == checkpoint.backup_id
            && self.manifest_ciphertext_sha256 == checkpoint.manifest_ciphertext_sha256
    }
}

struct StateStream {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
    hash: Sha256,
    total: u64,
    limit: u64,
    cancellation: QueryCancellation,
}

impl StateStream {
    fn send_chunk(&mut self) -> std::io::Result<()> {
        self.cancellation.check().map_err(std::io::Error::other)?;
        let bytes = std::mem::replace(&mut self.buffer, Vec::with_capacity(CHUNK_BYTES));
        self.sender
            .blocking_send(bytes)
            .map_err(|_| std::io::Error::other("backup consumer stopped"))
    }
    fn finish(mut self) -> std::io::Result<(u64, String)> {
        if !self.buffer.is_empty() {
            self.send_chunk()?;
        }
        Ok((self.total, hex::encode(self.hash.finalize())))
    }
}

impl Write for StateStream {
    fn write(&mut self, mut bytes: &[u8]) -> std::io::Result<usize> {
        self.cancellation.check().map_err(std::io::Error::other)?;
        let len = bytes.len();
        self.total = self
            .total
            .checked_add(len as u64)
            .filter(|value| *value <= self.limit)
            .ok_or_else(|| std::io::Error::other("backup resident state exceeds format limit"))?;
        self.hash.update(bytes);
        while !bytes.is_empty() {
            let count = bytes.len().min(CHUNK_BYTES - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == CHUNK_BYTES {
                self.send_chunk()?;
            }
        }
        Ok(len)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.cancellation.check().map_err(std::io::Error::other)
    }
}

struct StreamWork {
    generation: Arc<crate::Generation>,
    writer: StateStream,
    _reservation: Arc<Reservation>,
    _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    _registration: WorkRegistration,
}

impl StreamWork {
    fn run(mut self) -> Result<(u64, String)> {
        crate::snapshot_codec::write(&self.generation.state, &mut self.writer)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup state stream failed"))?;
        self.writer
            .finish()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup state stream incomplete"))
    }
}

impl Database {
    pub(super) async fn publish_full_backup(
        &self,
        context: RequestContext,
        destination: &dyn BackupDestination,
        session_id: uuid::Uuid,
    ) -> Result<(PublishedRoot, kasumi_store::VerifiedBackupSession)> {
        self.access()?;
        self.engine.authorize(&context, None, Action::Admin)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let _registration = self.work.begin(cancellation.clone())?;
        let permit = Arc::new(self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "backup concurrency limit reached",
            )
        })?);
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        let generation = self.engine.generation()?;
        let state = &generation.state;
        self.engine
            .authorize_release(&context, None, Action::Admin, state.policy_epoch)?;
        let reservation = Arc::new(
            self.admission()
                .reserve((96 << 20) as u64, Some(cancellation.clone()))?,
        );
        let intent = BackupSessionIntent {
            session_id,
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            revision: state.revision,
            principal: context.principal.clone(),
            request_id: context.request_id.clone(),
        };
        intent.validate()?;
        let intent_bytes = self
            .store
            .encrypt_session_record(state.revision, &intent)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup intent encryption failed"))?;
        destination
            .session_put(
                session_id,
                kasumi_store::BackupSessionSlot::Intent,
                intent_bytes,
            )
            .await
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "backup intent publication uncertain; resolve the same session identity",
                )
            })?;
        let session = self
            .backup_session(&context, destination, session_id)
            .await?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "backup intent readback unavailable",
                )
            })?;
        if session.intent() != &intent || session.outcome().is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "backup session was concurrently resolved or names another capture",
            ));
        }
        let objects = kasumi_store::BackupSessionObjects::new(destination, session_id)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid backup session"))?;
        let destination: &dyn BackupDestination = &objects;
        self.maintenance_audit_inner(context.clone(), "backup", "started", state.revision)
            .await?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let work = StreamWork {
            generation: generation.clone(),
            writer: StateStream {
                sender,
                buffer: Vec::with_capacity(CHUNK_BYTES),
                hash: Sha256::new(),
                total: 0,
                limit: state.limits.max_snapshot_bytes,
                cancellation: cancellation.clone(),
            },
            _reservation: reservation.clone(),
            _permit: permit.clone(),
            _registration: self.work.begin(cancellation.clone())?,
        };
        let producer = tokio::task::spawn_blocking(move || work.run());
        let mut chunks = Vec::with_capacity(PAGE_CHUNKS);
        let mut chunk_count = 0u64;
        let mut page_count = 0u64;
        let mut last_page = None;
        while let Some(bytes) = tokio::select! {
            bytes = receiver.recv() => bytes,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        } {
            let plaintext_bytes = bytes.len();
            let plaintext_sha256 = hex::encode(Sha256::digest(&bytes));
            let published = self
                .publish_history_object(
                    &context,
                    state.policy_epoch,
                    state.revision,
                    bytes,
                    destination,
                    &cancellation,
                )
                .await?;
            chunk_count = chunk_count
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "backup chunk overflow"))?;
            chunks.push(BackupChunk {
                object_id: published.id,
                ciphertext_sha256: published.ciphertext_sha256,
                plaintext_sha256,
                plaintext_bytes,
            });
            if chunks.len() == PAGE_CHUNKS {
                let page = BackupPage {
                    index: page_count,
                    previous: last_page.take(),
                    chunks: std::mem::replace(&mut chunks, Vec::with_capacity(PAGE_CHUNKS)),
                };
                let published = self
                    .publish_history_object(
                        &context,
                        state.policy_epoch,
                        state.revision,
                        serde_json::to_vec(&page).map_err(|_| {
                            Error::new(ErrorCode::Corruption, "backup page encoding failed")
                        })?,
                        destination,
                        &cancellation,
                    )
                    .await?;
                last_page = Some(BackupPageRef {
                    object_id: published.id,
                    ciphertext_sha256: published.ciphertext_sha256,
                });
                page_count += 1;
            }
        }
        if !chunks.is_empty() {
            let page = BackupPage {
                index: page_count,
                previous: last_page.take(),
                chunks,
            };
            let published = self
                .publish_history_object(
                    &context,
                    state.policy_epoch,
                    state.revision,
                    serde_json::to_vec(&page).map_err(|_| {
                        Error::new(ErrorCode::Corruption, "backup page encoding failed")
                    })?,
                    destination,
                    &cancellation,
                )
                .await?;
            last_page = Some(BackupPageRef {
                object_id: published.id,
                ciphertext_sha256: published.ciphertext_sha256,
            });
            page_count += 1;
        }
        let (resident_bytes, resident_sha256) = producer
            .await
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup producer failed"))??;
        let manifest = FullBackupManifest {
            kind: FullBackupKind::FullDatabase,
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            revision: state.revision,
            resident_bytes,
            resident_sha256,
            chunk_count,
            page_count,
            last_page: last_page.ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "backup manifest pages missing")
            })?,
        };
        manifest
            .validate()
            .map_err(|_| Error::new(ErrorCode::Corruption, "backup manifest invalid"))?;
        for archive in state.history_archives.values() {
            let source = self.archive_destination(&archive.storage_destination)?;
            let scoped = archive
                .storage_backup_session
                .map(|id| kasumi_store::BackupSessionObjects::new(source.as_ref(), id))
                .transpose()
                .map_err(|_| {
                    Error::new(
                        ErrorCode::Corruption,
                        "invalid history source backup session",
                    )
                })?;
            let source: &dyn BackupDestination =
                scoped.as_ref().map_or(source.as_ref(), |view| view);
            let plaintext = self
                .copy_history_dependency(
                    &context,
                    state.policy_epoch,
                    source,
                    destination,
                    &archive.manifest_object_id,
                    &archive.manifest_ciphertext_sha256,
                    MAX_ARCHIVE_MANIFEST_BYTES,
                    &cancellation,
                )
                .await?;
            let stored: HistoryArchiveManifest = serde_json::from_slice(&plaintext.snapshot)
                .map_err(|_| {
                    Error::new(ErrorCode::Corruption, "backup history manifest invalid")
                })?;
            if stored != archive.manifest {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "backup history catalog differs",
                ));
            }
            for descriptor in &archive.manifest.chunks {
                let plaintext = self
                    .copy_history_dependency(
                        &context,
                        state.policy_epoch,
                        source,
                        destination,
                        &descriptor.object_id,
                        &descriptor.ciphertext_sha256,
                        descriptor.plaintext_bytes,
                        &cancellation,
                    )
                    .await?;
                if plaintext.snapshot.len() != descriptor.plaintext_bytes
                    || hex::encode(Sha256::digest(&plaintext.snapshot))
                        != descriptor.plaintext_sha256
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "backup history plaintext differs",
                    ));
                }
            }
        }
        let bytes = serde_json::to_vec(&manifest).map_err(|_| {
            Error::new(
                ErrorCode::Corruption,
                "full backup manifest encoding failed",
            )
        })?;
        let published = self
            .publish_history_object_named(
                &context,
                state.policy_epoch,
                state.revision,
                session_id,
                bytes,
                destination,
                &cancellation,
            )
            .await?;
        self.maintenance_audit_inner(context.clone(), "backup", "completed", state.revision)
            .await?;
        self.engine
            .authorize_release(&context, None, Action::Admin, state.policy_epoch)?;
        self.admission().check_release(&cancellation)?;
        self.access()?;
        Ok((
            PublishedRoot {
                tenant: manifest.tenant,
                source_incarnation: manifest.source_incarnation,
                revision: manifest.revision,
                resident_sha256: manifest.resident_sha256,
                backup_id: published.id,
                manifest_ciphertext_sha256: published.ciphertext_sha256,
            },
            session,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn copy_history_dependency(
        &self,
        context: &RequestContext,
        policy_epoch: u64,
        source: &dyn BackupDestination,
        destination: &dyn BackupDestination,
        object_id: &str,
        ciphertext_sha256: &str,
        max_plaintext: usize,
        cancellation: &QueryCancellation,
    ) -> Result<kasumi_store::BackupContents> {
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        let verified = self
            .verified_history_object(
                source,
                object_id,
                ciphertext_sha256,
                max_plaintext,
                cancellation,
            )
            .await?;
        let id = uuid::Uuid::parse_str(object_id)
            .map_err(|_| Error::new(ErrorCode::Corruption, "history object identity invalid"))?;
        let bytes = tokio::select! {
            result = source.get(id, max_plaintext.saturating_add(OBJECT_OVERHEAD)) =>
                result.map_err(|_| Error::new(ErrorCode::Unavailable, "backup history source unavailable"))?,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        if hex::encode(Sha256::digest(&bytes)) != ciphertext_sha256 {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup history source changed",
            ));
        }
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        let _put_result = tokio::select! {
            result = destination.put(id, bytes) => result,
            _ = cancelled(cancellation) => return Err(cancelled_error()),
        };
        let copied = self
            .verified_history_object(
                destination,
                object_id,
                ciphertext_sha256,
                max_plaintext,
                cancellation,
            )
            .await?;
        if copied.snapshot != verified.snapshot {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup history destination differs",
            ));
        }
        self.engine
            .authorize_release(context, None, Action::Admin, policy_epoch)?;
        Ok(copied)
    }
}
