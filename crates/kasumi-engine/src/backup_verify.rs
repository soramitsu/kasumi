//! One complete-graph verifier shared by current administrative readback and
//! empty-target restore. Reader implementations own their authority boundary.
use crate::{
    admission::{NodeAdmission, Reservation, WorkRegistration},
    backup_format::*,
};
use kasumi_types::*;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    sync::Arc,
};
#[path = "backup_history_work.rs"]
mod history_work;

pub(crate) struct VerificationWork {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _registration: WorkRegistration,
    target: Option<(
        Arc<crate::TargetLifecycleInvocation>,
        kasumi_query::QueryCancellation,
        Arc<crate::TargetRequestAdmission>,
    )>,
}
impl VerificationWork {
    pub(crate) fn for_target(
        registration: WorkRegistration,
        permit: tokio::sync::OwnedSemaphorePermit,
        target: Arc<crate::TargetLifecycleInvocation>,
        token: kasumi_query::QueryCancellation,
        admission: Arc<crate::TargetRequestAdmission>,
    ) -> Arc<Self> {
        Arc::new(Self {
            _permit: permit,
            _registration: registration,
            target: Some((target, token, admission)),
        })
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some((target, token, admission)) = &self.target {
            admission.check()?;
            token.check()?;
            target.check()?;
        }
        Ok(())
    }
    pub(crate) fn binds(&self, target: &crate::TargetLifecycleInvocation) -> bool {
        self.target
            .as_ref()
            .is_some_and(|(actual, _, _)| Arc::ptr_eq(actual.gate(), target.gate()))
    }
    pub fn new(
        registration: WorkRegistration,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Arc<Self> {
        Arc::new(Self {
            _permit: permit,
            _registration: registration,
            target: None,
        })
    }
}

pub(crate) trait BackupReader: Sync {
    fn scratch_disk(&self) -> &Arc<kasumi_store::ScratchDisk>;
    fn tenant(&self) -> &str;
    fn session_key_catalog(&self) -> &str;
    fn work_registration(&self) -> Option<Arc<VerificationWork>>;
    fn cancellation(&self) -> Option<kasumi_query::QueryCancellation>;
    fn check_access(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn authorize_state<'a>(
        &'a self,
        state: &'a TenantState,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a;
    fn audit_target(&self) -> Option<Arc<kasumi_store::TenantStore>>;
    fn audit_dependency<'a>(
        &'a self,
        state: &'a VerifiedState,
        root: &'a kasumi_store::StoragePurpose,
        link: &'a AuditArchiveLink,
    ) -> impl Future<Output = anyhow::Result<kasumi_store::PreparedAuditSegment>> + Send + 'a;
    fn object<'a>(
        &'a self,
        id: uuid::Uuid,
        max_plaintext: usize,
        expected_ciphertext: Option<&'a str>,
        history: bool,
    ) -> impl Future<Output = anyhow::Result<kasumi_store::BackupContents>> + Send + 'a;
}

/// This private graph boundary authorizes the exact original application purpose
/// from authenticated state/lineage before fresh unwrap and AEAD verification.
pub(crate) async fn verify_audit_dependency(
    state: &TenantState,
    root: &kasumi_store::StoragePurpose,
    store: &kasumi_store::TenantStore,
    ciphertext: &[u8],
    link: &AuditArchiveLink,
) -> anyhow::Result<AuditArchiveReference> {
    let dependency = kasumi_store::InspectedAuditDependency::from_link(ciphertext, link)?;
    anyhow::ensure!(
        dependency.source_tenant() == state.tenant
            && dependency.reference().stream_id == state.audit_retention.stream_id,
        "backup audit stream differs"
    );
    crate::authorize_audit_source(state, root, dependency.source_purpose())?;
    let verified = store
        .verify_historical_audit(&dependency, dependency.source_purpose())
        .await?;
    Ok(verified.reference().clone())
}

pub(crate) async fn verify_indexed_audit_dependency(
    state: &VerifiedState,
    root: &kasumi_store::StoragePurpose,
    store: &kasumi_store::TenantStore,
    ciphertext: &[u8],
    link: &AuditArchiveLink,
) -> anyhow::Result<AuditArchiveReference> {
    let dependency = kasumi_store::InspectedAuditDependency::from_link(ciphertext, link)?;
    anyhow::ensure!(
        dependency.source_tenant() == state.metadata().tenant
            && dependency.reference().stream_id == state.metadata().audit_retention.stream_id,
        "backup audit stream differs"
    );
    state.authorize_source(root, dependency.source_purpose())?;
    Ok(store
        .verify_historical_audit(&dependency, dependency.source_purpose())
        .await?
        .reference()
        .clone())
}

#[derive(Clone, Copy)]
pub(crate) struct VerificationDeadline(tokio::time::Instant);
impl VerificationDeadline {
    pub fn new(timeout_ms: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=600_000).contains(&timeout_ms),
            "backup verification timeout outside bounds"
        );
        Ok(Self(
            tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms),
        ))
    }
    pub fn check(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            tokio::time::Instant::now() < self.0,
            "backup verification deadline expired"
        );
        Ok(())
    }
    pub async fn run<T>(self, future: impl Future<Output = T>) -> anyhow::Result<T> {
        self.check()?;
        tokio::time::timeout_at(self.0, future)
            .await
            .map_err(|_| anyhow::anyhow!("backup verification deadline expired"))
    }
    pub async fn blocking<T, F>(
        self,
        reservation: Arc<Reservation>,
        registration: Option<Arc<VerificationWork>>,
        work: F,
    ) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    {
        struct Resources {
            _reservation: Arc<Reservation>,
            _registration: Option<Arc<VerificationWork>>,
        }
        struct Output<T> {
            value: anyhow::Result<T>,
            // Output/state drops before resources; resources drop their byte
            // charge before the work registration permits shutdown to drain.
            _resources: Resources,
        }
        let output = self
            .run(tokio::task::spawn_blocking(move || {
                let resources = Resources {
                    _reservation: reservation,
                    _registration: registration,
                };
                let value = (|| {
                    self.check()?;
                    if let Some(work) = &resources._registration {
                        work.check()?;
                    }
                    let result = work()?;
                    self.check()?;
                    if let Some(work) = &resources._registration {
                        work.check()?;
                    }
                    Ok(result)
                })();
                Output {
                    value,
                    _resources: resources,
                }
            }))
            .await??;
        output.value
    }
}

pub(crate) struct VerifiedBackup {
    pub state: VerifiedState,
    pub bytes: Option<kasumi_store::SnapshotImage>,
    pub checkpoint: FullBackupCheckpoint,
    pub source_purpose: kasumi_store::StoragePurpose,
    pub _reservation: Arc<Reservation>,
    pub _registration: Option<Arc<VerificationWork>>,
}

/// A private receipt for the canonical bytes emitted from an already validated
/// committed generation. It is never accepted from a request or durable object.
pub(crate) struct ResidentCapture {
    pub generation: Arc<crate::Generation>,
    pub bytes: u64,
    pub sha256: String,
    pub source: kasumi_store::StoragePurpose,
}
pub(crate) enum VerifiedState {
    Captured(Arc<crate::Generation>),
    Indexed(Box<crate::state::snapshot_validation::ValidatedApplicationSnapshot>),
}
impl VerifiedState {
    fn verification_workspace(&self) -> anyhow::Result<u64> {
        match self {
            Self::Captured(_) => Ok(64 << 20),
            Self::Indexed(state) => state.index().summary().index_workspace(),
        }
    }
    /// Metadata fields only; record maps are accessed explicitly below so an
    /// indexed header cannot accidentally masquerade as a complete TenantState.
    pub(crate) fn metadata(&self) -> &TenantState {
        match self {
            Self::Captured(generation) => &generation.state,
            Self::Indexed(state) => state.header(),
        }
    }
    pub(crate) fn authorize_source(
        &self,
        root: &kasumi_store::StoragePurpose,
        source: &kasumi_store::StoragePurpose,
    ) -> anyhow::Result<()> {
        match self {
            Self::Captured(generation) => {
                crate::authorize_audit_source(&generation.state, root, source)
            }
            Self::Indexed(state) => state.authorize_source(root, source),
        }
    }
    pub(crate) fn collection(&self, name: &str) -> anyhow::Result<CollectionState> {
        match self {
            Self::Indexed(state) => state.collection(name),
            _ => self
                .metadata()
                .collections
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("backup collection absent")),
        }
    }
    pub(crate) fn archived(
        &self,
        collection: &str,
        id: &str,
    ) -> anyhow::Result<Arc<ArchivedDocument>> {
        match self {
            Self::Indexed(state) => state.archived(collection, id),
            _ => self
                .metadata()
                .collections
                .get(collection)
                .and_then(|c| c.archived_documents.get(id))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("backup archived reference absent")),
        }
    }
    pub(crate) fn records(
        &self,
        kind: u8,
        primary: Option<&str>,
    ) -> anyhow::Result<
        Box<dyn Iterator<Item = anyhow::Result<crate::snapshot_codec::Record>> + Send + '_>,
    > {
        match self {
            Self::Indexed(state) => Ok(Box::new(state.index().cursor(kind, primary)?)),
            Self::Captured(generation) if kind == 21 => {
                let primary = primary.map(str::to_owned);
                Ok(Box::new(
                    generation
                        .terminals
                        .records()
                        .map(|row| {
                            row.map(|row| crate::snapshot_codec::Record::Terminal(Box::new(row)))
                        })
                        .filter(move |record| {
                            primary.as_ref().is_none_or(|key| {
                                record
                                    .as_ref()
                                    .map_or(true, |record| record.order().1 == *key)
                            })
                        }),
                ))
            }
            Self::Captured(generation) if kind == 22 => {
                let primary = primary.map(str::to_owned);
                Ok(Box::new(
                    generation
                        .target_resolutions
                        .records()
                        .map(|row| {
                            row.map(|row| {
                                crate::snapshot_codec::Record::TargetResolution(Box::new(row))
                            })
                        })
                        .filter(move |record| {
                            primary.as_ref().is_none_or(|key| {
                                record
                                    .as_ref()
                                    .map_or(true, |record| record.order().1 == *key)
                            })
                        }),
                ))
            }
            _ => crate::snapshot_codec::records(self.metadata(), kind, primary),
        }
    }
}

/// Checked, constant-space commitment to catalogs in canonical graph traversal
/// order. Repeated catalogs remain records; no tenant-sized de-duplication set.
struct KeyLineage {
    hash: Sha256,
    count: u64,
}
impl KeyLineage {
    fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"kasumi.full-backup-key-catalog-stream.v1\0");
        Self { hash, count: 0 }
    }
    fn add(&mut self, digest: &str) -> Result<()> {
        validate_sha256(digest)?;
        self.count = self.count.checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "backup key record count overflow",
            )
        })?;
        self.hash.update([1]);
        self.hash.update(
            hex::decode(digest)
                .map_err(|_| Error::new(ErrorCode::Corruption, "invalid key catalog digest"))?,
        );
        Ok(())
    }
    fn add_audit(&mut self, key: &AuditArchiveKeyDependency) -> anyhow::Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("backup key record count overflow"))?;
        let encoded = serde_json::to_vec(key)?;
        anyhow::ensure!(
            encoded.len() <= 16 << 10,
            "audit key dependency exceeds limit"
        );
        self.hash.update([2]);
        self.hash.update((encoded.len() as u64).to_be_bytes());
        self.hash.update(encoded);
        Ok(())
    }
    fn finish(mut self) -> String {
        self.hash.update([0]);
        self.hash.update(self.count.to_be_bytes());
        hex::encode(self.hash.finalize())
    }
}

pub(crate) async fn verify(
    reader: &impl BackupReader,
    backup_id: uuid::Uuid,
    admission: &Arc<NodeAdmission>,
    deadline: VerificationDeadline,
    capture: Option<ResidentCapture>,
) -> anyhow::Result<VerifiedBackup> {
    reader.check_access().await?;
    // Bound the envelope before trusting its declared resident size.
    let reservation = admission.reserve(
        (MANIFEST_BYTES * 3 + (8 << 20)) as u64,
        reader.cancellation(),
    )?;
    let envelope = reader
        .object(backup_id, MANIFEST_BYTES, None, false)
        .await?;
    let manifest_ciphertext_sha256 = envelope.ciphertext_sha256.clone();
    let source_purpose = envelope.source_purpose.clone();
    let mut key_catalogs = KeyLineage::new();
    key_catalogs.add(reader.session_key_catalog())?;
    key_catalogs.add(&envelope.key_catalog_sha256)?;
    let manifest: FullBackupManifest = serde_json::from_slice(&envelope.snapshot)?;
    manifest.validate()?;
    source_purpose.validate_application_identity(&manifest.tenant, &manifest.source_incarnation)?;
    anyhow::ensure!(
        manifest.tenant == reader.tenant() && manifest.revision == envelope.revision,
        "full backup manifest identity differs"
    );
    drop(envelope);
    drop(reservation);
    if let Some(capture) = &capture {
        let state = &capture.generation.state;
        anyhow::ensure!(
            capture.bytes == manifest.resident_bytes
                && capture.sha256 == manifest.resident_sha256
                && capture.source == source_purpose
                && state.tenant == manifest.tenant
                && state.incarnation == manifest.source_incarnation
                && state.revision == manifest.revision,
            "backup differs from exact captured generation"
        );
    }
    let reservation = Arc::new(admission.reserve(
        if capture.is_some() {
            64 << 20
        } else {
            128 << 20
        },
        reader.cancellation(),
    )?);
    let ownership = reader.work_registration();
    // Walk the authenticated reverse page chain into an encrypted fixed-slot
    // spool. Reversing it needs one page of workspace, independent of backup size.
    let page_budget = manifest
        .page_count
        .checked_mul((PAGE_BYTES + 8) as u64)
        .ok_or_else(|| anyhow::anyhow!("backup page count overflow"))?;
    let mut pages = kasumi_store::EncryptedSpool::new(reader.scratch_disk(), page_budget)?;
    let mut reference = Some(manifest.last_page.clone());
    for expected in (0..manifest.page_count).rev() {
        reader.check_access().await?;
        let edge = reference
            .take()
            .ok_or_else(|| anyhow::anyhow!("backup page chain incomplete"))?;
        let contents = reader
            .object(
                edge.object_id,
                PAGE_BYTES,
                Some(&edge.ciphertext_sha256),
                false,
            )
            .await?;
        anyhow::ensure!(
            contents.revision == manifest.revision,
            "backup page revision differs"
        );
        let page: BackupPage = serde_json::from_slice(&contents.snapshot)?;
        page.validate()?;
        anyhow::ensure!(
            page.index == expected
                && (expected + 1 == manifest.page_count || page.chunks.len() == PAGE_CHUNKS),
            "backup page order differs"
        );
        key_catalogs.add(&contents.key_catalog_sha256)?;
        pages.write_all(&(contents.snapshot.len() as u64).to_be_bytes())?;
        pages.write_all(&contents.snapshot)?;
        pages.write_all(&vec![0; PAGE_BYTES - contents.snapshot.len()])?;
        reference = page.previous;
    }
    anyhow::ensure!(
        reference.is_none(),
        "backup page chain has trailing ancestors"
    );
    let mut spool = if capture.is_some() {
        None
    } else {
        Some(kasumi_store::EncryptedSpool::new(
            reader.scratch_disk(),
            manifest.resident_bytes,
        )?)
    };
    let mut resident_bytes = 0u64;
    let mut digest = Sha256::new();
    let mut chunk_count = 0u64;
    for index in (0..manifest.page_count).rev() {
        pages.seek(SeekFrom::Start(index * (PAGE_BYTES + 8) as u64))?;
        let mut length = [0; 8];
        pages.read_exact(&mut length)?;
        let size = u64::from_be_bytes(length);
        anyhow::ensure!(size <= PAGE_BYTES as u64, "staged backup page corrupt");
        let mut bytes = vec![0; size as usize];
        pages.read_exact(&mut bytes)?;
        let page: BackupPage = serde_json::from_slice(&bytes)?;
        for chunk in &page.chunks {
            reader.check_access().await?;
            let contents = reader
                .object(
                    chunk.object_id,
                    chunk.plaintext_bytes,
                    Some(&chunk.ciphertext_sha256),
                    false,
                )
                .await?;
            anyhow::ensure!(
                contents.revision == manifest.revision
                    && contents.snapshot.len() == chunk.plaintext_bytes
                    && hex::encode(Sha256::digest(&contents.snapshot)) == chunk.plaintext_sha256,
                "full backup chunk plaintext differs"
            );
            chunk_count = chunk_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("backup chunk count overflow"))?;
            anyhow::ensure!(
                chunk_count <= manifest.chunk_count
                    && (chunk_count == manifest.chunk_count
                        || chunk.plaintext_bytes == CHUNK_BYTES),
                "backup chunk order or size differs"
            );
            key_catalogs.add(&contents.key_catalog_sha256)?;
            digest.update(&contents.snapshot);
            resident_bytes = resident_bytes
                .checked_add(contents.snapshot.len() as u64)
                .filter(|bytes| *bytes <= manifest.resident_bytes)
                .ok_or_else(|| anyhow::anyhow!("backup resident byte count exceeded"))?;
            if let Some(spool) = &mut spool {
                spool.write_all(&contents.snapshot)?;
            }
        }
    }
    anyhow::ensure!(
        chunk_count == manifest.chunk_count,
        "backup chunk count differs"
    );
    anyhow::ensure!(
        resident_bytes == manifest.resident_bytes
            && hex::encode(digest.finalize()) == manifest.resident_sha256,
        "full backup resident stream differs"
    );
    let semantic_work = ownership.clone();
    let semantic_reservation = reservation.clone();
    let semantic_admission = admission.clone();
    let semantic_cancellation = reader.cancellation();
    let (state, bytes) = deadline
        .blocking(
            reservation.clone(),
            ownership.clone(),
            move || match capture {
                Some(capture) => Ok((VerifiedState::Captured(capture.generation), None)),
                None => {
                    let bytes =
                        kasumi_store::SnapshotImage::freeze(spool.ok_or_else(|| {
                            anyhow::anyhow!("historical backup staging missing")
                        })?)?;
                    let disk = bytes
                        .len()
                        .checked_mul(8)
                        .and_then(|v| v.checked_add(64 << 20))
                        .ok_or_else(|| anyhow::anyhow!("snapshot index disk budget overflow"))?;
                    let mut check = || {
                        deadline.check()?;
                        if let Some(work) = &semantic_work {
                            work.check()?;
                        }
                        if let Some(token) = &semantic_cancellation {
                            token.check()?;
                        }
                        Ok(())
                    };
                    let layout =
                        crate::snapshot_index::StagedSnapshot::inspect(&bytes, &mut check)?;
                    // Retain the complete index/cache floor while admitting
                    // the measured peak record work before any DTO decode.
                    semantic_reservation
                        .handoff_workspace(&semantic_admission, layout.index_workspace()?)?;
                    let validated =
                        crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
                            bytes.clone(),
                            disk,
                            &mut check,
                        )?;
                    anyhow::ensure!(
                        validated.index().summary() == layout,
                        "backup differs from admitted typed framing"
                    );
                    let state = VerifiedState::Indexed(Box::new(validated));
                    Ok((state, Some(bytes)))
                }
            },
        )
        .await?;
    let state = Arc::new(state);
    reader.authorize_state(state.metadata()).await?;
    anyhow::ensure!(
        state.metadata().tenant == manifest.tenant
            && state.metadata().incarnation == manifest.source_incarnation
            && state.metadata().revision == manifest.revision,
        "full backup state identity differs"
    );
    anyhow::ensure!(
        state.metadata().lifecycle_control.is_none()
            && state.metadata().recovery_control.is_empty(),
        "Control state cannot be an application backup"
    );
    state.authorize_source(&source_purpose, &source_purpose)?;
    for archive in state.records(11, None)? {
        let crate::snapshot_codec::Record::Archive(_, archive) = archive? else {
            unreachable!()
        };

        let archive = Arc::new(archive);
        reader.check_access().await?;
        let contents = reader
            .object(
                uuid::Uuid::parse_str(&archive.manifest_object_id)?,
                MAX_ARCHIVE_MANIFEST_BYTES,
                Some(&archive.manifest_ciphertext_sha256),
                true,
            )
            .await?;
        key_catalogs.add(&contents.key_catalog_sha256)?;
        contents.source_purpose.validate_application_identity(
            &state.metadata().tenant,
            &archive.manifest.source_incarnation,
        )?;
        let history_purpose = contents.source_purpose.clone();
        let stored: HistoryArchiveManifest = serde_json::from_slice(&contents.snapshot)?;
        anyhow::ensure!(
            stored == archive.manifest,
            "full backup history manifest differs"
        );
        drop(stored);
        drop(contents);
        for (index, chunk) in archive.manifest.chunks.iter().enumerate() {
            anyhow::ensure!(
                chunk.plaintext_bytes <= MAX_ARCHIVE_CHUNK_BYTES,
                "external history body exceeds its installed record limit"
            );
            let contents = reader
                .object(
                    uuid::Uuid::parse_str(&chunk.object_id)?,
                    chunk.plaintext_bytes,
                    Some(&chunk.ciphertext_sha256),
                    true,
                )
                .await?;
            key_catalogs.add(&contents.key_catalog_sha256)?;
            let semantic_state = state.clone();
            let semantic_archive = archive.clone();
            let semantic_purpose = history_purpose.clone();
            let semantic_cancellation = reader.cancellation();
            let semantic_work = ownership.clone();
            let semantic_reservation = reservation.clone();
            let semantic_admission = admission.clone();
            let retained_workspace = state.verification_workspace()?;
            deadline
                .blocking(reservation.clone(), ownership.clone(), move || {
                    let mut check = || -> anyhow::Result<()> {
                        deadline.check()?;
                        if let Some(token) = &semantic_cancellation {
                            token.check()?;
                        }
                        if let Some(work) = &semantic_work {
                            work.check()?;
                        }
                        Ok(())
                    };
                    check()?;
                    let chunk = &semantic_archive.manifest.chunks[index];
                    let archive = semantic_archive.as_ref();
                    anyhow::ensure!(
                        contents.source_purpose == semantic_purpose
                            && contents.snapshot.len() == chunk.plaintext_bytes
                            && hex::encode(Sha256::digest(&contents.snapshot))
                                == chunk.plaintext_sha256,
                        "full backup history chunk plaintext differs"
                    );
                    history_work::verify_body(
                        contents.snapshot,
                        &semantic_reservation,
                        &semantic_admission,
                        retained_workspace,
                        &mut check,
                        |body, check| {
                            anyhow::ensure!(
                                body.archive_id == archive.manifest.archive_id
                                    && body.collection == archive.manifest.collection
                                    && body.source_incarnation
                                        == archive.manifest.source_incarnation
                                    && body.index == index
                                    && body.documents.len() == chunk.document_count
                                    && body
                                        .documents
                                        .first()
                                        .is_some_and(|doc| doc.id == chunk.first_id)
                                    && body
                                        .documents
                                        .last()
                                        .is_some_and(|doc| doc.id == chunk.last_id)
                                    && body
                                        .documents
                                        .windows(2)
                                        .all(|pair| pair[0].id < pair[1].id),
                                "full backup history chunk identity differs"
                            );
                            let collection =
                                semantic_state.collection(&archive.manifest.collection)?;
                            for doc in &body.documents {
                                check()?;
                                let reference = semantic_state
                                    .archived(&archive.manifest.collection, &doc.id)?;
                                anyhow::ensure!(
                                    reference.archive_id == archive.manifest.archive_id
                                        && reference.chunk_index == index
                                        && reference.version == doc.version
                                        && reference.document_sha256 == staged_digest(doc)?.0
                                        && reference.document_bytes
                                            == crate::accounting::encoded_len(doc)?
                                        && reference.indexed_fields
                                            == crate::state::history::index_fields(
                                                &collection.definition,
                                                doc
                                            ),
                                    "full backup archived document differs from retained metadata"
                                );
                            }
                            check()?;
                            Ok(())
                        },
                    )
                })
                .await?;
        }
    }
    let retention = &state.metadata().audit_retention;
    let mut expected = retention
        .archive_head
        .as_ref()
        .map(|head| head.object.clone());
    let mut archive_bytes = 0u64;
    let mut archive_records = 0u64;
    while let Some(link) = expected {
        reader.check_access().await?;
        let segment = reader
            .audit_dependency(&state, &source_purpose, &link)
            .await?;
        if archive_records == 0 {
            anyhow::ensure!(
                retention.archive_head.as_ref() == Some(&segment.reference),
                "backup audit head differs"
            );
        }
        expected = segment.reference.previous.clone();
        archive_bytes = archive_bytes
            .checked_add(segment.ciphertext.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("backup audit byte count overflow"))?;
        archive_records = archive_records
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("backup audit segment count overflow"))?;
        anyhow::ensure!(
            archive_bytes <= retention.archive_bytes
                && archive_records <= retention.archive_segments,
            "backup audit accounting exceeded"
        );
        key_catalogs.add_audit(&segment.reference.key)?;
        if let Some(target) = reader.audit_target() {
            let placement = target.tenant_audit_archive()?;
            deadline
                .blocking(reservation.clone(), ownership.clone(), move || {
                    // Keep the exact store/OS ownership and byte/work reservations
                    // through filesystem completion even if its waiter disappears.
                    target.check_access()?;
                    placement.cache().publish_blocking(&segment)?;
                    target.check_access()?;
                    Ok(())
                })
                .await?;
        }
        reader.check_access().await?;
    }
    anyhow::ensure!(
        archive_bytes == retention.archive_bytes && archive_records == retention.archive_segments,
        "backup audit graph incomplete"
    );
    reader.check_access().await?;
    let checkpoint = FullBackupCheckpoint {
        tenant: manifest.tenant,
        source_incarnation: manifest.source_incarnation,
        revision: manifest.revision,
        resident_sha256: manifest.resident_sha256,
        backup_id,
        manifest_ciphertext_sha256,
        key_lineage_digest: key_catalogs.finish(),
    };
    checkpoint.validate()?;
    Ok(VerifiedBackup {
        source_purpose,
        state: Arc::try_unwrap(state).map_err(|_| {
            anyhow::anyhow!("backup semantic worker retained state after completion")
        })?,
        bytes,
        checkpoint,
        _reservation: reservation,
        _registration: ownership,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn expired_live_verification_worker_keeps_bytes_and_shutdown_registration_until_done() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let reservation = Arc::new(admission.reserve(1 << 20, None).unwrap());
        let fence = Arc::new(crate::admission::WorkFence::default());
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let registration = VerificationWork::new(
            fence.begin(Default::default()).unwrap(),
            slots.clone().try_acquire_owned().unwrap(),
        );
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, ready) = std::sync::mpsc::channel();
        let deadline = VerificationDeadline::new(100).unwrap();
        let task = tokio::spawn(async move {
            deadline
                .blocking(reservation, Some(registration), move || {
                    let _ = started.send(());
                    ready.recv()?;
                    Ok(vec![0u8; 1 << 20])
                })
                .await
        });
        entered.await.unwrap();
        assert!(task.await.unwrap().is_err());
        fence.seal();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), fence.drain())
                .await
                .is_err()
        );
        assert_eq!(admission.snapshot().reserved_bytes, 1 << 20);
        assert_eq!(slots.available_permits(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), fence.drain())
            .await
            .unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, 0);
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(admission.snapshot().inflight_operations, 0);
    }
}
