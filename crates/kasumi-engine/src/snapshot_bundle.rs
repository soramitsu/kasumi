//! Raft snapshots transport their immutable audit dependencies with the logical
//! state. Only a complete verified bundle can publish a new engine generation.
//! Frame and segment buffers are bounded independently of retained history.
use super::{Generation, TenantEngine};
use anyhow::{Context, Result, ensure};
use kasumi_store::{InspectedAuditDependency, PreparedAuditSegment, StoragePurpose, TenantStore};
use kasumi_types::{AuditArchiveLink, AuditArchiveReference, MAX_AUDIT_SEGMENT_BYTES, TenantState};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"KASUMID1";
const CHUNK: usize = 64 << 10;
const SOURCE_LIMIT: usize = 64 << 10;
const LOGICAL: u8 = 1;
const LOGICAL_END: u8 = 2;
const ARCHIVE: u8 = 3;
const END: u8 = 4;

#[derive(Default, Debug, PartialEq, Eq)]
struct Counts {
    logical_bytes: u64,
    logical_records: u64,
    archive_bytes: u64,
    archive_records: u64,
}
impl Counts {
    fn record(&mut self, archive: bool, length: usize) -> io::Result<()> {
        let (bytes, records) = if archive {
            (&mut self.archive_bytes, &mut self.archive_records)
        } else {
            (&mut self.logical_bytes, &mut self.logical_records)
        };
        *bytes = bytes.checked_add(length as u64).ok_or_else(overflow)?;
        *records = records.checked_add(1).ok_or_else(overflow)?;
        Ok(())
    }
    fn encode(&self) -> [u8; 32] {
        let mut result = [0; 32];
        for (index, count) in [
            self.logical_bytes,
            self.logical_records,
            self.archive_bytes,
            self.archive_records,
        ]
        .into_iter()
        .enumerate()
        {
            result[index * 8..index * 8 + 8].copy_from_slice(&count.to_be_bytes());
        }
        result
    }
}
fn overflow() -> io::Error {
    io::Error::other("snapshot count overflow")
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Encoder<'a> {
    writer: &'a mut dyn Write,
    digest: Sha256,
    counts: Counts,
}
impl Encoder<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes)?;
        self.digest.update(bytes);
        Ok(())
    }
    fn record(&mut self, tag: u8, bytes: &[u8]) -> io::Result<()> {
        self.bytes(&[tag])?;
        self.bytes(&(bytes.len() as u64).to_be_bytes())?;
        self.bytes(bytes)?;
        self.counts.record(tag == ARCHIVE, bytes.len())
    }
}
struct LogicalWriter<'a, 'b> {
    encoder: &'a mut Encoder<'b>,
    buffer: Vec<u8>,
}
impl LogicalWriter<'_, '_> {
    fn finish(self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            self.encoder.record(LOGICAL, &self.buffer)?;
        }
        self.encoder.bytes(&[LOGICAL_END])
    }
}
impl Write for LogicalWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let take = (CHUNK - self.buffer.len()).min(remaining.len());
            self.buffer.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buffer.len() == CHUNK {
                self.encoder.record(LOGICAL, &self.buffer)?;
                self.buffer.clear();
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.encoder.writer.flush()
    }
}

fn same_snapshot_resource(source: &StoragePurpose, current: &StoragePurpose) -> bool {
    source.same_application_resource(current)
        || matches!(
            (source, current),
            (StoragePurpose::NodeControl, StoragePurpose::NodeControl)
        )
}
fn authorize_root(
    state: &TenantState,
    source: &StoragePurpose,
    current: &StoragePurpose,
) -> Result<()> {
    ensure!(
        same_snapshot_resource(source, current),
        "snapshot source installation differs"
    );
    if matches!(source, StoragePurpose::NodeControl) {
        // Control metadata uses its own installed Raft group, incarnation and
        // immutable lifecycle installation checks in prepare_state. This is not
        // application-backup authority or historical audit-key authorization.
        ensure!(
            state.tenant == "__kasumi_control"
                && state.restore_lineage.is_empty()
                && state.restored_from.is_none(),
            "invalid Control snapshot domain"
        );
        return Ok(());
    }
    crate::authorize_audit_source(state, source, source)
}

pub(super) fn write(
    generation: &Generation,
    store: &TenantStore,
    writer: &mut dyn Write,
) -> Result<()> {
    store.check_access()?;
    let source = store.storage_access().purpose();
    authorize_root(&generation.state, source, store.storage_access().purpose())?;
    let encoded = serde_json::to_vec(source)?;
    ensure!(
        encoded.len() <= SOURCE_LIMIT,
        "snapshot source exceeds limit"
    );
    let mut encoder = Encoder {
        writer,
        digest: Sha256::new(),
        counts: Counts::default(),
    };
    encoder.bytes(MAGIC)?;
    encoder.bytes(&(encoded.len() as u64).to_be_bytes())?;
    encoder.bytes(&encoded)?;
    let mut logical = LogicalWriter {
        encoder: &mut encoder,
        buffer: Vec::with_capacity(CHUNK),
    };
    TenantEngine::write_generation(generation, &mut logical)?;
    logical.finish()?;
    let retention = &generation.state.audit_retention;
    let mut expected = retention
        .archive_head
        .as_ref()
        .map(|head| head.object.clone());
    if expected.is_some() {
        let placement = store.tenant_audit_archive()?;
        while let Some(link) = expected {
            let ciphertext = placement.cache().read_blocking(&link)?;
            let reference =
                verify_dependency(&generation.state, source, store, &ciphertext, &link)?;
            if encoder.counts.archive_records == 0 {
                ensure!(
                    retention.archive_head.as_ref() == Some(&reference),
                    "snapshot archive head differs"
                );
            }
            encoder.record(ARCHIVE, &ciphertext)?;
            ensure!(
                encoder.counts.archive_bytes <= retention.archive_bytes
                    && encoder.counts.archive_records <= retention.archive_segments,
                "snapshot archive budget exceeded"
            );
            expected = reference.previous;
        }
    }
    ensure!(
        encoder.counts.archive_bytes == retention.archive_bytes
            && encoder.counts.archive_records == retention.archive_segments,
        "snapshot archive accounting differs"
    );
    encoder.bytes(&[END])?;
    encoder.bytes(&encoder.counts.encode())?;
    let digest = encoder.digest.finalize();
    encoder.writer.write_all(&digest)?;
    store.check_access()?;
    Ok(())
}

/// Logical candidates are never sufficient evidence to publish a pruned state.
/// A caller with a locally installed store must independently verify the whole
/// already-preserved chain in an owned blocking worker.
#[cfg(any(test, feature = "test-utils"))]
pub(super) fn verify_local(generation: &Generation, store: &TenantStore) -> Result<()> {
    verify_local_checked(generation, store, || Ok(()))
}
pub(super) fn verify_local_checked(
    generation: &Generation,
    store: &TenantStore,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    check()?;
    store.check_access()?;
    let source = store.storage_access().purpose();
    authorize_root(&generation.state, source, store.storage_access().purpose())?;
    let retention = &generation.state.audit_retention;
    let placement = store.tenant_audit_archive()?;
    let mut expected = retention
        .archive_head
        .as_ref()
        .map(|head| head.object.clone());
    let mut counts = Counts::default();
    while let Some(link) = expected {
        check()?;
        let ciphertext = placement.cache().read_blocking(&link)?;
        let reference = verify_dependency(&generation.state, source, store, &ciphertext, &link)?;
        if counts.archive_records == 0 {
            ensure!(
                retention.archive_head.as_ref() == Some(&reference),
                "local audit head differs"
            );
        }
        counts.record(true, ciphertext.len())?;
        ensure!(
            counts.archive_bytes <= retention.archive_bytes
                && counts.archive_records <= retention.archive_segments,
            "local audit archive budget exceeded"
        );
        expected = reference.previous;
    }
    ensure!(
        counts.archive_bytes == retention.archive_bytes
            && counts.archive_records == retention.archive_segments,
        "local audit archive accounting differs"
    );
    check()?;
    store.check_access()?;
    Ok(())
}

pub(crate) fn verify_dependency(
    state: &TenantState,
    source: &StoragePurpose,
    store: &TenantStore,
    bytes: &[u8],
    link: &AuditArchiveLink,
) -> Result<AuditArchiveReference> {
    let inspected = InspectedAuditDependency::from_link(bytes, link)?;
    ensure!(
        inspected.source_tenant() == state.tenant
            && inspected.reference().stream_id == state.audit_retention.stream_id,
        "snapshot archive stream differs"
    );
    // The caller owns a blocking worker until verification and publication end.
    let runtime = tokio::runtime::Handle::try_current()?;
    let verified = if matches!(source, StoragePurpose::NodeControl) {
        authorize_root(state, source, store.storage_access().purpose())?;
        ensure!(
            inspected.source_purpose() == source,
            "Control audit source purpose differs"
        );
        runtime.block_on(store.decrypt_audit_segment(bytes, inspected.reference()))?
    } else {
        crate::authorize_audit_source(state, source, inspected.source_purpose())?;
        runtime.block_on(store.verify_historical_audit(&inspected, inspected.source_purpose()))?
    };
    Ok(verified.reference().clone())
}

struct Decoder<'a> {
    reader: &'a mut dyn Read,
    digest: Sha256,
    counts: Counts,
}
impl Decoder<'_> {
    fn bytes(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.reader.read_exact(bytes)?;
        self.digest.update(bytes);
        Ok(())
    }
    fn tag(&mut self) -> io::Result<u8> {
        let mut bytes = [0];
        self.bytes(&mut bytes)?;
        Ok(bytes[0])
    }
    fn length(&mut self, maximum: usize) -> io::Result<usize> {
        let mut bytes = [0; 8];
        self.bytes(&mut bytes)?;
        let length = u64::from_be_bytes(bytes);
        if length == 0 || length > maximum as u64 {
            return Err(invalid("snapshot record length exceeds limit"));
        }
        usize::try_from(length).map_err(|_| overflow())
    }
}
impl Decoder<'_> {
    fn finish(mut self) -> Result<Counts> {
        let mut counts = [0; 32];
        self.bytes(&mut counts)?;
        ensure!(
            counts == self.counts.encode(),
            "snapshot final counts differ"
        );
        let actual = self.digest.finalize();
        let mut digest = [0; 32];
        self.reader.read_exact(&mut digest)?;
        ensure!(actual.as_slice() == digest, "snapshot final digest differs");
        let mut extra = [0];
        ensure!(
            self.reader.read(&mut extra)? == 0,
            "snapshot trailing bytes"
        );
        Ok(self.counts)
    }
}

/// Verify both framing layers and their actual typed counts/digests with fixed
/// buffers. No JSON DTO or aggregate permanent history is allocated here.
pub(super) fn inspect(reader: &mut dyn Read) -> Result<crate::snapshot_codec::StreamSummary> {
    let mut decoder = Decoder {
        reader,
        digest: Sha256::new(),
        counts: Counts::default(),
    };
    let mut magic = [0; 8];
    decoder.bytes(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported tenant snapshot bundle format");
    let mut buffer = vec![0; CHUNK];
    let length = decoder.length(SOURCE_LIMIT)?;
    decoder.bytes(&mut buffer[..length])?;
    let mut logical = LogicalReader {
        decoder: &mut decoder,
        buffer: Vec::with_capacity(CHUNK),
        offset: 0,
        short: false,
        ended: false,
    };
    let summary = crate::snapshot_codec::inspect(&mut logical)?;
    ensure!(logical.ended, "logical snapshot end missing");
    ensure!(
        decoder.counts.logical_records != 0,
        "logical snapshot absent"
    );
    loop {
        match decoder.tag()? {
            ARCHIVE => {
                let length = decoder.length(MAX_AUDIT_SEGMENT_BYTES)?;
                let mut remaining = length;
                while remaining != 0 {
                    let take = remaining.min(CHUNK);
                    decoder.bytes(&mut buffer[..take])?;
                    remaining -= take;
                }
                decoder.counts.record(true, length)?;
            }
            END => break,
            _ => anyhow::bail!("invalid audit snapshot record"),
        }
    }
    ensure!(
        decoder.finish()?.logical_bytes == summary.bytes,
        "snapshot logical framed bytes differ"
    );
    Ok(summary)
}

struct LogicalReader<'a, 'b> {
    decoder: &'a mut Decoder<'b>,
    buffer: Vec<u8>,
    offset: usize,
    short: bool,
    ended: bool,
}
impl Read for LogicalReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.ended {
            return Ok(0);
        }
        if self.offset == self.buffer.len() {
            match self.decoder.tag()? {
                LOGICAL_END => {
                    self.ended = true;
                    return Ok(0);
                }
                LOGICAL if !self.short => {
                    let length = self.decoder.length(CHUNK)?;
                    self.short = length < CHUNK;
                    self.buffer.resize(length, 0);
                    self.decoder.bytes(&mut self.buffer)?;
                    self.decoder.counts.record(false, length)?;
                    self.offset = 0;
                }
                _ => return Err(invalid("noncanonical logical snapshot frames")),
            }
        }
        let take = output.len().min(self.buffer.len() - self.offset);
        output[..take].copy_from_slice(&self.buffer[self.offset..self.offset + take]);
        self.offset += take;
        Ok(take)
    }
}

pub(super) fn read(
    engine: &TenantEngine,
    reader: &mut dyn Read,
    expected: Option<crate::snapshot_codec::StreamSummary>,
) -> Result<Generation> {
    let store = engine
        .snapshot_store
        .get()
        .context("snapshot storage not installed")?;
    store.check_access()?;
    let mut decoder = Decoder {
        reader,
        digest: Sha256::new(),
        counts: Counts::default(),
    };
    let mut magic = [0; 8];
    decoder.bytes(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported tenant snapshot bundle format");
    let length = decoder.length(SOURCE_LIMIT)?;
    let mut encoded = vec![0; length];
    decoder.bytes(&mut encoded)?;
    let source: StoragePurpose = serde_json::from_slice(&encoded)?;
    ensure!(
        serde_json::to_vec(&source)? == encoded,
        "noncanonical snapshot source purpose"
    );
    ensure!(
        same_snapshot_resource(&source, store.storage_access().purpose()),
        "snapshot source installation differs"
    );
    let mut logical = LogicalReader {
        decoder: &mut decoder,
        buffer: Vec::with_capacity(CHUNK),
        offset: 0,
        short: false,
        ended: false,
    };
    let generation =
        engine.prepare_snapshot_reader(store.scratch_disk(), &mut logical, expected)?;
    ensure!(logical.ended, "logical snapshot end missing");
    authorize_root(&generation.state, &source, store.storage_access().purpose())?;
    let retention = &generation.state.audit_retention;
    let mut expected = retention
        .archive_head
        .as_ref()
        .map(|head| head.object.clone());
    if expected.is_some() {
        let placement = store.tenant_audit_archive()?;
        while let Some(link) = expected {
            ensure!(
                decoder.tag()? == ARCHIVE,
                "snapshot archive dependency missing"
            );
            let length = decoder.length(MAX_AUDIT_SEGMENT_BYTES)?;
            let mut ciphertext = vec![0; length];
            decoder.bytes(&mut ciphertext)?;
            let reference =
                verify_dependency(&generation.state, &source, store, &ciphertext, &link)?;
            if decoder.counts.archive_records == 0 {
                ensure!(
                    retention.archive_head.as_ref() == Some(&reference),
                    "snapshot archive head differs"
                );
            }
            expected = reference.previous.clone();
            decoder.counts.record(true, length)?;
            ensure!(
                decoder.counts.archive_bytes <= retention.archive_bytes
                    && decoder.counts.archive_records <= retention.archive_segments,
                "snapshot archive budget exceeded"
            );
            // Verified immutable orphans are harmless on a later failure. No
            // pruning watermark is published until this whole bundle succeeds.
            placement.cache().publish_blocking(&PreparedAuditSegment {
                reference,
                ciphertext,
            })?;
        }
    }
    ensure!(
        decoder.counts.archive_bytes == retention.archive_bytes
            && decoder.counts.archive_records == retention.archive_segments,
        "snapshot archive accounting differs"
    );
    ensure!(
        decoder.tag()? == END,
        "snapshot trailing dependency or missing final record"
    );
    decoder.finish()?;
    store.check_access()?;
    Ok(generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_raft::StateMachineBackend;
    use kasumi_store::{AuditSegmentBuilder, NodeStore, test_utils::LocalKeyProvider};
    use kasumi_types::{Action, AuditEvent, Grant, Limits, Policy};
    use std::sync::Arc;

    async fn fixture(
        incarnation: &str,
    ) -> (tempfile::TempDir, Arc<TenantEngine>, Arc<TenantStore>) {
        fixture_tenant(incarnation, "tenant").await
    }
    async fn fixture_tenant(
        incarnation: &str,
        tenant: &str,
    ) -> (tempfile::TempDir, Arc<TenantEngine>, Arc<TenantStore>) {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let store = TenantStore::open_fixture(
            node,
            tenant.into(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let engine = Arc::new(
            TenantEngine::new(
                tenant.into(),
                incarnation.into(),
                Policy {
                    grants: vec![Grant {
                        principal: "owner".into(),
                        collection: None,
                        actions: [Action::Admin].into_iter().collect(),
                    }],
                    strict_read_audit: false,
                },
                Limits::default(),
            )
            .unwrap(),
        );
        engine.install_storage_access(&store).unwrap();
        (directory, engine, store)
    }
    fn install_chain(engine: &TenantEngine, store: &TenantStore) -> Vec<AuditArchiveReference> {
        let mut state = engine.generation().unwrap().state.clone();
        let mut references = Vec::new();
        let mut previous = None;
        for sequence in 0..3 {
            let mut builder =
                AuditSegmentBuilder::new(state.audit_retention.stream_id, sequence, previous)
                    .unwrap();
            let event = AuditEvent {
                event_id: format!("archive-{sequence}"),
                principal: "owner".into(),
                action: "read".into(),
                request_id: "request".into(),
                timestamp_ms: 1_000,
                data_revision: Some(0),
                outcome: "authorized_release".into(),
                collection: None,
            };
            assert!(
                builder
                    .push(sequence, &serde_json::to_vec(&event).unwrap())
                    .unwrap()
            );
            let segment = store.encrypt_audit_segment(builder).unwrap();
            store
                .tenant_audit_archive()
                .unwrap()
                .cache()
                .publish_blocking(&segment)
                .unwrap();
            state.audit_retention.archive_bytes += segment.reference.ciphertext_bytes;
            state.audit_retention.archive_segments += 1;
            previous = Some(segment.reference.object.clone());
            references.push(segment.reference);
        }
        state.audit_retention.next_sequence = 3;
        state.audit_retention.pruned_before = 3;
        state.audit_retention.archive_head = references.last().cloned();
        engine.current.store(Some(Arc::new(
            engine
                .prepare_state(
                    state,
                    engine.generation().unwrap().receipts.clone(),
                    engine.generation().unwrap().terminals.clone(),
                    engine.generation().unwrap().target_resolutions.clone(),
                )
                .unwrap(),
        )));
        references
    }
    async fn capture(engine: Arc<TenantEngine>) -> Result<Vec<u8>> {
        // Capture happens before owned blocking materialization, as in Raft.
        let captured = engine.capture_snapshot()?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            captured.write(&mut bytes)?;
            Ok(bytes)
        })
        .await?
    }
    async fn restore(engine: Arc<TenantEngine>, bytes: Vec<u8>) -> Result<()> {
        tokio::task::spawn_blocking(move || {
            // These bundle fixtures remain at genesis (no applied Raft entry).
            // Exercise prepared validation and atomic namespace publication;
            // the Raft crate separately tests the joint custody/cursor commit.
            let store = engine
                .snapshot_store
                .get()
                .context("fixture snapshot storage absent")?;
            let image = kasumi_store::SnapshotImage::from_bytes(store.scratch_disk(), &bytes)?;
            let context = kasumi_raft::SnapshotRestoreContext {
                mode: kasumi_raft::SnapshotRestoreMode::Install,
                backend_sha256: image.sha256().into(),
                meta: kasumi_raft::SnapshotMeta {
                    last_log_id: None,
                    last_membership: Default::default(),
                    snapshot_id: uuid::Uuid::new_v4().to_string(),
                },
            };
            let prepared = engine.prepare_restore(&context, &mut image.reader())?;
            store.replace_namespaces(
                &prepared.application_replacements(),
                prepared.application_writes(),
            )?;
            prepared.publish()
        })
        .await?
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replacement_receives_complete_chain_and_restart_uses_local_dependencies() {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;
        let references = install_chain(&source, &source_store);
        let snapshot = capture(source.clone()).await.unwrap();
        let logical = source
            .logical_snapshot(&kasumi_store::ScratchDisk::fixture())
            .unwrap();
        let incomplete_target = target.clone();
        let candidate = logical.clone();
        assert!(
            tokio::task::spawn_blocking(move || incomplete_target.restore_candidate(&candidate))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(
            target
                .generation()
                .unwrap()
                .state
                .audit_retention
                .pruned_before,
            0
        );
        for reference in &references {
            assert!(
                target_store
                    .tenant_audit_archive()
                    .unwrap()
                    .cache()
                    .read_blocking(&reference.object)
                    .is_err()
            );
        }
        restore(target.clone(), snapshot.clone()).await.unwrap();
        assert_eq!(
            target.generation().unwrap().state.audit_retention,
            source.generation().unwrap().state.audit_retention
        );
        for reference in &references {
            assert_eq!(
                target_store
                    .tenant_audit_archive()
                    .unwrap()
                    .cache()
                    .read_blocking(&reference.object)
                    .unwrap(),
                source_store
                    .tenant_audit_archive()
                    .unwrap()
                    .cache()
                    .read_blocking(&reference.object)
                    .unwrap()
            );
        }
        source_store.shutdown().await;
        // The replacement is independently sufficient to create and reinstall
        // the snapshot while the original source is unavailable.
        let recaptured = capture(target.clone()).await.unwrap();
        assert_eq!(snapshot, recaptured);
        restore(target.clone(), recaptured).await.unwrap();
        tokio::task::spawn_blocking(move || target.restore_candidate(&logical))
            .await
            .unwrap()
            .unwrap();
        target_store.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incomplete_or_corrupt_bundle_never_publishes_pruned_state() {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;
        install_chain(&source, &source_store);
        let snapshot = capture(source.clone()).await.unwrap();
        let before = target.generation().unwrap().state.audit_retention.clone();
        for truncated in [0, 8, snapshot.len() / 2, snapshot.len() - 1] {
            assert!(
                restore(target.clone(), snapshot[..truncated].to_vec())
                    .await
                    .is_err()
            );
            assert_eq!(target.generation().unwrap().state.audit_retention, before);
        }
        let mut corrupt = snapshot.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(restore(target.clone(), corrupt).await.is_err());
        let mut trailing = snapshot.clone();
        trailing.push(0);
        assert!(restore(target.clone(), trailing).await.is_err());
        assert_eq!(target.generation().unwrap().state.audit_retention, before);
        // The logical-only encoding is not a supported transport fallback.
        let logical = source
            .logical_snapshot(&kasumi_store::ScratchDisk::fixture())
            .unwrap();
        let mut logical_bytes = Vec::new();
        logical.reader().read_to_end(&mut logical_bytes).unwrap();
        assert!(restore(target.clone(), logical_bytes).await.is_err());
        restore(target, snapshot).await.unwrap();
        source_store.shutdown().await;
        target_store.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_archive_and_incorrect_totals_prevent_snapshot_completion() {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let references = install_chain(&source, &source_store);
        let mut state = source.generation().unwrap().state.clone();
        state.audit_retention.archive_bytes += 1;
        source.current.store(Some(Arc::new(
            source
                .prepare_state(
                    state,
                    source.generation().unwrap().receipts.clone(),
                    source.generation().unwrap().terminals.clone(),
                    source.generation().unwrap().target_resolutions.clone(),
                )
                .unwrap(),
        )));
        assert!(capture(source.clone()).await.is_err());
        let mut state = source.generation().unwrap().state.clone();
        state.audit_retention.archive_bytes -= 1;
        source.current.store(Some(Arc::new(
            source
                .prepare_state(
                    state,
                    source.generation().unwrap().receipts.clone(),
                    source.generation().unwrap().terminals.clone(),
                    source.generation().unwrap().target_resolutions.clone(),
                )
                .unwrap(),
        )));
        // The source cache directory is fixed to this private installation.
        let cache = source_store
            .durable_directory()
            .unwrap()
            .join("tenant-audit-archives");
        let name = format!("{}.audit", references[1].object.object_id);
        std::fs::remove_file(cache.join(name)).unwrap();
        assert!(capture(source).await.is_err());
        source_store.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_archive_transfer_uses_exact_reserved_domain_without_application_authority() {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) =
            fixture_tenant(&incarnation, "__kasumi_control").await;
        let (_target_dir, target, target_store) =
            fixture_tenant(&incarnation, "__kasumi_control").await;
        assert_eq!(
            source_store.storage_access().purpose(),
            &StoragePurpose::NodeControl
        );
        install_chain(&source, &source_store);
        let snapshot = capture(source.clone()).await.unwrap();
        restore(target.clone(), snapshot).await.unwrap();
        assert_eq!(
            target.generation().unwrap().state.audit_retention,
            source.generation().unwrap().state.audit_retention
        );
        assert!(
            crate::authorize_audit_source(
                &source.generation().unwrap().state,
                &StoragePurpose::NodeControl,
                &StoragePurpose::NodeControl
            )
            .is_err()
        );
        source_store.shutdown().await;
        target_store.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_restore_admits_resident_state_without_charging_permanent_stream_as_ram() {
        use crate::staged_terminal::{AppliedIdentity, AppliedOrigin, Builder, Row};
        use kasumi_types::{
            ErrorCode, Mutation, Precondition, StagedChunk, StagedManifest, StagedOutcome,
            StagedTransaction, StagedTransactionScope, WriteReceipt, staged_digest,
        };

        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;
        let previous = source.generation().unwrap();
        let mut state = previous.state.clone();
        state.revision = 512;
        let manifest = StagedManifest::from_chunks(&vec![
            StagedChunk {
                read_set: vec![],
                operations: vec![Mutation::Delete {
                    collection: "rows".into(),
                    id: "one".into(),
                    expected: Precondition::Any,
                }],
            };
            256
        ])
        .unwrap();
        let mut builder = Builder::new(
            source_store.scratch_disk(),
            256 << 20,
            &state.tenant,
            &incarnation,
        )
        .unwrap();
        for ordinal in 1..=512 {
            let transaction_id = format!("terminal-{ordinal:04}");
            let row = Row {
                ordinal,
                key: super::super::staging::identity("owner", &transaction_id).unwrap(),
                previous_sha256: state.staged_terminal_head.sha256.clone(),
                applied: AppliedIdentity {
                    incarnation: incarnation.clone(),
                    revision: ordinal,
                    timestamp_ms: 1000,
                    command_sha256: "ab".repeat(32),
                    origin: AppliedOrigin::Raft {
                        term: 1,
                        leader: 1,
                        index: ordinal,
                        context_sha256: "cd".repeat(32),
                    },
                },
                stage: StagedTransaction {
                    scope: StagedTransactionScope {
                        tenant: state.tenant.clone(),
                        incarnation: incarnation.clone(),
                        principal: "owner".into(),
                    },
                    transaction_id,
                    manifest_digest: staged_digest(&manifest).unwrap().0,
                    manifest: manifest.clone(),
                    chunks: Default::default(),
                    stored_chunk_bytes: 0,
                    uploaded_payload_bytes: 0,
                    uploaded_operations: 0,
                    uploaded_read_assertions: 0,
                    expires_at_ms: None,
                    ttl_ms: 60000,
                    outcome: StagedOutcome::Aborted {
                        receipt: WriteReceipt {
                            revision: ordinal,
                            versions: Default::default(),
                        },
                    },
                },
            };
            builder.push(&row, &state).unwrap();
            crate::staged_terminal::advance(&mut state.staged_terminal_head, &row).unwrap();
        }
        state.permanent_staged_bytes = state.staged_terminal_head.encoded_bytes;
        let staged = builder.finish(&state.staged_terminal_head).unwrap();
        let install = staged
            .prepare_install(&source_store, &state, &"de".repeat(32), false)
            .unwrap();
        source_store
            .replace_namespaces(&install.replacements(), install.writes())
            .unwrap();
        let generation = source
            .prepare_state(
                state,
                previous.receipts.clone(),
                install.view,
                previous.target_resolutions.clone(),
            )
            .unwrap();
        source.publish_generation(Some(Arc::new(generation)));
        drop(previous);

        // This is a fixture governor with no production maintenance lanes. It
        // isolates point-stream admission, not final production node capacity.
        let maximum = 80 << 20;
        let admission = crate::admission::NodeAdmission::new(crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(maximum),
            ..Default::default()
        })
        .unwrap();
        let image = source.snapshot(admission.clone(), 60_000).await.unwrap();
        let layout = inspect(&mut image.reader()).unwrap();
        assert_eq!(layout.kinds[21].records, 512);
        assert!(layout.bytes.checked_mul(3).unwrap() + (64 << 20) > maximum);
        assert!(layout.materialization_workspace().unwrap() < maximum);
        let denied = crate::admission::NodeAdmission::new(crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(layout.materialization_workspace().unwrap() - 1),
            ..Default::default()
        })
        .unwrap();
        let live_files = image.disk().snapshot().live_files;
        let error = target
            .prepare_snapshot_restore(image.clone(), denied.clone(), 60_000)
            .await
            .err()
            .expect("accounted record work must be admitted before staging");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert_eq!(image.disk().snapshot().live_files, live_files);
        assert_eq!(denied.snapshot().reserved_bytes, 0);
        assert_eq!(denied.snapshot().inflight_operations, 0);
        let prepared = target
            .prepare_snapshot_restore(image.clone(), admission.clone(), 60_000)
            .await
            .unwrap();
        assert_eq!(prepared.revision(), 512);
        assert_eq!(prepared.image(), &image);
        assert_eq!(target.generation().unwrap().state.revision, 0);
        assert_eq!(target.generation().unwrap().terminals.head().count, 0);
        assert_eq!(admission.snapshot().reserved_bytes, 0);
        assert_eq!(admission.snapshot().inflight_operations, 0);
        source_store.shutdown().await;
        target_store.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_capture_and_restore_preparation_are_complete_admitted_and_never_publish() {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;
        install_chain(&source, &source_store);
        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
        let image = source.snapshot(admission.clone(), 60_000).await.unwrap();
        let before = target.generation().unwrap().state.audit_retention.clone();
        let prepared = target
            .prepare_snapshot_restore(image.clone(), admission.clone(), 60_000)
            .await
            .unwrap();
        assert_eq!(prepared.tenant(), "tenant");
        assert_eq!(prepared.incarnation(), incarnation);
        assert_eq!(
            prepared.revision(),
            source.generation().unwrap().state.revision
        );
        assert_eq!(prepared.image(), &image);
        assert_eq!(target.generation().unwrap().state.audit_retention, before);
        assert_eq!(admission.snapshot().reserved_bytes, 0);
        assert!(
            target
                .prepare_snapshot_restore(
                    source
                        .logical_snapshot(&kasumi_store::ScratchDisk::fixture())
                        .unwrap(),
                    admission.clone(),
                    60_000
                )
                .await
                .is_err()
        );
        assert_eq!(admission.snapshot().reserved_bytes, 0);
        let denied = crate::admission::NodeAdmission::new(crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(1 << 20),
            ..Default::default()
        })
        .unwrap();
        assert!(source.snapshot(denied, 60_000).await.is_err());
        source_store.shutdown().await;
        target_store.shutdown().await;
    }
}
