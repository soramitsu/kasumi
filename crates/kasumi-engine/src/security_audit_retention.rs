//! Archive publication is a durable phase: only a verified exact pending object
//! can authorize the atomic movement of a hot prefix into permanent archive roots.
use super::*;
use kasumi_store::{AuditSegmentBuilder, PreparedAuditSegment};
use kasumi_types::{
    AuditArchiveReference, AuditRetentionState, MAX_AUDIT_EVENT_BYTES, MAX_AUDIT_SEGMENT_BYTES,
    SecurityAuditCursor, SecurityAuditPage, SecurityAuditStatus,
};
use std::time::Duration;
use uuid::Uuid;

const META: &str = "security.audit.meta";
const ARCHIVES: &str = "security.audit.archives";
// Reserve wire-envelope and per-record separator bytes inside the shared limit.
const MAX_PAGE_BYTES: usize = kasumi_types::MAX_SECURITY_AUDIT_PAGE_BYTES - 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    format: u32,
    destination: String,
    pub position: AuditRetentionState,
    archived_bytes: u64,
    segments: u64,
    draining: bool,
}
impl Head {
    pub fn open(store: &TenantStore, destination: &str) -> Result<Self> {
        ensure!(
            store.get(META, b"next")?.is_none(),
            "unsupported service audit format"
        );
        if let Some(bytes) = store.get_bounded(META, b"head", 64 << 10)? {
            let head: Self = serde_json::from_slice(&bytes)?;
            ensure!(
                head.format == 1 && head.destination == destination,
                "unsupported service audit format"
            );
            head.position.validate()?;
            ensure!(
                (head.segments == 0) == head.position.archive_head.is_none(),
                "audit archive root count mismatch"
            );
            return Ok(head);
        }
        store.visit("security.audit", MAX_AUDIT_EVENT_BYTES, |_, _| {
            anyhow::bail!("audit records without canonical head")
        })?;
        let head = Self {
            format: 1,
            destination: destination.into(),
            position: AuditRetentionState::empty(Uuid::new_v4()),
            archived_bytes: 0,
            segments: 0,
            draining: false,
        };
        store.write_batch(&[head.write()?])?;
        Ok(head)
    }
    pub fn write(&self) -> Result<WriteOp> {
        self.position.validate()?;
        Ok(WriteOp::put(META, b"head", serde_json::to_vec(self)?))
    }
}

pub(super) fn start_worker(runtime: &tokio::runtime::Handle, weak: Weak<AuditWriter>) {
    runtime.spawn(async move {
        loop {
            let Some(writer) = weak.upgrade() else { return; };
            let wake = writer.wake.clone();
            let audit = SecurityAudit { writer };
            let Ok(work) = audit.begin() else { return; };
            drop(audit);
            let result = work.writer.maintenance_inner().await;
            let draining = result.is_ok() && work.writer.status().is_ok_and(|status| status.draining);
            if result.is_err() {
                work.writer.report_maintenance_failure();
            }
            // Store ownership remains inside the registration through every
            // publication and write. Never abort this worker during shutdown.
            drop(work);
            if draining { tokio::task::yield_now().await; continue; }
            // Do not retain storage or admission ownership while idle.
            tokio::select! { _ = wake.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(250)) => {} }
        }
    });
}

impl SecurityAudit {
    pub fn status(&self) -> Result<SecurityAuditStatus> {
        self.writer.store.check_access()?;
        let state = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
        Ok(SecurityAuditStatus {
            position: state.head.position.clone(),
            budget: self.writer.budget.clone(),
            archived_bytes: state.head.archived_bytes,
            archive_segments: state.head.segments,
            draining: state.head.draining,
            persistence_failed: state.failed,
            maintenance_failures: state.failures,
            last_failure: state.last_failure.clone(),
        })
    }

    /// Cancellation of the caller does not cancel owned archive publication.
    pub async fn maintain(&self) -> Result<SecurityAuditStatus> {
        let work = self.begin()?;
        tokio::spawn(async move {
            if let Err(error) = work.writer.maintenance_inner().await {
                work.writer.report_maintenance_failure();
                return Err(error);
            }
            work.writer.status()
        })
        .await?
    }

    fn report_maintenance_failure(&self) {
        if let Ok(mut state) = self.writer.sequence.lock() {
            state.failures = state.failures.saturating_add(1);
            state.last_failure = Some("archive maintenance failed; hot prefix retained".into());
        }
    }

    fn prepare_archive(&self) -> Result<Option<PreparedAuditSegment>> {
        let mut state = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
        ensure!(!state.failed, "service audit persistence requires recovery");
        if let Some(encoded) = self.writer.store.get_bounded(META, b"pending", 64 << 10)? {
            let reference: AuditArchiveReference = serde_json::from_slice(&encoded)?;
            reference.validate()?;
            ensure!(
                reference.stream_id == state.head.position.stream_id
                    && reference.object.first_sequence == state.head.position.pruned_before
                    && reference.previous
                        == state
                            .head
                            .position
                            .archive_head
                            .as_ref()
                            .map(|head| head.object.clone()),
                "pending audit publication conflicts with head"
            );
            let ciphertext = self
                .writer
                .store
                .get_bounded(META, b"pending-ciphertext", MAX_AUDIT_SEGMENT_BYTES)?
                .context("pending archive bytes missing")?;
            return Ok(Some(PreparedAuditSegment {
                reference,
                ciphertext,
            }));
        }
        let position = &state.head.position;
        if position.hot_bytes <= self.writer.budget.drains_to()
            || (!state.head.draining && position.hot_bytes < self.writer.budget.starts_at())
        {
            return Ok(None);
        }
        let mut builder = AuditSegmentBuilder::new(
            position.stream_id,
            position.pruned_before,
            position
                .archive_head
                .as_ref()
                .map(|head| head.object.clone()),
        )?;
        let mut removed = 0u64;
        for sequence in position.pruned_before..position.next_sequence {
            let bytes = self
                .writer
                .store
                .get_bounded(
                    "security.audit",
                    &sequence.to_be_bytes(),
                    MAX_AUDIT_EVENT_BYTES,
                )?
                .context("hot audit prefix is missing")?;
            if !builder.push(sequence, &bytes)? {
                break;
            }
            removed = removed
                .checked_add(bytes.len() as u64 + 8)
                .context("audit archive accounting overflow")?;
            if position
                .hot_bytes
                .checked_sub(removed)
                .context("audit hot accounting mismatch")?
                <= self.writer.budget.drains_to()
            {
                break;
            }
        }
        ensure!(
            builder.record_count() > 0,
            "audit maintenance made no progress"
        );
        let segment = self.writer.store.encrypt_audit_segment(builder)?;
        ensure!(
            state
                .head
                .archived_bytes
                .checked_add(segment.reference.ciphertext_bytes)
                .is_some_and(|n| n <= self.writer.budget.archive_bytes),
            "archive disk budget exhausted"
        );
        let mut updated = state.head.clone();
        updated.draining = true;
        if let Err(error) = self.writer.store.write_batch(&[
            updated.write()?,
            WriteOp::put(META, b"pending", serde_json::to_vec(&segment.reference)?),
            WriteOp::put(META, b"pending-ciphertext", segment.ciphertext.clone()),
        ]) {
            state.failed = true;
            return Err(error);
        }
        state.head = updated;
        Ok(Some(segment))
    }

    async fn maintenance_inner(&self) -> Result<()> {
        let _serial = self.writer.maintenance.lock().await;
        // One bounded segment per turn; permanent backlog resumes on the next
        // turn, leaving cancellation and other consumers a scheduling boundary.
        let worker = self.clone();
        let Some(segment) = tokio::task::spawn_blocking(move || worker.prepare_archive()).await??
        else {
            return Ok(());
        };
        self.writer.destination.publish(&segment).await?;
        let published = self
            .writer
            .destination
            .read(&segment.reference.object)
            .await?;
        let verified = self
            .writer
            .store
            .decrypt_audit_segment(&published, &segment.reference)
            .await?;
        drop(segment);
        drop(published);
        let worker = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut state = worker
                .writer
                .sequence
                .lock()
                .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
            ensure!(!state.failed, "service audit persistence requires recovery");
            let pending = worker
                .writer
                .store
                .get_bounded(META, b"pending", 64 << 10)?
                .context("pending archive missing")?;
            let pending: AuditArchiveReference = serde_json::from_slice(&pending)?;
            ensure!(
                &pending == verified.reference()
                    && pending.object.first_sequence == state.head.position.pruned_before,
                "audit publication phase changed"
            );
            let mut removed = 0u64;
            let mut operations = Vec::new();
            verified.visit(|sequence, bytes| {
                let hot = worker
                    .writer
                    .store
                    .get_bounded(
                        "security.audit",
                        &sequence.to_be_bytes(),
                        MAX_AUDIT_EVENT_BYTES,
                    )?
                    .context("published audit prefix is missing")?;
                ensure!(hot == bytes, "published audit differs from hot record");
                removed = removed
                    .checked_add(bytes.len() as u64 + 8)
                    .context("audit accounting overflow")?;
                operations.push(WriteOp::delete("security.audit", sequence.to_be_bytes()));
                Ok(())
            })?;
            let mut updated = state.head.clone();
            updated.position.hot_bytes = updated
                .position
                .hot_bytes
                .checked_sub(removed)
                .context("audit hot byte count mismatch")?;
            updated.position.pruned_before = pending.object.next_sequence;
            updated.position.archive_head = Some(pending.clone());
            updated.archived_bytes = updated
                .archived_bytes
                .checked_add(pending.ciphertext_bytes)
                .context("archive byte count overflow")?;
            updated.segments = updated
                .segments
                .checked_add(1)
                .context("archive index overflow")?;
            updated.draining = updated.position.hot_bytes > worker.writer.budget.drains_to();
            operations.extend([
                WriteOp::put(
                    ARCHIVES,
                    state.head.segments.to_be_bytes(),
                    serde_json::to_vec(&pending)?,
                ),
                updated.write()?,
                WriteOp::delete(META, b"pending"),
                WriteOp::delete(META, b"pending-ciphertext"),
            ]);
            if let Err(error) = worker.writer.store.write_batch(&operations) {
                state.failed = true;
                return Err(error);
            }
            state.head = updated;
            state.last_failure = None;
            Ok(())
        })
        .await??;
        Ok(())
    }

    pub fn archive_page(&self, first_index: u64, limit: u16) -> Result<Vec<AuditArchiveReference>> {
        ensure!(
            (1..=256).contains(&limit),
            "archive page limit must be 1..256"
        );
        let _work = self.begin()?;
        let state = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
        ensure!(
            first_index <= state.head.segments,
            "archive page position is beyond history"
        );
        let end = first_index
            .saturating_add(u64::from(limit))
            .min(state.head.segments);
        let mut page = Vec::new();
        let mut bytes = 0usize;
        for index in first_index..end {
            let reference = self.archive_reference(index)?;
            let size = serde_json::to_vec(&reference)?.len();
            if bytes
                .checked_add(size)
                .is_none_or(|next| next > MAX_PAGE_BYTES)
            {
                break;
            }
            bytes += size;
            page.push(reference);
        }
        Ok(page)
    }
    fn archive_reference(&self, index: u64) -> Result<AuditArchiveReference> {
        let bytes = self
            .writer
            .store
            .get_bounded(ARCHIVES, &index.to_be_bytes(), 64 << 10)?
            .context("audit archive root missing")?;
        let reference: AuditArchiveReference = serde_json::from_slice(&bytes)?;
        reference.validate()?;
        Ok(reference)
    }

    pub async fn verify_archive(&self, index: u64) -> Result<AuditArchiveReference> {
        let work = self.begin()?;
        tokio::spawn(async move {
            let _serial = work.writer.writer.maintenance.lock().await;
            let reference = work.writer.archive_reference(index)?;
            let bytes = work
                .writer
                .writer
                .destination
                .read(&reference.object)
                .await?;
            work.writer
                .writer
                .store
                .decrypt_audit_segment(&bytes, &reference)
                .await?;
            Ok(reference)
        })
        .await?
    }

    pub async fn export_page(
        &self,
        cursor: Option<SecurityAuditCursor>,
        limit: u16,
    ) -> Result<SecurityAuditPage> {
        ensure!(
            (1..=1024).contains(&limit),
            "audit page limit must be 1..1024"
        );
        let work = self.begin()?;
        tokio::spawn(async move {
            let audit = &work.writer;
            let _serial = audit.writer.maintenance.lock().await;
            let head = audit
                .writer
                .sequence
                .lock()
                .map_err(|_| anyhow::anyhow!("audit state unavailable"))?
                .head
                .clone();
            let cursor = cursor.unwrap_or(SecurityAuditCursor {
                stream_id: head.position.stream_id,
                next_sequence: 0,
                through_sequence: head.position.next_sequence,
            });
            ensure!(
                cursor.stream_id == head.position.stream_id,
                "audit cursor belongs to another installed stream"
            );
            let first_sequence = cursor.next_sequence;
            let end = cursor.through_sequence;
            ensure!(
                first_sequence <= end && end <= head.position.next_sequence,
                "audit export position is beyond history"
            );
            let mut page = SecurityAuditPage {
                stream_id: head.position.stream_id,
                through_sequence: end,
                next_sequence: first_sequence,
                records: Vec::new(),
            };
            if first_sequence == end {
                audit.writer.store.check_access()?;
                return Ok(page);
            }
            let mut bytes_read = 0usize;
            let mut push = |sequence: u64, bytes: &[u8]| -> Result<()> {
                if sequence == page.next_sequence
                    && sequence < end
                    && page.records.len() < usize::from(limit)
                    && bytes_read + bytes.len() <= MAX_PAGE_BYTES
                {
                    page.records.push(serde_json::from_slice(bytes)?);
                    page.next_sequence = sequence
                        .checked_add(1)
                        .context("export sequence overflow")?;
                    bytes_read += bytes.len();
                }
                Ok(())
            };
            if first_sequence < head.position.pruned_before {
                // Locate the first segment with a logarithmic number of point reads.
                let (mut low, mut high) = (0, head.segments);
                while low < high {
                    let middle = low + (high - low) / 2;
                    if audit.archive_reference(middle)?.object.next_sequence <= first_sequence {
                        low = middle + 1;
                    } else {
                        high = middle;
                    }
                }
                let reference = audit.archive_reference(low)?;
                let bytes = audit.writer.destination.read(&reference.object).await?;
                let verified = audit
                    .writer
                    .store
                    .decrypt_audit_segment(&bytes, &reference)
                    .await?;
                verified.visit(&mut push)?;
                // A page crosses at most one archive segment. The exact returned
                // cursor resumes the same sequence space on the next invocation.
            } else {
                for sequence in
                    first_sequence..end.min(first_sequence.saturating_add(u64::from(limit)))
                {
                    let bytes = audit
                        .writer
                        .store
                        .get_bounded(
                            "security.audit",
                            &sequence.to_be_bytes(),
                            MAX_AUDIT_EVENT_BYTES,
                        )?
                        .context("audit export hot record missing")?;
                    push(sequence, &bytes)?;
                }
            }
            audit.writer.store.check_access()?;
            Ok(page)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{
        AuditArchiveDestination, FilesystemAuditArchive, NodeStore, test_utils::LocalKeyProvider,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct UncertainArchive {
        inner: FilesystemAuditArchive,
        uncertain: AtomicBool,
        pause: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }
    #[async_trait::async_trait]
    impl AuditArchiveDestination for UncertainArchive {
        fn identity(&self) -> String {
            self.inner.identity()
        }
        async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()> {
            self.inner.publish(segment).await?;
            if self.pause.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.acquire().await?.forget();
            }
            ensure!(
                !self.uncertain.load(Ordering::SeqCst),
                "injected uncertain publication"
            );
            Ok(())
        }
        async fn read(&self, link: &kasumi_types::AuditArchiveLink) -> Result<Vec<u8>> {
            self.inner.read(link).await
        }
    }
    fn event(sequence: u64) -> SecurityEvent {
        SecurityEvent {
            kind: SecurityEventKind::AccessDenied,
            principal: Some("principal".into()),
            tenant: Some("tenant".into()),
            request_id: format!("event-{sequence}-{}", "a".repeat(120)),
            outcome: SecurityOutcome::Denied,
        }
    }
    async fn fill_to_high(audit: &SecurityAudit) {
        let _maintenance = audit.writer.maintenance.lock().await;
        while audit.status().unwrap().position.hot_bytes < audit.writer.budget.starts_at() {
            let sequence = audit.status().unwrap().position.next_sequence;
            audit.record_sync(event(sequence)).unwrap();
        }
    }

    #[tokio::test]
    async fn uncertain_publication_survives_restart_and_repeated_hot_budget_crossings_preserve_complete_history()
     {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("security.redb");
        let provider = Arc::new(LocalKeyProvider::new([181; 32]));
        let archive = Arc::new(UncertainArchive {
            inner: FilesystemAuditArchive::open(directory.path().join("archives")).unwrap(),
            uncertain: AtomicBool::new(true),
            pause: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        let budget = AuditRetentionBudget {
            hot_bytes: 128 << 10,
            archive_bytes: 128 << 20,
        };
        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
        let store = TenantStore::open_fixture(
            NodeStore::open(&path).unwrap(),
            SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open_with_archive(
            store.clone(),
            budget.clone(),
            archive.clone(),
            admission.clone(),
        )
        .unwrap();
        fill_to_high(&audit).await;
        let before = audit.status().unwrap();
        assert!(audit.maintain().await.is_err());
        assert_eq!(audit.status().unwrap().position.pruned_before, 0);
        assert_eq!(
            store.scan("security.audit").unwrap().len() as u64,
            before.position.next_sequence
        );
        let pending: AuditArchiveReference =
            serde_json::from_slice(&store.get(META, b"pending").unwrap().unwrap()).unwrap();
        // The remote object exists despite the failed acknowledgment. Its exact
        // identity is recovered from encrypted local metadata, never regenerated.
        archive.read(&pending.object).await.unwrap();
        audit.shutdown().await;
        drop(audit);
        drop(store);

        let store = TenantStore::open_fixture(
            NodeStore::open(&path).unwrap(),
            SECURITY_TENANT.into(),
            provider,
        )
        .await
        .unwrap();
        archive.uncertain.store(false, Ordering::SeqCst);
        let audit = SecurityAudit::open_with_archive(
            store.clone(),
            budget.clone(),
            archive.clone(),
            admission.clone(),
        )
        .unwrap();
        audit.maintain().await.unwrap();
        assert_eq!(audit.archive_page(0, 1).unwrap()[0], pending);
        for _ in 0..6 {
            fill_to_high(&audit).await;
            while audit.status().unwrap().position.hot_bytes > budget.drains_to() {
                audit.maintain().await.unwrap();
            }
        }
        let status = audit.status().unwrap();
        assert!(status.position.next_sequence > 500);
        assert!(status.archive_segments > 4);
        assert!(status.position.hot_bytes <= budget.drains_to());
        let mut next = 0;
        let end = status.position.next_sequence;
        while next < end {
            let page = audit
                .export_page(
                    Some(SecurityAuditCursor {
                        stream_id: status.position.stream_id,
                        next_sequence: next,
                        through_sequence: end,
                    }),
                    7,
                )
                .await
                .unwrap();
            assert!(page.next_sequence > next);
            for value in &page.records {
                assert_eq!(value["sequence"], next);
                assert_eq!(value["event"]["request_id"], event(next).request_id);
                next += 1;
            }
            assert_eq!(next, page.next_sequence);
            assert_eq!(page.through_sequence, end);
        }
        for index in 0..status.archive_segments {
            audit.verify_archive(index).await.unwrap();
        }
        assert!(
            audit
                .export_page(
                    Some(SecurityAuditCursor {
                        stream_id: status.position.stream_id,
                        next_sequence: 0,
                        through_sequence: end + 1
                    }),
                    10
                )
                .await
                .is_err()
        );
        assert!(audit.archive_page(status.archive_segments + 1, 10).is_err());
        assert!(
            audit
                .export_page(
                    Some(SecurityAuditCursor {
                        stream_id: Uuid::new_v4(),
                        next_sequence: 0,
                        through_sequence: end
                    }),
                    10
                )
                .await
                .is_err()
        );
        assert!(store.get(META, b"pending").unwrap().is_none());
        // Cancellation must leave the real publication registered. A stopped
        // installation cannot hand ownership to cleanup while it is still live.
        archive.pause.store(true, Ordering::SeqCst);
        fill_to_high(&audit).await;
        let caller_audit = audit.clone();
        let caller = tokio::spawn(async move { caller_audit.maintain().await });
        archive.entered.notified().await;
        caller.abort();
        let _ = caller.await;
        let mut shutdown = Box::pin(audit.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err()
        );
        store.check_access().unwrap();
        archive.release.add_permits(1);
        shutdown.await;
        assert!(store.check_access().is_err());
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
