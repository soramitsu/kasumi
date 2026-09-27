//! Archive publication is a durable phase: only a verified exact pending object
//! can authorize the atomic movement of a hot prefix into permanent archive roots.
use super::*;
use kasumi_store::{AuditSegmentBuilder, PreparedAuditSegment};
use kasumi_types::{
    AuditArchiveReference, AuditCapacity, AuditRetentionState, ErrorCode, MAX_AUDIT_EVENT_BYTES,
    MAX_AUDIT_SEGMENT_BYTES, SecurityAuditCursor, SecurityAuditPage, SecurityAuditStatus,
    audit_record_sha256, exact_json::decode_exact,
};
use sha2::Digest;
use std::time::Duration;
use uuid::Uuid;

const META: &str = "security.audit.meta";
const ARCHIVES: &str = "security.audit.archives";
const MAX_ROOT_BYTES: usize = 64 << 10;
// Reserve wire-envelope and per-record separator bytes inside the shared limit.
const MAX_PAGE_BYTES: usize = kasumi_types::MAX_SECURITY_AUDIT_PAGE_BYTES - 4096;

/// A hot or archived row is admitted only as the exact current writer's
/// bytes for its own sequence; an equivalent spelling is never normalized.
fn decode_record(sequence: u64, bytes: &[u8]) -> Result<SecurityAuditRecord> {
    let record: SecurityAuditRecord =
        decode_exact(bytes, MAX_AUDIT_EVENT_BYTES, "service audit record")?;
    internal(record.validate(), "invalid stored service audit record")?;
    ensure!(
        record.sequence == sequence,
        "service audit record format or sequence differs"
    );
    Ok(record)
}

/// A durable row or derived value that fails its own validation is storage
/// corruption or a broken invariant, never the caller's invalid argument.
fn internal(result: kasumi_types::Result<()>, context: &str) -> Result<()> {
    result.map_err(|error| anyhow::anyhow!("{context}: {}", error.message))
}

fn cursor_differs(message: &'static str) -> kasumi_types::Error {
    kasumi_types::Error::new(ErrorCode::InvalidArgument, message)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    format: u32,
    destination: String,
    pub position: AuditRetentionState,
}
impl Head {
    /// Explicit genesis creation. An existing audit namespace is never adopted,
    /// even when its head is missing or its hot log has already been pruned.
    pub fn initialize(store: &Arc<TenantStore>, destination: &str) -> Result<Self> {
        let view = store.read_view()?;
        for namespace in [META, ARCHIVES, "security.audit"] {
            view.visit(namespace, MAX_AUDIT_SEGMENT_BYTES, |_, _| {
                anyhow::bail!("service audit initialization requires empty audit namespaces")
            })?;
        }
        drop(view);
        let head = Self {
            format: 1,
            destination: destination.into(),
            position: AuditRetentionState::empty(Uuid::new_v4()),
        };
        store.write_batch(&[head.write()?])?;
        Ok(head)
    }

    /// Read one committed encrypted root. Missing state is corruption, never
    /// permission to assign a new permanent sequence space.
    pub fn open(
        store: &Arc<TenantStore>,
        destination: &str,
        budget: &AuditRetentionBudget,
    ) -> Result<Self> {
        let view = store.read_view()?;
        let bytes = view
            .get(META, b"head", MAX_ROOT_BYTES)?
            .context("installed service audit head is missing")?;
        let head: Self = decode_exact(&bytes, MAX_ROOT_BYTES, "service audit head")?;
        ensure!(
            head.format == 1 && head.destination == destination,
            "unsupported or substituted service audit head"
        );
        internal(
            head.position.validate(),
            "invalid stored service audit head",
        )?;
        ensure!(
            head.position.hot_bytes <= budget.hot_bytes
                && head.position.archive_bytes <= budget.archive_bytes,
            "installed service audit exceeds configured retention budgets"
        );
        view.visit(META, MAX_AUDIT_SEGMENT_BYTES, |key, _| {
            ensure!(
                matches!(key, b"head" | b"pending" | b"pending-ciphertext"),
                "unsupported service audit metadata"
            );
            Ok(())
        })?;
        let mut records = 0u64;
        let mut hot_bytes = 0u64;
        view.visit("security.audit", MAX_AUDIT_EVENT_BYTES, |key, bytes| {
            let key: [u8; 8] = key.try_into().context("invalid service audit record key")?;
            let sequence = u64::from_be_bytes(key);
            ensure!(
                sequence >= head.position.pruned_before && sequence < head.position.next_sequence,
                "service audit record lies outside its retained hot range"
            );
            decode_record(sequence, bytes)?;
            records = records
                .checked_add(1)
                .context("service audit count overflow")?;
            hot_bytes = hot_bytes
                .checked_add(bytes.len() as u64 + 8)
                .context("service audit byte count overflow")?;
            ensure!(
                hot_bytes <= budget.hot_bytes,
                "service audit hot read exceeds budget"
            );
            Ok(())
        })?;
        ensure!(
            records == head.position.next_sequence - head.position.pruned_before
                && hot_bytes == head.position.hot_bytes,
            "service audit hot range differs from its committed head"
        );
        match &head.position.archive_head {
            Some(expected) => {
                let bytes = view
                    .get(
                        ARCHIVES,
                        &(head.position.archive_segments - 1).to_be_bytes(),
                        MAX_ROOT_BYTES,
                    )?
                    .context("service audit archive root is missing")?;
                let actual: AuditArchiveReference =
                    decode_exact(&bytes, MAX_ROOT_BYTES, "service audit archive root")?;
                internal(
                    actual.validate(),
                    "invalid stored service audit archive root",
                )?;
                ensure!(
                    actual == *expected,
                    "service audit archive root differs from head"
                );
            }
            None => view.visit(ARCHIVES, MAX_ROOT_BYTES, |_, _| {
                anyhow::bail!("service audit archive records exist without a committed root")
            })?,
        }
        // An uncertain publication remains recoverable from this exact local
        // pending object and unchanged hot records; opening needs no remote I/O.
        let pending = view.get(META, b"pending", MAX_ROOT_BYTES)?;
        let ciphertext = view.get(META, b"pending-ciphertext", MAX_AUDIT_SEGMENT_BYTES)?;
        match (pending, ciphertext) {
            (None, None) => {}
            (Some(bytes), Some(ciphertext)) => {
                let reference: AuditArchiveReference =
                    decode_exact(&bytes, MAX_ROOT_BYTES, "pending service audit publication")?;
                internal(
                    reference.validate(),
                    "invalid stored pending service audit publication",
                )?;
                ensure!(
                    reference.stream_id == head.position.stream_id
                        && reference.object.first_sequence == head.position.pruned_before
                        && reference.object.next_sequence <= head.position.next_sequence
                        && reference.previous
                            == head
                                .position
                                .archive_head
                                .as_ref()
                                .map(|head| head.object.clone())
                        && reference.ciphertext_bytes == ciphertext.len() as u64
                        && reference.object.ciphertext_sha256
                            == hex::encode(sha2::Sha256::digest(&ciphertext)),
                    "pending service audit publication differs from its committed head"
                );
            }
            _ => anyhow::bail!("pending service audit publication is incomplete"),
        }
        Ok(head)
    }
    pub fn write(&self) -> Result<WriteOp> {
        internal(self.position.validate(), "invalid service audit head")?;
        Ok(WriteOp::put(META, b"head", serde_json::to_vec(self)?))
    }

    /// Digest of the exact stored record at next_sequence - 1 while it is hot.
    /// Callers have admitted every hot record through `open` or their writer.
    pub fn hot_tail_sha256(&self, store: &TenantStore) -> Result<Option<String>> {
        let position = &self.position;
        if position.next_sequence == position.pruned_before {
            return Ok(None);
        }
        let bytes = store
            .get_bounded(
                "security.audit",
                &(position.next_sequence - 1).to_be_bytes(),
                MAX_AUDIT_EVENT_BYTES,
            )?
            .context("service audit hot tail is missing")?;
        Ok(Some(audit_record_sha256(&bytes)))
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct WorkerPause {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

pub(super) fn start_worker(
    runtime: &tokio::runtime::Handle,
    weak: Weak<AuditWriter>,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        loop {
            let Some(writer) = weak.upgrade() else { return; };
            #[cfg(test)]
            {
                let pause = writer.worker_pause.lock().unwrap().take();
                if let Some(pause) = pause {
                    pause.entered.notify_one();
                    pause.release.notified().await;
                }
            }
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
    })
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
            archived_bytes: state.head.position.archive_bytes,
            archive_segments: state.head.position.archive_segments,
            draining: state.head.position.draining,
            persistence_failed: state.failed,
            maintenance_failures: state.failures,
            last_failure: state.last_failure.clone(),
            hot_tail_sha256: state.hot_tail_sha256.clone(),
        })
    }

    /// Status-derived capacity plus the exact locally persisted publication.
    /// Reads only local encrypted metadata, never the archive destination.
    pub fn capacity(&self) -> Result<AuditCapacity> {
        let _work = self.begin()?;
        self.writer.store.check_access()?;
        let state = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
        let pending = self.pending_reference(&state.head)?;
        let capacity = AuditCapacity::new(
            &state.head.position,
            &self.writer.budget,
            AuditRetentionBudget::MAINTENANCE_BYTES,
            pending.map(|reference| reference.object),
        );
        internal(capacity.validate(), "invalid service audit capacity")?;
        Ok(capacity)
    }

    /// The exact pending publication, which must continue the committed head.
    /// Callers hold the sequence lock that also serializes its writes.
    fn pending_reference(&self, head: &Head) -> Result<Option<AuditArchiveReference>> {
        let Some(encoded) = self
            .writer
            .store
            .get_bounded(META, b"pending", MAX_ROOT_BYTES)?
        else {
            return Ok(None);
        };
        let reference: AuditArchiveReference = decode_exact(
            &encoded,
            MAX_ROOT_BYTES,
            "pending service audit publication",
        )?;
        internal(
            reference.validate(),
            "invalid stored pending service audit publication",
        )?;
        ensure!(
            reference.stream_id == head.position.stream_id
                && reference.object.first_sequence == head.position.pruned_before
                && reference.previous
                    == head
                        .position
                        .archive_head
                        .as_ref()
                        .map(|head| head.object.clone()),
            "pending audit publication conflicts with head"
        );
        Ok(Some(reference))
    }

    /// Cancellation of the caller does not cancel owned archive publication.
    pub async fn maintain(&self) -> Result<SecurityAuditStatus> {
        self.run_owned(|work, _| async move {
            if let Err(error) = work.writer.maintenance_inner().await {
                work.writer.report_maintenance_failure();
                return Err(error);
            }
            work.writer.status()
        })
        .await
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
        if let Some(reference) = self.pending_reference(&state.head)? {
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
            || (!state.head.position.draining
                && position.hot_bytes < self.writer.budget.starts_at())
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
                .position
                .archive_bytes
                .checked_add(segment.reference.ciphertext_bytes)
                .is_some_and(|n| n <= self.writer.budget.archive_bytes),
            "archive disk budget exhausted"
        );
        let mut updated = state.head.clone();
        updated.position.draining = true;
        if let Err(error) = self.writer.store.write_batch(&[
            updated.write()?,
            WriteOp::put(META, b"pending", serde_json::to_vec(&segment.reference)?),
            WriteOp::put(META, b"pending-ciphertext", segment.ciphertext.clone()),
        ]) {
            state.failed = true;
            return Err(
                kasumi_types::drain::DrainFailure::retained(self.record_terminal(
                    "audit persistence",
                    0,
                    error,
                ))
                .into(),
            );
        }
        state.head = updated;
        Ok(Some(segment))
    }

    async fn maintenance_inner(&self) -> Result<()> {
        let _serial = self.writer.maintenance.lock().await;
        // An admitted waiter may acquire this mutex after another turn failed
        // terminally. It observes that same issue instead of dispatching another
        // failing worker or growing a process-lifetime failure inventory.
        if let Some(issue) = self
            .writer
            .report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .issues()
            .first()
        {
            return Err(kasumi_types::drain::DrainFailure::retained(issue.clone()).into());
        }
        // One bounded segment per turn; permanent backlog resumes on the next
        // turn, leaving cancellation and other consumers a scheduling boundary.
        let worker = self.clone();
        let prepared = tokio::task::spawn_blocking(move || worker.prepare_archive()).await;
        let Some(segment) = self.observe_join("audit archive preparation", 0, prepared)? else {
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
        let committed =
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
                    .get_bounded(META, b"pending", MAX_ROOT_BYTES)?
                    .context("pending archive missing")?;
                let pending: AuditArchiveReference = decode_exact(
                    &pending,
                    MAX_ROOT_BYTES,
                    "pending service audit publication",
                )?;
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
                updated.position.archive_bytes = updated
                    .position
                    .archive_bytes
                    .checked_add(pending.ciphertext_bytes)
                    .context("archive byte count overflow")?;
                updated.position.archive_segments = updated
                    .position
                    .archive_segments
                    .checked_add(1)
                    .context("archive index overflow")?;
                updated.position.draining =
                    updated.position.hot_bytes > worker.writer.budget.drains_to();
                operations.extend([
                    WriteOp::put(
                        ARCHIVES,
                        state.head.position.archive_segments.to_be_bytes(),
                        serde_json::to_vec(&pending)?,
                    ),
                    updated.write()?,
                    WriteOp::delete(META, b"pending"),
                    WriteOp::delete(META, b"pending-ciphertext"),
                ]);
                if let Err(error) = worker.writer.store.write_batch(&operations) {
                    state.failed = true;
                    return Err(kasumi_types::drain::DrainFailure::retained(
                        worker.record_terminal("audit persistence", 0, error),
                    )
                    .into());
                }
                state.head = updated;
                // Archiving moves a prefix; the last record stays hot unless
                // this publication consumed the whole hot range.
                if state.head.position.pruned_before == state.head.position.next_sequence {
                    state.hot_tail_sha256 = None;
                }
                state.last_failure = None;
                Ok(())
            })
            .await;
        self.observe_join("audit archive publication", 0, committed)?;
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
            first_index <= state.head.position.archive_segments,
            "archive page position is beyond history"
        );
        let end = first_index
            .saturating_add(u64::from(limit))
            .min(state.head.position.archive_segments);
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
            .get_bounded(ARCHIVES, &index.to_be_bytes(), MAX_ROOT_BYTES)?
            .context("audit archive root missing")?;
        let reference: AuditArchiveReference =
            decode_exact(&bytes, MAX_ROOT_BYTES, "service audit archive root")?;
        internal(
            reference.validate(),
            "invalid stored service audit archive root",
        )?;
        Ok(reference)
    }

    /// First root whose range ends after `sequence`, with a logarithmic number
    /// of point reads. The caller keeps `sequence` below the archived prefix.
    fn archive_index(&self, sequence: u64, segments: u64) -> Result<u64> {
        let (mut low, mut high) = (0, segments);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.archive_reference(middle)?.object.next_sequence <= sequence {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        ensure!(low < segments, "audit archive position is beyond history");
        Ok(low)
    }

    /// Verify one immutable object and its place in the committed chain: its
    /// link to the preceding root, and the exact head when it is the last root.
    pub async fn verify_archive(&self, index: u64) -> Result<AuditArchiveReference> {
        self.run_owned(move |work, _| async move {
            let _serial = work.writer.writer.maintenance.lock().await;
            let head = work
                .writer
                .writer
                .sequence
                .lock()
                .map_err(|_| anyhow::anyhow!("audit state unavailable"))?
                .head
                .clone();
            ensure!(
                index < head.position.archive_segments,
                "audit verification index is beyond history"
            );
            let reference = work.writer.archive_reference(index)?;
            let previous = match index.checked_sub(1) {
                Some(prior) => Some(work.writer.archive_reference(prior)?.object),
                None => None,
            };
            ensure!(
                reference.stream_id == head.position.stream_id && reference.previous == previous,
                "audit archive chain link differs"
            );
            if index + 1 == head.position.archive_segments {
                ensure!(
                    head.position.archive_head.as_ref() == Some(&reference),
                    "audit archive root differs from head"
                );
            }
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
        .await
    }

    /// One bounded page of typed records. The cursor must continue the exact
    /// captured archive snapshot, the exact record returned before it and the
    /// exact last hot record of its snapshot; a rolled-back or substituted
    /// history fails instead of restarting it or serving its own records.
    pub async fn export_page(
        &self,
        cursor: Option<SecurityAuditCursor>,
        limit: u16,
    ) -> Result<SecurityAuditPage> {
        ensure!(
            (1..=1024).contains(&limit),
            "audit page limit must be 1..1024"
        );
        if let Some(cursor) = &cursor {
            cursor.validate()?;
        }
        self.run_owned(move |work, _| async move {
            let audit = &work.writer;
            // Held for the whole page: no archive publication can move the
            // hot prefix between this status and the reads below.
            let _serial = audit.writer.maintenance.lock().await;
            let status = audit.status()?;
            let position = &status.position;
            let supplied = cursor.is_some();
            let cursor = cursor.unwrap_or_else(|| status.snapshot_cursor());
            ensure!(
                cursor.stream_id == position.stream_id,
                cursor_differs("audit cursor belongs to another installed stream")
            );
            ensure!(
                cursor.through_sequence <= position.next_sequence
                    && cursor.snapshot_segments <= position.archive_segments,
                cursor_differs("audit export position is beyond history")
            );
            // Roots are append-only, so the captured head remains at its index.
            if let Some(snapshot) = &cursor.snapshot_head {
                ensure!(
                    audit
                        .archive_reference(cursor.snapshot_segments - 1)?
                        .object
                        == *snapshot,
                    cursor_differs("audit cursor snapshot differs from the archive chain")
                );
            }
            let end = cursor.through_sequence;
            let hot_record = |sequence: u64| -> Result<Vec<u8>> {
                audit
                    .writer
                    .store
                    .get_bounded(
                        "security.audit",
                        &sequence.to_be_bytes(),
                        MAX_AUDIT_EVENT_BYTES,
                    )?
                    .context("audit export hot record missing")
            };
            let mut builder = PageBuilder {
                page: SecurityAuditPage {
                    stream_id: position.stream_id,
                    through_sequence: end,
                    next_sequence: cursor.next_sequence,
                    snapshot_segments: cursor.snapshot_segments,
                    snapshot_head: cursor.snapshot_head.clone(),
                    snapshot_tail_sha256: cursor.snapshot_tail_sha256.clone(),
                    previous_record_sha256: cursor.previous_record_sha256.clone(),
                    records: Vec::new(),
                },
                anchored: cursor.next_sequence == 0,
                tail_checked: cursor.snapshot_tail_sha256.is_none(),
                supplied,
                limit: usize::from(limit),
                bytes: 0,
                cursor,
            };
            // Every page checks the captured tail, so a copy that diverged
            // after the anchor cannot serve even one page of this range. A
            // still-hot tail is checked locally before any archive read. A
            // cursor carries a tail only for a nonempty range.
            let tail = end.saturating_sub(1);
            if !builder.tail_checked && tail >= position.pruned_before {
                builder.check_tail(tail, &hot_record(tail)?)?;
            }
            // Visit from the anchor record. A page reads records from at most
            // one archive segment; the anchor may lie in the preceding one.
            let mut sequence = builder.cursor.next_sequence.saturating_sub(1);
            while sequence < position.pruned_before && builder.needs() {
                let reference = audit
                    .archive_reference(audit.archive_index(sequence, position.archive_segments)?)?;
                let bytes = audit.writer.destination.read(&reference.object).await?;
                let verified = audit
                    .writer
                    .store
                    .decrypt_audit_segment(&bytes, &reference)
                    .await?;
                drop(bytes);
                verified.visit(|sequence, bytes| builder.visit(sequence, bytes))?;
                sequence = reference.object.next_sequence;
            }
            if builder.needs() {
                let hot_end = end.min(
                    builder
                        .cursor
                        .next_sequence
                        .saturating_add(u64::from(limit)),
                );
                for sequence in sequence.max(position.pruned_before)..hot_end {
                    builder.visit(sequence, &hot_record(sequence)?)?;
                }
            }
            if !builder.tail_checked {
                // Archived since capture and outside this page's segment.
                let reference = audit
                    .archive_reference(audit.archive_index(tail, position.archive_segments)?)?;
                let bytes = audit.writer.destination.read(&reference.object).await?;
                let verified = audit
                    .writer
                    .store
                    .decrypt_audit_segment(&bytes, &reference)
                    .await?;
                drop(bytes);
                verified.visit(|sequence, bytes| builder.check_tail(sequence, bytes))?;
                ensure!(builder.tail_checked, "audit export tail is not retained");
            }
            ensure!(
                builder.anchored,
                cursor_differs("audit cursor previous record is not retained")
            );
            audit.writer.store.check_access()?;
            Ok(builder.page)
        })
        .await
    }
}

struct PageBuilder {
    cursor: SecurityAuditCursor,
    page: SecurityAuditPage,
    anchored: bool,
    tail_checked: bool,
    /// The caller's cursor rather than this writer's own fresh capture.
    supplied: bool,
    limit: usize,
    bytes: usize,
}
impl PageBuilder {
    /// The anchor is still unread, or no record has been returned yet.
    fn needs(&self) -> bool {
        !self.anchored
            || (self.page.records.is_empty()
                && self.page.next_sequence < self.page.through_sequence)
    }

    /// An anchor row is first admitted as an exact valid record, so storage
    /// corruption is never reported as the caller's different history.
    fn check_tail(&mut self, sequence: u64, bytes: &[u8]) -> Result<()> {
        if let Some(tail) = &self.cursor.snapshot_tail_sha256
            && sequence.checked_add(1) == Some(self.cursor.through_sequence)
        {
            decode_record(sequence, bytes)?;
            if *tail != audit_record_sha256(bytes) {
                // Only a caller's cursor can name another history; this
                // writer's own capture differing from storage is corruption.
                ensure!(
                    self.supplied,
                    "service audit hot tail differs from its writer"
                );
                return Err(cursor_differs("audit cursor snapshot tail differs").into());
            }
            self.tail_checked = true;
        }
        Ok(())
    }

    fn visit(&mut self, sequence: u64, bytes: &[u8]) -> Result<()> {
        self.check_tail(sequence, bytes)?;
        if sequence.checked_add(1) == Some(self.cursor.next_sequence) {
            decode_record(sequence, bytes)?;
            ensure!(
                self.cursor.previous_record_sha256.as_deref()
                    == Some(audit_record_sha256(bytes).as_str()),
                cursor_differs("audit cursor previous record differs")
            );
            self.anchored = true;
        }
        if self.anchored
            && sequence == self.page.next_sequence
            && sequence < self.page.through_sequence
            && self.page.records.len() < self.limit
            && self.bytes + bytes.len() <= MAX_PAGE_BYTES
        {
            self.page.records.push(decode_record(sequence, bytes)?);
            self.page.previous_record_sha256 = Some(audit_record_sha256(bytes));
            self.page.next_sequence = sequence
                .checked_add(1)
                .context("export sequence overflow")?;
            self.bytes += bytes.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{
        AuditArchiveDestination, FilesystemAuditArchive, test_utils::LocalKeyProvider,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct UncertainArchive {
        inner: FilesystemAuditArchive,
        uncertain: AtomicBool,
        pause: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
        // Every destination call, including failed and paused publications.
        remote: AtomicUsize,
    }
    impl UncertainArchive {
        fn new(
            root: std::path::PathBuf,
            disk: Arc<kasumi_store::NodeDisk>,
            uncertain: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                inner: FilesystemAuditArchive::open(root, disk).unwrap(),
                uncertain: AtomicBool::new(uncertain),
                pause: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(0),
                remote: AtomicUsize::new(0),
            })
        }
    }
    #[async_trait::async_trait]
    impl AuditArchiveDestination for UncertainArchive {
        fn identity(&self) -> String {
            self.inner.identity()
        }
        async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()> {
            self.remote.fetch_add(1, Ordering::SeqCst);
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
            self.remote.fetch_add(1, Ordering::SeqCst);
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
    fn forked(sequence: u64) -> SecurityEvent {
        SecurityEvent {
            request_id: format!("forked-{sequence}-{}", "b".repeat(120)),
            ..event(sequence)
        }
    }
    async fn fill_to_high(audit: &SecurityAudit) {
        fill_with(audit, event).await;
    }
    async fn fill_with(audit: &SecurityAudit, event: fn(u64) -> SecurityEvent) {
        let _maintenance = audit.writer.maintenance.lock().await;
        fill_held(audit, event).await;
    }
    /// The caller holds the maintenance lock, so no worker turn starts early.
    /// Records are awaited so the store's key-lease monitor keeps running.
    async fn fill_held(audit: &SecurityAudit, event: fn(u64) -> SecurityEvent) {
        while audit.status().unwrap().position.hot_bytes < audit.writer.budget.starts_at() {
            let sequence = audit.status().unwrap().position.next_sequence;
            audit.record(event(sequence)).await.unwrap();
        }
    }
    async fn drain(audit: &SecurityAudit) {
        while audit.status().unwrap().position.hot_bytes > audit.writer.budget.drains_to() {
            audit.maintain().await.unwrap();
        }
    }
    /// Export the complete remaining range, checking each record and anchor.
    async fn export_rest(
        audit: &SecurityAudit,
        mut cursor: Option<SecurityAuditCursor>,
        limit: u16,
        expected: fn(u64) -> SecurityEvent,
    ) -> u64 {
        let mut next = cursor.as_ref().map_or(0, |cursor| cursor.next_sequence);
        loop {
            let page = audit.export_page(cursor.clone(), limit).await.unwrap();
            if let Some(cursor) = &cursor {
                assert_eq!(page.through_sequence, cursor.through_sequence);
                assert_eq!(page.snapshot_head, cursor.snapshot_head);
                assert_eq!(page.snapshot_segments, cursor.snapshot_segments);
                assert_eq!(page.snapshot_tail_sha256, cursor.snapshot_tail_sha256);
            }
            page.resumed().validate().unwrap();
            assert!(page.next_sequence > next || page.next_sequence == page.through_sequence);
            for record in &page.records {
                assert_eq!(record.sequence, next);
                assert_eq!(record.event, expected(next));
                next += 1;
            }
            assert_eq!(next, page.next_sequence);
            if let Some(last) = page.records.last() {
                assert_eq!(page.previous_record_sha256, Some(last.sha256().unwrap()));
            }
            cursor = page.cursor();
            if cursor.is_none() {
                return next;
            }
        }
    }
    fn hot_digest(store: &TenantStore, sequence: u64) -> Option<String> {
        let bytes = store
            .get("security.audit", &sequence.to_be_bytes())
            .unwrap()?;
        Some(audit_record_sha256(&bytes))
    }
    /// Durable corruption must never reach a caller as its own invalid argument.
    fn storage_failure(error: &anyhow::Error) -> String {
        assert!(
            error.downcast_ref::<kasumi_types::Error>().is_none(),
            "typed stored-row rejection: {error:#}"
        );
        format!("{error:#}")
    }
    fn invalid_argument(error: &anyhow::Error) -> &str {
        let error = error
            .downcast_ref::<kasumi_types::Error>()
            .unwrap_or_else(|| panic!("untyped cursor rejection: {error:#}"));
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        &error.message
    }
    /// The same JSON value in another spelling; only exact admission rejects it.
    fn alternate(bytes: &[u8]) -> Vec<u8> {
        let mut changed = b"{ ".to_vec();
        changed.extend_from_slice(&bytes[1..]);
        changed
    }
    type LogicalRows = Vec<(&'static str, Vec<(Vec<u8>, Vec<u8>)>)>;
    fn logical_rows(store: &TenantStore) -> LogicalRows {
        [META, "security.audit", ARCHIVES]
            .into_iter()
            .map(|namespace| (namespace, store.scan(namespace).unwrap()))
            .collect()
    }
    /// Replace every audit row with an earlier copy of the same installation,
    /// as a stopped node restored from an older disk image would observe it.
    fn roll_back(store: &TenantStore, copy: &LogicalRows) {
        let mut operations = Vec::new();
        for (namespace, rows) in logical_rows(store) {
            for (key, _) in rows {
                operations.push(WriteOp::delete(namespace, key));
            }
        }
        for (namespace, rows) in copy {
            for (key, value) in rows {
                operations.push(WriteOp::put(*namespace, key.clone(), value.clone()));
            }
        }
        store.write_batch(&operations).unwrap();
    }

    /// One installed security store with an explicit archive and restartable node.
    struct Fixture {
        storage: crate::test_utils::FixtureStorage,
        path: std::path::PathBuf,
        provider: Arc<LocalKeyProvider>,
        archive: Arc<UncertainArchive>,
        budget: AuditRetentionBudget,
        node: Arc<kasumi_store::NodeStore>,
        store: Arc<TenantStore>,
        _directory: tempfile::TempDir,
    }
    impl Fixture {
        async fn new(seed: u8, uncertain: bool) -> (Self, Arc<SecurityAudit>) {
            let directory = kasumi_store::test_utils::private_tempdir().unwrap();
            let (persistent_config, scratch_config) =
                crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
            let storage = crate::test_utils::FixtureStorage::open(
                &persistent_config,
                &scratch_config,
                Default::default(),
            )
            .unwrap();
            let path = directory.path().join("persistent/security.kv");
            let archive = UncertainArchive::new(
                directory.path().join("persistent/archives"),
                storage.persistent.clone(),
                uncertain,
            );
            let provider = Arc::new(LocalKeyProvider::new([seed; 32]));
            let node = storage
                .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
                .unwrap();
            let store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                SECURITY_TENANT.into(),
                provider.clone(),
            )
            .await
            .unwrap();
            let budget = AuditRetentionBudget {
                hot_bytes: 128 << 10,
                archive_bytes: 128 << 20,
            };
            let audit = SecurityAudit::initialize_with_archive(
                store.clone(),
                budget.clone(),
                archive.clone(),
                storage.admission.clone(),
            )
            .unwrap();
            let fixture = Self {
                storage,
                path,
                provider,
                archive,
                budget,
                node,
                store,
                _directory: directory,
            };
            (fixture, audit)
        }
        fn open(&self) -> Result<Arc<SecurityAudit>> {
            SecurityAudit::open_with_archive(
                self.store.clone(),
                self.budget.clone(),
                self.archive.clone(),
                self.storage.admission.clone(),
            )
        }
        /// Drain every owner, then reopen the same node file with no audit writer.
        async fn restart(self, audit: Option<Arc<SecurityAudit>>) -> Self {
            match audit {
                Some(audit) => audit.shutdown().await.unwrap(),
                None => self.store.shutdown().await.unwrap(),
            }
            self.node.shutdown().await.unwrap();
            let Self {
                storage,
                path,
                provider,
                archive,
                budget,
                node,
                store,
                _directory,
            } = self;
            drop(store);
            drop(node);
            let node = storage
                .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
                .unwrap();
            let store = TenantStore::open_existing_fixture(
                node.clone(),
                SECURITY_TENANT.into(),
                provider.clone(),
            )
            .await
            .unwrap();
            Self {
                storage,
                path,
                provider,
                archive,
                budget,
                node,
                store,
                _directory,
            }
        }
        async fn close(self, audit: Arc<SecurityAudit>) {
            audit.shutdown().await.unwrap();
            self.node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn uncertain_publication_survives_restart_and_repeated_hot_budget_crossings_preserve_complete_history()
     {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let metadata =
            crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)
                .unwrap();
        let storage = crate::test_utils::FixtureStorage::open(
            &persistent_config,
            &scratch_config,
            Default::default(),
        )
        .unwrap();
        let path = directory.path().join("persistent/security.kv");
        let provider = Arc::new(LocalKeyProvider::new([181; 32]));
        let archive = UncertainArchive::new(
            directory.path().join("persistent/archives"),
            storage.persistent.clone(),
            true,
        );
        let budget = AuditRetentionBudget {
            hot_bytes: 128 << 10,
            archive_bytes: 128 << 20,
        };
        let admission = storage.admission.clone();
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            metadata
        );
        let node = storage
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::initialize_with_archive(
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
        // A page exported before the restart keeps its anchored hot cursor.
        let interrupted = audit.export_page(None, 5).await.unwrap();
        assert_eq!(interrupted.snapshot_segments, 0);
        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        drop(audit);
        drop(store);

        let reopened_node = storage
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let store = TenantStore::open_existing_fixture(
            reopened_node.clone(),
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
        // The resumed publication moved the unread range into the archive.
        assert!(audit.status().unwrap().position.pruned_before > interrupted.next_sequence);
        assert_eq!(
            export_rest(&audit, interrupted.cursor(), 64, event).await,
            interrupted.through_sequence
        );
        for _ in 0..6 {
            fill_to_high(&audit).await;
            drain(&audit).await;
        }
        let status = audit.status().unwrap();
        assert!(status.position.next_sequence > 500);
        assert!(status.archive_segments > 4);
        assert!(status.position.hot_bytes <= budget.drains_to());
        let first = audit.export_page(None, 7).await.unwrap();
        let end = first.through_sequence;
        assert!(end >= status.position.next_sequence);
        assert_eq!(export_rest(&audit, first.cursor(), 7, event).await, end);
        for index in 0..status.archive_segments {
            audit.verify_archive(index).await.unwrap();
        }
        let cursor = first.cursor().unwrap();
        let error = audit
            .export_page(
                Some(SecurityAuditCursor {
                    through_sequence: audit.status().unwrap().position.next_sequence + 1,
                    ..cursor.clone()
                }),
                10,
            )
            .await
            .unwrap_err();
        assert!(invalid_argument(&error).contains("beyond history"));
        assert!(audit.archive_page(status.archive_segments + 1, 10).is_err());
        let error = audit
            .export_page(
                Some(SecurityAuditCursor {
                    stream_id: Uuid::new_v4(),
                    ..cursor
                }),
                10,
            )
            .await
            .unwrap_err();
        assert!(invalid_argument(&error).contains("another installed stream"));
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
        shutdown.await.unwrap();
        assert!(store.check_access().is_err());
        reopened_node.shutdown().await.unwrap();
        drop(audit);
        drop(store);
        // Strong installed disk owners and their eight metadata leases survive
        // audit shutdown; every operation, native index and maintenance charge
        // has drained after the final store handle is released.
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            metadata
        );
    }

    #[tokio::test]
    async fn anchored_export_crosses_archive_boundaries_and_rejects_a_rolled_back_copy() {
        let (fixture, audit) = Fixture::new(171, false).await;
        for sequence in 0..4 {
            audit.record_sync(event(sequence)).unwrap();
        }
        // The earlier image a stopped installation could be rolled back to.
        let copy = logical_rows(&fixture.store);
        for sequence in 4..20 {
            audit.record_sync(event(sequence)).unwrap();
        }
        // Below the start threshold no maintenance turn can archive this page.
        let first = audit.export_page(None, 7).await.unwrap();
        assert_eq!(first.next_sequence, 7);
        assert_eq!(first.through_sequence, 20);
        assert_eq!(
            (first.snapshot_segments, first.snapshot_head.clone()),
            (0, None)
        );
        assert_eq!(
            first.previous_record_sha256,
            Some(first.records[6].sha256().unwrap())
        );
        assert_eq!(first.snapshot_tail_sha256, hot_digest(&fixture.store, 19));
        // Maintenance moves the unread hot range into archives between two
        // pages, and a second crossing leaves a hot tail after several roots.
        fill_to_high(&audit).await;
        drain(&audit).await;
        fill_to_high(&audit).await;
        drain(&audit).await;
        let status = audit.status().unwrap();
        assert!(status.archive_segments >= 2);
        assert!(status.position.pruned_before > first.through_sequence);
        assert!(status.position.next_sequence > status.position.pruned_before);
        let remote = fixture.archive.remote.load(Ordering::SeqCst);
        assert_eq!(
            export_rest(&audit, first.cursor(), 64, event).await,
            first.through_sequence
        );
        assert!(fixture.archive.remote.load(Ordering::SeqCst) > remote);
        let late = audit.export_page(None, 3).await.unwrap();
        assert_eq!(late.snapshot_segments, status.archive_segments);
        assert_eq!(
            late.snapshot_head,
            status
                .position
                .archive_head
                .as_ref()
                .map(|head| head.object.clone())
        );
        // Pages read records from one archive segment. A page at a root
        // boundary reads the preceding segment for its anchor, and the first
        // hot page is anchored by the archive head's last record.
        assert_eq!(
            export_rest(&audit, late.cursor(), 1024, event).await,
            late.through_sequence
        );

        let fixture = fixture.restart(Some(audit)).await;
        roll_back(&fixture.store, &copy);
        let audit = fixture.open().unwrap();
        let rolled_back = audit.status().unwrap();
        assert_eq!(rolled_back.position.stream_id, status.position.stream_id);
        assert_eq!(rolled_back.position.next_sequence, 4);
        // The copy then diverges over the same sequence space and root indexes.
        while audit.status().unwrap().archive_segments < late.snapshot_segments
            || audit.status().unwrap().position.next_sequence < late.through_sequence
        {
            fill_with(&audit, forked).await;
            drain(&audit).await;
        }
        let error = audit.export_page(first.cursor(), 8).await.unwrap_err();
        assert!(invalid_argument(&error).contains("previous record differs"));
        let error = audit.export_page(late.cursor(), 8).await.unwrap_err();
        assert!(invalid_argument(&error).contains("snapshot differs"));
        // Fresh exports of the diverged copy remain available.
        let fork = audit.export_page(None, 8).await.unwrap();
        assert_eq!(fork.records[..4], first.records[..4]);
        assert_eq!(fork.records[4].event, forked(4));
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn capacity_matches_status_through_a_crossing_and_uncertain_publication() {
        let (fixture, audit) = Fixture::new(172, true).await;
        let observe = |pending: Option<&AuditArchiveReference>| {
            let status = audit.status().unwrap();
            let capacity = audit.capacity().unwrap();
            assert_eq!(
                capacity,
                AuditCapacity::new(
                    &status.position,
                    &status.budget,
                    AuditRetentionBudget::MAINTENANCE_BYTES,
                    pending.map(|reference| reference.object.clone()),
                )
            );
            capacity
        };
        audit.record_sync(event(0)).unwrap();
        {
            let _maintenance = audit.writer.maintenance.lock().await;
            let idle = observe(None);
            assert_eq!(idle.archive_backlog_bytes, 0);
            assert_eq!(idle.starts_at_bytes, fixture.budget.starts_at());
            assert_eq!(idle.drains_to_bytes, fixture.budget.drains_to());
        }
        {
            let _maintenance = audit.writer.maintenance.lock().await;
            fill_held(&audit, event).await;
            let crossed = observe(None);
            assert!(!crossed.draining);
            assert_eq!(
                crossed.archive_backlog_bytes,
                crossed.hot_bytes - fixture.budget.drains_to()
            );
        }
        assert!(audit.maintain().await.is_err());
        let pending: AuditArchiveReference =
            serde_json::from_slice(&fixture.store.get(META, b"pending").unwrap().unwrap()).unwrap();
        {
            let _maintenance = audit.writer.maintenance.lock().await;
            let uncertain = observe(Some(&pending));
            assert!(uncertain.draining);
            assert_eq!(uncertain.archive_segments, 0);
        }
        fixture.archive.uncertain.store(false, Ordering::SeqCst);
        drain(&audit).await;
        {
            let _maintenance = audit.writer.maintenance.lock().await;
            let drained = observe(None);
            assert!(!drained.draining);
            assert!(drained.archive_segments >= 1);
            assert_eq!(drained.archive_backlog_bytes, 0);
            assert_eq!(audit.archive_page(0, 1).unwrap()[0], pending);
        }
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn verify_requires_each_root_to_link_its_predecessor_and_the_head() {
        let (fixture, audit) = Fixture::new(173, false).await;
        while audit.status().unwrap().archive_segments < 3 {
            fill_to_high(&audit).await;
            drain(&audit).await;
        }
        let segments = audit.status().unwrap().archive_segments;
        for index in 0..segments {
            audit.verify_archive(index).await.unwrap();
        }
        assert!(audit.verify_archive(segments).await.is_err());
        let root = |index: u64| {
            let bytes = fixture
                .store
                .get(ARCHIVES, &index.to_be_bytes())
                .unwrap()
                .unwrap();
            let reference: AuditArchiveReference = serde_json::from_slice(&bytes).unwrap();
            (bytes, reference)
        };
        // A substituted but self-consistent predecessor breaks its successor's
        // link even though the successor's own object still decrypts.
        let (original, mut substituted) = root(0);
        substituted.object.ciphertext_sha256 = "0".repeat(64);
        substituted.validate().unwrap();
        fixture
            .store
            .write_batch(&[WriteOp::put(
                ARCHIVES,
                0u64.to_be_bytes(),
                serde_json::to_vec(&substituted).unwrap(),
            )])
            .unwrap();
        let error = audit.verify_archive(1).await.unwrap_err();
        assert!(format!("{error:#}").contains("chain link differs"));
        assert!(audit.verify_archive(0).await.is_err());
        fixture
            .store
            .write_batch(&[WriteOp::put(ARCHIVES, 0u64.to_be_bytes(), original)])
            .unwrap();
        audit.verify_archive(1).await.unwrap();
        // The last root must be exactly the committed head.
        let last = segments - 1;
        let (original, mut substituted) = root(last);
        substituted.key.provider = "substituted".into();
        substituted.validate().unwrap();
        fixture
            .store
            .write_batch(&[WriteOp::put(
                ARCHIVES,
                last.to_be_bytes(),
                serde_json::to_vec(&substituted).unwrap(),
            )])
            .unwrap();
        let error = audit.verify_archive(last).await.unwrap_err();
        assert!(format!("{error:#}").contains("root differs from head"));
        fixture
            .store
            .write_batch(&[WriteOp::put(ARCHIVES, last.to_be_bytes(), original)])
            .unwrap();
        audit.verify_archive(last).await.unwrap();
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn alternate_rows_fail_open_before_remote_io_and_exact_pending_resumes() {
        let (fixture, audit) = Fixture::new(174, false).await;
        fill_to_high(&audit).await;
        drain(&audit).await;
        // Leave an exact pending publication beside one committed root.
        fixture.archive.uncertain.store(true, Ordering::SeqCst);
        fill_to_high(&audit).await;
        assert!(audit.maintain().await.is_err());
        let status = audit.status().unwrap();
        assert_eq!(status.archive_segments, 1);
        let pending = fixture.store.get(META, b"pending").unwrap().unwrap();
        let fixture = fixture.restart(Some(audit)).await;
        let remote = fixture.archive.remote.load(Ordering::SeqCst);
        let rows = [
            (META, b"head".to_vec()),
            (
                "security.audit",
                status.position.pruned_before.to_be_bytes().to_vec(),
            ),
            (
                "security.audit",
                (status.position.next_sequence - 1).to_be_bytes().to_vec(),
            ),
            (ARCHIVES, 0u64.to_be_bytes().to_vec()),
            (META, b"pending".to_vec()),
        ];
        for (namespace, key) in rows {
            let original = fixture.store.get(namespace, &key).unwrap().unwrap();
            let changed = alternate(&original);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&changed).unwrap(),
                serde_json::from_slice::<serde_json::Value>(&original).unwrap()
            );
            fixture
                .store
                .write_batch(&[WriteOp::put(namespace, key.clone(), changed)])
                .unwrap();
            let Err(error) = fixture.open() else {
                panic!("alternate {namespace} row opened");
            };
            assert!(format!("{error:#}").contains("noncanonical"), "{namespace}");
            assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote);
            fixture
                .store
                .write_batch(&[WriteOp::put(namespace, key, original)])
                .unwrap();
        }
        // An untyped hot row is not a service audit record either.
        let key = status.position.pruned_before.to_be_bytes();
        let original = fixture.store.get("security.audit", &key).unwrap().unwrap();
        let untyped = serde_json::to_vec(&serde_json::json!({
            "sequence": status.position.pruned_before,
            "body": {"document": true}
        }))
        .unwrap();
        fixture
            .store
            .write_batch(&[WriteOp::put("security.audit", key, untyped)])
            .unwrap();
        let Err(error) = fixture.open() else {
            panic!("untyped hot row opened");
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("invalid service audit record") && message.contains("unknown field"),
            "{message}"
        );
        assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote);
        fixture
            .store
            .write_batch(&[WriteOp::put("security.audit", key, original)])
            .unwrap();

        // Restart with the exact current-writer pending publication resumes it.
        let fixture = fixture.restart(None).await;
        fixture.archive.uncertain.store(false, Ordering::SeqCst);
        let audit = fixture.open().unwrap();
        assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote);
        audit.maintain().await.unwrap();
        assert!(fixture.store.get(META, b"pending").unwrap().is_none());
        assert_eq!(
            serde_json::to_vec(&audit.archive_page(1, 1).unwrap()[0]).unwrap(),
            pending
        );
        assert_eq!(
            export_rest(&audit, None, 1024, event).await,
            status.position.next_sequence
        );
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn export_refuses_alternate_or_untyped_records_instead_of_normalizing() {
        let (fixture, audit) = Fixture::new(175, false).await;
        for sequence in 0..5 {
            audit.record_sync(event(sequence)).unwrap();
        }
        let key = 2u64.to_be_bytes();
        let original = fixture.store.get("security.audit", &key).unwrap().unwrap();
        let untyped = serde_json::to_vec(&serde_json::json!({
            "sequence": 2,
            "body": {"document": true}
        }))
        .unwrap();
        // Exact current-writer bytes that fail the record's own validation.
        let mut unsupported: SecurityAuditRecord = serde_json::from_slice(&original).unwrap();
        unsupported.format = 2;
        let mut unnamed: SecurityAuditRecord = serde_json::from_slice(&original).unwrap();
        unnamed.event.request_id = String::new();
        let prefix = audit.export_page(None, 2).await.unwrap();
        for (changed, expected) in [
            (alternate(&original), "noncanonical"),
            (untyped, "unknown field"),
            (
                serde_json::to_vec(&unsupported).unwrap(),
                "invalid stored service audit record: unsupported service audit record format",
            ),
            (
                serde_json::to_vec(&unnamed).unwrap(),
                "invalid stored service audit record",
            ),
        ] {
            fixture
                .store
                .write_batch(&[WriteOp::put("security.audit", key, changed)])
                .unwrap();
            for error in [
                audit.export_page(None, 5).await.unwrap_err(),
                audit.export_page(prefix.cursor(), 3).await.unwrap_err(),
            ] {
                let message = storage_failure(&error);
                assert!(message.contains(expected), "{message}");
            }
            // The page before the substituted row is still exact.
            assert_eq!(audit.export_page(None, 2).await.unwrap(), prefix);
        }
        // The next anchor digests the exact stored bytes of the returned record.
        let tail = prefix.cursor().unwrap();
        let prefix_anchor = fixture
            .store
            .get("security.audit", &1u64.to_be_bytes())
            .unwrap()
            .unwrap();
        let mut substituted = prefix.records[1].clone();
        substituted.timestamp_ms += 1;
        fixture
            .store
            .write_batch(&[
                WriteOp::put("security.audit", key, original),
                WriteOp::put(
                    "security.audit",
                    1u64.to_be_bytes(),
                    serde_json::to_vec(&substituted).unwrap(),
                ),
            ])
            .unwrap();
        let error = audit.export_page(Some(tail.clone()), 3).await.unwrap_err();
        assert!(invalid_argument(&error).contains("previous record differs"));

        // The captured tail is checked on every page the same way: another
        // valid record is a different history, a corrupt row is storage.
        let key = 4u64.to_be_bytes();
        let original = fixture.store.get("security.audit", &key).unwrap().unwrap();
        let mut substituted: SecurityAuditRecord = serde_json::from_slice(&original).unwrap();
        substituted.timestamp_ms += 1;
        fixture
            .store
            .write_batch(&[
                WriteOp::put("security.audit", 1u64.to_be_bytes(), prefix_anchor),
                WriteOp::put(
                    "security.audit",
                    key,
                    serde_json::to_vec(&substituted).unwrap(),
                ),
            ])
            .unwrap();
        let error = audit.export_page(Some(tail.clone()), 1).await.unwrap_err();
        assert!(invalid_argument(&error).contains("snapshot tail differs"));
        // The writer's own capture differing from its storage is corruption.
        let error = audit.export_page(None, 1).await.unwrap_err();
        assert!(storage_failure(&error).contains("hot tail differs from its writer"));
        fixture
            .store
            .write_batch(&[WriteOp::put("security.audit", key, alternate(&original))])
            .unwrap();
        let error = audit.export_page(Some(tail.clone()), 1).await.unwrap_err();
        assert!(storage_failure(&error).contains("noncanonical"));
        fixture
            .store
            .write_batch(&[WriteOp::put("security.audit", key, original)])
            .unwrap();
        assert_eq!(export_rest(&audit, Some(tail), 1, event).await, 5);
        fixture.close(audit).await;
    }

    /// The reviewer's case: the anchor lies before the copy's divergence, so
    /// only the captured tail can tell the two histories apart.
    #[tokio::test]
    async fn a_copy_diverging_after_the_anchor_serves_no_page_of_the_original_range() {
        let (fixture, audit) = Fixture::new(176, false).await;
        for sequence in 0..10 {
            audit.record_sync(event(sequence)).unwrap();
        }
        let copy = logical_rows(&fixture.store);
        for sequence in 10..20 {
            audit.record_sync(event(sequence)).unwrap();
        }
        let first = audit.export_page(None, 7).await.unwrap();
        assert_eq!((first.next_sequence, first.through_sequence), (7, 20));
        assert_eq!(first.snapshot_tail_sha256, hot_digest(&fixture.store, 19));
        let continued = audit.export_page(first.cursor(), 3).await.unwrap();

        let fixture = fixture.restart(Some(audit)).await;
        roll_back(&fixture.store, &copy);
        let audit = fixture.open().unwrap();
        let reopened = audit.status().unwrap();
        assert_eq!(reopened.position.next_sequence, 10);
        // Reopening takes the hot tail from the retained rows themselves.
        assert_eq!(reopened.hot_tail_sha256, hot_digest(&fixture.store, 9));
        for sequence in 10..20 {
            audit.record_sync(forked(sequence)).unwrap();
        }
        assert_eq!(
            audit.status().unwrap().hot_tail_sha256,
            hot_digest(&fixture.store, 19)
        );
        assert_ne!(
            audit.status().unwrap().hot_tail_sha256,
            first.snapshot_tail_sha256
        );
        // The anchor r6 and the records r7..r9 still match, and f10..f19
        // reach the captured end; neither cursor may continue.
        let remote = fixture.archive.remote.load(Ordering::SeqCst);
        for cursor in [first.cursor(), continued.cursor()] {
            let error = audit.export_page(cursor, 3).await.unwrap_err();
            assert!(invalid_argument(&error).contains("snapshot tail differs"));
        }
        // A hot tail is checked locally before any archive read.
        assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote);
        // The copy's divergent tail is refused after it is archived as well.
        while audit.status().unwrap().position.pruned_before < first.through_sequence {
            fill_with(&audit, forked).await;
            drain(&audit).await;
        }
        let error = audit.export_page(first.cursor(), 3).await.unwrap_err();
        assert!(invalid_argument(&error).contains("snapshot tail differs"));
        // A fresh capture of the copy is its own consistent range.
        let fork = audit.export_page(None, 12).await.unwrap();
        assert_eq!(
            fork.records[..10],
            [first.records.clone(), continued.records.clone()].concat()
        );
        assert_eq!(fork.records[10].event, forked(10));
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn a_tail_archived_after_capture_is_checked_in_its_own_segment() {
        let (fixture, audit) = Fixture::new(177, false).await;
        fill_to_high(&audit).await;
        let first = audit.export_page(None, 7).await.unwrap();
        let end = first.through_sequence;
        assert!(first.snapshot_tail_sha256.is_some());
        let status = loop {
            fill_to_high(&audit).await;
            drain(&audit).await;
            let status = audit.status().unwrap();
            if status.position.pruned_before >= end {
                break status;
            }
        };
        let segments = status.archive_segments;
        assert_ne!(
            audit.archive_index(6, segments).unwrap(),
            audit.archive_index(end - 1, segments).unwrap()
        );
        // Drained below the start threshold, so no worker publication races
        // this count: one read for the anchor's segment, one for the tail's.
        let remote = fixture.archive.remote.load(Ordering::SeqCst);
        let page = audit.export_page(first.cursor(), 8).await.unwrap();
        assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote + 2);
        assert_eq!(page.records.first().unwrap().sequence, 7);
        assert_eq!(export_rest(&audit, page.cursor(), 1024, event).await, end);
        fixture.close(audit).await;
    }
}
