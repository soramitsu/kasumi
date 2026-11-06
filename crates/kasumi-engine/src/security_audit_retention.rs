//! Archive publication is a durable phase: only a verified exact pending object
//! can authorize the atomic movement of a hot prefix into permanent archive roots.
use super::*;
use kasumi_store::{AuditSegmentBuilder, PreparedAuditSegment};
use kasumi_types::{
    AuditArchiveReference, AuditCapacity, AuditRetentionState, ErrorCode, MAX_AUDIT_EVENT_BYTES,
    MAX_AUDIT_SEGMENT_BYTES, SecurityAuditCursor, SecurityAuditPage, SecurityAuditPruneRequest,
    SecurityAuditPruneResult, SecurityAuditRetirement, SecurityAuditStatus, audit_record_sha256,
    exact_json::decode_exact,
};
use sha2::Digest;
use std::time::{Duration, Instant};
use uuid::Uuid;

const META: &str = "security.audit.meta";
const ARCHIVES: &str = "security.audit.archives";
/// The one retirement row of a pruned archive. Its own namespace leaves every
/// row that earlier releases check on open unchanged.
const RETIRED: &str = "security.audit.retired";
const RETIREMENT: &[u8] = b"retirement";
/// Pruned objects deleted per step; each step commits its progress.
const DELETION_CHUNK: u64 = 64;
/// How long a prune request deletes before leaving the rest to the
/// maintenance worker, well inside the client's request deadline.
const PRUNE_DELETION_BUDGET: Duration = Duration::from_secs(10);
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
        for namespace in [META, ARCHIVES, RETIRED, "security.audit"] {
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

/// Archive segments below `index` are pruned: their roots remain, and their
/// objects are deleted once `deleting` is None. Retained history starts at
/// `sequence`, the first record of segment `index`, anchored by the exact
/// digest of the record before it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retirement {
    format: u32,
    stream_id: Uuid,
    index: u64,
    sequence: u64,
    record_sha256: String,
    deleting: Option<Deletion>,
}

/// Pruned objects not yet deleted: indexes `from..index`, whose `bytes` of
/// ciphertext still count in `archive_bytes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deletion {
    from: u64,
    bytes: u64,
}

impl Retirement {
    /// The committed retirement, if any. A row that does not continue this
    /// head's stream and archive chain is corruption; this reads no archive
    /// object.
    pub fn open(store: &Arc<TenantStore>, head: &Head) -> Result<Option<Self>> {
        let view = store.read_view()?;
        let mut found: Option<Self> = None;
        view.visit(RETIRED, MAX_ROOT_BYTES, |key, bytes| {
            ensure!(
                key == RETIREMENT && found.is_none(),
                "unsupported service audit retirement row"
            );
            found = Some(decode_exact(
                bytes,
                MAX_ROOT_BYTES,
                "service audit retirement",
            )?);
            Ok(())
        })?;
        let Some(retirement) = found else {
            return Ok(None);
        };
        retirement.validate(&head.position)?;
        let bytes = view
            .get(ARCHIVES, &retirement.index.to_be_bytes(), MAX_ROOT_BYTES)?
            .context("first retained service audit archive root is missing")?;
        let root: AuditArchiveReference =
            decode_exact(&bytes, MAX_ROOT_BYTES, "service audit archive root")?;
        ensure!(
            root.object.first_sequence == retirement.sequence,
            "service audit retirement differs from its first retained root"
        );
        Ok(Some(retirement))
    }

    fn validate(&self, position: &AuditRetentionState) -> Result<()> {
        ensure!(
            self.format == 1 && self.stream_id == position.stream_id,
            "unsupported or substituted service audit retirement"
        );
        internal(
            self.observed().validate(position),
            "invalid stored service audit retirement",
        )?;
        if let Some(deletion) = &self.deleting {
            // The newest segment is never pruned, so its ciphertext is never
            // part of a pending deletion.
            let head = position
                .archive_head
                .as_ref()
                .context("service audit retirement without an archive head")?;
            ensure!(
                deletion.bytes > 0
                    && position
                        .archive_bytes
                        .checked_sub(head.ciphertext_bytes)
                        .is_some_and(|older| deletion.bytes <= older),
                "service audit retirement deletion exceeds its archived bytes"
            );
        }
        Ok(())
    }

    pub fn observed(&self) -> SecurityAuditRetirement {
        SecurityAuditRetirement {
            index: self.index,
            sequence: self.sequence,
            record_sha256: self.record_sha256.clone(),
            deleting_from: self.deleting.as_ref().map(|deletion| deletion.from),
        }
    }

    fn write(&self) -> Result<WriteOp> {
        Ok(WriteOp::put(RETIRED, RETIREMENT, serde_json::to_vec(self)?))
    }
}

/// Who prunes, under which age floor, and the check of their authority that
/// runs immediately before the retirement commits.
pub struct ArchivePrune {
    pub principal: String,
    pub tenant: String,
    pub request_id: String,
    /// No pruned record may be younger than this; zero disables the floor.
    pub minimum_age: Duration,
    /// An error refuses the prune before anything is committed.
    pub authorize: Box<dyn Fn() -> kasumi_types::Result<()> + Send + Sync>,
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
            // Counts of an ended window go first: they are small, and a long
            // archive publication must not hold them back.
            work.writer.write_ended_counts().await;
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
            retired: state.retired.as_ref().map(Retirement::observed),
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
        self.report_failure("archive maintenance failed; hot prefix retained");
    }

    fn report_failure(&self, message: &str) {
        if let Ok(mut state) = self.writer.sequence.lock() {
            state.failures = state.failures.saturating_add(1);
            state.last_failure = Some(message.into());
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
            return Ok(Some(
                self.writer
                    .store
                    .recover_audit_segment(reference, ciphertext)?,
            ));
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
        if let Err(error) = self.writer.store.write_audit_ciphertext_batch(
            [
                updated.write()?,
                WriteOp::put(META, b"pending", serde_json::to_vec(&segment.reference)?),
            ],
            META,
            b"pending-ciphertext",
            &segment,
        ) {
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
        // A prune's pending deletions go first, one bounded chunk per turn:
        // they free archive budget the next publication may need. A failed
        // deletion is reported and retried, and never holds publication back.
        if self.delete_retired(Instant::now()).await.is_err() {
            self.report_failure("pruned archive object deletion failed; it is retried");
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
            let (head, retained) = {
                let state = work
                    .writer
                    .writer
                    .sequence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
                let retained = state.retired.as_ref().map_or(0, |retired| retired.index);
                (state.head.clone(), retained)
            };
            ensure!(
                index < head.position.archive_segments,
                "audit verification index is beyond history"
            );
            // A pruned segment keeps its root, but its object is deleted.
            ensure!(
                index >= retained,
                kasumi_types::Error::new(
                    ErrorCode::NotFound,
                    format!("audit archive segment {index} was pruned"),
                )
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

    /// Retire the archive segments below `request.through_index` once the
    /// export that covers them matches stored history, then delete their
    /// objects. The retirement and its own record commit together; deletion
    /// then proceeds in chunks, each committing its freed bytes, and the
    /// maintenance worker finishes what this request leaves. A crash
    /// therefore leaves either no prune or a retirement whose deletions
    /// resume. Repeating a request retires and records nothing more.
    /// Cancelling the caller cancels nothing.
    pub async fn prune(
        &self,
        request: SecurityAuditPruneRequest,
        prune: ArchivePrune,
    ) -> Result<SecurityAuditPruneResult> {
        request.validate()?;
        self.run_owned(move |work, _| async move {
            // Publication, export, verification and pruning share this lock,
            // so the archive chain checked here is the one retired below.
            let _serial = work.writer.writer.maintenance.lock().await;
            work.writer.prune_held(request, prune).await
        })
        .await
    }

    async fn prune_held(
        &self,
        request: SecurityAuditPruneRequest,
        prune: ArchivePrune,
    ) -> Result<SecurityAuditPruneResult> {
        ensure!(
            self.writer.destination.deletes_objects(),
            kasumi_types::Error::new(
                ErrorCode::Unavailable,
                "the service audit archive destination keeps its objects; raise the archive budget instead",
            )
        );
        // An earlier prune's deletions finish first.
        ensure!(
            self.delete_retired(Instant::now() + PRUNE_DELETION_BUDGET)
                .await?,
            kasumi_types::Error::new(
                ErrorCode::Unavailable,
                "an earlier prune is still deleting archive objects; repeat the request",
            )
        );
        let (head, retired) = {
            let state = self
                .writer
                .sequence
                .lock()
                .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
            ensure!(!state.failed, "service audit persistence requires recovery");
            (state.head.clone(), state.retired.clone())
        };
        let position = &head.position;
        ensure!(
            request.stream_id == position.stream_id,
            cursor_differs("audit prune request belongs to another installed stream")
        );
        let retained = retired.as_ref().map_or(0, |retired| retired.index);
        let through = request.through_index;
        if through <= retained {
            return self.prune_result(0, 0);
        }
        ensure!(
            through < position.archive_segments,
            cursor_differs("the newest audit archive segment is never pruned")
        );
        // The pruned roots and the first retained one must form one chain
        // that continues from the last root pruned before.
        let mut previous = match retained.checked_sub(1) {
            Some(index) => Some(self.archive_reference(index)?.object),
            None => None,
        };
        let mut bytes = 0u64;
        let mut first_retained = None;
        for index in retained..=through {
            let root = self.archive_reference(index)?;
            ensure!(
                root.stream_id == position.stream_id && root.previous == previous,
                "audit archive chain link differs"
            );
            if index + 1 == position.archive_segments {
                ensure!(
                    position.archive_head.as_ref() == Some(&root),
                    "audit archive root differs from head"
                );
            }
            previous = Some(root.object.clone());
            if index < through {
                bytes = bytes
                    .checked_add(root.ciphertext_bytes)
                    .context("audit archive accounting overflow")?;
            } else {
                first_retained = Some(root);
            }
        }
        let first_retained = first_retained.context("first retained audit root missing")?;
        let sequence = first_retained.object.first_sequence;

        // The export must reach past every pruned record and agree with
        // stored history at its anchor, snapshot head and captured tail.
        let exported = &request.exported;
        ensure!(
            exported.next_sequence >= sequence,
            cursor_differs("the export does not cover the pruned audit archive segments")
        );
        ensure!(
            exported.through_sequence <= position.next_sequence
                && exported.snapshot_segments <= position.archive_segments,
            cursor_differs("audit export position is beyond history")
        );
        if let Some(snapshot) = &exported.snapshot_head {
            ensure!(
                self.archive_reference(exported.snapshot_segments - 1)?
                    .object
                    == *snapshot,
                cursor_differs("audit cursor snapshot differs from the archive chain")
            );
        }
        let mut records = RetainedRecords {
            audit: self,
            position,
            segment: None,
        };
        // Reading the last pruned record authenticates its segment.
        let anchor = records.digest(sequence - 1).await?;
        ensure!(
            exported.previous_record_sha256.as_deref()
                == Some(records.digest(exported.next_sequence - 1).await?.as_str()),
            cursor_differs("audit cursor previous record differs")
        );
        if let Some(tail) = &exported.snapshot_tail_sha256 {
            ensure!(
                *tail == records.digest(exported.through_sequence - 1).await?,
                cursor_differs("audit cursor snapshot tail differs")
            );
        }
        drop(records);
        // Timestamps follow the wall clock, not sequence order, so every
        // pruned record is checked against the floor.
        if !prune.minimum_age.is_zero() {
            let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
            let cutoff = now.saturating_sub(u64::try_from(prune.minimum_age.as_millis())?);
            for index in retained..through {
                let segment = self
                    .verified_segment(&self.archive_reference(index)?)
                    .await?;
                segment.visit(|record_sequence, record| {
                    ensure!(
                        decode_record(record_sequence, record)?.timestamp_ms <= cutoff,
                        cursor_differs(
                            "an audit record to prune is younger than the prune minimum age"
                        )
                    );
                    Ok(())
                })?;
            }
        }

        let event = SecurityEvent {
            kind: SecurityEventKind::ArchivePruned {
                retained_index: through,
                retained_sequence: sequence,
                pruned_record_sha256: anchor.clone(),
                segments: through - retained,
                bytes,
            },
            principal: Some(prune.principal),
            tenant: Some(prune.tenant),
            request_id: prune.request_id,
            outcome: SecurityOutcome::Succeeded,
        };
        event.validate()?;
        let retirement = Retirement {
            format: 1,
            stream_id: position.stream_id,
            index: through,
            sequence,
            record_sha256: anchor,
            deleting: Some(Deletion {
                from: retained,
                bytes,
            }),
        };
        let authorize = prune.authorize;
        let worker = self.clone();
        let committed =
            tokio::task::spawn_blocking(move || -> Result<()> {
                // The original credential and Control policy still hold at the
                // commit, however long the checks above took.
                authorize()?;
                let mut state = worker
                    .writer
                    .sequence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
                ensure!(!state.failed, "service audit persistence requires recovery");
                let current = &state.head.position;
                ensure!(
                    current.archive_segments == head.position.archive_segments
                        && current.archive_bytes == head.position.archive_bytes
                        && current.archive_head == head.position.archive_head
                        && state.retired == retired,
                    "audit prune phase changed"
                );
                let mut updated = state.head.clone();
                let (record, tail) =
                    worker.admit_record(&mut updated, event, None, RecordClass::Prune)?;
                let operations = [record, retirement.write()?, updated.write()?];
                if let Err(error) = worker.writer.store.write_batch(&operations) {
                    state.failed = true;
                    return Err(kasumi_types::drain::DrainFailure::retained(
                        worker.record_terminal("audit persistence", 0, error),
                    )
                    .into());
                }
                state.head = updated;
                state.hot_tail_sha256 = Some(tail);
                state.retired = Some(retirement);
                if state.head.position.hot_bytes >= worker.writer.budget.starts_at() {
                    worker.writer.wake.notify_one();
                }
                Ok(())
            })
            .await;
        self.observe_join("audit archive prune", 0, committed)?;
        // The retirement is committed; deletion left now resumes in maintenance.
        if self
            .delete_retired(Instant::now() + PRUNE_DELETION_BUDGET)
            .await
            .is_err()
        {
            self.report_failure("pruned archive object deletion failed; it is retried");
        }
        self.prune_result(through - retained, bytes)
    }

    fn prune_result(
        &self,
        pruned_segments: u64,
        pruned_bytes: u64,
    ) -> Result<SecurityAuditPruneResult> {
        let state = self
            .writer
            .sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
        Ok(SecurityAuditPruneResult {
            stream_id: state.head.position.stream_id,
            retired: state
                .retired
                .as_ref()
                .context("pruned service audit has no retirement")?
                .observed(),
            pruned_segments,
            pruned_bytes,
            archive_bytes: state.head.position.archive_bytes,
        })
    }

    /// Delete pending pruned objects a chunk at a time; each chunk's deletions
    /// are durable before its commit subtracts their bytes, so accounting never
    /// falls below what the destination holds. Stops once `deadline` has passed
    /// after a chunk. True once nothing is pending. The caller holds the
    /// maintenance lock.
    async fn delete_retired(&self, deadline: Instant) -> Result<bool> {
        loop {
            let (retirement, deletion) = {
                let state = self
                    .writer
                    .sequence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
                let Some(retirement) = &state.retired else {
                    return Ok(true);
                };
                let Some(deletion) = &retirement.deleting else {
                    return Ok(true);
                };
                ensure!(!state.failed, "service audit persistence requires recovery");
                (retirement.clone(), deletion.clone())
            };
            let end = retirement
                .index
                .min(deletion.from.saturating_add(DELETION_CHUNK));
            let mut links = Vec::new();
            let mut bytes = 0u64;
            for index in deletion.from..end {
                let root = self.archive_reference(index)?;
                bytes = bytes
                    .checked_add(root.ciphertext_bytes)
                    .context("audit archive accounting overflow")?;
                links.push(root.object);
            }
            let outcomes = self.writer.destination.delete(&links).await?;
            ensure!(
                outcomes.len() == links.len(),
                "audit archive deletion outcomes differ from their objects"
            );
            let worker = self.clone();
            let committed = tokio::task::spawn_blocking(move || -> Result<bool> {
                let mut state = worker
                    .writer
                    .sequence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("audit state unavailable"))?;
                ensure!(!state.failed, "service audit persistence requires recovery");
                ensure!(
                    state.retired.as_ref() == Some(&retirement),
                    "audit archive deletion phase changed"
                );
                let remaining = deletion
                    .bytes
                    .checked_sub(bytes)
                    .context("audit archive deletion accounting mismatch")?;
                let done = end == retirement.index;
                ensure!(
                    done == (remaining == 0),
                    "audit archive deletion accounting mismatch"
                );
                let mut updated = retirement.clone();
                updated.deleting = (!done).then_some(Deletion {
                    from: end,
                    bytes: remaining,
                });
                let mut head = state.head.clone();
                head.position.archive_bytes = head
                    .position
                    .archive_bytes
                    .checked_sub(bytes)
                    .context("audit archive byte count mismatch")?;
                if let Err(error) = worker
                    .writer
                    .store
                    .write_batch(&[updated.write()?, head.write()?])
                {
                    state.failed = true;
                    return Err(kasumi_types::drain::DrainFailure::retained(
                        worker.record_terminal("audit persistence", 0, error),
                    )
                    .into());
                }
                state.head = head;
                state.retired = Some(updated);
                Ok(done)
            })
            .await;
            if self.observe_join("audit archive deletion", 0, committed)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }

    /// One archived object, read and authenticated against its root.
    async fn verified_segment(
        &self,
        reference: &AuditArchiveReference,
    ) -> Result<kasumi_store::VerifiedAuditSegment> {
        let bytes = self.writer.destination.read(&reference.object).await?;
        self.writer
            .store
            .decrypt_audit_segment(&bytes, reference)
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
            let hot_record = |sequence: u64| -> Result<kasumi_store::PlaintextValue> {
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
            // Pruned records are gone. A cursor that still needs one has
            // expired; at the boundary itself, the retained digest of the
            // last pruned record stands for it, as anchor or captured tail.
            if let Some(retired) = &status.retired {
                ensure!(
                    builder.cursor.next_sequence >= retired.sequence,
                    kasumi_types::Error::new(
                        ErrorCode::CursorExpired,
                        format!(
                            "audit records before sequence {} were pruned; start a new export",
                            retired.sequence
                        ),
                    )
                );
                if builder.cursor.next_sequence == retired.sequence {
                    builder.check_retired_anchor(retired)?;
                    sequence = retired.sequence;
                }
                if !builder.tail_checked && end == retired.sequence {
                    builder.check_retired_tail(retired)?;
                }
            }
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

/// Exact stored records of retained history, read for a prune's checks. One
/// authenticated segment is kept: the checks usually fall in one segment.
struct RetainedRecords<'a> {
    audit: &'a SecurityAudit,
    position: &'a AuditRetentionState,
    segment: Option<kasumi_store::VerifiedAuditSegment>,
}
impl RetainedRecords<'_> {
    /// Digest of the exact stored record at `sequence`, admitted first as a
    /// valid record of that sequence.
    async fn digest(&mut self, sequence: u64) -> Result<String> {
        if sequence >= self.position.pruned_before {
            let bytes = self
                .audit
                .writer
                .store
                .get_bounded(
                    "security.audit",
                    &sequence.to_be_bytes(),
                    MAX_AUDIT_EVENT_BYTES,
                )?
                .context("audit hot record missing")?;
            decode_record(sequence, &bytes)?;
            return Ok(audit_record_sha256(&bytes));
        }
        let held = self.segment.as_ref().is_some_and(|segment| {
            let object = &segment.reference().object;
            (object.first_sequence..object.next_sequence).contains(&sequence)
        });
        if !held {
            let index = self
                .audit
                .archive_index(sequence, self.position.archive_segments)?;
            let reference = self.audit.archive_reference(index)?;
            self.segment = Some(self.audit.verified_segment(&reference).await?);
        }
        let segment = self
            .segment
            .as_ref()
            .context("audit archive segment missing")?;
        let mut digest = None;
        segment.visit(|current, bytes| {
            if current == sequence {
                decode_record(current, bytes)?;
                digest = Some(audit_record_sha256(bytes));
            }
            Ok(())
        })?;
        digest.context("audit archive segment lacks its record")
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

    /// A cursor at the retained boundary is anchored by the stored digest of
    /// the last pruned record instead of the record itself.
    fn check_retired_anchor(&mut self, retired: &SecurityAuditRetirement) -> Result<()> {
        if self.cursor.previous_record_sha256.as_deref() != Some(retired.record_sha256.as_str()) {
            ensure!(
                self.supplied,
                "service audit retirement anchor differs from its writer"
            );
            return Err(cursor_differs("audit cursor previous record differs").into());
        }
        self.anchored = true;
        Ok(())
    }

    /// A completed cursor ending at the retained boundary captured the last
    /// pruned record as its tail.
    fn check_retired_tail(&mut self, retired: &SecurityAuditRetirement) -> Result<()> {
        if self.cursor.snapshot_tail_sha256.as_deref() != Some(retired.record_sha256.as_str()) {
            ensure!(
                self.supplied,
                "service audit retirement anchor differs from its writer"
            );
            return Err(cursor_differs("audit cursor snapshot tail differs").into());
        }
        self.tail_checked = true;
        Ok(())
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
        /// Keep objects as an S3 destination does: pruning is refused.
        keeps: AtomicBool,
        /// Delete only this many objects of a call, then fail as a deletion
        /// interrupted before its progress commit would. MAX means never.
        interrupt_deletion: AtomicUsize,
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
                keeps: AtomicBool::new(false),
                interrupt_deletion: AtomicUsize::new(usize::MAX),
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
        fn deletes_objects(&self) -> bool {
            !self.keeps.load(Ordering::SeqCst)
        }
        async fn delete(
            &self,
            links: &[kasumi_types::AuditArchiveLink],
        ) -> Result<Vec<kasumi_store::AuditObjectDeletion>> {
            self.remote.fetch_add(1, Ordering::SeqCst);
            let interrupt = self.interrupt_deletion.load(Ordering::SeqCst);
            if interrupt != usize::MAX {
                self.inner
                    .delete(&links[..interrupt.min(links.len())])
                    .await?;
                anyhow::bail!("injected interrupted deletion");
            }
            self.inner.delete(links).await
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
    fn alternate(
        store: &TenantStore,
        bytes: &[u8],
    ) -> kasumi_store::test_utils::FixturePlaintextCopy {
        kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(store, b"{ ", &bytes[1..])
            .unwrap()
    }
    type LogicalRows = [(&'static str, kasumi_store::PlaintextScan); 3];
    fn logical_rows(store: &TenantStore) -> LogicalRows {
        [META, "security.audit", ARCHIVES]
            .map(|namespace| (namespace, store.scan(namespace).unwrap()))
    }
    /// Replace every audit row with an earlier copy of the same installation,
    /// as a stopped node restored from an older disk image would observe it.
    fn roll_back(store: &TenantStore, copy: &LogicalRows) {
        let current = logical_rows(store);
        let count = current
            .iter()
            .chain(copy.iter())
            .try_fold(0usize, |count, (_, rows)| {
                count
                    .checked_add(rows.len())
                    .context("fixture rollback count overflow")
            })
            .unwrap();
        let metadata_bytes = u64::try_from(
            count
                .checked_mul(std::mem::size_of::<
                    kasumi_store::test_utils::FixtureWrite<'_>,
                >())
                .unwrap(),
        )
        .unwrap()
        .checked_add(kasumi_store::DiskMemoryLease::token_allocation_bytes::<u8>().unwrap())
        .unwrap();
        let _metadata_charge = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(metadata_bytes)
            .unwrap();
        let mut operations = Vec::new();
        operations.try_reserve_exact(count).unwrap();
        assert!(
            operations
                .capacity()
                .checked_mul(std::mem::size_of::<
                    kasumi_store::test_utils::FixtureWrite<'_>,
                >())
                .unwrap() as u64
                <= metadata_bytes
        );
        for (namespace, rows) in &current {
            for (key, _) in rows {
                operations.push(kasumi_store::test_utils::FixtureWrite::Delete(
                    namespace, key,
                ));
            }
        }
        for (namespace, rows) in copy {
            for (key, value) in rows {
                operations.push(kasumi_store::test_utils::FixtureWrite::Put(
                    namespace, key, value,
                ));
            }
        }
        kasumi_store::test_utils::FixtureWriteBatch::prepare(store, &operations)
            .unwrap()
            .write(store)
            .unwrap();
    }

    /// One installed security store with an explicit archive and restartable node.
    struct Fixture {
        storage: crate::test_utils::FixtureStorage,
        path: std::path::PathBuf,
        provider: Arc<LocalKeyProvider>,
        archive: Arc<UncertainArchive>,
        budget: AuditRetentionBudget,
        node: kasumi_store::NodeStore,
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
        assert!(node.retire().is_retired());

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
        assert!(reopened_node.retire().is_retired());
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
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            ARCHIVES,
            &(0u64.to_be_bytes()),
            &(serde_json::to_vec(&substituted).unwrap()),
        )
        .unwrap();
        let error = audit.verify_archive(1).await.unwrap_err();
        assert!(format!("{error:#}").contains("chain link differs"));
        assert!(audit.verify_archive(0).await.is_err());
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            ARCHIVES,
            &(0u64.to_be_bytes()),
            original.as_bytes(),
        )
        .unwrap();
        audit.verify_archive(1).await.unwrap();
        // The last root must be exactly the committed head.
        let last = segments - 1;
        let (original, mut substituted) = root(last);
        substituted.key.provider = "substituted".into();
        substituted.validate().unwrap();
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            ARCHIVES,
            &(last.to_be_bytes()),
            &(serde_json::to_vec(&substituted).unwrap()),
        )
        .unwrap();
        let error = audit.verify_archive(last).await.unwrap_err();
        assert!(format!("{error:#}").contains("root differs from head"));
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            ARCHIVES,
            &(last.to_be_bytes()),
            original.as_bytes(),
        )
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
            let changed = alternate(&fixture.store, &original);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&changed).unwrap(),
                serde_json::from_slice::<serde_json::Value>(&original).unwrap()
            );
            kasumi_store::test_utils::write_plaintext_copy_for_fixture(
                &fixture.store,
                namespace,
                &(key),
                &(changed),
            )
            .unwrap();
            let Err(error) = fixture.open() else {
                panic!("alternate {namespace} row opened");
            };
            assert!(format!("{error:#}").contains("noncanonical"), "{namespace}");
            assert_eq!(fixture.archive.remote.load(Ordering::SeqCst), remote);
            kasumi_store::test_utils::write_plaintext_copy_for_fixture(
                &fixture.store,
                namespace,
                &(key),
                original.as_bytes(),
            )
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
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            "security.audit",
            &(key),
            &(untyped),
        )
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
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            "security.audit",
            &(key),
            original.as_bytes(),
        )
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
        enum TamperBytes {
            Generated(Vec<u8>),
            Copied(kasumi_store::test_utils::FixturePlaintextCopy),
        }
        impl TamperBytes {
            fn as_bytes(&self) -> &[u8] {
                match self {
                    Self::Generated(bytes) => bytes,
                    Self::Copied(bytes) => bytes.as_bytes(),
                }
            }
        }
        for (changed, expected) in [
            (
                TamperBytes::Copied(alternate(&fixture.store, &original)),
                "noncanonical",
            ),
            (TamperBytes::Generated(untyped), "unknown field"),
            (
                TamperBytes::Generated(serde_json::to_vec(&unsupported).unwrap()),
                "invalid stored service audit record: unsupported service audit record format",
            ),
            (
                TamperBytes::Generated(serde_json::to_vec(&unnamed).unwrap()),
                "invalid stored service audit record",
            ),
        ] {
            kasumi_store::test_utils::write_plaintext_copy_for_fixture(
                &fixture.store,
                "security.audit",
                &(key),
                changed.as_bytes(),
            )
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
        let substituted = serde_json::to_vec(&substituted).unwrap();
        kasumi_store::test_utils::FixtureWriteBatch::prepare(
            &fixture.store,
            &[
                kasumi_store::test_utils::FixtureWrite::Put(
                    "security.audit",
                    &key,
                    original.as_bytes(),
                ),
                kasumi_store::test_utils::FixtureWrite::Put(
                    "security.audit",
                    &1u64.to_be_bytes(),
                    &substituted,
                ),
            ],
        )
        .unwrap()
        .write(&fixture.store)
        .unwrap();
        let error = audit.export_page(Some(tail.clone()), 3).await.unwrap_err();
        assert!(invalid_argument(&error).contains("previous record differs"));

        // The captured tail is checked on every page the same way: another
        // valid record is a different history, a corrupt row is storage.
        let key = 4u64.to_be_bytes();
        let original = fixture.store.get("security.audit", &key).unwrap().unwrap();
        let mut substituted: SecurityAuditRecord = serde_json::from_slice(&original).unwrap();
        substituted.timestamp_ms += 1;
        let substituted = serde_json::to_vec(&substituted).unwrap();
        kasumi_store::test_utils::FixtureWriteBatch::prepare(
            &fixture.store,
            &[
                kasumi_store::test_utils::FixtureWrite::Put(
                    "security.audit",
                    &1u64.to_be_bytes(),
                    prefix_anchor.as_bytes(),
                ),
                kasumi_store::test_utils::FixtureWrite::Put("security.audit", &key, &substituted),
            ],
        )
        .unwrap()
        .write(&fixture.store)
        .unwrap();
        let error = audit.export_page(Some(tail.clone()), 1).await.unwrap_err();
        assert!(invalid_argument(&error).contains("snapshot tail differs"));
        // The writer's own capture differing from its storage is corruption.
        let error = audit.export_page(None, 1).await.unwrap_err();
        assert!(storage_failure(&error).contains("hot tail differs from its writer"));
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            "security.audit",
            &(key),
            &(alternate(&fixture.store, &original)),
        )
        .unwrap();
        let error = audit.export_page(Some(tail.clone()), 1).await.unwrap_err();
        assert!(storage_failure(&error).contains("noncanonical"));
        kasumi_store::test_utils::write_plaintext_copy_for_fixture(
            &fixture.store,
            "security.audit",
            &(key),
            original.as_bytes(),
        )
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

    fn pruner() -> ArchivePrune {
        ArchivePrune {
            principal: "operator".into(),
            tenant: "__kasumi_control".into(),
            request_id: "prune-request".into(),
            minimum_age: Duration::ZERO,
            authorize: Box::new(|| Ok(())),
        }
    }
    fn prune_request(
        through_index: u64,
        exported: &SecurityAuditPage,
    ) -> SecurityAuditPruneRequest {
        SecurityAuditPruneRequest {
            stream_id: exported.stream_id,
            through_index,
            exported: exported.resumed(),
        }
    }
    /// Every record of one export from `cursor` to its end, checked for
    /// contiguity, and its last page.
    async fn export_all(
        audit: &SecurityAudit,
        mut cursor: Option<SecurityAuditCursor>,
        limit: u16,
    ) -> (Vec<SecurityAuditRecord>, SecurityAuditPage) {
        let mut records: Vec<SecurityAuditRecord> = Vec::new();
        loop {
            let page = audit.export_page(cursor.clone(), limit).await.unwrap();
            page.resumed().validate().unwrap();
            let first = page.next_sequence - page.records.len() as u64;
            if let Some(last) = records.last() {
                assert_eq!(first, last.sequence + 1);
            }
            for (offset, record) in page.records.iter().enumerate() {
                assert_eq!(record.sequence, first + offset as u64);
            }
            records.extend(page.records.iter().cloned());
            cursor = page.cursor();
            if cursor.is_none() {
                return (records, page);
            }
        }
    }
    /// Export from the start until a page ends exactly at `boundary`.
    async fn export_until(audit: &SecurityAudit, boundary: u64) -> SecurityAuditCursor {
        let mut cursor = None;
        loop {
            let next = cursor
                .as_ref()
                .map_or(0, |cursor: &SecurityAuditCursor| cursor.next_sequence);
            if next == boundary {
                return cursor.unwrap();
            }
            let limit = (boundary - next).min(1024) as u16;
            cursor = audit.export_page(cursor, limit).await.unwrap().cursor();
        }
    }
    async fn fill_segments(audit: &SecurityAudit, segments: u64) {
        while audit.status().unwrap().archive_segments < segments {
            fill_to_high(audit).await;
            drain(audit).await;
        }
    }
    fn present(fixture: &Fixture, root: &AuditArchiveReference) -> bool {
        fixture.archive.inner.read_blocking(&root.object).is_ok()
    }
    fn code(error: &anyhow::Error) -> ErrorCode {
        error
            .downcast_ref::<kasumi_types::Error>()
            .unwrap_or_else(|| panic!("untyped prune refusal: {error:#}"))
            .code
    }

    #[tokio::test]
    async fn a_prune_keeps_retained_history_exportable_and_verifiable_across_restart() {
        let (fixture, audit) = Fixture::new(178, false).await;
        fill_segments(&audit, 4).await;
        let before = audit.status().unwrap();
        let segments = before.archive_segments;
        let roots = audit.archive_page(0, 256).unwrap();
        let through = segments - 1;
        let boundary = roots[through as usize].object.first_sequence;
        let (records, last) = export_all(&audit, None, 64).await;
        assert_eq!(records.len() as u64, before.position.next_sequence);
        // Cursors captured before the prune: one inside the pruned range and
        // one exactly at its end.
        let early = audit.export_page(None, 3).await.unwrap().cursor().unwrap();
        let at_boundary = export_until(&audit, boundary).await;
        let pruned_bytes: u64 = roots[..through as usize]
            .iter()
            .map(|root| root.ciphertext_bytes)
            .sum();

        let result = audit
            .prune(prune_request(through, &last), pruner())
            .await
            .unwrap();
        let anchor = records[boundary as usize - 1].sha256().unwrap();
        assert_eq!(
            result.retired,
            SecurityAuditRetirement {
                index: through,
                sequence: boundary,
                record_sha256: anchor.clone(),
                deleting_from: None,
            }
        );
        assert_eq!(
            (result.pruned_segments, result.pruned_bytes),
            (through, pruned_bytes)
        );
        assert_eq!(result.archive_bytes, before.archived_bytes - pruned_bytes);
        let status = audit.status().unwrap();
        status.validate().unwrap();
        assert_eq!(status.retired, Some(result.retired.clone()));
        assert_eq!(status.archive_segments, segments);
        assert_eq!(status.archived_bytes, result.archive_bytes);
        // The prune is the next record, written with the retirement.
        assert_eq!(
            status.position.next_sequence,
            before.position.next_sequence + 1
        );
        // Objects are gone but every root stays listed.
        for (index, root) in roots.iter().enumerate() {
            assert_eq!(present(&fixture, root), index as u64 >= through, "{index}");
        }
        assert_eq!(audit.archive_page(0, 256).unwrap(), roots);
        for index in 0..segments {
            match audit.verify_archive(index).await {
                Ok(root) => {
                    assert!(index >= through);
                    assert_eq!(root, roots[index as usize]);
                }
                Err(error) => {
                    assert!(index < through, "{error:#}");
                    assert_eq!(code(&error), ErrorCode::NotFound);
                }
            }
        }

        let check = |audit: Arc<SecurityAudit>,
                     early: SecurityAuditCursor,
                     at_boundary: SecurityAuditCursor| {
            let records = records.clone();
            let anchor = anchor.clone();
            let roots = roots.clone();
            async move {
                // A fresh export starts at the boundary, anchored by the last
                // pruned record's digest, and ends with the prune's record.
                let status = audit.status().unwrap();
                let cursor = status.snapshot_cursor();
                assert_eq!(cursor.next_sequence, boundary);
                assert_eq!(cursor.previous_record_sha256, Some(anchor.clone()));
                let (fresh, _) = export_all(&audit, None, 64).await;
                assert_eq!(fresh[..fresh.len() - 1], records[boundary as usize..]);
                let prune = fresh.last().unwrap();
                assert_eq!(prune.sequence, records.len() as u64);
                assert_eq!(
                    prune.event,
                    SecurityEvent {
                        kind: SecurityEventKind::ArchivePruned {
                            retained_index: through,
                            retained_sequence: boundary,
                            pruned_record_sha256: anchor.clone(),
                            segments: through,
                            bytes: pruned_bytes,
                        },
                        principal: Some("operator".into()),
                        tenant: Some("__kasumi_control".into()),
                        request_id: "prune-request".into(),
                        outcome: SecurityOutcome::Succeeded,
                    }
                );
                // A cursor exactly at the boundary continues the old range.
                let (continued, _) = export_all(&audit, Some(at_boundary.clone()), 64).await;
                assert_eq!(continued, records[boundary as usize..]);
                // One that still needs a pruned record has expired.
                let error = audit.export_page(Some(early), 8).await.unwrap_err();
                assert_eq!(code(&error), ErrorCode::CursorExpired);
                assert!(format!("{error:#}").contains(&format!("before sequence {boundary}")));
                // A boundary cursor with another anchor is another history.
                let error = audit
                    .export_page(
                        Some(SecurityAuditCursor {
                            previous_record_sha256: Some("0".repeat(64)),
                            ..at_boundary.clone()
                        }),
                        8,
                    )
                    .await
                    .unwrap_err();
                assert!(invalid_argument(&error).contains("previous record differs"));
                // A completed range captured when the stream ended at the
                // boundary checks its tail against the same digest.
                let completed = SecurityAuditCursor {
                    stream_id: status.position.stream_id,
                    next_sequence: boundary,
                    through_sequence: boundary,
                    snapshot_segments: 1,
                    snapshot_head: Some(roots[0].object.clone()),
                    snapshot_tail_sha256: Some(anchor.clone()),
                    previous_record_sha256: Some(anchor.clone()),
                };
                let page = audit.export_page(Some(completed.clone()), 8).await.unwrap();
                assert!(page.records.is_empty() && page.cursor().is_none());
                let other = Some(records[0].sha256().unwrap());
                let error = audit
                    .export_page(
                        Some(SecurityAuditCursor {
                            snapshot_tail_sha256: other.clone(),
                            previous_record_sha256: other,
                            ..completed
                        }),
                        8,
                    )
                    .await
                    .unwrap_err();
                assert!(invalid_argument(&error).contains("differs"));
            }
        };
        check(audit.clone(), early.clone(), at_boundary.clone()).await;
        let retired = audit.status().unwrap().retired;
        let fixture = fixture.restart(Some(audit)).await;
        let audit = fixture.open().unwrap();
        assert_eq!(audit.status().unwrap().retired, retired);
        check(audit.clone(), early, at_boundary).await;
        for index in through..segments {
            audit.verify_archive(index).await.unwrap();
        }
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn a_prune_refuses_what_its_export_does_not_vouch_for_and_repeats_as_a_no_op() {
        let (fixture, audit) = Fixture::new(179, false).await;
        fill_segments(&audit, 3).await;
        let roots = audit.archive_page(0, 256).unwrap();
        let segments = roots.len() as u64;
        let (_, last) = export_all(&audit, None, 64).await;
        let unchanged = |audit: &SecurityAudit, next_sequence: u64| {
            let status = audit.status().unwrap();
            assert!(status.retired.is_none());
            assert_eq!(status.position.next_sequence, next_sequence);
            assert!(roots.iter().all(|root| present(&fixture, root)));
        };
        let next = audit.status().unwrap().position.next_sequence;
        let refuse = |request: SecurityAuditPruneRequest, prune: ArchivePrune| {
            let audit = audit.clone();
            async move { audit.prune(request, prune).await.unwrap_err() }
        };
        // Another stream, the newest segment, and an export that stops short.
        let mut other = prune_request(1, &last);
        other.stream_id = Uuid::new_v4();
        other.exported.stream_id = other.stream_id;
        assert!(
            invalid_argument(&refuse(other, pruner()).await).contains("another installed stream")
        );
        assert!(
            invalid_argument(&refuse(prune_request(segments, &last), pruner()).await)
                .contains("never pruned")
        );
        let short = audit.export_page(None, 2).await.unwrap();
        assert!(
            invalid_argument(&refuse(prune_request(1, &short), pruner()).await)
                .contains("does not cover")
        );
        // Anchors that differ from stored history, on a page that covers the
        // first segment and continues.
        let covering = export_until(&audit, roots[1].object.first_sequence + 1).await;
        let forged = |change: fn(&mut SecurityAuditCursor)| {
            let mut exported = covering.clone();
            change(&mut exported);
            SecurityAuditPruneRequest {
                stream_id: exported.stream_id,
                through_index: 1,
                exported,
            }
        };
        let previous = forged(|cursor| cursor.previous_record_sha256 = Some("0".repeat(64)));
        assert!(
            invalid_argument(&refuse(previous, pruner()).await).contains("previous record differs")
        );
        let tail = forged(|cursor| cursor.snapshot_tail_sha256 = Some("0".repeat(64)));
        assert!(invalid_argument(&refuse(tail, pruner()).await).contains("snapshot tail differs"));
        let head =
            forged(|cursor| cursor.snapshot_head.as_mut().unwrap().object_id = Uuid::new_v4());
        assert!(invalid_argument(&refuse(head, pruner()).await).contains("snapshot differs"));
        // A destination that keeps its objects, a refused authority and the
        // age floor refuse before anything commits.
        fixture.archive.keeps.store(true, Ordering::SeqCst);
        assert_eq!(
            code(&refuse(prune_request(1, &last), pruner()).await),
            ErrorCode::Unavailable
        );
        fixture.archive.keeps.store(false, Ordering::SeqCst);
        let mut revoked = pruner();
        revoked.authorize = Box::new(|| {
            Err(kasumi_types::Error::new(
                ErrorCode::Forbidden,
                "credential revoked",
            ))
        });
        assert_eq!(
            code(&refuse(prune_request(1, &last), revoked).await),
            ErrorCode::Forbidden
        );
        let mut floor = pruner();
        floor.minimum_age = Duration::from_secs(86_400);
        assert!(
            invalid_argument(&refuse(prune_request(1, &last), floor).await)
                .contains("younger than the prune minimum age")
        );
        unchanged(&audit, next);

        // A valid prune, then the same request again: nothing more is pruned
        // or recorded.
        let first = audit
            .prune(prune_request(1, &last), pruner())
            .await
            .unwrap();
        assert_eq!(first.pruned_segments, 1);
        let next = audit.status().unwrap().position.next_sequence;
        let repeated = audit
            .prune(prune_request(1, &last), pruner())
            .await
            .unwrap();
        assert_eq!((repeated.pruned_segments, repeated.pruned_bytes), (0, 0));
        assert_eq!(repeated.retired, first.retired);
        assert_eq!(audit.status().unwrap().position.next_sequence, next);
        // A later prune continues the chain from the earlier one.
        fill_segments(&audit, segments + 2).await;
        let (_, last) = export_all(&audit, None, 64).await;
        let second = audit
            .prune(prune_request(segments, &last), pruner())
            .await
            .unwrap();
        assert_eq!(
            (second.retired.index, second.pruned_segments),
            (segments, segments - 1)
        );
        assert_eq!(
            second.pruned_bytes,
            roots[1..]
                .iter()
                .map(|root| root.ciphertext_bytes)
                .sum::<u64>()
        );
        assert!(roots.iter().all(|root| !present(&fixture, root)));
        audit.verify_archive(segments).await.unwrap();
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn an_interrupted_deletion_resumes_after_restart() {
        let (fixture, audit) = Fixture::new(180, false).await;
        fill_segments(&audit, 4).await;
        let roots = audit.archive_page(0, 256).unwrap();
        let through = roots.len() as u64 - 1;
        let pruned_bytes: u64 = roots[..through as usize]
            .iter()
            .map(|root| root.ciphertext_bytes)
            .sum();
        let (records, last) = export_all(&audit, None, 64).await;
        let before = audit.status().unwrap();
        // The first object is deleted, then the deletion stops before its
        // progress commits, as a crash there would leave it.
        fixture
            .archive
            .interrupt_deletion
            .store(1, Ordering::SeqCst);
        let result = audit
            .prune(prune_request(through, &last), pruner())
            .await
            .unwrap();
        assert_eq!(result.retired.deleting_from, Some(0));
        assert_eq!(result.archive_bytes, before.archived_bytes);
        let status = audit.status().unwrap();
        assert_eq!(status.retired, Some(result.retired.clone()));
        assert!(status.last_failure.unwrap().contains("deletion failed"));
        assert!(!present(&fixture, &roots[0]));
        assert!(roots[1..].iter().all(|root| present(&fixture, root)));
        // The retirement is committed: the pruned range is no longer served.
        assert_eq!(
            code(&audit.verify_archive(1).await.unwrap_err()),
            ErrorCode::NotFound
        );
        let fixture = fixture.restart(Some(audit)).await;
        let audit = fixture.open().unwrap();
        assert_eq!(
            audit.status().unwrap().retired,
            Some(result.retired.clone())
        );
        assert_eq!(
            audit.status().unwrap().archived_bytes,
            before.archived_bytes
        );
        fixture
            .archive
            .interrupt_deletion
            .store(usize::MAX, Ordering::SeqCst);
        audit.maintain().await.unwrap();
        let status = audit.status().unwrap();
        assert_eq!(status.retired.as_ref().unwrap().deleting_from, None);
        assert_eq!(status.archived_bytes, before.archived_bytes - pruned_bytes);
        assert!(
            roots[..through as usize]
                .iter()
                .all(|root| !present(&fixture, root))
        );
        assert!(present(&fixture, &roots[through as usize]));
        let (fresh, _) = export_all(&audit, None, 64).await;
        assert_eq!(
            fresh[..fresh.len() - 1],
            records[roots[through as usize].object.first_sequence as usize..]
        );
        // Reopening once more finds the completed retirement unchanged.
        let fixture = fixture.restart(Some(audit)).await;
        let audit = fixture.open().unwrap();
        assert_eq!(audit.status().unwrap().retired, status.retired);
        assert_eq!(
            audit.status().unwrap().archived_bytes,
            status.archived_bytes
        );
        fixture.close(audit).await;
    }

    #[tokio::test]
    async fn a_prune_records_itself_when_required_records_no_longer_fit() {
        let (fixture, audit) = Fixture::new(181, false).await;
        fill_segments(&audit, 3).await;
        let through = audit.status().unwrap().archive_segments - 1;
        let (_, last) = export_all(&audit, None, 64).await;
        // Archives stop draining; required records fill the hot log until
        // one is refused.
        fixture.archive.uncertain.store(true, Ordering::SeqCst);
        let refused = loop {
            let sequence = audit.status().unwrap().position.next_sequence;
            if let Err(error) = audit.record(event(sequence)).await {
                break error;
            }
        };
        assert!(refused.to_string().contains("hot budget exhausted"));
        let full = audit.status().unwrap();
        assert!(full.position.hot_bytes <= required_limit(&fixture.budget));
        let result = audit
            .prune(prune_request(through, &last), pruner())
            .await
            .unwrap();
        assert_eq!(result.pruned_segments, through);
        let status = audit.status().unwrap();
        assert_eq!(
            status.position.next_sequence,
            full.position.next_sequence + 1
        );
        assert!(status.position.hot_bytes <= fixture.budget.hot_bytes);
        let bytes = fixture
            .store
            .get("security.audit", &full.position.next_sequence.to_be_bytes())
            .unwrap()
            .unwrap();
        let record: SecurityAuditRecord = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            record.event.kind,
            SecurityEventKind::ArchivePruned { retained_index, .. } if retained_index == through
        ));
        // Required records still wait for archives to drain.
        assert!(audit.record(event(0)).await.is_err());
        fixture.archive.uncertain.store(false, Ordering::SeqCst);
        drain(&audit).await;
        audit
            .record(event(status.position.next_sequence))
            .await
            .unwrap();
        fixture.close(audit).await;
    }

    /// The reserve holds the largest record a prune can write.
    #[test]
    fn the_largest_prune_record_fits_the_hot_reserve() {
        let name = "\"".repeat(256);
        let record = SecurityAuditRecord {
            format: kasumi_types::SECURITY_AUDIT_RECORD_FORMAT,
            sequence: u64::MAX,
            timestamp_ms: u64::MAX,
            event: SecurityEvent {
                kind: SecurityEventKind::ArchivePruned {
                    retained_index: u64::MAX,
                    retained_sequence: u64::MAX,
                    pruned_record_sha256: "f".repeat(64),
                    segments: u64::MAX,
                    bytes: u64::MAX,
                },
                principal: Some(name.clone()),
                tenant: Some(name.clone()),
                request_id: name,
                outcome: SecurityOutcome::Succeeded,
            },
            transport: None,
        };
        record.validate().unwrap();
        let bytes = serde_json::to_vec(&record).unwrap().len() as u64 + 8;
        assert!(bytes * 2 <= super::super::PRUNE_RESERVE_BYTES, "{bytes}");
    }
}
