//! Ordered archive publication. A pruning command carries one bounded immutable
//! segment; every replica verifies its own hot prefix and durably preserves the
//! ciphertext before publishing the new root and pruning watermark together.
use super::*;
use anyhow::{Context, ensure};
use kasumi_store::{AuditSegmentBuilder, InspectedAuditDependency, PreparedAuditSegment};

pub(crate) const PREFIX: &[u8] = b"KASUMI_AUDIT_PRUNE_V1\0";
const MAX_REFERENCE: usize = 64 << 10;
const MAX_COMMAND: usize = PREFIX.len() + 4 + MAX_REFERENCE + MAX_AUDIT_SEGMENT_BYTES;

pub(crate) fn encode(segment: &PreparedAuditSegment) -> anyhow::Result<Vec<u8>> {
    segment.reference.validate()?;
    ensure!(
        segment.ciphertext.len() <= MAX_AUDIT_SEGMENT_BYTES,
        "audit segment exceeds limit"
    );
    let reference = serde_json::to_vec(&segment.reference)?;
    ensure!(
        reference.len() <= MAX_REFERENCE,
        "audit reference exceeds limit"
    );
    let mut bytes =
        Vec::with_capacity(PREFIX.len() + 4 + reference.len() + segment.ciphertext.len());
    bytes.extend(PREFIX);
    bytes.extend(u32::try_from(reference.len())?.to_be_bytes());
    bytes.extend(reference);
    bytes.extend(&segment.ciphertext);
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> anyhow::Result<(AuditArchiveReference, &[u8])> {
    ensure!(
        bytes.len() <= MAX_COMMAND && bytes.len() >= PREFIX.len() + 4 && bytes.starts_with(PREFIX),
        "invalid audit pruning format"
    );
    let encoded = &bytes[PREFIX.len()..];
    let length = u32::from_be_bytes(encoded[..4].try_into()?) as usize;
    ensure!(
        length <= MAX_REFERENCE && length <= encoded.len() - 4,
        "invalid audit reference length"
    );
    let reference: AuditArchiveReference = serde_json::from_slice(&encoded[4..4 + length])?;
    reference.validate()?;
    ensure!(
        serde_json::to_vec(&reference)? == encoded[4..4 + length],
        "noncanonical audit pruning reference"
    );
    let ciphertext = &encoded[4 + length..];
    ensure!(
        ciphertext.len() <= MAX_AUDIT_SEGMENT_BYTES
            && ciphertext.len() as u64 == reference.ciphertext_bytes,
        "audit ciphertext length differs"
    );
    Ok((reference, ciphertext))
}

impl TenantEngine {
    /// Install the shared node reservation before opening or replaying Raft.
    /// This does not start maintenance; Database construction starts the worker
    /// only when its backend has this explicit installation.
    pub fn install_audit_maintenance(
        &self,
        admission: &Arc<crate::admission::NodeAdmission>,
    ) -> Result<()> {
        let _apply = self.apply_lock.lock().map_err(|_| {
            Error::new(ErrorCode::Unavailable, "tenant apply ownership unavailable")
        })?;
        if self.generation()?.state.revision != self.revision_base {
            return Err(Error::new(
                ErrorCode::Conflict,
                "install audit maintenance before Raft replay",
            ));
        }
        let pool = crate::audit_maintenance::NodeAuditMaintenance::install(admission)?;
        let mut installed = self.audit_maintenance.lock().map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "audit maintenance ownership unavailable",
            )
        })?;
        if installed
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(old, &pool))
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "audit maintenance node governor differs",
            ));
        }
        *installed = Some(pool);
        Ok(())
    }

    /// Fixture-only raw command producer. Production uses the owned worker and
    /// its installed node reservation through preparation and proposal outcome.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn prepare_audit_prune(&self) -> anyhow::Result<Option<Vec<u8>>> {
        ensure!(
            self.snapshot_store
                .get()
                .context("audit storage not installed")?
                .storage_access()
                .purpose()
                .is_local_fixture(),
            "raw audit pruning requires fixture storage"
        );
        self.prepare_audit_prune_inner()
    }

    /// Captures only shared immutable roots; at most one segment is serialized.
    pub(crate) fn prepare_audit_prune_inner(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let generation = self.generation()?;
        let state = &generation.state;
        let retention = &state.audit_retention;
        let budget = &state.limits.audit_retention;
        if state.retired
            || state.pending_restore.is_some()
            || retention.hot_bytes <= budget.drains_to()
            || (!retention.draining && retention.hot_bytes < budget.starts_at())
        {
            return Ok(None);
        }
        let store = self
            .snapshot_store
            .get()
            .context("audit storage not installed")?;
        let mut builder = AuditSegmentBuilder::new(
            retention.stream_id,
            retention.pruned_before,
            retention
                .archive_head
                .as_ref()
                .map(|head| head.object.clone()),
        )?;
        let mut remaining = retention.hot_bytes;
        for (index, event) in state.audits.iter().enumerate() {
            if remaining <= budget.drains_to() {
                break;
            }
            let bytes = serde_json::to_vec(event)?;
            let sequence = retention
                .pruned_before
                .checked_add(u64::try_from(index)?)
                .context("audit sequence overflow")?;
            if !builder.push(sequence, &bytes)? {
                break;
            }
            remaining = remaining
                .checked_sub(u64::try_from(bytes.len())?)
                .context("audit hot accounting differs")?;
        }
        if builder.record_count() == 0 {
            return Ok(None);
        }
        let segment = store.encrypt_audit_segment(builder)?;
        ensure!(
            retention
                .archive_bytes
                .checked_add(segment.reference.ciphertext_bytes)
                .is_some_and(|bytes| bytes <= budget.archive_bytes),
            "tenant audit archive capacity exhausted"
        );
        Ok(Some(encode(&segment)?))
    }

    pub(crate) fn apply_audit_prune(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
    ) -> anyhow::Result<kasumi_raft::AppliedResponse> {
        let maintenance = self
            .audit_maintenance
            .lock()
            .map_err(|_| anyhow::anyhow!("audit maintenance ownership unavailable"))?
            .clone();
        ensure!(
            maintenance.is_some()
                || self
                    .snapshot_store
                    .get()
                    .is_some_and(|store| store.storage_access().purpose().is_local_fixture()),
            "audit apply workspace not installed"
        );
        // Committed materialization uses already reserved capacity even when
        // ordinary request admission is exhausted or under RSS pressure.
        let _workspace = maintenance
            .as_ref()
            .map(|pool| pool.applying.lock())
            .transpose()
            .map_err(|_| anyhow::anyhow!("audit apply workspace unavailable"))?;
        ensure!(
            position.retirement_seed.is_none(),
            "audit prune has retirement custody seed"
        );
        let (reference, ciphertext) = decode(bytes)?;
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("tenant apply lock poisoned"))?;
        let previous = self.generation()?;
        let revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .context("audit revision exhausted")?;
        ensure!(
            revision > previous.state.revision,
            "audit applied revision did not advance"
        );
        let mut next = previous.state.clone();
        next.revision = revision;
        let retention = &next.audit_retention;
        let applicable = !next.retired
            && next.pending_restore.is_none()
            && reference.stream_id == retention.stream_id
            && reference.object.first_sequence == retention.pruned_before
            && reference.object.next_sequence <= retention.next_sequence
            && reference.previous
                == retention
                    .archive_head
                    .as_ref()
                    .map(|head| head.object.clone());
        let outcome: Result<()> = if !applicable {
            Err(Error::new(
                ErrorCode::Conflict,
                "audit prefix changed or generation is closed",
            ))
        } else if !retention
            .archive_bytes
            .checked_add(reference.ciphertext_bytes)
            .is_some_and(|bytes| bytes <= next.limits.audit_retention.archive_bytes)
        {
            Err(Error::new(
                ErrorCode::QuotaExceeded,
                "tenant audit archive capacity exhausted",
            ))
        } else {
            let store = self
                .snapshot_store
                .get()
                .context("audit storage not installed")?;
            let dependency = InspectedAuditDependency::from_link(ciphertext, &reference.object)?;
            ensure!(
                dependency.reference() == &reference && dependency.source_tenant() == next.tenant,
                "audit pruning source differs"
            );
            let source = dependency.source_purpose();
            let root = store.storage_access().purpose();
            let runtime = tokio::runtime::Handle::try_current()?;
            let verified = if source == root {
                runtime.block_on(store.decrypt_audit_segment(ciphertext, &reference))?
            } else {
                crate::authorize_audit_source(&next, root, source)?;
                runtime.block_on(store.verify_historical_audit(&dependency, source))?
            };
            let mut removed_bytes = 0u64;
            verified.visit(|sequence, bytes| {
                let index = usize::try_from(
                    sequence
                        .checked_sub(retention.pruned_before)
                        .context("audit sequence differs")?,
                )?;
                let event = next.audits.get(index).context("audit hot prefix missing")?;
                ensure!(
                    serde_json::to_vec(event)? == bytes,
                    "archive differs from hot audit prefix"
                );
                removed_bytes = removed_bytes
                    .checked_add(u64::try_from(bytes.len())?)
                    .context("audit byte count exhausted")?;
                Ok(())
            })?;
            let placement = store.tenant_audit_archive()?;
            placement.preserve_blocking(&PreparedAuditSegment {
                reference: reference.clone(),
                ciphertext: ciphertext.to_vec(),
            })?;
            store.check_access()?;
            for _ in 0..reference.record_count {
                next.audits
                    .pop_front()
                    .context("audit hot prefix missing")?;
            }
            let retention = &mut next.audit_retention;
            retention.pruned_before = reference.object.next_sequence;
            retention.hot_bytes = retention
                .hot_bytes
                .checked_sub(removed_bytes)
                .context("audit hot accounting differs")?;
            retention.archive_bytes = retention
                .archive_bytes
                .checked_add(reference.ciphertext_bytes)
                .context("archive byte count exhausted")?;
            retention.archive_segments = retention
                .archive_segments
                .checked_add(1)
                .context("archive segment count exhausted")?;
            retention.archive_head = Some(reference);
            retention.draining = retention.hot_bytes > next.limits.audit_retention.drains_to();
            retention.validate()?;
            Ok(())
        };
        // Retirement freezes application state, including its authenticated
        // closure digest. A delayed maintenance command cannot mutate that image.
        if !previous.state.retired {
            let accounting = previous.snapshot_accounting.updated(
                &previous.state,
                &next,
                &BTreeMap::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )?;
            ensure!(
                accounting.fits(&next)?,
                "audit pruning metadata exceeds tenant capacity"
            );
            self.publish_generation(Some(Arc::new(Generation {
                terminals: previous.terminals.clone(),
                state: next,
                indexes: previous.indexes.clone(),
                receipt_expiry: previous.receipt_expiry.clone(),
                snapshot_accounting: accounting,
                _read_reservations: vec![],
            })));
        }
        Ok(kasumi_raft::AppliedResponse {
            data: serde_json::to_vec(&outcome)?,
            retirement: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{
        AuditArchiveDestination, FilesystemAuditArchive, NodeStore, TenantStore,
        test_utils::LocalKeyProvider,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    struct UncertainArchive {
        archive: FilesystemAuditArchive,
        fail: AtomicBool,
    }
    #[async_trait::async_trait]
    impl AuditArchiveDestination for UncertainArchive {
        fn identity(&self) -> String {
            format!("uncertain:{}", self.archive.identity())
        }
        async fn publish(&self, segment: &PreparedAuditSegment) -> anyhow::Result<()> {
            self.archive.publish(segment).await?;
            ensure!(
                !self.fail.load(Ordering::SeqCst),
                "uncertain archive publication"
            );
            Ok(())
        }
        async fn read(&self, link: &AuditArchiveLink) -> anyhow::Result<Vec<u8>> {
            self.archive.read(link).await
        }
    }
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<TenantEngine>,
        Arc<TenantStore>,
        Arc<UncertainArchive>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::open(
            directory.path().join("node.redb"),
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let store = TenantStore::open_fixture(
            node,
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([43; 32])),
        )
        .await
        .unwrap();
        let cache = Arc::new(
            FilesystemAuditArchive::open(directory.path().join("tenant-audit-archives")).unwrap(),
        );
        let archive = Arc::new(UncertainArchive {
            archive: FilesystemAuditArchive::open(directory.path().join("external")).unwrap(),
            fail: AtomicBool::new(false),
        });
        store
            .install_tenant_audit_archive(cache, archive.clone())
            .unwrap();
        let engine = Arc::new(
            TenantEngine::new(
                "tenant".into(),
                uuid::Uuid::new_v4().to_string(),
                Policy {
                    grants: vec![Grant {
                        principal: "owner".into(),
                        collection: None,
                        actions: [Action::Admin, Action::Read].into_iter().collect(),
                    }],
                    strict_read_audit: false,
                },
                Limits {
                    audit_retention: AuditRetentionBudget {
                        hot_bytes: 128 << 10,
                        archive_bytes: 8 << 20,
                    },
                    ..Limits::default()
                },
            )
            .unwrap(),
        );
        engine.install_storage_access(&store).unwrap();
        for revision in 1..=50 {
            engine
                .apply_command(
                    revision,
                    Command {
                        context: RequestContext {
                            authorization: RequestAuthorization::service_identity(),
                            tenant: "tenant".into(),
                            principal: "owner".into(),
                            scopes: [Action::Admin, Action::Read].into_iter().collect(),
                            request_id: "read".into(),
                        },
                        timestamp_ms: 1_000,
                        operation: Operation::Audit(AuditEvent {
                            event_id: format!("{revision}:{}", "x".repeat(2_000)),
                            principal: "owner".into(),
                            action: "read".into(),
                            request_id: "read".into(),
                            timestamp_ms: 1_000,
                            data_revision: Some(revision - 1),
                            outcome: "authorized_release".into(),
                            collection: None,
                        }),
                    },
                )
                .unwrap()
                .unwrap();
        }
        (directory, engine, store, archive)
    }
    async fn apply(
        engine: Arc<TenantEngine>,
        command: Vec<u8>,
        index: u64,
    ) -> anyhow::Result<Result<()>> {
        tokio::task::spawn_blocking(move || {
            let position = kasumi_raft::AppliedEntryContext {
                log_id: kasumi_raft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
                previous: None,
                membership: Default::default(),
                command_sha256: hex::encode(Sha256::digest(&command)),
                retirement_seed: None,
            };
            let result = engine.apply_audit_prune(&position, &command)?;
            Ok(serde_json::from_slice(&result.data)?)
        })
        .await?
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uncertain_publication_keeps_hot_prefix_and_exact_replay_publishes_matching_root() {
        let (_directory, engine, store, archive) = fixture().await;
        let before = engine.generation().unwrap();
        let command = engine.prepare_audit_prune().unwrap().unwrap();
        let (reference, _) = decode(&command).unwrap();
        archive.fail.store(true, Ordering::SeqCst);
        assert!(apply(engine.clone(), command.clone(), 51).await.is_err());
        assert_eq!(
            engine.generation().unwrap().state.audit_retention,
            before.state.audit_retention
        );
        assert_eq!(engine.generation().unwrap().state.revision, 50);
        assert!(
            store
                .tenant_audit_archive()
                .unwrap()
                .cache()
                .read_blocking(&reference.object)
                .is_ok()
        );
        archive.fail.store(false, Ordering::SeqCst);
        apply(engine.clone(), command.clone(), 51)
            .await
            .unwrap()
            .unwrap();
        let current = engine.generation().unwrap();
        assert_eq!(
            current.state.audit_retention.archive_head.as_ref(),
            Some(&reference)
        );
        assert_eq!(
            current.state.audit_retention.archive_bytes,
            reference.ciphertext_bytes
        );
        assert_eq!(current.state.audit_retention.archive_segments, 1);
        assert_eq!(
            current.state.audit_retention.next_sequence,
            before.state.audit_retention.next_sequence
        );
        assert!(
            current.state.audit_retention.hot_bytes
                <= current.state.limits.audit_retention.drains_to()
        );
        assert_eq!(
            current.state.audits.len() as u64 + reference.record_count,
            before.state.audits.len() as u64
        );
        assert!(engine.prepare_audit_prune().unwrap().is_none());
        assert_eq!(
            apply(engine.clone(), command, 52)
                .await
                .unwrap()
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(
            engine.generation().unwrap().state.audit_retention,
            current.state.audit_retention
        );
        store.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_wrong_prefix_and_corrupt_ciphertext_never_prune() {
        let (_directory, engine, store, _) = fixture().await;
        let before = engine.generation().unwrap();
        let mut builder =
            AuditSegmentBuilder::new(before.state.audit_retention.stream_id, 0, None).unwrap();
        builder.push(0, br#"{"forged":true}"#).unwrap();
        let wrong = store.encrypt_audit_segment(builder).unwrap();
        assert!(
            apply(engine.clone(), encode(&wrong).unwrap(), 51)
                .await
                .is_err()
        );
        let mut command = engine.prepare_audit_prune().unwrap().unwrap();
        *command.last_mut().unwrap() ^= 1;
        assert!(apply(engine.clone(), command, 51).await.is_err());
        assert_eq!(
            engine.generation().unwrap().state.audit_retention,
            before.state.audit_retention
        );
        assert_eq!(engine.generation().unwrap().state.revision, 50);
        store.shutdown().await;
    }
}
