//! Closed state machine for the existing retired source quorum. It owns only the
//! independently keyed custody store and never constructs an application backend.
use crate::control::{self, AppliedCursor, AppliedEntryContext, META, load};
use crate::lifetime::{StorageHandle, StorageLease};
use crate::storage::{SnapshotCoverage, SnapshotEnvelope, SnapshotKind, as_snapshot};
use crate::{BasicNode, LogId, SnapshotBuffer, TypeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::{CustodyStore, WriteOp};
use openraft::{
    Entry, EntryPayload, OptionalSend, RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership, storage::RaftStateMachine,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) const CLOSED_SNAPSHOT: &str = "raft.custody-snapshot";

fn err(error: impl std::fmt::Display) -> StorageError<u64> {
    StorageIOError::write(&std::io::Error::other(error.to_string())).into()
}

type AppliedState = (Option<LogId<u64>>, StoredMembership<u64, BasicNode>);

pub(crate) fn applied(custody: &CustodyStore) -> Result<AppliedState> {
    let cursor: AppliedCursor = load(custody.store(), META, b"applied")?
        .context("retired custody applied cursor absent")?;
    Ok(match cursor {
        AppliedCursor::Entry(position) => (Some(position.log_id), position.membership),
        AppliedCursor::Snapshot { meta, .. } => (meta.last_log_id, meta.last_membership),
    })
}

pub(crate) fn capture(custody: &CustodyStore) -> Result<SnapshotEnvelope> {
    let state = control::custody_head(custody)?.policy;
    let (last_log_id, last_membership) = applied(custody)?;
    let committed = control::committed_coverage(custody.store())?
        .context("closed snapshot lacks committed coverage")?;
    ensure!(
        last_log_id.is_some_and(|id| id <= committed && id.index <= committed.index),
        "closed snapshot applied position exceeds commitment"
    );
    let meta = SnapshotMeta {
        last_log_id,
        last_membership,
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    let retirement = crate::snapshot_custody::capture(custody, &meta, Some(state.origin))?;
    Ok(SnapshotEnvelope {
        version: 1,
        kind: SnapshotKind::Custody,
        meta,
        backend: kasumi_store::SnapshotImage::from_bytes(custody.store().scratch_disk(), &[])?,
        retirement,
    })
}

pub(crate) fn publish(
    custody: &CustodyStore,
    snapshot: &SnapshotEnvelope,
    limit: u64,
) -> Result<()> {
    crate::custody_snapshot_storage::check_format(custody)?;
    ensure!(
        snapshot.kind == SnapshotKind::Custody
            && snapshot.version == 1
            && snapshot.backend.is_empty(),
        "application payload forbidden in custody snapshot"
    );
    let retirement = snapshot
        .retirement
        .as_ref()
        .context("closed snapshot lacks retirement")?;
    retirement.validate(&snapshot.meta)?;
    let bytes = snapshot.encode(limit)?;
    let digest = bytes.sha256().to_owned();
    let backend_digest = crate::command::sha256(&[]);
    let coverage_bytes = crate::storage::encode_snapshot_coverage(&SnapshotCoverage {
        kind: SnapshotKind::Custody,
        manifest_id: uuid::Uuid::new_v4().to_string(),
        snapshot_sha256: digest.clone(),
        backend_sha256: backend_digest.clone(),
        meta: snapshot.meta.clone(),
    })?;
    // Bound control coverage before staging chunks or publishing custody.
    let (chunks, manifest) = crate::custody_snapshot_storage::stage(&bytes, limit)?;
    let mut install = crate::snapshot_custody::installation_writes(
        custody,
        &snapshot.meta,
        Some(retirement),
        &backend_digest,
        &digest,
    )?;
    install
        .writes
        .push(WriteOp::put(META, b"snapshot_coverage", coverage_bytes));
    install.writes.push(manifest);
    let mut replacements = install
        .records
        .as_ref()
        .map_or_else(Vec::new, |records| records.namespaces().to_vec());
    replacements.push((CLOSED_SNAPSHOT, &chunks));
    custody
        .store()
        .replace_namespaces(&replacements, &install.writes)
}

pub(crate) fn load_snapshot(
    custody: &CustodyStore,
    limit: u64,
) -> Result<Option<SnapshotEnvelope>> {
    let Some(bytes) = crate::custody_snapshot_storage::load_image(custody, limit)? else {
        return Ok(None);
    };
    let snapshot = SnapshotEnvelope::decode(bytes.disk(), &mut bytes.reader(), limit)?;
    ensure!(
        snapshot.kind == SnapshotKind::Custody
            && snapshot.version == 1
            && snapshot.backend.is_empty(),
        "application payload forbidden in custody snapshot"
    );
    let coverage = crate::storage::load_snapshot_coverage(custody.store())?
        .context("closed snapshot lacks control coverage")?;
    ensure!(
        coverage.kind == SnapshotKind::Custody
            && coverage.meta == snapshot.meta
            && coverage.snapshot_sha256 == bytes.sha256()
            && coverage.backend_sha256 == crate::command::sha256(&[]),
        "closed snapshot control coverage differs"
    );
    crate::snapshot_custody::check_published(
        custody,
        &snapshot.meta,
        &coverage.snapshot_sha256,
        snapshot.retirement.as_ref(),
    )?;
    ensure!(
        snapshot.retirement.is_some(),
        "closed snapshot retirement absent"
    );
    Ok(Some(snapshot))
}

#[derive(Clone)]
pub(crate) struct CustodyMachine {
    custody: StorageHandle<CustodyStore>,
    snapshot_limit: u64,
    snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    control_gate: Arc<Mutex<()>>,
    failed: Arc<AtomicBool>,
    // Keep the same ownership claim alive even after public handles disappear.
    _ownership: Arc<AtomicBool>,
}
impl CustodyMachine {
    pub async fn open(
        custody: Arc<CustodyStore>,
        lease: Arc<StorageLease>,
        ownership: Arc<AtomicBool>,
        snapshot_limit: u64,
        snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    ) -> Result<Self> {
        let control_gate = crate::storage::control_gate(&custody)?;
        let store = custody.clone();
        let gate = control_gate.clone();
        let startup_lease = lease.clone();
        let startup_ownership = ownership.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _lease = startup_lease;
            let _ownership = startup_ownership;
            let _gate = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            control::custody_head(&store)?;
            // This atomically records the latest durable closed state as a
            // snapshot before OpenRaft is allowed to purge its covered log prefix.
            publish(&store, &capture(&store)?, snapshot_limit)
        })
        .await??;
        Ok(Self {
            custody: StorageHandle::new(custody, Some(lease)),
            snapshot_limit,
            snapshot_buffers,
            control_gate,
            failed: Arc::new(AtomicBool::new(false)),
            _ownership: ownership,
        })
    }
    pub fn failure_flag(&self) -> Arc<AtomicBool> {
        self.failed.clone()
    }
    fn failure(&self, error: impl std::fmt::Display) -> StorageError<u64> {
        self.failed.store(true, Ordering::Release);
        err(error)
    }
}

pub(crate) struct CustodySnapshotBuilder {
    machine: CustodyMachine,
    captured: Result<Arc<SnapshotEnvelope>>,
}
impl RaftSnapshotBuilder<TypeConfig> for CustodySnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let snapshot = self.captured.as_ref().map_err(err)?.clone();
        let machine = self.machine.clone();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let _gate = machine
                .control_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            machine.custody.store().check_access()?;
            if let Some(current) = load_snapshot(&machine.custody, machine.snapshot_limit)?
                && current.meta.last_log_id.map(|id| id.index)
                    >= snapshot.meta.last_log_id.map(|id| id.index)
            {
                if current.meta.last_log_id.map(|id| id.index)
                    == snapshot.meta.last_log_id.map(|id| id.index)
                {
                    ensure!(
                        current.meta.last_log_id == snapshot.meta.last_log_id
                            && current.meta.last_membership == snapshot.meta.last_membership,
                        "closed snapshot position differs"
                    );
                    crate::snapshot_custody::check_same_retirement(
                        current.retirement.as_ref(),
                        snapshot.retirement.as_ref(),
                    )?;
                }
                return as_snapshot(&current, machine.snapshot_limit, &machine.snapshot_buffers);
            }
            publish(&machine.custody, &snapshot, machine.snapshot_limit)?;
            as_snapshot(&snapshot, machine.snapshot_limit, &machine.snapshot_buffers)
        })
        .await
        .map_err(|error| self.machine.failure(error))?
        .map_err(|error| self.machine.failure(error))
    }
}
impl RaftStateMachine<TypeConfig> for CustodyMachine {
    type SnapshotBuilder = CustodySnapshotBuilder;
    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let custody = self.custody.clone();
        tokio::task::spawn_blocking(move || applied(&custody))
            .await
            .map_err(err)?
            .map_err(err)
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Vec<u8>>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        let machine = self.clone();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let _gate = machine
                .control_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            ensure!(
                !machine.failed.load(Ordering::Acquire),
                "custody state machine requires recovery"
            );
            let mut responses = Vec::with_capacity(entries.len());
            for entry in entries {
                machine.custody.store().check_access()?;
                let (previous, mut membership) = applied(&machine.custody)?;
                ensure!(
                    previous.is_some_and(|id| id.index.checked_add(1) == Some(entry.log_id.index)),
                    "custody log application is not consecutive"
                );
                let digest = match &entry.payload {
                    EntryPayload::Normal(command) => crate::command::sha256(command.bytes()),
                    _ => crate::command::sha256(&crate::storage::encode_entry(&entry)?),
                };
                if let EntryPayload::Membership(value) = &entry.payload {
                    membership = StoredMembership::new(Some(entry.log_id), value.clone());
                }
                let position = AppliedEntryContext {
                    log_id: entry.log_id,
                    previous,
                    membership,
                    command_sha256: digest,
                    retirement_seed: None,
                };
                let response = match entry.payload {
                    EntryPayload::Normal(command) => {
                        let command = command
                            .custody_command()?
                            .context("application command forbidden in retired custody")?;
                        control::apply_custody(&machine.custody, &position, &command)?
                    }
                    _ => {
                        machine
                            .custody
                            .store()
                            .write_batch(&[control::applied_write(&position)?])?;
                        Vec::new()
                    }
                };
                responses.push(response);
            }
            Ok(responses)
        })
        .await
        .map_err(|error| self.failure(error))?
        .map_err(|error| self.failure(error))
    }
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let machine = self.clone();
        let captured = tokio::task::spawn_blocking(move || {
            let _gate = machine
                .control_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            capture(&machine.custody)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result)
        .map(Arc::new);
        CustodySnapshotBuilder {
            machine: self.clone(),
            captured,
        }
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotBuffer>, StorageError<u64>> {
        self.custody.store().check_access().map_err(err)?;
        Ok(Box::new(
            SnapshotBuffer::new(
                self.custody.store().scratch_disk(),
                self.snapshot_limit,
                &self.snapshot_buffers,
            )
            .map_err(err)?,
        ))
    }
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<SnapshotBuffer>,
    ) -> Result<(), StorageError<u64>> {
        let meta = meta.clone();
        let machine = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            ensure!(
                snapshot.len() <= machine.snapshot_limit,
                "closed snapshot byte budget exceeded"
            );
            let image = snapshot.into_image()?;
            let envelope = SnapshotEnvelope::decode(
                image.disk(),
                &mut image.reader(),
                machine.snapshot_limit,
            )?;
            ensure!(envelope.meta == meta, "closed snapshot metadata differs");
            let _gate = machine
                .control_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            let (previous, _) = applied(&machine.custody)?;
            ensure!(
                meta.last_log_id.map(|id| id.index) >= previous.map(|id| id.index),
                "closed snapshot reverts applied state"
            );
            publish(&machine.custody, &envelope, machine.snapshot_limit)
        })
        .await
        .map_err(|error| self.failure(error))?
        .map_err(|error| self.failure(error))
    }
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        let custody = self.custody.clone();
        let gate = self.control_gate.clone();
        let limit = self.snapshot_limit;
        let snapshot_buffers = self.snapshot_buffers.clone();
        tokio::task::spawn_blocking(move || {
            let _gate = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            load_snapshot(&custody, limit)?
                .map(|snapshot| as_snapshot(&snapshot, limit, &snapshot_buffers))
                .transpose()
        })
        .await
        .map_err(err)?
        .map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAX_CLOSED_SNAPSHOT_BYTES: u64 = 64 << 20;
    fn publish(custody: &CustodyStore, snapshot: &SnapshotEnvelope) -> Result<()> {
        super::publish(custody, snapshot, MAX_CLOSED_SNAPSHOT_BYTES)
    }
    fn load_snapshot(custody: &CustodyStore) -> Result<Option<SnapshotEnvelope>> {
        super::load_snapshot(custody, MAX_CLOSED_SNAPSHOT_BYTES)
    }
    use crate::control::tests::{fixture, group, id, retirement_entry, seed};
    use kasumi_store::test_utils::FaultBackend;
    use kasumi_types::{CustodyAction, CustodyReceipt, CustodyRequest, RetireSourceRequest};
    use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
    use std::collections::{BTreeMap, BTreeSet};

    fn membership() -> Entry<TypeConfig> {
        Entry {
            log_id: id(0),
            payload: EntryPayload::Membership(openraft::Membership::new(
                vec![BTreeSet::from([1])],
                BTreeMap::from([(1, BasicNode::new("local"))]),
            )),
        }
    }
    fn rotation(request: &RetireSourceRequest) -> crate::CustodyCommand {
        crate::CustodyCommand {
            context: seed().unwrap().0.context,
            admitted_at_ms: 200,
            request: CustodyRequest {
                retirement: request.reference().unwrap(),
                command_id: "rotate".into(),
                expected_policy_epoch: 1,
                not_after_ms: 1000,
                action: CustodyAction::ReplaceAdministrators(BTreeSet::from([
                    "owner".into(),
                    "custodian".into(),
                ])),
            },
        }
    }
    fn replace_with_alternate_json(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
    ) -> Result<Vec<u8>> {
        let original = store
            .get(namespace, key)?
            .context("expected current custody point row")?;
        let mut alternate = vec![b' '];
        alternate.extend_from_slice(&original);
        ensure!(
            serde_json::from_slice::<serde_json::Value>(&alternate)?
                == serde_json::from_slice::<serde_json::Value>(&original)?,
            "alternate JSON changed custody point value"
        );
        store.write_batch(&[WriteOp::put(namespace, key, alternate)])?;
        Ok(original)
    }
    fn restore_json(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
        original: Vec<u8>,
    ) -> Result<()> {
        store.write_batch(&[WriteOp::put(namespace, key, original)])
    }
    #[tokio::test]
    async fn custody_point_reads_require_exact_current_writer_bytes() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (domains, _, _, mut log) =
            fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let initial = control::custody_state(domains.custody())?;
        let command = rotation(&initial.origin.request);
        log.blocking_append([Entry {
            log_id: id(2),
            payload: EntryPayload::Normal(crate::RaftCommand::custody(&command)?),
        }])
        .await?;
        log.save_committed(Some(id(2))).await?;
        let (_, membership) = applied(domains.custody())?;
        control::apply_custody(
            domains.custody(),
            &AppliedEntryContext {
                log_id: id(2),
                previous: Some(id(1)),
                membership,
                retirement_seed: None,
                command_sha256: crate::command::sha256(&command.encoded()?),
            },
            &command,
        )?;
        let expected = control::custody_state(domains.custody())?;
        let store = domains.custody().store();
        let records = crate::custody_records::Records::capture(store)?;

        let original = replace_with_alternate_json(store, META, crate::custody_tables::HEAD)?;
        assert!(control::custody_head(domains.custody()).is_err());
        assert!(crate::custody_records::Records::capture(store).is_err());
        assert!(crate::custody_tables::prepare_replacement(store, records.clone()).is_err());
        restore_json(store, META, crate::custody_tables::HEAD, original)?;
        assert_eq!(control::custody_state(domains.custody())?, expected);
        assert!(crate::custody_tables::prepare_replacement(store, records.clone()).is_ok());

        let original =
            replace_with_alternate_json(store, crate::custody_tables::COMMANDS, b"rotate")?;
        assert!(crate::custody_tables::receipt(store, "rotate").is_err());
        assert!(crate::custody_records::Records::capture(store).is_err());
        restore_json(store, crate::custody_tables::COMMANDS, b"rotate", original)?;
        assert_eq!(
            crate::custody_tables::receipt(store, "rotate")?,
            expected.commands.get("rotate").cloned()
        );
        assert!(crate::custody_records::Records::capture(store).is_ok());

        let audit_key = 0u64.to_be_bytes();
        let original =
            replace_with_alternate_json(store, crate::custody_tables::AUDIT, &audit_key)?;
        assert!(crate::custody_records::Records::capture(store).is_err());
        assert!(crate::custody_tables::snapshot(store).is_err());
        restore_json(store, crate::custody_tables::AUDIT, &audit_key, original)?;
        assert_eq!(control::custody_state(domains.custody())?, expected);
        assert_eq!(
            crate::custody_records::Records::capture(store)?.sha256(),
            records.sha256()
        );
        Ok(())
    }
    #[tokio::test]
    async fn same_entry_position_snapshot_cannot_substitute_rotated_custody_state() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (domains, _, _, mut log) =
            fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let state = control::custody_state(domains.custody())?;
        let command = rotation(&state.origin.request);
        log.blocking_append([Entry {
            log_id: id(2),
            payload: EntryPayload::Normal(crate::RaftCommand::custody(&command)?),
        }])
        .await?;
        log.save_committed(Some(id(2))).await?;
        let (_, membership) = applied(domains.custody())?;
        control::apply_custody(
            domains.custody(),
            &AppliedEntryContext {
                log_id: id(2),
                previous: Some(id(1)),
                membership,
                retirement_seed: None,
                command_sha256: crate::command::sha256(&command.encoded()?),
            },
            &command,
        )?;
        let before = control::custody_state(domains.custody())?;
        let mut malicious = capture(domains.custody())?;
        malicious
            .retirement
            .as_mut()
            .unwrap()
            .custody
            .policy
            .administrators = BTreeSet::from(["substituted".into()]);
        assert!(publish(domains.custody(), &malicious).is_err());
        assert_eq!(control::custody_state(domains.custody())?, before);
        let legitimate = capture(domains.custody())?;
        publish(domains.custody(), &legitimate)?;
        publish(domains.custody(), &capture(domains.custody())?)?;
        assert_eq!(control::custody_state(domains.custody())?, before);
        let mut later = capture(domains.custody())?;
        later.meta.last_log_id = Some(id(3));
        let mut substituted = before.clone();
        substituted.commands.get_mut("rotate").unwrap().principal = "substituted".into();
        substituted.audit[0].principal = "substituted".into();
        let records = crate::custody_records::Records::from_state(
            &substituted,
            domains.custody().store().scratch_disk(),
        )?;
        let retirement = later.retirement.as_mut().unwrap();
        retirement.custody = records.head.clone();
        retirement.history_sha256 = records.sha256().into();
        retirement.records = Some(records);
        let error = publish(domains.custody(), &later).unwrap_err();
        assert!(
            error.to_string().contains("permanent custody history"),
            "{error}"
        );
        assert_eq!(control::custody_state(domains.custody())?, before);
        Ok(())
    }

    #[tokio::test]
    async fn existing_quorum_runs_closed_commands_after_application_key_revocation() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (domains, app, _, mut log) =
            fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        log.save_vote(&openraft::Vote::new_committed(3, 1)).await?;
        drop(log);
        app.revoke();
        assert!(domains.application().refresh_lease().await.is_err());
        let probes = app.probe_count();
        let router = Arc::new(crate::InProcessRouter::default());
        let instance = crate::CustodyRaftGroup::open(
            1,
            group(),
            domains.custody().clone(),
            router.clone(),
            crate::RaftGroupConfig::default(),
            crate::SnapshotBufferOwner::fixture(),
        )
        .await?;
        router.register(group(), 1, instance.raft().clone());
        instance
            .raft()
            .wait(Some(std::time::Duration::from_secs(10)))
            .current_leader(1, "closed source leader")
            .await?;
        instance.linearizable_barrier().await?;
        let command = rotation(instance.view()?.request());
        let outcome: kasumi_types::Result<CustodyReceipt> =
            serde_json::from_slice(&instance.write(command.clone()).await?)?;
        outcome?.outcome?;
        let replay: kasumi_types::Result<CustodyReceipt> =
            serde_json::from_slice(&instance.write(command).await?)?;
        replay?.outcome?;
        assert_eq!(instance.view()?.policy_epoch(), 2);
        assert_eq!(app.probe_count(), probes);
        instance.shutdown().await?;
        domains.custody().store().shutdown().await.unwrap();
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closed_custody_requires_fresh_existing_quorum_after_isolation() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let router = Arc::new(crate::InProcessRouter::default());
        let mut stores = Vec::new();
        let mut groups = Vec::new();
        let retirement = retirement_entry()?;
        let voters = BTreeSet::from([1, 2, 3]);
        let members = Entry {
            log_id: id(0),
            payload: EntryPayload::Membership(openraft::Membership::new(
                vec![voters.clone()],
                voters
                    .iter()
                    .map(|node| (*node, BasicNode::new(format!("node-{node}"))))
                    .collect::<BTreeMap<_, _>>(),
            )),
        };
        for node in voters {
            let (domains, app, _, mut log) =
                fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
            // This is installed consensus metadata for each distinct replica;
            // the source retirement producer is exercised by engine tests.
            domains.custody().store().write_batch(&[WriteOp::put(
                META,
                b"node_id",
                serde_json::to_vec(&node)?,
            )])?;
            log.blocking_append([members.clone(), retirement.clone()])
                .await?;
            log.save_committed(Some(id(1))).await?;
            log.save_vote(&openraft::Vote::new_committed(3, 1)).await?;
            drop(log);
            app.revoke();
            assert!(domains.application().refresh_lease().await.is_err());
            let instance = crate::CustodyRaftGroup::open(
                node,
                group(),
                domains.custody().clone(),
                router.clone(),
                crate::RaftGroupConfig::default(),
                crate::SnapshotBufferOwner::fixture(),
            )
            .await?;
            router.register(group(), node, instance.raft().clone());
            stores.push(domains);
            groups.push(instance);
        }
        let leader = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                for (index, instance) in groups.iter().enumerate() {
                    let metrics = instance.raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && instance.linearizable_barrier().await.is_ok()
                    {
                        return index;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await?;
        let instance = &groups[leader];
        let outcome: kasumi_types::Result<CustodyReceipt> =
            serde_json::from_slice(&instance.write(rotation(instance.view()?.request())).await?)?;
        outcome?.outcome?;
        router.isolate(&group(), leader as u64 + 1, true);
        assert!(
            instance.linearizable_barrier().await.is_err(),
            "retained term and local custody state cannot replace fresh quorum"
        );
        router.isolate(&group(), leader as u64 + 1, false);
        for instance in groups {
            instance.shutdown().await?;
        }
        for domains in stores {
            domains.custody().store().shutdown().await.unwrap();
        }
        Ok(())
    }
    #[tokio::test]
    async fn custody_point_head_receipt_audit_and_applied_cursor_survive_each_write_failure()
    -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let disk = FaultBackend::new();
        let (domains, _, _, mut log) = fixture(disk.clone(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let initial = control::custody_state(domains.custody())?;
        let command = rotation(&initial.origin.request);
        log.blocking_append([Entry {
            log_id: id(2),
            payload: EntryPayload::Normal(crate::RaftCommand::custody(&command)?),
        }])
        .await?;
        log.save_committed(Some(id(2))).await?;
        let (_, membership) = applied(domains.custody())?;
        let position = AppliedEntryContext {
            log_id: id(2),
            previous: Some(id(1)),
            membership,
            retirement_seed: None,
            command_sha256: crate::command::sha256(&command.encoded()?),
        };
        let baseline = disk.crash();
        drop(log);
        drop(domains);
        let measured = baseline.crash();
        let (domains, _, _, _) = fixture(measured.clone(), false, fixture_scratch.clone()).await?;
        let start = measured.operations();
        control::apply_custody(domains.custody(), &position, &command)?;
        let operations = measured.operations() - start;
        let complete = control::custody_state(domains.custody())?;
        assert_eq!(complete.commands.len(), 1);
        assert_eq!(complete.audit.len(), 1);
        assert!(operations > 0);
        drop(domains);
        for failure in 0..=operations {
            let disk = baseline.crash();
            let (domains, _, _, _) = fixture(disk.clone(), false, fixture_scratch.clone()).await?;
            disk.fail_after(failure);
            let result = control::apply_custody(domains.custody(), &position, &command);
            let crash = disk.crash();
            disk.disarm();
            drop(domains);
            let (reopened, _, _, _) = fixture(crash, false, fixture_scratch.clone()).await?;
            let actual = control::custody_state(reopened.custody())?;
            let (cursor, _) = applied(reopened.custody())?;
            if actual == initial {
                assert_eq!(cursor, Some(id(1)), "cursor torn at {failure}");
                assert!(result.is_err(), "successful result lost at {failure}");
                assert!(
                    crate::custody_tables::receipt(reopened.custody().store(), "rotate")?.is_none()
                );
            } else {
                assert_eq!(actual, complete, "custody records torn at {failure}");
                assert_eq!(cursor, Some(id(2)), "cursor torn at {failure}");
                assert_eq!(
                    crate::custody_tables::receipt(reopened.custody().store(), "rotate")?,
                    complete.commands.get("rotate").cloned()
                );
            }
        }
        Ok(())
    }
    #[tokio::test]
    async fn closed_snapshot_rejects_prior_format_without_rewriting_permanent_storage() -> Result<()>
    {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (domains, _, _, mut log) =
            fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let original: AppliedCursor = load(domains.custody().store(), META, b"applied")?.unwrap();
        domains.custody().store().write_batch(&[WriteOp::put(
            CLOSED_SNAPSHOT,
            b"current",
            b"KASUMIS2",
        )])?;
        let error = publish(domains.custody(), &capture(domains.custody())?).unwrap_err();
        assert!(
            error.to_string().contains("unsupported closed snapshot"),
            "{error}"
        );
        assert!(load_snapshot(domains.custody()).is_err());
        assert_eq!(
            load::<AppliedCursor>(domains.custody().store(), META, b"applied")?,
            Some(original)
        );
        assert_eq!(
            domains.custody().store().get(CLOSED_SNAPSHOT, b"current")?,
            Some(b"KASUMIS2".to_vec())
        );
        Ok(())
    }
    #[tokio::test]
    async fn canonical_custody_stream_authenticates_counts_digest_and_record_order() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        use sha2::{Digest, Sha256};
        let (domains, _, _, mut log) =
            fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let command = rotation(
            &control::custody_head(domains.custody())?
                .policy
                .origin
                .request,
        );
        log.blocking_append([Entry {
            log_id: id(2),
            payload: EntryPayload::Normal(crate::RaftCommand::custody(&command)?),
        }])
        .await?;
        log.save_committed(Some(id(2))).await?;
        let (_, membership) = applied(domains.custody())?;
        control::apply_custody(
            domains.custody(),
            &AppliedEntryContext {
                log_id: id(2),
                previous: Some(id(1)),
                membership,
                retirement_seed: None,
                command_sha256: crate::command::sha256(&command.encoded()?),
            },
            &command,
        )?;
        let snapshot = capture(domains.custody())?;
        let bytes = snapshot
            .encode(MAX_CLOSED_SNAPSHOT_BYTES)?
            .read_bounded(MAX_CLOSED_SNAPSHOT_BYTES as usize)?;
        let decoded = SnapshotEnvelope::decode(
            &fixture_scratch.clone(),
            &mut bytes.as_slice(),
            MAX_CLOSED_SNAPSHOT_BYTES,
        )?;
        assert_eq!(
            decoded.retirement.as_ref().unwrap().history_sha256,
            snapshot.retirement.as_ref().unwrap().history_sha256
        );
        assert!(
            decoded
                .retirement
                .as_ref()
                .unwrap()
                .verified_records()
                .is_ok()
        );
        let footer = bytes.len() - 65;
        let metadata_size = u64::from_be_bytes(bytes[9..17].try_into()?) as usize;
        let command_start = 17 + metadata_size;
        let command_size =
            u64::from_be_bytes(bytes[command_start + 1..command_start + 9].try_into()?) as usize;
        assert_eq!(bytes[command_start], 2);
        for case in 0..6 {
            let mut bad = bytes.clone();
            match case {
                0 => bad[..8].copy_from_slice(b"KASUMIS2"),
                1 => bad[footer + 17..footer + 25].copy_from_slice(&0u64.to_be_bytes()),
                2 => bad[footer + 33] ^= 1,
                3 => bad.push(0),
                4 => {
                    // Remove a whole command and recalculate the outer digest.
                    // The semantic head must still reject the missing identity.
                    bad.drain(command_start..command_start + 9 + command_size);
                    let footer = bad.len() - 65;
                    bad[footer + 17..footer + 25].copy_from_slice(&0u64.to_be_bytes());
                    let digest = Sha256::digest(&bad[..footer]);
                    bad[footer + 33..].copy_from_slice(&digest);
                }
                5 => {
                    // A re-authenticated custody record cannot change its type.
                    bad[command_start] = 3;
                    let digest = Sha256::digest(&bad[..footer]);
                    bad[footer + 33..].copy_from_slice(&digest);
                }
                _ => unreachable!(),
            }
            assert!(
                SnapshotEnvelope::decode(
                    &fixture_scratch.clone(),
                    &mut bad.as_slice(),
                    MAX_CLOSED_SNAPSHOT_BYTES
                )
                .is_err(),
                "accepted corruption {case}"
            );
        }
        Ok(())
    }
    #[tokio::test]
    async fn streamed_custody_tables_and_snapshot_coverage_publish_at_one_crash_boundary()
    -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let disk = FaultBackend::new();
        let (domains, _, _, mut log) = fixture(disk.clone(), true, fixture_scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?);
        let command = rotation(&control::custody_state(domains.custody())?.origin.request);
        log.blocking_append([Entry {
            log_id: id(2),
            payload: EntryPayload::Normal(crate::RaftCommand::custody(&command)?),
        }])
        .await?;
        log.save_committed(Some(id(2))).await?;
        let (_, membership) = applied(domains.custody())?;
        control::apply_custody(
            domains.custody(),
            &AppliedEntryContext {
                log_id: id(2),
                previous: Some(id(1)),
                membership,
                retirement_seed: None,
                command_sha256: crate::command::sha256(&command.encoded()?),
            },
            &command,
        )?;
        let original = control::custody_state(domains.custody())?;
        let baseline = disk.crash();
        drop(log);
        drop(domains);
        let measure = baseline.crash();
        let (domains, _, _, _) = fixture(measure.clone(), false, fixture_scratch.clone()).await?;
        let snapshot = capture(domains.custody())?;
        let start = measure.operations();
        publish(domains.custody(), &snapshot)?;
        let operations = measure.operations() - start;
        assert!(operations > 0);
        drop(domains);
        for failure in 0..=operations {
            let disk = baseline.crash();
            let (domains, _, _, _) = fixture(disk.clone(), false, fixture_scratch.clone()).await?;
            let snapshot = capture(domains.custody())?;
            disk.fail_after(failure);
            let result = publish(domains.custody(), &snapshot);
            let crash = disk.crash();
            disk.disarm();
            drop(domains);
            let (reopened, _, _, _) = fixture(crash, false, fixture_scratch.clone()).await?;
            assert_eq!(
                control::custody_state(reopened.custody())?,
                original,
                "table torn at {failure}"
            );
            let installed = load_snapshot(reopened.custody())?;
            let cursor: AppliedCursor =
                load(reopened.custody().store(), META, b"applied")?.unwrap();
            if let Some(installed) = installed {
                assert_eq!(installed.meta, snapshot.meta);
                assert!(matches!(cursor, AppliedCursor::Snapshot { .. }));
            } else {
                assert!(result.is_err(), "successful snapshot absent at {failure}");
                assert!(matches!(cursor, AppliedCursor::Entry(_)));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn closed_snapshot_near_metadata_limit_publishes_readable_coverage() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
        let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (source, _, _, mut log) = fixture(FaultBackend::new(), true, scratch.clone()).await?;
        log.blocking_append([membership(), retirement_entry()?])
            .await?;
        log.save_committed(Some(id(1))).await?;
        assert!(crate::ControlLog::open(source.custody().clone(), 1, group())?.recover_retired()?);
        let mut snapshot = capture(source.custody())?;
        let membership = |address: String| {
            StoredMembership::new(
                None,
                openraft::Membership::from(BTreeMap::from([(1u64, BasicNode::new(address))])),
            )
        };
        snapshot.meta.last_membership = membership(String::new());
        let base = snapshot
            .encode(MAX_CLOSED_SNAPSHOT_BYTES)?
            .read_bounded(usize::try_from(MAX_CLOSED_SNAPSHOT_BYTES)?)?;
        let base_metadata_len = usize::try_from(u64::from_be_bytes(base[9..17].try_into()?))?;
        let address_len = crate::snapshot_codec::MAX_METADATA
            .checked_sub(base_metadata_len + 4096)
            .context("base closed metadata exceeds test budget")?;
        snapshot.meta.last_membership = membership("x".repeat(address_len));
        let encoded = snapshot
            .encode(MAX_CLOSED_SNAPSHOT_BYTES)?
            .read_bounded(usize::try_from(MAX_CLOSED_SNAPSHOT_BYTES)?)?;
        assert_eq!(
            usize::try_from(u64::from_be_bytes(encoded[9..17].try_into()?))?,
            crate::snapshot_codec::MAX_METADATA - 4096
        );
        let (target, _, _, _) = fixture(FaultBackend::new(), true, scratch).await?;
        publish(target.custody(), &snapshot)?;
        let coverage_bytes = target
            .custody()
            .store()
            .get(META, b"snapshot_coverage")?
            .context("closed coverage absent")?;
        assert!(coverage_bytes.len() <= crate::storage::MAX_SNAPSHOT_COVERAGE_BYTES);
        assert!(crate::storage::load_snapshot_coverage(target.custody().store())?.is_some());
        assert!(load_snapshot(target.custody())?.is_some());
        Ok(())
    }
}
