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
pub(crate) const MAX_CLOSED_SNAPSHOT_BYTES: u64 = 2 << 20;

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
    let state = control::custody_state(custody)?;
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
        backend: kasumi_store::SnapshotImage::from_bytes(&[])?,
        retirement,
    })
}

pub(crate) fn publish(custody: &CustodyStore, snapshot: &SnapshotEnvelope) -> Result<()> {
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
    let bytes = snapshot
        .encode(MAX_CLOSED_SNAPSHOT_BYTES)?
        .read_bounded(MAX_CLOSED_SNAPSHOT_BYTES as usize)?;
    ensure!(
        bytes.len() as u64 <= MAX_CLOSED_SNAPSHOT_BYTES,
        "closed snapshot byte budget exceeded"
    );
    let digest = crate::command::sha256(&bytes);
    let backend_digest = crate::command::sha256(&[]);
    let mut writes = crate::snapshot_custody::installation_writes(
        custody,
        &snapshot.meta,
        Some(retirement),
        &backend_digest,
        &digest,
    )?;
    writes.push(WriteOp::put(
        META,
        b"snapshot_coverage",
        serde_json::to_vec(&SnapshotCoverage {
            kind: SnapshotKind::Custody,
            manifest_id: uuid::Uuid::new_v4().to_string(),
            snapshot_sha256: digest,
            backend_sha256: backend_digest,
            meta: snapshot.meta.clone(),
        })?,
    ));
    writes.push(WriteOp::put(CLOSED_SNAPSHOT, b"current", bytes));
    custody.store().write_batch(&writes)
}

pub(crate) fn load_snapshot(custody: &CustodyStore) -> Result<Option<SnapshotEnvelope>> {
    let Some(bytes) = custody.store().get_bounded(
        CLOSED_SNAPSHOT,
        b"current",
        MAX_CLOSED_SNAPSHOT_BYTES as usize,
    )?
    else {
        return Ok(None);
    };
    ensure!(
        bytes.len() as u64 <= MAX_CLOSED_SNAPSHOT_BYTES,
        "closed snapshot byte budget exceeded"
    );
    let snapshot = SnapshotEnvelope::decode(&mut bytes.as_slice(), MAX_CLOSED_SNAPSHOT_BYTES)?;
    ensure!(
        snapshot.kind == SnapshotKind::Custody
            && snapshot.version == 1
            && snapshot.backend.is_empty(),
        "application payload forbidden in custody snapshot"
    );
    let coverage: SnapshotCoverage = load(custody.store(), META, b"snapshot_coverage")?
        .context("closed snapshot lacks control coverage")?;
    ensure!(
        coverage.kind == SnapshotKind::Custody
            && coverage.meta == snapshot.meta
            && coverage.snapshot_sha256 == crate::command::sha256(&bytes)
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
    ) -> Result<Self> {
        let control_gate = crate::storage::control_gate(&custody)?;
        let store = custody.clone();
        let gate = control_gate.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _gate = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("control gate poisoned"))?;
            control::custody_state(&store)?;
            // This atomically records the latest durable closed state as a
            // snapshot before OpenRaft is allowed to purge its covered log prefix.
            publish(&store, &capture(&store)?)
        })
        .await??;
        Ok(Self {
            custody: StorageHandle::new(custody, Some(lease)),
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
            if let Some(current) = load_snapshot(&machine.custody)?
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
                return as_snapshot(&current, MAX_CLOSED_SNAPSHOT_BYTES);
            }
            publish(&machine.custody, &snapshot)?;
            as_snapshot(&snapshot, MAX_CLOSED_SNAPSHOT_BYTES)
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
            SnapshotBuffer::new(MAX_CLOSED_SNAPSHOT_BYTES).map_err(err)?,
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
                snapshot.len() <= MAX_CLOSED_SNAPSHOT_BYTES,
                "closed snapshot byte budget exceeded"
            );
            let image = snapshot.into_image()?;
            let envelope =
                SnapshotEnvelope::decode(&mut image.reader(), MAX_CLOSED_SNAPSHOT_BYTES)?;
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
            publish(&machine.custody, &envelope)
        })
        .await
        .map_err(|error| self.failure(error))?
        .map_err(|error| self.failure(error))
    }
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        let custody = self.custody.clone();
        tokio::task::spawn_blocking(move || {
            load_snapshot(&custody)?
                .map(|snapshot| as_snapshot(&snapshot, MAX_CLOSED_SNAPSHOT_BYTES))
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
    #[tokio::test]
    async fn same_entry_position_snapshot_cannot_substitute_rotated_custody_state() -> Result<()> {
        let (domains, _, _, mut log) = fixture(FaultBackend::new()).await?;
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
            .administrators = BTreeSet::from(["substituted".into()]);
        assert!(publish(domains.custody(), &malicious).is_err());
        assert_eq!(control::custody_state(domains.custody())?, before);
        let legitimate = capture(domains.custody())?;
        publish(domains.custody(), &legitimate)?;
        publish(domains.custody(), &capture(domains.custody())?)?;
        assert_eq!(control::custody_state(domains.custody())?, before);
        Ok(())
    }

    #[tokio::test]
    async fn existing_quorum_runs_closed_commands_after_application_key_revocation() -> Result<()> {
        let (domains, app, _, mut log) = fixture(FaultBackend::new()).await?;
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
            crate::Config::default(),
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
        domains.custody().store().shutdown().await;
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closed_custody_requires_fresh_existing_quorum_after_isolation() -> Result<()> {
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
            let (domains, app, _, mut log) = fixture(FaultBackend::new()).await?;
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
                crate::Config::default(),
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
            domains.custody().store().shutdown().await;
        }
        Ok(())
    }
}
