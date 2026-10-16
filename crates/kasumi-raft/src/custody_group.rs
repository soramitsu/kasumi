//! Installed local or replicated execution reopened with only the custody key domain.
use crate::ensure_result as ensure;
use crate::lifetime::StorageDrain;
use crate::{ControlLog, CustodyCommand, LogId, Raft, RaftCommand, RaftGroupConfig, RaftTransport};
use anyhow::{Context, Result};
use kasumi_store::CustodyStore;
use kasumi_store::ScratchOperationFailure;
use openraft::storage::RaftLogStorage;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A validated local observation. It is not fresh quorum authority and cannot
/// construct an engine/native verified retirement proof by deserialization.
pub struct CustodyView(pub(crate) crate::custody_state::CustodyState);
impl CustodyView {
    pub fn authorize(&self, context: &kasumi_types::RequestContext) -> kasumi_types::Result<()> {
        self.0.authorize(context)
    }
    pub fn revision(&self) -> u64 {
        self.0.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.0.policy_epoch
    }
    pub fn request(&self) -> &kasumi_types::RetireSourceRequest {
        &self.0.origin.request
    }
    pub fn retirement(&self) -> &kasumi_types::RetirementReceipt {
        &self.0.origin.receipt
    }
    pub fn limits(&self) -> &kasumi_types::CustodyLimits {
        &self.0.limits
    }
    pub fn administrators(&self) -> &std::collections::BTreeSet<String> {
        &self.0.administrators
    }
}

#[derive(Clone)]
pub struct CustodyRaftGroup {
    raft: Option<Raft>,
    local: Option<Arc<crate::local::LocalGroup<crate::custody_machine::CustodyMachine>>>,
    custody: Arc<CustodyStore>,
    machine_failed: Arc<AtomicBool>,
    storage_drain: StorageDrain,
    snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    shutdown_report: Arc<tokio::sync::Mutex<kasumi_types::drain::DrainReport>>,
    ownership: Arc<AtomicBool>,
}
impl CustodyRaftGroup {
    /// Existing membership is mandatory. There is no initialize/local-mode
    /// fallback; unavailable quorum cannot grant custody observation authority.
    pub async fn open(
        id: u64,
        group: String,
        custody: Arc<CustodyStore>,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    ) -> Result<Self, ScratchOperationFailure> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::open_inner(
                    id,
                    group,
                    custody,
                    Some(transport),
                    config,
                    snapshot_buffers,
                )
                .await
                .map(crate::startup_owner::StartedGroup::Custody)
            })
            .await?
        {
            crate::startup_owner::StartedGroup::Custody(group) => Ok(group),
            _ => unreachable!("custody startup result"),
        }
    }

    /// Reopen retired standalone custody under its exclusive local writer.
    /// This preserves the installed journal without starting consensus tasks.
    pub async fn local(
        id: u64,
        group: String,
        custody: Arc<CustodyStore>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    ) -> Result<Self, ScratchOperationFailure> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::open_inner(id, group, custody, None, config, snapshot_buffers)
                    .await
                    .map(crate::startup_owner::StartedGroup::Custody)
            })
            .await?
        {
            crate::startup_owner::StartedGroup::Custody(group) => Ok(group),
            _ => unreachable!("local custody startup result"),
        }
    }

    async fn open_inner(
        id: u64,
        group: String,
        custody: Arc<CustodyStore>,
        transport: Option<Arc<dyn RaftTransport>>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    ) -> Result<Self, ScratchOperationFailure> {
        let limits = config.limits;
        ensure!(
            limits.max_snapshot_bytes >= 4 << 20,
            "custody snapshot budget is too small for bounded control records"
        );
        let mut raft_config = config.raft;
        raft_config.cluster_name = group.clone();
        let config = if transport.is_some() {
            Some(Arc::new(
                raft_config.validate().map_err(anyhow::Error::from)?,
            ))
        } else {
            if let Some(binding) = custody.store().get("engine.deployment", b"mode")? {
                ensure!(
                    binding == b"local-v1",
                    "replicated custody cannot open in standalone mode"
                );
            }
            if let Some(first) = crate::control::first_applied_membership(custody.store())? {
                if let crate::control::HeaderPayload::Membership(membership) = &first.header.payload
                {
                    crate::local::check_membership(membership, id)?;
                }
            }
            None
        };
        let ownership = crate::claim_custody(&custody)?;
        snapshot_buffers.bind_group_ownership(ownership.clone(), custody.store().clone())?;
        let (storage_drain, lease) = StorageDrain::new();
        let opened = async {
            let control = ControlLog::open(custody.clone(), id, group.clone())?;
            let recovery_lease = lease.clone();
            let recovery_ownership = ownership.clone();
            let recovery_buffers = snapshot_buffers.clone();
            ensure!(
                tokio::task::spawn_blocking(move || {
                    let _lease = recovery_lease;
                    let _ownership = recovery_ownership;
                    let guard = recovery_buffers.scratch_failure_guard()?;
                    guard.capture_result(control.recover_retired())
                })
                .await??,
                "source has no successful committed retirement"
            );
            let machine = crate::custody_machine::CustodyMachine::open(
                custody.clone(),
                lease.clone(),
                ownership.clone(),
                limits.max_snapshot_bytes,
                snapshot_buffers.clone(),
            )
            .await?;
            let machine_failed = machine.failure_flag();
            let mut log = crate::LogStore::open_custody(custody.clone(), id, lease.clone()).await?;
            log.bind_group(group.clone())
                .await
                .map_err(anyhow::Error::from)?;
            let scratch_guard = snapshot_buffers.scratch_failure_guard()?;
            let saved = scratch_guard
                .capture_result(crate::custody_machine::load_snapshot(
                    &custody,
                    limits.max_snapshot_bytes,
                ))?
                .context("closed startup snapshot absent")?;
            let floor = saved
                .meta
                .last_log_id
                .context("closed startup has no log coverage")?;
            if transport.is_none() {
                crate::local::check_membership(saved.meta.last_membership.membership(), id)?;
                log.validate_local_membership(id)
                    .await
                    .map_err(anyhow::Error::from)?;
            }
            // Only encrypted control headers/bodies are removed. The immutable
            // retired municipal payload remains encrypted under its original key.
            log.purge(floor).await.map_err(anyhow::Error::from)?;
            let (raft, local) = match transport {
                Some(transport) => (
                    Some(
                        Raft::new(
                            id,
                            config.expect("replicated configuration"),
                            crate::network::NetworkFactory::new(id, group, transport),
                            log,
                            machine,
                        )
                        .await
                        .map_err(anyhow::Error::from)?,
                    ),
                    None,
                ),
                None => (
                    None,
                    Some(Arc::new(
                        crate::local::LocalGroup::open(id, log, machine, machine_failed.clone())
                            .await?,
                    )),
                ),
            };
            Ok::<_, ScratchOperationFailure>((raft, local, machine_failed))
        }
        .await;
        drop(lease);
        let (raft, local, machine_failed) = match opened {
            Ok(value) => value,
            Err(error) => {
                return Err(crate::failed_startup(error, &snapshot_buffers, &storage_drain).await);
            }
        };
        Ok(Self {
            raft,
            local,
            custody,
            machine_failed,
            storage_drain,
            snapshot_buffers,
            shutdown_report: Default::default(),
            ownership,
        })
    }
    pub fn is_local(&self) -> bool {
        self.local.is_some()
    }
    pub fn try_raft(&self) -> Option<&Raft> {
        self.raft.as_ref()
    }
    /// Replicated-only access to the consensus runtime.
    pub fn raft(&self) -> &Raft {
        self.try_raft()
            .expect("standalone custody has no Raft runtime")
    }
    pub fn metrics(&self) -> openraft::RaftMetrics<u64, crate::BasicNode> {
        match &self.local {
            Some(local) => local.metrics(),
            None => self.raft().metrics().borrow().clone(),
        }
    }
    pub fn custody_store(&self) -> &Arc<CustodyStore> {
        &self.custody
    }
    pub fn check_access(&self) -> Result<()> {
        self.snapshot_buffers.check()?;
        ensure!(
            self.ownership.load(Ordering::Acquire),
            "custody group has shut down"
        );
        self.custody.store().check_access()?;
        let ended = match &self.local {
            Some(local) => local.ended(),
            None => {
                let metrics = self.raft().metrics();
                metrics.borrow().running_state.is_err() || metrics.has_changed().is_err()
            }
        };
        ensure!(
            !ended && !self.machine_failed.load(Ordering::Acquire),
            "custody group requires recovery"
        );
        Ok(())
    }
    pub fn view(&self) -> Result<CustodyView> {
        self.check_access()?;
        let state = crate::control::custody_head(&self.custody)?.policy;
        self.check_access()?;
        Ok(CustodyView(state))
    }
    /// Local point lookup, not current quorum or response-release authority.
    pub fn receipt(&self, command_id: &str) -> Result<Option<kasumi_types::CustodyReceipt>> {
        self.check_access()?;
        kasumi_types::validate_name(command_id)?;
        let receipt = crate::custody_tables::receipt(self.custody.store(), command_id)?;
        self.check_access()?;
        Ok(receipt)
    }
    pub async fn write(&self, command: CustodyCommand) -> Result<Vec<u8>> {
        self.check_access()?;
        let command = RaftCommand::custody(&command)?;
        let data = match &self.local {
            Some(local) => local.write(command).await?,
            None => self.raft().client_write(command).await?.data,
        };
        self.check_access().context(crate::PostCommitAccessLost)?;
        Ok(data)
    }
    pub async fn linearizable_barrier(&self) -> Result<Option<LogId<u64>>> {
        if let Some(local) = &self.local {
            self.check_access()?;
            let applied = local.barrier().await?;
            self.check_access()?;
            return Ok(applied);
        }
        crate::quorum::barrier(
            self.raft(),
            || self.check_access(),
            self.custody.store(),
            None,
        )
        .await
    }
    pub async fn snapshot(&self) -> Result<()> {
        self.check_access()?;
        if let Some(local) = &self.local {
            return local.snapshot().await;
        }
        self.raft().trigger().snapshot().await?;
        Ok(())
    }
    pub async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        self.snapshot_buffers.seal_application_source_consumers();
        let mut report = self.shutdown_report.lock().await;
        let mut buffer_unresolved = None;
        if let Some(local) = &self.local {
            if let Err(failure) = local.shutdown().await {
                report.merge(&failure);
            }
        } else if let Err(error) = self.raft().shutdown().await {
            report.record("OpenRaft custody runtime", 0, error.into());
        }
        if let Err(failure) = self.snapshot_buffers.drain_buffers().await {
            report.merge(&failure);
            if failure.completion() == kasumi_types::drain::DrainCompletion::Retained {
                buffer_unresolved = Some(failure);
            }
        }
        self.storage_drain.wait().await;
        if let Err(failure) = self.snapshot_buffers.drain_buffers().await {
            report.merge(&failure);
            if failure.completion() == kasumi_types::drain::DrainCompletion::Retained {
                buffer_unresolved = Some(failure);
            }
        }
        let mut source_unresolved = None;
        if let Err(failure) = self.snapshot_buffers.drain_application_sources().await {
            report.merge(&failure);
            if failure.completion() == kasumi_types::drain::DrainCompletion::Retained {
                source_unresolved = Some(failure);
            }
        }
        let buffer_unresolved = self
            .snapshot_buffers
            .finish_failed_buffer_drain(buffer_unresolved, &mut report)
            .await;
        let unresolved = source_unresolved.or(buffer_unresolved);
        if unresolved.is_none() {
            self.snapshot_buffers.release_group_ownership();
        }
        report.outcome(unresolved)
    }
}
