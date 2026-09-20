//! The same installed Raft group reopened with only the custody key domain.
use crate::lifetime::StorageDrain;
use crate::{ControlLog, CustodyCommand, LogId, Raft, RaftCommand, RaftGroupConfig, RaftTransport};
use anyhow::{Context, Result, ensure};
use kasumi_store::CustodyStore;
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
    raft: Raft,
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
    ) -> Result<Self> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::open_inner(id, group, custody, transport, config, snapshot_buffers)
                    .await
                    .map(crate::startup_owner::StartedGroup::Custody)
            })
            .await?
        {
            crate::startup_owner::StartedGroup::Custody(group) => Ok(group),
            _ => unreachable!("custody startup result"),
        }
    }

    async fn open_inner(
        id: u64,
        group: String,
        custody: Arc<CustodyStore>,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<crate::SnapshotBufferOwner>,
    ) -> Result<Self> {
        let limits = config.limits;
        ensure!(
            limits.max_snapshot_bytes >= 4 << 20,
            "custody snapshot budget is too small for bounded control records"
        );
        let mut raft_config = config.raft;
        raft_config.cluster_name = group.clone();
        let config = Arc::new(raft_config.validate()?);
        let ownership = crate::claim_custody(&custody)?;
        let (storage_drain, lease) = StorageDrain::new();
        let opened = async {
            let control = ControlLog::open(custody.clone(), id, group.clone())?;
            let recovery_lease = lease.clone();
            let recovery_ownership = ownership.clone();
            ensure!(
                tokio::task::spawn_blocking(move || {
                    let _lease = recovery_lease;
                    let _ownership = recovery_ownership;
                    control.recover_retired()
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
            log.bind_group(group.clone()).await?;
            let saved = crate::custody_machine::load_snapshot(&custody, limits.max_snapshot_bytes)?
                .context("closed startup snapshot absent")?;
            let floor = saved
                .meta
                .last_log_id
                .context("closed startup has no log coverage")?;
            // Only encrypted control headers/bodies are removed. The immutable
            // retired municipal payload remains encrypted under its original key.
            log.purge(floor).await?;
            let raft = Raft::new(
                id,
                config,
                crate::network::NetworkFactory::new(id, group, transport),
                log,
                machine,
            )
            .await?;
            Ok::<_, anyhow::Error>((raft, machine_failed))
        }
        .await;
        drop(lease);
        let (raft, machine_failed) = match opened {
            Ok(value) => value,
            Err(error) => {
                return Err(crate::failed_startup(error, &snapshot_buffers, &storage_drain).await);
            }
        };
        Ok(Self {
            raft,
            custody,
            machine_failed,
            storage_drain,
            snapshot_buffers,
            shutdown_report: Default::default(),
            ownership,
        })
    }
    pub fn raft(&self) -> &Raft {
        &self.raft
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
        ensure!(
            self.raft.metrics().borrow().running_state.is_ok()
                && !self.machine_failed.load(Ordering::Acquire),
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
        let result = self
            .raft
            .client_write(RaftCommand::custody(&command)?)
            .await?;
        Ok(result.data)
    }
    pub async fn linearizable_barrier(&self) -> Result<Option<LogId<u64>>> {
        crate::quorum::barrier(
            &self.raft,
            || self.check_access(),
            self.custody.store(),
            None,
        )
        .await
    }
    pub async fn snapshot(&self) -> Result<()> {
        self.check_access()?;
        self.raft.trigger().snapshot().await?;
        Ok(())
    }
    pub async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        let mut report = self.shutdown_report.lock().await;
        if let Err(error) = self.raft.shutdown().await {
            report.record("OpenRaft custody runtime", 0, error.into());
        }
        if let Err(failure) = self.snapshot_buffers.drain_buffers().await {
            report.merge(&failure);
        }
        self.storage_drain.wait().await;
        self.ownership.store(false, Ordering::Release);
        report.complete()
    }
}
