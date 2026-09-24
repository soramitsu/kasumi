//! Explicit storage construction on one immutable, validated memory policy.
use anyhow::{Result, ensure};
use kasumi_engine::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
use kasumi_store::{CensusCancellation, NodeDisk, NodeDiskConfig, ScratchDisk, ScratchDiskConfig};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

// The policy is scalar data. This context adds no heap allocation or boxed
// factory; its inline fields travel inside the retained startup future.
#[derive(Clone)]
pub(crate) struct RuntimeStorage {
    policy: AdmissionConfig,
    memory: Arc<MemoryCore>,
    factory: DiskFactory,
}
#[derive(Clone, Copy)]
enum DiskFactory {
    Installed,
    #[cfg(test)]
    IsolatedFixture,
}
impl RuntimeStorage {
    pub(crate) fn installed(policy: &AdmissionConfig) -> Result<Self> {
        Ok(Self {
            policy: policy.clone(),
            memory: MemoryCore::installed(policy.clone())?,
            factory: DiskFactory::Installed,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture(policy: AdmissionConfig, memory: Arc<MemoryCore>) -> Result<Self> {
        memory.require_policy(&policy)?;
        Ok(Self {
            policy,
            memory,
            factory: DiskFactory::IsolatedFixture,
        })
    }
    #[cfg(test)]
    pub(crate) fn isolated_fixture(
        mut existing_policy: AdmissionConfig,
        persistent: &NodeDiskConfig,
        scratch: &ScratchDiskConfig,
    ) -> Result<Self> {
        let total = existing_policy.resolved_fixture_total_bytes()?;
        let disk_metadata =
            kasumi_engine::test_utils::isolated_disk_metadata_bytes(persistent, scratch)?;
        existing_policy.max_inflight_bytes = Some(
            total
                .checked_add(disk_metadata)
                .ok_or_else(|| anyhow::anyhow!("fixture disk memory total overflow"))?,
        );
        let memory = MemoryCore::new(existing_policy.clone())?;
        Self::fixture(existing_policy, memory)
    }
    #[cfg(test)]
    pub(crate) fn memory(&self) -> &Arc<MemoryCore> {
        &self.memory
    }
    #[cfg(test)]
    pub(crate) fn isolated_persistent_fixture(
        mut existing_policy: AdmissionConfig,
        persistent: &NodeDiskConfig,
    ) -> Result<Self> {
        let total = existing_policy.resolved_fixture_total_bytes()?;
        let metadata = kasumi_engine::test_utils::isolated_metadata_bytes(
            NodeDisk::memory_requirements(persistent)?,
        )?;
        existing_policy.max_inflight_bytes = Some(
            total
                .checked_add(metadata)
                .ok_or_else(|| anyhow::anyhow!("fixture persistent memory total overflow"))?,
        );
        let memory = MemoryCore::new(existing_policy.clone())?;
        Self::fixture(existing_policy, memory)
    }
    pub(crate) fn policy(&self) -> &AdmissionConfig {
        &self.policy
    }
    pub(crate) fn require_policy(&self, policy: &AdmissionConfig) -> Result<()> {
        self.memory.require_policy(policy)
    }
    pub(crate) fn facade(&self, policy: &AdmissionConfig) -> Result<Arc<NodeAdmission>> {
        self.require_policy(policy)?;
        NodeAdmission::from_memory(self.memory.clone())
    }
    pub(crate) fn require_admission(&self, admission: &NodeAdmission) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.memory, admission.memory()),
            "storage and runtime memory cores differ"
        );
        Ok(())
    }
    pub(crate) fn open_persistent(&self, config: &NodeDiskConfig) -> Result<Arc<NodeDisk>> {
        let cancel = CensusCancellation::default();
        Ok(match self.factory {
            DiskFactory::Installed => NodeDisk::open(config, self.memory.clone(), &cancel),
            #[cfg(test)]
            DiskFactory::IsolatedFixture => kasumi_store::test_utils::retry_disk_registry(|| {
                NodeDisk::open_fixture(config, self.memory.clone(), &cancel)
            }),
        }?)
    }
    pub(crate) fn open_scratch(&self, config: &ScratchDiskConfig) -> Result<Arc<ScratchDisk>> {
        Ok(match self.factory {
            DiskFactory::Installed => ScratchDisk::open(config, self.memory.clone()),
            #[cfg(test)]
            DiskFactory::IsolatedFixture => kasumi_store::test_utils::retry_disk_registry(|| {
                ScratchDisk::open_fixture(config, self.memory.clone())
            }),
        }?)
    }
    #[cfg(test)]
    fn fixture_disk_profile(config: NodeDiskConfig) -> NodeDiskConfig {
        NodeDiskConfig {
            max_census_entries: 16_384,
            max_open_files: 256,
            max_open_directories: 256,
            ..config
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_installation_disk_config(
        roots: BTreeMap<String, PathBuf>,
    ) -> NodeDiskConfig {
        Self::fixture_disk_profile(
            crate::persistent_disk::initial_config(roots, kasumi_store::DirectoryPolicy::fixture())
                .unwrap(),
        )
    }
    // Used only when generating a brand-new installation. Existing RuntimeConfig
    // disk policies are always passed directly to open_persistent unchanged.
    pub(crate) fn new_installation_disk_config(
        &self,
        roots: BTreeMap<String, PathBuf>,
        directory_policy: kasumi_store::DirectoryPolicy,
    ) -> Result<NodeDiskConfig> {
        let config = crate::persistent_disk::initial_config(roots, directory_policy)?;
        Ok(match self.factory {
            DiskFactory::Installed => config,
            #[cfg(test)]
            DiskFactory::IsolatedFixture => Self::fixture_disk_profile(config),
        })
    }
}
