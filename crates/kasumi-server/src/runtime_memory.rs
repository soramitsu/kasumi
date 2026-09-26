//! Explicit storage construction on one immutable, validated memory policy.
use anyhow::{Result, ensure};
use kasumi_engine::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
use kasumi_store::{
    CensusCancellation, DiskOpenError, NodeDisk, NodeDiskConfig, ScratchDisk, ScratchDiskConfig,
};
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
    /// Every caller is the start of a runtime, operator or provisioning step.
    /// An Open owner is shared. A fenced owner left by a drained predecessor
    /// is reopened only through `NodeDisk::reopen_fenced` and its fresh census;
    /// a still-live holder surfaces the typed `DiskOpenError::OwnerFenced`.
    /// Nothing waits for a predecessor or reuses a fenced owner.
    pub(crate) fn open_persistent(&self, config: &NodeDiskConfig) -> Result<Arc<NodeDisk>> {
        let cancel = CensusCancellation::default();
        let opened = match self.factory {
            DiskFactory::Installed => NodeDisk::open(config, self.memory.clone(), &cancel),
            #[cfg(test)]
            DiskFactory::IsolatedFixture => kasumi_store::test_utils::retry_disk_registry(|| {
                NodeDisk::open_fixture(config, self.memory.clone(), &cancel)
            }),
        };
        Ok(match opened {
            Err(DiskOpenError::OwnerFenced { .. }) => match self.factory {
                DiskFactory::Installed => {
                    NodeDisk::reopen_fenced(config, self.memory.clone(), &cancel)
                }
                #[cfg(test)]
                DiskFactory::IsolatedFixture => {
                    kasumi_store::test_utils::retry_disk_registry(|| {
                        NodeDisk::reopen_fenced(config, self.memory.clone(), &cancel)
                    })
                }
            },
            opened => opened,
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
            max_persistent_files: 16_384,
            max_persistent_subdirectories: 16_384,
            census_work_per_step: 16_384,
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

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{DiskWork, NodeDiskPhase};
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

    fn admitted(storage: &RuntimeStorage) -> (u64, u64, u64, usize) {
        let snapshot = storage.memory().snapshot();
        (
            snapshot.reserved_bytes,
            snapshot.bookkeeping_bytes,
            snapshot.resident_reserved_bytes,
            snapshot.live_reservations,
        )
    }

    fn accounting(disk: &NodeDisk) -> [u64; 6] {
        let snapshot = disk.snapshot();
        [
            snapshot.charged_bytes,
            snapshot.pending_bytes,
            snapshot.persistent_files,
            snapshot.persistent_directories,
            snapshot.observed_directory_bytes,
            snapshot.filesystem_pending_bytes,
        ]
    }

    #[test]
    fn fenced_persistent_owner_reopens_on_a_drained_start_without_a_second_charge() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let root = directory.path().join("persistent");
        let config = crate::persistent_disk::fixture_config(&root);
        let mut seeded = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("retained"))
            .unwrap();
        seeded.write_all(&[0x5a; 32 << 10]).unwrap();
        seeded.sync_all().unwrap();
        drop(seeded);
        let storage =
            RuntimeStorage::isolated_persistent_fixture(AdmissionConfig::default(), &config)
                .unwrap();
        let disk = storage.open_persistent(&config).unwrap();
        let accepted = accounting(&disk);
        assert_eq!(disk.snapshot().persistent_files, 1);
        let memory = admitted(&storage);

        // The previous runtime latches uncertain backend activity while it
        // still holds its file. A new start is refused with the typed fence.
        let file = disk.open_file("fixture", Path::new("retained")).unwrap();
        file.owner_failed();
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        for _ in 0..2 {
            let error = storage.open_persistent(&config).unwrap_err();
            let Some(DiskOpenError::OwnerFenced {
                phase: NodeDiskPhase::Failed,
                open_files: 1,
                ..
            }) = error.downcast_ref::<DiskOpenError>()
            else {
                panic!("a live fenced owner was reused: {error:#}");
            };
        }
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert!(!disk.snapshot().filesystem_admission_ready);
        assert_eq!(accounting(&disk), accepted);
        assert_eq!(admitted(&storage), memory);

        // The previous runtime drains and drops every handle. The next start
        // reopens the same installed owner only through its fresh census.
        let installed = Arc::as_ptr(&disk);
        drop(file);
        drop(disk);
        let disk = storage.open_persistent(&config).unwrap();
        assert_eq!(Arc::as_ptr(&disk), installed);
        let reopened = disk.snapshot();
        assert_eq!(reopened.phase, NodeDiskPhase::Open);
        assert!(reopened.filesystem_admission_ready);
        assert_eq!(reopened.open_files, 0);
        assert_eq!(accounting(&disk), accepted);
        assert_eq!(
            admitted(&storage),
            memory,
            "reopen must not acquire a second owner, registry or device charge"
        );
        let file = disk.open_file("fixture", Path::new("retained")).unwrap();
        let mut contents = vec![0; 32 << 10];
        file.read_exact_at(&mut contents, 0).unwrap();
        assert!(contents.iter().all(|byte| *byte == 0x5a));
        drop(file);

        // Admission recovered through the census; later starts share it.
        let created = disk
            .create_file("fixture", Path::new("after"), DiskWork::Foreground)
            .unwrap();
        created
            .reserve_growth(0, 4096, DiskWork::Foreground)
            .unwrap();
        created.grow_reserved(4096).unwrap();
        created.write_all_at(&[1; 4096], 0).unwrap();
        created.sync_all_and_parent().unwrap();
        drop(created);
        assert!(Arc::ptr_eq(
            &storage.open_persistent(&config).unwrap(),
            &disk
        ));
        assert_eq!(disk.snapshot().persistent_files, 2);
        assert_eq!(admitted(&storage), memory);
    }
}
