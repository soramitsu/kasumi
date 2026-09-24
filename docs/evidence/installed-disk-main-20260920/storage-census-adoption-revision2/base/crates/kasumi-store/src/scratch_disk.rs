//! Shared admission for encrypted temporary storage, independent of deterministic
//! tenant quotas. Charges follow the actual file owner, including detached workers
//! and immutable snapshot readers. This does not reserve persistent database space
//! or make filesystem allocation immune to other processes or device failures.
use crate::DiskOpenError;
use crate::{
    device_disk::{DeviceDisk, DeviceSelection},
    disk_memory::{self, DiskMemoryRequirements, Lease, List, NodeDiskMemoryAdmission},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchDiskConfig {
    pub directory: PathBuf,
    /// Aggregate rounded ciphertext extent capacity for all live scratch files.
    pub max_bytes: u64,
    /// Leave this observed filesystem capacity outside scratch admission so
    /// permanent journal, archive publication and operator recovery can progress.
    pub min_free_bytes: u64,
}
impl ScratchDiskConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.directory.is_absolute(),
            "scratch directory must be absolute"
        );
        ensure!(
            self.max_bytes > 0 && self.max_bytes <= i64::MAX as u64,
            "scratch byte budget is zero or exceeds supported file offsets"
        );
        ensure!(
            self.max_bytes.checked_add(self.min_free_bytes).is_some(),
            "scratch capacity and filesystem reserve overflow"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScratchDiskSnapshot {
    pub max_bytes: u64,
    pub min_free_bytes: u64,
    pub charged_bytes: u64,
    pub live_files: u64,
    /// Capacity promised but not yet observed in allocated file blocks, shared
    /// with every scratch governor on the same physical filesystem in this process.
    pub filesystem_pending_bytes: u64,
    pub filesystem_available_bytes: Option<u64>,
    pub filesystem_admission_ready: bool,
}
#[derive(Default, Debug)]
struct State {
    bytes: u64,
    files: u64,
}
struct RegisteredScratch {
    identity: (u64, u64),
    owner: Arc<ScratchDisk>,
    // Installed ownership, like NodeDisk: this entry and its actual owner remain
    // funded together until process exit, including external Weak observers.
    _charge: Lease,
}
type Registry = parking_lot::Mutex<List<RegisteredScratch>>;
fn registry() -> &'static Registry {
    static REGISTRY: Registry = parking_lot::Mutex::new(List::new());
    &REGISTRY
}

pub struct ScratchDisk {
    config: ScratchDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    directory_c: CString,
    identity: (u64, u64),
    directory: File,
    allocation_unit: u64,
    state: Mutex<State>,
    device: DeviceDisk,
    #[cfg(test)]
    available_override: Mutex<Option<u64>>,
    _memory_charge: Lease,
}
impl std::fmt::Debug for ScratchDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScratchDisk")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}
impl ScratchDisk {
    /// Open one exact private directory. Another live owner of the same physical
    /// directory shares the original governor and must request identical budgets.
    /// Parents must already exist; no implicit system temporary-directory fallback.
    pub fn memory(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.memory
    }
    pub fn required_metadata_bytes(config: &ScratchDiskConfig) -> Result<u64> {
        use std::os::unix::ffi::OsStrExt;
        config.validate()?;
        let path = u64::try_from(config.directory.as_os_str().as_bytes().len())?;
        Ok(disk_memory::add(
            disk_memory::arc::<Self>()?,
            disk_memory::add(64 << 10, disk_memory::mul(3, disk_memory::add(path, 1)?)?)?,
        )?)
    }
    pub fn memory_requirements(config: &ScratchDiskConfig) -> Result<DiskMemoryRequirements> {
        let (device_bytes, registration_bytes) = DeviceDisk::metadata_requirements()?;
        let registry_bytes = disk_memory::allocation::<disk_memory::Entry<RegisteredScratch>>(1)?;
        Ok(DiskMemoryRequirements {
            owner_bytes: Self::required_metadata_bytes(config)?,
            registry_bytes,
            device_bytes,
            registration_bytes,
        })
    }
    pub fn open(
        config: &ScratchDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        Self::open_inner(config, memory, DeviceSelection::Installed)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_fixture(
        config: &ScratchDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        Self::open_inner(config, memory, DeviceSelection::Isolated)
    }
    fn open_inner(
        config: &ScratchDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        selection: DeviceSelection,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        use std::os::unix::ffi::OsStrExt;
        config.validate()?;
        let mut registry = registry().try_lock().ok_or(DiskOpenError::RegistryBusy)?;
        let existing = registry
            .find(|entry| entry.owner.config.directory == config.directory)
            .map(|entry| entry.owner.clone());
        if let Some(existing) = existing {
            disk_memory::require(
                existing.config == *config,
                "live scratch directory has different installed budgets or path",
            )?;
            disk_memory::require(
                Arc::ptr_eq(existing.memory(), &memory),
                "live scratch directory has different memory admission",
            )?;
            existing.verify_nonallocating()?;
            return Ok(existing);
        }
        let requirements = Self::memory_requirements(config)?;
        let charge = memory.clone().reserve_installed(requirements.owner_bytes)?;
        let registry_charge = memory
            .clone()
            .reserve_installed(requirements.registry_bytes)?;
        let directory_c =
            CString::new(config.directory.as_os_str().as_bytes()).map_err(anyhow::Error::from)?;
        match crate::private_files::create_directory(&config.directory) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error.context("creating scratch directory").into()),
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&config.directory)
            .context("opening private scratch directory")?;
        let metadata = directory.metadata()?;
        check_directory(&metadata)?;
        let identity = (metadata.dev(), metadata.ino());
        disk_memory::require(
            !registry.iter().any(|entry| entry.identity == identity),
            "scratch physical directory already has another installed path",
        )?;
        let (_, allocation_unit) = filesystem(&directory)?;
        let device = selection.open(metadata.dev(), config.min_free_bytes, memory.clone())?;
        let disk = Arc::new(Self {
            config: config.clone(),
            memory,
            directory_c,
            identity,
            directory,
            allocation_unit,
            device,
            state: Mutex::new(State::default()),
            #[cfg(test)]
            available_override: Mutex::new(None),
            _memory_charge: charge,
        });
        drop(disk.state.lock().expect("unpublished scratch state"));
        #[cfg(test)]
        drop(disk.available_override.lock().unwrap());
        let entry = List::prepare(RegisteredScratch {
            identity,
            owner: disk.clone(),
            _charge: registry_charge,
        });
        registry.insert(entry);
        Ok(disk)
    }
    fn verify_nonallocating(&self) -> io::Result<()> {
        let fd = unsafe {
            libc::open(
                self.directory_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let observed = unsafe { File::from_raw_fd(fd) };
        let metadata = observed.metadata()?;
        let retained = self.directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || (metadata.dev(), metadata.ino()) != self.identity
            || (retained.dev(), retained.ino()) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    /// Trusted fixture setup must retain the enclosing private directory for
    /// the full fixture scope. The installed owner never owns a TempDir cleanup.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture(
        directory: impl AsRef<std::path::Path>,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Arc<Self> {
        let config = ScratchDiskConfig {
            directory: directory.as_ref().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
        };
        crate::test_utils::retry_disk_registry(|| Self::open_fixture(&config, memory.clone()))
            .expect("fixture scratch governor")
    }
    #[cfg(test)]
    pub(crate) fn isolated_fixture(
        directory: impl AsRef<std::path::Path>,
        max_bytes: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Arc<Self> {
        let config = ScratchDiskConfig {
            directory: directory.as_ref().to_owned(),
            max_bytes,
            min_free_bytes: 0,
        };
        crate::test_utils::retry_disk_registry(|| Self::open_fixture(&config, memory.clone()))
            .expect("isolated scratch governor")
    }
    #[cfg(test)]
    pub(crate) fn test_with_device(
        directory: PathBuf,
        device: DeviceDisk,
        available: u64,
    ) -> Arc<Self> {
        let memory = device.memory().clone();
        let config = ScratchDiskConfig {
            directory,
            max_bytes: 16 << 20,
            min_free_bytes: 0,
        };
        let owner = Self::open_inner(&config, memory, DeviceSelection::Existing(device)).unwrap();
        *owner.available_override.lock().unwrap() = Some(available);
        owner
    }
    pub fn snapshot(&self) -> ScratchDiskSnapshot {
        let state = self.lock_state();
        let pending = self.device.lock();
        ScratchDiskSnapshot {
            max_bytes: self.config.max_bytes,
            min_free_bytes: self.config.min_free_bytes,
            charged_bytes: state.bytes,
            live_files: state.files,
            filesystem_pending_bytes: *pending,
            filesystem_available_bytes: self.available().ok(),
            filesystem_admission_ready: pending.admission_ready(),
        }
    }
    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| {
            self.device.lock().fail_owner();
            p.into_inner()
        })
    }
    fn available(&self) -> io::Result<u64> {
        #[cfg(test)]
        if let Some(available) = *self.available_override.lock().unwrap() {
            return Ok(available);
        }
        filesystem(&self.directory).map(|v| v.0)
    }
    fn rounded(&self, ciphertext_len: u64) -> io::Result<u64> {
        ciphertext_len
            .div_ceil(self.allocation_unit)
            .checked_mul(self.allocation_unit)
            .ok_or_else(|| exhausted("scratch rounded extent overflow"))
    }
    pub(crate) fn file(self: &Arc<Self>) -> io::Result<(File, Charge)> {
        let state = self.lock_state();
        let ready = self.device.lock().admission_ready();
        drop(state);
        if !ready {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        check_directory(&self.directory.metadata()?).map_err(io::Error::other)?;
        let name = CString::new(format!("kasumi-scratch-{}", uuid::Uuid::new_v4())).unwrap();
        // The opened directory descriptor, not a replaceable pathname, selects
        // the filesystem. The random name is removed before any payload is written.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let identity = (metadata.dev(), metadata.ino());
        let mut state = self.lock_state();
        state.files = state
            .files
            .checked_add(1)
            .ok_or_else(|| exhausted("scratch file count overflow"))?;
        Ok((
            file,
            Charge {
                disk: self.clone(),
                identity,
                bytes: 0,
                allocated: 0,
            },
        ))
    }
}

fn check_directory(metadata: &std::fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "scratch directory must be private and owned"
    );
    Ok(())
}
fn exhausted(_message: &'static str) -> io::Error {
    io::Error::from(io::ErrorKind::StorageFull)
}

fn filesystem(directory: &File) -> io::Result<(u64, u64)> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: stat points to initialized storage and the directory remains open.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let unit = stat.f_frsize as u64;
    if unit == 0 {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    let available = (stat.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;
    Ok((available, unit))
}

/// File must close before this guard drops. A failed write keeps the full charge
/// until retry, explicit successful truncation, or final file-owner destruction.
pub(crate) struct Charge {
    disk: Arc<ScratchDisk>,
    identity: (u64, u64),
    bytes: u64,
    allocated: u64,
}
impl Charge {
    pub(crate) fn disk(&self) -> &Arc<ScratchDisk> {
        &self.disk
    }
    pub(crate) fn fail_owner(&self) {
        self.disk.device.lock().fail_owner();
    }

    pub(crate) fn check_owner(&self, file: &File) -> io::Result<()> {
        // Locking the retained owner observes a poisoned accounting state before
        // any physical operation. No pathname or newly allocated error is needed.
        let _state = self.disk.lock_state();
        if !self.disk.device.lock().admission_ready() {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let metadata = file.metadata().inspect_err(|_| self.fail_owner())?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
            || (metadata.dev(), metadata.ino()) != self.identity
        {
            self.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(())
    }

    pub(crate) fn grow(&mut self, ciphertext_len: u64) -> io::Result<()> {
        let bytes = self.disk.rounded(ciphertext_len)?;
        let mut state = self.disk.lock_state();
        let mut pending = self.disk.device.lock();
        if !pending.admission_ready() {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        if bytes <= self.bytes {
            return Ok(());
        }
        let delta = bytes - self.bytes;
        let next = state
            .bytes
            .checked_add(delta)
            .filter(|n| *n <= self.disk.config.max_bytes)
            .ok_or_else(|| exhausted("shared scratch byte budget exhausted"))?;
        let promised = pending
            .checked_add(delta)
            .ok_or_else(|| exhausted("scratch promises overflow"))?;
        let required = promised
            .checked_add(pending.minimum_free_bytes())
            .ok_or_else(|| exhausted("scratch filesystem reserve overflow"))?;
        let available = self
            .disk
            .available()
            .inspect_err(|_| pending.fail_owner())?;
        if available < required {
            return Err(exhausted("scratch filesystem free-space reserve exhausted"));
        }
        pending.set_pending(promised)?;
        state.bytes = next;
        self.bytes = bytes;
        Ok(())
    }
    pub(crate) fn observe(&mut self, file: &File) -> io::Result<()> {
        self.check_owner(file)?;
        let metadata = file.metadata().inspect_err(|_| self.fail_owner())?;
        let allocated = metadata.blocks().checked_mul(512).ok_or_else(|| {
            self.fail_owner();
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if metadata.len() > self.bytes || allocated > self.bytes {
            self.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let mut pending = self.disk.device.lock();
        let Some(next) = pending
            .checked_sub(self.bytes - self.allocated)
            .and_then(|n| n.checked_add(self.bytes - allocated))
        else {
            pending.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        pending.set_pending(next)?;
        self.allocated = allocated;
        Ok(())
    }

    // Only an exact synchronized anonymous extent can return unused promises.
    // This also settles a reservation whose capacity was never physically used.
    pub(crate) fn shrink(&mut self, file: &File, ciphertext_len: u64) -> io::Result<()> {
        self.check_owner(file)?;
        file.sync_all().inspect_err(|_| self.fail_owner())?;
        let metadata = file.metadata().inspect_err(|_| self.fail_owner())?;
        let bytes = self.disk.rounded(ciphertext_len)?;
        let allocated = metadata.blocks().checked_mul(512).ok_or_else(|| {
            self.fail_owner();
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if metadata.len() != ciphertext_len || bytes > self.bytes || allocated > bytes {
            self.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let mut state = self.disk.lock_state();
        let mut pending = self.disk.device.lock();
        let next = pending
            .checked_sub(self.bytes - self.allocated)
            .and_then(|n| n.checked_add(bytes - allocated));
        let owned = state.bytes.checked_sub(self.bytes - bytes);
        let (Some(next), Some(owned)) = (next, owned) else {
            pending.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        pending.set_pending(next)?;
        state.bytes = owned;
        self.bytes = bytes;
        self.allocated = allocated;
        Ok(())
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut state = self.disk.lock_state();
        let mut pending = self.disk.device.lock();
        let bytes = state.bytes.checked_sub(self.bytes);
        let files = state.files.checked_sub(1);
        let next = pending.checked_sub(self.bytes - self.allocated);
        if let (Some(bytes), Some(files), Some(next)) = (bytes, files, next) {
            if pending.set_pending(next).is_ok() {
                state.bytes = bytes;
                state.files = files;
            }
        } else {
            pending.fail_owner();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn disk(directory: &std::path::Path, max_bytes: u64, min_free_bytes: u64) -> Arc<ScratchDisk> {
        let memory = crate::test_utils::TestDiskMemory::new(16 << 20, 256);
        let config = ScratchDiskConfig {
            directory: directory.to_owned(),
            max_bytes,
            min_free_bytes,
        };
        crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_inner(&config, memory.clone(), DeviceSelection::Isolated)
        })
        .unwrap()
    }
    #[test]
    fn physical_directory_reopens_share_budget_and_cannot_change_it() {
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 0);
        let same = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&disk.config, disk.memory().clone())
        })
        .unwrap();
        assert!(Arc::ptr_eq(&disk, &same));
        let mut changed = disk.config.clone();
        changed.max_bytes += 1;
        assert!(
            crate::test_utils::retry_disk_registry(|| ScratchDisk::open_fixture(
                &changed,
                disk.memory().clone()
            ))
            .is_err()
        );
        let (file, mut charge) = disk.file().unwrap();
        charge.grow(1 << 20).unwrap();
        assert_eq!(same.snapshot().charged_bytes, 1 << 20);
        drop(file);
        drop(charge);
        assert_eq!(same.snapshot().charged_bytes, 0);
    }
    #[test]
    fn pending_files_share_filesystem_promises_and_keep_recovery_reserve() {
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 1 << 16);
        let (file, mut charge) = disk.file().unwrap();
        let baseline = disk.snapshot().filesystem_pending_bytes;
        *disk.available_override.lock().unwrap() = Some(baseline + (1 << 17));
        charge.grow(1 << 16).unwrap();
        let (second_file, mut second) = disk.file().unwrap();
        assert_eq!(
            second.grow(1).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(disk.snapshot().charged_bytes, 1 << 16);
        drop(file);
        drop(charge);
        second.grow(1 << 16).unwrap();
        drop(second_file);
        drop(second);
        assert_eq!(disk.snapshot().live_files, 0);
    }

    #[test]
    fn separate_governors_cannot_double_spend_filesystem_promises() {
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let first = disk(fixture_directory.path(), 1 << 20, 1 << 16);
        let directory = crate::test_utils::private_tempdir().unwrap();
        let config = ScratchDiskConfig {
            directory: directory.path().join("scratch"),
            max_bytes: 1 << 20,
            min_free_bytes: 1 << 16,
        };
        let second = ScratchDisk::open_inner(
            &config,
            first.memory().clone(),
            DeviceSelection::Existing(first.device.share(config.min_free_bytes)),
        )
        .unwrap();
        *first.available_override.lock().unwrap() = Some(1 << 17);
        *second.available_override.lock().unwrap() = Some(1 << 17);
        let (first_file, mut first_charge) = first.file().unwrap();
        let (second_file, mut second_charge) = second.file().unwrap();
        first_charge.grow(1 << 16).unwrap();
        assert!(second_charge.grow(1 << 16).is_err());
        assert_eq!(second.snapshot().charged_bytes, 0);
        assert_eq!(second.snapshot().filesystem_pending_bytes, 1 << 16);
        drop(first_file);
        drop(first_charge);
        second_charge.grow(1 << 16).unwrap();
        assert_eq!(second.snapshot().charged_bytes, 1 << 16);
        drop(second_file);
        drop(second_charge);
        assert_eq!(first.snapshot().filesystem_pending_bytes, 0);
    }
    #[test]
    fn pinned_directory_survives_path_substitution_without_using_replacement() {
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 0);
        let original = disk.config.directory.with_extension("held");
        std::fs::rename(&disk.config.directory, &original).unwrap();
        crate::private_files::create_directory(&disk.config.directory).unwrap();
        let (file, charge) = disk.file().unwrap();
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        assert_eq!(
            std::fs::read_dir(&disk.config.directory).unwrap().count(),
            0
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
        drop(file);
        drop(charge);
        std::fs::remove_dir(original).unwrap();
    }
    #[test]
    fn rejects_symlinks_and_overflowing_configuration() {
        let root = tempfile::tempdir().unwrap();
        let actual = root.path().join("actual");
        crate::private_files::create_directory(&actual).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(actual, &link).unwrap();
        let config = ScratchDiskConfig {
            directory: link,
            max_bytes: 1,
            min_free_bytes: 0,
        };
        let memory = crate::test_utils::TestDiskMemory::new(1 << 20, 32);
        assert!(
            crate::test_utils::retry_disk_registry(|| {
                ScratchDisk::open_fixture(&config, memory.clone())
            })
            .is_err()
        );
        assert!(
            ScratchDiskConfig {
                directory: root.path().to_owned(),
                max_bytes: i64::MAX as u64,
                min_free_bytes: u64::MAX
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn concurrent_spools_cannot_each_spend_the_aggregate_budget() {
        use std::{io::Write, sync::Barrier};
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 0);
        let barrier = Arc::new(Barrier::new(33));
        let mut workers = Vec::new();
        for _ in 0..32 {
            let disk = disk.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let mut spool = crate::EncryptedSpool::new(&disk, 1 << 20).unwrap();
                let accepted = spool.write_all(&[19]).is_ok();
                assert_eq!(spool.len(), u64::from(accepted));
                barrier.wait();
                barrier.wait();
                accepted
            }));
        }
        barrier.wait();
        let unit = disk.rounded((64 << 10) + 40).unwrap();
        let capacity = disk.config.max_bytes / unit;
        assert_eq!(disk.snapshot().charged_bytes, capacity * unit);
        barrier.wait();
        let accepted = workers
            .into_iter()
            .map(|worker| u64::from(worker.join().unwrap()))
            .sum::<u64>();
        assert_eq!(accepted, capacity);
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().live_files, 0);
    }

    #[test]
    fn immutable_image_readers_retain_capacity_until_the_last_owner_drains() {
        use std::io::Read;
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 0);
        let image = crate::SnapshotImage::capture(&disk, 128 << 10, |writer| {
            writer.write_all(&[37; 128 << 10])?;
            Ok(())
        })
        .unwrap();
        let charge = disk.snapshot().charged_bytes;
        assert!(charge > image.len());
        assert!(Arc::ptr_eq(image.disk(), &disk));
        let mut reader = image.reader();
        let clone = image.clone();
        drop(image);
        drop(clone);
        assert_eq!(disk.snapshot().charged_bytes, charge);
        let mut bytes = [0; 128];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [37; 128]);
        drop(reader);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }

    #[test]
    fn truncation_and_rejected_growth_preserve_exact_file_charges() {
        use std::io::{Read, Seek, Write};
        let fixture_directory = crate::test_utils::private_tempdir().unwrap();
        let disk = disk(fixture_directory.path(), 1 << 20, 0);
        let mut spool = crate::EncryptedSpool::new(&disk, 8 << 20).unwrap();
        spool.write_all(&[73; 128 << 10]).unwrap();
        spool.flush().unwrap();
        let charged = disk.snapshot().charged_bytes;
        // reserve failure must not mutate the existing logical bytes or extent.
        let (file, mut competing) = disk.file().unwrap();
        competing.grow((1 << 20) - charged).unwrap();
        assert!(spool.write_all(&[0]).is_err());
        assert_eq!(spool.len(), 128 << 10);
        drop(file);
        drop(competing);
        assert_eq!(disk.snapshot().charged_bytes, charged);
        spool.resize(7).unwrap();
        let one_block = disk.rounded((64 << 10) + 40).unwrap();
        assert_eq!(disk.snapshot().charged_bytes, one_block);
        spool.rewind().unwrap();
        let mut bytes = Vec::new();
        spool.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, [73; 7]);
        spool.resize(0).unwrap();
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use crate::test_utils::TestDiskMemory;

    fn total(config: &ScratchDiskConfig) -> u64 {
        let required = ScratchDisk::memory_requirements(config).unwrap();
        [
            required.owner_bytes,
            required.registry_bytes,
            required.device_bytes,
            required.registration_bytes,
        ]
        .into_iter()
        .map(|bytes| TestDiskMemory::required_reservation_bytes(bytes).unwrap())
        .try_fold(0_u64, u64::checked_add)
        .unwrap()
    }
    fn config(directory: &tempfile::TempDir, name: &str) -> ScratchDiskConfig {
        ScratchDiskConfig {
            directory: directory.path().join(name),
            max_bytes: 1 << 20,
            min_free_bytes: 0,
        }
    }

    #[test]
    fn scratch_metadata_denial_precedes_directory_creation() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory, "not-created");
        let required = ScratchDisk::memory_requirements(&config).unwrap();
        let memory = TestDiskMemory::new(
            TestDiskMemory::required_reservation_bytes(required.owner_bytes).unwrap() - 1,
            4,
        );
        assert!(
            crate::test_utils::retry_disk_registry(|| ScratchDisk::open_fixture(
                &config,
                memory.clone()
            ))
            .is_err()
        );
        assert!(!config.directory.exists());
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().attempts, 1);
    }

    #[test]
    fn installed_scratch_reuse_keeps_metadata_funded_after_public_strong_handles_drop() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory, "scratch");
        let memory = TestDiskMemory::new(total(&config), 4);
        let disk = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        })
        .unwrap();
        let held = memory.snapshot();
        assert_eq!(held.used_bytes, total(&config));
        assert_eq!(held.live_reservations, 4);
        let same = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        })
        .unwrap();
        assert!(Arc::ptr_eq(&disk, &same));
        assert_eq!(memory.snapshot(), held);
        let foreign = TestDiskMemory::new(total(&config), 4);
        assert!(
            crate::test_utils::retry_disk_registry(|| ScratchDisk::open_fixture(
                &config,
                foreign.clone()
            ))
            .is_err()
        );
        assert_eq!(foreign.snapshot().attempts, 0);
        let mut different = config.clone();
        different.max_bytes += 1;
        assert!(
            crate::test_utils::retry_disk_registry(|| ScratchDisk::open_fixture(
                &different,
                memory.clone()
            ))
            .is_err()
        );
        assert_eq!(memory.snapshot(), held);
        let external_weak = Arc::downgrade(&disk);
        drop(same);
        assert_eq!(memory.snapshot(), held);
        drop(disk);
        assert_eq!(memory.snapshot(), held);
        let retained = external_weak
            .upgrade()
            .expect("installed registry retains actual owner");
        let reopened = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        })
        .unwrap();
        assert!(Arc::ptr_eq(&retained, &reopened));
        assert_eq!(memory.snapshot(), held);
        drop(retained);
        drop(reopened);
        drop(external_weak);
        assert_eq!(memory.snapshot(), held);
    }

    #[test]
    fn fixture_directory_custody_stays_with_caller_while_metadata_stays_installed() {
        let directory = crate::test_utils::private_tempdir().unwrap();
        let path = directory.path().to_owned();
        let memory = TestDiskMemory::new(1 << 20, 4);
        let disk = ScratchDisk::fixture(&path, memory.clone());
        let observer = Arc::downgrade(&disk);
        let held = memory.snapshot();
        drop(disk);
        assert!(path.exists());
        assert_eq!(memory.snapshot(), held);
        drop(directory);
        assert!(!path.exists());
        assert!(observer.upgrade().is_some());
        assert_eq!(memory.snapshot(), held);
    }

    #[test]
    fn scratch_file_release_does_not_release_installed_owner_or_registry_memory() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory, "scratch");
        let memory = TestDiskMemory::new(total(&config), 4);
        let disk = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        })
        .unwrap();
        let held = memory.snapshot();
        let mut spool = crate::EncryptedSpool::new(&disk, 1 << 20).unwrap();
        spool.write_all(b"a real encrypted scratch file").unwrap();
        spool.flush().unwrap();
        assert_eq!(disk.snapshot().live_files, 1);
        assert!(disk.snapshot().charged_bytes > 0);
        drop(spool);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().filesystem_pending_bytes, 0);
        assert_eq!(memory.snapshot(), held);
        drop(disk);
        assert_eq!(memory.snapshot(), held);
    }
}

#[cfg(test)]
mod registry_busy_tests {
    use super::*;
    #[test]
    fn busy_scratch_registry_does_not_allocate_admit_or_create_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let config = ScratchDiskConfig {
            directory: temporary.path().join("not-created"),
            max_bytes: 1 << 20,
            min_free_bytes: 0,
        };
        let memory = crate::test_utils::TestDiskMemory::new(1, 1);
        let guard = registry().lock();
        let (result, allocations) =
            crate::allocation_tests::measure(|| ScratchDisk::open_fixture(&config, memory.clone()));
        assert!(matches!(result, Err(DiskOpenError::RegistryBusy)));
        assert_eq!(allocations, 0);
        assert_eq!(memory.snapshot().attempts, 0);
        assert!(!config.directory.exists());
        drop(guard);
    }
}
