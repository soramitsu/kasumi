//! Shared admission for encrypted temporary storage, independent of deterministic
//! tenant quotas. Charges follow the actual file owner, including detached workers
//! and immutable snapshot readers. This does not reserve persistent database space
//! or make filesystem allocation immune to other processes or device failures.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, Weak},
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
}
#[derive(Default, Debug)]
struct State {
    bytes: u64,
    files: u64,
}
#[derive(Default, Debug)]
struct Device {
    pending: Mutex<u64>,
}
#[derive(Default)]
struct Registry {
    directories: HashMap<(u64, u64), Weak<ScratchDisk>>,
    devices: HashMap<u64, Weak<Device>>,
}
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub struct ScratchDisk {
    config: ScratchDiskConfig,
    directory: File,
    allocation_unit: u64,
    state: Mutex<State>,
    device: Arc<Device>,
    #[cfg(any(test, feature = "test-utils"))]
    _fixture: Option<tempfile::TempDir>,
    #[cfg(test)]
    available_override: Mutex<Option<u64>>,
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
    pub fn open(config: ScratchDiskConfig) -> Result<Arc<Self>> {
        Self::open_inner(
            config,
            #[cfg(any(test, feature = "test-utils"))]
            None,
        )
    }
    fn open_inner(
        config: ScratchDiskConfig,
        #[cfg(any(test, feature = "test-utils"))] fixture: Option<tempfile::TempDir>,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        match crate::private_files::create_directory(&config.directory) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error.context("creating scratch directory")),
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&config.directory)
            .context("opening private scratch directory")?;
        let metadata = directory.metadata()?;
        check_directory(&metadata)?;
        let key = (metadata.dev(), metadata.ino());
        let mut registry = registry().lock().unwrap_or_else(|p| p.into_inner());
        registry.directories.retain(|_, v| v.strong_count() != 0);
        registry.devices.retain(|_, v| v.strong_count() != 0);
        if let Some(existing) = registry.directories.get(&key).and_then(Weak::upgrade) {
            ensure!(
                existing.config.max_bytes == config.max_bytes
                    && existing.config.min_free_bytes == config.min_free_bytes,
                "live scratch directory has different installed budgets"
            );
            return Ok(existing);
        }
        let (_, allocation_unit) = filesystem(&directory)?;
        let device = match registry
            .devices
            .get(&metadata.dev())
            .and_then(Weak::upgrade)
        {
            Some(device) => device,
            None => {
                let device = Arc::new(Device::default());
                registry
                    .devices
                    .insert(metadata.dev(), Arc::downgrade(&device));
                device
            }
        };
        let disk = Arc::new(Self {
            config,
            directory,
            allocation_unit,
            device,
            state: Mutex::new(State::default()),
            #[cfg(any(test, feature = "test-utils"))]
            _fixture: fixture,
            #[cfg(test)]
            available_override: Mutex::new(None),
        });
        registry.directories.insert(key, Arc::downgrade(&disk));
        Ok(disk)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Arc<Self> {
        let directory = tempfile::tempdir().expect("fixture scratch directory");
        Self::open_inner(
            ScratchDiskConfig {
                directory: directory.path().join("scratch"),
                max_bytes: 256 << 30,
                min_free_bytes: 0,
            },
            Some(directory),
        )
        .expect("fixture scratch governor")
    }
    pub fn snapshot(&self) -> ScratchDiskSnapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let pending = self
            .device
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ScratchDiskSnapshot {
            max_bytes: self.config.max_bytes,
            min_free_bytes: self.config.min_free_bytes,
            charged_bytes: state.bytes,
            live_files: state.files,
            filesystem_pending_bytes: *pending,
            filesystem_available_bytes: self.available().ok(),
        }
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
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.files = state
            .files
            .checked_add(1)
            .ok_or_else(|| exhausted("scratch file count overflow"))?;
        Ok((
            file,
            Charge {
                disk: self.clone(),
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
fn exhausted(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::StorageFull, message)
}
fn filesystem(directory: &File) -> io::Result<(u64, u64)> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: stat points to initialized storage and the directory remains open.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let unit = stat.f_frsize as u64;
    if unit == 0 {
        return Err(io::Error::other("filesystem allocation unit unavailable"));
    }
    let available = (stat.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| io::Error::other("filesystem capacity overflow"))?;
    Ok((available, unit))
}

/// File must close before this guard drops. A failed write keeps the full charge
/// until retry, explicit successful truncation, or final file-owner destruction.
pub(crate) struct Charge {
    disk: Arc<ScratchDisk>,
    bytes: u64,
    allocated: u64,
}
impl Charge {
    pub(crate) fn disk(&self) -> &Arc<ScratchDisk> {
        &self.disk
    }
    pub(crate) fn grow(&mut self, ciphertext_len: u64) -> io::Result<()> {
        let bytes = self.disk.rounded(ciphertext_len)?;
        if bytes <= self.bytes {
            return Ok(());
        }
        let delta = bytes - self.bytes;
        let mut state = self.disk.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .disk
            .device
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let next = state
            .bytes
            .checked_add(delta)
            .filter(|n| *n <= self.disk.config.max_bytes)
            .ok_or_else(|| exhausted("shared scratch byte budget exhausted"))?;
        let promised = pending
            .checked_add(delta)
            .ok_or_else(|| exhausted("scratch promises overflow"))?;
        let required = promised
            .checked_add(self.disk.config.min_free_bytes)
            .ok_or_else(|| exhausted("scratch filesystem reserve overflow"))?;
        if self.disk.available()? < required {
            return Err(exhausted("scratch filesystem free-space reserve exhausted"));
        }
        state.bytes = next;
        *pending = promised;
        self.bytes = bytes;
        Ok(())
    }
    pub(crate) fn observe(&mut self, file: &File) -> io::Result<()> {
        let allocated = file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| io::Error::other("scratch allocated blocks overflow"))?
            .min(self.bytes);
        let mut pending = self
            .disk
            .device
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *pending = pending
            .checked_sub(self.bytes - self.allocated)
            .and_then(|n| n.checked_add(self.bytes - allocated))
            .expect("owned scratch promises balance");
        self.allocated = allocated;
        Ok(())
    }
    pub(crate) fn shrink(&mut self, file: &File, ciphertext_len: u64) -> io::Result<()> {
        let bytes = self.disk.rounded(ciphertext_len)?;
        if bytes >= self.bytes {
            return self.observe(file);
        }
        let allocated = file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| io::Error::other("scratch allocated blocks overflow"))?
            .min(bytes);
        let mut state = self.disk.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .disk
            .device
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *pending = pending
            .checked_sub(self.bytes - self.allocated)
            .and_then(|n| n.checked_add(bytes - allocated))
            .expect("owned scratch promises balance");
        state.bytes -= self.bytes - bytes;
        self.bytes = bytes;
        self.allocated = allocated;
        Ok(())
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut state = self.disk.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .disk
            .device
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state.bytes -= self.bytes;
        state.files -= 1;
        *pending -= self.bytes - self.allocated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn disk(max_bytes: u64, min_free_bytes: u64) -> Arc<ScratchDisk> {
        let directory = tempfile::tempdir().unwrap();
        let disk = ScratchDisk::open_inner(
            ScratchDiskConfig {
                directory: directory.path().join("scratch"),
                max_bytes,
                min_free_bytes,
            },
            Some(directory),
        )
        .unwrap();
        // Synthetic free-space observations must not race unrelated test files
        // on the host's actual shared filesystem promise ledger.
        if min_free_bytes != 0 {
            let mut owned = Arc::try_unwrap(disk).expect("unique test governor");
            owned.device = Arc::new(Device::default());
            Arc::new(owned)
        } else {
            disk
        }
    }
    #[test]
    fn physical_directory_reopens_share_budget_and_cannot_change_it() {
        let disk = disk(1 << 20, 0);
        let same = ScratchDisk::open(disk.config.clone()).unwrap();
        assert!(Arc::ptr_eq(&disk, &same));
        let mut changed = disk.config.clone();
        changed.max_bytes += 1;
        assert!(ScratchDisk::open(changed).is_err());
        let (file, mut charge) = disk.file().unwrap();
        charge.grow(1 << 20).unwrap();
        assert_eq!(same.snapshot().charged_bytes, 1 << 20);
        drop(file);
        drop(charge);
        assert_eq!(same.snapshot().charged_bytes, 0);
    }
    #[test]
    fn pending_files_share_filesystem_promises_and_keep_recovery_reserve() {
        let disk = disk(1 << 20, 1 << 16);
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
        let first = disk(1 << 20, 1 << 16);
        let mut second = Arc::try_unwrap(disk(1 << 20, 1 << 16)).unwrap();
        second.device = first.device.clone();
        let second = Arc::new(second);
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
        let disk = disk(1 << 20, 0);
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
        assert!(
            ScratchDisk::open(ScratchDiskConfig {
                directory: link,
                max_bytes: 1,
                min_free_bytes: 0
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
        let disk = disk(1 << 20, 0);
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
        let disk = disk(1 << 20, 0);
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
        let disk = disk(1 << 20, 0);
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
