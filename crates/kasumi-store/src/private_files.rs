//! Durable owner-only files and directories. Operator material remains separate
//! from encrypted database files and must never enter ordinary data backups.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub fn create_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    anyhow::bail!("owner-only installation requires Unix file permissions");
    check_directory(path)
}

pub fn check_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_dir(), "private directory must not be a symlink");
    check_permissions(&metadata)
}

fn check_permissions(metadata: &std::fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.mode() & 0o077 == 0,
            "operator material must be owner-only"
        );
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "operator material has another owner"
        );
    }
    #[cfg(not(unix))]
    anyhow::bail!("owner-only installation requires Unix file permissions");
    Ok(())
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

/// Open the exact regular inode handed to redb. Validation runs on the opened
/// descriptor so a symlink or a replaced path cannot substitute another file
/// between permissions checking and database initialization. Redb retains its
/// own exclusive file lock on this descriptor.
pub(crate) fn open_database(path: &Path) -> Result<File> {
    let file = options().read(true).write(true).create(true).open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "database must be a regular file");
    check_permissions(&metadata)?;
    Ok(file)
}

pub fn read(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = options().read(true).open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "operator material must be a regular file"
    );
    check_permissions(&metadata)?;
    ensure!(
        metadata.len() <= maximum as u64,
        "operator material exceeds size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "operator material exceeds size limit"
    );
    Ok(bytes)
}

pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    check_directory(path.parent().context("operator file has no parent")?)?;
    let mut file = options().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

/// Atomic replacement: readers see either complete generation. A failure after
/// rename has uncertain durability and callers must reread before retrying.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("operator file has no parent")?;
    check_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    sync_parent(path)
}

pub fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().context("operator file has no parent")?)?.sync_all()?;
    Ok(())
}

/// Hold this guard throughout a read-modify-write transaction or the complete
/// lifetime of an offline exclusive operation. The lock inode is never deleted.
pub struct ExclusiveLock(File);
impl ExclusiveLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        check_directory(path.parent().context("lock has no parent")?)?;
        let file = options().read(true).write(true).create(true).open(path)?;
        check_permissions(&file.metadata()?)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "installation or operator material is already owned by another operation"
            );
        }
        Ok(Self(file))
    }
}
impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
