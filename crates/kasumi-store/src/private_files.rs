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
    check_directory(path)?;
    sync_parent(path)
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

pub fn read(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = options().read(true).open(path)?;
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
    // Read into one exact zeroizing allocation. A growing buffer would move
    // secret prefixes and free the old allocations without wiping them.
    let length = usize::try_from(metadata.len())?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .context("operator material allocation failed")?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    ensure!(
        file.read(&mut [0; 1])? == 0,
        "operator material changed while it was read"
    );
    Ok(bytes)
}

/// Read a configuration, certificate or operator request file. These decide
/// what the node trusts, so like operator material they must belong to this
/// user (or root) and be writable by no one else. Unlike operator material
/// they may be readable by others and may be reached through a symlink; the
/// checks apply to the file actually opened.
pub fn read_trusted(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = metadata.uid();
        ensure!(
            owner == unsafe { libc::geteuid() } || owner == 0,
            "{} belongs to another user (uid {owner})",
            path.display()
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "{} is writable by its group or by others; remove that with chmod go-w",
            path.display()
        );
    }
    #[cfg(not(unix))]
    anyhow::bail!("trusted configuration requires Unix file permissions");
    ensure!(
        metadata.len() <= maximum as u64,
        "configuration/certificate file exceeds byte limit"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "configuration/certificate file exceeds byte limit"
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

/// Publish one complete owner-only file without replacing any existing path.
/// A failed directory sync has an uncertain outcome; inspect the exact path.
pub fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("operator file has no parent")?;
    check_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
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

/// Physical identity retained by stopped-instance coordinators outside a
/// reclaimable generation directory. It prevents substitution of another inode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    device: u64,
    inode: u64,
}
impl DirectoryIdentity {
    pub(crate) fn from_verified((device, inode): (u64, u64)) -> Self {
        Self { device, inode }
    }
}
pub fn directory_identity(path: &Path) -> Result<DirectoryIdentity> {
    let directory = options().read(true).open(path)?;
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir(), "physical binding requires a directory");
    check_permissions(&metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    anyhow::bail!("physical directory identity requires Unix storage")
}

/// Publish a durably prepared inode without replacement or a transient second
/// hard link. Both names must belong to the same private directory. There is no
/// copy/delete fallback on a filesystem lacking exclusive rename support.
pub fn rename_exclusive(source: &Path, destination: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        source.parent() == destination.parent(),
        "exclusive publication crosses directories"
    );
    check_directory(source.parent().context("publication directory missing")?)?;
    let source_name = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let destination_name = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    // CString retains both NUL-terminated paths through this single syscall.
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_name.as_ptr(),
            libc::AT_FDCWD,
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renamex_np(
            source_name.as_ptr(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("exclusive prepared publication requires supported Unix storage");
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    sync_parent(destination)
}
pub fn file_identity(path: &Path) -> Result<FileIdentity> {
    let file = options().read(true).open(path)?;
    descriptor_identity(&file)
}
pub fn descriptor_identity(file: &File) -> Result<FileIdentity> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "physical binding requires a regular file"
    );
    check_permissions(&metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.nlink() == 1,
            "physical generation must have one directory entry"
        );
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    anyhow::bail!("physical file identity requires Unix storage")
}

pub fn open_read(path: &Path) -> Result<File> {
    let file = options().read(true).open(path)?;
    descriptor_identity(&file)?;
    Ok(file)
}

/// Hold this guard throughout a read-modify-write transaction or the complete
/// lifetime of an offline exclusive operation. The lock inode is never deleted.
pub struct ExclusiveLock(File);
impl ExclusiveLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        check_directory(path.parent().context("lock has no parent")?)?;
        let file = options().read(true).write(true).create(true).open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "exclusive ownership requires a regular file"
        );
        check_permissions(&metadata)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_read_fills_one_exact_zeroizing_allocation() {
        let root = crate::test_utils::private_tempdir().unwrap();
        let directory = root.path().join("private");
        create_directory(&directory).unwrap();
        let path = directory.join("material.json");
        // Large enough that an unsized read would grow and free old copies.
        let material = (0..5000u32).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        create(&path, &material).unwrap();
        let (bytes, allocations, requested) =
            crate::allocation_tests::measure_requested(|| read(&path, 1 << 20).unwrap());
        assert_eq!(bytes.as_slice(), material.as_slice());
        assert_eq!(allocations, 1);
        assert_eq!(requested, material.len());
        assert!(read(&path, material.len() - 1).is_err());
    }

    #[test]
    fn trusted_files_may_be_shared_for_reading_but_not_for_writing() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_utils::private_tempdir().unwrap();
        let path = root.path().join("ca.pem");
        std::fs::write(&path, b"certificate").unwrap();
        let mode = |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        for readable in [0o600, 0o640, 0o644, 0o444] {
            mode(readable).unwrap();
            assert_eq!(read_trusted(&path, 64).unwrap(), b"certificate");
        }
        let link = root.path().join("link.pem");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_trusted(&link, 64).unwrap(), b"certificate");
        for writable in [0o620, 0o602, 0o664, 0o666] {
            mode(writable).unwrap();
            let error = read_trusted(&path, 64).unwrap_err().to_string();
            assert!(
                error.contains("writable by its group or by others"),
                "{error}"
            );
            // A symlink cannot hide the file it reaches.
            assert!(read_trusted(&link, 64).is_err());
        }
        mode(0o644).unwrap();
        assert!(read_trusted(&path, 10).is_err());
        assert!(read_trusted(&root.path().join("missing.pem"), 64).is_err());
    }
}
