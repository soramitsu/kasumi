//! Closed native-group images for physical replacement fixtures.
//!
//! These helpers require every database holder and child process to have
//! stopped. They copy the current directory format, including all member
//! bytes; they neither interpret nor repair a database generation.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::{DiskMemoryLease, NodeDiskMemoryAdmission, disk_memory};

// Sixteen hexadecimal digits, the seven-byte checkpoint suffix, and a NUL.
const NAME_BYTES: usize = 24;

#[derive(Debug, PartialEq, Eq)]
struct MemberImage {
    name: [u8; NAME_BYTES],
    len: u64,
    sha256: [u8; 32],
}
impl MemberImage {
    fn name(&self) -> &[u8] {
        &self.name[..self.name.iter().position(|byte| *byte == 0).unwrap()]
    }
}

/// A complete sorted census with every member's full content digest. Inventory
/// allocation remains admitted until its backing has been destroyed.
pub struct FixtureNativeGroupImage {
    members: Vec<MemberImage>,
    _charge: DiskMemoryLease,
    directory_identity: (u64, u64),
    root_identity: (u64, u64),
}
impl FixtureNativeGroupImage {
    pub fn sha256(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        for member in &self.members {
            digest.update(member.name);
            digest.update(member.len.to_be_bytes());
            digest.update(member.sha256);
        }
        digest.finalize().into()
    }
}
impl std::fmt::Debug for FixtureNativeGroupImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixtureNativeGroupImage")
            .field("members", &self.members)
            .finish()
    }
}
impl PartialEq for FixtureNativeGroupImage {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}
impl Eq for FixtureNativeGroupImage {}

fn open_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        directory.metadata()?.is_dir(),
        "native group is not a directory"
    );
    Ok(directory)
}

fn identity(file: &File) -> Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn member_name(entry: &std::fs::DirEntry) -> Result<[u8; NAME_BYTES]> {
    let name = entry.file_name();
    let bytes = name.as_bytes();
    let text = std::str::from_utf8(bytes).context("non-UTF8 native group entry")?;
    ensure!(
        text == kasumi_kv::ROOT_FILE_NAME || kasumi_kv::GroupFile::parse_name(text).is_some(),
        "unexpected native group entry: {text}"
    );
    ensure!(
        entry.file_type()?.is_file(),
        "native group entry is not a regular file: {text}"
    );
    ensure!(
        bytes.len() < NAME_BYTES,
        "native group member name overflow"
    );
    let mut inline = [0; NAME_BYTES];
    inline[..bytes.len()].copy_from_slice(bytes);
    Ok(inline)
}

fn open_member(directory: &File, name: &[u8; NAME_BYTES], flags: libc::c_int) -> Result<File> {
    // The only accepted names above are bounded ASCII native member names.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr().cast(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        file.metadata()?.is_file(),
        "native group member is not a regular file"
    );
    Ok(file)
}

fn digest_member(directory: &File, name: [u8; NAME_BYTES]) -> Result<(MemberImage, (u64, u64))> {
    let mut file = open_member(directory, &name, libc::O_RDONLY)?;
    let original_identity = identity(&file)?;
    let original_len = file.metadata()?.len();
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 << 10];
    let mut len = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        len = len
            .checked_add(read as u64)
            .context("native image size overflow")?;
        digest.update(&buffer[..read]);
    }
    ensure!(
        len == original_len && file.metadata()?.len() == len,
        "native member changed while stopped image was captured"
    );
    Ok((
        MemberImage {
            name,
            len,
            sha256: digest.finalize().into(),
        },
        original_identity,
    ))
}

/// Fingerprint every current-format member with inline read workspace. The
/// explicit owner prepays both inventory and directory-enumeration workspace.
pub fn capture_native_group_image(
    path: &Path,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<FixtureNativeGroupImage> {
    let _workspace = memory
        .clone()
        .reserve_installed(disk_memory::allocation::<u8>(255)?)?;
    let directory = open_directory(path)?;
    let directory_identity = identity(&directory)?;
    let mut count = 0_usize;
    for entry in std::fs::read_dir(path)? {
        member_name(&entry?)?;
        count = count.checked_add(1).context("native inventory overflow")?;
    }
    let admitted = disk_memory::allocation::<MemberImage>(u64::try_from(count)?)?;
    let charge = memory.reserve_installed(admitted)?;
    let mut members = Vec::new();
    members.try_reserve_exact(count)?;
    ensure!(
        disk_memory::allocation::<MemberImage>(members.capacity() as u64)? <= admitted,
        "native inventory exceeded admission"
    );
    let mut root_identity = None;
    for entry in std::fs::read_dir(path)? {
        ensure!(
            members.len() < count,
            "native group grew while stopped image was captured"
        );
        let name = member_name(&entry?)?;
        let (member, file_identity) = digest_member(&directory, name)?;
        if member.name() == kasumi_kv::ROOT_FILE_NAME.as_bytes() {
            ensure!(
                root_identity.replace(file_identity).is_none(),
                "duplicate native root"
            );
        }
        members.push(member);
    }
    ensure!(
        members.len() == count,
        "native group changed while stopped image was captured"
    );
    members.sort_unstable_by_key(|member| member.name);
    ensure!(
        members.windows(2).all(|pair| pair[0].name != pair[1].name),
        "duplicate native group member"
    );
    ensure!(
        identity(&open_directory(path)?)? == directory_identity,
        "native group directory changed during capture"
    );
    Ok(FixtureNativeGroupImage {
        members,
        _charge: charge,
        directory_identity,
        root_identity: root_identity.context("native group root is missing")?,
    })
}

fn copy_members(
    source: &File,
    destination: &File,
    image: &FixtureNativeGroupImage,
    existing: Option<&FixtureNativeGroupImage>,
) -> Result<()> {
    let mut buffer = [0; 64 << 10];
    for member in &image.members {
        let mut input = open_member(source, &member.name, libc::O_RDONLY)?;
        let present = existing.is_some_and(|image| {
            image
                .members
                .binary_search_by_key(&member.name, |entry| entry.name)
                .is_ok()
        });
        let mut output = open_member(
            destination,
            &member.name,
            if present {
                libc::O_WRONLY
            } else {
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
            },
        )?;
        output.set_len(0)?;
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
        }
        output.sync_all()?;
    }
    destination.sync_all()?;
    Ok(())
}

/// Save a stopped native directory to a fresh private fixture directory.
pub fn copy_closed_native_group(
    source: &Path,
    destination: &Path,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<()> {
    let image = capture_native_group_image(source, memory.clone())?;
    std::fs::DirBuilder::new().mode(0o700).create(destination)?;
    copy_members(
        &open_directory(source)?,
        &open_directory(destination)?,
        &image,
        None,
    )?;
    ensure!(
        capture_native_group_image(source, memory.clone())? == image,
        "closed source group changed during copy"
    );
    ensure!(
        capture_native_group_image(destination, memory)? == image,
        "copied native group differs from complete source image"
    );
    Ok(())
}

/// Restore a stopped complete generation in place. The installed directory and
/// root inode survive; obsolete native members are removed and absent members
/// are created exclusively. Unexpected entries and symlinks refuse the restore.
pub fn restore_closed_native_group(
    source: &Path,
    destination: &Path,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<()> {
    let image = capture_native_group_image(source, memory.clone())?;
    let previous = capture_native_group_image(destination, memory.clone())?;
    ensure!(
        image.directory_identity != previous.directory_identity,
        "cannot restore a native group onto itself"
    );
    let source_directory = open_directory(source)?;
    let destination_directory = open_directory(destination)?;
    ensure!(
        identity(&destination_directory)? == previous.directory_identity,
        "restore destination directory changed"
    );
    copy_members(
        &source_directory,
        &destination_directory,
        &image,
        Some(&previous),
    )?;
    for member in &previous.members {
        if image
            .members
            .binary_search_by_key(&member.name, |entry| entry.name)
            .is_err()
        {
            let result = unsafe {
                libc::unlinkat(
                    destination_directory.as_raw_fd(),
                    member.name.as_ptr().cast(),
                    0,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    destination_directory.sync_all()?;
    ensure!(
        capture_native_group_image(source, memory.clone())? == image,
        "closed source group changed during restore"
    );
    let restored = capture_native_group_image(destination, memory)?;
    ensure!(
        restored == image,
        "restored native group differs from complete source image"
    );
    ensure!(
        restored.directory_identity == previous.directory_identity
            && restored.root_identity == previous.root_identity,
        "restore replaced installed native directory or root identity"
    );
    Ok(())
}

#[cfg(test)]
#[path = "test_utils_native_group_tests.rs"]
mod tests;
