//! A fixed-size, create-only attribute on the target directory inode.
//! It survives removal of every group file and disappears with the directory.
use std::{fs::File, io, os::fd::AsRawFd};
use uuid::Uuid;

const NAME: &std::ffi::CStr = c"user.kasumi.target-creation.v1";

pub(super) fn create(directory: &File, stamp: Uuid) -> io::Result<()> {
    let fd = directory.as_raw_fd();
    let value = stamp.as_bytes();
    // SAFETY: the retained FD, nul-terminated name and 16-byte buffer are live.
    // XATTR_CREATE disallows changing a previous materialization's stamp.
    let result = unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::fsetxattr(
                fd,
                NAME.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                libc::XATTR_CREATE,
            )
        }
        #[cfg(target_os = "macos")]
        {
            libc::fsetxattr(
                fd,
                NAME.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_CREATE,
            )
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn read(directory: &File) -> io::Result<Option<Uuid>> {
    let fd = directory.as_raw_fd();
    let mut value = [0u8; 16];
    // SAFETY: the live retained FD selects the inode and the kernel can write
    // at most the supplied fixed buffer length.
    let count = unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::fgetxattr(fd, NAME.as_ptr(), value.as_mut_ptr().cast(), value.len())
        }
        #[cfg(target_os = "macos")]
        {
            libc::fgetxattr(
                fd,
                NAME.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                0,
            )
        }
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        #[cfg(target_os = "linux")]
        let missing = libc::ENODATA;
        #[cfg(target_os = "macos")]
        let missing = libc::ENOATTR;
        return if error.raw_os_error() == Some(missing) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let stamp = Uuid::from_bytes(value);
    if count as usize != value.len() || stamp.is_nil() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(stamp))
}
