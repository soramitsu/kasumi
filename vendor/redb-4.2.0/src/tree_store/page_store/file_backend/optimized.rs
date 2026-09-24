use crate::{BackendCloseOutcome, DatabaseError, Result, StorageBackend};
use std::fs::{File, TryLockError};
use std::io;
use std::sync::RwLock;

#[cfg(any(unix, target_os = "wasi"))]
use std::os::fd::IntoRawFd;

#[cfg(windows)]
use std::os::windows::io::IntoRawHandle;

#[cfg(feature = "logging")]
use log::warn;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

/// Stores a database as a file on-disk.
#[derive(Debug)]
pub struct FileBackend {
    file: RwLock<CloseState>,
}

#[derive(Debug)]
enum CloseState {
    Open(File),
    // This phase is conservative if a close callback unwinds.
    Attempting,
    Drained,
    // The raw handle is diagnostic only. It must never be retried after an
    // uncertain native close result, even when its integer is later reused.
    Unknown { native_handle: usize },
}

#[cfg(any(unix, target_os = "wasi"))]
type NativeHandle = i32;

#[cfg(windows)]
type NativeHandle = *mut std::ffi::c_void;

#[cfg(any(unix, target_os = "wasi"))]
unsafe extern "C" {
    #[link_name = "close"]
    fn raw_close(fd: i32) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "CloseHandle"]
    fn raw_close(handle: NativeHandle) -> i32;
}

fn into_native_handle(file: File) -> NativeHandle {
    #[cfg(any(unix, target_os = "wasi"))]
    {
        file.into_raw_fd()
    }
    #[cfg(windows)]
    {
        file.into_raw_handle()
    }
}

#[cfg(any(unix, target_os = "wasi"))]
fn native_handle_number(handle: NativeHandle) -> usize {
    // A File's raw descriptor is nonnegative. Keep an impossible negative
    // value diagnostic without panicking across the native-close boundary.
    usize::try_from(handle).unwrap_or(usize::MAX)
}

#[cfg(windows)]
fn native_handle_number(handle: NativeHandle) -> usize {
    handle.addr()
}

fn close_native_handle(handle: NativeHandle) -> io::Result<()> {
    // File has relinquished ownership through into_raw_fd/into_raw_handle.
    // A failed close is uncertain: this call is never retried or replaced by
    // File's infallible destructor.
    #[cfg(any(unix, target_os = "wasi"))]
    let closed = unsafe { raw_close(handle) } == 0;
    #[cfg(windows)]
    let closed = unsafe { raw_close(handle) } != 0;
    if closed {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl FileBackend {
    /// Creates a new backend which stores data to the given file.
    pub fn new(file: File) -> Result<Self, DatabaseError> {
        Self::new_internal(file, false)
    }

    pub(crate) fn new_internal(file: File, read_only: bool) -> Result<Self, DatabaseError> {
        let result = if read_only {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };

        match result {
            Ok(()) => Ok(Self {
                file: RwLock::new(CloseState::Open(file)),
            }),
            Err(TryLockError::WouldBlock) => Err(DatabaseError::DatabaseAlreadyOpen),
            Err(TryLockError::Error(err)) if err.kind() == io::ErrorKind::Unsupported => {
                #[cfg(feature = "logging")]
                warn!(
                    "File locks not supported on this platform. You must ensure that only a single process opens the database file, at a time"
                );

                Ok(Self {
                    file: RwLock::new(CloseState::Open(file)),
                })
            }
            Err(TryLockError::Error(err)) => Err(err.into()),
        }
    }

    fn with_open<T>(&self, operation: impl FnOnce(&File) -> io::Result<T>) -> io::Result<T> {
        let state = self
            .file
            .read()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
        match &*state {
            CloseState::Open(file) => operation(file),
            CloseState::Attempting | CloseState::Drained | CloseState::Unknown { .. } => {
                Err(io::Error::from(io::ErrorKind::NotConnected))
            }
        }
    }

    /// The handle number retained after an uncertain native close. It is only
    /// diagnostic; calling close on this integer again would be unsafe.
    pub fn unknown_close_handle(&self) -> Option<usize> {
        let state = match self.file.read() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        match &*state {
            CloseState::Unknown { native_handle } => Some(*native_handle),
            _ => None,
        }
    }

    fn close_with(
        &self,
        closer: impl FnOnce(NativeHandle) -> io::Result<()>,
    ) -> BackendCloseOutcome {
        let Ok(mut state) = self.file.write() else {
            return BackendCloseOutcome::retained(io::ErrorKind::Other.into());
        };
        match std::mem::replace(&mut *state, CloseState::Attempting) {
            CloseState::Open(file) => {
                let handle = into_native_handle(file);
                *state = CloseState::Unknown {
                    native_handle: native_handle_number(handle),
                };
                match closer(handle) {
                    Ok(()) => {
                        *state = CloseState::Drained;
                        BackendCloseOutcome::drained(Ok(()))
                    }
                    Err(error) => BackendCloseOutcome::retained(error),
                }
            }
            CloseState::Drained => {
                *state = CloseState::Drained;
                BackendCloseOutcome::drained(Err(io::ErrorKind::AlreadyExists.into()))
            }
            CloseState::Unknown { native_handle } => {
                *state = CloseState::Unknown { native_handle };
                BackendCloseOutcome::retained(io::ErrorKind::AlreadyExists.into())
            }
            CloseState::Attempting => BackendCloseOutcome::retained(io::ErrorKind::Other.into()),
        }
    }
}

impl StorageBackend for FileBackend {
    fn len(&self) -> Result<u64, io::Error> {
        self.with_open(|file| Ok(file.metadata()?.len()))
    }

    #[cfg(unix)]
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        self.with_open(|file| file.read_exact_at(out, offset))
    }

    #[cfg(target_os = "wasi")]
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        self.with_open(|file| read_exact_at(file, out, offset))
    }

    #[cfg(windows)]
    fn read(&self, mut offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        self.with_open(|file| {
            let mut data_offset = 0;
            while data_offset < out.len() {
                let read = file.seek_read(&mut out[data_offset..], offset)?;
                // seek_read returns Ok(0) at EOF; treat a short read as an error so that reading
                // past the end of the file fails instead of looping forever.
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ));
                }
                offset += read as u64;
                data_offset += read;
            }
            Ok(())
        })
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        self.with_open(|file| file.set_len(len))
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.with_open(File::sync_data)
    }

    #[cfg(unix)]
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        self.with_open(|file| file.write_all_at(data, offset))
    }

    #[cfg(target_os = "wasi")]
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        self.with_open(|file| write_all_at(file, data, offset))
    }

    #[cfg(windows)]
    fn write(&self, mut offset: u64, data: &[u8]) -> Result<(), io::Error> {
        self.with_open(|file| {
            let mut data_offset = 0;
            while data_offset < data.len() {
                let written = file.seek_write(&data[data_offset..], offset)?;
                offset += written as u64;
                data_offset += written;
            }
            Ok(())
        })
    }

    fn close(&self) -> BackendCloseOutcome {
        self.close_with(close_native_handle)
    }
}

// TODO: replace these with wasi::FileExt when https://github.com/rust-lang/rust/issues/71213
// is stable
#[cfg(target_os = "wasi")]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    while !buf.is_empty() {
        let nbytes = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buf.as_mut_ptr() as _,
                core::cmp::min(buf.len(), libc::ssize_t::MAX as _),
                offset as _,
            )
        };
        match nbytes {
            0 => break,
            -1 => match io::Error::last_os_error() {
                err if err.kind() == io::ErrorKind::Interrupted => {}
                err => return Err(err),
            },
            n => {
                let tmp = buf;
                buf = &mut tmp[n as usize..];
                offset += n as u64;
            }
        }
    }
    if !buf.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "wasi")]
fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    while !buf.is_empty() {
        let nbytes = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                buf.as_ptr() as _,
                core::cmp::min(buf.len(), libc::ssize_t::MAX as _),
                offset as _,
            )
        };
        match nbytes {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            -1 => match io::Error::last_os_error() {
                err if err.kind() == io::ErrorKind::Interrupted => {}
                err => return Err(err),
            },
            n => {
                buf = &buf[n as usize..];
                offset += n as u64
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackendNativeDisposition;

    #[test]
    fn explicit_close_drains_the_native_file_once_and_fences_io() {
        let backend = FileBackend::new(tempfile::tempfile().unwrap()).unwrap();
        assert_eq!(backend.len().unwrap(), 0);

        let (result, native) = backend.close().into_parts();
        result.unwrap();
        assert!(matches!(native, BackendNativeDisposition::Drained));
        assert!(backend.len().is_err());
        assert!(backend.unknown_close_handle().is_none());

        let (duplicate, native) = backend.close().into_parts();
        assert!(duplicate.is_err());
        assert!(matches!(native, BackendNativeDisposition::Drained));
    }

    #[test]
    fn uncertain_native_close_retains_its_number_without_retry() {
        let backend = FileBackend::new(tempfile::tempfile().unwrap()).unwrap();
        let mut attempts = 0;
        let mut original_handle = None;
        let (result, native) = backend
            .close_with(|handle| {
                attempts += 1;
                original_handle = Some(native_handle_number(handle));
                // Model an interrupted close whose descriptor really was closed.
                // A retry could now close a reused descriptor in production.
                close_native_handle(handle).unwrap();
                Err(io::ErrorKind::Interrupted.into())
            })
            .into_parts();
        assert_eq!(attempts, 1);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(matches!(native, BackendNativeDisposition::Retained));
        assert_eq!(backend.unknown_close_handle(), original_handle);
        assert!(backend.len().is_err());

        let (duplicate, native) = backend
            .close_with(|_| {
                attempts += 1;
                panic!("an uncertain native handle must never be retried")
            })
            .into_parts();
        assert_eq!(attempts, 1);
        assert!(duplicate.is_err());
        assert!(matches!(native, BackendNativeDisposition::Retained));
        assert_eq!(backend.unknown_close_handle(), original_handle);
    }
}
