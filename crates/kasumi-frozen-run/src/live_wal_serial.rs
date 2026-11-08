//! Full file-integrity completion for a single WAL frame. A prior frame or
//! header has already finished its own barrier. Grouped appends synchronize
//! the whole WAL separately because their earlier writes may still be dirty.
//! See Linux [pwritev2(2)](https://man7.org/linux/man-pages/man2/pwritev2.2.html)
//! for the synchronized range, partial returns, and current-offset convention.
use super::sync_durable;
use std::{
    fs::File,
    io::{self, Write},
};

#[derive(Default)]
pub(super) struct SerialWriter {
    #[cfg(any(target_os = "linux", test))]
    unsupported: bool,
}

impl SerialWriter {
    /// Return the number of successful durability operations. Linux provides
    /// per-write O_SYNC with RWF_SYNC. Offset -1 advances the descriptor so a
    /// following grouped append can continue at the same append position.
    pub(super) fn write(&mut self, file: &mut File, offset: u64, bytes: &[u8]) -> io::Result<u64> {
        #[cfg(target_os = "linux")]
        {
            use rustix::io::{ReadWriteFlags, pwritev2};
            self.write_with(
                file,
                offset,
                bytes,
                |file, bytes| {
                    pwritev2(
                        file,
                        &[io::IoSlice::new(bytes)],
                        u64::MAX,
                        ReadWriteFlags::SYNC,
                    )
                    .map_err(Into::into)
                },
                sync_durable,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = offset;
            file.write_all(bytes)?;
            sync_durable(file)?;
            Ok(1)
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn write_with(
        &mut self,
        file: &mut File,
        offset: u64,
        bytes: &[u8],
        mut synchronized_write: impl FnMut(&mut File, &[u8]) -> io::Result<usize>,
        synchronize: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<u64> {
        use std::io::{ErrorKind, Seek, SeekFrom};
        let mut completed = 0;
        if !self.unsupported {
            loop {
                match synchronized_write(file, bytes) {
                    Ok(n) if n == bytes.len() => return Ok(1),
                    Ok(0) => return Err(ErrorKind::WriteZero.into()),
                    Ok(n) if n < bytes.len() => {
                        completed = n;
                        break;
                    }
                    Ok(_) => return Err(io::Error::other("invalid synchronized write count")),
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL)
                        ) =>
                    {
                        // The call used one valid span and the only flag is SYNC.
                        // Anchor the retry at the known WAL position even if
                        // the filesystem touched a prefix before rejecting it.
                        self.unsupported = true;
                        file.seek(SeekFrom::Start(offset))?;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        file.write_all(&bytes[completed..])?;
        synchronize(file)?;
        Ok(1 + u64::from(completed != 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Seek, SeekFrom};

    #[test]
    fn interrupted_then_successful_synchronized_write_needs_one_barrier() {
        let mut writer = SerialWriter::default();
        let mut file = tempfile::tempfile().unwrap();
        let mut calls = 0;
        let count = writer
            .write_with(
                &mut file,
                0,
                b"frame",
                |file, bytes| {
                    calls += 1;
                    if calls == 1 {
                        return Err(ErrorKind::Interrupted.into());
                    }
                    file.write_all(bytes)?;
                    Ok(bytes.len())
                },
                |_| panic!("unexpected extra barrier"),
            )
            .unwrap();
        assert_eq!((calls, count, file.stream_position().unwrap()), (2, 1, 5));
        assert!(!writer.unsupported);
    }

    #[test]
    fn unsupported_partial_and_failed_writes_preserve_recovery_offsets() {
        for code in [libc::ENOSYS, libc::EOPNOTSUPP, libc::EINVAL] {
            let mut writer = SerialWriter::default();
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(b"prior").unwrap();
            let mut syncs = 0;
            let count = writer
                .write_with(
                    file.as_file_mut(),
                    5,
                    b"frame",
                    |file, _| {
                        // Even a backend that moved the offset before rejecting the
                        // capability must not cause the whole frame to be appended twice.
                        file.write_all(b"fr")?;
                        Err(io::Error::from_raw_os_error(code))
                    },
                    |_| {
                        syncs += 1;
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(count, 1);
            assert!(writer.unsupported);
            writer
                .write_with(
                    file.as_file_mut(),
                    10,
                    b"next",
                    |_, _| panic!("unsupported retry"),
                    |_| {
                        syncs += 1;
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(syncs, 2);
            assert_eq!(std::fs::read(file.path()).unwrap(), b"priorframenext");
        }
        let mut writer = SerialWriter::default();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let count = writer
            .write_with(
                file.as_file_mut(),
                0,
                b"frame",
                |file, bytes| file.write(&bytes[..2]),
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(std::fs::read(file.path()).unwrap(), b"frame");
        assert!(!writer.unsupported);
        for code in [libc::EIO, libc::ENOSPC, libc::EROFS] {
            let err = writer
                .write_with(
                    file.as_file_mut(),
                    5,
                    b"new",
                    |_, _| Err(io::Error::from_raw_os_error(code)),
                    |_| panic!("uncertain write must fence"),
                )
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(code));
            assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 5);
        }
        let error = writer
            .write_with(
                file.as_file_mut(),
                5,
                b"new",
                |_, _| Ok(0),
                |_| panic!("unexpected barrier"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WriteZero);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_serial_and_buffered_group_writes_share_the_current_offset() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = SerialWriter::default();
        writer.write(file.as_file_mut(), 0, b"one").unwrap();
        file.write_all(b"two").unwrap();
        sync_durable(file.as_file()).unwrap();
        writer.write(file.as_file_mut(), 6, b"three").unwrap();
        assert_eq!(file.stream_position().unwrap(), 11);
        assert_eq!(std::fs::read(file.path()).unwrap(), b"onetwothree");
        eprintln!(
            "Linux serial WAL used {}",
            if writer.unsupported {
                "write + fsync"
            } else {
                "pwritev2(RWF_SYNC)"
            }
        );
    }
}
