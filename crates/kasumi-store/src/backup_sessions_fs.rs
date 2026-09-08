//! Descriptor-relative session publication and reclamation. No cleanup operation
//! resolves a caller path or follows a symlink out of the captured destination.
use super::*;
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

pub(crate) struct Directory(File);
impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(Self(file))
    }
    fn child(&self, name: &str, create: bool) -> Result<Option<Self>> {
        use std::os::unix::fs::MetadataExt;
        let name = CString::new(name)?;
        if create && unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            let error = std::io::Error::last_os_error();
            if !create && error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error.into());
        }
        let directory = Self(unsafe { File::from_raw_fd(fd) });
        let metadata = directory.0.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "backup session directory must be owner-only"
        );
        if create {
            directory.0.sync_all()?;
            self.0.sync_all()?;
        }
        Ok(Some(directory))
    }
    fn session(&self, id: Uuid, create: bool) -> Result<Option<Self>> {
        ensure!(!id.is_nil(), "nil backup session");
        let Some(sessions) = self.child("sessions", create)? else {
            return Ok(None);
        };
        sessions.child(&id.to_string(), create)
    }
    fn read(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        let name = CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error.into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= limit as u64,
            "invalid or oversized backup session object"
        );
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= limit, "backup session object exceeds limit");
        Ok(Some(bytes))
    }
    fn unlink(&self, name: &str) -> Result<()> {
        let name = CString::new(name)?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
        Ok(())
    }
    pub fn put(&self, session: Uuid, slot: BackupSessionSlot, bytes: &[u8]) -> Result<()> {
        slot.relative(session)?;
        let session = self
            .session(session, true)?
            .context("backup session absent")?;
        let objects = session
            .child("objects", true)?
            .context("backup object directory absent")?;
        // Every interrupted temporary upload is itself a UUID object inside the
        // deletable namespace. Control records are atomically linked outside it.
        let temporary = format!("{}.kasumi", Uuid::new_v4());
        let temporary_c = CString::new(temporary.as_str())?;
        let fd = unsafe {
            libc::openat(
                objects.0.as_raw_fd(),
                temporary_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(
            fd != -1,
            "creating backup upload: {}",
            std::io::Error::last_os_error()
        );
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            let (destination, name) = match slot {
                BackupSessionSlot::Intent => (&session, "intent.kasumi".to_owned()),
                BackupSessionSlot::Outcome => (&session, "outcome.kasumi".to_owned()),
                BackupSessionSlot::Object(id) => (&objects, format!("{id}.kasumi")),
            };
            let name = CString::new(name)?;
            ensure!(
                unsafe {
                    libc::linkat(
                        objects.0.as_raw_fd(),
                        temporary_c.as_ptr(),
                        destination.0.as_raw_fd(),
                        name.as_ptr(),
                        0,
                    )
                } == 0,
                "publishing create-only backup session object: {}",
                std::io::Error::last_os_error()
            );
            destination.0.sync_all()?;
            Ok(())
        })();
        let cleanup = objects
            .unlink(&temporary)
            .and_then(|()| Ok(objects.0.sync_all()?));
        result.and(cleanup)
    }
    pub fn get(
        &self,
        session: Uuid,
        slot: BackupSessionSlot,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        slot.relative(session)?;
        let Some(session) = self.session(session, false)? else {
            return Ok(None);
        };
        match slot {
            BackupSessionSlot::Intent => session.read("intent.kasumi", limit),
            BackupSessionSlot::Outcome => session.read("outcome.kasumi", limit),
            BackupSessionSlot::Object(id) => match session.child("objects", false)? {
                Some(objects) => objects.read(&format!("{id}.kasumi"), limit),
                None => Ok(None),
            },
        }
    }
    fn aborted_objects(&self, proof: &VerifiedBackupAbort) -> Result<Option<Self>> {
        let session = self
            .session(proof.session_id(), false)?
            .context("aborted backup session disappeared")?;
        proof.matches_outcome(
            &session
                .read(
                    "outcome.kasumi",
                    MAX_SESSION_RECORD_BYTES + crate::backup::HEADER_LIMIT + 84,
                )?
                .context("abort outcome disappeared")?,
        )?;
        session.child("objects", false)
    }
    pub fn list(
        &self,
        proof: &VerifiedBackupAbort,
        limit: usize,
    ) -> Result<BackupSessionObjectPage> {
        ensure!(
            (1..=MAX_SESSION_GC_OBJECTS).contains(&limit),
            "invalid backup cleanup page limit"
        );
        let Some(objects) = self.aborted_objects(proof)? else {
            return Ok(BackupSessionObjectPage {
                objects: Vec::new(),
                more: false,
            });
        };
        // openat(".") creates an independent directory cursor; dup would share it.
        let fd = unsafe {
            libc::openat(
                objects.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        ensure!(
            fd != -1,
            "opening backup enumeration: {}",
            std::io::Error::last_os_error()
        );
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            unsafe {
                libc::close(fd);
            }
            anyhow::bail!(
                "opening backup enumeration: {}",
                std::io::Error::last_os_error()
            );
        }
        struct Entries(*mut libc::DIR);
        impl Drop for Entries {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let entries = Entries(pointer);
        let mut found = BTreeSet::new();
        loop {
            proof.check()?;
            // readdir can return null on either EOF or failure.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(entries.0) };
            if entry.is_null() {
                ensure!(
                    std::io::Error::last_os_error().raw_os_error() == Some(0),
                    "reading backup enumeration failed"
                );
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_string_lossy();
            if name == "." || name == ".." {
                continue;
            }
            let value = name
                .strip_suffix(".kasumi")
                .and_then(|s| Uuid::parse_str(s).ok())
                .context("unexpected file in aborted object namespace")?;
            ensure!(
                name == format!("{value}.kasumi") && !value.is_nil(),
                "noncanonical file in aborted object namespace"
            );
            found.insert(value);
            if found.len() > limit {
                break;
            }
        }
        let more = found.len() > limit;
        if more {
            found.pop_last();
        }
        Ok(BackupSessionObjectPage {
            objects: found.into_iter().collect(),
            more,
        })
    }
    pub fn delete(&self, proof: &VerifiedBackupAbort, ids: &[Uuid]) -> Result<()> {
        ensure!(
            ids.len() <= MAX_SESSION_GC_OBJECTS,
            "backup cleanup deletion exceeds page limit"
        );
        let Some(objects) = self.aborted_objects(proof)? else {
            return Ok(());
        };
        for id in ids {
            proof.check()?;
            ensure!(!id.is_nil(), "nil cleanup object");
            objects.unlink(&format!("{id}.kasumi"))?;
        }
        objects.0.sync_all()?;
        Ok(())
    }
}
