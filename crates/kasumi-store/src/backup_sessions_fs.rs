//! Descriptor-relative session publication and reclamation. No cleanup operation
//! resolves a caller path or follows a symlink out of the captured destination.
use super::*;
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
};

pub(crate) struct Directory(File, Arc<crate::NodeDisk>, PathBuf);
impl Directory {
    pub fn open(path: &Path, disk: Arc<crate::NodeDisk>) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        disk.binding(&path.join("session-accounting-anchor"))?;
        Ok(Self(file, disk, path.to_owned()))
    }
    fn check(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let result = (|| -> Result<()> {
            ensure!(
                self.1.snapshot().phase == crate::NodeDiskPhase::Open,
                "backup physical owner is unavailable"
            );
            let current = std::fs::symlink_metadata(&self.2)?;
            let retained = self.0.metadata()?;
            ensure!(
                current.is_dir()
                    && current.dev() == retained.dev()
                    && current.ino() == retained.ino(),
                "backup directory binding changed"
            );
            crate::private_files::check_directory(&self.2)?;
            Ok(())
        })();
        if result.is_err() {
            self.1.fail();
        }
        result
    }
    fn child(&self, name: &str, create: bool) -> Result<Option<Self>> {
        self.check()?;
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
        let directory = Self(
            unsafe { File::from_raw_fd(fd) },
            self.1.clone(),
            self.2.join(name.to_str()?),
        );
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
    fn open_leaf(&self, name: &str) -> Result<Option<crate::NodeDiskFile>> {
        self.check()?;
        let path = self.2.join(name);
        let (root, relative) = self.1.binding(&path)?;
        match self.1.open_file(root, relative) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Only an unknown leaf is a healthy absence. An enrolled file
                // disappearing fences NodeDisk even when the OS reports ENOENT.
                self.check()
                    .map_err(|failure| anyhow::Error::new(error).context(failure))?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn read(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.open_leaf(name)? else {
            return Ok(None);
        };
        let length = file.observed_len()?;
        ensure!(
            length <= limit as u64,
            "invalid or oversized backup session object"
        );
        let mut bytes = vec![0; usize::try_from(length)?];
        file.read_exact_at(&mut bytes, 0)?;
        #[cfg(test)]
        test_sync::check(self, name, test_sync::Point::ReadFile)?;
        file.sync_all()?;
        #[cfg(test)]
        test_sync::check(self, name, test_sync::Point::ReadDirectory)?;
        file.sync_all_and_parent()?;
        self.check()?;
        Ok(Some(bytes))
    }
    fn unlink(&self, name: &str) -> Result<()> {
        let Some(file) = self.open_leaf(name)? else {
            self.0.sync_all().inspect_err(|_| {
                self.1.fail();
            })?;
            return self.check();
        };
        self.1.delete_file(file)?;
        self.check()
    }
    pub fn put(&self, session: Uuid, slot: BackupSessionSlot, bytes: &[u8]) -> Result<()> {
        slot.relative(session)?;
        let session = self
            .session(session, true)?
            .context("backup session absent")?;
        let objects = session
            .child("objects", true)?
            .context("backup object directory absent")?;
        // Interrupted uploads remain exact UUID objects in the authenticated
        // aborted namespace. Publication moves the original accounted inode;
        // it never creates a transient second hard link.
        let temporary = format!("{}.kasumi", Uuid::new_v4());
        let path = objects.2.join(&temporary);
        let (root, relative) = self.1.binding(&path)?;
        let file = self
            .1
            .create_file(root, relative, crate::DiskWork::Foreground)?;
        file.reserve_growth(0, bytes.len() as u64, crate::DiskWork::Foreground)?;
        file.grow_reserved(bytes.len() as u64)?;
        file.write_all_at(bytes, 0)?;
        file.sync_all_and_parent()?;
        let (destination, name) = match slot {
            BackupSessionSlot::Intent => (&session, "intent.kasumi".to_owned()),
            BackupSessionSlot::Outcome => (&session, "outcome.kasumi".to_owned()),
            BackupSessionSlot::Object(id) => (&objects, format!("{id}.kasumi")),
        };
        destination.check()?;
        let destination_path = destination.2.join(&name);
        let (root, relative) = self.1.binding(&destination_path)?;
        match self.1.publish_file(file, root, relative) {
            Ok(published) => {
                #[cfg(test)]
                test_sync::check(destination, &name, test_sync::Point::PublishDirectory)?;
                published.sync_all_and_parent()?;
                Ok(())
            }
            Err(error) => {
                // A definite create-only conflict did not publish this upload;
                // remove only its exact temporary UUID through the same owner.
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    objects.unlink(&temporary)?;
                }
                Err(error.into())
            }
        }
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
            objects: found
                .into_iter()
                .map(|id| BackupSessionObject::File { id })
                .collect(),
            more,
        })
    }
    pub fn delete(
        &self,
        proof: &VerifiedBackupAbort,
        entries: &[BackupSessionObject],
    ) -> Result<()> {
        ensure!(
            entries.len() <= MAX_SESSION_GC_OBJECTS,
            "backup cleanup deletion exceeds page limit"
        );
        // Reject the entire page before any deletion, including mixed backends.
        let mut ids = BTreeSet::new();
        for entry in entries {
            let BackupSessionObject::File { id } = entry else {
                anyhow::bail!("filesystem cleanup requires file selectors");
            };
            ensure!(
                !id.is_nil() && ids.insert(*id),
                "invalid or duplicate cleanup object"
            );
        }
        let Some(objects) = self.aborted_objects(proof)? else {
            return Ok(());
        };
        for id in ids {
            proof.check()?;
            objects.unlink(&format!("{id}.kasumi"))?;
        }
        objects.0.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_sync {
    use super::*;
    use std::{
        os::unix::fs::MetadataExt,
        sync::{Mutex, OnceLock},
    };

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) enum Point {
        PublishDirectory,
        ReadFile,
        ReadDirectory,
    }
    type Key = (u64, u64, String, Point);
    fn faults() -> &'static Mutex<BTreeSet<Key>> {
        static FAULTS: OnceLock<Mutex<BTreeSet<Key>>> = OnceLock::new();
        FAULTS.get_or_init(Default::default)
    }
    pub(crate) struct Guard(Vec<Key>);
    impl Drop for Guard {
        fn drop(&mut self) {
            let mut faults = faults().lock().unwrap();
            for key in &self.0 {
                faults.remove(key);
            }
        }
    }
    pub(crate) fn fail(directory: &Path, name: &str, points: &[Point]) -> Result<Guard> {
        let directory = std::fs::metadata(directory)?;
        let keys = points
            .iter()
            .map(|point| (directory.dev(), directory.ino(), name.to_owned(), *point))
            .collect::<Vec<_>>();
        let mut faults = faults().lock().unwrap();
        for key in &keys {
            assert!(faults.insert(key.clone()), "duplicate session sync fault");
        }
        Ok(Guard(keys))
    }
    pub(super) fn check(directory: &Directory, name: &str, point: Point) -> Result<()> {
        let directory = directory.0.metadata()?;
        ensure!(
            !faults().lock().unwrap().contains(&(
                directory.dev(),
                directory.ino(),
                name.to_owned(),
                point,
            )),
            "injected backup session synchronization failure"
        );
        Ok(())
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn missing_unknown_or_admitted_deleted_leaf_is_repeatably_absent() {
        let temporary = crate::test_utils::private_tempdir().unwrap();
        let path = temporary.path().join("object.kasumi");
        let disk = crate::NodeDisk::fixture_for_path(&path).unwrap();
        let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
        let before = disk.snapshot();
        for _ in 0..2 {
            assert!(directory.read("object.kasumi", 32).unwrap().is_none());
            directory.unlink("object.kasumi").unwrap();
        }
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
        let (root, relative) = disk.binding(&path).unwrap();
        let file = disk
            .create_file(root, relative, crate::DiskWork::Foreground)
            .unwrap();
        file.reserve_growth(0, 32, crate::DiskWork::Foreground)
            .unwrap();
        file.grow_reserved(32).unwrap();
        file.write_all_at(&[23; 32], 0).unwrap();
        file.sync_all_and_parent().unwrap();
        drop(file);
        assert_eq!(
            directory.read("object.kasumi", 32).unwrap().unwrap(),
            [23; 32]
        );
        directory.unlink("object.kasumi").unwrap();
        for _ in 0..2 {
            directory.unlink("object.kasumi").unwrap();
            assert!(directory.read("object.kasumi", 32).unwrap().is_none());
        }
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
    }

    #[test]
    fn missing_enrolled_leaf_fences_both_read_and_cleanup_without_releasing_credit() {
        for cleanup in [false, true] {
            let temporary = crate::test_utils::private_tempdir().unwrap();
            let path = temporary.path().join("object.kasumi");
            crate::private_files::create(&path, &[31; 32]).unwrap();
            let disk = crate::NodeDisk::fixture_for_path(&path).unwrap();
            let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
            let before = disk.snapshot();
            assert_eq!(before.persistent_files, 1);
            std::fs::remove_file(&path).unwrap();
            let error = if cleanup {
                directory.unlink("object.kasumi").unwrap_err()
            } else {
                directory.read("object.kasumi", 32).unwrap_err()
            };
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound
            );
            assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
            assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
            assert_eq!(disk.snapshot().open_files, 0);
            assert!(directory.read("another-unknown.kasumi", 32).is_err());
            assert!(directory.unlink("another-unknown.kasumi").is_err());
            disk.reconcile(&crate::CensusCancellation::default())
                .unwrap();
            assert_eq!(disk.snapshot().charged_bytes, 0);
            assert_eq!(disk.snapshot().persistent_files, 0);
        }
    }
}
