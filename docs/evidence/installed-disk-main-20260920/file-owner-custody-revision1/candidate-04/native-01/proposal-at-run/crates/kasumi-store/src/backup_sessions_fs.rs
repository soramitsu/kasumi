//! Descriptor-relative session publication and reclamation. No cleanup operation
//! resolves a caller path or follows a symlink out of the captured destination.
use super::*;
use std::{
    collections::BTreeSet,
    ffi::CString,
    path::{Path, PathBuf},
};

#[path = "backup_session_terminal.rs"]
mod terminal;
use crate::node_disk::{NamespaceAdmission, NamespacePart, NamespacePartKind};
use terminal::Terminal;
pub(crate) const TERMINAL_IO_BUFFER_BYTES: usize =
    terminal::IO_CHUNK_BYTES + 2 * terminal::HEADER_BYTES;

pub(crate) struct Directory(crate::NodeDiskDirectory, Arc<crate::NodeDisk>, PathBuf);
impl Directory {
    pub fn open(path: &Path, disk: Arc<crate::NodeDisk>) -> Result<Self> {
        let anchor = path.join("session-accounting-anchor");
        let (root, relative) = disk.binding(&anchor)?;
        let directory =
            disk.open_directory(root, relative.parent().context("directory binding")?)?;
        Ok(Self(directory, disk, path.to_owned()))
    }
    pub(crate) fn open_or_create(path: &Path, disk: Arc<crate::NodeDisk>) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let anchor = path.join("directory-accounting-anchor");
        let (root, relative) = disk.binding(&anchor)?;
        let relative = relative.parent().context("directory binding")?;
        if relative.as_os_str().is_empty() {
            return Self::open(path, disk);
        }
        let parent_relative = relative.parent().context("directory parent")?;
        let parent = disk.open_directory(root, parent_relative)?;
        let name = CString::new(relative.file_name().context("directory name")?.as_bytes())?;
        let directory = match parent.open_child(&name) {
            Ok(directory) => directory,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && disk.snapshot().phase == crate::NodeDiskPhase::Open =>
            {
                let mut admission = disk.admit_namespace(
                    &[NamespacePart {
                        root,
                        relative,
                        kind: NamespacePartKind::Directory,
                    }],
                    crate::DiskWork::Foreground,
                )?;
                let directory = parent.create_admitted_child(&name, &mut admission)?;
                admission.finish()?;
                directory
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self(directory, disk, path.to_owned()))
    }
    pub(crate) fn sync_all(&self) -> Result<()> {
        self.0.sync_all().map_err(Into::into)
    }
    fn check(&self) -> Result<()> {
        self.0.sync_all().map_err(Into::into)
    }
    fn child(&self, name: &str) -> Result<Option<Self>> {
        let name = CString::new(name)?;
        match self.0.open_child(&name) {
            Ok(directory) => Ok(Some(Self(
                directory,
                self.1.clone(),
                self.2.join(name.to_str()?),
            ))),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && self.1.snapshot().phase == crate::NodeDiskPhase::Open =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn create_child(&self, name: &str, admission: &mut NamespaceAdmission) -> Result<Self> {
        let name = CString::new(name)?;
        let directory = self.0.create_admitted_child(&name, admission)?;
        Ok(Self(directory, self.1.clone(), self.2.join(name.to_str()?)))
    }
    fn session(&self, id: Uuid) -> Result<Option<Self>> {
        ensure!(!id.is_nil(), "nil backup session");
        let Some(sessions) = self.child("sessions")? else {
            return Ok(None);
        };
        sessions.child(&id.to_string())
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
    fn read_terminal(
        &self,
        session: Uuid,
        slot: Terminal,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.open_leaf(slot.published())? else {
            return Ok(None);
        };
        let bytes = terminal::read(&file, session, slot, limit)?;
        #[cfg(test)]
        test_sync::check(self, slot.published(), test_sync::Point::ReadFile)?;
        file.sync_all()?;
        #[cfg(test)]
        test_sync::check(self, slot.published(), test_sync::Point::ReadDirectory)?;
        file.sync_all_and_parent()?;
        self.check()?;
        Ok(Some(bytes))
    }
    // A published terminal is canonical; a reserve must be the exact admitted
    // fixed length. Neither arbitrary names nor short reserve files are adopted.
    fn terminal_state(&self, session: Uuid, slot: Terminal) -> Result<(bool, bool)> {
        let published = match self.open_leaf(slot.published())? {
            Some(file) => {
                terminal::validate(&file, session, slot)?;
                file.sync_all_and_parent()?;
                true
            }
            None => false,
        };
        #[cfg(test)]
        test_sync::check(self, slot.published(), test_sync::Point::TerminalClassified)?;
        let reserve = self.open_leaf(slot.reserve())?;
        if let Some(file) = &reserve {
            if published || file.observed_len()? != terminal::FILE_BYTES as u64 {
                self.1.fail();
                anyhow::bail!("invalid backup terminal reservation");
            }
            file.sync_all_and_parent()?;
        }
        Ok((published, reserve.is_some()))
    }
    // The accepted claim is the first owned operation resource. UUID formatting
    // and both path components live on the stack while State is acquired.
    fn claim_session_namespace(
        &self,
        session: Uuid,
        slot: BackupSessionSlot,
    ) -> std::io::Result<crate::node_disk::NamespaceClaim> {
        if session.is_nil() || matches!(slot, BackupSessionSlot::Object(id) if id.is_nil()) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let mut name = [0_u8; 37];
        session.hyphenated().encode_lower(&mut name[..36]);
        let name = std::ffi::CStr::from_bytes_with_nul(&name)
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        self.0.claim_descendants(&[c"sessions", name])
    }
    pub fn put(&self, session_id: Uuid, slot: BackupSessionSlot, bytes: &[u8]) -> Result<()> {
        // Hold the physical claim across both terminal classification reads and
        // final publication. All owned paths below retire before this witness.
        let claim = self.claim_session_namespace(session_id, slot)?;
        let terminal_slot = match slot {
            BackupSessionSlot::Intent => Some(Terminal::Intent),
            BackupSessionSlot::Outcome => Some(Terminal::Outcome),
            BackupSessionSlot::Object(_) => None,
        };
        if let Some(terminal) = terminal_slot {
            terminal::header(session_id, terminal, bytes)?;
        }
        let sessions = self.child("sessions")?;
        let session = match &sessions {
            Some(dir) => dir.child(&session_id.to_string())?,
            None => None,
        };
        let objects = match &session {
            Some(dir) => dir.child("objects")?,
            None => None,
        };
        let mut terminals = [(false, false); 2];
        if let Some(session) = &session {
            for (index, terminal) in [Terminal::Intent, Terminal::Outcome]
                .into_iter()
                .enumerate()
            {
                terminals[index] = session.terminal_state(session_id, terminal)?;
            }
            if terminals.iter().any(|(published, _)| *published)
                && terminals
                    .iter()
                    .any(|(published, reserve)| !published && !reserve)
            {
                self.1.fail();
                anyhow::bail!("published backup session lost terminal capacity");
            }
        }
        if let Some(terminal) = terminal_slot {
            let index = usize::from(terminal == Terminal::Outcome);
            if terminals[index].0 {
                return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
            }
        }
        let sessions_path = self.2.join("sessions");
        let session_path = sessions_path.join(session_id.to_string());
        let objects_path = session_path.join("objects");
        let temporary = format!("{}.kasumi", Uuid::new_v4());
        let temporary_path = objects_path.join(&temporary);
        let mut missing = Vec::with_capacity(crate::node_disk::MAX_NAMESPACE_PARTS);
        if sessions.is_none() {
            missing.push((sessions_path, NamespacePartKind::Directory));
        }
        if session.is_none() {
            missing.push((session_path.clone(), NamespacePartKind::Directory));
        }
        if objects.is_none() {
            missing.push((objects_path, NamespacePartKind::Directory));
        }
        for (index, terminal) in [Terminal::Intent, Terminal::Outcome]
            .into_iter()
            .enumerate()
        {
            if terminals[index] == (false, false) {
                missing.push((
                    session_path.join(terminal.reserve()),
                    NamespacePartKind::File {
                        length: terminal::FILE_BYTES as u64,
                    },
                ));
            }
        }
        if terminal_slot.is_none() {
            missing.push((
                temporary_path.clone(),
                NamespacePartKind::File {
                    length: bytes.len() as u64,
                },
            ));
        }
        let mut requests = Vec::with_capacity(missing.len());
        for (path, kind) in &missing {
            let (root, relative) = self.1.binding(path)?;
            requests.push(NamespacePart {
                root,
                relative,
                kind: *kind,
            });
        }
        let mut admission = if requests.is_empty() {
            None
        } else {
            Some(
                self.1
                    .admit_claimed_namespace(&claim, &requests, crate::DiskWork::Foreground)?,
            )
        };
        let sessions = match sessions {
            Some(dir) => dir,
            None => self.create_child(
                "sessions",
                admission.as_mut().expect("admitted sessions directory"),
            )?,
        };
        let session = match session {
            Some(dir) => dir,
            None => sessions.create_child(
                &session_id.to_string(),
                admission.as_mut().expect("admitted session directory"),
            )?,
        };
        let objects = match objects {
            Some(dir) => dir,
            None => session.create_child(
                "objects",
                admission.as_mut().expect("admitted objects directory"),
            )?,
        };
        // Persist both terminal reservations before any session object/intent/
        // outcome is published. Cold census sees their complete extent and F.
        for (index, terminal) in [Terminal::Intent, Terminal::Outcome]
            .into_iter()
            .enumerate()
        {
            if terminals[index] == (false, false) {
                let path = session.2.join(terminal.reserve());
                let (root, relative) = self.1.binding(&path)?;
                let file = self.1.create_admitted_file(
                    admission.as_mut().expect("admitted terminal"),
                    root,
                    relative,
                )?;
                file.grow_reserved(terminal::FILE_BYTES as u64)?;
                file.sync_all_and_parent()?;
            }
        }
        let object = if terminal_slot.is_none() {
            let (root, relative) = self.1.binding(&temporary_path)?;
            let file = self.1.create_admitted_file(
                admission.as_mut().expect("admitted object"),
                root,
                relative,
            )?;
            file.grow_reserved(bytes.len() as u64)?;
            file.sync_all_and_parent()?;
            Some(file)
        } else {
            None
        };
        if let Some(admission) = admission {
            admission.finish()?;
        }
        let (file, destination, name) = if let Some(terminal) = terminal_slot {
            // open_file is exclusive across every wrapper for this physical
            // NodeDisk, through actual descriptor/registration retirement.
            let file = session
                .open_leaf(terminal.reserve())?
                .context("backup terminal reserve absent")?;
            terminal::write(&file, session_id, terminal, bytes)?;
            (file, &session, terminal.published().to_owned())
        } else {
            let BackupSessionSlot::Object(id) = slot else {
                unreachable!()
            };
            let file = object.expect("admitted object owner");
            file.write_all_at(bytes, 0)?;
            file.sync_all_and_parent()?;
            (file, &objects, format!("{id}.kasumi"))
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
                // Only an object upload temporary is authenticated GC content.
                // A terminal reserve remains permanently charged for resolution.
                if error.kind() == std::io::ErrorKind::AlreadyExists && terminal_slot.is_none() {
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
        let session_id = session;
        let Some(session) = self.session(session)? else {
            return Ok(None);
        };
        match slot {
            BackupSessionSlot::Intent => session.read_terminal(session_id, Terminal::Intent, limit),
            BackupSessionSlot::Outcome => {
                session.read_terminal(session_id, Terminal::Outcome, limit)
            }
            BackupSessionSlot::Object(id) => match session.child("objects")? {
                Some(objects) => objects.read(&format!("{id}.kasumi"), limit),
                None => Ok(None),
            },
        }
    }
    fn aborted_objects(&self, proof: &VerifiedBackupAbort) -> Result<Option<Self>> {
        let session = self
            .session(proof.session_id())?
            .context("aborted backup session disappeared")?;
        proof.matches_outcome(
            &session
                .read_terminal(
                    proof.session_id(),
                    Terminal::Outcome,
                    MAX_SESSION_RECORD_BYTES + crate::backup::HEADER_LIMIT + 84,
                )?
                .context("abort outcome disappeared")?,
        )?;
        session.child("objects")
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
        // Cleanup traverses only the exact enrolled, authenticated objects subtree.
        let anchor = objects.2.join("session-accounting-anchor");
        let (root, relative) = objects.1.binding(&anchor)?;
        let relative = relative
            .parent()
            .context("backup object directory has no parent")?;
        let cancellation = crate::CensusCancellation::default();
        let directory = objects.1.open_directory(root, relative)?;
        let mut entries = directory.cursor(&cancellation)?;
        let mut found = BTreeSet::new();
        let listing = (|| -> Result<()> {
            loop {
                proof.check()?;
                let Some(entry) = entries.next(&cancellation)? else {
                    break;
                };
                ensure!(
                    entry.kind() == crate::NodeDiskEntryKind::File,
                    "unexpected directory in aborted object namespace"
                );
                let name = entry
                    .name()
                    .to_str()
                    .context("backup object name is not UTF-8")?;
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
            Ok(())
        })();
        // Retire even when proof/name/read validation failed. Preserve the
        // original error and any independent native close error together.
        let closed = entries.close();
        drop(entries);
        if let Err(error) = listing {
            return Err(match closed {
                Ok(()) => error,
                Err(close) => error.context(close),
            });
        }
        closed?;
        proof.check()?;
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
        TerminalClassified,
    }
    type Key = (u64, u64, String, Point);
    fn faults() -> &'static Mutex<BTreeSet<Key>> {
        static FAULTS: OnceLock<Mutex<BTreeSet<Key>>> = OnceLock::new();
        FAULTS.get_or_init(Default::default)
    }
    struct Pause {
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    fn pauses() -> &'static Mutex<std::collections::BTreeMap<Key, Pause>> {
        static PAUSES: OnceLock<Mutex<std::collections::BTreeMap<Key, Pause>>> = OnceLock::new();
        PAUSES.get_or_init(Default::default)
    }
    pub(crate) fn pause(
        directory: &Path,
        name: &str,
        point: Point,
    ) -> Result<(
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    )> {
        let metadata = std::fs::metadata(directory)?;
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        assert!(
            pauses()
                .lock()
                .unwrap()
                .insert(
                    (metadata.dev(), metadata.ino(), name.to_owned(), point),
                    Pause {
                        entered: entered_tx,
                        release: release_rx
                    },
                )
                .is_none()
        );
        Ok((entered_rx, release_tx))
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
        directory.check()?;
        let directory = std::fs::metadata(&directory.2)?;
        let key = (directory.dev(), directory.ino(), name.to_owned(), point);
        let pause = pauses().lock().unwrap().remove(&key);
        if let Some(pause) = pause {
            pause.entered.send(())?;
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(10))?;
        }
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
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let disk = crate::test_utils::retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(&path, memory.clone())
        })
        .unwrap();
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
            let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
            let disk = crate::test_utils::retry_disk_registry(|| {
                crate::NodeDisk::fixture_for_path(&path, memory.clone())
            })
            .unwrap();
            let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
            let before = disk.snapshot();
            assert_eq!(before.persistent_files, 1);
            std::fs::remove_file(&path).unwrap();
            let error = if cleanup {
                directory.unlink("object.kasumi").unwrap_err()
            } else {
                directory.read("object.kasumi", 32).unwrap_err()
            };
            // The managed directory may detect the changed parent before the
            // missing leaf is opened; both preserve the first physical failure.
            assert!(error.downcast_ref::<std::io::Error>().is_some());
            assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
            assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
            assert_eq!(disk.snapshot().open_files, 0);
            assert!(directory.read("another-unknown.kasumi", 32).is_err());
            assert!(directory.unlink("another-unknown.kasumi").is_err());
            drop(directory);
            disk.reconcile(&crate::CensusCancellation::default())
                .unwrap();
            assert_eq!(
                disk.snapshot().charged_bytes,
                crate::DirectoryPolicy::fixture().extent_bytes
            );
            assert_eq!(disk.snapshot().persistent_files, 0);
        }
    }
}

#[cfg(test)]
#[path = "backup_session_admission_tests.rs"]
mod session_admission_tests;
