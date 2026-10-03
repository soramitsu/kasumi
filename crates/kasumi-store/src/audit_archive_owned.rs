use super::*;
use crate::private_files::FileIdentity;

/// Installed recovery ownership, never an authority derived from archive source
/// headers. Implementations durably record every callback before returning.
pub trait AuditArchivePublicationObserver: Send + Sync {
    fn prepare(&self, reference: &AuditArchiveReference) -> Result<()>;
    fn staged(&self, reference: &AuditArchiveReference, identity: &FileIdentity) -> Result<()>;
    fn published(&self, reference: &AuditArchiveReference, identity: &FileIdentity) -> Result<()>;
}

impl FilesystemAuditArchive {
    pub fn with_publication_observer(
        mut self,
        observer: Arc<dyn AuditArchivePublicationObserver>,
    ) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Runs between publication and readback, while the published handle is live.
    #[cfg(test)]
    fn with_publication_hook(mut self, hook: impl Fn(&Path) + Send + Sync + 'static) -> Self {
        self.publication_hook = Some(Arc::new(hook));
        self
    }

    /// The caller holds the publication lock. Every existence and identity
    /// observation comes from a NodeDisk handle; no archive name is opened or
    /// probed outside NodeDisk, and each observed identity is the inode of the
    /// handle that performed the verified readback.
    pub(super) fn publish_owned(
        &self,
        segment: &PreparedAuditSegment,
        observer: Option<&dyn AuditArchivePublicationObserver>,
    ) -> Result<()> {
        if let Some(observer) = observer {
            observer.prepare(&segment.reference)?;
        }
        let name = format!("{}.audit", segment.reference.object.object_id);
        let pending = format!("{name}.pending");
        if let Some(published) = self.open_leaf(&name)? {
            read_object(&published, &segment.reference.object, true)?;
            if let Some(observer) = observer {
                observer.published(&segment.reference, &published.identity()?)?;
            }
            drop(published);
            // The verified final object supersedes any staging inode left for
            // the same object; reclaim it only through exact unlink custody.
            if let Some(stale) = self.open_leaf(&pending)? {
                self.disk.delete_file(stale)?;
                self.directory.sync_all()?;
            }
            return Ok(());
        }
        // The object identity is durable before creation. There are no random
        // temporary names for a crash to leave outside the ownership ledger.
        let staged_path = self.root.join(&pending);
        let final_path = self.root.join(&name);
        let mut file = match self.open_leaf(&pending)? {
            Some(file) => file,
            None => {
                let (root, relative) = self.disk.binding(&staged_path)?;
                self.disk
                    .create_file(root, relative, DiskWork::Maintenance)?
            }
        };
        let staged = file.identity()?;
        if let Some(observer) = observer {
            observer.staged(&segment.reference, &staged)?;
        }
        let old_length = file.observed_len()?;
        let new_length = segment.ciphertext.len() as u64;
        if old_length > new_length {
            file.shrink(new_length)?;
        } else {
            file.reserve_growth(old_length, new_length, DiskWork::Maintenance)?;
            file.grow_reserved(new_length)?;
        }
        file.write_all_at(&segment.ciphertext, 0)?;
        file.sync_all_and_parent()?;
        let (root, relative) = self.disk.binding(&final_path)?;
        let published = self.disk.publish_file(file, root, relative)?;
        #[cfg(test)]
        if let Some(hook) = &self.publication_hook {
            hook(&final_path);
        }
        // Keep the published handle through the observer callback. Its reads
        // and identity verify the final name, so a substituted inode fences.
        read_object(&published, &segment.reference.object, true)?;
        let identity = published.identity()?;
        ensure!(identity == staged, "published archive inode changed");
        if let Some(observer) = observer {
            observer.published(&segment.reference, &identity)?;
        }
        Ok(())
    }

    /// Only an unknown leaf beneath the retained, verified archive directory is
    /// a healthy absence. An enrolled file that disappeared fences NodeDisk
    /// even when the OS reports ENOENT.
    fn open_leaf(&self, name: &str) -> Result<Option<crate::NodeDiskFile>> {
        self.directory.sync_all()?;
        let path = self.root.join(name);
        let (root, relative) = self.disk.binding(&path)?;
        match self.disk.open_file(root, relative) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.directory
                    .sync_all()
                    .map_err(|failure| anyhow::Error::new(error).context(failure))?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_files;
    use std::sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    };

    #[derive(Default)]
    struct Recorded {
        intent: Mutex<Option<AuditArchiveReference>>,
        inode: Mutex<Option<FileIdentity>>,
        published: Mutex<Option<FileIdentity>>,
        fault: AtomicU8,
    }
    impl AuditArchivePublicationObserver for Recorded {
        fn prepare(&self, reference: &AuditArchiveReference) -> Result<()> {
            ensure!(
                self.fault.load(Ordering::Acquire) != 4,
                "generation stopped"
            );
            let mut intent = self.intent.lock().unwrap();
            ensure!(
                intent.as_ref().is_none_or(|old| old == reference),
                "intent conflict"
            );
            *intent = Some(reference.clone());
            ensure!(
                self.fault.load(Ordering::Acquire) != 1,
                "prepare result lost"
            );
            Ok(())
        }
        fn staged(&self, _: &AuditArchiveReference, identity: &FileIdentity) -> Result<()> {
            let mut inode = self.inode.lock().unwrap();
            ensure!(
                inode.as_ref().is_none_or(|old| old == identity),
                "staged inode differs"
            );
            *inode = Some(identity.clone());
            ensure!(
                self.fault.load(Ordering::Acquire) != 2,
                "staging result lost"
            );
            Ok(())
        }
        fn published(&self, _: &AuditArchiveReference, identity: &FileIdentity) -> Result<()> {
            ensure!(
                self.inode.lock().unwrap().as_ref() == Some(identity),
                "final inode differs"
            );
            *self.published.lock().unwrap() = Some(identity.clone());
            ensure!(
                self.fault.load(Ordering::Acquire) != 3,
                "publication result lost"
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn owned_publication_resolves_partial_writes_and_uncertain_rename_without_adopting_files()
    {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let directory = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            crate::NodeStore::create_new_fixture(
                directory.path().join("node.kv"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant-a".into(),
            Arc::new(crate::test_utils::LocalKeyProvider::new([73; 32])),
        )
        .await
        .unwrap();
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        assert!(builder.push(0, b"retained audit event").unwrap());
        let segment = store.encrypt_audit_segment(builder).unwrap();
        let root = directory.path().join("owned");
        let observer = Arc::new(Recorded::default());
        let archive = FilesystemAuditArchive::open_fixture(&root, fixture_memory.clone())
            .unwrap()
            .with_publication_observer(observer.clone());
        observer.fault.store(1, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
        observer.fault.store(2, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        let staged = root.join(format!(
            "{}.audit.pending",
            segment.reference.object.object_id
        ));
        let original = private_files::file_identity(&staged).unwrap();
        // Model an interrupted admitted writer, retaining its exact inode and
        // capacity instead of injecting an unaccounted out-of-band extension.
        let (root_name, relative) = archive.disk.binding(&staged).unwrap();
        let partial = archive.disk.open_file(root_name, relative).unwrap();
        let bytes = b"partial interrupted write";
        partial
            .reserve_growth(0, bytes.len() as u64, DiskWork::Maintenance)
            .unwrap();
        partial.grow_reserved(bytes.len() as u64).unwrap();
        partial.write_all_at(bytes, 0).unwrap();
        partial.sync_all_and_parent().unwrap();
        drop(partial);
        observer.fault.store(3, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        assert!(!staged.exists());
        let final_path = root.join(format!("{}.audit", segment.reference.object.object_id));
        assert_eq!(private_files::file_identity(&final_path).unwrap(), original);
        assert_eq!(
            archive.read_blocking(&segment.reference.object).unwrap(),
            segment.ciphertext
        );
        let saved = directory.path().join("saved.audit");
        std::fs::rename(&final_path, &saved).unwrap();
        private_files::create(&final_path, &segment.ciphertext).unwrap();
        observer.fault.store(0, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        assert_eq!(std::fs::read(&final_path).unwrap(), segment.ciphertext);
        std::fs::remove_file(&final_path).unwrap();
        std::fs::rename(saved, &final_path).unwrap();
        assert_eq!(archive.disk.snapshot().phase, crate::NodeDiskPhase::Failed);
        assert!(archive.publish(&segment).await.is_err());
        let disk = archive.disk.clone();
        let before_close = disk.snapshot();
        let node_files = before_close.open_files;
        assert!(node_files >= 2);
        let node_path = directory.path().join("node.kv");
        let node_identity = crate::NodeGroupIdentity::read(&node_path).unwrap();
        let node_bytes = std::fs::read(node_path.join(kasumi_kv::ROOT_FILE_NAME)).unwrap();
        store.shutdown().await.unwrap();
        {
            let failure = store.node.shutdown().await.unwrap_err();
            assert_eq!(
                failure.completion(),
                kasumi_types::drain::DrainCompletion::Retained
            );
            assert!(!failure.issues().is_empty());
            let repeated = store.node.shutdown().await.unwrap_err();
            assert_eq!(
                repeated.completion(),
                kasumi_types::drain::DrainCompletion::Retained
            );
            assert_eq!(failure.issues().len(), repeated.issues().len());
            for (original, repeated) in failure.issues().iter().zip(repeated.issues()) {
                assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
                    original, repeated
                ));
            }
            assert!(store.node.db.begin_read().is_err());
            // The consuming close API cannot prove physical drain on a storage
            // failure. Its sticky Retained report preserves the original issues;
            // the installed FileOwner remains for explicit census recovery.
            assert_eq!(disk.snapshot().open_files, node_files);
            assert_eq!(
                disk.snapshot().retained_file_attempts,
                before_close.retained_file_attempts + usize::try_from(node_files).unwrap()
            );
        }
        assert_eq!(
            crate::NodeGroupIdentity::read(&node_path).unwrap(),
            node_identity
        );
        assert_eq!(
            std::fs::read(node_path.join(kasumi_kv::ROOT_FILE_NAME)).unwrap(),
            node_bytes
        );
        assert_eq!(disk.snapshot().open_directories, 1);
        assert_eq!(disk.snapshot().charged_bytes, before_close.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before_close.pending_bytes);
        let retained_charge = disk.snapshot().charged_bytes;
        let retained_pending = disk.snapshot().pending_bytes;
        let retained_attempts = disk.snapshot().retained_file_attempts;
        assert!(
            disk.reconcile(&crate::CensusCancellation::default())
                .is_err()
        );
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, retained_charge);
        assert_eq!(disk.snapshot().pending_bytes, retained_pending);
        assert_eq!(disk.snapshot().retained_file_attempts, retained_attempts);
        // Preserve the original repeated-shutdown assertion before explicitly
        // dropping the store facade; no store/backend owner may cross census.
        store.shutdown().await.unwrap();
        drop(store);
        assert_eq!(disk.snapshot().open_files, node_files);
        // The retained directory also remains a real operational owner.
        drop(archive);
        assert_eq!(disk.snapshot().open_directories, 0);
        let cancelled = crate::CensusCancellation::default();
        cancelled.cancel();
        assert!(disk.reconcile(&cancelled).is_err());
        assert_eq!(disk.snapshot().open_files, node_files);
        assert_eq!(disk.snapshot().retained_file_attempts, retained_attempts);
        assert_eq!(disk.snapshot().charged_bytes, retained_charge);
        assert_eq!(disk.snapshot().pending_bytes, retained_pending);
        assert_eq!(private_files::file_identity(&final_path).unwrap(), original);
        assert_eq!(std::fs::read(&final_path).unwrap(), segment.ciphertext);
        disk.reconcile(&crate::CensusCancellation::default())
            .unwrap();
        assert_eq!(disk.snapshot().open_files, 0);
        assert_eq!(disk.snapshot().retained_file_attempts, 0);
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        assert_eq!(
            crate::NodeGroupIdentity::read(&node_path).unwrap(),
            node_identity
        );
        assert_eq!(
            std::fs::read(node_path.join(kasumi_kv::ROOT_FILE_NAME)).unwrap(),
            node_bytes
        );
        let archive = FilesystemAuditArchive::open(&root, disk.clone())
            .unwrap()
            .with_publication_observer(observer.clone());
        assert!(Arc::ptr_eq(&archive.disk, &disk));
        assert_eq!(private_files::file_identity(&final_path).unwrap(), original);
        archive.publish(&segment).await.unwrap();
        observer.fault.store(4, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(private_files::file_identity(&final_path).unwrap(), original);
        assert_eq!(std::fs::read(&final_path).unwrap(), segment.ciphertext);
    }

    /// Encrypt one segment on a separate node store and disk, so faults injected
    /// into the archive disk never touch the source store's own ownership.
    async fn prepared_segment(
        memory: &Arc<crate::test_utils::TestDiskMemory>,
    ) -> ([tempfile::TempDir; 2], PreparedAuditSegment) {
        let scratch = crate::test_utils::private_tempdir().unwrap();
        let directory = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            crate::NodeStore::create_new_fixture(
                directory.path().join("node.kv"),
                crate::test_utils::NODE_STORE_ID,
                memory.clone(),
                crate::ScratchDisk::fixture(scratch.path(), memory.clone()),
            )
            .unwrap(),
            "tenant-a".into(),
            Arc::new(crate::test_utils::LocalKeyProvider::new([73; 32])),
        )
        .await
        .unwrap();
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        assert!(builder.push(0, b"retained audit event").unwrap());
        let segment = store.encrypt_audit_segment(builder).unwrap();
        store.shutdown().await.unwrap();
        store.node.shutdown().await.unwrap();
        ([directory, scratch], segment)
    }

    fn names(root: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    // Model an interrupted admitted writer through NodeDisk, retaining its exact
    // inode and capacity instead of an unaccounted out-of-band extension.
    fn write_admitted(archive: &FilesystemAuditArchive, name: &str, create: bool) {
        let path = archive.root.join(name);
        let (root, relative) = archive.disk.binding(&path).unwrap();
        let file = if create {
            archive
                .disk
                .create_file(root, relative, DiskWork::Maintenance)
                .unwrap()
        } else {
            archive.disk.open_file(root, relative).unwrap()
        };
        let bytes = b"partial interrupted write";
        file.reserve_growth(0, bytes.len() as u64, DiskWork::Maintenance)
            .unwrap();
        file.grow_reserved(bytes.len() as u64).unwrap();
        file.write_all_at(bytes, 0).unwrap();
        file.sync_all_and_parent().unwrap();
    }

    /// Model a process restart: every owner closes and a fresh exclusive census
    /// replaces the ledger before the archive reopens over the same directory.
    fn restart(
        archive: FilesystemAuditArchive,
        observer: Arc<dyn AuditArchivePublicationObserver>,
    ) -> FilesystemAuditArchive {
        let root = archive.root.clone();
        let disk = archive.disk.clone();
        drop(archive);
        disk.pause().unwrap();
        disk.reconcile(&crate::CensusCancellation::default())
            .unwrap();
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        FilesystemAuditArchive::open(&root, disk)
            .unwrap()
            .with_publication_observer(observer)
    }

    #[tokio::test]
    async fn restart_converges_pending_final_or_both_to_one_enrolled_final_inode() {
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Crash {
            PendingOnly,
            FinalOnly,
            Both,
        }
        for crash in [Crash::PendingOnly, Crash::FinalOnly, Crash::Both] {
            let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
            let (_source, segment) = prepared_segment(&memory).await;
            let directory = crate::test_utils::private_tempdir().unwrap();
            let root = directory.path().join("owned");
            let final_name = format!("{}.audit", segment.reference.object.object_id);
            let pending_name = format!("{final_name}.pending");
            let observer = Arc::new(Recorded::default());
            let archive = FilesystemAuditArchive::open_fixture(&root, memory.clone())
                .unwrap()
                .with_publication_observer(observer.clone());
            let expected = if crash == Crash::PendingOnly {
                observer.fault.store(2, Ordering::Release);
                assert!(archive.publish(&segment).await.is_err());
                write_admitted(&archive, &pending_name, false);
                private_files::file_identity(&root.join(&pending_name)).unwrap()
            } else {
                archive.publish(&segment).await.unwrap();
                if crash == Crash::Both {
                    // An earlier interrupted staging inode for the same object
                    // survived beside the published object.
                    write_admitted(&archive, &pending_name, true);
                }
                private_files::file_identity(&root.join(&final_name)).unwrap()
            };
            observer.fault.store(0, Ordering::Release);
            let archive = restart(archive, observer.clone());
            let disk = archive.disk.clone();
            let before = disk.snapshot();
            archive.publish(&segment).await.unwrap();
            let after = disk.snapshot();
            assert_eq!(names(&root), vec![final_name.clone()], "{crash:?}");
            assert_eq!(
                private_files::file_identity(&root.join(&final_name)).unwrap(),
                expected,
                "{crash:?}"
            );
            assert_eq!(observer.published.lock().unwrap().as_ref(), Some(&expected));
            assert_eq!(
                archive.read_blocking(&segment.reference.object).unwrap(),
                segment.ciphertext
            );
            assert_eq!(after.phase, crate::NodeDiskPhase::Open);
            assert_eq!(after.open_files, 0);
            match crash {
                // The original staging inode itself became the final object.
                Crash::PendingOnly => assert_eq!(after.persistent_files, before.persistent_files),
                Crash::FinalOnly => {
                    assert_eq!(after.persistent_files, before.persistent_files);
                    assert_eq!(after.charged_bytes, before.charged_bytes);
                }
                // Only the stale staging inode was reclaimed and credited.
                Crash::Both => {
                    assert_eq!(after.persistent_files + 1, before.persistent_files);
                    assert!(after.charged_bytes < before.charged_bytes);
                }
            }
            // The live ledger is exactly what a fresh census of the converged
            // directory charges, and a later replay changes nothing.
            let archive = restart(archive, observer.clone());
            let census = disk.snapshot();
            assert_eq!(census.charged_bytes, after.charged_bytes, "{crash:?}");
            assert_eq!(census.persistent_files, after.persistent_files);
            archive.publish(&segment).await.unwrap();
            assert_eq!(disk.snapshot().charged_bytes, census.charged_bytes);
            assert_eq!(disk.snapshot().persistent_files, census.persistent_files);
            assert_eq!(names(&root), vec![final_name]);
        }
    }

    #[tokio::test]
    async fn substituted_final_name_fences_before_any_identity_is_observed() {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let (_source, segment) = prepared_segment(&memory).await;
        let directory = crate::test_utils::private_tempdir().unwrap();
        let root = directory.path().join("owned");
        let final_path = root.join(format!("{}.audit", segment.reference.object.object_id));
        let saved = directory.path().join("saved.audit");
        let observer = Arc::new(Recorded::default());
        let (moved, foreign) = (saved.clone(), segment.ciphertext.clone());
        // Substitute identical bytes under the final name between publication
        // and readback; only an inode check can distinguish the foreign file.
        let archive = FilesystemAuditArchive::open_fixture(&root, memory.clone())
            .unwrap()
            .with_publication_observer(observer.clone())
            .with_publication_hook(move |published| {
                std::fs::rename(published, &moved).unwrap();
                private_files::create(published, &foreign).unwrap();
            });
        let disk = archive.disk.clone();
        assert!(archive.publish(&segment).await.is_err());
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
        assert!(
            observer.published.lock().unwrap().is_none(),
            "a foreign identity was observed"
        );
        let staged = observer.inode.lock().unwrap().clone().unwrap();
        assert_eq!(private_files::file_identity(&saved).unwrap(), staged);
        let substituted = private_files::file_identity(&final_path).unwrap();
        assert_ne!(substituted, staged);
        // The fenced disk admits nothing further, not even identical bytes.
        assert!(archive.publish(&segment).await.is_err());
        assert!(archive.read_blocking(&segment.reference.object).is_err());
        assert!(observer.published.lock().unwrap().is_none());
        assert_eq!(
            private_files::file_identity(&final_path).unwrap(),
            substituted
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), segment.ciphertext);

        // Explicit recovery restores the original inode, drains every owner
        // and accepts a fresh census before the same object converges.
        std::fs::remove_file(&final_path).unwrap();
        std::fs::rename(&saved, &final_path).unwrap();
        drop(archive);
        disk.reconcile(&crate::CensusCancellation::default())
            .unwrap();
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        let archive = FilesystemAuditArchive::open(&root, disk.clone())
            .unwrap()
            .with_publication_observer(observer.clone());
        archive.publish(&segment).await.unwrap();
        assert_eq!(observer.published.lock().unwrap().as_ref(), Some(&staged));
        assert_eq!(names(&root).len(), 1);
    }

    #[tokio::test]
    async fn enrolled_pending_or_final_disappearance_fences_instead_of_reporting_absence() {
        for published in [false, true] {
            let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
            let (_source, segment) = prepared_segment(&memory).await;
            let directory = crate::test_utils::private_tempdir().unwrap();
            let root = directory.path().join("owned");
            let observer = Arc::new(Recorded::default());
            let archive = FilesystemAuditArchive::open_fixture(&root, memory.clone())
                .unwrap()
                .with_publication_observer(observer.clone());
            let disk = archive.disk.clone();
            let name = if published {
                archive.publish(&segment).await.unwrap();
                format!("{}.audit", segment.reference.object.object_id)
            } else {
                observer.fault.store(2, Ordering::Release);
                assert!(archive.publish(&segment).await.is_err());
                observer.fault.store(0, Ordering::Release);
                format!("{}.audit.pending", segment.reference.object.object_id)
            };
            let before = disk.snapshot();
            std::fs::remove_file(root.join(&name)).unwrap();
            assert!(archive.publish(&segment).await.is_err());
            assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
            assert!(
                names(&root).is_empty(),
                "a missing enrolled {name} was treated as a fresh publication"
            );
            assert_eq!(
                observer.published.lock().unwrap().is_some(),
                published,
                "{name}"
            );
            // Enrolled charges are retained until an explicit fresh census.
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
        }
    }

    #[tokio::test]
    async fn publication_readback_and_identity_use_only_the_published_handle() {
        use std::os::unix::fs::PermissionsExt;
        struct Counting {
            inner: Arc<Recorded>,
            disk: Arc<NodeDisk>,
            open_files: Mutex<Option<u32>>,
        }
        impl AuditArchivePublicationObserver for Counting {
            fn prepare(&self, reference: &AuditArchiveReference) -> Result<()> {
                self.inner.prepare(reference)
            }
            fn staged(&self, reference: &AuditArchiveReference, id: &FileIdentity) -> Result<()> {
                self.inner.staged(reference, id)
            }
            fn published(
                &self,
                reference: &AuditArchiveReference,
                id: &FileIdentity,
            ) -> Result<()> {
                *self.open_files.lock().unwrap() = Some(self.disk.snapshot().open_files);
                self.inner.published(reference, id)
            }
        }
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let (_source, segment) = prepared_segment(&memory).await;
        let directory = crate::test_utils::private_tempdir().unwrap();
        let root = directory.path().join("owned");
        // Once published, the final name is no longer readable by any path
        // open; NodeDisk's already-open publication handle is unaffected.
        let archive = FilesystemAuditArchive::open_fixture(&root, memory.clone())
            .unwrap()
            .with_publication_hook(|published| {
                std::fs::set_permissions(published, std::fs::Permissions::from_mode(0o200))
                    .unwrap();
                assert_eq!(
                    std::fs::File::open(published).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            });
        let disk = archive.disk.clone();
        let recorded = Arc::new(Recorded::default());
        let counting = Arc::new(Counting {
            inner: recorded.clone(),
            disk: disk.clone(),
            open_files: Mutex::new(None),
        });
        let archive = archive.with_publication_observer(counting.clone());
        let before = disk.snapshot();
        archive.publish(&segment).await.unwrap();
        // The observer ran while the published handle was the only file owner.
        assert_eq!(
            *counting.open_files.lock().unwrap(),
            Some(before.open_files + 1)
        );
        let staged = recorded.inode.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.published.lock().unwrap().as_ref(), Some(&staged));
        assert_eq!(disk.snapshot().open_files, before.open_files);
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
        let final_path = root.join(format!("{}.audit", segment.reference.object.object_id));
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_files::file_identity(&final_path).unwrap(), staged);
        assert_eq!(
            archive.read_blocking(&segment.reference.object).unwrap(),
            segment.ciphertext
        );
    }

    #[test]
    fn exclusive_rename_preserves_an_existing_destination_and_the_source_inode() {
        let directory = crate::test_utils::private_tempdir().unwrap();
        let owned = directory.path().join("owned");
        private_files::create_directory(&owned).unwrap();
        let source = owned.join("prepared");
        let target = owned.join("published");
        private_files::create(&source, b"prepared").unwrap();
        private_files::create(&target, b"unrelated").unwrap();
        let identity = private_files::file_identity(&source).unwrap();
        assert!(private_files::rename_exclusive(&source, &target).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"prepared");
        assert_eq!(std::fs::read(&target).unwrap(), b"unrelated");
        std::fs::remove_file(&target).unwrap();
        private_files::rename_exclusive(&source, &target).unwrap();
        assert_eq!(private_files::file_identity(&target).unwrap(), identity);
        assert!(!source.exists());
    }
}
