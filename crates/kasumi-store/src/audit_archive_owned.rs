use super::*;
use crate::private_files::{self, FileIdentity};

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
    pub(super) fn publish_observed(
        &self,
        segment: &PreparedAuditSegment,
        observer: &dyn AuditArchivePublicationObserver,
    ) -> Result<()> {
        let _publication = self
            .publication
            .lock()
            .map_err(|_| anyhow::anyhow!("archive publication ownership unavailable"))?;
        observer.prepare(&segment.reference)?;
        let final_path = self
            .root
            .join(format!("{}.audit", segment.reference.object.object_id));
        if final_path.try_exists()? {
            read_file(&self.root, &self.disk, &segment.reference.object, true)?;
            return observer.published(
                &segment.reference,
                &private_files::file_identity(&final_path)?,
            );
        }
        // The object identity is durable before creation. There are no random
        // temporary names for a crash to leave outside the ownership ledger.
        let staged = self.root.join(format!(
            "{}.audit.pending",
            segment.reference.object.object_id
        ));
        let (root, relative) = self.disk.binding(&staged)?;
        let mut file = if staged.try_exists()? {
            self.disk.open_file(root, relative)?
        } else {
            self.disk
                .create_file(root, relative, DiskWork::Maintenance)?
        };
        let identity = file.identity()?;
        observer.staged(&segment.reference, &identity)?;
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
        ensure!(
            published.identity()? == identity,
            "published archive inode changed"
        );
        drop(published);
        read_file(&self.root, &self.disk, &segment.reference.object, true)?;
        observer.published(
            &segment.reference,
            &private_files::file_identity(&final_path)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    };

    #[derive(Default)]
    struct Recorded {
        intent: Mutex<Option<AuditArchiveReference>>,
        inode: Mutex<Option<FileIdentity>>,
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
        assert_eq!(before_close.open_files, 1);
        let node_path = directory.path().join("node.kv");
        let node_identity = private_files::file_identity(&node_path).unwrap();
        let node_bytes = std::fs::read(&node_path).unwrap();
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
                assert!(Arc::ptr_eq(original, repeated));
            }
            assert!(store.node.db.begin_read().is_err());
            // The consuming close API cannot prove physical drain on a storage
            // failure. Its sticky Retained report preserves the original issues;
            // the installed FileOwner remains for explicit census recovery.
            assert_eq!(disk.snapshot().open_files, 1);
            assert_eq!(
                disk.snapshot().retained_file_attempts,
                before_close.retained_file_attempts + 1
            );
        }
        assert_eq!(
            private_files::file_identity(&node_path).unwrap(),
            node_identity
        );
        assert_eq!(std::fs::read(&node_path).unwrap(), node_bytes);
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
        assert_eq!(disk.snapshot().open_files, 1);
        // The retained directory also remains a real operational owner.
        drop(archive);
        assert_eq!(disk.snapshot().open_directories, 0);
        let cancelled = crate::CensusCancellation::default();
        cancelled.cancel();
        assert!(disk.reconcile(&cancelled).is_err());
        assert_eq!(disk.snapshot().open_files, 1);
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
            private_files::file_identity(&node_path).unwrap(),
            node_identity
        );
        assert_eq!(std::fs::read(&node_path).unwrap(), node_bytes);
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
