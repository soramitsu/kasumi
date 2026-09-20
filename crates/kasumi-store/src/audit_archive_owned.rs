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
        let directory = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            crate::NodeStore::create_new_fixture(
                directory.path().join("node.redb"),
                crate::test_utils::NODE_STORE_ID,
                crate::ScratchDisk::fixture(),
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
        let archive = FilesystemAuditArchive::open_fixture(&root)
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
        store.shutdown().await.unwrap();
        if let Err(failure) = store.node.shutdown().await {
            assert_eq!(
                failure.completion(),
                kasumi_types::drain::DrainCompletion::Complete
            );
        }
        assert_eq!(archive.disk.snapshot().open_files, 0);
        archive
            .disk
            .reconcile(&crate::CensusCancellation::default())
            .unwrap();
        archive.publish(&segment).await.unwrap();
        observer.fault.store(4, Ordering::Release);
        assert!(archive.publish(&segment).await.is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        store.shutdown().await.unwrap();
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
