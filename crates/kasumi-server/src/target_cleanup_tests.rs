use super::super::{GenerationKey, checked_generation_path};
use super::*;
use kasumi_store::NodeStore;
use std::{path::PathBuf, sync::Mutex};

/// The journal's cleanup rules over memory: one binding, and only a first
/// record, an exact replay or the next stage of the same binding.
#[derive(Default)]
struct MemoryLedger {
    binding: Mutex<Option<TargetFileBinding>>,
    cleanup: Mutex<Option<TargetCleanup>>,
    records: Mutex<usize>,
}
impl CleanupLedger for MemoryLedger {
    fn binding(&self) -> Result<Option<TargetFileBinding>> {
        Ok(self.binding.lock().unwrap().clone())
    }
    fn bind(&self, binding: &TargetFileBinding) -> Result<()> {
        let mut bound = self.binding.lock().unwrap();
        ensure!(
            bound.as_ref().is_none_or(|old| old == binding),
            "bound to other storage"
        );
        *bound = Some(binding.clone());
        Ok(())
    }
    fn cleanup(&self) -> Result<Option<TargetCleanup>> {
        Ok(self.cleanup.lock().unwrap().clone())
    }
    fn record(&self, cleanup: &TargetCleanup) -> Result<()> {
        let mut recorded = self.cleanup.lock().unwrap();
        match recorded.as_ref() {
            None => {}
            Some(old) if old == cleanup => return Ok(()),
            Some(old)
                if old.stage.permits_successor(cleanup.stage) && old.binding == cleanup.binding => {
            }
            Some(_) => anyhow::bail!("target cleanup outcome differs"),
        }
        *recorded = Some(cleanup.clone());
        *self.records.lock().unwrap() += 1;
        Ok(())
    }
    fn check(&self) -> Result<()> {
        Ok(())
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    physical: kasumi_engine::test_utils::FixtureStorage,
    config: kasumi_store::NodeDiskConfig,
    parent: kasumi_store::NodeDiskDirectory,
    root: PathBuf,
    opened_root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        // Keep the configured spelling: macOS temp roots can resolve from /var
        // to /private/var while NodeDisk still binds the installed /var path.
        let installation = directory.path().to_path_buf();
        let physical =
            crate::runtime_storage_fixtures::physical(&installation, Default::default()).unwrap();
        let root = installation.join("persistent/targets");
        let config = kasumi_store::NodeDisk::fixture_config(
            installation.join("persistent/target-journal.kv"),
        )
        .unwrap();
        let parent =
            crate::persistent_disk::open_or_create_directory(&config, &physical.persistent, &root)
                .unwrap();
        let opened_root = std::fs::canonicalize(&root).unwrap();
        Self {
            _directory: directory,
            physical,
            config,
            parent,
            root,
            opened_root,
        }
    }
    fn storage(&self) -> TargetStorage<'_> {
        TargetStorage {
            disk: &self.physical.persistent,
            config: &self.config,
            parent: &self.parent,
        }
    }
    fn path(&self, key: &GenerationKey) -> PathBuf {
        checked_generation_path(&self.parent, &self.root, &self.opened_root, key).unwrap()
    }
    /// Create the target's storage as the original materialization does, and
    /// return the binding it records.
    async fn create(&self, key: &GenerationKey, id: Uuid) -> TargetFileBinding {
        let path = self.path(key);
        let stamp = Uuid::new_v4();
        let node = NodeStore::create_materialization_target(
            &path,
            id,
            stamp,
            self.physical.persistent.clone(),
            self.physical.scratch.clone(),
            self.physical.persistent.native_storage_config(),
        )
        .unwrap();
        assert_eq!(node.target_directory_stamp().unwrap(), Some(stamp));
        let binding = TargetFileBinding {
            tenant: key.0.clone(),
            target_incarnation: key.1,
            path: path.clone(),
            directory: node.physical_identity().unwrap().directory,
            directory_stamp: Some(stamp),
            node_store_id: id,
        };
        node.shutdown().await.unwrap();
        drop(node);
        binding
    }
    fn open(&self, key: &GenerationKey, id: Uuid) -> NodeStore {
        self.physical.open_existing(self.path(key), id).unwrap()
    }
}

fn file<'a>(key: &'a GenerationKey, path: &'a Path, id: Uuid) -> TargetFile<'a> {
    TargetFile {
        tenant: &key.0,
        target: key.1,
        path,
        node_store_id: id,
    }
}

/// Interrupt after the Deleting record, after the unlinks and after the
/// parent sync. Each replay finishes exactly the original storage, records
/// one terminal outcome, and leaves another generation in the same enrolled
/// directory untouched; a further replay changes nothing.
#[tokio::test]
async fn exact_cleanup_resumes_after_every_boundary_and_keeps_unrelated_generations() {
    for (boundary, expected_stage) in [
        ("deleting", TargetCleanupStage::Deleting),
        ("unlinked", TargetCleanupStage::Unlinked),
        ("synced", TargetCleanupStage::ParentSynced),
    ] {
        let fixture = Fixture::new();
        let key = ("city".to_owned(), Uuid::new_v4());
        let id = Uuid::new_v4();
        let binding = fixture.create(&key, id).await;
        let other = ("city".to_owned(), Uuid::new_v4());
        let other_id = Uuid::new_v4();
        fixture.create(&other, other_id).await;
        let ledger = MemoryLedger::default();
        ledger.bind(&binding).unwrap();
        let path = fixture.path(&key);
        interruption::stop_after(&path, boundary);
        let error = delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap_err();
        assert!(format!("{error:#}").contains(boundary), "{error:#}");
        let recorded = ledger.cleanup().unwrap().unwrap();
        assert_eq!(recorded.stage, expected_stage, "{boundary}");
        assert_eq!(recorded.binding.as_ref(), Some(&binding));
        assert_eq!(path.exists(), boundary == "deleting", "{boundary}");

        delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
        let terminal = ledger.cleanup().unwrap().unwrap();
        assert_eq!(terminal.stage, TargetCleanupStage::Deleted);
        assert_eq!(terminal.binding, Some(binding.clone()));
        assert!(!path.exists());
        let records = *ledger.records.lock().unwrap();
        assert_eq!(records, 4, "each durable stage and one terminal outcome");
        delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
        assert_eq!(*ledger.records.lock().unwrap(), records);

        let survivor = fixture.open(&other, other_id);
        survivor.shutdown().await.unwrap();
        assert_eq!(
            fixture.physical.persistent.snapshot().phase,
            kasumi_store::NodeDiskPhase::Open
        );
    }
}

/// A directory at the same path with the same store identity, but created
/// after the original was removed, is refused and kept.
#[tokio::test]
async fn substituted_directory_with_the_same_path_and_store_identity_is_refused() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let binding = fixture.create(&key, id).await;
    let path = fixture.path(&key);
    kasumi_store::NodeStore::claim_cleanup(
        &path,
        id,
        fixture.physical.persistent.clone(),
        fixture.physical.persistent.native_storage_config(),
    )
    .unwrap()
    .delete()
    .unwrap();
    let substitute = fixture.create(&key, id).await;
    assert_ne!(substitute.directory_stamp, binding.directory_stamp);
    // Exercise the recycled-inode case deterministically on filesystems that
    // allocate a different inode here as well as those that immediately reuse it.
    let recycled = TargetFileBinding {
        directory: substitute.directory,
        ..binding.clone()
    };
    for enrolled in [binding, recycled] {
        for deleting in [false, true] {
            let ledger = MemoryLedger::default();
            ledger.bind(&enrolled).unwrap();
            let target = file(&key, &path, id);
            let original = deleting
                .then(|| target.cleanup(TargetCleanupStage::Deleting, Some(enrolled.clone())));
            if let Some(record) = &original {
                ledger.record(record).unwrap();
            }
            let error = delete_exact(&ledger, &fixture.storage(), &target).unwrap_err();
            assert!(
                format!("{error:#}").contains("not its originally enrolled directory"),
                "{error:#}"
            );
            assert_eq!(ledger.cleanup().unwrap(), original);
        }
    }
    let kept = fixture.open(&key, id);
    assert_eq!(
        kept.physical_identity().unwrap().directory,
        substitute.directory
    );
    assert_eq!(
        kept.target_directory_stamp().unwrap(),
        substitute.directory_stamp
    );
    kept.shutdown().await.unwrap();
}

/// A never-created target has a managed absence proof and records a terminal
/// outcome without a binding.
#[tokio::test]
async fn absent_never_created_target_records_deletion_without_a_binding() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let path = fixture.path(&key);
    let ledger = MemoryLedger::default();
    delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
    let terminal = ledger.cleanup().unwrap().unwrap();
    assert_eq!(terminal.stage, TargetCleanupStage::Deleted);
    assert_eq!(terminal.binding, None);
    delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
    assert_eq!(*ledger.records.lock().unwrap(), 1);
}

/// A bound target whose directory disappeared outside cleanup is not
/// absent: the enrolled name is missing, so nothing terminal is recorded.
#[tokio::test]
async fn bound_target_removed_outside_cleanup_is_not_an_absence_proof() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let binding = fixture.create(&key, id).await;
    let path = fixture.path(&key);
    std::fs::remove_dir_all(&path).unwrap();
    let ledger = MemoryLedger::default();
    ledger.bind(&binding).unwrap();
    assert!(delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).is_err());
    assert!(ledger.cleanup().unwrap().is_none());
}

/// A managed deletion leaves a healthy disk that proves current absence.
#[tokio::test]
async fn a_missing_bound_target_never_starts_cleanup_even_after_a_clean_census() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let ledger = MemoryLedger::default();
    ledger.bind(&fixture.create(&key, id).await).unwrap();
    let path = fixture.path(&key);
    file(&key, &path, id)
        .claim(&fixture.storage())
        .unwrap()
        .delete()
        .unwrap();
    target_absence_from_installed_disk(&fixture.config, &fixture.physical.persistent, &path)
        .unwrap();
    assert!(delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).is_err());
    assert!(ledger.cleanup().unwrap().is_none());
}

/// After a recorded deletion, a later directory at the same path is never
/// deleted by a replay.
#[tokio::test]
async fn recorded_deletion_never_deletes_a_later_directory() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let binding = fixture.create(&key, id).await;
    let path = fixture.path(&key);
    let ledger = MemoryLedger::default();
    ledger.bind(&binding).unwrap();
    delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
    let later = fixture.create(&key, id).await;
    let error = delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap_err();
    assert!(format!("{error:#}").contains("occupied again"), "{error:#}");
    let kept = fixture.open(&key, id);
    assert_eq!(kept.physical_identity().unwrap().directory, later.directory);
    kept.shutdown().await.unwrap();
}

/// Storage created before its binding was recorded is selected by the store
/// identity its root carries, bound, and then deleted exactly.
#[tokio::test]
async fn unbound_original_is_bound_by_its_store_identity_before_deletion() {
    let fixture = Fixture::new();
    let key = ("city".to_owned(), Uuid::new_v4());
    let id = Uuid::new_v4();
    let original = fixture.create(&key, id).await;
    let path = fixture.path(&key);
    let ledger = MemoryLedger::default();
    delete_exact(&ledger, &fixture.storage(), &file(&key, &path, id)).unwrap();
    assert_eq!(ledger.binding().unwrap(), Some(original.clone()));
    let terminal = ledger.cleanup().unwrap().unwrap();
    assert_eq!(terminal.stage, TargetCleanupStage::Deleted);
    assert_eq!(terminal.binding, Some(original));
    assert!(!path.exists());
}
