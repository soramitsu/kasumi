use super::*;
use kasumi_store::{NodeStore, ScratchDisk, StorageAccess, test_utils::LocalKeyProvider};

struct Fixture {
    directory: tempfile::TempDir,
    id: Uuid,
    node: Arc<NodeStore>,
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    admission: Arc<crate::admission::NodeAdmission>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let installed = TargetJournalInstallation {
            root: ControlSigningRoot {
                control_incarnation: Uuid::new_v4(),
                public_key: "11".repeat(32),
            },
            node: NodeIdentity {
                node_id: 1,
                verifier: kasumi_types::TrustVerifierIdentity {
                    installation_id: Uuid::new_v4(),
                    node_id: 1,
                },
                principal: "target-node".into(),
                certificate_sha256: "22".repeat(32),
            },
        };
        let id = kasumi_store::node_store_ids::target_journal(
            installed.root.control_incarnation,
            &installed.node.verifier,
        )?;
        let node = NodeStore::create_new(
            directory.path().join("journal.redb"),
            id,
            ScratchDisk::fixture(),
        )?;
        let store = TenantStore::open(
            node.clone(),
            format!("kasumi.target.{}.1", installed.root.control_incarnation),
            Arc::new(LocalKeyProvider::new([39; 32])),
            StorageAccess::target_journal(&installed.root, &installed.node)?,
        )
        .await?;
        Ok(Self {
            directory,
            id,
            node,
            store,
            installed,
            admission: crate::admission::NodeAdmission::with_fixed_memory(
                Default::default(),
                2 << 30,
                0,
            )?,
        })
    }
    fn create(&self) -> Result<Arc<TargetJournal>> {
        TargetJournal::create_new(
            self.store.clone(),
            self.installed.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            self.admission.clone(),
        )
    }
    fn reopen(&self) -> Result<Arc<TargetJournal>> {
        TargetJournal::open_existing(
            self.store.clone(),
            self.installed.clone(),
            TargetJournalLimits {
                max_metadata_bytes: 4 << 20,
            },
            self.admission.clone(),
        )
    }
}

#[tokio::test]
async fn missing_journal_head_never_initializes_and_explicit_installation_cannot_repeat()
-> Result<()> {
    let f = Fixture::new().await?;
    assert!(f.reopen().is_err());
    assert!(f.store.get(NS, b"metadata")?.is_none());
    let journal = f.create()?;
    let head = f.store.get(NS, b"metadata")?.unwrap();
    assert!(f.create().is_err());
    assert!(Arc::ptr_eq(&journal, &f.reopen()?));
    f.store.write_batch(&[WriteOp::delete(NS, b"metadata")])?;
    assert!(
        f.reopen().is_err(),
        "cached owner must not bypass durable head validation"
    );
    assert!(f.store.get(NS, b"metadata")?.is_none());
    f.store
        .write_batch(&[WriteOp::put(NS, b"metadata", &head)])?;
    drop(journal);
    assert!(f.create().is_err());
    let journal = f.reopen()?;
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head));
    journal.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn corrupt_or_wrong_installed_journal_head_is_rejected_without_replacement() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    drop(journal);
    let original = f.store.get(NS, b"metadata")?.unwrap();
    let mut wrong: Metadata = serde_json::from_slice(&original)?;
    wrong.installation.root.control_incarnation = Uuid::new_v4();
    for bytes in [b"{".to_vec(), serde_json::to_vec(&wrong)?] {
        f.store
            .write_batch(&[WriteOp::put(NS, b"metadata", &bytes)])?;
        assert!(f.reopen().is_err());
        assert!(f.create().is_err());
        assert_eq!(f.store.get(NS, b"metadata")?, Some(bytes));
    }
    f.store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn installed_empty_journal_reopens_only_its_exact_node_after_owner_drain() -> Result<()> {
    let f = Fixture::new().await?;
    let journal = f.create()?;
    let original = f.store.get(NS, b"metadata")?.unwrap();
    journal.shutdown().await;
    drop(journal);
    let Fixture {
        directory,
        id,
        node,
        store,
        installed,
        admission,
    } = f;
    drop(store);
    drop(node);
    let path = directory.path().join("journal.redb");
    let bytes = std::fs::read(&path)?;
    assert!(NodeStore::open_existing(&path, Uuid::new_v4(), ScratchDisk::fixture()).is_err());
    assert_eq!(std::fs::read(&path)?, bytes);
    let node = NodeStore::open_existing(&path, id, ScratchDisk::fixture())?;
    let store = TenantStore::open_existing(
        node.clone(),
        format!("kasumi.target.{}.1", installed.root.control_incarnation),
        Arc::new(LocalKeyProvider::new([39; 32])),
        StorageAccess::target_journal(&installed.root, &installed.node)?,
    )
    .await?;
    let journal = TargetJournal::open_existing(
        store.clone(),
        installed,
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        admission,
    )?;
    assert_eq!(store.get(NS, b"metadata")?, Some(original));
    journal.shutdown().await;
    Ok(())
}
