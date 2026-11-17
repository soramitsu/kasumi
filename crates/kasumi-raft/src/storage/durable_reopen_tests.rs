//! A backend whose selected state is durable at the custody applied cursor
//! resumes there on reopen. It neither restores the older published snapshot
//! nor replays the entries that cursor already covers; installation still
//! selects the snapshot with the cursor, and capture never rolls it back.
use super::*;
use crate::test_utils::FixtureResult;
use openraft::storage::{RaftLogStorageExt, StorageHelper};
use std::sync::atomic::AtomicUsize;

const STATE: &str = "durable-state";

struct DurableBackend {
    store: Arc<TenantStore>,
    restores: AtomicUsize,
    applied: AtomicUsize,
}
impl DurableBackend {
    fn new(store: Arc<TenantStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            restores: AtomicUsize::new(0),
            applied: AtomicUsize::new(0),
        })
    }
    fn value(&self) -> Result<Vec<u8>> {
        Ok(self
            .store
            .get(STATE, b"value")?
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default())
    }
}
struct PreparedDurable {
    writes: Vec<WriteOp>,
}
impl crate::PreparedStateMachineRestore for PreparedDurable {
    fn retirement(&self) -> Option<crate::RetiredSnapshotState> {
        None
    }
    fn application_writes(&self) -> &[WriteOp] {
        &self.writes
    }
    fn publish(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}
impl StateMachineBackend for DurableBackend {
    fn resumes_durable_selection(&self) -> bool {
        true
    }
    fn close_application(&self) {}
    fn apply_with_publisher(
        &self,
        _: &crate::AppliedEntryContext,
        input: crate::AppliedInput<'_>,
        publisher: &mut dyn crate::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        let writes = match input {
            crate::AppliedInput::Command(bytes) => {
                self.applied.fetch_add(1, Ordering::SeqCst);
                vec![put(STATE, b"value", bytes.to_vec())]
            }
            crate::AppliedInput::Metadata => Vec::new(),
        };
        publisher
            .commit(crate::AppliedResponse::application(Vec::new()), &writes)
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<crate::CapturedSnapshot, kasumi_store::ScratchOperationFailure> {
        let value = self.value()?;
        Ok(crate::CapturedSnapshot::new(None, move |writer| {
            writer.write_all(&value)?;
            Ok(())
        }))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<crate::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        std::io::copy(bytes, &mut std::io::sink())?;
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn crate::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        self.restores.fetch_add(1, Ordering::SeqCst);
        let mut value = Vec::new();
        bytes.read_to_end(&mut value)?;
        Ok(Box::new(PreparedDurable {
            writes: vec![put(STATE, b"value", value)],
        }))
    }
}

fn entry(index: u64, bytes: &[u8]) -> Entry<TypeConfig> {
    Entry {
        initialization: None,
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(crate::RaftCommand::application(bytes.to_vec())),
    }
}

struct Opened {
    node: NodeStore,
    domains: Arc<TenantStorageSet>,
    backend: Arc<DurableBackend>,
    log: LogStore,
    machine: StateMachine,
}
impl Opened {
    // A reopen requires the previous node's own shutdown.
    async fn close(self) -> FixtureResult<()> {
        drop(self.machine);
        drop(self.log);
        drop(self.backend);
        self.domains.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

async fn open(
    path: &std::path::Path,
    create: bool,
    scratch: Arc<kasumi_store::ScratchDisk>,
) -> FixtureResult<Opened> {
    let provider = Arc::new(LocalKeyProvider::new([7; 32]));
    let custody = Arc::new(LocalKeyProvider::new([241; 32]));
    let (node, domains) = if create {
        let node = NodeStore::create_new_fixture(
            path,
            kasumi_store::test_utils::NODE_STORE_ID,
            scratch.memory().clone(),
            scratch.clone(),
        )?;
        let store =
            TenantStore::initialize_catalog_fixture(node.clone(), "durable".into(), provider)
                .await?;
        let domains = kasumi_store::test_utils::initialize_custody_fixture(store, custody).await?;
        domains.write_batch(&[], &crate::initial_storage_identity(1, "durable/group")?)?;
        (node, domains)
    } else {
        let node = NodeStore::open_existing_fixture(
            path,
            kasumi_store::test_utils::NODE_STORE_ID,
            scratch.memory().clone(),
            scratch.clone(),
        )?;
        let store =
            TenantStore::open_existing_fixture(node.clone(), "durable".into(), provider).await?;
        let domains =
            kasumi_store::test_utils::open_existing_custody_fixture(store, custody).await?;
        (node, domains)
    };
    let backend = DurableBackend::new(domains.application().clone());
    let log = LogStore::open(domains.clone(), 1).await?;
    let machine = StateMachine::open(
        domains.clone(),
        backend.clone(),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    Ok(Opened {
        node,
        domains,
        backend,
        log,
        machine,
    })
}

async fn applied_index(machine: &mut StateMachine) -> FixtureResult<Option<u64>> {
    Ok(machine.applied_state().await?.0.map(|id| id.index))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn durable_selection_reopens_after_its_applied_cursor_without_restoring_the_snapshot()
-> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("durable.kv");
    let mut opened = open(&path, true, scratch.clone()).await?;
    let zero = entry(0, b"zero");
    opened.log.blocking_append([zero.clone()]).await?;
    opened.log.save_committed(Some(zero.log_id)).await?;
    StorageHelper::new(&mut opened.log, &mut opened.machine)
        .get_initial_state()
        .await?;
    opened
        .machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await?;
    opened
        .log
        .blocking_append([entry(1, b"one"), entry(2, b"two")])
        .await?;
    opened
        .log
        .save_committed(Some(entry(2, b"").log_id))
        .await?;
    StorageHelper::new(&mut opened.log, &mut opened.machine)
        .get_initial_state()
        .await?;
    assert_eq!(opened.backend.applied.load(Ordering::SeqCst), 3);
    assert_eq!(opened.backend.value()?, b"two");
    // The published image is older than the durable selection and cursor.
    let published = load_snapshot(&opened.backend.store, 64 << 20)?.context("snapshot absent")?;
    assert_eq!(published.meta.last_log_id.map(|id| id.index), Some(0));
    assert_eq!(applied_index(&mut opened.machine).await?, Some(2));
    opened.close().await?;

    let mut opened = open(&path, false, scratch.clone()).await?;
    assert_eq!(applied_index(&mut opened.machine).await?, Some(2));
    StorageHelper::new(&mut opened.log, &mut opened.machine)
        .get_initial_state()
        .await?;
    assert_eq!(opened.backend.restores.load(Ordering::SeqCst), 0);
    assert_eq!(opened.backend.applied.load(Ordering::SeqCst), 0);
    assert_eq!(opened.backend.value()?, b"two");

    // Installation selects the snapshot's state with its cursor; the next
    // reopen resumes exactly there.
    let mut image = envelope(b"installed".to_vec(), scratch.clone());
    image.meta.last_log_id = Some(entry(5, b"").log_id);
    opened
        .machine
        .install_snapshot(
            &image.meta,
            Box::new(SnapshotBuffer::from_image(
                image.encode(64 << 20)?,
                &crate::SnapshotBufferOwner::fixture(),
            )?),
        )
        .await?;
    assert_eq!(opened.backend.restores.load(Ordering::SeqCst), 1);
    assert_eq!(opened.backend.value()?, b"installed");
    assert_eq!(applied_index(&mut opened.machine).await?, Some(5));
    opened.close().await?;
    let mut opened = open(&path, false, scratch).await?;
    assert_eq!(applied_index(&mut opened.machine).await?, Some(5));
    assert_eq!(opened.backend.restores.load(Ordering::SeqCst), 0);
    assert_eq!(opened.backend.value()?, b"installed");
    opened.close().await?;
    Ok(())
}
