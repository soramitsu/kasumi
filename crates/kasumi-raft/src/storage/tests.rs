use super::*;
use kasumi_store::{
    NodeStore,
    test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
};

#[path = "joint_publication_tests.rs"]
mod joint_publication_tests;
#[path = "worker_failure_tests.rs"]
mod worker_failure_tests;

struct PreparedFixtureRestore<'a> {
    retirement: Option<crate::RetiredSnapshotState>,
    commit: Box<dyn FnOnce() -> Result<()> + 'a>,
}
impl crate::PreparedStateMachineRestore for PreparedFixtureRestore<'_> {
    fn retirement(&self) -> Option<crate::RetiredSnapshotState> {
        self.retirement.clone()
    }
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)> {
        vec![]
    }
    fn application_writes(&self) -> &[kasumi_store::WriteOp] {
        &[]
    }
    fn publish(self: Box<Self>) -> Result<()> {
        (self.commit)()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_log_future_retains_drain_lease_until_blocking_persistence_finishes() -> Result<()>
{
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use crate::lifetime::StorageDrain;
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::Duration,
    };

    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("cancelled-persistence.kv");
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?,
        "cancelled-persistence".into(),
        Arc::new(LocalKeyProvider::new([19; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let (drain, lease) = StorageDrain::new();
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    domains.write_batch(
        &[],
        &crate::initial_storage_identity(1, "cancelled-persistence")?,
    )?;
    let log = LogStore::open_tracked(domains, 1, lease).await?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let operation = tokio::spawn(async move {
        log.mutate(move |store| {
            let _ = entered.send(());
            wait.recv_timeout(Duration::from_secs(10))?;
            store.write_batch(&[put("test", b"committed", b"whole-write".to_vec())])
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), ready).await??;
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    let mut drained = Box::pin(drain.wait());
    assert!(poll_fn(|cx| Poll::Ready(drained.as_mut().poll(cx).is_pending())).await);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(10), drained).await?;
    let domains = kasumi_store::test_utils::open_existing_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    assert_eq!(
        domains
            .custody()
            .store()
            .get("test", b"committed")?
            .unwrap(),
        b"whole-write"
    );
    domains.custody().store().shutdown().await.unwrap();
    drop(domains);
    drop(store);
    // An abandoned response does not detach persistence from its drain lease.
    let reopened = NodeStore::open_existing_fixture(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        fixture_scratch.memory().clone(),
        fixture_scratch.clone(),
    )?;
    drop(reopened);
    Ok(())
}

#[derive(Default)]
struct BytesBackend(Mutex<Vec<u8>>);

impl StateMachineBackend for BytesBackend {
    fn close_application(&self) {
        self.0.lock().unwrap().clear();
    }
    fn apply(
        &self,
        _: &crate::AppliedEntryContext,
        bytes: &[u8],
    ) -> Result<crate::AppliedResponse> {
        *self.0.lock().unwrap() = bytes.to_vec();
        Ok(crate::AppliedResponse::application(bytes.to_vec()))
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        let data = self.0.lock().unwrap().clone();
        Ok(crate::CapturedSnapshot::new(None, move |writer| {
            writer.write_all(&data)?;
            Ok(())
        }))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        let mut captured = Vec::new();
        bytes.read_to_end(&mut captured)?;
        ensure!(captured != b"invalid", "invalid application snapshot");
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _context: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        let mut captured = Vec::new();
        bytes.read_to_end(&mut captured)?;
        self.validate_snapshot(&mut captured.as_slice())?;
        Ok(Box::new(PreparedFixtureRestore {
            retirement: None,
            commit: Box::new(move || {
                *self.0.lock().unwrap() = captured;
                Ok(())
            }),
        }))
    }
}

async fn new_fault_store(
    disk: FaultBackend,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
) -> Result<Arc<TenantStore>> {
    TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::open_with_backend(
            disk,
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "snapshot-test".into(),
        Arc::new(LocalKeyProvider::new([7; 32])),
        Arc::new(ManualClock::new()),
    )
    .await
}

async fn existing_fault_store(
    disk: FaultBackend,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
) -> Result<Arc<TenantStore>> {
    TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_with_backend(
            disk,
            kasumi_store::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )?,
        "snapshot-test".into(),
        Arc::new(LocalKeyProvider::new([7; 32])),
        Arc::new(ManualClock::new()),
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn applied_metadata_does_not_block_runtime_while_snapshot_capture_holds_state_lock()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    struct PausedSnapshot {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl StateMachineBackend for PausedSnapshot {
        fn close_application(&self) {
            // This fixture retains no application state.
        }
        fn apply(
            &self,
            _: &crate::AppliedEntryContext,
            bytes: &[u8],
        ) -> Result<crate::AppliedResponse> {
            Ok(crate::AppliedResponse::application(bytes.to_vec()))
        }
        fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            // Bound a regression's stall instead of hanging the test runtime.
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(1));
            Ok(crate::CapturedSnapshot::new(None, |writer| {
                writer.write_all(b"consistent-snapshot")?;
                Ok(())
            }))
        }
        fn validate_snapshot(
            &self,
            _: &mut dyn std::io::Read,
        ) -> Result<Option<crate::RetiredSnapshotState>> {
            Ok(None)
        }
        fn prepare_restore<'a>(
            &'a self,
            _context: &crate::SnapshotRestoreContext,
            _: &mut dyn std::io::Read,
        ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
            Ok(Box::new(PreparedFixtureRestore {
                retirement: None,
                commit: Box::new(|| Ok(())),
            }))
        }
    }
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::initialize_custody_fixture(
            new_fault_store(FaultBackend::new(), fixture_scratch.clone()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(PausedSnapshot {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(wait),
        }),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    let mut capturing = machine.clone();
    let capture = tokio::spawn(async move { capturing.get_snapshot_builder().await });
    ready.await?;
    let start = tokio::time::Instant::now();
    let (metadata, elapsed) = tokio::join!(machine.applied_state(), async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let elapsed = start.elapsed();
        let _ = release.send(());
        elapsed
    });
    assert!(
        elapsed < std::time::Duration::from_millis(250),
        "metadata lookup blocked the runtime for {elapsed:?}"
    );
    assert_eq!(metadata?.0, None);
    let mut builder = capture.await?;
    let snapshot = builder.build_snapshot().await?;
    let envelope = {
        let image = snapshot.snapshot.into_image()?;
        SnapshotEnvelope::decode(image.disk(), &mut image.reader(), 64 << 20)?
    };
    assert_eq!(envelope.backend.read_bounded(1024)?, b"consistent-snapshot");
    assert_eq!(envelope.meta.last_log_id, None);
    Ok(())
}

fn envelope(bytes: Vec<u8>, fixture_scratch: Arc<kasumi_store::ScratchDisk>) -> SnapshotEnvelope {
    SnapshotEnvelope {
        version: 2,
        kind: SnapshotKind::Application,
        meta: SnapshotMeta {
            last_log_id: Some(LogId::new(openraft::CommittedLeaderId::new(1, 1), 3)),
            last_membership: StoredMembership::default(),
            snapshot_id: uuid::Uuid::new_v4().to_string(),
        },
        backend: kasumi_store::SnapshotImage::from_bytes(&fixture_scratch.clone(), &bytes).unwrap(),
        retirement: None,
        first_membership: None,
    }
}

#[tokio::test]
async fn invalid_backend_snapshot_never_replaces_durable_recoverable_state() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let store = new_fault_store(disk.clone(), fixture_scratch.clone()).await?;
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(BytesBackend::default()),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    let valid = envelope(b"valid".to_vec(), fixture_scratch.clone());
    machine
        .install_snapshot(
            &valid.meta,
            Box::new(SnapshotBuffer::from_bytes(
                &fixture_scratch.clone(),
                valid.encode(64 << 20)?.read_bounded(64 << 20)?,
                1024,
                &crate::SnapshotBufferOwner::fixture(),
            )?),
        )
        .await?;
    let invalid = envelope(b"invalid".to_vec(), fixture_scratch.clone());
    assert!(
        machine
            .install_snapshot(
                &invalid.meta,
                Box::new(SnapshotBuffer::from_bytes(
                    &fixture_scratch.clone(),
                    invalid.encode(64 << 20)?.read_bounded(64 << 20)?,
                    1024,
                    &crate::SnapshotBufferOwner::fixture()
                )?)
            )
            .await
            .is_err()
    );
    assert_eq!(
        load_snapshot(&store, 1024)?
            .unwrap()
            .backend
            .read_bounded(1024)?,
        b"valid"
    );
    let restored = Arc::new(BytesBackend::default());
    StateMachine::open(
        kasumi_store::test_utils::open_existing_custody_fixture(
            existing_fault_store(disk.crash(), fixture_scratch.clone()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        restored.clone(),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    assert_eq!(*restored.0.lock().unwrap(), b"valid");
    Ok(())
}

#[tokio::test]
async fn first_membership_snapshot_install_reopen_and_substitution_are_bound() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = FaultBackend::new();
    let store = new_fault_store(disk.clone(), fixture_scratch.clone()).await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let mut machine = StateMachine::open(
        domains.clone(),
        Arc::new(BytesBackend::default()),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;

    let first_id = LogId::new(openraft::CommittedLeaderId::new(1, 1), 1);
    let first_membership = openraft::Membership::new(
        vec![std::collections::BTreeSet::from([1])],
        std::collections::BTreeMap::from([(1, BasicNode::new("first"))]),
    );
    let first_entry = Entry::<TypeConfig> {
        log_id: first_id,
        payload: EntryPayload::Membership(first_membership),
    };
    let first_fact = crate::control::FirstAppliedMembership {
        header: LogHeader::build(&first_entry, &encode_entry(&first_entry)?)?.0,
    };
    let later_membership = openraft::Membership::new(
        vec![std::collections::BTreeSet::from([1])],
        std::collections::BTreeMap::from([(1, BasicNode::new("later"))]),
    );
    let mut snapshot = envelope(b"first-snapshot".to_vec(), fixture_scratch.clone());
    snapshot.meta.last_membership = StoredMembership::new(
        Some(LogId::new(openraft::CommittedLeaderId::new(1, 1), 2)),
        later_membership,
    );
    snapshot.first_membership = Some(first_fact.clone());
    let encoded = snapshot.encode(64 << 20)?;
    let decoded = SnapshotEnvelope::decode(encoded.disk(), &mut encoded.reader(), 64 << 20)?;
    assert_eq!(decoded.first_membership, Some(first_fact.clone()));
    machine
        .install_snapshot(
            &snapshot.meta,
            Box::new(SnapshotBuffer::from_bytes(
                &fixture_scratch,
                encoded.read_bounded(64 << 20)?,
                64 << 20,
                &crate::SnapshotBufferOwner::fixture(),
            )?),
        )
        .await?;
    assert_eq!(
        crate::control::first_applied_membership(domains.custody().store())?,
        Some(first_fact.clone())
    );
    assert_eq!(
        load_snapshot(&store, 64 << 20)?.unwrap().first_membership,
        Some(first_fact.clone())
    );

    let substituted = Entry::<TypeConfig> {
        log_id: first_id,
        payload: EntryPayload::Membership(openraft::Membership::new(
            vec![std::collections::BTreeSet::from([1])],
            std::collections::BTreeMap::from([(1, BasicNode::new("substituted"))]),
        )),
    };
    let mut alternate = snapshot.clone();
    alternate.first_membership = Some(crate::control::FirstAppliedMembership {
        header: LogHeader::build(&substituted, &encode_entry(&substituted)?)?.0,
    });
    let alternate_bytes = alternate.encode(64 << 20)?.read_bounded(64 << 20)?;
    assert!(
        machine
            .install_snapshot(
                &alternate.meta,
                Box::new(SnapshotBuffer::from_bytes(
                    &fixture_scratch,
                    alternate_bytes,
                    64 << 20,
                    &crate::SnapshotBufferOwner::fixture(),
                )?),
            )
            .await
            .is_err()
    );
    assert_eq!(
        crate::control::first_applied_membership(domains.custody().store())?,
        Some(first_fact.clone())
    );
    assert_eq!(
        load_snapshot(&store, 64 << 20)?.unwrap().first_membership,
        Some(first_fact.clone())
    );

    let crash = disk.crash();
    drop(machine);
    drop(domains);
    drop(store);
    let reopened_store = existing_fault_store(crash, fixture_scratch).await?;
    let reopened_domains = kasumi_store::test_utils::open_existing_custody_fixture(
        reopened_store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let restored = Arc::new(BytesBackend::default());
    StateMachine::open(
        reopened_domains.clone(),
        restored.clone(),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    assert_eq!(*restored.0.lock().unwrap(), b"first-snapshot");
    assert_eq!(
        crate::control::first_applied_membership(reopened_domains.custody().store())?,
        Some(first_fact.clone())
    );
    assert_eq!(
        load_snapshot(&reopened_store, 64 << 20)?
            .unwrap()
            .first_membership,
        Some(first_fact)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_larger_than_store_record_limit_are_chunked_and_recovered() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let store = TenantStore::initialize_catalog_fixture(
        NodeStore::create_new_fixture(
            dir.path().join("large.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?,
        "large".into(),
        Arc::new(LocalKeyProvider::new([8; 32])),
    )
    .await?;
    let value = envelope(vec![42; 33 * 1024 * 1024], fixture_scratch.clone());
    let bytes = value.encode(64 << 20)?.read_bounded(64 << 20)?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    persist_snapshot(&domains, &bytes, 64 * 1024 * 1024, &value)?;
    assert!(
        load_manifest(&store, b"current", 64 * 1024 * 1024)?
            .unwrap()
            .chunks
            > 8
    );
    assert_eq!(
        load_snapshot(&store, 64 * 1024 * 1024)?
            .unwrap()
            .backend
            .sha256(),
        value.backend.sha256()
    );
    assert!(load_snapshot(&store, 1024).is_err());
    assert!(load_manifest(&store, b"pending", 64 * 1024 * 1024)?.is_none());
    Ok(())
}

#[tokio::test]
async fn snapshot_install_power_loss_at_every_storage_operation_keeps_whole_old_or_new_snapshot()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let seed = FaultBackend::new();
    let old = envelope(b"old-complete-snapshot".to_vec(), fixture_scratch.clone());
    let mut new = envelope(b"new-complete-snapshot".to_vec(), fixture_scratch.clone());
    new.meta.last_log_id.as_mut().unwrap().index += 1;
    let initial = kasumi_store::test_utils::initialize_custody_fixture(
        new_fault_store(seed.clone(), fixture_scratch.clone()).await?,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    persist_snapshot(
        &initial,
        &old.encode(64 << 20)?.read_bounded(64 << 20)?,
        1024,
        &old,
    )?;
    initial.custody().store().shutdown().await.unwrap();
    drop(initial);
    let bytes = new.encode(64 << 20)?.read_bounded(64 << 20)?;
    let baseline = seed.crash();
    let store = existing_fault_store(baseline.clone(), fixture_scratch.clone()).await?;
    let domains = kasumi_store::test_utils::open_existing_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let start = baseline.operations();
    persist_snapshot(&domains, &bytes, 1024, &new)?;
    let operations = baseline.operations() - start;
    ensure!(
        operations > 10,
        "fault test must cover chunk, manifest, cleanup writes and syncs"
    );
    for failure in 0..=operations {
        let disk = seed.crash();
        let store = existing_fault_store(disk.clone(), fixture_scratch.clone()).await?;
        let domains = kasumi_store::test_utils::open_existing_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?;
        disk.fail_after(failure);
        let written = persist_snapshot(&domains, &bytes, 1024, &new);
        let recovered = existing_fault_store(disk.crash(), fixture_scratch.clone()).await?;
        cleanup_snapshots(&recovered, 1024)?;
        let restored = load_snapshot(&recovered, 1024)?.context("snapshot lost")?;
        let recovered_domains = kasumi_store::test_utils::open_existing_custody_fixture(
            recovered.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?;
        validate_snapshot_coverage(&recovered_domains, &restored, 1024)?;
        assert!(
            restored.backend.sha256() == old.backend.sha256()
                || restored.backend.sha256() == new.backend.sha256(),
            "torn snapshot at storage operation {failure}"
        );
        if written.is_ok() {
            assert_eq!(
                restored.backend.sha256(),
                new.backend.sha256(),
                "acknowledged snapshot lost at operation {failure}"
            );
        }
        assert!(load_manifest(&recovered, b"pending", 1024)?.is_none());
        assert!(load_manifest(&recovered, b"obsolete", 1024)?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn raft_open_rejects_missing_initial_identity_without_publishing_it() -> Result<()> {
    let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("missing-raft-identity.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        memory,
        scratch,
    )?;
    let application = TenantStore::initialize_catalog_fixture(
        node.clone(),
        "missing-raft-identity".into(),
        Arc::new(LocalKeyProvider::new([9; 32])),
    )
    .await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        application,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let error = match LogStore::open(domains.clone(), 1).await {
        Ok(_) => anyhow::bail!("Raft open created missing initial identity"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("persisted raft node identity is missing"));
    assert!(domains.custody().store().get(META, b"node_id")?.is_none());
    assert!(domains.custody().store().get(META, b"group")?.is_none());
    domains.shutdown().await?;
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn eight_mib_command_uses_compact_log_record_and_replays_after_reopen() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use openraft::storage::{RaftLogStorageExt, StorageHelper};
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("large-command.kv");
    let bytes = vec![171u8; (8 << 20) + (64 << 10)];
    async fn open(
        path: &std::path::Path,
        create: bool,
        fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    ) -> Result<Arc<TenantStore>> {
        let node = (if create {
            NodeStore::create_new_fixture(
                path,
                kasumi_store::test_utils::NODE_STORE_ID,
                fixture_scratch.memory().clone(),
                fixture_scratch.clone(),
            )
        } else {
            NodeStore::open_existing_fixture(
                path,
                kasumi_store::test_utils::NODE_STORE_ID,
                fixture_scratch.memory().clone(),
                fixture_scratch.clone(),
            )
        })?;
        if create {
            TenantStore::initialize_catalog_fixture(
                node,
                "large-command".into(),
                Arc::new(LocalKeyProvider::new([9; 32])),
            )
            .await
        } else {
            TenantStore::open_existing_fixture(
                node,
                "large-command".into(),
                Arc::new(LocalKeyProvider::new([9; 32])),
            )
            .await
        }
    }
    {
        let store = open(&path, true, fixture_scratch.clone()).await?;
        let domains = kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?;
        domains.write_batch(
            &[],
            &crate::initial_storage_identity(1, "large-command/group")?,
        )?;
        let mut log = LogStore::open(domains, 1).await?;
        let entry = Entry::<TypeConfig> {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 0),
            payload: EntryPayload::Normal(crate::RaftCommand::application(bytes.clone())),
        };
        log.blocking_append([entry.clone()]).await?;
        log.save_committed(Some(entry.log_id)).await?;
        let stored = store.get(LOG, &0u64.to_be_bytes())?.unwrap();
        assert!(stored.starts_with(LOG_FORMAT));
        assert!(
            stored.len() < bytes.len() + 128,
            "command must not expand into JSON integer arrays"
        );
    }
    let store = open(&path, false, fixture_scratch.clone()).await?;
    let mut log = LogStore::open(
        kasumi_store::test_utils::open_existing_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        1,
    )
    .await?;
    let backend = Arc::new(BytesBackend::default());
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::open_existing_custody_fixture(
            store,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        backend.clone(),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    StorageHelper::new(&mut log, &mut machine)
        .get_initial_state()
        .await?;
    assert_eq!(*backend.0.lock().unwrap(), bytes);
    Ok(())
}

#[path = "snapshot_custody_tests.rs"]
mod snapshot_custody_tests;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_materialization_releases_applied_lock_and_keeps_captured_root() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    struct PausedWriter {
        bytes: Mutex<Vec<u8>>,
        entered: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
        release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    }
    impl StateMachineBackend for PausedWriter {
        fn close_application(&self) {}
        fn apply(
            &self,
            _: &crate::AppliedEntryContext,
            bytes: &[u8],
        ) -> Result<crate::AppliedResponse> {
            *self.bytes.lock().unwrap() = bytes.to_vec();
            Ok(crate::AppliedResponse::application(bytes.to_vec()))
        }
        fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
            let bytes = self.bytes.lock().unwrap().clone();
            let entered = self.entered.clone();
            let release = self.release.clone();
            Ok(crate::CapturedSnapshot::new(None, move |writer| {
                if let Some(sender) = entered.lock().unwrap().take() {
                    sender.send(()).unwrap();
                    release
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(10))?;
                }
                writer.write_all(&bytes)?;
                Ok(())
            }))
        }
        fn validate_snapshot(
            &self,
            _: &mut dyn Read,
        ) -> Result<Option<crate::RetiredSnapshotState>> {
            Ok(None)
        }
        fn prepare_restore<'a>(
            &'a self,
            _context: &crate::SnapshotRestoreContext,
            _: &mut dyn Read,
        ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
            Ok(Box::new(PreparedFixtureRestore {
                retirement: None,
                commit: Box::new(|| Ok(())),
            }))
        }
    }
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let backend = Arc::new(PausedWriter {
        bytes: Mutex::new(b"captured-root".to_vec()),
        entered: Arc::new(Mutex::new(Some(entered))),
        release: Arc::new(Mutex::new(wait)),
    });
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::initialize_custody_fixture(
            new_fault_store(FaultBackend::new(), fixture_scratch.clone()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        backend.clone(),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    let mut capturing = machine.clone();
    let task = tokio::spawn(async move {
        let mut builder = capturing.get_snapshot_builder().await;
        builder.build_snapshot().await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), ready).await??;
    tokio::time::timeout(std::time::Duration::from_secs(1), machine.applied_state()).await??;
    // A new generation can publish while the old snapshot is materializing.
    *backend.bytes.lock().unwrap() = b"new-root".to_vec();
    release.send(())?;
    let snapshot = task.await??;
    let envelope = {
        let image = snapshot.snapshot.into_image()?;
        SnapshotEnvelope::decode(image.disk(), &mut image.reader(), 64 << 20)?
    };
    assert_eq!(envelope.backend.read_bounded(1024)?, b"captured-root");
    assert_eq!(*backend.bytes.lock().unwrap(), b"new-root");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_storage_metadata_requires_current_writer_bytes_and_v4_id() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let store = TenantStore::initialize_catalog_fixture(
        NodeStore::create_new_fixture(
            directory.path().join("manifest.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            scratch.memory().clone(),
            scratch.clone(),
        )?,
        "manifest".into(),
        Arc::new(LocalKeyProvider::new([8; 32])),
    )
    .await?;
    let manifest = SnapshotManifest {
        version: 1,
        sha256: "11".repeat(32),
        id: uuid::Uuid::new_v4().to_string(),
        bytes: 1,
        chunks: 1,
    };
    let canonical = serde_json::to_vec(&manifest)?;
    store.write_batch(&[put(SNAPSHOT, b"current", canonical.clone())])?;
    assert!(load_manifest(&store, b"current", 1024)?.is_some());

    let mut unknown = canonical.clone();
    assert_eq!(unknown.pop(), Some(b'}'));
    unknown.extend_from_slice(b",\"legacy\":true}");
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical);
    for bytes in [unknown, noncanonical] {
        store.write_batch(&[put(SNAPSHOT, b"current", bytes)])?;
        assert!(load_manifest(&store, b"current", 1024).is_err());
    }

    // These are canonical JSON, but the ID is not the writer's exact RFC v4 form.
    for id in [
        uuid::Uuid::parse_str(&manifest.id)?.simple().to_string(),
        format!("{{{}}}", manifest.id),
        uuid::Uuid::nil().to_string(),
        "123e4567-e89b-42d3-0123-426614174000".to_owned(),
    ] {
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert!(!current_snapshot_id(&id));
        let mut alternate = manifest.clone();
        alternate.id = id;
        store.write_batch(&[put(SNAPSHOT, b"current", serde_json::to_vec(&alternate)?)])?;
        assert!(load_manifest(&store, b"current", 1024).is_err());
    }

    let coverage = SnapshotCoverage {
        kind: SnapshotKind::Application,
        manifest_id: manifest.id,
        snapshot_sha256: manifest.sha256,
        backend_sha256: "22".repeat(32),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: uuid::Uuid::new_v4().to_string(),
        },
    };
    let canonical = serde_json::to_vec(&coverage)?;
    store.write_batch(&[put(META, b"snapshot_coverage", canonical.clone())])?;
    assert!(load_snapshot_coverage(&store)?.is_some());
    assert!(crate::control::committed_coverage(&store)?.is_none());
    let mut unknown = canonical.clone();
    assert_eq!(unknown.pop(), Some(b'}'));
    unknown.extend_from_slice(b",\"legacy\":true}");
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical);
    for bytes in [unknown, noncanonical] {
        store.write_batch(&[put(META, b"snapshot_coverage", bytes)])?;
        assert!(load_snapshot_coverage(&store).is_err());
        assert!(crate::control::committed_coverage(&store).is_err());
    }
    for alias in [
        uuid::Uuid::parse_str(&coverage.meta.snapshot_id)?
            .simple()
            .to_string(),
        uuid::Uuid::nil().to_string(),
    ] {
        let mut alternate = coverage.clone();
        alternate.meta.snapshot_id = alias;
        store.write_batch(&[put(
            META,
            b"snapshot_coverage",
            serde_json::to_vec(&alternate)?,
        )])?;
        assert!(load_snapshot_coverage(&store).is_err());
        assert!(crate::control::committed_coverage(&store).is_err());
    }
    let mut alternate = coverage.clone();
    alternate.manifest_id = uuid::Uuid::nil().to_string();
    store.write_batch(&[put(
        META,
        b"snapshot_coverage",
        serde_json::to_vec(&alternate)?,
    )])?;
    assert!(load_snapshot_coverage(&store).is_err());
    assert!(crate::control::committed_coverage(&store).is_err());

    let mut invalid_digest = coverage.clone();
    invalid_digest.backend_sha256 = "AA".repeat(32);
    store.write_batch(&[put(
        META,
        b"snapshot_coverage",
        serde_json::to_vec(&invalid_digest)?,
    )])?;
    assert!(load_snapshot_coverage(&store).is_err());
    assert!(crate::control::committed_coverage(&store).is_err());

    let mut alternate = envelope(vec![], scratch);
    alternate.meta.snapshot_id = uuid::Uuid::parse_str(&alternate.meta.snapshot_id)?
        .simple()
        .to_string();
    let image = alternate.encode(1 << 20)?;
    assert!(SnapshotEnvelope::decode(image.disk(), &mut image.reader(), 1 << 20).is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coverage_writer_refuses_one_byte_past_reader_limit_before_staging() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let store = TenantStore::initialize_catalog_fixture(
        NodeStore::create_new_fixture(
            directory.path().join("coverage-boundary.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            scratch.memory().clone(),
            scratch.clone(),
        )?,
        "coverage-boundary".into(),
        Arc::new(LocalKeyProvider::new([8; 32])),
    )
    .await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let membership = |address: String| {
        StoredMembership::new(
            None,
            openraft::Membership::from(std::collections::BTreeMap::from([(
                1u64,
                BasicNode::new(address),
            )])),
        )
    };
    let mut snapshot = envelope(vec![], scratch);
    snapshot.meta.last_membership = membership(String::new());
    let base = snapshot.encode(4 << 20)?.read_bounded(4 << 20)?;
    assert_eq!(base[8], 1, "first snapshot frame must be metadata");
    let base_metadata_len = usize::try_from(u64::from_be_bytes(base[9..17].try_into()?))?;
    let address_len = MAX_SNAPSHOT_COVERAGE_BYTES
        .checked_sub(base_metadata_len + 192)
        .context("base metadata exceeds coverage budget")?;
    snapshot.meta.last_membership = membership("x".repeat(address_len));
    let accepted_bytes = snapshot.encode(4 << 20)?.read_bounded(4 << 20)?;
    assert_eq!(
        usize::try_from(u64::from_be_bytes(accepted_bytes[9..17].try_into()?))?,
        MAX_SNAPSHOT_COVERAGE_BYTES - 192
    );
    persist_snapshot(&domains, &accepted_bytes, 4 << 20, &snapshot)?;
    let old_manifest = store.get(SNAPSHOT, b"current")?.context("current absent")?;
    let old_coverage = domains
        .custody()
        .store()
        .get(META, b"snapshot_coverage")?
        .context("coverage absent")?;
    assert_eq!(old_coverage.len(), MAX_SNAPSHOT_COVERAGE_BYTES);
    assert!(load_snapshot_coverage(domains.custody().store())?.is_some());

    let mut oversized = snapshot.clone();
    oversized.meta.last_membership = membership("x".repeat(address_len + 1));
    let oversized_image = oversized.encode(4 << 20)?;
    let oversized_bytes = oversized_image.read_bounded(4 << 20)?;
    assert_eq!(
        usize::try_from(u64::from_be_bytes(oversized_bytes[9..17].try_into()?))?,
        MAX_SNAPSHOT_COVERAGE_BYTES - 191
    );
    let error = stage_snapshot(&domains, &oversized_image, 4 << 20, &oversized)
        .err()
        .context("oversized coverage was staged")?;
    assert!(
        error
            .to_string()
            .contains("snapshot coverage exceeds byte limit")
    );
    assert_eq!(store.get(SNAPSHOT, b"current")?, Some(old_manifest));
    assert!(store.get(SNAPSHOT, b"pending")?.is_none());
    assert_eq!(
        domains.custody().store().get(META, b"snapshot_coverage")?,
        Some(old_coverage)
    );
    let mut reopened = StateMachine::open(
        domains,
        Arc::new(BytesBackend::default()),
        crate::SnapshotBufferOwner::fixture(),
    )
    .await?;
    assert_eq!(reopened.applied_state().await?.0, snapshot.meta.last_log_id);
    Ok(())
}
