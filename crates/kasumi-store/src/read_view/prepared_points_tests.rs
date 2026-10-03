use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock, TestDiskMemory, private_tempdir};

struct Fixture {
    store: Arc<TenantStore>,
    node: Arc<NodeStore>,
    memory: Arc<TestDiskMemory>,
    clock: Arc<ManualClock>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        crate::private_files::create_directory(&directory.path().join("persistent"))?;
        let memory = TestDiskMemory::new(64 << 20, 128);
        let scratch = ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
        let path = directory.path().join("persistent/node.kv");
        let disk = crate::test_utils::retry_disk_registry(|| {
            NodeDisk::fixture_for_path(&path, memory.clone())
        })?;
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch,
            crate::test_utils::node_storage_config(),
        )?;
        let clock = Arc::new(ManualClock::default());
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "single-points".into(),
            Arc::new(LocalKeyProvider::new([79; 32])),
            clock.clone(),
        )
        .await?;
        Ok(Self {
            store,
            node,
            memory,
            clock,
            _directory: directory,
        })
    }
    async fn close(self) -> Result<()> {
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn single_points_share_exact_root_and_reuse_backing_without_point_admission() -> Result<()> {
    let fixture = Fixture::new().await?;
    let long = vec![57; 8193];
    fixture.store.write_batch(&[
        WriteOp::put("payload", b"long", long.as_slice()),
        WriteOp::put("payload", b"short", b"short"),
    ])?;
    let baseline = fixture.memory.snapshot();
    let mut session = fixture
        .store
        .read_view()?
        .prepare_point_reads(7, 8, long.len())?;
    let id = session
        .registered_reader_id()
        .expect("real registered snapshot");
    let plaintext = session.workspace.backing.plaintext.as_ptr();
    let aad = session.workspace.backing.aad.as_ptr();
    fixture
        .store
        .write_batch(&[WriteOp::put("payload", b"long", b"new")])?;
    // This fixture's default native cache is disabled. Any point admission or
    // allocation after preparing the actual backing is an observable regression.
    let ((result, requests), allocations, bytes) =
        crate::allocation_tests::measure_requested(|| {
            crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
                assert_eq!(
                    session.get("payload", b"long", long.len())?,
                    Some(long.as_slice())
                );
                assert_eq!(
                    session.get("payload", b"short", long.len())?,
                    Some(b"short".as_slice())
                );
                let used = 12 + "payload".len() + b"short".len() + b"short".len();
                assert!(
                    session.workspace.backing.plaintext[used..]
                        .iter()
                        .all(|byte| *byte == 0)
                );
                assert!(session.get("payload", b"absent", long.len())?.is_none());
                assert!(
                    session
                        .workspace
                        .backing
                        .plaintext
                        .iter()
                        .all(|byte| *byte == 0)
                );
                Ok::<_, anyhow::Error>(())
            })
        });
    result?;
    assert_eq!((requests.count, allocations, bytes), (0, 0, 0));
    assert_eq!(session.workspace.backing.plaintext.as_ptr(), plaintext);
    assert_eq!(session.workspace.backing.aad.as_ptr(), aad);
    assert_eq!(session.registered_reader_id(), Some(id));
    assert_eq!(
        session.get("payload", b"long", long.len())?,
        Some(long.as_slice())
    );
    assert!(session.get("payload", b"long", long.len() + 1).is_err());
    assert!(
        session
            .workspace
            .backing
            .plaintext
            .iter()
            .all(|byte| *byte == 0)
    );
    session.close()?;
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    // Compare point backing after retiring the read snapshot. The intervening
    // write can retain independent native state, so compare lease counts only.
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    let mut current = fixture
        .store
        .read_view()?
        .prepare_point_reads(7, 8, long.len())?;
    assert_eq!(
        current.get("payload", b"long", long.len())?,
        Some(b"new".as_slice())
    );
    current.close()?;
    fixture.close().await
}

#[tokio::test]
async fn single_points_check_expiry_on_old_root_hits_and_absence_and_clear_failed_loans()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .store
        .write_batch(&[WriteOp::put("payload", b"key", b"secret")])?;
    let mut session = fixture.store.read_view()?.prepare_point_reads(7, 8, 64)?;
    assert_eq!(
        session.get("payload", b"key", 64)?,
        Some(b"secret".as_slice())
    );
    fixture.clock.advance(Duration::from_secs(301));
    for key in [b"key".as_slice(), b"absent".as_slice()] {
        assert!(session.get("payload", key, 64).is_err());
        assert!(
            session
                .workspace
                .backing
                .plaintext
                .iter()
                .all(|byte| *byte == 0)
        );
    }
    session.close()?;
    fixture.close().await
}

#[tokio::test]
async fn single_point_partial_admission_denial_keeps_actual_failure_and_has_no_allocating_fallback()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .store
        .write_batch(&[WriteOp::put("payload", b"key", b"secret")])?;
    let baseline = fixture.memory.snapshot();
    let view = fixture.store.read_view()?;
    let id = view.registered_reader_id().expect("real registered owner");
    let mut blockers = Vec::new();
    while fixture.memory.snapshot().live_reservations < 125 {
        blockers.push(fixture.memory.clone().reserve_installed(0)?);
    }
    // Exactly three of the four mandatory point grants fit; the real native
    // output reservation fails, preserving its original registered report.
    let error = match view.prepare_point_reads(7, 8, 64) {
        Ok(session) => {
            session.close()?;
            panic!("partial admission unexpectedly succeeded")
        }
        Err(error) => error,
    };
    let failure = error
        .downcast_ref::<NodeScopedReadFailure>()
        .expect("actual failure custody");
    assert!(matches!(
        failure.report().read_failure(),
        kasumi_kv::TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::Storage(
            kasumi_kv::StorageError::Core(kasumi_kv::CoreError::CapacityDenied)
        )))
    ));
    assert_eq!(failure.reader_id(), id);
    drop(error);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    drop(blockers);
    assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    let mut retry = fixture.store.read_view()?.prepare_point_reads(7, 8, 64)?;
    assert_eq!(
        retry.get("payload", b"key", 64)?,
        Some(b"secret".as_slice())
    );
    retry.close()?;
    fixture.close().await
}

#[tokio::test]
async fn single_point_finish_keeps_original_error_and_actual_retirement_panic() -> Result<()> {
    for transfer in [false, true] {
        let fixture = Fixture::new().await?;
        let session = fixture.store.read_view()?.prepare_point_reads(7, 8, 64)?;
        let id = session.registered_reader_id().unwrap();
        let original = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "original single point",
        );
        fixture
            .memory
            .panic_on_last_point_lease_drop(Box::new(0x715_u64));
        let error = if transfer {
            session
                .finish_with_workspace::<()>(Err(original.into()))
                .err()
                .expect("original transfer failure")
        } else {
            session.finish::<()>(Err(original.into())).unwrap_err()
        };
        let failure = error
            .downcast_ref::<crate::NodeScopedReadFailure>()
            .unwrap();
        assert_eq!(failure.reader_id(), id);
        let original = failure
            .body_error()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(original.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(original.to_string(), "original single point");
        for _ in 0..2 {
            assert_eq!(
                failure.try_retire_routine(),
                StorageCensusDisposition::Retained
            );
            let report = failure.report();
            let kasumi_kv::TerminalObservation::Panicked(payload) = report.body_panic() else {
                panic!("single point retirement payload missing");
            };
            assert_eq!(payload.downcast_ref::<u64>(), Some(&0x715));
        }
        drop(error);
        assert_eq!(
            RegisteredNodeRead::retained(fixture.memory.clone(), id)
                .unwrap()
                .retire(),
            StorageCensusDisposition::Retired
        );
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn single_point_shape_growth_uses_actual_old_root_and_keeps_original_on_refusal() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let payload = vec![43; 8193];
    fixture
        .store
        .write_batch(&[WriteOp::put("payload", b"key", payload.as_slice())])?;
    let mut session = fixture.store.read_view()?.prepare_point_reads(7, 8, 64)?;
    let id = session.registered_reader_id();
    let bound = session.value_bound("payload", b"key", 16384)?.unwrap();
    assert!(bound >= payload.len() && bound < payload.len() + 128);
    let before = fixture.memory.snapshot();
    let original_plaintext = session.workspace.backing.plaintext.as_ptr();
    let mut blockers = Vec::new();
    while let Ok(lease) = fixture.memory.clone().reserve_installed(0) {
        blockers.push(lease);
    }
    assert!(session.ensure_capacity(7, 8, bound).is_err());
    assert_eq!(
        session.workspace.backing.plaintext.as_ptr(),
        original_plaintext
    );
    assert_eq!(session.registered_reader_id(), id);
    drop(blockers);
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    fixture
        .store
        .write_batch(&[WriteOp::put("payload", b"key", b"new")])?;
    session.ensure_capacity(7, 8, bound)?;
    assert_eq!(
        session.get("payload", b"key", bound)?,
        Some(payload.as_slice())
    );
    let (_, workspace) = session.finish_with_workspace(Ok(()))?;
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert!(workspace.backing.plaintext.iter().all(|byte| *byte == 0));
    workspace.retire().expect("actual point backing retirement");
    fixture.close().await
}
