//! Installed pinned-root visitation retains one admitted plaintext backing.
use super::*;
use crate::test_utils::{
    LocalKeyProvider, ManualClock, TestDiskMemory, TestDiskMemorySnapshot, node_storage_config,
    private_tempdir, retry_disk_registry, source_quote_observer,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const VALUE_BYTES: usize = 48 << 10;
const PLAINTEXT_BYTES: usize = 12 + 4 + 3 + VALUE_BYTES;

struct Fixture {
    store: Arc<TenantStore>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    clock: Arc<ManualClock>,
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let path = directory.path().join("ordinary-pinned-visit.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            &path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        assert!(!node.body().db.has_fixture_direct_database());
        let clock = Arc::new(ManualClock::new());
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([101; 32])),
            clock.clone(),
        )
        .await?;
        store.write_batch(&[WriteOp::put("docs", b"key", vec![0x41; VALUE_BYTES])])?;
        Ok(Self {
            store,
            node,
            memory,
            clock,
            _directory: directory,
            _scratch: scratch,
        })
    }
    fn warmed_view(&self) -> Result<TenantReadView> {
        let view = self.store.read_view()?;
        view.visit("docs", VALUE_BYTES, |_, _| Ok(()))?;
        Ok(view)
    }
    async fn shutdown(self) -> Result<()> {
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
fn plaintext_request() -> Result<u64> {
    Ok(disk_memory::allocation::<u8>(PLAINTEXT_BYTES as u64)?)
}
fn plaintext_charge() -> Result<u64> {
    Ok(TestDiskMemory::required_reservation_bytes(
        plaintext_request()?,
    )?)
}
fn assert_baseline(memory: &TestDiskMemory, baseline: TestDiskMemorySnapshot) {
    let current = memory.snapshot();
    assert_eq!(current.used_bytes, baseline.used_bytes);
    assert_eq!(current.live_reservations, baseline.live_reservations);
}

#[tokio::test]
async fn pinned_visit_keeps_selected_root_and_borrows_one_admitted_record() -> Result<()> {
    let fixture = Fixture::new().await?;
    let view = fixture.warmed_view()?;
    let id = view.registered_reader_id().unwrap();
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", vec![0x42; VALUE_BYTES])])?;
    view.visit("docs", VALUE_BYTES, |_, _| Ok(()))?;
    let baseline = fixture.memory.snapshot();
    let charge = plaintext_charge()?;
    let mut calls = 0;
    let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
        view.visit("docs", VALUE_BYTES, |key, value| {
            assert_eq!(key, b"key");
            assert_eq!(value.len(), VALUE_BYTES);
            assert!(value.iter().all(|byte| *byte == 0x41));
            assert_eq!(value.as_ptr(), key.as_ptr().wrapping_add(key.len() + 4));
            let current = fixture.memory.snapshot();
            assert!(current.used_bytes >= baseline.used_bytes + charge);
            assert!(current.live_reservations > baseline.live_reservations);
            calls += 1;
            Ok(())
        })
    });
    result?;
    assert_eq!(calls, 1);
    assert_eq!(view.registered_reader_id(), Some(id));
    assert!(!observed.overflow);
    assert!(observed.requests[..observed.count].contains(&charge));
    assert_baseline(&fixture.memory, baseline);
    let current = fixture
        .store
        .get_bounded("docs", b"key", VALUE_BYTES)?
        .unwrap();
    assert!(current.iter().all(|byte| *byte == 0x42));
    drop(current);
    view.close()?;
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    fixture.shutdown().await
}

#[derive(Debug)]
struct OriginalCallbackError(Arc<()>);
impl std::fmt::Display for OriginalCallbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original ordinary visitor error")
    }
}
impl std::error::Error for OriginalCallbackError {}

#[tokio::test]
async fn callback_error_and_credential_expiry_release_the_actual_plaintext_backing() -> Result<()> {
    let fixture = Fixture::new().await?;
    let view = fixture.warmed_view()?;
    let baseline = fixture.memory.snapshot();
    let marker = Arc::new(());
    let error = view
        .visit("docs", VALUE_BYTES, |_, _| {
            assert!(
                fixture.memory.snapshot().used_bytes >= baseline.used_bytes + plaintext_charge()?
            );
            Err(OriginalCallbackError(marker.clone()).into())
        })
        .unwrap_err();
    assert!(Arc::ptr_eq(
        &error.downcast_ref::<OriginalCallbackError>().unwrap().0,
        &marker
    ));
    assert_baseline(&fixture.memory, baseline);
    drop(error);
    view.visit("docs", VALUE_BYTES, |_, _| Ok(()))?;
    let expired = view
        .visit("docs", VALUE_BYTES, |_, _| {
            fixture
                .clock
                .advance(MAX_KEY_LEASE + Duration::from_nanos(1));
            Ok(())
        })
        .unwrap_err();
    assert_baseline(&fixture.memory, baseline);
    drop(expired);
    let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
        view.visit("empty", VALUE_BYTES, |_, _| {
            panic!("expired visit called visitor")
        })
    });
    assert!(result.is_err());
    assert_eq!(observed.count, 0);
    assert_baseline(&fixture.memory, baseline);
    drop(result);
    view.close()?;
    fixture.shutdown().await
}

struct OriginalPanic {
    marker: u64,
    drops: Arc<AtomicUsize>,
}
impl Drop for OriginalPanic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn callback_and_installed_admission_panics_remain_on_the_same_pinned_reader() -> Result<()> {
    for at_admission in [false, true] {
        let fixture = Fixture::new().await?;
        let view = fixture.warmed_view()?;
        let id = view.registered_reader_id().unwrap();
        let baseline = fixture.memory.snapshot();
        let drops = Arc::new(AtomicUsize::new(0));
        let marker = if at_admission { 0xada1 } else { 0xcab1 };
        let mut payload = Some(Box::new(OriginalPanic {
            marker,
            drops: drops.clone(),
        }));
        let address = std::ptr::from_ref(payload.as_ref().unwrap().as_ref()) as usize;
        if at_admission {
            fixture
                .memory
                .panic_on_next_point_reservation(plaintext_request()?, payload.take().unwrap());
        }
        let mut called = false;
        let failure = view
            .visit("docs", VALUE_BYTES, |_, _| {
                called = true;
                std::panic::resume_unwind(payload.take().unwrap())
            })
            .unwrap_err()
            .downcast::<NodeScopedReadFailure>()?;
        assert_eq!(called, !at_admission);
        assert_eq!(failure.reader_id(), id);
        assert_baseline(&fixture.memory, baseline);
        {
            let report = failure.report();
            let kasumi_kv::TerminalObservation::Panicked(original) = report.body_panic() else {
                panic!("ordinary visitor lost the original panic");
            };
            let original = original.downcast_ref::<OriginalPanic>().unwrap();
            assert_eq!(original.marker, marker);
            assert_eq!(std::ptr::from_ref(original) as usize, address);
        }
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        let close = view
            .close()
            .unwrap_err()
            .downcast::<NodeScopedReadFailure>()?;
        assert_eq!(close.reader_id(), id);
        assert_eq!(close.phase(), NodeReadPhase::Finished);
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop((failure, close));
        let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_authenticated_record_and_value_bound_never_reach_callback() -> Result<()> {
    let fixture = Fixture::new().await?;
    let view = fixture.warmed_view()?;
    let baseline = fixture.memory.snapshot();
    let mut called = false;
    let error = view
        .visit("docs", VALUE_BYTES - 1, |_, _| {
            called = true;
            Ok(())
        })
        .unwrap_err();
    assert!(!called);
    assert_baseline(&fixture.memory, baseline);
    drop(error);
    view.close()?;

    // Authenticated but misbound contents must retire the admitted plaintext
    // before returning, without manufacturing another root or output copy.
    let disk_key = {
        let state = fixture.store.state.read();
        inline_record_key(
            &fixture.store.tenant,
            "docs",
            b"key",
            state.keys.get(INDEX_KEY).unwrap(),
        )
    };
    let envelope = {
        let state = fixture.store.state.read();
        let catalog = fixture.store.catalog.read();
        let mut envelope = Vec::new();
        append_bytes(&mut envelope, catalog.active.as_bytes())?;
        envelope.extend(encrypt(
            state.keys.get(&catalog.active).unwrap(),
            &encode_plain_record("docs", b"other", b"value")?,
            &record_aad(&fixture.store.tenant, &disk_key),
        )?);
        envelope
    };
    let transaction = fixture.node.body().db.begin_write()?;
    transaction
        .open_table(RECORDS)?
        .insert(&disk_key[..], &envelope[..])?;
    transaction.commit()?;
    let corrupt = fixture.store.read_view()?;
    let _ = corrupt.visit("docs", VALUE_BYTES, |_, _| Ok(()));
    let baseline = fixture.memory.snapshot();
    let error = corrupt
        .visit("docs", VALUE_BYTES, |_, _| {
            panic!("misbound record reached callback")
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("encrypted record identity mismatch"));
    assert_baseline(&fixture.memory, baseline);
    drop(error);
    corrupt.close()?;
    fixture.shutdown().await
}
