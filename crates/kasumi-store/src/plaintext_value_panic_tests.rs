//! Real installed provider callbacks through the ordinary point-owner APIs.
use crate::{
    NodeDisk, NodeDiskMemoryAdmission, NodeReadPhase, NodeScopedReadFailure, NodeStore,
    RegisteredNodeRead, ScratchDisk, StorageCensusDisposition, TenantPointReadFailure, TenantStore,
    WriteOp,
    test_utils::{
        LocalKeyProvider, ManualClock, TestDiskMemory, node_storage_config, private_tempdir,
        retry_disk_registry, source_quote_observer,
    },
};
use anyhow::Result;
use kasumi_kv::{ReadCloseSettlement, TerminalObservation};
use kasumi_types::drain::DrainCompletion;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const VALUE_BYTES: usize = 48 << 10;

struct Fixture {
    store: Arc<TenantStore>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let path = directory.path().join("point-callback-panic.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        assert!(!node.body().db.has_fixture_direct_database());
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([97; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        let value = vec![0x73; VALUE_BYTES];
        store.write_batch(&[WriteOp::put("docs", b"key", value.as_slice())])?;
        // Warm optional native cache backing before measuring failed work.
        drop(store.get_bounded("docs", b"key", VALUE_BYTES)?);
        Ok(Self {
            store,
            node,
            memory,
            _directory: directory,
            _scratch: scratch,
        })
    }

    fn plaintext_request() -> Result<u64> {
        Ok(crate::disk_memory::allocation::<u8>(
            (12 + "docs".len() + b"key".len() + VALUE_BYTES) as u64,
        )?)
    }

    fn finished_reader_bytes(&self) -> Result<u64> {
        let baseline = self.memory.snapshot();
        let reader = self.node.begin_registered_read()?;
        assert_eq!(reader.finish(), NodeReadPhase::Finished);
        let held = self.memory.snapshot().used_bytes - baseline.used_bytes;
        assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
        assert_eq!(self.memory.snapshot().used_bytes, baseline.used_bytes);
        Ok(held)
    }
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

fn original_panic(marker: u64) -> (Box<OriginalPanic>, usize, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = Box::new(OriginalPanic {
        marker,
        drops: drops.clone(),
    });
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    (payload, address, drops)
}

fn assert_original_body(reader: &RegisteredNodeRead, marker: u64, address: usize) {
    let report = reader.report();
    let TerminalObservation::Panicked(payload) = report.body_panic() else {
        panic!("installed admission panic lost its original payload");
    };
    let original = payload.downcast_ref::<OriginalPanic>().unwrap();
    assert_eq!(original.marker, marker);
    assert_eq!(std::ptr::from_ref(original) as usize, address);
}

#[tokio::test]
async fn installed_point_admission_panic_stays_in_exact_child_after_finish_and_drain() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let finished_reader_bytes = fixture.finished_reader_bytes()?;
    let baseline = fixture.memory.snapshot();
    let (payload, address, drops) = original_panic(0xc011_b0d1);
    fixture
        .memory
        .panic_on_next_point_reservation(Fixture::plaintext_request()?, payload);
    let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
        fixture.store.get_bounded("docs", b"key", VALUE_BYTES)
    });
    let failure = result
        .expect_err("provider panic must produce retained failure, never output")
        .downcast::<TenantPointReadFailure>()?;
    assert_eq!(failure.stage(), "body panic");
    assert!(failure.validation_error().is_none());
    let reader = failure.reader();
    let id = reader.id();
    assert_eq!(reader.phase(), NodeReadPhase::Finished);
    assert_original_body(reader, 0xc011_b0d1, address);
    {
        let report = reader.report();
        let close = report.close().unwrap();
        assert_eq!(close.settlement(), ReadCloseSettlement::Disposed);
        assert!(!close.retains_transaction());
        assert!(matches!(
            close.disposal(),
            TerminalObservation::Returned(Ok(()))
        ));
    }
    assert!(!observed.overflow);
    let plaintext_charge =
        TestDiskMemory::required_reservation_bytes(Fixture::plaintext_request()?)?;
    assert!(
        !observed.requests[..observed.count].contains(&plaintext_charge),
        "panic callback admitted an escaping plaintext allocation"
    );
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        baseline.used_bytes + finished_reader_bytes,
        "native/ciphertext/output capacity escaped failed work"
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 1);
    let attempts = fixture.memory.snapshot().attempts;
    drop(failure);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        fixture.memory.snapshot().attempts,
        attempts,
        "drain requested fresh admission"
    );
    fixture.store.shutdown().await?;
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    assert_original_body(&retained, 0xc011_b0d1, address);
    assert_eq!(retained.finish(), NodeReadPhase::Finished);
    // The original panic has now been inspected and native disposal positively
    // proved. Explicit acknowledgment retires that exact child without reopen.
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn installed_point_body_panic_and_native_disposal_panic_preserve_both_originals() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let (body, body_address, body_drops) = original_panic(0xc011_b0d2);
    let (finish, finish_address, finish_drops) = original_panic(0xc011_f1a1);
    fixture
        .memory
        .panic_on_next_point_reservation(Fixture::plaintext_request()?, body);
    let native_request = crate::node_file::segment_group::workspace_provider_request_bytes(
        kasumi_kv::ProtectedReadRequests::snapshot_backing_request_bytes(),
    )?;
    fixture
        .memory
        .panic_on_next_matching_point_lease_drop(native_request, finish);
    let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
        fixture.store.get_bounded("docs", b"key", VALUE_BYTES)
    });
    let failure = result
        .expect_err("two real callback panics must return exact retained child")
        .downcast::<TenantPointReadFailure>()?;
    assert_eq!(failure.stage(), "body panic");
    let id = failure.reader().id();
    assert_eq!(failure.reader().phase(), NodeReadPhase::Retained);
    assert_original_body(failure.reader(), 0xc011_b0d2, body_address);
    assert!(!observed.overflow);
    assert!(
        observed.requests[..observed.count]
            .contains(&TestDiskMemory::required_reservation_bytes(native_request)?),
        "fault did not target a real native snapshot constructor"
    );
    let assert_close = |reader: &RegisteredNodeRead| {
        let report = reader.report();
        let close = report.close().unwrap();
        assert_eq!(close.settlement(), ReadCloseSettlement::DisposalUncertain);
        assert!(!close.retains_transaction());
        assert!(
            close.retains_database(),
            "uncertain native disposal shed its observer"
        );
        assert!(matches!(
            close.release(),
            TerminalObservation::Returned(Ok(()))
        ));
        let TerminalObservation::Panicked(payload) = close.disposal() else {
            panic!("native disposal replaced or lost its original callback panic");
        };
        let original = payload.downcast_ref::<OriginalPanic>().unwrap();
        assert_eq!(original.marker, 0xc011_f1a1);
        assert_eq!(std::ptr::from_ref(original) as usize, finish_address);
    };
    assert_close(failure.reader());
    let attempts = fixture.memory.snapshot().attempts;
    assert_eq!(failure.reader().finish(), NodeReadPhase::Retained);
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    drop(failure);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    assert_original_body(&retained, 0xc011_b0d2, body_address);
    assert_close(&retained);
    assert_eq!(retained.finish(), NodeReadPhase::Retained);
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
    assert_eq!(
        fixture.memory.snapshot().attempts,
        attempts,
        "uncertain disposal was replayed or readmitted"
    );
    fixture.store.shutdown().await?;
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    assert_original_body(&retained, 0xc011_b0d2, body_address);
    assert_close(&retained);
    assert_eq!(body_drops.load(Ordering::Acquire), 0);
    assert_eq!(finish_drops.load(Ordering::Acquire), 0);
    // An uncertain native destructor remains installed. This test deliberately
    // leaves exact original custody; a synthetic reset would fake disposal.
    drop(retained);
    Ok(())
}

#[tokio::test]
async fn installed_pinned_point_admission_panic_survives_view_close_and_error_aliases() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let view = fixture.store.read_view()?;
    let id = view.registered_reader_id().unwrap();
    let (payload, address, drops) = original_panic(0xc011_b0d3);
    fixture
        .memory
        .panic_on_next_point_reservation(Fixture::plaintext_request()?, payload);
    let failure = view
        .get("docs", b"key", VALUE_BYTES)
        .expect_err("pinned provider panic must not escape as output or unwind")
        .downcast::<NodeScopedReadFailure>()?;
    assert_eq!(failure.reader_id(), id);
    assert_eq!(failure.stage(), "view read");
    let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    assert_original_body(&retained, 0xc011_b0d3, address);
    assert_eq!(
        failure.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    drop(retained);
    let close = view
        .close()
        .unwrap_err()
        .downcast::<NodeScopedReadFailure>()?;
    assert_eq!(close.reader_id(), id);
    assert_eq!(close.phase(), NodeReadPhase::Finished);
    assert_eq!(
        close.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    {
        let report = close.report();
        let native = report.close().unwrap();
        assert_eq!(native.settlement(), ReadCloseSettlement::Disposed);
        assert!(!native.retains_transaction());
    }
    drop(failure);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(close);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    fixture.store.shutdown().await?;
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    assert_original_body(&retained, 0xc011_b0d3, address);
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    fixture.node.shutdown().await?;
    Ok(())
}
