use super::*;
use crate::{
    NodeDisk, NodeStore, ScratchDisk, TenantStore, WriteOp, allocation_tests,
    test_utils::{
        LocalKeyProvider, ManualClock, TestDiskMemory, node_storage_config, private_tempdir,
        retry_disk_registry, source_quote_observer,
    },
};
use anyhow::Result;
use std::{
    alloc::Layout,
    time::{Duration, Instant},
};
const VALUE_BYTES: usize = 128 << 10;
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
        let path = directory.path().join("retained-point.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            &path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([83; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        store.write_batch(&[WriteOp::put("docs", b"key", vec![0x63; VALUE_BYTES])])?;
        drop(store.get_retained_bounded("docs", b"key", VALUE_BYTES)?);
        Ok(Self {
            store,
            node,
            memory,
            _directory: directory,
            _scratch: scratch,
        })
    }
    fn request() -> Result<u64> {
        Ok(crate::disk_memory::add(
            crate::disk_memory::allocation::<u8>(
                (12 + "docs".len() + b"key".len() + VALUE_BYTES) as u64,
            )?,
            SharedPlaintextState::required_bytes()?,
        )?)
    }
    async fn shutdown(self) -> Result<()> {
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
fn baseline(memory: &TestDiskMemory, before: crate::test_utils::TestDiskMemorySnapshot) {
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
}
#[tokio::test]
async fn actual_retained_point_joins_exact_control_into_one_original_plaintext_grant() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let before = fixture.memory.snapshot();
    let (value, observed) = source_quote_observer::measure(&fixture.memory, || {
        fixture
            .store
            .get_retained_bounded("docs", b"key", VALUE_BYTES)
    });
    let value = value?.unwrap();
    let original_charge = TestDiskMemory::required_reservation_bytes(Fixture::request()?)?;
    assert!(!observed.overflow);
    assert_eq!(
        observed.requests[..observed.count]
            .iter()
            .filter(|&&bytes| bytes == original_charge)
            .count(),
        1,
        "named shared point control and plaintext use the SAME one request"
    );
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        before.used_bytes + original_charge
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        before.live_reservations + 1
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    let original_attempts = fixture.memory.snapshot().attempts;
    let address = value.as_bytes().as_ptr();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = fixture.memory.clone();
    let foreign: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(256 << 20, 4096);
    let (alias, allocations) = allocation_tests::measure(|| {
        assert!(value.is_from_memory(&provider));
        assert!(!value.is_from_memory(&foreign));
        value.clone()
    });
    assert_eq!(allocations, 0);
    assert_eq!(fixture.memory.snapshot().attempts, original_attempts);
    drop(value);
    assert_eq!(alias.as_bytes().as_ptr(), address);
    assert!(alias.as_bytes().iter().all(|&byte| byte == 0x63));
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        before.used_bytes + original_charge
    );
    drop(alias);
    baseline(&fixture.memory, before);
    fixture.shutdown().await
}
#[tokio::test]
async fn final_retained_point_control_deallocation_precedes_same_original_lease_refund()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.memory.snapshot();
    let value = fixture
        .store
        .get_retained_bounded("docs", b"key", VALUE_BYTES)?
        .unwrap();
    let charged = fixture.memory.snapshot();
    let (layout, offset) =
        Layout::array::<usize>(2)?.extend(Layout::new::<SharedPlaintextState>())?;
    let layout = layout.pad_to_align();
    assert_eq!(
        kasumi_types::SharedBudgetCharge::allocation_layout::<SharedPlaintextState>()?,
        layout
    );
    let data = Arc::as_ptr(value.0.as_ref().unwrap()) as usize;
    assert_eq!(data % std::mem::align_of::<SharedPlaintextState>(), 0);
    let control_address = data.checked_sub(offset).unwrap();
    let byte_address = value.as_bytes().as_ptr();
    let aliases = (0..8).map(|_| value.clone()).collect::<Vec<_>>();
    drop(value);
    assert_eq!(aliases[0].as_bytes().as_ptr(), byte_address);
    let observation = allocation_tests::DeallocationObservation::new(true);
    let barrier = std::sync::Barrier::new(aliases.len());
    // An assertion unwind must release this SAME paused real deallocation
    // before thread::scope waits for its workers to finish.
    struct Release<'a>(&'a allocation_tests::DeallocationObservation);
    impl Drop for Release<'_> {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for alias in aliases {
            let barrier = &barrier;
            let observation = &observation;
            threads.push(scope.spawn(move || {
                barrier.wait();
                allocation_tests::observe_deallocation(
                    control_address as *const (),
                    observation,
                    || drop(alias),
                );
            }));
        }
        let release = Release(&observation);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !observation.entered() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(observation.entered());
        assert!(!observation.finished());
        assert_eq!(fixture.memory.snapshot().used_bytes, charged.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            charged.live_reservations
        );
        drop(release);
        for thread in threads {
            thread.join().unwrap();
        }
    });
    assert!(observation.finished());
    assert_eq!(observation.count(), 1);
    assert_eq!(observation.bytes(), layout.size());
    baseline(&fixture.memory, before);
    fixture.shutdown().await
}
#[tokio::test]
async fn retained_point_bound_and_authenticated_identity_refusals_keep_original_reader_protocol()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.memory.snapshot();
    assert!(
        fixture
            .store
            .get_retained_bounded("docs", b"key", VALUE_BYTES - 1)
            .is_err()
    );
    assert!(fixture.store.get_retained("docs", b"missing")?.is_none());
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    baseline(&fixture.memory, before);
    fixture.shutdown().await
}
