use super::*;
use crate::test_utils::{
    LocalKeyProvider, ManualClock, TestDiskMemory, node_storage_config, private_tempdir,
    retry_disk_registry,
};
use crate::{NodeDisk, NodeDiskMemoryAdmission, NodeStore, ScratchDisk, TenantStore, WriteOp};
use anyhow::Context;
use std::sync::Arc;

const MEMORY_LIMIT: u64 = 256 << 20;

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
        let memory = TestDiskMemory::new(MEMORY_LIMIT, 4096);
        let path = directory.path().join("point-owner.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([71; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        Ok(Self {
            store,
            node,
            memory,
            _directory: directory,
            _scratch: scratch,
        })
    }

    fn charge(value_bytes: usize) -> Result<u64> {
        // Exact admitted backing includes all three authenticated record fields.
        let plaintext_bytes = 12 + "docs".len() + b"key".len() + value_bytes;
        Ok(TestDiskMemory::required_reservation_bytes(
            crate::disk_memory::allocation::<u8>(plaintext_bytes as u64)?,
        )?)
    }
}

#[tokio::test]
async fn point_value_outlives_registered_reader_store_and_memory_facades() -> Result<()> {
    let fixture = Fixture::new().await?;
    let expected = vec![0x4d; 128 << 10];
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", expected.as_slice())])?;
    drop(fixture.store.get_bounded("docs", b"key", expected.len())?);
    let baseline = fixture.memory.snapshot();
    let value = fixture
        .store
        .get_bounded("docs", b"key", expected.len())?
        .unwrap();
    assert_eq!(value.as_bytes(), expected);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        baseline.used_bytes + Fixture::charge(expected.len())?
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    fixture.store.shutdown().await?;
    fixture.node.shutdown().await?;
    let memory = Arc::downgrade(&fixture.memory);
    drop(fixture.store);
    drop(fixture.node);
    drop(fixture.memory);
    assert!(
        memory.upgrade().is_some(),
        "point backing shed its installed owner"
    );
    assert_eq!(value.as_bytes(), expected);
    let before_drop = memory.upgrade().unwrap();
    let retained = before_drop.snapshot();
    let retained_census = before_drop.storage_census().snapshot();
    let installed_bytes = retained
        .used_bytes
        .checked_sub(Fixture::charge(expected.len())?)
        .unwrap();
    let installed_slots = retained.live_reservations.checked_sub(1).unwrap();
    drop(before_drop);
    drop(value);
    // The installed physical registry deliberately retains its exact provider
    // and aggregate charges after service shutdown. Retire only this output's
    // actual allocation and token; its drop must leave that baseline intact.
    let after_drop = memory
        .upgrade()
        .context("installed physical owner disappeared")?;
    let retired = after_drop.snapshot();
    assert_eq!(
        retired.used_bytes, installed_bytes,
        "last output retained plaintext credit"
    );
    assert_eq!(
        retired.live_reservations, installed_slots,
        "last output retained its lease slot"
    );
    assert_eq!(retired.bookkeeping_bytes, retained.bookkeeping_bytes);
    assert_eq!(
        retired.attempts, retained.attempts,
        "output drop requested more admission"
    );
    assert_eq!(after_drop.storage_census().snapshot(), retained_census);
    Ok(())
}

#[tokio::test]
async fn retained_point_output_consumes_real_capacity_and_drop_needs_no_readmission() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let expected = vec![0x5e; 128 << 10];
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", expected.as_slice())])?;
    let value = fixture
        .store
        .get_bounded("docs", b"key", expected.len())?
        .unwrap();
    let current = fixture.memory.snapshot();
    let zero = TestDiskMemory::required_reservation_bytes(0)?;
    let free = MEMORY_LIMIT - current.bookkeeping_bytes - current.used_bytes;
    let held = fixture.memory.clone().reserve_installed(free - zero)?;
    assert!(fixture.memory.clone().reserve_installed(0).is_err());
    assert_eq!(value.as_bytes(), expected);
    let attempts = fixture.memory.snapshot().attempts;
    drop(value);
    assert_eq!(
        fixture.memory.snapshot().attempts,
        attempts,
        "output drop requested more capacity"
    );
    let retry = fixture
        .memory
        .clone()
        .reserve_installed(Fixture::charge(expected.len())? - zero)?;
    drop(retry);
    drop(held);
    fixture.store.shutdown().await?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn owned_pinned_point_keeps_original_bytes_after_view_close_and_later_commit() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", b"original")])?;
    let view = fixture.store.read_view()?;
    let original = view.get("docs", b"key", 32)?.unwrap();
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", b"replacement")])?;
    let current = fixture.store.get_bounded("docs", b"key", 32)?.unwrap();
    drop(view);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    fixture.store.shutdown().await?;
    fixture.node.shutdown().await?;
    assert_eq!(original.as_bytes(), b"original");
    assert_eq!(current.as_bytes(), b"replacement");
    let held = fixture.memory.snapshot();
    drop(original);
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        held.used_bytes - Fixture::charge(b"original".len())?
    );
    drop(current);
    Ok(())
}
