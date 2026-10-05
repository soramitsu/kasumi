use super::*;
use crate::{
    INDEX_KEY, MAX_KEY_LEASE, NodeDisk, NodeStore, RECORDS, ScratchDisk, WriteOp, append_bytes,
    encode_plain_record, encrypt, inline_record_key, record_aad,
    test_utils::{
        LocalKeyProvider, ManualClock, NODE_STORE_ID, TestDiskMemory, TestDiskMemorySnapshot,
        node_storage_config, private_tempdir, retry_disk_registry, source_quote_observer,
    },
};
use std::time::Duration;

const MEMORY_LIMIT: u64 = 256 << 20;
struct Fixture {
    store: Arc<TenantStore>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    clock: Arc<ManualClock>,
    _directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let path = directory.path().join("charged-scan.kv");
        let memory = TestDiskMemory::new(MEMORY_LIMIT, 4096);
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let scratch_directory = private_tempdir()?;
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let node =
            NodeStore::create_new(&path, NODE_STORE_ID, disk, scratch, node_storage_config())
                .unwrap_or_else(|original| std::panic::panic_any(original));
        let clock = Arc::new(ManualClock::new());
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([93; 32])),
            clock.clone(),
        )
        .await?;
        assert!(!node.body().db.has_fixture_direct_database());
        Ok(Self {
            store,
            node,
            memory,
            clock,
            _directory: directory,
            _scratch_directory: scratch_directory,
        })
    }
    async fn shutdown(self) -> Result<()> {
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
    fn record(&self, key: &[u8], value: &[u8]) -> Result<PlaintextRecord> {
        let state = self.store.state.read();
        let catalog = self.store.catalog.read();
        let disk_key = inline_record_key(
            &self.store.tenant,
            "docs",
            key,
            state.keys.get(INDEX_KEY).unwrap(),
        );
        let encoded = encode_plain_record("docs", key, value)?;
        let mut envelope = Vec::new();
        append_bytes(&mut envelope, catalog.active.as_bytes())?;
        envelope.extend(encrypt(
            state.keys.get(&catalog.active).unwrap(),
            &encoded,
            &record_aad(&self.store.tenant, &disk_key),
        )?);
        PlaintextRecord::prepare(&self.store, &disk_key, &envelope, &state, "docs")
    }
}
fn resident_bytes(plaintext_len: usize) -> u64 {
    TestDiskMemory::required_reservation_bytes(
        disk_memory::allocation::<u8>(plaintext_len as u64).unwrap(),
    )
    .unwrap()
}
fn metadata_bytes(capacity: usize) -> u64 {
    TestDiskMemory::required_reservation_bytes(
        disk_memory::allocation::<PlaintextRecord>(capacity as u64).unwrap(),
    )
    .unwrap()
}
fn assert_baseline(memory: &TestDiskMemory, baseline: TestDiskMemorySnapshot) {
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn sorted_scan_retains_actual_row_and_container_credit_through_borrowed_iteration()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let keys: [&[u8]; 7] = [b"z", b"", b"\xff", b"ab", b"a", b"\0", b"m"];
    let value = vec![0x59; 16 << 10];
    fixture.store.write_batch(
        &keys
            .iter()
            .map(|key| WriteOp::put("docs", *key, value.clone()))
            .collect::<Vec<_>>(),
    )?;
    fixture.store.visit("docs", value.len(), |_, _| Ok(()))?;
    let baseline = fixture.memory.snapshot();
    let (result, observed) =
        source_quote_observer::measure(&fixture.memory, || fixture.store.scan("docs"));
    let rows = result?;
    assert_eq!(rows.len(), keys.len());
    let expected: [&[u8]; 7] = [b"", b"\0", b"a", b"ab", b"m", b"z", b"\xff"];
    for ((key, bytes), expected) in rows.iter().zip(expected) {
        assert_eq!(key, expected);
        assert_eq!(bytes, value);
        assert_eq!(bytes.as_ptr(), key.as_ptr().wrapping_add(key.len() + 4));
    }
    let row_bytes = expected
        .iter()
        .map(|key| resident_bytes(12 + "docs".len() + key.len() + value.len()))
        .sum::<u64>();
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        baseline.used_bytes + row_bytes + metadata_bytes(rows.rows.capacity())
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        baseline.live_reservations + keys.len() + 1
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert!(!observed.overflow);
    assert!(observed.requests[..observed.count].contains(&metadata_bytes(rows.rows.capacity())));
    let held = fixture.memory.snapshot();
    for (_, bytes) in &rows {
        assert_eq!(bytes.len(), value.len());
    }
    assert_baseline(&fixture.memory, held);
    drop(rows);
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn refused_container_growth_preserves_prior_rows_and_retires_the_new_row() -> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.memory.snapshot();
    let mut rows = PlaintextScan::new(fixture.memory.clone());
    rows.push(fixture.record(b"a", b"first")?)?;
    let first = fixture.memory.snapshot();
    let candidate = fixture.record(b"b", &[0x61; 1024])?;
    let candidate_cost = resident_bytes(12 + "docs".len() + 1 + 1024);
    let before = fixture.memory.snapshot();
    let filler = MEMORY_LIMIT
        - before.bookkeeping_bytes
        - before.used_bytes
        - TestDiskMemory::required_reservation_bytes(0)?;
    let pressure = fixture.memory.clone().reserve_installed(filler)?;
    let full = fixture.memory.snapshot();
    let error = rows.push(candidate).unwrap_err();
    assert!(format!("{error:#}").contains("record scan container admission denied"));
    assert_eq!(rows.rows.capacity(), 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].key(), rows[0].value()),
        (b"a".as_slice(), b"first".as_slice())
    );
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        full.used_bytes - candidate_cost
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        full.live_reservations - 1
    );
    drop(error);
    drop(pressure);
    assert_baseline(&fixture.memory, first);
    rows.push(fixture.record(b"b", b"second")?)?;
    rows.sort();
    assert_eq!(rows[1].value(), b"second");
    drop(rows);
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn late_authenticated_decode_failure_retires_all_accumulated_output() -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut keys = {
        let state = fixture.store.state.read();
        let index = state.keys.get(INDEX_KEY).unwrap();
        let mut keys = (0u8..6)
            .map(|key| {
                let user_key = [key];
                (
                    inline_record_key(&fixture.store.tenant, "docs", &user_key, index),
                    user_key,
                )
            })
            .collect::<Vec<_>>();
        keys.sort_unstable_by_key(|(disk_key, _)| *disk_key);
        keys
    };
    let bad = keys.pop().unwrap();
    fixture.store.write_batch(
        &keys
            .iter()
            .map(|(_, key)| WriteOp::put("docs", key.as_slice(), vec![0x67; 16 << 10]))
            .collect::<Vec<_>>(),
    )?;
    let envelope = {
        let state = fixture.store.state.read();
        let catalog = fixture.store.catalog.read();
        let mut envelope = Vec::new();
        append_bytes(&mut envelope, catalog.active.as_bytes())?;
        envelope.extend(encrypt(
            state.keys.get(&catalog.active).unwrap(),
            &[0, 0, 0],
            &record_aad(&fixture.store.tenant, &bad.0),
        )?);
        envelope
    };
    let transaction = fixture.node.body().db.begin_write()?;
    transaction
        .open_table(RECORDS)?
        .insert(bad.0.as_slice(), envelope.as_slice())?;
    transaction.commit()?;
    let _ = fixture.store.visit("docs", 16 << 10, |_, _| Ok(()));
    let baseline = fixture.memory.snapshot();
    let (result, observed) =
        source_quote_observer::measure(&fixture.memory, || fixture.store.scan("docs"));
    let error = result.expect_err("last authenticated row has invalid fields");
    assert!(format!("{error:#}").contains("truncated record field"));
    assert!(
        !observed.overflow,
        "record admissions exceeded the inline observer"
    );
    assert!(
        observed.requests[..observed.count]
            .iter()
            .filter(|bytes| **bytes == resident_bytes(12 + 4 + 1 + (16 << 10)))
            .count()
            >= keys.len()
    );
    drop(error);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn installed_scan_denies_resident_pressure_without_partial_output_and_can_retry() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let value = vec![0x6d; 512 << 10];
    let operations = (0u8..24)
        .map(|key| WriteOp::put("docs", vec![key], value.clone()))
        .collect::<Vec<_>>();
    fixture.store.write_batch(&operations)?;
    fixture.store.visit("docs", value.len(), |_, _| Ok(()))?;
    let baseline = fixture.memory.snapshot();
    let filler = MEMORY_LIMIT
        - baseline.bookkeeping_bytes
        - baseline.used_bytes
        - (40 << 20)
        - TestDiskMemory::required_reservation_bytes(0)?;
    let pressure = fixture.memory.clone().reserve_installed(filler)?;
    let full = fixture.memory.snapshot();
    let error = fixture
        .store
        .scan("docs")
        .expect_err("retained rows must exhaust installed memory");
    drop(error);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_baseline(&fixture.memory, full);
    drop(pressure);
    let rows = fixture.store.scan("docs")?;
    assert_eq!(rows.len(), operations.len());
    for ((key, bytes), expected) in rows.iter().zip(0u8..24) {
        assert_eq!(key, [expected]);
        assert_eq!(bytes, value);
    }
    drop(rows);
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn expired_scan_never_acquires_output_or_container_capacity() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .store
        .write_batch(&[WriteOp::put("docs", b"key", b"value")])?;
    fixture
        .clock
        .advance(MAX_KEY_LEASE + Duration::from_secs(1));
    let baseline = fixture.memory.snapshot();
    let (result, observed) =
        source_quote_observer::measure(&fixture.memory, || fixture.store.scan("docs"));
    assert!(result.is_err());
    assert_eq!(observed.count, 0);
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}
