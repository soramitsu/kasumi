use super::*;
use crate::{
    allocation_tests::measure_requested,
    disk_memory::ALLOCATION_ALLOWANCE,
    test_utils::{
        LocalKeyProvider, ManualClock, TestDiskMemory, node_storage_config, private_tempdir,
        retry_disk_registry,
    },
};

#[test]
fn plaintext_get_workspace_quote_is_checked_bounded_and_allocation_free() {
    for (tenant, namespace, key, value) in [
        (1, 1, 0, 0),
        (1024, 1024, 4096, MAX_RECORD),
        (6, 5, 24, 16 << 10),
    ] {
        let (quote, allocations, requested) =
            measure_requested(|| plaintext_get_workspace_bytes(tenant, namespace, key, value));
        assert!(quote.unwrap() > value as u64);
        assert_eq!((allocations, requested), (0, 0));
    }
    for (tenant, namespace, key, value) in [
        (0, 1, 0, 0),
        (1025, 1, 0, 0),
        (1, 0, 0, 0),
        (1, 1025, 0, 0),
        (1, 1, 4097, 0),
        (1, 1, 0, MAX_RECORD + 1),
        (usize::MAX, 1, 0, 0),
        (1, usize::MAX, 0, 0),
        (1, 1, usize::MAX, 0),
        (1, 1, 0, usize::MAX),
    ] {
        let (quote, allocations, requested) =
            measure_requested(|| plaintext_get_workspace_bytes(tenant, namespace, key, value));
        assert_eq!(quote.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!((allocations, requested), (0, 0));
    }
}

// Error backtrace capture is diagnostic custody outside this buffer quote. Use
// a fresh exact-test process with that optional capture disabled, instead of
// racing environment mutation against other tests or silently warm-up decoding.
// This still uses the same existing library allocator and production decoder.
fn isolated_census(qualified_name: &str) -> Result<bool> {
    let (_, name) = qualified_name
        .split_once("::")
        .expect("crate-qualified test");
    const MARKER: &str = "KASUMI_PLAINTEXT_CENSUS_TEST";
    if std::env::var(MARKER).as_deref() == Ok(name) {
        return Ok(false);
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture"])
        .env(MARKER, name)
        .env("RUST_LIB_BACKTRACE", "0")
        .env("RUST_BACKTRACE", "0")
        .output()?;
    ensure!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "isolated plaintext census failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(true)
}

// Fixture setup and encrypted/native input backing stay outside the plaintext
// observation. The exact production decoder is measured, including both HMAC
// keys, the AEAD/AAD buffers, borrowed malformed fields, and bounded local errors.
// This is a cumulative allocation-request census (stronger than simultaneous
// requested backing), not an RSS measurement or native/cache admission claim.
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
        let scratch_directory = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let path = directory.path().join("plaintext-workspace.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch,
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "t".repeat(1024),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(ManualClock::default()),
        )
        .await?;
        Ok(Self {
            store,
            node,
            memory,
            _directory: directory,
            _scratch: scratch_directory,
        })
    }

    fn envelope(&self, namespace: &str, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let state = self.store.state.read();
        let catalog = self.store.catalog.read();
        let disk_key = record_key(
            self.store.tenant(),
            namespace,
            key,
            state.keys.get(INDEX_KEY).unwrap(),
        );
        let mut envelope = Vec::new();
        append_bytes(&mut envelope, catalog.active.as_bytes())?;
        envelope.extend(encrypt(
            state.keys.get(&catalog.active).unwrap(),
            plaintext,
            &record_aad(self.store.tenant(), &disk_key),
        )?);
        Ok(envelope)
    }

    fn measured_decode(
        &self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
        envelope: &[u8],
    ) -> (Result<PlaintextValue>, usize, usize) {
        let quote = plaintext_get_workspace_bytes(
            self.store.tenant().len(),
            namespace.len(),
            key.len(),
            max_value_bytes,
        )
        .unwrap();
        let state = self.store.state.read();
        let (result, allocations, bytes) = measure_requested(|| {
            let disk_key = record_key(
                self.store.tenant(),
                namespace,
                key,
                state.keys.get(INDEX_KEY).unwrap(),
            );
            decode_get_record(
                &self.store,
                &disk_key,
                envelope,
                &state,
                namespace,
                key,
                max_value_bytes,
            )
        });
        assert!(allocations > 0, "real cryptographic path was not observed");
        assert!(
            allocations as u64 <= PLAINTEXT_GET_ALLOCATION_REQUESTS,
            "decode added an unquoted allocation request: {allocations}"
        );
        let observed_policy = (bytes as u64)
            .checked_add(
                (allocations as u64)
                    .checked_mul(ALLOCATION_ALLOWANCE)
                    .unwrap(),
            )
            .unwrap();
        assert!(
            observed_policy <= quote,
            "plaintext allocation policy exceeded quote: {observed_policy} > {quote} \
             ({bytes} requested bytes, {allocations} requests)"
        );
        (result, allocations, bytes)
    }

    async fn close(self) -> Result<()> {
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn plaintext_get_workspace_covers_first_read_pages_large_values_and_max_names() -> Result<()>
{
    if isolated_census(concat!(
        module_path!(),
        "::plaintext_get_workspace_covers_first_read_pages_large_values_and_max_names"
    ))? {
        return Ok(());
    }
    let fixture = Fixture::new().await?;
    // No warm-up decode before the first measurement. A valid encrypted record
    // carries a 16 KiB page-sized payload; Store does not interpret page format.
    for (namespace, key, value) in [
        ("pages".to_owned(), vec![7; 24], vec![9; 16 << 10]),
        ("n".repeat(1024), vec![8; 4096], vec![10; 1 << 20]),
        ("empty".to_owned(), Vec::new(), Vec::new()),
    ] {
        let plaintext = encode_plain_record(&namespace, &key, &value)?;
        let envelope = fixture.envelope(&namespace, &key, &plaintext)?;
        for _ in 0..2 {
            let (decoded, _, _) = fixture.measured_decode(&namespace, &key, value.len(), &envelope);
            assert_eq!(decoded?, value);
        }
        // Exercise the canonical registered read after the isolated census.
        // Its separate encrypted/output/census charges are intentionally not
        // subtracted from a whole-operation allocator observation.
        fixture.store.write_batch(&[WriteOp::put(
            namespace.as_str(),
            key.as_slice(),
            value.as_slice(),
        )])?;
        let view = fixture.store.read_view()?;
        assert!(view.registered_reader_id().is_some());
        assert_eq!(
            view.get(&namespace, &key, value.len())?.as_deref(),
            Some(value.as_slice())
        );
        view.close()?;
    }
    fixture.close().await
}

#[tokio::test]
async fn plaintext_get_workspace_covers_authenticated_long_fields_and_ciphertext_failures()
-> Result<()> {
    if isolated_census(concat!(
        module_path!(),
        "::plaintext_get_workspace_covers_authenticated_long_fields_and_ciphertext_failures"
    ))? {
        return Ok(());
    }
    let fixture = Fixture::new().await?;
    let namespace = "pages";
    let key = [7; 24];
    let value_bound = 16 << 10;
    let plaintext_bound = value_bound + namespace.len() + key.len() + 12;
    let long_namespace = "x".repeat(plaintext_bound - 12);
    let long_key = vec![11; plaintext_bound - namespace.len() - 12];
    let malformed = [
        encode_plain_record(&long_namespace, &[], &[])?,
        encode_plain_record(namespace, &long_key, &[])?,
    ];
    for plaintext in &malformed {
        assert_eq!(plaintext.len(), plaintext_bound);
        let envelope = fixture.envelope(namespace, &key, plaintext)?;
        let (decoded, _, requested) =
            fixture.measured_decode(namespace, &key, value_bound, &envelope);
        assert!(
            decoded
                .unwrap_err()
                .to_string()
                .contains("encrypted record identity mismatch")
        );
        // AEAD still materializes the full admitted plaintext. The shared
        // parser now validates these fields as borrows and rejects their
        // identity before allocating namespace/key/value copies. A second
        // payload-sized request would regress that property; measured_decode
        // independently preserves the original full workspace budget check.
        assert!(
            requested >= plaintext_bound,
            "plaintext decrypt was not observed"
        );
        assert!(
            requested < 2 * plaintext_bound,
            "rejected long field was copied"
        );
    }

    let value = vec![9; value_bound];
    let plaintext = encode_plain_record(namespace, &key, &value)?;
    let mut envelope = fixture.envelope(namespace, &key, &plaintext)?;
    *envelope.last_mut().unwrap() ^= 0x80;
    let (decoded, _, _) = fixture.measured_decode(namespace, &key, value_bound, &envelope);
    assert!(
        decoded
            .unwrap_err()
            .to_string()
            .contains("authentication failed")
    );

    // The same corrupted envelope is one byte over the caller's bound: reject
    // before AEAD or decoded field processing.
    let (decoded, allocations, requested) =
        fixture.measured_decode(namespace, &key, value_bound - 1, &envelope);
    assert!(
        decoded
            .unwrap_err()
            .to_string()
            .contains("exceeds read budget")
    );
    assert!(allocations <= 5);
    assert!(requested < 1024);

    let (decoded, _, requested) = fixture.measured_decode(namespace, &key, 0, &[0, 0, 0]);
    assert!(
        decoded
            .unwrap_err()
            .to_string()
            .contains("truncated record field")
    );
    assert!(requested < 1024);
    fixture.close().await
}
