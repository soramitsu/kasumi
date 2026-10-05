//! Actual installed nodes: original fixed fee, control, path and census custody.
use super::*;
#[tokio::test]
async fn initializer_disposal_panic_keeps_original_payload_and_later_handle_in_same_slot() {
    #[derive(Debug)]
    struct DropPanic {
        original: Option<Box<u64>>,
    }
    impl std::fmt::Display for DropPanic {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("initializer result destructor control")
        }
    }
    impl std::error::Error for DropPanic {}
    impl Drop for DropPanic {
        fn drop(&mut self) {
            std::panic::resume_unwind(self.original.take().unwrap());
        }
    }
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch = ScratchDisk::fixture(directory.path(), memory.clone());
    let node = NodeStore::create_new_fixture(
        directory.path().join("original-disposal.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory.clone(),
        scratch,
    )
    .expect("positive bounded original-disposal fixture");
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let pending = tokio::spawn(async move {
        waiting.await.unwrap();
        Ok(())
    });
    let pending_id = pending.id();
    let payload = Box::new(0xa190_u64);
    let payload_address = std::ptr::from_ref(payload.as_ref()) as usize;
    let failed = tokio::spawn(async move {
        Err(anyhow::Error::new(DropPanic {
            original: Some(payload),
        }))
    });
    node.body()
        .initializers
        .lock()
        .await
        .handles
        .extend([pending, failed]);
    let failure = node.drain_initializers().await.unwrap_err();
    let fee = memory.snapshot();
    failure
        .with_report(|report| {
            assert!(report.body_error().unwrap().is::<DropPanic>());
            assert!(matches!(
                report.handle_disposal(),
                TerminalObservation::Returned(Ok(()))
            ));
        })
        .await;
    assert!(!failure.dispose_original().await);
    failure
        .with_report(|report| {
            assert!(report.body_error().is_none());
            let TerminalObservation::Panicked(original) = report.original_disposal() else {
                panic!("actual original destructor panic must remain installed");
            };
            let original = original.downcast_ref::<u64>().unwrap();
            assert_eq!(*original, 0xa190);
            assert_eq!(std::ptr::from_ref(original) as usize, payload_address);
        })
        .await;
    let repeated = node.drain_initializers().await.unwrap_err();
    assert_eq!(repeated.opening_id(), failure.opening_id());
    assert!(
        !repeated.dispose_original().await,
        "no replay or replacement of the original callback"
    );
    {
        let registry = node.body().initializers.lock().await;
        assert_eq!(registry.handles.len(), 1);
        assert_eq!(registry.handles[0].id(), pending_id);
    }
    assert_eq!(memory.snapshot(), fee);
    release.send(()).unwrap();
    drop(repeated);
    drop(failure);
    let id = node.registered_opening_id().unwrap();
    drop(node);
    let retained = InitializerDrainFailure::retained(memory.clone(), id)
        .await
        .unwrap();
    retained
        .with_report(|report| {
            assert!(matches!(
                report.original_disposal(),
                TerminalObservation::Panicked(_)
            ));
        })
        .await;
    // This negative has no cleanup witness. The original node remains in its
    // census; preserve the exact directory while that intentionally retained
    // fixture exists. No disappearance is asserted as positive drain.
    std::mem::forget(directory);
}
use crate::allocation_tests::{DeallocationObservation, measure, observe_deallocation};
use crate::test_utils::{
    TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry,
};

struct Fixture {
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    before_node: crate::test_utils::TestDiskMemorySnapshot,
    node_fee: u64,
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = private_tempdir().unwrap();
        let scratch = private_tempdir().unwrap();
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let path = directory.path().join("composite.kv");
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let scratch_disk = ScratchDisk::fixture(scratch.path(), memory.clone());
        let config = node_storage_config();
        let before_node = memory.snapshot();
        let node_fee = TestDiskMemory::required_reservation_bytes(
            RegisteredNodeOpening::node_request_bytes(&path, config).unwrap(),
        )
        .unwrap();
        let node = NodeStore::create_new(
            &path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch_disk,
            config,
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        Self {
            node,
            memory,
            before_node,
            node_fee,
            _directory: directory,
            _scratch: scratch,
        }
    }
}

#[tokio::test]
async fn composite_node_aliases_keep_original_fee_until_actual_control_deallocation() {
    let fixture = Fixture::new();
    let before_alias = fixture.memory.snapshot();
    let (alias, allocations) = measure(|| fixture.node.clone());
    assert_eq!(allocations, 0);
    assert!(NodeStore::ptr_eq(&fixture.node, &alias));
    assert_eq!(fixture.memory.snapshot(), before_alias);
    assert_eq!(alias.group_path(), fixture.node.group_path());
    let early = alias.clone().retire();
    assert_eq!(early.disposition(), StorageCensusDisposition::Retained);
    assert_eq!(fixture.memory.snapshot(), before_alias);
    // A real native-backed capability remains usable after early facade
    // retirement. A lifecycle bit alone could miss accidentally sealed ingress.
    let read = fixture.node.body().db.queue_registered_read().unwrap();
    assert_eq!(read.begin(), NodeReadPhase::Active);
    assert!(
        read.catalog_bytes(tenant_hash("not-installed"), MAX_KEY_CATALOG_BYTES)
            .unwrap()
            .is_none()
    );
    assert_eq!(read.finish(), NodeReadPhase::Finished);
    assert_eq!(read.retire(), StorageCensusDisposition::Retired);
    fixture.node.shutdown().await.unwrap();
    assert!(fixture.node.body().db.native_resources_disposed());
    let after_native = fixture.memory.snapshot();
    assert_eq!(
        after_native.used_bytes,
        fixture.before_node.used_bytes + fixture.node_fee
    );
    assert_eq!(
        after_native.live_reservations,
        fixture.before_node.live_reservations + 1
    );
    let id = alias.registered_opening_id().unwrap();
    let control_address = alias.opening.allocation_address();
    let first = fixture.node.retire();
    assert_eq!(first.disposition(), StorageCensusDisposition::Retained);
    assert_eq!(fixture.memory.snapshot(), after_native);
    assert_eq!(fixture.memory.storage_census().snapshot().databases, 1);

    let observation = DeallocationObservation::new(true);
    let retired = std::thread::scope(|scope| {
        let observed = &observation;
        let retire = scope.spawn(move || {
            observe_deallocation(control_address as *const (), observed, || alias.retire())
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !observation.entered() {
            assert!(
                std::time::Instant::now() < deadline,
                "actual control deallocation not entered"
            );
            std::thread::yield_now();
        }
        assert!(!observation.finished());
        assert_eq!(fixture.memory.snapshot(), after_native);
        observation.release();
        retire.join().unwrap()
    });
    assert!(observation.finished());
    assert_eq!(observation.count(), 1);
    assert_eq!(retired.id(), id);
    assert!(retired.is_retired());
    let final_memory = fixture.memory.snapshot();
    assert_eq!(final_memory.used_bytes, fixture.before_node.used_bytes);
    assert_eq!(
        final_memory.live_reservations,
        fixture.before_node.live_reservations
    );
    assert_eq!(final_memory.attempts, after_native.attempts);
    assert_eq!(fixture.memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn composite_node_path_deallocation_precedes_original_fixed_fee_refund() {
    let fixture = Fixture::new();
    fixture.node.shutdown().await.unwrap();
    let before = fixture.memory.snapshot();
    let path_address = fixture
        .node
        .group_path()
        .unwrap()
        .as_os_str()
        .as_encoded_bytes()
        .as_ptr() as usize;
    let observation = DeallocationObservation::new(true);
    let node = fixture.node;
    let retired = std::thread::scope(|scope| {
        let observed = &observation;
        let retire = scope.spawn(move || {
            observe_deallocation(path_address as *const (), observed, || node.retire())
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !observation.entered() {
            assert!(
                std::time::Instant::now() < deadline,
                "actual node path deallocation not entered"
            );
            std::thread::yield_now();
        }
        assert!(!observation.finished());
        assert_eq!(fixture.memory.snapshot(), before);
        observation.release();
        retire.join().unwrap()
    });
    assert!(observation.finished());
    assert_eq!(observation.count(), 1);
    assert!(retired.is_retired());
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        fixture.before_node.used_bytes
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        fixture.before_node.live_reservations
    );
    assert_eq!(fixture.memory.snapshot().attempts, before.attempts);
}
