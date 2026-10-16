use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};

async fn store(directory: &tempfile::TempDir) -> Arc<TenantStore> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch = crate::ScratchDisk::fixture(directory.path(), memory.clone());
    let node = NodeStore::create_new_fixture(
        directory.path().join("cached-rows.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory,
        scratch,
    )
    .unwrap();
    TenantStore::initialize_catalog_fixture_with_clock(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([7; 32])),
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn namespace_epochs_advance_around_every_write_naming_them() {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let store = store(&directory).await;
    let families = store.namespace_epoch("families").unwrap();
    assert_eq!(families.current(), 0);
    store
        .write_batch(&[WriteOp::put("events", b"a", b"1")])
        .unwrap();
    assert_eq!(families.current(), 0);
    store
        .write_batch(&[
            WriteOp::put("events", b"b", b"2"),
            WriteOp::put("families", b"f", b"1"),
            WriteOp::put("families", b"g", b"1"),
        ])
        .unwrap();
    assert_eq!(families.current(), 2);
    // Every watcher of a namespace shares its one epoch.
    assert_eq!(store.namespace_epoch("families").unwrap().current(), 2);
    store
        .write_batch(&[WriteOp::delete("families", b"f")])
        .unwrap();
    assert_eq!(families.current(), 4);
    store
        .replace_namespaces(&[NamespaceReplacement::empty("families")], &[])
        .unwrap();
    assert_eq!(families.current(), 6);
    assert!(store.get("families", b"g").unwrap().is_none());
    store.shutdown().await.unwrap();
    store.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_namespace_epoch_is_odd_during_a_write_and_registration_waits_for_it() {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let store = store(&directory).await;
    let families = store.namespace_epoch("families").unwrap();
    let fence = store.cached_rows.fence(["families", "events"]);
    assert_eq!(families.current(), 1);
    let (registered, observed) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            registered
                .send(store.namespace_epoch("events").unwrap().current())
                .unwrap();
        });
        // The in-flight write did not fence an unwatched namespace, so a new
        // watcher must not start counting until that write's attempt returns.
        assert!(
            observed
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
        drop(fence);
        assert_eq!(observed.recv().unwrap(), 0);
    });
    assert_eq!(families.current(), 2);
    store.shutdown().await.unwrap();
    store.node.shutdown().await.unwrap();
}
