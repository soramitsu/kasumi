use super::*;
use crate::test_utils::{
    LocalKeyProvider, TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry,
};
use std::sync::atomic::{AtomicUsize, Ordering};

// No wall-clock wait: allow exactly one successful access check, then expire
// the key lease at the post-fork check. Explicit fixture catalog construction
// disables renewal, so no background clock observer participates.
struct ForkClock(AtomicUsize);
impl ForkClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicUsize::new(usize::MAX)))
    }
    fn expire_after_precheck(&self) {
        self.0.store(1, Ordering::SeqCst);
    }
    fn expire(&self) {
        self.0.store(0, Ordering::SeqCst);
    }
}
impl LeaseClock for ForkClock {
    fn now(&self) -> Duration {
        let before = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining != usize::MAX && remaining != 0).then_some(remaining.saturating_sub(1))
            })
            .unwrap_or_else(|remaining| remaining);
        if before == 0 {
            MAX_KEY_LEASE
        } else {
            Duration::ZERO
        }
    }
}
struct Fixture {
    stores: Arc<TenantStorageSet>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    app_clock: Arc<ForkClock>,
    custody_clock: Arc<ForkClock>,
    _directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let scratch_directory = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let path = directory.path().join("selected-view.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        // The real installed/census path, not NodeStore::create_new_fixture.
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch,
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let app_clock = ForkClock::new();
        let custody_clock = ForkClock::new();
        let app = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([11; 32])),
            app_clock.clone(),
        )
        .await?;
        let custody = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            CustodyStore::catalog_name("tenant"),
            Arc::new(LocalKeyProvider::new([12; 32])),
            custody_clock.clone(),
        )
        .await?;
        let stores = TenantStorageSet::install(app, custody)?;
        Ok(Self {
            stores,
            node,
            memory,
            app_clock,
            custody_clock,
            _directory: directory,
            _scratch_directory: scratch_directory,
        })
    }
    fn publish(&self, application: &[u8], custody: &[u8]) -> Result<()> {
        self.stores
            .write_batch(&[put(b"id", application)], &[put(b"id", custody)])
    }
    async fn finish(self) -> Result<()> {
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
fn put(key: &[u8], value: &[u8]) -> WriteOp {
    WriteOp::Put {
        namespace: "items".into(),
        key: key.into(),
        value: value.into(),
    }
}
fn pair(view: &TenantStorageReadView, application: &[u8], custody: &[u8]) -> Result<()> {
    assert_eq!(
        view.application_get("items", b"id", 64)?.as_deref(),
        Some(application)
    );
    assert_eq!(
        view.custody_get("items", b"id", 64)?.as_deref(),
        Some(custody)
    );
    Ok(())
}

#[tokio::test]
async fn selected_view_fork_keeps_both_encrypted_domains_on_one_old_root() -> Result<()> {
    for parent_first in [true, false] {
        let fixture = Fixture::new().await?;
        fixture.publish(b"app-old", b"custody-old")?;
        let parent = fixture.stores.read_view()?;
        let parent_id = parent.registered_reader_id().expect("installed reader");
        fixture.publish(b"app-new", b"custody-new")?;
        let child = parent.fork()?;
        assert_ne!(child.registered_reader_id().unwrap(), parent_id);
        // One census child for the pair, never an independent per-domain read.
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 2);
        pair(&parent, b"app-old", b"custody-old")?;
        pair(&child, b"app-old", b"custody-old")?;
        let latest = fixture.stores.read_view()?;
        pair(&latest, b"app-new", b"custody-new")?;
        latest.close()?;
        if parent_first {
            parent.close()?;
            pair(&child, b"app-old", b"custody-old")?;
            let grandchild = child.fork()?;
            child.close()?;
            pair(&grandchild, b"app-old", b"custody-old")?;
            grandchild.close()?;
        } else {
            child.close()?;
            pair(&parent, b"app-old", b"custody-old")?;
            parent.close()?;
        }
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn selected_view_fork_preserves_single_domain_point_and_range_after_parent_drop() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let app = fixture.stores.application();
    app.write_batch(&[put(b"id", b"old"), put(b"removed", b"still-historical")])?;
    let parent = app.read_view()?;
    app.write_batch(&[
        put(b"id", b"new"),
        WriteOp::Delete {
            namespace: "items".into(),
            key: b"removed".into(),
        },
    ])?;
    let child = parent.fork()?;
    assert_ne!(child.registered_reader_id(), parent.registered_reader_id());
    parent.close()?;
    assert_eq!(
        child.get("items", b"id", 64)?.as_deref(),
        Some(b"old".as_slice())
    );
    let mut historical = BTreeMap::new();
    child.visit("items", 64, |key, value| {
        historical.insert(key.to_vec(), value.to_vec());
        Ok(())
    })?;
    assert_eq!(
        historical,
        BTreeMap::from([
            (b"id".to_vec(), b"old".to_vec()),
            (b"removed".to_vec(), b"still-historical".to_vec())
        ])
    );
    let latest = app.read_view()?;
    assert_eq!(
        latest.get("items", b"id", 64)?.as_deref(),
        Some(b"new".as_slice())
    );
    assert!(latest.get("items", b"removed", 64)?.is_none());
    latest.close()?;
    child.close()?;
    fixture.finish().await
}

#[tokio::test]
async fn selected_view_fork_rechecks_expiry_and_settles_post_fork_denial() -> Result<()> {
    for paired in [false, true] {
        // Single-domain application expiry, and independent custody expiry in
        // a paired view. Both initial refusal and post-admission expiry are real.
        for after_admission in [false, true] {
            let fixture = Fixture::new().await?;
            fixture.publish(b"app", b"custody")?;
            let single = (!paired)
                .then(|| fixture.stores.application().read_view())
                .transpose()?;
            let pair = paired.then(|| fixture.stores.read_view()).transpose()?;
            let census = fixture.memory.storage_census().snapshot();
            let before = fixture.memory.snapshot();
            let clock = if paired {
                &fixture.custody_clock
            } else {
                &fixture.app_clock
            };
            if after_admission {
                clock.expire_after_precheck();
            } else {
                clock.expire();
            }
            let error = if let Some(view) = &single {
                match view.fork() {
                    Ok(_) => panic!("expired single fork succeeded"),
                    Err(error) => error,
                }
            } else {
                match pair.as_ref().unwrap().fork() {
                    Ok(_) => panic!("expired paired fork succeeded"),
                    Err(error) => error,
                }
            };
            assert!(
                error
                    .to_string()
                    .contains("key-access lease unavailable or expired")
            );
            assert_eq!(fixture.memory.storage_census().snapshot(), census);
            if after_admission {
                assert!(
                    fixture.memory.snapshot().attempts > before.attempts,
                    "post-check denial must follow real child admission"
                );
            } else {
                assert_eq!(fixture.memory.snapshot().attempts, before.attempts);
            }
            if let Some(view) = single {
                assert!(view.get("items", b"id", 64).is_err());
                view.close()?;
            }
            if let Some(view) = pair {
                assert!(view.custody_get("items", b"id", 64).is_err());
                view.close()?;
            }
            fixture.finish().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn selected_view_fork_rejects_foreign_database_even_with_same_provider_and_uuid() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let path = fixture._directory.path().join("foreign.kv");
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, fixture.memory.clone()))?;
    let other = NodeStore::create_new(
        path,
        crate::test_utils::NODE_STORE_ID,
        disk,
        fixture.node.scratch_disk().clone(),
        node_storage_config(),
    )
    .unwrap_or_else(|original| std::panic::panic_any(original));
    let parent = fixture.node.begin_registered_read()?;
    let census = fixture.memory.storage_census().snapshot();
    let before = fixture.memory.snapshot();
    let error = match other.fork_registered_read(&parent) {
        Ok(_) => panic!("foreign physical owner accepted selected parent"),
        Err(error) => error,
    };
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(fixture.memory.snapshot(), before);
    assert_eq!(fixture.memory.storage_census().snapshot(), census);
    assert_eq!(parent.phase(), NodeReadPhase::Active);
    fixture.node.settle_registered_read(parent, Ok(()))?;
    other.shutdown().await?;
    fixture.finish().await
}

#[tokio::test]
async fn prepared_pair_owns_one_census_child_before_selecting_the_published_root() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.publish(b"app-old", b"custody-old")?;
    let old = fixture.stores.read_view()?;
    let baseline = fixture.memory.storage_census().snapshot().readers;
    let prepared = fixture.stores.prepare_read_view()?;
    let id = prepared
        .registered_reader_id()
        .expect("installed queued owner");
    assert_eq!(
        fixture.memory.storage_census().snapshot().readers,
        baseline + 1
    );
    {
        let queued = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        assert_eq!(queued.phase(), NodeReadPhase::Queued);
        assert!(matches!(
            queued.report().begin(),
            kasumi_kv::TerminalObservation::NotEntered
        ));
    }
    fixture.publish(b"app-new", b"custody-new")?;
    let selected = prepared.begin()?;
    assert_eq!(selected.registered_reader_id(), Some(id));
    selected.require_domains(
        fixture.stores.application(),
        fixture.stores.custody().store(),
    )?;
    pair(&old, b"app-old", b"custody-old")?;
    pair(&selected, b"app-new", b"custody-new")?;
    selected.close()?;
    old.close()?;
    fixture.finish().await
}

#[tokio::test]
async fn prepared_pair_cancel_and_drop_retire_unbegun_actual_children() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.publish(b"app", b"custody")?;
    let baseline = fixture.memory.storage_census().snapshot();
    for explicit in [false, true] {
        let prepared = fixture.stores.prepare_read_view()?;
        let id = prepared.registered_reader_id().unwrap();
        if explicit {
            prepared.cancel()?;
        } else {
            drop(prepared);
        }
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        assert_eq!(fixture.memory.storage_census().snapshot(), baseline);
    }
    let selected = fixture.stores.read_view()?;
    pair(&selected, b"app", b"custody")?;
    selected.close()?;
    fixture.finish().await
}

#[tokio::test]
async fn prepared_pair_rechecks_each_domain_before_native_begin_and_retires_queue() -> Result<()> {
    for expire_application in [false, true] {
        let fixture = Fixture::new().await?;
        fixture.publish(b"app", b"custody")?;
        let baseline = fixture.memory.storage_census().snapshot();
        let prepared = fixture.stores.prepare_read_view()?;
        let id = prepared.registered_reader_id().unwrap();
        if expire_application {
            fixture.app_clock.expire();
        } else {
            fixture.custody_clock.expire();
        }
        let error = match prepared.begin() {
            Ok(_) => panic!("expired prepared pair began"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("key-access lease unavailable or expired")
        );
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        assert_eq!(fixture.memory.storage_census().snapshot(), baseline);
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_pair_denial_happens_before_registration_and_keeps_original_value() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.publish(b"app", b"custody")?;
    let baseline = fixture.memory.storage_census().snapshot();
    let before = fixture.memory.snapshot();
    let free = (256 << 20) - before.bookkeeping_bytes - before.used_bytes;
    let envelope = TestDiskMemory::required_reservation_bytes(0)?;
    let full = fixture.memory.clone().reserve_installed(free - envelope)?;
    let error = match fixture.stores.prepare_read_view() {
        Ok(_) => panic!("unfunded queued pair admitted"),
        Err(error) => error,
    };
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::OutOfMemory
    );
    assert_eq!(fixture.memory.storage_census().snapshot(), baseline);
    drop(full);
    let selected = fixture.stores.read_view()?;
    pair(&selected, b"app", b"custody")?;
    selected.close()?;
    fixture.finish().await
}

#[tokio::test]
async fn prepared_pair_unknown_cancellation_keeps_exact_payload_and_census_custody() -> Result<()> {
    for explicit in [false, true] {
        let fixture = Fixture::new().await?;
        let baseline = fixture.memory.storage_census().snapshot();
        let prepared = fixture.stores.prepare_read_view()?;
        let id = prepared.registered_reader_id().unwrap();
        let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        let payload = Box::new(0xbaadu64);
        let pointer = payload.as_ref() as *const u64;
        recovered.preserve_body_panic(payload);
        drop(recovered);
        if explicit {
            let error = prepared.cancel().unwrap_err();
            let failure = error.downcast_ref::<NodeScopedReadFailure>().unwrap();
            assert_eq!(failure.reader_id(), id);
            assert_eq!(
                failure.try_retire_routine(),
                StorageCensusDisposition::Retained
            );
            drop(error);
        } else {
            drop(prepared);
        }
        assert_eq!(
            fixture.memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        {
            let report = retained.report();
            assert_eq!(report.phase(), NodeReadPhase::Cancelled);
            let kasumi_kv::TerminalObservation::Panicked(payload) = report.body_panic() else {
                panic!("queued cancellation lost its original unknown outcome")
            };
            assert_eq!(
                payload.downcast_ref::<u64>().unwrap() as *const u64,
                pointer
            );
        }
        // Explicit acknowledgment cleans up this test's deliberately injected
        // unknown; neither cancel nor Drop is permitted to acknowledge it.
        assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
        assert_eq!(fixture.memory.storage_census().snapshot(), baseline);
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_pair_rejects_recovered_begin_before_application_publication() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.publish(b"app-old", b"custody-same")?;
    let prepared = fixture.stores.prepare_read_view()?;
    let id = prepared.registered_reader_id().unwrap();
    let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    let begun = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let worker = {
        let begun = begun.clone();
        let release = release.clone();
        std::thread::spawn(move || {
            assert_eq!(recovered.begin(), NodeReadPhase::Active);
            begun.wait();
            release.wait();
            recovered
        })
    };
    begun.wait();
    // Application bytes change while the custody bytes stay identical. The
    // old root must never be accepted merely because proof metadata matches.
    let published = fixture.publish(b"app-new", b"custody-same");
    let rejected = prepared.begin();
    release.wait();
    let recovered = worker.join().expect("recovered reader worker");
    published?;
    let error = match rejected {
        Ok(_) => panic!("prospective capture reused a previously begun native root"),
        Err(error) => error,
    };
    let failure = error.downcast_ref::<NodeScopedReadFailure>().unwrap();
    assert_eq!(failure.reader_id(), id);
    assert_eq!(failure.stage(), "prepared begin already entered");
    assert!(matches!(
        failure.report().begin(),
        kasumi_kv::TerminalObservation::Returned(Ok(()))
    ));
    drop(error);
    fixture.node.settle_registered_read(recovered, Ok(()))?;
    let current = fixture.stores.read_view()?;
    pair(&current, b"app-new", b"custody-same")?;
    current.close()?;
    fixture.finish().await
}
