use super::*;
use crate::test_utils::LocalKeyProvider;
use std::{future::Future, task::Poll};

struct Fixture {
    directory: tempfile::TempDir,
    node: Arc<NodeStore>,
    scratch_directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let directory = crate::test_utils::private_tempdir()?;
        let node = NodeStore::create_new_fixture(
            directory.path().join("existing.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )?;
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            "existing".into(),
            Arc::new(LocalKeyProvider::new([61; 32])),
            Arc::new(LocalKeyProvider::new([62; 32])),
            StorageAccess::fixture(),
        )
        .await?;
        stores
            .application
            .write_batch(&[WriteOp::put("data", b"kept", b"original".to_vec())])?;
        stores.shutdown().await.unwrap();
        node.drain_initializers().await?;
        Ok(Self {
            directory,
            node,
            scratch_directory,
        })
    }
    fn contents(&self) -> Result<Vec<u8>> {
        let tx = self.node.db.begin_read()?;
        let mut hash = Sha256::new();
        for (index, definition) in [CATALOG, RECORDS].into_iter().enumerate() {
            hash.update((index as u64).to_be_bytes());
            for row in tx.open_table(definition)?.iter()? {
                let (key, value) = row?;
                hash.update((key.value().len() as u64).to_be_bytes());
                hash.update(key.value());
                hash.update((value.value().len() as u64).to_be_bytes());
                hash.update(value.value());
            }
        }
        Ok(hash.finalize().to_vec())
    }
    async fn custody(&self) -> Result<Arc<CustodyStore>> {
        CustodyStore::open(
            self.node.clone(),
            "existing".into(),
            Arc::new(LocalKeyProvider::new([62; 32])),
        )
        .await
    }
    async fn reopened_after_release(self) -> Result<()> {
        let Fixture {
            directory,
            node,
            scratch_directory: _scratch_directory,
        } = self;
        let fixture_scratch = node.scratch_disk().clone();
        let fixture_memory = fixture_scratch.memory().clone();
        node.drain_initializers().await?;
        drop(node);
        let node = NodeStore::open_existing_fixture(
            directory.path().join("existing.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )?;
        let stores = TenantStorageSet::open_existing_fixture(
            node.clone(),
            "existing".into(),
            Arc::new(LocalKeyProvider::new([61; 32])),
            Arc::new(LocalKeyProvider::new([62; 32])),
        )
        .await?;
        assert_eq!(
            stores.application.get("data", b"kept")?,
            Some(b"original".to_vec())
        );
        stores.shutdown().await.unwrap();
        node.drain_initializers().await?;
        Ok(())
    }
}

struct PausedApplication {
    entered: Notify,
    release: Notify,
    entered_once: AtomicBool,
    active: AtomicBool,
    fail: bool,
    provider: LocalKeyProvider,
}
impl PausedApplication {
    fn new(fail: bool) -> Arc<Self> {
        Arc::new(Self {
            entered: Notify::new(),
            release: Notify::new(),
            entered_once: AtomicBool::new(false),
            active: AtomicBool::new(false),
            fail,
            provider: LocalKeyProvider::new([61; 32]),
        })
    }
}
#[async_trait::async_trait]
impl KeyProvider for PausedApplication {
    async fn generate_key(&self, _: &str) -> Result<GeneratedKey> {
        anyhow::bail!("existing open attempted key generation")
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        if !self.entered_once.swap(true, Ordering::AcqRel) {
            self.active.store(true, Ordering::Release);
            self.entered.notify_one();
            self.release.notified().await;
            self.active.store(false, Ordering::Release);
        }
        ensure!(!self.fail, "injected application unwrap failure");
        self.provider.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, _: &str, _: &WrappedKey) -> Result<WrappedKey> {
        anyhow::bail!("existing open attempted rewrap")
    }
}

async fn interrupted_after_custody(borrowed: bool, cancel: bool) -> Result<()> {
    let fixture = Fixture::new().await?;
    let custody = if borrowed {
        Some(fixture.custody().await?)
    } else {
        None
    };
    let deadline = custody
        .as_ref()
        .map(|store| store.store.state.read().deadline);
    let before = fixture.contents()?;
    let provider = PausedApplication::new(!cancel);
    let mut opening = Box::pin(TenantStorageSet::open_existing(
        fixture.node.clone(),
        "existing".into(),
        provider.clone(),
        Arc::new(LocalKeyProvider::new([62; 32])),
        StorageAccess::fixture(),
    ));
    std::future::poll_fn(|context| {
        assert!(opening.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    assert!(provider.active.load(Ordering::Acquire));
    if cancel {
        // The future owns the result receiver. Drop its actual allocated future,
        // not just a Pin reborrow, while the provider operation remains pending.
        drop(opening);
    } else {
        provider.release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), opening)
                .await?
                .is_err()
        );
    }
    if cancel {
        provider.release.notify_one();
    }
    let drained =
        tokio::time::timeout(Duration::from_secs(5), fixture.node.drain_initializers()).await?;
    if cancel {
        let error = drained.unwrap_err();
        assert!(format!("{error:#}").contains("existing catalog receiver closed"));
        fixture.node.drain_initializers().await?;
    } else {
        drained?;
    }
    assert!(!provider.active.load(Ordering::Acquire));
    assert_eq!(fixture.contents()?, before);
    if let Some(custody) = custody {
        custody.store.check_access()?;
        assert_eq!(Some(custody.store.state.read().deadline), deadline);
        let same = fixture.custody().await?;
        assert!(Arc::ptr_eq(same.store(), custody.store()));
        drop(same);
        custody.store.shutdown().await.unwrap();
        drop(custody);
    }
    fixture.reopened_after_release().await
}

#[tokio::test]
async fn application_failure_drains_new_custody_without_changing_existing_bytes() -> Result<()> {
    interrupted_after_custody(false, false).await
}
#[tokio::test]
async fn application_failure_preserves_borrowed_custody_and_original_deadline() -> Result<()> {
    interrupted_after_custody(true, false).await
}
#[tokio::test]
async fn caller_cancellation_drains_only_new_domains_after_active_provider_work() -> Result<()> {
    interrupted_after_custody(false, true).await
}
#[tokio::test]
async fn caller_cancellation_never_closes_a_borrowed_custody_owner() -> Result<()> {
    interrupted_after_custody(true, true).await
}

#[tokio::test]
async fn buffered_existing_pair_ticket_publishes_nothing_and_drains_its_new_workers() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let before = fixture.contents()?;
    let (send, receive) = oneshot::channel();
    let prepared = prepare(
        fixture.node.clone(),
        "existing".into(),
        Arc::new(LocalKeyProvider::new([62; 32])),
        Some((
            Arc::new(LocalKeyProvider::new([61; 32])),
            StorageAccess::fixture(),
        )),
        &send,
    )
    .await?;
    assert!(prepared.custody.ownership == Ownership::New);
    assert!(prepared.application.as_ref().unwrap().ownership == Ownership::New);
    let custody = prepared.custody.store.clone();
    let application = prepared.application.as_ref().unwrap().store.clone();
    let delivery = deliver(Ok(prepared), send);
    tokio::pin!(delivery);
    std::future::poll_fn(|context| {
        assert!(delivery.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(receive);
    tokio::time::timeout(Duration::from_secs(5), delivery).await??;
    assert!(custody.background.lock().await.handles.is_empty());
    assert!(application.background.lock().await.handles.is_empty());
    assert!(custody.check_access().is_err());
    assert!(application.check_access().is_err());
    for tenant in [
        "existing".to_owned(),
        CustodyStore::catalog_name("existing"),
    ] {
        let gate = fixture.node.tenants.lock().await[&tenant].clone();
        assert!(gate.lock().await.upgrade().is_none());
    }
    assert_eq!(fixture.contents()?, before);
    drop(custody);
    drop(application);
    fixture.reopened_after_release().await
}

#[tokio::test]
async fn missing_binding_rejects_new_custody_and_leaves_every_existing_byte_unchanged() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let custody = fixture.custody().await?;
    custody
        .store
        .write_batch(&[WriteOp::delete(BINDING_NS, BINDING_KEY)])?;
    custody.store.shutdown().await.unwrap();
    drop(custody);
    let before = fixture.contents()?;
    for _ in 0..2 {
        assert!(fixture.custody().await.is_err());
        tokio::time::timeout(Duration::from_secs(5), fixture.node.drain_initializers()).await??;
        assert_eq!(fixture.contents()?, before);
    }
    let Fixture {
        directory,
        node,
        scratch_directory: _scratch_directory,
    } = fixture;
    let fixture_scratch = node.scratch_disk().clone();
    let fixture_memory = fixture_scratch.memory().clone();
    drop(node);
    let _node = NodeStore::open_existing_fixture(
        directory.path().join("existing.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )?;
    Ok(())
}

#[tokio::test]
async fn unclaimed_borrowed_pair_and_changed_binding_never_close_its_cached_owners() -> Result<()> {
    let fixture = Fixture::new().await?;
    let original = TenantStorageSet::open_existing_fixture(
        fixture.node.clone(),
        "existing".into(),
        Arc::new(LocalKeyProvider::new([61; 32])),
        Arc::new(LocalKeyProvider::new([62; 32])),
    )
    .await?;
    let application_deadline = original.application.state.read().deadline;
    let custody_deadline = original.custody.store.state.read().deadline;
    let saved_binding = original
        .custody
        .store
        .get(BINDING_NS, BINDING_KEY)?
        .unwrap();
    for change_binding in [false, true] {
        let (send, receive) = oneshot::channel();
        // Providers deliberately cannot generate/rewrap and would pause on an
        // unwrap. Neither borrowed owner may replace its original provider.
        let unused = PausedApplication::new(true);
        let prepared = prepare(
            fixture.node.clone(),
            "existing".into(),
            unused.clone(),
            Some((unused.clone(), StorageAccess::fixture())),
            &send,
        )
        .await?;
        assert!(prepared.custody.ownership == Ownership::Borrowed);
        assert!(prepared.application.as_ref().unwrap().ownership == Ownership::Borrowed);
        assert!(!unused.entered_once.load(Ordering::Acquire));
        let delivery = deliver(Ok(prepared), send);
        tokio::pin!(delivery);
        std::future::poll_fn(|context| {
            assert!(delivery.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        if change_binding {
            original
                .custody
                .store
                .write_batch(&[WriteOp::delete(BINDING_NS, BINDING_KEY)])?;
            let before = fixture.contents()?;
            assert!(receive.await?.claim().is_err());
            tokio::time::timeout(Duration::from_secs(5), delivery).await??;
            assert_eq!(fixture.contents()?, before);
            original.custody.store.write_batch(&[WriteOp::put(
                BINDING_NS,
                BINDING_KEY,
                saved_binding.clone(),
            )])?;
        } else {
            let before = fixture.contents()?;
            drop(receive);
            tokio::time::timeout(Duration::from_secs(5), delivery).await??;
            assert_eq!(fixture.contents()?, before);
        }
        original.check_access()?;
        assert_eq!(
            original.application.state.read().deadline,
            application_deadline
        );
        assert_eq!(
            original.custody.store.state.read().deadline,
            custody_deadline
        );
        assert_eq!(
            original.application.get("data", b"kept")?,
            Some(b"original".to_vec())
        );
    }
    original.shutdown().await.unwrap();
    drop(original);
    fixture.reopened_after_release().await
}

#[tokio::test]
async fn buffered_existing_preparation_failure_requires_claim_and_preserves_borrowed_owners()
-> Result<()> {
    for borrowed in [false, true] {
        for claim in [false, true] {
            let fixture = Fixture::new().await?;
            let custody = if borrowed {
                Some(fixture.custody().await?)
            } else {
                None
            };
            let deadline = custody
                .as_ref()
                .map(|value| value.store.state.read().deadline);
            let before = fixture.contents()?;
            let (send, receive) = oneshot::channel();
            let buffered = Arc::new(Notify::new());
            let sent = buffered.clone();
            let node = fixture.node.clone();
            let task = tokio::spawn(async move {
                let outcome = prepare(
                    node,
                    "existing".into(),
                    Arc::new(LocalKeyProvider::new([62; 32])),
                    Some((
                        Arc::new(LocalKeyProvider::new([97; 32])),
                        StorageAccess::fixture(),
                    )),
                    &send,
                )
                .await
                .map_err(|error| error.context("buffered existing application failure"));
                assert!(
                    outcome.is_err(),
                    "wrong application wrapping key must fail preparation"
                );
                let delivery = deliver(outcome, send);
                tokio::pin!(delivery);
                std::future::poll_fn(|context| {
                    assert!(delivery.as_mut().poll(context).is_pending());
                    Poll::Ready(())
                })
                .await;
                sent.notify_one();
                delivery.await
            });
            fixture.node.initializers.lock().await.handles.push(task);
            tokio::time::timeout(Duration::from_secs(5), buffered.notified()).await?;
            if claim {
                let error = receive.await?.claim().err().expect("preparation must fail");
                assert!(format!("{error:#}").contains("buffered existing application failure"));
            } else {
                drop(receive);
            }
            let outcome =
                tokio::time::timeout(Duration::from_secs(5), fixture.node.drain_initializers())
                    .await?;
            if claim {
                outcome?;
            } else {
                assert!(
                    format!("{:#}", outcome.unwrap_err())
                        .contains("buffered existing application failure")
                );
            }
            fixture.node.drain_initializers().await?;
            assert_eq!(fixture.contents()?, before);
            if let Some(custody) = custody {
                custody.store.check_access()?;
                assert_eq!(Some(custody.store.state.read().deadline), deadline);
                let same = fixture.custody().await?;
                assert!(Arc::ptr_eq(same.store(), custody.store()));
                drop(same);
                custody.store.shutdown().await.unwrap();
                drop(custody);
            }
            fixture.reopened_after_release().await?;
        }
    }
    Ok(())
}
