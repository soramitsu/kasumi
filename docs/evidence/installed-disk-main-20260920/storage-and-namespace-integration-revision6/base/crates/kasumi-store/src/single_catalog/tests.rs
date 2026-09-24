use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};
use std::{future::Future, sync::atomic::AtomicUsize, task::Poll};

const TENANT: &str = "__kasumi_security";
fn node(
    fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>,
    fixture_scratch: std::sync::Arc<crate::ScratchDisk>,
) -> Result<(tempfile::TempDir, Arc<NodeStore>)> {
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("singleton.redb"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )?;
    Ok((directory, node))
}
fn input(node: Arc<NodeStore>, mode: Mode) -> Input {
    Input {
        node,
        tenant: TENANT.into(),
        provider: Arc::new(LocalKeyProvider::new([31; 32])),
        access: StorageAccess::security_audit(),
        clock: Arc::new(ManualClock::new()),
        renew: true,
        mode,
    }
}
fn contents(node: &NodeStore) -> Result<String> {
    let tx = node.db.begin_read()?;
    let mut hash = Sha256::new();
    for (index, table) in [CATALOG, RECORDS].into_iter().enumerate() {
        hash.update((index as u64).to_be_bytes());
        for row in tx.open_table(table)?.iter()? {
            let (key, value) = row?;
            hash.update((key.value().len() as u64).to_be_bytes());
            hash.update(key.value());
            hash.update((value.value().len() as u64).to_be_bytes());
            hash.update(value.value());
        }
    }
    Ok(hex::encode(hash.finalize()))
}
async fn drain(node: &NodeStore) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), node.drain_initializers()).await?
}

#[derive(Debug)]
struct PreparationFailure;
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("singleton provider preparation failed")
    }
}
impl std::error::Error for PreparationFailure {}
struct FailingProvider {
    generate: AtomicUsize,
    fail_unwrap: bool,
}
#[async_trait::async_trait]
impl KeyProvider for FailingProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.generate.fetch_add(1, Ordering::SeqCst);
        if self.fail_unwrap {
            LocalKeyProvider::new([31; 32]).generate_key(tenant).await
        } else {
            Err(PreparationFailure.into())
        }
    }
    async fn unwrap_key(&self, _: &str, _: &WrappedKey) -> Result<SecretKey> {
        Err(PreparationFailure.into())
    }
    async fn rewrap_key(&self, _: &str, _: &WrappedKey) -> Result<WrappedKey> {
        anyhow::bail!("unexpected rewrap")
    }
}

/// Stop only after the actual private delivery has buffered its ticket. Keep
/// the same preparation/delivery path and register its real terminal outcome.
async fn buffered(
    request: Input,
) -> Result<(oneshot::Receiver<Ticket>, Option<Weak<TenantStore>>)> {
    let node = request.node.clone();
    let (send, receive) = oneshot::channel();
    let (info, observed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let outcome = prepare(request, &send).await;
        let weak = outcome.as_ref().ok().map(|p| Arc::downgrade(&p.store));
        let delivery = deliver(outcome, send);
        tokio::pin!(delivery);
        std::future::poll_fn(|cx| {
            assert!(delivery.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let _ = info.send(weak);
        delivery.await
    });
    node.initializers.lock().await.handles.push(task);
    let weak = tokio::time::timeout(Duration::from_secs(5), observed).await??;
    Ok((receive, weak))
}

#[tokio::test]
async fn production_singletons_reject_paired_capabilities_before_provider_or_catalog_effects()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let provider = Arc::new(FailingProvider {
        generate: AtomicUsize::new(0),
        fail_unwrap: false,
    });
    let before = contents(&node)?;
    for (tenant, access) in [
        (
            "tenant".to_owned(),
            StorageAccess::standalone(Uuid::new_v4(), "tenant", Uuid::new_v4())?,
        ),
        ("__kasumi_control".to_owned(), StorageAccess::node_control()),
        (
            CustodyStore::catalog_name("tenant"),
            StorageAccess::custody("tenant"),
        ),
        ("fixture".to_owned(), StorageAccess::fixture()),
        (
            "wrong-security-namespace".to_owned(),
            StorageAccess::security_audit(),
        ),
    ] {
        assert!(
            TenantStore::initialize_catalog(
                node.clone(),
                tenant.clone(),
                provider.clone(),
                access.clone()
            )
            .await
            .is_err()
        );
        assert!(
            TenantStore::open_existing(node.clone(), tenant, provider.clone(), access)
                .await
                .is_err()
        );
    }
    assert_eq!(provider.generate.load(Ordering::SeqCst), 0);
    assert_eq!(contents(&node)?, before);
    assert!(node.initializers.lock().await.handles.is_empty());
    Ok(())
}

#[tokio::test]
async fn strict_singleton_creation_rejects_orphan_partial_and_existing_catalogs_without_mutation()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for kind in ["orphan", "partial", "existing"] {
        let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
        let owner = if kind == "existing" {
            Some(open(input(node.clone(), Mode::Initialize)).await?)
        } else {
            None
        };
        if kind != "existing" {
            let tx = node.db.begin_write()?;
            let hash = tenant_hash(TENANT);
            if kind == "orphan" {
                let mut key = hash.to_vec();
                key.extend_from_slice(b"retained");
                tx.open_table(RECORDS)?
                    .insert(key.as_slice(), b"unknown ciphertext".as_slice())?;
            } else {
                tx.open_table(CATALOG)?
                    .insert(hash.as_slice(), b"unsupported catalog".as_slice())?;
            }
            tx.commit()?;
        }
        let before = contents(&node)?;
        let failing = Arc::new(FailingProvider {
            generate: AtomicUsize::new(0),
            fail_unwrap: false,
        });
        let mut request = input(node.clone(), Mode::Initialize);
        request.provider = failing.clone();
        assert!(open(request).await.is_err());
        assert_eq!(failing.generate.load(Ordering::SeqCst), 0);
        if kind != "existing" {
            assert!(open(input(node.clone(), Mode::Existing)).await.is_err());
        }
        assert_eq!(contents(&node)?, before);
        if let Some(owner) = owner {
            owner.check_access()?;
            owner.shutdown().await.unwrap();
        }
        drain(&node).await?;
    }
    Ok(())
}

#[tokio::test]
async fn existing_singleton_requires_installed_catalog_and_never_repairs_cached_substitution()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let before = contents(&node)?;
    assert!(open(input(node.clone(), Mode::Existing)).await.is_err());
    assert_eq!(contents(&node)?, before);
    let owner = open(input(node.clone(), Mode::Initialize)).await?;
    let mut catalog = node.catalog(TENANT)?.unwrap();
    catalog.catalog_id = Uuid::new_v4();
    node.save_catalog(TENANT, &catalog)?;
    let before = contents(&node)?;
    assert!(open(input(node.clone(), Mode::Existing)).await.is_err());
    assert_eq!(contents(&node)?, before);
    owner.check_access()?;
    owner.shutdown().await.unwrap();
    drain(&node).await
}

#[tokio::test]
async fn buffered_singleton_success_publishes_only_on_claim_and_abandonment_preserves_borrowers()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for installed in ["fresh", "closed", "borrowed"] {
        for claim in [false, true] {
            let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
            let mut original = if installed != "fresh" {
                Some(open(input(node.clone(), Mode::Initialize)).await?)
            } else {
                None
            };
            if installed == "closed" {
                let closed = original.take().unwrap();
                closed.shutdown().await.unwrap();
                drop(closed);
            }
            drain(&node).await?;
            let before = contents(&node)?;
            let original_deadline = original.as_ref().map(|store| store.state.read().deadline);
            let request = input(
                node.clone(),
                if installed != "fresh" {
                    Mode::Existing
                } else {
                    Mode::Initialize
                },
            );
            let (receive, weak) = buffered(request).await?;
            let weak = weak.unwrap();
            let received = if claim {
                Some(receive.await?.claim()?)
            } else {
                drop(receive);
                None
            };
            drain(&node).await?;
            if installed != "fresh" {
                assert_eq!(contents(&node)?, before);
            }
            if let Some(original) = &original {
                original.check_access()?;
                assert_eq!(Some(original.state.read().deadline), original_deadline);
                if let Some(received) = &received {
                    assert!(Arc::ptr_eq(original, received));
                }
            } else if let Some(received) = &received {
                let same = open(input(node.clone(), Mode::Existing)).await?;
                assert!(Arc::ptr_eq(received, &same));
            } else {
                assert!(
                    weak.upgrade().is_none(),
                    "abandoned unpublished worker owner leaked"
                );
                assert!(
                    node.tenants.lock().await[TENANT]
                        .lock()
                        .await
                        .upgrade()
                        .is_none()
                );
            }
            if let Some(received) = received {
                received.shutdown().await.unwrap();
            }
            if let Some(original) = original {
                original.shutdown().await.unwrap();
            }
            drain(&node).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn borrowed_singleton_keeps_original_provider_clock_and_deadline() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let mut request = input(node.clone(), Mode::Initialize);
    request.renew = false;
    let provider = request.provider.clone();
    let clock = request.clock.clone();
    let original = open(request).await?;
    let deadline = original.state.read().deadline;
    let failing = Arc::new(FailingProvider {
        generate: AtomicUsize::new(0),
        fail_unwrap: false,
    });
    let same = TenantStore::open_existing(
        node.clone(),
        TENANT.into(),
        failing,
        StorageAccess::security_audit(),
    )
    .await?;
    assert!(Arc::ptr_eq(&original, &same));
    assert!(Arc::ptr_eq(&same.provider, &provider));
    assert!(Arc::ptr_eq(&same.clock, &clock));
    assert_eq!(same.state.read().deadline, deadline);
    assert!(same.background.lock().await.handles.is_empty());
    same.shutdown().await.unwrap();
    drain(&node).await
}

#[tokio::test]
async fn buffered_singleton_preparation_errors_require_actual_claim_and_preserve_partial_installation()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for existing in [false, true] {
        for claim in [false, true] {
            let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
            if existing {
                open(input(node.clone(), Mode::Initialize))
                    .await?
                    .shutdown()
                    .await
                    .unwrap();
            }
            drain(&node).await?;
            let before = contents(&node)?;
            let mut request = input(
                node.clone(),
                if existing {
                    Mode::Existing
                } else {
                    Mode::Initialize
                },
            );
            let provider = Arc::new(FailingProvider {
                generate: AtomicUsize::new(0),
                fail_unwrap: false,
            });
            request.provider = provider.clone();
            let (receive, weak) = buffered(request).await?;
            assert_eq!(
                provider.generate.load(Ordering::SeqCst),
                usize::from(!existing)
            );
            assert!(weak.is_none());
            if claim {
                assert!(
                    receive
                        .await?
                        .claim()
                        .err()
                        .unwrap()
                        .is::<PreparationFailure>()
                );
            } else {
                drop(receive);
            }
            let outcome = drain(&node).await;
            if claim {
                outcome?;
            } else {
                assert!(outcome.unwrap_err().is::<PreparationFailure>());
            }
            drain(&node).await?;
            assert_eq!(contents(&node)?, before);
        }
    }
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let mut request = input(node.clone(), Mode::Initialize);
    request.provider = Arc::new(FailingProvider {
        generate: AtomicUsize::new(0),
        fail_unwrap: true,
    });
    assert!(
        open(request)
            .await
            .err()
            .unwrap()
            .is::<PreparationFailure>()
    );
    assert!(node.catalog(TENANT)?.is_some());
    let partial = contents(&node)?;
    assert!(open(input(node.clone(), Mode::Initialize)).await.is_err());
    assert_eq!(contents(&node)?, partial);
    drain(&node).await
}

#[tokio::test]
async fn cancelled_singleton_drain_retains_buffered_preparation_error() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let mut request = input(node.clone(), Mode::Initialize);
    request.provider = Arc::new(FailingProvider {
        generate: AtomicUsize::new(0),
        fail_unwrap: false,
    });
    let (receive, _) = buffered(request).await?;
    let (release, wait) = oneshot::channel::<()>();
    let retained = node.clone();
    let pending = tokio::spawn(async move {
        let _retained = retained;
        wait.await?;
        Ok(())
    });
    node.initializers.lock().await.handles.insert(0, pending);
    drop(receive);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !node
            .initializers
            .lock()
            .await
            .handles
            .last()
            .unwrap()
            .is_finished()
        {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let mut draining = Box::pin(node.drain_initializers());
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(draining);
    assert!(
        node.initializers
            .lock()
            .await
            .failure
            .as_ref()
            .unwrap()
            .is::<PreparationFailure>()
    );
    release.send(()).unwrap();
    assert!(drain(&node).await.unwrap_err().is::<PreparationFailure>());
    drain(&node).await
}

struct PausedProvider {
    inner: LocalKeyProvider,
    entered: Notify,
    release: Notify,
}
#[async_trait::async_trait]
impl KeyProvider for PausedProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.generate_key(tenant).await
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.inner.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.inner.rewrap_key(tenant, wrapped).await
    }
}

#[tokio::test]
async fn cancelling_during_singleton_key_preparation_retains_actual_node_until_provider_drains()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let provider = Arc::new(PausedProvider {
        inner: LocalKeyProvider::new([31; 32]),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let mut request = input(node.clone(), Mode::Initialize);
    request.provider = provider.clone();
    let receive = begin(request).await?;
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    drop(receive);
    let mut draining = Box::pin(node.drain_initializers());
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(draining);
    assert!(
        NodeStore::open_existing_fixture(
            directory.path().join("singleton.redb"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    provider.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    provider.release.notify_one();
    assert!(format!("{:#}", drain(&node).await.unwrap_err()).contains("singleton receiver closed"));
    drain(&node).await?;
    assert!(node.catalog(TENANT)?.is_none());
    drop(node);
    let reopened = NodeStore::open_existing_fixture(
        directory.path().join("singleton.redb"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )?;
    assert!(reopened.catalog(TENANT)?.is_none());
    Ok(())
}
