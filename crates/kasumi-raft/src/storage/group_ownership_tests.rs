//! A retained group fence owns its exact, admitted store identity.
use super::*;

#[tokio::test]
async fn group_fence_keeps_store_identity_until_positive_release() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(
        directory.path(),
        kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096),
    );
    let store = new_fault_store(FaultBackend::new(), scratch.clone()).await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let identity = Arc::downgrade(domains.custody().store());
    let first = crate::claim_store(&domains)?;
    let owner = SnapshotBufferOwner::fixture();
    owner.bind_group_ownership(first.clone(), domains.custody().store().clone())?;
    assert!(crate::claim_store(&domains).is_err());

    // No Raft worker was started. Its empty positive census can release this
    // claim, and a new claim on the very same store must then succeed.
    owner.drain_buffers().await?;
    owner.release_group_ownership();
    assert!(!first.load(Ordering::Acquire));
    let second = crate::claim_store(&domains)?;
    assert!(!Arc::ptr_eq(&first, &second));
    let retained = SnapshotBufferOwner::fixture();
    retained.bind_group_ownership(second.clone(), domains.custody().store().clone())?;
    domains.shutdown().await?;
    drop(domains);
    assert!(second.load(Ordering::Acquire));
    assert!(
        identity.upgrade().is_some(),
        "live fence lost its store identity"
    );

    // A different physical store remains independent while the old fence is
    // unresolved. The old address cannot be recycled: its full owner survives.
    let unrelated = new_fault_store(FaultBackend::new(), scratch).await?;
    let unrelated = kasumi_store::test_utils::initialize_custody_fixture(
        unrelated,
        Arc::new(LocalKeyProvider::new([242; 32])),
    )
    .await?;
    assert_ne!(identity.as_ptr(), Arc::as_ptr(unrelated.custody().store()));
    let other = crate::claim_store(&unrelated)?;
    let other_owner = SnapshotBufferOwner::fixture();
    other_owner.bind_group_ownership(other.clone(), unrelated.custody().store().clone())?;
    assert!(crate::claim_store(&unrelated).is_err());
    other_owner.drain_buffers().await?;
    other_owner.release_group_ownership();
    unrelated.shutdown().await?;

    retained.drain_buffers().await?;
    retained.release_group_ownership();
    assert!(!second.load(Ordering::Acquire));
    assert!(
        identity.upgrade().is_none(),
        "completed drain retained the store"
    );
    Ok(())
}
