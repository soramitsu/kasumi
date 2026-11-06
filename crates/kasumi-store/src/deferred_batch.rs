//! A paired-domain batch whose commit waits for the next publication its own
//! thread makes on its storage set, so that one transaction carries both.
//!
//! The standalone writer defers an entry's journal record this way while the
//! entry applies, and the entry's publication carries it. Any other durable
//! tenant write the applying thread makes on the same node first commits the
//! deferred batch by itself, under the caller's gate, exactly as the record's
//! own earlier commit would have. So nothing an apply writes ahead of its
//! publication (an immutable receipt or terminal pair, say) can outlive a
//! refused or interrupted publication without the record it belongs to.
use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

/// What became of a deferred batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredState {
    /// Nothing has committed or taken it.
    Waiting,
    /// The carrying publication took it; that publication's outcome is its
    /// outcome.
    Carried,
    /// Another write on the node committed it by itself first.
    Committed,
    /// Committing it by itself failed. Whether it took effect is unknown
    /// unless the returned error proves a refusal.
    Failed,
}

struct Pending {
    // The caller's own owner of the set, which may track its storage lifetime.
    set: Box<dyn std::ops::Deref<Target = TenantStorageSet>>,
    application: Vec<WriteOp>,
    custody: Vec<WriteOp>,
    gate: Arc<std::sync::Mutex<()>>,
    state: Rc<Cell<DeferredState>>,
    // The carrying publication has begun, under the gate: no other write on
    // the node may commit the batch from now on.
    sealed: bool,
}

thread_local! {
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

/// The registration of one deferred batch on the current thread. Dropping it
/// discards a batch that nothing committed. It is neither Send nor Sync: it
/// ends on the thread that deferred it.
pub struct DeferredBatch {
    state: Rc<Cell<DeferredState>>,
}

/// A deferred batch's operations, moved into the publication that carries
/// them ahead of its own operations in each domain.
pub struct CarriedBatch {
    application: Vec<WriteOp>,
    custody: Vec<WriteOp>,
}
impl CarriedBatch {
    pub(crate) fn application(&self) -> &[WriteOp] {
        &self.application
    }
    pub(crate) fn custody(&self) -> &[WriteOp] {
        &self.custody
    }
}

impl TenantStorageSet {
    /// Defer `application` and `custody` on this thread until this thread's
    /// next publication on the set `owner` holds carries them, or until
    /// another tenant write on the same node commits them first, under
    /// `gate`. At most one batch waits per thread; `owner` lives as long.
    pub fn defer_batch(
        owner: impl std::ops::Deref<Target = TenantStorageSet> + 'static,
        application: Vec<WriteOp>,
        custody: Vec<WriteOp>,
        gate: Arc<std::sync::Mutex<()>>,
    ) -> Result<DeferredBatch> {
        validate_batch(&[&application, &custody])?;
        reject_unpaired_identity_ops(&application)?;
        reject_unpaired_identity_ops(&custody)?;
        let state = Rc::new(Cell::new(DeferredState::Waiting));
        PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            ensure!(
                pending.is_none(),
                "another deferred batch is waiting on this thread"
            );
            *pending = Some(Pending {
                set: Box::new(owner),
                application,
                custody,
                gate,
                state: state.clone(),
                sealed: false,
            });
            Ok(())
        })?;
        Ok(DeferredBatch { state })
    }

    /// Publish `application_ops` and `custody_ops` in one durable transaction
    /// that also carries `carried`, ahead of them in each domain.
    pub fn write_batch_replacing_outcome_carrying(
        &self,
        carried: CarriedBatch,
        application_ops: &[WriteOp],
        custody_ops: &[WriteOp],
    ) -> Result<DomainPublicationOutcome> {
        self.publish_carrying(Some(&carried), application_ops, custody_ops)
    }
}

impl DeferredBatch {
    pub fn state(&self) -> DeferredState {
        self.state.get()
    }

    /// The carrying publication is beginning, under the gate the batch would
    /// commit under by itself. Any other write this thread makes on the node
    /// from now on fails with no effect instead of committing the batch, so
    /// nothing can precede the publication or wait for that gate.
    pub fn seal(&self) {
        PENDING.with(|pending| {
            if let Some(pending) = pending
                .borrow_mut()
                .as_mut()
                .filter(|pending| Rc::ptr_eq(&pending.state, &self.state))
            {
                pending.sealed = true;
            }
        });
    }

    /// The operations, for the publication that carries them. None once
    /// another write has committed them, or failed to.
    pub fn take(&self) -> Option<CarriedBatch> {
        if self.state.get() != DeferredState::Waiting {
            return None;
        }
        let pending = PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            if pending
                .as_ref()
                .is_some_and(|pending| Rc::ptr_eq(&pending.state, &self.state))
            {
                pending.take()
            } else {
                None
            }
        })?;
        self.state.set(DeferredState::Carried);
        Some(CarriedBatch {
            application: pending.application,
            custody: pending.custody,
        })
    }
}

impl Drop for DeferredBatch {
    fn drop(&mut self) {
        let _ = PENDING.try_with(|pending| {
            let mut pending = pending.borrow_mut();
            if pending
                .as_ref()
                .is_some_and(|pending| Rc::ptr_eq(&pending.state, &self.state))
            {
                drop(pending.take());
            }
        });
    }
}

/// Every tenant write entry point calls this first, before taking any store
/// lock: a batch waiting on this thread for a set on `node` commits by itself
/// before the write. Its failure fails the write, which then has no effect.
pub(crate) fn before_write(node: &NodeStore) -> Result<()> {
    let pending = PENDING.with(|pending| {
        let mut pending = pending.borrow_mut();
        match pending.as_ref() {
            Some(waiting) if NodeStore::ptr_eq(&waiting.set.application().node, node) => {
                ensure!(
                    !waiting.sealed,
                    "write inside the publication that carries a deferred batch"
                );
                Ok(pending.take())
            }
            _ => Ok(None),
        }
    })?;
    let Some(pending) = pending else {
        return Ok(());
    };
    #[cfg(any(test, feature = "test-utils"))]
    pending
        .set
        .deferred_flushes
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let gate = pending
        .gate
        .lock()
        .map_err(|_| anyhow::anyhow!("deferred batch gate poisoned"))?;
    let result = pending
        .set
        .write_batch(&pending.application, &pending.custody);
    drop(gate);
    pending.state.set(if result.is_ok() {
        DeferredState::Committed
    } else {
        DeferredState::Failed
    });
    result
}

impl TenantStorageSet {
    /// Deferred batches on this set that another write committed by itself
    /// before their carrying publication.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn deferred_flushes_for_test(&self) -> u64 {
        self.deferred_flushes
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::LocalKeyProvider;

    const NS: &str = "deferred.test";

    struct Fixture {
        _scratch_directory: tempfile::TempDir,
        directory: tempfile::TempDir,
        memory: Arc<crate::test_utils::TestDiskMemory>,
        scratch: Arc<crate::ScratchDisk>,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
            let scratch_directory = crate::test_utils::private_tempdir()?;
            let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
            Ok(Self {
                _scratch_directory: scratch_directory,
                directory: crate::test_utils::private_tempdir()?,
                memory,
                scratch,
            })
        }
        async fn set(&self, name: &str) -> Result<Arc<TenantStorageSet>> {
            let node = NodeStore::create_new_fixture(
                self.directory.path().join(name),
                crate::test_utils::NODE_STORE_ID,
                self.memory.clone(),
                self.scratch.clone(),
            )
            .expect("bounded node fixture setup succeeds");
            TenantStorageSet::initialize_catalogs_fixture(
                node,
                "tenant".into(),
                Arc::new(LocalKeyProvider::new([31; 32])),
                Arc::new(LocalKeyProvider::new([32; 32])),
            )
            .await
        }
    }

    fn defer(stores: &Arc<TenantStorageSet>) -> Result<DeferredBatch> {
        TenantStorageSet::defer_batch(
            stores.clone(),
            vec![WriteOp::put(NS, b"record", b"application".to_vec())],
            vec![WriteOp::put(NS, b"record", b"custody".to_vec())],
            Arc::new(std::sync::Mutex::new(())),
        )
    }

    fn read(store: &TenantStore, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(store.get(NS, key)?.map(|value| value.to_vec()))
    }

    fn recorded(stores: &TenantStorageSet) -> Result<bool> {
        let application = read(stores.application(), b"record")?;
        let custody = read(stores.custody().store(), b"record")?;
        assert_eq!(application.is_some(), custody.is_some());
        Ok(application.is_some())
    }

    #[tokio::test]
    async fn the_carrying_publication_commits_the_batch_with_its_own_writes() -> Result<()> {
        let fixture = Fixture::new()?;
        let stores = fixture.set("carried.kv").await?;
        let deferred = defer(&stores)?;
        assert_eq!(deferred.state(), DeferredState::Waiting);
        let carried = deferred.take().context("waiting batch")?;
        assert_eq!(deferred.state(), DeferredState::Carried);
        assert!(deferred.take().is_none());
        stores
            .write_batch_replacing_outcome_carrying(
                carried,
                &[WriteOp::put(NS, b"effect", b"effect".to_vec())],
                &[WriteOp::put(NS, b"cursor", b"cursor".to_vec())],
            )?
            .into_result()?;
        assert!(recorded(&stores)?);
        assert_eq!(
            read(stores.application(), b"effect")?,
            Some(b"effect".to_vec())
        );
        assert_eq!(
            read(stores.custody().store(), b"cursor")?,
            Some(b"cursor".to_vec())
        );
        assert_eq!(stores.deferred_flushes_for_test(), 0);
        drop(deferred);
        stores.shutdown().await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn any_other_write_on_the_node_commits_the_batch_first() -> Result<()> {
        let fixture = Fixture::new()?;
        let stores = fixture.set("ahead.kv").await?;
        let deferred = defer(&stores)?;
        // An immutable pair staged ahead of the publication, say.
        stores
            .application()
            .write_batch(&[WriteOp::put(NS, b"ahead", b"ahead".to_vec())])?;
        assert_eq!(deferred.state(), DeferredState::Committed);
        assert!(recorded(&stores)?);
        assert_eq!(
            read(stores.application(), b"ahead")?,
            Some(b"ahead".to_vec())
        );
        assert_eq!(stores.deferred_flushes_for_test(), 1);
        // The publication finds nothing left to carry, and later writes do
        // not commit the batch again.
        assert!(deferred.take().is_none());
        stores.write_batch(
            &[WriteOp::put(NS, b"effect", b"effect".to_vec())],
            &[WriteOp::put(NS, b"cursor", b"cursor".to_vec())],
        )?;
        assert_eq!(stores.deferred_flushes_for_test(), 1);
        drop(deferred);
        stores.shutdown().await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn a_sealed_batch_refuses_other_writes_until_its_publication_carries_it() -> Result<()> {
        let fixture = Fixture::new()?;
        let stores = fixture.set("sealed.kv").await?;
        let deferred = defer(&stores)?;
        deferred.seal();
        assert!(
            stores
                .application()
                .write_batch(&[WriteOp::put(NS, b"inside", b"inside".to_vec())])
                .is_err()
        );
        assert_eq!(read(stores.application(), b"inside")?, None);
        assert_eq!(deferred.state(), DeferredState::Waiting);
        let carried = deferred.take().context("sealed batch still waits")?;
        stores
            .write_batch_replacing_outcome_carrying(carried, &[], &[])?
            .into_result()?;
        assert!(recorded(&stores)?);
        assert_eq!(stores.deferred_flushes_for_test(), 0);
        drop(deferred);
        stores.shutdown().await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_batch_is_discarded_and_other_nodes_and_threads_never_commit_it() -> Result<()>
    {
        let fixture = Fixture::new()?;
        let stores = fixture.set("dropped.kv").await?;
        let other = fixture.set("other.kv").await?;
        let deferred = defer(&stores)?;
        // Another node's writes, and this node's writes from another thread,
        // belong to no deferred batch.
        other
            .application()
            .write_batch(&[WriteOp::put(NS, b"other", b"other".to_vec())])?;
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    stores.application().write_batch(&[WriteOp::put(
                        NS,
                        b"thread",
                        b"thread".to_vec(),
                    )])
                })
                .join()
                .unwrap()
        })?;
        assert_eq!(deferred.state(), DeferredState::Waiting);
        assert!(!recorded(&stores)?);
        // One batch waits per thread.
        assert!(defer(&other).is_err());
        drop(deferred);
        stores
            .application()
            .write_batch(&[WriteOp::put(NS, b"after", b"after".to_vec())])?;
        assert!(!recorded(&stores)?);
        assert_eq!(stores.deferred_flushes_for_test(), 0);
        assert_eq!(other.deferred_flushes_for_test(), 0);
        stores.shutdown().await.unwrap();
        other.shutdown().await.unwrap();
        Ok(())
    }
}
