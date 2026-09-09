//! Detached-worker counterexamples use actual encrypted snapshot publication.
use super::*;
use std::time::Duration;

struct RestoreFailureBackend {
    current: BytesBackend,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    panic: bool,
}
struct RestoreFailureCandidate<'a> {
    backend: &'a RestoreFailureBackend,
    writes: Vec<WriteOp>,
}
impl crate::PreparedStateMachineRestore for RestoreFailureCandidate<'_> {
    fn retirement(&self) -> Option<crate::RetiredSnapshotState> {
        None
    }
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)> {
        vec![]
    }
    fn application_writes(&self) -> &[WriteOp] {
        &self.writes
    }
    fn publish(self: Box<Self>) -> Result<()> {
        self.backend
            .entered
            .lock()
            .unwrap()
            .take()
            .context("publication already attempted")?
            .send(())
            .map_err(|_| anyhow::anyhow!("publication observer disappeared"))?;
        self.backend
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))?;
        assert!(
            !self.backend.panic,
            "injected post-publication backend panic"
        );
        anyhow::bail!("injected post-publication backend failure")
    }
}
impl StateMachineBackend for RestoreFailureBackend {
    fn close_application(&self) {
        self.current.close_application();
    }
    fn apply(
        &self,
        context: &crate::AppliedEntryContext,
        bytes: &[u8],
    ) -> Result<crate::AppliedResponse> {
        self.current.apply(context, bytes)
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        self.current.capture_snapshot()
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        self.current.validate_snapshot(bytes)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        self.validate_snapshot(bytes)?;
        Ok(Box::new(RestoreFailureCandidate {
            backend: self,
            writes: vec![put(
                "worker-failure",
                b"checkpoint",
                context.checkpoint_sha256()?.into_bytes(),
            )],
        }))
    }
}

async fn cancelled_publication_failure(panic: bool) -> Result<()> {
    let disk = FaultBackend::new();
    let store = new_fault_store(disk.clone()).await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let backend = Arc::new(RestoreFailureBackend {
        current: BytesBackend(Mutex::new(b"old-generation".to_vec())),
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(wait),
        panic,
    });
    let (drain, lease) = crate::lifetime::StorageDrain::new();
    let machine = StateMachine::open_tracked(
        domains.clone(),
        backend.clone(),
        RaftLimits::default(),
        lease,
    )
    .await?;
    let failed = machine.failure_flag();
    let expected = envelope(b"new-generation".to_vec());
    let checkpoint = crate::SnapshotRestoreContext {
        mode: crate::SnapshotRestoreMode::Install,
        backend_sha256: expected.backend.sha256().into(),
        meta: expected.meta.clone(),
    }
    .checkpoint_sha256()?;
    let buffer = SnapshotBuffer::from_image(expected.encode(64 << 20)?);
    let meta = expected.meta.clone();
    let mut installing = machine.clone();
    let waiter =
        tokio::spawn(async move { installing.install_snapshot(&meta, Box::new(buffer)).await });
    tokio::time::timeout(Duration::from_secs(10), ready).await??;
    // Prepared publish has begun only after the joint application write and
    // custody/snapshot cursor commit. The old in-memory generation is unchanged.
    assert_eq!(
        store.get("worker-failure", b"checkpoint")?.unwrap(),
        checkpoint.as_bytes()
    );
    let published = load_snapshot(&store, 64 << 20)?.context("new checkpoint absent")?;
    validate_snapshot_coverage(&domains, &published, 64 << 20)?;
    assert_eq!(published.meta, expected.meta);
    assert_eq!(*backend.current.0.lock().unwrap(), b"old-generation");
    assert!(!failed.load(Ordering::Acquire));
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !failed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(*backend.current.0.lock().unwrap(), b"old-generation");
    drop(machine);
    // The flag is independent of, and visible before waiting on, actual storage
    // ownership drain. The panic path must not lock the poisoned applied mutex.
    tokio::time::timeout(Duration::from_secs(10), drain.wait()).await?;
    let recovered_store = existing_fault_store(disk.crash()).await?;
    let recovered = Arc::new(BytesBackend::default());
    let mut reopened = StateMachine::open(
        kasumi_store::test_utils::open_existing_custody_fixture(
            recovered_store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        recovered.clone(),
    )
    .await?;
    assert_eq!(*recovered.0.lock().unwrap(), b"new-generation");
    assert_eq!(reopened.applied_state().await?.0, expected.meta.last_log_id);
    assert_eq!(
        recovered_store
            .get("worker-failure", b"checkpoint")?
            .unwrap(),
        checkpoint.as_bytes()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_snapshot_waiter_cannot_hide_failure_after_durable_publication() -> Result<()> {
    cancelled_publication_failure(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_snapshot_waiter_cannot_hide_panic_after_durable_publication() -> Result<()> {
    cancelled_publication_failure(true).await
}
