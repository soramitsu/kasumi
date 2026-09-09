//! Actual encrypted replacement tables join snapshot and applied publication.
use super::*;
use sha2::Digest;
use std::time::Duration;

const META: &str = "joint-prefix";
const ROW_BYTES: usize = 32 << 10;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Selection {
    checkpoint: String,
    namespace: String,
    root: String,
    tag: u8,
}
fn selection(context: &crate::SnapshotRestoreContext, tag: u8) -> Result<Selection> {
    let checkpoint = context.checkpoint_sha256()?;
    let mut root = sha2::Sha256::new();
    for ordinal in 0..2 {
        root.update(row(tag, ordinal));
    }
    Ok(Selection {
        namespace: format!("joint-prefix-{checkpoint}"),
        checkpoint,
        root: hex::encode(root.finalize()),
        tag,
    })
}
fn row(tag: u8, ordinal: u8) -> Vec<u8> {
    vec![tag + ordinal; ROW_BYTES]
}
fn check_table(store: &TenantStore, selected: &Selection) -> Result<()> {
    let observed: Selection = serde_json::from_slice(
        &store
            .get_bounded(META, b"selected", 64 << 10)?
            .context("prefix selector missing")?,
    )?;
    ensure!(
        observed == *selected,
        "prefix selector differs from snapshot"
    );
    let mut root = sha2::Sha256::new();
    for ordinal in 0..2 {
        let value = store
            .get_bounded(&selected.namespace, &[ordinal], ROW_BYTES)?
            .context("immutable prefix row missing")?;
        ensure!(
            value == row(selected.tag, ordinal),
            "immutable prefix row differs"
        );
        root.update(value);
    }
    ensure!(
        hex::encode(root.finalize()) == selected.root,
        "prefix root differs"
    );
    Ok(())
}
struct Pause {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
struct JointBackend {
    store: Arc<TenantStore>,
    current: Mutex<Option<Selection>>,
    pause: Mutex<Option<Pause>>,
}
impl JointBackend {
    fn new(store: Arc<TenantStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            current: Mutex::new(None),
            pause: Mutex::new(None),
        })
    }
}
struct PreparedJoint<'a> {
    backend: &'a JointBackend,
    selected: Selection,
    replacement: Option<kasumi_store::EncryptedTable>,
    writes: Vec<WriteOp>,
}
impl crate::PreparedStateMachineRestore for PreparedJoint<'_> {
    fn retirement(&self) -> Option<crate::RetiredSnapshotState> {
        None
    }
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)> {
        self.replacement
            .as_ref()
            .map(|table| vec![(self.selected.namespace.as_str(), table)])
            .unwrap_or_default()
    }
    fn application_writes(&self) -> &[WriteOp] {
        &self.writes
    }
    fn publish(self: Box<Self>) -> Result<()> {
        // This verifies full point rows and their root after the actual joint
        // durable commit, before the resident selection can advance.
        check_table(&self.backend.store, &self.selected)?;
        let pause = self.backend.pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause
                .entered
                .send(())
                .map_err(|_| anyhow::anyhow!("observer closed"))?;
            pause.release.recv_timeout(Duration::from_secs(10))?;
            anyhow::bail!("injected failure after joint immutable table publication");
        }
        *self.backend.current.lock().unwrap() = Some(self.selected.clone());
        Ok(())
    }
}
impl StateMachineBackend for JointBackend {
    fn close_application(&self) {
        self.current.lock().unwrap().take();
    }
    fn apply(&self, _: &crate::AppliedEntryContext, _: &[u8]) -> Result<crate::AppliedResponse> {
        anyhow::bail!("joint fixture accepts only snapshot installation")
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        let tag = self
            .current
            .lock()
            .unwrap()
            .as_ref()
            .context("prefix absent")?
            .tag;
        Ok(crate::CapturedSnapshot::new(None, move |writer| {
            writer.write_all(&[tag])?;
            Ok(())
        }))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        let mut data = Vec::new();
        bytes.take(2).read_to_end(&mut data)?;
        ensure!(
            matches!(data.as_slice(), [7] | [9]),
            "invalid joint fixture image"
        );
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        let mut data = Vec::new();
        bytes.take(2).read_to_end(&mut data)?;
        self.validate_snapshot(&mut data.as_slice())?;
        let selected = selection(context, data[0])?;
        let (replacement, writes) = match context.mode {
            crate::SnapshotRestoreMode::Reopen => {
                check_table(&self.store, &selected)?;
                (None, vec![])
            }
            crate::SnapshotRestoreMode::Install => {
                let table = kasumi_store::EncryptedTable::new(self.store.scratch_disk(), 1 << 20)?;
                for ordinal in 0..2 {
                    table.insert(&[ordinal], &row(selected.tag, ordinal))?;
                }
                let writes = vec![put(META, b"selected", serde_json::to_vec(&selected)?)];
                (Some(table), writes)
            }
        };
        Ok(Box::new(PreparedJoint {
            backend: self,
            selected,
            replacement,
            writes,
        }))
    }
}
fn image(tag: u8, index: u64) -> SnapshotEnvelope {
    let mut result = envelope(vec![tag]);
    result.meta.last_log_id.as_mut().unwrap().index = index;
    result
}
async fn install(machine: &mut StateMachine, image: &SnapshotEnvelope) -> Result<()> {
    machine
        .install_snapshot(
            &image.meta,
            Box::new(SnapshotBuffer::from_image(image.encode(64 << 20)?)),
        )
        .await?;
    Ok(())
}
async fn open(disk: FaultBackend) -> Result<(Arc<TenantStore>, Arc<JointBackend>, StateMachine)> {
    let store = fault_store(disk).await?;
    let backend = JointBackend::new(store.clone());
    let domains = kasumi_store::test_utils::with_custody(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let machine = StateMachine::open(domains, backend.clone()).await?;
    Ok((store, backend, machine))
}
async fn selected(
    store: &TenantStore,
    backend: &JointBackend,
    machine: &mut StateMachine,
) -> Result<Selection> {
    let snapshot = load_snapshot(store, 64 << 20)?.context("joint snapshot missing")?;
    let context = crate::SnapshotRestoreContext {
        mode: crate::SnapshotRestoreMode::Reopen,
        backend_sha256: snapshot.backend.sha256().into(),
        meta: snapshot.meta.clone(),
    };
    let expected = selection(&context, snapshot.backend.read_bounded(1)?[0])?;
    check_table(store, &expected)?;
    ensure!(
        backend.current.lock().unwrap().as_ref() == Some(&expected),
        "resident prefix differs"
    );
    let (position, membership) = machine.applied_state().await?;
    ensure!(
        position == snapshot.meta.last_log_id && membership == snapshot.meta.last_membership,
        "applied cursor differs"
    );
    Ok(expected)
}

#[tokio::test]
async fn joint_immutable_table_snapshot_power_loss_selects_complete_old_or_new_prefix() -> Result<()>
{
    let seed = FaultBackend::new();
    let old = image(7, 3);
    let new = image(9, 4);
    let (store, backend, mut machine) = open(seed.clone()).await?;
    install(&mut machine, &old).await?;
    let old_selection = selected(&store, &backend, &mut machine).await?;
    let baseline = seed.crash();
    let (_, _, mut measured) = open(baseline.clone()).await?;
    let start = baseline.operations();
    install(&mut measured, &new).await?;
    let operations = baseline.operations() - start;
    ensure!(
        operations > 10,
        "fault sweep must include actual table/chunk/selector writes"
    );
    for boundary in 0..=operations {
        let disk = seed.crash();
        let (_, _, mut installing) = open(disk.clone()).await?;
        disk.fail_after(boundary);
        let outcome = install(&mut installing, &new).await;
        let (recovered_store, recovered_backend, mut recovered) = open(disk.crash()).await?;
        let observed = selected(&recovered_store, &recovered_backend, &mut recovered).await?;
        ensure!(
            observed.tag == 7 || observed.tag == 9,
            "torn prefix at {boundary}"
        );
        if observed.tag == 7 {
            ensure!(
                observed == old_selection,
                "old prefix changed at {boundary}"
            );
        }
        if outcome.is_ok() {
            ensure!(observed.tag == 9, "acknowledged prefix lost at {boundary}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_joint_table_publication_seals_and_reopens_exact_committed_prefix() -> Result<()>
{
    let disk = FaultBackend::new();
    let store = fault_store(disk.clone()).await?;
    let backend = JointBackend::new(store.clone());
    let domains = kasumi_store::test_utils::with_custody(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let (drain, lease) = crate::lifetime::StorageDrain::new();
    let mut machine =
        StateMachine::open_tracked(domains, backend.clone(), RaftLimits::default(), lease).await?;
    install(&mut machine, &image(7, 3)).await?;
    let old = backend.current.lock().unwrap().clone();
    let new = image(9, 4);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *backend.pause.lock().unwrap() = Some(Pause {
        entered,
        release: wait,
    });
    let failed = machine.failure_flag();
    let mut installing = machine.clone();
    let waiter = tokio::spawn(async move { install(&mut installing, &new).await });
    tokio::time::timeout(Duration::from_secs(10), ready).await??;
    let committed = load_snapshot(&store, 64 << 20)?.context("committed snapshot absent")?;
    let expected = selection(
        &crate::SnapshotRestoreContext {
            mode: crate::SnapshotRestoreMode::Reopen,
            backend_sha256: committed.backend.sha256().into(),
            meta: committed.meta.clone(),
        },
        9,
    )?;
    check_table(&store, &expected)?;
    assert_eq!(*backend.current.lock().unwrap(), old);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !failed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(*backend.current.lock().unwrap(), old);
    drop(machine);
    tokio::time::timeout(Duration::from_secs(10), drain.wait()).await?;
    let (recovered_store, recovered_backend, mut recovered) = open(disk.crash()).await?;
    assert_eq!(
        selected(&recovered_store, &recovered_backend, &mut recovered).await?,
        expected
    );
    Ok(())
}
