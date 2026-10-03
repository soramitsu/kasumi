//! Exercise the callback barrier in the actual detached storage worker.
use super::*;
use std::{cell::Cell, sync::atomic::AtomicUsize, time::Duration};

const WAIT: Duration = Duration::from_secs(10);
const APPLICATION: &str = "apply-publication-fixture";

#[derive(Clone, Copy)]
enum Behavior {
    Publish,
    Missing,
    Repeated,
    InvalidMetadata,
    PanicAfterRefusal,
}
struct Pause {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
struct Backend {
    behavior: Behavior,
    selected: BytesBackend,
    calls: AtomicUsize,
    pause: Mutex<Option<Pause>>,
    panic_drops: Arc<AtomicUsize>,
}
struct OwnedPanic {
    value: Cell<u8>,
    drops: Arc<AtomicUsize>,
}
impl Drop for OwnedPanic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
impl StateMachineBackend for Backend {
    fn close_application(&self) {
        self.selected.close_application();
    }
    fn apply_with_publisher(
        &self,
        position: &crate::AppliedEntryContext,
        input: crate::AppliedInput<'_>,
        publisher: &mut dyn crate::ApplyPublisher,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if matches!(self.behavior, Behavior::Missing) {
            return Ok(());
        }
        let bytes = match input {
            crate::AppliedInput::Command(bytes) => bytes.to_vec(),
            crate::AppliedInput::Metadata => position.log_id.index.to_be_bytes().to_vec(),
        };
        let response = if matches!(input, crate::AppliedInput::Metadata)
            && !matches!(
                self.behavior,
                Behavior::InvalidMetadata | Behavior::PanicAfterRefusal
            ) {
            Vec::new()
        } else {
            bytes.clone()
        };
        let result = publisher.commit(
            crate::AppliedResponse::application(response),
            &[WriteOp::put(APPLICATION, b"selected", bytes.clone())],
        );
        if let Some(pause) = self.pause.lock().unwrap().take() {
            pause
                .entered
                .send(())
                .map_err(|_| anyhow::anyhow!("observer gone"))?;
            pause.release.recv_timeout(WAIT)?;
        }
        if matches!(self.behavior, Behavior::PanicAfterRefusal) {
            assert_eq!(result, Err(crate::PublishCallError::Failed));
            std::panic::panic_any(OwnedPanic {
                value: Cell::new(17),
                drops: self.panic_drops.clone(),
            });
        }
        if matches!(self.behavior, Behavior::InvalidMetadata) {
            assert_eq!(result, Err(crate::PublishCallError::Failed));
            return Ok(()); // Deliberately swallow the non-owning notification.
        }
        result?;
        if matches!(self.behavior, Behavior::Repeated) {
            assert_eq!(
                publisher.commit(crate::AppliedResponse::application(Vec::new()), &[]),
                Err(crate::PublishCallError::Repeated)
            );
            return Ok(()); // First durable commit must not mask the violation.
        }
        *self.selected.0.lock().unwrap() = bytes;
        Ok(())
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        self.selected.capture_snapshot()
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        self.selected.validate_snapshot(bytes)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &crate::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        self.selected.prepare_restore(context, bytes)
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    scratch: Arc<kasumi_store::ScratchDisk>,
    disk: FaultBackend,
    domains: Arc<TenantStorageSet>,
    owner: Arc<SnapshotBufferOwner>,
    backend: Arc<Backend>,
    machine: StateMachine,
    drain: crate::lifetime::StorageDrain,
}
async fn fixture(behavior: Behavior) -> Result<Fixture> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let scratch = kasumi_store::ScratchDisk::fixture(
        directory.path(),
        kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096),
    );
    let disk = FaultBackend::new();
    let store = new_fault_store(disk.clone(), scratch.clone()).await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let owner = SnapshotBufferOwner::fixture();
    let backend = Arc::new(Backend {
        behavior,
        selected: BytesBackend::default(),
        calls: AtomicUsize::new(0),
        pause: Mutex::new(None),
        panic_drops: Arc::new(AtomicUsize::new(0)),
    });
    let (drain, lease) = crate::lifetime::StorageDrain::new();
    let machine = StateMachine::open_tracked(
        domains.clone(),
        backend.clone(),
        RaftLimits::default(),
        lease,
        owner.clone(),
    )
    .await?;
    Ok(Fixture {
        _directory: directory,
        scratch,
        disk,
        domains,
        owner,
        backend,
        machine,
        drain,
    })
}
fn entry(index: u64, payload: EntryPayload<TypeConfig>) -> Entry<TypeConfig> {
    Entry {
        initialization: None,
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        payload,
    }
}
fn command(index: u64, bytes: &[u8]) -> Entry<TypeConfig> {
    entry(
        index,
        EntryPayload::Normal(crate::RaftCommand::application(bytes.to_vec())),
    )
}
fn durable_cursor(domains: &TenantStorageSet) -> Result<Option<LogId<u64>>> {
    Ok(
        load::<crate::control::AppliedCursor>(domains.custody().store(), META, b"applied")?
            .and_then(|cursor| cursor.log_id()),
    )
}

#[tokio::test]
async fn metadata_application_write_and_cursor_publish_together() -> Result<()> {
    let mut fixture = fixture(Behavior::Publish).await?;
    let step = entry(1, EntryPayload::Blank);
    assert_eq!(
        fixture.machine.apply([step.clone()]).await?,
        vec![Vec::<u8>::new()]
    );
    assert_eq!(
        fixture
            .domains
            .application()
            .get(APPLICATION, b"selected")?,
        Some(1u64.to_be_bytes().to_vec())
    );
    assert_eq!(durable_cursor(&fixture.domains)?, Some(step.log_id));
    assert_eq!(fixture.machine.applied_state().await?.0, Some(step.log_id));
    Ok(())
}

#[tokio::test]
async fn covered_replay_publishes_application_writes_without_rolling_custody_back() -> Result<()> {
    let mut fixture = fixture(Behavior::Publish).await?;
    fixture
        .machine
        .apply([command(1, b"one"), command(2, b"two")])
        .await?;
    let selected = durable_cursor(&fixture.domains)?;
    let recovered = existing_fault_store(fixture.disk.crash(), fixture.scratch.clone()).await?;
    let domains = kasumi_store::test_utils::open_existing_custody_fixture(
        recovered,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let mut replay = StateMachine::open(
        domains.clone(),
        Arc::new(Backend {
            behavior: Behavior::Publish,
            selected: BytesBackend::default(),
            calls: AtomicUsize::new(0),
            pause: Mutex::new(None),
            panic_drops: Arc::new(AtomicUsize::new(0)),
        }),
        SnapshotBufferOwner::fixture(),
    )
    .await?;
    replay.apply([command(1, b"one")]).await?;
    assert_eq!(
        domains
            .application()
            .get(APPLICATION, b"selected")?
            .as_deref(),
        Some(b"one".as_slice())
    );
    assert_eq!(durable_cursor(&domains)?, selected);
    replay.apply([command(2, b"two")]).await?;
    assert_eq!(
        domains
            .application()
            .get(APPLICATION, b"selected")?
            .as_deref(),
        Some(b"two".as_slice())
    );
    assert_eq!(durable_cursor(&domains)?, selected);
    Ok(())
}

#[tokio::test]
async fn swallowed_missing_repeated_and_metadata_refusal_never_advance_resident_state() -> Result<()>
{
    for behavior in [
        Behavior::Missing,
        Behavior::Repeated,
        Behavior::InvalidMetadata,
    ] {
        let mut fixture = fixture(behavior).await?;
        let step = if matches!(behavior, Behavior::InvalidMetadata) {
            entry(
                1,
                EntryPayload::Membership(openraft::Membership::new(
                    vec![std::collections::BTreeSet::from([1])],
                    std::collections::BTreeMap::from([(1, BasicNode::new("member"))]),
                )),
            )
        } else {
            command(1, b"attempt")
        };
        assert!(fixture.machine.apply([step.clone()]).await.is_err());
        assert!(fixture.machine.failed());
        {
            let state = fixture.machine.state.lock().unwrap();
            assert_eq!(state.log_id, None);
            assert_eq!(state.membership, StoredMembership::default());
        }
        assert!(fixture.backend.selected.0.lock().unwrap().is_empty());
        assert_eq!(
            durable_cursor(&fixture.domains)?,
            matches!(behavior, Behavior::Repeated).then_some(step.log_id)
        );
        assert!(fixture.machine.apply([command(2, b"later")]).await.is_err());
        assert_eq!(fixture.backend.calls.load(Ordering::Acquire), 1);
        let failure = fixture.owner.drain_buffers().await.unwrap_err();
        assert_eq!(
            failure.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_joint_commit_preserves_application_and_custody_after_crash() -> Result<()> {
    let mut fixture = fixture(Behavior::Publish).await?;
    fixture.machine.apply([command(1, b"old")]).await?;
    fixture.disk.fail_after(0);
    assert!(fixture.machine.apply([command(2, b"new")]).await.is_err());
    assert_eq!(
        fixture.machine.state.lock().unwrap().log_id,
        Some(command(1, b"old").log_id)
    );
    assert_eq!(*fixture.backend.selected.0.lock().unwrap(), b"old");
    let recovered = existing_fault_store(fixture.disk.crash(), fixture.scratch.clone()).await?;
    let domains = kasumi_store::test_utils::open_existing_custody_fixture(
        recovered,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    assert_eq!(
        domains
            .application()
            .get(APPLICATION, b"selected")?
            .as_deref(),
        Some(b"old".as_slice())
    );
    assert_eq!(durable_cursor(&domains)?, Some(command(1, b"old").log_id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_apply_retains_callback_error_and_send_only_panic_after_actual_drain() -> Result<()>
{
    let fixture = fixture(Behavior::PanicAfterRefusal).await?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *fixture.backend.pause.lock().unwrap() = Some(Pause {
        entered,
        release: wait,
    });
    let mut applying = fixture.machine.clone();
    let waiter = tokio::spawn(async move { applying.apply([entry(1, EntryPayload::Blank)]).await });
    tokio::time::timeout(WAIT, ready).await??;
    // The first census precedes the terminal worker outcome; it cannot be the
    // final shutdown evidence. The worker owns its publisher throughout.
    fixture.owner.drain_buffers().await?;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let mut queued = fixture.machine.clone();
    let later = tokio::spawn(async move { queued.apply([command(2, b"queued")]).await });
    release.send(())?;
    assert!(tokio::time::timeout(WAIT, later).await??.is_err());
    assert_eq!(fixture.backend.calls.load(Ordering::Acquire), 1);
    assert_eq!(durable_cursor(&fixture.domains)?, None);
    let drops = fixture.backend.panic_drops.clone();
    drop(fixture.machine);
    tokio::time::timeout(WAIT, fixture.drain.wait()).await?;
    let failure = fixture.owner.drain_buffers().await.unwrap_err();
    assert_eq!(
        failure.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    let retained = fixture
        .owner
        .apply_failure()
        .context("original error absent")?;
    retained
        .try_with_report(|report| {
            let crate::RetainedApplyReport::Single(original) = report else {
                panic!("non-completion backend requires its single original")
            };
            let original = original
                .downcast_ref::<crate::apply_publication::ApplyPublicationFailure>()
                .expect("combined publication and panic failure absent");
            assert!(
                original
                    .publication
                    .as_ref()
                    .unwrap()
                    .to_string()
                    .contains("metadata publication")
            );
            let panic = original
                .backend
                .as_ref()
                .unwrap()
                .downcast_ref::<crate::apply_failure::ApplyBackendPanic>()
                .expect("original panic absent");
            panic.with_payload(|payload| {
                assert_eq!(
                    payload.downcast_ref::<OwnedPanic>().unwrap().value.get(),
                    17
                )
            });
        })
        .expect("settled retained report is busy");
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(retained);
    drop(fixture.owner);
    assert_eq!(
        drops.load(Ordering::Acquire),
        0,
        "drain report retains the exact payload"
    );
    drop(failure);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    Ok(())
}
