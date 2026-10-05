//! Real installed synchronous writer control, terminal and diagnostic custody.
use super::*;
use crate::test_utils::{
    TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry,
};
use kasumi_kv::{TerminalObservation, WriteTerminalOperation, WriteTerminalSettlement};
use std::sync::atomic::{AtomicUsize, Ordering};

const MEMORY_BYTES: u64 = 256 << 20;
const KEY: &[u8] = &[0x61; 32];
struct Fixture {
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(MEMORY_BYTES, 4096);
        let path = directory.path().join("registered-scoped-write.kv");
        let disk =
            retry_disk_registry(|| crate::NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            &path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        assert!(!node.body().db.has_fixture_direct_database());
        Ok(Self {
            node,
            memory,
            _directory: directory,
            _scratch: scratch,
        })
    }
    fn publish(&self, value: &[u8]) -> Result<()> {
        self.node.with_registered_write(
            &mut (),
            |tx, _| {
                tx.open_table(CATALOG)?.insert(KEY, value)?;
                Ok(())
            },
            |_| Ok(()),
        )
    }
    fn assert_read(&self, expected: &[u8]) -> Result<()> {
        self.node.with_registered_read(|reader| {
            let bytes = reader.catalog_bytes(KEY.try_into().unwrap(), 64)?;
            assert_eq!(
                bytes.as_ref().map(AdmittedReadBytes::as_bytes),
                Some(expected)
            );
            Ok(())
        })
    }
}

#[tokio::test]
async fn successful_write_is_registered_before_native_body_and_disposed_before_acknowledgment()
-> Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.memory.storage_census().snapshot();
    let output = fixture.node.with_registered_write(
        &mut (),
        |tx, _| {
            assert_eq!(
                fixture.memory.storage_census().snapshot().writers,
                before.writers + 1
            );
            tx.open_table(CATALOG)?
                .insert(KEY, b"selected".as_slice())?;
            Ok(())
        },
        |_| {
            // A recovered observer cannot acknowledge the future output while
            // this synchronous post-commit callback still owns its decision.
            let observer = (0..fixture.memory.storage_census().capacity())
                .filter_map(|index| fixture.memory.storage_census().owner_at(index))
                .find_map(|id| RegisteredNodeWrite::retained(fixture.memory.clone(), id))
                .unwrap();
            assert_eq!(observer.retire(), StorageCensusDisposition::Retained);
            // This still owns the exact successful native writer, so an admitted
            // close cannot claim physical drain while the post-commit body runs.
            assert!(matches!(fixture.node.body().db.close(), Err(ref failure)
            if failure.completion() == kasumi_types::drain::DrainCompletion::Retained));
            Ok(71u64)
        },
    )?;
    assert_eq!(output, 71);
    assert_eq!(
        fixture.memory.storage_census().snapshot().writers,
        before.writers
    );
    fixture.node.shutdown().await?;
    Ok(())
}

struct HandoffOutput {
    marker: u64,
    drops: Arc<AtomicUsize>,
}
impl Drop for HandoffOutput {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn successful_write_keeps_original_output_while_prephysical_metadata_contention_retires()
-> Result<()> {
    let fixture = Fixture::new()?;
    let body_calls = Arc::new(AtomicUsize::new(0));
    let capture_calls = Arc::new(AtomicUsize::new(0));
    let output_drops = Arc::new(AtomicUsize::new(0));
    let (id, address, output) = fixture.node.with_registered_write(
        &mut (),
        |tx, _| {
            body_calls.fetch_add(1, Ordering::AcqRel);
            tx.open_table(CATALOG)?
                .insert(KEY, b"committed once".as_slice())?;
            Ok(())
        },
        |_| {
            capture_calls.fetch_add(1, Ordering::AcqRel);
            let observer = (0..fixture.memory.storage_census().capacity())
                .filter_map(|index| fixture.memory.storage_census().owner_at(index))
                .find_map(|id| RegisteredNodeWrite::retained(fixture.memory.clone(), id))
                .unwrap();
            let id = observer.id();
            drop(observer);
            let output = Box::new(HandoffOutput {
                marker: 71,
                drops: output_drops.clone(),
            });
            let address = std::ptr::from_ref(output.as_ref()) as usize;
            let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
            let memory = fixture.memory.clone();
            let holder = std::thread::spawn(move || {
                memory
                    .storage_census()
                    .with_owner_metadata_held_for_test(id, || {
                        held_tx.send(()).unwrap();
                        let _ = release_rx.recv();
                    });
            });
            held_rx.recv().unwrap();
            let memory = fixture.memory.clone();
            let output_drops = output_drops.clone();
            let body_calls = body_calls.clone();
            let capture_calls = capture_calls.clone();
            WRITE_HANDOFF_RETRY_HOOK.with(|hook| {
                let mut hook = hook.borrow_mut();
                assert!(hook.is_none());
                *hook = Some(Box::new(move || {
                    // The first real retirement attempt encounters held metadata
                    // before either physical callback. Output is still original.
                    assert!(!memory.storage_census().write_retirement_completed(id));
                    assert_eq!(output_drops.load(Ordering::Acquire), 0);
                    assert_eq!(body_calls.load(Ordering::Acquire), 1);
                    assert_eq!(capture_calls.load(Ordering::Acquire), 1);
                    release_tx.send(()).unwrap();
                    holder.join().unwrap();
                }));
            });
            Ok((id, address, output))
        },
    )?;
    assert!(WRITE_HANDOFF_RETRY_HOOK.with(|hook| hook.borrow().is_none()));
    assert!(
        fixture
            .memory
            .storage_census()
            .write_retirement_completed(id)
    );
    assert_eq!(fixture.memory.storage_census().snapshot().writers, 0);
    assert_eq!(body_calls.load(Ordering::Acquire), 1);
    assert_eq!(capture_calls.load(Ordering::Acquire), 1);
    assert_eq!(output.marker, 71);
    assert_eq!(std::ptr::from_ref(output.as_ref()) as usize, address);
    assert_eq!(output_drops.load(Ordering::Acquire), 0);
    drop(output);
    assert_eq!(output_drops.load(Ordering::Acquire), 1);
    fixture.assert_read(b"committed once")?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[derive(Debug)]
struct OriginalError(Arc<()>);
impl std::fmt::Display for OriginalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original scoped body error")
    }
}
impl std::error::Error for OriginalError {}

#[tokio::test]
async fn clean_body_error_keeps_original_until_facade_drop_and_native_abort_is_whole() -> Result<()>
{
    let fixture = Fixture::new()?;
    fixture.publish(b"old")?;
    let marker = Arc::new(());
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |tx, _| {
                tx.open_table(CATALOG)?
                    .insert(KEY, b"never published".as_slice())?;
                Err(OriginalError(marker.clone()).into())
            },
            |_| -> Result<()> { panic!("aborted body entered post-commit callback") },
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    {
        let report = failure.report();
        let TerminalObservation::Returned(Err(original)) = report.body() else {
            panic!("original body error absent");
        };
        assert!(Arc::ptr_eq(
            &original.downcast_ref::<OriginalError>().unwrap().0,
            &marker
        ));
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Abort));
        assert_eq!(terminal.settlement(), WriteTerminalSettlement::Settled);
        assert!(terminal.disposal_complete());
    }
    fixture.assert_read(b"old")?;
    assert!(RegisteredNodeWrite::retained(fixture.memory.clone(), id).is_some());
    drop(failure);
    assert_eq!(fixture.memory.storage_census().snapshot().writers, 0);
    assert!(RegisteredNodeWrite::retained(fixture.memory.clone(), id).is_none());
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn clean_error_drop_during_report_borrow_retires_exact_child_on_parent_retry() -> Result<()> {
    let fixture = Fixture::new()?;
    let calls = AtomicUsize::new(0);
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |_, _| {
                calls.fetch_add(1, Ordering::AcqRel);
                Err(OriginalError(Arc::new(())).into())
            },
            |_| Ok(()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    let retained = RegisteredNodeWrite::retained(fixture.memory.clone(), id).unwrap();
    let acquired = std::sync::Barrier::new(2);
    let released = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let acquired = &acquired;
        let released = &released;
        scope.spawn(move || {
            let report = retained.report();
            assert!(report.terminal().unwrap().disposal_complete());
            acquired.wait();
            released.wait();
            drop(report);
            drop(retained);
        });
        acquired.wait();
        drop(failure);
        assert_eq!(fixture.memory.storage_census().snapshot().writers, 1);
        released.wait();
    });
    let attempts = fixture.memory.snapshot().attempts;
    fixture.node.shutdown().await?;
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(RegisteredNodeWrite::retained(fixture.memory.clone(), id).is_none());
    Ok(())
}

#[tokio::test]
async fn post_commit_original_error_preserves_committed_disposition_and_requires_inspection()
-> Result<()> {
    let fixture = Fixture::new()?;
    let marker = Arc::new(());
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |tx, _| {
                tx.open_table(CATALOG)?
                    .insert(KEY, b"committed".as_slice())?;
                Ok(())
            },
            |_| Err::<(), _>(OriginalError(marker.clone()).into()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    {
        let report = failure.report();
        let TerminalObservation::Returned(Err(original)) = report.post_commit() else {
            panic!("original post-commit error absent");
        };
        assert!(Arc::ptr_eq(
            &original.downcast_ref::<OriginalError>().unwrap().0,
            &marker
        ));
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(terminal.disposal_complete());
        assert!(!report.is_capacity_denied());
    }
    fixture.assert_read(b"committed")?;
    assert_eq!(failure.retire(), StorageCensusDisposition::Retired);
    fixture.node.shutdown().await?;
    Ok(())
}

#[derive(Debug)]
struct OriginalPanic {
    marker: u64,
    drops: Arc<AtomicUsize>,
}
impl Drop for OriginalPanic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn payload(marker: u64) -> (Box<OriginalPanic>, usize, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let original = Box::new(OriginalPanic {
        marker,
        drops: drops.clone(),
    });
    let address = std::ptr::from_ref(original.as_ref()) as usize;
    (original, address, drops)
}
fn assert_payload(observation: TerminalObservation<'_, impl Sized>, marker: u64, address: usize) {
    let TerminalObservation::Panicked(original) = observation else {
        panic!("original panic missing");
    };
    let original = original.downcast_ref::<OriginalPanic>().unwrap();
    assert_eq!(original.marker, marker);
    assert_eq!(std::ptr::from_ref(original) as usize, address);
}
fn assert_native_begin_payload(report: &NodeWriteReport<'_>, marker: u64, address: usize) {
    let TerminalObservation::Returned(Err(original)) = report.begin() else {
        panic!("native provider panic did not return its exact begin error");
    };
    let kasumi_kv::StorageError::Core(original) = &original.0 else {
        panic!("original native CorePanic missing");
    };
    assert!(!original.is_unknown_commit());
    let original = original.panic().expect("original native CorePanic missing");
    original.with_payload(|original| {
        let original = original.downcast_ref::<OriginalPanic>().unwrap();
        assert_eq!(original.marker, marker);
        assert_eq!(std::ptr::from_ref(original) as usize, address);
    });
    assert!(matches!(
        report.outer(),
        TerminalObservation::Returned(Ok(()))
    ));
}

#[tokio::test]
async fn actual_native_point_output_refund_panic_keeps_original_on_registered_body() -> Result<()> {
    let fixture = Fixture::new()?;
    let value = b"original admitted point output";
    fixture.publish(value)?;
    let (original, address, drops) = payload(0x1ea5e);
    let request = crate::node_file::segment_group::workspace_provider_request_bytes(
        kasumi_kv::PointReadRequests::new(value.len())?.output_request_bytes(),
    )?;
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |tx, _| {
                let table = tx.open_table(CATALOG)?;
                fixture
                    .memory
                    .panic_on_next_matching_point_lease_drop(request, original);
                let output = table.get(KEY)?.unwrap();
                assert_eq!(output.value(), value);
                drop(output);
                Ok(())
            },
            |_| -> Result<()> {
                panic!("original body output retirement panic entered commit capture")
            },
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    {
        let report = failure.report();
        assert_payload(report.body(), 0x1ea5e, address);
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Abort));
        assert_eq!(terminal.settlement(), WriteTerminalSettlement::Settled);
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(terminal.disposal_complete());
        assert!(matches!(
            report.post_commit(),
            TerminalObservation::NotEntered
        ));
        assert!(!report.is_capacity_denied());
    }
    let attempts = fixture.memory.snapshot().attempts;
    drop(failure);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let retained = RegisteredNodeWrite::retained(fixture.memory.clone(), id).unwrap();
    assert_payload(retained.report().body(), 0x1ea5e, address);
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    fixture.assert_read(value)?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn body_panic_and_real_native_control_disposal_panic_keep_both_originals() -> Result<()> {
    let fixture = Fixture::new()?;
    let (body, body_address, body_drops) = payload(0xb0d1);
    let (disposal, disposal_address, disposal_drops) = payload(0xd150);
    let request = crate::node_file::segment_group::workspace_provider_request_bytes(
        kasumi_kv::WriteTransaction::staging_backing_request_bytes(),
    )?;
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |_, _| {
                fixture
                    .memory
                    .panic_on_next_matching_point_lease_drop(request, disposal);
                std::panic::resume_unwind(body)
            },
            |_| Ok(()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    {
        let report = failure.report();
        assert_payload(report.body(), 0xb0d1, body_address);
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Abort));
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_payload(terminal.disposal(), 0xd150, disposal_address);
        assert!(!terminal.disposal_complete());
        assert!(!report.is_capacity_denied());
    }
    let attempts = fixture.memory.snapshot().attempts;
    drop(failure);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    let retained = RegisteredNodeWrite::retained(fixture.memory.clone(), id).unwrap();
    {
        let report = retained.report();
        assert_payload(report.body(), 0xb0d1, body_address);
        assert_payload(
            report.terminal().unwrap().disposal(),
            0xd150,
            disposal_address,
        );
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
    assert_eq!(body_drops.load(Ordering::Acquire), 0);
    assert_eq!(disposal_drops.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    Ok(())
}

#[derive(Debug)]
struct PostCommitOutputPanic(Option<Box<OriginalPanic>>);
impl Drop for PostCommitOutputPanic {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.0.take().unwrap());
    }
}

#[tokio::test]
async fn refused_native_disposal_retains_original_post_commit_output_drop_panic_in_paid_slot()
-> Result<()> {
    let fixture = Fixture::new()?;
    let (disposal, disposal_address, disposal_drops) = payload(0xd150);
    let (output, output_address, output_drops) = payload(0x007);
    let request = crate::node_file::segment_group::workspace_provider_request_bytes(
        kasumi_kv::WriteTransaction::staging_backing_request_bytes(),
    )?;
    let post_calls = AtomicUsize::new(0);
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |tx, _| {
                tx.open_table(CATALOG)?
                    .insert(KEY, b"committed".as_slice())?;
                fixture
                    .memory
                    .panic_on_next_matching_point_lease_drop(request, disposal);
                Ok(())
            },
            |_| {
                post_calls.fetch_add(1, Ordering::AcqRel);
                Ok(PostCommitOutputPanic(Some(output)))
            },
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    {
        let report = failure.report();
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_payload(terminal.disposal(), 0xd150, disposal_address);
        assert_payload(report.output_disposal(), 0x007, output_address);
        assert!(!report.is_capacity_denied());
    }
    let attempts = fixture.memory.snapshot().attempts;
    assert_eq!(post_calls.load(Ordering::Acquire), 1);
    drop(failure);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let retained = RegisteredNodeWrite::retained(fixture.memory.clone(), id).unwrap();
    {
        let report = retained.report();
        assert_payload(
            report.terminal().unwrap().disposal(),
            0xd150,
            disposal_address,
        );
        assert_payload(report.output_disposal(), 0x007, output_address);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    assert_eq!(disposal_drops.load(Ordering::Acquire), 0);
    assert_eq!(output_drops.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    Ok(())
}

#[tokio::test]
async fn registration_pressure_and_close_racing_queued_dispatch_enter_no_borrowed_body()
-> Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.memory.snapshot();
    let filler = MEMORY_BYTES
        - before.bookkeeping_bytes
        - before.used_bytes
        - TestDiskMemory::required_reservation_bytes(0)?;
    let pressure = fixture.memory.clone().reserve_installed(filler)?;
    let census = fixture.memory.storage_census().snapshot();
    let result = fixture.node.body().db.queue_registered_write();
    assert!(matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::OutOfMemory));
    assert_eq!(fixture.memory.storage_census().snapshot(), census);
    drop(pressure);
    let queued = fixture.node.body().db.queue_registered_write()?;
    fixture.node.body().db.stop();
    let calls = AtomicUsize::new(0);
    assert!(
        queued
            .run(
                &mut (),
                |_, _| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                |_| Ok(())
            )
            .is_none()
    );
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert_eq!(queued.report().phase(), NodeWriterPhase::Cancelled);
    assert!(matches!(
        queued.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(queued.retire(), StorageCensusDisposition::Retired);
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn actual_staging_capacity_error_is_classified_only_with_clean_abort_and_disposal()
-> Result<()> {
    let fixture = Fixture::new()?;
    fixture.publish(b"old")?;
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |tx, _| {
                let mut table = tx.open_table(CATALOG)?;
                let before = fixture.memory.snapshot();
                let filler = MEMORY_BYTES
                    - before.bookkeeping_bytes
                    - before.used_bytes
                    - TestDiskMemory::required_reservation_bytes(0)?;
                let pressure = fixture.memory.clone().reserve_installed(filler)?;
                let original = table
                    .insert(KEY, b"never published".as_slice())
                    .err()
                    .expect("real staging reservation must be refused");
                assert!(original.is_capacity_denied());
                drop(pressure);
                Err(original.into())
            },
            |_| Ok(()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    {
        let report = failure.report();
        assert!(report.is_capacity_denied());
        let TerminalObservation::Returned(Err(original)) = report.body() else {
            panic!("native capacity error missing");
        };
        assert!(
            original
                .downcast_ref::<kasumi_kv::TableError>()
                .unwrap()
                .is_capacity_denied()
        );
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Abort));
        assert!(terminal.disposal_complete());
    }
    fixture.assert_read(b"old")?;
    drop(failure);
    assert_eq!(fixture.memory.storage_census().snapshot().writers, 0);
    fixture.publish(b"retry")?;
    fixture.assert_read(b"retry")?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn actual_native_staging_backing_admission_panic_remains_on_exact_begin_child() -> Result<()>
{
    let fixture = Fixture::new()?;
    let (original, address, drops) = payload(0x6e61);
    let request = crate::node_file::segment_group::workspace_provider_request_bytes(
        kasumi_kv::WriteTransaction::staging_backing_request_bytes(),
    )?;
    fixture
        .memory
        .panic_on_next_point_reservation(request, original);
    let called = AtomicUsize::new(0);
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |_, _| {
                called.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    {
        let report = failure.report();
        assert!(matches!(report.body(), TerminalObservation::NotEntered));
        assert_native_begin_payload(&report, 0x6e61, address);
        assert!(report.terminal().is_none());
    }
    assert_eq!(called.load(Ordering::Acquire), 0);
    let attempts = fixture.memory.snapshot().attempts;
    drop(failure);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(fixture.memory.snapshot().attempts, attempts);
    let retained = RegisteredNodeWrite::retained(fixture.memory.clone(), id).unwrap();
    assert_native_begin_payload(&retained.report(), 0x6e61, address);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    Ok(())
}

#[derive(Debug)]
struct DiagnosticDropPanic(std::sync::Mutex<Option<Box<OriginalPanic>>>);
impl std::fmt::Display for DiagnosticDropPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original returned error with destructor panic")
    }
}
impl std::error::Error for DiagnosticDropPanic {}
impl Drop for DiagnosticDropPanic {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.0.get_mut().unwrap().take().unwrap());
    }
}
#[tokio::test]
async fn clean_error_diagnostic_destructor_panic_stays_observed_before_census_credit_reuse()
-> Result<()> {
    let fixture = Fixture::new()?;
    let (original, address, drops) = payload(0xd1a6);
    let failure = fixture
        .node
        .with_registered_write(
            &mut (),
            |_, _| Err(DiagnosticDropPanic(std::sync::Mutex::new(Some(original))).into()),
            |_| Ok(()),
        )
        .unwrap_err()
        .downcast::<NodeScopedWriteFailure>()?;
    let id = failure.writer_id();
    let before = fixture.memory.snapshot();
    drop(failure);
    let observed = fixture.memory.storage_census().observation(id).unwrap();
    assert_eq!(observed.phase(), StorageCensusPanicPhase::PayloadDisposal);
    let original = observed.payload().downcast_ref::<OriginalPanic>().unwrap();
    assert_eq!(original.marker, 0xd1a6);
    assert_eq!(std::ptr::from_ref(original) as usize, address);
    drop(observed);
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.node.shutdown().await.unwrap_err().completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    Ok(())
}
