use super::*;
use crate::{lifetime::StorageDrain, selected_application::allocation_tests};
use kasumi_store::{
    NodeDisk, NodeDiskMemoryAdmission, NodeStore, ScratchDisk, TenantStore, WriteOp,
    test_utils::{
        LocalKeyProvider, ManualClock, NODE_STORE_ID, TestDiskMemory, node_storage_config,
        private_tempdir, retry_disk_registry,
    },
};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::{Duration, Instant},
};

const MEMORY_LIMIT: u64 = 256 << 20;
pub(crate) struct Fixture {
    pub(crate) store: Arc<TenantStore>,
    pub(crate) node: NodeStore,
    pub(crate) memory: Arc<TestDiskMemory>,
    _directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
}
impl Fixture {
    pub(crate) async fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let path = directory.path().join("stored-proposal.kv");
        let memory = TestDiskMemory::new(MEMORY_LIMIT, 4096);
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let scratch_directory = private_tempdir()?;
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let node =
            NodeStore::create_new(&path, NODE_STORE_ID, disk, scratch, node_storage_config())
                .expect("installed application fixture node startup");
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([97; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        store.write_batch(&[WriteOp::put("commands", b"proposal", vec![0x71; 64 << 10])])?;
        // Prime the installed descriptor cache before observing output credit.
        drop(
            store
                .get("commands", b"proposal")?
                .context("stored command missing")?,
        );
        Ok(Self {
            store,
            node,
            memory,
            _directory: directory,
            _scratch_directory: scratch_directory,
        })
    }
    pub(crate) async fn shutdown(self) -> Result<()> {
        self.store.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
async fn require_pending(drain: &StorageDrain) {
    let waiting = drain.wait();
    tokio::pin!(waiting);
    poll_fn(|cx| {
        assert!(
            matches!(waiting.as_mut().poll(cx), Poll::Pending),
            "storage drain completed with retained output"
        );
        Poll::Ready(())
    })
    .await;
}
fn assert_baseline(
    memory: &TestDiskMemory,
    baseline: kasumi_store::test_utils::TestDiskMemorySnapshot,
) {
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn stored_proposal_refuses_foreign_provider_and_control_pressure_without_leaking_credit()
-> Result<()> {
    let first = Fixture::new().await?;
    let second = Fixture::new().await?;
    let baseline = first.memory.snapshot();
    let foreign_baseline = second.memory.snapshot();
    let (_, lease) = StorageDrain::new();
    let value = first.store.get("commands", b"proposal")?.unwrap();
    let error = ApplicationProposal::stored(value)
        .admit(&second.store, &Arc::downgrade(&lease))
        .err()
        .expect("foreign provider must refuse");
    assert!(format!("{error:#}").contains("plaintext installed memory owner differs"));
    drop(error);
    assert_baseline(&first.memory, baseline);
    assert_baseline(&second.memory, foreign_baseline);

    let value = first.store.get("commands", b"proposal")?.unwrap();
    let held = first.memory.snapshot();
    let filler = MEMORY_LIMIT
        - held.bookkeeping_bytes
        - held.used_bytes
        - TestDiskMemory::required_reservation_bytes(0)?;
    let pressure = first.memory.clone().reserve_installed(filler)?;
    let full = first.memory.snapshot();
    let error = ApplicationProposal::stored(value)
        .admit(&first.store, &Arc::downgrade(&lease))
        .err()
        .expect("control allocation must be preadmitted");
    assert!(format!("{error:#}").contains("application shared control admission denied"));
    assert_eq!(
        first.memory.snapshot().used_bytes,
        full.used_bytes - (held.used_bytes - baseline.used_bytes)
    );
    drop(error);
    drop(pressure);
    assert_baseline(&first.memory, baseline);
    drop(lease);
    first.shutdown().await?;
    second.shutdown().await
}

#[tokio::test]
async fn canceled_original_and_clones_retain_exact_plaintext_until_the_final_output() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let baseline = fixture.memory.snapshot();
    let (drain, lease) = StorageDrain::new();
    let value = fixture.store.get("commands", b"proposal")?.unwrap();
    let original_address = value.as_bytes().as_ptr();
    let payload =
        ApplicationProposal::stored(value).admit(&fixture.store, &Arc::downgrade(&lease))?;
    assert_eq!(payload.as_bytes().as_ptr(), original_address);
    let retained = allocation_tests::require_no_allocations(|| payload.clone());
    let charged = fixture.memory.snapshot();
    let waiting = tokio::spawn(async move {
        let _owned = payload;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    drop(lease);
    require_pending(&drain).await;
    assert_eq!(retained.as_bytes().as_ptr(), original_address);
    assert_eq!(retained.len(), 64 << 10);
    assert_baseline(&fixture.memory, charged);
    drop(retained);
    tokio::time::timeout(Duration::from_secs(5), drain.wait()).await?;
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn concurrent_last_drop_deallocates_shared_arc_before_returning_credit_or_storage_drain()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.memory.snapshot();
    let (drain, lease) = StorageDrain::new();
    let original_lease = Arc::downgrade(&lease);
    let value = fixture.store.get("commands", b"proposal")?.unwrap();
    let (result, address, allocations) = allocation_tests::observe_last_allocation(|| {
        ApplicationProposal::stored(value).admit(&fixture.store, &original_lease)
    });
    let payload = result?;
    assert_eq!(allocations, 2, "one admitted token and one shared Arc");
    let copies = (0..8).map(|_| payload.clone()).collect::<Vec<_>>();
    drop(payload);
    drop(lease);
    let charged = fixture.memory.snapshot();
    let observation = allocation_tests::DeallocationObservation::new(true);
    struct Release<'a>(&'a allocation_tests::DeallocationObservation);
    impl Drop for Release<'_> {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let gate = Arc::new(std::sync::Barrier::new(copies.len()));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for payload in copies {
            let gate = gate.clone();
            let observer = &observation;
            workers.push(scope.spawn(move || {
                gate.wait();
                allocation_tests::observe_deallocation(address, observer, || drop(payload));
            }));
        }
        let release = Release(&observation);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !observation.entered() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            observation.entered(),
            "shared Arc never reached System.dealloc"
        );
        assert!(!observation.finished());
        assert_baseline(&fixture.memory, charged);
        assert!(
            original_lease.upgrade().is_some(),
            "drain lease retired before actual Arc backing"
        );
        drop(release);
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert!(observation.finished());
    assert_eq!(observation.count(), 1);
    assert!(original_lease.upgrade().is_none());
    tokio::time::timeout(Duration::from_secs(5), drain.wait()).await?;
    assert_baseline(&fixture.memory, baseline);
    fixture.shutdown().await
}

#[tokio::test]
async fn stored_and_generated_forms_preserve_one_canonical_wire_and_decode_as_ingress() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let baseline = fixture.memory.snapshot();
    let (_, lease) = StorageDrain::new();
    let value = fixture.store.get("commands", b"proposal")?.unwrap();
    let stored =
        ApplicationProposal::stored(value).admit(&fixture.store, &Arc::downgrade(&lease))?;
    let expected = vec![0x71; 64 << 10];
    let generated = ApplicationProposal::generated(expected.clone())
        .admit(&fixture.store, &Arc::downgrade(&lease))?;
    assert_eq!(serde_json::to_vec(&stored)?, serde_json::to_vec(&expected)?);
    let wire = postcard::to_allocvec(&stored)?;
    assert_eq!(wire, postcard::to_allocvec(&expected)?);
    assert_eq!(wire, postcard::to_allocvec(&generated)?);
    let (result, _, allocations) = allocation_tests::observe_last_allocation(|| {
        postcard::from_bytes::<ApplicationPayload>(&wire)
    });
    let decoded = result?;
    assert!(matches!(&decoded.0, Payload::Ingress(_)));
    assert_eq!(decoded.as_bytes(), expected);
    assert_eq!(
        allocations, 1,
        "ingress decode adds no shared Arc or lease allocation"
    );
    #[derive(Serialize)]
    enum PreviousCommand {
        Application(Vec<u8>),
        Retirement { application: Vec<u8>, seed: Vec<u8> },
        Custody(Vec<u8>),
    }
    let command = crate::RaftCommand::Application(stored);
    let previous = PreviousCommand::Application(expected.clone());
    assert_eq!(
        serde_json::to_vec(&command)?,
        serde_json::to_vec(&previous)?
    );
    let command_wire = postcard::to_allocvec(&command)?;
    assert_eq!(command_wire, postcard::to_allocvec(&previous)?);
    for (previous, current) in [
        (
            PreviousCommand::Retirement {
                application: vec![1],
                seed: vec![2],
            },
            crate::RaftCommand::Retirement {
                application: vec![1],
                seed: vec![2],
            },
        ),
        (
            PreviousCommand::Custody(vec![3]),
            crate::RaftCommand::Custody(vec![3]),
        ),
    ] {
        assert_eq!(
            serde_json::to_vec(&current)?,
            serde_json::to_vec(&previous)?
        );
        assert_eq!(
            postcard::to_allocvec(&current)?,
            postcard::to_allocvec(&previous)?
        );
    }
    let (round_trip, _, allocations) = allocation_tests::observe_last_allocation(|| {
        postcard::from_bytes::<crate::RaftCommand>(&command_wire)
    });
    let round_trip = round_trip?;
    assert!(matches!(
        &round_trip,
        crate::RaftCommand::Application(ApplicationPayload(Payload::Ingress(_)))
    ));
    assert_eq!(round_trip.bytes(), expected);
    assert_eq!(allocations, 1);
    drop(command);
    assert_baseline(&fixture.memory, baseline);
    drop(lease);
    fixture.shutdown().await
}
