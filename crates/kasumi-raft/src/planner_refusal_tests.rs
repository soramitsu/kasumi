//! Lease expires only after the actual controlled planner registers its reader.
use super::*;
use kasumi_store::{
    CustodyStore, NodeDisk, NodeDiskMemoryAdmission, NodeStore, ScratchDisk, TenantStorageSet,
    TenantStore,
    test_utils::{LocalKeyProvider, PlannerExpiryClock, TestDiskMemory, private_tempdir},
};

struct Fixture {
    stores: Arc<TenantStorageSet>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    clock: Arc<PlannerExpiryClock>,
    _persistent: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let persistent = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 128);
        let path = persistent.path().join("planner-expiry.kv");
        let disk = kasumi_store::test_utils::retry_disk_registry(|| {
            NodeDisk::fixture_for_path(&path, memory.clone())
        })?;
        let node = NodeStore::create_new(
            path,
            kasumi_store::test_utils::NODE_STORE_ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            kasumi_store::test_utils::node_storage_config(),
        )
        .expect("registered node for the admitted planner fixture");
        let clock = Arc::new(PlannerExpiryClock::new(memory.clone()));
        let tenant = "planner-expiry";
        let application = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            tenant.into(),
            Arc::new(LocalKeyProvider::new([81; 32])),
            clock.clone(),
        )
        .await?;
        let custody = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            CustodyStore::catalog_name(tenant),
            Arc::new(LocalKeyProvider::new([82; 32])),
            clock.clone(),
        )
        .await?;
        Ok(Self {
            stores: kasumi_store::test_utils::with_domains(application, custody)?,
            node,
            memory,
            clock,
            _persistent: persistent,
            _scratch: scratch,
        })
    }
}

struct StoppedAfterSink;
impl CompletionAction for StoppedAfterSink {
    fn run(
        &mut self,
        _: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<(), kasumi_store::ScratchOperationFailure> {
        assert_eq!(
            publisher.commit(AppliedResponse::application(vec![7, 9]), &[]),
            Err(PublishCallError::Failed)
        );
        Ok(())
    }
}

struct WithContext<'a> {
    actual: EntryPublicationSink<'a>,
    context: Arc<AtomicUsize>,
}
#[derive(Debug)]
struct OwningContext(Arc<AtomicUsize>);
impl std::fmt::Display for OwningContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "owned context {}",
            self.0.load(Ordering::Acquire)
        )
    }
}
impl PublicationSink for WithContext<'_> {
    fn plain(&mut self, response: &AppliedResponse, writes: &[WriteOp]) -> SinkResult<()> {
        self.actual.plain(response, writes).map_err(|failure| {
            let original = failure.into_error();
            original.context(OwningContext(self.context.clone())).into()
        })
    }
    fn selected<'call>(
        &mut self,
        response: &AppliedResponse,
        writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>> {
        self.actual.selected(response, writes, preparer, challenge)
    }
}

#[tokio::test]
async fn controlled_planner_access_denial_retires_actual_reader_and_keeps_failed_response()
-> Result<()> {
    for contextual in [false, true] {
        let fixture = Fixture::new().await?;
        let position = crate::AppliedEntryContext {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 2),
            previous: None,
            membership: openraft::StoredMembership::default(),
            command_sha256: "17".repeat(32),
            retirement_seed: None,
        };
        let baseline = fixture.memory.snapshot();
        let (slot, control) = owner();
        let context = Arc::new(AtomicUsize::new(711));
        let mut actual = EntryPublicationSink::new(&fixture.stores, &position, None, false);
        let mut wrapper = WithContext {
            actual: EntryPublicationSink::new(&fixture.stores, &position, None, false),
            context: context.clone(),
        };
        fixture.clock.arm();
        let sink: &mut dyn PublicationSink = if contextual {
            &mut wrapper
        } else {
            &mut actual
        };
        let mut publication = ApplyPublication::new_bound(sink, &slot);
        assert!(matches!(
            publication.with_completion(&control.identity, &mut StoppedAfterSink),
            Err(crate::CompletionCallError::Recorded)
        ));
        let returned = failed(publication.finish_observed(Ok(Ok(())), || {}));
        assert!(fixture.clock.observed_reader());
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations
        );
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
        let inspect = || {
            slot.completion()
                .try_with_report(None, |report| {
                    let RetainedApplyReport::Ordinary(report) = report else {
                        panic!("ordinary report")
                    };
                    let O::Error(original) = report.sink else {
                        panic!("actual planner original")
                    };
                    // Anyhow inner downcast succeeds even through the context; only
                    // the exact outer Store marker is eligible for retirement.
                    assert!(
                        original
                            .downcast_ref::<kasumi_store::KeyAccessDenied>()
                            .is_some()
                    );
                    let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
                    assert_eq!(
                        outer
                            .downcast_ref::<kasumi_store::KeyAccessDenied>()
                            .is_some(),
                        !contextual
                    );
                    assert!(report.response.is_some());
                    assert!(matches!(report.action, O::Returned));
                    assert_eq!(report.custody_guards.sink_no_native_children, !contextual);
                    assert_eq!(
                        report.custody_guards.refusal_stage,
                        (!contextual).then_some(ApplyRefusalStage::PlannerRetired)
                    );
                    (
                        std::ptr::from_ref(outer) as *const () as usize,
                        report.response.unwrap().data.as_ptr() as usize,
                    )
                })
                .unwrap()
        };
        let exact = inspect();
        drop(returned);
        let waker = Waker::noop();
        assert!(
            slot.completion()
                .poll_drain(&mut Context::from_waker(waker))
                .is_ready()
        );
        assert_eq!(slot.completion().failure_ownership_drained(), !contextual);
        assert!(slot.completion().failed());
        assert!(slot.completion().unsettled());
        assert_eq!(inspect(), exact);
        if contextual {
            assert!(
                Arc::strong_count(&context) >= 3,
                "context owner was discarded"
            );
        }
        fixture.stores.shutdown().await?;
        fixture.node.shutdown().await?;
        assert_eq!(inspect(), exact);
    }
    Ok(())
}

#[tokio::test]
async fn bare_store_refusal_at_other_entry_stages_keeps_native_custody_unproven() -> Result<()> {
    let fixture = Fixture::new().await?;
    let position = crate::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 2),
        previous: None,
        membership: openraft::StoredMembership::default(),
        command_sha256: "17".repeat(32),
        retirement_seed: None,
    };
    let actual = EntryPublicationSink::new(&fixture.stores, &position, None, false);
    fixture.stores.application().seal();
    for stage in [
        EntryFailureStage::Challenge,
        EntryFailureStage::Receipt,
        EntryFailureStage::Preparer,
        EntryFailureStage::Publication,
    ] {
        let original = fixture.stores.check_access().unwrap_err();
        let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
        assert!(
            outer
                .downcast_ref::<kasumi_store::KeyAccessDenied>()
                .is_some()
        );
        let address = std::ptr::from_ref(outer) as *const () as usize;
        let failed = actual.entered_failure(stage, original);
        assert_eq!(failed.refusal_stage(), None);
        let (original, no_native_children) = failed.into_parts();
        assert!(!no_native_children);
        let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
        assert_eq!(std::ptr::from_ref(outer) as *const () as usize, address);
    }
    fixture.stores.shutdown().await?;
    fixture.node.shutdown().await?;
    Ok(())
}
