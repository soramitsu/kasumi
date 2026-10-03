use super::*;
use crate::document_pool::allocation_tests::measure_topology_input;
use kasumi_store::NodeDiskMemoryAdmission;

fn producer_plan(
    fixture: &Fixture,
) -> Result<(
    PreparedSelectionPlan,
    kasumi_raft::AppliedEntryContext,
    PreparedTenantPointWorkspace,
)> {
    struct Capture(Option<(PreparedSelectionPlan, PreparedTenantPointWorkspace)>);
    impl SelectionPreparer for Capture {
        fn prepare(
            &mut self,
            plan: &PreparedSelectionPlan,
            points: kasumi_store::PreparedTenantPointWorkspace,
        ) -> Result<()> {
            self.0 = Some((plan.clone(), points));
            Ok(())
        }
    }
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let mut capture = Capture(None);
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, |publisher| {
        let receipt = publisher.commit_with_selection(
            response,
            &[],
            &mut capture,
            expectation.challenge()?,
        )?;
        expectation.consume(
            receipt,
            &capture
                .0
                .as_ref()
                .context("actual producer omitted plan")?
                .0,
        )?;
        Ok(())
    })?;
    let (plan, points) = capture.0.context("producer omitted exact plan")?;
    Ok((plan, position, points))
}

#[tokio::test]
async fn source_quote_is_allocation_free_bound_and_covers_real_capture_peak() -> Result<()> {
    let fixture = Fixture::new().await?;
    let initial = fixture.storage.admission.snapshot();
    let (plan, position, points) = producer_plan(&fixture)?;
    // Record actual target layouts beside the real allocator/admission witness.
    // This imposes no guessed size ceiling and prints outside its measured span.
    eprintln!(
        "publication_owner_layout expectation={} challenge={} receipt={} plan={} root_preparation={} publication_preparation={} source_roots={} cell_bytes={}",
        std::mem::size_of::<kasumi_raft::PublicationExpectation<'static>>(),
        std::mem::size_of::<kasumi_raft::PublicationChallenge<'static>>(),
        std::mem::size_of::<kasumi_raft::JointPublicationReceipt<'static>>(),
        std::mem::size_of::<PreparedSelectionPlan>(),
        std::mem::size_of::<RootPreparation>(),
        std::mem::size_of::<PublicationPreparation<'static>>(),
        std::mem::size_of::<SourceRoots>(),
        cell_bytes()?,
    );
    let native = fixture.stores.quote_read_memory()?;
    let backing =
        plan.prepared_read_peak_bytes(&native)? - native.begin_peak_bytes()? - plan.peak_bytes();
    drop(native);
    let before = fixture.storage.admission.snapshot();
    let (quote, live, peak, allocations) =
        measure_topology_input(|| fixture.roots.quote_source_plan(&plan));
    let quote = quote?;
    assert_eq!((live, peak, allocations), (0, 0, 0));
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert!(quote.peak >= quote.retained);
    assert!(quote.planning_peak >= cell_bytes()? + quote.native.begin_peak_bytes()?);
    assert!(quote.rights > kasumi_kv::ProtectedReadRequests::rights_request_bytes());
    assert_eq!(quote.native.retained_lease_requests(), 4);
    assert_eq!(quote.native.peak_lease_requests(), 7);
    // The already admitted backing is part of the initial capture baseline.
    // Add its exact provider quote to measured new allocations; its retirement
    // may make the signed allocation delta negative without losing coverage.
    let (selected, live, peak, allocations) = measure_topology_input(|| {
        fixture
            .roots
            .prepare_kind_planned(true, Some(&plan), &mut Some(points))?
            .capture(ApplicationBoundaryRef::Entry(&position), false)
    });
    let selected = selected?;
    assert!(allocations > 0 && peak > 0 && peak >= live);
    assert!(
        backing + peak as u64 <= quote.peak,
        "actual requested peak plus transferred backing {} exceeds {}",
        backing + peak as u64,
        quote.peak
    );
    let after = fixture.storage.admission.snapshot();
    let retained = after.reserved_bytes - initial.reserved_bytes;
    assert!(retained > 0 && retained <= quote.retained);
    drop(selected);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        initial.reserved_bytes
    );
    drop(quote);
    fixture.close().await
}

#[tokio::test]
async fn source_quote_reader_retained_amount_matches_actual_installed_provider_requests()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let quote = fixture.stores.quote_read_memory()?;
    let before = fixture.storage.admission.snapshot();
    let view = fixture.stores.read_view()?;
    let during = fixture.storage.admission.snapshot();
    assert_eq!(
        during.reserved_bytes - before.reserved_bytes,
        quote.retained_bytes()
    );
    assert_eq!(
        during.live_reservations - before.live_reservations,
        quote.retained_lease_requests()
    );
    view.close()?;
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    let other = NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0)?;
    let foreign: Arc<dyn NodeDiskMemoryAdmission> = other.memory().clone();
    assert_eq!(
        quote.require_memory(&foreign).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        quote
            .require_domains(
                fixture.stores.custody().store(),
                fixture.stores.application()
            )
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    drop(quote);
    fixture.close().await
}

#[test]
fn source_quote_actual_engine_provider_token_is_preclaimed_and_request_is_pure() -> Result<()> {
    let node = NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0)?;
    let memory = node.memory();
    let before = memory.snapshot();
    let (quote, live, peak, allocations) = measure_topology_input(|| memory.quote_installed(1234));
    let quote = quote?;
    assert_eq!((live, peak, allocations), (0, 0, 0));
    assert_eq!(
        quote,
        MemoryCore::required_installed_reservation_bytes(1234)?
    );
    let (lease, live, peak, allocations) =
        measure_topology_input(|| memory.clone().reserve_installed(1234));
    let lease = lease?;
    assert!(allocations > 0 && live > 0 && peak >= live);
    assert!(peak as u64 <= quote - 1234);
    assert_eq!(
        memory.snapshot().reserved_bytes - before.reserved_bytes,
        quote
    );
    drop(lease);
    assert_eq!(memory.snapshot().reserved_bytes, before.reserved_bytes);
    assert!(memory.quote_installed(u64::MAX).is_err());
    Ok(())
}

#[tokio::test]
async fn source_quote_covered_planning_tracks_actual_rows_and_transferred_backing() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (advance, _, points) = producer_plan(&fixture)?;
    drop(points);
    let before = fixture.storage.admission.snapshot();
    let (covered, position, points) = producer_plan(&fixture)?;
    let native = fixture.stores.quote_read_memory()?;
    let format_sized = native.custody_get("raft.meta".len(), b"applied".len(), 2 << 20)?;
    for plan in [&advance, &covered] {
        let planning = plan.planning_read_peak_bytes(&native)?;
        let backing = plan.prepared_read_peak_bytes(&native)?
            - native.begin_peak_bytes()?
            - plan.peak_bytes();
        assert!(planning >= native.begin_peak_bytes()?);
        assert!(planning >= native.retained_bytes() + backing);
        // The real producer preflights this root before authenticated reads.
        // Its small covered cursor does not require a format-maximum buffer.
        assert!(planning < native.retained_bytes() + format_sized.peak_bytes()?);
    }
    let selected = fixture
        .roots
        .prepare_kind_planned(true, Some(&covered), &mut Some(points))?
        .capture(ApplicationBoundaryRef::Entry(&position), false)?;
    drop(selected);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    drop(native);
    fixture.close().await
}
