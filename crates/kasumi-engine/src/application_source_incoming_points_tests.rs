//! Early failures use the real Entry producer's exact installed point leases.
use super::*;

fn incoming_backing(
    fixture: &Fixture,
    fault: Option<(&Probe, &Arc<PointRetirementOriginal>)>,
) -> Result<(PreparedSelectionPlan, PreparedTenantPointWorkspace)> {
    struct Capture<'a> {
        fault: Option<(&'a Probe, &'a Arc<PointRetirementOriginal>)>,
        owned: Option<(PreparedSelectionPlan, PreparedTenantPointWorkspace)>,
    }
    impl SelectionPreparer for Capture<'_> {
        fn prepare(
            &mut self,
            plan: &PreparedSelectionPlan,
            points: PreparedTenantPointWorkspace,
        ) -> Result<()> {
            if let Some((probe, payload)) = self.fault.take() {
                probe.arm_last(Box::new(payload.clone()));
            }
            self.owned = Some((plan.clone(), points));
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
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    let mut capture = Capture { fault, owned: None };
    kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, |publisher| {
        let receipt = publisher.commit_with_selection(
            response,
            &[],
            &mut capture,
            expectation.challenge()?,
        )?;
        expectation.consume(
            receipt,
            &capture.owned.as_ref().context("real plan absent")?.0,
        )?;
        Ok(())
    })?;
    capture.owned.context("real incoming backing absent")
}

fn combined<'a>(
    error: &'a anyhow::Error,
    payload: &Arc<PointRetirementOriginal>,
) -> &'a kasumi_store::PointRetirementFailure {
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::PointRetirementFailure>())
        .expect("original and point retirement panic must share custody");
    failure.with_panic_payload(|saved| {
        assert!(Arc::ptr_eq(
            saved
                .downcast_ref::<Arc<PointRetirementOriginal>>()
                .unwrap(),
            payload
        ));
    });
    failure
}

#[tokio::test]
async fn incoming_actual_points_preserve_each_pre_cell_rejection_with_drop_panic() -> Result<()> {
    // Both identities are rejected before any Cell, and the two local failures
    // exercise the source gate and its actual constructor reservation.
    for mode in ["plan", "points", "sealed", "capacity"] {
        let fixture = Fixture::new().await?;
        let foreign = if matches!(mode, "plan" | "points") {
            Some(Fixture::new().await?)
        } else {
            None
        };
        let foreign_plan = if mode == "points" {
            let (plan, points) = incoming_backing(foreign.as_ref().unwrap(), None)?;
            drop(points);
            Some(plan)
        } else {
            None
        };
        let baseline = fixture.storage.admission.snapshot();
        let probe = Probe::begin(fixture.storage.admission.memory());
        let payload = Arc::new(PointRetirementOriginal);
        let (plan, points) = incoming_backing(&fixture, Some((&probe, &payload)))?;
        assert!(!probe.fired());
        let roots = foreign
            .as_ref()
            .map_or(&fixture.roots, |fixture| &fixture.roots);
        let before = roots.gate.lock().unwrap().next;
        if mode == "sealed" {
            assert!(matches!(drain(roots), Poll::Ready(Ok(()))));
        }
        let pressure = if mode == "capacity" {
            Some(fixture.storage.admission.reserve_resident(
                fixture.budget - fixture.storage.admission.snapshot().reserved_bytes,
            )?)
        } else {
            None
        };
        let mut actual = roots.publication_preparation();
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            actual.prepare(foreign_plan.as_ref().unwrap_or(&plan), points)
        }));
        assert!(
            outcome.is_ok(),
            "incoming point destructor replaced {mode} refusal"
        );
        let error = outcome.unwrap().unwrap_err();
        let failure = combined(&error, &payload);
        let original = failure.original_error().expect("actual preparation error");
        match mode {
            "plan" => assert_eq!(
                original.to_string(),
                "selection plan belongs to another storage pair"
            ),
            "points" => assert_eq!(
                original.to_string(),
                "prepared point backing belongs to another storage pair"
            ),
            "sealed" => assert_eq!(
                original.to_string(),
                "application source preparation sealed"
            ),
            "capacity" => assert_eq!(
                original.downcast_ref::<kasumi_types::Error>().unwrap().code,
                kasumi_types::ErrorCode::ResourceExhausted
            ),
            _ => unreachable!(),
        }
        assert!(probe.fired());
        assert!(actual.prepared.is_none());
        assert_eq!(roots.gate.lock().unwrap().next, before);
        assert!(roots.gate.lock().unwrap().cells.is_empty());
        assert_eq!(
            fixture
                .node
                .persistent_disk()
                .memory()
                .storage_census()
                .snapshot()
                .readers,
            0
        );
        drop(actual);
        drop(pressure);
        drop(error);
        drop(probe);
        assert_eq!(
            fixture.storage.admission.snapshot().live_reservations,
            baseline.live_reservations
        );
        assert_eq!(
            fixture.storage.admission.snapshot().reserved_bytes,
            baseline.reserved_bytes
        );
        if let Some(foreign) = foreign {
            foreign.close().await?;
        }
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn incoming_actual_duplicate_preserves_panic_and_cancels_original_queue() -> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.storage.admission.snapshot();
    let (plan, points) = incoming_backing(&fixture, None)?;
    let mut actual = fixture.roots.publication_preparation();
    actual.prepare(&plan, points)?;
    let prepared = actual.prepared.as_ref().unwrap();
    let cell = prepared.cell.clone();
    let reader = prepared
        .queued
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    let probe = Probe::begin(fixture.storage.admission.memory());
    let payload = Arc::new(PointRetirementOriginal);
    let (_, repeated) = incoming_backing(&fixture, Some((&probe, &payload)))?;
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| actual.prepare(&plan, repeated)));
    assert!(outcome.is_ok());
    let error = outcome.unwrap().unwrap_err();
    assert_eq!(
        combined(&error, &payload)
            .original_error()
            .unwrap()
            .to_string(),
        "application source preparation repeated"
    );
    assert!(probe.fired());
    assert!(actual.repeated);
    let failure = actual
        .finish_inner()
        .err()
        .context("duplicate preparation was accepted")?;
    assert!(failure.to_string().contains("repeated"));
    assert!(cell.state.lock().unwrap().closed);
    assert!(!cell.state.lock().unwrap().preparing);
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            reader,
        )
        .is_none()
    );
    assert_eq!(
        fixture
            .node
            .persistent_disk()
            .memory()
            .storage_census()
            .snapshot()
            .readers,
        0
    );
    // The queued owner closed normally; the independent incoming panic remains
    // with the rejected call's original, as returned to the actual publisher.
    combined(&error, &payload);
    drop(failure);
    drop(error);
    drop(cell);
    drop(probe);
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        baseline.reserved_bytes
    );
    fixture.close().await
}

#[derive(Debug)]
struct IncomingOriginal(Arc<()>);
impl std::fmt::Display for IncomingOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("exact incoming preparation original")
    }
}
impl std::error::Error for IncomingOriginal {}

#[tokio::test]
async fn incoming_actual_points_retain_exact_error_or_panic_and_remain_unknown_in_cell()
-> Result<()> {
    for panics in [false, true] {
        let fixture = Fixture::new().await?;
        let baseline = fixture.storage.admission.snapshot();
        let probe = Probe::begin(fixture.storage.admission.memory());
        let payload = Arc::new(PointRetirementOriginal);
        let (_, points) = incoming_backing(&fixture, Some((&probe, &payload)))?;
        let original = Arc::new(());
        let result: Result<()> = with_incoming_points(points, |_| {
            if panics {
                std::panic::resume_unwind(Box::new(original.clone()));
            }
            Err(IncomingOriginal(original.clone()).into())
        });
        let error = result.unwrap_err();
        assert!(probe.fired());
        let failure = combined(&error, &payload);
        let body = failure.original_error().unwrap();
        if panics {
            let body = body.downcast_ref::<SourcePanic>().unwrap();
            assert!(Arc::ptr_eq(
                body._payload
                    .lock()
                    .unwrap()
                    .downcast_ref::<Arc<()>>()
                    .unwrap(),
                &original
            ));
        } else {
            assert!(Arc::ptr_eq(
                &body.downcast_ref::<IncomingOriginal>().unwrap().0,
                &original
            ));
        }
        // If a later source owns this diagnostic, it must not infer clean
        // retirement from the caught destructor or its ordinary original.
        let preparation = fixture.roots.prepare()?;
        let cell = preparation.cell.clone();
        cell.record_failure(error, false);
        drop(preparation);
        assert_strict_repeated_drain(&fixture, 1);
        let saved = &cell.failure.get().unwrap().owner.original;
        combined(saved, &payload);
        remove_only_injected_unknown(&fixture, &cell);
        drop(cell);
        drop(probe);
        assert_eq!(
            fixture.storage.admission.snapshot().live_reservations,
            baseline.live_reservations
        );
        assert_eq!(
            fixture.storage.admission.snapshot().reserved_bytes,
            baseline.reserved_bytes
        );
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn incoming_actual_points_clean_retirement_resumes_the_exact_original_unwind() -> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.storage.admission.snapshot();
    let (_, points) = incoming_backing(&fixture, None)?;
    let original = Arc::new(());
    let payload: Box<dyn std::any::Any + Send> = Box::new(original.clone());
    let address = payload.as_ref() as *const dyn std::any::Any as *const () as usize;
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        with_incoming_points(points, |_| std::panic::resume_unwind(payload))
    }));
    let saved = outcome.expect_err("clean retirement must preserve the unwind observation");
    assert_eq!(
        saved.as_ref() as *const dyn std::any::Any as *const () as usize,
        address,
        "the original payload allocation must survive"
    );
    assert!(Arc::ptr_eq(
        saved.downcast_ref::<Arc<()>>().unwrap(),
        &original
    ));
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert_eq!(
        fixture
            .node
            .persistent_disk()
            .memory()
            .storage_census()
            .snapshot()
            .readers,
        0
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        baseline.reserved_bytes
    );
    drop(saved);
    fixture.close().await
}
