fn proposal_topology() -> crate::control::ControlTopology {
    serde_json::from_value(json!({
        "nodes": {"1": {"endpoint":"https://node.invalid/", "failure_domain":"rack", "certificate_pins":["01".repeat(32)]}},
        "tenants": {}
    })).unwrap()
}

#[tokio::test]
async fn topology_input_credit_survives_actual_child_after_caller_cancellation() {
    use crate::control::{CONTROL_TENANT, ControlPlane};
    let fixture = CredentialFixture::new_for_tenant(CONTROL_TENANT).await;
    let plane = ControlPlane::new(fixture.db.clone()).unwrap();
    plane.initialize(fixture.context.clone()).await.unwrap();
    fixture.db.proposals.check().unwrap();
    let before = fixture.db.admission().snapshot();
    let source = proposal_topology();
    let key = "cancelled-topology-input";
    let exact = proposal_input::retained_for_test(&source, key);
    let command_workspace = ((8 << 20) + (64 << 10)) * 3u64;
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let gate = fixture.db.proposal_gate.lock().await;
    let mut request = Box::pin(plane.replace_topology(
        fixture.credential(clock.clone()),
        source,
        Precondition::Absent,
        key.into(),
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.db.proposals.wait_for_admission(request.as_mut()),
    )
    .await
    .unwrap();
    let admitted = fixture.db.admission().snapshot();
    assert_eq!(
        admitted.reserved_bytes,
        before.reserved_bytes + command_workspace + exact
    );
    assert_eq!(admitted.live_reservations, before.live_reservations + 2);
    drop(request);
    assert_eq!(
        fixture.db.admission().snapshot().reserved_bytes,
        admitted.reserved_bytes
    );
    assert_eq!(
        fixture.db.admission().snapshot().live_reservations,
        admitted.live_reservations
    );
    // Release with the captured authority expired. No synthetic mutation is
    // submitted; the actual child destroys the original topology Command.
    clock.0.store(1000, Ordering::SeqCst);
    drop(gate);
    tokio::time::timeout(Duration::from_secs(5), fixture.db.work.drain())
        .await
        .unwrap();
    fixture.db.proposals.check().unwrap();
    assert_eq!(
        fixture.db.admission().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.db.admission().snapshot().live_reservations,
        before.live_reservations
    );
    assert!(plane.topology(&fixture.context).await.unwrap().is_none());
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, key)
            .await
            .unwrap()
            .is_none()
    );
    drop(plane);
    fixture.close().await;
}

#[tokio::test]
async fn topology_input_refused_actual_proposal_destroys_json_before_its_credit() {
    use crate::document_pool::allocation_tests::check_topology_input_drop;
    let fixture = CredentialFixture::new().await;
    let node = fixture.db.admission().clone();
    let before = node.snapshot();
    let source = proposal_topology();
    let exact = proposal_input::retained_for_test(&source, "refused");
    let input =
        proposal_input::OperationInput::topology(&node, source, Precondition::Absent, "refused")
            .unwrap();
    let command = input.into_command(fixture.context.clone());
    let address = proposal_input::payload_address_for_test(&command);
    let work = ProposalWork {
        group: fixture.db.group.clone(),
        admission_gate: fixture.db.proposal_gate.clone(),
        clock: fixture.db.command_clock.lock().unwrap().clone(),
        source_engine: fixture.db.engine.clone(),
        admission: node.clone(),
        _reservation: node.reserve(1, None).unwrap(),
        _registration: Arc::new(fixture.db.work.begin(QueryCancellation::default()).unwrap()),
    };
    let jobs = proposal_jobs::Jobs::default();
    jobs.drain().await.unwrap(); // actual closed registry refuses before polling
    check_topology_input_drop(
        address,
        move || {
            let error = jobs.start(work, command, 8 << 20).err().unwrap();
            assert_eq!(error.code, ErrorCode::Unavailable);
        },
        || {
            assert!(node.snapshot().reserved_bytes >= before.reserved_bytes + exact);
            assert!(node.snapshot().live_reservations > before.live_reservations);
        },
    );
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    fixture.close().await;
}
