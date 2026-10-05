use super::*;
use crate::admission::AdmissionConfig;
use std::task::Poll;

fn selected_scan() -> (
    Arc<NodeAdmission>,
    crate::state::lease_retention::tests::CodecFixture,
    SelectedPageInput,
    QueryCancellation,
) {
    let node = NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(64 << 20),
            low_water_bytes: Some(48 << 20),
            max_inflight_bytes: Some(32 << 20),
            ..Default::default()
        })
        .unwrap(),
        64 << 20,
        0,
    )
    .unwrap();
    let (engine, selected, cancellation) =
        crate::state::lease_retention::tests::scan_workspace_fixture(&node);
    (node, engine, SelectedPageInput::new(selected), cancellation)
}

#[test]
fn cancelled_page_preparation_keeps_selected_payload_and_charge_together() {
    let (node, engine, mut input, cancellation) = selected_scan();
    let generation = Arc::downgrade(&input.generation);
    let charged = crate::test_utils::reserved_payload_bytes(&node);
    cancellation.cancel();
    let error = input
        .memory
        .reserve(input.selected_input_bytes)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), charged);
    assert!(generation.upgrade().is_some());
    drop(engine);
    assert!(!input.handle.live());
    assert!(crate::test_utils::reserved_payload_bytes(&node) > 0);
    assert!(generation.upgrade().is_some());
    drop(input);
    assert!(generation.upgrade().is_none());
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 0);
}

#[tokio::test]
async fn completed_scan_keeps_output_charged_after_lease_expiry_until_abandoned() {
    let (node, engine, mut input, cancellation) = selected_scan();
    input.memory.reserve(input.selected_input_bytes).unwrap();
    let generation = Arc::downgrade(&input.generation);
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(cancellation.clone()).unwrap());
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let request = ScanSnapshotPage {
        lease_id: input.handle.header.lease_id.clone(),
        collection: "docs".into(),
        after_id: None,
        limit: 1,
    };
    let work = ScanWork {
        lease: input.handle,
        generation: input.generation,
        ids: input.scan_ids,
        has_more: input.scan_has_more,
        request,
        cancellation,
        _permit: slots.clone().try_acquire_owned().unwrap(),
        memory: input.memory,
        registration,
    };
    drop(engine);
    assert!(!work.lease.live());
    let output = tokio::task::spawn_blocking(move || work.run())
        .await
        .unwrap();
    fence.seal();
    let response = output.response.as_ref().unwrap();
    assert_eq!(response.data_epoch, 1);
    assert_eq!(response.documents.len(), 1);
    assert_eq!(response.documents[0].version, 1);
    assert_eq!(
        response.documents[0].body["value"].as_str().unwrap().len(),
        8192
    );
    assert!(generation.upgrade().is_none());
    assert_eq!(slots.available_permits(), 1);
    assert!(crate::test_utils::reserved_payload_bytes(&node) > 0);
    let mut draining = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    // Final lease validation would reject release; abandoning that completed
    // output must still drop the payload before its admission and registration.
    drop(output);
    draining.await;
    assert_eq!(crate::test_utils::reserved_payload_bytes(&node), 0);
}
