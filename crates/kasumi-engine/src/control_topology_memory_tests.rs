use super::*;
use crate::admission::AdmissionConfig;
use serde_json::json;

fn body() -> Value {
    json!({
        "nodes": {"1": {"endpoint":"https://node.invalid:8443/", "failure_domain":"zone", "certificate_pins":["01".repeat(32)]}},
        "tenants": {"tenant": {"incarnation":"00000000-0000-4000-8000-000000000001", "mode":"local", "voters":[1]}}
    })
}
fn admission_node(payload: u64) -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(64 << 20),
            low_water_bytes: Some(48 << 20),
            max_inflight_bytes: Some(payload),
            max_inflight_operations: 1,
            max_reservations: 16,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            ..Default::default()
        })
        .unwrap(),
        64 << 20,
        0,
    )
    .unwrap()
}
fn total(body: &Value) -> u64 {
    ControlTopology::memory_from_value(body).unwrap().peak_bytes
        + OUTPUT_CHARGE_BYTES
        + token_bytes().unwrap()
        + failure_owner_bytes().unwrap()
}

#[test]
fn local_topology_denial_precedes_decode_and_allocation() {
    let body = body();
    let required = total(&body);
    let node = admission_node(required - 1);
    let before = node.snapshot();
    let error = Decode::new(&node, &body).err().unwrap();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    assert_eq!(
        node.snapshot().inflight_operations,
        before.inflight_operations
    );
}

#[test]
fn local_topology_retains_independent_output_and_one_slot_until_final_drop() {
    let body = body();
    let node = admission_node(total(&body));
    let before = node.snapshot();
    let mut decoder = Decode::new(&node, &body).unwrap();
    assert_eq!(node.snapshot().inflight_operations, 1);
    decoder.decode(&node, 42, &body).unwrap();
    let output = decoder.finish().unwrap();
    let retained = node.snapshot();
    let quote = ControlTopology::memory_from_value(&body).unwrap();
    assert_eq!(
        retained.reserved_bytes - before.reserved_bytes,
        quote.retained_bytes + OUTPUT_CHARGE_BYTES
    );
    assert_eq!(retained.live_reservations, before.live_reservations + 1);
    assert_eq!(retained.inflight_operations, 0);
    drop(body);
    std::thread::spawn(move || {
        assert_eq!(output.version, 42);
        assert_eq!(
            output.topology.nodes[&1].endpoint,
            "https://node.invalid:8443/"
        );
        drop(output);
    })
    .join()
    .unwrap();
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn local_topology_cancelled_or_invalid_decode_drains_without_reclassifying_errors() {
    let good = body();
    let node = admission_node(total(&good));
    let baseline = node.snapshot();
    let mut decoder = Decode::new(&node, &good).unwrap();
    decoder.cancellation.cancel();
    let failure = decoder.decode(&node, 7, &good).unwrap_err();
    assert!(decoder.value.is_none());
    let error = decoder.fail(failure);
    assert_eq!(
        error
            .downcast_ref::<LocalTopologyFailure>()
            .unwrap()
            .validation_error()
            .unwrap()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert!(node.snapshot().reserved_bytes > baseline.reserved_bytes);
    drop(error);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);

    for value in [
        json!({"nodes":{},"tenants":{},"unknown":"value"}),
        json!({"nodes":{"01":{}},"tenants":{}}),
        json!({"nodes":{},"tenants":{"tenant":{"incarnation":"bad","mode":"local","voters":[]}}}),
    ] {
        let node = admission_node(total(&value));
        let before = node.snapshot();
        let expected = serde_json::from_value::<ControlTopology>(value.clone())
            .map_err(anyhow::Error::from)
            .and_then(|value| value.validate().map_err(anyhow::Error::from))
            .unwrap_err();
        let mut decoder = Decode::new(&node, &value).unwrap();
        let failure = decoder.decode(&node, 9, &value).unwrap_err();
        let actual = decoder.fail(failure);
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            std::error::Error::source(actual.downcast_ref::<LocalTopologyFailure>().unwrap())
                .unwrap()
                .downcast_ref::<serde_json::Error>()
                .is_some(),
            expected.downcast_ref::<serde_json::Error>().is_some()
        );
        assert_eq!(
            actual
                .downcast_ref::<LocalTopologyFailure>()
                .unwrap()
                .validation_error()
                .map(|e| e.code),
            expected.downcast_ref::<Error>().map(|e| e.code)
        );
        assert_eq!(node.snapshot().inflight_operations, 0);
        assert!(node.snapshot().reserved_bytes > before.reserved_bytes);
        drop(actual);
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    }
}

#[test]
fn local_topology_consuming_or_mutable_downcast_cannot_detach_failure_charge() {
    let body =
        json!({"nodes":{},"tenants":{"tenant":{"incarnation":"bad","mode":"local","voters":[]}}});
    let node = admission_node(total(&body));
    let before = node.snapshot();
    let mut decoder = Decode::new(&node, &body).unwrap();
    let failure = decoder.decode(&node, 1, &body).unwrap_err();
    let mut error = decoder.fail(failure);
    assert!(
        error.downcast_mut::<Error>().is_none(),
        "original mutable extraction is not exposed"
    );
    let held = node.snapshot();
    let owner = error.downcast::<LocalTopologyFailure>().unwrap();
    assert_eq!(
        owner.validation_error().unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        owner.to_string(),
        owner.validation_error().unwrap().to_string()
    );
    assert_eq!(
        owner.validation_error().unwrap().message,
        "invalid tenant incarnation"
    );
    assert_eq!(node.snapshot().reserved_bytes, held.reserved_bytes);
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert!(
        std::error::Error::source(&owner)
            .unwrap()
            .downcast_ref::<Error>()
            .is_some()
    );
    drop(owner);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn selected_decode_keeps_optional_and_installed_validation_semantics() {
    let invalid =
        json!({"nodes":{},"tenants":{"tenant":{"incarnation":"bad","mode":"local","voters":[]}}});
    let node = admission_node(total(&invalid));
    let baseline = node.snapshot();
    let mut decode = Decode::new(&node, &invalid).unwrap();
    decode
        .decode_with_validation(&node, 17, &invalid, false, false)
        .unwrap();
    let output = decode.finish().unwrap();
    assert_eq!(output.version, 17);
    assert_eq!(output.topology.tenants["tenant"].incarnation, "bad");
    drop(output);
    let mut decode = Decode::new(&node, &invalid).unwrap();
    let error = decode
        .decode_with_validation(&node, 17, &invalid, true, true)
        .unwrap_err();
    let error = decode
        .fail(error)
        .downcast::<LocalTopologyFailure>()
        .unwrap();
    assert_eq!(
        error.validation_error().unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        error.validation_error().unwrap().message,
        "invalid tenant incarnation"
    );
    assert_eq!(
        error.to_string(),
        error.validation_error().unwrap().to_string()
    );
    drop(error);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    for installed in [false, true] {
        let malformed = json!({"nodes":{"bad-id":{}},"tenants":{}});
        let node = admission_node(total(&malformed));
        let baseline = node.snapshot();
        let mut decode = Decode::new(&node, &malformed).unwrap();
        let error = decode
            .decode_with_validation(&node, 17, &malformed, installed, installed)
            .unwrap_err();
        let error = decode
            .fail(error)
            .downcast::<LocalTopologyFailure>()
            .unwrap();
        if installed {
            assert_eq!(
                error.validation_error().unwrap().code,
                ErrorCode::Corruption
            );
            assert_eq!(
                error.validation_error().unwrap().message,
                "installed Control topology is invalid"
            );
            assert_eq!(
                error.to_string(),
                error.validation_error().unwrap().to_string()
            );
        } else {
            assert!(error.validation_error().is_none());
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .is::<serde_json::Error>()
            );
        }
        drop(error);
        assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    }
}
