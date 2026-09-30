//! Structural topology admission is separate from authenticated remote custody.

use super::*;
use serde_json::json;
use uuid::Uuid;

fn topology() -> ControlTopology {
    ControlTopology {
        nodes: (1..=3)
            .map(|id| {
                (
                    id,
                    ControlNode {
                        endpoint: format!("https://node-{id}.invalid:8443"),
                        failure_domain: format!("rack-{id}"),
                        certificate_pins: BTreeSet::from([format!("{id:064x}")]),
                    },
                )
            })
            .collect(),
        tenants: BTreeMap::from([(
            "bpng".into(),
            TenantRoute {
                incarnation: "b63744c9-1caf-4a95-884b-c7c4d261a12f".into(),
                mode: DeploymentMode::Replicated,
                voters: BTreeSet::from([1, 2, 3]),
            },
        )]),
    }
}

#[test]
fn topology_json_uses_canonical_distinct_numeric_node_keys_and_closed_fields() {
    let original = serde_json::to_string(&topology()).unwrap();
    let decoded: ControlTopology = serde_json::from_str(&original).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded, topology());
    for key in ["01", "+1", " 1", "1.0", "18446744073709551616"] {
        let alias = original.replacen("\"1\":", &format!("\"{key}\":"), 1);
        assert_ne!(alias, original);
        assert!(serde_json::from_str::<ControlTopology>(&alias).is_err());
    }
    let node = serde_json::to_string(&topology().nodes[&1]).unwrap();
    let duplicate = format!("{{\"nodes\":{{\"1\":{node},\"1\":{node}}},\"tenants\":{{}}}}");
    assert!(serde_json::from_str::<ControlTopology>(&duplicate).is_err());
    let mut unknown = serde_json::to_value(topology()).unwrap();
    unknown["nodes"]["1"]["authority"] = json!(true);
    assert!(serde_json::from_value::<ControlTopology>(unknown).is_err());
}

#[test]
fn replicated_topology_requires_distinct_tls_nodes_domains_and_exact_voters() {
    topology().validate().unwrap();
    for mutation in 0..9 {
        let mut value = topology();
        match mutation {
            0 => {
                value.nodes.get_mut(&2).unwrap().certificate_pins =
                    value.nodes[&1].certificate_pins.clone()
            }
            1 => value.nodes.get_mut(&2).unwrap().failure_domain = "rack-1".into(),
            2 => {
                value.tenants.get_mut("bpng").unwrap().voters.remove(&3);
            }
            3 => {
                value.tenants.get_mut("bpng").unwrap().voters.insert(4);
            }
            4 => {
                value.nodes.remove(&3);
            }
            5 => value.nodes.get_mut(&1).unwrap().endpoint = "http://node.invalid".into(),
            6 => value.nodes.get_mut(&1).unwrap().endpoint = "https://user@node.invalid".into(),
            7 => value.nodes.get_mut(&1).unwrap().certificate_pins.clear(),
            _ => value
                .nodes
                .get_mut(&1)
                .unwrap()
                .certificate_pins
                .insert("z".repeat(64))
                .then_some(())
                .unwrap(),
        }
        assert!(value.validate().is_err(), "mutation {mutation}");
    }
    let mut local = topology();
    local.tenants.get_mut("bpng").unwrap().mode = DeploymentMode::Local;
    assert!(local.validate().is_err());
    local.tenants.get_mut("bpng").unwrap().voters = BTreeSet::from([1]);
    local.validate().unwrap();
}

#[test]
fn tenant_incarnation_has_one_non_nil_canonical_uuid() {
    for incarnation in [
        Uuid::nil().to_string(),
        "B63744C9-1CAF-4A95-884B-C7C4D261A12F".into(),
        "b63744c91caf4a95884bc7c4d261a12f".into(),
        "not-an-id".into(),
    ] {
        let mut value = topology();
        value.tenants.get_mut("bpng").unwrap().incarnation = incarnation;
        assert!(value.validate().is_err());
    }
}

fn observation() -> ControlTopologyObservation {
    let incarnation = Uuid::parse_str("c23537ca-f43b-42bd-95c8-b1c6f7e6cb48").unwrap();
    ControlTopologyObservation {
        request: ReadControlTopology {
            request_id: Uuid::new_v4(),
            control_incarnation: incarnation,
            maximum_lifetime_ms: 500,
        },
        root: ControlSigningRoot {
            control_incarnation: incarnation,
            public_key: "57".repeat(32),
        },
        caller: ControlTopologyCaller {
            principal: "data-node".into(),
            certificate_sha256: "21".repeat(32),
            credential_sha256: "32".repeat(32),
        },
        policy_epoch: 1,
        revision: 2,
        term: 3,
        leader_node_id: 4,
        voters: BTreeSet::from([4, 5, 6]),
        topology: VersionedTopology {
            version: 7,
            topology: topology(),
        },
        admitted_at_ms: 1_000,
        not_after_ms: 1_500,
    }
}

#[test]
fn topology_observation_binds_distinct_control_voters_identity_and_bounded_lifetime() {
    let original = observation();
    original.validate().unwrap();
    assert_eq!(
        serde_json::from_slice::<ControlTopologyObservation>(
            &serde_json::to_vec(&original).unwrap()
        )
        .unwrap(),
        original
    );
    for mutation in 0..13 {
        let mut value = original.clone();
        match mutation {
            0 => value.request.request_id = Uuid::nil(),
            1 => value.request.control_incarnation = Uuid::new_v4(),
            2 => value.request.maximum_lifetime_ms = 5_001,
            3 => value.policy_epoch = 0,
            4 => value.revision = 0,
            5 => value.term = 0,
            6 => value.leader_node_id = 1,
            7 => {
                value.voters.remove(&6);
            }
            8 => {
                value.voters = BTreeSet::from([0, 4, 5]);
            }
            9 => value.topology.version = 0,
            10 => value.not_after_ms = value.admitted_at_ms,
            11 => value.not_after_ms += 1,
            _ => value.caller.certificate_sha256 = "not-a-pin".into(),
        }
        assert!(value.validate().is_err(), "mutation {mutation}");
    }
    // A shape-valid response still has no signature verification or execution authority.
    let mut unverified = original;
    unverified.root.public_key = "68".repeat(32);
    unverified.validate().unwrap();
}
