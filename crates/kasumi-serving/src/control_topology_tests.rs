//! Disposable signatures test immutable origin only, never live Control authority.

use super::*;
use kasumi_types::control_topology::{
    ControlNode, ControlTopology, DeploymentMode, TenantRoute, VersionedTopology,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeSet;
use uuid::Uuid;

struct Fixture {
    key: Ed25519KeyPair,
    trust: ControlTrust,
    signed: SignedControlTopology,
}
impl Fixture {
    fn new() -> Self {
        // Public synthetic seed; this fixture is not installed or network authority.
        let key = Ed25519KeyPair::from_seed_unchecked(&[0x37; 32]).unwrap();
        let incarnation = Uuid::new_v4();
        let root = ControlSigningRoot {
            control_incarnation: incarnation,
            public_key: hex::encode(key.public_key().as_ref()),
        };
        let trust = ControlTrust::install(root.clone()).unwrap();
        let mut fixture = Self {
            key,
            trust,
            signed: SignedControlTopology {
                observation: ControlTopologyObservation {
                    request: ReadControlTopology {
                        request_id: Uuid::new_v4(),
                        control_incarnation: incarnation,
                        maximum_lifetime_ms: 500,
                    },
                    root,
                    caller: ControlTopologyCaller {
                        principal: "data-node".into(),
                        certificate_sha256: "21".repeat(32),
                        credential_sha256: "32".repeat(32),
                    },
                    policy_epoch: 2,
                    revision: 5,
                    term: 3,
                    leader_node_id: 4,
                    voters: BTreeSet::from([4, 5, 6]),
                    topology: VersionedTopology {
                        version: 1,
                        topology: ControlTopology {
                            nodes: (1..=3)
                                .map(|id| {
                                    (
                                        id,
                                        ControlNode {
                                            endpoint: format!("https://node-{id}.invalid:8443"),
                                            failure_domain: format!("rack-{id}"),
                                            certificate_pins: BTreeSet::from([format!(
                                                "{id:064x}"
                                            )]),
                                        },
                                    )
                                })
                                .collect(),
                            tenants: BTreeMap::from([(
                                "bpng".into(),
                                TenantRoute {
                                    incarnation: Uuid::new_v4().to_string(),
                                    mode: DeploymentMode::Replicated,
                                    voters: BTreeSet::from([1, 2, 3]),
                                },
                            )]),
                        },
                    },
                    admitted_at_ms: 1_000,
                    not_after_ms: 1_500,
                },
                signature: String::new(),
            },
        };
        fixture.signed.signature =
            fixture.sign("kasumi.control-topology.v1", &fixture.signed.observation);
        fixture
    }
    fn sign(&self, domain: &str, value: &impl serde::Serialize) -> String {
        hex::encode(
            self.key
                .sign(&serde_json::to_vec(&(domain, value)).unwrap())
                .as_ref(),
        )
    }
    fn release(&self, request_id: Uuid) -> SignedControlTopologyRelease {
        let release = ControlTopologyRelease {
            request_id,
            original_sha256: digest(&self.signed).unwrap(),
            revision: self.signed.observation.revision + 1,
            not_after_ms: self.signed.observation.not_after_ms,
        };
        let signature = self.sign("kasumi.control-topology-release.v1", &release);
        SignedControlTopologyRelease { release, signature }
    }
}

#[test]
fn topology_signature_binds_every_routing_identity_and_the_installed_root() {
    let f = Fixture::new();
    f.trust.verify_topology(&f.signed).unwrap();
    for mutation in 0..12 {
        let mut changed = f.signed.clone();
        let o = &mut changed.observation;
        match mutation {
            0 => o.request.request_id = Uuid::new_v4(),
            1 => o.caller.principal = "another-node".into(),
            2 => o.caller.credential_sha256 = "43".repeat(32),
            3 => o.caller.certificate_sha256 = "54".repeat(32),
            4 => o.policy_epoch += 1,
            5 => o.revision += 1,
            6 => o.term += 1,
            7 => o.leader_node_id = 5,
            8 => o.topology.version += 1,
            9 => {
                o.topology.topology.nodes.get_mut(&1).unwrap().endpoint =
                    "https://replacement.invalid:8443".into()
            }
            10 => o.not_after_ms -= 1,
            _ => o.root.public_key = "65".repeat(32),
        }
        assert!(
            f.trust.verify_topology(&changed).is_err(),
            "mutation {mutation}"
        );
    }
    let other = Fixture::new();
    assert!(other.trust.verify_topology(&f.signed).is_err());
}

#[test]
fn valid_signatures_cannot_relax_release_request_original_revision_or_deadline() {
    let f = Fixture::new();
    let id = Uuid::new_v4();
    let original = f.release(id);
    f.trust
        .verify_topology_release(&f.signed, id, &original)
        .unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.release.request_id = Uuid::new_v4(),
            1 => changed.release.original_sha256 = "76".repeat(32),
            2 => changed.release.revision = f.signed.observation.revision - 1,
            3 => changed.release.not_after_ms += 1,
            _ => changed.release.not_after_ms -= 1,
        }
        changed.signature = f.sign("kasumi.control-topology-release.v1", &changed.release);
        assert!(
            f.trust
                .verify_topology_release(&f.signed, id, &changed)
                .is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        f.trust
            .verify_topology_release(&f.signed, Uuid::nil(), &original)
            .is_err()
    );
    let other_original = Fixture::new();
    assert!(
        f.trust
            .verify_topology_release(&other_original.signed, id, &original)
            .is_err()
    );
}

#[test]
fn topology_and_release_domains_are_distinct_and_malformed_signatures_reject() {
    let f = Fixture::new();
    let id = Uuid::new_v4();
    let mut release = f.release(id);
    release.signature = f.sign("kasumi.control-topology.v1", &release.release);
    assert!(
        f.trust
            .verify_topology_release(&f.signed, id, &release)
            .is_err()
    );
    for signature in [
        String::new(),
        "00".repeat(63),
        "00".repeat(64),
        "zz".repeat(64),
    ] {
        let mut changed = f.signed.clone();
        changed.signature = signature;
        assert!(f.trust.verify_topology(&changed).is_err());
    }
}
