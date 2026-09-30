//! Disposable origin signatures exercise the real native-client admission.
use super::*;
use kasumi_clock::{EpochClock, LeaseClock, WallClock};
use kasumi_types::control_topology::{ControlTopology, VersionedTopology};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct Elapsed(AtomicU64);
impl LeaseClock for Elapsed {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
struct Wall;
impl WallClock for Wall {
    fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(1_000)
    }
}
struct Fixture {
    elapsed: Arc<Elapsed>,
    clock: EpochClock,
    key: Ed25519KeyPair,
    trust: ControlTrust,
    signed: SignedControlTopology,
}
impl Fixture {
    fn new() -> Self {
        let elapsed = Arc::new(Elapsed(AtomicU64::new(0)));
        let clock = EpochClock::new(elapsed.clone(), Arc::new(Wall)).unwrap();
        // Public synthetic seed, never installation or deployment material.
        let key = Ed25519KeyPair::from_seed_unchecked(&[0x62; 32]).unwrap();
        let root = ControlSigningRoot {
            control_incarnation: uuid::Uuid::new_v4(),
            public_key: hex::encode(key.public_key().as_ref()),
        };
        let trust = ControlTrust::install(root.clone()).unwrap();
        let mut value = Self {
            elapsed,
            clock,
            key,
            trust,
            signed: SignedControlTopology {
                observation: ControlTopologyObservation {
                    request: ReadControlTopology {
                        request_id: uuid::Uuid::new_v4(),
                        control_incarnation: root.control_incarnation,
                        maximum_lifetime_ms: 500,
                    },
                    root,
                    caller: ControlTopologyCaller {
                        principal: "reader".into(),
                        certificate_sha256: "31".repeat(32),
                        credential_sha256: "42".repeat(32),
                    },
                    policy_epoch: 2,
                    revision: 7,
                    term: 3,
                    leader_node_id: 4,
                    voters: std::collections::BTreeSet::from([4, 5, 6]),
                    topology: VersionedTopology {
                        version: 1,
                        topology: ControlTopology::default(),
                    },
                    admitted_at_ms: 1_000,
                    not_after_ms: 1_500,
                },
                signature: String::new(),
            },
        };
        value.sign();
        value
    }
    fn sign(&mut self) {
        self.signed.signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&("kasumi.control-topology.v1", &self.signed.observation))
                        .unwrap(),
                )
                .as_ref(),
        );
    }
    fn admit(&self, anchor: ClockObservation) -> Result<CurrentControlTopology, ClientError> {
        CurrentControlTopology::admit(
            &self.trust,
            &self.signed.observation.request,
            &self.signed.observation.caller,
            anchor,
            self.signed.clone(),
        )
    }
}

#[test]
fn delayed_reply_and_clones_preserve_original_elapsed_expiry() {
    let f = Fixture::new();
    let anchor = f.clock.observe().unwrap();
    f.elapsed.0.store(450, Ordering::SeqCst);
    let current = f.admit(anchor.clone()).unwrap();
    let copy = current.clone();
    assert_eq!(copy.observation().unwrap().revision, 7);
    f.elapsed.0.store(500, Ordering::SeqCst);
    assert!(current.observation().is_err());
    assert!(copy.check().is_err());
    assert!(f.admit(anchor).is_err());
    // Once elapsed regression/expiry seals a retained proof, a clock change
    // cannot revive that proof or its copies.
    f.elapsed.0.store(499, Ordering::SeqCst);
    assert!(copy.check().is_err());
}

#[test]
fn future_signed_server_time_cannot_extend_the_request_lifetime() {
    let mut f = Fixture::new();
    let anchor = f.clock.observe().unwrap();
    f.signed.observation.admitted_at_ms += 100_000;
    f.signed.observation.not_after_ms += 100_000;
    f.sign();
    let current = f.admit(anchor).unwrap();
    f.elapsed.0.store(500, Ordering::SeqCst);
    assert!(current.check().is_err());
}

#[test]
fn actual_request_caller_and_installed_root_are_independently_bound() {
    let f = Fixture::new();
    let anchor = f.clock.observe().unwrap();
    let request = &f.signed.observation.request;
    let caller = &f.signed.observation.caller;
    let mut other_request = request.clone();
    other_request.request_id = uuid::Uuid::new_v4();
    assert!(
        CurrentControlTopology::admit(
            &f.trust,
            &other_request,
            caller,
            anchor.clone(),
            f.signed.clone()
        )
        .is_err()
    );
    for field in ["principal", "certificate", "credential"] {
        let mut other = caller.clone();
        match field {
            "principal" => other.principal = "another".into(),
            "certificate" => other.certificate_sha256 = "53".repeat(32),
            _ => other.credential_sha256 = "64".repeat(32),
        }
        assert!(
            CurrentControlTopology::admit(
                &f.trust,
                request,
                &other,
                anchor.clone(),
                f.signed.clone()
            )
            .is_err()
        );
    }
    let mut root = f.trust.root().clone();
    root.control_incarnation = uuid::Uuid::new_v4();
    assert!(
        CurrentControlTopology::admit(
            &ControlTrust::install(root).unwrap(),
            request,
            caller,
            anchor.clone(),
            f.signed.clone()
        )
        .is_err()
    );
    let mut unsigned_change = f.signed.clone();
    unsigned_change.observation.revision += 1;
    assert!(
        CurrentControlTopology::admit(&f.trust, request, caller, anchor, unsigned_change).is_err()
    );
}

#[test]
fn shorter_server_deadline_and_elapsed_regression_fail_closed() {
    let mut f = Fixture::new();
    let anchor = f.clock.observe().unwrap();
    f.signed.observation.not_after_ms = 1_100;
    f.sign();
    let current = f.admit(anchor).unwrap();
    f.elapsed.0.store(80, Ordering::SeqCst);
    current.check().unwrap();
    f.elapsed.0.store(79, Ordering::SeqCst);
    assert!(current.check().is_err());
    f.elapsed.0.store(90, Ordering::SeqCst);
    assert!(current.check().is_err());
    let anchor = f.clock.observe().unwrap();
    let current = f.admit(anchor).unwrap();
    f.elapsed.0.store(100, Ordering::SeqCst);
    assert!(current.check().is_err());
}
