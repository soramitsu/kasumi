use super::*;
use kasumi_clock::LeaseClock;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
struct Clock(AtomicU64);
impl LeaseClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
fn fixture() -> (AuthoritySigner, ServingBoot, Arc<Clock>) {
    let bytes =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let signer = AuthoritySigner::from_pkcs8(bytes.as_ref()).unwrap();
    let manifest = AuthorityManifest {
        authority_id: Uuid::new_v4(),
        partitions: BTreeMap::from([(
            0,
            AuthorityPartition {
                group: "independent-0".into(),
                public_key: signer.public_key(),
            },
        )]),
        max_lease_ms: 1000,
        clock_rate_error_ppm: 0,
    };
    let identity = ServingIdentity {
        tenant: "city".into(),
        incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        node: NodeIdentity {
            node_id: 1,
            principal: "node-1".into(),
            certificate_sha256: "a".repeat(64),
        },
    };
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let boot = ServingBoot::with_test_clock(
        AuthorityTrust::install(manifest).unwrap(),
        identity,
        clock.clone(),
    )
    .unwrap();
    (signer, boot, clock)
}
fn signed(signer: &AuthoritySigner, boot: &ServingBoot, attempt: &LeaseAttempt) -> SignedLease {
    signer
        .sign_lease(LeaseClaims {
            request: attempt.request().clone(),
            authority_id: boot.authority().manifest().authority_id,
            partition: 0,
            authority_term: 3,
            authority_revision: 5,
            lifetime_ms: 1000,
            credential_lifetime_ms: 1000,
            activation_digest: "b".repeat(64),
            recovery_checkpoint: None,
        })
        .unwrap()
}
#[test]
fn delayed_response_retry_clone_and_reinstallation_never_extend_original_attempt() {
    let (signer, boot, clock) = fixture();
    let attempt = boot.begin_acquisition().unwrap();
    let response = signed(&signer, &boot, &attempt);
    clock.0.store(900, Ordering::SeqCst);
    let proof = attempt.verify(response.clone()).unwrap();
    let gate = ServingGate::new(proof.clone()).unwrap();
    let fence = gate.capture().unwrap();
    clock.0.store(1000, Ordering::SeqCst);
    assert!(attempt.clone().verify(response.clone()).is_err());
    assert!(ServingGate::new(proof).is_err());
    assert!(fence.check().is_err());
    let new_attempt = boot.begin_acquisition().unwrap();
    assert!(new_attempt.verify(response).is_err());
    let fresh = new_attempt
        .verify(signed(&signer, &boot, &new_attempt))
        .unwrap();
    assert!(gate.renew(fresh.clone()).is_err());
    assert!(fence.check().is_err());
    ServingGate::new(fresh).unwrap().check().unwrap();
}
#[test]
fn boot_incarnation_epoch_peer_issuer_and_signature_substitution_are_rejected() {
    let (signer, boot, _) = fixture();
    let attempt = boot.begin_acquisition().unwrap();
    let good = signed(&signer, &boot, &attempt);
    for selector in 0..7 {
        let mut bad = good.clone();
        match selector {
            0 => bad.claims.request.boot_id = Uuid::new_v4(),
            1 => bad.claims.request.identity.incarnation = Uuid::new_v4(),
            2 => bad.claims.request.identity.authority_epoch += 1,
            3 => bad.claims.request.identity.node.certificate_sha256 = "f".repeat(64),
            4 => bad.claims.authority_id = Uuid::new_v4(),
            5 => bad.claims.lifetime_ms += 1,
            _ => bad.signature = "0".repeat(128),
        }
        assert!(attempt.verify(bad).is_err());
    }
    let (other, _, _) = fixture();
    assert!(
        attempt
            .verify(other.sign_lease(good.claims).unwrap())
            .is_err()
    );
    let other_boot = ServingBoot::new(boot.authority().clone(), boot.identity().clone()).unwrap();
    assert!(
        other_boot
            .begin_acquisition()
            .unwrap()
            .verify(signed(&signer, &boot, &attempt))
            .is_err()
    );
}
#[test]
fn suspend_and_elapsed_rollback_close_all_clones_and_cannot_be_reanchored() {
    let (signer, boot, clock) = fixture();
    clock.0.store(10, Ordering::SeqCst);
    let attempt = boot.begin_acquisition().unwrap();
    let lease = attempt.verify(signed(&signer, &boot, &attempt)).unwrap();
    let gate = ServingGate::new(lease).unwrap();
    clock.0.store(9, Ordering::SeqCst);
    assert!(gate.check().is_err());
    clock.0.store(11, Ordering::SeqCst);
    assert!(boot.begin_acquisition().is_err());
    assert!(gate.check().is_err());
    let (signer, boot, clock) = fixture();
    let attempt = boot.begin_acquisition().unwrap();
    let proof = attempt.verify(signed(&signer, &boot, &attempt)).unwrap();
    clock.0.store(3_600_000, Ordering::SeqCst);
    assert!(proof.check().is_err());
}
#[test]
fn continuous_fresh_renewal_preserves_work_without_reanchoring_old_response() {
    let (signer, boot, clock) = fixture();
    let attempt = boot.begin_acquisition().unwrap();
    let initial = attempt.verify(signed(&signer, &boot, &attempt)).unwrap();
    let gate = ServingGate::new(initial.clone()).unwrap();
    let fence = gate.capture().unwrap();
    clock.0.store(500, Ordering::SeqCst);
    let renewal = boot.begin_acquisition().unwrap();
    gate.renew(renewal.verify(signed(&signer, &boot, &renewal)).unwrap())
        .unwrap();
    assert!(gate.renew(initial).is_err());
    clock.0.store(1000, Ordering::SeqCst);
    fence.check().unwrap();
    clock.0.store(1500, Ordering::SeqCst);
    assert!(fence.check().is_err());
}

#[test]
fn delayed_renewal_cannot_bridge_an_unobserved_expired_interval() {
    let (signer, boot, clock) = fixture();
    let initial = boot.begin_acquisition().unwrap();
    let gate = ServingGate::new(initial.verify(signed(&signer, &boot, &initial)).unwrap()).unwrap();
    let retained_response = gate.capture().unwrap();
    clock.0.store(900, Ordering::SeqCst);
    let renewal = boot.begin_acquisition().unwrap();
    let response = signed(&signer, &boot, &renewal);
    // No access/check observes the old interval expiring. The delayed response
    // is valid for its own attempt but may not reconnect this old serving gate.
    clock.0.store(1001, Ordering::SeqCst);
    let fresh = renewal.verify(response).unwrap();
    assert!(gate.renew(fresh.clone()).is_err());
    assert!(*gate.notifications().borrow());
    assert!(retained_response.check().is_err());
    // A distinct admission can use that independently verified live proof; it
    // cannot mutate or revive any captured fence from the old gate.
    ServingGate::new(fresh).unwrap().check_serving().unwrap();
    assert!(retained_response.check().is_err());
}

#[test]
fn immutable_drain_covers_slowest_client_against_fastest_issuer() {
    let (_, boot, _) = fixture();
    let mut manifest = boot.authority().manifest().clone();
    manifest.clock_rate_error_ppm = 1000;
    assert_eq!(manifest.drain_ms().unwrap(), 1003);
    // Express real time as scaled integers; even the fastest issuer's completed
    // wait covers the slowest client's original entire lease interval.
    assert!(
        manifest.drain_ms().unwrap() * (1_000_000 - manifest.clock_rate_error_ppm)
            >= manifest.max_lease_ms * (1_000_000 + manifest.clock_rate_error_ppm)
    );
    assert_ne!(manifest.digest().unwrap(), boot.authority().digest());
}
