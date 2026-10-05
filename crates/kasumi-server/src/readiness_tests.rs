use super::*;
use kasumi_engine::admission::AdmissionConfig;
use kasumi_raft::MembershipObserver;

fn admission(bytes: u64) -> Arc<NodeAdmission> {
    let mut config = AdmissionConfig {
        max_inflight_bytes: Some(bytes),
        max_sample_age_ms: 60_000,
        ..Default::default()
    };
    let bookkeeping = NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
    config.max_inflight_bytes = Some(bookkeeping.checked_add(bytes).unwrap());
    NodeAdmission::new(config).unwrap()
}
fn epoch() -> Epoch {
    Epoch {
        topology_version: 1,
        installed_routes: 2,
        actual_membership: 3,
    }
}
fn sample(index: usize, quorum: bool) -> Sample {
    Sample {
        tenant: format!("tenant-{index}"),
        incarnation: "original".into(),
        quorum,
    }
}
fn complete(coverage: &Coverage, groups: usize, now: Instant) {
    coverage.begin(epoch(), groups, now);
    for index in 0..groups {
        coverage.record(sample(index, true), true);
    }
    coverage.finish(epoch());
}

#[test]
fn complete_coverage_exceeds_diagnostic_page_without_group_count_cutoff() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    complete(&coverage, 1025, now);
    let snapshot = coverage.snapshot(epoch(), now);
    assert!(snapshot.status.ready());
    assert_eq!(snapshot.status.expected_groups, Some(1025));
    assert_eq!(snapshot.status.examined_groups, 1025);
    assert_eq!(snapshot.status.healthy_groups, 1025);
    assert_eq!(snapshot.details.len(), DETAIL_LIMIT);
    assert!(coverage.check(snapshot.token.unwrap(), epoch(), now));
}

#[test]
fn unhealthy_group_beyond_detail_page_preserves_complete_coverage_and_original_token() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    complete(&coverage, 130, now);
    let token = coverage.snapshot(epoch(), now).token.unwrap();
    coverage.begin(epoch(), 130, now + Duration::from_secs(1));
    for index in 0..129 {
        coverage.record(sample(index, true), true);
    }
    assert!(coverage.snapshot(epoch(), now).status.ready());
    assert!(coverage.check(token, epoch(), now));
    coverage.record(sample(129, false), false);
    assert!(coverage.check(token, epoch(), now));
    coverage.finish(epoch());
    let completed = coverage.snapshot(epoch(), now);
    assert!(completed.status.complete && completed.status.fresh);
    assert_eq!(completed.status.examined_groups, 130);
    assert_eq!(completed.status.healthy_groups, 129);
    assert!(completed.status.ready());
    assert!(coverage.check(token, epoch(), now));
    assert_eq!(completed.details.len(), DETAIL_LIMIT);
    assert!(completed.details.iter().all(|sample| sample.quorum));
}

#[test]
fn partial_and_slow_complete_sweeps_do_not_certify_readiness() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    assert!(!coverage.snapshot(epoch(), now).status.ready());
    coverage.begin(epoch(), 2, now);
    coverage.record(sample(0, true), true);
    let partial = coverage.snapshot(epoch(), now);
    assert_eq!(partial.status.examined_groups, 1);
    assert!(!partial.status.complete && !partial.status.fresh);
    assert!(partial.token.is_none());
    coverage.record(sample(1, true), true);
    coverage.finish(epoch());
    let expired = coverage.snapshot(epoch(), now + FRESHNESS);
    assert!(expired.status.complete);
    assert!(!expired.status.fresh && !expired.status.ready());
    assert!(expired.token.is_none());
    assert_eq!(expired.status.oldest_probe_age_seconds, Some(30.0));
}

#[test]
fn refreshing_and_renewed_coverage_never_extend_original_release_deadline() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    complete(&coverage, 2, now);
    let original = coverage.snapshot(epoch(), now).token.unwrap();
    coverage.begin(epoch(), 2, now + Duration::from_secs(1));
    coverage.record(sample(0, true), true);
    assert!(
        coverage
            .snapshot(epoch(), now + Duration::from_secs(1))
            .status
            .ready()
    );
    assert!(coverage.check(original, epoch(), now + Duration::from_secs(1)));
    coverage.record(sample(1, true), true);
    coverage.finish(epoch());
    let refreshed = coverage.snapshot(epoch(), now + FRESHNESS);
    assert!(refreshed.status.ready());
    assert!(!coverage.check(original, epoch(), now + FRESHNESS));
    assert!(coverage.check(refreshed.token.unwrap(), epoch(), now + FRESHNESS));
}

#[test]
fn original_coverage_freshness_deadline_applies_even_beyond_detail_page() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    coverage.begin(epoch(), 130, now);
    for index in 0..130 {
        coverage.record(sample(index, true), true);
    }
    coverage.finish(epoch());
    let original = coverage.snapshot(epoch(), now);
    assert_eq!(original.details.len(), DETAIL_LIMIT);
    let token = original.token.unwrap();
    let deadline = now + FRESHNESS;
    let before_deadline = deadline - Duration::from_millis(1);
    assert!(coverage.check(token, epoch(), before_deadline));
    assert!(coverage.snapshot(epoch(), before_deadline).status.ready());
    assert!(!coverage.check(token, epoch(), deadline));
    assert!(!coverage.snapshot(epoch(), deadline).status.ready());
    complete(&coverage, 130, now + Duration::from_secs(1));
    let renewed = coverage.snapshot(epoch(), deadline);
    assert!(renewed.status.ready());
    assert!(coverage.check(renewed.token.unwrap(), epoch(), deadline));
    assert!(!coverage.check(token, epoch(), deadline));
}

#[test]
fn every_membership_epoch_component_fences_original_release_and_requires_new_sweep() {
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    complete(&coverage, 1, now);
    let token = coverage.snapshot(epoch(), now).token.unwrap();
    for changed in [
        Epoch {
            topology_version: 2,
            ..epoch()
        },
        Epoch {
            installed_routes: 3,
            ..epoch()
        },
        Epoch {
            actual_membership: 4,
            ..epoch()
        },
    ] {
        assert!(!coverage.check(token, changed, now));
        let snapshot = coverage.snapshot(changed, now);
        assert!(snapshot.status.expected_groups.is_none());
        assert!(!snapshot.status.ready());
        assert!(snapshot.token.is_none());
    }
    coverage.invalidate();
    assert!(!coverage.check(token, epoch(), now));
}

#[test]
fn membership_and_failure_epoch_saturation_permanently_fail_closed() {
    let observer = MembershipEpoch(AtomicU64::new(u64::MAX - 1));
    observer.membership_changing();
    observer.membership_changing();
    assert!(observer.current().is_err());
    assert_eq!(observer.0.load(Ordering::Acquire), u64::MAX);
    let coverage = Coverage::new(&admission(4 << 20)).unwrap();
    let now = Instant::now();
    complete(&coverage, 1, now);
    let token = coverage.snapshot(epoch(), now).token.unwrap();
    coverage.state.lock().unwrap().invalidation = u64::MAX - 1;
    coverage.invalidate();
    coverage.invalidate();
    complete(&coverage, 1, now);
    assert!(coverage.snapshot(epoch(), now).token.is_none());
    assert!(!coverage.check(token, epoch(), now));
}

#[test]
fn coverage_metadata_has_real_lifetime_charge_and_admission_rejection() {
    let admission = admission(METADATA_BYTES);
    let bookkeeping = admission.snapshot().bookkeeping_bytes;
    let coverage = Coverage::new(&admission).unwrap();
    assert_eq!(
        admission.snapshot().reserved_bytes,
        bookkeeping + METADATA_BYTES
    );
    assert_eq!(admission.snapshot().inflight_operations, 0);
    assert!(Coverage::new(&admission).is_err());
    drop(coverage);
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping);
    assert!(Coverage::new(&admission).is_ok());
}
