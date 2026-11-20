use super::*;

fn remote() -> RemoteControl {
    RemoteControl {
        root: ControlSigningRoot {
            control_incarnation: uuid::Uuid::new_v4(),
            public_key: "ab".repeat(32),
        },
        principal: "reader".into(),
        observers: BTreeSet::from(["operator".into()]),
        refresh: Duration::from_secs(2),
        timeout: Duration::from_secs(1),
        admission: NodeAdmission::new_fixture(Default::default()).unwrap(),
        pool: tokio::sync::Mutex::new(None),
        fence: Fence::default(),
        closed: watch::channel(false).0,
        state: Mutex::new(State {
            state: AccessState::Connecting,
            current: None,
            consecutive_failures: 0,
            last_failure: None,
        }),
    }
}

fn observation(
    remote: &RemoteControl,
    version: u64,
    revision: u64,
    digest: u8,
) -> Arc<RemoteTopology> {
    Arc::new(RemoteTopology {
        version,
        topology: ControlTopology::default(),
        policy_epoch: 1,
        revision,
        term: 4,
        leader: 1,
        voters: BTreeSet::from([1, 2, 3]),
        digest: [digest; 32],
        _resident: remote.admission.reserve_resident(4096).unwrap(),
    })
}

#[tokio::test]
async fn sealed_remote_observations_drain_all_admitted_readers() {
    let remote = remote();
    let one = remote.fence.begin().unwrap();
    let two = remote.fence.begin().unwrap();
    remote.close();
    assert!(remote.fence.begin().is_none());
    assert!(matches!(remote.refresh().await, Err(Failure::Closed)));
    let drain = remote.drain();
    tokio::pin!(drain);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut drain)
            .await
            .is_err()
    );
    drop(one);
    assert_eq!(remote.active_observations(), 1);
    drop(two);
    tokio::time::timeout(Duration::from_secs(3), drain)
        .await
        .unwrap();
    assert_eq!(remote.active_observations(), 0);
    assert!(matches!(remote.status().state, AccessState::Closed));
}

#[test]
fn remote_topology_keeps_the_last_verified_snapshot_and_its_readers() {
    let remote = remote();
    assert!(remote.topology().is_err());
    let first = remote.admit(observation(&remote, 7, 15, 1)).unwrap();
    let reserved = remote.admission.snapshot().reserved_bytes;
    let current = remote.admit(observation(&remote, 8, 16, 2)).unwrap();
    assert!(remote.admission.snapshot().reserved_bytes >= reserved + 4096);
    assert!(matches!(
        remote.admit(observation(&remote, 7, 17, 1)),
        Err(Failure::Regressed)
    ));
    assert!(matches!(
        remote.admit(observation(&remote, 9, 14, 1)),
        Err(Failure::Regressed)
    ));
    assert!(matches!(
        remote.admit(observation(&remote, 8, 17, 3)),
        Err(Failure::Inconsistent)
    ));
    assert!(Arc::ptr_eq(&remote.topology().unwrap(), &current));
    drop(first);
    assert_eq!(remote.admission.snapshot().reserved_bytes, reserved);
    remote.close();
    assert!(matches!(
        remote.admit(observation(&remote, 9, 17, 4)),
        Err(Failure::Closed)
    ));
}
