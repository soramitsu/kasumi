use super::*;
use crate::runtime::{MutualTlsEndpoint, ReplicaConfig, ReplicationConfig, TlsFiles};

fn configuration() -> ReplicationConfig {
    ReplicationConfig {
        initial_voters: BTreeSet::from([1, 2, 3]),
        node_id: 1,
        listener: MutualTlsEndpoint {
            listen: "127.0.0.1:1".parse().unwrap(),
            tls: TlsFiles {
                certificate: "/synthetic/cert".into(),
                private_key: "/synthetic/key".into(),
            },
            client_ca: "/synthetic/ca".into(),
        },
        peers: (1..=3)
            .map(|id| ReplicaConfig {
                node_id: id,
                endpoint: format!("https://node-{id}.invalid/"),
                failure_domain: format!("rack-{id}"),
                certificate_pins: vec![format!("{id:02x}").repeat(32)],
            })
            .collect(),
    }
}
fn node(payload: u64) -> Arc<NodeAdmission> {
    NodeAdmission::new(
        kasumi_engine::test_utils::admission_config_with_bookkeeping(
            kasumi_engine::admission::AdmissionConfig {
                max_inflight_bytes: Some(payload),
                max_inflight_operations: 2,
                max_reservations: 16,
                max_snapshot_startups: 2,
                max_startup_scopes: 2,
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap()
}
fn construct(
    admission: &Arc<NodeAdmission>,
    config: &ReplicationConfig,
) -> Result<ConfiguredNodes> {
    let mut work = NodesWork::new(admission, configured_quote(config)?)?;
    match config.control_nodes() {
        Ok(nodes) => {
            work.nodes = Some(nodes);
            work.finish()
        }
        Err(error) => Err(work.fail(error)),
    }
}
#[test]
fn configured_node_ownership_denial_retention_failure_and_transfer() {
    let config = configuration();
    let quoted = configured_quote(&config).unwrap();
    let denied = node(quoted - 1);
    let before = denied.snapshot();
    let error = construct(&denied, &config).err().unwrap();
    assert_eq!(
        error.downcast_ref::<kasumi_types::Error>().unwrap().code,
        kasumi_types::ErrorCode::ResourceExhausted
    );
    assert_eq!(denied.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        denied.snapshot().live_reservations,
        before.live_reservations
    );

    let admission = node(32 << 20);
    let before = admission.snapshot();
    let nodes = construct(&admission, &config).unwrap();
    assert_eq!(nodes.as_ref_for_test(), &config.control_nodes().unwrap());
    assert_eq!(admission.snapshot().inflight_operations, 0);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + nodes_retained(&nodes).unwrap() + fixed().unwrap()
    );
    let bytes = admission.snapshot().reserved_bytes;
    let moved = std::thread::spawn(move || nodes).join().unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, bytes);
    let update = moved.replacement(ControlTopology::default()).unwrap();
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1,
        "replacement renewed the grant"
    );
    let encoded = serde_json::to_value(update.topology.as_ref().unwrap()).unwrap();
    assert_eq!(encoded["nodes"].as_object().unwrap().len(), 3);
    drop(encoded);
    drop(update);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);

    let mut invalid = config;
    invalid.peers[0].endpoint = "http://node.invalid/".into();
    let error = construct(&admission, &invalid).err().unwrap();
    assert_eq!(admission.snapshot().inflight_operations, 0);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    let original = error.to_string();
    let error = error.downcast::<Failure>().unwrap();
    assert_eq!(error.to_string(), original);
    std::thread::spawn(move || drop(error)).join().unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);

    // Replacement rejects before returning the object consumed after the
    // management Started event, retaining the original validation diagnostic.
    let nodes = construct(&admission, &configuration()).unwrap();
    let invalid = ControlTopology {
        nodes: BTreeMap::new(),
        tenants: BTreeMap::from([(
            "tenant".into(),
            kasumi_engine::control::TenantRoute {
                incarnation: "bad".into(),
                mode: kasumi_engine::control::DeploymentMode::Local,
                voters: BTreeSet::from([1]),
            },
        )]),
    };
    let error = nodes.replacement(invalid).err().unwrap();
    let error = error.downcast::<Failure>().unwrap();
    assert_eq!(
        error.validation_error().unwrap().message,
        "invalid tenant incarnation"
    );
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    drop(error);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
}
#[test]
fn empty_peer_replacement_retains_publication_failure_credit_until_original_drop() {
    use std::sync::atomic::{AtomicBool, Ordering};

    // The observer is dropped after the original typed diagnostic, proving
    // that diagnostic destruction precedes credit release inside Failure.
    struct AfterOriginal {
        admission: Arc<NodeAdmission>,
        bytes: u64,
        slots: usize,
        observed: Arc<AtomicBool>,
    }
    impl Drop for AfterOriginal {
        fn drop(&mut self) {
            let snapshot = self.admission.snapshot();
            assert_eq!(snapshot.reserved_bytes, self.bytes);
            assert_eq!(snapshot.live_reservations, self.slots);
            self.observed.store(true, Ordering::SeqCst);
        }
    }
    struct Original {
        diagnostic: kasumi_types::Error,
        _after: AfterOriginal,
    }
    impl std::fmt::Debug for Original {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(&self.diagnostic, f)
        }
    }
    impl std::fmt::Display for Original {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(&self.diagnostic, f)
        }
    }
    impl std::error::Error for Original {}

    let mut config = configuration();
    config.peers.clear();
    let fixed = fixed().unwrap();
    assert!(fixed > 0);
    assert_eq!(configured_quote(&config).unwrap(), fixed);

    // The initial empty map fits exactly, but the additional validation
    // scratch cannot be admitted. Failure must retain its already-owned fixed
    // credit without trying to admit memory during cleanup.
    let refused = node(fixed);
    let before_refusal = refused.snapshot();
    let nodes = construct(&refused, &config).unwrap();
    let failure = nodes.replacement(ControlTopology::default()).err().unwrap();
    let failure = failure.downcast::<Failure>().unwrap();
    assert_eq!(
        failure.validation_error().unwrap().code,
        kasumi_types::ErrorCode::ResourceExhausted
    );
    assert_eq!(
        refused.snapshot().reserved_bytes,
        before_refusal.reserved_bytes + fixed
    );
    assert_eq!(
        refused.snapshot().live_reservations,
        before_refusal.live_reservations + 1
    );
    std::thread::spawn(move || drop(failure)).join().unwrap();
    assert_eq!(
        refused.snapshot().reserved_bytes,
        before_refusal.reserved_bytes
    );
    assert_eq!(
        refused.snapshot().live_reservations,
        before_refusal.live_reservations
    );

    let admission = node(32 << 20);
    let baseline = admission.snapshot();
    let nodes = construct(&admission, &config).unwrap();
    assert!(nodes.is_empty());
    assert_eq!(nodes_retained(&nodes).unwrap(), 0);
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline.reserved_bytes + fixed
    );
    let update = nodes.replacement(ControlTopology::default()).unwrap();
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline.reserved_bytes + fixed
    );
    assert_eq!(
        admission.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert_eq!(
        admission.snapshot().inflight_operations,
        baseline.inflight_operations
    );
    let observed = Arc::new(AtomicBool::new(false));
    let original = Original {
        diagnostic: kasumi_types::Error::new(
            kasumi_types::ErrorCode::Unavailable,
            "publication refused after validation",
        ),
        _after: AfterOriginal {
            admission: admission.clone(),
            bytes: baseline.reserved_bytes + fixed,
            slots: baseline.live_reservations + 1,
            observed: observed.clone(),
        },
    };
    // This is the same private failure endpoint used after publish's await.
    // No dispatch is needed to exercise the retained original owner contract.
    let failure = update.fail(anyhow::Error::new(original));
    assert!(!observed.load(Ordering::SeqCst));
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline.reserved_bytes + fixed
    );
    let failure = failure.downcast::<Failure>().unwrap();
    assert_eq!(
        failure.to_string(),
        "Unavailable: publication refused after validation"
    );
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline.reserved_bytes + fixed
    );
    std::thread::spawn(move || drop(failure)).join().unwrap();
    assert!(observed.load(Ordering::SeqCst));
    assert_eq!(admission.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        baseline.live_reservations
    );
}

impl ConfiguredNodes {
    fn as_ref_for_test(&self) -> &BTreeMap<u64, ControlNode> {
        &self.nodes
    }
}
#[test]
fn configured_quotes_cover_normalized_maps() {
    let mut config = configuration();
    for host in [
        "node.invalid",
        "BÜCHER.invalid",
        "xn--bcher-kva.invalid",
        "[::1]",
    ] {
        config.peers[0].endpoint = format!("https://{host}:443/");
        config.peers[0].certificate_pins = vec!["AA".repeat(32), "aa".repeat(32)];
        let nodes = config.control_nodes().unwrap();
        assert!(
            configured_quote(&config).unwrap()
                >= nodes_retained(&nodes).unwrap() + fixed().unwrap()
        );
        assert_eq!(nodes[&1].certificate_pins.len(), 1);
        assert_eq!(
            nodes[&1].certificate_pins.iter().next().unwrap(),
            &"aa".repeat(32)
        );
    }
    assert!(tree::<String, ControlNode>(usize::MAX).is_err());
    assert!(backing(usize::MAX).is_err());
}

#[test]
fn concrete_node_normalization_heap_census() -> Result<()> {
    const NAME: &str = "administration::topology::tests::concrete_node_normalization_heap_census";
    const MARKER: &str = "KASUMI_ADMIN_TOPOLOGY_CENSUS";
    if std::env::var(MARKER).as_deref() != Ok(NAME) {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(MARKER, NAME)
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .output()?;
        ensure!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "topology heap census failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    use super::super::configured_tenant_enrollment::measure_topology;
    let mut config = configuration();
    for count in [1usize, 3, 48, 1024] {
        config.peers = (1..=count)
            .map(|id| ReplicaConfig {
                node_id: id as u64,
                endpoint: format!("https://node-{id}.invalid/"),
                failure_domain: format!("rack-{id}"),
                certificate_pins: vec![format!("{id:064X}"), format!("{id:064x}")],
            })
            .collect();
        for endpoint in [
            "https://node.invalid/",
            "https://BÜCHER.invalid/",
            "https://\u{fdfa}.invalid/",
            "http://bad.invalid/",
            "not a URL",
        ] {
            config.peers[0].endpoint = endpoint.into();
            let (quote, live, peak, invalid, allocations) =
                measure_topology(|| configured_quote(&config));
            assert_eq!((live, peak, invalid, allocations), (0, 0, false, 0));
            let quote = quote?;
            let (_, live, peak, invalid, _) = measure_topology(|| drop(config.control_nodes()));
            assert!(
                !invalid && live == 0,
                "normalizer census lost an allocation lifetime"
            );
            assert!(peak as u64 <= quote, "normalizer {peak} > {quote}");
        }
    }
    Ok(())
}
