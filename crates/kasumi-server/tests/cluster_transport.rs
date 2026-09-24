mod tls_support;

use anyhow::{Context, Result, ensure};
use kasumi_raft::{
    BasicNode, Config, RaftGroup, RaftTransport, RpcRequest, SnapshotPolicy, StateMachineBackend,
};
use kasumi_server::{
    cluster::{ClusterNetwork, PeerConfig, PeerLimits},
    tls::{ListenerLimits, serve_tls},
};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tls_support::{Authority, client};
use tokio::{net::TcpListener, sync::watch};

#[derive(Default)]
struct Backend(Mutex<BTreeMap<u64, Vec<u8>>>);

struct PreparedRestore<'a> {
    current: std::sync::MutexGuard<'a, BTreeMap<u64, Vec<u8>>>,
    restored: BTreeMap<u64, Vec<u8>>,
}
impl kasumi_raft::PreparedStateMachineRestore for PreparedRestore<'_> {
    fn retirement(&self) -> Option<kasumi_raft::RetiredSnapshotState> {
        None
    }
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)> {
        vec![]
    }
    fn application_writes(&self) -> &[kasumi_store::WriteOp] {
        &[]
    }
    fn publish(self: Box<Self>) -> Result<()> {
        let Self {
            mut current,
            restored,
        } = *self;
        *current = restored;
        Ok(())
    }
}

impl StateMachineBackend for Backend {
    fn close_application(&self) {
        self.0.lock().unwrap().clear();
    }
    fn apply(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        command: &[u8],
    ) -> Result<kasumi_raft::AppliedResponse> {
        let index = position.log_id.index;
        self.0.lock().unwrap().insert(index, command.to_vec());
        Ok(kasumi_raft::AppliedResponse::application(command.to_vec()))
    }
    fn capture_snapshot(&self) -> Result<kasumi_raft::CapturedSnapshot> {
        let data = self.0.lock().unwrap().clone();
        Ok(kasumi_raft::CapturedSnapshot::new(None, move |writer| {
            serde_json::to_writer(writer, &data)?;
            Ok(())
        }))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<kasumi_raft::RetiredSnapshotState>> {
        serde_json::from_reader::<_, BTreeMap<u64, Vec<u8>>>(bytes)?;
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>> {
        let current = self.0.lock().unwrap();
        let restored = serde_json::from_reader(bytes)?;
        Ok(Box::new(PreparedRestore { current, restored }))
    }
}

fn vote(source: u64) -> serde_json::Value {
    serde_json::json!({"rpc":"vote","payload":{"vote":{"leader_id":{"term":100,"node_id":source},"committed":false},"last_log_id":null}})
}

async fn store(node: Arc<NodeStore>) -> Result<Arc<TenantStore>> {
    TenantStore::initialize_catalog_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([13; 32])),
    )
    .await
}

fn physical(root: &std::path::Path) -> Result<kasumi_engine::test_utils::FixtureStorage> {
    let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(root)?;
    kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_three_node_raft_replicates_over_pinned_mutual_tls_http() -> Result<()> {
    let ca = Authority::new()?;
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let mut listeners = Vec::new();
    let mut identities = Vec::new();
    let mut peers = Vec::new();
    for id in 1..=3 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let identity = ca.issue("127.0.0.1")?.tls()?;
        peers.push(PeerConfig {
            node_id: id,
            endpoint: format!("https://{}", listener.local_addr()?),
            certificate_pins: BTreeSet::from([identity.certificate_pin()]),
        });
        listeners.push(listener);
        identities.push(identity);
    }
    let mut groups = Vec::new();
    let mut physical_nodes = Vec::new();
    let mut networks = Vec::new();
    let mut backends = Vec::new();
    let mut servers = Vec::new();
    let http_versions = Arc::new(Mutex::new(Vec::new()));
    let (stop, stopped) = watch::channel(false);
    for (index, listener) in listeners.into_iter().enumerate() {
        let id = index as u64 + 1;
        let network = ClusterNetwork::new(
            id,
            &identities[index],
            ca.pem.as_bytes(),
            peers.clone(),
            PeerLimits::default(),
        )?;
        network.install_audit(tls_support::audit())?;
        let backend = Arc::new(Backend::default());
        let config = Config {
            heartbeat_interval: 100,
            election_timeout_min: 500,
            election_timeout_max: 900,
            snapshot_policy: SnapshotPolicy::Never,
            ..Config::default()
        };
        let replica_root = dir.path().join(format!("replica-{id}"));
        kasumi_store::private_files::create_directory(&replica_root)?;
        let physical = physical(&replica_root)?;
        let node = physical.create_new(
            replica_root.join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        physical_nodes.push(node.clone());
        let group = RaftGroup::open(
            id,
            "tenant-a".into(),
            kasumi_store::test_utils::initialize_custody_fixture(
                store(node).await?,
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await?,
            backend.clone(),
            network.clone(),
            kasumi_raft::RaftGroupConfig {
                raft: config,
                limits: kasumi_raft::RaftLimits::default(),
            },
            physical.admission.snapshot_buffer_owner()?,
        )
        .await?;
        network.register_group(
            "tenant-a".into(),
            group.raft().clone(),
            BTreeSet::from([1, 2, 3]),
        )?;
        let observed = http_versions.clone();
        let router = network.router().layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(request.version());
                    next.run(request).await
                }
            },
        ));
        servers.push(tokio::spawn(serve_tls(
            listener,
            network.server_tls(),
            router,
            ListenerLimits::default(),
            tls_support::audit(),
            stopped.clone(),
        )));
        networks.push(network);
        groups.push(group);
        backends.push(backend);
    }
    // Replicated BasicNode addresses are deliberately unusable. Only the
    // operator's pinned peer directory may supply outbound endpoints.
    groups[0]
        .initialize(
            (1..=3)
                .map(|id| (id, BasicNode::new("http://untrusted.invalid")))
                .collect(),
        )
        .await?;
    let leader = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for (index, group) in groups.iter().enumerate() {
                if group.raft().metrics().borrow().current_leader == Some(index as u64 + 1)
                    && group.linearizable_barrier().await.is_ok()
                {
                    return index;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("no leader over authenticated network")?;
    ensure!(
        groups[leader]
            .write(b"quorum-durable-over-tls".to_vec())
            .await?
            == b"quorum-durable-over-tls",
        "wrong replicated response"
    );
    let target = groups[leader].linearizable_barrier().await?.unwrap();
    for (index, group) in groups.iter().enumerate() {
        group
            .raft()
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |metrics| {
                    metrics
                        .last_applied
                        .is_some_and(|id| id.index >= target.index)
                },
                "TLS follower application",
            )
            .await?;
        assert_eq!(
            backends[index]
                .0
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            vec![b"quorum-durable-over-tls".to_vec()]
        );
    }
    {
        let versions = http_versions.lock().unwrap();
        ensure!(
            !versions.is_empty(),
            "no authenticated cluster HTTP requests observed"
        );
        ensure!(
            versions
                .iter()
                .all(|version| *version == axum::http::Version::HTTP_2),
            "pinned cluster RPC did not negotiate HTTP/2: {versions:?}"
        );
    }
    for (network, group) in networks.iter().zip(&groups) {
        network.unregister_group("tenant-a")?;
        group.shutdown().await?;
    }
    for node in physical_nodes {
        node.shutdown().await?;
    }
    stop.send(true)?;
    for server in servers {
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn peer_requests_bind_certificate_source_candidate_target_and_group_and_limit_body()
-> Result<()> {
    let ca = Authority::new()?;
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let identities = [
        ca.issue("127.0.0.1")?,
        ca.issue("node2.example")?,
        ca.issue("node3.example")?,
    ];
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}", listener.local_addr()?);
    let peers = identities
        .iter()
        .enumerate()
        .map(|(index, identity)| {
            Ok(PeerConfig {
                node_id: index as u64 + 1,
                endpoint: endpoint.clone(),
                certificate_pins: BTreeSet::from([identity.tls()?.certificate_pin()]),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let network = ClusterNetwork::new(
        1,
        &identities[0].tls()?,
        ca.pem.as_bytes(),
        peers,
        PeerLimits {
            max_rpc_bytes: 1024,
            ..PeerLimits::default()
        },
    )?;
    let config = Config {
        enable_elect: false,
        ..Config::default()
    };
    let physical = physical(dir.path())?;
    let node = physical.create_new(
        dir.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )?;
    let group = RaftGroup::open(
        1,
        "tenant-a".into(),
        kasumi_store::test_utils::initialize_custody_fixture(
            store(node.clone()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(Backend::default()),
        network.clone(),
        kasumi_raft::RaftGroupConfig {
            raft: config,
            limits: kasumi_raft::RaftLimits::default(),
        },
        physical.admission.snapshot_buffer_owner()?,
    )
    .await?;
    network.register_group(
        "tenant-a".into(),
        group.raft().clone(),
        BTreeSet::from([1, 2]),
    )?;
    let (stop, stopped) = watch::channel(false);
    let server = tokio::spawn(serve_tls(
        listener,
        network.server_tls(),
        network.router(),
        ListenerLimits::default(),
        tls_support::audit(),
        stopped,
    ));
    let endpoint = format!("{endpoint}/internal/raft");
    let authorized = client(&ca, Some(&identities[1]))?;
    let normal = serde_json::json!({"group":"tenant-a","source":2,"target":1,"request":vote(2),"bootstrap_sha256":null});
    assert_eq!(
        authorized
            .post(&endpoint)
            .json(&normal)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "missing security audit must fail closed"
    );
    let request_audit = tls_support::audit();
    network.install_audit(request_audit.clone())?;
    assert_eq!(
        authorized
            .post(&endpoint)
            .json(&normal)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    let mut missing_bootstrap = normal.clone();
    missing_bootstrap
        .as_object_mut()
        .unwrap()
        .remove("bootstrap_sha256");
    assert_eq!(
        authorized
            .post(&endpoint)
            .json(&missing_bootstrap)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "omitted bootstrap binding must not decode as null"
    );
    for (field, value) in [
        ("source", serde_json::json!(3)),
        ("target", serde_json::json!(2)),
        ("group", serde_json::json!("tenant-b")),
        ("request", vote(3)),
    ] {
        let mut forged = normal.clone();
        forged[field] = value;
        assert_eq!(
            authorized
                .post(&endpoint)
                .json(&forged)
                .send()
                .await?
                .status(),
            reqwest::StatusCode::FORBIDDEN,
            "{field}"
        );
    }
    let denied = client(&ca, Some(&identities[2]))?;
    let unassigned = serde_json::json!({"group":"tenant-a","source":3,"target":1,"request":vote(3),"bootstrap_sha256":null});
    assert_eq!(
        denied
            .post(&endpoint)
            .json(&unassigned)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(request_audit.requests.lock().unwrap().len(), 5);
    network.set_group_allowed_peers("tenant-a", BTreeSet::from([1, 2, 3]))?;
    assert_eq!(
        denied
            .post(&endpoint)
            .json(&unassigned)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    assert!(
        network
            .set_group_allowed_peers("tenant-a", BTreeSet::from([1, 2, 4]))
            .is_err()
    );
    network.set_group_allowed_peers("tenant-a", BTreeSet::from([1, 2]))?;
    request_audit
        .fail
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        denied
            .post(&endpoint)
            .json(&unassigned)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "audit failure must never lift a denial"
    );
    request_audit
        .fail
        .store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(
        authorized
            .post(&endpoint)
            .header("content-type", "application/json")
            .body(vec![b' '; 2048])
            .send()
            .await?
            .status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    let forged: RpcRequest = serde_json::from_value(vote(2))?;
    assert!(
        network
            .send(
                "tenant-a",
                2,
                1,
                &BasicNode::new("https://127.0.0.1"),
                forged
            )
            .await
            .is_err()
    );
    let entries = (0..4).map(|index| serde_json::json!({"log_id":{"leader_id":{"term":1,"node_id":1},"index":index},"payload":{"Normal":kasumi_raft::RaftCommand::application(vec![171; 100])}})).collect::<Vec<_>>();
    let oversized: RpcRequest = serde_json::from_value(
        serde_json::json!({"rpc":"append","payload":{"vote":{"leader_id":{"term":1,"node_id":1},"committed":true},"prev_log_id":null,"leader_commit":null,"entries":entries}}),
    )?;
    let too_large = network
        .send(
            "tenant-a",
            1,
            2,
            &BasicNode::new("https://untrusted.invalid"),
            oversized,
        )
        .await
        .unwrap_err();
    assert_eq!(
        too_large
            .downcast_ref::<kasumi_raft::RpcPayloadTooLarge>()
            .unwrap()
            .max_entries,
        2
    );
    network.unregister_group("tenant-a")?;
    group.shutdown().await?;
    node.shutdown().await?;
    stop.send(true)?;
    server.await??;
    Ok(())
}
