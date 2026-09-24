//! Actual encrypted source retirement and cluster registration rejection. The
//! transport has TLS configuration, but this fixture sends consensus in-process.
use super::*;
use kasumi_engine::admission::NodeAdmission;
use kasumi_store::{CustodyStore, test_utils::LocalKeyProvider};
use std::{
    future::Future,
    sync::{Mutex, OnceLock, Weak},
    task::Poll,
};
use tokio::sync::Notify;

#[derive(Default)]
struct HeldCore {
    owner: Mutex<Weak<kasumi_engine::RetiredCustody>>,
    context: Mutex<Option<RequestContext>>,
    entered: Notify,
    release: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}
fn held() -> &'static Mutex<BTreeMap<Uuid, Arc<HeldCore>>> {
    static HELD: OnceLock<Mutex<BTreeMap<Uuid, Arc<HeldCore>>>> = OnceLock::new();
    HELD.get_or_init(Default::default)
}
struct ReleaseCore(Uuid, Arc<HeldCore>);
impl ReleaseCore {
    fn release(&self) {
        if let Some(release) = self.1.release.lock().unwrap().take() {
            let _ = release.send(());
        }
    }
}
impl Drop for ReleaseCore {
    fn drop(&mut self) {
        held().lock().unwrap().remove(&self.0);
        self.release();
    }
}
pub(super) async fn after_open(
    id: Uuid,
    custody: &Arc<kasumi_engine::RetiredCustody>,
) -> Result<()> {
    let selected = held().lock().unwrap().get(&id).cloned();
    let Some(selected) = selected else {
        return Ok(());
    };
    *selected.owner.lock().unwrap() = Arc::downgrade(custody);
    custody.response_fence(selected.context.lock().unwrap().as_ref().unwrap())?;
    let (release, released) = std::sync::mpsc::channel();
    *selected.release.lock().unwrap() = Some(release);
    let (entered, entry) = tokio::sync::oneshot::channel();
    custody
        .raft_group()
        .unwrap()
        .raft()
        .external_request(move |_| {
            // Block the actual core while allowing Tokio to hand this worker's
            // local queue to another executor thread. Otherwise the oneshot can
            // wake the opener into this blocked worker's non-stealable LIFO slot,
            // starving the test's own entry acknowledgement until its deadline.
            tokio::task::block_in_place(|| {
                let _ = entered.send(());
                // The guard releases on assertion failure as well as success.
                // The original core hold and observation deadlines are unchanged.
                released.recv_timeout(Duration::from_secs(20)).unwrap();
            });
        });
    tokio::time::timeout(Duration::from_secs(10), entry)
        .await
        .context("retired core entry acknowledgement timed out")??;
    selected.entered.notify_one();
    Ok(())
}

struct Fixture {
    _root: tempfile::TempDir,
    config: RuntimeConfig,
    network: Arc<ClusterNetwork>,
    node: Arc<NodeStore>,
    custody: Arc<CustodyStore>,
    audit: Arc<SecurityAudit>,
    admission: Arc<NodeAdmission>,
    resident: Arc<kasumi_engine::Database>,
    context: RequestContext,
    group: String,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let mut config = example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        config.database_id = Uuid::new_v4();
        config.database_path = root.path().join("replica-1/persistent/source.redb");
        let tenant = config.tenants[0].tenant.clone();
        let policy = config.tenants[0].initial_policy.clone();
        let incarnation = Uuid::new_v4().to_string();
        config.tenants[0].incarnation = Some(incarnation.clone());
        let bootstrap = ReplicatedBootstrap {
            genesis: kasumi_engine::ReplicatedGenesis::Application,
            incarnation: incarnation.clone(),
            initial_policy: policy.clone(),
            initial_limits: config.tenants[0].initial_limits.clone(),
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        kasumi_engine::ReplicaPlacement {
                            address: format!("https://node-{id}.example:9446"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        };
        let group = format!("{tenant}/{incarnation}");
        let transport = Arc::new(kasumi_raft::InProcessRouter::default());
        let mut replicas = Vec::new();
        for id in 1..=3 {
            let replica_root = root.path().join(format!("replica-{id}"));
            kasumi_store::private_files::create_directory(&replica_root)?;
            let physical =
                crate::runtime_storage_fixtures::physical(&replica_root, Default::default())?;
            let node = physical.create_new(
                replica_root.join("persistent/source.redb"),
                if id == 1 {
                    config.database_id
                } else {
                    Uuid::new_v4()
                },
            )?;
            let stores = TenantStorageSet::initialize_catalogs_fixture(
                node.clone(),
                tenant.clone(),
                Arc::new(LocalKeyProvider::new([31; 32])),
                Arc::new(LocalKeyProvider::new([32; 32])),
            )
            .await?;
            let audit_store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                SECURITY_TENANT.into(),
                Arc::new(LocalKeyProvider::new([33; 32])),
            )
            .await?;
            let admission = physical.admission.clone();
            let audit =
                SecurityAudit::initialize(audit_store, Default::default(), admission.clone())?;
            let database = kasumi_engine::test_utils::open_fixture_replicated(
                id,
                stores.clone(),
                &bootstrap,
                transport.clone(),
                kasumi_raft::Config::default(),
                audit.clone(),
            )
            .await?;
            transport.register(group.clone(), id, database.raft_group().raft().clone());
            replicas.push((node, stores, audit, admission, database));
        }
        replicas[0]
            .4
            .raft_group()
            .initialize(
                bootstrap
                    .voters
                    .iter()
                    .map(|(id, placement)| (*id, kasumi_raft::BasicNode::new(&placement.address)))
                    .collect(),
            )
            .await?;
        replicas[0]
            .4
            .raft_group()
            .raft()
            .wait(Some(Duration::from_secs(10)))
            .current_leader(1, "retirement fixture source leader")
            .await?;
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "acme-admin".into(),
            tenant,
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            request_id: "retired-source-startup".into(),
        };
        let destination = Arc::new(kasumi_store::FilesystemBackupDestination::new(
            root.path().join("replica-1/persistent/backup"),
            32 << 20,
            replicas[0].0.persistent_disk().clone(),
        )?);
        replicas[0]
            .4
            .install_archive_destination("approved".into(), destination.clone())?;
        let backup = replicas[0]
            .4
            .backup_checkpoint(context.clone(), destination.as_ref(), Uuid::new_v4())
            .await?;
        let retirement = kasumi_types::RetireSourceRequest {
            retirement_id: "registration-rejected".into(),
            expected_source_incarnation: incarnation,
            target_incarnation: Uuid::new_v4().to_string(),
            checkpoint: backup.checkpoint().clone(),
            destination: "approved".into(),
            not_after_ms: u64::MAX,
        };
        replicas[0]
            .4
            .retire_source(context.clone(), retirement)
            .await?;
        let custody = replicas[0].4.detach_retired_custody().await?;
        for (index, replica) in replicas.iter().enumerate() {
            transport.unregister(&group, index as u64 + 1);
            replica.4.shutdown().await?;
            if index > 0 {
                replica.2.shutdown().await?;
                replica.0.shutdown().await?;
            }
        }
        let (node, _stores, audit, admission, old) = replicas.remove(0);
        drop(old);
        drop(replicas);
        drop(transport);
        let resident_stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "resident".into(),
            Arc::new(LocalKeyProvider::new([34; 32])),
            Arc::new(LocalKeyProvider::new([35; 32])),
        )
        .await?;
        let resident = kasumi_engine::test_utils::open_fixture(
            resident_stores,
            policy,
            config.tenants[0].initial_limits.clone(),
            audit.clone(),
        )
        .await?;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let identity = kasumi_transport::TlsIdentity::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )?;
        let peers = config
            .replication
            .as_ref()
            .unwrap()
            .peers
            .iter()
            .map(|peer| crate::cluster::PeerConfig {
                node_id: peer.node_id,
                endpoint: peer.endpoint.clone(),
                certificate_pins: BTreeSet::from([if peer.node_id == 1 {
                    identity.certificate_pin()
                } else {
                    [peer.node_id as u8; 32]
                }]),
            })
            .collect();
        let network = ClusterNetwork::new(
            1,
            &identity,
            cert.pem().as_bytes(),
            peers,
            Default::default(),
        )?;
        // A distinct existing route occupies the name. Rejection must leave this
        // borrowed resident alive and registered; it is never a cleanup owner.
        network.register_group(
            group.clone(),
            resident.raft_group().raft().clone(),
            BTreeSet::from([1, 2, 3]),
        )?;
        Ok(Self {
            _root: root,
            config,
            network,
            node,
            custody,
            audit,
            admission,
            resident,
            context,
            group,
        })
    }
    async fn close(self) -> Result<()> {
        self.network.unregister_group(&self.group)?;
        self.resident.shutdown().await?;
        self.audit.shutdown().await?;
        self.node.drain_initializers().await?;
        Ok(())
    }
}

struct Opened(Arc<kasumi_engine::RetiredCustody>);
impl crate::startup_owner::Runtime for Opened {
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn Future<Output = kasumi_types::drain::DrainResult> + Send + '_>> {
        Box::pin(self.0.shutdown())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_registration_rejection_retains_new_owner_until_cancelled_waiter_drains()
-> Result<()> {
    let _serial = crate::standalone::ownership_tests::drain_serial()
        .lock()
        .await;
    let fixture = Fixture::new().await?;
    let observation = Arc::new(HeldCore::default());
    *observation.context.lock().unwrap() = Some(fixture.context.clone());
    held()
        .lock()
        .unwrap()
        .insert(fixture.config.database_id, observation.clone());
    let release = ReleaseCore(fixture.config.database_id, observation.clone());
    let config = fixture.config.clone();
    let network = fixture.network.clone();
    let store = fixture.custody.clone();
    let audit = fixture.audit.clone();
    let admission = fixture.admission.clone();
    let mut opening = Box::pin(crate::startup_owner::open(
        crate::startup_owner::Kind::Data,
        async move {
            open_retired_source(&config, store, Some(&network), audit, admission)
                .await
                .map(Opened)
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), observation.entered.notified())
        .await
        .context("retired startup fixture did not acknowledge core entry")?;
    // The actual duplicate registration has failed once cleanup closes request
    // admission. Its core remains blocked, so no error/RecoveringControl may return.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let custody = observation.owner.lock().unwrap().upgrade().unwrap();
            if custody.response_fence(&fixture.context).is_err() {
                break;
            }
            drop(custody);
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("rejected retired registration did not close request admission")?;
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(opening);
    let mut drain = Box::pin(NodeRuntime::drain_startups());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(observation.owner.lock().unwrap().upgrade().is_some());
    fixture.resident.raft_group().check_access()?;
    assert!(
        fixture
            .network
            .register_group(
                fixture.group.clone(),
                fixture.resident.raft_group().raft().clone(),
                BTreeSet::from([1, 2, 3])
            )
            .unwrap_err()
            .to_string()
            .contains("already registered")
    );
    release.release();
    let error = tokio::time::timeout(Duration::from_secs(10), NodeRuntime::drain_startups())
        .await
        .context("retired startup ownership did not drain after core release")?
        .unwrap_err();
    assert!(
        error.to_string().contains("group already registered"),
        "{error:#}"
    );
    assert!(observation.owner.lock().unwrap().upgrade().is_none());
    assert!(fixture.custody.store().check_access().is_err());
    fixture.resident.raft_group().check_access()?;
    fixture.audit.store().check_access()?;
    // Strictly reopen the existing encrypted custody after the failed owner's
    // cleanup completed, without reopening or closing the borrowed resident.
    let reopened = CustodyStore::open(
        fixture.node.clone(),
        fixture.context.tenant.clone(),
        Arc::new(LocalKeyProvider::new([32; 32])),
    )
    .await?;
    let recovered =
        kasumi_raft::ControlLog::installed(reopened.clone())?.context("retirement missing")?;
    assert!(recovered.is_retired()?);
    reopened.store().shutdown().await?;
    drop(recovered);
    drop(reopened);
    drop(release);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_preparation_panic_drains_only_new_custody_owner() -> Result<()> {
    let fixture = Fixture::new().await?;
    let fault =
        crate::startup_preparation::install(fixture.config.database_id, "retired-custody-owner");
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        open_retired_source(
            &fixture.config,
            fixture.custody.clone(),
            Some(&fixture.network),
            fixture.audit.clone(),
            fixture.admission.clone(),
        ),
    )
    .await?
    .err()
    .context("injected panic unexpectedly succeeded")?;
    assert!(
        error
            .downcast_ref::<crate::startup_preparation::PreparationPanic>()
            .is_some()
    );
    assert!(fixture.custody.store().check_access().is_err());
    fixture.resident.raft_group().check_access()?;
    fixture.audit.store().check_access()?;
    drop(fault);
    fixture.close().await
}
