//! Typed benchmark opening in the existing initial MemoryCore startup census.
//!
//! The recipe covers this producer's fixed controls and acquisition arrays.
//! It does not certify DTO construction, raw task/future backing, nested
//! key/provider and router producers, or escaping output aliases. The census
//! stays retained even after a successful output transfer.
use super::benchmark_retirement::{
    Alias, Audit, ClosePhase, Disposal, Node, Replica, Resources, ResourcesOwner, ResourcesState,
};
use super::*;
use kasumi_engine::{
    SnapshotFailure,
    admission::startup::{PrepaidStartup, StartupBacking, StartupTerminal, StartupTerminalLoan},
};

pub(super) type BenchmarkResult<T> = std::result::Result<T, BenchmarkFailure>;
pub(super) type BenchmarkStartup = PrepaidStartup<BenchmarkTerminal>;

/// No StdError implementation: a live terminal cannot enter Anyhow's blanket
/// owning conversion. Its originals stay in the exact installed census cell.
pub(super) enum BenchmarkFailure {
    Operation(anyhow::Error),
    Domain(kasumi_types::Error),
    Startup(BenchmarkStartup),
    Close(ResourcesOwner),
}
impl From<anyhow::Error> for BenchmarkFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
impl From<kasumi_types::Error> for BenchmarkFailure {
    fn from(original: kasumi_types::Error) -> Self {
        Self::Domain(original)
    }
}
impl From<std::io::Error> for BenchmarkFailure {
    fn from(original: std::io::Error) -> Self {
        Self::Operation(original.into())
    }
}
impl From<serde_json::Error> for BenchmarkFailure {
    fn from(original: serde_json::Error) -> Self {
        Self::Operation(original.into())
    }
}
impl From<std::time::SystemTimeError> for BenchmarkFailure {
    fn from(original: std::time::SystemTimeError) -> Self {
        Self::Operation(original.into())
    }
}
impl std::fmt::Display for BenchmarkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(original) => std::fmt::Display::fmt(original, f),
            Self::Domain(original) => std::fmt::Display::fmt(original, f),
            Self::Close(owner) => owner.with_report(|value| {
                write!(f, "benchmark close retained")?;
                if let Some(value) = value {
                    value.fmt_report(f)?;
                }
                Ok(())
            }),
            Self::Startup(owner) => {
                let id = owner.id();
                write!(
                    f,
                    "benchmark startup retained at {}:{}",
                    id.slot(),
                    id.generation()
                )?;
                owner.with_report(|value| {
                    if let Some(original) = value.and_then(|v| v.original.as_ref()) {
                        write!(f, ": {original}")?;
                    }
                    Ok(())
                })
            }
        }
    }
}
impl std::fmt::Debug for BenchmarkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "The initial admitted terminal owns whole native opening and snapshot failures inline, without an error-path allocation."
)]
enum BenchmarkOriginal {
    NodeStart(kasumi_store::NodeStoreStartFailure),
    Snapshot(SnapshotFailure),
    Operation(anyhow::Error),
}
impl From<kasumi_store::NodeStoreStartFailure> for BenchmarkOriginal {
    fn from(original: kasumi_store::NodeStoreStartFailure) -> Self {
        Self::NodeStart(original)
    }
}
impl From<SnapshotFailure> for BenchmarkOriginal {
    fn from(original: SnapshotFailure) -> Self {
        Self::Snapshot(original)
    }
}
impl From<anyhow::Error> for BenchmarkOriginal {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
impl std::fmt::Display for BenchmarkOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeStart(original) => std::fmt::Display::fmt(original, f),
            Self::Snapshot(original) => std::fmt::Display::fmt(original, f),
            Self::Operation(original) => std::fmt::Display::fmt(original, f),
        }
    }
}

pub(super) struct BenchmarkPlan<'a> {
    physical: &'a BenchmarkStorage,
    tenants: usize,
    replicas: usize,
    documents: usize,
    operations: usize,
    replicated: bool,
    bootstraps: Option<Vec<ReplicatedBootstrap>>,
    create: bool,
}
struct Arguments {
    storage: kasumi_engine::test_utils::FixtureStorage,
    admissions: Vec<Arc<kasumi_engine::admission::NodeAdmission>>,
    paths: Vec<PathBuf>,
    documents: usize,
    operations: usize,
    replicated: bool,
    bootstraps: Option<Vec<ReplicatedBootstrap>>,
    create: bool,
}
pub(super) struct BenchmarkTerminal {
    original: Option<BenchmarkOriginal>,
    output: Option<Databases>,
    pub(super) resources: ResourcesOwner,
    arguments: Arguments,
    entered: bool,
    succeeded: bool,
}

/// Filename capacity is derived from usize's representation, not a policy cap.
struct ReplicaName {
    bytes: [u8; 8 + usize::BITS as usize + 3],
    length: usize,
}
impl std::fmt::Write for ReplicaName {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or(std::fmt::Error)?;
        let destination = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(std::fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}
impl ReplicaName {
    fn new(replica: usize) -> Self {
        use std::fmt::Write;
        let mut name = Self {
            bytes: [0; 8 + usize::BITS as usize + 3],
            length: 0,
        };
        write!(name, "replica-{replica}.kv").expect("representation-sized replica filename");
        name
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.length]).expect("ASCII replica filename")
    }
}
fn path_capacity(root: &Path, replica: usize) -> anyhow::Result<usize> {
    root.as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(ReplicaName::new(replica).length))
        .context("replica path capacity overflow")
}

impl StartupTerminal for BenchmarkTerminal {
    type Plan<'a> = BenchmarkPlan<'a>;
    type Output = Databases;

    fn backing(plan: &BenchmarkPlan<'_>) -> anyhow::Result<StartupBacking> {
        let groups = plan
            .tenants
            .checked_mul(plan.replicas)
            .context("benchmark group count overflow")?;
        let stores = groups
            .checked_add(plan.replicas)
            .context("benchmark catalog count overflow")?;
        let mut recipe = StartupBacking::empty()
            .shared::<ResourcesState>()?
            .array::<Node>(plan.replicas)?
            .array::<Audit>(plan.replicas)?
            .array::<Tenant>(plan.tenants)?
            .array::<Alias<Arc<TenantStore>>>(stores)?
            .array::<Alias<Arc<kasumi_store::TenantStorageSet>>>(groups)?
            .array::<Arc<LocalKeyProvider>>(plan.replicas)?
            .array::<Arc<kasumi_engine::admission::NodeAdmission>>(plan.replicas)?
            .array::<PathBuf>(plan.replicas)?
            .shared::<LocalKeyProvider>()?
            .shared::<LocalKeyProvider>()?
            .shared::<InProcessRouter>()?;
        for replica in 0..plan.replicas {
            recipe = recipe
                .shared::<LocalKeyProvider>()?
                .array::<u8>(path_capacity(&plan.physical.root, replica)?)?;
        }
        for _ in 0..plan.tenants {
            recipe = recipe.array::<Replica>(plan.replicas)?;
        }
        Ok(recipe)
    }
    fn allocate(plan: BenchmarkPlan<'_>, charge: SharedBudgetCharge) -> Self {
        // The checked recipe ran before this infallible inert allocation phase.
        let groups = plan.tenants * plan.replicas;
        let mut paths = Vec::with_capacity(plan.replicas);
        let mut security_providers = Vec::with_capacity(plan.replicas);
        for replica in 0..plan.replicas {
            let capacity = path_capacity(&plan.physical.root, replica)
                .expect("same checked replica path recipe");
            let mut path = PathBuf::with_capacity(capacity);
            path.push(&plan.physical.root);
            path.push(ReplicaName::new(replica).as_str());
            paths.push(path);
            security_providers.push(Arc::new(LocalKeyProvider::new([0xA7; 32])));
        }
        let mut tenants = Vec::with_capacity(plan.tenants);
        for _ in 0..plan.tenants {
            tenants.push(Tenant {
                replicas: Vec::with_capacity(plan.replicas),
                bootstrap: None,
            });
        }
        let mut admissions = Vec::with_capacity(plan.replicas);
        admissions.extend(plan.physical.admissions.iter().cloned());
        let resources = ResourcesOwner::new(
            Resources {
                tenants,
                nodes: Vec::with_capacity(plan.replicas),
                router: Arc::new(InProcessRouter::default()),
                provider: Arc::new(LocalKeyProvider::new([0x42; 32])),
                audits: Vec::with_capacity(plan.replicas),
                stores: Vec::with_capacity(groups + plan.replicas),
                domains: Vec::with_capacity(groups),
                security_providers,
                custody_provider: Arc::new(LocalKeyProvider::new([241; 32])),
                close_phase: ClosePhase::NotEntered,
                bootstrap_capture: Disposal::NotEntered,
                close_bootstraps: None,
            },
            charge,
        );
        Self {
            original: None,
            output: Some(Databases {
                resources: resources.clone(),
                tenant_count: plan.tenants,
                audit_count: plan.replicas,
                _startup: None,
            }),
            resources,
            arguments: Arguments {
                storage: kasumi_engine::test_utils::FixtureStorage {
                    admission: plan.physical.storage.admission.clone(),
                    persistent: plan.physical.storage.persistent.clone(),
                    scratch: plan.physical.storage.scratch.clone(),
                },
                admissions,
                paths,
                documents: plan.documents,
                operations: plan.operations,
                replicated: plan.replicated,
                bootstraps: plan.bootstraps,
                create: plan.create,
            },
            entered: false,
            succeeded: false,
        }
    }
    fn begin(&mut self) -> bool {
        if self.entered {
            return false;
        }
        self.entered = true;
        true
    }
    fn retirement_ready(&self) -> bool {
        // Escaping router/Database aliases and DTO/future producers do not yet
        // have an explicit closed disposal witness. Never infer it from Drop.
        false
    }
    fn claim_output(&mut self) -> Option<Databases> {
        if self.succeeded && self.original.is_none() {
            self.output.take()
        } else {
            None
        }
    }
}

impl BenchmarkTerminal {
    #[allow(
        clippy::result_large_err,
        reason = "The preowned terminal stages original native and snapshot custody inline before any foreign result or cleanup."
    )]
    async fn acquire(&mut self) -> std::result::Result<(), BenchmarkOriginal> {
        let arguments = &self.arguments;
        let mut opened = self.resources.lock().await;
        for path in &arguments.paths {
            let node = if arguments.create {
                arguments
                    .storage
                    .create_new(path, kasumi_store::test_utils::NODE_STORE_ID)
            } else {
                arguments
                    .storage
                    .open_existing(path, kasumi_store::test_utils::NODE_STORE_ID)
            }?;
            opened.nodes.push(Node::new(node));
        }
        for replica in 0..opened.nodes.len() {
            let node = opened.nodes[replica].get().clone();
            let store = TenantStore::initialize_catalog_fixture(
                node,
                SECURITY_TENANT.into(),
                opened.security_providers[replica].clone(),
            )
            .await?;
            opened.stores.push(Alias::new(store));
            let store = opened
                .stores
                .last()
                .expect("same staged security store")
                .get()
                .clone();
            let audit = (if arguments.create {
                SecurityAudit::initialize
            } else {
                SecurityAudit::open
            })(
                store,
                AuditRetentionBudget::default(),
                arguments.admissions[replica].clone(),
            )?;
            opened.audits.push(Audit::new(audit));
        }
        let tenants = opened.tenants.len();
        for tenant in 0..tenants {
            let count =
                arguments.documents / tenants + usize::from(tenant < arguments.documents % tenants);
            let workload_limits = limits(count, arguments.operations)?;
            if arguments.replicated {
                opened.tenants[tenant].bootstrap = Some(
                    arguments
                        .bootstraps
                        .as_ref()
                        .map(|values| values[tenant].clone())
                        .unwrap_or_else(|| ReplicatedBootstrap {
                            genesis: kasumi_engine::ReplicatedGenesis::Application,
                            incarnation: uuid::Uuid::new_v4().to_string(),
                            initial_policy: policy(),
                            initial_limits: workload_limits.clone(),
                            voters: (1..=3)
                                .map(|id| {
                                    (
                                        id,
                                        ReplicaPlacement {
                                            address: format!("in-process-{id}"),
                                            failure_domain: format!(
                                                "logical-benchmark-replica-{id}"
                                            ),
                                        },
                                    )
                                })
                                .collect(),
                        }),
                );
            }
            for replica in 0..opened.nodes.len() {
                let node = opened.nodes[replica].get().clone();
                let store = TenantStore::initialize_catalog_fixture(
                    node,
                    context(tenant).tenant,
                    opened.provider.clone(),
                )
                .await?;
                opened.stores.push(Alias::new(store));
                let domains = kasumi_store::test_utils::initialize_custody_fixture(
                    opened
                        .stores
                        .last()
                        .expect("same staged application store")
                        .get()
                        .clone(),
                    opened.custody_provider.clone(),
                )
                .await?;
                opened.domains.push(Alias::new(domains));
                let domains = opened
                    .domains
                    .last()
                    .expect("same staged storage domains")
                    .get()
                    .clone();
                let database = if let Some(bootstrap) = &opened.tenants[tenant].bootstrap {
                    open_replicated(
                        replica as u64 + 1,
                        domains,
                        bootstrap,
                        opened.router.clone(),
                        server_config(),
                        opened.audits[replica].audit.get().clone(),
                    )
                    .await?
                } else {
                    open_local(
                        domains,
                        policy(),
                        workload_limits.clone(),
                        opened.audits[replica].audit.get().clone(),
                    )
                    .await?
                };
                opened.tenants[tenant].replicas.push(Replica::new(database));
                if let Some(bootstrap) = &opened.tenants[tenant].bootstrap {
                    let database = opened.tenants[tenant]
                        .replicas
                        .last()
                        .expect("same staged Database")
                        .database
                        .get();
                    opened.router.register(
                        format!("{}/{}", context(tenant).tenant, bootstrap.incarnation),
                        replica as u64 + 1,
                        database.raft_group().raft().clone(),
                    );
                }
            }
            if let Some(bootstrap) = &opened.tenants[tenant].bootstrap {
                initialize_replicated(opened.tenants[tenant].replicas[0].database.get(), bootstrap)
                    .await?;
            }
            if (tenant + 1) % 100 == 0 {
                eprintln!("opened {}/{} tenant groups", tenant + 1, tenants);
            }
        }
        for tenant in 0..tenants {
            let readiness = Instant::now();
            loop {
                let database = opened.leader(tenant).await?;
                if database.raft_group().linearizable_barrier().await.is_ok() {
                    break;
                }
                if readiness.elapsed() >= Duration::from_secs(30) {
                    return Err(anyhow::anyhow!(
                        "tenant {tenant} did not establish a serving quorum during setup"
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok(())
    }
}

async fn produce(mut loan: StartupTerminalLoan<BenchmarkTerminal>, (): ()) {
    match loan.acquire().await {
        Ok(()) => loan.succeeded = true,
        Err(original) => loan.original = Some(original),
    }
}

pub(super) async fn open(
    physical: &BenchmarkStorage,
    tenants: usize,
    documents: usize,
    operations: usize,
    replicated: bool,
    bootstraps: Option<Vec<ReplicatedBootstrap>>,
    create: bool,
) -> BenchmarkResult<Databases> {
    let replicas = if replicated { 3 } else { 1 };
    // All ordinary input validation precedes the initial typed grant/effects.
    (|| -> anyhow::Result<()> {
        ensure!(tenants != 0, "benchmark tenant count must be nonzero");
        ensure!(
            physical.admissions.len() == replicas,
            "benchmark physical replica count changed"
        );
        if let Some(values) = &bootstraps {
            ensure!(
                values.len() == tenants,
                "benchmark bootstrap topology changed"
            );
        }
        Ok(())
    })()?;
    let prepared = physical.admissions[0]
        .memory()
        .prepare_prepaid_startup::<BenchmarkTerminal>()?;
    let owner = prepared.install(BenchmarkPlan {
        physical,
        tenants,
        replicas,
        documents,
        operations,
        replicated,
        bootstraps,
        create,
    })?;
    let loan = owner.begin()?;
    let owner = loan.spawn(produce, ());
    owner.join_worker().await;
    if let Some(mut output) = owner.take_output().await {
        output._startup = Some(owner);
        Ok(output)
    } else {
        Err(BenchmarkFailure::Startup(owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn plan(physical: &BenchmarkStorage) -> BenchmarkPlan<'_> {
        BenchmarkPlan {
            physical,
            tenants: 1,
            replicas: 1,
            documents: 1,
            operations: 4,
            replicated: false,
            bootstraps: None,
            create: true,
        }
    }
    fn install(physical: &BenchmarkStorage) -> BenchmarkStartup {
        physical.admissions[0]
            .memory()
            .prepare_prepaid_startup::<BenchmarkTerminal>()
            .unwrap()
            .install(plan(physical))
            .unwrap()
    }
    fn original_address(owner: &BenchmarkStartup) -> usize {
        owner.with_report(|value| match value.and_then(|v| v.original.as_ref()) {
            Some(BenchmarkOriginal::NodeStart(original)) => original as *const _ as usize,
            _ => panic!("expected the same whole node opening original"),
        })
    }

    #[tokio::test]
    async fn benchmark_inert_terminal_uses_one_exact_initial_credit_before_native_effects() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        let before = physical.admissions[0].snapshot();
        let required = BenchmarkStartup::required_bytes(&plan(&physical)).unwrap();
        let owner = install(&physical);
        let after = physical.admissions[0].snapshot();
        assert_eq!(after.reserved_bytes - before.reserved_bytes, required);
        assert_eq!(after.live_reservations, before.live_reservations + 1);
        owner.with_report(|value| {
            let value = value.unwrap();
            assert!(!value.entered);
            assert!(value.original.is_none());
            assert!(
                value
                    .resources
                    .with_report(|resources| resources.unwrap().nodes.is_empty())
            );
            assert!(value.arguments.paths.iter().all(|path| !path.exists()));
        });
        let id = owner.id();
        drop(owner);
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<BenchmarkTerminal>(id)
            .unwrap();
        assert_eq!(
            physical.admissions[0].snapshot().reserved_bytes,
            after.reserved_bytes
        );
        assert!(!recovered.retire_empty().await);
    }

    #[tokio::test]
    async fn benchmark_native_opening_failure_keeps_exact_original_after_facade_drop() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        let existing = physical
            .storage
            .create_new(
                physical.root.join("replica-0.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        existing.shutdown().await.unwrap();
        let failure = match open(&physical, 1, 1, 4, false, None, true).await {
            Err(BenchmarkFailure::Startup(owner)) => owner,
            Err(other) => panic!("the real duplicate opening must remain typed: {other:?}"),
            Ok(_) => panic!("duplicate native creation unexpectedly succeeded"),
        };
        let id = failure.id();
        let original = original_address(&failure);
        let opening = failure.with_report(|value| {
            let value = value.unwrap();
            assert_eq!(
                value
                    .resources
                    .with_report(|resources| resources.unwrap().nodes.len()),
                0
            );
            match value.original.as_ref().unwrap() {
                BenchmarkOriginal::NodeStart(kasumi_store::NodeStoreStartFailure::Opening(
                    original,
                )) => original.opening_id(),
                _ => panic!("actual duplicate opening must preserve its registered opening"),
            }
        });
        let charged = physical.admissions[0].snapshot().reserved_bytes;
        assert!(!failure.retire_empty().await);
        assert!(failure.begin().is_err());
        drop(failure);
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<BenchmarkTerminal>(id)
            .unwrap();
        assert_eq!(original_address(&recovered), original);
        recovered.with_report(|value| match value.unwrap().original.as_ref().unwrap() {
            BenchmarkOriginal::NodeStart(kasumi_store::NodeStoreStartFailure::Opening(
                original,
            )) => assert_eq!(original.opening_id(), opening),
            _ => panic!("same original node opening variant"),
        });
        assert_eq!(physical.admissions[0].snapshot().reserved_bytes, charged);
        assert!(!recovered.retire_empty().await);
    }

    async fn returned_snapshot(
        mut loan: StartupTerminalLoan<BenchmarkTerminal>,
        original: SnapshotFailure,
    ) {
        loan.original = Some(BenchmarkOriginal::Snapshot(original));
    }

    #[tokio::test]
    async fn benchmark_whole_snapshot_source_keeps_original_allocation_in_exact_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        // This is an original externally produced source, not a claim that the
        // terminal's shell quote pays arbitrary diagnostic producer backing.
        let original = anyhow::Error::new(std::io::Error::other("exact benchmark source"));
        let address = original.as_ref() as *const dyn std::error::Error as *const () as usize;
        let owner = install(&physical);
        let id = owner.id();
        let owner = owner
            .begin()
            .unwrap()
            .spawn(returned_snapshot, SnapshotFailure::Source(original));
        owner.join_worker().await;
        assert!(owner.take_output().await.is_none());
        let charged = physical.admissions[0].snapshot().reserved_bytes;
        drop(owner);
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<BenchmarkTerminal>(id)
            .unwrap();
        recovered.with_report(|value| match value.unwrap().original.as_ref().unwrap() {
            BenchmarkOriginal::Snapshot(SnapshotFailure::Source(original)) => {
                assert_eq!(
                    original.as_ref() as *const dyn std::error::Error as *const () as usize,
                    address
                );
                assert_eq!(
                    original
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .to_string(),
                    "exact benchmark source"
                );
            }
            _ => panic!("whole Snapshot Source allocation must remain unchanged"),
        });
        assert_eq!(physical.admissions[0].snapshot().reserved_bytes, charged);
        assert!(!recovered.retire_empty().await);
    }

    static STAGED_NATIVE_NODES: AtomicUsize = AtomicUsize::new(0);
    async fn pending_after_actual_node(mut loan: StartupTerminalLoan<BenchmarkTerminal>, (): ()) {
        let original = loan.arguments.storage.create_new(
            &loan.arguments.paths[0],
            kasumi_store::test_utils::NODE_STORE_ID,
        );
        match original {
            Ok(node) => {
                loan.resources.lock().await.nodes.push(Node::new(node));
                STAGED_NATIVE_NODES.store(1, Ordering::Release);
            }
            Err(original) => {
                loan.original = Some(BenchmarkOriginal::NodeStart(original));
                STAGED_NATIVE_NODES.store(2, Ordering::Release);
                return;
            }
        }
        std::future::pending::<()>().await;
    }

    #[tokio::test]
    async fn benchmark_cancelled_wait_keeps_actual_native_worker_and_same_credit() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        STAGED_NATIVE_NODES.store(0, Ordering::Release);
        let owner = install(&physical);
        let id = owner.id();
        let owner = owner.begin().unwrap().spawn(pending_after_actual_node, ());
        tokio::time::timeout(Duration::from_secs(10), async {
            while STAGED_NATIVE_NODES.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(STAGED_NATIVE_NODES.load(Ordering::Acquire), 1);
        let charged = physical.admissions[0].snapshot().reserved_bytes;
        {
            let mut waiting = std::pin::pin!(owner.join_worker());
            assert!(matches!(
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(std::future::Future::poll(waiting.as_mut(), cx))
                })
                .await,
                std::task::Poll::Pending
            ));
        }
        drop(owner);
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<BenchmarkTerminal>(id)
            .unwrap();
        assert!(
            recovered
                .with_worker_report(|report| report.handle_retained())
                .unwrap()
        );
        assert!(recovered.with_report(|value| value.is_none()));
        assert_eq!(STAGED_NATIVE_NODES.load(Ordering::Acquire), 1);
        assert_eq!(physical.admissions[0].snapshot().reserved_bytes, charged);
    }
}
