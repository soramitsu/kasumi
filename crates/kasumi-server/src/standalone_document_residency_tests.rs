//! Real TLS/native SDK concurrency for the disk-resident document path. This is
//! Kasumi CRUD/query coverage, not a substitute for full wallet enrollment E2E.
use super::*;
use anyhow::ensure;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kasumi_client::{ClientDecodeLimits, ClientResources, JsonReadOptions, Kasumi};
use kasumi_engine::test_utils::SnapshotFixture;
use kasumi_types::{
    ChangeFeedPage, ChangeFeedStart, DocumentSlot, Filter, IndexDefinition, IndexField,
    QueryRequest, ReadChangeFeed, ScalarType, WriteReceipt,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const USERS: usize = 100;
const WRITE_DEADLINE: Duration = Duration::from_secs(20);
const READ_DEADLINE: Duration = Duration::from_secs(10);

type PanicOwner = Box<dyn std::any::Any + Send + 'static>;
type WorkOutcome<T> = std::result::Result<Result<T>, PanicOwner>;

enum WorkFailure {
    Operation(anyhow::Error),
    Panic(PanicOwner),
}
#[derive(Debug)]
enum DrainFailure {
    Join(tokio::task::JoinError),
    Operation(anyhow::Error),
}
struct WorkAndDrainFailure {
    work: WorkFailure,
    drain: DrainFailure,
}

// SnapshotFailure intentionally cannot be erased into anyhow. Catch the exact
// owning panic (and unexpected assertion panics) until runtime shutdown joins.
async fn preserve_work_outcome<T>(
    work: impl std::future::Future<Output = Result<T>>,
) -> WorkOutcome<T> {
    let mut work = std::pin::pin!(work);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work.as_mut().poll(cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(output)) => std::task::Poll::Ready(Ok(output)),
            Err(original) => std::task::Poll::Ready(Err(original)),
        }
    })
    .await
}

fn after_drain<T>(
    work: WorkOutcome<T>,
    drain: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<T> {
    let drain = match drain {
        Ok(Ok(())) => None,
        Ok(Err(original)) => Some(DrainFailure::Operation(original)),
        Err(original) => Some(DrainFailure::Join(original)),
    };
    match (work, drain) {
        (Ok(Ok(value)), None) => Ok(value),
        (Ok(Err(original)), None) => Err(original),
        (Err(original), None) => std::panic::resume_unwind(original),
        (work, Some(drain)) => {
            match &drain {
                DrainFailure::Join(error) => eprintln!("native runtime drain join failed: {error}"),
                DrainFailure::Operation(error) => {
                    eprintln!("native runtime drain failed: {error:#}")
                }
            }
            let work = match work {
                Ok(Ok(value)) => {
                    drop(value);
                    return match drain {
                        DrainFailure::Join(original) => Err(original.into()),
                        DrainFailure::Operation(original) => Err(original),
                    };
                }
                Ok(Err(original)) => {
                    eprintln!("native workload also failed: {original:#}");
                    WorkFailure::Operation(original)
                }
                Err(original) => WorkFailure::Panic(original),
            };
            // Both owners survive when cleanup itself also fails. The test
            // harness reports failure only after the actual drain completed.
            std::panic::panic_any(WorkAndDrainFailure { work, drain })
        }
    }
}

#[test]
fn document_residency_native_100_concurrent_workflows_meet_client_deadlines() -> Result<()> {
    ownership_tests::run_large_fixture("100 native document workflows", concurrent_workflows)
}

#[derive(Clone)]
struct Proofs {
    hex: Arc<String>,
    base64: Arc<String>,
}
impl Proofs {
    fn new() -> Self {
        let raw: Vec<u8> = (0..32_768).map(|index| (index * 73 % 251) as u8).collect();
        Self {
            hex: Arc::new(hex::encode(&raw)),
            base64: Arc::new(STANDARD.encode(&raw)),
        }
    }
    fn body(&self, user: usize) -> serde_json::Value {
        serde_json::json!({
            "owner": format!("user-{user:03}"),
            "proof": if user.is_multiple_of(2) { self.hex.as_str() } else { self.base64.as_str() },
            "encoding": if user.is_multiple_of(2) { "hex" } else { "base64" },
        })
    }
    fn batch(&self, user: usize) -> MutationBatch {
        MutationBatch {
            idempotency_key: format!("residency-{user:03}"),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "proofs".into(),
                id: format!("user-{user:03}"),
                body: self.body(user),
                expected: Precondition::Absent,
            }],
        }
    }
}

struct Preserved {
    receipts: BTreeMap<usize, WriteReceipt>,
    history: Vec<(MutationBatch, WriteReceipt)>,
    // Canonical full logical snapshot includes current rows, every retained feed
    // after-image/tombstone, receipts and original tenant/incarnation metadata.
    snapshot: (String, u64, String),
    feed_sha256: [u8; 32],
}

async fn connected(
    registry: &crate::api::DatabaseRegistry,
    profile: &std::path::Path,
) -> Result<Kasumi> {
    tokio::time::timeout(READ_DEADLINE, async {
        while registry.database(&context("residency")).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        loop {
            match Kasumi::from_profile(profile).await {
                Ok(client) => break client,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .context("native tenant/TLS readiness deadline")
}

fn logical_identity(registry: &crate::api::DatabaseRegistry) -> Result<(String, u64, String)> {
    let database = registry.database(&context("residency"))?;
    let generation = database.engine().generation()?;
    let documents = &generation.state.collections["proofs"].documents;
    ensure!(documents.len() == USERS, "committed document count differs");
    ensure!(
        documents
            .values()
            .all(|slot| matches!(slot.as_ref(), DocumentSlot::Stored(_))),
        "published generation retained decoded proof bodies"
    );
    let incarnation = generation.state.incarnation.clone();
    drop(generation);
    let snapshot = database
        .engine()
        .fixture_snapshot(database.stores().application().scratch_disk())
        .unwrap_or_else(|original| std::panic::panic_any(original));
    Ok((snapshot.sha256().to_owned(), snapshot.len(), incarnation))
}

async fn feed_identity(
    client: &Kasumi,
    profile: &ClientProfile,
    proofs: &Proofs,
    receipts: &BTreeMap<usize, WriteReceipt>,
    history: &[(MutationBatch, WriteReceipt)],
) -> Result<[u8; 32]> {
    let limits = ClientDecodeLimits::default();
    let resources = ClientResources::new(limits.accounted_bytes()?, 1)?;
    let bearer = profile.bearer()?;
    let mut source = client.client();
    let mut start = ChangeFeedStart::Beginning;
    let mut count = 0;
    let mut hash = Sha256::new();
    loop {
        let options = JsonReadOptions {
            limits,
            resources: resources.clone(),
            deadline: tokio::time::Instant::now() + READ_DEADLINE,
        };
        let page = source
            .read_change_feed(
                &bearer,
                &ReadChangeFeed {
                    collections: BTreeSet::from(["proofs".into()]),
                    start,
                    limit: 25,
                },
                &options,
            )
            .await?;
        let ChangeFeedPage::Events {
            events,
            next,
            caught_up,
            ..
        } = &*page
        else {
            anyhow::bail!("preserved change feed unexpectedly has a retention gap");
        };
        ensure!(
            !events.is_empty() || *caught_up,
            "change feed did not advance"
        );
        for event in events {
            if event.id == "history-sample" {
                let (batch, receipt) = history
                    .iter()
                    .find(|(_, receipt)| receipt.revision == event.revision)
                    .context("unrecognized retained history revision")?;
                match &batch.operations[0] {
                    Mutation::Put { body, .. } => {
                        let document = event
                            .document
                            .as_ref()
                            .context("history after-image disappeared")?;
                        ensure!(
                            document.body == *body && document.version == receipt.revision,
                            "history after-image differs"
                        );
                    }
                    Mutation::Delete { .. } => ensure!(
                        event.document.is_none(),
                        "history deletion became an after-image"
                    ),
                    _ => anyhow::bail!("unexpected history fixture mutation"),
                }
            } else {
                let user: usize = event
                    .id
                    .strip_prefix("user-")
                    .context("unexpected feed id")?
                    .parse()?;
                let receipt = receipts.get(&user).context("feed contains unknown user")?;
                let document = event
                    .document
                    .as_ref()
                    .context("original feed proof disappeared")?;
                ensure!(
                    document.body == proofs.body(user)
                        && document.version == receipt.revision
                        && event.revision == receipt.revision,
                    "original immutable proof changed in feed"
                );
            }
            // One event at a time; do not retain a second decoded full feed.
            let bytes = serde_json::to_vec(event)?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
            count += 1;
        }
        if *caught_up {
            break;
        }
        start = ChangeFeedStart::After {
            cursor: next.clone(),
        };
    }
    ensure!(count == USERS + history.len(), "feed event count changed");
    Ok(hash.finalize().into())
}

async fn seed(
    registry: &crate::api::DatabaseRegistry,
    profile_path: &std::path::Path,
    profile: &ClientProfile,
    proofs: &Proofs,
) -> Result<Preserved> {
    let client = connected(registry, profile_path).await?;
    let database = registry.database(&context("residency"))?;
    database
        .administer(
            context("residency"),
            Operation::CreateCollection(CollectionDefinition {
                name: "proofs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![IndexDefinition {
                    name: "owner".into(),
                    fields: vec![IndexField {
                        path: "/owner".into(),
                        kind: ScalarType::String,
                    }],
                    unique: true,
                    text: None,
                }],
                strict_read_audit: false,
            }),
        )
        .await?;
    drop(database);
    let start = Arc::new(tokio::sync::Barrier::new(USERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for user in 0..USERS {
        let writer = client.clone().with_timeout(WRITE_DEADLINE);
        let reader = client.clone().with_timeout(READ_DEADLINE);
        let proofs = proofs.clone();
        let start = start.clone();
        tasks.spawn(async move {
            start.wait().await;
            let result = async {
                let id = format!("user-{user:03}");
                let body = proofs.body(user);
                let batch = proofs.batch(user);
                let began = Instant::now();
                let receipt = writer.mutate(&batch).await.context("native mutation")?;
                let write = began.elapsed();
                ensure!(
                    write <= WRITE_DEADLINE,
                    "write exceeded shipped client deadline"
                );
                let began = Instant::now();
                let document = reader
                    .get("proofs", &id)
                    .await
                    .context("native point read")?
                    .context("committed document absent")?;
                let get = began.elapsed();
                ensure!(
                    get <= READ_DEADLINE,
                    "point read exceeded shipped client deadline"
                );
                ensure!(
                    document.id == id
                        && document.version == receipt.revision
                        && document.body == body,
                    "exact committed document changed"
                );
                drop(document);
                let query = QueryRequest::new("proofs")
                    .filter(Filter::new().eq("/owner", id.clone()))
                    .limit(1);
                let began = Instant::now();
                let page = reader.query(&query).await.context("native indexed query")?;
                let query = began.elapsed();
                ensure!(
                    query <= READ_DEADLINE,
                    "query exceeded shipped client deadline"
                );
                ensure!(
                    page.rows().len() == 1
                        && page.rows()[0].id == id
                        && page.rows()[0].body == body,
                    "indexed query changed the exact proof"
                );
                ensure!(!page.has_more(), "unique owner query produced an extra row");
                Ok::<_, anyhow::Error>((receipt, write, get, query))
            }
            .await;
            (user, result)
        });
    }
    start.wait().await;
    let mut receipts = BTreeMap::new();
    let mut failures = Vec::new();
    let mut maximum = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((user, Ok((receipt, write, get, query)))) => {
                receipts.insert(user, receipt);
                maximum = (
                    maximum.0.max(write),
                    maximum.1.max(get),
                    maximum.2.max(query),
                );
            }
            Ok((user, Err(error))) => failures.push(format!("user {user}: {error:#}")),
            Err(error) => failures.push(format!("joined workflow: {error}")),
        }
    }
    eprintln!(
        "native residency workload: completed={}/{USERS}, max_write_ms={}, max_get_ms={}, max_query_ms={}, failures={}",
        receipts.len(),
        maximum.0.as_millis(),
        maximum.1.as_millis(),
        maximum.2.as_millis(),
        failures.len()
    );
    for failure in &failures {
        eprintln!("native residency failure: {failure}");
    }
    ensure!(
        failures.is_empty(),
        "100 native workflows failed: {}",
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ")
    );
    ensure!(receipts.len() == USERS, "native workflow cohort incomplete");
    let writer = client.clone().with_timeout(WRITE_DEADLINE);
    let mut history = Vec::new();
    for version in 0..3 {
        let previous = history
            .last()
            .map(|(_, receipt): &(MutationBatch, WriteReceipt)| receipt.revision);
        let operation = if version == 2 {
            Mutation::Delete {
                collection: "proofs".into(),
                id: "history-sample".into(),
                expected: Precondition::Version(previous.unwrap()),
            }
        } else {
            Mutation::Put {
                collection: "proofs".into(),
                id: "history-sample".into(),
                body: serde_json::json!({"owner":"history-sample", "proof":proofs.hex.as_str(), "version":version}),
                expected: previous.map_or(Precondition::Absent, Precondition::Version),
            }
        };
        let batch = MutationBatch {
            idempotency_key: format!("history-{version}"),
            read_set: vec![],
            operations: vec![operation],
        };
        let receipt = writer.mutate(&batch).await?;
        history.push((batch, receipt));
    }
    let feed_sha256 = feed_identity(&client, profile, proofs, &receipts, &history).await?;
    let snapshot = logical_identity(registry)?;
    Ok(Preserved {
        receipts,
        history,
        snapshot,
        feed_sha256,
    })
}

async fn verify_reopened(
    registry: &crate::api::DatabaseRegistry,
    profile_path: &std::path::Path,
    profile: &ClientProfile,
    proofs: &Proofs,
    preserved: &Preserved,
) -> Result<()> {
    let client = connected(registry, profile_path).await?;
    ensure!(
        logical_identity(registry)? == preserved.snapshot,
        "cold physical reopen changed full logical snapshot or incarnation"
    );
    ensure!(
        feed_identity(
            &client,
            profile,
            proofs,
            &preserved.receipts,
            &preserved.history
        )
        .await?
            == preserved.feed_sha256,
        "cold physical reopen changed an immutable feed event"
    );
    let reader = client.clone().with_timeout(READ_DEADLINE);
    let writer = client.with_timeout(WRITE_DEADLINE);
    for user in 0..USERS {
        let id = format!("user-{user:03}");
        let receipt = &preserved.receipts[&user];
        let document = reader
            .get("proofs", &id)
            .await?
            .context("cold committed document absent")?;
        ensure!(
            document.id == id
                && document.version == receipt.revision
                && document.body == proofs.body(user),
            "cold original proof differs"
        );
        let query = QueryRequest::new("proofs")
            .filter(Filter::new().eq("/owner", id.clone()))
            .limit(1);
        let page = reader.query(&query).await?;
        ensure!(
            page.rows().len() == 1
                && page.rows()[0].id == id
                && page.rows()[0].body == proofs.body(user),
            "cold index result differs"
        );
        ensure!(
            writer.mutate(&proofs.batch(user)).await? == *receipt,
            "retry changed original committed outcome"
        );
    }
    for (batch, receipt) in &preserved.history {
        ensure!(
            writer.mutate(batch).await? == *receipt,
            "history retry changed original outcome"
        );
    }
    ensure!(
        reader.get("proofs", "history-sample").await?.is_none(),
        "replayed old mutation resurrected deleted row"
    );
    let page = reader
        .query(
            &QueryRequest::new("proofs")
                .filter(Filter::new().eq("/owner", "history-sample"))
                .limit(1),
        )
        .await?;
    ensure!(
        page.rows().is_empty(),
        "deleted row remained in unique index"
    );
    Ok(())
}

async fn concurrent_workflows() -> Result<()> {
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("kasumi"),
        "residency",
    )
    .await?;
    let mut config = RuntimeConfig::load(&installation.configuration)?;
    let mut control = ClientProfile::load(&installation.control_profile)?;
    let mut tenant = ClientProfile::load(&installation.tenant_profile)?;
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    let addresses = listeners
        .iter()
        .map(|listener| listener.local_addr())
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = addresses[0];
    config.native.listen = addresses[1];
    config.admin.listen = addresses[2];
    config.mcp.protocol =
        crate::mcp::McpConfig::new(format!("https://localhost:{}/mcp", addresses[0].port()))?;
    for profile in [&mut control, &mut tenant] {
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", addresses[1].port());
        profile.administrative_members.get_mut(&1).unwrap().endpoint =
            format!("https://localhost:{}", addresses[2].port());
    }
    private_files::replace(
        &installation.control_profile,
        &serde_json::to_vec_pretty(&control)?,
    )?;
    private_files::replace(
        &installation.tenant_profile,
        &serde_json::to_vec_pretty(&tenant)?,
    )?;
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    let runtime = NodeRuntime::open_using_storage(
        config.clone(),
        crate::runtime::file_secret,
        storage.clone(),
    )
    .await?;
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let proofs = Proofs::new();
    // Always drain the real runtime, even if the concurrent cohort fails.
    let seeded = preserve_work_outcome(seed(
        &registry,
        &installation.tenant_profile,
        &tenant,
        &proofs,
    ))
    .await;
    stop.send_replace(true);
    let drained = serving.await;
    drop(registry);
    let preserved = after_drain(seeded, drained)?;

    // Reopen the same encrypted files, configuration and native identity. No
    // initialization, snapshot import or reset occurs between the two daemons.
    let runtime =
        NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage).await?;
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let verified = preserve_work_outcome(verify_reopened(
        &registry,
        &installation.tenant_profile,
        &tenant,
        &proofs,
        &preserved,
    ))
    .await;
    stop.send_replace(true);
    let drained = serving.await;
    drop(registry);
    after_drain(verified, drained)
}

#[tokio::test]
async fn document_residency_work_panic_waits_for_drain_and_preserves_both_failures() {
    let original = Box::new(731u64);
    let address = std::ptr::from_ref(original.as_ref());
    let work = preserve_work_outcome(async move {
        std::panic::panic_any(original);
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let ended = std::sync::atomic::AtomicBool::new(false);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ended.store(true, std::sync::atomic::Ordering::Release);
        after_drain(work, Ok(Err(anyhow::anyhow!("drain original"))))
    }))
    .unwrap_err()
    .downcast::<WorkAndDrainFailure>()
    .unwrap();
    assert!(ended.load(std::sync::atomic::Ordering::Acquire));
    let WorkAndDrainFailure { work, drain } = *failure;
    let WorkFailure::Panic(original) = work else {
        panic!("panic owner changed")
    };
    let original = original.downcast::<Box<u64>>().unwrap();
    assert_eq!(std::ptr::from_ref(original.as_ref().as_ref()), address);
    assert!(
        matches!(drain, DrainFailure::Operation(ref error) if error.to_string() == "drain original")
    );
}

#[test]
fn document_residency_work_error_preserves_both_original_failures() {
    let work = anyhow::Error::new(std::io::Error::other("work original"));
    let drain = anyhow::Error::new(std::io::Error::other("drain original"));
    let work_address = std::ptr::from_ref(work.downcast_ref::<std::io::Error>().unwrap());
    let drain_address = std::ptr::from_ref(drain.downcast_ref::<std::io::Error>().unwrap());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        after_drain::<()>(Ok(Err(work)), Ok(Err(drain)))
    }))
    .unwrap_err()
    .downcast::<WorkAndDrainFailure>()
    .unwrap();
    let WorkAndDrainFailure {
        work: WorkFailure::Operation(work),
        drain: DrainFailure::Operation(drain),
    } = *failure
    else {
        panic!("original failure owners changed")
    };
    assert_eq!(
        std::ptr::from_ref(work.downcast_ref::<std::io::Error>().unwrap()),
        work_address
    );
    assert_eq!(
        std::ptr::from_ref(drain.downcast_ref::<std::io::Error>().unwrap()),
        drain_address
    );
}
