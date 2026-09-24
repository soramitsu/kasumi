//! Reproducible local benchmark. Test-only wrapping is explicit in every report;
//! it performs authenticated encryption but excludes network Transit latency.
use anyhow::{Context, Result, ensure};
use kasumi_bench::{Measurement, Samples};
use kasumi_engine::{
    Database, ReplicaPlacement, ReplicatedBootstrap, SECURITY_TENANT, SecurityAudit,
    initialize_replicated, open_local, open_replicated,
};
use kasumi_raft::{Config, InProcessRouter, server_config};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    hint::black_box,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize)]
struct Options {
    documents: usize,
    tenants: Vec<usize>,
    operations: usize,
    modes: Vec<String>,
    output: PathBuf,
    work_parent: Option<PathBuf>,
}
impl Options {
    fn parse() -> Result<Self> {
        let mut options = Self {
            documents: 1_000_000,
            tenants: vec![1, 100, 1000],
            operations: 10_000,
            modes: vec![
                "raw".into(),
                "local".into(),
                "replicated".into(),
                "text".into(),
            ],
            output: PathBuf::from("kasumi-benchmark.json"),
            work_parent: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--smoke" {
                options.documents = 100;
                options.tenants = vec![1, 3];
                options.operations = 32;
                continue;
            }
            if arg == "--help" {
                println!(
                    "kasumi-bench [--smoke] [--documents 1000000] [--tenants 1,100,1000] [--operations 10000] [--modes raw,local,replicated,text] [--output report.json] [--work-parent /directory]\nDefaults run every requested local mode. Network transport benchmarks require a separate authenticated endpoint runner; this harness never labels in-process calls as RPC/MCP."
                );
                std::process::exit(0);
            }
            let value = args.next().context("option requires a value")?;
            match arg.as_str() {
                "--documents" => options.documents = value.parse()?,
                "--tenants" => {
                    options.tenants = value
                        .split(',')
                        .map(str::parse)
                        .collect::<std::result::Result<_, _>>()?
                }
                "--operations" => options.operations = value.parse()?,
                "--modes" => options.modes = value.split(',').map(str::to_owned).collect(),
                "--output" => options.output = value.into(),
                "--work-parent" => options.work_parent = Some(value.into()),
                _ => anyhow::bail!("unknown option {arg}"),
            }
        }
        ensure!(
            options.documents > 0
                && options.documents <= 10_000_000
                && options.operations > 0
                && options.operations <= 1_000_000,
            "invalid document/operation count"
        );
        ensure!(
            !options.tenants.is_empty()
                && options
                    .tenants
                    .iter()
                    .all(|n| *n > 0 && *n <= options.documents && *n <= 1000),
            "tenant counts must be 1..min(documents,1000)"
        );
        ensure!(
            !options.modes.is_empty()
                && options
                    .modes
                    .iter()
                    .all(|mode| matches!(mode.as_str(), "raw" | "local" | "replicated" | "text")),
            "unknown benchmark mode"
        );
        Ok(options)
    }
}

#[derive(Serialize)]
struct Case {
    mode: String,
    tenants: usize,
    documents: usize,
    replicas: usize,
    security_audit_stores: usize,
    raft_timing_milliseconds: Option<Value>,
    payload_bytes: usize,
    open_seconds: f64,
    baseline_rss_bytes: Option<u64>,
    empty_rss_bytes: Option<u64>,
    collection_setup_seconds: Option<f64>,
    empty_index_rss_bytes: Option<u64>,
    load_seconds: f64,
    resident_rss_bytes: Option<u64>,
    after_workload_rss_bytes: Option<u64>,
    after_recovery_rss_bytes: Option<u64>,
    peak_rss_bytes: Option<u64>,
    disk_bytes: u64,
    shutdown_seconds: Option<f64>,
    recovery_seconds: Option<f64>,
    measurements: Vec<Measurement>,
    notes: Vec<String>,
}
#[derive(Serialize)]
struct Report {
    format: u32,
    created_unix_ms: u128,
    options: Options,
    os: String,
    architecture: String,
    build_profile: String,
    rustc: Option<String>,
    source_sha256: String,
    executable_sha256: String,
    git_status: Vec<String>,
    logical_cpus: Option<usize>,
    evidence_status: String,
    guarantees: Vec<String>,
    not_measured: Vec<String>,
    cases: Vec<Case>,
    progress: Vec<Value>,
    failures: Vec<String>,
}

fn body(ordinal: usize, version: usize, tenants: usize) -> Value {
    let local_ordinal = ordinal / tenants;
    let mut value = json!({"ordinal":ordinal,"version":version,"text":format!("searchable document token{:04} feature{:04} {} revision{version} ",local_ordinal%1000,local_ordinal%1000,if local_ordinal.is_multiple_of(1000) {"図書館"}else{"動物"}),"padding":""});
    let encoded = serde_json::to_vec(&value).unwrap().len();
    value["padding"] = Value::String("x".repeat(1024usize.saturating_sub(encoded)));
    value
}
fn context(tenant: usize) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "benchmark".into(),
        tenant: format!("bench-{tenant:04}"),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: uuid::Uuid::new_v4().to_string(),
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "benchmark".into(),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        }],
        strict_read_audit: false,
    }
}
fn limits(documents: usize, operations: usize) -> anyhow::Result<Limits> {
    let receipt_count = operations
        .checked_mul(3)
        .and_then(|n| n.checked_add(documents.div_ceil(256)))
        .and_then(|n| n.checked_add(128))
        .context("receipt workload count overflow")?;
    Ok(Limits {
        max_documents: documents as u64 + 1,
        max_logical_bytes: (documents as u64 + 1) * 2048,
        max_mutation_receipt_bytes: u64::try_from(receipt_count)
            .context("receipt workload exceeds address space")?
            .checked_mul(2 << 20)
            .context("receipt workload byte budget overflow")?,
        audit_retention: AuditRetentionBudget {
            hot_bytes: ((documents.div_ceil(256) + operations * 3 + 1024) as u64 * 1024)
                .max(AuditRetentionBudget::default().hot_bytes),
            ..AuditRetentionBudget::default()
        },
        ..Limits::default()
    })
}

fn definition(text: bool) -> CollectionDefinition {
    let mut indexes = vec![IndexDefinition {
        name: "ordinal".into(),
        fields: vec![IndexField {
            path: "/ordinal".into(),
            kind: ScalarType::Number,
        }],
        unique: false,
        text: None,
    }];
    if text {
        for (name, analyzer) in [
            ("english", Analyzer::EnglishV1),
            ("japanese", Analyzer::JapaneseV1),
        ] {
            indexes.push(IndexDefinition {
                name: name.into(),
                fields: vec![IndexField {
                    path: "/text".into(),
                    kind: ScalarType::String,
                }],
                unique: false,
                text: Some(TextIndex { analyzer }),
            });
        }
    }
    CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "docs".into(),
        schema: json!({"type":"object","required":["ordinal","version","text","padding"],"properties":{"ordinal":{"type":"integer"},"version":{"type":"integer"},"text":{"type":"string"},"padding":{"type":"string"}},"additionalProperties":false}),
        indexes,
        strict_read_audit: false,
    }
}
fn raw(options: &Options, tenants: usize) -> Result<Case> {
    let baseline_rss_bytes = rss();
    let opened = Instant::now();
    let mut maps: Vec<HashMap<String, Value>> = (0..tenants).map(|_| HashMap::new()).collect();
    let open_seconds = opened.elapsed().as_secs_f64();
    let empty_rss_bytes = rss();
    let started = Instant::now();
    let mut payload_bytes = 0;
    for ordinal in 0..options.documents {
        let value = body(ordinal, 0, tenants);
        payload_bytes += serde_json::to_vec(&value)?.len();
        maps[ordinal % tenants].insert(ordinal.to_string(), value);
    }
    let load_seconds = started.elapsed().as_secs_f64();
    let keys: Vec<_> = (0..options.operations)
        .map(|i| ((i.wrapping_mul(7919)) % options.documents).to_string())
        .collect();
    let mut samples = Samples::new("raw_hashmap_borrowed_lookup", keys.len());
    for (i, key) in keys.iter().enumerate() {
        let ordinal = (i.wrapping_mul(7919)) % options.documents;
        let start = Instant::now();
        black_box(
            maps[ordinal % tenants]
                .get(key)
                .context("raw document missing")?,
        );
        samples.record(start.elapsed(), Ok(()));
    }
    let measurement = samples.finish();
    Ok(Case { mode:"raw".into(),tenants,documents:options.documents,replicas:1,security_audit_stores:0,raft_timing_milliseconds:None,payload_bytes,open_seconds,baseline_rss_bytes,empty_rss_bytes,collection_setup_seconds:None,empty_index_rss_bytes:None,load_seconds,resident_rss_bytes:rss(),after_workload_rss_bytes:rss(),after_recovery_rss_bytes:None,peak_rss_bytes:peak_rss(),disk_bytes:0,shutdown_seconds:None,recovery_seconds:None,measurements:vec![measurement],notes:vec!["Borrowed map lookup only: no authentication, cloning, schema checks, consistency barrier, indexing, or durability. Timer overhead is included.".into()] })
}

struct Tenant {
    replicas: Vec<Arc<Database>>,
    bootstrap: Option<ReplicatedBootstrap>,
}
/// Retained for the entire benchmark case, including close/reopen. Replicas
/// share the original ONE scratch quota. Distinct runtime facades share the
/// aggregate of their original payload allowances; RSS ceilings are unchanged.
struct BenchmarkStorage {
    storage: kasumi_engine::test_utils::FixtureStorage,
    admissions: Vec<Arc<kasumi_engine::admission::NodeAdmission>>,
    root: PathBuf,
}
impl BenchmarkStorage {
    fn open(root: &Path, replicas: usize) -> Result<Self> {
        use kasumi_engine::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
        let data = root.join("persistent");
        kasumi_store::private_files::create_directory(&data)?;
        let persistent = kasumi_store::NodeDisk::fixture_config(data.join("node.kv"))?;
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: root.join("scratch"),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        };
        let original = AdmissionConfig::default();
        let payload = original
            .resolved_fixture_total_bytes()?
            .checked_sub(NodeAdmission::required_bookkeeping_bytes(&original)?)
            .context("original benchmark policy cannot fund its bookkeeping")?;
        let replicas_u64 = u64::try_from(replicas).context("replica count exceeds u64")?;
        let mut config = original.clone();
        config.max_inflight_operations = original
            .max_inflight_operations
            .checked_mul(replicas)
            .context("benchmark operation-slot count overflow")?;
        config.max_reservations = original
            .max_reservations
            .checked_mul(replicas)
            .context("benchmark reservation-slot count overflow")?;
        config.max_startup_scopes = original
            .max_startup_scopes
            .checked_mul(replicas)
            .context("benchmark startup-scope count overflow")?;
        let core = MemoryCore::required_bookkeeping_bytes(&config)?;
        let facade = NodeAdmission::required_bookkeeping_bytes(&config)?
            .checked_sub(core)
            .context("benchmark facade bookkeeping underflow")?;
        let metadata =
            kasumi_engine::test_utils::isolated_disk_metadata_bytes(&persistent, &scratch)?;
        config.max_inflight_bytes = Some(
            payload
                .checked_mul(replicas_u64)
                .and_then(|n| n.checked_add(core))
                .and_then(|n| {
                    facade
                        .checked_mul(replicas_u64)
                        .and_then(|f| n.checked_add(f))
                })
                .and_then(|n| n.checked_add(metadata))
                .context("benchmark aggregate admission capacity overflow")?,
        );
        config.validate()?;
        let first = NodeAdmission::new(config)?;
        let mut admissions = Vec::with_capacity(replicas);
        admissions.push(first.clone());
        for _ in 1..replicas {
            admissions.push(NodeAdmission::from_memory(first.memory().clone())?);
        }
        let storage = kasumi_engine::test_utils::FixtureStorage::with_admission(
            &persistent,
            &scratch,
            first,
        )?;
        Ok(Self {
            storage,
            admissions,
            root: data,
        })
    }
    fn path(&self, replica: usize) -> PathBuf {
        self.root.join(format!("replica-{replica}.kv"))
    }
}

struct Databases {
    tenants: Vec<Tenant>,
    nodes: Vec<Arc<NodeStore>>,
    router: Arc<InProcessRouter>,
    provider: Arc<LocalKeyProvider>,
    audits: Vec<Arc<SecurityAudit>>,
}
impl Databases {
    async fn open(
        physical: &BenchmarkStorage,
        tenants: usize,
        documents: usize,
        operations: usize,
        replicated: bool,
        bootstraps: Option<Vec<ReplicatedBootstrap>>,
        create: bool,
    ) -> Result<Self> {
        let replicas = if replicated { 3 } else { 1 };
        let mut nodes = Vec::new();
        ensure!(
            physical.admissions.len() == replicas,
            "benchmark physical replica count changed"
        );
        for replica in 0..replicas {
            nodes.push(
                (if create {
                    physical.storage.create_new(
                        physical.path(replica),
                        kasumi_store::test_utils::NODE_STORE_ID,
                    )
                } else {
                    physical.storage.open_existing(
                        physical.path(replica),
                        kasumi_store::test_utils::NODE_STORE_ID,
                    )
                })?,
            );
        }
        let mut audits = Vec::new();
        for (replica, node) in nodes.iter().enumerate() {
            let service_store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                SECURITY_TENANT.into(),
                Arc::new(LocalKeyProvider::new([0xA7; 32])),
            )
            .await?;
            audits.push((if create {
                SecurityAudit::initialize
            } else {
                SecurityAudit::open
            })(
                service_store,
                kasumi_types::AuditRetentionBudget::default(),
                physical.admissions[replica].clone(),
            )?);
        }
        let provider = Arc::new(LocalKeyProvider::new([0x42; 32]));
        let router = Arc::new(InProcessRouter::default());
        let mut result = Vec::new();
        for tenant in 0..tenants {
            let count = documents / tenants + usize::from(tenant < documents % tenants);
            let workload_limits = limits(count, operations)?;
            let bootstrap = if replicated {
                Some(
                    bootstraps
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
                )
            } else {
                None
            };
            let mut databases = Vec::new();
            for (replica, node) in nodes.iter().enumerate() {
                let store = TenantStore::initialize_catalog_fixture(
                    node.clone(),
                    context(tenant).tenant,
                    provider.clone(),
                )
                .await?;
                let database = if let Some(bootstrap) = &bootstrap {
                    let database = open_replicated(
                        replica as u64 + 1,
                        kasumi_store::test_utils::initialize_custody_fixture(
                            store,
                            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new(
                                [241; 32],
                            )),
                        )
                        .await
                        .unwrap(),
                        bootstrap,
                        router.clone(),
                        server_config(),
                        audits[replica].clone(),
                    )
                    .await?;
                    router.register(
                        format!("{}/{}", context(tenant).tenant, bootstrap.incarnation),
                        replica as u64 + 1,
                        database.raft_group().raft().clone(),
                    );
                    database
                } else {
                    open_local(
                        kasumi_store::test_utils::initialize_custody_fixture(
                            store,
                            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new(
                                [241; 32],
                            )),
                        )
                        .await
                        .unwrap(),
                        policy(),
                        workload_limits.clone(),
                        audits[replica].clone(),
                    )
                    .await?
                };
                databases.push(database);
            }
            if let Some(bootstrap) = &bootstrap {
                initialize_replicated(&databases[0], bootstrap).await?;
            }
            result.push(Tenant {
                replicas: databases,
                bootstrap,
            });
            if (tenant + 1) % 100 == 0 {
                eprintln!("opened {}/{} tenant groups", tenant + 1, tenants);
            }
        }
        let opened = Self {
            tenants: result,
            nodes,
            router,
            provider,
            audits,
        };
        for tenant in 0..tenants {
            let readiness = Instant::now();
            loop {
                let database = opened.leader(tenant).await?;
                if database.raft_group().linearizable_barrier().await.is_ok() {
                    break;
                }
                ensure!(
                    readiness.elapsed() < Duration::from_secs(30),
                    "tenant {tenant} did not establish a serving quorum during setup"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok(opened)
    }
    async fn leader(&self, tenant: usize) -> Result<Arc<Database>> {
        let start = Instant::now();
        loop {
            for database in &self.tenants[tenant].replicas {
                let metrics = database.raft_group().raft().metrics();
                let metrics = metrics.borrow();
                if metrics.current_leader == Some(metrics.id) {
                    return Ok(database.clone());
                }
            }
            ensure!(
                start.elapsed() < Duration::from_secs(10),
                "no serving leader for tenant {tenant}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn close(mut self) -> Result<Option<Vec<ReplicatedBootstrap>>> {
        let bootstraps = self
            .tenants
            .iter()
            .map(|tenant| tenant.bootstrap.clone())
            .collect::<Option<Vec<_>>>();
        for (tenant_index, tenant) in self.tenants.iter().enumerate() {
            for database in &tenant.replicas {
                database.shutdown().await?;
                if let Some(bootstrap) = &tenant.bootstrap {
                    self.router.unregister(
                        &format!("{}/{}", context(tenant_index).tenant, bootstrap.incarnation),
                        database.raft_group().raft().metrics().borrow().id,
                    );
                }
            }
        }
        self.tenants.clear();
        let mut report = kasumi_types::drain::DrainReport::default();
        for audit in &self.audits {
            if let Err(failure) = audit.shutdown().await {
                report.merge(&failure);
            }
        }
        self.audits.clear();
        for node in &self.nodes {
            if let Err(failure) = node.shutdown().await {
                report.merge(&failure);
            }
        }
        self.nodes.clear();
        drop(self.provider);
        drop(self.router);
        report.complete()?;
        Ok(bootstraps)
    }
}

fn raft_timing(replicated: bool) -> Value {
    let config = if replicated {
        server_config()
    } else {
        Config::default()
    };
    json!({
        "heartbeat_interval":config.heartbeat_interval,
        "election_timeout_min":config.election_timeout_min,
        "election_timeout_max":config.election_timeout_max,
        "install_snapshot_timeout":config.install_snapshot_timeout,
    })
}

async fn database_case(
    options: &Options,
    tenants: usize,
    mode: &str,
    report: &mut Report,
) -> Result<Case> {
    checkpoint(report, mode, tenants, "opening", json!({}), &[])?;
    let directory = if let Some(parent) = &options.work_parent {
        tempfile::Builder::new()
            .prefix("kasumi-bench-")
            .tempdir_in(parent)?
    } else {
        tempfile::Builder::new().prefix("kasumi-bench-").tempdir()?
    };
    let replicated = mode == "replicated";
    let text = mode == "text";
    let baseline_rss_bytes = rss();
    let opened = Instant::now();
    let physical = BenchmarkStorage::open(directory.path(), if replicated { 3 } else { 1 })?;
    let databases = Databases::open(
        &physical,
        tenants,
        options.documents,
        options.operations,
        replicated,
        None,
        true,
    )
    .await?;
    let open_seconds = opened.elapsed().as_secs_f64();
    let empty_rss_bytes = rss();
    checkpoint(
        report,
        mode,
        tenants,
        "collection_setup",
        json!({"open_seconds":open_seconds,"empty_rss_bytes":empty_rss_bytes,"security_audit_stores":databases.audits.len()}),
        &[],
    )?;
    let collection_setup = Instant::now();
    for tenant in 0..tenants {
        let database = databases.leader(tenant).await?;
        database
            .administer(
                context(tenant),
                Operation::CreateCollection(definition(text)),
            )
            .await?;
    }
    let collection_setup_seconds = Some(collection_setup.elapsed().as_secs_f64());
    let empty_index_rss_bytes = rss();
    checkpoint(
        report,
        mode,
        tenants,
        "loading",
        json!({"loaded_batches":0,"payload_bytes":0}),
        &[],
    )?;
    let started = Instant::now();
    let mut payload_bytes = 0;
    let mut load_batches = 0;
    for tenant in 0..tenants {
        let database = databases.leader(tenant).await?;
        let mut operations = Vec::with_capacity(256);
        for ordinal in (tenant..options.documents).step_by(tenants) {
            let value = body(ordinal, 0, tenants);
            payload_bytes += serde_json::to_vec(&value)?.len();
            operations.push(Mutation::Put {
                collection: "docs".into(),
                id: ordinal.to_string(),
                body: value,
                expected: Precondition::Absent,
            });
            if operations.len() == 256 {
                database
                    .mutate(
                        context(tenant),
                        MutationBatch {
                            read_set: Vec::new(),
                            idempotency_key: format!("load-{load_batches}"),
                            operations: std::mem::take(&mut operations),
                        },
                    )
                    .await?;
                load_batches += 1;
                if load_batches % 100 == 0 {
                    checkpoint(
                        report,
                        mode,
                        tenants,
                        "loading",
                        json!({"loaded_batches":load_batches,"payload_bytes":payload_bytes,"elapsed_seconds":started.elapsed().as_secs_f64()}),
                        &[],
                    )?;
                    eprintln!(
                        "loaded {} batches ({mode}, tenant {})",
                        load_batches,
                        tenant + 1
                    );
                }
            }
        }
        if !operations.is_empty() {
            database
                .mutate(
                    context(tenant),
                    MutationBatch {
                        read_set: Vec::new(),
                        idempotency_key: format!("load-{load_batches}"),
                        operations,
                    },
                )
                .await?;
            load_batches += 1;
        }
        if (tenant + 1) % 100 == 0 || tenants == 1 {
            eprintln!("loaded tenant {}/{} ({mode})", tenant + 1, tenants);
        }
    }
    let load_seconds = started.elapsed().as_secs_f64();
    let resident_rss_bytes = rss();
    let mut measurements = Vec::new();
    let mut details = json!({"security_audit_stores":databases.audits.len(),"mode":mode,"tenants":tenants,"documents":options.documents,"payload_bytes":payload_bytes,"open_seconds":open_seconds,"load_seconds":load_seconds,"baseline_rss_bytes":baseline_rss_bytes,"resident_rss_bytes":resident_rss_bytes,"empty_rss_bytes":empty_rss_bytes,"collection_setup_seconds":collection_setup_seconds,"empty_index_rss_bytes":empty_index_rss_bytes});
    for (name, percent, phase) in [
        ("embedded_authorized_owned_point_get", 0, 0),
        ("embedded_authorized_shared_point_get", 0, 0),
        ("durable_single_document_write", 100, 1),
        ("read_heavy_90_read_10_write", 10, 2),
        ("balanced_50_read_50_write", 50, 3),
    ] {
        checkpoint(report, mode, tenants, name, details.clone(), &measurements)?;
        let measurement = workload(&databases, options, name, percent, phase).await;
        measurements.push(measurement);
        checkpoint(
            report,
            mode,
            tenants,
            "measured_workload",
            details.clone(),
            &measurements,
        )?;
    }
    measurements.push(queries(&databases, options, None).await);
    checkpoint(
        report,
        mode,
        tenants,
        "measured_query",
        details.clone(),
        &measurements,
    )?;
    if text {
        for (index, query, mode) in [
            ("english", "token0007 feature0007", TextMode::Phrase),
            ("english", "token000", TextMode::Prefix),
            ("english", "tokeq0007", TextMode::Fuzzy),
            ("japanese", "図書館", TextMode::Terms),
        ] {
            measurements.push(
                queries(
                    &databases,
                    options,
                    Some(TextSearch {
                        index: index.into(),
                        query: query.into(),
                        mode,
                        distance: 1,
                    }),
                )
                .await,
            );
            checkpoint(
                report,
                "text",
                tenants,
                "measured_text_query",
                details.clone(),
                &measurements,
            )?;
        }
    }
    let disk_bytes = directory_size(directory.path())?;
    let after_workload_rss_bytes = rss();
    let peak = peak_rss();
    details["disk_bytes"] = json!(disk_bytes);
    details["after_workload_rss_bytes"] = json!(after_workload_rss_bytes);
    details["peak_rss_bytes"] = json!(peak);
    checkpoint(
        report,
        mode,
        tenants,
        "shutting_down",
        details.clone(),
        &measurements,
    )?;
    let shutdown = Instant::now();
    let bootstraps = databases.close().await?;
    let shutdown_seconds = Some(shutdown.elapsed().as_secs_f64());
    details["shutdown_seconds"] = json!(shutdown_seconds);
    checkpoint(
        report,
        mode,
        tenants,
        "recovering",
        details.clone(),
        &measurements,
    )?;
    let recovered = Instant::now();
    let databases = Databases::open(
        &physical,
        tenants,
        options.documents,
        options.operations,
        replicated,
        bootstraps,
        false,
    )
    .await?;
    for tenant in 0..tenants {
        let database = databases.leader(tenant).await?;
        let result = database
            .get(&context(tenant), "docs", &tenant.to_string())
            .await
            .with_context(|| format!("recovery verification, tenant {tenant}"))?;
        ensure!(
            result.body["ordinal"] == json!(tenant),
            "recovery document mismatch"
        );
    }
    let recovery_seconds = Some(recovered.elapsed().as_secs_f64());
    let after_recovery_rss_bytes = rss();
    details["recovery_seconds"] = json!(recovery_seconds);
    details["after_recovery_rss_bytes"] = json!(after_recovery_rss_bytes);
    checkpoint(report, mode, tenants, "recovered", details, &measurements)?;
    databases.close().await?;
    Ok(Case {mode:mode.into(),tenants,documents:options.documents,replicas:if replicated{3}else{1},security_audit_stores:if replicated{3}else{1},raft_timing_milliseconds:Some(raft_timing(replicated)),payload_bytes,open_seconds,baseline_rss_bytes,empty_rss_bytes,collection_setup_seconds,empty_index_rss_bytes,load_seconds,resident_rss_bytes,after_workload_rss_bytes,after_recovery_rss_bytes,peak_rss_bytes:peak,disk_bytes,shutdown_seconds,recovery_seconds,measurements,
        notes:vec!["Actual Database API: tenant RBAC, read barrier, schema validation, persistent indexes, encrypted Kasumi KV durable commits, and mutation audit/receipt retention are active.".into(),"Each initial load batch has at most 256 documents; measured writes contain one document. Setup establishes a real quorum barrier before readiness. Measured operations are never retried; no additional warmup samples are discarded after loading.".into(),if replicated{"Three real OpenRaft voters use separate Kasumi KV files in one process; this measures local quorum persistence, not independent physical failure domains, TLS or network latency.".into()}else{"One real OpenRaft voter; no network protocol overhead.".into()},"Test-only authenticated key wrapping excludes Transit network latency. Each replica node has one independently encrypted service security-audit tenant with a distinct wrapping key shared across its customer groups; its opening/key/RSS/disk overhead is included. No successful-read strict audit; mutation and denial audits remain enabled.".into(),"Shutdown measures complete Database closure and release of fixture stores. Recovery starts after shutdown and measures reopen, index reconstruction, key access, readiness and one verified point read per tenant; final cleanup and crash safety are separate.".into()]})
}

async fn workload(
    databases: &Databases,
    options: &Options,
    name: &str,
    write_percent: usize,
    phase: usize,
) -> Measurement {
    let mut samples = Samples::new(name, options.operations);
    for operation in 0..options.operations {
        let ordinal = operation.wrapping_mul(7919) % options.documents;
        let tenant = ordinal % databases.tenants.len();
        let selection = Instant::now();
        let database = match databases.leader(tenant).await {
            Ok(database) => database,
            Err(error) => {
                samples.record(selection.elapsed(), Err(error));
                break;
            }
        };
        let context = context(tenant);
        let id = ordinal.to_string();
        let start = Instant::now();
        let result: Result<()> = async {
            if (operation + 1) * write_percent / 100 > operation * write_percent / 100 {
                database
                    .mutate(
                        context,
                        MutationBatch {
                            read_set: Vec::new(),
                            idempotency_key: format!("work-{phase}-{operation}"),
                            operations: vec![Mutation::Put {
                                collection: "docs".into(),
                                id,
                                body: body(
                                    ordinal,
                                    phase * options.operations + operation + 1,
                                    databases.tenants.len(),
                                ),
                                expected: Precondition::Any,
                            }],
                        },
                    )
                    .await?;
            } else if name == "embedded_authorized_shared_point_get" {
                black_box(database.get_shared(&context, "docs", &id).await?);
            } else {
                black_box(database.get(&context, "docs", &id).await?);
            }
            Ok(())
        }
        .await;
        if !samples.record(start.elapsed(), result) {
            break;
        }
    }
    samples.finish()
}
async fn queries(
    databases: &Databases,
    options: &Options,
    text: Option<TextSearch>,
) -> Measurement {
    let name = text
        .as_ref()
        .map(|text| format!("text_{}_{:?}_complete_pages", text.index, text.mode))
        .unwrap_or_else(|| "structured_indexed_equality".into());
    let mut samples = Samples::new(name, options.operations);
    for operation in 0..options.operations {
        let ordinal = operation.wrapping_mul(7919) % options.documents;
        let tenant = ordinal % databases.tenants.len();
        let selection = Instant::now();
        let database = match databases.leader(tenant).await {
            Ok(database) => database,
            Err(error) => {
                samples.record(selection.elapsed(), Err(error));
                break;
            }
        };
        let mut page = QueryRequest {
            collection: "docs".into(),
            filter: if text.is_none() {
                Predicate::Eq {
                    field: "/ordinal".into(),
                    value: json!(ordinal),
                }
            } else {
                Predicate::All
            },
            sort: Vec::new(),
            projection: vec!["/ordinal".into()],
            aggregates: Vec::new(),
            group_by: Vec::new(),
            text: text.clone(),
            limit: 1000,
            cursor: None,
            allow_scan: false,
        };
        let identity = context(tenant);
        let start = Instant::now();
        let result: Result<()> = async {
            loop {
                let response = database.query(&identity, page.clone()).await?;
                let cursor = response.cursor.clone();
                black_box(response);
                if let Some(cursor) = cursor {
                    page.cursor = Some(cursor);
                } else {
                    break;
                }
            }
            Ok(())
        }
        .await;
        if !samples.record(start.elapsed(), result) {
            break;
        }
    }
    samples.finish()
}

fn checkpoint(
    report: &mut Report,
    mode: &str,
    tenants: usize,
    stage: &str,
    details: Value,
    measurements: &[Measurement],
) -> Result<()> {
    if stage != "loading" {
        if let Some(last) = measurements.last() {
            eprintln!(
                "checkpoint mode={mode} tenants={tenants} stage={stage} workload={} success={} failed={} unattempted={}",
                last.name,
                last.successful_operations,
                last.failed_operations,
                last.unattempted_operations
            );
        } else {
            eprintln!("checkpoint mode={mode} tenants={tenants} stage={stage}");
        }
    }
    let value = json!({"mode":mode,"tenants":tenants,"stage":stage,"details":details,"measurements":measurements});
    if let Some(previous) = report
        .progress
        .iter_mut()
        .find(|entry| entry["mode"] == mode && entry["tenants"] == tenants)
    {
        *previous = value;
    } else {
        report.progress.push(value);
    }
    save(report)
}

fn rss() -> Option<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}
fn peak_rss() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the entire output on success; no pointers escape.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let bytes = unsafe { usage.assume_init() }.ru_maxrss as u64;
    Some(if cfg!(target_os = "macos") {
        bytes
    } else {
        bytes * 1024
    })
}
fn directory_size(path: &Path) -> Result<u64> {
    let mut size = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            size += directory_size(&entry.path())?;
        } else if metadata.is_file() {
            size += metadata.len();
        }
    }
    Ok(size)
}
fn source_hash() -> Result<String> {
    fn files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                files(&p, out)?;
            } else if matches!(
                p.extension().and_then(|v| v.to_str()),
                Some("rs" | "toml" | "proto")
            ) {
                out.push(p);
            }
        }
        Ok(())
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut sources = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    files(&root.join("crates"), &mut sources)?;
    sources.sort();
    let mut hash = Sha256::new();
    for path in sources {
        hash.update(path.strip_prefix(root)?.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(std::fs::read(path)?);
    }
    Ok(hex::encode(hash.finalize()))
}
fn save(report: &Report) -> Result<()> {
    if let Some(parent) = report
        .options
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = report.options.output.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(report)?)?;
    std::fs::rename(temporary, &report.options.output)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse()?;
    let mut report=Report {format:1,created_unix_ms:SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),options:options.clone(),os:std::env::consts::OS.into(),architecture:std::env::consts::ARCH.into(),build_profile:if cfg!(debug_assertions){"debug"}else{"release"}.into(),rustc:std::process::Command::new("rustc").arg("--version").output().ok().map(|output|String::from_utf8_lossy(&output.stdout).trim().to_owned()),source_sha256:source_hash()?, executable_sha256:hex::encode(Sha256::digest(std::fs::read(std::env::current_exe()?)?)), git_status:std::process::Command::new("git").args(["status","--porcelain"]).output().ok().map(|output|String::from_utf8_lossy(&output.stdout).lines().map(str::to_owned).collect()).unwrap_or_default(), logical_cpus:std::thread::available_parallelism().ok().map(usize::from), evidence_status:"Preliminary development measurement; repeat on a quiet host with stable source for publication".into(),guarantees:vec!["Raw lookup, authorized resident reads, and durable writes are reported separately; no 50x comparison is inferred.".into(),
            "RSS is process resident memory; peak RSS covers the whole process lifetime. Sequential cases may retain allocator pages; run one case per process for independent capacity estimates.".into(),
            "Source hash records files at process start, executable hash identifies actual compiled bytes; use quiet stable checkout for publication.".into(),"All datasets are deterministic and total approximately 1 KiB of exact JSON per document across all tenants.".into(),"Latency samples include each API operation; throughput additionally includes driver identity, ID preparation and leader selection.".into()],not_measured:vec!["Authenticated gRPC/MCP wire latency (use a separately configured TLS endpoint benchmark)".into(),"Physically distributed quorum network/disk/failure-domain behavior".into(),"Live OpenBao/Vault request latency and production Linux behavior when this report is run on macOS".into()],cases:Vec::new(),progress:Vec::new(),failures:Vec::new()};
    save(&report)?;
    for &tenants in &options.tenants {
        for mode in &options.modes {
            eprintln!(
                "starting mode={mode} tenants={tenants} documents={} operations={}",
                options.documents, options.operations
            );
            let result = if mode == "raw" {
                raw(&options, tenants)
            } else {
                database_case(&options, tenants, mode, &mut report).await
            };
            match result {
                Ok(case) => {
                    eprintln!(
                        "completed mode={mode} tenants={tenants} load={:.3}s",
                        case.load_seconds
                    );
                    for measured in &case.measurements {
                        if measured.failed() {
                            report.failures.push(format!("mode={mode} tenants={tenants} workload={}: {} failed; {} unattempted",measured.name,measured.failed_operations,measured.unattempted_operations));
                        }
                    }
                    checkpoint(&mut report, mode, tenants, "completed", json!({}), &[])?;
                    report.cases.push(case);
                }
                Err(error) => {
                    report
                        .failures
                        .push(format!("mode={mode} tenants={tenants}: {error:#}"));
                    save(&report)?;
                    return Err(error);
                }
            }
            save(&report)?;
        }
    }
    eprintln!("benchmark report: {}", options.output.display());
    ensure!(
        report.failures.is_empty(),
        "benchmark completed with recorded workload failures"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_read_workload_retains_counts_and_later_independent_work_can_run() {
        let dir = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(dir.path(), 1).unwrap();
        let databases = Databases::open(&physical, 1, 1, 4, false, None, true)
            .await
            .unwrap();
        let database = databases.leader(0).await.unwrap();
        database
            .administer(context(0), Operation::CreateCollection(definition(false)))
            .await
            .unwrap();
        let options = Options {
            documents: 1,
            tenants: vec![1],
            operations: 4,
            modes: vec!["local".into()],
            output: dir.path().join("result.json"),
            work_parent: None,
        };
        let failed = workload(
            &databases,
            &options,
            "embedded_authorized_owned_point_get",
            0,
            0,
        )
        .await;
        assert_eq!(
            (
                failed.successful_operations,
                failed.failed_operations,
                failed.unattempted_operations
            ),
            (0, 1, 3)
        );
        assert_eq!(
            failed.failed_attempts[0].error_code,
            Some(ErrorCode::NotFound)
        );
        assert!(failed.latency.is_none());
        database
            .mutate(
                context(0),
                MutationBatch {
                    read_set: Vec::new(),
                    idempotency_key: "load".into(),
                    operations: vec![Mutation::Put {
                        collection: "docs".into(),
                        id: "0".into(),
                        body: body(0, 0, 1),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap();
        let succeeded = workload(
            &databases,
            &options,
            "embedded_authorized_owned_point_get",
            0,
            0,
        )
        .await;
        assert_eq!(
            (
                succeeded.successful_operations,
                succeeded.failed_operations,
                succeeded.unattempted_operations
            ),
            (4, 0, 0)
        );
        databases.close().await.unwrap();
    }
}
