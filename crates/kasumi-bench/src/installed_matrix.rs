//! Runs the same embedded operations against separately enrolled, production nodes.
use anyhow::{Context, Result, ensure};
use kasumi_bench::{
    Measurement,
    embedded::{self, Dimensions, EmbeddedDatabases},
    raw::document_body,
};
use kasumi_engine::Database;
use kasumi_server::{
    api::DatabaseRegistry,
    runtime::{DeploymentMode, KeyProviderSettings, NodeRuntime, RuntimeConfig},
};
use kasumi_types::{
    Action, Mutation, MutationBatch, Operation, Precondition, RequestAuthorization, RequestContext,
    TextMode, TextSearch,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinSet};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    mode: String,
    documents: usize,
    operations: usize,
    nodes: Vec<NodeFile>,
    network: Option<NodeFile>,
    tenants: BTreeMap<String, Principals>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeFile {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Principals {
    administrator: String,
    application: String,
}

#[derive(Serialize)]
struct NodeFact {
    configuration_sha256: String,
    database_id: Uuid,
    voter: Option<u64>,
    providers: BTreeMap<String, [String; 2]>,
}
#[derive(Serialize)]
struct Report {
    schema: &'static str,
    executable_sha256: String,
    plan_sha256: String,
    mode: String,
    attempt: Uuid,
    nodes: Vec<NodeFact>,
    tenants: Vec<String>,
    voters: BTreeMap<String, Vec<u64>>,
    documents: usize,
    canonical_bytes: u64,
    receipts: usize,
    measurements: Vec<Measurement>,
    complete: bool,
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "configuration exceeds size limit");
    Ok(bytes)
}
fn provider(k: &KeyProviderSettings) -> String {
    match k {
        KeyProviderSettings::Transit(_) => "transit",
        KeyProviderSettings::File { .. } => "file",
    }
    .to_owned()
}

struct Cluster<'a> {
    plan: &'a Plan,
    names: Vec<String>,
    registries: Vec<DatabaseRegistry>,
    voters: BTreeSet<u64>,
    attempt: Uuid,
}
impl Cluster<'_> {
    fn identity(&self, i: usize, admin: bool) -> RequestContext {
        let tenant = &self.names[i];
        let identity = &self.plan.tenants[tenant];
        RequestContext {
            authorization: RequestAuthorization::service_identity(),
            principal: if admin {
                identity.administrator.clone()
            } else {
                identity.application.clone()
            },
            tenant: tenant.clone(),
            scopes: if admin {
                BTreeSet::from([Action::Admin])
            } else {
                BTreeSet::from([Action::Read, Action::Write])
            },
            request_id: Uuid::new_v4().to_string(),
        }
    }
}
impl EmbeddedDatabases for Cluster<'_> {
    fn tenant_count(&self) -> usize {
        self.names.len()
    }
    fn context(&self, i: usize) -> RequestContext {
        self.identity(i, false)
    }
    fn write_key(&self, phase: usize, operation: usize) -> String {
        format!("{}-work-{phase}-{operation}", self.attempt)
    }
    async fn leader(&self, i: usize) -> Result<Arc<Database>> {
        let context = self.context(i);
        let start = Instant::now();
        loop {
            for registry in &self.registries {
                let db = registry.database(&context)?;
                let metrics = db.raft_group().metrics();
                if metrics.current_leader == Some(metrics.id) {
                    let actual: BTreeSet<_> =
                        metrics.membership_config.membership().voter_ids().collect();
                    if self.plan.mode == "replicated" {
                        ensure!(
                            actual == self.voters,
                            "actual tenant voters differ from enrolled nodes"
                        );
                    } else {
                        ensure!(
                            db.raft_group().is_local() && actual.len() == 1,
                            "tenant is not local"
                        );
                    }
                    return Ok(db);
                }
            }
            ensure!(
                start.elapsed() < Duration::from_secs(30),
                "no serving leader for tenant {}",
                self.names[i]
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
fn checkpoint(output: &Path, report: &Report) -> Result<()> {
    let tmp = output.join("progress.tmp");
    let mut file = File::create(&tmp)?;
    serde_json::to_writer(&mut file, report)?;
    file.sync_all()?;
    std::fs::rename(&tmp, output.join("case.json"))?;
    File::open(output)?.sync_all()?;
    Ok(())
}
fn wire_case(input: &NodeFile, plan: &Plan, node: &RuntimeConfig) -> Result<super::Configuration> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use kasumi_transport::credentials::{FileCredentialSource, token};
    ensure!(input.path.is_absolute(), "network input must be absolute");
    let bytes = read(&input.path, 4 << 20)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == input.sha256,
        "network input changed"
    );
    let cfg: super::Configuration = serde_json::from_slice(&bytes)?;
    let mut protocols = BTreeSet::new();
    let pin = hex::encode(kasumi_transport::certificate_pin(&read(
        &node.native.tls.certificate,
        1 << 20,
    )?)?);
    for case in &cfg.cases {
        super::validate(case)?;
        let (name, port) = match case.protocol {
            super::Protocol::Grpc => {
                ensure!(
                    case.server_certificate_sha256.as_deref() == Some(pin.as_str()),
                    "another native server certificate"
                );
                ("grpc", node.native.listen.port())
            }
            super::Protocol::Mcp => {
                ensure!(
                    case.endpoint == node.mcp.protocol.public_url,
                    "another deployed MCP endpoint"
                );
                ("mcp", node.mcp.listen.port())
            }
        };
        let url = reqwest::Url::parse(&case.endpoint)?;
        ensure!(
            url.host_str() == Some("localhost")
                || url.host_str().is_some_and(|h| h
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
            "network case must use its own local node"
        );
        ensure!(
            url.port_or_known_default() == Some(port)
                && case.name == name
                && protocols.insert(name)
                && case.operations == plan.operations
                && case.targets.len() == plan.tenants.len(),
            "network case roster differs"
        );
        for (i, (target, tenant)) in case.targets.iter().zip(plan.tenants.keys()).enumerate() {
            ensure!(
                target.id == i.to_string()
                    && target.collection == "docs"
                    && target
                        .query
                        .as_ref()
                        .is_some_and(|q| q.collection == "docs" && q.cursor.is_none())
                    && target.mutation_body.is_some(),
                "network target does not belong to this new corpus"
            );
            let credentials = FileCredentialSource::new(&target.token_file)?;
            let secret = token(&credentials)?;
            let parts: Vec<_> = secret.split('.').collect();
            ensure!(
                parts.len() == 3,
                "network target requires a signed credential"
            );
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
            ensure!(
                claims["tenant"].as_str() == Some(tenant.as_str()),
                "network credential tenant differs"
            );
        }
    }
    ensure!(
        protocols == BTreeSet::from(["grpc", "mcp"]),
        "both secure network protocols are required"
    );
    Ok(cfg)
}

async fn run_case(
    plan: &Plan,
    output: &Path,
    report: &mut Report,
    stop: &watch::Sender<bool>,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    let replicated = plan.mode == "replicated";
    ensure!(
        matches!(
            plan.mode.as_str(),
            "local" | "replicated" | "text" | "network"
        ) && plan.network.is_some() == (plan.mode == "network")
            && plan.nodes.len() == if replicated { 3 } else { 1 }
            && (1..=1000).contains(&plan.tenants.len())
            && (plan.tenants.len()..=1_000_000).contains(&plan.documents)
            && (1..=10_000).contains(&plan.operations),
        "invalid installed benchmark dimensions"
    );
    let names: Vec<_> = plan.tenants.keys().cloned().collect();
    let mut cluster = Cluster {
        plan,
        names: names.clone(),
        registries: vec![],
        voters: BTreeSet::new(),
        attempt: report.attempt,
    };
    let mut configured = Vec::new();
    let mut owners = BTreeSet::new();
    for node in &plan.nodes {
        ensure!(
            node.path.is_absolute(),
            "node configuration must have an absolute path"
        );
        let bytes = read(&node.path, 4 << 20)?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == node.sha256,
            "node configuration changed"
        );
        let cfg: RuntimeConfig = serde_json::from_slice(&bytes)?;
        cfg.validate()?;
        ensure!(
            (cfg.mode == DeploymentMode::Replicated) == replicated
                && owners.insert(cfg.database_path.clone()),
            "node mode or storage path repeats"
        );
        let keys: BTreeMap<_, _> = cfg
            .tenants
            .iter()
            .map(|t| {
                (
                    t.tenant.clone(),
                    [provider(&t.keys), provider(&t.custody_keys)],
                )
            })
            .collect();
        ensure!(
            keys.keys().eq(names.iter()),
            "installed and requested tenants differ"
        );
        let voter = cfg.replication.as_ref().map(|r| r.node_id);
        if let Some(id) = voter {
            ensure!(cluster.voters.insert(id), "replica voter id repeats");
        }
        report.nodes.push(NodeFact {
            configuration_sha256: node.sha256.clone(),
            database_id: cfg.database_id,
            voter,
            providers: keys,
        });
        configured.push(cfg);
    }
    ensure!(
        configured.iter().all(|c| c
            .replication
            .as_ref()
            .is_none_or(|r| r.initial_voters == cluster.voters)),
        "enrolled voters disagree"
    );
    checkpoint(output, report)?;
    let wire = plan
        .network
        .as_ref()
        .map(|input| wire_case(input, plan, &configured[0]))
        .transpose()?;
    for cfg in configured {
        let runtime = NodeRuntime::open(cfg).await?;
        cluster.registries.push(runtime.registry().clone());
        tasks.spawn(runtime.serve(stop.subscribe()));
    }
    // Enrollment can return while the initial serving route is still being published.
    // Only wait for startup here. Every measured operation retains its first outcome.
    let startup = Instant::now();
    for (i, name) in names.iter().enumerate() {
        let context = cluster.context(i);
        for (n, registry) in cluster.registries.iter().enumerate() {
            loop {
                match registry.database(&context) {
                    Ok(_) => break,
                    Err(error) if startup.elapsed() >= Duration::from_secs(120) => {
                        return Err(error).with_context(|| {
                            format!("waiting for installed tenant {name} on node {n}")
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        }
    }
    let mut receipts = File::create_new(output.join("load-receipts.jsonl"))?;
    for (i, name) in names.iter().enumerate() {
        let db = cluster
            .leader(i)
            .await
            .with_context(|| format!("selecting initial leader for {name}"))?;
        let admin = cluster.identity(i, true);
        ensure!(
            !db.collections(&cluster.context(i))
                .await
                .context("checking fresh collection namespace")?
                .iter()
                .any(|c| c.name == "docs"),
            "benchmark collection already exists"
        );
        db.administer(
            admin,
            Operation::CreateCollection(embedded::definition(plan.mode == "text")),
        )
        .await
        .context("creating fresh benchmark collection")?;
        let metrics = db.raft_group().metrics();
        report.voters.insert(
            name.clone(),
            metrics.membership_config.membership().voter_ids().collect(),
        );
        let mut ordinals = (i..plan.documents).step_by(names.len());
        loop {
            let mut keys = Vec::with_capacity(256);
            let mut operations = Vec::with_capacity(256);
            let mut bytes = 0;
            for ordinal in ordinals.by_ref().take(256) {
                let body = document_body(ordinal, 0, names.len());
                bytes += serde_json::to_vec(&body)?.len() as u64;
                keys.push(ordinal);
                operations.push(Mutation::Put {
                    collection: "docs".into(),
                    id: ordinal.to_string(),
                    body,
                    expected: Precondition::Absent,
                });
            }
            if keys.is_empty() {
                break;
            }
            let key = format!("{}-load-{}", cluster.attempt, report.receipts);
            let submitted = db
                .mutate(
                    cluster.context(i),
                    MutationBatch {
                        read_set: vec![],
                        idempotency_key: key.clone(),
                        operations,
                    },
                )
                .await;
            let receipt = match submitted {
                Ok(receipt) => receipt,
                Err(original) => {
                    let failure = anyhow::Error::new(original).context(format!(
                        "installed load failed for tenant {name}, first ordinal {}, {} documents, idempotency key {key}",
                        keys[0], keys.len(),
                    ));
                    // Retain only acknowledged batches. The attempted key and the
                    // original cause identify the write a cold client can resolve.
                    if let Err(error) = receipts.sync_all() {
                        return Err(failure.context(format!(
                            "syncing acknowledged load receipts failed: {error}"
                        )));
                    }
                    return Err(failure);
                }
            };
            ensure!(
                receipt.revision > 0
                    && receipt.versions.len() == keys.len()
                    && keys
                        .iter()
                        .all(|k| receipt.versions.get(&format!("/docs/{k}"))
                            == Some(&receipt.revision)),
                "load receipt differs from submitted batch"
            );
            serde_json::to_writer(
                &mut receipts,
                &serde_json::json!({"tenant":name,"first":keys[0],"documents":keys.len(),"canonical_bytes":bytes,"revision":receipt.revision}),
            )?;
            receipts.write_all(b"\n")?;
            report.documents += keys.len();
            report.canonical_bytes += bytes;
            report.receipts += 1;
        }
        receipts.sync_all()?;
        checkpoint(output, report)?;
    }
    ensure!(
        report.documents == plan.documents
            && report.canonical_bytes == plan.documents as u64 * 1024,
        "installed corpus differs"
    );
    if let Some(wire) = wire {
        let input = plan.network.as_ref().unwrap();
        let parent = input
            .path
            .parent()
            .context("network inputs directory missing")?;
        super::run_configured(wire, parent, &output.join("network.json"), true, true).await?;
        return Ok(());
    }
    let options = Dimensions {
        documents: plan.documents,
        operations: plan.operations,
        retain_samples: true,
    };
    for (name, percent, phase) in [
        ("embedded_authorized_owned_point_get", 0, 0),
        ("embedded_authorized_shared_point_get", 0, 0),
        ("durable_single_document_write", 100, 1),
        ("read_heavy_90_read_10_write", 10, 2),
        ("balanced_50_read_50_write", 50, 3),
    ] {
        report
            .measurements
            .push(embedded::workload(&cluster, options, name, percent, phase).await);
        checkpoint(output, report)?;
    }
    report
        .measurements
        .push(embedded::queries(&cluster, options, None).await);
    checkpoint(output, report)?;
    if plan.mode == "text" {
        for (index, query, mode) in [
            ("english", "searchable document", TextMode::Phrase),
            ("english", "token000", TextMode::Prefix),
            ("english", "tokeq0007", TextMode::Fuzzy),
            ("japanese", "図書館", TextMode::Terms),
        ] {
            report.measurements.push(
                embedded::queries(
                    &cluster,
                    options,
                    Some(TextSearch::new(index, query).mode(mode)),
                )
                .await,
            );
            checkpoint(output, report)?;
        }
    }
    ensure!(
        report
            .measurements
            .iter()
            .all(|m| !m.failed() && m.successful_operations == plan.operations),
        "installed benchmark has failed or omitted operations"
    );
    Ok(())
}

pub(super) async fn run(plan_file: &Path, output: &Path) -> Result<()> {
    let bytes = read(plan_file, 1 << 20)?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    std::fs::create_dir(output)?;
    let mut report = Report {
        schema: "kasumi-installed-embedded-v1",
        executable_sha256: hex::encode(Sha256::digest(std::fs::read(std::env::current_exe()?)?)),
        plan_sha256: hex::encode(Sha256::digest(&bytes)),
        mode: plan.mode.clone(),
        attempt: Uuid::new_v4(),
        nodes: vec![],
        tenants: plan.tenants.keys().cloned().collect(),
        voters: BTreeMap::new(),
        documents: 0,
        canonical_bytes: 0,
        receipts: 0,
        measurements: vec![],
        complete: false,
    };
    checkpoint(output, &report)?;
    let (stop, _) = watch::channel(false);
    let mut nodes = JoinSet::new();
    let result = run_case(&plan, output, &mut report, &stop, &mut nodes).await;
    stop.send_replace(true);
    let mut errors = Vec::new();
    while let Some(done) = nodes.join_next().await {
        match done {
            Ok(Ok(())) => (),
            Ok(Err(e)) => errors.push(e.to_string()),
            Err(e) => errors.push(e.to_string()),
        }
    }
    if let Err(e) = result {
        let e = match checkpoint(output, &report) {
            Ok(()) => e,
            Err(error) => e.context(format!("saving partial benchmark progress failed: {error}")),
        };
        return Err(e)
            .with_context(|| format!("embedded benchmark failed (node drain errors: {errors:?})"));
    }
    ensure!(errors.is_empty(), "node drain failed: {errors:?}");
    report.complete = true;
    checkpoint(output, &report)?;
    let case = output.join("case.json");
    let loads = output.join("load-receipts.jsonl");
    let network = output.join("network.json");
    let mut files = vec![
        ("case.json", case.as_path()),
        ("load-receipts.jsonl", loads.as_path()),
    ];
    if plan.mode == "network" {
        files.push(("network.json", network.as_path()));
    }
    super::original_outputs(&files)
}
