//! Live TLS endpoint measurements. Each request reads a fresh private credential
//! file snapshot; secrets are never reported. Writes require --allow-writes.
use anyhow::{Context, Result, ensure};
use kasumi_bench::{Measurement, Samples};
use kasumi_server::rpc::proto;
use kasumi_transport::{TlsIdentity, credentials::FileCredentialSource, grpc_channel};
use kasumi_types::{Mutation, MutationBatch, Precondition, QueryRequest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Grpc,
    Mcp,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    cases: Vec<CaseConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseConfig {
    name: String,
    protocol: Protocol,
    endpoint: String,
    ca_pem: PathBuf,
    client_certificate_pem: Option<PathBuf>,
    client_private_key_pem: Option<PathBuf>,
    server_certificate_sha256: Option<String>,
    operations: usize,
    targets: Vec<TargetConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    token_file: PathBuf,
    collection: String,
    id: String,
    query: Option<QueryRequest>,
    /// Exact JSON replacement for a dedicated benchmark document. Used only
    /// when every target supplies a body and --allow-writes is explicit.
    mutation_body: Option<PathBuf>,
}
struct Target {
    credentials: FileCredentialSource,
    collection: String,
    id: String,
    query: Option<QueryRequest>,
    mutation_body: Option<Value>,
}
impl Target {
    fn authorization(&self) -> Result<Zeroizing<String>> {
        let token = kasumi_transport::credentials::token(&self.credentials)?;
        Ok(Zeroizing::new(format!("Bearer {}", token.as_str())))
    }
}
#[derive(Clone, Serialize)]
struct CaseReport {
    name: String,
    protocol: Protocol,
    endpoint: String,
    credentials: usize,
    configured_targets: usize,
    phase: String,
    connection_seconds: Option<f64>,
    warmup_seconds: Option<f64>,
    measurements: Vec<Measurement>,
}
#[derive(Serialize)]
struct Report {
    format: u32,
    created_unix_ms: u128,
    os: String,
    architecture: String,
    build_profile: String,
    executable_sha256: String,
    logical_cpus: Option<usize>,
    evidence_status: String,
    notes: Vec<String>,
    cases: Vec<CaseReport>,
    failures: Vec<String>,
}

enum Client {
    Grpc(proto::kasumi_data_client::KasumiDataClient<tonic::transport::Channel>),
    Mcp {
        http: reqwest::Client,
        endpoint: String,
    },
}
fn validate(config: &CaseConfig) -> Result<()> {
    let url = reqwest::Url::parse(&config.endpoint)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "endpoint must be HTTPS with no credentials, query, or fragment"
    );
    ensure!(
        !config.targets.is_empty()
            && config.targets.len() <= 10000
            && config.operations > 0
            && config.operations <= 1_000_000,
        "invalid operation/target count"
    );
    ensure!(
        config.client_certificate_pem.is_some() == config.client_private_key_pem.is_some(),
        "client certificate and private key must be paired"
    );
    if matches!(config.protocol, Protocol::Grpc) {
        ensure!(
            config.client_certificate_pem.is_some() && config.server_certificate_sha256.is_some(),
            "native RPC requires client certificate, private key, and server certificate SHA256 pin"
        );
    } else {
        ensure!(
            config.server_certificate_sha256.is_none(),
            "MCP uses the configured CA; certificate pin option is native RPC only"
        );
    }
    for target in &config.targets {
        kasumi_types::validate_name(&target.collection)?;
        kasumi_types::validate_name(&target.id)?;
        ensure!(
            !target.token_file.as_os_str().is_empty(),
            "credential file path missing"
        );
    }
    Ok(())
}
fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.into()
    } else {
        root.join(path)
    }
}
impl Client {
    async fn connect(config: &CaseConfig, root: &Path) -> Result<Self> {
        let ca = std::fs::read(resolve(root, &config.ca_pem))?;
        let certificate = config
            .client_certificate_pem
            .as_ref()
            .map(|path| std::fs::read(resolve(root, path)))
            .transpose()?;
        let key = config
            .client_private_key_pem
            .as_ref()
            .map(|path| std::fs::read(resolve(root, path)).map(Zeroizing::new))
            .transpose()?;
        Ok(match config.protocol {
            Protocol::Grpc => {
                let identity =
                    TlsIdentity::from_pem(certificate.as_ref().unwrap(), key.as_ref().unwrap())?;
                let pin: [u8; 32] =
                    hex::decode(config.server_certificate_sha256.as_ref().unwrap())?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("certificate pin must have 32 bytes"))?;
                let channel =
                    grpc_channel(&config.endpoint, &identity, &ca, BTreeSet::from([pin])).await?;
                Self::Grpc(
                    proto::kasumi_data_client::KasumiDataClient::new(channel)
                        .max_decoding_message_size(16 << 20)
                        .max_encoding_message_size(8 << 20),
                )
            }
            Protocol::Mcp => {
                let mut builder = reqwest::Client::builder()
                    .https_only(true)
                    .min_tls_version(reqwest::tls::Version::TLS_1_3)
                    .max_tls_version(reqwest::tls::Version::TLS_1_3)
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(30));
                if let (Some(certificate), Some(key)) = (&certificate, &key) {
                    let mut pem = Zeroizing::new(certificate.clone());
                    pem.extend_from_slice(key);
                    builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
                }
                Self::Mcp {
                    http: builder.build()?,
                    endpoint: config.endpoint.clone(),
                }
            }
        })
    }
    async fn get(&mut self, target: &Target) -> Result<()> {
        match self {
            Self::Grpc(client) => {
                let result = client
                    .get(authenticated(
                        proto::GetRequest {
                            collection: target.collection.clone(),
                            id: target.id.clone(),
                        },
                        target,
                    )?)
                    .await?
                    .into_inner();
                let _: Value = serde_json::from_slice(&result.body_json)?;
                ensure!(
                    result.id == target.id,
                    "native response document ID mismatch"
                );
            }
            Self::Mcp { http, endpoint } => {
                let result = mcp(
                    http,
                    endpoint,
                    target,
                    "kasumi_get",
                    json!({"collection":target.collection,"id":target.id}),
                )
                .await?;
                ensure!(
                    result["id"] == target.id && result.get("body").is_some(),
                    "MCP response document mismatch"
                );
            }
        }
        Ok(())
    }
    async fn mutate(&mut self, target: &Target, key: &str) -> Result<()> {
        let batch = MutationBatch {
            read_set: Vec::new(),
            idempotency_key: key.into(),
            operations: vec![Mutation::Put {
                collection: target.collection.clone(),
                id: target.id.clone(),
                body: target
                    .mutation_body
                    .clone()
                    .context("mutation body missing")?,
                expected: Precondition::Any,
            }],
        };
        match self {
            Self::Grpc(client) => {
                client
                    .mutate(authenticated(
                        proto::MutateRequest {
                            batch_json: serde_json::to_vec(&batch)?,
                        },
                        target,
                    )?)
                    .await?;
            }
            Self::Mcp { http, endpoint } => {
                let result = mcp(
                    http,
                    endpoint,
                    target,
                    "kasumi_mutate",
                    serde_json::to_value(batch)?,
                )
                .await?;
                ensure!(result["revision"].is_u64(), "MCP mutation receipt missing");
            }
        }
        Ok(())
    }
    async fn query(&mut self, target: &Target) -> Result<()> {
        let mut query = target.query.clone().context("query missing")?;
        ensure!(
            query.cursor.is_none(),
            "benchmark queries must start a new snapshot"
        );
        loop {
            query.cursor = match self {
                Self::Grpc(client) => {
                    let response = client
                        .query(authenticated(
                            proto::QueryRequest {
                                query_json: serde_json::to_vec(&query)?,
                            },
                            target,
                        )?)
                        .await?
                        .into_inner();
                    for row in response.rows {
                        let _: Value = serde_json::from_slice(
                            &row.document.context("document missing")?.body_json,
                        )?;
                    }
                    response.cursor
                }
                Self::Mcp { http, endpoint } => {
                    let response = mcp(
                        http,
                        endpoint,
                        target,
                        "kasumi_query",
                        serde_json::to_value(&query)?,
                    )
                    .await?;
                    ensure!(response["rows"].is_array(), "MCP query rows missing");
                    response["cursor"].as_str().map(str::to_owned)
                }
            };
            if query.cursor.is_none() {
                break;
            }
        }
        Ok(())
    }
}
fn authenticated<T>(value: T, target: &Target) -> Result<tonic::Request<T>> {
    let authorization = target.authorization()?;
    let mut request = tonic::Request::new(value);
    request.metadata_mut().insert(
        "authorization",
        authorization
            .as_str()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid bearer token header"))?,
    );
    request.set_timeout(Duration::from_secs(30));
    Ok(request)
}
fn mcp_request(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"kasumi-bench","version":env!("CARGO_PKG_VERSION")},"io.modelcontextprotocol/clientCapabilities":{}}}})
}
async fn mcp(
    http: &reqwest::Client,
    endpoint: &str,
    target: &Target,
    name: &str,
    arguments: Value,
) -> Result<Value> {
    let authorization = target.authorization()?;
    let mut response = http
        .post(endpoint)
        .header("authorization", authorization.as_str())
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .json(&mcp_request(name, arguments))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "MCP HTTP status {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json")),
        "MCP benchmark requires JSON response mode"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 16 << 20,
            "MCP response exceeds 16 MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        value["id"] == 1 && value.get("error").is_none(),
        "MCP protocol error"
    );
    if value["result"]["isError"] == true {
        let error: kasumi_types::Error =
            serde_json::from_value(value["result"]["structuredContent"]["error"].clone())
                .context("MCP operation rejected without database error")?;
        return Err(error.into());
    }
    value["result"]
        .get("structuredContent")
        .cloned()
        .context("MCP structured result missing")
}
async fn run(
    config: CaseConfig,
    root: &Path,
    allow_writes: bool,
    mut checkpoint: impl FnMut(&CaseReport) -> Result<()>,
) -> Result<CaseReport> {
    validate(&config)?;
    let credentials = config
        .targets
        .iter()
        .map(|target| resolve(root, &target.token_file))
        .collect::<BTreeSet<_>>()
        .len();
    let targets = config
        .targets
        .iter()
        .map(|target| -> Result<Target> {
            let credentials = FileCredentialSource::new(resolve(root, &target.token_file))?;
            let mutation_body = if allow_writes {
                target
                    .mutation_body
                    .as_ref()
                    .map(|path| -> Result<Value> {
                        Ok(serde_json::from_slice(&std::fs::read(resolve(
                            root, path,
                        ))?)?)
                    })
                    .transpose()?
            } else {
                None
            };
            Ok(Target {
                credentials,
                collection: target.collection.clone(),
                id: target.id.clone(),
                query: target.query.clone(),
                mutation_body,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut result = CaseReport {
        name: config.name.clone(),
        protocol: config.protocol,
        endpoint: config.endpoint.clone(),
        credentials,
        configured_targets: targets.len(),
        phase: "connecting".into(),
        connection_seconds: None,
        warmup_seconds: None,
        measurements: Vec::new(),
    };
    checkpoint(&result)?;
    let start = Instant::now();
    let mut client = Client::connect(&config, root).await?;
    result.connection_seconds = Some(start.elapsed().as_secs_f64());
    result.phase = "warming_credentials".into();
    checkpoint(&result)?;
    let start = Instant::now();
    let mut warmed = BTreeSet::new();
    for (configuration, target) in config.targets.iter().zip(&targets) {
        if warmed.insert(resolve(root, &configuration.token_file)) {
            client.get(target).await?;
        }
    }
    result.warmup_seconds = Some(start.elapsed().as_secs_f64());
    let run_id = uuid::Uuid::new_v4();
    let writes = allow_writes && targets.iter().all(|target| target.mutation_body.is_some());
    for (name, percent) in [
        ("authenticated_point_get", 0),
        ("durable_single_document_write", 100),
        ("read_heavy_90_read_10_write", 10),
        ("balanced_50_read_50_write", 50),
    ] {
        if percent > 0 && !writes {
            continue;
        }
        result.phase = name.into();
        checkpoint(&result)?;
        let mut samples = Samples::new(name, config.operations);
        for operation in 0..config.operations {
            let target = &targets[operation % targets.len()];
            let started = Instant::now();
            let outcome = if (operation + 1) * percent / 100 > operation * percent / 100 {
                client
                    .mutate(target, &format!("{run_id}-{percent}-{operation}"))
                    .await
            } else {
                client.get(target).await
            };
            if !samples.record(started.elapsed(), outcome) {
                break;
            }
        }
        result.measurements.push(samples.finish());
        checkpoint(&result)?;
    }
    if targets.iter().all(|target| target.query.is_some()) {
        result.phase = "authenticated_query_complete_pages".into();
        checkpoint(&result)?;
        let mut samples = Samples::new("authenticated_query_complete_pages", config.operations);
        for operation in 0..config.operations {
            let started = Instant::now();
            let outcome = client.query(&targets[operation % targets.len()]).await;
            if !samples.record(started.elapsed(), outcome) {
                break;
            }
        }
        result.measurements.push(samples.finish());
        checkpoint(&result)?;
    }
    result.phase = "completed".into();
    checkpoint(&result)?;
    Ok(result)
}
fn save(path: &Path, report: &Report) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(report)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let config_path = PathBuf::from(
        args.next()
            .context("usage: kasumi-bench-network CONFIG.json OUTPUT.json [--allow-writes]")?,
    );
    let output = PathBuf::from(args.next().context("report path required")?);
    let allow_writes = match args.next().as_deref() {
        None => false,
        Some("--allow-writes") => true,
        _ => anyhow::bail!("unknown argument"),
    };
    ensure!(args.next().is_none(), "extra arguments");
    let config: Configuration = serde_json::from_slice(&std::fs::read(&config_path)?)?;
    ensure!(!config.cases.is_empty(), "at least one case required");
    let mut report=Report{format:1,created_unix_ms:SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),os:std::env::consts::OS.into(),architecture:std::env::consts::ARCH.into(),build_profile:if cfg!(debug_assertions){"debug"}else{"release"}.into(),executable_sha256:hex::encode(Sha256::digest(std::fs::read(std::env::current_exe()?)?)),logical_cpus:std::thread::available_parallelism().ok().map(usize::from),evidence_status:"Preliminary development measurement; repeat on quiet host with stable server/client source".into(),notes:vec!["Real authenticated TLS 1.3 network requests. Native RPC additionally requires mTLS and pins the server certificate against the configured CA.".into(),"Credentials and document/query values are omitted from this report. Credential count is configured token sources, not a claim of verified distinct tenants.".into(),"Connections and one warmup point read per credential are excluded from measured API latency. Requests are sequential and no automatic retries are attempted.".into(),"Server replication, KMS, hardware, and audit configuration must be disclosed separately for comparison; this client does not infer their guarantees.".into(),"Writes occur only with --allow-writes and a replacement body on every dedicated target. Query measurements consume all historical pages.".into()],cases:Vec::new(),failures:Vec::new()};
    save(&output, &report)?;
    let config_path = std::fs::canonicalize(config_path)?;
    let root = config_path
        .parent()
        .context("configuration parent missing")?;
    for case in config.cases {
        eprintln!("running network case {}", case.name);
        let name = case.name.clone();
        let result = run(case, root, allow_writes, |partial| {
            if let Some(previous) = report
                .cases
                .iter_mut()
                .find(|entry| entry.name == partial.name)
            {
                *previous = partial.clone();
            } else {
                report.cases.push(partial.clone());
            }
            save(&output, &report)
        })
        .await;
        match result {
            Ok(result) => {
                for measurement in &result.measurements {
                    if measurement.failed() {
                        report.failures.push(format!(
                            "case={name} workload={}: {} failed; {} unattempted",
                            measurement.name,
                            measurement.failed_operations,
                            measurement.unattempted_operations
                        ));
                    }
                }
            }
            Err(error) => report.failures.push(format!("case={name}: {error:#}")),
        }
        save(&output, &report)?;
    }
    eprintln!("network benchmark report: {}", output.display());
    ensure!(
        report.failures.is_empty(),
        "network benchmark completed with recorded failures"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    fn publish(path: &Path, value: &[u8]) {
        let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.write_all(value).unwrap();
        file.as_file().sync_all().unwrap();
        file.persist(path).unwrap();
    }

    #[test]
    fn renewal_changes_the_next_request_and_invalid_replacement_never_uses_old_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let target = Target {
            credentials: FileCredentialSource::new(&path).unwrap(),
            collection: "documents".into(),
            id: "one".into(),
            query: None,
            mutation_body: None,
        };
        publish(&path, b"first-token\n");
        let original = authenticated((), &target).unwrap();
        let timeout = original.metadata().get("grpc-timeout").unwrap().clone();
        publish(&path, b"renewed-token\r\n");
        let next = authenticated((), &target).unwrap();
        assert_eq!(
            original.metadata().get("authorization").unwrap(),
            "Bearer first-token"
        );
        assert_eq!(
            next.metadata().get("authorization").unwrap(),
            "Bearer renewed-token"
        );
        assert_eq!(original.metadata().get("grpc-timeout").unwrap(), &timeout);
        publish(&path, b"bad\nheader");
        assert!(authenticated((), &target).is_err());
        std::fs::remove_file(path).unwrap();
        assert!(target.authorization().is_err());
    }

    #[test]
    fn environment_credential_configuration_is_unsupported() {
        let old = json!({"token_env":"OLD_TOKEN","collection":"documents","id":"one"});
        assert!(serde_json::from_value::<TargetConfig>(old).is_err());
        let current = json!({"token_file":"credential","collection":"documents","id":"one"});
        assert!(serde_json::from_value::<TargetConfig>(current).is_ok());
    }
}
