//! Isolated real-process fixture for authenticated wire measurements. The issuer
//! uses ephemeral test keys; all data and service keys use a real local OpenBao.
#[path = "../fixture_bao.rs"]
mod fixture_bao;
use anyhow::{Context, Result, ensure};
use axum::{Json, Router, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use kasumi_server::{
    auth::AuthConfig,
    mcp::McpConfig,
    rpc::proto,
    runtime::{KeyProviderSettings, TenantConfig, TlsFiles, TransitSettings, example_config},
    tls::{self, ListenerLimits},
};
use kasumi_transport::{ClientAuthentication, TlsIdentity};
use kasumi_types::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::watch};
use zeroize::Zeroizing;

struct Process(Option<Child>);
impl Process {
    async fn shutdown(&mut self) -> Result<()> {
        if let Some(mut child) = self.0.take() {
            // This PID belongs to the child this guard created and still owns.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            let start = Instant::now();
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success(), "kasumid shutdown failed");
                    break;
                }
                if start.elapsed() > Duration::from_secs(20) {
                    child.kill()?;
                    child.wait()?;
                    anyhow::bail!("kasumid graceful shutdown timed out");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
struct Authority {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}
impl Authority {
    fn new() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Self {
            pem: cert.pem(),
            issuer: Issuer::new(params, key),
        })
    }
    fn issue(&self, path: &Path, name: &str) -> Result<TlsFiles> {
        let mut params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        let files = TlsFiles {
            certificate: path.join(format!("{name}.pem")),
            private_key: path.join(format!("{name}-key.pem")),
        };
        std::fs::write(&files.certificate, cert.pem())?;
        private(&files.private_key, key.serialize_pem().as_bytes())?;
        Ok(files)
    }
}
fn resident_bytes(pid: u32) -> Option<u64> {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value * 1024)
}
fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
fn identity(files: &TlsFiles) -> Result<TlsIdentity> {
    TlsIdentity::from_pem(
        &std::fs::read(&files.certificate)?,
        &Zeroizing::new(std::fs::read(&files.private_key)?),
    )
}
struct IssuerAudit;
#[async_trait::async_trait]
impl tls::TlsHandshakeAudit for IssuerAudit {
    async fn record(&self, _: &tls::TlsHandshakeEvent) -> anyhow::Result<()> {
        Ok(())
    }
}
fn addresses() -> Result<[SocketAddr; 3]> {
    let sockets = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok([
        sockets[0].local_addr()?,
        sockets[1].local_addr()?,
        sockets[2].local_addr()?,
    ])
}
fn token(
    key: &EncodingKey,
    issuer: &str,
    audience: &str,
    tenant: &str,
    incarnation: uuid::Uuid,
) -> Result<Zeroizing<String>> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("fixture-issuer".into());
    header.typ = Some("at+jwt".into());
    Ok(Zeroizing::new(jsonwebtoken::encode(
        &header,
        &json!({"sub":"benchmark","tenant":tenant,"kasumi_resource":{"kind":"database","incarnation":incarnation},"scope":"kasumi:read kasumi:write kasumi:admin kasumi:audit","iss":issuer,"aud":audience,"exp":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()+86_400}),
        key,
    )?))
}
fn request<T>(value: T, token: &str) -> Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(value);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid generated bearer header"))?,
    );
    request.set_timeout(Duration::from_secs(30));
    Ok(request)
}
fn body(ordinal: usize) -> Value {
    let mut value = json!({"ordinal":ordinal,"version":0,"text":format!("token{:04} feature{:04} {}",ordinal%1000,ordinal%1000,if ordinal.is_multiple_of(1000){"図書館"}else{"動物"}),"padding":""});
    let size = serde_json::to_vec(&value).unwrap().len();
    value["padding"] = json!("x".repeat(1024usize.saturating_sub(size)));
    value
}
fn definition() -> CollectionDefinition {
    CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "docs".into(),
        schema: json!({"type":"object","required":["ordinal","version","text","padding"],"properties":{"ordinal":{"type":"integer"},"version":{"type":"integer"},"text":{"type":"string"},"padding":{"type":"string"}},"additionalProperties":false}),
        indexes: vec![IndexDefinition {
            name: "ordinal".into(),
            fields: vec![IndexField {
                path: "/ordinal".into(),
                kind: ScalarType::Number,
            }],
            unique: false,
            text: None,
        }],
        strict_read_audit: false,
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "benchmark".into(),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        }],
        strict_read_audit: false,
    }
}
async fn benchmark(
    documents: usize,
    tenants: usize,
    operations: usize,
    output: &Path,
) -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("kasumi-live-benchmark-")
        .tempdir()?;
    let path = temp.path();
    let authority = Authority::new()?;
    let ca = path.join("ca.pem");
    std::fs::write(&ca, &authority.pem)?;
    let server = authority.issue(path, "server")?;
    let client = authority.issue(path, "client")?;
    let issuer_socket = TcpListener::bind("127.0.0.1:0").await?;
    let issuer_url = format!("https://localhost:{}", issuer_socket.local_addr()?.port());
    let issuer_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"fixture-issuer","x":URL_SAFE_NO_PAD.encode(issuer_key.public_key_raw())}]});
    let signing_key = EncodingKey::from_ed_pem(issuer_key.serialize_pem().as_bytes())?;
    let (issuer_stop, shutdown) = watch::channel(false);
    let issuer = tokio::spawn(tls::serve_tls(
        issuer_socket,
        kasumi_transport::server_config(&identity(&server)?, ClientAuthentication::OAuth)?,
        Router::new().route(
            "/keys",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        ),
        ListenerLimits::default(),
        Arc::new(IssuerAudit),
        shutdown,
    ));
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux-amd64",
        _ => anyhow::bail!("no pinned OpenBao fixture for this platform"),
    };
    let bao_binary = std::env::var_os("KASUMI_OPENBAO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(format!("target/tools/openbao-2.6.2/{platform}/bao"))
        });
    let bao = fixture_bao::BaoFixture::start(&bao_binary).await?;
    ensure!(
        bao.directory().is_dir() && !bao.ca_pem.is_empty(),
        "Bao fixture state unavailable"
    );
    let [mcp, native, admin] = addresses()?;
    let audience = format!("https://localhost:{}/mcp", mcp.port());
    let mut config = example_config();
    // This benchmark explicitly exercises the fixture-only local deployment.
    // Its daemon must be built with kasumi-server/test-utils; production builds
    // reject this configuration instead of bypassing the serving authority.
    config.mode = kasumi_server::runtime::DeploymentMode::Standalone;
    config.replication = None;
    config.control.incarnation = None;
    config.serving_authorities.clear();
    config.signer_verifier = None;
    config.database_path = path.join("node.redb");
    config.scratch_disk.directory = path.join("scratch");
    config.auth = AuthConfig {
        issuer: issuer_url.clone(),
        audience: audience.clone(),
        source: kasumi_server::auth::AuthKeySource::ExternalOAuth {
            jwks_uri: format!("{issuer_url}/keys"),
            trusted_ca_pem: Some(authority.pem.clone()),
        },
        algorithms: vec![Algorithm::EdDSA],
        access_token_types: BTreeSet::from(["at+jwt".into()]),
    };
    config.mcp.listen = mcp;
    config.mcp.tls = server.clone();
    config.mcp.protocol = McpConfig::new(audience.clone())?;
    config.native.listen = native;
    config.native.tls = server.clone();
    config.native.client_ca = ca.clone();
    config.admin.listen = admin;
    config.admin.tls = server.clone();
    config.admin.client_ca = ca.clone();
    let transit = |key: &str, env: &str| {
        KeyProviderSettings::Transit(TransitSettings {
            endpoint: bao.endpoint.clone(),
            mount: "transit".into(),
            key_name: key.into(),
            token_file: path.join(env).to_string_lossy().into_owned(),
            namespace: None,
            ca_certificate: Some(bao.ca_path.clone()),
            derived: false,
        })
    };
    let mut secrets = Vec::new();
    let control = bao.provision_key("control", false).await?;
    secrets.push(("KASUMI_BENCH_CONTROL".to_owned(), Zeroizing::new(control)));
    config.control.keys = transit("control", "KASUMI_BENCH_CONTROL");
    let custody_control = bao.provision_key("control-custody", false).await?;
    secrets.push((
        "KASUMI_BENCH_CONTROL_CUSTODY".to_owned(),
        Zeroizing::new(custody_control),
    ));
    config.control.custody_keys = transit("control-custody", "KASUMI_BENCH_CONTROL_CUSTODY");
    config.control.initial_policy = policy();
    let security = bao.provision_key("security", false).await?;
    secrets.push(("KASUMI_BENCH_SECURITY".to_owned(), Zeroizing::new(security)));
    config.security_audit.keys = transit("security", "KASUMI_BENCH_SECURITY");
    config.tenants.clear();
    let mut oauth = Vec::new();
    let mut targets = Vec::new();
    for tenant in 0..tenants {
        let name = format!("bench-{tenant:04}");
        let incarnation = uuid::Uuid::new_v4();
        let env = format!("KASUMI_BENCH_TRANSIT_{tenant}");
        let secret = bao.provision_key(&name, false).await?;
        secrets.push((env.clone(), Zeroizing::new(secret)));
        let custody_name = format!("{name}-custody");
        let custody_env = format!("KASUMI_BENCH_CUSTODY_{tenant}");
        let custody_secret = bao.provision_key(&custody_name, false).await?;
        secrets.push((custody_env.clone(), Zeroizing::new(custody_secret)));
        let count = documents.div_ceil(tenants);
        config.tenants.push(TenantConfig {
            serving: kasumi_server::serving_runtime::TenantServingConfig::LocalFixture,
            tenant: name.clone(),
            keys: transit(&name, &env),
            custody_keys: transit(&custody_name, &custody_env),
            initial_policy: policy(),
            initial_limits: Limits {
                max_documents: count as u64 + 1,
                max_logical_bytes: (count as u64 + 1) * 2048,
                max_mutation_receipt_bytes: u64::try_from(
                    operations
                        .checked_mul(4)
                        .and_then(|n| n.checked_add(documents.div_ceil(256)))
                        .and_then(|n| n.checked_add(1000))
                        .context("receipt workload count overflow")?,
                )
                .context("receipt workload exceeds address space")?
                .checked_mul(2 << 20)
                .context("receipt workload byte budget overflow")?,
                ..Limits::default()
            },
            incarnation: Some(incarnation.to_string()),
        });
        let token_file = path.join(format!("access-{tenant}.token"));
        let access = token(&signing_key, &issuer_url, &audience, &name, incarnation)?;
        private(&token_file, access.as_bytes())?;
        oauth.push((token_file, access));
    }
    // Match the local harness's deterministic key sequence rather than repeatedly
    // measuring one hot document per tenant. Credential warmup remains separate.
    for operation in 0..operations.max(tenants).min(10_000) {
        let ordinal = operation.wrapping_mul(7919) % documents;
        let token_file = &oauth[ordinal % tenants].0;
        let mutation = path.join(format!("body-{ordinal}.json"));
        let mut value = body(ordinal);
        value["version"] = json!(1);
        std::fs::write(&mutation, serde_json::to_vec(&value)?)?;
        targets.push(json!({"token_file":token_file,"collection":"docs","id":ordinal.to_string(),"query":QueryRequest{collection:"docs".into(),filter:Predicate::Eq{field:"/ordinal".into(),value:json!(ordinal)},sort:Vec::new(),projection:vec!["/ordinal".into()],aggregates:Vec::new(),group_by:Vec::new(),text:None,limit:1000,cursor:None,allow_scan:false},"mutation_body":mutation}));
    }
    config.validate()?;
    let config_path = path.join("node.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    let executable = std::env::current_exe()?.parent().unwrap().to_owned();
    let server_executable_sha256 =
        hex::encode(Sha256::digest(std::fs::read(executable.join("kasumid"))?));
    let log = path.join("kasumid.log");
    let mut command = Command::new(executable.join("kasumid"));
    command
        .args(["serve", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log)?);
    for (name, secret) in &secrets {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))?;
        file.write_all(secret.as_bytes())?;
        file.sync_all()?;
    }
    let mut process =
        Process(Some(command.spawn().context(
            "build kasumid in the same profile before loopback benchmark",
        )?));
    let client_identity = identity(&client)?;
    let pin = kasumi_transport::certificate_pin(&std::fs::read(&server.certificate)?)?;
    let native_url = format!("https://localhost:{}", native.port());
    let admin_url = format!("https://localhost:{}", admin.port());
    let opened = Instant::now();
    let channel = loop {
        match kasumi_transport::grpc_channel(
            &admin_url,
            &client_identity,
            authority.pem.as_bytes(),
            BTreeSet::from([pin]),
        )
        .await
        {
            Ok(channel) => break channel,
            Err(_) => {
                if let Some(child) = &mut process.0
                    && child.try_wait()?.is_some()
                {
                    let message = std::fs::read_to_string(&log).unwrap_or_default();
                    anyhow::bail!("kasumid exited before readiness: {message}");
                }
                ensure!(
                    opened.elapsed() < Duration::from_secs(300 + tenants as u64),
                    "kasumid readiness timed out"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let mut admin_client = proto::kasumi_admin_client::KasumiAdminClient::new(channel);
    let channel = kasumi_transport::grpc_channel(
        &native_url,
        &client_identity,
        authority.pem.as_bytes(),
        BTreeSet::from([pin]),
    )
    .await?;
    let mut data = proto::kasumi_data_client::KasumiDataClient::new(channel);
    let open_seconds = opened.elapsed().as_secs_f64();
    let server_pid = process.0.as_ref().unwrap().id();
    let empty_rss_bytes = resident_bytes(server_pid);
    let invalid = data
        .collections(request(proto::CollectionsRequest {}, "forged")?)
        .await
        .unwrap_err();
    ensure!(
        invalid.code() == tonic::Code::Unauthenticated,
        "invalid JWT was not rejected over native TLS"
    );
    let forbidden_token = token(
        &signing_key,
        &issuer_url,
        &audience,
        "unconfigured-tenant",
        uuid::Uuid::new_v4(),
    )?;
    let denied = data
        .collections(request(proto::CollectionsRequest {}, &forbidden_token)?)
        .await
        .unwrap_err();
    ensure!(
        denied.code() == tonic::Code::PermissionDenied,
        "unconfigured tenant was not rejected over native TLS"
    );
    let http = reqwest::Client::builder()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(reqwest::Certificate::from_pem(authority.pem.as_bytes())?)
        .build()?;
    let denied = http
        .post(&audience)
        .header("authorization", "Bearer forged")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .send()
        .await?;
    ensure!(
        denied.status() == reqwest::StatusCode::UNAUTHORIZED,
        "invalid JWT was not rejected over MCP TLS"
    );

    let collection_setup = Instant::now();
    for (_, token) in &oauth {
        admin_client
            .create_collection(request(
                proto::CollectionDefinitionRequest {
                    definition_json: serde_json::to_vec(&definition())?,
                },
                token,
            )?)
            .await?;
    }
    let collection_setup_seconds = collection_setup.elapsed().as_secs_f64();
    let empty_index_rss_bytes = resident_bytes(server_pid);
    let load = Instant::now();
    for (tenant, (_, token)) in oauth.iter().enumerate() {
        let mut operations_batch = Vec::new();
        let mut batch = 0;
        for ordinal in (tenant..documents).step_by(tenants) {
            operations_batch.push(Mutation::Put {
                collection: "docs".into(),
                id: ordinal.to_string(),
                body: body(ordinal),
                expected: Precondition::Absent,
            });
            if operations_batch.len() == 256 {
                data.mutate(request(
                    proto::MutateRequest {
                        batch_json: serde_json::to_vec(&MutationBatch {
                            read_set: Vec::new(),
                            idempotency_key: format!("load-{batch}"),
                            operations: std::mem::take(&mut operations_batch),
                        })?,
                    },
                    token,
                )?)
                .await?;
                batch += 1;
            }
        }
        if !operations_batch.is_empty() {
            data.mutate(request(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&MutationBatch {
                        read_set: Vec::new(),
                        idempotency_key: format!("load-{batch}"),
                        operations: operations_batch,
                    })?,
                },
                token,
            )?)
            .await?;
        }
        if (tenant + 1) % 100 == 0 || tenants == 1 {
            eprintln!("network fixture loaded tenant {}/{tenants}", tenant + 1);
        }
    }
    let load_seconds = load.elapsed().as_secs_f64();
    let rss = resident_bytes(server_pid);
    let mut cases = Vec::new();
    for (protocol, endpoint) in [("grpc", native_url.clone()), ("mcp", audience)] {
        cases.push(json!({"name":format!("{protocol}-{tenants}-tenants"),"protocol":protocol,"endpoint":endpoint,"ca_pem":ca,"client_certificate_pem":client.certificate,"client_private_key_pem":client.private_key,"server_certificate_sha256":if protocol=="grpc"{Some(hex::encode(pin))}else{None},"operations":operations,"targets":targets}));
    }
    let network_config = path.join("network.json");
    std::fs::write(
        &network_config,
        serde_json::to_vec_pretty(&json!({"cases":cases}))?,
    )?;
    let mut network = Command::new(executable.join("kasumi-bench-network"));
    network
        .arg(&network_config)
        .arg(output)
        .arg("--allow-writes");
    let mut network = Process(Some(
        network
            .spawn()
            .context("build kasumi-bench-network in same profile first")?,
    ));
    let status = loop {
        if let Some(status) = network.0.as_mut().unwrap().try_wait()? {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    network.0.take();
    let mut report: Value = serde_json::from_slice(&std::fs::read(output)?)?;
    report["fixture"] = json!({"database":"real separate kasumid NodeRuntime process","kms":"real local OpenBao 2.6.2 TLS Transit, separate wrapping keys and scoped tokens for data/control/security","issuer":"ephemeral signed Ed25519 access tokens and real TLS JWKS requests","deployment":"local one voter, durable mutation, authentication and engine denial audits enabled; one independently encrypted security audit shared by all node tenants; strict read audit disabled","documents":documents,"tenants":tenants,"payload_bytes_each":1024,"security_audit_stores":1,"runtime_open_seconds":open_seconds,"server_empty_rss_bytes":empty_rss_bytes,"collection_setup_seconds":collection_setup_seconds,"server_empty_index_rss_bytes":empty_index_rss_bytes,"load_seconds":load_seconds,"server_after_workload_rss_bytes":resident_bytes(server_pid),"server_resident_rss_bytes":rss,"server_disk_bytes":std::fs::metadata(&config.database_path)?.len(),"server_executable_sha256":server_executable_sha256,"server_profile":if cfg!(debug_assertions){"debug"}else{"release"},"network":"loopback TCP/TLS1.3, native mTLS, warm persistent connections; not a physical distributed network","access_checks":"native invalid JWT and signed unconfigured tenant rejected; MCP invalid JWT rejected before measurement"});
    report["fixture"]["phase"] = json!("shutting_down");
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    drop(data);
    drop(admin_client);
    let shutdown = Instant::now();
    process.shutdown().await?;
    report["fixture"]["shutdown_seconds"] = json!(shutdown.elapsed().as_secs_f64());
    report["fixture"]["phase"] = json!("recovering");
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    let recovery = Instant::now();
    process = Process(Some(
        command
            .spawn()
            .context("restart kasumid for recovery measurement")?,
    ));
    let channel = loop {
        match kasumi_transport::grpc_channel(
            &native_url,
            &client_identity,
            authority.pem.as_bytes(),
            BTreeSet::from([pin]),
        )
        .await
        {
            Ok(channel) => break channel,
            Err(_) => {
                ensure!(
                    process.0.as_mut().unwrap().try_wait()?.is_none(),
                    "kasumid exited during recovery"
                );
                ensure!(
                    recovery.elapsed() < Duration::from_secs(300 + tenants as u64),
                    "kasumid recovery timed out"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let mut recovered = proto::kasumi_data_client::KasumiDataClient::new(channel);
    for (tenant, (_, token)) in oauth.iter().enumerate() {
        let document = recovered
            .get(request(
                proto::GetRequest {
                    collection: "docs".into(),
                    id: tenant.to_string(),
                },
                token,
            )?)
            .await?
            .into_inner();
        let document: Value = serde_json::from_slice(&document.body_json)?;
        ensure!(
            document["ordinal"] == json!(tenant),
            "network recovery document mismatch"
        );
    }
    report["fixture"]["recovery_seconds"] = json!(recovery.elapsed().as_secs_f64());
    report["fixture"]["server_after_recovery_rss_bytes"] =
        json!(resident_bytes(process.0.as_ref().unwrap().id()));
    report["fixture"]["phase"] = json!("recovered");
    report["fixture"]["recovery_contract"] = json!(
        "Shutdown measures SIGTERM through successful kasumid process exit. Recovery starts after shutdown and measures a fresh kasumid process spawn, index reconstruction, key access, readiness and one authenticated native read per tenant. The encrypted database is retained; issuer and OpenBao remain running. Final cleanup and crash tests are separate."
    );
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    drop(recovered);
    process.shutdown().await?;
    issuer_stop.send_replace(true);
    issuer.await??;
    bao.shutdown().await?;
    ensure!(
        status.success(),
        "network workloads completed with recorded failures"
    );
    report["fixture"]["phase"] = json!("completed");
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut documents = 100;
    let mut tenants = vec![1, 3];
    let mut operations = 32;
    let mut output = PathBuf::from("benchmarks/results/network-loopback");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().context("option requires value")?;
        match arg.as_str() {
            "--documents" => documents = value.parse()?,
            "--tenants" => {
                tenants = value
                    .split(',')
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()?
            }
            "--operations" => operations = value.parse()?,
            "--output-prefix" => output = value.into(),
            _ => anyhow::bail!("unknown option"),
        }
    }
    ensure!(
        documents > 0
            && documents <= 1_000_000
            && operations > 0
            && operations <= 1_000_000
            && tenants
                .iter()
                .all(|n| *n > 0 && *n <= 1000 && *n <= documents),
        "invalid counts"
    );
    for tenant_count in tenants {
        eprintln!("starting live loopback benchmark tenants={tenant_count}, documents={documents}");
        let report = PathBuf::from(format!("{}-{tenant_count}.json", output.display()));
        if let Err(error) = benchmark(documents, tenant_count, operations, &report).await {
            if let Some(parent) = report.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let mut result = std::fs::read(&report)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .unwrap_or_else(
                    || json!({"format":1,"cases":[],"documents":documents,"tenants":tenant_count}),
                );
            result["fixture_error"] = json!(error.to_string());
            result["evidence_status"] = json!("failed development fixture; no success claimed");
            std::fs::write(&report, serde_json::to_vec_pretty(&result)?)?;
            return Err(error);
        }
    }
    Ok(())
}
