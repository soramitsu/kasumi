//! Closed-loop Kasumi/Redis comparison driver.
//!
//! One process drives one system with the same key space, document bytes,
//! concurrency, timing and percentile method, so the two sides differ only in
//! the server and its wire protocol. Each worker owns its own connections:
//! Kasumi native gRPC (TLS 1.3, mTLS, pinned server certificate, bearer token)
//! or Redis RESP2 (TLS 1.3, mTLS, ACL user and password). Results are JSON on
//! stdout or `--output`; bodies and secrets never enter them.
//!
//! `benchmarks/redis-comparison/run.py` installs both servers, matches their
//! durability, and records server-side RSS, CPU, physical disk writes and
//! startup/recovery time around these runs. See `benchmarks/REDIS-COMPARISON.md`.
use anyhow::{Context, Result, anyhow, bail, ensure};
use kasumi_client::{
    ClientDecodeLimits, ClientProfile, ClientResources, Kasumi, SnapshotReadOptions,
};
use kasumi_types::{
    CredentialResource, DocumentKey, Filter, MutationBatch, QueryRequest, ReadSnapshotRequest,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::Serialize;
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use zeroize::Zeroizing;

const USAGE: &str =
    "usage: kasumi-bench-compare --system kasumi|redis --workload WORKLOAD [options]

workloads: load point-read point-write mixed batch-read batch-write range-scan probe
common:    --keys N (100000) --value-bytes N (1024) --clients N (16)
           --duration-seconds S (20) --warmup-seconds S (2) --batch-size N (10)
           --scan-limit N (50) --load-batch N (100) --read-percent N (90)
           --seed N (1) --probe-timeout-seconds S (900) --output FILE
           --probe-ping true|false (false: probe reads key 0; true: a data-free call)
           --timeout-seconds S (60): Kasumi call deadline, including resends
kasumi:    --profile PROFILE.json --collection NAME (bench)
redis:     --redis-endpoint HOST:PORT --redis-ca PEM --redis-cert PEM --redis-key PEM
           --redis-user NAME --redis-password-file FILE [--redis-index true|false]";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
enum Workload {
    Load,
    PointRead,
    PointWrite,
    Mixed,
    BatchRead,
    BatchWrite,
    RangeScan,
    Probe,
}

impl Workload {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "load" => Self::Load,
            "point-read" => Self::PointRead,
            "point-write" => Self::PointWrite,
            "mixed" => Self::Mixed,
            "batch-read" => Self::BatchRead,
            "batch-write" => Self::BatchWrite,
            "range-scan" => Self::RangeScan,
            "probe" => Self::Probe,
            other => bail!("unknown workload {other}\n{USAGE}"),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
enum System {
    Kasumi,
    Redis,
}

#[derive(Clone)]
struct Options {
    system: System,
    workload: Workload,
    keys: u64,
    value_bytes: usize,
    clients: usize,
    duration: Duration,
    warmup: Duration,
    batch_size: usize,
    scan_limit: usize,
    load_batch: usize,
    read_percent: u64,
    seed: u64,
    probe_timeout: Duration,
    probe_ping: bool,
    timeout: Duration,
    output: Option<PathBuf>,
    profile: Option<PathBuf>,
    collection: String,
    redis: Option<RedisOptions>,
}

#[derive(Clone)]
struct RedisOptions {
    endpoint: String,
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    user: String,
    password_file: PathBuf,
    index: bool,
}

fn parse_options() -> Result<Options> {
    let mut arguments = std::env::args().skip(1);
    let mut values = std::collections::BTreeMap::<String, String>::new();
    while let Some(flag) = arguments.next() {
        if flag == "--help" || flag == "-h" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let name = flag
            .strip_prefix("--")
            .with_context(|| format!("unexpected argument {flag}\n{USAGE}"))?;
        let value = arguments
            .next()
            .with_context(|| format!("--{name} needs a value"))?;
        ensure!(
            values.insert(name.to_owned(), value).is_none(),
            "--{name} repeated"
        );
    }
    let mut take = |name: &str| values.remove(name);
    let number = |value: Option<String>, default: u64| -> Result<u64> {
        value.map_or(Ok(default), |v| {
            v.parse().with_context(|| format!("invalid number {v}"))
        })
    };
    let system = match take("system").as_deref() {
        Some("kasumi") => System::Kasumi,
        Some("redis") => System::Redis,
        _ => bail!("--system kasumi|redis is required\n{USAGE}"),
    };
    let workload = Workload::parse(&take("workload").context(USAGE)?)?;
    let redis = if system == System::Redis {
        Some(RedisOptions {
            endpoint: take("redis-endpoint").context("--redis-endpoint")?,
            ca: take("redis-ca").context("--redis-ca")?.into(),
            cert: take("redis-cert").context("--redis-cert")?.into(),
            key: take("redis-key").context("--redis-key")?.into(),
            user: take("redis-user").context("--redis-user")?,
            password_file: take("redis-password-file")
                .context("--redis-password-file")?
                .into(),
            index: match take("redis-index").as_deref() {
                None | Some("true") => true,
                Some("false") => false,
                Some(other) => bail!("--redis-index true|false, not {other}"),
            },
        })
    } else {
        None
    };
    let options = Options {
        system,
        workload,
        keys: number(take("keys"), 100_000)?,
        value_bytes: number(take("value-bytes"), 1024)? as usize,
        clients: number(take("clients"), 16)? as usize,
        duration: Duration::from_secs_f64(number(take("duration-seconds"), 20)? as f64),
        warmup: Duration::from_secs_f64(number(take("warmup-seconds"), 2)? as f64),
        batch_size: number(take("batch-size"), 10)? as usize,
        scan_limit: number(take("scan-limit"), 50)? as usize,
        load_batch: number(take("load-batch"), 100)? as usize,
        read_percent: number(take("read-percent"), 90)?,
        seed: number(take("seed"), 1)?,
        probe_timeout: Duration::from_secs(number(take("probe-timeout-seconds"), 900)?),
        timeout: Duration::from_secs(number(take("timeout-seconds"), 60)?),
        probe_ping: match take("probe-ping").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => bail!("--probe-ping true|false, not {other}"),
        },
        output: take("output").map(PathBuf::from),
        profile: take("profile").map(PathBuf::from),
        collection: take("collection").unwrap_or_else(|| "bench".into()),
        redis,
    };
    ensure!(
        values.is_empty(),
        "unknown options {:?}\n{USAGE}",
        values.keys()
    );
    ensure!(
        options.keys >= 1 && options.clients >= 1,
        "keys and clients must be positive"
    );
    ensure!(
        options.value_bytes >= 64,
        "--value-bytes must be at least 64"
    );
    ensure!(
        options.batch_size >= 1 && options.load_batch >= 1 && options.scan_limit >= 1,
        "batch sizes and scan limit must be positive"
    );
    ensure!(
        options.keys > options.scan_limit as u64,
        "--keys must exceed --scan-limit"
    );
    ensure!(options.read_percent <= 100, "--read-percent is 0..=100");
    if options.system == System::Kasumi {
        ensure!(
            options.profile.is_some(),
            "--profile is required for kasumi"
        );
    }
    Ok(options)
}

/// splitmix64: small, deterministic and identical on both sides.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn key_id(index: u64) -> String {
    format!("k{index:010}")
}

/// Exactly `value_bytes` of compact JSON: `{"n":<index>,"v":<version>,"pad":"…"}`.
/// Both systems store these identical bytes; Kasumi indexes `/n`, and Redis
/// keeps the same value in the `idx:n` sorted set when its index is enabled.
fn document(index: u64, version: u64, value_bytes: usize, rng: &mut Rng) -> String {
    let prefix = format!("{{\"n\":{index},\"v\":{version},\"pad\":\"");
    let pad = value_bytes.saturating_sub(prefix.len() + 2);
    let mut body = String::with_capacity(value_bytes);
    body.push_str(&prefix);
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bits = 0u64;
    for position in 0..pad {
        if position % 8 == 0 {
            bits = rng.next();
        }
        body.push(ALPHABET[(bits & 63) as usize % ALPHABET.len()] as char);
        bits >>= 8;
    }
    body.push_str("\"}");
    body
}

#[derive(Serialize)]
struct Report {
    system: System,
    workload: Workload,
    clients: usize,
    keys: u64,
    value_bytes: usize,
    batch_size: usize,
    scan_limit: usize,
    read_percent: u64,
    redis_index: Option<bool>,
    warmup_seconds: f64,
    elapsed_seconds: f64,
    operations: u64,
    /// Documents read or written by successful operations.
    items: u64,
    /// Logical document bytes written by successful operations (body bytes plus
    /// id bytes), the denominator for write amplification.
    logical_bytes_written: u64,
    throughput_ops_per_second: f64,
    items_per_second: f64,
    p50_microseconds: Option<f64>,
    p90_microseconds: Option<f64>,
    p99_microseconds: Option<f64>,
    p999_microseconds: Option<f64>,
    max_microseconds: Option<f64>,
    errors: u64,
    first_error: Option<String>,
    probe_seconds: Option<f64>,
    client_load_average: [f64; 3],
}

fn load_average() -> [f64; 3] {
    let mut values = [0f64; 3];
    // SAFETY: getloadavg writes at most `values.len()` doubles.
    let count = unsafe { libc::getloadavg(values.as_mut_ptr(), 3) };
    if count != 3 {
        return [f64::NAN; 3];
    }
    values
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (sorted.len() * numerator).div_ceil(denominator).max(1) - 1;
    Some(sorted[rank.min(sorted.len() - 1)] as f64 / 1000.0)
}

/// One operation's outcome: documents touched and logical bytes written.
#[derive(Default, Clone, Copy)]
struct Done {
    items: u64,
    written: u64,
}

#[derive(Default)]
struct Totals {
    samples: Vec<u64>,
    items: u64,
    written: u64,
    errors: u64,
    first_error: Option<String>,
}

#[async_trait::async_trait]
trait Driver: Send {
    /// One authenticated round trip that needs no data.
    async fn ping(&mut self) -> Result<()>;
    async fn read(&mut self, index: u64) -> Result<Done>;
    async fn write(&mut self, index: u64, body: String) -> Result<Done>;
    async fn batch_read(&mut self, indexes: &[u64]) -> Result<Done>;
    async fn batch_write(&mut self, writes: Vec<(u64, String)>) -> Result<Done>;
    async fn range(&mut self, start: u64, limit: usize) -> Result<Done>;
}

// ---------------------------------------------------------------- Kasumi

struct KasumiDriver {
    db: Kasumi,
    collection: String,
    incarnation: uuid::Uuid,
    credential: Arc<CachedToken>,
    timeout: Duration,
}

/// The bearer file is reread at most once per second rather than on every
/// call, so driver-side file I/O does not pollute server-side latency.
struct CachedToken {
    path: PathBuf,
    cached: Mutex<(Instant, Zeroizing<String>)>,
}
impl CachedToken {
    fn new(path: PathBuf) -> Result<Self> {
        let token = read_token(&path)?;
        Ok(Self {
            path,
            cached: Mutex::new((Instant::now(), token)),
        })
    }
    fn load(&self) -> anyhow::Result<Zeroizing<String>> {
        let mut cached = self.cached.lock().unwrap();
        if cached.0.elapsed() >= Duration::from_secs(1) {
            *cached = (Instant::now(), read_token(&self.path)?);
        }
        Ok(cached.1.clone())
    }
}
fn read_token(path: &PathBuf) -> Result<Zeroizing<String>> {
    let text = Zeroizing::new(std::fs::read_to_string(path).context("read bearer file")?);
    Ok(Zeroizing::new(text.trim().to_owned()))
}

impl KasumiDriver {
    async fn connect(options: &Options) -> Result<Self> {
        let profile = ClientProfile::load(options.profile.as_ref().unwrap())?;
        let incarnation = match profile.resource {
            CredentialResource::Database { incarnation } => incarnation,
            _ => bail!("profile is not a database profile"),
        };
        let credential = Arc::new(CachedToken::new(profile.bearer_file.clone())?);
        let source = credential.clone();
        let db = Kasumi::connect(&profile.connection(false)?, move || source.load())
            .await
            .context("connect Kasumi")?
            .with_timeout(options.timeout);
        Ok(Self {
            db,
            collection: options.collection.clone(),
            incarnation,
            credential,
            timeout: options.timeout,
        })
    }
}

#[async_trait::async_trait]
impl Driver for KasumiDriver {
    async fn ping(&mut self) -> Result<()> {
        let collections = self.db.collections().await?;
        ensure!(
            collections
                .iter()
                .any(|definition| definition.name == self.collection),
            "collection {} is not installed",
            self.collection
        );
        Ok(())
    }
    async fn read(&mut self, index: u64) -> Result<Done> {
        let document = self.db.get(&self.collection, &key_id(index)).await?;
        ensure!(document.is_some(), "document {index} missing");
        Ok(Done {
            items: 1,
            written: 0,
        })
    }
    async fn write(&mut self, index: u64, body: String) -> Result<Done> {
        let id = key_id(index);
        let written = (id.len() + body.len()) as u64;
        let value: Value = serde_json::from_str(&body)?;
        self.db
            .mutate(&MutationBatch::new().upsert(&self.collection, &id, value))
            .await?;
        Ok(Done { items: 1, written })
    }
    async fn batch_read(&mut self, indexes: &[u64]) -> Result<Done> {
        let request = ReadSnapshotRequest {
            documents: indexes
                .iter()
                .map(|index| DocumentKey {
                    collection: self.collection.clone(),
                    id: key_id(*index),
                })
                .collect(),
            queries: Vec::new(),
            time_bounds: None,
        };
        let limits = ClientDecodeLimits::default();
        let options = SnapshotReadOptions {
            resources: ClientResources::new(limits.accounted_bytes()?, 1)?,
            limits,
            deadline: tokio::time::Instant::now() + self.timeout,
            expected_incarnation: self.incarnation,
        };
        let token = self.credential.load()?;
        let response = self
            .db
            .client()
            .read_snapshot(&token, &request, &options)
            .await?;
        let found = response
            .documents
            .iter()
            .filter(|row| row.document.is_some())
            .count();
        ensure!(
            found == indexes.len(),
            "batch read found {found}/{}",
            indexes.len()
        );
        Ok(Done {
            items: found as u64,
            written: 0,
        })
    }
    async fn batch_write(&mut self, writes: Vec<(u64, String)>) -> Result<Done> {
        let mut batch = MutationBatch::new();
        let mut written = 0;
        let items = writes.len() as u64;
        for (index, body) in writes {
            let id = key_id(index);
            written += (id.len() + body.len()) as u64;
            batch = batch.upsert(&self.collection, &id, serde_json::from_str::<Value>(&body)?);
        }
        self.db.mutate(&batch).await?;
        Ok(Done { items, written })
    }
    async fn range(&mut self, start: u64, limit: usize) -> Result<Done> {
        let query = QueryRequest::new(&self.collection)
            .filter(
                Filter::new()
                    .gte("/n", start)
                    .lt("/n", start + limit as u64),
            )
            .sort_asc("/n")
            .limit(limit);
        let page = self.db.query(&query).await?;
        let rows = page.rows().len();
        ensure!(rows == limit, "range returned {rows}/{limit} rows");
        Ok(Done {
            items: rows as u64,
            written: 0,
        })
    }
}

// ---------------------------------------------------------------- Redis

// Payloads of status and integer replies are shown only in error messages.
#[derive(Debug)]
#[allow(dead_code)]
enum Reply {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Reply>>),
}

impl Reply {
    fn ok(self) -> Result<Self> {
        match self {
            Reply::Error(message) => Err(anyhow!("redis error: {message}")),
            Reply::Array(Some(items)) => {
                for item in &items {
                    if let Reply::Error(message) = item {
                        bail!("redis error: {message}");
                    }
                }
                Ok(Reply::Array(Some(items)))
            }
            other => Ok(other),
        }
    }
}

type RedisStream = BufStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

struct RedisConnection {
    stream: RedisStream,
    scratch: Vec<u8>,
}

impl RedisConnection {
    async fn connect(options: &RedisOptions) -> Result<Self> {
        let roots = {
            let mut store = rustls::RootCertStore::empty();
            for certificate in CertificateDer::pem_file_iter(&options.ca)? {
                store.add(certificate?)?;
            }
            store
        };
        let chain = CertificateDer::pem_file_iter(&options.cert)?.collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&options.key)?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
        let socket = tokio::net::TcpStream::connect(&options.endpoint).await?;
        socket.set_nodelay(true)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut connection = Self {
            stream: BufStream::new(tls),
            scratch: Vec::new(),
        };
        let password = read_token(&options.password_file)?;
        connection
            .call(&[b"AUTH", options.user.as_bytes(), password.as_bytes()])
            .await?
            .ok()?;
        Ok(connection)
    }

    fn encode(&mut self, arguments: &[&[u8]]) {
        let buffer = &mut self.scratch;
        buffer.extend_from_slice(format!("*{}\r\n", arguments.len()).as_bytes());
        for argument in arguments {
            buffer.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
            buffer.extend_from_slice(argument);
            buffer.extend_from_slice(b"\r\n");
        }
    }

    async fn flush(&mut self) -> Result<()> {
        self.stream.write_all(&self.scratch).await?;
        self.scratch.clear();
        self.stream.flush().await?;
        Ok(())
    }

    async fn call(&mut self, arguments: &[&[u8]]) -> Result<Reply> {
        self.encode(arguments);
        self.flush().await?;
        read_reply(&mut self.stream).await
    }

    /// Send every command in one write, then read every reply in order.
    async fn pipeline(&mut self, commands: &[Vec<&[u8]>]) -> Result<Vec<Reply>> {
        for command in commands {
            self.encode(command);
        }
        self.flush().await?;
        let mut replies = Vec::with_capacity(commands.len());
        for _ in commands {
            replies.push(read_reply(&mut self.stream).await?);
        }
        Ok(replies)
    }
}

async fn read_line(stream: &mut RedisStream) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    stream.read_until(b'\n', &mut line).await?;
    ensure!(line.ends_with(b"\r\n"), "truncated RESP line");
    line.truncate(line.len() - 2);
    Ok(line)
}

fn read_reply(
    stream: &mut RedisStream,
) -> std::pin::Pin<Box<dyn Future<Output = Result<Reply>> + Send + '_>> {
    Box::pin(async move {
        let line = read_line(stream).await?;
        ensure!(!line.is_empty(), "empty RESP line");
        let text = std::str::from_utf8(&line[1..])?;
        Ok(match line[0] {
            b'+' => Reply::Simple(text.to_owned()),
            b'-' => Reply::Error(text.to_owned()),
            b':' => Reply::Integer(text.parse()?),
            b'$' => {
                let length: i64 = text.parse()?;
                if length < 0 {
                    Reply::Bulk(None)
                } else {
                    let mut body = vec![0; length as usize + 2];
                    stream.read_exact(&mut body).await?;
                    body.truncate(length as usize);
                    Reply::Bulk(Some(body))
                }
            }
            b'*' => {
                let length: i64 = text.parse()?;
                if length < 0 {
                    Reply::Array(None)
                } else {
                    let mut items = Vec::with_capacity(length as usize);
                    for _ in 0..length {
                        items.push(read_reply(stream).await?);
                    }
                    Reply::Array(Some(items))
                }
            }
            other => bail!("unknown RESP type {other}"),
        })
    })
}

/// ZRANGE BYSCORE then MGET in one server-side step, the single-round-trip
/// equivalent of Kasumi's indexed range query.
const RANGE_SCRIPT: &str = "local ids = redis.call('ZRANGE', KEYS[1], ARGV[1], ARGV[2], 'BYSCORE', 'LIMIT', 0, ARGV[3]) \
if #ids == 0 then return {} end \
for i = 1, #ids do ids[i] = 'doc:' .. ids[i] end \
return redis.call('MGET', unpack(ids))";

struct RedisDriver {
    connection: RedisConnection,
    index: bool,
    range_sha: Option<String>,
}

fn redis_key(index: u64) -> String {
    format!("doc:{}", key_id(index))
}

impl RedisDriver {
    async fn connect(options: &RedisOptions) -> Result<Self> {
        Ok(Self {
            connection: RedisConnection::connect(options).await?,
            index: options.index,
            range_sha: None,
        })
    }
}

fn bulk_present(reply: &Reply) -> bool {
    matches!(reply, Reply::Bulk(Some(_)))
}

#[async_trait::async_trait]
impl Driver for RedisDriver {
    async fn ping(&mut self) -> Result<()> {
        let reply = self.connection.call(&[b"PING"]).await?.ok()?;
        ensure!(
            matches!(reply, Reply::Simple(ref pong) if pong == "PONG"),
            "PING returned {reply:?}"
        );
        Ok(())
    }
    async fn read(&mut self, index: u64) -> Result<Done> {
        let key = redis_key(index);
        let reply = self
            .connection
            .call(&[b"GET", key.as_bytes()])
            .await?
            .ok()?;
        ensure!(bulk_present(&reply), "document {index} missing");
        Ok(Done {
            items: 1,
            written: 0,
        })
    }
    async fn write(&mut self, index: u64, body: String) -> Result<Done> {
        let key = redis_key(index);
        let id = key_id(index);
        let written = (id.len() + body.len()) as u64;
        if self.index {
            // Document and index entry change atomically, as in Kasumi.
            let score = index.to_string();
            let replies = self
                .connection
                .pipeline(&[
                    vec![b"MULTI".as_slice()],
                    vec![b"SET", key.as_bytes(), body.as_bytes()],
                    vec![b"ZADD", b"idx:n", score.as_bytes(), id.as_bytes()],
                    vec![b"EXEC"],
                ])
                .await?;
            for reply in replies {
                reply.ok()?;
            }
        } else {
            self.connection
                .call(&[b"SET", key.as_bytes(), body.as_bytes()])
                .await?
                .ok()?;
        }
        Ok(Done { items: 1, written })
    }
    async fn batch_read(&mut self, indexes: &[u64]) -> Result<Done> {
        let keys: Vec<String> = indexes.iter().map(|index| redis_key(*index)).collect();
        let mut command: Vec<&[u8]> = vec![b"MGET"];
        command.extend(keys.iter().map(|key| key.as_bytes()));
        let reply = self.connection.call(&command).await?.ok()?;
        let Reply::Array(Some(values)) = reply else {
            bail!("MGET returned {reply:?}");
        };
        let found = values.iter().filter(|value| bulk_present(value)).count();
        ensure!(
            found == indexes.len(),
            "batch read found {found}/{}",
            indexes.len()
        );
        Ok(Done {
            items: found as u64,
            written: 0,
        })
    }
    async fn batch_write(&mut self, writes: Vec<(u64, String)>) -> Result<Done> {
        let keys: Vec<(String, String, String)> = writes
            .iter()
            .map(|(index, _)| (redis_key(*index), key_id(*index), index.to_string()))
            .collect();
        let mut written = 0;
        let mut mset: Vec<&[u8]> = vec![b"MSET"];
        let mut zadd: Vec<&[u8]> = vec![b"ZADD", b"idx:n"];
        for ((key, id, score), (_, body)) in keys.iter().zip(&writes) {
            written += (id.len() + body.len()) as u64;
            mset.push(key.as_bytes());
            mset.push(body.as_bytes());
            zadd.push(score.as_bytes());
            zadd.push(id.as_bytes());
        }
        let commands = if self.index {
            vec![vec![b"MULTI".as_slice()], mset, zadd, vec![b"EXEC"]]
        } else {
            vec![mset]
        };
        for reply in self.connection.pipeline(&commands).await? {
            reply.ok()?;
        }
        Ok(Done {
            items: writes.len() as u64,
            written,
        })
    }
    async fn range(&mut self, start: u64, limit: usize) -> Result<Done> {
        ensure!(self.index, "range-scan needs --redis-index true");
        if self.range_sha.is_none() {
            let reply = self
                .connection
                .call(&[b"SCRIPT", b"LOAD", RANGE_SCRIPT.as_bytes()])
                .await?
                .ok()?;
            let Reply::Bulk(Some(sha)) = reply else {
                bail!("SCRIPT LOAD returned {reply:?}");
            };
            self.range_sha = Some(String::from_utf8(sha)?);
        }
        let minimum = start.to_string();
        let maximum = format!("({}", start + limit as u64);
        let count = limit.to_string();
        let sha = self.range_sha.clone().unwrap();
        let reply = self
            .connection
            .call(&[
                b"EVALSHA",
                sha.as_bytes(),
                b"1",
                b"idx:n",
                minimum.as_bytes(),
                maximum.as_bytes(),
                count.as_bytes(),
            ])
            .await?
            .ok()?;
        let Reply::Array(Some(values)) = reply else {
            bail!("range script returned {reply:?}");
        };
        let rows = values.iter().filter(|value| bulk_present(value)).count();
        ensure!(rows == limit, "range returned {rows}/{limit} rows");
        Ok(Done {
            items: rows as u64,
            written: 0,
        })
    }
}

async fn connect(options: &Options) -> Result<Box<dyn Driver>> {
    Ok(match options.system {
        System::Kasumi => Box::new(KasumiDriver::connect(options).await?),
        System::Redis => Box::new(RedisDriver::connect(options.redis.as_ref().unwrap()).await?),
    })
}

/// One operation of the measured workload, chosen from the worker's stream.
async fn operate(
    driver: &mut dyn Driver,
    options: &Options,
    rng: &mut Rng,
    version: &AtomicU64,
) -> Result<Done> {
    let keys = options.keys;
    let write = |rng: &mut Rng| {
        let index = rng.below(keys);
        let body = document(
            index,
            version.fetch_add(1, Ordering::Relaxed),
            options.value_bytes,
            rng,
        );
        (index, body)
    };
    match options.workload {
        Workload::PointRead => driver.read(rng.below(keys)).await,
        Workload::PointWrite => {
            let (index, body) = write(rng);
            driver.write(index, body).await
        }
        Workload::Mixed => {
            if rng.below(100) < options.read_percent {
                driver.read(rng.below(keys)).await
            } else {
                let (index, body) = write(rng);
                driver.write(index, body).await
            }
        }
        Workload::BatchRead => {
            let indexes = distinct(rng, keys, options.batch_size);
            driver.batch_read(&indexes).await
        }
        Workload::BatchWrite => {
            let indexes = distinct(rng, keys, options.batch_size);
            let writes = indexes
                .into_iter()
                .map(|index| {
                    let body = document(
                        index,
                        version.fetch_add(1, Ordering::Relaxed),
                        options.value_bytes,
                        rng,
                    );
                    (index, body)
                })
                .collect();
            driver.batch_write(writes).await
        }
        Workload::RangeScan => {
            let start = rng.below(keys - options.scan_limit as u64 + 1);
            driver.range(start, options.scan_limit).await
        }
        Workload::Load | Workload::Probe => unreachable!(),
    }
}

/// `count` distinct keys; a batch never names one document twice.
fn distinct(rng: &mut Rng, keys: u64, count: usize) -> Vec<u64> {
    let mut chosen = Vec::with_capacity(count);
    while chosen.len() < count.min(keys as usize) {
        let index = rng.below(keys);
        if !chosen.contains(&index) {
            chosen.push(index);
        }
    }
    chosen
}

async fn measured(options: Options) -> Result<Report> {
    let version = Arc::new(AtomicU64::new(1));
    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let mut drivers = Vec::with_capacity(options.clients);
    for _ in 0..options.clients {
        drivers.push(connect(&options).await?);
    }
    let mut workers = Vec::new();
    for (worker, mut driver) in drivers.into_iter().enumerate() {
        let options = options.clone();
        let version = version.clone();
        let recording = recording.clone();
        let stop = stop.clone();
        workers.push(tokio::spawn(async move {
            let mut rng = Rng(options.seed.wrapping_mul(1_000_003) ^ (worker as u64 + 1) << 32);
            let mut totals = Totals::default();
            while !stop.load(Ordering::Relaxed) {
                let record = recording.load(Ordering::Relaxed);
                let started = Instant::now();
                let outcome = operate(driver.as_mut(), &options, &mut rng, &version).await;
                let elapsed = started.elapsed();
                if !record {
                    continue;
                }
                match outcome {
                    Ok(done) => {
                        totals.samples.push(elapsed.as_nanos() as u64);
                        totals.items += done.items;
                        totals.written += done.written;
                    }
                    Err(error) => {
                        totals.errors += 1;
                        if totals.first_error.is_none() {
                            totals.first_error = Some(format!("{error:#}"));
                        }
                        // A failing server is not hammered at full speed.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
            totals
        }));
    }
    tokio::time::sleep(options.warmup).await;
    recording.store(true, Ordering::Relaxed);
    let started = Instant::now();
    tokio::time::sleep(options.duration).await;
    stop.store(true, Ordering::Relaxed);
    let mut merged = Totals::default();
    for worker in workers {
        let mut totals = worker.await?;
        merged.samples.append(&mut totals.samples);
        merged.items += totals.items;
        merged.written += totals.written;
        merged.errors += totals.errors;
        if merged.first_error.is_none() {
            merged.first_error = totals.first_error;
        }
    }
    // Operations in flight at the stop signal finish after it; the interval
    // covers them so throughput is not overstated.
    let elapsed = started.elapsed();
    Ok(report(&options, merged, elapsed, None))
}

fn report(options: &Options, mut totals: Totals, elapsed: Duration, probe: Option<f64>) -> Report {
    totals.samples.sort_unstable();
    let operations = totals.samples.len() as u64;
    let seconds = elapsed.as_secs_f64();
    Report {
        system: options.system,
        workload: options.workload,
        clients: options.clients,
        keys: options.keys,
        value_bytes: options.value_bytes,
        batch_size: options.batch_size,
        scan_limit: options.scan_limit,
        read_percent: options.read_percent,
        redis_index: options.redis.as_ref().map(|redis| redis.index),
        warmup_seconds: options.warmup.as_secs_f64(),
        elapsed_seconds: seconds,
        operations,
        items: totals.items,
        logical_bytes_written: totals.written,
        throughput_ops_per_second: operations as f64 / seconds,
        items_per_second: totals.items as f64 / seconds,
        p50_microseconds: percentile(&totals.samples, 50, 100),
        p90_microseconds: percentile(&totals.samples, 90, 100),
        p99_microseconds: percentile(&totals.samples, 99, 100),
        p999_microseconds: percentile(&totals.samples, 999, 1000),
        max_microseconds: totals.samples.last().map(|value| *value as f64 / 1000.0),
        errors: totals.errors,
        first_error: totals.first_error,
        probe_seconds: probe,
        client_load_average: load_average(),
    }
}

/// Write every key once, in disjoint ranges per client, `load_batch` per call.
async fn load(options: Options) -> Result<Report> {
    let started = Instant::now();
    let next = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for worker in 0..options.clients {
        let options = options.clone();
        let next = next.clone();
        workers.push(tokio::spawn(async move {
            let mut driver = connect(&options).await?;
            let mut rng = Rng(options.seed ^ 0x5eed_0000 ^ worker as u64);
            let mut totals = Totals::default();
            loop {
                let first = next.fetch_add(options.load_batch as u64, Ordering::Relaxed);
                if first >= options.keys {
                    break;
                }
                let last = (first + options.load_batch as u64).min(options.keys);
                let writes = (first..last)
                    .map(|index| (index, document(index, 0, options.value_bytes, &mut rng)))
                    .collect();
                let begun = Instant::now();
                let done = driver
                    .batch_write(writes)
                    .await
                    .with_context(|| format!("load batch at {first}"))?;
                totals.samples.push(begun.elapsed().as_nanos() as u64);
                totals.items += done.items;
                totals.written += done.written;
            }
            anyhow::Ok(totals)
        }));
    }
    let mut merged = Totals::default();
    for worker in workers {
        let mut totals = worker.await??;
        merged.samples.append(&mut totals.samples);
        merged.items += totals.items;
        merged.written += totals.written;
    }
    ensure!(
        merged.items == options.keys,
        "loaded {} of {} keys",
        merged.items,
        options.keys
    );
    Ok(report(&options, merged, started.elapsed(), None))
}

/// Connect and read key 0 (or ping) until it succeeds: the client-visible end
/// of a startup or recovery. The caller starts its clock before spawning the
/// server.
async fn probe(options: Options) -> Result<Report> {
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < options.probe_timeout {
        let attempt = async {
            let mut driver = connect(&options).await?;
            if options.probe_ping {
                driver.ping().await.map(|()| Done::default())
            } else {
                driver.read(0).await
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), attempt).await {
            Ok(Ok(_)) => {
                let elapsed = started.elapsed();
                let mut totals = Totals::default();
                totals.samples.push(elapsed.as_nanos() as u64);
                totals.items = 1;
                return Ok(report(
                    &options,
                    totals,
                    elapsed,
                    Some(elapsed.as_secs_f64()),
                ));
            }
            Ok(Err(error)) => last_error = Some(format!("{error:#}")),
            Err(_) => last_error = Some("probe attempt timed out".into()),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    bail!(
        "probe did not succeed within {:?}: {}",
        options.probe_timeout,
        last_error.unwrap_or_default()
    )
}

fn main() -> Result<()> {
    let options = parse_options()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(options.clients.clamp(2, 8))
        .enable_all()
        .build()?;
    let output = options.output.clone();
    let report = runtime.block_on(async move {
        match options.workload {
            Workload::Load => load(options).await,
            Workload::Probe => probe(options).await,
            _ => measured(options).await,
        }
    })?;
    let json = serde_json::to_string_pretty(&report)?;
    match output {
        Some(path) => std::fs::write(&path, json + "\n")
            .with_context(|| format!("write {}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}
