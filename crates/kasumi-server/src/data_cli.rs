//! `kasumictl --profile <profile.json>` data commands: reads, conditional writes,
//! coherent snapshots and receipt resolution from a shell or another program,
//! using the same query language and client as applications.
//!
//! Every invocation prints exactly one JSON document on standard output,
//! `{"ok":true,"result":...}` or `{"ok":false,"error":{...}}`, and exits with
//! the status of its [`ErrorClass`]. JSON arguments are inline text, `@path` to
//! read a file, or `-` for standard input; numbers keep their exact decimal text.
use anyhow::{Context, Result, bail, ensure};
use kasumi_client::{
    ClientDecodeLimits, ClientError, ClientProfile, ClientResources, Kasumi, KasumiClientConfig,
    KasumiClientPool, RECEIPT_FOR_OTHER_INPUT, RECEIPT_FOR_OTHER_SCOPE, SnapshotReadOptions,
};
use kasumi_transport::credentials::{CredentialSource, FileCredentialSource, token};
use kasumi_types::{
    CollectionDefinition, CredentialResource, Document, ErrorCode, Filter, MutationBatch,
    MutationReceiptScope, Paging, Precondition, QueryRequest, QueryRow, ReadAssertion,
    ReadSnapshotRequest, SnapshotReadResponse, Sort, TextSearch, WriteReceipt,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

pub const USAGE: &str = "\
kasumictl --profile <profile.json> [<option>...] <command>
  get <collection> <id>
  query <collection> [<filter>] [--sort <field>]... [--select <field>]... [--limit <n>]
        [--search <index> <text>] [--allow-scan] [--seek] [--all]
  query --json <query> [--all]
  put <collection> <id> <body> [--if absent|any|<version>] [--key <idempotency-key>]
  patch <collection> <id> <merge-patch> [--if any|<version>] [--key <idempotency-key>]
  delete <collection> <id> [--if any|<version>] [--key <idempotency-key>]
  mutate <batch>
  read-snapshot <request>
  resolve-mutation <batch> [--scope <scope>]
  collections
Options, in any order before the command, checked before connecting:
  --profile <profile.json>   (required)
  --expect-profile-sha256 <hex>
  --expect-tenant <tenant> --expect-incarnation <uuid>
    --expect-principal <principal> --expect-family-id <uuid>   (all four together)
  --timeout-ms <milliseconds>   (default 30000, from process start)
JSON arguments are inline, @path to read a file, or - for standard input (once).
Sort fields are JSON Pointers; prefix with - to sort descending (e.g. -/amount).
Every command prints one JSON document and exits with its error class status.";

/// Reads larger than one request are refused before parsing.
const MAX_ARGUMENT_BYTES: u64 = crate::api::MAX_REQUEST_BYTES as u64;
/// One invocation keeps one credential snapshot, which lives at most an hour.
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);
const OPTIONS: [&str; 7] = [
    "--profile",
    "--expect-profile-sha256",
    "--expect-tenant",
    "--expect-incarnation",
    "--expect-principal",
    "--expect-family-id",
    "--timeout-ms",
];

/// Stable failure classes for programs. Each has its own exit status; any
/// other status (termination by a signal) carries no document, and a write it
/// interrupted must be treated as `uncertain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Internal,
    /// The command line, a JSON argument or the request itself is wrong.
    InvalidRequest,
    /// The profile or its bearer file could not be loaded, or the profile
    /// differs from its expected checks. Nothing connected.
    ProfileRejected,
    Unauthorized,
    NotFound,
    /// A definite rejection not proven to be a failed precondition: typically
    /// an idempotency key that already identifies different input, or a
    /// receipt check that did not finish before the deadline.
    Conflict,
    /// A definite rejection of exactly this batch, proven by its retained
    /// receipt: a document precondition, read assertion, unique index or
    /// archived identity conflicted with current state.
    PreconditionFailed,
    ResourceExhausted,
    /// Nothing was applied; the same command may succeed later. For
    /// `resolve-mutation` it describes only the lookup.
    Unavailable,
    /// A write may have been applied. Resolve it or resend the identical batch;
    /// never build a new one.
    Uncertain,
}

impl ErrorClass {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::InvalidRequest => 2,
            Self::ProfileRejected => 3,
            Self::Unauthorized => 4,
            Self::NotFound => 5,
            Self::Conflict => 6,
            Self::PreconditionFailed => 7,
            Self::ResourceExhausted => 8,
            Self::Unavailable => 9,
            Self::Uncertain => 10,
        }
    }
}

/// The `error` member of a failed command's document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Failure {
    pub class: ErrorClass,
    /// The database's own error code, when the server reported one.
    pub code: Option<ErrorCode>,
    pub message: String,
    /// The key to resolve or resend a failed write with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl Failure {
    fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            code: None,
            message: message.into(),
            idempotency_key: None,
        }
    }

    fn client(error: &ClientError, write: bool) -> Self {
        let message = match error {
            ClientError::Transport(status) => status.message().to_owned(),
            other => other.to_string(),
        };
        Self {
            class: classify(error, write),
            code: error.code(),
            message,
            idempotency_key: None,
        }
    }

    fn read(error: ClientError) -> Self {
        Self::client(&error, false)
    }

    fn write(error: &ClientError, key: &str) -> Self {
        let mut failure = Self::client(error, true);
        if failure.class == ErrorClass::Uncertain {
            failure.message = format!(
                "{}; the batch may have been applied: resolve it or resend it unchanged",
                failure.message
            );
        }
        failure.with_key(key)
    }

    /// A rejection the database retained for exactly the original batch.
    fn retained(error: kasumi_types::Error) -> Self {
        Self {
            class: match error.code {
                ErrorCode::Conflict => ErrorClass::PreconditionFailed,
                code => database_class(code, false),
            },
            code: Some(error.code),
            message: error.message,
            idempotency_key: None,
        }
    }

    fn with_key(mut self, key: &str) -> Self {
        self.idempotency_key = Some(key.to_owned());
        self
    }

    /// A failed receipt lookup reports on the lookup, never on its batch.
    fn unresolved(mut self) -> Self {
        self.message = format!(
            "{}; the lookup failed, so the batch's outcome is still unresolved",
            self.message
        );
        self
    }

    fn document(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Failed<'a> {
            ok: bool,
            error: &'a Failure,
        }
        serde_json::to_vec(&Failed {
            ok: false,
            error: self,
        })
        .expect("a failure document contains only strings and closed codes")
    }
}

/// Only a database code or an error raised before dispatch proves that a write
/// did not apply. Every other failure after dispatch leaves it `uncertain`. A
/// code is definite because the server reports any failure after accepting a
/// write, and the client any failure after an uncertain attempt, as
/// `UNKNOWN_OUTCOME`.
fn classify(error: &ClientError, write: bool) -> ErrorClass {
    if let Some(code) = error.code() {
        return database_class(code, write);
    }
    match error {
        ClientError::Connection(_) => ErrorClass::Unavailable,
        ClientError::Authorization => ErrorClass::Unauthorized,
        ClientError::RequestTooLarge => ErrorClass::ResourceExhausted,
        _ if write => ErrorClass::Uncertain,
        ClientError::Transport(status) => transport_class(status.code()),
        ClientError::DecodeRejected { code, .. } => transport_class(*code),
        ClientError::Json(_) | ClientError::InvalidResponse(_) => ErrorClass::Internal,
    }
}

fn database_class(code: ErrorCode, write: bool) -> ErrorClass {
    match code {
        ErrorCode::InvalidArgument | ErrorCode::SchemaViolation | ErrorCode::IndexRequired => {
            ErrorClass::InvalidRequest
        }
        ErrorCode::Unauthorized | ErrorCode::Forbidden => ErrorClass::Unauthorized,
        ErrorCode::NotFound => ErrorClass::NotFound,
        ErrorCode::AlreadyExists | ErrorCode::Conflict => ErrorClass::Conflict,
        ErrorCode::QuotaExceeded | ErrorCode::ResourceExhausted => ErrorClass::ResourceExhausted,
        ErrorCode::CursorExpired | ErrorCode::Sealed => ErrorClass::Unavailable,
        ErrorCode::Unavailable
        | ErrorCode::AuditUnavailable
        | ErrorCode::UnknownOutcome
        | ErrorCode::Corruption
            if write =>
        {
            ErrorClass::Uncertain
        }
        ErrorCode::Unavailable | ErrorCode::AuditUnavailable | ErrorCode::UnknownOutcome => {
            ErrorClass::Unavailable
        }
        ErrorCode::Corruption => ErrorClass::Internal,
    }
}

fn transport_class(code: tonic::Code) -> ErrorClass {
    use tonic::Code;
    match code {
        Code::InvalidArgument | Code::OutOfRange => ErrorClass::InvalidRequest,
        Code::Unauthenticated | Code::PermissionDenied => ErrorClass::Unauthorized,
        Code::NotFound => ErrorClass::NotFound,
        Code::ResourceExhausted => ErrorClass::ResourceExhausted,
        Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled | Code::Unknown => {
            ErrorClass::Unavailable
        }
        _ => ErrorClass::Internal,
    }
}

/// Failures raised while building a request never reached the server.
fn dispatched(error: &ClientError) -> bool {
    !matches!(
        error,
        ClientError::Connection(_) | ClientError::Authorization | ClientError::RequestTooLarge
    )
}

/// What a read-only receipt lookup after a failed write found for that batch.
#[derive(Debug)]
enum Retained {
    Outcome(std::result::Result<WriteReceipt, kasumi_types::Error>),
    /// The key's retained outcome belongs to different input, so this batch
    /// can never apply under it.
    OtherBatch,
    /// Nothing retained, or the lookup did not finish.
    Unknown,
}

/// A retained outcome of exactly this batch is final whatever the attempt
/// reported: a commit is the write's success, a rejection keeps its retained
/// class. Without one, the attempt's own classification stands.
fn settle(
    failure: Failure,
    retained: Retained,
    key: &str,
) -> std::result::Result<WriteReceipt, Failure> {
    match retained {
        Retained::Outcome(Ok(receipt)) => Ok(receipt),
        Retained::Outcome(Err(error)) => Err(Failure::retained(error).with_key(key)),
        Retained::OtherBatch if failure.class != ErrorClass::Conflict => Err(Failure::new(
            ErrorClass::Conflict,
            "the outcome retained under this idempotency key belongs to a different batch",
        )
        .with_key(key)),
        Retained::OtherBatch | Retained::Unknown => Err(failure),
    }
}

/// Identity supplied independently of the profile file. A profile cannot vouch
/// for itself, so these come from the caller's own signed configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileChecks {
    pub sha256: Option<String>,
    pub binding: Option<DatabaseBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseBinding {
    pub tenant: String,
    pub incarnation: Uuid,
    pub principal: String,
    pub family_id: Uuid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub profile: PathBuf,
    pub checks: ProfileChecks,
    pub timeout: Duration,
    /// `timeout` after parsing began, before any argument or file was read.
    pub deadline: Instant,
    pub command: DataCommand,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataCommand {
    Get {
        collection: String,
        id: String,
    },
    Query {
        query: Box<QueryRequest>,
        all: bool,
    },
    Write(MutationBatch),
    ReadSnapshot(ReadSnapshotRequest),
    /// `scope` defaults to the profile's own tenant, incarnation and principal.
    ResolveMutation {
        original: MutationBatch,
        scope: Option<MutationReceiptScope>,
    },
    Collections,
}

impl DataCommand {
    /// The key a failed write or resolution reports.
    fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Write(batch)
            | Self::ResolveMutation {
                original: batch, ..
            } => Some(&batch.idempotency_key),
            _ => None,
        }
    }
}

/// Whether `kasumictl` arguments are a data command: they start with
/// `--profile` or another data option. Anything else is administrative.
pub fn selects_data(first: &OsStr) -> bool {
    OPTIONS.iter().any(|option| first == *option)
}

/// Parse a data command line: options, `--profile` among them, then one
/// command. The invocation's deadline starts here.
pub fn parse(arguments: &[String]) -> Result<Invocation> {
    let started = Instant::now();
    let mut options = BTreeMap::new();
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first()
        && flag.starts_with("--")
    {
        ensure!(
            OPTIONS.contains(&flag.as_str()),
            "unknown option `{flag}`\n{USAGE}"
        );
        let (value, tail) = tail
            .split_first()
            .with_context(|| format!("{flag} needs a value"))?;
        ensure!(
            options.insert(flag.as_str(), value.as_str()).is_none(),
            "{flag} is given twice"
        );
        rest = tail;
    }
    let profile = options
        .get("--profile")
        .with_context(|| format!("--profile <profile.json> is required\n{USAGE}"))?;
    let sha256 = options
        .get("--expect-profile-sha256")
        .map(|digest| {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "--expect-profile-sha256 takes 64 hexadecimal digits"
            );
            Ok(digest.to_ascii_lowercase())
        })
        .transpose()?;
    let [_, _, tenant, incarnation, principal, family_id, _] = OPTIONS;
    let binding = match [tenant, incarnation, principal, family_id]
        .map(|flag| options.get(flag).copied())
    {
        [None, None, None, None] => None,
        [
            Some(tenant),
            Some(incarnation),
            Some(principal),
            Some(family_id),
        ] => Some(DatabaseBinding {
            tenant: tenant.to_owned(),
            incarnation: identity(incarnation, "--expect-incarnation")?,
            principal: principal.to_owned(),
            family_id: identity(family_id, "--expect-family-id")?,
        }),
        _ => bail!(
            "--expect-tenant, --expect-incarnation, --expect-principal and --expect-family-id are checked together"
        ),
    };
    let timeout = match options.get("--timeout-ms") {
        None => Kasumi::DEFAULT_TIMEOUT,
        Some(milliseconds) => {
            let timeout = Duration::from_millis(
                milliseconds
                    .parse()
                    .context("--timeout-ms needs a number of milliseconds")?,
            );
            ensure!(
                !timeout.is_zero() && timeout <= MAX_TIMEOUT,
                "--timeout-ms must be between 1 and {}",
                MAX_TIMEOUT.as_millis()
            );
            timeout
        }
    };
    let deadline = started + timeout;
    let input = JsonInput {
        deadline,
        stdin_taken: Cell::new(false),
    };
    Ok(Invocation {
        profile: PathBuf::from(profile),
        checks: ProfileChecks { sha256, binding },
        timeout,
        deadline,
        command: parse_command(rest, &input)?,
    })
}

fn identity(value: &str, flag: &str) -> Result<Uuid> {
    let value = Uuid::try_parse(value).with_context(|| format!("{flag} takes a UUID"))?;
    ensure!(!value.is_nil(), "{flag} cannot be the nil UUID");
    Ok(value)
}

fn parse_command(arguments: &[String], input: &JsonInput) -> Result<DataCommand> {
    let Some((command, rest)) = arguments.split_first() else {
        bail!("missing command\n{USAGE}");
    };
    match command.as_str() {
        "get" => {
            let [collection, id] = rest else {
                bail!("get takes <collection> <id>");
            };
            Ok(DataCommand::Get {
                collection: collection.clone(),
                id: id.clone(),
            })
        }
        "query" => parse_query(rest, input),
        "put" | "patch" | "delete" => parse_write(command, rest, input),
        "mutate" => {
            let [batch] = rest else {
                bail!("mutate takes one <batch> JSON argument");
            };
            Ok(DataCommand::Write(
                input.parse(batch).context("invalid mutation batch")?,
            ))
        }
        "read-snapshot" => {
            let [request] = rest else {
                bail!("read-snapshot takes one <request> JSON argument");
            };
            let request = input.parse(request).context("invalid snapshot request")?;
            validate_snapshot(&request)?;
            Ok(DataCommand::ReadSnapshot(request))
        }
        "resolve-mutation" => {
            let (original, scope) = match rest {
                [original] => (original, None),
                [original, flag, scope] if flag == "--scope" => (original, Some(scope)),
                _ => bail!("resolve-mutation takes <batch> [--scope <scope>]"),
            };
            Ok(DataCommand::ResolveMutation {
                original: input.parse(original).context("invalid mutation batch")?,
                scope: scope
                    .map(|scope| input.parse(scope).context("invalid receipt scope"))
                    .transpose()?,
            })
        }
        "collections" => {
            ensure!(rest.is_empty(), "collections takes no arguments");
            Ok(DataCommand::Collections)
        }
        other => bail!("unknown data command `{other}`\n{USAGE}"),
    }
}

fn parse_query(rest: &[String], input: &JsonInput) -> Result<DataCommand> {
    if let [flag, rest @ ..] = rest
        && flag == "--json"
    {
        let Some((query, options)) = rest.split_first() else {
            bail!("query --json takes <query> [--all]");
        };
        ensure!(
            options.is_empty() || options == ["--all"],
            "query --json takes <query> [--all]"
        );
        let query: QueryRequest = input.parse(query).context("invalid query")?;
        return Ok(DataCommand::Query {
            query: Box::new(query),
            all: !options.is_empty(),
        });
    }
    let Some((collection, mut rest)) = rest.split_first() else {
        bail!("query takes <collection> or --json <query>");
    };
    ensure!(
        !collection.starts_with("--"),
        "query takes <collection> or --json <query>"
    );
    let mut query = QueryRequest::new(collection.clone());
    let mut all = false;
    if let Some((filter, tail)) = rest.split_first()
        && !filter.starts_with("--")
    {
        let filter: Filter = input.parse(filter).context("invalid filter")?;
        query = query.filter(filter);
        rest = tail;
    }
    while let Some((flag, tail)) = rest.split_first() {
        let mut value = |name: &str| -> Result<&String> {
            let (value, tail) = tail
                .split_first()
                .with_context(|| format!("{name} needs a value"))?;
            rest = tail;
            Ok(value)
        };
        match flag.as_str() {
            "--sort" => {
                let field = value("--sort")?;
                query.sort.push(
                    serde_json::from_value::<Sort>(Value::String(field.clone()))
                        .context("invalid sort key")?,
                );
            }
            "--select" => {
                let field = value("--select")?.clone();
                query.select.push(field);
            }
            "--limit" => {
                let limit = value("--limit")?;
                query.limit = Some(limit.parse().context("--limit needs a number")?);
            }
            "--search" => {
                let index = value("--search")?.clone();
                let text = {
                    let (text, tail) = rest
                        .split_first()
                        .context("--search needs <index> <text>")?;
                    rest = tail;
                    text.clone()
                };
                query.search = Some(TextSearch::new(index, text));
            }
            "--allow-scan" => {
                query.allow_scan = true;
                rest = tail;
            }
            "--seek" => {
                query.paging = Paging::Seek;
                rest = tail;
            }
            "--all" => {
                all = true;
                rest = tail;
            }
            other => bail!("unknown query option `{other}`"),
        }
    }
    Ok(DataCommand::Query {
        query: Box::new(query),
        all,
    })
}

fn parse_write(command: &str, rest: &[String], input: &JsonInput) -> Result<DataCommand> {
    let positional = if command == "delete" { 2 } else { 3 };
    ensure!(
        rest.len() >= positional,
        "{command} takes <collection> <id>{}",
        if command == "delete" { "" } else { " <json>" }
    );
    let (arguments, mut options) = rest.split_at(positional);
    let mut expected = Precondition::Any;
    let mut key = None;
    while let Some((flag, tail)) = options.split_first() {
        let (value, tail) = tail
            .split_first()
            .with_context(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--if" => {
                expected = match value.as_str() {
                    "any" => Precondition::Any,
                    "absent" if command == "put" => Precondition::Absent,
                    version => Precondition::Version(version.parse().with_context(|| {
                        format!(
                            "--if takes any, a version number{}",
                            if command == "put" { " or absent" } else { "" }
                        )
                    })?),
                }
            }
            "--key" => key = Some(value.clone()),
            other => bail!("unknown {command} option `{other}`"),
        }
        options = tail;
    }
    let (collection, id) = (arguments[0].clone(), arguments[1].clone());
    let mutation = match command {
        "put" => kasumi_types::Mutation::put(
            collection,
            id,
            input.parse::<Value>(&arguments[2])?,
            expected,
        ),
        "patch" => kasumi_types::Mutation::patch(
            collection,
            id,
            input.parse::<Value>(&arguments[2])?,
            expected,
        ),
        _ => kasumi_types::Mutation::delete(collection, id, expected),
    };
    let batch = match key {
        Some(key) => MutationBatch::with_key(key),
        None => MutationBatch::new(),
    };
    Ok(DataCommand::Write(batch.push(mutation)))
}

/// The server's bounds, checked before connecting so that a mistake is not
/// reported as a client decode failure.
fn validate_snapshot(request: &ReadSnapshotRequest) -> Result<()> {
    ensure!(
        !(request.documents.is_empty() && request.queries.is_empty())
            && request.documents.len() <= 256
            && request.queries.len() <= 16,
        "a snapshot reads up to 256 documents and 16 queries, and at least one of either"
    );
    ensure!(
        request.documents.iter().collect::<BTreeSet<_>>().len() == request.documents.len(),
        "a snapshot names each document once"
    );
    ensure!(
        request
            .queries
            .iter()
            .all(|query| query.cursor.is_none() && query.paging == Paging::Snapshot),
        "snapshot queries are complete, without a cursor or seek paging"
    );
    ensure!(
        request
            .time_bounds
            .as_ref()
            .is_none_or(|bounds| bounds.not_before_ms <= bounds.not_after_ms),
        "snapshot time bounds are inverted"
    );
    Ok(())
}

/// JSON arguments: inline text, `@path`, or `-` for standard input, which can
/// supply only one argument. Files and standard input are read within the
/// invocation's deadline.
struct JsonInput {
    deadline: Instant,
    stdin_taken: Cell<bool>,
}

impl JsonInput {
    /// Parse one argument with exact numbers.
    fn parse<T: DeserializeOwned>(&self, argument: &str) -> Result<T> {
        let text = if argument == "-" {
            ensure!(
                !self.stdin_taken.replace(true),
                "only one JSON argument can be read from standard input"
            );
            self.read(None)?
        } else if let Some(path) = argument.strip_prefix('@') {
            self.read(Some(PathBuf::from(path)))?
        } else {
            argument.to_owned()
        };
        ensure!(
            text.len() as u64 <= MAX_ARGUMENT_BYTES,
            "JSON argument exceeds the request limit"
        );
        serde_json::from_str(&text).context("invalid JSON argument")
    }

    /// A reader blocked on standard input left open, or on a FIFO, is
    /// abandoned at the deadline; it ends with the process.
    fn read(&self, path: Option<PathBuf>) -> Result<String> {
        let source = path.as_ref().map_or_else(
            || "standard input".to_owned(),
            |path| path.display().to_string(),
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let read = || -> Result<String> {
                let mut text = String::new();
                match path {
                    None => std::io::stdin()
                        .take(MAX_ARGUMENT_BYTES + 1)
                        .read_to_string(&mut text)?,
                    Some(path) => std::fs::File::open(&path)
                        .with_context(|| format!("opening {}", path.display()))?
                        .take(MAX_ARGUMENT_BYTES + 1)
                        .read_to_string(&mut text)?,
                };
                Ok(text)
            };
            let _ = sender.send(read());
        });
        receiver
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| anyhow::anyhow!("{source} did not reach its end before the deadline"))?
    }
}

/// Connection material for one invocation, from one loaded profile, and the
/// invocation's one deadline. Clients connect only when a command runs.
pub struct Session {
    config: KasumiClientConfig,
    credential: Arc<dyn CredentialSource>,
    scope: MutationReceiptScope,
    incarnation: Uuid,
    deadline: Instant,
}

impl Session {
    /// Hash and parse the exact private profile once and compare it with the
    /// independent checks before loading its TLS material and bearer file.
    pub fn open(path: &Path, checks: &ProfileChecks, deadline: Instant) -> Result<Self> {
        let (profile, sha256) = ClientProfile::load_with_sha256(path)?;
        if let Some(expected) = &checks.sha256 {
            ensure!(
                sha256 == *expected,
                "installed profile SHA-256 {sha256} differs from the expected {expected}"
            );
        }
        if let Some(binding) = &checks.binding {
            profile.require_database_binding(
                &binding.tenant,
                binding.incarnation,
                &binding.principal,
                binding.family_id,
            )?;
        }
        let CredentialResource::Database { incarnation } = profile.resource.clone() else {
            bail!("data commands need a database profile");
        };
        let config = profile.connection(false)?;
        let credential = Arc::new(FileCredentialSource::new(&profile.bearer_file)?);
        // A missing, exposed or malformed bearer file is this profile's fault,
        // not a server refusal. The token read here is dropped at once.
        token(credential.as_ref()).context("reading the profile's bearer file")?;
        let scope = MutationReceiptScope {
            tenant: profile.tenant,
            incarnation: incarnation.to_string(),
            principal: profile.principal,
        };
        Ok(Self::new(config, credential, scope, incarnation, deadline))
    }

    /// Explicit connection material, as `Kasumi::connect` takes. `scope` is the
    /// namespace the credential's own receipts are retained under.
    pub fn new(
        config: KasumiClientConfig,
        credential: Arc<dyn CredentialSource>,
        scope: MutationReceiptScope,
        incarnation: Uuid,
        deadline: Instant,
    ) -> Self {
        Self {
            config,
            credential,
            scope,
            incarnation,
            deadline,
        }
    }

    /// What remains of the deadline. No request is sent after it elapses, so
    /// this failure rules out a write.
    fn remaining(&self) -> std::result::Result<Duration, ClientError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Connection(anyhow::anyhow!(
                "deadline elapsed before the request was sent"
            )));
        }
        Ok(remaining)
    }

    /// A refused or silent connection is reported before anything was sent.
    async fn kasumi(&self) -> std::result::Result<Kasumi, ClientError> {
        let credential = self.credential.clone();
        let connect = Kasumi::connect(&self.config, move || credential.load());
        tokio::time::timeout_at(self.deadline, connect)
            .await
            .map_err(|_| ClientError::Connection(anyhow::anyhow!("connection deadline elapsed")))?
    }

    /// The handle for one call, bounded by what remains of the deadline.
    fn bounded(&self, db: &Kasumi) -> std::result::Result<Kasumi, ClientError> {
        Ok(db.clone().with_timeout(self.remaining()?))
    }

    fn pool(&self) -> std::result::Result<KasumiClientPool, Failure> {
        KasumiClientPool::new(
            BTreeMap::from([(1, self.config.clone())]),
            self.credential.clone(),
        )
        .map_err(|error| Failure::new(ErrorClass::ProfileRejected, format!("{error:#}")))
    }

    fn snapshot_options(&self) -> std::result::Result<SnapshotReadOptions, Failure> {
        let limits = ClientDecodeLimits::default();
        // Room for a retried attempt while a cancelled one still holds its charge.
        let resources = limits
            .accounted_bytes()
            .and_then(|bytes| ClientResources::new(bytes.saturating_mul(4), 4))
            .map_err(Failure::read)?;
        Ok(SnapshotReadOptions {
            resources,
            limits,
            deadline: self.deadline,
            expected_incarnation: self.incarnation,
        })
    }

    /// The retained outcome of a write whose attempt failed after dispatch,
    /// read on the write's own connection within what remains of the deadline.
    /// The failure may hide a commit, and a CONFLICT is a failed precondition
    /// only when retained for this batch: reusing a key is never retained.
    async fn retained(&self, db: &Kasumi, batch: &MutationBatch) -> Retained {
        let (Ok(bearer), Ok(remaining)) = (token(self.credential.as_ref()), self.remaining())
        else {
            return Retained::Unknown;
        };
        match db
            .client()
            .resolve_mutation(&bearer, &self.scope, batch, remaining)
            .await
        {
            Ok(Some(receipt)) => Retained::Outcome(receipt.outcome),
            Err(ClientError::InvalidResponse(reason)) if reason == RECEIPT_FOR_OTHER_INPUT => {
                Retained::OtherBatch
            }
            Ok(None) | Err(_) => Retained::Unknown,
        }
    }
}

/// Run a data command line (every argument after the program name), print its
/// one JSON document and return the exit status. Mistakes, including
/// arguments that are not UTF-8, are reported before the profile is read.
pub async fn run(arguments: Vec<OsString>, out: &mut impl Write) -> u8 {
    let (document, status) = match invoke(arguments).await {
        Ok(document) => (document, 0),
        Err(failure) => (failure.document(), failure.class.exit_code()),
    };
    let printed = out
        .write_all(&document)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    if printed.is_err() {
        return ErrorClass::Internal.exit_code();
    }
    status
}

async fn invoke(arguments: Vec<OsString>) -> std::result::Result<Vec<u8>, Failure> {
    let arguments = arguments
        .into_iter()
        .map(OsString::into_string)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Failure::new(ErrorClass::InvalidRequest, "arguments must be UTF-8"))?;
    let invocation = parse(&arguments)
        .map_err(|error| Failure::new(ErrorClass::InvalidRequest, format!("{error:#}")))?;
    let interrupted = interrupted(&invocation.command);
    guarded(interrupted, async move {
        let session = invocation.session()?;
        execute(invocation.command, &session).await
    })
    .await
}

impl Invocation {
    /// The profile's session; a rejected profile still reports a write's key.
    fn session(&self) -> std::result::Result<Session, Failure> {
        Session::open(&self.profile, &self.checks, self.deadline).map_err(|error| {
            let failure = Failure::new(ErrorClass::ProfileRejected, format!("{error:#}"));
            match self.command.idempotency_key() {
                Some(key) => failure.with_key(key),
                None => failure,
            }
        })
    }
}

/// What a command reports if it stops unexpectedly: a write may already have
/// been sent, so it is uncertain; a read or lookup says nothing about data.
fn interrupted(command: &DataCommand) -> Failure {
    let stopped = "the command stopped unexpectedly";
    match command {
        DataCommand::Write(batch) => Failure::new(
            ErrorClass::Uncertain,
            format!(
                "{stopped}; the batch may have been applied: resolve it or resend it unchanged"
            ),
        )
        .with_key(&batch.idempotency_key),
        DataCommand::ResolveMutation { original, .. } => {
            Failure::new(ErrorClass::Internal, stopped)
                .unresolved()
                .with_key(&original.idempotency_key)
        }
        _ => Failure::new(ErrorClass::Internal, stopped),
    }
}

/// Run a command so that a panic still ends in its one document.
async fn guarded(
    interrupted: Failure,
    command: impl Future<Output = std::result::Result<Vec<u8>, Failure>> + Send + 'static,
) -> std::result::Result<Vec<u8>, Failure> {
    tokio::spawn(command).await.unwrap_or(Err(interrupted))
}

#[derive(Serialize)]
struct Got {
    document: Option<Document>,
}

/// `more` is true when another page follows a page read without `--all`.
#[derive(Serialize)]
struct Queried {
    revision: u64,
    rows: Vec<QueryRow>,
    aggregates: Vec<Value>,
    more: bool,
}

#[derive(Serialize)]
struct Written<'a> {
    idempotency_key: &'a str,
    request_digest: &'a str,
    receipt: &'a WriteReceipt,
}

/// `read_assertions` fences a following batch on everything this snapshot saw.
#[derive(Serialize)]
struct Snapshot<'a> {
    snapshot: &'a SnapshotReadResponse,
    read_assertions: Vec<ReadAssertion>,
}

/// `unknown` means no retained outcome was found. It is not evidence that the
/// batch never committed and never authorizes a different batch.
#[derive(Serialize)]
struct Resolved<'a> {
    outcome: &'static str,
    idempotency_key: &'a str,
    request_digest: &'a str,
    scope: &'a MutationReceiptScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<WriteReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Failure>,
}

#[derive(Serialize)]
struct Collections {
    collections: Vec<CollectionDefinition>,
}

/// A read that the invocation's deadline cut short.
fn elapsed(what: &str) -> ClientError {
    tonic::Status::deadline_exceeded(format!("deadline elapsed before the {what} finished")).into()
}

fn success(result: &impl Serialize) -> std::result::Result<Vec<u8>, Failure> {
    #[derive(Serialize)]
    struct Succeeded<'a, T> {
        ok: bool,
        result: &'a T,
    }
    serde_json::to_vec(&Succeeded { ok: true, result })
        .map_err(|error| Failure::new(ErrorClass::Internal, error.to_string()))
}

/// Run one command and return its complete success document.
pub async fn execute(
    command: DataCommand,
    session: &Session,
) -> std::result::Result<Vec<u8>, Failure> {
    match command {
        DataCommand::Get { collection, id } => {
            let db = session.kasumi().await.map_err(Failure::read)?;
            let document = session
                .bounded(&db)
                .map_err(Failure::read)?
                .get(&collection, &id)
                .await
                .map_err(Failure::read)?;
            success(&Got { document })
        }
        DataCommand::Query { query, all } => {
            let db = session.kasumi().await.map_err(Failure::read)?;
            let bounded = || session.bounded(&db).map_err(Failure::read);
            let mut page = bounded()?.query(&query).await.map_err(Failure::read)?;
            let revision = page.revision();
            let (mut rows, mut aggregates) = (Vec::new(), Vec::new());
            loop {
                let next = if all {
                    bounded()?.next_page(&page).await.map_err(Failure::read)?
                } else {
                    None
                };
                aggregates.extend_from_slice(page.aggregates());
                let more = page.has_more();
                rows.append(&mut page.into_rows());
                match next {
                    Some(next) => page = next,
                    None => {
                        return success(&Queried {
                            revision,
                            rows,
                            aggregates,
                            more: more && !all,
                        });
                    }
                }
            }
        }
        DataCommand::Write(batch) => {
            let key = &batch.idempotency_key;
            let request_digest = batch.digest().map_err(|error| {
                Failure::new(ErrorClass::InvalidRequest, error.message).with_key(key)
            })?;
            let db = session
                .kasumi()
                .await
                .and_then(|db| session.bounded(&db))
                .map_err(|error| Failure::write(&error, key))?;
            let receipt = match db.mutate(&batch).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    let retained = if dispatched(&error) {
                        session.retained(&db, &batch).await
                    } else {
                        Retained::Unknown
                    };
                    settle(Failure::write(&error, key), retained, key)?
                }
            };
            success(&Written {
                idempotency_key: key,
                request_digest: &request_digest,
                receipt: &receipt,
            })
        }
        DataCommand::ReadSnapshot(request) => {
            let options = session.snapshot_options()?;
            let mut pool = session.pool()?;
            let snapshot =
                tokio::time::timeout_at(session.deadline, pool.read_snapshot(&request, &options))
                    .await
                    .unwrap_or_else(|_| Err(elapsed("snapshot read")))
                    .map_err(Failure::read)?;
            success(&Snapshot {
                read_assertions: snapshot.read_assertions(),
                snapshot: &snapshot,
            })
        }
        DataCommand::ResolveMutation { original, scope } => {
            let key = &original.idempotency_key;
            // Outcomes are looked up under this credential's own tenant and
            // principal; only the incarnation can differ, after a restore.
            let scope = match scope {
                None => session.scope.clone(),
                Some(scope)
                    if scope.tenant == session.scope.tenant
                        && scope.principal == session.scope.principal =>
                {
                    scope
                }
                Some(_) => {
                    return Err(Failure::new(
                        ErrorClass::InvalidRequest,
                        "--scope can differ from the profile only in its incarnation: outcomes are looked up under the profile's tenant and principal",
                    )
                    .with_key(key));
                }
            };
            let request_digest = original.digest().map_err(|error| {
                Failure::new(ErrorClass::InvalidRequest, error.message).with_key(key)
            })?;
            let remaining = session
                .remaining()
                .map_err(|error| Failure::read(error).unresolved().with_key(key))?;
            let mut pool = session.pool().map_err(|failure| failure.with_key(key))?;
            let resolved = tokio::time::timeout_at(
                session.deadline,
                pool.resolve_mutation(&scope, &original, remaining),
            )
            .await
            .unwrap_or_else(|_| Err(elapsed("receipt lookup")));
            let (outcome, receipt, error) = match resolved {
                Ok(Some(retained)) => match retained.outcome {
                    Ok(receipt) => ("committed", Some(receipt), None),
                    Err(error) => ("rejected", None, Some(Failure::retained(error))),
                },
                Ok(None) => ("unknown", None, None),
                Err(ClientError::InvalidResponse(reason))
                    if reason == RECEIPT_FOR_OTHER_INPUT || reason == RECEIPT_FOR_OTHER_SCOPE =>
                {
                    return Err(Failure::new(
                        ErrorClass::Conflict,
                        format!(
                            "the outcome retained under this idempotency key {}",
                            if reason == RECEIPT_FOR_OTHER_INPUT {
                                "belongs to a different batch"
                            } else {
                                "belongs to another tenant, incarnation or principal"
                            }
                        ),
                    )
                    .with_key(key));
                }
                Err(error) => return Err(Failure::read(error).unresolved().with_key(key)),
            };
            success(&Resolved {
                outcome,
                idempotency_key: key,
                request_digest: &request_digest,
                scope: &scope,
                receipt,
                error,
            })
        }
        DataCommand::Collections => {
            let db = session.kasumi().await.map_err(Failure::read)?;
            let collections = session
                .bounded(&db)
                .map_err(Failure::read)?
                .collections()
                .await
                .map_err(Failure::read)?;
            success(&Collections { collections })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
    }

    /// Arguments after a `--profile` option, as most invocations start.
    fn profiled(text: &str) -> Vec<String> {
        args(format!("--profile /p {text}").trim_end())
    }

    fn command(text: &str) -> DataCommand {
        parse(&profiled(text)).unwrap().command
    }

    #[test]
    fn query_flags_build_the_same_request_as_the_builder() {
        let DataCommand::Query { query, all } = parse(&[
            "--profile".into(),
            "/p".into(),
            "query".into(),
            "invoices".into(),
            r#"{"/status":"open","/amount":{"gte":10}}"#.into(),
            "--sort".into(),
            "-/amount".into(),
            "--select".into(),
            "/amount".into(),
            "--limit".into(),
            "20".into(),
            "--search".into(),
            "body".into(),
            "tokyo tower".into(),
            "--allow-scan".into(),
            "--all".into(),
        ])
        .unwrap()
        .command
        else {
            panic!("query command")
        };
        assert!(all);
        assert_eq!(
            *query,
            QueryRequest::new("invoices")
                .filter(Filter::new().eq("/status", "open").gte("/amount", 10))
                .sort_desc("/amount")
                .select(["/amount"])
                .limit(20)
                .search(TextSearch::new("body", "tokyo tower"))
                .allow_scan()
        );
        let DataCommand::Query { query, .. } =
            command(r#"query events {"/tenant":"acme"} --sort /at --seek"#)
        else {
            panic!("query command")
        };
        assert_eq!(query.paging, Paging::Seek);
        let DataCommand::Query { query, all } =
            command(r#"query --json {"collection":"docs","limit":5}"#)
        else {
            panic!("query command")
        };
        assert_eq!((*query, all), (QueryRequest::new("docs").limit(5), false));
        let DataCommand::Query { query, all } =
            command(r#"query --json {"collection":"docs","limit":5} --all"#)
        else {
            panic!("query command")
        };
        assert_eq!((*query, all), (QueryRequest::new("docs").limit(5), true));
    }

    #[test]
    fn writes_carry_preconditions_keys_and_exact_numbers() {
        let DataCommand::Write(batch) = command(
            r#"put docs a {"amount":9007199254740993.123456789} --if absent --key order-7"#,
        ) else {
            panic!("write command")
        };
        assert_eq!(batch.idempotency_key, "order-7");
        assert_eq!(
            serde_json::to_string(&batch.operations).unwrap(),
            r#"[{"op":"put","collection":"docs","id":"a","body":{"amount":9007199254740993.123456789},"expected":"absent"}]"#
        );
        let DataCommand::Write(batch) = command(r#"patch docs a {"note":null} --if 4"#) else {
            panic!("write command")
        };
        assert_eq!(
            batch.operations,
            [kasumi_types::Mutation::patch(
                "docs",
                "a",
                json!({"note": null}),
                Precondition::Version(4)
            )]
        );
        let DataCommand::Write(batch) = command("delete docs a") else {
            panic!("write command")
        };
        assert_eq!(
            batch.operations,
            [kasumi_types::Mutation::delete(
                "docs",
                "a",
                Precondition::Any
            )]
        );
    }

    #[test]
    fn one_batch_expresses_absent_creates_exact_versions_and_read_fences() {
        let DataCommand::Write(batch) = command(
            r#"mutate {"idempotency_key":"is/run-1/op-7/finish","read_set":[{"kind":"snapshot","incarnation":"54b2e0dd-135a-439e-b053-38ba6cba2310","policy_epoch":2,"schema_epoch":4},{"kind":"document","collection":"receipts","id":"op-7","expected":"absent"}],"operations":[{"op":"put","collection":"claims","id":"op-7","body":{"state":"done"},"expected":{"version":31}},{"op":"put","collection":"receipts","id":"op-7","body":{"amount":10.50},"expected":"absent"}]}"#,
        ) else {
            panic!("write command")
        };
        assert_eq!(batch.idempotency_key, "is/run-1/op-7/finish");
        assert_eq!(batch.read_set.len(), 2);
        assert_eq!(
            batch
                .operations
                .iter()
                .map(|op| *op.expected())
                .collect::<Vec<_>>(),
            [Precondition::Version(31), Precondition::Absent]
        );
        assert!(batch.digest().unwrap().len() == 64);
    }

    #[test]
    fn snapshot_and_resolution_take_canonical_typed_json() {
        let DataCommand::ReadSnapshot(request) = command(
            r#"read-snapshot {"documents":[{"collection":"intents","id":"a"},{"collection":"receipts","id":"a"}],"queries":[],"time_bounds":null}"#,
        ) else {
            panic!("snapshot command")
        };
        assert_eq!(request.documents[1].collection, "receipts");
        let batch =
            r#"{"idempotency_key":"k","operations":[{"op":"delete","collection":"c","id":"a"}]}"#;
        let DataCommand::ResolveMutation { original, scope } =
            command(&format!("resolve-mutation {batch}"))
        else {
            panic!("resolve command")
        };
        assert_eq!((original.idempotency_key.as_str(), scope), ("k", None));
        let DataCommand::ResolveMutation { scope, .. } = command(&format!(
            r#"resolve-mutation {batch} --scope {{"tenant":"t","incarnation":"i","principal":"p"}}"#
        )) else {
            panic!("resolve command")
        };
        assert_eq!(scope.unwrap().principal, "p");
    }

    #[test]
    fn profile_checks_and_deadline_precede_the_command() {
        let incarnation = "54b2e0dd-135a-439e-b053-38ba6cba2310";
        let family = "9d347667-433e-4b7f-b49e-a9ba6db43eaa";
        let before = Instant::now();
        // --profile is one of the options, in any position before the command.
        let invocation = parse(&args(&format!(
            "--expect-profile-sha256 {} --expect-tenant default --expect-incarnation {incarnation} --profile /etc/kasumi/app.json --expect-principal app --expect-family-id {family} --timeout-ms 2500 collections",
            "AB".repeat(32)
        )))
        .unwrap();
        assert_eq!(invocation.profile, PathBuf::from("/etc/kasumi/app.json"));
        assert!(
            invocation.deadline >= before + Duration::from_millis(2500)
                && invocation.deadline <= Instant::now() + Duration::from_millis(2500)
        );
        assert_eq!(invocation.checks.sha256, Some("ab".repeat(32)));
        assert_eq!(
            invocation.checks.binding,
            Some(DatabaseBinding {
                tenant: "default".into(),
                incarnation: incarnation.parse().unwrap(),
                principal: "app".into(),
                family_id: family.parse().unwrap(),
            })
        );
        assert_eq!(invocation.timeout, Duration::from_millis(2500));
        assert_eq!(invocation.command, DataCommand::Collections);
        let plain = parse(&profiled("collections")).unwrap();
        assert_eq!(plain.checks, ProfileChecks::default());
        assert_eq!(plain.timeout, Kasumi::DEFAULT_TIMEOUT);
    }

    #[test]
    fn mistakes_are_reported_before_connecting() {
        let uuid = "54b2e0dd-135a-439e-b053-38ba6cba2310";
        for (command, message) in [
            ("", "missing command"),
            ("fetch docs a", "unknown data command"),
            ("get docs", "get takes"),
            ("query docs --sort amount", "invalid sort key"),
            ("query docs {\"status\":\"open\"}", "invalid filter"),
            ("query docs --limit many", "--limit needs a number"),
            ("query docs --frobnicate", "unknown query option"),
            ("query --json", "query --json takes"),
            ("query --json {} --sort /n", "query --json takes"),
            ("query --all", "query takes"),
            (r#"query docs {"/n":1,"/n":2}"#, "duplicate filter field"),
            (
                r#"query --json {"collection":"docs","collection":"other"}"#,
                "duplicate field",
            ),
            (
                r#"query --json {"collection":"docs","aggregate":{"n":{"count":"*"},"n":{"sum":"/n"}}}"#,
                "duplicate aggregate",
            ),
            (
                r#"mutate {"idempotency_key":"a","idempotency_key":"b","operations":[]}"#,
                "duplicate field",
            ),
            (
                r#"mutate {"idempotency_key":"a","operations":[],"retry":true}"#,
                "unknown field",
            ),
            ("put docs a", "put takes"),
            ("put docs a {} --if later", "--if takes"),
            ("patch docs a {} --if absent", "--if takes"),
            ("put docs a {broken", "invalid JSON argument"),
            ("collections extra", "takes no arguments"),
            ("read-snapshot", "read-snapshot takes"),
            (
                r#"read-snapshot {"documents":[{"collection":"c","id":"a"}],"queries":[]}"#,
                "time_bounds",
            ),
            (
                r#"read-snapshot {"documents":[],"queries":[],"time_bounds":null}"#,
                "at least one",
            ),
            (
                r#"read-snapshot {"documents":[{"collection":"c","id":"a"},{"collection":"c","id":"a"}],"queries":[],"time_bounds":null}"#,
                "each document once",
            ),
            (
                r#"read-snapshot {"documents":[],"queries":[{"collection":"c","cursor":"x"}],"time_bounds":null}"#,
                "without a cursor",
            ),
            (
                r#"read-snapshot {"documents":[{"collection":"c","id":"a"}],"queries":[],"time_bounds":{"not_before_ms":2,"not_after_ms":1}}"#,
                "inverted",
            ),
            ("resolve-mutation", "resolve-mutation takes"),
            (
                r#"resolve-mutation {"idempotency_key":"k","operations":[]} --scope {"tenant":"t"}"#,
                "invalid receipt scope",
            ),
            ("--frobnicate 1 collections", "unknown option"),
            ("--timeout-ms", "needs a value"),
            ("--timeout-ms 0 collections", "between 1 and"),
            ("--timeout-ms 3600001 collections", "between 1 and"),
            ("--timeout-ms 1 --timeout-ms 2 collections", "given twice"),
            ("--expect-profile-sha256 abc collections", "64 hexadecimal"),
            ("--expect-tenant default collections", "checked together"),
            ("--profile /q collections", "given twice"),
            (
                &format!(
                    "--expect-tenant t --expect-incarnation {uuid} --expect-principal p --expect-family-id nope collections"
                ),
                "--expect-family-id takes a UUID",
            ),
            (
                "--expect-tenant t --expect-incarnation 00000000-0000-0000-0000-000000000000 --expect-principal p --expect-family-id 00000000-0000-0000-0000-000000000001 collections",
                "nil UUID",
            ),
        ] {
            let error = format!("{:#}", parse(&profiled(command)).unwrap_err());
            assert!(error.contains(message), "{command}: {error}");
        }
        for (command, message) in [
            ("collections", "--profile <profile.json> is required"),
            (
                "--timeout-ms 5 collections",
                "--profile <profile.json> is required",
            ),
            ("--profile", "--profile needs a value"),
        ] {
            let error = format!("{:#}", parse(&args(command)).unwrap_err());
            assert!(error.contains(message), "{command}: {error}");
        }
        for first in ["--profile", "--expect-tenant", "--timeout-ms"] {
            assert!(selects_data(OsStr::new(first)), "{first}");
        }
        for first in ["--config", "schema-reference", "get", "--sort"] {
            assert!(!selects_data(OsStr::new(first)), "{first}");
        }
    }

    #[test]
    fn classes_have_stable_names_and_distinct_exit_statuses() {
        let classes = [
            (ErrorClass::Internal, "internal", 1),
            (ErrorClass::InvalidRequest, "invalid_request", 2),
            (ErrorClass::ProfileRejected, "profile_rejected", 3),
            (ErrorClass::Unauthorized, "unauthorized", 4),
            (ErrorClass::NotFound, "not_found", 5),
            (ErrorClass::Conflict, "conflict", 6),
            (ErrorClass::PreconditionFailed, "precondition_failed", 7),
            (ErrorClass::ResourceExhausted, "resource_exhausted", 8),
            (ErrorClass::Unavailable, "unavailable", 9),
            (ErrorClass::Uncertain, "uncertain", 10),
        ];
        for (class, name, status) in classes {
            assert_eq!(serde_json::to_value(class).unwrap(), json!(name));
            assert_eq!(class.exit_code(), status);
        }
        let failure = Failure::write(
            &ClientError::Transport(crate::api::status(kasumi_types::Error::new(
                ErrorCode::UnknownOutcome,
                "resolve",
            ))),
            "k-1",
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&failure.document()).unwrap(),
            json!({"ok": false, "error": {
                "class": "uncertain",
                "code": "UNKNOWN_OUTCOME",
                "message": "resolve; the batch may have been applied: resolve it or resend it unchanged",
                "idempotency_key": "k-1",
            }})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(
                &Failure::new(ErrorClass::InvalidRequest, "missing command").document()
            )
            .unwrap(),
            json!({"ok": false, "error": {
                "class": "invalid_request", "code": null, "message": "missing command",
            }})
        );
    }

    #[test]
    fn only_database_rejections_and_undispatched_failures_rule_out_a_write() {
        let database =
            |code| ClientError::Transport(crate::api::status(kasumi_types::Error::new(code, "x")));
        let bare = |code| ClientError::Transport(tonic::Status::new(code, "x"));
        for (error, read, write) in [
            (
                database(ErrorCode::Conflict),
                ErrorClass::Conflict,
                ErrorClass::Conflict,
            ),
            (
                database(ErrorCode::AlreadyExists),
                ErrorClass::Conflict,
                ErrorClass::Conflict,
            ),
            (
                database(ErrorCode::NotFound),
                ErrorClass::NotFound,
                ErrorClass::NotFound,
            ),
            (
                database(ErrorCode::Forbidden),
                ErrorClass::Unauthorized,
                ErrorClass::Unauthorized,
            ),
            (
                database(ErrorCode::Unauthorized),
                ErrorClass::Unauthorized,
                ErrorClass::Unauthorized,
            ),
            (
                database(ErrorCode::SchemaViolation),
                ErrorClass::InvalidRequest,
                ErrorClass::InvalidRequest,
            ),
            (
                database(ErrorCode::IndexRequired),
                ErrorClass::InvalidRequest,
                ErrorClass::InvalidRequest,
            ),
            (
                database(ErrorCode::QuotaExceeded),
                ErrorClass::ResourceExhausted,
                ErrorClass::ResourceExhausted,
            ),
            (
                database(ErrorCode::Sealed),
                ErrorClass::Unavailable,
                ErrorClass::Unavailable,
            ),
            (
                database(ErrorCode::CursorExpired),
                ErrorClass::Unavailable,
                ErrorClass::Unavailable,
            ),
            (
                database(ErrorCode::Unavailable),
                ErrorClass::Unavailable,
                ErrorClass::Uncertain,
            ),
            (
                database(ErrorCode::AuditUnavailable),
                ErrorClass::Unavailable,
                ErrorClass::Uncertain,
            ),
            (
                database(ErrorCode::UnknownOutcome),
                ErrorClass::Unavailable,
                ErrorClass::Uncertain,
            ),
            (
                database(ErrorCode::Corruption),
                ErrorClass::Internal,
                ErrorClass::Uncertain,
            ),
            (
                bare(tonic::Code::Unavailable),
                ErrorClass::Unavailable,
                ErrorClass::Uncertain,
            ),
            (
                bare(tonic::Code::DeadlineExceeded),
                ErrorClass::Unavailable,
                ErrorClass::Uncertain,
            ),
            (
                bare(tonic::Code::Unauthenticated),
                ErrorClass::Unauthorized,
                ErrorClass::Uncertain,
            ),
            (
                bare(tonic::Code::Internal),
                ErrorClass::Internal,
                ErrorClass::Uncertain,
            ),
            (
                ClientError::DecodeRejected {
                    code: tonic::Code::ResourceExhausted,
                    reason: "budget",
                    database: None,
                },
                ErrorClass::ResourceExhausted,
                ErrorClass::Uncertain,
            ),
            (
                ClientError::DecodeRejected {
                    code: tonic::Code::Unavailable,
                    reason: "routed",
                    database: Some(ErrorCode::NotFound),
                },
                ErrorClass::NotFound,
                ErrorClass::NotFound,
            ),
            (
                ClientError::InvalidResponse("receipt"),
                ErrorClass::Internal,
                ErrorClass::Uncertain,
            ),
            (
                ClientError::Connection(anyhow::anyhow!("refused")),
                ErrorClass::Unavailable,
                ErrorClass::Unavailable,
            ),
            (
                ClientError::Authorization,
                ErrorClass::Unauthorized,
                ErrorClass::Unauthorized,
            ),
            (
                ClientError::RequestTooLarge,
                ErrorClass::ResourceExhausted,
                ErrorClass::ResourceExhausted,
            ),
        ] {
            assert_eq!(classify(&error, false), read, "read {error}");
            assert_eq!(classify(&error, true), write, "write {error}");
        }
        let retained = Failure::retained(kasumi_types::Error::new(
            ErrorCode::Conflict,
            "document precondition failed",
        ));
        assert_eq!(
            (retained.class, retained.code),
            (ErrorClass::PreconditionFailed, Some(ErrorCode::Conflict))
        );
        assert_eq!(
            Failure::retained(kasumi_types::Error::new(
                ErrorCode::Forbidden,
                "append-only"
            ))
            .class,
            ErrorClass::Unauthorized
        );
    }

    #[test]
    fn a_retained_outcome_of_the_batch_overrides_what_its_attempt_reported() {
        let database =
            |code| ClientError::Transport(crate::api::status(kasumi_types::Error::new(code, "x")));
        let receipt = WriteReceipt {
            revision: 12,
            versions: BTreeMap::from([("/claims/op-1".to_owned(), 12)]),
        };
        let stale = || {
            Retained::Outcome(Err(kasumi_types::Error::new(
                ErrorCode::Conflict,
                "document precondition failed",
            )))
        };
        let failed = |code| Failure::write(&database(code), "k");
        // A commit hidden behind a later refusal or a lost reply is a success.
        for code in [
            ErrorCode::Conflict,
            ErrorCode::UnknownOutcome,
            ErrorCode::ResourceExhausted,
        ] {
            assert_eq!(
                settle(failed(code), Retained::Outcome(Ok(receipt.clone())), "k"),
                Ok(receipt.clone())
            );
        }
        // A retained rejection is this batch's final outcome.
        for code in [ErrorCode::Conflict, ErrorCode::UnknownOutcome] {
            let failure = settle(failed(code), stale(), "k").unwrap_err();
            assert_eq!(
                (
                    failure.class,
                    failure.code,
                    failure.idempotency_key.as_deref()
                ),
                (
                    ErrorClass::PreconditionFailed,
                    Some(ErrorCode::Conflict),
                    Some("k")
                )
            );
        }
        // A key retained for other input never applies this batch.
        let reused = settle(failed(ErrorCode::Conflict), Retained::OtherBatch, "k").unwrap_err();
        assert_eq!(reused, failed(ErrorCode::Conflict));
        let reused =
            settle(failed(ErrorCode::UnknownOutcome), Retained::OtherBatch, "k").unwrap_err();
        assert_eq!((reused.class, reused.code), (ErrorClass::Conflict, None));
        // Without a retained outcome the attempt's own class stands: uncertain
        // stays uncertain, and only a definite refusal stays definite.
        for code in [
            ErrorCode::UnknownOutcome,
            ErrorCode::Conflict,
            ErrorCode::Forbidden,
        ] {
            assert_eq!(
                settle(failed(code), Retained::Unknown, "k").unwrap_err(),
                failed(code)
            );
        }
        assert_eq!(
            failed(ErrorCode::UnknownOutcome).class,
            ErrorClass::Uncertain
        );
        for (error, sent) in [
            (ClientError::Connection(anyhow::anyhow!("refused")), false),
            (ClientError::Authorization, false),
            (ClientError::RequestTooLarge, false),
            (database(ErrorCode::Forbidden), true),
            (ClientError::InvalidResponse("receipt"), true),
        ] {
            assert_eq!(dispatched(&error), sent, "{error}");
        }
    }

    #[tokio::test]
    async fn a_command_that_stops_unexpectedly_still_reports_its_class() {
        fn stop() -> std::result::Result<Vec<u8>, Failure> {
            panic!("injected command failure")
        }
        let batch =
            MutationBatch::with_key("is/run-1/op-1/claim").insert("claims", "op-1", json!({}));
        for (command, class, key) in [
            (
                DataCommand::Write(batch.clone()),
                ErrorClass::Uncertain,
                Some("is/run-1/op-1/claim"),
            ),
            (
                DataCommand::ResolveMutation {
                    original: batch,
                    scope: None,
                },
                ErrorClass::Internal,
                Some("is/run-1/op-1/claim"),
            ),
            (DataCommand::Collections, ErrorClass::Internal, None),
        ] {
            let failure = guarded(interrupted(&command), async { stop() })
                .await
                .unwrap_err();
            assert_eq!(
                (failure.class, failure.idempotency_key.as_deref()),
                (class, key),
                "{command:?}"
            );
            assert!(!failure.message.contains("injected"), "{failure:?}");
        }
        let finished = guarded(interrupted(&DataCommand::Collections), async {
            Ok(b"{}".to_vec())
        });
        assert_eq!(finished.await.unwrap(), b"{}");
    }

    #[tokio::test]
    async fn profile_pins_are_compared_before_connecting() {
        use kasumi_client::{ProfileAuthorityEndpoint, ProfileTlsFiles};
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = |name: &str| directory.path().join(name);
        let incarnation = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        // The TLS files do not exist: a check that passes reaches TLS loading
        // and fails there, while a check that differs never gets that far.
        let profile = ClientProfile {
            format: 2,
            family_id,
            tenant: "default".into(),
            principal: "application".into(),
            resource: CredentialResource::Database { incarnation },
            native_endpoint: "https://localhost:9".into(),
            administrative_members: BTreeMap::from([(
                1,
                ProfileAuthorityEndpoint {
                    endpoint: "https://localhost:10".into(),
                    certificate_pins: BTreeSet::from(["ab".repeat(32)]),
                },
            )]),
            mcp_endpoint: "https://localhost:11/mcp".into(),
            identity: ProfileTlsFiles {
                certificate: path("client.pem"),
                private_key: path("client-key.pem"),
            },
            server_ca: path("ca.pem"),
            native_certificate_pin: "cd".repeat(32),
            bearer_file: path("token"),
        };
        let bytes = serde_json::to_vec(&profile).unwrap();
        std::fs::write(path("profile.json"), &bytes).unwrap();
        std::fs::set_permissions(path("profile.json"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let profile_path = path("profile.json").display().to_string();
        let digest = hex::encode(Sha256::digest(&bytes));
        let invoke = |command: String| {
            let profile_path = profile_path.clone();
            async move {
                let mut out = Vec::new();
                let arguments = args(&format!("--profile {profile_path} {command}"));
                let status = run(
                    arguments.into_iter().map(OsString::from).collect(),
                    &mut out,
                )
                .await;
                let document: Value = serde_json::from_slice(&out).unwrap();
                assert_eq!(out.iter().filter(|byte| **byte == b'\n').count(), 1);
                (status, document)
            }
        };
        let check = |options: String| invoke(format!("{options}collections"));
        let binding = |tenant: &str, family: Uuid| {
            format!(
                "--expect-tenant {tenant} --expect-incarnation {incarnation} --expect-principal application --expect-family-id {family} "
            )
        };
        for options in [
            format!("--expect-profile-sha256 {} ", "0".repeat(64)),
            binding("other", family_id),
            binding("default", Uuid::new_v4()),
            format!(
                "--expect-profile-sha256 {digest} {}",
                binding("default", Uuid::new_v4())
            ),
        ] {
            let (status, document) = check(options.clone()).await;
            assert_eq!(status, ErrorClass::ProfileRejected.exit_code(), "{options}");
            assert_eq!(document["error"]["class"], json!("profile_rejected"));
            let message = document["error"]["message"].as_str().unwrap();
            assert!(!message.contains("opening"), "{options}: {message}");
        }
        let (status, document) = check(format!(
            "--expect-profile-sha256 {digest} {}",
            binding("default", family_id)
        ))
        .await;
        assert_eq!(status, ErrorClass::ProfileRejected.exit_code());
        let message = document["error"]["message"].as_str().unwrap();
        assert!(message.contains("client.pem"), "{message}");

        // With its TLS files in place, the profile's bearer file is checked
        // before connecting; a problem there is the profile's, not the server's.
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        for (name, contents) in [
            ("client.pem", certificate.pem()),
            ("client-key.pem", key.serialize_pem()),
            ("ca.pem", certificate.pem()),
        ] {
            std::fs::write(path(name), contents).unwrap();
            std::fs::set_permissions(path(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (status, document) = invoke("put docs a {} --key k-1".into()).await;
        assert_eq!(
            status,
            ErrorClass::ProfileRejected.exit_code(),
            "{document}"
        );
        assert_eq!(document["error"]["idempotency_key"], json!("k-1"));
        let message = document["error"]["message"].as_str().unwrap();
        assert!(message.contains("bearer file"), "{message}");
        std::fs::write(path("token"), "synthetic-bearer-for-profile-checks").unwrap();
        std::fs::set_permissions(path("token"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let (status, document) = check(String::new()).await;
        assert_eq!(
            status,
            ErrorClass::ProfileRejected.exit_code(),
            "{document}"
        );
        let message = document["error"]["message"].as_str().unwrap();
        assert!(message.contains("owner-only"), "{message}");
        assert!(!message.contains("synthetic-bearer"), "{message}");
        // A readable bearer file passes; nothing listens at the endpoint.
        std::fs::set_permissions(path("token"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let (status, document) = check(String::new()).await;
        assert_eq!(status, ErrorClass::Unavailable.exit_code(), "{document}");

        let control = ClientProfile {
            resource: CredentialResource::Control { incarnation },
            ..profile
        };
        std::fs::write(path("profile.json"), serde_json::to_vec(&control).unwrap()).unwrap();
        let (status, document) = check(String::new()).await;
        assert_eq!(status, ErrorClass::ProfileRejected.exit_code());
        assert_eq!(
            document["error"]["message"],
            json!("data commands need a database profile")
        );
        let (status, document) = check("--expect-tenant default ".into()).await;
        assert_eq!(status, ErrorClass::InvalidRequest.exit_code());
        assert_eq!(document["ok"], json!(false));
    }

    #[tokio::test]
    async fn a_write_that_was_never_sent_is_unavailable_rather_than_uncertain() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let identity = kasumi_transport::TlsIdentity::from_pem(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        // Nothing listens on a port that was just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let session = |timeout| {
            Session::new(
                KasumiClientConfig {
                    endpoint: format!("https://localhost:{port}"),
                    identity: identity.clone(),
                    trusted_ca_pem: certificate.pem().into_bytes(),
                    server_certificate_pins: BTreeSet::from([identity.certificate_pin()]),
                },
                Arc::new(|| -> Result<zeroize::Zeroizing<String>> { bail!("no request is sent") }),
                MutationReceiptScope {
                    tenant: "default".into(),
                    incarnation: Uuid::from_u128(2).to_string(),
                    principal: "application".into(),
                },
                Uuid::from_u128(2),
                Instant::now() + timeout,
            )
        };
        let batch =
            MutationBatch::with_key("is/run-1/op-1/intent").insert("intents", "op-1", json!({}));
        let refused = execute(
            DataCommand::Write(batch.clone()),
            &session(Duration::from_secs(5)),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (refused.class, refused.idempotency_key.as_deref()),
            (ErrorClass::Unavailable, Some("is/run-1/op-1/intent")),
            "{refused:?}"
        );
        let expired = session(Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(5)).await;
        for command in [
            DataCommand::Write(batch.clone()),
            DataCommand::ResolveMutation {
                original: batch,
                scope: None,
            },
            DataCommand::ReadSnapshot(ReadSnapshotRequest {
                documents: vec![kasumi_types::DocumentKey {
                    collection: "intents".into(),
                    id: "op-1".into(),
                }],
                queries: vec![],
                time_bounds: None,
            }),
        ] {
            let failure = execute(command, &expired).await.unwrap_err();
            assert_eq!(failure.class, ErrorClass::Unavailable, "{failure:?}");
        }
    }
}
