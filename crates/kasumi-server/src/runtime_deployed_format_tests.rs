//! Standalone installations written by the deployed builds
//! (`tests/deployed-format`), served by the current runtime.
//!
//! Each copy is unpacked into a new directory and opened as `kasumid serve`
//! opens it. The build that wrote the copy recorded what it answered for
//! every document, query, receipt, policy, limit and credential before it
//! stopped; the current code must give the same answers from those bytes,
//! then write, snapshot, compact, stop and reopen without losing any of them
//! or changing the pinned root, envelope and directory layouts on disk.
//!
//! An installation is bound to its directory, so a copy elsewhere is refused
//! at three places. `rebind` moves exactly those: the path strings in the
//! plaintext configuration and markers, the service audit head's archive
//! identity, and each store's tenant audit cache placement (through the
//! store's own relocation), in a child process of the test binary so that
//! the runtime installs the first persistent disk owner over the copy in
//! this one. The filesystem backup destination names its
//! directory by inode and cannot follow a copy; it is left out of the copy's
//! configuration.
use super::*;
use crate::{
    auth::AuthKeySource, local_auth::LocalCredentials, serving_runtime::TenantServingConfig,
};
use kasumi_store::{FilesystemAuditArchive, StorageAccess, WriteOp};
use kasumi_types::{
    CollectionDefinition, MutationBatch, Operation, QueryRequest, QueryRow, ReadPolicyLimits,
    RequestAuthorization,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[path = "../../../tests/deployed-format/support.rs"]
mod support;
use support::{FIRST_CLEAN, FIRST_KILLED, Fixtures, SECOND_CLEAN, layout};

const TENANT: &str = "default";
/// Manifests carry a digest instead of any longer string.
const LONG_STRING: usize = 4096;
/// Bound for waits on work this test started. A wait ends as soon as the work
/// does; the bound only keeps a broken store from hanging the suite.
const PATIENCE: Duration = Duration::from_secs(900);
const SERVICE_AUDIT_META: &str = "security.audit.meta";
const BOOTSTRAP: &str = "engine.bootstrap";

fn context(principal: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: TENANT.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}

fn administrator() -> RequestContext {
    context("administrator")
}

/// The manifest form of a JSON value: long strings become their digest.
fn summarize(value: &Value) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(name, member)| (name.clone(), summarize(member)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(summarize).collect()),
        Value::String(text) if text.len() > LONG_STRING => json!({
            "$sha256": hex::encode(Sha256::digest(text.as_bytes())),
            "$bytes": text.len(),
        }),
        other => other.clone(),
    }
}

/// Every member the deployed build reported is reported unchanged. The
/// current code may add members the deployed build did not have.
fn require_reported(expected: &Value, actual: &Value, at: &str) -> Result<()> {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (name, value) in expected {
                let found = actual
                    .get(name)
                    .with_context(|| format!("{at}/{name} is no longer reported"))?;
                require_reported(value, found, &format!("{at}/{name}"))?;
            }
            Ok(())
        }
        (Value::Array(expected), Value::Array(actual)) => {
            ensure!(
                expected.len() == actual.len(),
                "{at} has {} items, the deployed build reported {}",
                actual.len(),
                expected.len()
            );
            for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                require_reported(expected, actual, &format!("{at}/{index}"))?;
            }
            Ok(())
        }
        _ => {
            ensure!(
                expected == actual,
                "{at} is {actual}, the deployed build reported {expected}"
            );
            Ok(())
        }
    }
}

/// One unpacked copy and the configuration that serves it where it is now.
struct Copy {
    _directory: tempfile::TempDir,
    root: PathBuf,
    manifest: Value,
    /// The directory the deployed build served this installation in.
    original: String,
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
}

enum Source<'fixtures> {
    Packed(&'fixtures Fixtures, &'static str),
    /// A generator copy on disk: `<directory>/installation` and its manifest.
    Directory(PathBuf),
}

/// Copy a generator copy as the packed ones are extracted: owner-only
/// directories, files with the generator's owner-only modes.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Replace the original directory in every plaintext JSON file of the copy.
fn rewrite_paths(directory: &Path, original: &str, current: &str) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if entry.file_name() != "node.kv" {
                rewrite_paths(&path, original, current)?;
            }
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let text = std::fs::read_to_string(&path)?;
            if text.contains(original) {
                std::fs::write(&path, text.replace(original, current))?;
            }
        }
    }
    Ok(())
}

fn install(source: Source<'_>) -> Result<Copy> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = std::fs::canonicalize(directory.path())?.join("installation");
    let manifest = match source {
        Source::Packed(fixtures, fixture) => {
            fixtures.extract(fixture, &root)?;
            support::manifest(fixture)
        }
        Source::Directory(copy) => {
            copy_tree(&copy.join("installation"), &root)?;
            std::fs::read_to_string(copy.join("manifest.json"))?
        }
    };
    let manifest: Value = serde_json::from_str(&manifest)?;
    let original = manifest["installation"]["directory"]
        .as_str()
        .context("the manifest names no installation directory")?
        .to_owned();
    rewrite_paths(
        &root,
        &original,
        root.to_str().context("temporary path is not UTF-8")?,
    )?;
    let mut config = RuntimeConfig::load(root.join("kasumi.json"))?;
    ensure!(
        config.mode == DeploymentMode::Standalone && config.database_path.starts_with(&root),
        "the copy's configuration does not name the copy"
    );
    // The enrolled backup directory is identified by its inode, which no copy
    // keeps. The tenant's own backup bindings stay in its state.
    config.backup_destinations.clear();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = listeners[0].local_addr()?;
    config.native.listen = listeners[1].local_addr()?;
    config.admin.listen = listeners[2].local_addr()?;
    drop(listeners);
    let storage =
        crate::runtime_memory::RuntimeStorage::isolated_installation(config.admission.clone())?;
    Ok(Copy {
        _directory: directory,
        root,
        manifest,
        original,
        config,
        storage,
    })
}

const REBIND_ROOT: &str = "KASUMI_DEPLOYED_FORMAT_REBIND_ROOT";
const REBIND_ORIGINAL: &str = "KASUMI_DEPLOYED_FORMAT_REBIND_ORIGINAL";
const REBIND_OUTPUT: &str = "KASUMI_DEPLOYED_FORMAT_REBIND_OUTPUT";

/// Rebind the copy in a child process of this test binary. A process keeps
/// the persistent disk owner it installed over the copy's directories, and
/// the runtime this test serves must be the first to install one.
fn rebind_in_child(copy: &Copy) -> Result<BTreeMap<String, Vec<u8>>> {
    let output = copy.root.with_file_name("bootstraps.json");
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "runtime::deployed_format_tests::rebind_a_copy_in_this_process",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(REBIND_ROOT, &copy.root)
        .env(REBIND_ORIGINAL, &copy.original)
        .env(REBIND_OUTPUT, &output)
        .status()?;
    ensure!(status.success(), "rebinding the copy failed: {status}");
    let stored: BTreeMap<String, String> = serde_json::from_slice(&std::fs::read(&output)?)?;
    stored
        .into_iter()
        .map(|(tenant, manifest)| Ok((tenant, hex::decode(manifest)?)))
        .collect()
}

/// The child half of `rebind_in_child`; without its variables, nothing.
#[test]
fn rebind_a_copy_in_this_process() {
    let Some(root) = std::env::var_os(REBIND_ROOT).map(PathBuf::from) else {
        return;
    };
    let original = std::env::var(REBIND_ORIGINAL).unwrap();
    let output = PathBuf::from(std::env::var_os(REBIND_OUTPUT).unwrap());
    std::thread::Builder::new()
        .name("deployed rebind".into())
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(async move {
                    let bootstraps = rebind(&root, &original).await?;
                    let stored: BTreeMap<_, _> = bootstraps
                        .into_iter()
                        .map(|(tenant, manifest)| (tenant, hex::encode(manifest)))
                        .collect();
                    std::fs::write(&output, serde_json::to_vec(&stored)?)?;
                    anyhow::Ok(())
                }))
                .unwrap_or_else(|error| panic!("{error:#}"));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Move the bindings that name the installation's directory to the copy, and
/// return each group's bootstrap manifest as the deployed build stored it.
async fn rebind(root: &Path, original: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut config = RuntimeConfig::load(root.join("kasumi.json"))?;
    config.backup_destinations.clear();
    let config = &config;
    let current = root.to_str().context("temporary path is not UTF-8")?;
    let storage =
        crate::runtime_memory::RuntimeStorage::isolated_installation(config.admission.clone())?;
    let _admission = storage.facade(&config.admission)?;
    let disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
    let scratch = storage.open_scratch(&config.scratch_disk)?;
    let node = NodeStore::open_existing(
        &config.database_path,
        config.database_id,
        disk.clone(),
        scratch,
        disk.native_storage_config(),
    )
    .map_err(|failure| anyhow::anyhow!("the deployed node group did not open: {failure}"))?;
    let source: crate::serving_runtime::CredentialSource = Arc::new(file_secret);

    let security = TenantStore::open_existing(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        config.security_audit.keys.provider(source.clone())?,
        StorageAccess::security_audit(),
    )
    .await?;
    let head = security
        .get(SERVICE_AUDIT_META, b"head")?
        .context("the deployed service audit head is missing")?;
    let head = String::from_utf8(head.to_vec())?;
    ensure!(
        head.contains(original),
        "the service audit head does not name the original archive directory"
    );
    security.write_batch(&[WriteOp::put(
        SERVICE_AUDIT_META,
        b"head",
        head.replace(original, current).into_bytes(),
    )])?;
    security.shutdown().await?;
    drop(security);

    let mut groups = vec![(
        CONTROL_TENANT.to_owned(),
        &config.control.keys,
        &config.control.custody_keys,
        StorageAccess::node_control(),
    )];
    for tenant in &config.tenants {
        let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
            anyhow::bail!("the deployed installation is standalone");
        };
        let incarnation = Uuid::parse_str(
            tenant
                .incarnation
                .as_deref()
                .context("tenant incarnation missing")?,
        )?;
        groups.push((
            tenant.tenant.clone(),
            &tenant.keys,
            &tenant.custody_keys,
            StorageAccess::standalone(installation_id, &tenant.tenant, incarnation)?,
        ));
    }
    let mut bootstraps = BTreeMap::new();
    for (tenant, keys, custody_keys, access) in groups {
        let stores = TenantStorageSet::open_existing(
            node.clone(),
            tenant.clone(),
            keys.provider(source.clone())?,
            custody_keys.provider(source.clone())?,
            access,
        )
        .await?;
        let store = stores.application();
        let (cache, _) = store
            .installed_tenant_audit_placement()?
            .with_context(|| format!("{tenant} has no installed audit placement"))?;
        let installed = kasumi_store::filesystem_archive_directory(&cache)
            .context("the installed audit cache is not a directory")?;
        ensure!(
            installed.starts_with(original),
            "{tenant}'s audit cache is outside the original installation"
        );
        let moved = Arc::new(FilesystemAuditArchive::open(
            config.tenant_audit_cache_directory(store)?,
            disk.clone(),
        )?);
        ensure!(
            store.relocate_tenant_audit_cache(&cache, &moved)?,
            "{tenant}'s audit cache already named the copy"
        );
        drop(moved);
        bootstraps.insert(
            tenant.clone(),
            store
                .get(BOOTSTRAP, b"manifest")?
                .with_context(|| format!("{tenant} has no bootstrap manifest"))?
                .to_vec(),
        );
        stores.shutdown().await?;
        drop(stores);
    }
    // Close the database before the runtime opens the same files.
    node.shutdown().await?;
    drop(node);
    Ok(bootstraps)
}

struct Serving {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
    registry: DatabaseRegistry,
    administration: Arc<crate::administration::Administration>,
    security: Arc<TenantStore>,
    control: Arc<Database>,
}

impl Serving {
    async fn start(copy: &Copy) -> Result<Self> {
        let runtime =
            NodeRuntime::open_using_storage(copy.config.clone(), file_secret, copy.storage.clone())
                .await?;
        let registry = runtime.registry().clone();
        let administration = runtime
            .administration
            .clone()
            .context("a standalone runtime has its administration")?;
        let security = runtime.security_audit().store().clone();
        let control = runtime.control_database().clone();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(runtime.serve(shutdown));
        let serving = Self {
            stop,
            task,
            registry,
            administration,
            security,
            control,
        };
        let started = Instant::now();
        while serving.registry.database(&administrator()).is_err() {
            ensure!(
                !serving.task.is_finished() && started.elapsed() < PATIENCE,
                "the deployed tenant did not serve"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(serving)
    }

    fn database(&self) -> Result<Arc<Database>> {
        Ok(self.registry.database(&administrator())?)
    }

    async fn stop(self) -> Result<()> {
        let Self {
            stop,
            task,
            registry,
            administration,
            security,
            control,
        } = self;
        drop((registry, administration, security, control));
        stop.send(true)?;
        task.await?
    }
}

async fn wait_for(what: &str, mut done: impl FnMut() -> Result<bool>) -> Result<()> {
    let started = Instant::now();
    while !done()? {
        ensure!(started.elapsed() < PATIENCE, "{what} did not finish");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Every page of one query, as the deployed build's client collected them.
async fn query_all(database: &Database, request: &Value) -> Result<(u64, Vec<QueryRow>, Value)> {
    let mut request: QueryRequest = serde_json::from_value(request.clone())?;
    let mut rows = Vec::new();
    loop {
        let page = database.query(&administrator(), request.clone()).await?;
        rows.extend(page.rows.iter().cloned());
        match &page.cursor {
            Some(cursor) => request.cursor = Some(cursor.clone()),
            None => return Ok((page.revision, rows, Value::Array(page.aggregates.clone()))),
        }
    }
}

/// The rows of one query in manifest form, without relevance scores.
fn manifest_rows(rows: &[QueryRow]) -> Vec<Value> {
    rows.iter()
        .map(|row| json!({"id": row.id, "version": row.version, "body": summarize(&row.body)}))
        .collect()
}

/// What the current code answers for every manifest query: the rows and
/// aggregates only, so it can be compared across this test's own restarts.
async fn answers(database: &Database, manifest: &Value) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    for query in manifest["queries"].as_array().context("queries")? {
        let (_, rows, aggregates) = query_all(database, &query["request"]).await?;
        all.push(
            json!({"name": query["name"], "rows": manifest_rows(&rows), "aggregates": aggregates}),
        );
    }
    Ok(all)
}

/// Compare the current code's answers with the deployed build's own.
/// Revisions only move forward: the writing build kept serving, and audited
/// reads of the manifest itself committed audit records, after a query ran.
async fn check_manifest(database: &Database, manifest: &Value) -> Result<()> {
    let admin = administrator();
    let collections = serde_json::to_value(database.collections(&admin).await?)?;
    require_reported(&manifest["collections"], &collections, "collections")?;
    for definition in manifest["collections"].as_array().context("collections")? {
        // The stored definition still parses as the current type.
        serde_json::from_value::<CollectionDefinition>(definition.clone())?;
    }

    let documents = manifest["documents"].as_object().context("documents")?;
    ensure!(documents.len() == 4, "the manifest lists every collection");
    for (collection, expected) in documents {
        for expected in expected.as_array().context("documents")? {
            let id = expected["id"].as_str().context("document id")?;
            let found = database
                .get(&admin, collection, id)
                .await?
                .with_context(|| format!("{collection}/{id} is missing"))?;
            ensure!(
                json!(found.version) == expected["version"]
                    && summarize(&found.body) == expected["body"],
                "{collection}/{id} differs from the deployed build's answer"
            );
        }
    }
    for absent in manifest["absent"].as_array().context("absent")? {
        let (collection, id) = (
            absent["collection"].as_str().context("collection")?,
            absent["id"].as_str().context("id")?,
        );
        ensure!(
            database.get(&admin, collection, id).await?.is_none(),
            "{collection}/{id} was deleted by the deployed build"
        );
    }

    for query in manifest["queries"].as_array().context("queries")? {
        let name = &query["name"];
        let (revision, rows, aggregates) = query_all(database, &query["request"]).await?;
        let expected = query["rows"].as_array().context("rows")?;
        ensure!(
            manifest_rows(&rows)
                == expected
                    .iter()
                    .map(|row| json!({"id": row["id"], "version": row["version"], "body": row["body"]}))
                    .collect::<Vec<_>>(),
            "query {name} returns different rows"
        );
        for (row, expected) in rows.iter().zip(expected) {
            // Relevance comes from corpus statistics, not from a persisted
            // value, and the current scores differ by a few percent; the
            // ranking is the rows' order above.
            let (found, expected) = (row.score.map(f64::from), expected["score"].as_f64());
            ensure!(
                match (found, expected) {
                    (Some(found), Some(_)) => found.is_finite() && found > 0.0,
                    (None, None) => true,
                    _ => false,
                },
                "query {name} scores {} as {found:?}, not {expected:?}",
                row.id
            );
        }
        ensure!(
            aggregates == query["aggregates"],
            "query {name} aggregates {aggregates}, the deployed build reported {}",
            query["aggregates"]
        );
        ensure!(
            query["revision"]
                .as_u64()
                .is_some_and(|recorded| revision >= recorded),
            "query {name} reads revision {revision}, before the deployed build's"
        );
    }

    // Permanent receipts: the retained outcome of each original batch, and
    // the same outcome again when the identical batch is resent.
    for receipt in manifest["receipts"].as_array().context("receipts")? {
        let principal = context(receipt["principal"].as_str().context("principal")?);
        let batch: MutationBatch = serde_json::from_value(receipt["batch"].clone())?;
        let resolution = &receipt["resolution"];
        let retained = database
            .operation_receipt(&principal, &batch.idempotency_key)
            .await?
            .with_context(|| format!("receipt {} is not retained", batch.idempotency_key))?;
        ensure!(
            json!(retained.request_digest) == resolution["request_digest"]
                && serde_json::to_value(&retained.scope)? == resolution["scope"],
            "receipt {} names another request",
            batch.idempotency_key
        );
        // A resent batch returns its receipt and is not applied again; the
        // current code may still audit the resolution.
        let resent = database.mutate(principal, batch.clone()).await;
        ensure!(
            resent == retained.outcome,
            "resending {} returned {resent:?}, not its retained {:?}",
            batch.idempotency_key,
            retained.outcome
        );
        match (&retained.outcome, resolution["outcome"].as_str()) {
            (Ok(written), Some("committed")) => ensure!(
                serde_json::to_value(written)? == resolution["receipt"],
                "receipt {} differs",
                batch.idempotency_key
            ),
            (Err(error), Some("rejected")) => ensure!(
                serde_json::to_value(error.code)? == resolution["error"]["code"]
                    && json!(error.message) == resolution["error"]["message"],
                "rejection {} differs: {error}",
                batch.idempotency_key
            ),
            (outcome, expected) => {
                anyhow::bail!(
                    "receipt {} is {outcome:?}, not {expected:?}",
                    batch.idempotency_key
                )
            }
        }
    }

    // Policy and the serialized limits, read back through the same request.
    let expected = &manifest["policy_limits"];
    let found = serde_json::to_value(
        database
            .read_policy_limits(
                &admin,
                ReadPolicyLimits {
                    tenant: TENANT.into(),
                    expected_incarnation: manifest["installation"]["incarnation"]
                        .as_str()
                        .context("incarnation")?
                        .into(),
                },
            )
            .await?,
    )?;
    for member in [
        "tenant",
        "incarnation",
        "policy_epoch",
        "schema_epoch",
        "policy",
        "limits",
    ] {
        require_reported(
            &expected[member],
            &found[member],
            &format!("policy_limits/{member}"),
        )?;
    }
    ensure!(
        found["revision"]
            .as_u64()
            .zip(expected["revision"].as_u64())
            .is_some_and(|(found, recorded)| found >= recorded),
        "the tenant is at revision {}, before the deployed build's",
        found["revision"]
    );

    // The decoded tenant state behind those answers.
    let generation = database.engine().generation()?;
    let state = &generation.state;
    // Backup bindings are Control's; the tenant's head stays empty.
    ensure!(
        json!(state.backup_binding_head.origin_incarnation)
            == manifest["installation"]["incarnation"],
        "the tenant's backup binding head belongs to another incarnation"
    );
    // Activations are keyed by a digest of the principal and their id.
    ensure!(
        state.schema_activations.values().any(|activation| {
            activation.activation_id == "notes-v1"
                && activation.collections.contains("notes")
                && activation.outcome.is_ok()
        }),
        "the schema activation is not retained"
    );
    ensure!(
        state.mutation_receipt_head.count > 100,
        "the receipt head lists {} receipts",
        state.mutation_receipt_head.count
    );
    let audit = &manifest["tenant_audit"];
    let recorded = |field: &str| audit[field].as_u64().context("tenant audit figure");
    ensure!(
        state.audit_retention.next_sequence >= recorded("next_sequence")?
            && state.audit_retention.archive_segments >= recorded("archive_segments")?
            && recorded("archive_segments")? > 0,
        "the tenant audit stream lost records or archive segments"
    );
    Ok(())
}

/// The durable credential records, read as the administrative API reads them.
fn check_credentials(copy: &Copy, serving: &Serving) -> Result<()> {
    let AuthKeySource::Local { signer_file } = &copy.config.auth.source else {
        anyhow::bail!("the deployed installation issues its own credentials");
    };
    let credentials = LocalCredentials::open(
        serving.security.clone(),
        signer_file.clone(),
        copy.config.auth.issuer.clone(),
        copy.config.auth.audience.clone(),
    )?;
    let recorded = copy.manifest["credentials"]
        .as_array()
        .context("credentials")?;
    ensure!(
        recorded.len() == 5,
        "the manifest lists five credential families"
    );
    let mut revoked = 0;
    for credential in recorded {
        let family = Uuid::parse_str(credential["family_id"].as_str().context("family")?)?;
        let status = serde_json::to_value(credentials.status(family)?)?;
        require_reported(
            &credential["status"],
            &status,
            &format!("credential {family}"),
        )?;
        revoked += usize::from(!status["revoked_at_ms"].is_null());
    }
    ensure!(revoked == 1, "one family was revoked by the deployed build");
    Ok(())
}

/// The node group's files as they are on disk: the pinned envelope of each,
/// the pinned root slots and Fixed directory arenas.
fn check_node_files(copy: &Copy) -> Result<[Vec<(u8, u64)>; 2]> {
    let node = &copy.config.database_path;
    let root = std::fs::read(node.join(layout::ROOT_FILE_NAME))?;
    let garbage = layout::check_root_file(&root);
    let id = &root[layout::NODE_STORE_ID_AT];
    ensure!(
        id == copy.config.database_id.as_bytes(),
        "the root names another node store"
    );
    let mut pages = 0;
    for entry in std::fs::read_dir(node)? {
        let name = entry?.file_name();
        let name = name.to_str().context("group file name")?;
        if name == layout::ROOT_FILE_NAME {
            continue;
        }
        let file = std::fs::read(node.join(name))?;
        if file.len() < layout::ENVELOPE_BYTES {
            // Created and not yet written: its first write adds the envelope.
            continue;
        }
        layout::check_envelope(name, &file, id);
        pages += layout::check_data_file(name, &file[layout::ENVELOPE_BYTES..], id);
    }
    ensure!(pages > 0, "the node group has no directory pages");
    Ok(garbage)
}

/// Writes of every kind through the current code, beside the deployed data.
async fn write(database: &Database) -> Result<()> {
    let admin = administrator();
    let existing = database
        .get(&admin, "accounts", "acct-000")
        .await?
        .context("acct-000")?;
    let version = existing.version;
    drop(existing);
    let large = "current build ".repeat(20_000);
    let batch = MutationBatch::with_key("current-build-1")
        .insert(
            "accounts",
            "current-1",
            json!({"email": "current@example.test", "balance": 31337, "region": "jp",
                   "status": "open", "tags": ["current"], "scores": [6], "credit": "1500.00",
                   "active": true, "notes": "settlement invoices of the current build",
                   "memo": "東京の現在"}),
        )
        .replace(
            "accounts",
            "acct-000",
            json!({"email": "user0@example.test", "balance": 1, "status": "closed"}),
            version,
        )
        .insert(
            "ledger",
            "current-0001",
            json!({"account": "acct-001", "seq": 700000, "amount": "12.34"}),
        )
        .insert(
            "blobs",
            "blob-current",
            json!({"label": "current", "data": large}),
        )
        .delete("accounts", "acct-005");
    database.mutate(admin.clone(), batch).await?;
    // The deployed unique index still refuses a second owner of an address.
    let duplicate = MutationBatch::with_key("current-build-duplicate").insert(
        "accounts",
        "current-duplicate",
        json!({"email": "user10@example.test"}),
    );
    ensure!(
        database.mutate(admin.clone(), duplicate).await.is_err(),
        "the deployed unique index accepted a duplicate"
    );
    // The append-only collection still refuses an overwrite.
    let overwrite = MutationBatch::with_key("current-build-overwrite").upsert(
        "ledger",
        "acct-000-0000",
        json!({"account": "acct-000", "seq": 0, "amount": "0.00"}),
    );
    ensure!(
        database.mutate(admin.clone(), overwrite).await.is_err(),
        "the deployed append-only collection accepted an overwrite"
    );
    database
        .administer(
            admin.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "current".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    database
        .mutate(
            admin.clone(),
            MutationBatch::with_key("current-build-2").insert("current", "one", json!({"n": 1})),
        )
        .await?;
    let found = query_all(
        database,
        &json!({"collection": "accounts", "filter": {"/email": "current@example.test"}}),
    )
    .await?;
    ensure!(
        found.1.len() == 1 && found.1[0].id == "current-1",
        "the new document is not in the deployed unique index"
    );
    let found = query_all(
        database,
        &json!({"collection": "accounts", "search": {"index": "memo_ja", "query": "現在"}}),
    )
    .await?;
    ensure!(
        found.1.iter().any(|row| row.id == "current-1"),
        "the new document is not in the deployed text index"
    );
    Ok(())
}

/// Remove what the killed build's writer may have left: the manifest of that
/// copy describes everything else.
async fn remove_in_flight(database: &Database, manifest: &Value) -> Result<()> {
    let in_flight = &manifest["in_flight"];
    let collection = in_flight["collection"].as_str().context("collection")?;
    let prefix = in_flight["id_prefix"].as_str().context("prefix")?;
    for slot in 0..8 {
        database
            .mutate(
                administrator(),
                MutationBatch::new().delete(collection, format!("{prefix}{slot}")),
            )
            .await?;
    }
    Ok(())
}

async fn serve_deployed_copy(source: Source<'_>) -> Result<()> {
    // These historical stores retain the same installed node identity. Only one
    // copy may own its serving registration in this test process at a time.
    static DEPLOYED_NODE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _node = DEPLOYED_NODE.lock().await;
    let fixture = match &source {
        Source::Packed(_, fixture) => Some(*fixture),
        Source::Directory(_) => None,
    };
    let copy = install(source)?;
    let manifest = &copy.manifest;
    let killed = !manifest["in_flight"].is_null();
    ensure!(killed == (fixture == Some(FIRST_KILLED)) || fixture.is_none());
    if !killed {
        // The copy is exactly what the deployed build left.
        let garbage = check_node_files(&copy)?;
        ensure!(
            garbage.iter().all(Vec::is_empty),
            "a clean stop left garbage"
        );
    }
    let bootstraps = rebind_in_child(&copy)?;

    // First open: the deployed build's snapshot and journal tail.
    let serving = Serving::start(&copy).await?;
    let database = serving.database()?;
    let group = database.raft_group();
    ensure!(
        group.is_local(),
        "the deployed tenant is a standalone group"
    );
    let metrics = group.metrics();
    let snapshot = metrics
        .snapshot
        .context("the deployed tenant reopened without its snapshot")?
        .index;
    let interval = manifest["written_by"]["schedule"]["snapshot_interval"]
        .as_u64()
        .context("snapshot interval")?;
    // The second build stored its snapshot by reference; the first embedded it.
    let reference = database.engine().reopened_from_reference_snapshot();
    ensure!(
        reference == (manifest["written_by"]["commit"] == "cf9959f1"),
        "the deployed snapshot has another form than its build wrote"
    );
    // Served embedded, a group reopened from a by-reference snapshot first
    // publishes an embedded one over its replayed journal tail.
    let applied = metrics.last_applied.map_or(0, |applied| applied.index);
    ensure!(
        snapshot >= interval && (applied > snapshot || reference && applied == snapshot),
        "the deployed tenant has no journal tail after its snapshot at {snapshot}"
    );
    if killed {
        remove_in_flight(&database, manifest).await?;
    }
    check_manifest(&database, manifest).await?;
    check_credentials(&copy, &serving)?;
    let control = serving.control.engine().generation()?;
    ensure!(
        control.state.audit_retention.next_sequence
            >= manifest["control_audit"]["next_sequence"]
                .as_u64()
                .unwrap_or(u64::MAX),
        "the Control audit stream lost records"
    );
    // The deployed builds' standalone backups to a local destination bind
    // nothing, so these copies hold empty binding heads and no snapshot
    // record of kind 24; the head itself is decoded from the deployed state.
    ensure!(
        json!(control.state.backup_binding_head.origin_incarnation)
            == manifest["installation"]["control_incarnation"],
        "Control's backup binding head belongs to another incarnation"
    );
    drop(control);

    // Write, snapshot and compact with the current code.
    write(&database).await?;
    let expected = answers(&database, manifest).await?;
    database.raft_group().snapshot().await?;
    wait_for("the current build's snapshot", || {
        Ok(database
            .raft_group()
            .metrics()
            .snapshot
            .is_some_and(|stored| stored.index > snapshot))
    })
    .await?;
    let store = database.stores().application().clone();
    let cycles = store.storage_maintenance_status()?.cycles_completed;
    let control = configured_control_context(&copy.config.control)?;
    let requested = serving
        .administration
        .request_storage_compaction(&control)
        .await?;
    ensure!(
        requested.iter().all(|outcome| outcome.accepted),
        "the compaction request was refused"
    );
    wait_for("the current build's compaction cycle", || {
        let status = store.storage_maintenance_status()?;
        Ok(status.cycles_completed > cycles
            && status.phase == kasumi_store::StorageCompactionPhase::Idle
            && status.garbage_files == 0)
    })
    .await?;
    ensure!(
        answers(&database, manifest).await? == expected,
        "answers changed across the snapshot and compaction"
    );
    drop((store, database));
    serving.stop().await?;

    // What the current code left on disk keeps every pinned layout, and the
    // bootstrap manifests are the deployed build's bytes. The root may list
    // garbage again: a reclaim round can start after the cycle, and the next
    // open finishes it.
    check_node_files(&copy)?;

    // Second open: this build's own snapshot of the deployed state.
    let serving = Serving::start(&copy).await?;
    let database = serving.database()?;
    ensure!(
        answers(&database, manifest).await? == expected,
        "answers changed across the restart"
    );
    for (tenant, stored) in [
        (
            CONTROL_TENANT,
            serving.control.stores().application().clone(),
        ),
        (TENANT, database.stores().application().clone()),
    ] {
        ensure!(
            stored.get(BOOTSTRAP, b"manifest")?.as_deref()
                == bootstraps.get(tenant).map(Vec::as_slice),
            "{tenant}'s bootstrap manifest changed"
        );
    }
    check_credentials(&copy, &serving)?;
    let current = database
        .get(&administrator(), "blobs", "blob-current")
        .await?
        .context("the current build's large document")?;
    ensure!(
        current.body["data"]
            .as_str()
            .is_some_and(|data| data.len() == 280_000)
    );
    drop(current);
    // Documents this test did not touch are still the deployed build's.
    let untouched = database
        .get(&administrator(), "blobs", "blob-live")
        .await?
        .context("the deployed large document")?;
    let recorded = manifest["documents"]["blobs"]
        .as_array()
        .and_then(|blobs| blobs.iter().find(|blob| blob["id"] == "blob-live"))
        .context("blob-live in the manifest")?;
    ensure!(
        summarize(&untouched.body) == recorded["body"]
            && recorded["body"]["data"]["$bytes"].is_u64(),
        "the deployed large document changed"
    );
    drop(untouched);
    drop(database);
    serving.stop().await
}

fn run(name: &'static str, fixture: &'static str) {
    // The installed stack of a generated installation needs more than
    // libtest's thread.
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(async move {
                    let fixtures = Fixtures::load();
                    serve_deployed_copy(Source::Packed(&fixtures, fixture))
                        .await
                        .unwrap_or_else(|error| panic!("{fixture}: {error:#}"));
                }));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn the_store_the_first_build_stopped_cleanly_serves_snapshots_compacts_and_reopens() {
    run("deployed 12140939 clean", FIRST_CLEAN);
}

#[test]
fn the_store_the_first_build_was_killed_in_recovers_and_serves() {
    run("deployed 12140939 killed", FIRST_KILLED);
}

#[test]
fn the_store_the_second_build_served_keeps_its_reference_snapshot_readable() {
    run("deployed cf9959f1 clean", SECOND_CLEAN);
}

/// A copy `scripts/deployed_format_fixture.py` wrote, before it is packed:
/// name its directory in `KASUMI_DEPLOYED_FORMAT_COPY` to serve it.
#[test]
fn a_named_local_copy_serves_like_the_committed_ones() {
    let Some(copy) = std::env::var_os("KASUMI_DEPLOYED_FORMAT_COPY") else {
        return;
    };
    std::thread::Builder::new()
        .name("deployed local copy".into())
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(async move {
                    serve_deployed_copy(Source::Directory(copy.into()))
                        .await
                        .unwrap_or_else(|error| panic!("{error:#}"));
                }));
        })
        .unwrap()
        .join()
        .unwrap();
}
