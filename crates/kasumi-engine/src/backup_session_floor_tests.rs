//! G11 backup-session acceptance witness on the adopted floor of 100,001
//! distinct sessions. No historical global backup-session count limit exists;
//! the floor is a new threshold. The historical controls exercised here are the
//! 64 KiB session intent/outcome record and the 256-object cleanup page.
//!
//! The parent test never opens the installation. It re-executes this test
//! binary for each stage, so every stage is a separate physical process:
//!
//! 1. `populate` creates a standalone source and its installed Control owner,
//!    checks the record boundary, and writes the cohort through the production
//!    paths: complete sessions through `backup_checkpoint_named`; failed
//!    sessions through the Control claim, intent publication and the public
//!    abort. One failed session carries more objects than one cleanup page.
//! 2. `kill` (once per reserved ordinal) arms a test hook in Control apply,
//!    journals the original input and dispatches the session write. The hook
//!    fires after the target claim or terminal row is durable and before its
//!    generation and response publish, prints `KASUMI_FLOOR_WRITE_OUTSTANDING`
//!    and blocks with the operation outstanding; the parent sends SIGKILL.
//! 3. `resolve` cold-opens, requires replay to reselect each interrupted row,
//!    resubmits each original input, completes the cohort, and fsyncs the
//!    complete sorted pre-restart observation and `resolve.json`. It then
//!    prints `KASUMI_FLOOR_PRE_RESTART_DURABLE` and keeps its stores open
//!    until the parent sends SIGKILL.
//! 4. `verify` cold-opens the same data directories, records the post-restart
//!    observation, replays every original input and requires the original
//!    outcomes with an unchanged Control ledger and destination.
//!
//! The parent then re-reads every retained stream and journal independently.
use super::*;
use anyhow::Context as _;
use kasumi_store::test_utils::LocalKeyProvider;
use kasumi_store::{BackupSessionSlot, FilesystemBackupDestination};
use serde::{Deserialize, Serialize};
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

const STAGE: &str = "KASUMI_BACKUP_FLOOR_STAGE";
const ROOT: &str = "KASUMI_BACKUP_FLOOR_ROOT";
const TARGET: &str = "KASUMI_BACKUP_FLOOR_TARGET";
const EVIDENCE: &str = "KASUMI_BACKUP_FLOOR_EVIDENCE";
const REPLAY: &str = "KASUMI_BACKUP_FLOOR_REPLAY";
const SCHEMA: &str = "kasumi-backup-session-floor-v1";
const PREFIX: &str = "KASUMI_BACKUP_SESSION_FLOOR ";
const ALIAS: &str = "floor";
const SOURCE_TENANT: &str = "floor-source";
const PRINCIPAL: &str = "owner";
/// Adopted new threshold. It is not a former limit.
const FLOOR: u64 = 100_001;
const MIN_FAILED: u64 = 257;
const INSTALLED_DEFAULT_BINDING_BYTES: u64 = 128 << 20;
/// The original input is durably journaled; the operation is dispatched next.
const DISPATCH: &str = "KASUMI_FLOOR_DISPATCH ";
/// Emitted inside Control apply after the target row is durable and before
/// its generation and response publish. The writer then blocks there with the
/// operation outstanding, and the parent sends SIGKILL.
const OUTSTANDING: &str = "KASUMI_FLOOR_WRITE_OUTSTANDING ";
/// The operation returned: its kill point was never reached.
const WRITTEN: &str = "KASUMI_FLOOR_WRITTEN ";
const CLAIMED: &str = "KASUMI_FLOOR_CLAIMED ";
/// The complete sorted pre-restart observation and `resolve.json` are fsynced;
/// the resolve process keeps its stores open until the parent sends SIGKILL.
const DURABLE: &str = "KASUMI_FLOOR_PRE_RESTART_DURABLE ";

trait Native<T> {
    fn native(self, what: &str) -> anyhow::Result<T>;
}
impl<T, E: std::fmt::Debug> Native<T> for std::result::Result<T, E> {
    fn native(self, what: &str) -> anyhow::Result<T> {
        self.map_err(|original| anyhow::anyhow!("{what}: {original:?}"))
    }
}

// The wire-facing Debug representation omits the physical cause. Preserve
// that chain in the local qualification record when a session operation fails.
fn snapshot_diagnostic(original: crate::SnapshotFailure) -> anyhow::Error {
    match original {
        crate::SnapshotFailure::Operation(error) => error.into(),
        crate::SnapshotFailure::Source(error) => error,
        other => anyhow::anyhow!("{other:?}"),
    }
}

#[test]
fn local_session_diagnostic_retains_the_storage_cause() {
    let cause = std::io::Error::from_raw_os_error(libc::EIO);
    let error = kasumi_types::Error::from_physical_source(cause.into());
    let diagnostic = snapshot_diagnostic(error.into()).context("public abort");
    assert!(diagnostic.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .and_then(|e| e.raw_os_error())
            == Some(libc::EIO)
    }));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    cohort: String,
    sessions: u64,
    failure_stride: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<SessionFloorProfile>,
    kill_reserve: u64,
    nonce: uuid::Uuid,
    control_binding_budget: u64,
    source_hot_audit_bytes: u64,
    control_hot_audit_bytes: u64,
    cleanup_objects: u64,
    /// Sessions requested per observation page, at most 256. Roots retained
    /// before this field existed used the full bound.
    #[serde(default = "full_page")]
    page_limit: usize,
}

/// A prospective workload and disk policy for a fresh installation. Every
/// cold child reloads it from the original plan on the same filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFloorProfile {
    device: u64,
    probe_sha256: String,
    directory_policy: kasumi_store::DirectoryPolicy,
    file_allocation_policy: kasumi_store::FileAllocationPolicy,
    max_persistent_files: u64,
    max_persistent_subdirectories: u64,
    /// With this interval, every nth session runs an entire checkpoint.
    /// The other original IDs are durably claimed, published and aborted.
    complete_interval: Option<u64>,
}

impl SessionFloorProfile {
    fn check(&self, root: &Path, sessions: u64) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            sessions == FLOOR,
            "measured profile requires the full session floor"
        );
        kasumi_types::validate_sha256(&self.probe_sha256)?;
        self.directory_policy.validate()?;
        self.file_allocation_policy.validate()?;
        // Every retained terminal session owns one directory and at least two
        // regular inodes. Even empty files would retain both standing promises.
        let minimum = u128::from(sessions)
            * (u128::from(self.directory_policy.extent_bytes)
                + 2 * u128::from(self.file_allocation_policy.maximum_extra_extent_bytes));
        anyhow::ensure!(
            minimum <= 200_u128 << 30,
            "permanent session inode allowances alone require {minimum} bytes of the 200 GiB installation"
        );
        anyhow::ensure!(
            self.device == root.metadata()?.dev(),
            "session profile belongs to a different filesystem"
        );
        anyhow::ensure!(
            self.complete_interval
                .is_none_or(|stride| (2..=256).contains(&stride)),
            "full workload must exercise both outcomes across at least one full page"
        );
        anyhow::ensure!(
            self.directory_policy.max_entries >= sessions + 4
                && self.max_persistent_files >= 2 * sessions
                && self.max_persistent_subdirectories >= sessions,
            "disk namespace cannot retain the requested original sessions"
        );
        Ok(())
    }
}

fn full_page() -> usize {
    crate::MAX_CONTROL_BACKUP_SESSION_PAGE
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Complete,
    Aborted,
}

impl Plan {
    fn reserve_start(&self) -> u64 {
        self.sessions - self.kill_reserve
    }
    fn kind(&self, ordinal: u64) -> Kind {
        let reserve = self.reserve_start();
        if ordinal >= reserve {
            if ordinal < reserve + self.kill_reserve / 2 {
                Kind::Complete
            } else {
                Kind::Aborted
            }
        } else if let Some(interval) = self.profile.as_ref().and_then(|p| p.complete_interval) {
            if ordinal.is_multiple_of(interval) {
                Kind::Complete
            } else {
                Kind::Aborted
            }
        } else if ordinal % self.failure_stride == self.failure_stride - 1 {
            Kind::Aborted
        } else {
            Kind::Complete
        }
    }
    fn planned_failures(&self) -> u64 {
        (0..self.sessions)
            .filter(|ordinal| self.kind(*ordinal) == Kind::Aborted)
            .count() as u64
    }
    fn session_id(&self, ordinal: u64) -> uuid::Uuid {
        let digest = Sha256::digest(format!("{SCHEMA}/{}/{ordinal}", self.nonce));
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }
    fn cleanup_ordinal(&self) -> u64 {
        if self
            .profile
            .as_ref()
            .is_some_and(|p| p.complete_interval.is_some())
        {
            1
        } else {
            self.failure_stride - 1
        }
    }
}

fn request_id(ordinal: u64) -> String {
    format!("floor-{ordinal:06}")
}

fn abort_reason(ordinal: u64) -> String {
    format!("floor failure {ordinal:06}: source capture abandoned")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ids {
    installation: uuid::Uuid,
    source_incarnation: uuid::Uuid,
    control_incarnation: uuid::Uuid,
}

/// Write, fsync, rename and fsync the directory.
fn durable_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let staged = path.with_extension("staged");
    let mut file = std::fs::File::create(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&staged, path)?;
    std::fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

/// libtest with `--nocapture` prefixes the first stdout line with
/// `test <name> ... `. End that line before any marker so every marker starts
/// its own line and strict prefix parsing holds.
fn begin_stdout() -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    durable_write(path, &serde_json::to_vec_pretty(value)?)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn file_sha256(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    Ok(hex::encode(hash.finalize()))
}

fn base_context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: tenant.into(),
        principal: PRINCIPAL.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "floor-installation".into(),
    }
}

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: PRINCIPAL.into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: false,
    }
}

/// A standalone source and its installed Control owner at a fixed directory.
struct Installation {
    storage: crate::test_utils::FixtureStorage,
    node: kasumi_store::NodeStore,
    source_stores: Arc<TenantStorageSet>,
    control_stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    source: Arc<Database>,
    control: Arc<Database>,
    destination: Arc<FilesystemBackupDestination>,
    context: RequestContext,
    operator: RequestContext,
}

impl Installation {
    async fn open(root: &Path, plan: &Plan) -> anyhow::Result<Self> {
        let create = !root.join("ids.json").exists();
        let (mut persistent, scratch) = if create {
            crate::test_utils::fixture_disk_configs(root)?
        } else {
            (
                kasumi_store::NodeDisk::fixture_config(root.join("persistent/node.kv"))?,
                kasumi_store::ScratchDiskConfig {
                    directory: root.join("scratch"),
                    max_bytes: 256 << 30,
                    min_free_bytes: 0,
                    file_allocation_policy: kasumi_store::FileAllocationPolicy::new(0).unwrap(),
                    native_cache_bytes: 8 << 20,
                },
            )
        };
        if plan.sessions == FLOOR {
            // Two terminal files and two directories per session, retained
            // checkpoint objects, and space for the original native stores.
            persistent.max_persistent_files += 4 * FLOOR;
            persistent.max_persistent_subdirectories += 2 * FLOOR;
            persistent.max_bytes = 200 << 30;
        }
        if let Some(profile) = &plan.profile {
            profile.check(root, plan.sessions)?;
            persistent.directory_policy = profile.directory_policy;
            persistent.file_allocation_policy = profile.file_allocation_policy;
            persistent.max_persistent_files = profile.max_persistent_files;
            persistent.max_persistent_subdirectories = profile.max_persistent_subdirectories;
        }
        let mut disk_policy = serde_json::json!({
            "max_bytes": persistent.max_bytes,
            "max_persistent_files": persistent.max_persistent_files,
            "max_persistent_subdirectories": persistent.max_persistent_subdirectories,
            "min_free_bytes": persistent.min_free_bytes,
        });
        if let Some(profile) = &plan.profile {
            disk_policy["profile"] = serde_json::to_value(profile)?;
        }
        let policy_path = root.join("disk-policy.json");
        if create {
            write_json(&policy_path, &disk_policy)?;
        } else if policy_path.exists() {
            anyhow::ensure!(
                read_json::<serde_json::Value>(&policy_path)? == disk_policy,
                "reopened disk policy differs"
            );
        }
        let storage =
            crate::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())?;
        let node_path = root.join("persistent/node.kv");
        let node = if create {
            storage.create_new(&node_path, kasumi_store::test_utils::NODE_STORE_ID)
        } else {
            storage.open_existing(&node_path, kasumi_store::test_utils::NODE_STORE_ID)
        }
        .inspect_err(|failure| {
            crate::test_utils::report_node_opening_failure(failure);
            if let Some(operation) = storage.persistent.pending_directory_operation() {
                eprintln!("physical directory operation: {operation:#?}");
            }
        })
        .native("node store")?;
        let ids = if create {
            Ids {
                installation: uuid::Uuid::new_v4(),
                source_incarnation: uuid::Uuid::new_v4(),
                control_incarnation: uuid::Uuid::new_v4(),
            }
        } else {
            read_json(&root.join("ids.json"))?
        };
        let source_access = kasumi_store::StorageAccess::standalone(
            ids.installation,
            SOURCE_TENANT,
            ids.source_incarnation,
        )?;
        let source_keys = Arc::new(LocalKeyProvider::new([0x31; 32]));
        let source_custody = Arc::new(LocalKeyProvider::new([0x32; 32]));
        let control_keys = Arc::new(LocalKeyProvider::new([0x4a; 32]));
        let control_custody = Arc::new(LocalKeyProvider::new([0x4b; 32]));
        let audit_keys = Arc::new(LocalKeyProvider::new([0x33; 32]));
        let control_access = kasumi_store::StorageAccess::node_control();
        let control_tenant = crate::control::CONTROL_TENANT.to_owned();
        let (source_stores, control_stores, audit) = if create {
            let source_stores = TenantStorageSet::initialize_catalogs(
                node.clone(),
                SOURCE_TENANT.into(),
                source_keys,
                source_custody,
                source_access,
            )
            .await?;
            let control_stores = TenantStorageSet::initialize_catalogs(
                node.clone(),
                control_tenant,
                control_keys,
                control_custody,
                control_access,
            )
            .await?;
            let audit_store = TenantStore::initialize_catalog(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                audit_keys,
                kasumi_store::StorageAccess::security_audit(),
            )
            .await?;
            let audit = SecurityAudit::initialize(
                audit_store,
                Default::default(),
                storage.admission.clone(),
            )
            .native("security audit")?;
            (source_stores, control_stores, audit)
        } else {
            let source_stores = TenantStorageSet::open_existing(
                node.clone(),
                SOURCE_TENANT.into(),
                source_keys,
                source_custody,
                source_access,
            )
            .await?;
            let control_stores = TenantStorageSet::open_existing(
                node.clone(),
                control_tenant,
                control_keys,
                control_custody,
                control_access,
            )
            .await?;
            let audit_store = TenantStore::open_existing(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                audit_keys,
                kasumi_store::StorageAccess::security_audit(),
            )
            .await?;
            let audit =
                SecurityAudit::open(audit_store, Default::default(), storage.admission.clone())
                    .native("security audit")?;
            (source_stores, control_stores, audit)
        };
        crate::test_utils::install_local_replica_audit_placement(source_stores.application())?;
        crate::test_utils::install_local_replica_audit_placement(control_stores.application())?;
        let source_limits = Limits {
            audit_retention: AuditRetentionBudget {
                hot_bytes: plan.source_hot_audit_bytes,
                ..Default::default()
            },
            ..Default::default()
        };
        let control_limits = Limits {
            max_backup_binding_bytes: plan.control_binding_budget,
            audit_retention: AuditRetentionBudget {
                hot_bytes: plan.control_hot_audit_bytes,
                ..Default::default()
            },
            ..Default::default()
        };
        let source = if create {
            crate::open_local_with_incarnation(
                source_stores.clone(),
                policy(),
                source_limits,
                audit.clone(),
                ids.source_incarnation,
            )
            .await
        } else {
            crate::open_existing_local(source_stores.clone(), audit.clone(), ids.source_incarnation)
                .await
        }
        .native("open source")?;
        // Initial policy and limits apply only when no Control state exists.
        let control = crate::open_local_with_incarnation(
            control_stores.clone(),
            policy(),
            control_limits,
            audit.clone(),
            ids.control_incarnation,
        )
        .await
        .native("open Control")?;
        let context = base_context(SOURCE_TENANT);
        let operator = base_context(crate::control::CONTROL_TENANT);
        source
            .install_backup_control(&control, &operator)
            .native("install Control")?;
        let destination = Arc::new(FilesystemBackupDestination::new(
            root.join("persistent/destination"),
            32 << 20,
            storage.persistent.clone(),
        )?);
        source
            .install_archive_destination(ALIAS.into(), destination.clone())
            .native("install destination")?;
        if create {
            source
                .administer(
                    context.clone(),
                    Operation::CreateCollection(CollectionDefinition {
                        name: "docs".into(),
                        write_mode: CollectionWriteMode::Mutable,
                        retention_class: CollectionRetentionClass::Operational,
                        schema: serde_json::json!({"type":"object"}),
                        indexes: vec![],
                        strict_read_audit: false,
                    }),
                )
                .await
                .native("create collection")?;
            write_json(&root.join("ids.json"), &ids)?;
        }
        Ok(Self {
            storage,
            node,
            source_stores,
            control_stores,
            audit,
            source,
            control,
            destination,
            context,
            operator,
        })
    }

    fn context(&self, ordinal: u64) -> RequestContext {
        let mut context = self.context.clone();
        context.request_id = request_id(ordinal);
        context
    }

    fn head(&self) -> anyhow::Result<BackupBindingHead> {
        Ok(self
            .control
            .engine
            .generation()
            .native("Control generation")?
            .state
            .backup_binding_head
            .clone())
    }

    fn aggregate(&self) -> anyhow::Result<crate::ControlBackupSessions> {
        self.control
            .engine
            .generation()
            .native("Control generation")?
            .control_backup_sessions()
            .context("Control aggregate absent")
    }

    /// Exact Control and destination state of one session.
    async fn session_state(&self, id: uuid::Uuid) -> anyhow::Result<serde_json::Value> {
        let generation = self
            .control
            .engine
            .generation()
            .native("Control generation")?;
        let claim = generation.backup_bindings.get(id)?.map(|row| row.ordinal);
        let terminal = generation
            .backup_bindings
            .terminal(id)?
            .map(|row| row.ordinal);
        let mut destination = BTreeMap::new();
        for (name, slot) in [
            ("intent", BackupSessionSlot::Intent),
            ("outcome", BackupSessionSlot::Outcome),
            ("root", BackupSessionSlot::Object(id)),
        ] {
            let bytes = self
                .destination
                .session_get(id, slot, kasumi_store::MAX_BACKUP_BUNDLE_BYTES)
                .await?;
            destination.insert(name, bytes.map(|b| hex::encode(Sha256::digest(b))));
        }
        Ok(serde_json::json!({
            "claim_ordinal": claim,
            "terminal_ordinal": terminal,
            "destination_sha256": destination,
        }))
    }

    async fn close(self) -> anyhow::Result<()> {
        self.source.shutdown().await.native("source drain")?;
        self.control.shutdown().await.native("Control drain")?;
        drop(self.source);
        drop(self.control);
        drop(self.destination);
        self.source_stores
            .shutdown()
            .await
            .native("source stores drain")?;
        self.control_stores
            .shutdown()
            .await
            .native("Control stores drain")?;
        self.audit.shutdown().await.native("security audit drain")?;
        self.node.shutdown().await.native("node drain")?;
        drop(self.storage);
        Ok(())
    }
}

/// One original operation result, journaled when the production call returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Original {
    ordinal: u64,
    session_id: uuid::Uuid,
    request_id: String,
    kind: Kind,
    stage: String,
    checkpoint: Option<FullBackupCheckpoint>,
    outcome: Option<BackupSessionOutcome>,
    seconds: f64,
    resolution: Option<serde_json::Value>,
}

impl Original {
    fn outcome_matches(&self, decision: &BackupSessionOutcome) -> bool {
        match (self.kind, decision) {
            (Kind::Complete, BackupSessionOutcome::Complete { checkpoint, .. }) => {
                self.checkpoint.as_ref() == Some(checkpoint)
            }
            (Kind::Aborted, BackupSessionOutcome::Aborted { .. }) => {
                self.outcome.as_ref() == Some(decision)
            }
            _ => false,
        }
    }
}

enum JournalTail {
    Complete,
    MissingNewline,
    Torn { valid_bytes: u64 },
}

fn read_journal(file: &std::fs::File) -> anyhow::Result<(BTreeMap<u64, Original>, JournalTail)> {
    let mut reader = std::io::BufReader::new(file);
    let mut originals = BTreeMap::new();
    let mut valid_bytes = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok((originals, JournalTail::Complete));
        }
        let terminated = line.ends_with(b"\n");
        let original: Original = match serde_json::from_slice(&line) {
            Ok(original) => original,
            Err(error) if !terminated && error.is_eof() => {
                return Ok((originals, JournalTail::Torn { valid_bytes }));
            }
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            originals.insert(original.ordinal, original).is_none(),
            "duplicate original ordinal"
        );
        if !terminated {
            return Ok((originals, JournalTail::MissingNewline));
        }
        valid_bytes += line.len() as u64;
    }
}

fn read_originals(root: &Path) -> anyhow::Result<BTreeMap<u64, Original>> {
    match std::fs::File::open(root.join("original.jsonl")) {
        Ok(file) => Ok(read_journal(&file)?.0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}

struct Journal(std::fs::File);
impl Journal {
    fn resume(root: &Path) -> anyhow::Result<(BTreeMap<u64, Original>, Self)> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(root.join("original.jsonl"))?;
        let (originals, tail) = read_journal(&file)?;
        match tail {
            JournalTail::Complete => {}
            JournalTail::MissingNewline => {
                file.write_all(b"\n")?;
                file.sync_all()?;
            }
            JournalTail::Torn { valid_bytes } => {
                file.set_len(valid_bytes)?;
                file.sync_all()?;
            }
        }
        std::fs::File::open(root)?.sync_all()?;
        Ok((originals, Self(file)))
    }
    fn append(&mut self, original: &Original) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(original)?;
        line.push(b'\n');
        self.0.write_all(&line)?;
        Ok(())
    }
    fn sync(&mut self) -> anyhow::Result<()> {
        self.0.sync_all()?;
        Ok(())
    }
}

#[test]
fn journal_resume_preserves_originals_across_every_last_record_cut() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let path = root.join("original.jsonl");
    let record = |ordinal| Original {
        ordinal,
        session_id: uuid::Uuid::from_u128(ordinal as u128 + 1),
        request_id: format!("請求-{ordinal}"),
        kind: Kind::Aborted,
        stage: "populate".into(),
        checkpoint: None,
        outcome: None,
        seconds: 0.5,
        resolution: None,
    };
    let (first, second, third) = (record(0), record(1), record(2));
    let mut prefix = serde_json::to_vec(&first)?;
    prefix.push(b'\n');
    let encoded = serde_json::to_vec(&second)?;
    for cut in 0..=encoded.len() {
        let mut interrupted = prefix.clone();
        interrupted.extend_from_slice(&encoded[..cut]);
        std::fs::write(&path, &interrupted)?;
        let originals = read_originals(root)?;
        assert_eq!(std::fs::read(&path)?, interrupted);
        let (resumed, mut journal) = Journal::resume(root)?;
        assert_eq!(resumed, originals);
        assert_eq!(resumed.get(&0), Some(&first));
        if cut == encoded.len() {
            assert_eq!(resumed.get(&1), Some(&second));
        } else {
            assert_eq!(resumed.len(), 1);
            journal.append(&second)?;
        }
        journal.append(&third)?;
        journal.sync()?;
        drop(journal);
        assert_eq!(
            read_originals(root)?,
            BTreeMap::from([(0, first.clone()), (1, second.clone()), (2, third.clone())]),
            "cut at byte {cut}"
        );
    }
    for tail in [b"{broken}".as_slice(), b"{\n", prefix.as_slice()] {
        let bytes = [prefix.as_slice(), tail].concat();
        std::fs::write(&path, &bytes)?;
        assert!(Journal::resume(root).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
    }
    Ok(())
}

fn stats(values: &mut [f64]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({"count": 0});
    }
    values.sort_by(f64::total_cmp);
    let at = |q: f64| values[((values.len() - 1) as f64 * q).round() as usize];
    serde_json::json!({
        "count": values.len(),
        "min": values[0],
        "median": at(0.5),
        "p90": at(0.9),
        "p99": at(0.99),
        "max": values[values.len() - 1],
        "total": values.iter().sum::<f64>(),
    })
}

/// Production claim and intent publication, exactly as a full backup starts.
async fn claim_and_publish(inst: &Installation, plan: &Plan, ordinal: u64) -> anyhow::Result<()> {
    let id = plan.session_id(ordinal);
    let context = inst.context(ordinal);
    let generation = inst
        .source
        .engine
        .generation()
        .native("source generation")?;
    let intent = BackupSessionIntent {
        session_id: id,
        tenant: SOURCE_TENANT.into(),
        source_incarnation: generation.incarnation().into(),
        revision: generation.state.revision,
        principal: context.principal.clone(),
        request_id: context.request_id.clone(),
    };
    let claim = inst
        .source
        .claim_backup_intent(
            &context,
            inst.destination.as_ref(),
            &intent,
            &generation,
            Some(ALIAS),
        )
        .await;
    publish_claim_result(inst, &context, &intent, claim).await
}

async fn publish_claim_result(
    inst: &Installation,
    context: &RequestContext,
    intent: &BackupSessionIntent,
    claim: Result<kasumi_store::AdmittedBackupBundle>,
) -> anyhow::Result<()> {
    let error = match claim {
        Ok(bytes) => {
            return inst
                .destination
                .session_put(intent.session_id, BackupSessionSlot::Intent, bytes.into())
                .await
                .context("intent publication");
        }
        Err(error) if error.code == ErrorCode::UnknownOutcome => anyhow::Error::new(error),
        Err(error) => return Err(anyhow::Error::new(error).context("Control claim")),
    };
    eprintln!(
        "backup floor request {} Control claim: {error:#}",
        intent.request_id
    );
    // A committed claim can exist before the intent object. Prove the selected
    // Control input before publishing its original randomized bytes.
    let selected = inst
        .source
        .selected_backup(context, inst.destination.as_ref(), intent.session_id)
        .await
        .context("read Control after uncertain population claim")?;
    let Some(selected) = selected else {
        return Err(error.context("no committed population claim to publish"));
    };
    let row = &selected.record;
    if selected.terminal.is_some()
        || row.claim.intent() != *intent
        || row.claim.destination_alias.as_deref() != Some(ALIAS)
        || row.claim.source_purpose_sha256
            != kasumi_types::staged_digest(inst.source.store.storage_access().purpose())?.0
    {
        return Err(error.context("Control did not select the exact pending population claim"));
    }
    // Status can prove Control ownership even when the destination is empty.
    // Inspect the authenticated object itself before accepting publication.
    let published = || async {
        let Some(session) = inst
            .source
            .backup_session(context, inst.destination.as_ref(), intent.session_id)
            .await
            .context("verify population intent readback")?
        else {
            return Ok(false);
        };
        anyhow::ensure!(
            session.intent() == intent
                && session.intent_ciphertext_sha256() == row.claim.intent_ciphertext_sha256
                && session.outcome().is_none(),
            "destination differs from the exact pending population claim"
        );
        anyhow::Ok(true)
    };
    if !published().await? {
        let bytes = inst
            .source
            .original_backup_intent_for_effect(context, row)
            .await
            .context("verify original committed population intent")?;
        if let Err(original) = inst
            .destination
            .session_put(intent.session_id, BackupSessionSlot::Intent, bytes.into())
            .await
        {
            eprintln!(
                "backup floor request {} intent publication: {original:#}",
                intent.request_id
            );
        }
        anyhow::ensure!(
            published().await?,
            "original committed population intent awaits destination publication"
        );
    }
    Ok(())
}

async fn abort(
    inst: &Installation,
    plan: &Plan,
    ordinal: u64,
) -> anyhow::Result<BackupSessionStatus> {
    let context = inst.context(ordinal);
    let request = AbortBackupSession {
        destination: ALIAS.into(),
        session_id: plan.session_id(ordinal),
        reason: abort_reason(ordinal),
    };
    let status = match inst
        .source
        .abort_backup_session(context.clone(), request.clone())
        .await
    {
        Ok(status) => status,
        Err(crate::SnapshotFailure::Operation(error))
            if error.code == ErrorCode::UnknownOutcome =>
        {
            eprintln!("backup floor ordinal {ordinal} abort returned {error:?}");
            let observed = inst
                .source
                .backup_session_status(
                    context.clone(),
                    BackupSessionRequest {
                        destination: request.destination.clone(),
                        session_id: request.session_id,
                    },
                )
                .await
                .context("public abort status after unknown outcome")?;
            anyhow::ensure!(
                observed.intent.session_id == request.session_id
                    && observed.intent.tenant == context.tenant
                    && observed.intent.principal == context.principal
                    && observed.intent.request_id == context.request_id
                    && observed.intent.source_incarnation
                        == inst.source.engine.generation()?.incarnation(),
                "public abort status selected another original request"
            );
            if observed.outcome.is_some() {
                observed
            } else {
                inst.source
                    .abort_backup_session(context, request)
                    .await
                    .map_err(snapshot_diagnostic)
                    .context("same public abort after a verified pending session")?
            }
        }
        Err(original) => return Err(snapshot_diagnostic(original).context("public abort")),
    };
    anyhow::ensure!(
        matches!(&status.outcome, Some(BackupSessionOutcome::Aborted { reason, .. }) if *reason == abort_reason(ordinal)),
        "abort did not select its original failure"
    );
    Ok(status)
}

/// The public full backup. An operation refusal is the inner error; any
/// other native failure ends the stage.
async fn complete(
    inst: &Installation,
    plan: &Plan,
    ordinal: u64,
) -> anyhow::Result<Result<FullBackupCheckpoint>> {
    match inst
        .source
        .backup_checkpoint_named(inst.context(ordinal), ALIAS, plan.session_id(ordinal))
        .await
    {
        Ok(proof) => Ok(Ok(proof.checkpoint().clone())),
        Err(crate::SnapshotFailure::Operation(error)) => Ok(Err(error)),
        Err(native) => Err(anyhow::anyhow!("full backup native failure: {native:?}")),
    }
}

/// More objects than one cleanup page, staged before the failure is decided.
async fn stage_cleanup_objects(
    inst: &Installation,
    plan: &Plan,
    ordinal: u64,
) -> anyhow::Result<()> {
    let id = plan.session_id(ordinal);
    let revision = inst
        .source
        .engine
        .generation()
        .native("source generation")?
        .state
        .revision;
    for n in 0..plan.cleanup_objects {
        let object = inst
            .source
            .store
            .encrypt_backup(revision, format!("partial upload {n}").as_bytes())?
            .to_bytes()?;
        inst.destination
            .session_put(
                id,
                BackupSessionSlot::Object(uuid::Uuid::new_v4()),
                object.into(),
            )
            .await
            .native("partial upload")?;
    }
    Ok(())
}

async fn cleanup(
    inst: &Installation,
    plan: &Plan,
    max_objects: usize,
) -> std::result::Result<BackupCleanupResult, String> {
    let ordinal = plan.cleanup_ordinal();
    inst.source
        .cleanup_backup_session(
            inst.context(ordinal),
            CleanupBackupSession {
                destination: ALIAS.into(),
                session_id: plan.session_id(ordinal),
                max_objects,
            },
        )
        .await
        .map_err(|error| format!("{:?}: {}", error.code, error.message))
}

/// An unjournaled abort may already own a Control claim at an older
/// source revision. Resolve the actual session before attempting another claim.
async fn interrupted_abort_status(
    inst: &Installation,
    plan: &Plan,
    ordinal: u64,
) -> anyhow::Result<Option<BackupSessionStatus>> {
    let context = inst.context(ordinal);
    let session_id = plan.session_id(ordinal);
    let observed = match inst
        .source
        .backup_session_status(
            context.clone(),
            BackupSessionRequest {
                destination: ALIAS.into(),
                session_id,
            },
        )
        .await
    {
        Ok(status) => status,
        Err(error) if error.code == ErrorCode::NotFound && !error.has_physical_source() => {
            return Ok(None);
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context("resolve original population session"));
        }
    };
    let live = inst.source.engine.generation()?;
    anyhow::ensure!(
        observed.intent.session_id == session_id && observed.intent.tenant == context.tenant
            && observed.intent.principal == context.principal
            && observed.intent.request_id == context.request_id
            && observed.intent.source_incarnation == live.incarnation()
            && observed.intent.revision <= live.state.revision
            && observed.source_purpose_sha256 == kasumi_types::staged_digest(inst.source.store.storage_access().purpose())?.0
            && observed.outcome.as_ref().is_none_or(|outcome|
                matches!(outcome, BackupSessionOutcome::Aborted { reason, .. } if *reason == abort_reason(ordinal))),
        "the retained population session belongs to another original request or outcome"
    );
    Ok(Some(observed))
}

async fn run_session(
    inst: &Installation,
    plan: &Plan,
    ordinal: u64,
    stage: &str,
    resume: bool,
) -> anyhow::Result<Original> {
    let started = Instant::now();
    let mut resolution = None;
    let id = plan.session_id(ordinal);
    let (checkpoint, outcome) = match plan.kind(ordinal) {
        Kind::Complete => (
            Some(complete(inst, plan, ordinal).await?.native("full backup")?),
            None,
        ),
        Kind::Aborted => {
            let previous = if resume {
                interrupted_abort_status(inst, plan, ordinal).await?
            } else {
                None
            };
            if previous.is_none() {
                claim_and_publish(inst, plan, ordinal).await?;
                if ordinal == plan.cleanup_ordinal() {
                    stage_cleanup_objects(inst, plan, ordinal).await?;
                }
            }
            let status = abort(inst, plan, ordinal).await?;
            if let Some(original) = previous {
                anyhow::ensure!(
                    original.intent == status.intent
                        && original.source_purpose_sha256 == status.source_purpose_sha256
                        && original
                            .outcome
                            .as_ref()
                            .is_none_or(|outcome| Some(outcome) == status.outcome.as_ref()),
                    "public abort changed the original population identity or terminal result"
                );
                resolution = Some(serde_json::json!({"before": original, "after": status}));
            }
            (None, status.outcome)
        }
    };
    Ok(Original {
        ordinal,
        session_id: id,
        request_id: request_id(ordinal),
        kind: plan.kind(ordinal),
        stage: stage.into(),
        checkpoint,
        outcome,
        seconds: started.elapsed().as_secs_f64(),
        resolution,
    })
}

/// Emits a valid record followed by insignificant JSON whitespace. With
/// serde_json's arbitrary-precision number token, the string is written
/// verbatim, so the real session record encoder sees exactly these bytes.
struct Padded(String);
impl Serialize for Padded {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut value = serializer.serialize_struct("$serde_json::private::Number", 1)?;
        value.serialize_field("$serde_json::private::Number", &self.0)?;
        value.end()
    }
}

fn padded(value: &impl Serialize, total: usize) -> anyhow::Result<Padded> {
    let mut text = serde_json::to_string(value)?;
    anyhow::ensure!(text.len() <= total, "record already exceeds padding target");
    text.extend(std::iter::repeat_n(' ', total - text.len()));
    let value = Padded(text);
    anyhow::ensure!(
        serde_json::to_vec(&value)?.len() == total,
        "padded encoding differs"
    );
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    record_limit: usize,
    encrypted_read_limit: usize,
    accepted_session: uuid::Uuid,
    accepted_intent_plaintext_bytes: usize,
    accepted_intent_ciphertext_sha256: String,
    accepted_intent_ciphertext_bytes: usize,
    accepted_outcome_plaintext_bytes: usize,
    accepted_outcome_ciphertext_sha256: String,
    accepted_outcome_ciphertext_bytes: usize,
    accepted_status_outcome: BackupSessionOutcome,
    rejected_intent_write: String,
    rejected_outcome_write: String,
    forged_intent_session: uuid::Uuid,
    forged_intent_plaintext_bytes: usize,
    forged_intent_read: String,
    forged_outcome_session: uuid::Uuid,
    forged_outcome_read: String,
}

async fn boundary(inst: &Installation, plan: &Plan) -> anyhow::Result<Boundary> {
    let limit = kasumi_store::MAX_SESSION_RECORD_BYTES;
    anyhow::ensure!(limit == 65_536, "historical session record bound differs");
    let store = inst.source.store.clone();
    let destination = inst.destination.as_ref();
    let generation = inst
        .source
        .engine
        .generation()
        .native("source generation")?;
    let revision = generation.state.revision;
    let intent = |label: &str| BackupSessionIntent {
        session_id: plan.session_id(u64::MAX - label.len() as u64),
        tenant: SOURCE_TENANT.into(),
        source_incarnation: generation.incarnation().into(),
        revision,
        principal: PRINCIPAL.into(),
        request_id: format!("floor-boundary-{label}"),
    };
    let accepted = intent("accepted");
    let id = accepted.session_id;
    let bytes = store
        .encrypt_session_record(revision, &padded(&accepted, limit)?)
        .context("65,536-byte intent record must be accepted")?;
    let rejected_intent_write =
        match store.encrypt_session_record(revision, &padded(&accepted, limit + 1)?) {
            Ok(_) => anyhow::bail!("65,537-byte intent record was accepted"),
            Err(error) => format!("{error:#}"),
        };
    let intent_ciphertext_bytes = bytes.len();
    destination
        .session_put(id, BackupSessionSlot::Intent, bytes.into())
        .await?;
    let verified = store
        .verify_backup_session(destination, id)
        .await?
        .context("accepted intent unreadable")?;
    anyhow::ensure!(verified.intent() == &accepted && verified.outcome().is_none());
    let outcome = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        session_id: id,
        principal: PRINCIPAL.into(),
        reason: "boundary outcome record".into(),
    };
    let outcome_bytes = store
        .encrypt_session_record(revision, &padded(&outcome, limit)?)
        .context("65,536-byte outcome record must be accepted")?;
    let rejected_outcome_write =
        match store.encrypt_session_record(revision, &padded(&outcome, limit + 1)?) {
            Ok(_) => anyhow::bail!("65,537-byte outcome record was accepted"),
            Err(error) => format!("{error:#}"),
        };
    let outcome_ciphertext_bytes = outcome_bytes.len();
    destination
        .session_put(id, BackupSessionSlot::Outcome, outcome_bytes.into())
        .await?;
    let decided = store
        .verify_backup_session(destination, id)
        .await?
        .context("accepted outcome unreadable")?;
    anyhow::ensure!(decided.outcome() == Some(&outcome));
    let status = inst
        .source
        .backup_session_status(
            inst.context.clone(),
            BackupSessionRequest {
                destination: ALIAS.into(),
                session_id: id,
            },
        )
        .await
        .native("boundary status")?;
    anyhow::ensure!(status.intent == accepted && status.outcome.as_ref() == Some(&outcome));
    // The writer refuses 65,537 bytes; a record forged below that writer
    // check is refused by the reader as well.
    let forged = intent("forged-intent");
    let forged_plaintext = serde_json::to_vec(&padded(&forged, limit + 1)?)?;
    let forged_bytes = store
        .encrypt_backup(revision, &forged_plaintext)?
        .to_bytes()?;
    destination
        .session_put(
            forged.session_id,
            BackupSessionSlot::Intent,
            forged_bytes.into(),
        )
        .await?;
    let forged_intent_read = match store
        .verify_backup_session(destination, forged.session_id)
        .await
    {
        Ok(_) => anyhow::bail!("65,537-byte intent record was read"),
        Err(error) => format!("{error:#}"),
    };
    let target = intent("forged-outcome");
    destination
        .session_put(
            target.session_id,
            BackupSessionSlot::Intent,
            store.encrypt_session_record(revision, &target)?.into(),
        )
        .await?;
    let target_verified = store
        .verify_backup_session(destination, target.session_id)
        .await?
        .context("forged-outcome intent unreadable")?;
    let forged_outcome = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: target_verified.intent_ciphertext_sha256().into(),
        session_id: target.session_id,
        principal: PRINCIPAL.into(),
        reason: "forged oversized outcome".into(),
    };
    let forged_outcome_bytes = store
        .encrypt_backup(
            revision,
            &serde_json::to_vec(&padded(&forged_outcome, limit + 1)?)?,
        )?
        .to_bytes()?;
    destination
        .session_put(
            target.session_id,
            BackupSessionSlot::Outcome,
            forged_outcome_bytes.into(),
        )
        .await?;
    let forged_outcome_read = match store
        .verify_backup_session(destination, target.session_id)
        .await
    {
        Ok(_) => anyhow::bail!("65,537-byte outcome record was read"),
        Err(error) => format!("{error:#}"),
    };
    Ok(Boundary {
        record_limit: limit,
        encrypted_read_limit: kasumi_store::MAX_ENCRYPTED_SESSION_RECORD_BYTES,
        accepted_session: id,
        accepted_intent_plaintext_bytes: limit,
        accepted_intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        accepted_intent_ciphertext_bytes: intent_ciphertext_bytes,
        accepted_outcome_plaintext_bytes: limit,
        accepted_outcome_ciphertext_sha256: decided
            .outcome_ciphertext_sha256()
            .context("outcome digest")?
            .into(),
        accepted_outcome_ciphertext_bytes: outcome_ciphertext_bytes,
        accepted_status_outcome: outcome,
        rejected_intent_write,
        rejected_outcome_write,
        forged_intent_session: forged.session_id,
        forged_intent_plaintext_bytes: forged_plaintext.len(),
        forged_intent_read,
        forged_outcome_session: target.session_id,
        forged_outcome_read,
    })
}

/// After a restart the accepted records decode unchanged and both forged
/// records remain unreadable.
async fn recheck_boundary(
    inst: &Installation,
    recorded: &Boundary,
) -> anyhow::Result<serde_json::Value> {
    let store = inst.source.store.clone();
    let destination = inst.destination.as_ref();
    let accepted = store
        .verify_backup_session(destination, recorded.accepted_session)
        .await?
        .context("accepted boundary session lost")?;
    anyhow::ensure!(
        accepted.intent_ciphertext_sha256() == recorded.accepted_intent_ciphertext_sha256
            && accepted.outcome_ciphertext_sha256()
                == Some(recorded.accepted_outcome_ciphertext_sha256.as_str())
            && accepted.outcome() == Some(&recorded.accepted_status_outcome),
        "boundary record changed across restart"
    );
    let intent = store
        .verify_backup_session(destination, recorded.forged_intent_session)
        .await
        .err()
        .context("forged intent became readable")?;
    let outcome = store
        .verify_backup_session(destination, recorded.forged_outcome_session)
        .await
        .err()
        .context("forged outcome became readable")?;
    Ok(serde_json::json!({
        "accepted_unchanged": true,
        "forged_intent_read": format!("{intent:#}"),
        "forged_outcome_read": format!("{outcome:#}"),
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageSummary {
    index: u64,
    entries: u64,
    scanned_from: u64,
    scanned_through: u64,
    next: Option<crate::ControlBackupSessionCursor>,
    first_session: Option<uuid::Uuid>,
    last_session: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    label: String,
    process_id: u32,
    head: BackupBindingHead,
    aggregate: serde_json::Value,
    pages: Vec<PageSummary>,
    max_page_entries: u64,
    sessions: u64,
    completed: u64,
    aborted: u64,
    pending: u64,
    stream: String,
    stream_sha256: String,
    stream_bytes: u64,
    seconds: f64,
}

/// Enumerate every session in bounded pages from one quiescent Control head
/// and write the stream sorted by session ID.
async fn observe(
    inst: &Installation,
    plan: &Plan,
    root: &Path,
    label: &str,
) -> anyhow::Result<Observation> {
    let started = Instant::now();
    let mut cursor = None;
    let mut pages = Vec::new();
    let mut entries = Vec::new();
    let mut head: Option<BackupBindingHead> = None;
    let mut seen = BTreeSet::new();
    let mut last_ordinal = 0;
    let mut through = 0;
    loop {
        let page = inst
            .control
            .control_backup_session_page(&inst.operator, cursor.clone(), plan.page_limit)
            .await
            .native("Control session page")?;
        anyhow::ensure!(
            page.entries.len() <= plan.page_limit
                && plan.page_limit <= crate::MAX_CONTROL_BACKUP_SESSION_PAGE,
            "page exceeds its session bound"
        );
        anyhow::ensure!(
            head.as_ref().is_none_or(|head| *head == page.head),
            "Control head moved during a quiescent observation"
        );
        anyhow::ensure!(
            page.scanned_from == through + 1,
            "observation page gap or overlap"
        );
        for entry in &page.entries {
            anyhow::ensure!(
                seen.insert(entry.session_id),
                "duplicate session across pages"
            );
            anyhow::ensure!(
                entry.binding.ordinal > last_ordinal,
                "claim order regressed"
            );
            last_ordinal = entry.binding.ordinal;
        }
        through = page.scanned_through;
        pages.push(PageSummary {
            index: pages.len() as u64,
            entries: page.entries.len() as u64,
            scanned_from: page.scanned_from,
            scanned_through: page.scanned_through,
            next: page.next.clone(),
            first_session: page.entries.first().map(|e| e.session_id),
            last_session: page.entries.last().map(|e| e.session_id),
        });
        head = Some(page.head);
        entries.extend(page.entries);
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let head = head.context("no observation page")?;
    anyhow::ensure!(
        through == head.count,
        "enumeration ended before the selected head"
    );
    entries.sort_by_key(|entry| entry.session_id);
    let directory = root.join("streams");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{label}.jsonl"));
    let mut stream = Vec::new();
    for entry in &entries {
        serde_json::to_writer(&mut stream, entry)?;
        stream.push(b'\n');
    }
    durable_write(&path, &stream)?;
    let count = |kind: Option<Kind>| {
        entries
            .iter()
            .filter(|entry| match (&entry.decision, kind) {
                (None, None) => true,
                (Some(d), Some(Kind::Complete)) => {
                    matches!(d.outcome, BackupSessionOutcome::Complete { .. })
                }
                (Some(d), Some(Kind::Aborted)) => {
                    matches!(d.outcome, BackupSessionOutcome::Aborted { .. })
                }
                _ => false,
            })
            .count() as u64
    };
    let aggregate = inst.aggregate()?;
    let observation = Observation {
        label: label.into(),
        process_id: std::process::id(),
        aggregate: serde_json::to_value(aggregate)?,
        max_page_entries: pages.iter().map(|page| page.entries).max().unwrap_or(0),
        sessions: entries.len() as u64,
        completed: count(Some(Kind::Complete)),
        aborted: count(Some(Kind::Aborted)),
        pending: count(None),
        stream: format!("streams/{label}.jsonl"),
        stream_sha256: hex::encode(Sha256::digest(&stream)),
        stream_bytes: stream.len() as u64,
        pages,
        head,
        seconds: started.elapsed().as_secs_f64(),
    };
    anyhow::ensure!(
        aggregate.completed == observation.completed
            && aggregate.aborted == observation.aborted
            && aggregate.claimed_without_terminal == observation.pending
            && aggregate.last_binding_revision == observation.head.last_applied_revision,
        "paged sessions differ from the Control aggregate"
    );
    write_json(
        &directory.join(format!("{label}.observation.json")),
        &observation,
    )?;
    Ok(observation)
}

/// Every file under the destination with its size; session records also
/// carry their digest.
fn census(root: &Path) -> anyhow::Result<serde_json::Value> {
    fn walk(
        base: &Path,
        dir: &Path,
        out: &mut Vec<(String, u64, Option<String>)>,
    ) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(base, &path, out)?;
            } else {
                let name = path.strip_prefix(base)?.to_string_lossy().into_owned();
                let digest = (name.ends_with("intent.kasumi") || name.ends_with("outcome.kasumi"))
                    .then(|| file_sha256(&path))
                    .transpose()?;
                out.push((name, entry.metadata()?.len(), digest));
            }
        }
        Ok(())
    }
    let base = root.join("persistent/destination");
    let mut files = Vec::new();
    walk(&base, &base, &mut files)?;
    files.sort();
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let (mut intents, mut outcomes, mut objects) = (0u64, 0u64, 0u64);
    for (name, len, digest) in &files {
        hash.update(format!(
            "{name}\t{len}\t{}\n",
            digest.as_deref().unwrap_or("-")
        ));
        bytes += len;
        if name.ends_with("intent.kasumi") {
            intents += 1;
        } else if name.ends_with("outcome.kasumi") {
            outcomes += 1;
        } else if name.contains("/objects/") {
            objects += 1;
        }
    }
    Ok(serde_json::json!({
        "files": files.len(),
        "bytes": bytes,
        "intents": intents,
        "outcomes": outcomes,
        "session_objects": objects,
        "sha256": hex::encode(hash.finalize()),
    }))
}

fn plan_of(root: &Path) -> anyhow::Result<Plan> {
    let plan: Plan = read_json(&root.join("plan.json"))?;
    anyhow::ensure!(plan.schema == SCHEMA, "plan schema differs");
    if let Some(profile) = &plan.profile {
        profile.check(root, plan.sessions)?;
    }
    Ok(plan)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPages {
    session_id: uuid::Uuid,
    ordinal: u64,
    bound: usize,
    staged_objects: u64,
    over_bound_request: String,
    zero_request: String,
    passes: Vec<BackupCleanupResult>,
    repeat: Option<BackupCleanupResult>,
}

async fn record_cleanup(root: &Path, inst: &Installation, plan: &Plan) -> anyhow::Result<()> {
    let ordinal = plan.cleanup_ordinal();
    let session_id = plan.session_id(ordinal);
    let bound = kasumi_store::MAX_SESSION_GC_OBJECTS;
    anyhow::ensure!(bound == 256, "historical cleanup page bound differs");
    let path = root.join("cleanup.json");
    let mut record: CleanupPages = if path.try_exists()? {
        read_json(&path)?
    } else {
        let invalid = |answer: std::result::Result<BackupCleanupResult, String>| {
            let error = answer.err().context("out-of-bounds cleanup was accepted")?;
            anyhow::ensure!(
                error.starts_with("InvalidArgument:"),
                "cleanup boundary: {error}"
            );
            anyhow::Ok(error)
        };
        let record = CleanupPages {
            session_id,
            ordinal,
            bound,
            staged_objects: plan.cleanup_objects,
            over_bound_request: invalid(cleanup(inst, plan, bound + 1).await)?,
            zero_request: invalid(cleanup(inst, plan, 0).await)?,
            passes: Vec::new(),
            repeat: None,
        };
        write_json(&path, &record)?;
        record
    };
    anyhow::ensure!(
        record.session_id == session_id
            && record.ordinal == ordinal
            && record.bound == bound
            && record.staged_objects == plan.cleanup_objects,
        "persisted cleanup evidence belongs to a different plan"
    );
    while record.passes.last().is_none_or(|p| p.more_objects_observed) {
        anyhow::ensure!(record.passes.len() < 16, "cleanup did not converge");
        let pass = cleanup(inst, plan, bound)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(pass.deleted_objects <= bound as u64 && pass.session_id == session_id);
        record.passes.push(pass);
        write_json(&path, &record)?;
    }
    let deleted: u64 = record.passes.iter().map(|p| p.deleted_objects).sum();
    anyhow::ensure!(
        record.passes.len() >= 2 && deleted == plan.cleanup_objects,
        "retained cleanup responses account for {deleted} of {} objects",
        plan.cleanup_objects
    );
    if record.repeat.is_none() {
        let after = cleanup(inst, plan, bound)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            after.session_id == session_id
                && after.deleted_objects == 0
                && !after.more_objects_observed
        );
        record.repeat = Some(after);
        write_json(&path, &record)?;
    }
    Ok(())
}

async fn populate(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let started = Instant::now();
    let resumed = root.join("ids.json").exists();
    let inst = Installation::open(root, &plan).await?;
    let opened = started.elapsed().as_secs_f64();
    if !root.join("boundary.json").exists() {
        let recorded = boundary(&inst, &plan).await?;
        write_json(&root.join("boundary.json"), &recorded)?;
    }
    let (done, mut journal) = Journal::resume(root)?;
    let mut durations: BTreeMap<Kind, Vec<f64>> = BTreeMap::new();
    let reserve = plan.reserve_start();
    // Control and the destination can durably advance several sessions between
    // external journal syncs. Follow that original prefix across completed
    // checkpoints until an abort has no previously published claim.
    let mut resolve_existing = resumed;
    for ordinal in 0..reserve {
        if done.contains_key(&ordinal) {
            if ordinal == plan.cleanup_ordinal() {
                record_cleanup(root, &inst, &plan).await?;
            }
            continue;
        }
        let original = run_session(&inst, &plan, ordinal, "populate", resolve_existing).await?;
        durations
            .entry(original.kind)
            .or_default()
            .push(original.seconds);
        journal.append(&original)?;
        if resolve_existing {
            journal.sync()?;
            if original.kind == Kind::Aborted && original.resolution.is_none() {
                resolve_existing = false;
            }
        }
        if ordinal == plan.cleanup_ordinal() {
            journal.sync()?;
            record_cleanup(root, &inst, &plan).await?;
        }
        if (ordinal + 1) % 256 == 0 {
            journal.sync()?;
            eprintln!(
                "populate {}/{} sessions, {:.1}s",
                ordinal + 1,
                reserve,
                started.elapsed().as_secs_f64()
            );
        }
    }
    journal.sync()?;
    let head = inst.head()?;
    let aggregate = inst.aggregate()?;
    let mut summary = BTreeMap::new();
    for (kind, values) in &mut durations {
        summary.insert(format!("{kind:?}").to_lowercase(), stats(values));
    }
    let report = serde_json::json!({
        "process_id": std::process::id(),
        "resumed": resumed,
        "open_seconds": opened,
        "seconds": started.elapsed().as_secs_f64(),
        "written": durations.values().map(Vec::len).sum::<usize>(),
        "durations": summary,
        "head": head,
        "aggregate": aggregate,
    });
    write_json(
        &root.join(format!("populate-{}.json", std::process::id())),
        &report,
    )?;
    write_json(&root.join("populate.json"), &report)?;
    inst.close().await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inflight {
    ordinal: u64,
    session_id: uuid::Uuid,
    request_id: String,
    kind: Kind,
    operation: String,
    input: serde_json::Value,
}

/// Block the target row's Control apply after the row is durable and before
/// its generation and response publish, and announce that point.
fn arm_outstanding_write(ordinal: u64, session: uuid::Uuid, terminal: bool) {
    let hook: crate::state::backup_claim::OutstandingWriteHook =
        Box::new(move |observed, is_terminal| {
            if observed != session || is_terminal != terminal {
                return;
            }
            let marker = serde_json::json!({
                "ordinal": ordinal,
                "session_id": session,
                "write": if terminal { "terminal" } else { "claim" },
                "point": "control-apply-row-durable-before-publication",
                "process_id": std::process::id(),
            });
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "\n{OUTSTANDING}{marker}");
            let _ = out.flush();
            drop(out);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        });
    *crate::state::backup_claim::OUTSTANDING_WRITE_HOOK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(hook);
}

async fn kill_child(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let ordinal: u64 = std::env::var(TARGET)?.parse()?;
    let inst = Installation::open(root, &plan).await?;
    let id = plan.session_id(ordinal);
    let kind = plan.kind(ordinal);
    let (operation, input) = match kind {
        Kind::Complete => (
            "backup_checkpoint_named",
            serde_json::json!({"destination": ALIAS, "session_id": id, "request_id": request_id(ordinal)}),
        ),
        Kind::Aborted => {
            claim_and_publish(&inst, &plan, ordinal).await?;
            println!("{CLAIMED}{ordinal}");
            (
                "abort_backup_session",
                serde_json::to_value(AbortBackupSession {
                    destination: ALIAS.into(),
                    session_id: id,
                    reason: abort_reason(ordinal),
                })?,
            )
        }
    };
    let record = Inflight {
        ordinal,
        session_id: id,
        request_id: request_id(ordinal),
        kind,
        operation: operation.into(),
        input,
    };
    write_json(&root.join(format!("inflight-{ordinal:06}.json")), &record)?;
    // A complete capture is interrupted in its Control claim; a failure in
    // its Control terminal decision.
    arm_outstanding_write(ordinal, id, kind == Kind::Aborted);
    println!("{DISPATCH}{ordinal}");
    std::io::stdout().flush()?;
    match kind {
        Kind::Complete => drop(
            complete(&inst, &plan, ordinal)
                .await?
                .native("full backup")?,
        ),
        Kind::Aborted => drop(abort(&inst, &plan, ordinal).await?),
    }
    println!("{WRITTEN}{ordinal}");
    std::io::stdout().flush()?;
    inst.close().await?;
    anyhow::bail!("session write {ordinal} returned without reaching its kill point")
}

async fn resolve(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let started = Instant::now();
    let inst = Installation::open(root, &plan).await?;
    let opened = started.elapsed().as_secs_f64();
    let (mut done, mut journal) = Journal::resume(root)?;
    let mut inflight: Vec<Inflight> = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("inflight-") && name.ends_with(".json") {
            inflight.push(read_json(&path)?);
        }
    }
    inflight.sort_by_key(|record| record.ordinal);
    let mut resolutions = Vec::new();
    for record in &inflight {
        anyhow::ensure!(
            !done.contains_key(&record.ordinal),
            "killed session already journaled"
        );
        let id = record.session_id;
        anyhow::ensure!(
            id == plan.session_id(record.ordinal) && record.kind == plan.kind(record.ordinal)
        );
        let before = inst.session_state(id).await?;
        // The killed apply ran for a committed entry; replay must select the
        // durable row it wrote ahead of the applied cursor.
        let interrupted = if record.kind == Kind::Aborted {
            "terminal_ordinal"
        } else {
            "claim_ordinal"
        };
        let reselected = !before[interrupted].is_null();
        anyhow::ensure!(
            reselected,
            "interrupted {interrupted} for {} was not reselected after cold open: {before}",
            record.ordinal
        );
        let head_before = inst.head()?;
        let resolution_started = Instant::now();
        let (checkpoint, outcome, resubmitted, recovery) = match record.kind {
            Kind::Complete => match complete(&inst, &plan, record.ordinal).await? {
                Ok(checkpoint) => (Some(checkpoint), None, "completed".to_owned(), None),
                // A capture killed before its root published cannot finish.
                // Its original failure is retained and the session is aborted.
                Err(original) => {
                    let failure = format!("{original:?}");
                    let status = inst
                        .source
                        .abort_backup_session(
                            inst.context(record.ordinal),
                            AbortBackupSession {
                                destination: ALIAS.into(),
                                session_id: id,
                                reason: "interrupted capture could not complete after restart"
                                    .into(),
                            },
                        )
                        .await
                        .native("abort interrupted capture")?;
                    (None, status.outcome, "failed".to_owned(), Some(failure))
                }
            },
            Kind::Aborted => (
                None,
                abort(&inst, &plan, record.ordinal).await?.outcome,
                "aborted".to_owned(),
                None,
            ),
        };
        let after = inst.session_state(id).await?;
        let head_after = inst.head()?;
        let missing = u64::from(before["claim_ordinal"].is_null())
            + u64::from(before["terminal_ordinal"].is_null());
        anyhow::ensure!(
            head_after.count - head_before.count == missing
                && !after["claim_ordinal"].is_null()
                && !after["terminal_ordinal"].is_null(),
            "resolution re-executed or skipped a committed session write"
        );
        // The resolved session keeps whichever outcome Control selected.
        let (kind, checkpoint, outcome) = match outcome {
            Some(BackupSessionOutcome::Complete { checkpoint, .. }) => {
                (Kind::Complete, Some(checkpoint), None)
            }
            Some(aborted @ BackupSessionOutcome::Aborted { .. }) => {
                (Kind::Aborted, None, Some(aborted))
            }
            None => (Kind::Complete, checkpoint, None),
        };
        anyhow::ensure!(
            checkpoint.is_some() != outcome.is_some(),
            "resolution selected no terminal outcome"
        );
        let resolution = serde_json::json!({
            "operation": record.operation,
            "interrupted_write": interrupted.trim_end_matches("_ordinal"),
            "interrupted_row_reselected_by_replay": reselected,
            "observed_after_kill": before,
            "observed_after_resolution": after,
            "head_before": head_before,
            "head_after": head_after,
            "rows_added": head_after.count - head_before.count,
            "resubmitted": resubmitted,
            "original_failure": recovery,
        });
        let original = Original {
            ordinal: record.ordinal,
            session_id: id,
            request_id: record.request_id.clone(),
            kind,
            stage: "resolve".into(),
            checkpoint,
            outcome,
            seconds: resolution_started.elapsed().as_secs_f64(),
            resolution: Some(resolution.clone()),
        };
        journal.append(&original)?;
        done.insert(record.ordinal, original);
        resolutions.push(resolution);
    }
    for ordinal in plan.reserve_start()..plan.sessions {
        if let std::collections::btree_map::Entry::Vacant(entry) = done.entry(ordinal) {
            let original = run_session(&inst, &plan, ordinal, "resolve", false).await?;
            journal.append(&original)?;
            entry.insert(original);
        }
    }
    journal.sync()?;
    anyhow::ensure!(
        done.len() as u64 == plan.sessions,
        "cohort incomplete before observation"
    );
    let observation = observe(&inst, &plan, root, "pre-restart").await?;
    check_against_originals(root, &observation, &done)?;
    let page_errors = page_refusals(&inst).await?;
    let destination = census(root)?;
    let identities = identities(root)?;
    write_json(
        &root.join("resolve.json"),
        &serde_json::json!({
            "process_id": std::process::id(),
            "open_seconds": opened,
            "seconds": started.elapsed().as_secs_f64(),
            "resolutions": resolutions,
            "page_refusals": page_errors,
            "destination": destination,
            "data_identities": identities,
            "head": inst.head()?,
        }),
    )?;
    // No clean close: the complete observation must survive a cold kill of
    // this process while its real stores remain open.
    let marker = serde_json::json!({
        "process_id": std::process::id(),
        "stream": observation.stream,
        "stream_sha256": observation.stream_sha256,
        "sessions": observation.sessions,
        "head": observation.head,
        "resolve_sha256": file_sha256(&root.join("resolve.json"))?,
    });
    println!("\n{DURABLE}{marker}");
    std::io::stdout().flush()?;
    let _open = &inst;
    std::future::pending::<()>().await;
    unreachable!("the parent kills resolve with its stores open")
}

/// Device and inode of every data directory; reopen must use the same ones.
fn identities(root: &Path) -> anyhow::Result<serde_json::Value> {
    use std::os::unix::fs::MetadataExt as _;
    let mut out = BTreeMap::new();
    for relative in [
        ".",
        "persistent",
        "persistent/node.kv",
        "persistent/destination",
        "scratch",
    ] {
        let metadata = std::fs::symlink_metadata(root.join(relative))?;
        out.insert(
            relative,
            serde_json::json!({"device": metadata.dev(), "inode": metadata.ino(), "directory": metadata.is_dir()}),
        );
    }
    Ok(serde_json::to_value(out)?)
}

/// Original page refusals: an over-bound page and a forged continuation.
async fn page_refusals(inst: &Installation) -> anyhow::Result<serde_json::Value> {
    let over = inst
        .control
        .control_backup_session_page(
            &inst.operator,
            None,
            crate::MAX_CONTROL_BACKUP_SESSION_PAGE + 1,
        )
        .await
        .err()
        .context("over-bound session page accepted")?;
    let forged = inst
        .control
        .control_backup_session_page(
            &inst.operator,
            Some(crate::ControlBackupSessionCursor {
                after_ordinal: 1,
                after_row_sha256: "00".repeat(32),
            }),
            1,
        )
        .await
        .err()
        .context("forged continuation accepted")?;
    anyhow::ensure!(
        over.code == ErrorCode::InvalidArgument && forged.code == ErrorCode::InvalidArgument
    );
    Ok(serde_json::json!({
        "over_bound": format!("{:?}: {}", over.code, over.message),
        "forged_cursor": format!("{:?}: {}", forged.code, forged.message),
    }))
}

fn read_stream(
    root: &Path,
    relative: &str,
) -> anyhow::Result<Vec<crate::ControlBackupSessionEntry>> {
    let text = std::fs::read_to_string(root.join(relative))?;
    text.lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn check_against_originals(
    root: &Path,
    observation: &Observation,
    originals: &BTreeMap<u64, Original>,
) -> anyhow::Result<()> {
    let stream = read_stream(root, &observation.stream)?;
    let by_id: BTreeMap<uuid::Uuid, &crate::ControlBackupSessionEntry> = stream
        .iter()
        .map(|entry| (entry.session_id, entry))
        .collect();
    anyhow::ensure!(
        by_id.len() == originals.len(),
        "Control sessions differ from originals"
    );
    for original in originals.values() {
        let entry = by_id
            .get(&original.session_id)
            .context("original session absent from Control")?;
        let decision = entry
            .decision
            .as_ref()
            .context("original session undecided")?;
        anyhow::ensure!(
            entry.binding.request_id == original.request_id
                && entry.binding.destination_alias.as_deref() == Some(ALIAS)
                && original.outcome_matches(&decision.outcome),
            "Control outcome differs from original result for {}",
            original.ordinal
        );
    }
    Ok(())
}

async fn verify(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let started = Instant::now();
    let inst = Installation::open(root, &plan).await?;
    let opened = started.elapsed().as_secs_f64();
    let originals = read_originals(root)?;
    anyhow::ensure!(originals.len() as u64 == plan.sessions);
    let head_before = inst.head()?;
    let aggregate_before = inst.aggregate()?;
    let pre: Observation = read_json(&root.join("streams/pre-restart.observation.json"))?;
    let post = observe(&inst, &plan, root, "post-restart").await?;
    anyhow::ensure!(
        std::fs::read(root.join(&pre.stream))? == std::fs::read(root.join(&post.stream))?
            && pre.head == post.head,
        "sorted session stream changed across physical restart"
    );
    let resolve: serde_json::Value = read_json(&root.join("resolve.json"))?;
    let identities = identities(root)?;
    anyhow::ensure!(
        identities == resolve["data_identities"] && post.head == pre.head,
        "cold reopen used different data directories or lost the selected head"
    );
    let census_before = census(root)?;
    anyhow::ensure!(
        census_before == resolve["destination"],
        "destination changed across restart"
    );
    let boundary_record: Boundary = read_json(&root.join("boundary.json"))?;
    let boundary = recheck_boundary(&inst, &boundary_record).await?;
    // Replay every original input. Complete sessions return their original
    // checkpoint; failed sessions keep the first selected failure against a
    // contender, and a backup retry receives the original refusal.
    let replay_started = Instant::now();
    let mut replayed = BTreeMap::new();
    let mut refusals = BTreeMap::new();
    let mut first_refusal = None;
    for original in originals.values() {
        match original.kind {
            Kind::Complete => {
                let checkpoint = complete(&inst, &plan, original.ordinal)
                    .await?
                    .native("replayed full backup")?;
                anyhow::ensure!(
                    original.checkpoint.as_ref() == Some(&checkpoint),
                    "replayed backup differs from original for {}",
                    original.ordinal
                );
            }
            Kind::Aborted => {
                let status = inst
                    .source
                    .abort_backup_session(
                        inst.context(original.ordinal),
                        AbortBackupSession {
                            destination: ALIAS.into(),
                            session_id: original.session_id,
                            reason: format!("replay contender {}", original.ordinal),
                        },
                    )
                    .await
                    .native("replayed abort")?;
                anyhow::ensure!(
                    status.outcome == original.outcome,
                    "replayed abort differs from original for {}",
                    original.ordinal
                );
                let error = complete(&inst, &plan, original.ordinal)
                    .await?
                    .err()
                    .context("aborted session completed on replay")?;
                anyhow::ensure!(
                    error.code == ErrorCode::Conflict,
                    "aborted replay refusal changed: {error:?}"
                );
                *refusals
                    .entry(format!("{:?}: {}", error.code, error.message))
                    .or_insert(0u64) += 1;
                first_refusal.get_or_insert_with(|| format!("{error:?}"));
            }
        }
        *replayed
            .entry(format!("{:?}", original.kind).to_lowercase())
            .or_insert(0u64) += 1;
        let done = replayed.values().sum::<u64>();
        if done % 1024 == 0 {
            eprintln!(
                "replay {done}/{} sessions, {:.1}s",
                originals.len(),
                replay_started.elapsed().as_secs_f64()
            );
        }
    }
    let replay_seconds = replay_started.elapsed().as_secs_f64();
    let cleanup_repeat = cleanup(&inst, &plan, kasumi_store::MAX_SESSION_GC_OBJECTS)
        .await
        .map_err(|e| anyhow::anyhow!("cleanup after restart: {e}"))?;
    anyhow::ensure!(cleanup_repeat.deleted_objects == 0 && !cleanup_repeat.more_objects_observed);
    let head_after = inst.head()?;
    let aggregate_after = inst.aggregate()?;
    anyhow::ensure!(
        head_after == head_before && aggregate_after == aggregate_before,
        "replay re-executed a session mutation"
    );
    let census_after = census(root)?;
    anyhow::ensure!(
        census_after == census_before,
        "replay changed the destination"
    );
    let replay = observe(&inst, &plan, root, "post-replay").await?;
    anyhow::ensure!(
        std::fs::read(root.join(&pre.stream))? == std::fs::read(root.join(&replay.stream))?,
        "replay changed the sorted session stream"
    );
    write_json(
        &root.join("verify.json"),
        &serde_json::json!({
            "process_id": std::process::id(),
            "open_seconds": opened,
            "seconds": started.elapsed().as_secs_f64(),
            "replay_seconds": replay_seconds,
            "replayed": replayed,
            "aborted_backup_refusals": refusals,
            "first_aborted_backup_refusal": first_refusal,
            "head_before": head_before,
            "head_after": head_after,
            "aggregate_before": aggregate_before,
            "aggregate_after": aggregate_after,
            "destination_before": census_before,
            "destination_after": census_after,
            "boundary_after_restart": boundary,
            "data_identities": identities,
            "cleanup_after_restart": cleanup_repeat,
        }),
    )?;
    inst.close().await
}

async fn replay_retained(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let inst = Installation::open(root, &plan).await?;
    let head = inst.head()?;
    let label = format!("replay-{}", std::process::id());
    let observation = observe(&inst, &plan, root, &label).await?;
    let pre: Observation = read_json(&root.join("streams/pre-restart.observation.json"))?;
    anyhow::ensure!(
        observation.stream_sha256 == pre.stream_sha256 && inst.head()? == head,
        "retained installation no longer reproduces the recorded stream"
    );
    println!(
        "KASUMI_BACKUP_SESSION_FLOOR_REPLAY {}",
        serde_json::to_string(&observation)?
    );
    inst.close().await
}

/// Reopen a failed population and exercise only the first unacknowledged
/// input. Its result is kept apart from the acceptance journal and witness.
async fn diagnose_next(root: &Path) -> anyhow::Result<()> {
    let plan = plan_of(root)?;
    let original = read_originals(root)?;
    let ordinal = original.len() as u64;
    anyhow::ensure!(
        ordinal < plan.reserve_start() && original.keys().copied().eq(0..ordinal),
        "diagnosis requires a contiguous interrupted population"
    );
    let installation = Installation::open(root, &plan).await?;
    let attempt = run_session(&installation, &plan, ordinal, "diagnose", true).await;
    let drain = installation.close().await;
    let evidence = serde_json::json!({
        "ordinal": ordinal, "session_id": plan.session_id(ordinal),
        "source_commit": std::env::var("KASUMI_SOURCE_COMMIT").ok(),
        "original": attempt.as_ref().ok(), "error": attempt.as_ref().err().map(|e| format!("{e:#}")),
        "drain_error": drain.as_ref().err().map(|e| format!("{e:#}")),
    });
    write_json(
        &root.join(format!("diagnose-{ordinal}-{}.json", std::process::id())),
        &evidence,
    )?;
    attempt?;
    drain
}

async fn child(stage: &str, root: &Path) -> anyhow::Result<()> {
    match stage {
        "populate" => populate(root).await,
        "diagnose-next" => diagnose_next(root).await,
        "kill" => kill_child(root).await,
        "resolve" => resolve(root).await,
        "verify" => verify(root).await,
        "replay" => replay_retained(root).await,
        other => anyhow::bail!("unknown backup floor stage {other}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    stage: String,
    argv: Vec<String>,
    process_id: u32,
    exit_code: Option<i32>,
    signal: Option<i32>,
    seconds: f64,
    stdout: String,
    stderr: String,
    stdout_sha256: String,
    stderr_sha256: String,
}

struct Parent {
    root: PathBuf,
    test: String,
    exe: PathBuf,
    processes: Vec<Process>,
}

impl Parent {
    fn command(&self, stage: &str) -> (std::process::Command, Vec<String>) {
        let args = vec![
            "--exact".to_owned(),
            self.test.clone(),
            "--include-ignored".to_owned(),
            "--nocapture".to_owned(),
            "--test-threads=1".to_owned(),
        ];
        let mut command = std::process::Command::new(&self.exe);
        command.args(&args).env(STAGE, stage).env(ROOT, &self.root);
        let mut argv = vec![self.exe.display().to_string()];
        argv.extend(args);
        (command, argv)
    }

    fn logs(&self, label: &str) -> (PathBuf, PathBuf) {
        let index = self.processes.len();
        (
            self.root.join(format!("logs/{index:02}-{label}.stdout")),
            self.root.join(format!("logs/{index:02}-{label}.stderr")),
        )
    }

    fn record(
        &mut self,
        stage: &str,
        argv: Vec<String>,
        (process_id, status, started): (u32, std::process::ExitStatus, Instant),
        (stdout, stderr): (&Path, &Path),
    ) -> anyhow::Result<Process> {
        use std::os::unix::process::ExitStatusExt as _;
        let relative = |path: &Path| path.strip_prefix(&self.root).unwrap().display().to_string();
        let process = Process {
            stage: stage.into(),
            argv,
            process_id,
            exit_code: status.code(),
            signal: status.signal(),
            seconds: started.elapsed().as_secs_f64(),
            stdout: relative(stdout),
            stderr: relative(stderr),
            stdout_sha256: file_sha256(stdout)?,
            stderr_sha256: file_sha256(stderr)?,
        };
        self.processes.push(process.clone());
        write_json(&self.root.join("processes.json"), &self.processes)?;
        Ok(process)
    }

    /// Run one stage to completion; a failed stage keeps its original output.
    fn run(&mut self, stage: &str) -> anyhow::Result<()> {
        let (stdout, stderr) = self.logs(stage);
        let (mut command, argv) = self.command(stage);
        let started = Instant::now();
        let mut child = command
            .stdout(std::fs::File::create(&stdout)?)
            .stderr(std::fs::File::create(&stderr)?)
            .spawn()?;
        let pid = child.id();
        let status = child.wait()?;
        let process = self.record(stage, argv, (pid, status, started), (&stdout, &stderr))?;
        let passed = std::fs::read_to_string(&stdout)?.contains("test result: ok. 1 passed");
        anyhow::ensure!(
            status.success() && passed,
            "stage {stage} failed: {process:?}; stderr tail: {}",
            tail(&stderr)
        );
        Ok(())
    }

    /// Run `stage` until it prints `marker`, then SIGKILL it at once. The
    /// child decides the instant: it emits the marker from the point under
    /// test and blocks there, so no timer chooses the kill point.
    fn kill_at(
        &mut self,
        stage: &str,
        target: Option<u64>,
        marker: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let label = target.map_or_else(|| stage.to_owned(), |t| format!("{stage}-{t}"));
        let (stdout, stderr) = self.logs(&label);
        let (mut command, argv) = self.command(stage);
        if let Some(target) = target {
            command.env(TARGET, target.to_string());
        }
        let started = Instant::now();
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::fs::File::create(&stderr)?)
            .spawn()?;
        let pid = child.id();
        let pipe = child.stdout.take().context("child stdout")?;
        let (lines, received) = std::sync::mpsc::channel::<String>();
        let log = stdout.clone();
        let tee = std::thread::spawn(move || -> std::io::Result<()> {
            let mut file = std::fs::File::create(log)?;
            for line in std::io::BufReader::new(pipe).lines() {
                let line = line?;
                writeln!(file, "{line}")?;
                file.flush()?;
                let _ = lines.send(line);
            }
            file.sync_all()
        });
        let observed = loop {
            match received.recv_timeout(std::time::Duration::from_secs(4 * 3600)) {
                Ok(line) if line.starts_with(marker) => break line,
                Ok(_) => {}
                // The child ended or stalled before its kill point.
                Err(_) => {
                    let _ = child.kill();
                    let status = child.wait()?;
                    let _ = tee.join();
                    let process =
                        self.record(stage, argv, (pid, status, started), (&stdout, &stderr))?;
                    anyhow::bail!(
                        "{label} never reached {marker:?}: {process:?}; {}",
                        tail(&stderr)
                    );
                }
            }
        };
        let marked = Instant::now();
        child.kill()?;
        let status = child.wait()?;
        let killed_after = marked.elapsed().as_secs_f64();
        tee.join().map_err(|_| anyhow::anyhow!("tee panicked"))??;
        let output = std::fs::read_to_string(&stdout)?;
        let returned = output.lines().any(|line| line.starts_with(WRITTEN));
        let process = self.record(stage, argv, (pid, status, started), (&stdout, &stderr))?;
        let payload: serde_json::Value =
            serde_json::from_str(&observed[marker.len()..]).unwrap_or(serde_json::Value::Null);
        anyhow::ensure!(
            process.signal == Some(9) && !returned,
            "{label} was not killed at {marker:?}: {process:?}"
        );
        Ok(serde_json::json!({
            "stage": stage,
            "target": target,
            "marker": marker.trim_end(),
            "marker_payload": payload,
            "seconds_from_marker_to_reap": killed_after,
            "signal": process.signal,
            "exit_code": process.exit_code,
            "operation_returned": returned,
            "process_id": pid,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }))
    }
}

fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// Re-read every retained artifact without opening the installation.
fn independent_check(root: &Path, plan: &Plan) -> anyhow::Result<serde_json::Value> {
    let originals = read_originals(root)?;
    anyhow::ensure!(
        originals.keys().copied().eq(0..plan.sessions),
        "original journal is not exactly the cohort"
    );
    let mut digests = BTreeMap::new();
    let mut reference: Option<Vec<u8>> = None;
    for label in ["pre-restart", "post-restart", "post-replay"] {
        let observation: Observation =
            read_json(&root.join(format!("streams/{label}.observation.json")))?;
        let bytes = std::fs::read(root.join(&observation.stream))?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(&bytes)) == observation.stream_sha256
                && bytes.len() as u64 == observation.stream_bytes,
            "{label} stream digest differs"
        );
        let stream = read_stream(root, &observation.stream)?;
        anyhow::ensure!(
            stream.windows(2).all(|w| w[0].session_id < w[1].session_id),
            "{label} stream is not strictly sorted by session ID"
        );
        anyhow::ensure!(
            stream.len() as u64 == plan.sessions && observation.sessions == plan.sessions
        );
        let aborted = stream
            .iter()
            .filter(|e| {
                matches!(
                    e.decision.as_ref().map(|d| &d.outcome),
                    Some(BackupSessionOutcome::Aborted { .. })
                )
            })
            .count() as u64;
        anyhow::ensure!(
            stream.iter().all(|e| e.decision.is_some()) && aborted == observation.aborted,
            "{label} decisions differ"
        );
        // Pages: bounded, contiguous, cover the whole head, distinct sessions.
        let mut through = 0;
        let mut total = 0;
        for (index, page) in observation.pages.iter().enumerate() {
            anyhow::ensure!(
                page.index == index as u64
                    && page.entries <= plan.page_limit as u64
                    && page.entries <= crate::MAX_CONTROL_BACKUP_SESSION_PAGE as u64
                    && page.scanned_from == through + 1
                    && page.scanned_through >= page.scanned_from
                    && page
                        .next
                        .as_ref()
                        .is_some_and(|n| n.after_ordinal == page.scanned_through)
                        == (index + 1 < observation.pages.len()),
                "{label} page {index} violates its bound or continuity"
            );
            through = page.scanned_through;
            total += page.entries;
        }
        anyhow::ensure!(
            through == observation.head.count && total == plan.sessions,
            "{label} pages leave a gap"
        );
        let ids: BTreeSet<_> = stream.iter().map(|e| e.session_id).collect();
        let expected: BTreeSet<_> = originals.values().map(|o| o.session_id).collect();
        anyhow::ensure!(ids == expected, "{label} sessions differ from the cohort");
        for original in originals.values() {
            let entry = &stream[stream
                .binary_search_by_key(&original.session_id, |e| e.session_id)
                .unwrap()];
            anyhow::ensure!(
                original.outcome_matches(&entry.decision.as_ref().unwrap().outcome),
                "{label} outcome differs for {}",
                original.ordinal
            );
        }
        if let Some(reference) = &reference {
            anyhow::ensure!(
                *reference == bytes,
                "{label} differs from the pre-restart stream"
            );
        } else {
            reference = Some(bytes);
        }
        digests.insert(
            label,
            serde_json::json!({
                "stream": observation.stream,
                "sha256": observation.stream_sha256,
                "bytes": observation.stream_bytes,
                "pages": observation.pages.len(),
                "max_page_entries": observation.max_page_entries,
                "process_id": observation.process_id,
                "head": observation.head,
                "aborted": aborted,
                "completed": observation.completed,
            }),
        );
    }
    let failed = originals
        .values()
        .filter(|o| o.kind == Kind::Aborted)
        .count() as u64;
    Ok(serde_json::json!({
        "original_journal_sha256": file_sha256(&root.join("original.jsonl"))?,
        "originals": originals.len(),
        "original_failed": failed,
        "streams": digests,
    }))
}

struct Cohort {
    name: &'static str,
    sessions: u64,
    failure_stride: u64,
    control_binding_budget: u64,
    page_limit: usize,
}

async fn witness(test: &str, cohort: Cohort) -> anyhow::Result<()> {
    if let Ok(stage) = std::env::var(STAGE) {
        begin_stdout()?;
        let root = PathBuf::from(std::env::var(ROOT)?);
        return match child(&stage, &root).await {
            Ok(()) => Ok(()),
            Err(original) => {
                eprintln!("KASUMI_BACKUP_FLOOR_STAGE_FAILURE {stage}: {original:?}");
                Err(original)
            }
        };
    }
    begin_stdout()?;
    let started = Instant::now();
    let (_temporary, root) = match std::env::var(EVIDENCE) {
        Ok(directory) => {
            let root = PathBuf::from(directory).join(format!(
                "{}-{}-{}",
                cohort.name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            ));
            std::fs::create_dir_all(&root)?;
            (None, root)
        }
        Err(_) => {
            let temporary = kasumi_store::test_utils::private_tempdir()?;
            let root = temporary.path().join("installation");
            std::fs::create_dir(&root)?;
            (Some(temporary), root)
        }
    };
    std::fs::create_dir_all(root.join("logs"))?;
    let profile = if cohort.sessions == FLOOR
        && let Some(path) = std::env::var_os("KASUMI_BACKUP_FLOOR_PROFILE")
    {
        let path = PathBuf::from(path);
        let profile: SessionFloorProfile = read_json(&path)?;
        profile.check(&root, cohort.sessions)?;
        let probe = std::fs::read(path.with_file_name("filesystem-probe.json"))?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(&probe)) == profile.probe_sha256,
            "original filesystem probe differs"
        );
        durable_write(&root.join("filesystem-probe.json"), &probe)?;
        Some(profile)
    } else {
        None
    };
    let plan = Plan {
        schema: SCHEMA.into(),
        cohort: cohort.name.into(),
        sessions: cohort.sessions,
        failure_stride: cohort.failure_stride,
        profile,
        kill_reserve: 2,
        nonce: uuid::Uuid::new_v4(),
        control_binding_budget: cohort.control_binding_budget,
        source_hot_audit_bytes: 128 << 10,
        control_hot_audit_bytes: 1 << 20,
        cleanup_objects: 300,
        page_limit: cohort.page_limit,
    };
    write_json(&root.join("plan.json"), &plan)?;
    let exe = std::env::current_exe()?;
    let mut parent = Parent {
        root: root.clone(),
        test: test.into(),
        exe: exe.clone(),
        processes: Vec::new(),
    };
    let outcome = async {
        parent.run("populate")?;
        // One complete capture killed inside its Control claim write and one
        // failure killed inside its Control terminal write.
        let mut kills = Vec::new();
        for ordinal in plan.reserve_start()..plan.sessions {
            kills.push(parent.kill_at("kill", Some(ordinal), OUTSTANDING)?);
        }
        write_json(&root.join("kills.json"), &kills)?;
        // The complete sorted observation must survive a cold kill of the
        // process that recorded it, with its stores still open.
        let cold = parent.kill_at("resolve", None, DURABLE)?;
        write_json(&root.join("cold-kill.json"), &cold)?;
        parent.run("verify")?;
        let independent = independent_check(&root, &plan)?;
        let populate: serde_json::Value = read_json(&root.join("populate.json"))?;
        let resolve: serde_json::Value = read_json(&root.join("resolve.json"))?;
        let verify: serde_json::Value = read_json(&root.join("verify.json"))?;
        let boundary: Boundary = read_json(&root.join("boundary.json"))?;
        let cleanup: serde_json::Value = read_json(&root.join("cleanup.json"))?;
        let head: BackupBindingHead = serde_json::from_value(verify["head_after"].clone())?;
        let failed = independent["original_failed"].as_u64().unwrap();
        let per_session = head.encoded_bytes as f64 / plan.sessions as f64;
        let witness = serde_json::json!({
            "schema": SCHEMA,
            "case": "backup-sessions",
            "qualification": "component",
            "cohort": plan.cohort,
            "floor": FLOOR,
            "floor_basis": "adopted new threshold; no historical global backup-session count limit exists",
            "observed_distinct_sessions": plan.sessions,
            "crosses_floor": plan.sessions >= FLOOR,
            "failed_terminal_outcomes": failed,
            "minimum_failed_terminal_outcomes": MIN_FAILED,
            "planned_failed_terminal_outcomes": plan.planned_failures(),
            "plan": plan,
            "architecture": {"arch": std::env::consts::ARCH, "os": std::env::consts::OS, "family": std::env::consts::FAMILY},
            "test": {
                "name": test,
                "executable": exe.display().to_string(),
                "executable_sha256": file_sha256(&exe)?,
                "source_commit": std::env::var("KASUMI_SOURCE_COMMIT").ok(),
                "parent_process_id": std::process::id(),
            },
            "limits": {
                "session_record_bytes": kasumi_store::MAX_SESSION_RECORD_BYTES,
                "encrypted_session_record_read_bytes": kasumi_store::MAX_ENCRYPTED_SESSION_RECORD_BYTES,
                "cleanup_page_objects": kasumi_store::MAX_SESSION_GC_OBJECTS,
                "observation_page_sessions": crate::MAX_CONTROL_BACKUP_SESSION_PAGE,
                "observation_page_limit_used": plan.page_limit,
                "control_binding_intent_ciphertext_bytes": kasumi_types::MAX_BACKUP_BINDING_INTENT_BYTES,
                "control_binding_budget_bytes": plan.control_binding_budget,
                "persistent_disk": read_json::<serde_json::Value>(&root.join("disk-policy.json"))?,
                "installed_default_binding_budget_bytes": INSTALLED_DEFAULT_BINDING_BYTES,
                "selected_binding_bytes": head.encoded_bytes,
                "binding_bytes_per_session": per_session,
                "sessions_within_installed_default": (INSTALLED_DEFAULT_BINDING_BYTES as f64 / per_session).floor(),
            },
            "processes": parent.processes,
            "kills": kills,
            "cold_kill": cold,
            "populate": populate,
            "resolve": resolve,
            "verify": verify,
            "boundary": boundary,
            "cleanup": cleanup,
            "independent": independent,
            "seconds": started.elapsed().as_secs_f64(),
        });
        write_json(&root.join("witness.json"), &witness)?;
        let summary = serde_json::json!({
            "case": "backup-sessions",
            "cohort": plan.cohort,
            "floor": FLOOR,
            "observed_distinct_sessions": plan.sessions,
            "failed_terminal_outcomes": failed,
            "pre_restart_stream_sha256": independent["streams"]["pre-restart"]["sha256"],
            "post_restart_stream_sha256": independent["streams"]["post-restart"]["sha256"],
            "post_replay_stream_sha256": independent["streams"]["post-replay"]["sha256"],
            "head": head,
            "witness": root.join("witness.json").display().to_string(),
            "witness_sha256": file_sha256(&root.join("witness.json"))?,
        });
        println!("{PREFIX}{summary}");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(original) = &outcome {
        write_json(
            &root.join("failure.json"),
            &serde_json::json!({
                "error": format!("{original:?}"),
                "processes": parent.processes,
                "seconds": started.elapsed().as_secs_f64(),
            }),
        )?;
        // Keep the failed installation for diagnosis even without an evidence root.
        if let Some(temporary) = _temporary {
            let kept = temporary.keep();
            eprintln!(
                "retained failed backup floor installation at {}",
                kept.display()
            );
        }
    }
    outcome
}

fn test_name(leaf: &str) -> String {
    let module = module_path!();
    format!(
        "{}::{leaf}",
        module.split_once("::").map_or(module, |(_, rest)| rest)
    )
}

async fn prepare_interrupted_claim(root: &Path, plan: &Plan, ordinal: u64) -> anyhow::Result<()> {
    let inst = Installation::open(root, plan).await?;
    claim_and_publish(&inst, plan, ordinal).await?;
    let previous = interrupted_abort_status(&inst, plan, ordinal)
        .await?
        .context("original claim absent")?;
    anyhow::ensure!(
        previous.outcome.is_none(),
        "original claim already terminal"
    );
    write_json(&root.join("original-claim.json"), &previous)?;
    advance_population_source(&inst, ordinal + 1).await?;
    inst.close().await
}

async fn advance_population_source(inst: &Installation, ordinal: u64) -> anyhow::Result<()> {
    inst.source
        .administer(
            inst.context(ordinal),
            Operation::CreateCollection(CollectionDefinition {
                name: "later".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .native("advance source after original claim")
        .map(|_| ())
}

fn interrupted_population_plan() -> Plan {
    Plan {
        schema: SCHEMA.into(),
        cohort: "regression".into(),
        sessions: 24,
        failure_stride: 3,
        profile: None,
        kill_reserve: 2,
        nonce: uuid::Uuid::new_v4(),
        control_binding_budget: INSTALLED_DEFAULT_BINDING_BYTES,
        source_hot_audit_bytes: 128 << 10,
        control_hot_audit_bytes: 1 << 20,
        cleanup_objects: 300,
        page_limit: 8,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uncertain_population_claim_requires_the_exact_committed_input() -> anyhow::Result<()> {
    let temp = kasumi_store::test_utils::private_tempdir()?;
    let root = temp.path().join("installation");
    std::fs::create_dir_all(root.join("logs"))?;
    let plan = interrupted_population_plan();
    let inst = Installation::open(&root, &plan).await?;
    let ordinal = 5;
    assert_eq!(plan.kind(ordinal), Kind::Aborted);
    let id = plan.session_id(ordinal);
    let context = inst.context(ordinal);
    let generation = inst.source.engine.generation()?;
    let intent = BackupSessionIntent {
        session_id: id,
        tenant: context.tenant.clone(),
        source_incarnation: generation.incarnation().into(),
        revision: generation.state.revision,
        principal: context.principal.clone(),
        request_id: context.request_id.clone(),
    };
    // Replace only the response at the Control proposal boundary. Every read,
    // permanent claim, external create and terminal decision uses real stores.
    let lost = || {
        Err(Error::new(
            ErrorCode::UnknownOutcome,
            "forced lost Control claim reply",
        ))
    };
    let object = || {
        inst.destination.session_get(
            id,
            BackupSessionSlot::Intent,
            kasumi_store::MAX_ENCRYPTED_SESSION_RECORD_BYTES,
        )
    };
    let before = inst.head()?;
    let missing = publish_claim_result(&inst, &context, &intent, lost())
        .await
        .unwrap_err();
    assert_eq!(
        missing.downcast_ref::<Error>().unwrap().code,
        ErrorCode::UnknownOutcome
    );
    assert!(
        missing
            .to_string()
            .contains("no committed population claim")
    );
    assert_eq!(inst.head()?, before);
    assert!(object().await?.is_none());

    let bytes = inst
        .source
        .claim_backup_intent(
            &context,
            inst.destination.as_ref(),
            &intent,
            &generation,
            Some(ALIAS),
        )
        .await?;
    drop(generation);
    let claimed = inst.head()?;
    assert_eq!(claimed.count, before.count + 1);
    assert!(object().await?.is_none());
    let mut other = context.clone();
    other.request_id.push_str("-other");
    let wrong = BackupSessionIntent {
        request_id: other.request_id.clone(),
        ..intent.clone()
    };
    let denied = publish_claim_result(&inst, &other, &wrong, lost())
        .await
        .unwrap_err();
    assert!(
        denied
            .to_string()
            .contains("exact pending population claim")
    );
    assert_eq!(inst.head()?, claimed);
    assert!(object().await?.is_none());

    // A newer source generation cannot become this session's snapshot.
    advance_population_source(&inst, ordinal + 1).await?;
    assert!(inst.source.engine.generation()?.state.revision > intent.revision);
    publish_claim_result(&inst, &context, &intent, lost()).await?;
    assert_eq!(object().await?.as_deref(), Some(bytes.as_bytes()));
    publish_claim_result(&inst, &context, &intent, lost()).await?;
    assert_eq!(object().await?.as_deref(), Some(bytes.as_bytes()));
    let pending = interrupted_abort_status(&inst, &plan, ordinal)
        .await?
        .unwrap();
    assert_eq!(pending.intent, intent);
    assert!(pending.outcome.is_none());
    assert_eq!(inst.head()?, claimed);
    let terminal = abort(&inst, &plan, ordinal).await?;
    assert_eq!(terminal.intent, intent);
    assert!(
        matches!(&terminal.outcome, Some(BackupSessionOutcome::Aborted {
        reason, intent_ciphertext_sha256, ..
    }) if *reason == abort_reason(ordinal) && *intent_ciphertext_sha256 == hex::encode(Sha256::digest(bytes.as_bytes())))
    );
    let ended = inst.head()?;
    assert_eq!(ended.count, claimed.count + 1);
    let replay = run_session(&inst, &plan, ordinal, "populate", true).await?;
    assert_eq!(replay.outcome, terminal.outcome);
    assert_eq!(inst.head()?, ended);
    inst.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_population_reuses_a_cold_claim_after_source_revision_advances()
-> anyhow::Result<()> {
    let ordinal = 5;
    if std::env::var(STAGE).as_deref() == Ok("prepare-interrupted-claim") {
        let root = PathBuf::from(std::env::var(ROOT)?);
        return prepare_interrupted_claim(&root, &plan_of(&root)?, ordinal).await;
    }
    let temp = kasumi_store::test_utils::private_tempdir()?;
    let root = temp.path().join("installation");
    std::fs::create_dir_all(root.join("logs"))?;
    let plan = interrupted_population_plan();
    write_json(&root.join("plan.json"), &plan)?;
    // The persistent disk registry owns its admission until process exit.
    Parent {
        root: root.clone(),
        test: test_name(
            "interrupted_population_reuses_a_cold_claim_after_source_revision_advances",
        ),
        exe: std::env::current_exe()?,
        processes: Vec::new(),
    }
    .run("prepare-interrupted-claim")?;
    let previous: BackupSessionStatus = read_json(&root.join("original-claim.json"))?;
    let reopened = Installation::open(&root, &plan).await?;
    anyhow::ensure!(
        reopened.source.engine.generation()?.state.revision > previous.intent.revision,
        "cold generation did not advance beyond the captured revision"
    );
    let before = reopened.head()?;
    let result = run_session(&reopened, &plan, ordinal, "populate", true).await?;
    anyhow::ensure!(
        result.resolution.is_some()
            && result.session_id == previous.intent.session_id
            && reopened.head()?.count == before.count + 1,
        "cold abort did not select the one original claim"
    );
    let after = interrupted_abort_status(&reopened, &plan, ordinal)
        .await?
        .context("cold terminal absent")?;
    anyhow::ensure!(
        after.intent == previous.intent
            && after.source_purpose_sha256 == previous.source_purpose_sha256
            && after.outcome == result.outcome,
        "original cold claim changed"
    );
    let replay = run_session(&reopened, &plan, ordinal, "populate", true).await?;
    anyhow::ensure!(
        replay.outcome == result.outcome && reopened.head()?.count == before.count + 1,
        "retained terminal replay published another Control row"
    );
    reopened.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_population_recovers_all_unjournaled_originals() -> anyhow::Result<()> {
    if let Ok(stage) = std::env::var(STAGE) {
        let root = PathBuf::from(std::env::var(ROOT)?);
        if stage == "populate" {
            return populate(&root).await;
        }
        anyhow::ensure!(stage == "original-prefix");
        let plan = plan_of(&root)?;
        let inst = Installation::open(&root, &plan).await?;
        let (_, mut journal) = Journal::resume(&root)?;
        let mut originals = Vec::new();
        // The node and destination durably acknowledge six sessions. Only
        // the first result reaches the external observer's durable journal.
        for ordinal in 0..6 {
            let original = run_session(&inst, &plan, ordinal, "original", false).await?;
            if ordinal == 0 {
                journal.append(&original)?;
                journal.sync()?;
            }
            originals.push(original);
        }
        write_json(&root.join("acknowledged.json"), &originals)?;
        advance_population_source(&inst, plan.sessions + 1).await?;
        return inst.close().await;
    }

    let temp = kasumi_store::test_utils::private_tempdir()?;
    let root = temp.path().join("installation");
    std::fs::create_dir_all(root.join("logs"))?;
    let plan = Plan {
        sessions: 11,
        failure_stride: 2,
        ..interrupted_population_plan()
    };
    write_json(&root.join("plan.json"), &plan)?;
    let mut parent = Parent {
        root: root.clone(),
        test: test_name("interrupted_population_recovers_all_unjournaled_originals"),
        exe: std::env::current_exe()?,
        processes: Vec::new(),
    };
    parent.run("original-prefix")?;
    let prefix = std::fs::read(root.join("original.jsonl"))?;
    let originals: Vec<Original> = read_json(&root.join("acknowledged.json"))?;
    parent.run("populate")?;
    let journal = std::fs::read(root.join("original.jsonl"))?;
    anyhow::ensure!(journal.starts_with(&prefix));
    let recovered = read_originals(&root)?;
    anyhow::ensure!(recovered.len() as u64 == plan.reserve_start());
    for original in originals {
        let current = &recovered[&original.ordinal];
        anyhow::ensure!(
            current.session_id == original.session_id
                && current.request_id == original.request_id
                && current.kind == original.kind
                && current.outcome == original.outcome
                && current.checkpoint == original.checkpoint
        );
        if original.kind == Kind::Aborted {
            anyhow::ensure!(current.resolution.is_some());
        }
    }
    anyhow::ensure!(recovered[&7].resolution.is_none());
    Ok(())
}

/// Small normal regression: every process, kill point, replay, boundary and
/// cleanup check of the full witness on 24 sessions, paged eight at a time.
/// Each session reserves both terminal slots before it publishes its first object.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_session_floor_regression() -> anyhow::Result<()> {
    witness(
        &test_name("backup_session_floor_regression"),
        Cohort {
            name: "regression",
            sessions: 24,
            failure_stride: 3,
            control_binding_budget: INSTALLED_DEFAULT_BINDING_BYTES,
            page_limit: 8,
        },
    )
    .await
}

/// Explicit page cohort: 520 sessions with 260 planned failures, enumerated
/// at the full 256-session page bound, at the installed default binding budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit 520-session page cohort across physical restart"]
async fn backup_session_floor_page_cohort() -> anyhow::Result<()> {
    witness(
        &test_name("backup_session_floor_page_cohort"),
        Cohort {
            name: "page",
            sessions: 520,
            failure_stride: 2,
            control_binding_budget: INSTALLED_DEFAULT_BINDING_BYTES,
            page_limit: crate::MAX_CONTROL_BACKUP_SESSION_PAGE,
        },
    )
    .await
}

/// Explicit full cohort: 100,001 distinct sessions with more than 256 failed
/// terminal outcomes. The Control binding budget is raised explicitly; the
/// witness records how many sessions the installed default would retain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit G11 backup-session floor; 100,001 sessions across physical restarts"]
async fn backup_session_floor_full_cohort() -> anyhow::Result<()> {
    witness(
        &test_name("backup_session_floor_full_cohort"),
        Cohort {
            name: "full",
            sessions: FLOOR,
            failure_stride: 389,
            control_binding_budget: 16 << 30,
            page_limit: crate::MAX_CONTROL_BACKUP_SESSION_PAGE,
        },
    )
    .await
}

/// Re-derive the sorted stream from a retained installation in a new process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "replays a retained backup-session floor installation named by KASUMI_BACKUP_FLOOR_REPLAY"]
async fn backup_session_floor_replay_retained() -> anyhow::Result<()> {
    if std::env::var(STAGE).is_ok() {
        begin_stdout()?;
        let root = PathBuf::from(std::env::var(ROOT)?);
        return child("replay", &root).await;
    }
    let root = PathBuf::from(std::env::var(REPLAY).context("KASUMI_BACKUP_FLOOR_REPLAY")?);
    let mut parent = Parent {
        root: root.clone(),
        test: test_name("backup_session_floor_replay_retained"),
        exe: std::env::current_exe()?,
        processes: read_json(&root.join("processes.json")).unwrap_or_default(),
    };
    parent.run("replay")
}
