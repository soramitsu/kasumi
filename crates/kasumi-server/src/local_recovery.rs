//! Exclusive local recovery. Its activation and stop records fence this installed
//! standalone process; they do not claim that another independently running copy
//! or a distributed source has stopped.
use crate::runtime::{KeyProviderSettings, RuntimeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::{StoragePurpose, TenantStore, WriteOp, private_files};
use kasumi_types::{FullBackupCheckpoint, validate_name};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

const PHASES: &str = "standalone-recovery-phases";
const OPERATIONS: &str = "standalone-recovery-operations";
const GENERATIONS: &str = "standalone-recovery-generations";
const ACTIVE: &str = "standalone-recovery-active";
const INSTALLATION: &str = "standalone-recovery-installation";
const MAX_RECORD: usize = 2 << 20;
#[path = "local_recovery_archives.rs"]
mod archives;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecoveryStart {
    pub operation_id: Uuid,
    pub tenant: String,
    pub expected_active_incarnation: Uuid,
    pub target_incarnation: Uuid,
    pub checkpoint: FullBackupCheckpoint,
    pub source_purpose: StoragePurpose,
    pub source_keys: KeyProviderSettings,
    pub source_principal: String,
    /// Installed alias; neither the backup graph nor a client chooses endpoints.
    pub destination: String,
    pub phase_timeout_ms: u64,
}
impl LocalRecoveryStart {
    fn validate(&self) -> Result<()> {
        self.checkpoint.validate()?;
        validate_name(&self.tenant)?;
        validate_name(&self.source_principal)?;
        validate_name(&self.destination)?;
        ensure!(
            !self.operation_id.is_nil()
                && !self.target_incarnation.is_nil()
                && !self.expected_active_incarnation.is_nil(),
            "local recovery identities must be non-nil"
        );
        ensure!(
            self.tenant == self.checkpoint.tenant
                && self.target_incarnation != self.expected_active_incarnation
                && self.target_incarnation.to_string() != self.checkpoint.source_incarnation,
            "local recovery source/target binding differs"
        );
        ensure!(
            (1..=600_000).contains(&self.phase_timeout_ms),
            "local phase timeout must be 1..600000 milliseconds"
        );
        ensure!(
            matches!(&self.source_purpose, StoragePurpose::Standalone { installation_id, tenant, incarnation } if !installation_id.is_nil() && tenant == &self.tenant && incarnation.to_string() == self.checkpoint.source_incarnation),
            "standalone recovery requires the exact standalone source storage purpose"
        );
        match &self.source_keys {
            KeyProviderSettings::File { path } => {
                ensure!(path.is_absolute(), "source keyring path must be absolute")
            }
            KeyProviderSettings::Transit(settings) => {
                settings.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalRecoveryPhase {
    Materialize,
    Complete,
    Activate,
    Publish,
    Finished,
    Stopping,
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecoveryStatus {
    pub request: LocalRecoveryStart,
    pub phase: LocalRecoveryPhase,
    pub phase_id: Uuid,
    pub last_failure: Option<String>,
    /// Explicit local scope, carried in every status rather than implying a
    /// distributed source-unavailable fencing claim.
    pub fencing_scope: String,
    pub client_profile: Option<PathBuf>,
    pub cleanup_evidence: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u32,
    status: LocalRecoveryStatus,
    installation_id: Uuid,
    database_path: PathBuf,
    target_directory: PathBuf,
    database_file: Option<private_files::FileIdentity>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    archive_directory: Option<private_files::DirectoryIdentity>,
    source_provider: serde_json::Value,
    application_provider: serde_json::Value,
    custody_provider: serde_json::Value,
    target_family: Uuid,
    publication: Option<Publication>,
    profile_renewal: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    id: Uuid,
    topology: kasumi_engine::control::ControlTopology,
    expected: kasumi_types::Precondition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveGeneration {
    pub operation_id: Uuid,
    pub incarnation: Uuid,
    pub directory: PathBuf,
    pub checkpoint: FullBackupCheckpoint,
    application_provider: serde_json::Value,
    custody_provider: serde_json::Value,
}

impl ActiveGeneration {
    /// The selected operation/installation facts already passed the permanent
    /// generation journal checks in `active_generation`; aliases cannot select
    /// another expected physical node-file identity.
    pub(crate) fn database_id(&self, config: &RuntimeConfig, tenant: &str) -> Result<Uuid> {
        kasumi_store::node_store_ids::local_generation(
            installation_id(config, tenant)?,
            self.operation_id,
            self.incarnation,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum GenerationRecord {
    Reserved { operation_id: Uuid },
    Active { operation_id: Uuid },
    Stopped { operation_id: Uuid },
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_RECORD,
        "local recovery record exceeds its work limit"
    );
    Ok(serde_json::from_slice(bytes)?)
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_RECORD,
        "local recovery record exceeds its work limit"
    );
    Ok(bytes)
}
fn record(store: &TenantStore, operation: Uuid) -> Result<Journal> {
    let journal: Journal = decode(
        &store
            .get(OPERATIONS, operation.as_bytes())?
            .context("local recovery operation is unknown")?,
    )?;
    ensure!(
        journal.format == 2 && journal.status.request.operation_id == operation,
        "unsupported or substituted local recovery record"
    );
    Ok(journal)
}
fn persist(store: &TenantStore, journal: &Journal) -> Result<()> {
    store.write_batch(&[WriteOp::put(
        OPERATIONS,
        journal.status.request.operation_id.as_bytes(),
        encoded(journal)?,
    )])
}
fn phase_entry(journal: &Journal) -> Result<WriteOp> {
    // Every dispatch has immutable exact inputs even after the mutable cursor
    // advances. The encrypted table retains the identities permanently.
    Ok(WriteOp::put(
        PHASES,
        journal.status.phase_id.as_bytes(),
        encoded(&(
            journal.status.phase,
            &journal.status.request,
            journal.installation_id,
            &journal.database_path,
            &journal.target_directory,
            &journal.source_provider,
            &journal.application_provider,
            &journal.custody_provider,
        ))?,
    ))
}
fn directory(config: &RuntimeConfig, target: Uuid) -> Result<PathBuf> {
    Ok(config
        .database_path
        .parent()
        .context("standalone data directory missing")?
        .join("generations")
        .join(target.to_string()))
}
fn installation_id(config: &RuntimeConfig, tenant: &str) -> Result<Uuid> {
    let configured = config
        .tenants
        .iter()
        .find(|configured| configured.tenant == tenant)
        .context("local recovery tenant is not installed")?;
    match configured.serving {
        crate::serving_runtime::TenantServingConfig::Standalone { installation_id } => {
            Ok(installation_id)
        }
        _ => anyhow::bail!("local recovery requires an installed standalone tenant"),
    }
}

pub(crate) fn active_generation(
    config: &RuntimeConfig,
    store: &TenantStore,
    tenant: &str,
) -> Result<Option<ActiveGeneration>> {
    let Some(bytes) = store.get(ACTIVE, tenant.as_bytes())? else {
        return Ok(None);
    };
    let active: ActiveGeneration = decode(&bytes)?;
    let configured = config
        .tenants
        .iter()
        .find(|configured| configured.tenant == tenant)
        .context("active generation tenant is not installed")?;
    ensure!(
        active.directory == directory(config, active.incarnation)? && !active.operation_id.is_nil(),
        "active standalone physical generation binding differs"
    );
    ensure!(
        active.application_provider == configured.keys.identity_descriptor()?
            && active.custody_provider == configured.custody_keys.identity_descriptor()?,
        "active standalone key-provider binding differs"
    );
    let outcome: GenerationRecord = decode(
        &store
            .get(GENERATIONS, active.incarnation.as_bytes())?
            .context("active standalone generation outcome is missing")?,
    )?;
    ensure!(
        matches!(outcome, GenerationRecord::Active { operation_id } if operation_id == active.operation_id),
        "standalone generation is permanently stopped or belongs to another operation"
    );
    let journal = record(store, active.operation_id)?;
    ensure!(
        journal.installation_id == installation_id(config, tenant)?
            && journal.status.request.tenant == tenant
            && journal.status.request.target_incarnation == active.incarnation
            && journal.status.request.checkpoint == active.checkpoint
            && journal.target_directory == active.directory
            && matches!(
                journal.status.phase,
                LocalRecoveryPhase::Publish | LocalRecoveryPhase::Finished
            ),
        "active generation differs from committed recovery"
    );
    check_binding(&journal)?;
    check_database_file(&journal)?;
    ensure!(
        active.directory.join("node.redb").is_file(),
        "activated standalone database is missing"
    );
    Ok(Some(active))
}

/// Called before any application provider is opened by the serving runtime.
/// A partially executed offline recovery cannot accidentally resume source writes.
pub(crate) fn require_runtime_ready(store: &TenantStore) -> Result<()> {
    ensure!(
        !runtime_pending(store)?,
        "standalone recovery is incomplete; resume or stop the recorded local operation before serving"
    );
    Ok(())
}

/// A point observation under the installed security store's live ownership.
pub(crate) fn runtime_pending(store: &TenantStore) -> Result<bool> {
    Ok(store.get(INSTALLATION, b"pending")?.is_some())
}

struct Operator {
    config: RuntimeConfig,
    node: Arc<kasumi_store::NodeStore>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    credentials: Arc<crate::local_auth::LocalCredentials>,
    _lock: private_files::ExclusiveLock,
}
impl Operator {
    async fn open(configuration: &Path) -> Result<Self> {
        let config = RuntimeConfig::load(configuration)?;
        let (lock, node, audit, credentials) = crate::standalone::operator_state(&config).await?;
        Ok(Self {
            config,
            node,
            audit,
            credentials,
            _lock: lock,
        })
    }
    fn store(&self) -> &TenantStore {
        self.audit.store()
    }
    fn validate(&self, journal: &Journal) -> Result<()> {
        journal.status.request.validate()?;
        let request = &journal.status.request;
        ensure!(
            journal.installation_id == installation_id(&self.config, &request.tenant)?
                && journal.database_path == self.config.database_path
                && journal.target_directory == directory(&self.config, request.target_incarnation)?,
            "local recovery physical installation binding differs"
        );
        if !matches!(
            journal.status.phase,
            LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped
        ) {
            let pending: Uuid = decode(
                &self
                    .store()
                    .get(INSTALLATION, b"pending")?
                    .context("local recovery pending owner is missing")?,
            )?;
            ensure!(
                pending == request.operation_id,
                "local recovery belongs to another pending owner"
            );
        }
        Ok(())
    }
    async fn event(
        &self,
        journal: &Journal,
        outcome: kasumi_engine::SecurityOutcome,
    ) -> Result<()> {
        self.audit
            .record(kasumi_engine::SecurityEvent {
                kind: kasumi_engine::SecurityEventKind::Restore,
                principal: Some("offline-operator".into()),
                tenant: Some(journal.status.request.tenant.clone()),
                request_id: journal.status.phase_id.to_string(),
                outcome,
            })
            .await?;
        Ok(())
    }
    async fn context(
        &self,
        tenant: &str,
        principal: &str,
        resource: kasumi_types::CredentialResource,
        phase: Uuid,
    ) -> Result<kasumi_types::RequestContext> {
        // Physical ownership issues a fresh family for this invocation. A resumed
        // operation obtains a new deadline and resolves its original phase ID;
        // no old request or expired token is extended or accepted.
        let token = self.credentials.create(
            kasumi_types::CreateCredential {
                family_id: Uuid::new_v4(),
                principal: principal.into(),
                tenant: tenant.into(),
                resource,
                scopes: std::collections::BTreeSet::from([
                    kasumi_types::Action::Read,
                    kasumi_types::Action::Write,
                    kasumi_types::Action::Admin,
                    kasumi_types::Action::Audit,
                ]),
                lifetime_seconds: 3600,
            },
            "offline-recovery",
        )?;
        let auth = crate::auth::Authenticator::new(self.config.auth.clone())?;
        auth.install_audit(self.audit.clone())?;
        auth.install_local_credentials(self.credentials.clone())?;
        let mut context = auth
            .authenticate(&format!("Bearer {}", token.token))
            .await?;
        context.request_id = phase.to_string();
        Ok(context)
    }
    fn transition(&self, journal: &mut Journal, phase: LocalRecoveryPhase) -> Result<()> {
        journal.status.phase = phase;
        journal.status.phase_id = Uuid::new_v4();
        journal.status.last_failure = None;
        self.store().write_batch(&[
            WriteOp::put(
                OPERATIONS,
                journal.status.request.operation_id.as_bytes(),
                encoded(journal)?,
            ),
            phase_entry(journal)?,
        ])
    }
}

pub async fn start(
    configuration: &Path,
    request: LocalRecoveryStart,
) -> Result<LocalRecoveryStatus> {
    request.validate()?;
    let operator = Operator::open(configuration).await?;
    let result = async {
        if let Some(bytes) = operator
            .store()
            .get(OPERATIONS, request.operation_id.as_bytes())?
        {
            let journal: Journal = decode(&bytes)?;
            ensure!(
                encoded(&journal.status.request)? == encoded(&request)?,
                "local recovery operation ID conflicts with original inputs"
            );
            operator.validate(&journal)?;
            return Ok(journal.status);
        }
        require_runtime_ready(operator.store())?;
        let tenant = operator
            .config
            .tenants
            .iter()
            .find(|tenant| tenant.tenant == request.tenant)
            .context("local recovery tenant is not installed")?;
        let active = active_generation(&operator.config, operator.store(), &request.tenant)?;
        let current = match active {
            Some(active) => active.incarnation,
            None => Uuid::parse_str(
                tenant
                    .incarnation
                    .as_deref()
                    .context("installed incarnation is missing")?,
            )?,
        };
        ensure!(
            current == request.expected_active_incarnation,
            "local recovery active generation changed"
        );
        ensure!(
            operator
                .config
                .backup_destinations
                .contains_key(&request.destination),
            "local recovery backup destination is not installed"
        );
        ensure!(
            operator
                .store()
                .get(GENERATIONS, request.target_incarnation.as_bytes())?
                .is_none(),
            "target incarnation is permanently reserved or stopped"
        );
        let target_directory = directory(&operator.config, request.target_incarnation)?;
        ensure!(
            !target_directory.try_exists()?,
            "target generation directory already exists"
        );
        let journal = Journal {
            format: 2,
            installation_id: installation_id(&operator.config, &request.tenant)?,
            database_path: operator.config.database_path.clone(),
            target_directory,
            database_file: None,
            archive_directory: None,
            source_provider: request.source_keys.identity_descriptor()?,
            application_provider: tenant.keys.identity_descriptor()?,
            custody_provider: tenant.custody_keys.identity_descriptor()?,
            target_family: Uuid::new_v4(),
            publication: None,
            profile_renewal: None,
            status: LocalRecoveryStatus {
                request,
                phase: LocalRecoveryPhase::Materialize,
                phase_id: Uuid::new_v4(),
                last_failure: None,
                fencing_scope: "exclusive_local_installation".into(),
                client_profile: None,
                cleanup_evidence: None,
            },
        };
        operator.store().write_batch(&[
            WriteOp::put(
                OPERATIONS,
                journal.status.request.operation_id.as_bytes(),
                encoded(&journal)?,
            ),
            WriteOp::put(
                GENERATIONS,
                journal.status.request.target_incarnation.as_bytes(),
                encoded(&GenerationRecord::Reserved {
                    operation_id: journal.status.request.operation_id,
                })?,
            ),
            WriteOp::put(
                INSTALLATION,
                b"pending",
                encoded(&journal.status.request.operation_id)?,
            ),
            phase_entry(&journal)?,
        ])?;
        operator
            .event(&journal, kasumi_engine::SecurityOutcome::Started)
            .await?;
        Ok(journal.status)
    }
    .await;
    operator.audit.shutdown().await;
    result
}

pub async fn status(configuration: &Path, operation: Uuid) -> Result<LocalRecoveryStatus> {
    let operator = Operator::open(configuration).await?;
    let result = (|| {
        let journal = record(operator.store(), operation)?;
        operator.validate(&journal)?;
        Ok(journal.status)
    })();
    operator.audit.shutdown().await;
    result
}

pub async fn resume(configuration: &Path, operation: Uuid) -> Result<LocalRecoveryStatus> {
    let operator = Operator::open(configuration).await?;
    let result = async {
        let mut journal = record(operator.store(), operation)?;
        operator.validate(&journal)?;
        while !matches!(
            journal.status.phase,
            LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped
        ) {
            if let Err(error) = operator.step(&mut journal).await {
                // Resolve a possibly committed atomic transition before writing
                // diagnostics; never turn an uncertain activation into a stop.
                journal = record(operator.store(), operation)?;
                let mut failure = error.to_string();
                while failure.len() > 1024 {
                    failure.pop();
                }
                journal.status.last_failure = Some(failure);
                persist(operator.store(), &journal)?;
                let _ = operator
                    .event(&journal, kasumi_engine::SecurityOutcome::Failed)
                    .await;
                return Err(error);
            }
            if journal.status.phase == LocalRecoveryPhase::Stopping {
                tokio::task::yield_now().await;
            }
        }
        Ok(journal.status)
    }
    .await;
    operator.audit.shutdown().await;
    result
}

pub async fn stop(configuration: &Path, operation: Uuid) -> Result<LocalRecoveryStatus> {
    let operator = Operator::open(configuration).await?;
    let result = async {
        let mut journal = record(operator.store(), operation)?;
        operator.validate(&journal)?;
        ensure!(
            !matches!(
                journal.status.phase,
                LocalRecoveryPhase::Publish | LocalRecoveryPhase::Finished
            ),
            "local activation has committed; recovery must proceed forward"
        );
        if journal.status.phase == LocalRecoveryPhase::Stopped {
            return Ok(journal.status);
        }
        if journal.status.phase != LocalRecoveryPhase::Stopping {
            journal.status.phase = LocalRecoveryPhase::Stopping;
            journal.status.phase_id = Uuid::new_v4();
        }
        operator.store().write_batch(&[
            WriteOp::put(OPERATIONS, operation.as_bytes(), encoded(&journal)?),
            WriteOp::put(
                GENERATIONS,
                journal.status.request.target_incarnation.as_bytes(),
                encoded(&GenerationRecord::Stopped {
                    operation_id: operation,
                })?,
            ),
            phase_entry(&journal)?,
        ])?;
        operator.cleanup(&mut journal).await?;
        Ok(journal.status)
    }
    .await;
    operator.audit.shutdown().await;
    result
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PhysicalBinding {
    format: u32,
    installation: Uuid,
    operation: Uuid,
    incarnation: Uuid,
    tenant: String,
    coordinator: PathBuf,
}
fn binding(journal: &Journal) -> PhysicalBinding {
    PhysicalBinding {
        format: 1,
        installation: journal.installation_id,
        operation: journal.status.request.operation_id,
        incarnation: journal.status.request.target_incarnation,
        tenant: journal.status.request.tenant.clone(),
        coordinator: journal.database_path.clone(),
    }
}
fn check_binding(journal: &Journal) -> Result<()> {
    private_files::check_directory(&journal.target_directory)?;
    ensure!(
        std::fs::canonicalize(&journal.target_directory)? == journal.target_directory,
        "local generation has an aliased ancestor"
    );
    let actual: PhysicalBinding = decode(&private_files::read(
        &journal.target_directory.join("binding.json"),
        MAX_RECORD,
    )?)?;
    ensure!(
        actual == binding(journal),
        "local recovery physical generation identity differs"
    );
    Ok(())
}
fn check_database_file(journal: &Journal) -> Result<()> {
    let path = journal.target_directory.join("node.redb");
    let identity = journal
        .database_file
        .as_ref()
        .context("target file has no durable physical binding")?;
    ensure!(
        &private_files::file_identity(&path)? == identity,
        "target database inode has been substituted"
    );
    Ok(())
}
impl Operator {
    fn prepare_database_file(&self, journal: &mut Journal) -> Result<()> {
        self.prepare_directory(journal)?;
        let path = journal.target_directory.join("node.redb");
        if journal.database_file.is_none() {
            if path.try_exists()? {
                // A crash can leave the just-created empty inode before its
                // journal commit. An unbound populated file is never adopted.
                private_files::read(&path, 0)?;
            } else {
                private_files::create(&path, b"")?;
            }
            journal.database_file = Some(private_files::file_identity(&path)?);
            self.store().write_batch(&[
                WriteOp::put(
                    OPERATIONS,
                    journal.status.request.operation_id.as_bytes(),
                    encoded(journal)?,
                ),
                WriteOp::put(
                    PHASES,
                    format!("{}/physical", journal.status.phase_id).as_bytes(),
                    encoded(&journal.database_file)?,
                ),
            ])?;
        }
        check_database_file(journal)?;
        self.prepare_archives(journal)
    }
    fn prepare_directory(&self, journal: &Journal) -> Result<()> {
        let parent = journal
            .target_directory
            .parent()
            .context("target directory has no parent")?;
        if parent.try_exists()? {
            private_files::check_directory(parent)?;
        } else {
            private_files::create_directory(parent)?;
        }
        if journal.target_directory.try_exists()? {
            private_files::check_directory(&journal.target_directory)?;
            let marker = journal.target_directory.join("binding.json");
            if !marker.try_exists()? {
                ensure!(
                    std::fs::read_dir(&journal.target_directory)?
                        .next()
                        .is_none(),
                    "unbound target directory is not empty"
                );
                private_files::create(&marker, &encoded(&binding(journal))?)?;
            }
        } else {
            private_files::create_directory(&journal.target_directory)?;
            private_files::create(
                &journal.target_directory.join("binding.json"),
                &encoded(&binding(journal))?,
            )?;
        }
        check_binding(journal)
    }
    async fn target(
        &self,
        journal: &Journal,
        materialize: bool,
    ) -> Result<Arc<kasumi_engine::Database>> {
        let request = &journal.status.request;
        let outcome: GenerationRecord = decode(
            &self
                .store()
                .get(GENERATIONS, request.target_incarnation.as_bytes())?
                .context("target generation reservation missing")?,
        )?;
        ensure!(
            matches!(outcome, GenerationRecord::Reserved { operation_id } | GenerationRecord::Active { operation_id } if operation_id == request.operation_id),
            "target generation is permanently stopped or substituted"
        );
        check_binding(journal)?;
        check_database_file(journal)?;
        let path = journal.target_directory.join("node.redb");
        ensure!(
            materialize || path.is_file(),
            "materialized target database is missing"
        );
        let tenant = self
            .config
            .tenants
            .iter()
            .find(|tenant| tenant.tenant == request.tenant)
            .context("installed tenant missing")?;
        ensure!(
            journal.application_provider == tenant.keys.identity_descriptor()?
                && journal.custody_provider == tenant.custody_keys.identity_descriptor()?,
            "local target wrapping-key identity differs"
        );
        if materialize {
            ensure!(
                journal.source_provider == request.source_keys.identity_descriptor()?,
                "local source wrapping-key identity differs"
            );
        }
        let source = Arc::new(crate::runtime::file_secret);
        let application = tenant.keys.provider(source.clone())?;
        let custody = tenant.custody_keys.provider(source)?;
        let access = kasumi_store::StorageAccess::standalone(
            journal.installation_id,
            &request.tenant,
            request.target_incarnation,
        )?;
        let database_id = kasumi_store::node_store_ids::local_generation(
            journal.installation_id,
            request.operation_id,
            request.target_incarnation,
        )?;
        let node = if materialize && std::fs::symlink_metadata(&path)?.len() == 0 {
            // The constructor rechecks the exact journal-bound empty descriptor
            // while holding its file lock before the first envelope write.
            kasumi_store::NodeStore::initialize_owned_empty(
                &path,
                journal
                    .database_file
                    .as_ref()
                    .context("target inode binding missing")?,
                database_id,
                self.store().scratch_disk().clone(),
            )?
        } else {
            // A nonempty file must already have a complete exact envelope. A
            // partially published envelope is never reset or adopted on retry.
            kasumi_store::NodeStore::open_existing(
                &path,
                database_id,
                self.store().scratch_disk().clone(),
            )?
        };
        let stores = if materialize {
            kasumi_store::TenantStorageSet::open(
                node,
                request.tenant.clone(),
                application,
                custody,
                access,
            )
            .await?
        } else {
            kasumi_store::TenantStorageSet::open_existing(
                node,
                request.tenant.clone(),
                application,
                custody,
                access,
            )
            .await?
        };
        self.config.install_tenant_audit_archive(
            stores.application(),
            Some(self.observed_archives(journal)?),
        )?;
        let initialized = stores
            .application()
            .get("engine.bootstrap", b"manifest")?
            .is_some();
        ensure!(
            materialize || initialized,
            "materialized target bootstrap is missing"
        );
        let admission = self.audit.admission().clone();
        let database = if initialized {
            kasumi_engine::open_existing_local(
                stores.clone(),
                self.audit.clone(),
                request.target_incarnation,
            )
            .await?
        } else {
            let source_context = self
                .context(
                    &request.tenant,
                    &request.source_principal,
                    kasumi_types::CredentialResource::Database {
                        incarnation: Uuid::parse_str(&request.checkpoint.source_incarnation)?,
                    },
                    journal.status.phase_id,
                )
                .await?;
            let target_context = self
                .context(
                    &request.tenant,
                    &request.source_principal,
                    kasumi_types::CredentialResource::Database {
                        incarnation: request.target_incarnation,
                    },
                    journal.status.phase_id,
                )
                .await?;
            kasumi_engine::restore_local(
                &kasumi_engine::RestoreSource {
                    destination_alias: request.destination.clone(),
                    destination: self.config.backup_destinations[&request.destination].open()?,
                    keys: request
                        .source_keys
                        .provider(Arc::new(crate::runtime::file_secret))?,
                    timeout_ms: request.phase_timeout_ms,
                },
                stores.clone(),
                kasumi_engine::LocalRestoreRequest {
                    checkpoint: request.checkpoint.clone(),
                    target_incarnation: request.target_incarnation,
                    source_context,
                    target_context,
                    source_purpose: request.source_purpose.clone(),
                },
                admission.clone(),
                self.audit.clone(),
            )
            .await?
        };
        let validated = (|| {
            let generation = database.engine().generation()?;
            ensure!(
                generation.state.incarnation == request.target_incarnation.to_string()
                    && generation.state.restored_from.as_ref() == Some(&request.checkpoint),
                "target materialization differs from exact local recovery checkpoint"
            );
            if initialized {
                database.install_admission(admission)?;
            }
            for (alias, destination) in &self.config.backup_destinations {
                if !initialized && alias == &request.destination {
                    continue;
                }
                database.install_archive_destination(alias.clone(), destination.open()?)?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = validated {
            database.shutdown().await?;
            return Err(error);
        }
        Ok(database)
    }
    async fn step(&self, journal: &mut Journal) -> Result<()> {
        self.validate(journal)?;
        match journal.status.phase {
            LocalRecoveryPhase::Materialize => {
                self.prepare_database_file(journal)?;
                let target = self.target(journal, true).await?;
                target.shutdown().await?;
                drop(target);
                self.transition(journal, LocalRecoveryPhase::Complete)?;
            }
            LocalRecoveryPhase::Complete => {
                let target = self.target(journal, false).await?;
                let result = async {
                    let context = self
                        .context(
                            &journal.status.request.tenant,
                            &journal.status.request.source_principal,
                            kasumi_types::CredentialResource::Database {
                                incarnation: journal.status.request.target_incarnation,
                            },
                            journal.status.phase_id,
                        )
                        .await?;
                    target.complete_restore(context).await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                target.shutdown().await?;
                result?;
                self.transition(journal, LocalRecoveryPhase::Activate)?;
            }
            LocalRecoveryPhase::Activate => {
                let target = self.target(journal, false).await?;
                let ready = target.engine().generation().map(|generation| {
                    generation.state.pending_restore.is_none() && generation.state.suspended
                });
                target.shutdown().await?;
                drop(target);
                ensure!(
                    ready?,
                    "local target is not durably completed and suspended"
                );
                let request = &journal.status.request;
                let current = active_generation(&self.config, self.store(), &request.tenant)?;
                let configured = self
                    .config
                    .tenants
                    .iter()
                    .find(|tenant| tenant.tenant == request.tenant)
                    .context("installed tenant missing")?;
                let current = match current {
                    Some(active) => active.incarnation,
                    None => Uuid::parse_str(
                        configured
                            .incarnation
                            .as_deref()
                            .context("installed incarnation missing")?,
                    )?,
                };
                ensure!(
                    current == request.expected_active_incarnation,
                    "another local activation has already won"
                );
                let active = ActiveGeneration {
                    operation_id: request.operation_id,
                    incarnation: request.target_incarnation,
                    directory: journal.target_directory.clone(),
                    checkpoint: request.checkpoint.clone(),
                    application_provider: journal.application_provider.clone(),
                    custody_provider: journal.custody_provider.clone(),
                };
                journal.status.phase = LocalRecoveryPhase::Publish;
                journal.status.phase_id = Uuid::new_v4();
                journal.status.last_failure = None;
                self.store().write_batch(&[
                    WriteOp::put(
                        OPERATIONS,
                        request.operation_id.as_bytes(),
                        encoded(journal)?,
                    ),
                    phase_entry(journal)?,
                    WriteOp::put(ACTIVE, request.tenant.as_bytes(), encoded(&active)?),
                    WriteOp::put(
                        GENERATIONS,
                        request.target_incarnation.as_bytes(),
                        encoded(&GenerationRecord::Active {
                            operation_id: request.operation_id,
                        })?,
                    ),
                    WriteOp::put(
                        GENERATIONS,
                        request.expected_active_incarnation.as_bytes(),
                        encoded(&GenerationRecord::Stopped {
                            operation_id: request.operation_id,
                        })?,
                    ),
                ])?;
            }
            LocalRecoveryPhase::Publish => self.publish(journal).await?,
            LocalRecoveryPhase::Stopping => self.cleanup(journal).await?,
            LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped => {}
        }
        Ok(())
    }
    async fn cleanup(&self, journal: &mut Journal) -> Result<()> {
        ensure!(
            journal.status.phase == LocalRecoveryPhase::Stopping,
            "local cleanup requires permanent stop first"
        );
        let outcome: GenerationRecord = decode(
            &self
                .store()
                .get(
                    GENERATIONS,
                    journal.status.request.target_incarnation.as_bytes(),
                )?
                .context("target stop outcome missing")?,
        )?;
        ensure!(
            matches!(outcome, GenerationRecord::Stopped { operation_id } if operation_id == journal.status.request.operation_id),
            "target permanent stop differs"
        );
        if journal.target_directory.try_exists()? {
            private_files::check_directory(&journal.target_directory)?;
            let marker = journal.target_directory.join("binding.json");
            if marker.try_exists()? {
                check_binding(journal)?;
            }
            let mut entries = Vec::with_capacity(3);
            for entry in std::fs::read_dir(&journal.target_directory)? {
                ensure!(
                    entries.len() < 3,
                    "cleanup refuses unexpected target entries"
                );
                entries.push(entry?);
            }
            for entry in &entries {
                ensure!(
                    (entry.file_type()?.is_file()
                        && matches!(
                            entry.file_name().to_str(),
                            Some("binding.json" | "node.redb")
                        ))
                        || (entry.file_type()?.is_dir()
                            && entry.file_name() == "tenant-audit-archives"),
                    "cleanup refuses an unrelated or linked target entry"
                );
            }
            ensure!(
                marker.try_exists()? || entries.is_empty(),
                "nonempty target generation has lost its ownership binding"
            );
            let database = journal.target_directory.join("node.redb");
            let ownership = if database.try_exists()? {
                if journal.database_file.is_some() {
                    check_database_file(journal)?;
                } else {
                    private_files::read(&database, 0)?;
                }
                // This uses the same exclusive inode lock as redb. Existing
                // workers must drain before the owned directory entry is deleted.
                Some(private_files::ExclusiveLock::acquire(&database)?)
            } else {
                None
            };
            if !self.cleanup_archives(journal)? {
                return Ok(());
            }
            if database.try_exists()? {
                std::fs::remove_file(&database)?;
                private_files::sync_parent(&database)?;
            }
            drop(ownership);
            if marker.try_exists()? {
                std::fs::remove_file(&marker)?;
                private_files::sync_parent(&marker)?;
            }
            std::fs::remove_dir(&journal.target_directory)?;
            private_files::sync_parent(&journal.target_directory)?;
        }
        journal.status.cleanup_evidence = Some(
            kasumi_types::staged_digest(&(
                "kasumi.local-cleanup.v2",
                &binding(journal),
                &journal.target_directory,
                &journal.database_file,
                &journal.archive_directory,
            ))?
            .0,
        );
        journal.status.phase = LocalRecoveryPhase::Stopped;
        journal.status.last_failure = None;
        self.event(journal, kasumi_engine::SecurityOutcome::Succeeded)
            .await?;
        self.store().write_batch(&[
            WriteOp::put(
                OPERATIONS,
                journal.status.request.operation_id.as_bytes(),
                encoded(journal)?,
            ),
            WriteOp::delete(INSTALLATION, b"pending"),
        ])?;
        Ok(())
    }
}

impl Operator {
    fn initial_topology(&self) -> Result<kasumi_engine::control::ControlTopology> {
        use kasumi_engine::control::{ControlNode, ControlTopology, DeploymentMode, TenantRoute};
        let mut tenants = std::collections::BTreeMap::new();
        for tenant in &self.config.tenants {
            let incarnation = match active_generation(&self.config, self.store(), &tenant.tenant)? {
                Some(active) => active.incarnation.to_string(),
                None => tenant
                    .incarnation
                    .clone()
                    .context("installed incarnation missing")?,
            };
            tenants.insert(
                tenant.tenant.clone(),
                TenantRoute {
                    incarnation,
                    mode: DeploymentMode::Local,
                    voters: std::collections::BTreeSet::from([1]),
                },
            );
        }
        let topology = ControlTopology {
            nodes: std::collections::BTreeMap::from([(
                1,
                ControlNode {
                    endpoint: url::Url::parse(&self.config.mcp.protocol.public_url)?
                        .origin()
                        .ascii_serialization(),
                    failure_domain: "local".into(),
                    certificate_pins: std::collections::BTreeSet::from([hex::encode(
                        self.config.mcp.tls.load()?.certificate_pin(),
                    )]),
                },
            )]),
            tenants,
        };
        topology.validate()?;
        Ok(topology)
    }
    async fn publish(&self, journal: &mut Journal) -> Result<()> {
        let active = active_generation(&self.config, self.store(), &journal.status.request.tenant)?
            .context("local activation is not committed")?;
        ensure!(
            active.operation_id == journal.status.request.operation_id
                && active.incarnation == journal.status.request.target_incarnation,
            "another local activation has won"
        );
        let control = crate::standalone::operator_control(
            &self.config,
            self.node.clone(),
            self.audit.clone(),
        )
        .await?;
        let result = async {
            let administrator = crate::standalone::offline_context(&control)?;
            let context = self
                .context(
                    &administrator.tenant,
                    &administrator.principal,
                    kasumi_types::CredentialResource::Control {
                        incarnation: Uuid::parse_str(
                            &control.engine().generation()?.state.incarnation,
                        )?,
                    },
                    journal.status.phase_id,
                )
                .await?;
            let plane = kasumi_engine::control::ControlPlane::new(control.clone())?;
            plane.initialize(context.clone()).await?;
            if journal.publication.is_none() {
                let current = plane.topology(&context).await?;
                let (mut topology, expected) = match current {
                    Some(current) => (
                        current.topology,
                        kasumi_types::Precondition::Version(current.version),
                    ),
                    None => (self.initial_topology()?, kasumi_types::Precondition::Absent),
                };
                let route = topology
                    .tenants
                    .get_mut(&journal.status.request.tenant)
                    .context("local tenant route missing")?;
                ensure!(
                    route.incarnation
                        == journal
                            .status
                            .request
                            .expected_active_incarnation
                            .to_string()
                        || route.incarnation
                            == journal.status.request.target_incarnation.to_string(),
                    "Control route points at an unrelated generation"
                );
                route.incarnation = journal.status.request.target_incarnation.to_string();
                journal.publication = Some(Publication {
                    id: Uuid::new_v4(),
                    topology,
                    expected,
                });
                let publication = journal
                    .publication
                    .as_ref()
                    .context("publication missing")?;
                self.store().write_batch(&[
                    WriteOp::put(
                        OPERATIONS,
                        journal.status.request.operation_id.as_bytes(),
                        encoded(journal)?,
                    ),
                    WriteOp::put(PHASES, publication.id.as_bytes(), encoded(publication)?),
                ])?;
            }
            let publication = journal
                .publication
                .as_ref()
                .context("publication identity missing")?;
            plane
                .replace_topology(
                    context,
                    publication.topology.clone(),
                    publication.expected.clone(),
                    publication.id.to_string(),
                )
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        control.shutdown().await?;
        drop(control);
        result?;
        let target = self.target(journal, false).await?;
        let result = async {
            let request = &journal.status.request;
            let context = self
                .context(
                    &request.tenant,
                    &request.source_principal,
                    kasumi_types::CredentialResource::Database {
                        incarnation: request.target_incarnation,
                    },
                    journal.status.phase_id,
                )
                .await?;
            let state = target.engine().generation()?;
            ensure!(
                state.state.pending_restore.is_none(),
                "local target completion has not committed"
            );
            if state.state.suspended {
                target
                    .administer(context, kasumi_types::Operation::Suspend(false))
                    .await?;
            }
            self.publish_profile(journal)?;
            self.event(journal, kasumi_engine::SecurityOutcome::Succeeded)
                .await?;
            journal.status.phase = LocalRecoveryPhase::Finished;
            journal.status.last_failure = None;
            self.store().write_batch(&[
                WriteOp::put(
                    OPERATIONS,
                    journal.status.request.operation_id.as_bytes(),
                    encoded(journal)?,
                ),
                WriteOp::delete(INSTALLATION, b"pending"),
            ])?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        target.shutdown().await?;
        result
    }
    fn publish_profile(&self, journal: &mut Journal) -> Result<()> {
        let request = &journal.status.request;
        let root = crate::standalone::installation_root(&self.config)?;
        let profile_path = root
            .join("profiles")
            .join(format!("recovery-{}.json", request.operation_id));
        let resource = kasumi_types::CredentialResource::Database {
            incarnation: request.target_incarnation,
        };
        if profile_path.try_exists()? {
            let existing = crate::standalone::ClientProfile::load(&profile_path)?;
            ensure!(
                existing.family_id == journal.target_family
                    && existing.tenant == request.tenant
                    && existing.resource == resource,
                "recovery profile path is occupied by unrelated credentials"
            );
        }
        let mut token = self.credentials.create(
            kasumi_types::CreateCredential {
                family_id: journal.target_family,
                principal: request.source_principal.clone(),
                tenant: request.tenant.clone(),
                resource: resource.clone(),
                scopes: std::collections::BTreeSet::from([
                    kasumi_types::Action::Read,
                    kasumi_types::Action::Write,
                    kasumi_types::Action::Admin,
                    kasumi_types::Action::Audit,
                ]),
                lifetime_seconds: 3600,
            },
            "offline-recovery-profile",
        )?;
        let now = kasumi_clock::EpochClock::system()?.now_ms()?;
        if token.expires_at_ms <= now.saturating_add(300_000) {
            if journal.profile_renewal.is_none() {
                journal.profile_renewal = Some(Uuid::new_v4());
                persist(self.store(), journal)?;
            }
            token = self.credentials.renew(
                &kasumi_types::RenewCredential {
                    family_id: journal.target_family,
                    renewal_id: journal.profile_renewal.context("profile renewal missing")?,
                },
                "offline-recovery-profile",
            )?;
            if token.expires_at_ms <= now.saturating_add(300_000) {
                journal.profile_renewal = Some(Uuid::new_v4());
                persist(self.store(), journal)?;
                token = self.credentials.renew(
                    &kasumi_types::RenewCredential {
                        family_id: journal.target_family,
                        renewal_id: journal.profile_renewal.context("profile renewal missing")?,
                    },
                    "offline-recovery-profile",
                )?;
            }
        }
        let issuance = journal.profile_renewal.unwrap_or(journal.target_family);
        let bearer_file = root
            .join("profiles")
            .join(format!("recovery-{}.token", issuance));
        if bearer_file.try_exists()? {
            ensure!(
                private_files::read(&bearer_file, 32 << 10)?.as_slice() == token.token.as_bytes(),
                "recovery token path is occupied"
            );
        } else {
            private_files::create(&bearer_file, token.token.as_bytes())?;
        }
        let profile = crate::standalone::ClientProfile {
            format: 1,
            family_id: journal.target_family,
            tenant: journal.status.request.tenant.clone(),
            resource,
            native_endpoint: format!("https://localhost:{}", self.config.native.listen.port()),
            admin_endpoint: format!("https://localhost:{}", self.config.admin.listen.port()),
            mcp_endpoint: self.config.mcp.protocol.public_url.clone(),
            identity: crate::runtime::TlsFiles {
                certificate: root.join("profiles/client.pem"),
                private_key: root.join("profiles/client-key.pem"),
            },
            server_ca: root.join("tls/ca.pem"),
            native_certificate_pin: hex::encode(self.config.native.tls.load()?.certificate_pin()),
            admin_certificate_pin: hex::encode(self.config.admin.tls.load()?.certificate_pin()),
            bearer_file,
        };
        private_files::replace(&profile_path, &encoded(&profile)?)?;
        journal.status.client_profile = Some(profile_path);
        Ok(())
    }
}

#[cfg(test)]
#[path = "local_recovery_tests.rs"]
mod tests;
