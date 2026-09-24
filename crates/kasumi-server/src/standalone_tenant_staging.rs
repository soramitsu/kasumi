//! Explicit stopped-installation staging. Key files and the configuration are
//! owned by a durable operation; no tenant catalog or credential is created here.
use super::*;
use sha2::{Digest, Sha256};

const NS: &str = "standalone.tenant-staging";
const MAX_RECORD: usize = 8 << 20;
const MAX_KEYRING: usize = 1 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageTenantRequest {
    pub operation_id: Uuid,
    pub tenant: String,
    pub incarnation: Uuid,
    pub initial_policy: Policy,
    pub initial_limits: kasumi_types::Limits,
}
impl StageTenantRequest {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.operation_id.is_nil() && !self.incarnation.is_nil(),
            "nil staging identity"
        );
        kasumi_types::validate_name(&self.tenant)?;
        ensure!(
            !self.tenant.starts_with("kasumi.") && !self.tenant.starts_with("__kasumi_"),
            "reserved tenant cannot be staged"
        );
        kasumi_engine::TenantEngine::new(
            self.tenant.clone(),
            self.incarnation.to_string(),
            self.initial_policy.clone(),
            self.initial_limits.clone(),
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Dispatched,
    FilesReady {
        application_sha256: String,
        custody_sha256: String,
    },
    Completed {
        application_sha256: String,
        custody_sha256: String,
    },
    Failed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u32,
    database_id: Uuid,
    installation_id: Uuid,
    configuration: PathBuf,
    request: StageTenantRequest,
    before_sha256: String,
    after_json: String,
    directory: PathBuf,
    outcome: Outcome,
}
#[derive(Debug, Serialize)]
pub struct StagedTenant {
    pub operation_id: Uuid,
    pub tenant: String,
    pub incarnation: Uuid,
    pub configuration: PathBuf,
    pub state: &'static str,
}
impl Record {
    fn status(&self) -> StagedTenant {
        StagedTenant {
            operation_id: self.request.operation_id,
            tenant: self.request.tenant.clone(),
            incarnation: self.request.incarnation,
            configuration: self.configuration.clone(),
            state: match self.outcome {
                Outcome::Dispatched => "incomplete",
                Outcome::FilesReady { .. } => "files_ready",
                Outcome::Completed { .. } => "completed",
                Outcome::Failed => "failed",
            },
        }
    }
    fn validate(&self, owner: &OperatorState, configuration: &Path) -> Result<()> {
        self.request.validate()?;
        ensure!(
            self.installation_id == installation(owner)?,
            "staged installation identity differs"
        );
        ensure!(
            self.format == 1
                && self.database_id == owner.config.database_id
                && self.configuration == configuration
                && self.directory
                    == installation_root(&owner.config)?
                        .join("operator")
                        .join(format!("tenant-stage-{}", self.request.operation_id)),
            "staging record identity differs"
        );
        kasumi_types::validate_sha256(&self.before_sha256)?;
        if let Outcome::FilesReady {
            application_sha256,
            custody_sha256,
        }
        | Outcome::Completed {
            application_sha256,
            custody_sha256,
        } = &self.outcome
        {
            kasumi_types::validate_sha256(application_sha256)?;
            kasumi_types::validate_sha256(custody_sha256)?;
        }
        let after: RuntimeConfig = serde_json::from_str(&self.after_json)?;
        after.validate()?;
        ensure!(
            after.database_id == self.database_id
                && after.database_path == owner.config.database_path,
            "staged configuration changes physical installation"
        );
        let tenant = after
            .tenants
            .iter()
            .find(|entry| entry.tenant == self.request.tenant)
            .context("staged configuration lost tenant")?;
        ensure!(
            tenant.incarnation.as_deref() == Some(self.request.incarnation.to_string().as_str())
                && matches!(tenant.serving, TenantServingConfig::Standalone { installation_id } if installation_id == self.installation_id),
            "staged tenant identity differs"
        );
        ensure!(
            serde_json::to_vec(&tenant.initial_policy)?
                == serde_json::to_vec(&self.request.initial_policy)?
                && serde_json::to_vec(&tenant.initial_limits)?
                    == serde_json::to_vec(&self.request.initial_limits)?,
            "staged policy/limits differ"
        );
        ensure!(
            matches!(&tenant.keys, KeyProviderSettings::File { path } if path == &self.directory.join("application.json"))
                && matches!(&tenant.custody_keys, KeyProviderSettings::File { path } if path == &self.directory.join("custody.json")),
            "staged key paths differ"
        );
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn key(id: Uuid) -> String {
    id.to_string()
}
fn load(owner: &OperatorState, operation: Uuid) -> Result<Option<Record>> {
    owner
        .audit
        .store()
        .get_bounded(NS, key(operation).as_bytes(), MAX_RECORD)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
}
fn save(owner: &OperatorState, record: &Record) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() <= MAX_RECORD,
        "tenant staging record exceeds budget"
    );
    owner
        .audit
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            NS,
            key(record.request.operation_id).as_bytes(),
            bytes,
        )])
}
fn installation(owner: &OperatorState) -> Result<Uuid> {
    let identity = owner
        .installed_owner
        .identity_for(owner.node.persistent_disk())?;
    let installed: Installation = serde_json::from_slice(&private_files::read(
        &owner
            .config
            .database_path
            .parent()
            .context("database parent missing")?
            .join("installation.json"),
        16 << 10,
    )?)?;
    ensure!(
        installed.format == 4
            && installed.database_id == owner.config.database_id
            && installed.installation_id == identity.installation_id
            && installed.origin_node_id == identity.node_id,
        "installed staging scope differs"
    );
    Ok(identity.installation_id)
}
fn verify_files(record: &Record, application: &str, custody: &str) -> Result<()> {
    private_files::check_directory(&record.directory)?;
    let entries = std::fs::read_dir(&record.directory)?
        .take(3)
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        entries
            == BTreeSet::from([
                std::ffi::OsString::from("application.json"),
                std::ffi::OsString::from("custody.json")
            ]),
        "staging directory contains unrelated material"
    );
    for (name, expected) in [("application.json", application), ("custody.json", custody)] {
        kasumi_types::validate_sha256(expected)?;
        let path = record.directory.join(name);
        ensure!(
            digest(&private_files::read(&path, MAX_KEYRING)?) == expected,
            "staged keyring differs from its durable receipt"
        );
        FileKeyProvider::open(path)?;
    }
    Ok(())
}

pub async fn stage_tenant(
    configuration: &Path,
    request: StageTenantRequest,
) -> Result<StagedTenant> {
    request.validate()?;
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    stage_tenant_with_storage(configuration, request, storage).await
}

pub(crate) async fn stage_tenant_with_storage(
    configuration: &Path,
    request: StageTenantRequest,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<StagedTenant> {
    request.validate()?;
    let configuration = configuration.to_owned();
    let observed = kasumi_clock::EpochClock::system()?.observe()?;
    let deadline = observed.until(
        observed
            .utc_ms()
            .checked_add(60_000)
            .context("staging deadline overflow")?,
    )?;
    operator::run(async move {
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        let request_id = request.operation_id.to_string();
        let outcome = stage_owned(&owner, &configuration, request, &deadline).await;
        if outcome.is_err() {
            let _ = owner
                .audit
                .record(operator_event(
                    &request_id,
                    kasumi_engine::SecurityOutcome::Failed,
                ))
                .await;
        }
        owner.finish(outcome).await
    })
    .await
}
pub async fn tenant_stage_status(configuration: &Path, operation: Uuid) -> Result<StagedTenant> {
    ensure!(!operation.is_nil(), "nil staging operation");
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    tenant_stage_status_with_storage(configuration, operation, storage).await
}

pub(crate) async fn tenant_stage_status_with_storage(
    configuration: &Path,
    operation: Uuid,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<StagedTenant> {
    ensure!(!operation.is_nil(), "nil staging operation");
    let configuration = configuration.to_owned();
    operator::run(async move {
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        let outcome = (|| {
            let _reservation = owner
                .audit
                .admission()
                .reserve(MAX_RECORD as u64 * 3, None)?;
            let record = load(&owner, operation)?.context("staging operation is absent")?;
            record.validate(&owner, &configuration)?;
            Ok(record.status())
        })();
        owner.finish(outcome).await
    })
    .await
}
async fn stage_owned(
    owner: &OperatorState,
    configuration: &Path,
    request: StageTenantRequest,
    deadline: &kasumi_clock::ElapsedDeadline,
) -> Result<StagedTenant> {
    deadline.check()?;
    let _reservation = owner
        .audit
        .admission()
        .reserve((MAX_RECORD as u64) * 4 + (MAX_KEYRING as u64) * 2, None)?;
    ensure!(
        configuration == installation_root(&owner.config)?.join("kasumi.json"),
        "staging requires the installation's canonical configuration path"
    );
    crate::node_enrollment::require_complete(
        owner.audit.store(),
        owner.config.database_id,
        crate::node_enrollment::Kind::Data,
    )?;
    let current = private_files::read(configuration, 2 << 20)?;
    let original = load(owner, request.operation_id)?;
    let mut record = match original {
        Some(record) => {
            record.validate(owner, configuration)?;
            ensure!(
                serde_json::to_vec(&record.request)? == serde_json::to_vec(&request)?,
                "staging operation has different permanent inputs"
            );
            match &record.outcome {
                Outcome::Completed { .. } => return Ok(record.status()),
                Outcome::Failed => anyhow::bail!(
                    "staging operation permanently failed; retain its private namespace and use a new operation identity"
                ),
                Outcome::Dispatched => {
                    // The original file-creation attempt is never reconstructed.
                    let mut failed = record;
                    failed.outcome = Outcome::Failed;
                    save(owner, &failed)?;
                    anyhow::bail!(
                        "interrupted key creation has no complete ownership receipt; original attempt is permanently failed"
                    )
                }
                Outcome::FilesReady { .. } => record,
            }
        }
        None => {
            ensure!(
                !owner
                    .config
                    .tenants
                    .iter()
                    .any(|entry| entry.tenant == request.tenant),
                "tenant is already configured"
            );
            ensure!(
                crate::node_enrollment::tenant_record(owner.audit.store(), &request.tenant)?
                    .is_none(),
                "tenant already has permanent catalog enrollment"
            );
            let installation_id = installation(owner)?;
            let directory = installation_root(&owner.config)?
                .join("operator")
                .join(format!("tenant-stage-{}", request.operation_id));
            let mut after = owner.config.clone();
            after.tenants.push(crate::runtime::TenantConfig {
                tenant: request.tenant.clone(),
                serving: TenantServingConfig::Standalone { installation_id },
                keys: KeyProviderSettings::File {
                    path: directory.join("application.json"),
                },
                custody_keys: KeyProviderSettings::File {
                    path: directory.join("custody.json"),
                },
                initial_policy: request.initial_policy.clone(),
                initial_limits: request.initial_limits.clone(),
                incarnation: Some(request.incarnation.to_string()),
            });
            after.validate()?;
            let after_json = serde_json::to_string_pretty(&after)?;
            ensure!(
                after_json.len() <= 2 << 20,
                "staged configuration exceeds budget"
            );
            let mut record = Record {
                format: 1,
                database_id: owner.config.database_id,
                installation_id,
                configuration: configuration.to_owned(),
                request,
                before_sha256: digest(&current),
                after_json,
                directory,
                outcome: Outcome::Dispatched,
            };
            owner
                .audit
                .record(operator_event(
                    &record.request.operation_id.to_string(),
                    kasumi_engine::SecurityOutcome::Started,
                ))
                .await?;
            deadline.check()?;
            save(owner, &record)?;
            let created = (|| {
                deadline.check()?;
                private_files::create_directory(&record.directory)?;
                FileKeyProvider::initialize(
                    &record.directory.join("application.json"),
                    &format!("{}-application", record.request.operation_id),
                )?;
                FileKeyProvider::initialize(
                    &record.directory.join("custody.json"),
                    &format!("{}-custody", record.request.operation_id),
                )?;
                let application_sha256 = digest(&private_files::read(
                    &record.directory.join("application.json"),
                    MAX_KEYRING,
                )?);
                let custody_sha256 = digest(&private_files::read(
                    &record.directory.join("custody.json"),
                    MAX_KEYRING,
                )?);
                verify_files(&record, &application_sha256, &custody_sha256)?;
                record.outcome = Outcome::FilesReady {
                    application_sha256,
                    custody_sha256,
                };
                save(owner, &record)
            })();
            if let Err(error) = created {
                // Uncertain receipt writes must be resolved before assigning an
                // outcome. No failed retry creates or adopts another keyring.
                if let Some(observed) = load(owner, record.request.operation_id)?
                    && matches!(observed.outcome, Outcome::Dispatched)
                {
                    record.outcome = Outcome::Failed;
                    save(owner, &record)?;
                }
                return Err(error);
            }
            record
        }
    };
    let Outcome::FilesReady {
        application_sha256,
        custody_sha256,
    } = &record.outcome
    else {
        unreachable!("only recorded files advance publication")
    };
    #[cfg(test)]
    tests::checkpoint(owner.config.database_id, "files-ready").await?;
    verify_files(&record, application_sha256, custody_sha256)?;
    let current = private_files::read(configuration, 2 << 20)?;
    if current.as_slice() != record.after_json.as_bytes() {
        ensure!(
            digest(&current) == record.before_sha256,
            "configuration changed after staging dispatch"
        );
        deadline.check()?;
        private_files::replace(configuration, record.after_json.as_bytes())?;
    }
    #[cfg(test)]
    tests::checkpoint(owner.config.database_id, "configuration-published").await?;
    // Exact configuration publication resolves an uncertain earlier replace.
    // Once committed, finish its permanent outcome even if response time expires.
    record.outcome = Outcome::Completed {
        application_sha256: application_sha256.clone(),
        custody_sha256: custody_sha256.clone(),
    };
    save(owner, &record)?;
    owner
        .audit
        .record(operator_event(
            &record.request.operation_id.to_string(),
            kasumi_engine::SecurityOutcome::Succeeded,
        ))
        .await?;
    Ok(record.status())
}

#[cfg(test)]
#[path = "standalone_tenant_staging_tests.rs"]
mod tests;
