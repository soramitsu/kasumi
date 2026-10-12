//! Explicit stopped-installation renewal of existing credential families.
//! The private manifest is durable operator intent; its renewal IDs are reused
//! after interruption. No network authentication or retained identity changes.
use super::*;
use kasumi_types::{CredentialStatus, RenewCredential};

const MAX_MANIFEST: usize = 128 << 10;
const MAX_PROFILES: usize = 128;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    operation_id: Uuid,
    profiles: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    profile: PathBuf,
    profile_sha256: String,
    renewal_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CredentialRecoveryReport {
    operation_id: Uuid,
    profiles: Vec<RecoveredProfile>,
}

#[derive(Debug, Serialize)]
struct RecoveredProfile {
    profile: PathBuf,
    family_id: Uuid,
    renewal_id: Uuid,
    expires_at_ms: u64,
}

struct Prepared {
    entry: Entry,
    profile: ClientProfile,
    journal: PathBuf,
    archive: PathBuf,
    previous_journal: Option<zeroize::Zeroizing<Vec<u8>>>,
}

fn optional_private(path: &Path, maximum: usize) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => private_files::read(path, maximum).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn manifest(path: &Path) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(&private_files::read(path, MAX_MANIFEST)?)?;
    ensure!(
        manifest.format == 1 && !manifest.operation_id.is_nil(),
        "invalid credential recovery manifest identity"
    );
    ensure!(
        !manifest.profiles.is_empty() && manifest.profiles.len() <= MAX_PROFILES,
        "credential recovery profile count exceeds bounds"
    );
    let mut paths = BTreeSet::new();
    for entry in &manifest.profiles {
        ensure!(
            entry.profile.is_absolute() && std::fs::canonicalize(&entry.profile)? == entry.profile,
            "recovery profile path must be canonical and absolute"
        );
        ensure!(
            paths.insert(entry.profile.clone()),
            "duplicate recovery profile path"
        );
        ensure!(
            !entry.renewal_id.is_nil(),
            "recovery renewal ID must not be nil"
        );
        ensure!(
            entry.profile_sha256.len() == 64
                && entry
                    .profile_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid recovery profile SHA-256"
        );
    }
    Ok(manifest)
}

fn validate_family(profile: &ClientProfile, status: &CredentialStatus) -> Result<()> {
    let specification = &status.specification;
    specification.validate()?;
    ensure!(
        status.revoked_at_ms.is_none(),
        "credential recovery refuses a revoked family"
    );
    ensure!(
        specification.family_id == profile.family_id
            && specification.principal == profile.principal
            && specification.tenant == profile.tenant
            && specification.resource == profile.resource,
        "credential recovery profile differs from registered family specification"
    );
    Ok(())
}

fn validate_policy(specification: &CreateCredential, policy: &Policy) -> Result<()> {
    // Collection restrictions remain enforced by every request. Recovery only
    // preserves registered scopes that still have a grant in the current policy.
    ensure!(
        specification.scopes.iter().all(|action| policy
            .grants
            .iter()
            .any(|grant| grant.principal == specification.principal
                && grant.actions.contains(action))),
        "credential recovery scopes are no longer granted by current policy"
    );
    Ok(())
}

/// Renew exact registered families under the exclusive stopped installation
/// owner. The caller must persist a private manifest before dispatch and retain
/// it unchanged for retries. Expired recovery issuances require a new intent.
pub async fn recover_existing_credentials(
    configuration: &Path,
    manifest_path: &Path,
) -> Result<CredentialRecoveryReport> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    recover_with_storage(configuration, manifest_path, storage).await
}

async fn recover_with_storage(
    configuration: &Path,
    manifest_path: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<CredentialRecoveryReport> {
    let configuration = configuration.to_owned();
    let manifest_path = manifest_path.to_owned();
    operator::run(async move {
        let intent = manifest(&manifest_path)?;
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        let result = recover_owned(&config, &configuration, &manifest_path, intent, &owner).await;
        owner.finish(result).await
    })
    .await
}

async fn recover_owned(
    config: &RuntimeConfig,
    configuration: &Path,
    manifest_path: &Path,
    intent: Manifest,
    owner: &OperatorState,
) -> Result<CredentialRecoveryReport> {
    crate::local_recovery::require_runtime_ready(owner.audit.store())?;
    let (tenants, nodes) = operator_tenants(config, owner.audit.store(), owner).await?;
    let mut targets = BTreeMap::new();
    let control = owner.control().await?;
    let generation = control.engine().generation()?;
    targets.insert(
        crate::runtime::CONTROL_TENANT.to_owned(),
        (
            CredentialResource::Control {
                incarnation: Uuid::parse_str(generation.incarnation())?,
            },
            generation.policy().clone(),
        ),
    );
    let wanted: BTreeSet<_> = intent
        .profiles
        .iter()
        .map(|entry| {
            let (profile, hash) = ClientProfile::load_with_sha256(&entry.profile)?;
            ensure!(
                hash == entry.profile_sha256,
                "credential recovery profile SHA-256 differs"
            );
            Ok(profile.tenant)
        })
        .collect::<Result<_>>()?;
    for tenant in tenants
        .iter()
        .filter(|tenant| wanted.contains(&tenant.tenant))
    {
        let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
            anyhow::bail!("credential recovery target is not standalone");
        };
        let incarnation = Uuid::parse_str(
            tenant
                .incarnation
                .as_deref()
                .context("tenant incarnation missing")?,
        )?;
        let source = Arc::new(crate::runtime::file_secret);
        let stores = kasumi_store::TenantStorageSet::open_existing(
            nodes
                .get(&tenant.tenant)
                .context("credential recovery target node missing")?
                .clone(),
            tenant.tenant.clone(),
            tenant.keys.provider(source.clone())?,
            tenant.custody_keys.provider(source)?,
            StorageAccess::standalone(installation_id, &tenant.tenant, incarnation)?,
        )
        .await?;
        owner.retain_stores(&stores);
        config.install_tenant_audit_archive(stores.application(), None)?;
        let database = owner
            .snapshot(
                &tenant.tenant,
                kasumi_engine::open_existing_local(stores, owner.audit.clone(), incarnation),
            )
            .await?;
        owner.retain_database(database.clone());
        let generation = database.engine().generation()?;
        ensure!(
            generation.tenant() == tenant.tenant
                && generation.incarnation() == incarnation.to_string(),
            "credential recovery target generation differs"
        );
        targets.insert(
            tenant.tenant.clone(),
            (
                CredentialResource::Database { incarnation },
                generation.policy().clone(),
            ),
        );
    }

    let mut prepared = Vec::new();
    let mut locks = Vec::new();
    let mut families = BTreeMap::new();
    let mut bearer_paths = BTreeSet::new();
    let mut protected = BTreeSet::from([configuration.to_owned(), manifest_path.to_owned()]);
    for entry in intent.profiles {
        let (profile, hash) = ClientProfile::load_with_sha256(&entry.profile)?;
        ensure!(
            hash == entry.profile_sha256,
            "credential recovery profile SHA-256 differs"
        );
        let status = owner.credentials.status(profile.family_id)?;
        validate_family(&profile, &status)?;
        let (resource, policy) = targets
            .get(&profile.tenant)
            .context("credential recovery target is not installed")?;
        ensure!(
            resource == &profile.resource,
            "credential recovery target incarnation or resource differs"
        );
        validate_policy(&status.specification, policy)?;
        ensure!(
            entry.renewal_id != profile.family_id,
            "recovery renewal ID must differ from family"
        );
        if let Some(previous) = families.insert(profile.family_id, entry.renewal_id) {
            ensure!(
                previous == entry.renewal_id,
                "one family requires one recovery renewal ID"
            );
        }
        ensure!(
            std::fs::canonicalize(&profile.bearer_file)? == profile.bearer_file
                && bearer_paths.insert(profile.bearer_file.clone()),
            "duplicate or noncanonical recovery bearer path"
        );
        protected.extend([
            entry.profile.clone(),
            profile.identity.certificate.clone(),
            profile.identity.private_key.clone(),
            profile.server_ca.clone(),
        ]);
        locks.push(private_files::ExclusiveLock::acquire(
            &profile.bearer_file.with_extension("watch.lock"),
        )?);
        // Validate ownership and type without authenticating an expired bearer.
        private_files::read(&profile.bearer_file, 64 << 10)?;
        let journal = profile.bearer_file.with_extension("renewal.json");
        let archive = profile
            .bearer_file
            .with_extension(format!("renewal.before-recovery-{}.json", entry.renewal_id));
        let previous_journal = optional_private(&journal, 4096)?;
        if let Some(bytes) = &previous_journal {
            let request: RenewCredential = serde_json::from_slice(bytes)?;
            ensure!(
                request.family_id == profile.family_id
                    && !request.renewal_id.is_nil()
                    && request.renewal_id != profile.family_id,
                "pending renewal journal differs from recovery family"
            );
            if let Some(archived) = optional_private(&archive, 4096)? {
                let prior: RenewCredential = serde_json::from_slice(&archived)?;
                ensure!(
                    prior.family_id == profile.family_id,
                    "recovery journal archive belongs to another family"
                );
                ensure!(
                    request.renewal_id == entry.renewal_id
                        || archived.as_slice() == bytes.as_slice(),
                    "recovery journal archive differs from pending original"
                );
            }
        }
        prepared.push(Prepared {
            entry,
            profile,
            journal,
            archive,
            previous_journal,
        });
    }
    ensure!(
        bearer_paths.is_disjoint(&protected),
        "recovery bearer overlaps an immutable input"
    );
    // Every registered family, current generation, policy, file and watch lock
    // is validated before any issuance or token replacement begins.
    let operation = intent.operation_id.to_string();
    owner
        .audit
        .record(operator_event(
            &operation,
            kasumi_engine::SecurityOutcome::Started,
        ))
        .await?;
    let clock = kasumi_clock::EpochClock::system()?;
    let mut issued = BTreeMap::new();
    for (family_id, renewal_id) in families {
        let credential = owner.credentials.renew(
            &RenewCredential {
                family_id,
                renewal_id,
            },
            "offline-credential-recovery",
        )?;
        ensure!(
            credential.family_id == family_id && credential.expires_at_ms > clock.now_ms()?,
            "recovery issuance has expired; persist a new explicit recovery manifest"
        );
        issued.insert(family_id, credential);
    }
    let mut report = CredentialRecoveryReport {
        operation_id: intent.operation_id,
        profiles: Vec::new(),
    };
    for prepared in prepared {
        let (_, hash) = ClientProfile::load_with_sha256(&prepared.entry.profile)?;
        ensure!(
            hash == prepared.entry.profile_sha256,
            "credential recovery profile changed before publication"
        );
        let credential = &issued[&prepared.profile.family_id];
        ensure!(
            credential.expires_at_ms > clock.now_ms()?,
            "recovery issuance expired before publication; persist a new explicit recovery manifest"
        );
        stage_journal(&prepared)?;
        private_files::replace(&prepared.profile.bearer_file, credential.token.as_bytes())?;
        retire_journal(&prepared)?;
        report.profiles.push(RecoveredProfile {
            profile: prepared.entry.profile,
            family_id: credential.family_id,
            renewal_id: prepared.entry.renewal_id,
            expires_at_ms: credential.expires_at_ms,
        });
    }
    owner
        .audit
        .record(operator_event(
            &operation,
            kasumi_engine::SecurityOutcome::Succeeded,
        ))
        .await?;
    drop(locks);
    Ok(report)
}

fn recovery_request(prepared: &Prepared) -> RenewCredential {
    RenewCredential {
        family_id: prepared.profile.family_id,
        renewal_id: prepared.entry.renewal_id,
    }
}

fn stage_journal(prepared: &Prepared) -> Result<()> {
    let recovery = recovery_request(prepared);
    if let Some(original) = &prepared.previous_journal {
        let current = private_files::read(&prepared.journal, 4096)?;
        ensure!(
            current.as_slice() == original.as_slice(),
            "pending renewal journal changed during recovery"
        );
        let previous: RenewCredential = serde_json::from_slice(original)?;
        if previous.renewal_id == recovery.renewal_id {
            return Ok(());
        }
        match optional_private(&prepared.archive, 4096)? {
            Some(archived) => ensure!(
                archived.as_slice() == original.as_slice(),
                "recovery journal archive changed"
            ),
            None => private_files::publish(&prepared.archive, original)?,
        }
        private_files::replace(&prepared.journal, &serde_json::to_vec(&recovery)?)?;
    } else {
        private_files::create(&prepared.journal, &serde_json::to_vec(&recovery)?)?;
    }
    Ok(())
}

fn retire_journal(prepared: &Prepared) -> Result<()> {
    let current: RenewCredential =
        serde_json::from_slice(&private_files::read(&prepared.journal, 4096)?)?;
    let recovery = recovery_request(prepared);
    ensure!(
        current.family_id == recovery.family_id && current.renewal_id == recovery.renewal_id,
        "pending recovery journal changed before retirement"
    );
    // The old journal is already archived, the active journal names only the
    // durable recovery issuance, and the fresh bearer is durably published.
    std::fs::remove_file(&prepared.journal)?;
    private_files::sync_parent(&prepared.journal)
}

#[cfg(test)]
#[path = "standalone_credential_recovery_tests.rs"]
mod tests;
