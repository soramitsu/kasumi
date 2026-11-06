//! Explicit stopped-installation migration of an installation initialized
//! before the generated credential was split. There, `profiles/default.json`
//! is the tenant administrator with every scope, and every profile shares one
//! client certificate. Afterwards the installation has a new installation's
//! layout: `default.json` is the application, which reads and writes;
//! `operator.json` administers and audits the tenant and reads for schema
//! assertions; and the Control profile keeps its credential. Each has its own
//! client certificate, and the replaced family is revoked.
//!
//! A journal written before anything it names is created lets a rerun after
//! any interruption finish the same split with the same families.
use super::*;
use kasumi_types::{IssuedCredential, Operation, RenewCredential};

const MAX_JOURNAL: usize = 16 << 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    tenant: String,
    resource: CredentialResource,
    legacy_family: Uuid,
    application_family: Uuid,
    operator_family: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CredentialSplitReport {
    /// False when `profiles/default.json` already was the application's.
    pub split: bool,
    pub application_profile: PathBuf,
    pub operator_profile: PathBuf,
    pub control_profile: PathBuf,
    /// The tenant administrator family `default.json` named, now revoked.
    pub revoked_family: Option<Uuid>,
}

pub async fn split_credentials(configuration: &Path) -> Result<CredentialSplitReport> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    split_credentials_with_storage(configuration, storage).await
}

pub(crate) async fn split_credentials_with_storage(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<CredentialSplitReport> {
    let configuration = configuration.to_owned();
    operator::run(async move {
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        let result = split(&config, &owner).await;
        owner.finish(result).await
    })
    .await
}

async fn split(config: &RuntimeConfig, owner: &OperatorState) -> Result<CredentialSplitReport> {
    crate::local_recovery::require_runtime_ready(owner.audit.store())?;
    let root = installation_root(config)?;
    let profiles = root.join("profiles");
    let journal_path = profiles.join("credential-split.json");
    let report = |split, revoked_family| CredentialSplitReport {
        split,
        application_profile: profiles.join("default.json"),
        operator_profile: profiles.join("operator.json"),
        control_profile: profiles.join("control.json"),
        revoked_family,
    };
    let current = ClientProfile::load(&profiles.join("default.json"))?;
    // A running watcher would renew the replaced family with the new bearer.
    let _watcher =
        private_files::ExclusiveLock::acquire(&current.bearer_file.with_extension("watch.lock"))
            .context("stop the credential watcher of profiles/default.json first")?;
    let journal = if journal_path.try_exists()? {
        let journal: Journal =
            serde_json::from_slice(&private_files::read(&journal_path, MAX_JOURNAL)?)?;
        ensure!(
            current.tenant == journal.tenant
                && current.resource == journal.resource
                && [journal.legacy_family, journal.application_family].contains(&current.family_id),
            "the credential split journal belongs to another profile"
        );
        journal
    } else {
        if current.principal == APPLICATION_PRINCIPAL {
            return Ok(report(false, None));
        }
        let legacy = owner.credentials.status(current.family_id)?.specification;
        ensure!(
            current.principal == ADMINISTRATOR_PRINCIPAL
                && matches!(current.resource, CredentialResource::Database { .. })
                && legacy.principal == current.principal
                && legacy.tenant == current.tenant
                && legacy.resource == current.resource
                && legacy.scopes == all_actions(),
            "profiles/default.json is not a generated tenant administrator credential holding every scope"
        );
        let journal = Journal {
            tenant: current.tenant.clone(),
            resource: current.resource.clone(),
            legacy_family: current.family_id,
            application_family: Uuid::new_v4(),
            operator_family: Uuid::new_v4(),
        };
        private_files::create(&journal_path, &serde_json::to_vec_pretty(&journal)?)?;
        journal
    };
    let operation = Uuid::new_v4().to_string();
    owner
        .audit
        .record(operator_event(
            &operation,
            kasumi_engine::SecurityOutcome::Started,
        ))
        .await?;
    let result = apply(config, owner, &profiles, &journal, &current).await;
    let recorded = owner
        .audit
        .record(operator_event(
            &operation,
            if result.is_ok() {
                kasumi_engine::SecurityOutcome::Succeeded
            } else {
                kasumi_engine::SecurityOutcome::Failed
            },
        ))
        .await;
    result?;
    recorded?;
    std::fs::remove_file(&journal_path)?;
    private_files::sync_parent(&journal_path)?;
    Ok(report(true, Some(journal.legacy_family)))
}

/// Every step is idempotent, so a rerun repeats the ones already done.
async fn apply(
    config: &RuntimeConfig,
    owner: &OperatorState,
    profiles: &Path,
    journal: &Journal,
    current: &ClientProfile,
) -> Result<()> {
    let root = installation_root(config)?;
    let identities = client_identities(config, root, profiles)?;
    restrict_tenant_policy(config, owner, journal).await?;
    let application = live_credential(
        &owner.credentials,
        CreateCredential {
            family_id: journal.application_family,
            principal: APPLICATION_PRINCIPAL.into(),
            tenant: journal.tenant.clone(),
            resource: journal.resource.clone(),
            scopes: application_actions(),
            lifetime_seconds: 3600,
        },
    )?;
    let operator = live_credential(
        &owner.credentials,
        CreateCredential {
            family_id: journal.operator_family,
            principal: ADMINISTRATOR_PRINCIPAL.into(),
            tenant: journal.tenant.clone(),
            resource: journal.resource.clone(),
            scopes: tenant_operator_actions(),
            lifetime_seconds: 3600,
        },
    )?;
    let operator_token = profiles.join("operator.token");
    private_files::replace(&operator_token, operator.token.as_bytes())?;
    let operator_profile = ClientProfile {
        family_id: journal.operator_family,
        principal: ADMINISTRATOR_PRINCIPAL.into(),
        identity: identities["operator-client"].clone().into(),
        bearer_file: operator_token,
        ..current.clone()
    };
    private_files::replace(
        &profiles.join("operator.json"),
        &serde_json::to_vec_pretty(&operator_profile)?,
    )?;
    // The Control credential is unchanged; only its certificate stops being
    // the one the application holds.
    let control_path = profiles.join("control.json");
    let mut control = ClientProfile::load(&control_path)?;
    if control.identity.certificate == identity_files(profiles, "client").certificate {
        control.identity = identities["control-client"].clone().into();
        private_files::replace(&control_path, &serde_json::to_vec_pretty(&control)?)?;
    }
    // The stopped watcher's journal would renew the replaced family.
    let renewal = current.bearer_file.with_extension("renewal.json");
    if renewal.try_exists()? {
        let request: RenewCredential =
            serde_json::from_slice(&private_files::read(&renewal, 4096)?)?;
        if request.family_id == journal.legacy_family {
            std::fs::remove_file(&renewal)?;
            private_files::sync_parent(&renewal)?;
        }
    }
    // The bearer first: a client that rereads it per request moves to the
    // application's credential with the same certificate.
    private_files::replace(&current.bearer_file, application.token.as_bytes())?;
    let application_profile = ClientProfile {
        family_id: journal.application_family,
        principal: APPLICATION_PRINCIPAL.into(),
        ..current.clone()
    };
    private_files::replace(
        &profiles.join("default.json"),
        &serde_json::to_vec_pretty(&application_profile)?,
    )?;
    owner
        .credentials
        .revoke(journal.legacy_family, "credential-split")?;
    Ok(())
}

/// The operator's and the Control administrator's own client certificates,
/// signed by the installation CA. A rerun keeps a pair an earlier run wrote.
fn client_identities(
    config: &RuntimeConfig,
    root: &Path,
    profiles: &Path,
) -> Result<BTreeMap<&'static str, TlsFiles>> {
    let ca_key_pem = private_files::read(&root.join("operator/ca-key.pem"), 1 << 20)?;
    let ca_pem = private_files::read(&root.join("tls/ca.pem"), 1 << 20)?;
    let ca_key = rcgen::KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(std::str::from_utf8(&ca_pem)?, &ca_key)?;
    let mut identities = BTreeMap::new();
    for name in ["operator-client", "control-client"] {
        let files = identity_files(profiles, name);
        if files.load().is_err() {
            let (certificate, key) = leaf(name, &issuer, true)?;
            // Admitted before it exists; an earlier run's leftover is retired.
            crate::client_pins::enroll_configured(
                config,
                kasumi_transport::certificate_pin(certificate.as_bytes())?,
                name,
            )?;
            private_files::replace(&files.private_key, key.as_bytes())?;
            private_files::replace(&files.certificate, certificate.as_bytes())?;
        }
        let pin = files.load()?.certificate_pin();
        crate::client_pins::enroll_configured(config, pin, name)?;
        crate::client_pins::retire_configured(config, name, pin)?;
        identities.insert(name, files);
    }
    Ok(identities)
}

/// Remove document write from the tenant administrator's tenant-wide grants
/// and grant the application read and write. Other grants are kept.
async fn restrict_tenant_policy(
    config: &RuntimeConfig,
    owner: &OperatorState,
    journal: &Journal,
) -> Result<()> {
    let database = open_tenant(config, owner, &journal.tenant, &journal.resource).await?;
    let restricted = async {
        let current = database.engine().generation()?.policy().clone();
        let target = split_policy(&current)?;
        if serde_json::to_value(&target)? != serde_json::to_value(&current)? {
            database
                .administer(offline_context(&database)?, Operation::SetPolicy(target))
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    database.shutdown().await?;
    restricted
}

/// Open the selected generation of `tenant`, which `resource` must name. The
/// caller shuts it down.
async fn open_tenant(
    config: &RuntimeConfig,
    owner: &OperatorState,
    tenant: &str,
    resource: &CredentialResource,
) -> Result<Arc<kasumi_engine::Database>> {
    let (tenants, nodes) = operator_tenants(config, owner.audit.store(), owner).await?;
    let tenant = tenants
        .iter()
        .find(|configured| configured.tenant == tenant)
        .context("the tenant of profiles/default.json is not configured")?;
    let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
        anyhow::bail!("the tenant of profiles/default.json is not a standalone tenant");
    };
    let incarnation = Uuid::parse_str(
        tenant
            .incarnation
            .as_deref()
            .context("tenant incarnation missing")?,
    )?;
    ensure!(
        *resource == CredentialResource::Database { incarnation },
        "profiles/default.json names another generation of its tenant"
    );
    let source = Arc::new(crate::runtime::file_secret);
    let stores = kasumi_store::TenantStorageSet::open_existing(
        nodes
            .get(&tenant.tenant)
            .cloned()
            .unwrap_or_else(|| owner.node.clone()),
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
    Ok(database)
}

fn split_policy(policy: &Policy) -> Result<Policy> {
    let mut grants = Vec::with_capacity(policy.grants.len() + 1);
    let mut application = false;
    for grant in &policy.grants {
        let mut grant = grant.clone();
        if grant.principal == ADMINISTRATOR_PRINCIPAL && grant.collection.is_none() {
            grant.actions.remove(&Action::Write);
        }
        if grant.principal == APPLICATION_PRINCIPAL {
            ensure!(
                grant.collection.is_none() && grant.actions == application_actions(),
                "the tenant policy already grants the application principal other authority"
            );
            application = true;
        }
        if !grant.actions.is_empty() {
            grants.push(grant);
        }
    }
    if !application {
        grants.push(Grant {
            principal: APPLICATION_PRINCIPAL.into(),
            collection: None,
            actions: application_actions(),
        });
    }
    Ok(Policy {
        grants,
        strict_read_audit: policy.strict_read_audit,
    })
}

/// A rerun replays the family's original issuance, which may have expired.
fn live_credential(
    credentials: &LocalCredentials,
    specification: CreateCredential,
) -> Result<IssuedCredential> {
    let family_id = specification.family_id;
    let issued = credentials.create(specification, "credential-split")?;
    let now = kasumi_clock::EpochClock::system()?.now_ms()?;
    if issued.expires_at_ms > now.saturating_add(300_000) {
        return Ok(issued);
    }
    credentials.renew(
        &RenewCredential {
            family_id,
            renewal_id: Uuid::new_v4(),
        },
        "credential-split",
    )
}

#[cfg(test)]
#[path = "standalone_credential_split_tests.rs"]
mod tests;
