//! Explicit stopped-installation migration to certificate-bound native
//! credentials and a separate MCP audience, for an installation initialized
//! before them. Its native tokens are accepted from any certificate the CA
//! issued and on MCP too. Afterwards each profile in `profiles/` has a family
//! bound to the certificate that profile presents, `profiles/mcp.json` holds
//! an unbound MCP credential for MCP's own audience, the replaced families are
//! revoked, and the configuration refuses unbound native tokens.
//!
//! A journal written before anything it names is created lets a rerun after
//! any interruption finish the same migration with the same families.
use super::*;
use kasumi_types::{CredentialStatus, RenewCredential};

const MAX_JOURNAL: usize = 256 << 10;
const MAX_PROFILES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    mcp_audience: String,
    mcp_family: Uuid,
    /// Each rebound profile, by file name: the family it named and the bound
    /// family that replaces it.
    profiles: BTreeMap<String, Replacement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    replaced: Uuid,
    family: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CredentialBindingReport {
    /// False when the installation already refused unbound native tokens.
    pub bound: bool,
    pub mcp_audience: Option<String>,
    pub mcp_profile: PathBuf,
    /// The profiles now bound to their own certificates, by file name, with
    /// the family each replaced, now revoked.
    pub profiles: BTreeMap<String, Uuid>,
}

pub async fn bind_credentials(configuration: &Path) -> Result<CredentialBindingReport> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    bind_credentials_with_storage(configuration, storage).await
}

pub(crate) async fn bind_credentials_with_storage(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<CredentialBindingReport> {
    let configuration = configuration.to_owned();
    operator::run(async move {
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        let result = bind(&configuration, &config, &owner).await;
        owner.finish(result).await
    })
    .await
}

/// Every loadable profile directly in `profiles/`, by file name.
fn installed_profiles(profiles: &Path) -> Result<BTreeMap<String, ClientProfile>> {
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(profiles)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Some(name) = path.file_name().and_then(|name| name.to_str())
            && let Ok(profile) = ClientProfile::load(&path)
        {
            found.insert(name.to_owned(), profile);
        }
    }
    ensure!(
        found.len() <= MAX_PROFILES,
        "more than {MAX_PROFILES} profiles in profiles/"
    );
    Ok(found)
}

fn unbound_native(status: &CredentialStatus) -> bool {
    status.revoked_at_ms.is_none()
        && status.specification.client_certificate_sha256.is_none()
        && status.specification.audience.is_native()
}

async fn bind(
    configuration: &Path,
    config: &RuntimeConfig,
    owner: &OperatorState,
) -> Result<CredentialBindingReport> {
    crate::local_recovery::require_runtime_ready(owner.audit.store())?;
    let root = installation_root(config)?;
    let profiles = root.join("profiles");
    let journal_path = profiles.join("credential-binding.json");
    let mcp_path = profiles.join("mcp.json");
    let journal = if journal_path.try_exists()? {
        serde_json::from_slice::<Journal>(&private_files::read(&journal_path, MAX_JOURNAL)?)?
    } else {
        if config.auth.require_certificate_binding {
            return Ok(CredentialBindingReport {
                bound: false,
                mcp_audience: config.auth.mcp_audience.clone(),
                mcp_profile: mcp_path,
                profiles: BTreeMap::new(),
            });
        }
        let mut replacements = BTreeMap::new();
        for (name, profile) in installed_profiles(&profiles)? {
            if unbound_native(&owner.credentials.status(profile.family_id)?) {
                replacements.insert(
                    name,
                    Replacement {
                        replaced: profile.family_id,
                        family: Uuid::new_v4(),
                    },
                );
            }
        }
        let journal = Journal {
            mcp_audience: config.auth.mcp_audience.clone().unwrap_or_else(|| {
                format!("{}/mcp", config.auth.audience.trim_end_matches("/api"))
            }),
            mcp_family: Uuid::new_v4(),
            profiles: replacements,
        };
        private_files::create(&journal_path, &serde_json::to_vec_pretty(&journal)?)?;
        journal
    };
    // Running watchers would renew the replaced families.
    let mut watchers = Vec::new();
    for name in journal.profiles.keys() {
        let profile = ClientProfile::load(&profiles.join(name))?;
        watchers.push(
            private_files::ExclusiveLock::acquire(
                &profile.bearer_file.with_extension("watch.lock"),
            )
            .with_context(|| format!("stop the credential watcher of profiles/{name} first"))?,
        );
    }
    let operation = Uuid::new_v4().to_string();
    owner
        .audit
        .record(operator_event(
            &operation,
            kasumi_engine::SecurityOutcome::Started,
        ))
        .await?;
    let result = apply(configuration, config, owner, &profiles, &journal).await;
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
    drop(watchers);
    std::fs::remove_file(&journal_path)?;
    private_files::sync_parent(&journal_path)?;
    Ok(CredentialBindingReport {
        bound: true,
        mcp_audience: Some(journal.mcp_audience),
        mcp_profile: mcp_path,
        profiles: journal
            .profiles
            .into_iter()
            .map(|(name, replacement)| (name, replacement.replaced))
            .collect(),
    })
}

/// Every step is idempotent, so a rerun repeats the ones already done.
async fn apply(
    configuration: &Path,
    config: &RuntimeConfig,
    owner: &OperatorState,
    profiles: &Path,
    journal: &Journal,
) -> Result<()> {
    let AuthKeySource::Local { signer_file } = &config.auth.source else {
        anyhow::bail!("certificate binding migrates the local credential issuer");
    };
    let credentials = LocalCredentials::open(
        owner.audit.store().clone(),
        signer_file.clone(),
        config.auth.issuer.clone(),
        config.auth.audience.clone(),
    )?
    .with_mcp_audience(Some(journal.mcp_audience.clone()))?;
    for (name, replacement) in &journal.profiles {
        let path = profiles.join(name);
        let profile = ClientProfile::load(&path)?;
        ensure!(
            [replacement.replaced, replacement.family].contains(&profile.family_id),
            "profiles/{name} names another family than the binding journal"
        );
        let mut specification = credentials.status(replacement.replaced)?.specification;
        specification.family_id = replacement.family;
        specification.client_certificate_sha256 = Some(hex::encode(
            TlsFiles::from(profile.identity.clone())
                .load()?
                .certificate_pin(),
        ));
        let issued = live_credential(&credentials, specification, "credential-binding")?;
        // The stopped watcher's journal would renew the replaced family.
        let renewal = profile.bearer_file.with_extension("renewal.json");
        if renewal.try_exists()? {
            let request: RenewCredential =
                serde_json::from_slice(&private_files::read(&renewal, 4096)?)?;
            if request.family_id == replacement.replaced {
                std::fs::remove_file(&renewal)?;
                private_files::sync_parent(&renewal)?;
            }
        }
        private_files::replace(&profile.bearer_file, issued.token.as_bytes())?;
        private_files::replace(
            &path,
            &serde_json::to_vec_pretty(&ClientProfile {
                family_id: replacement.family,
                ..profile
            })?,
        )?;
        credentials.revoke(replacement.replaced, "credential-binding")?;
    }
    // The MCP credential acts for the application, with its authority.
    let application = ClientProfile::load(&profiles.join("default.json"))?;
    let template = credentials.status(application.family_id)?.specification;
    let mcp = live_credential(
        &credentials,
        CreateCredential {
            family_id: journal.mcp_family,
            client_certificate_sha256: None,
            audience: CredentialAudience::Mcp,
            ..template
        },
        "credential-binding",
    )?;
    let mcp_token = profiles.join("mcp.token");
    private_files::replace(&mcp_token, mcp.token.as_bytes())?;
    private_files::replace(
        &profiles.join("mcp.json"),
        &serde_json::to_vec_pretty(&ClientProfile {
            family_id: journal.mcp_family,
            bearer_file: mcp_token,
            ..application
        })?,
    )?;
    let mut config = config.clone();
    config.auth.mcp_audience = Some(journal.mcp_audience.clone());
    config.auth.require_certificate_binding = true;
    config.validate()?;
    private_files::replace(configuration, &serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

#[cfg(test)]
#[path = "standalone_credential_binding_tests.rs"]
mod tests;
