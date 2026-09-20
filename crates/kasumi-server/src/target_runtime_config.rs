//! Explicit target templates are installed independently of source serving.
//! Requests select exact committed identifiers, never endpoints, keys or paths.
use crate::{
    runtime::{KeyProviderSettings, RuntimeConfig, TlsFiles, credential_path},
    serving_runtime::AuthorityEndpoint,
};
use anyhow::{Context, Result, ensure};
use kasumi_client::KasumiClientConfig;
use kasumi_serving::NodeIdentity;
use kasumi_types::{ControlSigningRoot, TargetJournalLimits};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRunnerLimits {
    pub journal: TargetJournalLimits,
    pub max_live_generations: u16,
    pub operation_timeout_ms: u64,
}
impl TargetRunnerLimits {
    pub(crate) fn validate(&self) -> Result<()> {
        self.journal.validate()?;
        ensure!(
            (1..=64).contains(&self.max_live_generations)
                && (1..=600_000).contains(&self.operation_timeout_ms),
            "target runtime limits outside bounds"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBackupSource {
    pub destination_alias: String,
    pub keys: KeyProviderSettings,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTenantTemplate {
    pub authority: String,
    pub application_keys: KeyProviderSettings,
    pub custody_keys: KeyProviderSettings,
    pub source_backups: BTreeMap<Uuid, TargetBackupSource>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRecoveryConfig {
    pub control_root: ControlSigningRoot,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub control_endpoints: BTreeMap<u64, AuthorityEndpoint>,
    pub control_tls: TlsFiles,
    pub control_ca: PathBuf,
    pub node: NodeIdentity,
    pub attestation_key: PathBuf,
    pub issuer_admin_bearer_file: BTreeMap<Uuid, String>,
    pub journal_path: PathBuf,
    pub journal_keys: KeyProviderSettings,
    pub generation_root: PathBuf,
    pub tenants: BTreeMap<String, TargetTenantTemplate>,
    pub limits: TargetRunnerLimits,
}
impl TargetRecoveryConfig {
    pub(crate) fn validate(&self, runtime: &RuntimeConfig) -> Result<()> {
        self.control_root.validate()?;
        self.node.validate()?;
        ensure!(
            runtime
                .signer_verifier
                .as_ref()
                .is_some_and(|verifier| verifier.identity == self.node.verifier),
            "target physical verifier differs from runtime installation"
        );
        self.control_tls.validate()?;
        self.limits.validate()?;
        crate::installed_clients::validate(&self.control_endpoints)?;
        let replication = runtime
            .replication
            .as_ref()
            .context("target recovery requires replicated runtime")?;
        ensure!(
            runtime.mode == crate::runtime::DeploymentMode::Replicated
                && replication.node_id == self.node.node_id,
            "target recovery installation node differs"
        );
        for path in [
            &self.control_ca,
            &self.attestation_key,
            &self.journal_path,
            &self.generation_root,
        ] {
            ensure!(
                path.is_absolute(),
                "target custody paths must be installed absolute paths"
            );
        }
        ensure!(
            self.journal_path != runtime.database_path
                && !self.journal_path.starts_with(&self.generation_root)
                && !runtime.database_path.starts_with(&self.generation_root),
            "target cleanup root contains original or journal storage"
        );
        let journal_key = self.journal_keys.validate()?;
        let mut protected = BTreeSet::from([
            runtime.control.keys.validate()?,
            runtime.control.custody_keys.validate()?,
            runtime.security_audit.keys.validate()?,
        ]);
        for tenant in &runtime.tenants {
            protected.insert(tenant.keys.validate()?);
            protected.insert(tenant.custody_keys.validate()?);
        }
        ensure!(
            (1..=10_000).contains(&self.tenants.len()),
            "target templates must be explicitly bounded"
        );
        let mut target_keys = BTreeSet::new();
        for (tenant, template) in &self.tenants {
            kasumi_types::validate_name(tenant)?;
            ensure!(
                !tenant.starts_with("__kasumi_") && !tenant.starts_with("kasumi."),
                "reserved target tenant"
            );
            let authority = runtime
                .serving_authorities
                .get(&template.authority)
                .context("target issuer is not installed")?;
            ensure!(
                authority.principal == self.node.principal
                    && authority
                        .manifest
                        .lifecycle_controls
                        .get(&self.control_root.control_incarnation)
                        == Some(&self.control_root.public_key),
                "target authority does not install the exact Control root/node"
            );
            ensure!(
                self.issuer_admin_bearer_file
                    .contains_key(&authority.manifest.authority_id),
                "target issuer admission credential missing"
            );
            for provider in [&template.application_keys, &template.custody_keys] {
                let key = provider.validate()?;
                ensure!(
                    key != journal_key && !protected.contains(&key) && target_keys.insert(key),
                    "target, source and custody encryption identities must remain independent"
                );
            }
            ensure!(
                (1..=64).contains(&template.source_backups.len()),
                "target source key lineage bound exceeded"
            );
            for (incarnation, source) in &template.source_backups {
                ensure!(
                    !incarnation.is_nil()
                        && runtime
                            .backup_destinations
                            .contains_key(&source.destination_alias),
                    "target backup source is not installed"
                );
                ensure!(
                    source.keys.validate()? != journal_key,
                    "source backup cannot use target journal key"
                );
            }
        }
        for template in self.tenants.values() {
            for source in template.source_backups.values() {
                ensure!(
                    !target_keys.contains(&source.keys.validate()?),
                    "source backup key cannot be reused for a target application or custody domain"
                );
            }
        }
        ensure!(
            !protected.contains(&journal_key),
            "target journal requires an independent key identity"
        );
        let installed: BTreeSet<_> = runtime
            .serving_authorities
            .values()
            .map(|a| a.manifest.authority_id)
            .collect();
        ensure!(
            self.issuer_admin_bearer_file
                .keys()
                .all(|id| installed.contains(id)),
            "target credential names an uninstalled issuer"
        );
        for name in self.issuer_admin_bearer_file.values() {
            credential_path(name)?;
        }
        Ok(())
    }
    pub(crate) fn control_connections(&self) -> Result<BTreeMap<u64, KasumiClientConfig>> {
        crate::installed_clients::connections(
            &self.control_endpoints,
            &self.control_tls,
            &self.control_ca,
        )
    }
}
