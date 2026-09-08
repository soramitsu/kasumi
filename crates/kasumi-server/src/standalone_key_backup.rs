//! Exact installed operator-file inventories. These are secret-bearing local
//! backups, kept separately from ordinary encrypted database backup sessions.
use crate::{
    auth::AuthKeySource,
    runtime::{KeyProviderSettings, RuntimeConfig},
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{FileKeyProvider, private_files};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const MAX_FILE: usize = 1 << 20;
const MAX_MANIFEST: usize = 8 << 20;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    installation_database: PathBuf,
    files: Vec<Entry>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    role: String,
    source: PathBuf,
    file: String,
    sha256: String,
    key_ref: Option<String>,
    active_generation: Option<u64>,
    retained_generations: Vec<u64>,
}
#[derive(Debug, Serialize)]
pub struct Verification {
    pub manifest_sha256: String,
    pub files: usize,
    pub wrapping_keyrings: usize,
    pub retained_wrapping_generations: u64,
}

pub(crate) fn create(config: &RuntimeConfig, output: &Path) -> Result<()> {
    let root = crate::standalone::installation_root(config)?;
    let mut inputs = vec![
        (
            "security".to_owned(),
            "security-keys.json".to_owned(),
            &config.security_audit.keys,
        ),
        (
            "control".to_owned(),
            "control-keys.json".to_owned(),
            &config.control.keys,
        ),
        (
            "control-custody".to_owned(),
            "control-custody-keys.json".to_owned(),
            &config.control.custody_keys,
        ),
    ];
    for tenant in &config.tenants {
        let id = hex::encode(Sha256::digest(tenant.tenant.as_bytes()));
        inputs.push((
            format!("application:{}", tenant.tenant),
            format!("application-{id}-keys.json"),
            &tenant.keys,
        ));
        inputs.push((
            format!("custody:{}", tenant.tenant),
            format!("custody-{id}-keys.json"),
            &tenant.custody_keys,
        ));
    }
    ensure!(
        inputs
            .iter()
            .all(|(_, _, provider)| matches!(provider, KeyProviderSettings::File { .. })),
        "operator file backup requires local file keyrings; external providers require their own key backup"
    );
    private_files::create_directory(output)?;
    let mut manifest = Manifest {
        format: 1,
        installation_database: config.database_path.clone(),
        files: Vec::new(),
    };
    for (role, file, provider) in inputs {
        let KeyProviderSettings::File { path } = provider else {
            unreachable!("validated local keyrings")
        };
        let keyring = FileKeyProvider::open(path)?;
        let (active, retained) = keyring.generations()?;
        let mut entry = copy(&role, path, &file, output)?;
        entry.key_ref = Some(keyring.key_ref().into());
        entry.active_generation = Some(active);
        entry.retained_generations = retained;
        manifest.files.push(entry);
    }
    let AuthKeySource::Local { signer_file } = &config.auth.source else {
        anyhow::bail!("local operator backup requires installed local signing keys")
    };
    for (role, source, file) in [
        ("jwt-signers", signer_file.clone(), "signers.json"),
        (
            "certificate-authority-private",
            root.join("operator/ca-key.pem"),
            "ca-key.pem",
        ),
        (
            "certificate-authority-public",
            root.join("tls/ca.pem"),
            "ca.pem",
        ),
    ] {
        manifest.files.push(copy(role, &source, file, output)?);
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(
        bytes.len() <= MAX_MANIFEST,
        "operator backup manifest work budget exceeded"
    );
    // The manifest publishes only after every private copied dependency is durable.
    private_files::create(&output.join("manifest.json"), &bytes)?;
    verify(output)?;
    Ok(())
}
fn copy(role: &str, source: &Path, file: &str, output: &Path) -> Result<Entry> {
    let bytes = private_files::read(source, MAX_FILE)?;
    private_files::create(&output.join(file), &bytes)?;
    Ok(Entry {
        role: role.into(),
        source: source.into(),
        file: file.into(),
        sha256: hex::encode(Sha256::digest(bytes.as_slice())),
        key_ref: None,
        active_generation: None,
        retained_generations: Vec::new(),
    })
}
/// Detect incomplete, substituted, or corrupted files relative to the private
/// inventory. Retain the returned manifest digest independently with key escrow.
/// The digest is not a substitute for authenticating the original operator copy.
pub fn verify(directory: &Path) -> Result<Verification> {
    private_files::check_directory(directory)?;
    let bytes = private_files::read(&directory.join("manifest.json"), MAX_MANIFEST)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.format == 1
            && manifest.installation_database.is_absolute()
            && !manifest.files.is_empty(),
        "unsupported operator backup inventory"
    );
    let mut names = BTreeSet::new();
    let mut keys = 0;
    let mut generations = 0u64;
    for entry in &manifest.files {
        ensure!(
            Path::new(&entry.file).components().count() == 1
                && matches!(
                    Path::new(&entry.file).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                && names.insert(&entry.file),
            "operator inventory contains a duplicate or unsafe file name"
        );
        let path = directory.join(&entry.file);
        let content = private_files::read(&path, MAX_FILE)?;
        ensure!(
            hex::encode(Sha256::digest(content.as_slice())) == entry.sha256,
            "operator backup file digest differs: {}",
            entry.file
        );
        if let Some(reference) = &entry.key_ref {
            let keyring = FileKeyProvider::open(path)?;
            let (active, retained) = keyring.generations()?;
            ensure!(
                keyring.key_ref() == reference
                    && entry.active_generation == Some(active)
                    && entry.retained_generations == retained,
                "operator wrapping-key inventory differs"
            );
            keys += 1;
            generations = generations
                .checked_add(retained.len() as u64)
                .context("operator key count overflow")?;
        } else {
            ensure!(
                entry.active_generation.is_none() && entry.retained_generations.is_empty(),
                "operator non-keyring generation inventory is invalid"
            );
        }
    }
    Ok(Verification {
        manifest_sha256: hex::encode(Sha256::digest(bytes.as_slice())),
        files: manifest.files.len(),
        wrapping_keyrings: keys,
        retained_wrapping_generations: generations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn relocated_installed_keys_are_copied_and_inventory_detects_corruption() {
        let root = tempfile::tempdir().unwrap();
        let installed = crate::standalone::initialize(&root.path().join("kasumi"), "a/tenant")
            .await
            .unwrap();
        let mut config = RuntimeConfig::load(&installed.configuration).unwrap();
        let KeyProviderSettings::File { path: original } = &config.tenants[0].keys else {
            panic!()
        };
        let moved = root.path().join("separate-key-storage");
        private_files::create_directory(&moved).unwrap();
        let relocated = moved.join("installed.json");
        private_files::create(
            &relocated,
            &private_files::read(original, MAX_FILE).unwrap(),
        )
        .unwrap();
        std::fs::remove_file(original).unwrap();
        config.tenants[0].keys = KeyProviderSettings::File {
            path: relocated.clone(),
        };
        private_files::replace(
            &installed.configuration,
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let unrelated = installed
            .configuration
            .parent()
            .unwrap()
            .join("operator/unrelated.txt");
        private_files::create(&unrelated, b"must not be copied").unwrap();
        let output = root.path().join("operator-backup");
        crate::standalone::backup_operator_keys(&installed.configuration, &output)
            .await
            .unwrap();
        assert!(!output.join("unrelated.txt").exists());
        let verified = verify(&output).unwrap();
        assert_eq!(verified.wrapping_keyrings, 5);
        assert_eq!(verified.retained_wrapping_generations, 5);
        let manifest: Manifest = serde_json::from_slice(
            &private_files::read(&output.join("manifest.json"), MAX_MANIFEST).unwrap(),
        )
        .unwrap();
        let application = manifest
            .files
            .iter()
            .find(|entry| entry.role == "application:a/tenant")
            .unwrap();
        assert_eq!(application.source, relocated);
        let copied = output.join(&application.file);
        let saved = private_files::read(&copied, MAX_FILE).unwrap();
        private_files::replace(&copied, b"corrupted operator file").unwrap();
        assert!(verify(&output).is_err());
        private_files::replace(&copied, &saved).unwrap();
        assert_eq!(
            verify(&output).unwrap().manifest_sha256,
            verified.manifest_sha256
        );
        assert!(
            crate::standalone::backup_operator_keys(&installed.configuration, &output)
                .await
                .is_err()
        );
        assert_eq!(
            verify(&output).unwrap().manifest_sha256,
            verified.manifest_sha256
        );
    }
}
