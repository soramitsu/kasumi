//! The client certificates a mutual-TLS listener admits beyond its CA check.
//!
//! A listener whose configuration names `client_certificate_pins` completes a
//! handshake only when the client's leaf certificate passes the WebPKI checks
//! against `client_ca` (chain, validity, client-authentication usage and the
//! handshake signature) and its SHA-256 pin is in this file. A listener that
//! names no file checks the CA only. A named file that is missing or malformed
//! fails startup and is refused by a TLS reload, which keeps the previous
//! generation; an empty list admits no client.
//!
//! The file is trust configuration, read through `read_bounded`, so it must be
//! owned by this user (or root) and writable by no one else. Removing a pin
//! takes effect for new handshakes once the listener reloads (SIGHUP) or
//! restarts; established connections drain as for any TLS reload.
use crate::runtime::{MutualTlsEndpoint, RuntimeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use kasumi_transport::CertificatePin;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// At most this many admitted certificates in one file.
pub const MAX_CLIENT_PINS: usize = 4096;
const MAX_FILE_BYTES: usize = 1 << 20;
const MAX_NAME_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedCertificate {
    /// Lowercase hex SHA-256 of the leaf certificate's DER encoding.
    pub pin: String,
    /// What the certificate is for, such as the generated identity's name.
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPins {
    pub format: u32,
    pub certificates: Vec<AdmittedCertificate>,
}

impl Default for ClientPins {
    fn default() -> Self {
        Self {
            format: 1,
            certificates: Vec::new(),
        }
    }
}

impl ClientPins {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = crate::runtime::read_bounded(path, MAX_FILE_BYTES)
            .with_context(|| format!("reading client certificate pins {}", path.display()))?;
        let pins: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid client certificate pins {}", path.display()))?;
        pins.validate()
            .with_context(|| format!("invalid client certificate pins {}", path.display()))?;
        Ok(pins)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1,
            "unsupported client certificate pin format"
        );
        ensure!(
            self.certificates.len() <= MAX_CLIENT_PINS,
            "more than {MAX_CLIENT_PINS} admitted client certificates"
        );
        let mut seen = BTreeSet::new();
        for certificate in &self.certificates {
            let pin = parse_pin(&certificate.pin)?;
            ensure!(seen.insert(pin), "client certificate pin listed twice");
            ensure!(
                !certificate.name.is_empty()
                    && certificate.name.len() <= MAX_NAME_BYTES
                    && !certificate.name.chars().any(char::is_control),
                "client certificate name must be 1 to {MAX_NAME_BYTES} bytes without control characters"
            );
        }
        Ok(())
    }

    pub fn admitted(&self) -> Result<BTreeSet<CertificatePin>> {
        self.validate()?;
        self.certificates
            .iter()
            .map(|certificate| parse_pin(&certificate.pin))
            .collect()
    }

    /// Admit `pin` under `name`; an already admitted pin keeps its entry.
    pub fn enroll(&mut self, pin: CertificatePin, name: &str) -> Result<bool> {
        let pin = hex::encode(pin);
        if self.certificates.iter().any(|entry| entry.pin == pin) {
            return Ok(false);
        }
        self.certificates.push(AdmittedCertificate {
            pin,
            name: name.into(),
        });
        self.validate()?;
        Ok(true)
    }

    /// Stop admitting `pin`. Whether it was admitted.
    pub fn remove(&mut self, pin: CertificatePin) -> bool {
        let pin = hex::encode(pin);
        let before = self.certificates.len();
        self.certificates.retain(|entry| entry.pin != pin);
        self.certificates.len() != before
    }

    /// Stop admitting every certificate enrolled under `name` except `keep`.
    pub fn retire_others(&mut self, name: &str, keep: CertificatePin) {
        let keep = hex::encode(keep);
        self.certificates
            .retain(|entry| entry.name != name || entry.pin == keep);
    }

    pub fn store(&self, path: &Path) -> Result<()> {
        self.validate()?;
        private_files::replace(path, &serde_json::to_vec_pretty(self)?)
    }
}

fn parse_pin(value: &str) -> Result<CertificatePin> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "client certificate pin must be 64 lowercase hex digits"
    );
    let mut pin = [0; 32];
    hex::decode_to_slice(value, &mut pin)?;
    Ok(pin)
}

/// The distinct allowlist files the configuration's mutual-TLS listeners name.
pub fn configured_files(config: &RuntimeConfig) -> BTreeSet<PathBuf> {
    [&config.native, &config.admin]
        .into_iter()
        .filter_map(|endpoint: &MutualTlsEndpoint| endpoint.client_certificate_pins.clone())
        .collect()
}

/// Admit `pin` under `name` in every allowlist the configuration names,
/// before anything presents that certificate.
pub fn enroll_configured(config: &RuntimeConfig, pin: CertificatePin, name: &str) -> Result<()> {
    for path in configured_files(config) {
        let _lock = lock(&path)?;
        let mut pins = ClientPins::load(&path)?;
        if pins.enroll(pin, name)? {
            pins.store(&path)?;
        }
    }
    Ok(())
}

/// Retire every certificate enrolled under `name` except `keep`, in every
/// allowlist the configuration names.
pub fn retire_configured(config: &RuntimeConfig, name: &str, keep: CertificatePin) -> Result<()> {
    for path in configured_files(config) {
        let _lock = lock(&path)?;
        let mut pins = ClientPins::load(&path)?;
        let before = pins.clone();
        pins.retire_others(name, keep);
        if pins != before {
            pins.store(&path)?;
        }
    }
    Ok(())
}

/// Serializes the operator commands that edit one allowlist.
pub fn lock(path: &Path) -> Result<private_files::ExclusiveLock> {
    private_files::ExclusiveLock::acquire(&path.with_extension("lock"))
        .context("another operation is changing the client certificate pins")
}

/// `kasumid client-certificate list|enroll|remove|enable ...`.
pub async fn command(arguments: &[String]) -> Result<bool> {
    let [command, action, configuration, rest @ ..] = arguments else {
        return Ok(false);
    };
    if command != "client-certificate" {
        return Ok(false);
    }
    let configuration = Path::new(configuration);
    let output = match (action.as_str(), rest) {
        ("list", []) => list(&RuntimeConfig::load(configuration)?)?,
        ("enroll", [certificate, name]) => enroll(
            &RuntimeConfig::load(configuration)?,
            Path::new(certificate),
            name,
        )?,
        ("remove", [certificate]) => remove(&RuntimeConfig::load(configuration)?, certificate)?,
        ("enable", []) => enable(configuration)?,
        _ => anyhow::bail!(
            "usage: client-certificate list|enable <configuration.json>, enroll <configuration.json> <certificate.pem> <name>, remove <configuration.json> <certificate.pem-or-sha256-pin>"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(true)
}

fn require_configured(config: &RuntimeConfig) -> Result<BTreeSet<PathBuf>> {
    let files = configured_files(config);
    ensure!(
        !files.is_empty(),
        "no listener names a client certificate allowlist; run `kasumid client-certificate enable <configuration.json>` first"
    );
    Ok(files)
}

fn list(config: &RuntimeConfig) -> Result<serde_json::Value> {
    let mut files = serde_json::Map::new();
    for path in require_configured(config)? {
        files.insert(
            path.display().to_string(),
            serde_json::to_value(ClientPins::load(&path)?.certificates)?,
        );
    }
    Ok(serde_json::Value::Object(files))
}

fn enroll(config: &RuntimeConfig, certificate: &Path, name: &str) -> Result<serde_json::Value> {
    let files = require_configured(config)?;
    let pem = crate::runtime::read_bounded(certificate, 1 << 20)?;
    let mut pin = None;
    // Admit only what the listeners naming the allowlist would verify anyway.
    for endpoint in [&config.native, &config.admin] {
        if endpoint.client_certificate_pins.is_some() {
            let ca = crate::runtime::read_bounded(&endpoint.client_ca, 1 << 20)?;
            pin = Some(kasumi_transport::admissible_client_pin(&ca, &pem)?);
        }
    }
    let pin = pin.context("no listener names a client certificate allowlist")?;
    let mut enrolled = false;
    for path in &files {
        let _lock = lock(path)?;
        let mut pins = ClientPins::load(path)?;
        if pins.enroll(pin, name)? {
            pins.store(path)?;
            enrolled = true;
        }
    }
    Ok(serde_json::json!({
        "pin": hex::encode(pin),
        "name": name,
        "enrolled": enrolled,
        "files": files,
        "next": "send SIGHUP to kasumid, or restart it, before the certificate connects",
    }))
}

fn remove(config: &RuntimeConfig, certificate: &str) -> Result<serde_json::Value> {
    let files = require_configured(config)?;
    let pin = match parse_pin(certificate) {
        Ok(pin) => pin,
        Err(_) => kasumi_transport::certificate_pin(&crate::runtime::read_bounded(
            Path::new(certificate),
            1 << 20,
        )?)?,
    };
    let mut removed = false;
    let mut remaining = 0;
    for path in &files {
        let _lock = lock(path)?;
        let mut pins = ClientPins::load(path)?;
        if pins.remove(pin) {
            pins.store(path)?;
            removed = true;
        }
        remaining += pins.certificates.len();
    }
    Ok(serde_json::json!({
        "pin": hex::encode(pin),
        "removed": removed,
        "admitted_remaining": remaining,
        "files": files,
        "next": "send SIGHUP to kasumid, or restart it: new handshakes are refused from then on, and established connections drain; also revoke the credential families that certificate used",
    }))
}

/// Turn on pin admission for an installation that checks the CA only: admit
/// the certificate of every profile in the installation's `profiles`
/// directory, then name the allowlist on the native and administrative
/// listeners. Rerunning it after an interruption finishes the same change,
/// and each step is kept: the allowlist is written before the configuration
/// names it. Enforcement begins when kasumid next starts.
fn enable(configuration: &Path) -> Result<serde_json::Value> {
    let mut config = RuntimeConfig::load(configuration)?;
    let root = crate::standalone::installation_root(&config)?;
    let path = root.join("tls/client-pins.json");
    let _lock = lock(&path)?;
    let mut pins = if path.try_exists()? {
        ClientPins::load(&path)?
    } else {
        ClientPins::default()
    };
    let mut admitted = Vec::new();
    let mut entries = std::fs::read_dir(root.join("profiles"))?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    for profile in entries {
        if profile
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Ok(profile) = crate::standalone::ClientProfile::load(&profile)
        {
            let identity = crate::runtime::TlsFiles::from(profile.identity);
            let name = identity
                .certificate
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("client")
                .to_owned();
            let pin = kasumi_transport::certificate_pin(&crate::runtime::read_bounded(
                &identity.certificate,
                1 << 20,
            )?)?;
            pins.enroll(pin, &name)?;
            admitted.push(serde_json::json!({"pin": hex::encode(pin), "name": name}));
        }
    }
    pins.store(&path)?;
    let mut changed = false;
    for endpoint in [&mut config.native, &mut config.admin] {
        if endpoint.client_certificate_pins.as_ref() != Some(&path) {
            endpoint.client_certificate_pins = Some(path.clone());
            changed = true;
        }
    }
    if changed {
        config.validate()?;
        private_files::replace(configuration, &serde_json::to_vec_pretty(&config)?)?;
    }
    Ok(serde_json::json!({
        "allowlist": path,
        "admitted": admitted,
        "next": "restart kasumid to enforce the allowlist; enroll any other client certificate first",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlists_are_bounded_strict_and_keep_names_with_pins() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let path = directory.path().join("client-pins.json");
        let mut pins = ClientPins::default();
        assert!(pins.enroll([1; 32], "client")?);
        assert!(!pins.enroll([1; 32], "renamed")?);
        assert!(pins.enroll([2; 32], "client")?);
        assert!(pins.enroll([3; 32], "operator-client")?);
        pins.store(&path)?;
        assert_eq!(ClientPins::load(&path)?, pins);
        assert_eq!(
            ClientPins::load(&path)?.admitted()?,
            BTreeSet::from([[1; 32], [2; 32], [3; 32]])
        );
        pins.retire_others("client", [2; 32]);
        assert_eq!(pins.admitted()?, BTreeSet::from([[2; 32], [3; 32]]));
        assert!(pins.remove([3; 32]) && !pins.remove([3; 32]));
        // An explicitly empty list is valid and admits no one.
        pins.remove([2; 32]);
        pins.store(&path)?;
        assert!(ClientPins::load(&path)?.admitted()?.is_empty());
        let pin = "ab".repeat(32);
        for invalid in [
            serde_json::json!({"format": 2, "certificates": []}),
            serde_json::json!({"certificates": []}),
            serde_json::json!({"format": 1, "certificates": [], "mode": "permissive"}),
            serde_json::json!({"format": 1, "certificates": [{"pin": "AB".repeat(32), "name": "x"}]}),
            serde_json::json!({"format": 1, "certificates": [{"pin": "ab".repeat(31), "name": "x"}]}),
            serde_json::json!({"format": 1, "certificates": [{"pin": pin, "name": ""}]}),
            serde_json::json!({"format": 1, "certificates": [{"pin": pin, "name": "a\nb"}]}),
            serde_json::json!({"format": 1, "certificates": [{"pin": pin, "name": "x"}, {"pin": pin, "name": "y"}]}),
            serde_json::json!({"format": 1, "certificates": [{"pin": pin}]}),
        ] {
            private_files::replace(&path, &serde_json::to_vec(&invalid)?)?;
            assert!(ClientPins::load(&path).is_err(), "{invalid}");
        }
        let many = ClientPins {
            format: 1,
            certificates: (0..=MAX_CLIENT_PINS)
                .map(|index| AdmittedCertificate {
                    pin: format!("{index:064x}"),
                    name: "x".into(),
                })
                .collect(),
        };
        assert!(many.validate().is_err());
        // A file another user could have written is not trusted.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ClientPins::default().store(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622))?;
            assert!(ClientPins::load(&path).is_err());
        }
        std::fs::remove_file(&path)?;
        assert!(ClientPins::load(&path).is_err());
        Ok(())
    }
}
