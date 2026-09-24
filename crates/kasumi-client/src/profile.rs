//! Installed native client profile shared by applications and standalone tools.
//! The profile is an exact private file; bearer tokens remain request-local and
//! are reloaded from their separate atomically replaced file for each call.
use crate::KasumiClientConfig;
use anyhow::{Context, Result, ensure};
use kasumi_transport::{
    CertificatePin, TlsIdentity,
    credentials::{FileCredentialSource, token},
};
use kasumi_types::{CredentialResource, validate_name};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_PROFILE_BYTES: usize = 128 << 10;
const MAX_PEM_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl ProfileTlsFiles {
    fn validate(&self) -> Result<()> {
        absolute(&self.certificate)?;
        absolute(&self.private_key)
    }

    pub fn load(&self) -> Result<TlsIdentity> {
        self.validate()?;
        let certificate = read_file(&self.certificate, MAX_PEM_BYTES, false)?;
        let private_key = Zeroizing::new(read_file(&self.private_key, MAX_PEM_BYTES, true)?);
        TlsIdentity::from_pem(&certificate, &private_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAuthorityEndpoint {
    pub endpoint: String,
    pub certificate_pins: BTreeSet<String>,
}

/// Format 2 adds an explicit principal and rejects earlier profile files.
/// Exact profile bytes can be bound by an independently signed runtime digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    pub format: u32,
    pub family_id: Uuid,
    pub tenant: String,
    pub principal: String,
    pub resource: CredentialResource,
    pub native_endpoint: String,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub administrative_members: BTreeMap<u64, ProfileAuthorityEndpoint>,
    pub mcp_endpoint: String,
    pub identity: ProfileTlsFiles,
    pub server_ca: PathBuf,
    pub native_certificate_pin: String,
    pub bearer_file: PathBuf,
}

impl ClientProfile {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_sha256(path).map(|(profile, _)| profile)
    }

    /// Hash the exact bytes read from one owner-only inode before parsing.
    /// Callers compare this digest with their independently signed runtime pin.
    pub fn load_with_sha256(path: &Path) -> Result<(Self, String)> {
        let bytes = read_file(path, MAX_PROFILE_BYTES, true)?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let profile: Self = serde_json::from_slice(&bytes)?;
        profile.validate()?;
        Ok((profile, sha256))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 2 && !self.family_id.is_nil(),
            "unsupported client profile"
        );
        validate_name(&self.tenant)?;
        validate_name(&self.principal)?;
        self.resource.validate()?;
        origin(&self.native_endpoint)?;
        let mcp = url::Url::parse(&self.mcp_endpoint)?;
        ensure!(
            mcp.scheme() == "https"
                && mcp.host_str().is_some()
                && mcp.username().is_empty()
                && mcp.password().is_none()
                && mcp.query().is_none()
                && mcp.fragment().is_none(),
            "MCP endpoint must be a credential-free HTTPS URL"
        );
        self.identity.validate()?;
        absolute(&self.server_ca)?;
        absolute(&self.bearer_file)?;
        parse_pin(&self.native_certificate_pin)?;
        validate_members(&self.administrative_members)
    }

    /// Compare the installed profile to the exact signed database identity.
    /// A Control/Custody credential cannot become a data credential.
    pub fn require_database_binding(
        &self,
        tenant: &str,
        incarnation: Uuid,
        principal: &str,
        family_id: Uuid,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.tenant == tenant
                && self.principal == principal
                && self.family_id == family_id
                && !family_id.is_nil()
                && self.resource == CredentialResource::Database { incarnation },
            "native client profile differs from signed database binding"
        );
        Ok(())
    }

    pub fn administrative_member(&self) -> Result<&ProfileAuthorityEndpoint> {
        validate_members(&self.administrative_members)?;
        ensure!(
            self.administrative_members.len() == 1,
            "this member-specific operation requires a profile with exactly one administrative member"
        );
        Ok(self.administrative_members.values().next().unwrap())
    }

    pub fn administrative_connections(&self) -> Result<BTreeMap<u64, KasumiClientConfig>> {
        self.validate()?;
        let identity = self.identity.load()?;
        let trusted_ca_pem = read_file(&self.server_ca, MAX_PEM_BYTES, false)?;
        self.administrative_members
            .iter()
            .map(|(id, member)| {
                Ok((
                    *id,
                    KasumiClientConfig {
                        endpoint: member.endpoint.clone(),
                        identity: identity.clone(),
                        trusted_ca_pem: trusted_ca_pem.clone(),
                        server_certificate_pins: member
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_pin(pin))
                            .collect::<Result<_>>()?,
                    },
                ))
            })
            .collect()
    }

    pub fn connection(&self, administrative: bool) -> Result<KasumiClientConfig> {
        self.validate()?;
        if administrative {
            self.administrative_member()?;
            return Ok(self
                .administrative_connections()?
                .into_values()
                .next()
                .unwrap());
        }
        Ok(KasumiClientConfig {
            endpoint: self.native_endpoint.clone(),
            identity: self.identity.load()?,
            trusted_ca_pem: read_file(&self.server_ca, MAX_PEM_BYTES, false)?,
            server_certificate_pins: BTreeSet::from([parse_pin(&self.native_certificate_pin)?]),
        })
    }

    pub fn bearer(&self) -> Result<Zeroizing<String>> {
        self.validate()?;
        token(&FileCredentialSource::new(&self.bearer_file)?)
    }
}

fn absolute(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "client profile paths must be absolute");
    Ok(())
}

fn origin(value: &str) -> Result<()> {
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "endpoint must be an HTTPS origin without credentials, path, query, or fragment"
    );
    Ok(())
}

fn parse_pin(value: &str) -> Result<CertificatePin> {
    ensure!(
        value.len() == 64,
        "certificate pin must be a SHA-256 hex digest"
    );
    let decoded = hex::decode(value).context("invalid certificate pin hex")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid certificate pin length"))
}

fn validate_members(members: &BTreeMap<u64, ProfileAuthorityEndpoint>) -> Result<()> {
    ensure!(
        (1..=64).contains(&members.len()) && !members.contains_key(&0),
        "installed service requires one to 64 nonzero member IDs"
    );
    let mut origins = BTreeSet::new();
    for member in members.values() {
        origin(&member.endpoint)?;
        ensure!(
            origins.insert(url::Url::parse(&member.endpoint)?.to_string())
                && (1..=8).contains(&member.certificate_pins.len()),
            "installed service needs unique origins and bounded explicit pins"
        );
        for pin in &member.certificate_pins {
            parse_pin(pin)?;
        }
    }
    Ok(())
}

fn read_file(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    absolute(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(
        before.is_file(),
        "client profile input must be a regular file"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.mode() & 0o077 == 0 && before.uid() == unsafe { libc::geteuid() },
            "client profile private file must be owned by this user with owner-only permissions"
        );
    }
    ensure!(
        before.len() > 0 && before.len() <= maximum as u64,
        "client profile input exceeds byte limit"
    );
    let mut bytes = Vec::new();
    (&file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() <= maximum
            && bytes.len() as u64 == after.len()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "client profile input changed during read"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixture(directory: &Path) -> ClientProfile {
        let certificate = directory.join("client.pem");
        let private_key = directory.join("client-key.pem");
        let bearer_file = directory.join("client.token");
        private(&certificate, include_bytes!("installed-pool-test-cert.pem"));
        private(&private_key, include_bytes!("installed-pool-test-key.pem"));
        private(&bearer_file, b"first");
        ClientProfile {
            format: 2,
            family_id: Uuid::from_u128(1),
            tenant: "bpng-vault".into(),
            principal: "vault-service".into(),
            resource: CredentialResource::Database {
                incarnation: Uuid::from_u128(2),
            },
            native_endpoint: "https://localhost:9444".into(),
            administrative_members: BTreeMap::from([(
                1,
                ProfileAuthorityEndpoint {
                    endpoint: "https://localhost:9445".into(),
                    certificate_pins: BTreeSet::from(["ab".repeat(32)]),
                },
            )]),
            mcp_endpoint: "https://localhost:9443/mcp".into(),
            identity: ProfileTlsFiles {
                certificate: certificate.clone(),
                private_key,
            },
            server_ca: certificate,
            native_certificate_pin: "cd".repeat(32),
            bearer_file,
        }
    }

    #[test]
    fn exact_private_profile_bytes_bind_identity_and_refresh_the_bearer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let profile = fixture(directory.path());
        let bytes = serde_json::to_vec_pretty(&profile).unwrap();
        private(&path, &bytes);
        let (loaded, digest) = ClientProfile::load_with_sha256(&path).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(&bytes)));
        loaded
            .require_database_binding(
                "bpng-vault",
                Uuid::from_u128(2),
                "vault-service",
                Uuid::from_u128(1),
            )
            .unwrap();
        assert!(
            loaded
                .require_database_binding(
                    "bpng-vault",
                    Uuid::from_u128(2),
                    "other",
                    Uuid::from_u128(1)
                )
                .is_err()
        );
        assert!(
            loaded
                .require_database_binding(
                    "bpng-vault",
                    Uuid::from_u128(3),
                    "vault-service",
                    Uuid::from_u128(1)
                )
                .is_err()
        );
        assert_eq!(&*loaded.bearer().unwrap(), "first");
        private(&loaded.bearer_file, b"renewed");
        assert_eq!(&*loaded.bearer().unwrap(), "renewed");
        assert_eq!(
            loaded
                .connection(false)
                .unwrap()
                .server_certificate_pins
                .len(),
            1
        );
        assert_eq!(loaded.administrative_connections().unwrap().len(), 1);
    }

    #[test]
    fn profile_loader_rejects_retired_shape_and_unsafe_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let profile = fixture(directory.path());
        let mut old = serde_json::to_value(&profile).unwrap();
        old["format"] = serde_json::json!(1);
        private(&path, &serde_json::to_vec(&old).unwrap());
        assert!(ClientProfile::load(&path).is_err());
        old["format"] = serde_json::json!(2);
        old.as_object_mut().unwrap().remove("principal");
        private(&path, &serde_json::to_vec(&old).unwrap());
        assert!(ClientProfile::load(&path).is_err());
        private(&path, &serde_json::to_vec(&profile).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ClientProfile::load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("profile-link.json");
        symlink(&path, &link).unwrap();
        assert!(ClientProfile::load(&link).is_err());
    }

    #[test]
    fn database_profile_rejects_untrusted_endpoints_purpose_and_secret_files() {
        let directory = tempfile::tempdir().unwrap();
        let mut profile = fixture(directory.path());
        let expected = (
            "bpng-vault",
            Uuid::from_u128(2),
            "vault-service",
            Uuid::from_u128(1),
        );
        let connection = profile.connection(false).unwrap();
        assert_eq!(connection.endpoint, "https://localhost:9444");
        assert_eq!(
            connection.server_certificate_pins,
            BTreeSet::from([[0xcd; 32]])
        );
        assert!(!connection.trusted_ca_pem.is_empty());

        profile.native_endpoint = "http://localhost:9444".into();
        assert!(
            profile
                .require_database_binding(expected.0, expected.1, expected.2, expected.3)
                .is_err()
        );
        profile.native_endpoint = "https://localhost:9444/other".into();
        assert!(profile.connection(false).is_err());
        profile.native_endpoint = "https://localhost:9444".into();
        profile.native_certificate_pin = "invalid".into();
        assert!(profile.connection(false).is_err());
        profile.native_certificate_pin = "cd".repeat(32);
        profile.resource = CredentialResource::Control {
            incarnation: expected.1,
        };
        assert!(
            profile
                .require_database_binding(expected.0, expected.1, expected.2, expected.3)
                .is_err()
        );
        profile.resource = CredentialResource::Database {
            incarnation: Uuid::nil(),
        };
        assert!(
            profile
                .require_database_binding(expected.0, Uuid::nil(), expected.2, expected.3)
                .is_err()
        );
        profile.resource = CredentialResource::Database {
            incarnation: expected.1,
        };

        private(&profile.identity.private_key, b"not a PEM private key");
        assert!(profile.connection(false).is_err());
        private(
            &profile.identity.private_key,
            include_bytes!("installed-pool-test-key.pem"),
        );
        assert_eq!(&*profile.bearer().unwrap(), "first");
        std::fs::set_permissions(&profile.bearer_file, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(profile.bearer().is_err());
        std::fs::remove_file(&profile.bearer_file).unwrap();
        symlink(&profile.identity.certificate, &profile.bearer_file).unwrap();
        assert!(profile.bearer().is_err());
    }
}
