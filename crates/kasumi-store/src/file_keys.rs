//! Production local key wrapping for a trusted host. Every unwrap rereads the
//! installed keyring; rotations never rely on a constructor-time secret cache.
use crate::{GeneratedKey, KeyProvider, SecretKey, WrappedKey, decrypt, encrypt, private_files};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_KEYRING_BYTES: usize = 1 << 20;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyring {
    format: u32,
    id: Uuid,
    domain: String,
    active: u64,
    versions: BTreeMap<u64, String>,
}
impl Drop for Keyring {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for key in self.versions.values_mut() {
            key.zeroize();
        }
    }
}
impl Keyring {
    fn validate(&self) -> Result<()> {
        ensure!(self.format == 1, "unsupported file keyring format");
        ensure!(
            !self.id.is_nil() && !self.domain.is_empty(),
            "invalid file keyring identity"
        );
        ensure!(
            self.active > 0 && self.versions.contains_key(&self.active),
            "missing active wrapping key"
        );
        for (version, key) in &self.versions {
            ensure!(
                *version > 0 && *version <= self.active,
                "invalid wrapping key generation"
            );
            ensure!(
                Zeroizing::new(STANDARD.decode(key)?).len() == 32,
                "invalid wrapping key size"
            );
        }
        Ok(())
    }
    fn key_ref(&self) -> String {
        format!("kasumi.file-key/{}/{}", self.id, self.domain)
    }
    fn key(&self, version: u64) -> Result<SecretKey> {
        let bytes = Zeroizing::new(
            STANDARD.decode(
                self.versions
                    .get(&version)
                    .context("wrapping key generation unavailable")?,
            )?,
        );
        let mut fixed = Zeroizing::new([0; 32]);
        ensure!(bytes.len() == fixed.len(), "invalid wrapping key size");
        fixed.copy_from_slice(&bytes);
        Ok(SecretKey::from_bytes(*fixed))
    }
}

pub struct FileKeyProvider {
    path: PathBuf,
    key_ref: String,
}
impl FileKeyProvider {
    pub fn initialize(path: &Path, domain: &str) -> Result<Self> {
        kasumi_types::validate_name(domain)?;
        let ring = Keyring {
            format: 1,
            id: Uuid::new_v4(),
            domain: domain.into(),
            active: 1,
            versions: BTreeMap::from([(1, STANDARD.encode(SecretKey::random()?.as_bytes()))]),
        };
        private_files::create(path, &Zeroizing::new(serde_json::to_vec(&ring)?))?;
        Self::open(path)
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ensure!(path.is_absolute(), "file keyring path must be absolute");
        private_files::check_directory(path.parent().context("keyring has no parent")?)?;
        let ring = Self::read(path)?;
        Ok(Self {
            path: path.into(),
            key_ref: ring.key_ref(),
        })
    }
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }
    fn read(path: &Path) -> Result<Keyring> {
        let ring: Keyring = serde_json::from_slice(&private_files::read(path, MAX_KEYRING_BYTES)?)?;
        ring.validate()?;
        Ok(ring)
    }
    fn load(&self) -> Result<Keyring> {
        let ring = Self::read(&self.path)?;
        ensure!(
            ring.key_ref() == self.key_ref,
            "installed wrapping key identity changed"
        );
        Ok(ring)
    }
    /// Retains every previous generation for existing catalogs and completed
    /// backups. Removing keys requires an independently verified dependency inventory.
    pub fn rotate(&self) -> Result<u64> {
        let _lock = private_files::ExclusiveLock::acquire(&self.path.with_extension("lock"))?;
        let mut ring = self.load()?;
        ring.active = ring
            .active
            .checked_add(1)
            .context("wrapping generation exhausted")?;
        ring.versions.insert(
            ring.active,
            STANDARD.encode(SecretKey::random()?.as_bytes()),
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&ring)?);
        ensure!(
            bytes.len() <= MAX_KEYRING_BYTES,
            "keyring storage budget exceeded"
        );
        private_files::replace(&self.path, &bytes)?;
        Ok(ring.active)
    }
    pub fn generations(&self) -> Result<(u64, Vec<u64>)> {
        let ring = self.load()?;
        Ok((ring.active, ring.versions.keys().copied().collect()))
    }
    fn aad(&self, tenant: &str, version: u64) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(1u32, &self.key_ref, tenant, version))?)
    }
    fn wrap(&self, ring: &Keyring, tenant: &str, key: &SecretKey) -> Result<WrappedKey> {
        Ok(WrappedKey {
            provider: "file".into(),
            key_ref: self.key_ref.clone(),
            version: ring.active,
            ciphertext: STANDARD.encode(encrypt(
                &ring.key(ring.active)?,
                key.as_bytes(),
                &self.aad(tenant, ring.active)?,
            )?),
            context: Some(tenant.into()),
        })
    }
    fn unwrap(&self, ring: &Keyring, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        ensure!(
            wrapped.provider == "file"
                && wrapped.key_ref == self.key_ref
                && wrapped.context.as_deref() == Some(tenant),
            "wrapped file key resource mismatch"
        );
        let bytes = Zeroizing::new(decrypt(
            &ring.key(wrapped.version)?,
            &STANDARD.decode(&wrapped.ciphertext)?,
            &self.aad(tenant, wrapped.version)?,
        )?);
        ensure!(bytes.len() == 32, "invalid data key size");
        let mut fixed = Zeroizing::new([0; 32]);
        fixed.copy_from_slice(&bytes);
        Ok(SecretKey::from_bytes(*fixed))
    }
}
#[async_trait]
impl KeyProvider for FileKeyProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        let ring = self.load()?;
        let plaintext = SecretKey::random()?;
        Ok(GeneratedKey {
            wrapped: self.wrap(&ring, tenant, &plaintext)?,
            plaintext,
        })
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.unwrap(&self.load()?, tenant, wrapped)
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        let ring = self.load()?;
        self.wrap(&ring, tenant, &self.unwrap(&ring, tenant, wrapped)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn file_keyring_rotation_binding_fresh_reads_and_reopen() {
        let root = tempfile::tempdir().unwrap();
        let dir_path = root.path().join("private");
        private_files::create_directory(&dir_path).unwrap();
        let dir = dir_path.as_path();
        let path = dir.join("application.json");
        let provider = FileKeyProvider::initialize(&path, "application").unwrap();
        let generated = provider.generate_key("tenant-a").await.unwrap();
        assert!(
            provider
                .unwrap_key("tenant-b", &generated.wrapped)
                .await
                .is_err()
        );
        let custody = FileKeyProvider::initialize(&dir.join("custody.json"), "custody").unwrap();
        assert!(
            custody
                .unwrap_key("tenant-a", &generated.wrapped)
                .await
                .is_err()
        );
        assert_eq!(provider.rotate().unwrap(), 2);
        let wrapped = provider
            .rewrap_key("tenant-a", &generated.wrapped)
            .await
            .unwrap();
        assert_eq!(wrapped.version, 2);
        let reopened = FileKeyProvider::open(&path).unwrap();
        assert_eq!(
            reopened
                .unwrap_key("tenant-a", &wrapped)
                .await
                .unwrap()
                .as_bytes(),
            generated.plaintext.as_bytes()
        );
        let mut tampered = wrapped.clone();
        tampered.version = 1;
        assert!(provider.unwrap_key("tenant-a", &tampered).await.is_err());
        std::fs::remove_file(path).unwrap();
        assert!(provider.unwrap_key("tenant-a", &wrapped).await.is_err());
    }
    #[tokio::test]
    async fn standalone_catalog_binds_installation_tenant_and_generation() {
        use crate::{NodeStore, StorageAccess, TenantStore, WriteOp};
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        private_files::create_directory(&private).unwrap();
        let provider = Arc::new(
            FileKeyProvider::initialize(&private.join("key.json"), "application").unwrap(),
        );
        let node = NodeStore::open(root.path().join("db")).unwrap();
        let installation = Uuid::new_v4();
        let incarnation = Uuid::new_v4();
        let access = StorageAccess::standalone(installation, "tenant", incarnation).unwrap();
        let store = TenantStore::open(
            node.clone(),
            "tenant".into(),
            provider.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        store
            .write_batch(&[WriteOp::put("docs", b"a", b"private")])
            .unwrap();
        assert!(
            TenantStore::open(
                node.clone(),
                "tenant".into(),
                provider.clone(),
                StorageAccess::fixture()
            )
            .await
            .is_err()
        );
        assert!(
            TenantStore::open(
                node.clone(),
                "tenant".into(),
                provider.clone(),
                StorageAccess::standalone(Uuid::new_v4(), "tenant", incarnation).unwrap()
            )
            .await
            .is_err()
        );
        drop(store);
        let reopened = TenantStore::open(node.clone(), "tenant".into(), provider.clone(), access)
            .await
            .unwrap();
        assert_eq!(
            reopened.get("docs", b"a").unwrap(),
            Some(b"private".to_vec())
        );
        assert!(StorageAccess::standalone(installation, "__kasumi_control", incarnation).is_err());
        assert!(StorageAccess::standalone(Uuid::nil(), "tenant", incarnation).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_public_keyrings_symlinks_and_unsupported_formats() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let dir_path = root.path().join("private");
        private_files::create_directory(&dir_path).unwrap();
        let dir = dir_path.as_path();
        let path = dir.join("keys.json");
        FileKeyProvider::initialize(&path, "application").unwrap();
        let alias = dir.join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!(FileKeyProvider::open(alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileKeyProvider::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut ring = FileKeyProvider::read(&path).unwrap();
        ring.format = 2;
        private_files::replace(&path, &serde_json::to_vec(&ring).unwrap()).unwrap();
        assert!(FileKeyProvider::open(&path).is_err());
    }
}
