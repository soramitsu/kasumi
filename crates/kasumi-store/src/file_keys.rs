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
        ensure!(!self.id.is_nil(), "invalid file keyring identity");
        kasumi_types::validate_name(&self.domain).context("invalid file keyring domain")?;
        ensure!(
            self.active > 0 && self.versions.contains_key(&self.active),
            "missing active wrapping key"
        );
        ensure!(
            u64::try_from(self.versions.len())? == self.active,
            "file keyring generations are not contiguous"
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
        let bytes = private_files::read(path, MAX_KEYRING_BYTES)?;
        let ring: Keyring = serde_json::from_slice(&bytes)?;
        ring.validate()?;
        // Re-serialize into the bounded original row, never another full
        // secret-bearing buffer. Every current writer uses to_vec on Keyring.
        struct Exact<'a> {
            original: &'a [u8],
            offset: usize,
        }
        impl std::io::Write for Exact<'_> {
            fn write(&mut self, encoded: &[u8]) -> std::io::Result<usize> {
                let end = self
                    .offset
                    .checked_add(encoded.len())
                    .ok_or_else(|| std::io::Error::other("noncanonical file keyring"))?;
                if self.original.get(self.offset..end) != Some(encoded) {
                    return Err(std::io::Error::other("noncanonical file keyring"));
                }
                self.offset = end;
                Ok(encoded.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut exact = Exact {
            original: bytes.as_slice(),
            offset: 0,
        };
        serde_json::to_writer(&mut exact, &ring).context("noncanonical file keyring")?;
        ensure!(exact.offset == bytes.len(), "noncanonical file keyring");
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

    fn must_fail<T>(result: Result<T>, message: &'static str) -> anyhow::Error {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
    #[tokio::test]
    async fn file_keyring_rotation_binding_fresh_reads_and_reopen() {
        let root = crate::test_utils::private_tempdir().unwrap();
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
    async fn keyring_requires_current_writer_bytes_without_repair() -> Result<()> {
        let root = crate::test_utils::private_tempdir()?;
        let directory = root.path().join("private");
        private_files::create_directory(&directory)?;
        let path = directory.join("application.json");
        let provider = FileKeyProvider::initialize(&path, "application")?;
        let generated = provider.generate_key("tenant-a").await?;
        assert_eq!(provider.rotate()?, 2);
        let canonical = private_files::read(&path, MAX_KEYRING_BYTES)?;
        let ring = FileKeyProvider::read(&path)?;
        let writer = Zeroizing::new(serde_json::to_vec(&ring)?);
        assert!(writer.as_slice() == canonical.as_slice());

        let mut alternate = Zeroizing::new(canonical.to_vec());
        alternate.push(b' ');
        let parsed: Keyring = serde_json::from_slice(&alternate)?;
        let parsed_writer = Zeroizing::new(serde_json::to_vec(&parsed)?);
        assert!(parsed_writer.as_slice() == canonical.as_slice());
        private_files::replace(&path, alternate.as_slice())?;
        for error in [
            must_fail(FileKeyProvider::open(&path), "alternate open must fail"),
            must_fail(provider.generations(), "alternate load must fail"),
            must_fail(provider.rotate(), "alternate rotation must fail"),
            must_fail(
                provider.unwrap_key("tenant-a", &generated.wrapped).await,
                "alternate unwrap must fail",
            ),
        ] {
            assert!(
                format!("{error:#}").contains("noncanonical file keyring"),
                "{error:#}"
            );
        }
        assert!(
            private_files::read(&path, MAX_KEYRING_BYTES)?.as_slice() == alternate.as_slice(),
            "failed keyring operations repaired alternate bytes"
        );

        private_files::replace(&path, canonical.as_slice())?;
        let restored = FileKeyProvider::open(&path)?;
        assert_eq!(restored.generations()?, (2, vec![1, 2]));
        assert!(
            restored
                .unwrap_key("tenant-a", &generated.wrapped)
                .await?
                .as_bytes()
                == generated.plaintext.as_bytes(),
            "restored key differs"
        );
        assert_eq!(restored.rotate()?, 3);
        let rotated = private_files::read(&path, MAX_KEYRING_BYTES)?;
        let ring = FileKeyProvider::read(&path)?;
        let writer = Zeroizing::new(serde_json::to_vec(&ring)?);
        assert!(writer.as_slice() == rotated.as_slice());
        Ok(())
    }

    #[test]
    fn keyring_rejects_writer_impossible_domain_and_generation_gaps_without_repair() -> Result<()> {
        use zeroize::Zeroize;
        let root = crate::test_utils::private_tempdir()?;
        let directory = root.path().join("private");
        private_files::create_directory(&directory)?;
        let path = directory.join("application.json");
        let provider = FileKeyProvider::initialize(&path, "application")?;
        assert_eq!(provider.rotate()?, 2);
        let canonical = private_files::read(&path, MAX_KEYRING_BYTES)?;

        let mut invalid_domain = FileKeyProvider::read(&path)?;
        invalid_domain.domain = "invalid\ndomain".into();
        let invalid_bytes = Zeroizing::new(serde_json::to_vec(&invalid_domain)?);
        private_files::replace(&path, invalid_bytes.as_slice())?;
        let error = must_fail(FileKeyProvider::open(&path), "invalid domain must fail");
        assert!(
            format!("{error:#}").contains("invalid file keyring domain"),
            "{error:#}"
        );
        let error = must_fail(provider.rotate(), "invalid domain rotation must fail");
        assert!(
            format!("{error:#}").contains("invalid file keyring domain"),
            "{error:#}"
        );
        assert!(
            private_files::read(&path, MAX_KEYRING_BYTES)?.as_slice() == invalid_bytes.as_slice()
        );

        private_files::replace(&path, canonical.as_slice())?;
        let mut missing_generation = FileKeyProvider::read(&path)?;
        let mut removed = missing_generation.versions.remove(&1).expect("prior key");
        removed.zeroize();
        let invalid_bytes = Zeroizing::new(serde_json::to_vec(&missing_generation)?);
        private_files::replace(&path, invalid_bytes.as_slice())?;
        let error = must_fail(FileKeyProvider::open(&path), "generation gap must fail");
        assert!(
            format!("{error:#}").contains("file keyring generations are not contiguous"),
            "{error:#}"
        );
        let error = must_fail(provider.rotate(), "generation gap rotation must fail");
        assert!(
            format!("{error:#}").contains("file keyring generations are not contiguous"),
            "{error:#}"
        );
        assert!(
            private_files::read(&path, MAX_KEYRING_BYTES)?.as_slice() == invalid_bytes.as_slice()
        );

        private_files::replace(&path, canonical.as_slice())?;
        assert_eq!(
            FileKeyProvider::open(&path)?.generations()?,
            (2, vec![1, 2])
        );
        Ok(())
    }

    #[tokio::test]
    async fn standalone_catalog_binds_installation_tenant_and_generation() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        use crate::{NodeStore, StorageAccess, TenantStore, WriteOp};
        use std::sync::Arc;
        let root = crate::test_utils::private_tempdir().unwrap();
        let private = root.path().join("private");
        private_files::create_directory(&private).unwrap();
        let provider = Arc::new(
            FileKeyProvider::initialize(&private.join("key.json"), "application").unwrap(),
        );
        let node = NodeStore::create_new_fixture(
            root.path().join("db"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap();
        let installation = Uuid::new_v4();
        let incarnation = Uuid::new_v4();
        let access = StorageAccess::standalone(installation, "tenant", incarnation).unwrap();
        let store = TenantStore::initialize_catalog_fixture_with_access(
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
            TenantStore::open_existing_fixture_with_access(
                node.clone(),
                "tenant".into(),
                provider.clone(),
                StorageAccess::fixture()
            )
            .await
            .is_err()
        );
        assert!(
            TenantStore::open_existing_fixture_with_access(
                node.clone(),
                "tenant".into(),
                provider.clone(),
                StorageAccess::standalone(Uuid::new_v4(), "tenant", incarnation).unwrap()
            )
            .await
            .is_err()
        );
        drop(store);
        let reopened = TenantStore::open_existing_fixture_with_access(
            node.clone(),
            "tenant".into(),
            provider.clone(),
            access,
        )
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
        let root = crate::test_utils::private_tempdir().unwrap();
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
