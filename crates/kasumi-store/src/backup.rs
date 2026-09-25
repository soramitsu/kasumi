//! Logical backup encryption is independent of Raft's node identity and log state.
//! The caller captures a committed logical snapshot and must restore into a new,
//! suspended incarnation before admitting traffic. This layer never installs data.

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AccessGuard, AdmittedKeyCatalog, DiskMemoryLease, KeyCatalog, KeyProvider, MAX_KEY_LEASE,
    NodeDiskMemoryAdmission, PROVIDER_TIMEOUT, SecretKey, TenantStore, decrypt,
};
use kasumi_clock::{LeaseClock, SystemLeaseClock};

#[path = "backup_sessions_s3.rs"]
mod sessions_s3;

const FORMAT: u32 = 1;
pub(crate) const HEADER_LIMIT: usize = 2 * 1024 * 1024;
pub const MAX_BACKUP_OBJECT_BYTES: usize = 32 * 1024 * 1024;
/// Header + digest + nonce/tag + fixed framing above a maximum snapshot.
pub const MAX_BACKUP_BUNDLE_BYTES: usize = MAX_BACKUP_OBJECT_BYTES + HEADER_LIMIT + 84;
const MAGIC: &[u8; 8] = b"KASUMIB1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    backup_id: Uuid,
    tenant: String,
    revision: u64,
    plaintext_bytes: u64,
    catalog: KeyCatalog,
}

/// An opaque, authenticated encrypted logical snapshot. Metadata and retained
/// wrapped-key dependencies are authenticated as AEAD associated data.
pub struct EncryptedBackup {
    manifest: Manifest,
    // Decoded/related manifests and directly cloned catalogs drop before this lease.
    _catalog_charge: Option<DiskMemoryLease>,
    ciphertext: Zeroizing<Vec<u8>>,
    // Every ciphertext buffer is wiped and freed before its installed lease.
    _ciphertext_charge: DiskMemoryLease,
    memory_owner: Arc<dyn NodeDiskMemoryAdmission>,
}

/// One exact-owner serialized backup object. The byte allocation is retired
/// before its installed memory lease, including when an async upload is
/// cancelled after the body has taken ownership of the object.
pub struct AdmittedBackupBundle {
    bytes: Zeroizing<Vec<u8>>,
    _charge: DiskMemoryLease,
    memory_owner: Arc<dyn NodeDiskMemoryAdmission>,
}

/// Preserves the installed owner's failure kind across an `anyhow` boundary.
/// Capacity denial is distinct from a failed owner or reservation identity.
#[derive(Debug)]
pub struct BackupBundleAdmissionError(std::io::Error);

impl BackupBundleAdmissionError {
    pub fn kind(&self) -> std::io::ErrorKind {
        self.0.kind()
    }
}

impl From<std::io::Error> for BackupBundleAdmissionError {
    fn from(error: std::io::Error) -> Self {
        Self(error)
    }
}

impl std::fmt::Display for BackupBundleAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "backup bundle output admission denied: {}",
            self.0
        )
    }
}

impl std::error::Error for BackupBundleAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl std::fmt::Debug for AdmittedBackupBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedBackupBundle")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl AdmittedBackupBundle {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn try_clone(&self) -> Result<Self> {
        Self::copy_from(self.as_bytes(), &self.memory_owner)
    }

    fn copy_from(bytes: &[u8], owner: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<Self> {
        let allocation = crate::disk_memory::allocation::<u8>(u64::try_from(bytes.len())?)?;
        let charge = owner
            .clone()
            .reserve_installed(allocation)
            .map_err(BackupBundleAdmissionError::from)?;
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(bytes.len())
            .context("backup bundle allocation failed")?;
        ensure!(
            u64::try_from(output.capacity())? <= allocation,
            "backup bundle allocation exceeds admission"
        );
        output.extend_from_slice(bytes);
        Ok(Self {
            bytes: output,
            _charge: charge,
            memory_owner: owner.clone(),
        })
    }
}

impl AsRef<[u8]> for AdmittedBackupBundle {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::ops::Deref for AdmittedBackupBundle {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

/// Upload bytes are either newly serialized with retained installed memory
/// admission, or received from an existing destination/audit archive. The
/// latter path does not claim admission for that upstream read allocation.
pub enum BackupUpload {
    Generated(AdmittedBackupBundle),
    Received(Vec<u8>),
}

impl BackupUpload {
    pub fn received(bytes: Vec<u8>) -> Self {
        Self::Received(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Generated(bundle) => bundle.as_bytes(),
            Self::Received(bytes) => bytes,
        }
    }

    fn into_http_body(self) -> reqwest::Body {
        match self {
            Self::Generated(bundle) => reqwest::Body::from(bytes::Bytes::from_owner(bundle)),
            Self::Received(bytes) => reqwest::Body::from(bytes),
        }
    }
}

impl From<AdmittedBackupBundle> for BackupUpload {
    fn from(bundle: AdmittedBackupBundle) -> Self {
        Self::Generated(bundle)
    }
}

impl AsRef<[u8]> for BackupUpload {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::ops::Deref for BackupUpload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

pub struct BackupContents {
    pub backup_id: Uuid,
    pub source_tenant: String,
    pub source_purpose: crate::StoragePurpose,
    pub revision: u64,
    pub snapshot: Zeroizing<Vec<u8>>,
    /// Digests returned only after complete authenticated object/key verification.
    pub ciphertext_sha256: String,
    pub key_catalog_sha256: String,
}

impl TenantStore {
    /// The service supplies a logical snapshot containing documents, definitions,
    /// receipts, and policy from one committed generation. No raw Raft identity is
    /// imported by this API. Every resident key version is included as a dependency.
    pub fn encrypt_backup(&self, revision: u64, snapshot: &[u8]) -> Result<EncryptedBackup> {
        self.encrypt_backup_with_id(Uuid::new_v4(), revision, snapshot)
    }
    /// A session's root uses the identity durably chosen before its first upload.
    pub fn encrypt_backup_with_id(
        &self,
        id: Uuid,
        revision: u64,
        snapshot: &[u8],
    ) -> Result<EncryptedBackup> {
        ensure!(!id.is_nil(), "nil backup object identity");
        let _access = AccessGuard(self);
        self.check_access()?;
        ensure!(
            snapshot.len() <= MAX_BACKUP_OBJECT_BYTES,
            "backup object exceeds record budget"
        );
        let state = self.state.read();
        self.require_access(&state)?;
        let tenant = self.tenant.clone();
        let admitted = {
            let current = self.catalog.read();
            AdmittedKeyCatalog::clone_for_backup(&current, self.scratch_disk().memory().clone())?
        };
        let key = state
            .keys
            .get(&admitted.active)
            .context("backup data key missing")?;
        let (catalog, catalog_charge) = admitted.into_parts();
        let manifest = Manifest {
            format: FORMAT,
            backup_id: id,
            tenant,
            revision,
            plaintext_bytes: snapshot.len() as u64,
            catalog,
        };
        let memory_owner = self.scratch_disk().memory().clone();
        let aad = manifest_bytes(&manifest, &memory_owner)?;
        let ciphertext_charge = reserve_backup_ciphertext(snapshot.len(), &memory_owner)?;
        // Keep this lease live through encryption and then in the returned object.
        let ciphertext = encrypt_backup_ciphertext(key, snapshot, &aad.bytes)?;
        self.require_access(&state)?;
        Ok(EncryptedBackup {
            manifest,
            _catalog_charge: catalog_charge,
            ciphertext,
            _ciphertext_charge: ciphertext_charge,
            memory_owner,
        })
    }
}

impl EncryptedBackup {
    /// Reuse authenticated historical wrapping dependencies and source purpose
    /// for a session outcome written by another currently authorized replica.
    pub(crate) async fn encrypt_related(
        &self,
        snapshot: &[u8],
        provider: Arc<dyn KeyProvider>,
        owner: &TenantStore,
    ) -> Result<Self> {
        ensure!(
            snapshot.len() <= crate::MAX_SESSION_RECORD_BYTES,
            "session outcome exceeds limit"
        );
        owner.check_access()?;
        ensure!(
            owner.tenant() == self.source_tenant(),
            "backup source tenant differs from installed owner"
        );
        self.check_memory_owner(owner)?;
        let charge = AdmittedKeyCatalog::admit_backup_manifest_clone(
            &self.manifest,
            self.manifest.catalog.keys.len(),
            owner.scratch_disk().memory().clone(),
        )?;
        let mut manifest = self.manifest.clone();
        manifest.backup_id = Uuid::new_v4();
        manifest.plaintext_bytes = snapshot.len() as u64;
        let aad = manifest_bytes(&manifest, &self.memory_owner)?;
        let ciphertext_charge = reserve_backup_ciphertext(snapshot.len(), &self.memory_owner)?;
        self.decrypt(self.source_tenant(), provider.clone(), owner)
            .await?;
        let wrapped = self
            .manifest
            .catalog
            .keys
            .get(&self.manifest.catalog.active)
            .context("session source key missing")?;
        let key = tokio::time::timeout(
            PROVIDER_TIMEOUT,
            provider.unwrap_key(self.source_tenant(), wrapped),
        )
        .await
        .context("session source key authorization timed out")??;
        owner.check_access()?;
        // The earlier exact-owner lease remains live across provider calls.
        let ciphertext = encrypt_backup_ciphertext(&key, snapshot, &aad.bytes)?;
        owner.check_access()?;
        Ok(Self {
            manifest,
            _catalog_charge: Some(charge),
            ciphertext,
            _ciphertext_charge: ciphertext_charge,
            memory_owner: self.memory_owner.clone(),
        })
    }
    fn check_memory_owner(&self, owner: &TenantStore) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.memory_owner, owner.scratch_disk().memory()),
            "backup memory owner differs from installed target"
        );
        Ok(())
    }
    pub fn id(&self) -> Uuid {
        self.manifest.backup_id
    }
    pub fn source_purpose(&self) -> &crate::StoragePurpose {
        &self.manifest.catalog.purpose
    }
    pub fn source_tenant(&self) -> &str {
        &self.manifest.tenant
    }
    pub fn revision(&self) -> u64 {
        self.manifest.revision
    }

    pub fn to_bytes(&self) -> Result<AdmittedBackupBundle> {
        let header = manifest_bytes(&self.manifest, &self.memory_owner)?;
        let length = 12usize
            .checked_add(header.bytes.len())
            .and_then(|len| len.checked_add(self.ciphertext.len()))
            .context("backup bundle length overflow")?;
        let allocation = crate::disk_memory::allocation::<u8>(u64::try_from(length)?)?;
        let charge = self
            .memory_owner
            .clone()
            .reserve_installed(allocation)
            .map_err(BackupBundleAdmissionError::from)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .context("backup bundle allocation failed")?;
        ensure!(
            u64::try_from(bytes.capacity())? <= allocation,
            "backup bundle allocation exceeds admission"
        );
        bytes.extend(MAGIC);
        bytes.extend((header.bytes.len() as u32).to_be_bytes());
        bytes.extend(&header.bytes);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(AdmittedBackupBundle {
            bytes,
            _charge: charge,
            memory_owner: self.memory_owner.clone(),
        })
    }

    /// Parse bounded input without contacting a key service. Metadata is not
    /// trusted until `decrypt` authenticates it.
    pub fn from_bytes(
        bytes: &[u8],
        max_snapshot_bytes: usize,
        owner: &TenantStore,
    ) -> Result<Self> {
        owner.check_access()?;
        ensure!(
            bytes.len() >= 12 && &bytes[..8] == MAGIC,
            "invalid backup magic"
        );
        let header_len = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(
            header_len <= HEADER_LIMIT && bytes.len() >= 12 + header_len,
            "invalid backup header length"
        );
        let header = &bytes[12..12 + header_len];
        let charge = AdmittedKeyCatalog::admit_backup_manifest_decode(
            header,
            owner.scratch_disk().memory().clone(),
        )?;
        let manifest: Manifest =
            serde_json::from_slice(header).context("invalid backup manifest")?;
        ensure!(manifest.format == FORMAT, "unsupported backup format");
        ensure!(
            manifest.tenant == owner.tenant(),
            "backup tenant differs from installed owner"
        );
        manifest.catalog.validate(&manifest.tenant)?;
        ensure!(
            manifest.plaintext_bytes <= max_snapshot_bytes.min(MAX_BACKUP_OBJECT_BYTES) as u64,
            "backup exceeds snapshot byte limit"
        );
        let ciphertext = &bytes[12 + header_len..];
        // 32-byte internal digest, 24-byte nonce and 16-byte authentication tag.
        ensure!(
            ciphertext.len() as u64 == manifest.plaintext_bytes + 72,
            "backup ciphertext length mismatch"
        );
        let canonical = manifest_bytes(&manifest, owner.scratch_disk().memory())?;
        ensure!(canonical.bytes == header, "noncanonical backup manifest");
        drop(canonical);
        let copy_bytes = crate::disk_memory::allocation::<u8>(u64::try_from(ciphertext.len())?)?;
        let ciphertext_charge = owner
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(copy_bytes)
            .context("backup ciphertext copy admission denied")?;
        Ok(Self {
            manifest,
            _catalog_charge: Some(charge),
            ciphertext: Zeroizing::new(ciphertext.to_vec()),
            _ciphertext_charge: ciphertext_charge,
            memory_owner: owner.scratch_disk().memory().clone(),
        })
    }

    pub async fn decrypt(
        &self,
        source_tenant: &str,
        provider: Arc<dyn KeyProvider>,
        owner: &TenantStore,
    ) -> Result<BackupContents> {
        self.check_memory_owner(owner)?;
        self.decrypt_with_clock(
            source_tenant,
            provider,
            &SystemLeaseClock,
            owner.storage_access(),
        )
        .await
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn decrypt_fixture(
        &self,
        tenant: &str,
        provider: Arc<dyn KeyProvider>,
        owner: &TenantStore,
    ) -> Result<BackupContents> {
        self.decrypt(tenant, provider, owner).await
    }

    async fn decrypt_with_clock(
        &self,
        source_tenant: &str,
        provider: Arc<dyn KeyProvider>,
        clock: &dyn LeaseClock,
        access: &crate::StorageAccess,
    ) -> Result<BackupContents> {
        access.validate_tenant(source_tenant)?;
        ensure!(
            self.manifest.tenant == source_tenant,
            "backup source tenant mismatch"
        );
        self.manifest.catalog.validate(source_tenant)?;
        let aad = manifest_bytes(&self.manifest, &self.memory_owner)?;
        let start = clock.now();
        let keys = tokio::time::timeout(PROVIDER_TIMEOUT, async {
            let mut keys = std::collections::BTreeMap::new();
            for (id, wrapped) in &self.manifest.catalog.keys {
                access.check()?;
                keys.insert(
                    id.clone(),
                    provider.unwrap_key(source_tenant, wrapped).await?,
                );
                access.check()?;
            }
            Ok::<_, anyhow::Error>(keys)
        })
        .await
        .context("backup key authorization timed out")??;
        let deadline = start
            .checked_add(MAX_KEY_LEASE)
            .context("backup key lease overflow")?;
        ensure!(clock.now() < deadline, "backup key authorization expired");
        access.check()?;
        let key = keys
            .get(&self.manifest.catalog.active)
            .context("backup key missing")?;
        let mut plaintext = Zeroizing::new(decrypt(key, &self.ciphertext, &aad.bytes)?);
        ensure!(plaintext.len() >= 32, "invalid backup integrity record");
        let digest = Sha256::digest(&plaintext[32..]);
        ensure!(
            digest.as_slice() == &plaintext[..32],
            "backup integrity digest mismatch"
        );
        ensure!(
            plaintext.len() as u64 == self.manifest.plaintext_bytes + 32,
            "backup snapshot size mismatch"
        );
        plaintext.drain(..32);
        ensure!(
            clock.now() < deadline,
            "backup key authorization expired before release"
        );
        let mut ciphertext_digest = Sha256::new();
        ciphertext_digest.update(MAGIC);
        ciphertext_digest.update((aad.bytes.len() as u32).to_be_bytes());
        ciphertext_digest.update(&aad.bytes);
        ciphertext_digest.update(self.ciphertext.as_slice());
        let ciphertext_sha256 = hex::encode(ciphertext_digest.finalize());
        let key_catalog_sha256 =
            hex::encode(Sha256::digest(serde_json::to_vec(&self.manifest.catalog)?));
        access.check()?;
        ensure!(
            clock.now() < deadline,
            "backup key authorization expired before digest release"
        );
        Ok(BackupContents {
            backup_id: self.id(),
            source_tenant: source_tenant.into(),
            source_purpose: self.source_purpose().clone(),
            revision: self.revision(),
            snapshot: plaintext,
            ciphertext_sha256,
            key_catalog_sha256,
        })
    }
}

fn backup_ciphertext_len(snapshot_len: usize) -> Result<usize> {
    snapshot_len
        .checked_add(72) // 24-byte nonce, 32-byte digest, 16-byte tag.
        .context("backup ciphertext length overflow")
}

fn reserve_backup_ciphertext(
    snapshot_len: usize,
    owner: &Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<DiskMemoryLease> {
    let allocation =
        crate::disk_memory::allocation::<u8>(u64::try_from(backup_ciphertext_len(snapshot_len)?)?)?;
    owner
        .clone()
        .reserve_installed(allocation)
        .context("backup ciphertext output admission denied")
}

/// Fill one pre-admitted buffer in the same nonce/ciphertext/tag format as
/// encrypted records. The caller keeps its installed lease until this buffer
/// has been zeroized and freed.
fn encrypt_backup_ciphertext(
    key: &SecretKey,
    snapshot: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let length = backup_ciphertext_len(snapshot.len())?;
    let admitted_bytes = crate::disk_memory::allocation::<u8>(u64::try_from(length)?)?;
    let mut ciphertext = Zeroizing::new(Vec::new());
    ciphertext
        .try_reserve_exact(length)
        .context("backup ciphertext allocation failed")?;
    ensure!(
        u64::try_from(ciphertext.capacity())? <= admitted_bytes,
        "backup ciphertext allocation exceeds admission"
    );
    ciphertext.resize(length, 0);
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    ciphertext[..24].copy_from_slice(&nonce);
    ciphertext[24..56].copy_from_slice(&Sha256::digest(snapshot));
    let tag_start = 56 + snapshot.len();
    ciphertext[56..tag_start].copy_from_slice(snapshot);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            aad,
            &mut ciphertext[24..tag_start],
        )
        .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
    ciphertext[tag_start..].copy_from_slice(&tag);
    Ok(ciphertext)
}

struct AdmittedManifestBytes {
    bytes: Vec<u8>,
    // The serialized bytes drop before their installed allocation lease.
    _charge: DiskMemoryLease,
}

struct ManifestByteCount(usize);

impl std::io::Write for ManifestByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= HEADER_LIMIT)
            .ok_or_else(|| std::io::Error::other("backup manifest too large"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ManifestWriter<'a> {
    bytes: &'a mut Vec<u8>,
    admitted_len: usize,
}

impl std::io::Write for ManifestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= self.admitted_len)
            .ok_or_else(|| std::io::Error::other("backup manifest changed after admission"))?;
        self.bytes.extend_from_slice(bytes);
        debug_assert_eq!(self.bytes.len(), next);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn manifest_bytes(
    manifest: &Manifest,
    owner: &Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<AdmittedManifestBytes> {
    let mut count = ManifestByteCount(0);
    serde_json::to_writer(&mut count, manifest).context("backup manifest too large")?;
    let required = crate::disk_memory::allocation::<u8>(u64::try_from(count.0)?)?;
    let charge = owner
        .clone()
        .reserve_installed(required)
        .context("backup manifest serialization admission denied")?;
    let mut bytes = Vec::with_capacity(count.0);
    serde_json::to_writer(
        ManifestWriter {
            bytes: &mut bytes,
            admitted_len: count.0,
        },
        manifest,
    )
    .context("backup manifest serialization changed after admission")?;
    ensure!(
        bytes.len() == count.0,
        "backup manifest serialization changed after admission"
    );
    Ok(AdmittedManifestBytes {
        bytes,
        _charge: charge,
    })
}

#[async_trait]
pub trait BackupDestination: Send + Sync {
    /// Publishing is create-only: an existing backup must never be overwritten.
    async fn put(&self, id: Uuid, encrypted: BackupUpload) -> Result<()>;
    /// Enforce the caller's expected object bound before allocation and while
    /// reading, in addition to the destination's configured maximum.
    async fn get(&self, id: Uuid, max_bytes: usize) -> Result<Vec<u8>>;
    /// Full-backup sessions require explicit managed storage capabilities.
    async fn session_put(
        &self,
        _session: Uuid,
        _slot: crate::BackupSessionSlot,
        _encrypted: BackupUpload,
    ) -> Result<()> {
        anyhow::bail!("backup destination lacks managed session storage")
    }
    async fn session_get(
        &self,
        _session: Uuid,
        _slot: crate::BackupSessionSlot,
        _max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        anyhow::bail!("backup destination lacks managed session storage")
    }
    async fn session_objects(
        &self,
        _aborted: &crate::VerifiedBackupAbort,
        _limit: usize,
    ) -> Result<crate::BackupSessionObjectPage> {
        anyhow::bail!("backup destination lacks managed session reclamation")
    }
    async fn session_delete(
        &self,
        _aborted: &crate::VerifiedBackupAbort,
        _objects: &[crate::BackupSessionObject],
    ) -> Result<()> {
        anyhow::bail!("backup destination lacks managed session reclamation")
    }
}

pub struct FilesystemBackupDestination {
    root: PathBuf,
    disk: Arc<crate::NodeDisk>,
    sessions: Arc<crate::backup_sessions::filesystem::Directory>,
    max_bytes: usize,
}
impl FilesystemBackupDestination {
    pub fn new(
        root: impl AsRef<Path>,
        max_bytes: usize,
        disk: Arc<crate::NodeDisk>,
    ) -> Result<Self> {
        ensure!(max_bytes > 0, "backup byte limit must be positive");
        let root = root.as_ref().to_owned();
        let sessions = Arc::new(
            crate::backup_sessions::filesystem::Directory::open_or_create(&root, disk.clone())?,
        );
        Ok(Self {
            root,
            disk,
            sessions,
            max_bytes,
        })
    }
    fn path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.kasumi"))
    }
}

#[async_trait]
impl BackupDestination for FilesystemBackupDestination {
    async fn session_put(
        &self,
        session: Uuid,
        slot: crate::BackupSessionSlot,
        encrypted: BackupUpload,
    ) -> Result<()> {
        ensure!(
            encrypted.len() <= self.max_bytes,
            "backup exceeds destination byte limit"
        );
        let root = self.sessions.clone();
        tokio::task::spawn_blocking(move || root.put(session, slot, &encrypted)).await?
    }
    async fn session_get(
        &self,
        session: Uuid,
        slot: crate::BackupSessionSlot,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        let root = self.sessions.clone();
        let limit = max_bytes.min(self.max_bytes);
        tokio::task::spawn_blocking(move || root.get(session, slot, limit)).await?
    }
    async fn session_objects(
        &self,
        aborted: &crate::VerifiedBackupAbort,
        limit: usize,
    ) -> Result<crate::BackupSessionObjectPage> {
        let root = self.sessions.clone();
        let proof = aborted.clone();
        tokio::task::spawn_blocking(move || root.list(&proof, limit)).await?
    }
    async fn session_delete(
        &self,
        aborted: &crate::VerifiedBackupAbort,
        objects: &[crate::BackupSessionObject],
    ) -> Result<()> {
        ensure!(
            objects.len() <= crate::MAX_SESSION_GC_OBJECTS,
            "backup cleanup exceeds page limit"
        );
        let root = self.sessions.clone();
        let proof = aborted.clone();
        let objects = objects.to_vec();
        tokio::task::spawn_blocking(move || root.delete(&proof, &objects)).await?
    }
    async fn put(&self, id: Uuid, encrypted: BackupUpload) -> Result<()> {
        ensure!(
            encrypted.len() <= self.max_bytes,
            "backup exceeds destination byte limit"
        );
        let root = self.sessions.clone();
        tokio::task::spawn_blocking(move || root.put_backup(id, &encrypted)).await?
    }

    async fn get(&self, id: Uuid, max_bytes: usize) -> Result<Vec<u8>> {
        let path = self.path(id);
        let disk = self.disk.clone();
        let limit = self.max_bytes.min(max_bytes);
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let (root, relative) = disk.binding(&path)?;
            let file = disk.open_file(root, relative)?;
            let length = file.observed_len()?;
            ensure!(
                length <= limit as u64,
                "backup exceeds destination byte limit"
            );
            let mut result = vec![0; usize::try_from(length)?];
            file.read_exact_at(&mut result, 0)?;
            file.sync_all_and_parent()?;
            Ok(result)
        })
        .await?
    }
}

/// Runtime-only SigV4 credentials. Neither credentials nor bearer sessions are
/// serialized. Only HTTPS origins and TLS 1.3 are accepted.
pub struct S3BackupConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub credential: Arc<dyn kasumi_transport::credentials::CredentialSource>,
    pub ca_pem: Option<Vec<u8>>,
    pub max_bytes: usize,
}

pub struct S3BackupDestination {
    endpoint: Url,
    region: String,
    bucket: String,
    prefix: String,
    credential: Arc<dyn kasumi_transport::credentials::CredentialSource>,
    max_bytes: usize,
    client: Client,
}

/// One atomic SigV4 bundle. Every request loads all fields from the same inode.
/// Unknown fields are rejected and every owned secret is wiped on drop.
#[derive(Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct S3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}
impl S3Credentials {
    fn load(source: &dyn kasumi_transport::credentials::CredentialSource) -> Result<Self> {
        let bytes = source.load()?;
        let value: Self = serde_json::from_str(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid S3 credential bundle"))?;
        ensure!(
            !value.access_key_id.is_empty()
                && !value.secret_access_key.is_empty()
                && value
                    .access_key_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric())
                && value
                    .secret_access_key
                    .bytes()
                    .all(|b| b.is_ascii_graphic()),
            "invalid S3 credential bundle"
        );
        if let Some(token) = &value.session_token {
            ensure!(
                !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic()),
                "invalid S3 session token"
            );
        }
        Ok(value)
    }
}
impl S3BackupDestination {
    pub(crate) fn namespace_identity(&self) -> String {
        format!(
            "s3:{}:{}:{}:{}",
            self.endpoint, self.region, self.bucket, self.prefix
        )
    }
    /// Physical session identity excludes renewable credentials and trust files.
    /// The constructor validates that every installed destination can yield it.
    pub fn namespace_binding(&self) -> Result<kasumi_types::BackupNamespaceBinding> {
        let binding = kasumi_types::BackupNamespaceBinding::S3 {
            https_origin: self.endpoint.as_str().to_owned(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }
    pub fn new(config: S3BackupConfig) -> Result<Self> {
        ensure!(
            config.endpoint.len() <= 2048,
            "S3 endpoint exceeds binding limit"
        );
        let endpoint = Url::parse(&config.endpoint)?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/",
            "S3 endpoint must be an HTTPS origin"
        );
        ensure!(
            valid_segment(&config.region)
                && valid_segment(&config.bucket)
                && (config.prefix.is_empty() || config.prefix.split('/').all(valid_segment)),
            "invalid S3 region, bucket or prefix"
        );
        ensure!(config.max_bytes > 0, "invalid S3 byte limit");
        let mut client = Client::builder()
            .no_proxy()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30));
        if let Some(ca) = config.ca_pem {
            client = client.add_root_certificate(reqwest::Certificate::from_pem(&ca)?);
        }
        let destination = Self {
            endpoint,
            region: config.region,
            bucket: config.bucket,
            prefix: config.prefix,
            credential: config.credential,
            max_bytes: config.max_bytes,
            client: client.build()?,
        };
        destination.namespace_binding()?;
        Ok(destination)
    }

    fn object_url(&self, id: Uuid) -> Result<Url> {
        let middle = if self.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.prefix)
        };
        Ok(self
            .endpoint
            .join(&format!("{}/{middle}{id}.kasumi", self.bucket))?)
    }

    fn signed_headers(
        &self,
        method: &str,
        url: &Url,
        payload: &[u8],
        now: time::OffsetDateTime,
    ) -> Result<HeaderMap> {
        self.signed_headers_extra(method, url, payload, now, std::collections::BTreeMap::new())
    }

    fn signed_headers_extra(
        &self,
        method: &str,
        url: &Url,
        payload: &[u8],
        now: time::OffsetDateTime,
        mut canonical: std::collections::BTreeMap<&str, String>,
    ) -> Result<HeaderMap> {
        let credentials = S3Credentials::load(self.credential.as_ref())?;
        let timestamp = now.format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))?;
        let date = &timestamp[..8];
        let payload_hash = hex::encode(Sha256::digest(payload));
        let hostname = url.host().context("S3 endpoint has no host")?;
        let host = match url.port() {
            Some(port) => format!("{hostname}:{port}"),
            None => hostname.to_string(),
        };
        canonical.extend([
            ("host", host),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", timestamp.clone()),
        ]);
        if method == "PUT" {
            canonical.insert("if-none-match", "*".into());
        }
        if let Some(token) = &credentials.session_token {
            canonical.insert("x-amz-security-token", token.to_string());
        }
        let signed_names = canonical.keys().copied().collect::<Vec<_>>().join(";");
        let canonical_headers = canonical
            .iter()
            .map(|(name, value)| {
                format!(
                    "{name}:{}\n",
                    value.split_whitespace().collect::<Vec<_>>().join(" ")
                )
            })
            .collect::<String>();
        let canonical_request = format!(
            "{method}\n{}\n{}\n{canonical_headers}\n{signed_names}\n{payload_hash}",
            url.path(),
            sessions_s3::canonical_query(url)
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request))
        );
        let key = Zeroizing::new(format!("AWS4{}", credentials.secret_access_key.as_str()));
        let date_key = Zeroizing::new(hmac(key.as_bytes(), date.as_bytes()));
        let region_key = Zeroizing::new(hmac(date_key.as_ref(), self.region.as_bytes()));
        let service_key = Zeroizing::new(hmac(region_key.as_ref(), b"s3"));
        let signing_key = Zeroizing::new(hmac(service_key.as_ref(), b"aws4_request"));
        let signature = hex::encode(hmac(signing_key.as_ref(), to_sign.as_bytes()));
        let mut headers = HeaderMap::new();
        for (name, mut value) in canonical {
            let mut header = HeaderValue::from_str(&value)?;
            if name == "x-amz-security-token" {
                header.set_sensitive(true);
                value.zeroize();
            }
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                header,
            );
        }
        let mut authorization = HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
            credentials.access_key_id
        ))?;
        authorization.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        Ok(headers)
    }
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn hmac(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut hmac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key size");
    hmac.update(bytes);
    hmac.finalize().into_bytes().into()
}

#[async_trait]
impl BackupDestination for S3BackupDestination {
    async fn session_put(
        &self,
        session: Uuid,
        slot: crate::BackupSessionSlot,
        encrypted: BackupUpload,
    ) -> Result<()> {
        self.managed_put(session, slot, encrypted).await
    }
    async fn session_get(
        &self,
        session: Uuid,
        slot: crate::BackupSessionSlot,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.managed_get(session, slot, max_bytes).await
    }
    async fn session_objects(
        &self,
        aborted: &crate::VerifiedBackupAbort,
        limit: usize,
    ) -> Result<crate::BackupSessionObjectPage> {
        self.managed_list(aborted, limit).await
    }
    async fn session_delete(
        &self,
        aborted: &crate::VerifiedBackupAbort,
        objects: &[crate::BackupSessionObject],
    ) -> Result<()> {
        self.managed_delete(aborted, objects).await
    }
    async fn put(&self, id: Uuid, encrypted: BackupUpload) -> Result<()> {
        ensure!(
            encrypted.len() <= self.max_bytes,
            "backup exceeds destination byte limit"
        );
        let url = self.object_url(id)?;
        let headers =
            self.signed_headers("PUT", &url, &encrypted, time::OffsetDateTime::now_utc())?;
        let response = self
            .client
            .put(url)
            .headers(headers)
            .body(encrypted.into_http_body())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("S3 backup upload failed; outcome may be unknown"))?;
        ensure!(
            response.status().is_success(),
            "S3 rejected create-only backup upload (HTTP {})",
            response.status().as_u16()
        );
        Ok(())
    }
    async fn get(&self, id: Uuid, max_bytes: usize) -> Result<Vec<u8>> {
        let limit = self.max_bytes.min(max_bytes);
        let url = self.object_url(id)?;
        let headers = self.signed_headers("GET", &url, &[], time::OffsetDateTime::now_utc())?;
        let mut response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("S3 backup download failed"))?;
        ensure!(
            response.status().is_success(),
            "S3 rejected backup download (HTTP {})",
            response.status().as_u16()
        );
        ensure!(
            response.content_length().is_none_or(|n| n <= limit as u64),
            "backup exceeds destination byte limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.context("reading S3 backup")? {
            ensure!(
                chunk.len() <= limit.saturating_sub(bytes.len()),
                "backup exceeds destination byte limit"
            );
            bytes.extend(chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeDiskMemoryAdmission;
    use crate::{
        NodeStore, WriteOp,
        test_utils::{LocalKeyProvider, ManualClock},
    };

    const MANIFEST_TEST_MEMORY_LIMIT: u64 = 256 << 20;

    struct ManifestAdmissionFixture {
        store: Arc<TenantStore>,
        memory: Arc<crate::test_utils::TestDiskMemory>,
        provider: Arc<LocalKeyProvider>,
        _scratch_directory: tempfile::TempDir,
        _directory: tempfile::TempDir,
    }

    impl ManifestAdmissionFixture {
        async fn new() -> Self {
            let memory = crate::test_utils::TestDiskMemory::new(MANIFEST_TEST_MEMORY_LIMIT, 4096);
            let scratch_directory = crate::test_utils::private_tempdir().unwrap();
            let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
            let directory = crate::test_utils::private_tempdir().unwrap();
            let provider = Arc::new(LocalKeyProvider::new([96; 32]));
            let store = TenantStore::initialize_catalog_fixture_with_clock(
                NodeStore::create_new_fixture(
                    directory.path().join("manifest-admission.kv"),
                    crate::test_utils::NODE_STORE_ID,
                    memory.clone(),
                    scratch,
                )
                .unwrap(),
                "tenant".into(),
                provider.clone(),
                Arc::new(ManualClock::new()),
            )
            .await
            .unwrap();
            Self {
                store,
                memory,
                provider,
                _scratch_directory: scratch_directory,
                _directory: directory,
            }
        }

        fn manifest_cost(&self, backup: &EncryptedBackup) -> u64 {
            let header = serde_json::to_vec(&backup.manifest).unwrap();
            let allocation = crate::disk_memory::allocation::<u8>(header.len() as u64).unwrap();
            crate::test_utils::TestDiskMemory::required_reservation_bytes(allocation).unwrap()
        }

        fn ciphertext_cost(&self, snapshot_len: usize) -> u64 {
            let allocation =
                crate::disk_memory::allocation::<u8>((snapshot_len + 72) as u64).unwrap();
            crate::test_utils::TestDiskMemory::required_reservation_bytes(allocation).unwrap()
        }

        fn bundle_cost(&self, backup: &EncryptedBackup) -> u64 {
            let header = serde_json::to_vec(&backup.manifest).unwrap();
            let length = 12 + header.len() + backup.ciphertext.len();
            let allocation = crate::disk_memory::allocation::<u8>(length as u64).unwrap();
            crate::test_utils::TestDiskMemory::required_reservation_bytes(allocation).unwrap()
        }

        fn leave_available(&self, available: u64) -> DiskMemoryLease {
            let before = self.memory.snapshot();
            let filler = MANIFEST_TEST_MEMORY_LIMIT
                - before.bookkeeping_bytes
                - before.used_bytes
                - available
                - crate::test_utils::TestDiskMemory::required_reservation_bytes(0).unwrap();
            self.memory.clone().reserve_installed(filler).unwrap()
        }
    }

    #[tokio::test]
    async fn serialized_bundle_requires_owner_headroom_and_retains_it_through_http_body() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let baseline = fixture.memory.snapshot();
        let manifest_cost = fixture.manifest_cost(&original);
        let bundle_cost = fixture.bundle_cost(&original);
        let held = fixture.leave_available(manifest_cost + bundle_cost - 1);
        let low = fixture.memory.snapshot();
        let error = original
            .to_bytes()
            .expect_err("the serialized output must be denied before allocation");
        assert!(format!("{error:#}").contains("backup bundle output admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            low.live_reservations
        );
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);

        let bundle = original.to_bytes().unwrap();
        assert_eq!(
            fixture.memory.snapshot().used_bytes - baseline.used_bytes,
            bundle_cost
        );
        let expected = bundle.as_bytes().to_vec();
        let body = BackupUpload::from(bundle).into_http_body();
        assert_eq!(body.as_bytes(), Some(expected.as_slice()));
        assert_eq!(
            fixture.memory.snapshot().used_bytes - baseline.used_bytes,
            bundle_cost
        );
        drop(body);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations
        );
    }

    #[tokio::test]
    async fn cancelled_destination_put_retires_bundle_only_after_future_drop() {
        struct PausedUpload {
            entered: tokio::sync::Notify,
        }

        #[async_trait]
        impl BackupDestination for PausedUpload {
            async fn put(&self, _id: Uuid, upload: BackupUpload) -> Result<()> {
                self.entered.notify_one();
                std::future::pending::<()>().await;
                drop(upload);
                Ok(())
            }

            async fn get(&self, _id: Uuid, _max_bytes: usize) -> Result<Vec<u8>> {
                anyhow::bail!("paused upload has no objects")
            }
        }

        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let baseline = fixture.memory.snapshot();
        let bundle_cost = fixture.bundle_cost(&original);
        let bundle = original.to_bytes().unwrap();
        let destination = Arc::new(PausedUpload {
            entered: tokio::sync::Notify::new(),
        });
        let entered = destination.clone();
        let id = original.id();
        let upload = tokio::spawn(async move { destination.put(id, bundle.into()).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            entered.entered.notified(),
        )
        .await
        .unwrap();
        assert_eq!(
            fixture.memory.snapshot().used_bytes - baseline.used_bytes,
            bundle_cost
        );
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations
        );
    }

    #[tokio::test]
    async fn non_capacity_bundle_owner_failure_retains_typed_cause_and_no_output() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FailBundleMemory {
            backing: Arc<crate::test_utils::TestDiskMemory>,
            calls: AtomicUsize,
            fail_on: AtomicUsize,
        }

        impl NodeDiskMemoryAdmission for FailBundleMemory {
            fn storage_census(&self) -> &crate::StorageCensus {
                self.backing.storage_census()
            }

            fn reserve_installed(self: Arc<Self>, bytes: u64) -> std::io::Result<DiskMemoryLease> {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call == self.fail_on.load(Ordering::SeqCst) {
                    return Err(std::io::Error::other("installed owner failed"));
                }
                self.backing.clone().reserve_installed(bytes)
            }
        }

        let backing = crate::test_utils::TestDiskMemory::new(MANIFEST_TEST_MEMORY_LIMIT, 4096);
        let memory = Arc::new(FailBundleMemory {
            backing: backing.clone(),
            calls: AtomicUsize::new(0),
            fail_on: AtomicUsize::new(usize::MAX),
        });
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let directory = crate::test_utils::private_tempdir().unwrap();
        let provider = Arc::new(LocalKeyProvider::new([97; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                directory.path().join("bundle-owner.kv"),
                crate::test_utils::NODE_STORE_ID,
                memory.clone(),
                scratch,
            )
            .unwrap(),
            "tenant".into(),
            provider,
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let backup = store.encrypt_backup(1, b"seed").unwrap();
        let before = backing.snapshot();
        memory
            .fail_on
            .store(memory.calls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        let error = backup
            .to_bytes()
            .expect_err("owner failure must stop output");
        assert_eq!(
            error
                .downcast_ref::<BackupBundleAdmissionError>()
                .expect("exact typed bundle admission cause")
                .kind(),
            std::io::ErrorKind::Other
        );
        assert_eq!(backing.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            backing.snapshot().live_reservations,
            before.live_reservations
        );
        let bundle = backup.to_bytes().unwrap();
        assert_eq!(&bundle[..8], MAGIC);
        drop(bundle);
        assert_eq!(backing.snapshot().used_bytes, before.used_bytes);
    }

    #[tokio::test]
    async fn manifest_serialization_denies_direct_backup_and_bundle_before_output() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let baseline = fixture.memory.snapshot();
        let cloned = AdmittedKeyCatalog::clone_for_backup(
            &fixture.store.catalog.read(),
            fixture.store.scratch_disk().memory().clone(),
        )
        .unwrap();
        let catalog_cost = fixture.memory.snapshot().used_bytes - baseline.used_bytes;
        drop(cloned);
        let manifest_cost = fixture.manifest_cost(&original);
        assert!(catalog_cost > 0 && manifest_cost > 1);

        let held = fixture.leave_available(catalog_cost + manifest_cost - 1);
        let low = fixture.memory.snapshot();
        let error = fixture
            .store
            .encrypt_backup(2, b"next")
            .err()
            .expect("manifest serialization must deny before direct ciphertext");
        assert!(format!("{error:#}").contains("backup manifest serialization admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            low.live_reservations
        );
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);

        let held = fixture.leave_available(manifest_cost - 1);
        let low = fixture.memory.snapshot();
        let error = original
            .to_bytes()
            .expect_err("manifest serialization must deny before bundle allocation");
        assert!(format!("{error:#}").contains("backup manifest serialization admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[tokio::test]
    async fn direct_ciphertext_output_requires_owner_headroom_before_crypto() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let baseline = fixture.memory.snapshot();
        let ciphertext_cost = fixture.ciphertext_cost(b"next".len());
        let cloned = AdmittedKeyCatalog::clone_for_backup(
            &fixture.store.catalog.read(),
            fixture.store.scratch_disk().memory().clone(),
        )
        .unwrap();
        let catalog_cost = fixture.memory.snapshot().used_bytes - baseline.used_bytes;
        drop(cloned);
        let manifest_cost = fixture.manifest_cost(&original);
        assert!(catalog_cost > 0 && ciphertext_cost > 0);

        let held = fixture.leave_available(catalog_cost + manifest_cost + ciphertext_cost - 1);
        let low = fixture.memory.snapshot();
        let error = fixture
            .store
            .encrypt_backup(2, b"next")
            .err()
            .expect("direct ciphertext must be denied before allocation");
        assert!(format!("{error:#}").contains("backup ciphertext output admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            low.live_reservations
        );
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);

        let direct = fixture.store.encrypt_backup(3, b"next").unwrap();
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations + 2
        );
        drop(direct);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[tokio::test]
    async fn related_ciphertext_output_requires_owner_headroom_before_provider() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let baseline = fixture.memory.snapshot();
        let snapshot = vec![0x5a; crate::MAX_SESSION_RECORD_BYTES];
        let ciphertext_cost = fixture.ciphertext_cost(snapshot.len());
        let manifest_cost = fixture.manifest_cost(&original);
        let clone = AdmittedKeyCatalog::admit_backup_manifest_clone(
            &original.manifest,
            original.manifest.catalog.keys.len(),
            fixture.store.scratch_disk().memory().clone(),
        )
        .unwrap();
        let clone_cost = fixture.memory.snapshot().used_bytes - baseline.used_bytes;
        drop(clone);
        let held = fixture.leave_available(clone_cost + manifest_cost + ciphertext_cost - 1);
        let low = fixture.memory.snapshot();
        let probes = fixture.provider.probe_count();
        let error = original
            .encrypt_related(&snapshot, fixture.provider.clone(), &fixture.store)
            .await
            .err()
            .expect("related ciphertext must be denied before provider effects");
        assert!(format!("{error:#}").contains("backup ciphertext output admission denied"));
        assert_eq!(fixture.provider.probe_count(), probes);
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            low.live_reservations
        );
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);

        let related = original
            .encrypt_related(&snapshot, fixture.provider.clone(), &fixture.store)
            .await
            .unwrap();
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations + 2
        );
        assert_eq!(
            related
                .decrypt("tenant", fixture.provider.clone(), &fixture.store)
                .await
                .unwrap()
                .snapshot
                .as_slice(),
            snapshot.as_slice()
        );
        drop(related);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[tokio::test]
    async fn manifest_canonical_check_denies_before_ciphertext_copy() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let bytes = original.to_bytes().unwrap();
        let header_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let header = &bytes[12..12 + header_len];
        let before = fixture.memory.snapshot();
        let typed = AdmittedKeyCatalog::admit_backup_manifest_decode(
            header,
            fixture.store.scratch_disk().memory().clone(),
        )
        .unwrap();
        let typed_cost = fixture.memory.snapshot().used_bytes - before.used_bytes;
        drop(typed);
        assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
        let ciphertext_len = bytes.len() - 12 - header_len;
        let ciphertext_allocation =
            crate::disk_memory::allocation::<u8>(ciphertext_len as u64).unwrap();
        let copy_cost =
            crate::test_utils::TestDiskMemory::required_reservation_bytes(ciphertext_allocation)
                .unwrap();
        assert!(fixture.manifest_cost(&original) > copy_cost);

        let held = fixture.leave_available(typed_cost + copy_cost);
        let low = fixture.memory.snapshot();
        let error = EncryptedBackup::from_bytes(&bytes, 1024, &fixture.store)
            .err()
            .expect("canonical header admission must deny before ciphertext copy");
        assert!(format!("{error:#}").contains("backup manifest serialization admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            low.live_reservations
        );
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    }

    #[tokio::test]
    async fn manifest_serialization_denies_decrypt_and_related_before_provider() {
        let fixture = ManifestAdmissionFixture::new().await;
        let original = fixture.store.encrypt_backup(1, b"seed").unwrap();
        let manifest_cost = fixture.manifest_cost(&original);
        let baseline = fixture.memory.snapshot();

        let held = fixture.leave_available(manifest_cost - 1);
        let low = fixture.memory.snapshot();
        let probes = fixture.provider.probe_count();
        let error = original
            .decrypt("tenant", fixture.provider.clone(), &fixture.store)
            .await
            .err()
            .expect("manifest serialization must deny before key provider");
        assert!(format!("{error:#}").contains("backup manifest serialization admission denied"));
        assert_eq!(fixture.provider.probe_count(), probes);
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);

        let clone = AdmittedKeyCatalog::admit_backup_manifest_clone(
            &original.manifest,
            original.manifest.catalog.keys.len(),
            fixture.store.scratch_disk().memory().clone(),
        )
        .unwrap();
        let clone_cost = fixture.memory.snapshot().used_bytes - baseline.used_bytes;
        drop(clone);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
        let held = fixture.leave_available(clone_cost + manifest_cost - 1);
        let low = fixture.memory.snapshot();
        let probes = fixture.provider.probe_count();
        let error = original
            .encrypt_related(b"next", fixture.provider.clone(), &fixture.store)
            .await
            .err()
            .expect("related header admission must deny before provider");
        assert!(format!("{error:#}").contains("backup manifest serialization admission denied"));
        assert_eq!(fixture.provider.probe_count(), probes);
        assert_eq!(fixture.memory.snapshot().used_bytes, low.used_bytes);
        drop(held);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[tokio::test]
    async fn parsed_backup_ciphertext_copy_requires_installed_headroom_and_keeps_lease() {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let directory = crate::test_utils::private_tempdir().unwrap();
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                directory.path().join("ciphertext-copy.kv"),
                crate::test_utils::NODE_STORE_ID,
                memory.clone(),
                scratch,
            )
            .unwrap(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([95; 32])),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let original = store.encrypt_backup(1, &vec![0xA5; 8 << 20]).unwrap();
        let bytes = original.to_bytes().unwrap();
        let copy_bound =
            crate::disk_memory::allocation::<u8>(original.ciphertext.len() as u64).unwrap();
        let before = memory.snapshot();
        let available = 512 << 10;
        assert!(copy_bound > available);
        let filler = (256 << 20)
            - before.bookkeeping_bytes
            - before.used_bytes
            - available
            - crate::test_utils::TestDiskMemory::required_reservation_bytes(0).unwrap();
        let held = memory.clone().reserve_installed(filler).unwrap();
        let low_headroom = memory.snapshot();
        let error = EncryptedBackup::from_bytes(&bytes, 8 << 20, &store)
            .err()
            .expect("ciphertext copy must deny before Vec allocation");
        assert!(format!("{error:#}").contains("backup ciphertext copy admission denied"));
        assert_eq!(memory.snapshot().used_bytes, low_headroom.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            low_headroom.live_reservations
        );
        drop(held);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);

        let parsed = EncryptedBackup::from_bytes(&bytes, 8 << 20, &store).unwrap();
        assert_eq!(parsed.ciphertext, original.ciphertext);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations + 2
        );
        drop(parsed);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
    }

    #[tokio::test]
    async fn decoded_and_related_backup_manifest_reserve_installed_memory_before_allocation() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let directory = crate::test_utils::private_tempdir().unwrap();
        let provider = Arc::new(LocalKeyProvider::new([91; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                directory.path().join("backup-manifest.kv"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                scratch,
            )
            .unwrap(),
            "tenant".into(),
            provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let original = store.encrypt_backup(1, b"source").unwrap();
        let bytes = original.to_bytes().unwrap();
        let before = fixture_memory.snapshot();
        let available = 48 << 10;
        let filler = (256 << 20)
            - before.bookkeeping_bytes
            - before.used_bytes
            - available
            - crate::test_utils::TestDiskMemory::required_reservation_bytes(0).unwrap();
        let held = fixture_memory.clone().reserve_installed(filler).unwrap();
        let low_headroom = fixture_memory.snapshot();
        let error = EncryptedBackup::from_bytes(&bytes, 1024, &store)
            .err()
            .expect("decoded manifest admission must fail");
        assert!(format!("{error:#}").contains("backup manifest typed allocation admission denied"));
        assert_eq!(
            fixture_memory.snapshot().used_bytes,
            low_headroom.used_bytes
        );
        let foreign_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let foreign_scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let foreign_scratch =
            crate::ScratchDisk::fixture(foreign_scratch_directory.path(), foreign_memory.clone());
        let foreign_directory = crate::test_utils::private_tempdir().unwrap();
        let foreign_store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                foreign_directory.path().join("foreign.kv"),
                crate::test_utils::NODE_STORE_ID,
                foreign_memory,
                foreign_scratch,
            )
            .unwrap(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([93; 32])),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let foreign_decoded = EncryptedBackup::from_bytes(&bytes, 1024, &foreign_store).unwrap();
        let error = foreign_decoded
            .decrypt("tenant", provider.clone(), &store)
            .await
            .err()
            .expect("foreign parse owner must not authorize target release");
        assert!(format!("{error:#}").contains("backup memory owner differs from installed target"));
        drop(foreign_decoded);
        assert_eq!(
            fixture_memory.snapshot().used_bytes,
            low_headroom.used_bytes
        );
        let error = original
            .encrypt_related(b"outcome", provider.clone(), &store)
            .await
            .err()
            .expect("related manifest clone admission must fail");
        assert!(format!("{error:#}").contains("backup manifest clone admission denied"));
        assert_eq!(
            fixture_memory.snapshot().used_bytes,
            low_headroom.used_bytes
        );
        drop(held);
        assert_eq!(fixture_memory.snapshot().used_bytes, before.used_bytes);

        let decoded = EncryptedBackup::from_bytes(&bytes, 1024, &store).unwrap();
        assert_eq!(
            fixture_memory.snapshot().live_reservations,
            before.live_reservations + 2
        );
        assert_eq!(
            decoded
                .decrypt("tenant", provider.clone(), &store)
                .await
                .unwrap()
                .snapshot
                .as_slice(),
            b"source"
        );
        drop(decoded);
        assert_eq!(fixture_memory.snapshot().used_bytes, before.used_bytes);
        let related = original
            .encrypt_related(b"outcome", provider, &store)
            .await
            .unwrap();
        assert_eq!(
            fixture_memory.snapshot().live_reservations,
            before.live_reservations + 2
        );
        drop(related);
        assert_eq!(fixture_memory.snapshot().used_bytes, before.used_bytes);
    }

    #[tokio::test]
    async fn encrypted_bundle_round_trip_filesystem_reopen_and_tamper_rejection() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let dir = crate::test_utils::private_tempdir().unwrap();
        let provider = Arc::new(LocalKeyProvider::new([17; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant".into(),
            provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        store
            .write_batch(&[WriteOp::put("docs", b"a", b"test")])
            .unwrap();
        let snapshot = br#"{"documents":{"a":{"secret":"very-private"}},"receipts":{"r":42}}"#;
        let backup = store.encrypt_backup(42, snapshot).unwrap();
        let bytes = backup.to_bytes().unwrap();
        assert!(
            !bytes
                .windows(b"very-private".len())
                .any(|window| window == b"very-private")
        );
        let destination = FilesystemBackupDestination::new_fixture(
            dir.path().join("backups"),
            1 << 20,
            fixture_memory.clone(),
        )
        .unwrap();
        destination
            .put(backup.id(), bytes.try_clone().unwrap().into())
            .await
            .unwrap();
        assert!(
            destination
                .put(backup.id(), bytes.try_clone().unwrap().into())
                .await
                .is_err()
        );
        let read = destination.get(backup.id(), 16 << 20).await.unwrap();
        assert_eq!(bytes.as_bytes(), read);
        let parsed = EncryptedBackup::from_bytes(&read, 1 << 20, &store).unwrap();
        let plain = parsed
            .decrypt_fixture("tenant", provider.clone(), &store)
            .await
            .unwrap();
        assert_eq!(&*plain.snapshot, snapshot);
        assert_eq!(plain.revision, 42);
        assert!(
            parsed
                .decrypt_fixture("another", provider.clone(), &store)
                .await
                .is_err()
        );
        assert!(EncryptedBackup::from_bytes(&read, 1, &store).is_err());
        let mut damaged = read;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(
            EncryptedBackup::from_bytes(&damaged, 1 << 20, &store)
                .unwrap()
                .decrypt_fixture("tenant", provider.clone(), &store)
                .await
                .is_err()
        );
        let mut swapped = backup;
        swapped.manifest.revision += 1;
        assert!(
            swapped
                .decrypt_fixture("tenant", provider, &store)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn historical_backup_keeps_original_key_dependencies_after_rewrap() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let dir = crate::test_utils::private_tempdir().unwrap();
        let provider = Arc::new(LocalKeyProvider::new([22; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "t".into(),
            provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let old = store.encrypt_backup(1, b"old").unwrap();
        provider.rotate();
        store.rewrap_keys().await.unwrap();
        let new = store.encrypt_backup(1, b"new").unwrap();
        provider.set_minimum_version(2);
        assert!(
            old.decrypt_fixture("t", provider.clone(), &store)
                .await
                .is_err()
        );
        assert_eq!(
            &*new
                .decrypt_fixture("t", provider, &store)
                .await
                .unwrap()
                .snapshot,
            b"new"
        );
    }

    #[tokio::test]
    async fn removal_of_an_inactive_backup_key_dependency_breaks_authentication() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let dir = crate::test_utils::private_tempdir().unwrap();
        let provider = Arc::new(LocalKeyProvider::new([31; 32]));
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant".into(),
            provider.clone(),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        provider.rotate();
        store.rotate_data_key().await.unwrap();
        let mut backup = store.encrypt_backup(7, b"logical state").unwrap();
        let inactive = backup
            .manifest
            .catalog
            .keys
            .keys()
            .find(|id| id.as_str() != crate::INDEX_KEY && *id != &backup.manifest.catalog.active)
            .unwrap()
            .clone();
        backup.manifest.catalog.keys.remove(&inactive);
        // Parsing cannot grant trust even when the remaining catalog is well-formed.
        let parsed =
            EncryptedBackup::from_bytes(&backup.to_bytes().unwrap(), 1024, &store).unwrap();
        assert!(
            parsed
                .decrypt_fixture("tenant", provider, &store)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn destination_byte_limits_and_untrusted_format_are_rejected() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let dir = crate::test_utils::private_tempdir().unwrap();
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            NodeStore::create_new_fixture(
                dir.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                scratch,
            )
            .unwrap(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([92; 32])),
            Arc::new(ManualClock::new()),
        )
        .await
        .unwrap();
        let destination =
            FilesystemBackupDestination::new_fixture(dir.path(), 5, fixture_memory.clone())
                .unwrap();
        let id = Uuid::new_v4();
        assert!(
            destination
                .put(id, BackupUpload::received(vec![0; 6]))
                .await
                .is_err()
        );
        std::fs::write(destination.path(id), [0; 6]).unwrap();
        assert!(destination.get(id, 16 << 20).await.is_err());
        for bytes in [b"".as_slice(), b"KASUMIB1", b"KASUMIB1\xff\xff\xff\xff"] {
            assert!(EncryptedBackup::from_bytes(bytes, 1024, &store).is_err());
        }
    }
}

#[cfg(test)]
mod s3_tests {
    use super::*;
    use crate::tls_fixture::TlsFixture;
    use axum::{
        Router,
        body::Bytes,
        extract::{OriginalUri, State},
        http::{HeaderMap, Method, StatusCode},
        response::{IntoResponse, Response},
        routing::any,
    };

    fn test_credential(
        session_token: Option<&str>,
    ) -> Arc<dyn kasumi_transport::credentials::CredentialSource> {
        let session_token = session_token.map(str::to_owned);
        Arc::new(move || {
            Ok(Zeroizing::new(
                serde_json::json!({
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "session_token": session_token
                })
                .to_string(),
            ))
        })
    }
    fn config(endpoint: &str, ca: Option<Vec<u8>>) -> S3BackupConfig {
        S3BackupConfig {
            endpoint: endpoint.into(),
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            prefix: "backup/v1".into(),
            credential: test_credential(None),
            ca_pem: ca,
            max_bytes: 1 << 20,
        }
    }

    #[test]
    fn s3_namespace_binding_tracks_physical_namespace_not_credentials() {
        let original = S3BackupDestination::new(config("https://S3.EXAMPLE:443", None)).unwrap();
        let binding = original.namespace_binding().unwrap();
        assert_eq!(
            binding,
            kasumi_types::BackupNamespaceBinding::S3 {
                https_origin: "https://s3.example/".into(),
                region: "us-east-1".into(),
                bucket: "examplebucket".into(),
                prefix: "backup/v1".into(),
            }
        );
        let mut rotated_config = config("https://s3.example/", None);
        rotated_config.credential = test_credential(Some("renewed-session"));
        let rotated = S3BackupDestination::new(rotated_config).unwrap();
        assert_eq!(binding, rotated.namespace_binding().unwrap());
        let mut changed = config("https://s3.example/", None);
        changed.prefix = "backup/v2".into();
        let changed = S3BackupDestination::new(changed).unwrap();
        assert_ne!(binding, changed.namespace_binding().unwrap());
        let mut changed = config("https://s3.example/", None);
        changed.bucket = "another-bucket".into();
        assert_ne!(
            binding,
            S3BackupDestination::new(changed)
                .unwrap()
                .namespace_binding()
                .unwrap()
        );
        let mut changed = config("https://s3.example/", None);
        changed.region = "ap-northeast-1".into();
        assert_ne!(
            binding,
            S3BackupDestination::new(changed)
                .unwrap()
                .namespace_binding()
                .unwrap()
        );
        assert_ne!(
            binding,
            S3BackupDestination::new(config("https://other.example/", None))
                .unwrap()
                .namespace_binding()
                .unwrap()
        );
        let mut invalid = config("https://s3.example/", None);
        invalid.prefix = "backup/../other".into();
        assert!(S3BackupDestination::new(invalid).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn s3_credentials_are_reloaded_as_one_atomic_bundle() {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let dir = crate::test_utils::private_tempdir().unwrap();
        let path = dir.path().join("s3.json");
        let publish = |id: &str, secret: &str, token: &str| {
            let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
            write!(file, "{}", serde_json::json!({"access_key_id":id,"secret_access_key":secret,"session_token":token})).unwrap();
            file.persist(&path).unwrap();
        };
        publish("FIRST", "first-secret", "first-session");
        let mut settings = config("https://s3.example", None);
        settings.credential =
            Arc::new(kasumi_transport::credentials::FileCredentialSource::new(&path).unwrap());
        let destination = S3BackupDestination::new(settings).unwrap();
        let url = destination.object_url(Uuid::new_v4()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let first = destination.signed_headers("GET", &url, b"", now).unwrap();
        assert!(
            first["authorization"]
                .to_str()
                .unwrap()
                .contains("Credential=FIRST/")
        );
        assert_eq!(first["x-amz-security-token"], "first-session");
        publish("SECOND", "second-secret", "second-session");
        let second = destination.signed_headers("GET", &url, b"", now).unwrap();
        assert!(
            second["authorization"]
                .to_str()
                .unwrap()
                .contains("Credential=SECOND/")
        );
        assert_eq!(second["x-amz-security-token"], "second-session");
        assert_ne!(first["authorization"], second["authorization"]);
        publish("THIRD", "third-secret", "bad\nheader");
        assert!(destination.signed_headers("GET", &url, b"", now).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(destination.signed_headers("GET", &url, b"", now).is_err());
    }

    #[test]
    fn aws_published_signature_v4_get_object_vector() {
        // Independent published AWS S3 single-chunk signature test vector:
        // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
        let signer =
            S3BackupDestination::new(config("https://examplebucket.s3.amazonaws.com", None))
                .unwrap();
        let headers = signer
            .signed_headers_extra(
                "GET",
                &Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap(),
                &[],
                time::macros::datetime!(2013-05-24 0:00 UTC),
                std::collections::BTreeMap::from([("range", "bytes=0-9".into())]),
            )
            .unwrap();
        assert_eq!(headers["x-amz-date"], "20130524T000000Z");
        assert!(headers["authorization"].to_str().unwrap().ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObjectVersion {
        id: String,
        data: Option<Vec<u8>>,
    }
    #[derive(Default)]
    struct Objects {
        // Each key keeps every version, newest first. None is a delete marker.
        values: parking_lot::Mutex<std::collections::BTreeMap<String, Vec<ObjectVersion>>>,
        deletes: parking_lot::Mutex<Vec<(String, Option<String>)>>,
        list_response: parking_lot::Mutex<Option<String>>,
        signer: parking_lot::Mutex<Option<S3BackupDestination>>,
    }
    async fn object(
        State(state): State<Arc<Objects>>,
        method: Method,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
        bytes: Bytes,
    ) -> Response {
        let signature_ok = (|| -> Result<bool> {
            let signer = state.signer.lock();
            let signer = signer.as_ref().unwrap();
            let url = signer.endpoint.join(&uri.to_string())?;
            let timestamp = headers["x-amz-date"].to_str()?;
            // The fixture recomputes the signature from actual method/path/body and
            // signed session token, so transport mutation does not pass unnoticed.
            let numbers =
                |start: usize, end: usize| -> Result<u8> { Ok(timestamp[start..end].parse()?) };
            let date = time::Date::from_calendar_date(
                timestamp[..4].parse()?,
                numbers(4, 6)?.try_into()?,
                numbers(6, 8)?,
            )?;
            let time = time::Time::from_hms(numbers(9, 11)?, numbers(11, 13)?, numbers(13, 15)?)?;
            let expected = signer.signed_headers(
                method.as_str(),
                &url,
                &bytes,
                date.with_time(time).assume_utc(),
            )?;
            Ok(expected["authorization"] == headers["authorization"]
                && expected["x-amz-content-sha256"] == headers["x-amz-content-sha256"]
                && expected.get("x-amz-security-token") == headers.get("x-amz-security-token"))
        })()
        .unwrap_or(false);
        if !signature_ok {
            return StatusCode::FORBIDDEN.into_response();
        }
        let mut values = state.values.lock();
        if method == Method::PUT {
            if headers.get("if-none-match").is_none_or(|v| v != "*") {
                return StatusCode::BAD_REQUEST.into_response();
            }
            if values
                .get(uri.path())
                .and_then(|versions| versions.first())
                .is_some_and(|version| version.data.is_some())
            {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            values.entry(uri.path().into()).or_default().insert(
                0,
                ObjectVersion {
                    id: Uuid::new_v4().to_string(),
                    data: Some(bytes.to_vec()),
                },
            );
            StatusCode::OK.into_response()
        } else if method == Method::GET && uri.query().is_some() {
            let url = Url::parse(&format!("https://fixture{uri}")).unwrap();
            let query = url
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            if !query.contains_key("versions")
                || query.contains_key("key-marker")
                || query.contains_key("version-id-marker")
            {
                return StatusCode::BAD_REQUEST.into_response();
            }
            if let Some(response) = state.list_response.lock().as_ref() {
                return response.clone().into_response();
            }
            let prefix = query.get("prefix").unwrap();
            let maximum: usize = query.get("max-keys").unwrap().parse().unwrap();
            let bucket = format!("{}/", uri.path());
            let mut entries = values
                .iter()
                .filter_map(|(key, versions)| key.strip_prefix(&bucket).map(|key| (key, versions)))
                .filter(|(key, _)| key.starts_with(prefix.as_ref()))
                .flat_map(|(key, versions)| versions.iter().map(move |version| (key, version)))
                .collect::<Vec<_>>();
            let truncated = entries.len() > maximum;
            entries.truncate(maximum);
            let records = entries
                .iter()
                .map(|(key, version)| {
                    let tag = if version.data.is_some() {
                        "Version"
                    } else {
                        "DeleteMarker"
                    };
                    let version_id = quick_xml::escape::escape(&version.id);
                    format!("<{tag}><Key>{key}</Key><VersionId>{version_id}</VersionId></{tag}>")
                })
                .collect::<String>();
            format!("<ListVersionsResult><Prefix>{prefix}</Prefix>{records}<IsTruncated>{truncated}</IsTruncated></ListVersionsResult>").into_response()
        } else if method == Method::DELETE {
            let url = Url::parse(&format!("https://fixture{uri}")).unwrap();
            let version_id = url
                .query_pairs()
                .find(|(name, _)| name == "versionId")
                .map(|(_, value)| value.into_owned());
            state
                .deletes
                .lock()
                .push((uri.path().into(), version_id.clone()));
            if let Some(version_id) = version_id {
                if let Some(versions) = values.get_mut(uri.path()) {
                    versions.retain(|version| version.id != version_id);
                    if versions.is_empty() {
                        values.remove(uri.path());
                    }
                }
            } else {
                // Model S3 faithfully: a simple DELETE retains every data version.
                values.entry(uri.path().into()).or_default().insert(
                    0,
                    ObjectVersion {
                        id: Uuid::new_v4().to_string(),
                        data: None,
                    },
                );
            }
            StatusCode::NO_CONTENT.into_response()
        } else if method == Method::GET {
            values
                .get(uri.path())
                .and_then(|versions| versions.first())
                .and_then(|version| version.data.clone())
                .map(|bytes| bytes.into_response())
                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
        } else {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
    }

    async fn assert_versioned_session_cleanup(
        destination: &S3BackupDestination,
        state: &Objects,
        store: &Arc<TenantStore>,
        keys: Arc<dyn KeyProvider>,
        proof: &crate::VerifiedBackupAbort,
    ) {
        use crate::{BackupSessionObject, BackupSessionSlot, verify_backup_session};
        use kasumi_types::{BackupSessionIntent, BackupSessionOutcome, FullBackupCheckpoint};
        let session = proof.session_id();
        let id = Uuid::from_u128(1);
        let path = |session: Uuid, slot: BackupSessionSlot| {
            format!(
                "/{}/{}",
                destination.bucket,
                if destination.prefix.is_empty() {
                    slot.relative(session).unwrap()
                } else {
                    format!("{}/{}", destination.prefix, slot.relative(session).unwrap())
                }
            )
        };
        let object_path = path(session, BackupSessionSlot::Object(id));
        let marker_path = path(session, BackupSessionSlot::Object(Uuid::from_u128(2)));
        let prefix = object_path
            .strip_suffix(&format!("{id}.kasumi"))
            .unwrap()
            .to_owned();
        let key_prefix = prefix
            .strip_prefix(&format!("/{}/", destination.bucket))
            .unwrap();
        let selector = |version_id: &str| BackupSessionObject::S3Version {
            id,
            version_id: version_id.into(),
        };

        // A completed backup and an independent archive share this destination.
        let complete_session = Uuid::new_v4();
        let intent = BackupSessionIntent {
            session_id: complete_session,
            tenant: "tenant".into(),
            source_incarnation: "source".into(),
            revision: 3,
            principal: "admin".into(),
            request_id: "complete".into(),
        };
        destination
            .session_put(
                complete_session,
                BackupSessionSlot::Intent,
                store.encrypt_session_record(3, &intent).unwrap().into(),
            )
            .await
            .unwrap();
        let pending = verify_backup_session(destination, complete_session, store, keys.clone())
            .await
            .unwrap()
            .unwrap();
        let complete = BackupSessionOutcome::Complete {
            intent_ciphertext_sha256: pending.intent_ciphertext_sha256().into(),
            checkpoint: FullBackupCheckpoint {
                tenant: "tenant".into(),
                source_incarnation: "source".into(),
                revision: 3,
                resident_sha256: "a".repeat(64),
                backup_id: complete_session,
                manifest_ciphertext_sha256: "b".repeat(64),
                key_lineage_digest: "c".repeat(64),
            },
        };
        destination
            .session_put(
                complete_session,
                BackupSessionSlot::Object(id),
                BackupUpload::received(b"complete root".to_vec()),
            )
            .await
            .unwrap();
        destination
            .session_put(
                complete_session,
                BackupSessionSlot::Outcome,
                store.encrypt_session_record(3, &complete).unwrap().into(),
            )
            .await
            .unwrap();
        assert!(
            verify_backup_session(destination, complete_session, store, keys.clone())
                .await
                .unwrap()
                .unwrap()
                .aborted()
                .is_err()
        );
        destination
            .put(
                Uuid::new_v4(),
                BackupUpload::received(b"independent archive".to_vec()),
            )
            .await
            .unwrap();
        let preserved = state.values.lock().clone();
        state.deletes.lock().clear();
        state.values.lock().insert(
            object_path.clone(),
            vec![
                ObjectVersion {
                    id: "z/+&=".into(),
                    data: None,
                },
                ObjectVersion {
                    id: "a".into(),
                    data: Some(vec![1]),
                },
                ObjectVersion {
                    id: "null".into(),
                    data: Some(vec![2]),
                },
            ],
        );
        state.values.lock().insert(
            marker_path,
            vec![ObjectVersion {
                id: "null".into(),
                data: None,
            }],
        );
        assert!(
            destination
                .session_get(session, BackupSessionSlot::Object(id), 1024)
                .await
                .unwrap()
                .is_none()
        );
        let page = destination.session_objects(proof, 2).await.unwrap();
        assert_eq!(page.objects, vec![selector("z/+&="), selector("a")]);
        assert!(page.more);
        // Reject every malformed page before issuing even its first valid DELETE.
        for invalid in [
            vec![selector("a"), BackupSessionObject::File { id }],
            vec![selector("a"), selector("a")],
            vec![selector("a"), selector("")],
            vec![selector("a"), selector(&"x".repeat(1025))],
            vec![
                selector("a"),
                BackupSessionObject::S3Version {
                    id: Uuid::nil(),
                    version_id: "v".into(),
                },
            ],
        ] {
            assert!(destination.session_delete(proof, &invalid).await.is_err());
            assert!(state.deletes.lock().is_empty());
        }
        *state.list_response.lock() = Some(format!(
            "<ListVersionsResult><Prefix>{key_prefix}</Prefix>
            <Version><Key>{key_prefix}{id}.kasumi</Key><VersionId>a</VersionId></Version>
            <DeleteMarker><Key>outside/key.kasumi</Key><VersionId>v</VersionId></DeleteMarker>
            <IsTruncated>false</IsTruncated></ListVersionsResult>"
        ));
        assert!(destination.session_objects(proof, 2).await.is_err());
        assert!(state.deletes.lock().is_empty());
        *state.list_response.lock() = None;

        // An upload admitted before abort finishes after listing. Its new version
        // must survive deletion of the exact older page, then be found on rescan.
        destination
            .session_put(
                session,
                BackupSessionSlot::Object(id),
                BackupUpload::received(vec![9]),
            )
            .await
            .unwrap();
        destination
            .session_delete(proof, &page.objects)
            .await
            .unwrap();
        destination
            .session_delete(proof, &page.objects)
            .await
            .unwrap();
        assert_eq!(
            destination
                .session_get(session, BackupSessionSlot::Object(id), 1024)
                .await
                .unwrap(),
            Some(vec![9])
        );
        let tail = destination.session_objects(proof, 2).await.unwrap();
        assert_eq!(tail.objects.len(), 2);
        assert_eq!(tail.objects[1], selector("null"));
        assert!(tail.more);
        destination
            .session_delete(proof, &tail.objects)
            .await
            .unwrap();
        let markers = destination.session_objects(proof, 2).await.unwrap();
        assert_eq!(
            markers.objects,
            vec![BackupSessionObject::S3Version {
                id: Uuid::from_u128(2),
                version_id: "null".into()
            }]
        );
        assert!(!markers.more);
        destination
            .session_delete(proof, &markers.objects)
            .await
            .unwrap();
        assert!(
            destination
                .session_objects(proof, 2)
                .await
                .unwrap()
                .objects
                .is_empty()
        );
        // A pass that observed an empty namespace is not a permanent GC receipt.
        destination
            .session_put(
                session,
                BackupSessionSlot::Object(id),
                BackupUpload::received(vec![8]),
            )
            .await
            .unwrap();
        let late = destination.session_objects(proof, 2).await.unwrap();
        assert_eq!(late.objects.len(), 1);
        destination
            .session_delete(proof, &late.objects)
            .await
            .unwrap();
        assert!(
            destination
                .session_objects(proof, 2)
                .await
                .unwrap()
                .objects
                .is_empty()
        );
        assert_eq!(
            *state.values.lock(),
            preserved,
            "only aborted object versions may be removed"
        );
        assert!(
            state
                .deletes
                .lock()
                .iter()
                .all(|(key, version)| key.starts_with(&prefix) && version.is_some())
        );
        assert!(
            verify_backup_session(destination, session, store, keys)
                .await
                .unwrap()
                .unwrap()
                .aborted()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn s3_tls_round_trip_signed_session_token_create_only_and_bounded_download() {
        let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let fixture_scratch =
            crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
        let state = Arc::new(Objects::default());
        let fixture = TlsFixture::spawn(
            Router::new()
                .route("/{*object}", any(object))
                .with_state(state.clone()),
        )
        .await;
        let make = || {
            let mut c = config(&fixture.endpoint, Some(fixture.ca_pem.clone()));
            c.credential = test_credential(Some("temporary-session-token"));
            c
        };
        *state.signer.lock() = Some(S3BackupDestination::new(make()).unwrap());
        let destination = S3BackupDestination::new(make()).unwrap();
        let directory = crate::test_utils::private_tempdir().unwrap();
        let keys = Arc::new(crate::test_utils::LocalKeyProvider::new([77; 32]));
        let store = TenantStore::initialize_catalog_fixture(
            crate::NodeStore::create_new_fixture(
                directory.path().join("db"),
                crate::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "tenant".into(),
            keys.clone(),
        )
        .await
        .unwrap();
        let session = Uuid::new_v4();
        let intent = kasumi_types::BackupSessionIntent {
            session_id: session,
            tenant: "tenant".into(),
            source_incarnation: "source".into(),
            revision: 3,
            principal: "admin".into(),
            request_id: "s3-test".into(),
        };
        destination
            .session_put(
                session,
                crate::BackupSessionSlot::Intent,
                store.encrypt_session_record(3, &intent).unwrap().into(),
            )
            .await
            .unwrap();
        let pending = crate::verify_backup_session(&destination, session, &store, keys.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(pending.aborted().is_err());
        let outcome = kasumi_types::BackupSessionOutcome::Aborted {
            intent_ciphertext_sha256: pending.intent_ciphertext_sha256().into(),
            session_id: session,
            principal: "admin".into(),
            reason: "stop".into(),
        };
        destination
            .session_put(
                session,
                crate::BackupSessionSlot::Outcome,
                store.encrypt_session_record(3, &outcome).unwrap().into(),
            )
            .await
            .unwrap();
        let proof = crate::verify_backup_session(&destination, session, &store, keys.clone())
            .await
            .unwrap()
            .unwrap()
            .aborted()
            .unwrap();
        for id in 1..=3 {
            destination
                .session_put(
                    session,
                    crate::BackupSessionSlot::Object(Uuid::from_u128(id)),
                    BackupUpload::received(vec![3]),
                )
                .await
                .unwrap();
        }
        let page = destination.session_objects(&proof, 2).await.unwrap();
        assert_eq!(
            page.objects
                .iter()
                .map(crate::BackupSessionObject::id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(1), Uuid::from_u128(2)]
        );
        assert!(page.more);
        destination
            .session_delete(&proof, &page.objects)
            .await
            .unwrap();
        destination
            .session_put(
                session,
                crate::BackupSessionSlot::Object(Uuid::from_u128(1)),
                BackupUpload::received(vec![9]),
            )
            .await
            .unwrap();
        let tail = destination.session_objects(&proof, 2).await.unwrap();
        assert_eq!(
            tail.objects
                .iter()
                .map(crate::BackupSessionObject::id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(1), Uuid::from_u128(3)]
        );
        destination
            .session_delete(&proof, &tail.objects)
            .await
            .unwrap();
        destination
            .session_put(
                session,
                crate::BackupSessionSlot::Object(Uuid::from_u128(1)),
                BackupUpload::received(vec![8]),
            )
            .await
            .unwrap();
        let late = destination.session_objects(&proof, 2).await.unwrap();
        assert_eq!(
            late.objects
                .iter()
                .map(crate::BackupSessionObject::id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(1)]
        );
        destination
            .session_delete(&proof, &late.objects)
            .await
            .unwrap();
        assert!(
            destination
                .session_objects(&proof, 2)
                .await
                .unwrap()
                .objects
                .is_empty()
        );
        assert!(
            destination
                .session_get(session, crate::BackupSessionSlot::Outcome, 1 << 20)
                .await
                .unwrap()
                .is_some()
        );
        assert_versioned_session_cleanup(&destination, &state, &store, keys, &proof).await;
        let id = Uuid::new_v4();
        destination
            .put(
                id,
                BackupUpload::received(b"encrypted snapshot bytes".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            destination.get(id, 16 << 20).await.unwrap(),
            b"encrypted snapshot bytes"
        );
        assert!(
            destination
                .put(id, BackupUpload::received(b"replacement".to_vec()))
                .await
                .is_err()
        );
        assert!(
            destination
                .get(Uuid::new_v4(), MAX_BACKUP_BUNDLE_BYTES)
                .await
                .is_err()
        );
        let mut small = make();
        small.max_bytes = 5;
        assert!(
            S3BackupDestination::new(small)
                .unwrap()
                .get(id, 16 << 20)
                .await
                .is_err()
        );
        let mut wrong = make();
        let original = wrong.credential.clone();
        wrong.credential = Arc::new(move || {
            let mut bundle: serde_json::Value = serde_json::from_str(&original.load()?)?;
            bundle["secret_access_key"] = serde_json::json!("wrong-key");
            Ok(Zeroizing::new(bundle.to_string()))
        });
        assert!(
            S3BackupDestination::new(wrong)
                .unwrap()
                .get(id, 16 << 20)
                .await
                .is_err()
        );
        let mut untrusted = make();
        untrusted.ca_pem = None;
        assert!(
            S3BackupDestination::new(untrusted)
                .unwrap()
                .get(id, 16 << 20)
                .await
                .is_err()
        );
        assert!(
            destination
                .put(
                    Uuid::new_v4(),
                    BackupUpload::received(vec![0; (1 << 20) + 1]),
                )
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod minio_live;
