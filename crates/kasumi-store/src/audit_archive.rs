//! An archive is a bounded authenticated sequence, not a tenant snapshot. A
//! destination confirms durable, identical ciphertext before a caller may prune.
use crate::{
    AccessGuard, BackupDestination, PROVIDER_TIMEOUT, S3BackupDestination, StoragePurpose,
    TenantStore, WrappedKey, decrypt, encrypt,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use kasumi_types::{
    AuditArchiveKeyDependency, AuditArchiveLink, AuditArchiveReference, MAX_AUDIT_EVENT_BYTES,
    MAX_AUDIT_SEGMENT_BYTES, MAX_AUDIT_SEGMENT_RECORDS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"KASUMIA1";
const HEADER_LIMIT: usize = 64 << 10;
const PAYLOAD_LIMIT: usize = MAX_AUDIT_SEGMENT_BYTES - HEADER_LIMIT - 52;

/// Holds at most one segment of encoded records. Each append is all-or-nothing.
pub struct AuditSegmentBuilder {
    stream_id: Uuid,
    first_sequence: u64,
    next_sequence: u64,
    previous: Option<AuditArchiveLink>,
    payload: Zeroizing<Vec<u8>>,
}

impl AuditSegmentBuilder {
    pub fn new(
        stream_id: Uuid,
        first_sequence: u64,
        previous: Option<AuditArchiveLink>,
    ) -> Result<Self> {
        ensure!(!stream_id.is_nil(), "invalid audit stream identity");
        match &previous {
            Some(link) => {
                ensure!(
                    !link.object_id.is_nil()
                        && link.first_sequence < link.next_sequence
                        && link.next_sequence == first_sequence,
                    "noncontiguous audit predecessor"
                );
                kasumi_types::validate_sha256(&link.ciphertext_sha256)?;
            }
            None => ensure!(
                first_sequence == 0,
                "audit archive is missing its predecessor"
            ),
        }
        Ok(Self {
            stream_id,
            first_sequence,
            next_sequence: first_sequence,
            previous,
            payload: Zeroizing::new(Vec::new()),
        })
    }

    /// False means this segment is full; the record has not been consumed.
    pub fn push(&mut self, sequence: u64, record: &[u8]) -> Result<bool> {
        ensure!(
            sequence == self.next_sequence,
            "noncontiguous audit sequence"
        );
        ensure!(
            !record.is_empty() && record.len() <= MAX_AUDIT_EVENT_BYTES,
            "audit event exceeds record limit"
        );
        let next = sequence
            .checked_add(1)
            .context("audit sequence exhausted")?;
        let length = self
            .payload
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(record.len()))
            .context("audit segment size overflow")?;
        if length > PAYLOAD_LIMIT || self.record_count() >= MAX_AUDIT_SEGMENT_RECORDS {
            return Ok(false);
        }
        self.payload
            .extend(u32::try_from(record.len())?.to_be_bytes());
        self.payload.extend(record);
        self.next_sequence = next;
        Ok(true)
    }

    pub fn record_count(&self) -> u64 {
        self.next_sequence - self.first_sequence
    }
    pub fn plaintext_bytes(&self) -> u64 {
        self.payload.len() as u64
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: u32,
    object_id: Uuid,
    tenant: String,
    purpose: StoragePurpose,
    stream_id: Uuid,
    first_sequence: u64,
    next_sequence: u64,
    previous: Option<AuditArchiveLink>,
    record_count: u64,
    plaintext_bytes: u64,
    plaintext_sha256: String,
    wrapped_key: WrappedKey,
}

pub struct PreparedAuditSegment {
    pub reference: AuditArchiveReference,
    pub ciphertext: Vec<u8>,
}

/// Bounded metadata from an object whose bytes match a selected immutable
/// archive link. This is not decrypted evidence or authorization: the caller
/// must authorize its original source purpose against the verified checkpoint
/// and lineage, then use HistoricalAuditVerifier before accepting plaintext.
/// No public fields or deserializer can substitute another object afterward.
pub struct InspectedAuditDependency<'a> {
    bytes: &'a [u8],
    header: Header,
    reference: AuditArchiveReference,
}
impl<'a> InspectedAuditDependency<'a> {
    pub fn from_link(bytes: &'a [u8], expected: &AuditArchiveLink) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_AUDIT_SEGMENT_BYTES && bytes.len() >= 12 && &bytes[..8] == MAGIC,
            "unsupported audit archive format"
        );
        ensure!(
            hex::encode(Sha256::digest(bytes)) == expected.ciphertext_sha256,
            "audit archive link digest differs"
        );
        let length = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(
            length <= HEADER_LIMIT && length <= bytes.len() - 12,
            "invalid audit archive header length"
        );
        let encoded = &bytes[12..12 + length];
        let header: Header = serde_json::from_slice(encoded)?;
        ensure!(header.format == 1, "unsupported audit archive version");
        ensure!(
            serde_json::to_vec(&header)? == encoded,
            "noncanonical audit archive header"
        );
        let reference = reference(&header, bytes)?;
        reference.validate()?;
        ensure!(
            reference.object == *expected,
            "audit archive link identity differs"
        );
        ensure!(
            header.plaintext_bytes <= PAYLOAD_LIMIT as u64,
            "audit plaintext exceeds limit"
        );
        Ok(Self {
            bytes,
            header,
            reference,
        })
    }
    pub fn source_tenant(&self) -> &str {
        &self.header.tenant
    }
    pub fn source_purpose(&self) -> &StoragePurpose {
        &self.header.purpose
    }
    pub fn reference(&self) -> &AuditArchiveReference {
        &self.reference
    }
    pub async fn verify(
        &self,
        verifier: &HistoricalAuditVerifier<'_>,
    ) -> Result<VerifiedAuditSegment> {
        verifier.decrypt(self.bytes, &self.reference).await
    }
}

pub struct VerifiedAuditSegment {
    reference: AuditArchiveReference,
    source_purpose: StoragePurpose,
    plaintext: Zeroizing<Vec<u8>>,
}

impl VerifiedAuditSegment {
    pub fn source_purpose(&self) -> &StoragePurpose {
        &self.source_purpose
    }
    pub fn reference(&self) -> &AuditArchiveReference {
        &self.reference
    }

    /// The segment has already been checked in full before any record escapes.
    pub fn visit(&self, mut visitor: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
        walk_records(
            &self.plaintext,
            self.reference.object.first_sequence,
            self.reference.record_count,
            &mut visitor,
        )
    }
}

fn walk_records(
    bytes: &[u8],
    first: u64,
    expected_count: u64,
    visitor: &mut impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut remaining = bytes;
    let mut sequence = first;
    while !remaining.is_empty() {
        ensure!(remaining.len() >= 4, "truncated audit record length");
        let length = u32::from_be_bytes(remaining[..4].try_into()?) as usize;
        remaining = &remaining[4..];
        ensure!(
            length > 0 && length <= MAX_AUDIT_EVENT_BYTES && length <= remaining.len(),
            "invalid audit record length"
        );
        visitor(sequence, &remaining[..length])?;
        sequence = sequence.checked_add(1).context("audit sequence overflow")?;
        remaining = &remaining[length..];
    }
    ensure!(
        sequence.checked_sub(first) == Some(expected_count),
        "audit record count mismatch"
    );
    Ok(())
}

impl TenantStore {
    /// The engine selects the exact historical source from a verified graph and
    /// lineage. This retains this store's live fences throughout fresh historical
    /// key authorization; it cannot open or renew the historical source store.
    pub async fn verify_historical_audit(
        &self,
        dependency: &InspectedAuditDependency<'_>,
        source_purpose: &StoragePurpose,
    ) -> Result<VerifiedAuditSegment> {
        let _access = AccessGuard(self);
        self.check_access()?;
        let verifier = HistoricalAuditVerifier::new(
            &self.tenant,
            source_purpose,
            self.provider.as_ref(),
            &self.access,
        )?;
        let verified = dependency.verify(&verifier).await?;
        self.check_access()?;
        Ok(verified)
    }

    pub fn encrypt_audit_segment(
        &self,
        builder: AuditSegmentBuilder,
    ) -> Result<PreparedAuditSegment> {
        let _access = AccessGuard(self);
        self.check_access()?;
        ensure!(
            builder.record_count() > 0,
            "cannot archive an empty audit range"
        );
        let state = self.state.read();
        self.require_access(&state)?;
        let catalog = self.catalog.read();
        let header = Header {
            format: 1,
            object_id: Uuid::new_v4(),
            tenant: self.tenant.clone(),
            purpose: self.access.purpose().clone(),
            stream_id: builder.stream_id,
            first_sequence: builder.first_sequence,
            next_sequence: builder.next_sequence,
            record_count: builder.record_count(),
            plaintext_bytes: builder.plaintext_bytes(),
            plaintext_sha256: hex::encode(Sha256::digest(builder.payload.as_slice())),
            previous: builder.previous,
            wrapped_key: catalog
                .keys
                .get(&catalog.active)
                .context("audit archive key missing")?
                .clone(),
        };
        let encoded = serde_json::to_vec(&header)?;
        ensure!(
            encoded.len() <= HEADER_LIMIT,
            "audit archive header exceeds limit"
        );
        let encrypted = encrypt(
            state
                .keys
                .get(&catalog.active)
                .context("audit archive key unavailable")?,
            &builder.payload,
            &encoded,
        )?;
        let mut ciphertext = Vec::with_capacity(12 + encoded.len() + encrypted.len());
        ciphertext.extend(MAGIC);
        ciphertext.extend(u32::try_from(encoded.len())?.to_be_bytes());
        ciphertext.extend(&encoded);
        ciphertext.extend(encrypted);
        ensure!(
            ciphertext.len() <= MAX_AUDIT_SEGMENT_BYTES,
            "audit segment exceeds 8 MiB"
        );
        let reference = reference(&header, &ciphertext)?;
        reference.validate()?;
        self.require_access(&state)?;
        Ok(PreparedAuditSegment {
            reference,
            ciphertext,
        })
    }

    /// Authorize the exact historical wrapping key afresh; never substitute the
    /// current key or accept a digest before authenticated decoding completes.
    pub async fn decrypt_audit_segment(
        &self,
        bytes: &[u8],
        expected: &AuditArchiveReference,
    ) -> Result<VerifiedAuditSegment> {
        let _access = AccessGuard(self);
        self.check_access()?;
        AuditDecoder {
            tenant: &self.tenant,
            purpose: self.access.purpose(),
            provider: self.provider.as_ref(),
            clock: self.clock.as_ref(),
        }
        .decode(bytes, expected, || self.check_access())
        .await
    }
}

/// Verify an application archive from an explicitly selected historical source.
/// The exact source purpose must come from an authenticated checkpoint/dependency
/// graph. This verifier grants no source storage access and never substitutes a
/// current replica or target identity for the identity authenticated in the bytes.
/// The caller retains its request, policy and response-release fences.
pub struct HistoricalAuditVerifier<'a> {
    decoder: AuditDecoder<'a>,
    access: &'a crate::StorageAccess,
}
impl<'a> HistoricalAuditVerifier<'a> {
    pub fn new(
        tenant: &'a str,
        source_purpose: &'a StoragePurpose,
        provider: &'a dyn crate::KeyProvider,
        current_access: &'a crate::StorageAccess,
    ) -> Result<Self> {
        current_access.validate_tenant(tenant)?;
        current_access.check()?;
        match source_purpose {
            StoragePurpose::Standalone {
                installation_id,
                tenant: source_tenant,
                incarnation,
            } => ensure!(
                source_tenant == tenant && !installation_id.is_nil() && !incarnation.is_nil(),
                "historical audit application identity differs"
            ),
            StoragePurpose::Serving {
                manifest_digest,
                identity,
                recovery_checkpoint,
            } => {
                kasumi_types::validate_sha256(manifest_digest)?;
                identity.validate()?;
                ensure!(identity.tenant == tenant, "historical audit tenant differs");
                if let Some(checkpoint) = recovery_checkpoint {
                    checkpoint.validate()?;
                    ensure!(
                        checkpoint.tenant == tenant,
                        "historical audit lineage tenant differs"
                    );
                }
            }
            #[cfg(any(test, feature = "test-utils"))]
            StoragePurpose::LocalFixture => (),
            _ => anyhow::bail!("reserved storage purpose is not application history"),
        }
        Ok(Self {
            decoder: AuditDecoder {
                tenant,
                purpose: source_purpose,
                provider,
                clock: &kasumi_clock::SystemLeaseClock,
            },
            access: current_access,
        })
    }

    pub async fn decrypt(
        &self,
        bytes: &[u8],
        expected: &AuditArchiveReference,
    ) -> Result<VerifiedAuditSegment> {
        self.access.check()?;
        self.decoder
            .decode(bytes, expected, || self.access.check())
            .await
    }
}

struct AuditDecoder<'a> {
    tenant: &'a str,
    purpose: &'a StoragePurpose,
    provider: &'a dyn crate::KeyProvider,
    clock: &'a dyn kasumi_clock::LeaseClock,
}
impl AuditDecoder<'_> {
    async fn decode(
        &self,
        bytes: &[u8],
        expected: &AuditArchiveReference,
        check: impl Fn() -> Result<()>,
    ) -> Result<VerifiedAuditSegment> {
        check()?;
        expected.validate()?;
        ensure!(
            bytes.len() <= MAX_AUDIT_SEGMENT_BYTES && bytes.len() >= 12 && &bytes[..8] == MAGIC,
            "unsupported audit archive format"
        );
        ensure!(
            bytes.len() as u64 == expected.ciphertext_bytes
                && hex::encode(Sha256::digest(bytes)) == expected.object.ciphertext_sha256,
            "audit archive dependency mismatch"
        );
        let length = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(
            length <= HEADER_LIMIT && length <= bytes.len() - 12,
            "invalid audit archive header length"
        );
        let encoded = &bytes[12..12 + length];
        let header: Header = serde_json::from_slice(encoded)?;
        ensure!(
            header.format == 1 && header.tenant == self.tenant && &header.purpose == self.purpose,
            "audit archive purpose mismatch"
        );
        ensure!(
            serde_json::to_vec(&header)? == encoded,
            "noncanonical audit archive header"
        );
        ensure!(
            reference(&header, bytes)? == *expected,
            "audit archive identity mismatch"
        );
        ensure!(
            header.plaintext_bytes <= PAYLOAD_LIMIT as u64,
            "audit archive plaintext exceeds limit"
        );
        let start = self.clock.now();
        let deadline = start
            .checked_add(crate::MAX_KEY_LEASE)
            .context("audit key deadline overflow")?;
        let key = tokio::time::timeout(
            PROVIDER_TIMEOUT,
            self.provider.unwrap_key(self.tenant, &header.wrapped_key),
        )
        .await
        .context("audit archive key authorization timed out")??;
        check()?;
        ensure!(
            self.clock.now() < deadline,
            "audit archive key authorization expired"
        );
        let plaintext = Zeroizing::new(decrypt(&key, &bytes[12 + length..], encoded)?);
        ensure!(
            plaintext.len() as u64 == header.plaintext_bytes
                && hex::encode(Sha256::digest(plaintext.as_slice())) == header.plaintext_sha256,
            "audit archive final digest or byte count mismatch"
        );
        walk_records(
            &plaintext,
            header.first_sequence,
            header.record_count,
            &mut |_, _| Ok(()),
        )?;
        check()?;
        ensure!(
            self.clock.now() < deadline,
            "audit archive key authorization expired before release"
        );
        Ok(VerifiedAuditSegment {
            reference: expected.clone(),
            source_purpose: header.purpose,
            plaintext,
        })
    }
}

fn reference(header: &Header, ciphertext: &[u8]) -> Result<AuditArchiveReference> {
    Ok(AuditArchiveReference {
        stream_id: header.stream_id,
        object: AuditArchiveLink {
            object_id: header.object_id,
            first_sequence: header.first_sequence,
            next_sequence: header.next_sequence,
            ciphertext_sha256: hex::encode(Sha256::digest(ciphertext)),
        },
        previous: header.previous.clone(),
        record_count: header.record_count,
        plaintext_bytes: header.plaintext_bytes,
        ciphertext_bytes: ciphertext.len() as u64,
        key: AuditArchiveKeyDependency {
            provider: header.wrapped_key.provider.clone(),
            key_ref: header.wrapped_key.key_ref.clone(),
            version: header.wrapped_key.version,
            wrapped_key_sha256: hex::encode(Sha256::digest(serde_json::to_vec(
                &header.wrapped_key,
            )?)),
        },
    })
}

#[async_trait]
pub trait AuditArchiveDestination: Send + Sync {
    /// Stable installed namespace identity, excluding renewable credentials.
    fn identity(&self) -> String;
    /// Idempotent only for identical bytes. Success proves durable publication
    /// and a complete readback. An error never authorizes hot-record deletion.
    async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()>;
    async fn read(&self, link: &AuditArchiveLink) -> Result<Vec<u8>>;
}

/// Every replica owns a durable ciphertext cache independently of the selected
/// external destination. Snapshot capture uses only this cache. Placement is a
/// local installation binding, never replicated from another member's paths.
pub struct TenantAuditPlacement {
    cache: Arc<FilesystemAuditArchive>,
    destination: Arc<dyn AuditArchiveDestination>,
}
impl TenantAuditPlacement {
    pub fn cache(&self) -> &Arc<FilesystemAuditArchive> {
        &self.cache
    }
    pub fn destination_identity(&self) -> String {
        self.destination.identity()
    }
    /// Use in an owned blocking apply worker. Publication uncertainty cannot
    /// authorize pruning, even if the local cache already contains the object.
    pub fn preserve_blocking(&self, segment: &PreparedAuditSegment) -> Result<()> {
        self.cache.publish_blocking(segment)?;
        if self.cache.identity() != self.destination.identity() {
            tokio::runtime::Handle::try_current()?.block_on(self.destination.publish(segment))?;
        }
        Ok(())
    }
}
impl TenantStore {
    /// Call before engine replay to install an S3 destination or an explicit
    /// fixture cache. A persisted destination cannot silently become the default
    /// filesystem destination after a restart or missing configuration.
    pub fn install_tenant_audit_archive(
        &self,
        cache: Arc<FilesystemAuditArchive>,
        destination: Arc<dyn AuditArchiveDestination>,
    ) -> Result<Arc<TenantAuditPlacement>> {
        self.check_access()?;
        let mut placement = self.audit_placement.lock();
        let identity = serde_json::to_vec(&(cache.identity(), destination.identity()))?;
        ensure!(
            identity.len() <= 16 << 10,
            "audit placement identity exceeds limit"
        );
        if let Some(existing) = placement.as_ref() {
            ensure!(
                existing.cache.identity() == cache.identity()
                    && existing.destination.identity() == destination.identity(),
                "live tenant audit placement differs"
            );
            return Ok(existing.clone());
        }
        const NS: &str = "engine.audit.placement";
        match self.get(NS, b"identity")? {
            Some(stored) => ensure!(
                stored == identity,
                "installed tenant audit placement differs"
            ),
            None => {
                self.write_batch(&[crate::WriteOp::put(NS, b"identity", identity.as_slice())])?
            }
        }
        self.check_access()?;
        let installed = Arc::new(TenantAuditPlacement { cache, destination });
        *placement = Some(installed.clone());
        Ok(installed)
    }
    pub fn tenant_audit_archive(&self) -> Result<Arc<TenantAuditPlacement>> {
        if let Some(placement) = self.audit_placement.lock().clone() {
            self.check_access()?;
            return Ok(placement);
        }
        let cache = Arc::new(FilesystemAuditArchive::open(
            self.durable_directory()?.join("tenant-audit-archives"),
        )?);
        self.install_tenant_audit_archive(cache.clone(), cache)
    }
}

pub struct FilesystemAuditArchive {
    root: PathBuf,
}
impl FilesystemAuditArchive {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        match std::fs::symlink_metadata(root) {
            Ok(_) => crate::private_files::check_directory(root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Exclusive creation never changes an existing directory's
                // owner or permissions, including when another opener races.
                if let Err(error) = crate::private_files::create_directory(root) {
                    crate::private_files::check_directory(root).map_err(|_| error)?;
                }
            }
            Err(error) => return Err(error.into()),
        }
        std::fs::File::open(root)?.sync_all()?;
        crate::private_files::sync_parent(root)?;
        Ok(Self {
            root: std::fs::canonicalize(root)?,
        })
    }

    /// For an already-owned blocking snapshot/apply worker. One bounded object
    /// is read and checked without network I/O or a nested async runtime.
    pub fn read_blocking(&self, link: &AuditArchiveLink) -> Result<Vec<u8>> {
        read_file(&self.root, link, false)
    }

    /// Successful return includes file and directory synchronization and an
    /// exact complete readback. This may be replayed after an uncertain result.
    pub fn publish_blocking(&self, segment: &PreparedAuditSegment) -> Result<()> {
        segment.reference.validate()?;
        ensure!(
            segment.ciphertext.len() as u64 == segment.reference.ciphertext_bytes
                && hex::encode(Sha256::digest(&segment.ciphertext))
                    == segment.reference.object.ciphertext_sha256,
            "invalid prepared audit segment"
        );
        let path = self
            .root
            .join(format!("{}.audit", segment.reference.object.object_id));
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        temporary.write_all(&segment.ciphertext)?;
        temporary.as_file().sync_all()?;
        if let Err(error) = temporary.persist_noclobber(path) {
            ensure!(
                error.error.kind() == std::io::ErrorKind::AlreadyExists,
                "audit archive publication failed"
            );
        }
        read_file(&self.root, &segment.reference.object, true)?;
        Ok(())
    }
}

fn read_file(root: &Path, link: &AuditArchiveLink, durable: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(durable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join(format!("{}.audit", link.object_id)))?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_AUDIT_SEGMENT_BYTES as u64,
        "invalid audit archive object"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_AUDIT_SEGMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_AUDIT_SEGMENT_BYTES
            && hex::encode(Sha256::digest(&bytes)) == link.ciphertext_sha256,
        "audit archive readback mismatch"
    );
    if durable {
        file.sync_all()?;
        std::fs::File::open(root)?.sync_all()?;
    }
    Ok(bytes)
}

#[async_trait]
impl AuditArchiveDestination for FilesystemAuditArchive {
    fn identity(&self) -> String {
        format!("filesystem:{}", self.root.display())
    }
    async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()> {
        segment.reference.validate()?;
        ensure!(
            segment.ciphertext.len() as u64 == segment.reference.ciphertext_bytes
                && hex::encode(Sha256::digest(&segment.ciphertext))
                    == segment.reference.object.ciphertext_sha256,
            "invalid prepared audit segment"
        );
        let archive = Self {
            root: self.root.clone(),
        };
        let segment = PreparedAuditSegment {
            reference: segment.reference.clone(),
            ciphertext: segment.ciphertext.clone(),
        };
        tokio::task::spawn_blocking(move || archive.publish_blocking(&segment)).await?
    }
    async fn read(&self, link: &AuditArchiveLink) -> Result<Vec<u8>> {
        let root = self.root.clone();
        let link = link.clone();
        tokio::task::spawn_blocking(move || read_file(&root, &link, false)).await?
    }
}

/// Uses the installed S3 origin/prefix and its atomic renewable credentials.
/// The destination must provide durable create-only PUT and strongly consistent
/// GET semantics; these are part of the supported S3 deployment contract.
pub struct S3AuditArchive {
    destination: Arc<S3BackupDestination>,
}
impl S3AuditArchive {
    pub fn new(destination: Arc<S3BackupDestination>) -> Self {
        Self { destination }
    }
}
#[async_trait]
impl AuditArchiveDestination for S3AuditArchive {
    fn identity(&self) -> String {
        self.destination.namespace_identity()
    }
    async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()> {
        segment.reference.validate()?;
        ensure!(
            segment.ciphertext.len() as u64 == segment.reference.ciphertext_bytes
                && hex::encode(Sha256::digest(&segment.ciphertext))
                    == segment.reference.object.ciphertext_sha256,
            "invalid prepared audit segment"
        );
        let publication = self
            .destination
            .put(
                segment.reference.object.object_id,
                segment.ciphertext.clone(),
            )
            .await;
        // A lost PUT reply or an identical existing object is resolved by exact
        // authenticated readback; a failed readback cannot permit pruning.
        let readback = self.read(&segment.reference.object).await;
        match readback {
            Ok(_) => Ok(()),
            Err(error) => Err(publication.err().unwrap_or(error)),
        }
    }
    async fn read(&self, link: &AuditArchiveLink) -> Result<Vec<u8>> {
        let bytes = self
            .destination
            .get(link.object_id, MAX_AUDIT_SEGMENT_BYTES)
            .await?;
        ensure!(
            bytes.len() <= MAX_AUDIT_SEGMENT_BYTES
                && hex::encode(Sha256::digest(&bytes)) == link.ciphertext_sha256,
            "audit archive readback mismatch"
        );
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeStore, test_utils::LocalKeyProvider};

    async fn store(directory: &Path) -> Arc<TenantStore> {
        TenantStore::open_fixture(
            NodeStore::open(directory.join("audit.redb")).unwrap(),
            "__kasumi_security".into(),
            Arc::new(LocalKeyProvider::new([73; 32])),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn verified_archive_is_private_immutable_contiguous_and_reopenable() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(directory.path()).await;
        let stream = Uuid::new_v4();
        let mut first = AuditSegmentBuilder::new(stream, 0, None).unwrap();
        assert!(first.push(0, b"secret audit record zero").unwrap());
        assert!(first.push(1, b"secret audit record one").unwrap());
        assert!(first.push(3, b"gap").is_err());
        let first = store.encrypt_audit_segment(first).unwrap();
        assert!(
            !first
                .ciphertext
                .windows(19)
                .any(|b| b == b"secret audit record")
        );
        let path = directory.path().join("archives");
        let destination = FilesystemAuditArchive::open(&path).unwrap();
        destination.publish(&first).await.unwrap();
        destination.publish(&first).await.unwrap();
        drop(destination);
        let destination = FilesystemAuditArchive::open(&path).unwrap();
        let bytes = destination.read(&first.reference.object).await.unwrap();
        let verified = store
            .decrypt_audit_segment(&bytes, &first.reference)
            .await
            .unwrap();
        let mut records = Vec::new();
        verified
            .visit(|sequence, bytes| {
                records.push((sequence, bytes.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            records,
            vec![
                (0, b"secret audit record zero".to_vec()),
                (1, b"secret audit record one".to_vec())
            ]
        );

        let mut next =
            AuditSegmentBuilder::new(stream, 2, Some(first.reference.object.clone())).unwrap();
        next.push(2, b"third record").unwrap();
        let next = store.encrypt_audit_segment(next).unwrap();
        destination.publish(&next).await.unwrap();
        assert_eq!(
            next.reference.previous,
            Some(first.reference.object.clone())
        );
        assert_eq!(next.reference.object.next_sequence, 3);

        let object = path.join(format!("{}.audit", first.reference.object.object_id));
        std::fs::write(&object, b"corrupted ciphertext").unwrap();
        assert!(destination.publish(&first).await.is_err());
        assert_eq!(std::fs::read(&object).unwrap(), b"corrupted ciphertext");
        assert!(destination.read(&first.reference.object).await.is_err());
        store.shutdown().await;
    }

    #[tokio::test]
    async fn segment_capacity_is_bounded_and_positions_use_checked_u64() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(directory.path()).await;
        let first = u64::from(u32::MAX) + 100;
        let previous = AuditArchiveLink {
            object_id: Uuid::new_v4(),
            first_sequence: 0,
            next_sequence: first,
            ciphertext_sha256: "a".repeat(64),
        };
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), first, Some(previous)).unwrap();
        let record = vec![93; MAX_AUDIT_EVENT_BYTES];
        let mut sequence = first;
        while builder.push(sequence, &record).unwrap() {
            sequence += 1;
        }
        assert!(sequence > first);
        let count = builder.record_count();
        assert!(!builder.push(sequence, &record).unwrap());
        assert_eq!(builder.record_count(), count);
        let segment = store.encrypt_audit_segment(builder).unwrap();
        assert!(segment.ciphertext.len() <= MAX_AUDIT_SEGMENT_BYTES);
        let verified = store
            .decrypt_audit_segment(&segment.ciphertext, &segment.reference)
            .await
            .unwrap();
        let mut seen = 0;
        verified
            .visit(|sequence, bytes| {
                assert_eq!(sequence, first + seen);
                assert_eq!(bytes, record);
                seen += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, count);

        let previous = AuditArchiveLink {
            object_id: Uuid::new_v4(),
            first_sequence: 0,
            next_sequence: u64::MAX,
            ciphertext_sha256: "a".repeat(64),
        };
        let mut exhausted =
            AuditSegmentBuilder::new(Uuid::new_v4(), u64::MAX, Some(previous)).unwrap();
        assert!(exhausted.push(u64::MAX, b"overflow").is_err());
        assert_eq!(exhausted.record_count(), 0);
        store.shutdown().await;
    }

    #[tokio::test]
    async fn authentication_and_final_record_counts_precede_any_release() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(directory.path()).await;
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        builder.push(0, b"one").unwrap();
        // Model an authenticated but malformed producer: count claims two while
        // the plaintext contains one frame. No caller can obtain partial data.
        builder.next_sequence = 2;
        let malformed = store.encrypt_audit_segment(builder).unwrap();
        assert!(
            store
                .decrypt_audit_segment(&malformed.ciphertext, &malformed.reference)
                .await
                .is_err()
        );

        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        builder.push(0, b"one").unwrap();
        let mut segment = store.encrypt_audit_segment(builder).unwrap();
        let last = segment.ciphertext.len() - 1;
        segment.ciphertext[last] ^= 1;
        // Even a caller that substitutes a matching public digest cannot forge
        // the AEAD tag and make altered plaintext escape.
        segment.reference.object.ciphertext_sha256 =
            hex::encode(Sha256::digest(&segment.ciphertext));
        assert!(
            store
                .decrypt_audit_segment(&segment.ciphertext, &segment.reference)
                .await
                .is_err()
        );
        store.shutdown().await;
    }

    #[tokio::test]
    async fn object_symlink_cannot_read_or_overwrite_unrelated_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(directory.path()).await;
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        builder.push(0, b"one").unwrap();
        let segment = store.encrypt_audit_segment(builder).unwrap();
        let path = directory.path().join("archives");
        let destination = FilesystemAuditArchive::open(&path).unwrap();
        let unrelated = directory.path().join("unrelated");
        std::fs::write(&unrelated, &segment.ciphertext).unwrap();
        std::os::unix::fs::symlink(
            &unrelated,
            path.join(format!("{}.audit", segment.reference.object.object_id)),
        )
        .unwrap();
        assert!(destination.read(&segment.reference.object).await.is_err());
        assert!(destination.publish(&segment).await.is_err());
        assert_eq!(std::fs::read(&unrelated).unwrap(), segment.ciphertext);
        store.shutdown().await;
    }

    #[tokio::test]
    async fn historical_source_is_exact_and_does_not_reopen_a_live_generation() {
        let directory = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeyProvider::new([31; 32]));
        let installation = Uuid::new_v4();
        let source =
            crate::StorageAccess::standalone(installation, "tenant", Uuid::new_v4()).unwrap();
        let store = TenantStore::open(
            NodeStore::open(directory.path().join("source.redb")).unwrap(),
            "tenant".into(),
            keys.clone(),
            source.clone(),
        )
        .await
        .unwrap();
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        builder.push(0, b"retained before recovery").unwrap();
        let segment = store.encrypt_audit_segment(builder).unwrap();
        store.shutdown().await;
        // Source shutdown is permanent for its live store. A separately authorized
        // target can still verify exactly selected historical data and keys.
        assert!(
            store
                .decrypt_audit_segment(&segment.ciphertext, &segment.reference)
                .await
                .is_err()
        );
        let target =
            crate::StorageAccess::standalone(installation, "tenant", Uuid::new_v4()).unwrap();
        let historical =
            HistoricalAuditVerifier::new("tenant", source.purpose(), keys.as_ref(), &target)
                .unwrap();
        let verified = historical
            .decrypt(&segment.ciphertext, &segment.reference)
            .await
            .unwrap();
        verified
            .visit(|sequence, bytes| {
                assert_eq!(sequence, 0);
                assert_eq!(bytes, b"retained before recovery");
                Ok(())
            })
            .unwrap();
        assert!(
            HistoricalAuditVerifier::new("tenant", target.purpose(), keys.as_ref(), &target)
                .unwrap()
                .decrypt(&segment.ciphertext, &segment.reference)
                .await
                .is_err()
        );
        let other =
            crate::StorageAccess::standalone(Uuid::new_v4(), "tenant", Uuid::new_v4()).unwrap();
        assert!(
            HistoricalAuditVerifier::new("tenant", other.purpose(), keys.as_ref(), &target)
                .unwrap()
                .decrypt(&segment.ciphertext, &segment.reference)
                .await
                .is_err()
        );
        assert!(
            HistoricalAuditVerifier::new("other", source.purpose(), keys.as_ref(), &target)
                .is_err()
        );
        assert!(
            HistoricalAuditVerifier::new(
                "tenant",
                &StoragePurpose::SecurityAudit,
                keys.as_ref(),
                &target
            )
            .is_err()
        );
        keys.revoke();
        assert!(
            historical
                .decrypt(&segment.ciphertext, &segment.reference)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reverse_archive_dependencies_are_bounded_and_require_exact_link_and_source_verification()
     {
        let directory = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeyProvider::new([33; 32]));
        let access =
            crate::StorageAccess::standalone(Uuid::new_v4(), "tenant", Uuid::new_v4()).unwrap();
        let store = TenantStore::open(
            NodeStore::open(directory.path().join("source.redb")).unwrap(),
            "tenant".into(),
            keys.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        let stream = Uuid::new_v4();
        let mut first = AuditSegmentBuilder::new(stream, 0, None).unwrap();
        first.push(0, b"first").unwrap();
        let first = store.encrypt_audit_segment(first).unwrap();
        let mut second =
            AuditSegmentBuilder::new(stream, 1, Some(first.reference.object.clone())).unwrap();
        second.push(1, b"second").unwrap();
        let second = store.encrypt_audit_segment(second).unwrap();
        let destination = FilesystemAuditArchive::open(directory.path().join("archives")).unwrap();
        destination.publish(&first).await.unwrap();
        destination.publish(&second).await.unwrap();
        let verifier =
            HistoricalAuditVerifier::new("tenant", access.purpose(), keys.as_ref(), &access)
                .unwrap();
        let mut link = Some(second.reference.object.clone());
        let mut count = 0u64;
        while let Some(expected) = link.take() {
            let bytes = destination.read(&expected).await.unwrap();
            let inspected = InspectedAuditDependency::from_link(&bytes, &expected).unwrap();
            assert_eq!(inspected.source_tenant(), "tenant");
            assert_eq!(inspected.source_purpose(), access.purpose());
            let verified = inspected.verify(&verifier).await.unwrap();
            assert_eq!(verified.source_purpose(), access.purpose());
            count += verified.reference().record_count;
            link = verified.reference().previous.clone();
        }
        assert_eq!(count, 2);
        assert!(
            InspectedAuditDependency::from_link(&first.ciphertext, &second.reference.object)
                .is_err()
        );
        let mut incorrect = first.reference.object.clone();
        incorrect.object_id = Uuid::new_v4();
        assert!(InspectedAuditDependency::from_link(&first.ciphertext, &incorrect).is_err());
        let mut forged = first.ciphertext.clone();
        *forged.last_mut().unwrap() ^= 1;
        let mut forged_link = first.reference.object.clone();
        forged_link.ciphertext_sha256 = hex::encode(Sha256::digest(&forged));
        // Even an attacker-controlled selected link only yields inspection;
        // altered ciphertext cannot cross the authenticated proof boundary.
        let inspected = InspectedAuditDependency::from_link(&forged, &forged_link).unwrap();
        assert!(inspected.verify(&verifier).await.is_err());
        store.shutdown().await;
    }

    #[tokio::test]
    async fn historical_verification_checks_the_original_clock_and_release_fence() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct ExpiringKey {
            inner: Arc<LocalKeyProvider>,
            clock: Arc<crate::test_utils::ManualClock>,
            revoked: Arc<AtomicBool>,
        }
        #[async_trait]
        impl crate::KeyProvider for ExpiringKey {
            async fn generate_key(&self, _: &str) -> Result<crate::GeneratedKey> {
                anyhow::bail!("unused")
            }
            async fn unwrap_key(&self, tenant: &str, key: &WrappedKey) -> Result<crate::SecretKey> {
                let key = self.inner.unwrap_key(tenant, key).await?;
                self.clock.advance(crate::MAX_KEY_LEASE);
                self.revoked.store(true, Ordering::SeqCst);
                Ok(key)
            }
            async fn rewrap_key(&self, _: &str, _: &WrappedKey) -> Result<WrappedKey> {
                anyhow::bail!("unused")
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeyProvider::new([32; 32]));
        let access =
            crate::StorageAccess::standalone(Uuid::new_v4(), "tenant", Uuid::new_v4()).unwrap();
        let store = TenantStore::open(
            NodeStore::open(directory.path().join("source.redb")).unwrap(),
            "tenant".into(),
            keys.clone(),
            access.clone(),
        )
        .await
        .unwrap();
        let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
        builder.push(0, b"never released").unwrap();
        let segment = store.encrypt_audit_segment(builder).unwrap();
        let clock = Arc::new(crate::test_utils::ManualClock::new());
        let revoked = Arc::new(AtomicBool::new(false));
        let provider = ExpiringKey {
            inner: keys,
            clock: clock.clone(),
            revoked: revoked.clone(),
        };
        let decoder = AuditDecoder {
            tenant: "tenant",
            purpose: access.purpose(),
            provider: &provider,
            clock: clock.as_ref(),
        };
        assert!(
            decoder
                .decode(&segment.ciphertext, &segment.reference, || Ok(()))
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("expired")
        );
        revoked.store(false, Ordering::SeqCst);
        assert!(
            decoder
                .decode(&segment.ciphertext, &segment.reference, || {
                    ensure!(
                        !revoked.load(Ordering::SeqCst),
                        "request revoked during key unwrap"
                    );
                    Ok(())
                })
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("request revoked")
        );
        store.shutdown().await;
    }

    #[test]
    fn existing_nonprivate_archive_directory_is_rejected_without_chmod() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("public");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FilesystemAuditArchive::open(&root).is_err());
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o755);
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(directory.path(), &alias).unwrap();
        assert!(FilesystemAuditArchive::open(&alias).is_err());
    }
}
