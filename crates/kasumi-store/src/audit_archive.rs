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

pub struct VerifiedAuditSegment {
    reference: AuditArchiveReference,
    plaintext: Zeroizing<Vec<u8>>,
}

impl VerifiedAuditSegment {
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
            header.format == 1
                && header.tenant == self.tenant
                && &header.purpose == self.access.purpose(),
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
            self.provider.unwrap_key(&self.tenant, &header.wrapped_key),
        )
        .await
        .context("audit archive key authorization timed out")??;
        self.check_access()?;
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
        self.check_access()?;
        ensure!(
            self.clock.now() < deadline,
            "audit archive key authorization expired before release"
        );
        Ok(VerifiedAuditSegment {
            reference: expected.clone(),
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
    /// Idempotent only for identical bytes. Success proves durable publication
    /// and a complete readback. An error never authorizes hot-record deletion.
    async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()>;
    async fn read(&self, link: &AuditArchiveLink) -> Result<Vec<u8>>;
}

pub struct FilesystemAuditArchive {
    root: PathBuf,
}
impl FilesystemAuditArchive {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let root = root.as_ref();
        crate::durable_directory(root)?;
        ensure!(
            !std::fs::symlink_metadata(root)?.file_type().is_symlink(),
            "audit archive root cannot be a symlink"
        );
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::File::open(root)?.sync_all()?;
        Ok(Self {
            root: std::fs::canonicalize(root)?,
        })
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
    async fn publish(&self, segment: &PreparedAuditSegment) -> Result<()> {
        segment.reference.validate()?;
        ensure!(
            segment.ciphertext.len() as u64 == segment.reference.ciphertext_bytes
                && hex::encode(Sha256::digest(&segment.ciphertext))
                    == segment.reference.object.ciphertext_sha256,
            "invalid prepared audit segment"
        );
        let root = self.root.clone();
        let link = segment.reference.object.clone();
        let bytes = segment.ciphertext.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let path = root.join(format!("{}.audit", link.object_id));
            let mut temporary = tempfile::NamedTempFile::new_in(&root)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            if let Err(error) = temporary.persist_noclobber(path) {
                ensure!(
                    error.error.kind() == std::io::ErrorKind::AlreadyExists,
                    "audit archive publication failed"
                );
            }
            // Also resolves a previous rename/fsync uncertainty. Existing data
            // must match before its file and directory are synchronized again.
            read_file(&root, &link, true)?;
            Ok(())
        })
        .await?
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
}
