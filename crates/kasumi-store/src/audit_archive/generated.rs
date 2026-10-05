//! Serialize and encrypt directly into the single pre-admitted output buffer.
use super::*;
use crate::disk_memory;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use std::io::Write;

#[derive(Serialize)]
struct BorrowedHeader<'a> {
    format: u32,
    object_id: Uuid,
    tenant: &'a str,
    purpose: &'a StoragePurpose,
    stream_id: Uuid,
    first_sequence: u64,
    next_sequence: u64,
    previous: &'a Option<AuditArchiveLink>,
    record_count: u64,
    plaintext_bytes: u64,
    plaintext_sha256: &'a str,
    wrapped_key: &'a WrappedKey,
}

struct ByteCount(usize);
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= HEADER_LIMIT)
            .ok_or_else(|| std::io::Error::other("audit archive header exceeds limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HeaderWriter<'a> {
    output: &'a mut Vec<u8>,
    end: usize,
}
impl Write for HeaderWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= self.end)
            .ok_or_else(|| std::io::Error::other("audit header changed after admission"))?;
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn encrypt(
    store: &TenantStore,
    builder: AuditSegmentBuilder,
) -> Result<PreparedAuditSegment> {
    let _access = AccessGuard(store);
    store.check_access()?;
    ensure!(
        builder.record_count() > 0,
        "cannot archive an empty audit range"
    );
    let state = store.state.read();
    store.require_access(&state)?;
    let catalog = store.catalog.read();
    let wrapped_key = catalog
        .keys
        .get(&catalog.active)
        .context("audit archive key missing")?;
    let data_key = state
        .keys
        .get(&catalog.active)
        .context("audit archive key unavailable")?;
    let mut plaintext_digest = [0u8; 64];
    hex::encode_to_slice(
        Sha256::digest(builder.payload.as_slice()),
        &mut plaintext_digest,
    )?;
    let header = BorrowedHeader {
        format: 1,
        object_id: Uuid::new_v4(),
        tenant: &store.tenant,
        purpose: store.access.purpose(),
        stream_id: builder.stream_id,
        first_sequence: builder.first_sequence,
        next_sequence: builder.next_sequence,
        previous: &builder.previous,
        record_count: builder.record_count(),
        plaintext_bytes: builder.plaintext_bytes(),
        plaintext_sha256: std::str::from_utf8(&plaintext_digest)?,
        wrapped_key,
    };
    let mut count = ByteCount(0);
    serde_json::to_writer(&mut count, &header)?;
    let length = count
        .0
        .checked_add(builder.payload.len())
        .and_then(|size| size.checked_add(52))
        .context("audit ciphertext size overflow")?;
    ensure!(
        length <= MAX_AUDIT_SEGMENT_BYTES,
        "audit segment exceeds 8 MiB"
    );
    let owner = ciphertext::memory_owner(store);
    let allocation = owner
        .clone()
        .reserve_installed(AuditCiphertext::allocation_bytes()?)
        .context("audit archive shared custody admission denied")?;
    let admitted = disk_memory::allocation::<u8>(u64::try_from(length)?)?;
    let charge = owner
        .clone()
        .reserve_installed(admitted)
        .context("audit archive ciphertext output admission denied")?;
    let mut metadata_bytes = 0;
    for length in [
        Some(64usize),
        builder
            .previous
            .as_ref()
            .map(|link| link.ciphertext_sha256.len()),
        Some(wrapped_key.provider.len()),
        Some(wrapped_key.key_ref.len()),
        Some(64),
    ]
    .into_iter()
    .flatten()
    {
        metadata_bytes = disk_memory::add(
            metadata_bytes,
            disk_memory::allocation::<u8>(u64::try_from(length)?)?,
        )?;
    }
    let metadata = owner
        .clone()
        .reserve_installed(metadata_bytes)
        .context("audit archive metadata admission denied")?;

    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .context("audit ciphertext allocation failed")?;
    ensure!(
        u64::try_from(output.capacity())? <= admitted,
        "audit ciphertext allocation exceeds admission"
    );
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&u32::try_from(count.0)?.to_be_bytes());
    serde_json::to_writer(
        HeaderWriter {
            output: &mut output,
            end: 12 + count.0,
        },
        &header,
    )?;
    ensure!(
        output.len() == 12 + count.0,
        "audit header changed after admission"
    );
    let body_start = output.len();
    output.resize(length, 0);
    let (prefix, body) = output.split_at_mut(body_start);
    getrandom::fill(&mut body[..24]).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    let nonce: [u8; 24] = body[..24].try_into()?;
    let tag_start = body.len() - 16;
    body[24..tag_start].copy_from_slice(&builder.payload);
    let cipher = XChaCha20Poly1305::new_from_slice(data_key.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &prefix[12..],
            &mut body[24..tag_start],
        )
        .map_err(|_| anyhow::anyhow!("record encryption failed"))?;
    body[tag_start..].copy_from_slice(&tag);
    let mut wrapped_digest = HashWriter(Sha256::new());
    serde_json::to_writer(&mut wrapped_digest, wrapped_key)?;
    let reference = AuditArchiveReference {
        stream_id: header.stream_id,
        object: AuditArchiveLink {
            object_id: header.object_id,
            first_sequence: header.first_sequence,
            next_sequence: header.next_sequence,
            ciphertext_sha256: hex::encode(Sha256::digest(output.as_slice())),
        },
        previous: builder.previous.clone(),
        record_count: header.record_count,
        plaintext_bytes: header.plaintext_bytes,
        ciphertext_bytes: output.len() as u64,
        key: AuditArchiveKeyDependency {
            provider: wrapped_key.provider.clone(),
            key_ref: wrapped_key.key_ref.clone(),
            version: wrapped_key.version,
            wrapped_key_sha256: hex::encode(wrapped_digest.0.finalize()),
        },
    };
    reference.validate()?;
    store.require_access(&state)?;
    Ok(PreparedAuditSegment {
        reference,
        ciphertext: AuditCiphertext::generated(output, charge, owner, allocation),
        _reference_charge: metadata,
    })
}
