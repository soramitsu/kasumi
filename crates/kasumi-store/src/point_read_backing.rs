//! Reusable ordinary-funded point bytes shared by actual single and paired views.
//! Wrappers retain their own exact Store identity and per-loan access checks.
use super::*;
use std::{io, ops::Range};

pub(crate) struct EncryptedPointBacking {
    native: kasumi_kv::PreparedPointRead,
    pub(crate) plaintext: Zeroizing<Vec<u8>>,
    pub(crate) aad: Vec<u8>,
    plaintext_used: usize,
    namespace_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
    _charge: DiskMemoryLease,
}

pub(crate) struct PointBufferLayout {
    pub(crate) encrypted_bytes: usize,
    plaintext_bytes: usize,
    bounds: (usize, usize, usize),
    aad_bytes: usize,
    pub(crate) charge_bytes: u64,
}

pub(crate) fn point_buffer_layout(
    namespace_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
    tenant_bytes: usize,
    key_id_bytes: usize,
    owner_bytes: u64,
) -> io::Result<PointBufferLayout> {
    if !(1..=1024).contains(&namespace_bytes) || key_bytes > 4096 || value_bytes > MAX_RECORD {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let encrypted_bytes = encrypted_record_length(
        namespace_bytes,
        key_bytes,
        value_bytes,
        key_id_bytes.max(uuid::fmt::Hyphenated::LENGTH),
    )
    .filter(|bytes| *bytes <= MAX_BATCH)
    .ok_or_else(crate::disk_memory::overflow)?;
    let plaintext_bytes = namespace_bytes
        .checked_add(key_bytes)
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .and_then(|bytes| bytes.checked_add(12))
        .ok_or_else(crate::disk_memory::overflow)?;
    let aad_bytes = b"kasumi.encrypted-record.v1"
        .len()
        .checked_add(8)
        .and_then(|bytes| bytes.checked_add(tenant_bytes))
        .and_then(|bytes| bytes.checked_add(96))
        .ok_or_else(crate::disk_memory::overflow)?;
    let charge_bytes = crate::disk_memory::add(
        owner_bytes,
        crate::disk_memory::add(
            crate::disk_memory::allocation::<u8>(plaintext_bytes as u64)?,
            crate::disk_memory::allocation::<u8>(aad_bytes as u64)?,
        )?,
    )?;
    Ok(PointBufferLayout {
        encrypted_bytes,
        plaintext_bytes,
        bounds: (namespace_bytes, key_bytes, value_bytes),
        aad_bytes,
        charge_bytes,
    })
}

impl EncryptedPointBacking {
    pub(crate) fn new(
        transaction: &read_view::ViewTransaction,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        layout: PointBufferLayout,
    ) -> Result<Self> {
        let PointBufferLayout {
            encrypted_bytes,
            plaintext_bytes,
            aad_bytes,
            bounds,
            charge_bytes,
        } = layout;
        let charge = provider.clone().reserve_installed(charge_bytes)?;
        let native = transaction.prepare_point_read(encrypted_bytes)?;
        let mut plaintext = Vec::new();
        plaintext.try_reserve_exact(plaintext_bytes)?;
        ensure!(
            plaintext.capacity() == plaintext_bytes,
            "prepared plaintext backing exceeds admission"
        );
        plaintext.resize(plaintext_bytes, 0);
        let mut aad = Vec::new();
        aad.try_reserve_exact(aad_bytes)?;
        ensure!(
            aad.capacity() == aad_bytes,
            "prepared AAD backing exceeds admission"
        );
        Ok(Self {
            native,
            plaintext: Zeroizing::new(plaintext),
            aad,
            plaintext_used: 0,
            namespace_bytes: bounds.0,
            key_bytes: bounds.1,
            value_bytes: bounds.2,
            _charge: charge,
        })
    }
    pub(crate) fn verify_source_tables(
        &mut self,
        reader: &RegisteredNodeRead,
    ) -> Result<(), NodeReadAccessError> {
        reader.verify_source_tables_prepared(&mut self.native)
    }

    pub(crate) fn bounds(&self) -> (usize, usize, usize) {
        (self.namespace_bytes, self.key_bytes, self.value_bytes)
    }
    pub(crate) fn clear_plaintext(&mut self) {
        // The allocation starts zeroed. Only decrypt can write plaintext and it
        // records the full attempted prefix first, including failure paths.
        self.plaintext[..self.plaintext_used].zeroize();
        self.plaintext_used = 0;
    }
    /// Directory extent quotation only: the following real loan must still
    /// authenticate every byte and exact identity. Never allocate or resize.
    pub(crate) fn value_bound(
        &mut self,
        store: &TenantStore,
        transaction: &read_view::ViewTransaction,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<usize>> {
        validate_record(namespace, key, max_value_bytes)?;
        ensure!(
            namespace.len() <= self.namespace_bytes && key.len() <= self.key_bytes,
            "record exceeds prepared point bounds"
        );
        let state = store.state.read();
        store.require_access(&state)?;
        let disk_key = inline_record_key(
            &store.tenant,
            namespace,
            key,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let length = transaction.record_length_prepared(&disk_key, &mut self.native)?;
        store.require_access(&state)?;
        length
            .map(|length| {
                // Subtract only the minimum framing/key-ID width. The extra actual
                // key-ID bytes make this conservative, never an authenticated size.
                let minimum = encrypted_record_length(namespace.len(), key.len(), 0, 0)
                    .context("record size preflight overflow")?;
                let limit =
                    encrypted_record_limit(namespace.len(), key.len(), max_value_bytes, &state)?;
                ensure!(
                    length <= limit,
                    "encrypted record exceeds preflight read bound"
                );
                Ok(length.saturating_sub(minimum).min(max_value_bytes))
            })
            .transpose()
    }

    pub(crate) fn read(
        &mut self,
        store: &TenantStore,
        transaction: &read_view::ViewTransaction,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Range<usize>>> {
        validate_record(namespace, key, 0)?;
        ensure!(
            namespace.len() <= self.namespace_bytes
                && key.len() <= self.key_bytes
                && max_value_bytes <= self.value_bytes,
            "record exceeds prepared point bounds"
        );
        let state = store.state.read();
        store.require_access(&state)?;
        let encrypted_limit =
            encrypted_record_limit(namespace.len(), key.len(), max_value_bytes, &state)?;
        ensure!(
            encrypted_limit <= self.native.capacity(),
            "key catalog exceeds prepared point capacity"
        );
        let disk_key = inline_record_key(
            &store.tenant,
            namespace,
            key,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let Some(envelope) =
            transaction.record_bytes_prepared(&disk_key, encrypted_limit, &mut self.native)?
        else {
            store.require_access(&state)?;
            return Ok(None);
        };
        check_encrypted_record_budget(envelope, namespace.len(), key.len(), max_value_bytes)?;
        let mut ciphertext = envelope;
        let id = std::str::from_utf8(take_bytes(&mut ciphertext)?)
            .context("invalid encrypted record key id")?;
        let data_key = state
            .keys
            .get(id)
            .context("encrypted record references an unavailable key")?;
        ensure!(ciphertext.len() >= 40, "truncated encrypted record");
        let length = ciphertext.len() - 40;
        ensure!(
            length <= self.plaintext.len(),
            "decrypted record exceeds prepared capacity"
        );
        record_aad_into(&mut self.aad, &store.tenant, &disk_key);
        // A failed decrypt can still write this prefix; clear it on every exit.
        self.plaintext_used = length;
        decrypt_into(
            data_key,
            ciphertext,
            &self.aad,
            &mut self.plaintext[..length],
        )?;
        let record = store.decode_record_fields(&disk_key, &self.plaintext[..length], &state)?;
        ensure!(
            record.namespace == namespace
                && record.key == key
                && record.value.len() <= max_value_bytes,
            "view record identity or size differs"
        );
        let result = length - record.value.len()..length;
        store.require_access(&state)?;
        Ok(Some(result))
    }
}
