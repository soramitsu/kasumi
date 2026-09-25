//! Exact, provider-admitted input for one missing paired-domain binding.
use super::*;
use chacha20poly1305::aead::AeadInPlace;
use std::io::{self, Cursor, Write};

struct Count(usize);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The first serialization writes no owned byte until its exact allocation is
/// admitted. The observed bytes remain charged if installation needs a write.
pub(crate) struct AdmittedBindingBytes {
    bytes: Zeroizing<Vec<u8>>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    _charge: DiskMemoryLease,
}
impl AdmittedBindingBytes {
    pub(crate) fn prepare(
        binding: &StorageBinding,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        let mut count = Count(0);
        serde_json::to_writer(&mut count, binding)?;
        ensure!(
            count.0 != 0 && count.0 <= MAX_RECORD,
            "storage binding exceeds record limit"
        );
        let allocation = disk_memory::allocation::<u8>(u64::try_from(count.0)?)?;
        let charge = provider.clone().reserve_installed(allocation)?;
        let mut bytes = Zeroizing::new(vec![0u8; count.0]);
        let mut cursor = Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut cursor, binding)?;
        ensure!(
            usize::try_from(cursor.position())? == count.0,
            "storage binding changed during serialization"
        );
        Ok(Self {
            bytes,
            provider,
            _charge: charge,
        })
    }
    /// Encrypt into one admitted envelope. The fixed key and AAD are inline;
    /// no plaintext WriteOp or raw native handle is materialized.
    pub(crate) fn encrypt(
        self,
        store: &TenantStore,
        state: &KeyState,
        catalog: &KeyCatalog,
    ) -> Result<AdmittedBindingPut> {
        store.require_access(state)?;
        validate_record(BINDING_NS, BINDING_KEY, self.bytes.len())?;
        let index = state.keys.get(INDEX_KEY).context("index key missing")?;
        let data = state
            .keys
            .get(&catalog.active)
            .context("active data key missing")?;
        let active = catalog.active.as_bytes();
        let active_len = u32::try_from(active.len())?;
        let plain_len = 12usize
            .checked_add(BINDING_NS.len())
            .and_then(|len| len.checked_add(BINDING_KEY.len()))
            .and_then(|len| len.checked_add(self.bytes.len()))
            .context("storage binding plaintext length overflow")?;
        let prefix_len = 4usize
            .checked_add(active.len())
            .context("storage binding key ID overflow")?;
        let plain_start = prefix_len
            .checked_add(24)
            .context("storage binding nonce overflow")?;
        let plain_end = plain_start
            .checked_add(plain_len)
            .context("storage binding record overflow")?;
        let envelope_len = plain_end
            .checked_add(16)
            .context("storage binding tag overflow")?;
        let allocation = disk_memory::allocation::<u8>(u64::try_from(envelope_len)?)?;
        let envelope_charge = self.provider.clone().reserve_installed(allocation)?;

        let tenant = store.tenant.as_bytes();
        ensure!(tenant.len() <= 1024, "invalid binding tenant");
        let mut key = [0u8; 96];
        key[..32].copy_from_slice(&tenant_hash(&store.tenant));
        key[32..64].copy_from_slice(&keyed_hash(
            index,
            &[b"kasumi.namespace.v1", tenant, BINDING_NS.as_bytes()],
        ));
        key[64..].copy_from_slice(&keyed_hash(
            index,
            &[
                b"kasumi.record.v1",
                tenant,
                BINDING_NS.as_bytes(),
                BINDING_KEY,
            ],
        ));

        const AAD_PREFIX: &[u8] = b"kasumi.encrypted-record.v1";
        const AAD_MAX: usize = AAD_PREFIX.len() + 8 + 1024 + 96;
        let mut aad = Zeroizing::new([0u8; AAD_MAX]);
        let aad_len = AAD_PREFIX.len() + 8 + tenant.len() + key.len();
        aad[..AAD_PREFIX.len()].copy_from_slice(AAD_PREFIX);
        aad[AAD_PREFIX.len()..AAD_PREFIX.len() + 8]
            .copy_from_slice(&(tenant.len() as u64).to_be_bytes());
        aad[AAD_PREFIX.len() + 8..AAD_PREFIX.len() + 8 + tenant.len()].copy_from_slice(tenant);
        aad[AAD_PREFIX.len() + 8 + tenant.len()..aad_len].copy_from_slice(&key);

        let mut envelope = Zeroizing::new(vec![0u8; envelope_len]);
        envelope[..4].copy_from_slice(&active_len.to_be_bytes());
        envelope[4..prefix_len].copy_from_slice(active);
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        envelope[prefix_len..plain_start].copy_from_slice(&nonce);
        let mut at = plain_start;
        for part in [BINDING_NS.as_bytes(), BINDING_KEY, self.bytes.as_slice()] {
            let length = u32::try_from(part.len())?;
            envelope[at..at + 4].copy_from_slice(&length.to_be_bytes());
            at += 4;
            envelope[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        debug_assert_eq!(at, plain_end);
        let cipher = XChaCha20Poly1305::new_from_slice(data.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &aad[..aad_len],
                &mut envelope[plain_start..plain_end],
            )
            .map_err(|_| anyhow::anyhow!("record encryption failed"))?;
        envelope[plain_end..].copy_from_slice(&tag);
        store.require_access(state)?;
        Ok(AdmittedBindingPut {
            key,
            envelope,
            _envelope_charge: envelope_charge,
            serialized: self,
        })
    }
}

pub(crate) struct AdmittedBindingPut {
    key: [u8; 96],
    envelope: Zeroizing<Vec<u8>>,
    // Drop after envelope, whose sensitive bytes must clear before credit.
    _envelope_charge: DiskMemoryLease,
    serialized: AdmittedBindingBytes,
}
impl AdmittedBindingPut {
    pub(crate) fn key(&self) -> &[u8; 96] {
        &self.key
    }
    pub(crate) fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub(crate) fn provider(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.serialized.provider
    }
}
