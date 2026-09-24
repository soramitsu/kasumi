//! Fixed, admitted catalog input for a future retained write request.
//!
//! This type performs no database operation. It only establishes a finite,
//! provider-owned byte buffer before materializing serialized output. Redb transaction, cache,
//! diagnostics, and terminal custody need their own separate proofs.
use crate::{
    DiskMemoryLease, KeyCatalog, MAX_KEY_CATALOG_BYTES, NodeDiskMemoryAdmission, disk_memory,
    tenant_hash,
};
use anyhow::{Result, ensure};
use std::{io::Cursor, sync::Arc};
use zeroize::Zeroizing;

/// One validated catalog insertion with its actual output buffer still charged.
/// The fixed hash is copied inline; no caller callback or raw transaction exists.
pub(crate) struct AdmittedCatalogPut {
    hash: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    // Drop after `bytes`: zeroize and free the actual buffer before credit.
    _charge: DiskMemoryLease,
}
impl AdmittedCatalogPut {
    pub(crate) fn prepare(
        tenant: &str,
        catalog: &KeyCatalog,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        catalog.validate(tenant)?;
        let bound = disk_memory::allocation::<u8>(u64::try_from(MAX_KEY_CATALOG_BYTES)?)?;
        let charge = provider.clone().reserve_installed(bound)?;
        // The fixed-length slice rejects serializer growth instead of silently
        // reallocating after admission. The catalog was checked against this
        // exact maximum while held under the caller's immutable borrow.
        let mut bytes = Zeroizing::new(vec![0u8; MAX_KEY_CATALOG_BYTES]);
        let written = {
            let mut cursor = Cursor::new(bytes.as_mut_slice());
            serde_json::to_writer(&mut cursor, catalog)?;
            usize::try_from(cursor.position())?
        };
        ensure!(
            written != 0 && written <= MAX_KEY_CATALOG_BYTES,
            "catalog serialization exceeded admitted buffer"
        );
        bytes.truncate(written);
        Ok(Self {
            hash: tenant_hash(tenant),
            bytes,
            provider,
            _charge: charge,
        })
    }
    pub(crate) fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn provider(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StoragePurpose, WrappedKey, test_utils::TestDiskMemory};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn catalog() -> KeyCatalog {
        let wrapped = WrappedKey {
            provider: "fixture".into(),
            key_ref: "fixed".into(),
            ciphertext: "opaque".into(),
            version: 1,
            context: None,
        };
        KeyCatalog {
            format: 1,
            catalog_id: Uuid::from_u128(1),
            tenant: "catalog-plan".into(),
            purpose: StoragePurpose::LocalFixture,
            active: "current".into(),
            keys: BTreeMap::from([
                ("index".into(), wrapped.clone()),
                ("current".into(), wrapped),
            ]),
        }
    }

    #[test]
    fn catalog_input_is_admitted_before_its_fixed_serialized_buffer() {
        let memory = TestDiskMemory::new(8 << 20, 8);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let before = memory.snapshot();
        let plan =
            AdmittedCatalogPut::prepare("catalog-plan", &catalog(), provider.clone()).unwrap();
        assert_eq!(plan.hash(), &tenant_hash("catalog-plan"));
        assert!(Arc::ptr_eq(plan.provider(), &provider));
        assert!(serde_json::from_slice::<KeyCatalog>(plan.bytes()).unwrap() == catalog());
        assert!(memory.snapshot().used_bytes > before.used_bytes);
        drop(plan);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
    }

    #[test]
    fn refused_input_reservation_creates_no_plan_or_redb_effect() {
        let bookkeeping = TestDiskMemory::required_bookkeeping_bytes(8).unwrap();
        let memory = TestDiskMemory::new(bookkeeping + 1024, 8);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let before = memory.snapshot();
        assert!(AdmittedCatalogPut::prepare("catalog-plan", &catalog(), provider).is_err());
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
    }

    #[test]
    fn exact_catalog_limit_fits_fixed_buffer_and_one_extra_byte_is_rejected() {
        let memory = TestDiskMemory::new(8 << 20, 8);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let before = memory.snapshot();
        let mut catalog = catalog();
        let base_len = serde_json::to_vec(&catalog).unwrap().len();
        catalog
            .keys
            .get_mut("index")
            .unwrap()
            .key_ref
            .push_str(&"x".repeat(MAX_KEY_CATALOG_BYTES - base_len));
        let plan = AdmittedCatalogPut::prepare("catalog-plan", &catalog, provider.clone()).unwrap();
        assert_eq!(plan.bytes().len(), MAX_KEY_CATALOG_BYTES);
        assert!(memory.snapshot().used_bytes > before.used_bytes);
        drop(plan);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);

        catalog.keys.get_mut("index").unwrap().key_ref.push('x');
        assert!(AdmittedCatalogPut::prepare("catalog-plan", &catalog, provider).is_err());
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
    }
}
