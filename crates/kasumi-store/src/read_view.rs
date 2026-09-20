//! Read transactions pin immutable encrypted pages, never a tenant's plaintext.
use super::*;
/// A stable database root with access rechecked for every decrypted record.
pub struct TenantReadView {
    store: Arc<TenantStore>,
    transaction: redb::ReadTransaction,
}
impl TenantStore {
    pub fn read_view(self: &Arc<Self>) -> Result<TenantReadView> {
        self.check_access()?;
        Ok(TenantReadView {
            store: self.clone(),
            transaction: self.node.db.begin_read()?,
        })
    }
    /// Replace verified encrypted tables and publish their metadata in one
    /// durable transaction. The caller owns validation, disk/work admission and
    /// the blocking operation through actual completion.
    pub fn replace_namespaces(
        &self,
        replacements: &[(&str, &EncryptedTable)],
        operations: &[WriteOp],
    ) -> Result<()> {
        validate_replacements(replacements, operations)?;
        let _access = AccessGuard(self);
        self.check_access()?;
        let _mutation = self.mutations.lock();
        let mut tx = self.node.db.begin_write()?;
        tx.set_durability(Durability::Immediate)?;
        tx.set_two_phase_commit(true);
        replace_domain(&tx, self, replacements)?;
        {
            let state = self.state.read();
            self.require_access(&state)?;
            let catalog = self.catalog.read();
            write_domain(&tx, self, &state, &catalog, operations)?;
        }
        self.check_access()?;
        tx.commit()
            .context("table publication outcome may be unknown")?;
        self.check_access()
    }
}
impl TenantReadView {
    pub(super) fn catalog(&self, tenant: &str) -> Result<Option<KeyCatalog>> {
        NodeStore::catalog_at(&self.transaction, tenant)
    }
    pub fn scratch_disk(&self) -> &Arc<ScratchDisk> {
        self.store.scratch_disk()
    }

    pub fn get(
        &self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        ensure!(
            max_value_bytes <= MAX_RECORD,
            "view record bound exceeds store limit"
        );
        let store = &self.store;
        let _access = AccessGuard(store);
        validate_record(namespace, key, 0)?;
        store.check_access()?;
        let state = store.state.read();
        store.require_access(&state)?;
        let disk_key = record_key(
            &store.tenant,
            namespace,
            key,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let table = self.transaction.open_table(RECORDS)?;
        let result = if let Some(value) = table.get(disk_key.as_slice())? {
            check_encrypted_record_budget(
                value.value(),
                namespace.len(),
                key.len(),
                max_value_bytes,
            )?;
            let mut record = store.decode_record(&disk_key, value.value(), &state)?;
            ensure!(
                record.namespace == namespace
                    && record.key == key
                    && record.value.len() <= max_value_bytes,
                "view record identity or size differs"
            );
            Some(std::mem::take(&mut record.value))
        } else {
            None
        };
        store.require_access(&state)?;
        Ok(result)
    }
    pub fn visit(
        &self,
        namespace: &str,
        max_value_bytes: usize,
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            max_value_bytes <= MAX_RECORD,
            "view record bound exceeds store limit"
        );
        let store = &self.store;
        let _access = AccessGuard(store);
        validate_record(namespace, &[], 0)?;
        let prefix = {
            let state = store.state.read();
            store.require_access(&state)?;
            namespace_prefix(
                &store.tenant,
                namespace,
                state.keys.get(INDEX_KEY).context("index key missing")?,
            )
        };
        let table = self.transaction.open_table(RECORDS)?;
        for entry in table.range(prefix.as_slice()..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            let record = {
                let state = store.state.read();
                store.require_access(&state)?;
                check_encrypted_record_budget(
                    value.value(),
                    namespace.len(),
                    4096,
                    max_value_bytes,
                )?;
                let record = store.decode_record(key.value(), value.value(), &state)?;
                ensure!(
                    record.namespace == namespace && record.value.len() <= max_value_bytes,
                    "view record namespace or size differs"
                );
                record
            };
            visitor(&record.key, &record.value)?;
            store.check_access()?;
        }
        store.check_access()
    }
}

pub(crate) fn validate_replacements(
    replacements: &[(&str, &EncryptedTable)],
    operations: &[WriteOp],
) -> Result<()> {
    validate_batch(&[operations])?;
    let mut names = std::collections::BTreeSet::new();
    for (namespace, _) in replacements {
        validate_record(namespace, &[], 0)?;
        ensure!(names.insert(*namespace), "duplicate replacement namespace");
    }
    for operation in operations {
        let namespace = match operation {
            WriteOp::Put { namespace, .. } | WriteOp::Delete { namespace, .. } => namespace,
        };
        ensure!(
            !names.contains(namespace.as_str()),
            "metadata overlaps a replaced table"
        );
    }
    Ok(())
}

pub(crate) fn replace_domain(
    tx: &redb::WriteTransaction,
    store: &TenantStore,
    replacements: &[(&str, &EncryptedTable)],
) -> Result<()> {
    for (namespace, source) in replacements {
        let prefix = {
            let state = store.state.read();
            store.require_access(&state)?;
            namespace_prefix(
                &store.tenant,
                namespace,
                state.keys.get(INDEX_KEY).context("index key missing")?,
            )
        };
        {
            let mut table = tx.open_table(RECORDS)?;
            table.retain_in(prefix.as_slice().., |key, _| !key.starts_with(&prefix))?;
        }
        let mut count = 0u64;
        source.visit(|key, value| {
            count = count
                .checked_add(1)
                .context("replacement record count overflow")?;
            // Drop key-state guards after each bounded record so a large import
            // does not block normal provider renewal for its entire duration.
            let state = store.state.read();
            store.require_access(&state)?;
            let catalog = store.catalog.read();
            let operation = WriteOp::put(*namespace, key, value);
            validate_batch(&[std::slice::from_ref(&operation)])?;
            write_domain(tx, store, &state, &catalog, &[operation])
        })?;
        store.check_access()?;
    }
    Ok(())
}
