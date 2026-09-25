//! Read transactions pin immutable encrypted pages, never a tenant's plaintext.
use super::*;
/// A stable database root with access rechecked for every decrypted record.
pub struct TenantReadView {
    store: Arc<TenantStore>,
    transaction: Option<ViewTransaction>,
}
pub(crate) enum ViewTransaction {
    Registered(RegisteredNodeRead),
    #[cfg(any(test, feature = "test-utils"))]
    Fixture(kasumi_kv::ReadTransaction),
}
impl ViewTransaction {
    pub(crate) fn begin(node: &NodeStore) -> Result<Self> {
        #[cfg(any(test, feature = "test-utils"))]
        if node.db.has_fixture_direct_database() {
            return Ok(Self::Fixture(node.db.begin_read()?));
        }
        Ok(Self::Registered(node.begin_registered_read()?))
    }
    pub(crate) fn close(self, node: &NodeStore) -> Result<()> {
        match self {
            Self::Registered(reader) => node.settle_registered_read(reader, Ok(())),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(_) => Ok(()),
        }
    }
    pub(crate) fn reader_id(&self) -> Option<StorageOwnerId> {
        match self {
            Self::Registered(reader) => Some(reader.id()),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(_) => None,
        }
    }
    pub(crate) fn preserve_report(&self, error: anyhow::Error) -> anyhow::Error {
        match self {
            Self::Registered(reader)
                if matches!(
                    error.downcast_ref::<NodeReadAccessError>(),
                    Some(NodeReadAccessError::Reported)
                ) && reader.report().has_failures() =>
            {
                NodeScopedReadFailure::from_view(reader, error).into()
            }
            _ => error,
        }
    }
    pub(crate) fn close_on_drop(self, node: &NodeStore) {
        match self {
            Self::Registered(reader) if std::thread::panicking() => {
                reader.mark_unwinding_body();
                let _ = reader.finish();
            }
            Self::Registered(reader) => {
                let _ = node.settle_registered_read(reader, Ok(()));
            }
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(_) => {}
        }
    }
}
impl TenantStore {
    pub fn read_view(self: &Arc<Self>) -> Result<TenantReadView> {
        self.check_access()?;
        Ok(TenantReadView {
            store: self.clone(),
            transaction: Some(ViewTransaction::begin(&self.node)?),
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
        reject_unpaired_identity_ops(operations)?;
        let _access = AccessGuard(self);
        self.check_access()?;
        let _mutation = self.mutations.lock();
        let tx = self.node.db.begin_write()?;
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
    pub(super) fn catalog(&self, tenant: &str) -> Result<Option<AdmittedKeyCatalog>> {
        let transaction = self.transaction.as_ref().expect("live view transaction");
        match transaction {
            ViewTransaction::Registered(reader) => reader
                .catalog_bytes(tenant_hash(tenant), MAX_KEY_CATALOG_BYTES)
                .map_err(|error| transaction.preserve_report(error.into()))?
                .as_ref()
                .map(|bytes| {
                    AdmittedKeyCatalog::decode(
                        bytes.as_bytes(),
                        tenant,
                        self.store.node.persistent_disk().memory().clone(),
                    )
                })
                .transpose(),
            #[cfg(any(test, feature = "test-utils"))]
            ViewTransaction::Fixture(tx) => NodeStore::catalog_at(tx, tenant)
                .map(|catalog| catalog.map(AdmittedKeyCatalog::unadmitted)),
        }
    }
    /// A caller needing an acknowledged terminal result should close the
    /// view explicitly. Drop still attempts the exact close and retains any
    /// failed child in the installed census for inspection.
    pub fn close(mut self) -> Result<()> {
        self.transaction
            .take()
            .expect("live view transaction")
            .close(&self.store.node)
    }
    pub fn registered_reader_id(&self) -> Option<StorageOwnerId> {
        self.transaction
            .as_ref()
            .expect("live view transaction")
            .reader_id()
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
        get_at(
            &self.store,
            self.transaction.as_ref().expect("live view transaction"),
            namespace,
            key,
            max_value_bytes,
        )
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
        let mut visit_one = |key: &[u8], envelope: &[u8]| -> Result<()> {
            let record = {
                let state = store.state.read();
                store.require_access(&state)?;
                check_encrypted_record_budget(envelope, namespace.len(), 4096, max_value_bytes)?;
                let record = store.decode_record(key, envelope, &state)?;
                ensure!(
                    record.namespace == namespace && record.value.len() <= max_value_bytes,
                    "view record namespace or size differs"
                );
                record
            };
            visitor(&record.key, &record.value)?;
            store.check_access()?;
            Ok(())
        };
        match self.transaction.as_ref().expect("live view transaction") {
            ViewTransaction::Registered(reader) => {
                let state = store.state.read();
                let encrypted_limit =
                    encrypted_record_limit(namespace.len(), 4096, max_value_bytes, &state)?;
                drop(state);
                let mut cursor: Option<AdmittedReadBytes> = None;
                while let Some(row) = reader
                    .next_record(
                        &prefix,
                        cursor.as_ref().map(AdmittedReadBytes::as_bytes),
                        encrypted_limit,
                    )
                    .map_err(|error| {
                        self.transaction
                            .as_ref()
                            .expect("live view transaction")
                            .preserve_report(error.into())
                    })?
                {
                    visit_one(row.key(), row.value())?;
                    cursor = Some(row.into_key());
                }
            }
            #[cfg(any(test, feature = "test-utils"))]
            ViewTransaction::Fixture(tx) => {
                let table = tx.open_table(RECORDS)?;
                for entry in table.range(prefix.as_slice()..)? {
                    let (key, value) = entry?;
                    if !key.value().starts_with(&prefix) {
                        break;
                    }
                    visit_one(key.value(), value.value())?;
                }
            }
        }
        store.check_access()
    }
}

pub(crate) fn get_at(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    key: &[u8],
    max_value_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    get_at_body(store, transaction, namespace, key, max_value_bytes)
        .map_err(|error| transaction.preserve_report(error))
}

fn get_at_body(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    key: &[u8],
    max_value_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    ensure!(
        max_value_bytes <= MAX_RECORD,
        "view record bound exceeds store limit"
    );
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
    let decode = |envelope: &[u8]| -> Result<Vec<u8>> {
        check_encrypted_record_budget(envelope, namespace.len(), key.len(), max_value_bytes)?;
        let mut record = store.decode_record(&disk_key, envelope, &state)?;
        ensure!(
            record.namespace == namespace
                && record.key == key
                && record.value.len() <= max_value_bytes,
            "view record identity or size differs"
        );
        Ok(std::mem::take(&mut record.value))
    };
    let result = match transaction {
        ViewTransaction::Registered(reader) => {
            let encrypted_limit =
                encrypted_record_limit(namespace.len(), key.len(), max_value_bytes, &state)?;
            reader
                .record_bytes(&disk_key, encrypted_limit)?
                .as_ref()
                .map(|value| decode(value.as_bytes()))
                .transpose()?
        }
        #[cfg(any(test, feature = "test-utils"))]
        ViewTransaction::Fixture(tx) => {
            let table = tx.open_table(RECORDS)?;
            table
                .get(disk_key.as_slice())?
                .as_ref()
                .map(|value| decode(value.value()))
                .transpose()?
        }
    };
    store.require_access(&state)?;
    Ok(result)
}

impl Drop for TenantReadView {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            transaction.close_on_drop(&self.store.node);
        }
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
        ensure!(
            !is_initial_identity_namespace(namespace),
            "initial identity namespace cannot be replaced"
        );
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
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    replacements: &[(&str, &EncryptedTable)],
) -> Result<()> {
    for (namespace, source) in replacements {
        ensure!(
            !is_initial_identity_namespace(namespace),
            "initial identity namespace cannot be replaced"
        );
        let prefix = {
            let state = store.state.read();
            store.require_access(&state)?;
            let index = state.keys.get(INDEX_KEY).context("index key missing")?;
            namespace_prefix(&store.tenant, namespace, index)
        };
        {
            let mut table = tx.open_table(RECORDS)?;
            table.retain_in(prefix.as_slice().., |key, _| !key.starts_with(&prefix))?;
        }
        let mut count = 0u64;
        source.visit(|key, value| {
            ensure!(
                !is_write_once_identity(namespace, key),
                "initial bootstrap identity cannot be replaced"
            );
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
