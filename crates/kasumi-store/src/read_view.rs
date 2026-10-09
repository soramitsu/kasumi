//! Read transactions pin immutable encrypted pages, never a tenant's plaintext.
use super::*;
mod point_retirement;
pub use point_retirement::PointRetirementFailure;
pub(crate) use point_retirement::retire_point_backing;
#[cfg(test)]
mod ordinary_visit_tests;
mod prepared_points;
pub use prepared_points::{
    PreparedTenantReadPoints, PreparedTenantReadSource, PreparedTenantReadSourceLoan,
    PreparedTenantReadWorkspace,
};
/// A complete namespace replacement, published atomically with binding metadata.
///
/// An explicit empty replacement removes every current record in the namespace.
/// Omitting a namespace from the replacement list leaves its records unchanged.
#[derive(Clone, Copy)]
pub struct NamespaceReplacement<'a> {
    namespace: &'a str,
    source: Option<&'a EncryptedTable>,
}
impl<'a> NamespaceReplacement<'a> {
    pub fn empty(namespace: &'a str) -> Self {
        Self {
            namespace,
            source: None,
        }
    }
    pub fn from_table(namespace: &'a str, source: &'a EncryptedTable) -> Self {
        Self {
            namespace,
            source: Some(source),
        }
    }
}

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
        if node.body().db.has_fixture_direct_database() {
            return Ok(Self::Fixture(node.body().db.begin_read()?));
        }
        Ok(Self::Registered(node.begin_registered_read()?))
    }
    pub(crate) fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<kasumi_kv::PreparedPointRead> {
        match self {
            Self::Registered(reader) => reader
                .prepare_point_read(max_value_bytes)
                .map_err(|error| self.preserve_report(error.into())),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(transaction) => transaction
                .prepare_point_read(max_value_bytes)
                .map_err(Into::into),
        }
    }

    pub(crate) fn record_length_prepared(
        &self,
        key: &[u8],
        workspace: &mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<usize>> {
        match self {
            Self::Registered(reader) => reader
                .record_length_prepared(key, workspace)
                .map_err(|error| self.preserve_report(error.into())),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(transaction) => transaction
                .point_length_prepared(RECORDS.name(), key, workspace)
                .map_err(Into::into),
        }
    }

    pub(crate) fn record_bytes_prepared<'workspace>(
        &self,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>> {
        match self {
            Self::Registered(reader) => reader
                .record_bytes_prepared(key, max_value_bytes, workspace)
                .map_err(|error| self.preserve_report(error.into())),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(transaction) => transaction
                .get_bytes_prepared(RECORDS.name(), key, max_value_bytes, workspace)
                .map_err(Into::into),
        }
    }

    pub(crate) fn fork(&self, node: &NodeStore) -> Result<Self> {
        match self {
            Self::Registered(reader) => node.fork_registered_read(reader).map(Self::Registered),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Fixture(transaction) => transaction.fork().map(Self::Fixture).map_err(Into::into),
        }
    }

    pub(crate) fn close(self, node: &NodeStore) -> Result<()> {
        let deadline = std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT;
        match self {
            Self::Registered(reader) => {
                node.settle_registered_read_until(reader, Ok(()), Some(deadline))
            }
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
        replacements: &[NamespaceReplacement<'_>],
        operations: &[WriteOp],
    ) -> Result<()> {
        validate_replacements(replacements, operations)?;
        reject_unpaired_identity_ops(operations)?;
        let _access = AccessGuard(self);
        self.check_access()?;
        let _mutation = self.mutations.lock();
        self.node.with_registered_write(
            &mut (),
            |tx, _| {
                replace_domain(tx, self, replacements)?;
                {
                    let state = self.state.read();
                    self.require_access(&state)?;
                    let catalog = self.catalog.read();
                    write_domain(tx, self, &state, &catalog, operations)?;
                }
                self.check_access()
            },
            |_| self.check_access(),
        )
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
                        self.store.node.memory().clone(),
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
    /// Independently retain this exact selected root while rechecking current
    /// tenant access. The child has its own registered failure/close state.
    pub fn fork(&self) -> Result<Self> {
        let _access = AccessGuard(&self.store);
        self.store.check_access()?;
        let transaction = self
            .transaction
            .as_ref()
            .expect("live view transaction")
            .fork(&self.store.node)?;
        if let Err(error) = self.store.check_access() {
            return match transaction {
                ViewTransaction::Registered(reader) => {
                    self.store.node.settle_registered_read(reader, Err(error))
                }
                #[cfg(any(test, feature = "test-utils"))]
                ViewTransaction::Fixture(_) => Err(error),
            };
        }
        Ok(Self {
            store: self.store.clone(),
            transaction: Some(transaction),
        })
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
    ) -> Result<Option<PlaintextValue>> {
        get_at(
            &self.store,
            self.transaction.as_ref().expect("live view transaction"),
            namespace,
            key,
            max_value_bytes,
        )
    }
    /// Borrow each authenticated record under its installed plaintext charge.
    /// The callback must admit any result it retains beyond this call.
    pub fn visit(
        &self,
        namespace: &str,
        max_value_bytes: usize,
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let transaction = self.transaction.as_ref().expect("live view transaction");
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            visit_encrypted_at(
                &self.store,
                transaction,
                namespace,
                max_value_bytes,
                |key, envelope| {
                    let record = {
                        let state = self.store.state.read();
                        self.store.require_access(&state)?;
                        let record = PlaintextRecord::prepare(
                            &self.store,
                            key,
                            envelope,
                            &state,
                            namespace,
                        )?;
                        ensure!(
                            record.value().len() <= max_value_bytes,
                            "view record namespace or size differs"
                        );
                        record
                    };
                    visitor(record.key(), record.value())
                },
            )
        })) {
            Ok(result) => result.map_err(|error| transaction.preserve_report(error)),
            Err(payload) => match transaction {
                ViewTransaction::Registered(reader) => {
                    reader.preserve_body_panic(payload);
                    Err(transaction.preserve_report(NodeReadAccessError::Reported.into()))
                }
                #[cfg(any(test, feature = "test-utils"))]
                ViewTransaction::Fixture(_) => Err(PointRetirementFailure::new(
                    anyhow::anyhow!("ordinary record visit panicked"),
                    payload,
                )
                .into()),
            },
        }
    }
}

// Prepared custody visitation borrows the caller's original admission through
// decode and callback. It must not acquire another plaintext reservation.
pub(crate) fn visit_at<W>(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    max_value_bytes: usize,
    workspace: &mut W,
    mut prepare: impl FnMut(&mut W, &[u8]) -> Result<()>,
    mut visitor: impl FnMut(&mut W, &[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    visit_encrypted_at(
        store,
        transaction,
        namespace,
        max_value_bytes,
        |key, envelope| {
            prepare(workspace, envelope)?;
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
            visitor(workspace, &record.key, &record.value)
        },
    )
}

// The selected root, encrypted output owner and access/bounds checks are shared
// by ordinary admitted records and caller-funded prepared custody visitation.
fn visit_encrypted_at(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    max_value_bytes: usize,
    mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(
        max_value_bytes <= MAX_RECORD,
        "view record bound exceeds store limit"
    );
    let _access = AccessGuard(store);
    validate_record(namespace, &[], 0)?;
    let prefix = {
        let state = store.state.read();
        store.require_access(&state)?;
        let index = state.keys.get(INDEX_KEY).context("index key missing")?;
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&tenant_hash(&store.tenant));
        prefix[32..].copy_from_slice(&keyed_hash(
            index,
            &[
                b"kasumi.namespace.v1",
                store.tenant.as_bytes(),
                namespace.as_bytes(),
            ],
        ));
        prefix
    };
    let mut visit_one = |key: &[u8], envelope: &[u8]| -> Result<()> {
        {
            let state = store.state.read();
            store.require_access(&state)?;
            check_encrypted_record_budget(envelope, namespace.len(), 4096, max_value_bytes)?;
        }
        visitor(key, envelope)?;
        store.check_access()?;
        Ok(())
    };
    match transaction {
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
                .map_err(|error| transaction.preserve_report(error.into()))?
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

/// Conservative plaintext workspace for one bounded `TenantReadView::get`,
/// `TenantStorageReadView::application_get` or `custody_get` call.
///
/// All lengths are bytes; tenant means the actual encrypted domain catalog
/// tenant (including the custody prefix for custody reads). The caller must fund
/// this conservative operation quote before the read, separately from native
/// encrypted output/cache/census charges. The actual returned `PlaintextValue`
/// independently acquires and retains its installed plaintext allocation lease
/// until the last owned result drops. This pure quote grants no byte credit.
/// Caller scratch, retained
/// inputs, decoded JSON/DTOs, diagnostic backtraces, arbitrary provider/error
/// payloads and native memory are not included. Access, authorization and the
/// read's value bound still apply.
///
/// The quote uses checked power-of-two backing envelopes plus the existing Store
/// allocation policy allowance for every bounded allocation/reallocation request.
/// This is a conservative supported-allocator policy, not an exact RSS bound.
/// Keep the real decode allocation census in sync with changes to this path.
pub fn plaintext_get_workspace_bytes(
    tenant_bytes: usize,
    namespace_bytes: usize,
    key_bytes: usize,
    max_value_bytes: usize,
) -> std::io::Result<u64> {
    use crate::disk_memory::{ALLOCATION_ALLOWANCE, add, mul, overflow};
    if !(1..=1024).contains(&tenant_bytes)
        || !(1..=1024).contains(&namespace_bytes)
        || key_bytes > 4096
        || max_value_bytes > MAX_RECORD
    {
        return Err(overflow());
    }
    let length = |value: usize| u64::try_from(value).map_err(|_| overflow());
    let rounded = |value: u64| value.checked_next_power_of_two().ok_or_else(overflow);
    // check_encrypted_record_budget admits at most P bytes of framed plaintext.
    // The whole authenticated backing is retained even though callers borrow
    // only the value. The exact installed plaintext acquisition is performed by
    // the canonical point owner before allocating that single backing.
    let plaintext = add(
        add(
            add(length(max_value_bytes)?, length(namespace_bytes)?)?,
            length(key_bytes)?,
        )?,
        12,
    )?;
    let aad = add(
        add(b"kasumi.encrypted-record.v1".len() as u64, 8)?,
        add(length(tenant_bytes)?, 96)?,
    )?;
    // Each HMAC key Vec requests 32 + 64 + 128 bytes as it grows. AAD has at
    // most four allocation requests and their total backing is below 4*A.
    // These cumulative envelopes also cover old/new backing during reallocation.
    let keys = mul(2, rounded(256)?)?;
    let aad = rounded(mul(4, aad)?)?;
    // Retain this conservative historical operation upper bound. Ordinary
    // reads now use inline identity/AAD and one admitted in-place AEAD buffer;
    // changing source-envelope operation quotes is a separate contract change.
    let decrypted = rounded(add(plaintext, 16)?)?;
    let decoded = mul(3, rounded(plaintext)?)?;
    let backing = add(add(keys, aad)?, add(decrypted, decoded)?)?;
    // Two three-request physical keys + four AAD requests + AEAD + three
    // decoded fields = fourteen. Two more cover bounded local error wrapping.
    // Diagnostic backtraces and original external errors/panics remain under
    // their separate census owner; the quote does not bound diagnostic capture.
    add(
        backing,
        mul(PLAINTEXT_GET_ALLOCATION_REQUESTS, ALLOCATION_ALLOWANCE)?,
    )
}

const PLAINTEXT_GET_ALLOCATION_REQUESTS: u64 = 16;

pub(crate) fn get_at(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    key: &[u8],
    max_value_bytes: usize,
) -> Result<Option<PlaintextValue>> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        get_at_body(store, transaction, namespace, key, max_value_bytes)
    })) {
        Ok(result) => result.map_err(|error| transaction.preserve_report(error)),
        Err(payload) => match transaction {
            ViewTransaction::Registered(reader) => {
                reader.preserve_body_panic(payload);
                Err(transaction.preserve_report(NodeReadAccessError::Reported.into()))
            }
            #[cfg(any(test, feature = "test-utils"))]
            ViewTransaction::Fixture(_) => Err(PointRetirementFailure::new(
                anyhow::anyhow!("ordinary point read panicked"),
                payload,
            )
            .into()),
        },
    }
}

fn get_at_body(
    store: &TenantStore,
    transaction: &ViewTransaction,
    namespace: &str,
    key: &[u8],
    max_value_bytes: usize,
) -> Result<Option<PlaintextValue>> {
    ensure!(
        max_value_bytes <= MAX_RECORD,
        "view record bound exceeds store limit"
    );
    let _access = AccessGuard(store);
    validate_record(namespace, key, 0)?;
    store.check_access()?;
    let state = store.state.read();
    store.require_access(&state)?;
    let disk_key = inline_record_key(
        &store.tenant,
        namespace,
        key,
        state.keys.get(INDEX_KEY).context("index key missing")?,
    );
    let decode = |envelope: &[u8]| {
        decode_get_record(
            store,
            &disk_key,
            envelope,
            &state,
            namespace,
            key,
            max_value_bytes,
        )
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

// The same plaintext boundary is used by real reads and allocator qualification.
// Native encrypted output is acquired separately before entering this function.
fn decode_get_record(
    store: &TenantStore,
    disk_key: &[u8],
    envelope: &[u8],
    state: &KeyState,
    namespace: &str,
    key: &[u8],
    max_value_bytes: usize,
) -> Result<PlaintextValue> {
    PlaintextValue::prepare(
        store,
        disk_key,
        envelope,
        state,
        namespace,
        key,
        max_value_bytes,
    )
}

#[cfg(test)]
#[path = "read_view_workspace_tests.rs"]
mod workspace_tests;

impl Drop for TenantReadView {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            transaction.close_on_drop(&self.store.node);
        }
    }
}

pub(crate) fn validate_replacements(
    replacements: &[NamespaceReplacement<'_>],
    operations: &[WriteOp],
) -> Result<()> {
    validate_batch(&[operations])?;
    let mut names = std::collections::BTreeSet::new();
    for replacement in replacements {
        let namespace = replacement.namespace;
        validate_record(namespace, &[], 0)?;
        ensure!(
            !is_initial_identity_namespace(namespace),
            "initial identity namespace cannot be replaced"
        );
        ensure!(names.insert(namespace), "duplicate replacement namespace");
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
    replacements: &[NamespaceReplacement<'_>],
) -> Result<()> {
    for replacement in replacements {
        let namespace = replacement.namespace;
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
            table.retain_prefix(prefix.as_slice(), |_, _| false)?;
        }
        if let Some(source) = replacement.source {
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
                let operation = WriteOp::put(namespace, key, value);
                validate_batch(&[std::slice::from_ref(&operation)])?;
                write_domain(tx, store, &state, &catalog, &[operation])
            })?;
        }
        store.check_access()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "read_view_fork_tests.rs"]
mod fork_tests;

#[path = "read_view/source_publication.rs"]
mod source_publication;
