//! Bounded installation of the append-only auxiliary namespaces. Their existing
//! authenticated checkpoint bindings are the selectors: rows become reachable
//! only when the binding and the sealed owner's selection commit together.
//!
//! This is the auxiliary part of generation publication, not a replacement for
//! the application forest/manifest. In particular, a selected namespace cannot
//! be collected here: snapshots and readers may still reference its prefix.
use super::*;

pub(crate) const OWNERS: &str = "kasumi.app.staging";
const OWNER_BYTES: usize = 4096;
// One of the sixteen native puts is reserved for the durable owner.
const ROWS_PER_BATCH: usize = EncryptedTableBatch::MAX_ENTRIES - 1;
const WORKSPACE: u64 = (EncryptedTableBatch::MAX_BYTES + (64 << 10)) as u64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u32,
    id: Uuid,
    phase: Phase,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
enum Phase {
    Writing {
        records: u64,
        bytes: u64,
    },
    Sealed {
        records: u64,
        bytes: u64,
        sha256: [u8; 32],
    },
    Selected,
    Abandoned,
}
impl Owner {
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= OWNER_BYTES,
            "namespace stage owner exceeds bound"
        );
        let owner: Self = serde_json::from_slice(bytes)?;
        ensure!(
            owner.version == 1 && !owner.id.is_nil() && serde_json::to_vec(&owner)? == bytes,
            "invalid namespace stage owner"
        );
        Ok(owner)
    }
    fn write(&self, namespace: &str) -> Result<WriteOp> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= OWNER_BYTES,
            "namespace stage owner exceeds bound"
        );
        Ok(WriteOp::put(OWNERS, namespace.as_bytes(), bytes))
    }
}

/// A private, durably owned auxiliary generation. The caller retains its apply
/// owner and work admission through staging, publication and visible selection.
/// Drop performs no I/O: an interrupted stage is recovered from its owner row.
///
/// Each input row must fit the existing 4 MiB staging batch, including framing.
/// This covers the auxiliary formats (at most 2 MiB per row); larger application
/// objects must be chunked before using this primitive.
pub struct NamespaceStage {
    store: Arc<TenantStore>,
    namespace: String,
    owner: Owner,
    // All retained descriptor allocations retire before their credit.
    _memory: DiskMemoryLease,
}
impl NamespaceStage {
    /// Claim a fresh physical namespace before its first row is written.
    pub fn begin(store: &Arc<TenantStore>, namespace: &str) -> Result<Self> {
        validate_target(namespace)?;
        let memory = store
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(16 << 10)?;
        let owner = Owner {
            version: 1,
            id: Uuid::new_v4(),
            phase: Phase::Writing {
                records: 0,
                bytes: 0,
            },
        };
        let operation = owner.write(namespace)?;
        mutate(store, &[OWNERS], |tx, state, catalog| {
            ensure!(
                read_owner(tx, store, state, namespace)?.is_none(),
                "namespace already owned"
            );
            ensure!(
                namespace_keys(tx, store, state, namespace, 1)?.is_empty(),
                "staging namespace is not fresh"
            );
            write_domain(tx, store, state, catalog, &[operation])
        })?;
        Ok(Self {
            store: store.clone(),
            namespace: namespace.into(),
            owner,
            _memory: memory,
        })
    }

    /// The fixed-size selection write joins the checkpoint binding and applied
    /// cursor in the existing paired transaction. Store rejects it unless this
    /// exact owner has sealed successfully; it cannot select an abandoned stage.
    pub fn publication_write(&self) -> WriteOp {
        Owner {
            phase: Phase::Selected,
            ..self.owner.clone()
        }
        .write(&self.namespace)
        .expect("fixed namespace stage selection encoding")
    }

    pub fn seal_empty(&self) -> Result<()> {
        self.seal(0, 0, Sha256::digest([]).into())
    }

    /// Stream verified immutable rows without collecting the table. Before seal,
    /// retrying the same owner accepts only identical bytes and exact coverage.
    /// A sealed token is ready for publication and cannot be written again.
    pub fn write_table(&self, source: &EncryptedTable) -> Result<()> {
        let _memory = self
            .store
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(WORKSPACE)?;
        let overhead = self
            .store
            .record_encryption_overhead()?
            .checked_add(96)
            .context("namespace stage framing overflow")?;
        let owner_bound = OWNER_BYTES + OWNERS.len() + self.namespace.len() + overhead;
        ensure!(
            owner_bound < EncryptedTableBatch::MAX_BYTES,
            "namespace stage framing exceeds batch"
        );
        let mut batch = Vec::with_capacity(ROWS_PER_BATCH);
        let mut batch_bytes = owner_bound;
        let mut records = 0u64;
        let mut bytes = 0u64;
        let mut digest = Sha256::new();
        source.visit(|key, value| {
            validate_record(&self.namespace, key, value.len())?;
            let framed = self
                .namespace
                .len()
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .and_then(|n| n.checked_add(overhead))
                .context("namespace stage row overflow")?;
            ensure!(
                framed <= EncryptedTableBatch::MAX_BYTES - owner_bound,
                "namespace stage row exceeds batch"
            );
            if batch.len() == ROWS_PER_BATCH
                || batch_bytes + framed > EncryptedTableBatch::MAX_BYTES
            {
                self.write_batch(&batch)?;
                batch.clear();
                batch_bytes = owner_bound;
            }
            records = records
                .checked_add(1)
                .context("namespace stage count overflow")?;
            bytes = bytes
                .checked_add(u64::try_from(key.len() + value.len())?)
                .context("namespace stage bytes overflow")?;
            digest.update((key.len() as u64).to_be_bytes());
            digest.update(key);
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
            batch.push(WriteOp::put(&self.namespace, key, value));
            batch_bytes += framed;
            Ok(())
        })?;
        if !batch.is_empty() {
            self.write_batch(&batch)?;
        }
        self.seal(records, bytes, digest.finalize().into())
    }

    fn require_writing(
        &self,
        tx: &kasumi_kv::WriteTransaction,
        state: &KeyState,
    ) -> Result<(u64, u64)> {
        let owner = read_owner(tx, &self.store, state, &self.namespace)?
            .context("namespace stage owner absent")?;
        ensure!(owner.id == self.owner.id, "namespace stage owner differs");
        let Phase::Writing { records, bytes } = owner.phase else {
            anyhow::bail!("namespace stage is not writable")
        };
        Ok((records, bytes))
    }

    fn write_batch(&self, operations: &[WriteOp]) -> Result<()> {
        validate_batch(&[operations])?;
        mutate(
            &self.store,
            &[OWNERS, &self.namespace],
            |tx, state, catalog| {
                let (mut records, mut bytes) = self.require_writing(tx, state)?;
                for operation in operations {
                    let WriteOp::Put {
                        namespace,
                        key,
                        value,
                    } = operation
                    else {
                        unreachable!()
                    };
                    if let Some(existing) =
                        read_record(tx, &self.store, state, namespace, key, value.len())?
                    {
                        ensure!(
                            existing.value.as_slice() == value,
                            "staged immutable row differs"
                        );
                    } else {
                        records = records
                            .checked_add(1)
                            .context("namespace stage count overflow")?;
                        bytes = bytes
                            .checked_add(u64::try_from(key.len() + value.len())?)
                            .context("namespace stage bytes overflow")?;
                        write_domain(
                            tx,
                            &self.store,
                            state,
                            catalog,
                            std::slice::from_ref(operation),
                        )?;
                    }
                }
                let owner = Owner {
                    phase: Phase::Writing { records, bytes },
                    ..self.owner.clone()
                };
                write_domain(
                    tx,
                    &self.store,
                    state,
                    catalog,
                    &[owner.write(&self.namespace)?],
                )
            },
        )
    }

    fn seal(&self, records: u64, bytes: u64, sha256: [u8; 32]) -> Result<()> {
        let owner = Owner {
            phase: Phase::Sealed {
                records,
                bytes,
                sha256,
            },
            ..self.owner.clone()
        };
        let operation = owner.write(&self.namespace)?;
        mutate(&self.store, &[OWNERS], |tx, state, catalog| {
            let actual = self.require_writing(tx, state)?;
            ensure!(
                actual == (records, bytes),
                "namespace stage seal accounting differs"
            );
            write_domain(tx, &self.store, state, catalog, &[operation])
        })
    }

    /// Retire at most fifteen rows and one owner per commit. A selected owner
    /// is never eligible. Marking abandonment shares the deletion transaction;
    /// any racing stage/selection subsequently fails its owner check. Existing
    /// read views keep their native root, even after every current row is gone.
    /// Returns true once this unpublished namespace has been completely removed.
    pub fn reclaim(store: &Arc<TenantStore>, namespace: &str) -> Result<bool> {
        validate_target(namespace)?;
        let _memory = store
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(64 << 10)?;
        mutate(store, &[OWNERS, namespace], |tx, state, catalog| {
            let Some(mut owner) = read_owner(tx, store, state, namespace)? else {
                return Ok(true);
            };
            ensure!(
                owner.phase != Phase::Selected,
                "selected namespace cannot be reclaimed"
            );
            let keys = namespace_keys(tx, store, state, namespace, ROWS_PER_BATCH)?;
            owner.phase = Phase::Abandoned;
            write_domain(tx, store, state, catalog, &[owner.write(namespace)?])?;
            if keys.is_empty() {
                write_domain(
                    tx,
                    store,
                    state,
                    catalog,
                    &[WriteOp::delete(OWNERS, namespace.as_bytes())],
                )?;
                return Ok(true);
            }
            let mut table = tx.open_table(RECORDS)?;
            for key in keys {
                table.delete_key(key.as_slice())?;
            }
            Ok(false)
        })
    }

    /// Recovery under the caller's exclusive publication/apply gate, before it
    /// creates any candidate stages. Each deletion commit is bounded; the scan
    /// holds only a registered native snapshot and one owner at a time. It also
    /// removes sealed candidates whose selection never committed. Selected
    /// namespaces require the future snapshot/reference reachability collector.
    pub fn reclaim_unpublished(store: &Arc<TenantStore>) -> Result<()> {
        let view = store.read_view()?;
        view.visit(OWNERS, OWNER_BYTES, |namespace, bytes| {
            let owner = Owner::decode(bytes)?;
            if owner.phase != Phase::Selected {
                let namespace = std::str::from_utf8(namespace)?;
                while !Self::reclaim(store, namespace)? {}
            }
            Ok(())
        })?;
        view.close()
    }
}

fn validate_target(namespace: &str) -> Result<()> {
    validate_record(namespace, &[], 0)?;
    ensure!(
        namespace != OWNERS && !is_initial_identity_namespace(namespace),
        "protected namespace cannot be staged"
    );
    Ok(())
}

// Use the same write ownership, access checks and post-commit uncertainty as
// ordinary Store writes. Never hold key guards while waiting for fsync.
fn mutate<T>(
    store: &TenantStore,
    namespaces: &[&str],
    body: impl FnOnce(&kasumi_kv::WriteTransaction, &KeyState, &KeyCatalog) -> Result<T>,
) -> Result<T> {
    crate::deferred_batch::before_write(&store.node)?;
    let _access = AccessGuard(store);
    store.check_access()?;
    let _mutation = store.mutations.lock();
    let _fence = store.cached_rows.fence(namespaces.iter().copied());
    let mut output = None;
    store.node.with_registered_write(
        |tx| {
            let state = store.state.read();
            store.require_access(&state)?;
            let catalog = store.catalog.read();
            output = Some(body(tx, &state, &catalog)?);
            store.require_access(&state)
        },
        || {
            store
                .check_access()
                .context("namespace stage commit completed but access was lost; outcome unknown")
        },
    )?;
    Ok(output.expect("successful stage body"))
}

struct StageRecord {
    value: Zeroizing<Vec<u8>>,
    _memory: DiskMemoryLease,
}
fn read_record(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    namespace: &str,
    key: &[u8],
    max_bytes: usize,
) -> Result<Option<StageRecord>> {
    let index = state.keys.get(INDEX_KEY).context("index key missing")?;
    let disk_key = record_key(&store.tenant, namespace, key, index);
    let table = tx.open_table(RECORDS)?;
    let Some(value) = table.get(disk_key.as_slice())? else {
        return Ok(None);
    };
    check_encrypted_record_budget(value.value(), namespace.len(), key.len(), max_bytes)?;
    let workspace = u64::try_from(value.value().len())?
        .checked_mul(2)
        .and_then(|n| n.checked_add(8192))
        .context("stage decode workspace overflow")?;
    let memory = store
        .scratch_disk()
        .memory()
        .clone()
        .reserve_installed(workspace)?;
    let mut record = store.decode_record(&disk_key, value.value(), state)?;
    ensure!(
        record.namespace == namespace && record.key == key && record.value.len() <= max_bytes,
        "namespace stage record identity differs"
    );
    Ok(Some(StageRecord {
        value: Zeroizing::new(std::mem::take(&mut record.value)),
        _memory: memory,
    }))
}
fn read_owner(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    namespace: &str,
) -> Result<Option<Owner>> {
    read_record(tx, store, state, OWNERS, namespace.as_bytes(), OWNER_BYTES)?
        .map(|record| Owner::decode(&record.value))
        .transpose()
}
fn namespace_keys(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    namespace: &str,
    limit: usize,
) -> Result<Vec<Vec<u8>>> {
    let index = state.keys.get(INDEX_KEY).context("index key missing")?;
    let prefix = namespace_prefix(&store.tenant, namespace, index);
    let table = tx.open_table(RECORDS)?;
    let mut keys = Vec::with_capacity(limit);
    for entry in table.range(prefix.as_slice()..)? {
        let (key, _) = entry?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        keys.push(key.value().to_vec());
        if keys.len() == limit {
            break;
        }
    }
    Ok(keys)
}

/// The sealed check runs inside *the selecting native transaction*, including
/// paired publication. Checking only before calling write_batch permits GC to
/// delete a candidate in the gap and then publish a dangling checkpoint.
pub(super) fn validate_transitions(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    operations: &[WriteOp],
) -> Result<()> {
    for (position, operation) in operations.iter().enumerate() {
        let (namespace, key) = match operation {
            WriteOp::Put { namespace, key, .. } | WriteOp::Delete { namespace, key } => {
                (namespace, key)
            }
        };
        if namespace != OWNERS {
            continue;
        }
        ensure!(
            !operations[..position]
                .iter()
                .any(|previous| match previous {
                    WriteOp::Put {
                        namespace,
                        key: previous_key,
                        ..
                    }
                    | WriteOp::Delete {
                        namespace,
                        key: previous_key,
                    } => namespace == OWNERS && previous_key == key,
                }),
            "duplicate namespace stage transition"
        );
        let name = std::str::from_utf8(key)?;
        validate_target(name)?;
        let previous = read_owner(tx, store, state, name)?;
        match operation {
            WriteOp::Put { value, .. } => {
                let next = Owner::decode(value)?;
                let allowed = match (&previous, &next.phase) {
                    (
                        None,
                        Phase::Writing {
                            records: 0,
                            bytes: 0,
                        },
                    ) => true,
                    (Some(old), Phase::Writing { records, bytes }) => {
                        old.id == next.id
                            && matches!(old.phase, Phase::Writing { records: old_records, bytes: old_bytes } if *records >= old_records && *bytes >= old_bytes)
                    }
                    (Some(old), Phase::Sealed { .. }) => {
                        old.id == next.id && matches!(old.phase, Phase::Writing { .. })
                    }
                    (Some(old), Phase::Selected) => {
                        old.id == next.id && matches!(old.phase, Phase::Sealed { .. })
                    }
                    (Some(old), Phase::Abandoned) => {
                        old.id == next.id && old.phase != Phase::Selected
                    }
                    _ => false,
                };
                ensure!(allowed, "invalid namespace stage transition");
            }
            WriteOp::Delete { .. } => {
                ensure!(
                    previous.is_some_and(|owner| owner.phase == Phase::Abandoned),
                    "namespace stage is not abandoned"
                );
                ensure!(
                    namespace_keys(tx, store, state, name, 1)?.is_empty(),
                    "namespace stage still owns rows"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
