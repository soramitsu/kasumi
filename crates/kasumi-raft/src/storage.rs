use crate::lifetime::{StorageHandle, StorageLease};
use crate::{BasicNode, RaftLimits, SnapshotBuffer, StateMachineBackend, TypeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::{TenantStore, WriteOp};
use openraft::{
    Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    io,
    ops::RangeBounds,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const LOG: &str = "raft.log";
const LOG_FORMAT: &[u8] = b"kasumi-log\x01";
const META: &str = "raft.meta";
const SNAPSHOT: &str = "raft.snapshot";
// Store records are capped at 32 MiB. Snapshots have a separate, much larger
// tenant limit and must be installed through bounded encrypted chunks.
const SNAPSHOT_CHUNK_BYTES: usize = 4 * 1024 * 1024;

fn err(error: impl std::fmt::Display) -> StorageError<u64> {
    StorageIOError::write(&io::Error::other(error.to_string())).into()
}
fn put(namespace: &str, key: &[u8], value: Vec<u8>) -> WriteOp {
    WriteOp::Put {
        namespace: namespace.into(),
        key: key.into(),
        value,
    }
}
fn delete(namespace: &str, key: Vec<u8>) -> WriteOp {
    WriteOp::Delete {
        namespace: namespace.into(),
        key,
    }
}
fn load<T: DeserializeOwned>(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
) -> Result<Option<T>> {
    store
        .get(namespace, key)?
        .map(|bytes| serde_json::from_slice(&bytes).context("invalid raft storage record"))
        .transpose()
}

#[derive(Clone)]
pub struct LogStore {
    store: StorageHandle<TenantStore>,
    // Cloned log readers and snapshot writers can run concurrently. Every log/vote
    // mutation shares this gate, including read/modify/write deletion operations.
    io_gate: Arc<tokio::sync::Mutex<()>>,
    // Only IDs are resident. Point/range reads decrypt the requested records,
    // rather than scanning/decrypting the entire retained log on every apply.
    index: Arc<Mutex<BTreeMap<u64, LogId<u64>>>>,
}

impl LogStore {
    pub async fn open(store: Arc<TenantStore>, node_id: u64) -> Result<Self> {
        Self::open_inner(store, node_id, None).await
    }

    pub(crate) async fn open_tracked(
        store: Arc<TenantStore>,
        node_id: u64,
        lease: Arc<StorageLease>,
    ) -> Result<Self> {
        Self::open_inner(store, node_id, Some(lease)).await
    }

    async fn open_inner(
        store: Arc<TenantStore>,
        node_id: u64,
        lease: Option<Arc<StorageLease>>,
    ) -> Result<Self> {
        let store = StorageHandle::new(store, lease);
        let captured = store.clone();
        let index = tokio::task::spawn_blocking(move || -> Result<BTreeMap<u64, LogId<u64>>> {
            if let Some(saved) = load::<u64>(&captured, META, b"node_id")? {
                ensure!(
                    saved == node_id,
                    "persisted raft node identity differs from configuration"
                );
            } else {
                captured.write_batch(&[put(META, b"node_id", serde_json::to_vec(&node_id)?)])?;
            }
            // Detect malformed keys/entries before handing state to Raft.
            let entries = read_entries(&captured)?;
            for pair in entries.windows(2) {
                ensure!(
                    pair[1].log_id.index == pair[0].log_id.index + 1,
                    "raft log contains a hole"
                );
            }
            Ok(entries
                .into_iter()
                .map(|entry| (entry.log_id.index, entry.log_id))
                .collect())
        })
        .await??;
        Ok(Self {
            store,
            io_gate: Arc::new(tokio::sync::Mutex::new(())),
            index: Arc::new(Mutex::new(index)),
        })
    }

    async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&TenantStore) -> Result<T> + Send + 'static,
    ) -> Result<T, StorageError<u64>> {
        self.mutate(f).await
    }

    async fn mutate<T: Send + 'static>(
        &self,
        f: impl FnOnce(&TenantStore) -> Result<T> + Send + 'static,
    ) -> Result<T, StorageError<u64>> {
        let gate = self.io_gate.clone().lock_owned().await;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            // Keep ordering even when the awaiting future is cancelled: blocking
            // persistence must finish before the next mutation acquires this gate.
            let _gate = gate;
            f(&store)
        })
        .await
        .map_err(err)?
        .map_err(err)
    }

    pub(crate) async fn bind_group(&self, group: String) -> Result<(), StorageError<u64>> {
        self.mutate(move |store| {
            if let Some(saved) = load::<String>(store, META, b"group")? {
                ensure!(
                    saved == group,
                    "persisted raft group identity differs from configuration"
                );
            } else {
                store.write_batch(&[put(META, b"group", serde_json::to_vec(&group)?)])?;
            }
            Ok(())
        })
        .await
    }
}

fn read_entries(store: &TenantStore) -> Result<Vec<Entry<TypeConfig>>> {
    let mut result = Vec::new();
    for (key, value) in store.scan(LOG)? {
        let key: [u8; 8] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid raft index key"))?;
        let entry = decode_entry(&value)?;
        ensure!(
            entry.log_id.index == u64::from_be_bytes(key),
            "raft key/index mismatch"
        );
        result.push(entry);
    }
    result.sort_by_key(|entry| entry.log_id.index);
    Ok(result)
}

fn encode_entry(entry: &Entry<TypeConfig>) -> Result<Vec<u8>> {
    let mut bytes = LOG_FORMAT.to_vec();
    bytes.extend(postcard::to_allocvec(entry)?);
    Ok(bytes)
}

fn decode_entry(bytes: &[u8]) -> Result<Entry<TypeConfig>> {
    if let Some(bytes) = bytes.strip_prefix(LOG_FORMAT) {
        postcard::from_bytes(bytes).context("invalid binary raft log entry")
    } else if bytes.first() == Some(&b'{') {
        // Read early development stores; all subsequent writes use the compact,
        // versioned binary format. No fallback is attempted for malformed binary.
        serde_json::from_slice(bytes).context("invalid legacy raft log entry")
    } else {
        anyhow::bail!("unknown raft log record format")
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let index = self.index.clone();
        let bounds = (range.start_bound().cloned(), range.end_bound().cloned());
        self.read(move |store| {
            let ids = index
                .lock()
                .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?
                .range(bounds)
                .map(|(&index, &id)| (index, id))
                .collect::<Vec<_>>();
            ids.into_iter()
                .map(|(index, id)| {
                    let entry = decode_entry(
                        &store
                            .get(LOG, &index.to_be_bytes())?
                            .context("missing cached raft log entry")?,
                    )?;
                    ensure!(entry.log_id == id, "raft cached log ID mismatch");
                    Ok(entry)
                })
                .collect()
        })
        .await
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let index = self.index.clone();
        self.read(move |store| {
            let last_purged_log_id = load(store, META, b"purged")?;
            let last_log_id = index
                .lock()
                .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?
                .last_key_value()
                .map(|(_, &id)| id)
                .or(last_purged_log_id);
            Ok(LogState {
                last_purged_log_id,
                last_log_id,
            })
        })
        .await
    }

    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(vote).map_err(err)?;
        self.mutate(move |store| store.write_batch(&[put(META, b"vote", bytes)]))
            .await
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        self.read(|store| load(store, META, b"vote")).await
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(&committed).map_err(err)?;
        self.mutate(move |store| store.write_batch(&[put(META, b"committed", bytes)]))
            .await
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        self.read(|store| Ok(load::<Option<LogId<u64>>>(store, META, b"committed")?.flatten()))
            .await
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        let writes = entries
            .iter()
            .map(|entry| {
                Ok(put(
                    LOG,
                    &entry.log_id.index.to_be_bytes(),
                    encode_entry(entry)?,
                ))
            })
            .collect::<Result<Vec<_>>>()
            .map_err(err)?;
        let index = self.index.clone();
        let result = self
            .mutate(move |store| {
                let mut index = index
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?;
                // Appending may be larger than one store transaction. Persist a
                // contiguous prefix in each bounded transaction; signal completion
                // only after every entry is durable. Recovery accepts partial tails.
                let mut start = 0;
                while start < writes.len() {
                    let mut end = start;
                    let mut bytes = 0;
                    while end < writes.len() && end - start < 65536 {
                        let WriteOp::Put {
                            namespace,
                            key,
                            value,
                        } = &writes[end]
                        else {
                            unreachable!()
                        };
                        let size = namespace.len() + key.len() + value.len();
                        if end > start && bytes + size > 48 * 1024 * 1024 {
                            break;
                        }
                        bytes += size;
                        end += 1;
                    }
                    store.write_batch(&writes[start..end])?;
                    for entry in &entries[start..end] {
                        index.insert(entry.log_id.index, entry.log_id);
                    }
                    start = end;
                }
                Ok(())
            })
            .await;
        // Completion is sent only after the transactional store's durable commit.
        callback.log_io_completed(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| io::Error::other(error.to_string())),
        );
        result
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let index = self.index.clone();
        self.mutate(move |store| {
            let mut index = index
                .lock()
                .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?;
            // Remove a suffix from its end, so a crash during a multi-transaction
            // truncation never leaves a hole in the remaining contiguous log.
            let ids = index
                .range(log_id.index..)
                .rev()
                .map(|(&index, _)| index)
                .collect::<Vec<_>>();
            for ids in ids.chunks(65536) {
                let writes = ids
                    .iter()
                    .map(|index| delete(LOG, index.to_be_bytes().to_vec()))
                    .collect::<Vec<_>>();
                store.write_batch(&writes)?;
                for id in ids {
                    index.remove(id);
                }
            }
            Ok(())
        })
        .await
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let index = self.index.clone();
        self.mutate(move |store| {
            let mut index = index
                .lock()
                .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?;
            let ids = index
                .range(..=log_id.index)
                .map(|(_, &id)| id)
                .collect::<Vec<_>>();
            // Move the purge cursor in the same transaction as every removed
            // prefix. Covered snapshots were persisted before Raft calls purge.
            for ids in ids.chunks(65535) {
                let mut writes = ids
                    .iter()
                    .map(|id| delete(LOG, id.index.to_be_bytes().to_vec()))
                    .collect::<Vec<_>>();
                writes.push(put(
                    META,
                    b"purged",
                    serde_json::to_vec(ids.last().unwrap())?,
                ));
                store.write_batch(&writes)?;
                for id in ids {
                    index.remove(&id.index);
                }
            }
            if ids.last().copied() != Some(log_id) {
                store.write_batch(&[put(META, b"purged", serde_json::to_vec(&log_id)?)])?;
            }
            Ok(())
        })
        .await
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SnapshotEnvelope {
    version: u32,
    meta: SnapshotMeta<u64, BasicNode>,
    backend: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    version: u32,
    id: String,
    bytes: u64,
    chunks: u64,
}

fn chunk_key(manifest: &SnapshotManifest, chunk: u64) -> Vec<u8> {
    let mut key = manifest.id.as_bytes().to_vec();
    key.push(b'/');
    key.extend_from_slice(&chunk.to_be_bytes());
    key
}

fn load_manifest(store: &TenantStore, key: &[u8], limit: u64) -> Result<Option<SnapshotManifest>> {
    let manifest = load::<SnapshotManifest>(store, SNAPSHOT, key)?;
    if let Some(manifest) = &manifest {
        ensure!(
            manifest.version == 1 && uuid::Uuid::parse_str(&manifest.id).is_ok(),
            "invalid snapshot manifest"
        );
        ensure!(
            manifest.bytes <= limit,
            "stored snapshot exceeds byte limit"
        );
        ensure!(
            manifest.chunks == manifest.bytes.div_ceil(SNAPSHOT_CHUNK_BYTES as u64),
            "invalid snapshot chunk count"
        );
    }
    Ok(manifest)
}

// Pending chunks and an obsolete manifest have durable cleanup cursors. A crash
// at any chunk or manifest write leaves either the entire old snapshot or the
// entire new snapshot recoverable, with bounded cleanup on the next open/build.
fn cleanup_snapshots(store: &TenantStore, limit: u64) -> Result<()> {
    for marker in [b"pending".as_slice(), b"obsolete".as_slice()] {
        if let Some(manifest) = load_manifest(store, marker, limit)? {
            for start in (0..manifest.chunks).step_by(1024) {
                let writes = (start..manifest.chunks.min(start + 1024))
                    .map(|chunk| delete(SNAPSHOT, chunk_key(&manifest, chunk)))
                    .collect::<Vec<_>>();
                store.write_batch(&writes)?;
            }
            store.write_batch(&[delete(SNAPSHOT, marker.to_vec())])?;
        }
    }
    Ok(())
}

fn persist_snapshot(store: &TenantStore, bytes: &[u8], limit: u64) -> Result<()> {
    ensure!(bytes.len() as u64 <= limit, "snapshot exceeds byte limit");
    cleanup_snapshots(store, limit)?;
    let previous = load_manifest(store, b"current", limit)?;
    let manifest = SnapshotManifest {
        version: 1,
        id: uuid::Uuid::new_v4().to_string(),
        bytes: bytes.len() as u64,
        chunks: bytes.len().div_ceil(SNAPSHOT_CHUNK_BYTES) as u64,
    };
    let encoded = serde_json::to_vec(&manifest)?;
    store.write_batch(&[put(SNAPSHOT, b"pending", encoded.clone())])?;
    // Limit temporary write batches to 32 MiB as well as each individual record.
    for (batch, bytes) in bytes.chunks(SNAPSHOT_CHUNK_BYTES * 8).enumerate() {
        let writes = bytes
            .chunks(SNAPSHOT_CHUNK_BYTES)
            .enumerate()
            .map(|(offset, bytes)| {
                put(
                    SNAPSHOT,
                    &chunk_key(&manifest, (batch * 8 + offset) as u64),
                    bytes.to_vec(),
                )
            })
            .collect::<Vec<_>>();
        store.write_batch(&writes)?;
    }
    let mut install = vec![
        put(SNAPSHOT, b"current", encoded),
        delete(SNAPSHOT, b"pending".to_vec()),
    ];
    if let Some(previous) = previous {
        install.push(put(SNAPSHOT, b"obsolete", serde_json::to_vec(&previous)?));
    }
    store.write_batch(&install)?;
    cleanup_snapshots(store, limit)
}

#[derive(Default)]
struct AppliedState {
    log_id: Option<LogId<u64>>,
    membership: StoredMembership<u64, BasicNode>,
}

#[derive(Clone)]
pub struct StateMachine {
    store: StorageHandle<TenantStore>,
    backend: StorageHandle<dyn StateMachineBackend>,
    state: Arc<Mutex<AppliedState>>,
    snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    failed: Arc<AtomicBool>,
    limits: RaftLimits,
}

impl StateMachine {
    pub async fn open(
        store: Arc<TenantStore>,
        backend: Arc<dyn StateMachineBackend>,
    ) -> Result<Self> {
        Self::open_with_limits(store, backend, RaftLimits::default()).await
    }

    pub async fn open_with_limits(
        store: Arc<TenantStore>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
    ) -> Result<Self> {
        Self::open_inner(store, backend, limits, None).await
    }

    pub(crate) async fn open_tracked(
        store: Arc<TenantStore>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Arc<StorageLease>,
    ) -> Result<Self> {
        Self::open_inner(store, backend, limits, Some(lease)).await
    }

    async fn open_inner(
        store: Arc<TenantStore>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Option<Arc<StorageLease>>,
    ) -> Result<Self> {
        let store = StorageHandle::new(store, lease.clone());
        let backend = StorageHandle::new(backend, lease);
        let captured = store.clone();
        let target = backend.clone();
        let limit = limits.max_snapshot_bytes;
        let state = tokio::task::spawn_blocking(move || -> Result<AppliedState> {
            cleanup_snapshots(&captured, limit)?;
            if let Some(snapshot) = load_snapshot(&captured, limit)? {
                ensure!(snapshot.version == 1, "unsupported raft snapshot version");
                target.validate_snapshot(&snapshot.backend)?;
                target.restore(&snapshot.backend)?;
                Ok(AppliedState {
                    log_id: snapshot.meta.last_log_id,
                    membership: snapshot.meta.last_membership,
                })
            } else {
                Ok(AppliedState::default())
            }
        })
        .await??;
        Ok(Self {
            store,
            backend,
            state: Arc::new(Mutex::new(state)),
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            failed: Arc::new(AtomicBool::new(false)),
            limits,
        })
    }

    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    pub(crate) fn failure_flag(&self) -> Arc<AtomicBool> {
        self.failed.clone()
    }

    fn storage_failure(&self, error: impl std::fmt::Display) -> StorageError<u64> {
        self.failed.store(true, Ordering::Release);
        err(error)
    }
}

pub struct SnapshotBuilder {
    machine: StateMachine,
    captured: Result<Arc<SnapshotEnvelope>>,
}

fn load_snapshot(store: &TenantStore, limit: u64) -> Result<Option<SnapshotEnvelope>> {
    load_manifest(store, b"current", limit)?
        .map(|manifest| {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(usize::try_from(manifest.bytes)?)?;
            for chunk in 0..manifest.chunks {
                let data = store
                    .get(SNAPSHOT, &chunk_key(&manifest, chunk))?
                    .context("missing snapshot chunk")?;
                let expected =
                    (manifest.bytes - bytes.len() as u64).min(SNAPSHOT_CHUNK_BYTES as u64) as usize;
                ensure!(data.len() == expected, "snapshot chunk length mismatch");
                bytes.extend_from_slice(&data);
            }
            ensure!(bytes.len() as u64 == manifest.bytes, "incomplete snapshot");
            Ok(postcard::from_bytes(&bytes)?)
        })
        .transpose()
}

fn as_snapshot(snapshot: &SnapshotEnvelope, limit: u64) -> Result<Snapshot<TypeConfig>> {
    Ok(Snapshot {
        meta: snapshot.meta.clone(),
        snapshot: Box::new(SnapshotBuffer::from_bytes(
            postcard::to_allocvec(&snapshot)?,
            limit,
        )?),
    })
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let gate = self.machine.snapshot_gate.clone().lock_owned().await;
        let captured = self.captured.as_ref().map_err(err)?.clone();
        let store = self.machine.store.clone();
        let limit = self.machine.limits.max_snapshot_bytes;
        tokio::task::spawn_blocking(move || -> Result<Snapshot<TypeConfig>> {
            let _gate = gate;
            if let Some(current) = load_snapshot(&store, limit)?
                && current.meta.last_log_id.map(|id| id.index)
                    > captured.meta.last_log_id.map(|id| id.index)
            {
                return as_snapshot(&current, limit);
            }
            let snapshot = as_snapshot(&captured, limit)?;
            persist_snapshot(&store, snapshot.snapshot.as_bytes(), limit)?;
            Ok(snapshot)
        })
        .await
        .map_err(|error| self.machine.storage_failure(error))?
        .map_err(|error| self.machine.storage_failure(error))
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let state = self.state.clone();
        // Snapshot capture holds this lock while serializing its matching
        // generation. Never wait for that potentially large job on a Tokio worker.
        tokio::task::spawn_blocking(move || -> Result<_> {
            let state = state
                .lock()
                .map_err(|_| anyhow::anyhow!("applied state lock poisoned"))?;
            Ok((state.log_id, state.membership.clone()))
        })
        .await
        .map_err(err)?
        .map_err(err)
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Vec<u8>>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        let machine = self.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Vec<u8>>> {
            machine.store.check_access()?;
            ensure!(!machine.failed(), "state machine requires recovery");
            let mut state = machine
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("state machine lock poisoned"))?;
            let mut responses = Vec::with_capacity(entries.len());
            for entry in entries {
                let response = match entry.payload {
                    EntryPayload::Blank => Vec::new(),
                    EntryPayload::Membership(membership) => {
                        state.membership = StoredMembership::new(Some(entry.log_id), membership);
                        Vec::new()
                    }
                    EntryPayload::Normal(command) => {
                        machine.backend.apply(entry.log_id.index, &command)?
                    }
                };
                // Backend has published its complete generation before advancing this cursor.
                state.log_id = Some(entry.log_id);
                responses.push(response);
            }
            Ok(responses)
        })
        .await
        .map_err(|error| self.storage_failure(error))?
        .map_err(|error| self.storage_failure(error))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let machine = self.clone();
        let captured = tokio::task::spawn_blocking(move || -> Result<SnapshotEnvelope> {
            machine.store.check_access()?;
            let state = machine
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("state machine lock poisoned"))?;
            Ok(SnapshotEnvelope {
                version: 1,
                meta: SnapshotMeta {
                    last_log_id: state.log_id,
                    last_membership: state.membership.clone(),
                    snapshot_id: uuid::Uuid::new_v4().to_string(),
                },
                backend: machine.backend.snapshot()?,
            })
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
        SnapshotBuilder {
            machine: self.clone(),
            // Cloning the builder's captured payload must only clone an Arc;
            // serialization belongs to the blocking storage worker below.
            captured: captured.map(Arc::new),
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotBuffer>, StorageError<u64>> {
        self.store.check_access().map_err(err)?;
        Ok(Box::new(SnapshotBuffer::new(
            self.limits.max_snapshot_bytes,
        )))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<SnapshotBuffer>,
    ) -> Result<(), StorageError<u64>> {
        let gate = self.snapshot_gate.clone().lock_owned().await;
        if snapshot.as_bytes().len() as u64 > self.limits.max_snapshot_bytes {
            return Err(err("snapshot exceeds byte limit"));
        }
        let meta = meta.clone();
        let machine = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _gate = gate;
            // Parsing allocates the complete backend image. Do it off the
            // runtime along with validation, persistence, and materialization.
            let envelope: SnapshotEnvelope = postcard::from_bytes(snapshot.as_bytes())?;
            ensure!(
                envelope.version == 1 && envelope.meta == meta,
                "snapshot metadata mismatch"
            );
            let mut state = machine
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("state machine lock poisoned"))?;
            ensure!(
                envelope.meta.last_log_id.map(|id| id.index) >= state.log_id.map(|id| id.index),
                "snapshot would revert applied state"
            );
            machine.backend.validate_snapshot(&envelope.backend)?;
            // Durably install encrypted chunks and their manifest, then atomically publish backend state.
            // A crash between these steps recovers the new snapshot on restart.
            persist_snapshot(
                &machine.store,
                snapshot.as_bytes(),
                machine.limits.max_snapshot_bytes,
            )?;
            machine.backend.restore(&envelope.backend)?;
            state.log_id = envelope.meta.last_log_id;
            state.membership = envelope.meta.last_membership;
            Ok(())
        })
        .await
        .map_err(|error| self.storage_failure(error))?
        .map_err(|error| self.storage_failure(error))
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        let store = self.store.clone();
        let limit = self.limits.max_snapshot_bytes;
        tokio::task::spawn_blocking(move || {
            load_snapshot(&store, limit)?
                .map(|snapshot| as_snapshot(&snapshot, limit))
                .transpose()
        })
        .await
        .map_err(err)?
        .map_err(err)
    }
}

#[cfg(test)]
mod tests;
