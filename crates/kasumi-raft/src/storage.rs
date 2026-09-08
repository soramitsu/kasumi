use crate::command::sha256;
use crate::control::{AppliedEntryContext, HEADERS, HeaderPayload, LogHeader, RetainedSeed, SEEDS};
use crate::lifetime::{StorageHandle, StorageLease};
use crate::{BasicNode, RaftLimits, SnapshotBuffer, StateMachineBackend, TypeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedSpool, SnapshotImage};
use kasumi_store::{TenantStorageSet, TenantStore, WriteOp};
use openraft::{
    Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    io,
    ops::RangeBounds,
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

const LOG: &str = "raft.log";
pub(crate) const CUSTODY_LOG: &str = "raft.custody-log";
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

// Log cleanup, accepted application cursors and snapshot publication share this
// per-store gate. It is process-local ordering, never durable authority.
type ControlGateMap = Mutex<HashMap<usize, Weak<Mutex<()>>>>;
static CONTROL_GATES: LazyLock<ControlGateMap> = LazyLock::new(|| Mutex::new(HashMap::new()));
pub(crate) fn control_gate(custody: &kasumi_store::CustodyStore) -> Result<Arc<Mutex<()>>> {
    let mut gates = CONTROL_GATES
        .lock()
        .map_err(|_| anyhow::anyhow!("control gate registry poisoned"))?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    let key = Arc::as_ptr(custody.store()) as usize;
    if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(key, Arc::downgrade(&gate));
    Ok(gate)
}

#[derive(Clone)]
pub struct LogStore {
    store: StorageHandle<TenantStore>,
    domains: StorageHandle<crate::domains::Domains>,
    // Cloned log readers and snapshot writers can run concurrently. Every log/vote
    // mutation shares this gate, including read/modify/write deletion operations.
    io_gate: Arc<tokio::sync::Mutex<()>>,
    control_gate: Arc<Mutex<()>>,
    // Only IDs are resident. Point/range reads decrypt the requested records,
    // rather than scanning/decrypting the entire retained log on every apply.
    index: Arc<Mutex<BTreeMap<u64, LogId<u64>>>>,
}

impl LogStore {
    pub async fn open(domains: Arc<TenantStorageSet>, node_id: u64) -> Result<Self> {
        Self::open_inner(
            Arc::new(crate::domains::Domains::Serving(domains)),
            node_id,
            None,
        )
        .await
    }

    pub(crate) async fn open_tracked(
        domains: Arc<TenantStorageSet>,
        node_id: u64,
        lease: Arc<StorageLease>,
    ) -> Result<Self> {
        Self::open_inner(
            Arc::new(crate::domains::Domains::Serving(domains)),
            node_id,
            Some(lease),
        )
        .await
    }

    pub(crate) async fn open_custody(
        custody: Arc<kasumi_store::CustodyStore>,
        node_id: u64,
        lease: Arc<StorageLease>,
    ) -> Result<Self> {
        Self::open_inner(
            Arc::new(crate::domains::Domains::Custody(custody)),
            node_id,
            Some(lease),
        )
        .await
    }

    async fn open_inner(
        domains: Arc<crate::domains::Domains>,
        node_id: u64,
        lease: Option<Arc<StorageLease>>,
    ) -> Result<Self> {
        let control_gate = control_gate(domains.custody())?;
        let store = StorageHandle::new(domains.custody().store().clone(), lease.clone());
        let domains = StorageHandle::new(domains, lease);
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
            let entries = read_headers(&captured)?;
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
            domains,
            io_gate: Arc::new(tokio::sync::Mutex::new(())),
            control_gate,
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
        let control = self.control_gate.clone();
        tokio::task::spawn_blocking(move || {
            // Keep ordering even when the awaiting future is cancelled: blocking
            // persistence must finish before the next mutation acquires this gate.
            let _gate = gate;
            let _control = control
                .lock()
                .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))?;
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

fn read_headers(store: &TenantStore) -> Result<Vec<LogHeader>> {
    let mut result = Vec::new();
    for (key, value) in store.scan(HEADERS)? {
        let key: [u8; 8] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid raft index key"))?;
        let header: LogHeader = serde_json::from_slice(&value)?;
        header.validate()?;
        ensure!(
            header.log_id.index == u64::from_be_bytes(key),
            "raft key/index mismatch"
        );
        result.push(header);
    }
    result.sort_by_key(|entry| entry.log_id.index);
    Ok(result)
}

pub(crate) fn encode_entry(entry: &Entry<TypeConfig>) -> Result<Vec<u8>> {
    let mut bytes = LOG_FORMAT.to_vec();
    bytes.extend(postcard::to_allocvec(entry)?);
    Ok(bytes)
}

fn decode_entry(bytes: &[u8]) -> Result<Entry<TypeConfig>> {
    let bytes = bytes
        .strip_prefix(LOG_FORMAT)
        .context("unknown raft log record format")?;
    postcard::from_bytes(bytes).context("invalid binary raft log entry")
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let index = self.index.clone();
        let domains = self.domains.clone();
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
                    let header: LogHeader = load(store, HEADERS, &index.to_be_bytes())?
                        .context("missing cached raft header")?;
                    ensure!(header.log_id == id, "raft cached log ID mismatch");
                    let entry = match &header.payload {
                        HeaderPayload::Blank => Entry {
                            log_id: id,
                            payload: EntryPayload::Blank,
                        },
                        HeaderPayload::Membership(membership) => Entry {
                            log_id: id,
                            payload: EntryPayload::Membership(membership.clone()),
                        },
                        HeaderPayload::Custody { .. } => {
                            let encoded = store
                                .get(CUSTODY_LOG, &index.to_be_bytes())?
                                .context("missing closed custody raft body")?;
                            let entry = decode_entry(&encoded)?;
                            header.check_entry(&entry, &encoded)?;
                            entry
                        }
                        _ => {
                            let encoded = domains
                                .application()?
                                .get(LOG, &index.to_be_bytes())?
                                .context("missing application raft body")?;
                            let entry = decode_entry(&encoded)?;
                            header.check_entry(&entry, &encoded)?;
                            entry
                        }
                    };
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
        self.mutate(move |store| {
            let previous = load::<Option<LogId<u64>>>(store, META, b"committed")?.flatten();
            ensure!(
                committed >= previous,
                "committed source position cannot regress"
            );
            if let Some(id) = committed {
                let active = load::<LogHeader>(store, HEADERS, &id.index.to_be_bytes())?;
                let covered = load::<LogId<u64>>(store, META, b"purged")?;
                ensure!(
                    active.is_some_and(|header| header.log_id == id) || covered == Some(id),
                    "commit position lacks exact source log coverage"
                );
            }
            store.write_batch(&[put(META, b"committed", bytes)])
        })
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
        let bootstrap_sha256 =
            load::<String>(&self.store, META, b"application_bootstrap_sha256").map_err(err)?;
        let storage_binding_sha256 = self.domains.custody().binding().digest().map_err(err)?;
        let writes = entries
            .iter()
            .map(|entry| {
                let encoded = encode_entry(entry)?;
                let (header, seed) = LogHeader::build(entry, &encoded)?;
                header.validate()?;
                let key = entry.log_id.index.to_be_bytes();
                let closed = matches!(header.payload, HeaderPayload::Custody { .. });
                let mut control = vec![put(HEADERS, &key, serde_json::to_vec(&header)?)];
                if let Some(seed) = seed {
                    control.push(put(
                        SEEDS,
                        &key,
                        serde_json::to_vec(&RetainedSeed {
                            header,
                            seed,
                            bootstrap_sha256: bootstrap_sha256
                                .clone()
                                .context("retirement seed lacks installed application bootstrap")?,
                            storage_binding_sha256: storage_binding_sha256.clone(),
                        })?,
                    ));
                } else {
                    control.push(delete(SEEDS, key.to_vec()));
                }
                let application = if closed {
                    control.push(put(CUSTODY_LOG, &key, encoded));
                    self.domains.serving().map(|_| delete(LOG, key.to_vec()))
                } else {
                    control.push(delete(CUSTODY_LOG, key.to_vec()));
                    if self.domains.serving().is_some() {
                        Some(put(LOG, &key, encoded))
                    } else {
                        ensure!(
                            !matches!(entry.payload, EntryPayload::Normal(_)),
                            "payload log append forbidden in retired custody"
                        );
                        None
                    }
                };
                Ok((application, control))
            })
            .collect::<Result<Vec<_>>>()
            .map_err(err)?;
        let index = self.index.clone();
        let domains = self.domains.clone();
        let result = self
            .mutate(move |store| {
                // OpenRaft may repopulate physical logs beneath a snapshot.
                // That does not change the separately committed snapshot. Only
                // an exact accepted retirement identity is immutable here.
                if let Some(boundary) = crate::control::retired_boundary(domains.custody())? {
                    for entry in &entries {
                        if entry.log_id.index > boundary.position.log_id.index
                            && let EntryPayload::Normal(command) = &entry.payload
                        {
                            ensure!(
                                command.custody_command()?.is_some(),
                                "application log entry after permanent retirement"
                            );
                        }
                    }
                    for entry in entries
                        .iter()
                        .filter(|entry| entry.log_id.index == boundary.position.log_id.index)
                    {
                        let retained: RetainedSeed =
                            load(store, SEEDS, &entry.log_id.index.to_be_bytes())?
                                .context("accepted retirement seed absent")?;
                        retained.header.check_entry(entry, &encode_entry(entry)?)?;
                    }
                }
                let mut index = index
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?;
                // Each prefix commits bodies and their headers/seeds together. The
                // I/O callback observes only complete durable entries, never a sidecar.
                let mut start = 0;
                while start < writes.len() {
                    let mut end = start;
                    let mut bytes = 0usize;
                    let mut count = 0usize;
                    let mut data = Vec::new();
                    let mut control = Vec::new();
                    while end < writes.len() {
                        let entry_ops = usize::from(writes[end].0.is_some()) + writes[end].1.len();
                        let size = writes[end]
                            .0
                            .iter()
                            .chain(writes[end].1.iter())
                            .map(|op| match op {
                                WriteOp::Put {
                                    namespace,
                                    key,
                                    value,
                                } => namespace.len() + key.len() + value.len(),
                                WriteOp::Delete { namespace, key } => namespace.len() + key.len(),
                            })
                            .sum::<usize>();
                        if end > start
                            && (bytes + size > 48 * 1024 * 1024 || count + entry_ops > 65536)
                        {
                            break;
                        }
                        bytes += size;
                        count += entry_ops;
                        data.extend(writes[end].0.iter().cloned());
                        control.extend(writes[end].1.iter().cloned());
                        end += 1;
                    }
                    domains.write_batch(&data, &control)?;
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
        let domains = self.domains.clone();
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
            if let Some(committed) =
                load::<Option<LogId<u64>>>(store, META, b"committed")?.flatten()
            {
                ensure!(
                    log_id.index > committed.index,
                    "cannot truncate committed source log"
                );
            }
            let protected = crate::control::retired_boundary(domains.custody())?
                .map(|boundary| boundary.position.log_id.index);
            for ids in ids.chunks(16384) {
                let writes = if domains.serving().is_some() {
                    ids.iter()
                        .map(|index| delete(LOG, index.to_be_bytes().to_vec()))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let control = ids
                    .iter()
                    .flat_map(|index| {
                        [
                            delete(HEADERS, index.to_be_bytes().to_vec()),
                            delete(CUSTODY_LOG, index.to_be_bytes().to_vec()),
                        ]
                        .into_iter()
                        .chain(
                            (Some(*index) != protected)
                                .then(|| delete(SEEDS, index.to_be_bytes().to_vec())),
                        )
                    })
                    .collect::<Vec<_>>();
                domains.write_batch(&writes, &control)?;
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
        let domains = self.domains.clone();
        self.mutate(move |store| {
            let mut index = index
                .lock()
                .map_err(|_| anyhow::anyhow!("raft index lock poisoned"))?;
            let retired = crate::control::retired_boundary(domains.custody())?.is_some();
            let ids = index
                .range(..=log_id.index)
                .map(|(_, &id)| id)
                .collect::<Vec<_>>();
            // Move the purge cursor in the same transaction as every removed
            // prefix. Covered snapshots were persisted before Raft calls purge.
            for ids in ids.chunks(21845) {
                let mut writes = ids
                    .iter()
                    .flat_map(|id| {
                        [
                            delete(HEADERS, id.index.to_be_bytes().to_vec()),
                            delete(CUSTODY_LOG, id.index.to_be_bytes().to_vec()),
                        ]
                    })
                    .collect::<Vec<_>>();
                writes.push(put(
                    META,
                    b"purged",
                    serde_json::to_vec(ids.last().unwrap())?,
                ));
                if retired {
                    store.write_batch(&writes)?;
                } else {
                    let bodies = ids
                        .iter()
                        .map(|id| delete(LOG, id.index.to_be_bytes().to_vec()))
                        .collect::<Vec<_>>();
                    domains.write_batch(&bodies, &writes)?;
                }
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum SnapshotKind {
    Application,
    Custody,
}

#[derive(Clone)]
pub(crate) struct SnapshotEnvelope {
    pub(crate) version: u32,
    pub(crate) kind: SnapshotKind,
    pub(crate) meta: SnapshotMeta<u64, BasicNode>,
    pub(crate) backend: SnapshotImage,
    pub(crate) retirement: Option<crate::snapshot_custody::SnapshotRetirement>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    version: u32,
    sha256: String,
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
        kasumi_types::validate_sha256(&manifest.sha256)?;
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotCoverage {
    pub(crate) kind: SnapshotKind,
    pub(crate) manifest_id: String,
    pub(crate) snapshot_sha256: String,
    pub(crate) backend_sha256: String,
    pub(crate) meta: SnapshotMeta<u64, BasicNode>,
}

pub fn recovery_snapshot_bytes(domains: &TenantStorageSet) -> Result<u64> {
    Ok(load_manifest(
        domains.application(),
        b"current",
        RaftLimits::default().max_snapshot_bytes,
    )?
    .map_or(0, |manifest| manifest.bytes))
}

fn validate_snapshot_coverage(
    domains: &TenantStorageSet,
    snapshot: &SnapshotEnvelope,
    limit: u64,
) -> Result<()> {
    let manifest = load_manifest(domains.application(), b"current", limit)?
        .context("snapshot manifest absent")?;
    let coverage: SnapshotCoverage =
        load(domains.custody().store(), META, b"snapshot_coverage")?
            .context("snapshot lacks independently readable control coverage")?;
    ensure!(
        coverage.kind == SnapshotKind::Application
            && snapshot.kind == SnapshotKind::Application
            && coverage.manifest_id == manifest.id
            && coverage.snapshot_sha256 == manifest.sha256
            && coverage.backend_sha256 == snapshot.backend.sha256()
            && coverage.meta == snapshot.meta,
        "snapshot/control coverage mismatch"
    );
    crate::snapshot_custody::check_published(
        domains.custody(),
        &snapshot.meta,
        &manifest.sha256,
        snapshot.retirement.as_ref(),
    )?;
    Ok(())
}

struct PendingSnapshot {
    application: Vec<WriteOp>,
    coverage: SnapshotCoverage,
}

fn stage_snapshot(
    domains: &TenantStorageSet,
    bytes: &SnapshotImage,
    limit: u64,
    snapshot: &SnapshotEnvelope,
) -> Result<PendingSnapshot> {
    let meta = &snapshot.meta;
    let store = domains.application();
    ensure!(bytes.len() <= limit, "snapshot exceeds byte limit");
    cleanup_snapshots(store, limit)?;
    let previous = load_manifest(store, b"current", limit)?;
    let manifest = SnapshotManifest {
        version: 1,
        sha256: bytes.sha256().to_owned(),
        id: uuid::Uuid::new_v4().to_string(),
        bytes: bytes.len(),
        chunks: bytes.len().div_ceil(SNAPSHOT_CHUNK_BYTES as u64),
    };
    let encoded = serde_json::to_vec(&manifest)?;
    store.write_batch(&[put(SNAPSHOT, b"pending", encoded.clone())])?;
    let mut reader = bytes.reader();
    let mut remaining = bytes.len();
    for index in 0..manifest.chunks {
        let mut chunk = vec![0; remaining.min(SNAPSHOT_CHUNK_BYTES as u64) as usize];
        reader.read_exact(&mut chunk)?;
        remaining -= chunk.len() as u64;
        store.write_batch(&[put(SNAPSHOT, &chunk_key(&manifest, index), chunk)])?;
    }
    let mut install = vec![
        put(SNAPSHOT, b"current", encoded),
        delete(SNAPSHOT, b"pending".to_vec()),
    ];
    if let Some(previous) = previous {
        install.push(put(SNAPSHOT, b"obsolete", serde_json::to_vec(&previous)?));
    }
    let coverage = SnapshotCoverage {
        kind: SnapshotKind::Application,
        manifest_id: manifest.id,
        snapshot_sha256: manifest.sha256,
        backend_sha256: snapshot.backend.sha256().to_owned(),
        meta: meta.clone(),
    };
    Ok(PendingSnapshot {
        application: install,
        coverage,
    })
}

// The caller holds the state-machine applied lock through this exact publication.
// Chunk upload does not hold that lock, and cannot advance the durable cursor.
fn publish_snapshot(
    domains: &TenantStorageSet,
    pending: PendingSnapshot,
    snapshot: &SnapshotEnvelope,
    backend: Option<&dyn crate::PreparedStateMachineRestore>,
) -> Result<()> {
    let coverage = pending.coverage;
    let mut custody = crate::snapshot_custody::installation_writes(
        domains.custody(),
        &snapshot.meta,
        snapshot.retirement.as_ref(),
        &coverage.backend_sha256,
        &coverage.snapshot_sha256,
    )?;
    custody.writes.push(put(
        META,
        b"snapshot_coverage",
        serde_json::to_vec(&coverage)?,
    ));
    let replacements = custody.records.as_ref().map(|records| records.namespaces());
    let mut application = pending.application;
    if let Some(backend) = backend {
        application.extend_from_slice(backend.application_writes());
    }
    let application_replacements = backend.map_or_else(Vec::new, |b| b.application_replacements());
    domains.write_batch_replacing(
        &application,
        &custody.writes,
        &application_replacements,
        replacements
            .as_ref()
            .map_or(&[], |namespaces| namespaces.as_slice()),
    )
}

#[cfg(test)]
fn persist_snapshot(
    domains: &TenantStorageSet,
    bytes: &[u8],
    limit: u64,
    snapshot: &SnapshotEnvelope,
) -> Result<()> {
    let pending = stage_snapshot(
        domains,
        &SnapshotImage::from_bytes(domains.application().scratch_disk(), bytes)?,
        limit,
        snapshot,
    )?;
    publish_snapshot(domains, pending, snapshot, None)?;
    cleanup_snapshots(domains.application(), limit)
}

#[derive(Default)]
struct AppliedState {
    log_id: Option<LogId<u64>>,
    membership: StoredMembership<u64, BasicNode>,
}

#[derive(Clone)]
pub struct StateMachine {
    domains: StorageHandle<TenantStorageSet>,
    store: StorageHandle<TenantStore>,
    backend: StorageHandle<dyn StateMachineBackend>,
    state: Arc<Mutex<AppliedState>>,
    snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    control_gate: Arc<Mutex<()>>,
    failed: Arc<AtomicBool>,
    limits: RaftLimits,
}

impl StateMachine {
    pub async fn open(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
    ) -> Result<Self> {
        Self::open_with_limits(domains, backend, RaftLimits::default()).await
    }

    pub async fn open_with_limits(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
    ) -> Result<Self> {
        Self::open_inner(domains, backend, limits, None).await
    }

    pub(crate) async fn open_tracked(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Arc<StorageLease>,
    ) -> Result<Self> {
        Self::open_inner(domains, backend, limits, Some(lease)).await
    }

    async fn open_inner(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Option<Arc<StorageLease>>,
    ) -> Result<Self> {
        let control_gate = control_gate(domains.custody())?;
        let store = StorageHandle::new(domains.application().clone(), lease.clone());
        let domains = StorageHandle::new(domains, lease.clone());
        let backend = StorageHandle::new(backend, lease);
        let captured_domains = domains.clone();
        let captured = store.clone();
        let target = backend.clone();
        let limit = limits.max_snapshot_bytes;
        let state = tokio::task::spawn_blocking(move || -> Result<AppliedState> {
            captured_domains.check_access()?;
            cleanup_snapshots(&captured, limit)?;
            if let Some(snapshot) = load_snapshot(&captured, limit)? {
                validate_snapshot_coverage(&captured_domains, &snapshot, limit)?;
                ensure!(snapshot.version == 1, "unsupported raft snapshot version");
                let prepared = target.prepare_restore(&mut snapshot.backend.reader())?;
                crate::snapshot_custody::check_backend(
                    &snapshot.meta,
                    snapshot.retirement.as_ref(),
                    prepared.retirement(),
                )?;
                captured_domains.write_batch_replacing(
                    prepared.application_writes(), &[],
                    &prepared.application_replacements(), &[],
                )?;
                prepared.publish()?;
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
            domains,
            store,
            backend,
            state: Arc::new(Mutex::new(state)),
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            control_gate,
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

struct LogicalSnapshot {
    meta: SnapshotMeta<u64, BasicNode>,
    backend: crate::CapturedSnapshot,
    retirement: Option<crate::snapshot_custody::SnapshotRetirement>,
}
pub struct SnapshotBuilder {
    machine: StateMachine,
    captured: Result<Arc<LogicalSnapshot>>,
}

fn load_snapshot(store: &TenantStore, limit: u64) -> Result<Option<SnapshotEnvelope>> {
    load_manifest(store, b"current", limit)?
        .map(|manifest| {
            let mut spool = EncryptedSpool::new(store.scratch_disk(), limit)?;
            for index in 0..manifest.chunks {
                let data = store
                    .get(SNAPSHOT, &chunk_key(&manifest, index))?
                    .context("missing snapshot chunk")?;
                let expected =
                    (manifest.bytes - spool.len()).min(SNAPSHOT_CHUNK_BYTES as u64) as usize;
                ensure!(data.len() == expected, "snapshot chunk length mismatch");
                spool.write_all(&data)?;
            }
            let image = SnapshotImage::freeze(spool)?;
            ensure!(
                image.len() == manifest.bytes && image.sha256() == manifest.sha256,
                "snapshot content digest differs"
            );
            SnapshotEnvelope::decode(image.disk(), &mut image.reader(), limit)
        })
        .transpose()
}

pub(crate) fn as_snapshot(snapshot: &SnapshotEnvelope, limit: u64) -> Result<Snapshot<TypeConfig>> {
    Ok(Snapshot {
        meta: snapshot.meta.clone(),
        snapshot: Box::new(SnapshotBuffer::from_image(snapshot.encode(limit)?)),
    })
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let gate = self.machine.snapshot_gate.clone().lock_owned().await;
        let captured = self.captured.as_ref().map_err(err)?.clone();
        let domains = self.machine.domains.clone();
        let store = self.machine.store.clone();
        let limit = self.machine.limits.max_snapshot_bytes;
        let applied = self.machine.state.clone();
        let control = self.machine.control_gate.clone();
        tokio::task::spawn_blocking(move || -> Result<Snapshot<TypeConfig>> {
            let _gate = gate;
            domains.check_access()?;
            if let Some(current) = load_snapshot(&store, limit)?
                && current.meta.last_log_id.map(|id| id.index)
                    >= captured.meta.last_log_id.map(|id| id.index)
            {
                validate_snapshot_coverage(&domains, &current, limit)?;
                if current.meta.last_log_id.map(|id| id.index)
                    == captured.meta.last_log_id.map(|id| id.index)
                {
                    ensure!(
                        current.meta.last_log_id == captured.meta.last_log_id
                            && current.meta.last_membership == captured.meta.last_membership,
                        "snapshot log or membership identity differs at the same position"
                    );
                    crate::snapshot_custody::check_same_retirement(
                        current.retirement.as_ref(),
                        captured.retirement.as_ref(),
                    )?;
                }
                return as_snapshot(&current, limit);
            }
            let captured = SnapshotEnvelope {
                version: 1,
                kind: SnapshotKind::Application,
                meta: captured.meta.clone(),
                backend: SnapshotImage::capture(store.scratch_disk(), limit, |writer| {
                    captured.backend.write(writer)
                })?,
                retirement: captured.retirement.clone(),
            };
            let snapshot = as_snapshot(&captured, limit)?;
            let pending = stage_snapshot(&domains, &snapshot.snapshot.image()?, limit, &captured)?;
            let publication = applied
                .lock()
                .map_err(|_| anyhow::anyhow!("applied publication lock poisoned"))?;
            let control_publication = control
                .lock()
                .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))?;
            publish_snapshot(&domains, pending, &captured, None)?;
            drop(control_publication);
            drop(publication);
            cleanup_snapshots(&store, limit)?;
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
            machine.domains.check_access()?;
            ensure!(!machine.failed(), "state machine requires recovery");
            let mut state = machine
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("state machine lock poisoned"))?;
            let mut responses = Vec::with_capacity(entries.len());
            for entry in entries {
                machine.domains.check_access()?;
                let (command_sha256, retirement_seed) = match &entry.payload {
                    EntryPayload::Normal(command) => (sha256(command.bytes()), command.seed()?),
                    _ => (sha256(&encode_entry(&entry)?), None),
                };
                let mut position = AppliedEntryContext {
                    log_id: entry.log_id,
                    previous: state.log_id,
                    membership: state.membership.clone(),
                    command_sha256,
                    retirement_seed,
                };
                let response = match entry.payload {
                    EntryPayload::Blank => crate::AppliedResponse::application(Vec::new()),
                    EntryPayload::Membership(membership) => {
                        state.membership = StoredMembership::new(Some(entry.log_id), membership);
                        position.membership = state.membership.clone();
                        crate::AppliedResponse::application(Vec::new())
                    }
                    EntryPayload::Normal(command) => {
                        if let Some(closed) = command.custody_command()? {
                            let _control = machine.control_gate.lock().map_err(|_| {
                                anyhow::anyhow!("control publication lock poisoned")
                            })?;
                            let data = crate::control::apply_custody(
                                machine.domains.custody(),
                                &position,
                                &closed,
                            )?;
                            state.log_id = Some(entry.log_id);
                            responses.push(data);
                            continue;
                        }
                        machine.backend.apply(&position, command.bytes())?
                    }
                };
                // A crash before this marker leaves the committed seed available
                // independently; it never falsely marks a projection as applied.
                {
                    let _control = machine
                        .control_gate
                        .lock()
                        .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))?;
                    crate::control::persist_applied(
                        &machine.domains,
                        &position,
                        response.retirement,
                    )?;
                }
                // Backend has published its complete generation before advancing this cursor.
                state.log_id = Some(entry.log_id);
                responses.push(response.data);
            }
            Ok(responses)
        })
        .await
        .map_err(|error| self.storage_failure(error))?
        .map_err(|error| self.storage_failure(error))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let machine = self.clone();
        let captured = tokio::task::spawn_blocking(move || -> Result<LogicalSnapshot> {
            machine.domains.check_access()?;
            let state = machine
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("state machine lock poisoned"))?;
            let meta = SnapshotMeta {
                last_log_id: state.log_id,
                last_membership: state.membership.clone(),
                snapshot_id: uuid::Uuid::new_v4().to_string(),
            };
            let captured = machine.backend.capture_snapshot()?;
            let retirement = crate::snapshot_custody::capture(
                machine.domains.custody(),
                &meta,
                captured.retirement.clone(),
            )?;
            Ok(LogicalSnapshot {
                meta,
                backend: captured,
                retirement,
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
        Ok(Box::new(
            SnapshotBuffer::new(self.store.scratch_disk(), self.limits.max_snapshot_bytes)
                .map_err(err)?,
        ))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<SnapshotBuffer>,
    ) -> Result<(), StorageError<u64>> {
        let gate = self.snapshot_gate.clone().lock_owned().await;
        if snapshot.len() > self.limits.max_snapshot_bytes {
            return Err(err("snapshot exceeds byte limit"));
        }
        let meta = meta.clone();
        let machine = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _gate = gate;
            // Parsing stages bounded records into encrypted scratch. Keep disk,
            // crypto, validation and materialization off the async runtime.
            let snapshot = snapshot.into_image()?;
            let envelope = SnapshotEnvelope::decode(
                snapshot.disk(),
                &mut snapshot.reader(),
                machine.limits.max_snapshot_bytes,
            )?;
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
            if envelope.kind == SnapshotKind::Custody {
                ensure!(
                    envelope.backend.is_empty(),
                    "custody snapshot contains application payload"
                );
                envelope
                    .retirement
                    .as_ref()
                    .context("custody snapshot retirement absent")?
                    .validate(&meta)?;
                let _control = machine
                    .control_gate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))?;
                // A serving engine must stop releasing plaintext before the
                // closed retirement boundary becomes visible. Recovery then
                // opens the same group using custody storage only.
                machine.failed.store(true, Ordering::Release);
                machine.backend.close_application();
                crate::custody_machine::publish(
                    machine.domains.custody(),
                    &envelope,
                    machine.limits.max_snapshot_bytes,
                )?;
                state.log_id = envelope.meta.last_log_id;
                state.membership = envelope.meta.last_membership;
                return Ok(());
            }
            let prepared = machine.backend.prepare_restore(&mut envelope.backend.reader())?;
            crate::snapshot_custody::check_backend(&meta, envelope.retirement.as_ref(), prepared.retirement())?;
            // Durably install encrypted chunks and their manifest, then atomically publish backend state.
            // A crash between these steps recovers the new snapshot on restart.
            let pending = stage_snapshot(
                &machine.domains,
                &snapshot,
                machine.limits.max_snapshot_bytes,
                &envelope,
            )?;
            {
                let _control = machine
                    .control_gate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))?;
                publish_snapshot(&machine.domains, pending, &envelope, Some(prepared.as_ref()))?;
            }
            cleanup_snapshots(&machine.store, machine.limits.max_snapshot_bytes)?;
            prepared.publish()?;
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
        let domains = self.domains.clone();
        let limit = self.limits.max_snapshot_bytes;
        tokio::task::spawn_blocking(move || {
            domains.check_access()?;
            let result = load_snapshot(&store, limit)?
                .map(|snapshot| {
                    validate_snapshot_coverage(&domains, &snapshot, limit)?;
                    as_snapshot(&snapshot, limit)
                })
                .transpose()?;
            domains.check_access()?;
            Ok::<_, anyhow::Error>(result)
        })
        .await
        .map_err(err)?
        .map_err(err)
    }
}

#[cfg(test)]
mod tests;
