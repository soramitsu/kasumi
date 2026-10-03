use crate::Entry;
use crate::command::sha256;
use crate::control::{AppliedEntryContext, HEADERS, HeaderPayload, LogHeader, RetainedSeed, SEEDS};
use crate::lifetime::{StorageHandle, StorageLease};
use crate::{
    BasicNode, RaftLimits, SnapshotBuffer, SnapshotBufferOwner, StateMachineBackend, TypeConfig,
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedSpool, SnapshotImage};
use kasumi_store::{TenantStorageSet, TenantStore, WriteOp};
use openraft::{
    EntryPayload, LogId, LogState, OptionalSend, RaftLogReader, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    ops::RangeBounds,
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

#[path = "storage/retained_logs.rs"]
pub(crate) mod retained_logs;
use retained_logs::{EntryBatches, RetainedSpan, read_header, retained_span};

const LOG: &str = "raft.log";
pub(crate) const CUSTODY_LOG: &str = "raft.custody-log";
const LOG_FORMAT: &[u8] = b"kasumi-log\x01";
const META: &str = "raft.meta";
const SNAPSHOT: &str = "raft.snapshot";
// Store records are capped at 32 MiB. Snapshots have a separate, much larger
// tenant limit and must be installed through bounded encrypted chunks.
const SNAPSHOT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
// A coverage record must fit the same bounded control read on every path.
pub(crate) const MAX_SNAPSHOT_COVERAGE_BYTES: usize = 2 << 20;

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
fn load<T: DeserializeOwned + Serialize>(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
) -> Result<Option<T>> {
    store
        .get(namespace, key)?
        .map(|bytes| {
            crate::control::decode_canonical(&bytes).context("invalid raft storage record")
        })
        .transpose()
}

/// Snapshot metadata has exactly one first-release writer encoding. Neither
/// discarded fields nor alternate JSON spellings may enter restore or cleanup.
fn load_canonical_snapshot_record<T: DeserializeOwned + Serialize>(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
) -> Result<Option<T>> {
    let Some(bytes) = store.get_bounded(namespace, key, MAX_SNAPSHOT_COVERAGE_BYTES)? else {
        return Ok(None);
    };
    decode_snapshot_record_admitted(&bytes, |_| Ok(())).map(Some)
}

pub(crate) fn decode_snapshot_record_admitted<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    before_encode: impl FnOnce(&T) -> Result<()>,
) -> Result<T> {
    let record: T = serde_json::from_slice(bytes).context("invalid raft snapshot record")?;
    before_encode(&record)?;
    ensure!(
        serde_json::to_vec(&record)? == bytes,
        "noncanonical raft snapshot record"
    );
    Ok(record)
}

/// Every production snapshot writer generates a random RFC UUID and writes its
/// lower-case hyphenated form. Parseable aliases are not persisted identities.
pub(crate) fn current_snapshot_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.to_string() == value
            && id.get_version() == Some(uuid::Version::Random)
            && id.get_variant() == uuid::Variant::RFC4122
    })
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
    // Only the two retained endpoints are resident. Authenticated headers remain
    // authoritative; requested IDs are loaded by exact index from disk.
    retained: Arc<Mutex<Option<RetainedSpan>>>,
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
        let retained = tokio::task::spawn_blocking(move || -> Result<Option<RetainedSpan>> {
            let saved = load::<u64>(&captured, META, b"node_id")?
                .context("persisted raft node identity is missing")?;
            ensure!(
                saved == node_id,
                "persisted raft node identity differs from configuration"
            );
            // HMAC order is unrelated to log order. Fold authenticated unique
            // keys into a checked span without collecting or sorting headers.
            retained_span(&captured)
        })
        .await??;
        Ok(Self {
            store,
            domains,
            io_gate: Arc::new(tokio::sync::Mutex::new(())),
            control_gate,
            retained: Arc::new(Mutex::new(retained)),
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
            let saved = load::<String>(store, META, b"group")?
                .context("persisted raft group identity is missing")?;
            ensure!(
                saved == group,
                "persisted raft group identity differs from configuration"
            );
            Ok(())
        })
        .await
    }
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

impl LogStore {
    async fn read_entries(
        &self,
        bounds: (std::ops::Bound<u64>, std::ops::Bound<u64>),
        mut batch: Option<retained_logs::ReadBatch>,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let retained = self.retained.clone();
        let domains = self.domains.clone();
        self.read(move |store| {
            let span = *retained
                .lock()
                .map_err(|_| anyhow::anyhow!("raft retained span lock poisoned"))?;
            let Some(range) = span.and_then(|span| span.intersect(bounds)) else {
                ensure!(batch.is_none(), "requested raft read prefix is unavailable");
                return Ok(Vec::new());
            };
            if batch.is_some() {
                ensure!(
                    bounds.0 == std::ops::Bound::Included(*range.start()),
                    "requested raft read prefix is unavailable"
                );
            }
            // Exact reads retain the complete requested EntryVec. Limited reads
            // retain one prefix, plus at most one authenticated encoded candidate
            // before deciding whether its decoded entry belongs in this batch.
            let mut entries = Vec::new();
            for index in range {
                if batch.as_ref().is_some_and(retained_logs::ReadBatch::full) {
                    break;
                }
                let header = read_header(store, index)?;
                if let Some(span) = span {
                    span.check_endpoint(header.log_id)?;
                }
                let metadata = match &header.payload {
                    HeaderPayload::Blank => Some(Entry {
                        initialization: None,
                        log_id: header.log_id,
                        payload: EntryPayload::Blank,
                    }),
                    HeaderPayload::Membership(membership) => Some(Entry {
                        initialization: header.initialization.clone(),
                        log_id: header.log_id,
                        payload: EntryPayload::Membership(membership.clone()),
                    }),
                    _ => None,
                };
                let encoded = match &metadata {
                    Some(entry) => encode_entry(entry)?,
                    None if matches!(header.payload, HeaderPayload::Custody { .. }) => store
                        .get(CUSTODY_LOG, &index.to_be_bytes())?
                        .context("missing closed custody raft body")?,
                    None => domains
                        .application()?
                        .get(LOG, &index.to_be_bytes())?
                        .context("missing application raft body")?,
                };
                if let Some(batch) = &mut batch
                    && !batch.admit(encoded.len())?
                {
                    break;
                }
                let entry = match metadata {
                    Some(entry) => entry,
                    None => decode_entry(&encoded)?,
                };
                header.check_entry(&entry, &encoded)?;
                entries.push(entry);
            }
            Ok(entries)
        })
        .await
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        self.read_entries(
            (range.start_bound().cloned(), range.end_bound().cloned()),
            None,
        )
        .await
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        if start >= end {
            return Ok(Vec::new());
        }
        self.read_entries(
            (
                std::ops::Bound::Included(start),
                std::ops::Bound::Excluded(end),
            ),
            Some(retained_logs::ReadBatch::default()),
        )
        .await
    }
}

/// Opt-in observation of the actual vote write; no error text or storage name.
/// Queue time includes the original I/O gate, blocking dispatch and control gate.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy)]
struct VoteSaveObservation {
    started: std::time::Instant,
    owner: usize,
    term: u64,
    leader: u64,
}
#[cfg(any(test, feature = "test-utils"))]
impl VoteSaveObservation {
    fn start(store: &TenantStore, vote: &Vote<u64>) -> Option<Self> {
        if std::env::var_os("KASUMI_TEST_REPLICA_TRACE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return None;
        }
        let trace = Self {
            started: std::time::Instant::now(),
            // Process-local correlation only, never a protocol/storage identity.
            owner: store as *const TenantStore as usize,
            term: vote.leader_id.term,
            leader: vote.leader_id.node_id,
        };
        Self::emit(Some(trace), "submitted", None);
        Some(trace)
    }
    fn emit(trace: Option<Self>, phase: &'static str, succeeded: Option<bool>) {
        let Some(trace) = trace else {
            return;
        };
        // Ignore diagnostic-output failure; persistence retains its exact result.
        let _ = writeln!(
            std::io::stderr().lock(),
            "raft_vote_save phase={phase} owner={} term={} leader={} elapsed_ms={} succeeded={succeeded:?}",
            trace.owner,
            trace.term,
            trace.leader,
            trace.started.elapsed().as_millis(),
        );
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let retained = self.retained.clone();
        self.read(move |store| {
            let last_purged_log_id = load(store, META, b"purged")?;
            let last_log_id = retained
                .lock()
                .map_err(|_| anyhow::anyhow!("raft retained span lock poisoned"))?
                .map(|span| span.last)
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
        #[cfg(any(test, feature = "test-utils"))]
        let trace = VoteSaveObservation::start(&self.store, vote);
        let result = self
            .mutate(move |store| {
                #[cfg(any(test, feature = "test-utils"))]
                VoteSaveObservation::emit(trace, "write_entered", None);
                let result = store.write_batch(&[put(META, b"vote", bytes)]);
                #[cfg(any(test, feature = "test-utils"))]
                VoteSaveObservation::emit(trace, "write_returned", Some(result.is_ok()));
                result
            })
            .await;
        #[cfg(any(test, feature = "test-utils"))]
        VoteSaveObservation::emit(trace, "wait_returned", Some(result.is_ok()));
        result
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
                crate::initialization_association::validate_entry(self.domains.custody(), entry)?;
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
        let retained = self.retained.clone();
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
                let mut retained = retained
                    .lock()
                    .map_err(|_| anyhow::anyhow!("raft retained span lock poisoned"))?;
                let mut batches = EntryBatches::new(*retained, &entries)?;
                // Commit the overlap/suffix forward, then a prepended prefix
                // backward. Every durable chunk remains contiguous after crash,
                // including physical logs repopulated below a snapshot.
                while let Some(range) = batches.next_range(&writes)? {
                    let mut data = Vec::new();
                    let mut control = Vec::new();
                    for (application, custody) in &writes[range.clone()] {
                        data.extend(application.iter().cloned());
                        control.extend(custody.iter().cloned());
                    }
                    let next = RetainedSpan::including(*retained, &entries[range])?;
                    domains.write_batch(&data, &control)?;
                    *retained = Some(next);
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
        let retained = self.retained.clone();
        let domains = self.domains.clone();
        self.mutate(move |store| {
            let mut retained = retained
                .lock()
                .map_err(|_| anyhow::anyhow!("raft retained span lock poisoned"))?;
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
            while let Some(span) = *retained {
                if span.last.index < log_id.index {
                    break;
                }
                let end = span.last.index;
                let start = end
                    .saturating_sub(16383)
                    .max(log_id.index)
                    .max(span.first.index);
                // Observe the exact new endpoint before publishing any deletion.
                let next = if start == span.first.index {
                    None
                } else {
                    Some(RetainedSpan {
                        first: span.first,
                        last: read_header(store, start - 1)?.log_id,
                    })
                };
                let writes = if domains.serving().is_some() {
                    (start..=end)
                        .rev()
                        .map(|index| delete(LOG, index.to_be_bytes().to_vec()))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let control = (start..=end)
                    .rev()
                    .flat_map(|index| {
                        [
                            delete(HEADERS, index.to_be_bytes().to_vec()),
                            delete(CUSTODY_LOG, index.to_be_bytes().to_vec()),
                        ]
                        .into_iter()
                        .chain(
                            (Some(index) != protected)
                                .then(|| delete(SEEDS, index.to_be_bytes().to_vec())),
                        )
                    })
                    .collect::<Vec<_>>();
                domains.write_batch(&writes, &control)?;
                *retained = next;
            }
            Ok(())
        })
        .await
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let retained = self.retained.clone();
        let domains = self.domains.clone();
        self.mutate(move |store| {
            let mut retained = retained
                .lock()
                .map_err(|_| anyhow::anyhow!("raft retained span lock poisoned"))?;
            let first = crate::control::first_applied_membership(domains.custody().store())?;
            crate::control::local_first_association_write(domains.custody(), first.as_ref(), None)?;
            crate::initialization_association::load_state(domains.custody(), first.as_ref())?;
            let retired = crate::control::retired_boundary(domains.custody())?.is_some();
            let mut last_removed = None;
            // Each fixed-size prefix and its exact purge cursor commit together.
            while let Some(span) = *retained {
                if span.first.index > log_id.index {
                    break;
                }
                let start = span.first.index;
                let end = start
                    .saturating_add(21844)
                    .min(log_id.index)
                    .min(span.last.index);
                let purged = read_header(store, end)?.log_id;
                span.check_endpoint(purged)?;
                let next = if end == span.last.index {
                    None
                } else {
                    Some(RetainedSpan {
                        first: read_header(store, end + 1)?.log_id,
                        last: span.last,
                    })
                };
                let mut writes = (start..=end)
                    .flat_map(|index| {
                        [
                            delete(HEADERS, index.to_be_bytes().to_vec()),
                            delete(CUSTODY_LOG, index.to_be_bytes().to_vec()),
                        ]
                    })
                    .collect::<Vec<_>>();
                writes.push(put(META, b"purged", serde_json::to_vec(&purged)?));
                if retired {
                    store.write_batch(&writes)?;
                } else {
                    let bodies = (start..=end)
                        .map(|index| delete(LOG, index.to_be_bytes().to_vec()))
                        .collect::<Vec<_>>();
                    domains.write_batch(&bodies, &writes)?;
                }
                *retained = next;
                last_removed = Some(purged);
            }
            if last_removed != Some(log_id) {
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
    pub(crate) first_membership: Option<crate::control::FirstAppliedMembership>,
    pub(crate) initialization_association:
        Option<crate::initialization_association::AssociationState>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotManifest {
    pub(crate) version: u32,
    pub(crate) sha256: String,
    pub(crate) id: String,
    pub(crate) bytes: u64,
    pub(crate) chunks: u64,
}

fn chunk_key(manifest: &SnapshotManifest, chunk: u64) -> Vec<u8> {
    let mut key = manifest.id.as_bytes().to_vec();
    key.push(b'/');
    key.extend_from_slice(&chunk.to_be_bytes());
    key
}

fn load_manifest(store: &TenantStore, key: &[u8], limit: u64) -> Result<Option<SnapshotManifest>> {
    let manifest = load_canonical_snapshot_record::<SnapshotManifest>(store, SNAPSHOT, key)?;
    if let Some(manifest) = &manifest {
        validate_snapshot_manifest(manifest, limit)?;
    }
    Ok(manifest)
}

pub(crate) fn validate_snapshot_manifest(manifest: &SnapshotManifest, limit: u64) -> Result<()> {
    kasumi_types::validate_sha256(&manifest.sha256)?;
    ensure!(
        manifest.version == 1 && current_snapshot_id(&manifest.id),
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
    Ok(())
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

pub(crate) fn encode_snapshot_coverage(coverage: &SnapshotCoverage) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(coverage)?;
    ensure!(
        bytes.len() <= MAX_SNAPSHOT_COVERAGE_BYTES,
        "snapshot coverage exceeds byte limit"
    );
    Ok(bytes)
}

pub(crate) fn load_snapshot_coverage(store: &TenantStore) -> Result<Option<SnapshotCoverage>> {
    load_snapshot_coverage_at(&mut &*store)
}

pub(crate) fn load_snapshot_coverage_at(
    reads: &mut impl crate::control::CustodyRead,
) -> Result<Option<SnapshotCoverage>> {
    reads.with_point(
        META,
        b"snapshot_coverage",
        MAX_SNAPSHOT_COVERAGE_BYTES,
        |bytes| {
            let coverage = bytes
                .map(|bytes| decode_snapshot_record_admitted::<SnapshotCoverage>(bytes, |_| Ok(())))
                .transpose()?;
            if let Some(coverage) = &coverage {
                validate_snapshot_coverage_record(coverage)?;
            }
            Ok(coverage)
        },
    )
}

pub(crate) fn validate_snapshot_coverage_record(coverage: &SnapshotCoverage) -> Result<()> {
    ensure!(
        current_snapshot_id(&coverage.manifest_id)
            && current_snapshot_id(&coverage.meta.snapshot_id),
        "invalid snapshot coverage identity"
    );
    kasumi_types::validate_sha256(&coverage.snapshot_sha256)?;
    kasumi_types::validate_sha256(&coverage.backend_sha256)?;
    Ok(())
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
    let coverage = load_snapshot_coverage(domains.custody().store())?
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
        snapshot.first_membership.as_ref(),
        snapshot.initialization_association.as_ref(),
    )?;
    Ok(())
}

/// A historical target read cannot treat a custody cursor as a complete
/// snapshot proof. Read the bounded published image and match its manifest,
/// control coverage, portable first fact and any snapshot applied cursor.
pub(crate) fn validate_target_history_snapshot(
    domains: &TenantStorageSet,
    first: &crate::control::FirstAppliedMembership,
    applied: &crate::control::AppliedCursor,
) -> Result<()> {
    let custody = domains.custody().store();
    let limit = RaftLimits::default().max_snapshot_bytes;
    let coverage = load_snapshot_coverage(custody)?;
    let snapshot = load_snapshot(domains.application(), limit)?;
    match (coverage, snapshot) {
        (None, None) => {
            ensure!(
                !matches!(applied, crate::control::AppliedCursor::Snapshot { .. }),
                "target snapshot applied cursor lacks published image"
            );
            Ok(())
        }
        (Some(coverage), Some(snapshot)) => {
            ensure!(
                coverage.kind == SnapshotKind::Application,
                "target history snapshot has another kind"
            );
            validate_snapshot_coverage(domains, &snapshot, limit)?;
            if snapshot
                .meta
                .last_log_id
                .is_some_and(|id| id >= first.header.log_id)
            {
                ensure!(
                    snapshot.first_membership.as_ref() == Some(first),
                    "target history snapshot lost exact first membership"
                );
            }
            if let crate::control::AppliedCursor::Snapshot {
                meta,
                backend_sha256,
                snapshot_sha256,
            } = applied
            {
                ensure!(
                    meta == &coverage.meta
                        && backend_sha256 == &coverage.backend_sha256
                        && snapshot_sha256 == &coverage.snapshot_sha256,
                    "target applied snapshot differs from published coverage"
                );
            }
            Ok(())
        }
        _ => anyhow::bail!("target snapshot manifest or control coverage absent"),
    }
}

struct PendingSnapshot {
    application: Vec<WriteOp>,
    coverage: SnapshotCoverage,
    coverage_bytes: Vec<u8>,
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
    // All application publication paths pass through this function. Refuse a
    // deterministic projection overflow before cleanup or pending chunk writes.
    crate::snapshot_custody::preflight_projection(
        meta,
        snapshot.retirement.as_ref(),
        bytes.sha256(),
    )?;
    let manifest = SnapshotManifest {
        version: 1,
        sha256: bytes.sha256().to_owned(),
        id: uuid::Uuid::new_v4().to_string(),
        bytes: bytes.len(),
        chunks: bytes.len().div_ceil(SNAPSHOT_CHUNK_BYTES as u64),
    };
    let coverage = SnapshotCoverage {
        kind: SnapshotKind::Application,
        manifest_id: manifest.id.clone(),
        snapshot_sha256: manifest.sha256.clone(),
        backend_sha256: snapshot.backend.sha256().to_owned(),
        meta: meta.clone(),
    };
    // Reject before cleanup or the first pending/chunk write; the prior
    // snapshot remains intact when current-format coverage is too large.
    let coverage_bytes = encode_snapshot_coverage(&coverage)?;
    cleanup_snapshots(store, limit)?;
    let previous = load_manifest(store, b"current", limit)?;
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
    Ok(PendingSnapshot {
        application: install,
        coverage,
        coverage_bytes,
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
    let coverage_bytes = pending.coverage_bytes;
    let mut custody = crate::snapshot_custody::installation_writes(
        domains.custody(),
        &snapshot.meta,
        snapshot.retirement.as_ref(),
        snapshot.first_membership.as_ref(),
        snapshot.initialization_association.as_ref(),
        &coverage.backend_sha256,
        &coverage.snapshot_sha256,
    )?;
    custody
        .writes
        .push(put(META, b"snapshot_coverage", coverage_bytes));
    let replacements = custody.records.as_ref().map(|records| {
        records.namespaces().map(|(namespace, table)| {
            kasumi_store::NamespaceReplacement::from_table(namespace, table)
        })
    });
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

/// Lives inside actual blocking work, not its cancellable async waiter. Failure
/// or unwinding must close serving even if nobody remains to receive the result.
/// Drop only publishes an atomic fence: storage drain and teardown happen later.
struct StorageWorkFailure {
    failed: Arc<AtomicBool>,
    complete: bool,
}
impl StorageWorkFailure {
    fn new(failed: Arc<AtomicBool>) -> Self {
        Self {
            failed,
            complete: false,
        }
    }
    fn complete(mut self) {
        self.complete = true;
    }
}
impl Drop for StorageWorkFailure {
    fn drop(&mut self) {
        if !self.complete {
            self.failed.store(true, Ordering::Release);
        }
    }
}

// Returning the preadmitted diagnostic from a detached worker only clones its
// two handles. In particular, it does not allocate another anyhow error box.
enum ApplyWorkerError {
    Retained(crate::apply_failure::RetainedApplyFailure),
    Fenced,
}
impl std::fmt::Display for ApplyWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained(failure) => std::fmt::Display::fmt(failure, f),
            Self::Fenced => f.write_str("state machine requires recovery"),
        }
    }
}

#[derive(Clone)]
pub struct StateMachine {
    domains: StorageHandle<TenantStorageSet>,
    store: StorageHandle<TenantStore>,
    backend: StorageHandle<dyn StateMachineBackend>,
    state: Arc<Mutex<AppliedState>>,
    snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    snapshot_buffers: Arc<SnapshotBufferOwner>,
    control_gate: Arc<Mutex<()>>,
    failed: Arc<AtomicBool>,
    limits: RaftLimits,
}

impl StateMachine {
    pub async fn open(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        Self::open_with_limits(domains, backend, RaftLimits::default(), snapshot_buffers).await
    }

    pub async fn open_with_limits(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        Self::open_inner(domains, backend, limits, None, snapshot_buffers).await
    }

    pub(crate) async fn open_tracked(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Arc<StorageLease>,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        Self::open_inner(domains, backend, limits, Some(lease), snapshot_buffers).await
    }

    async fn open_inner(
        domains: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        limits: RaftLimits,
        lease: Option<Arc<StorageLease>>,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
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
            let first =
                crate::control::first_applied_membership(captured_domains.custody().store())?;
            crate::control::local_first_association_write(
                captured_domains.custody(),
                first.as_ref(),
                None,
            )?;
            crate::initialization_association::load_state(
                captured_domains.custody(),
                first.as_ref(),
            )?;
            cleanup_snapshots(&captured, limit)?;
            if let Some(snapshot) = load_snapshot(&captured, limit)? {
                validate_snapshot_coverage(&captured_domains, &snapshot, limit)?;
                ensure!(snapshot.version == 2, "unsupported raft snapshot version");
                let context = crate::SnapshotRestoreContext {
                    mode: crate::SnapshotRestoreMode::Reopen,
                    backend_sha256: snapshot.backend.sha256().into(),
                    meta: snapshot.meta.clone(),
                };
                let prepared = target.prepare_restore(&context, &mut snapshot.backend.reader())?;
                crate::snapshot_custody::check_backend(
                    &snapshot.meta,
                    snapshot.retirement.as_ref(),
                    prepared.retirement(),
                )?;
                captured_domains.write_batch_replacing(
                    prepared.application_writes(),
                    &[],
                    &prepared.application_replacements(),
                    &[],
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
            snapshot_buffers,
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
    first_membership: Option<crate::control::FirstAppliedMembership>,
    initialization_association: Option<crate::initialization_association::AssociationState>,
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

pub(crate) fn as_snapshot(
    snapshot: &SnapshotEnvelope,
    limit: u64,
    snapshot_buffers: &Arc<SnapshotBufferOwner>,
) -> Result<Snapshot<TypeConfig>> {
    Ok(Snapshot {
        meta: snapshot.meta.clone(),
        snapshot: Box::new(SnapshotBuffer::from_image(
            snapshot.encode(limit)?,
            snapshot_buffers,
        )?),
    })
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let gate = self.machine.snapshot_gate.clone().lock_owned().await;
        let captured = self.captured.as_ref().map_err(err)?.clone();
        let domains = self.machine.domains.clone();
        let store = self.machine.store.clone();
        let limit = self.machine.limits.max_snapshot_bytes;
        let snapshot_buffers = self.machine.snapshot_buffers.clone();
        let applied = self.machine.state.clone();
        let control = self.machine.control_gate.clone();
        let failed = self.machine.failure_flag();
        tokio::task::spawn_blocking(move || -> Result<Snapshot<TypeConfig>> {
            let failure = StorageWorkFailure::new(failed.clone());
            let _gate = gate;
            ensure!(
                !failed.load(Ordering::Acquire),
                "state machine requires recovery"
            );
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
                let snapshot = as_snapshot(&current, limit, &snapshot_buffers)?;
                failure.complete();
                return Ok(snapshot);
            }
            let logical = captured;
            let captured = SnapshotEnvelope {
                version: 2,
                kind: SnapshotKind::Application,
                meta: logical.meta.clone(),
                backend: SnapshotImage::capture(store.scratch_disk(), limit, |writer| {
                    logical.backend.write(writer)
                })?,
                retirement: logical.retirement.clone(),
                first_membership: logical.first_membership.clone(),
                initialization_association: logical.initialization_association.clone(),
            };
            let snapshot = as_snapshot(&captured, limit, &snapshot_buffers)?;
            let mut pending =
                stage_snapshot(&domains, &snapshot.snapshot.image()?, limit, &captured)?;
            pending
                .application
                .extend(
                    logical
                        .backend
                        .checkpoint_writes(&crate::SnapshotRestoreContext {
                            mode: crate::SnapshotRestoreMode::Install,
                            backend_sha256: captured.backend.sha256().into(),
                            meta: captured.meta.clone(),
                        })?,
                );
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
            failure.complete();
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
        tokio::task::spawn_blocking(
            move || -> std::result::Result<Vec<Vec<u8>>, ApplyWorkerError> {
                // Recheck the terminal fence only after serialization. A queued
                // worker must not create a second independent failure owner.
                let (mut state, poisoned) = match machine.state.lock() {
                    Ok(state) => (state, false),
                    Err(poisoned) => (poisoned.into_inner(), true),
                };
                if let Some(failure) = machine.snapshot_buffers.apply_failure() {
                    return Err(ApplyWorkerError::Retained(failure));
                }
                if machine.failed() {
                    return Err(ApplyWorkerError::Fenced);
                }
                let failure = StorageWorkFailure::new(machine.failure_flag());
                let outcome = (|| -> Result<std::result::Result<Vec<Vec<u8>>,crate::apply_failure::RetainedApplyFailure>> {
                    ensure!(!poisoned, "state machine lock poisoned");
                    machine.snapshot_buffers.check()?;
                    machine.domains.check_access()?;
                    let mut responses = Vec::with_capacity(entries.len());
                    for entry in entries {
                        machine.domains.check_access()?;
                        let (command_sha256, retirement_seed) = match &entry.payload {
                            EntryPayload::Normal(command) => {
                                (sha256(command.bytes()), command.seed()?)
                            }
                            _ => (sha256(&encode_entry(&entry)?), None),
                        };
                        let membership = match &entry.payload {
                            EntryPayload::Membership(membership) => {
                                StoredMembership::new(Some(entry.log_id), membership.clone())
                            }
                            _ => state.membership.clone(),
                        };
                        let position = AppliedEntryContext {
                            log_id: entry.log_id,
                            previous: state.log_id,
                            membership,
                            command_sha256,
                            retirement_seed,
                        };
                        let input = match &entry.payload {
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
                                crate::AppliedInput::Command(command.bytes())
                            }
                            _ => crate::AppliedInput::Metadata,
                        };
                        let metadata = matches!(input, crate::AppliedInput::Metadata);
                        let retired_metadata = metadata
                            && crate::control::retired_boundary(machine.domains.custody())?
                                .is_some();
                        let mut sink = crate::apply_publication::EntryPublicationSink::new(
                            &machine.domains,
                            &position,
                            Some(&machine.control_gate),
                            metadata,
                        );
                        // Keep the publisher and its original failure outside the
                        // catcher. A backend may panic after a failed callback.
                        let mut publication =
                            crate::apply_publication::ApplyPublication::new_bound(
                                &mut sink, machine.snapshot_buffers.apply_slot(),
                            );
                        let backend =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                if retired_metadata {
                                    crate::ApplyPublisher::commit(
                                        &mut publication,
                                        crate::AppliedResponse::application(Vec::new()),
                                        &[],
                                    )?;
                                    Ok(())
                                } else {
                                    machine.backend.apply_with_publisher(
                                        &position,
                                        input,
                                        &mut publication,
                                    )
                                }
                            }));
                        let finished=match publication.finish_observed(backend,||{}) {
                            Ok(finished)=>finished,
                            Err(crate::apply_publication::FinishFailure::Single(error))=>return Err(error),
                            Err(crate::apply_publication::FinishFailure::Retained(failure))=>return Ok(Err(failure)),
                        };
                        let crate::apply_publication::FinishedPublication{response,acknowledgment}=finished;
                        // Backend preparation/guard has been released only after
                        // successful joint publication. Failed metadata cannot
                        // advance either this membership or its cursor.
                        state.membership = position.membership;
                        state.log_id = Some(entry.log_id);
                        responses.push(response.data);
                        crate::apply_publication::acknowledge_publication(acknowledgment);
                    }
                    Ok(Ok(responses))
                })();
                match outcome {
                    Ok(Err(retained))=>{machine.failed.store(true,Ordering::Release);Err(ApplyWorkerError::Retained(retained))},
                    Ok(Ok(responses)) => {
                        failure.complete();
                        Ok(responses)
                    }
                    Err(error) => {
                        machine.failed.store(true, Ordering::Release);
                        Err(ApplyWorkerError::Retained(
                            machine.snapshot_buffers.retain_apply_failure(error),
                        ))
                    }
                }
            },
        )
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
            let first_membership =
                crate::control::first_membership_for_snapshot(machine.domains.custody(), &meta)?;
            Ok(LogicalSnapshot {
                meta,
                backend: captured,
                retirement,
                initialization_association: crate::initialization_association::load_state(
                    machine.domains.custody(),
                    first_membership.as_ref(),
                )?,
                first_membership,
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
            SnapshotBuffer::new(
                self.store.scratch_disk(),
                self.limits.max_snapshot_bytes,
                &self.snapshot_buffers,
            )
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
            let failure = StorageWorkFailure::new(machine.failure_flag());
            let _gate = gate;
            ensure!(!machine.failed(), "state machine requires recovery");
            // Parsing stages bounded records into encrypted scratch. Keep disk,
            // crypto, validation and materialization off the async runtime.
            let snapshot = snapshot.into_image()?;
            let envelope = SnapshotEnvelope::decode(
                snapshot.disk(),
                &mut snapshot.reader(),
                machine.limits.max_snapshot_bytes,
            )?;
            ensure!(
                envelope.version == 2 && envelope.meta == meta,
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
                failure.complete();
                return Ok(());
            }
            let context = crate::SnapshotRestoreContext {
                mode: crate::SnapshotRestoreMode::Install,
                backend_sha256: envelope.backend.sha256().into(),
                meta: envelope.meta.clone(),
            };
            let prepared = machine
                .backend
                .prepare_restore(&context, &mut envelope.backend.reader())?;
            crate::snapshot_custody::check_backend(
                &meta,
                envelope.retirement.as_ref(),
                prepared.retirement(),
            )?;
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
                publish_snapshot(
                    &machine.domains,
                    pending,
                    &envelope,
                    Some(prepared.as_ref()),
                )?;
            }
            cleanup_snapshots(&machine.store, machine.limits.max_snapshot_bytes)?;
            prepared.publish()?;
            state.log_id = envelope.meta.last_log_id;
            state.membership = envelope.meta.last_membership;
            failure.complete();
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
        let snapshot_buffers = self.snapshot_buffers.clone();
        tokio::task::spawn_blocking(move || {
            domains.check_access()?;
            let result = load_snapshot(&store, limit)?
                .map(|snapshot| {
                    validate_snapshot_coverage(&domains, &snapshot, limit)?;
                    as_snapshot(&snapshot, limit, &snapshot_buffers)
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
