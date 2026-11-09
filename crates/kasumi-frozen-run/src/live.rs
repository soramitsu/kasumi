//! Exclusively owned, mutable ordered storage with a durable WAL and immutable
//! tiered checkpoints. Every on-disk namespace operation uses the locked directory fd.
use crate::{
    WalOp, invalid,
    live_files::{Files, MANIFEST},
    live_levels::{self, Level},
    live_merge::Delta,
    live_wal::{Wal, sync_durable, validate_wal_batch, wal_header},
};
use arrayvec::ArrayVec;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, ErrorKind, Read},
    ops::Bound,
    path::Path,
};

/// Minimum write-buffer budget, also used by legacy v2 databases.
pub const LIVE_CHECKPOINT_BYTES: u64 = 512 << 10;
/// Default buffer budget for new databases. Each acknowledgement still syncs the WAL.
pub const LIVE_DEFAULT_BUFFER_BYTES: u64 = 4 << 20;
pub(super) fn valid_budget(n: u64) -> bool {
    (LIVE_CHECKPOINT_BYTES..=16 << 20).contains(&n)
}
/// Maximum independently sequenced blocks sharing one WAL synchronization.
pub const LIVE_GROUP_MAX_BATCHES: usize = 64;
/// Maximum aggregate conservative delta charge for a multi-block group.
pub const LIVE_GROUP_MAX_BYTES: u64 = 512 << 10;

#[path = "live_group.rs"]
mod group;

#[path = "live_bulk.rs"]
mod bulk;

const MAGIC: &[u8; 8] = b"KSLIVE02";
const BUDGET_MAGIC: &[u8; 8] = b"KSLIVE03";
const MAX_LEVELS: usize = 64;
const BULK_TIER: u8 = (MAX_LEVELS - 1) as u8;
const HEADER_BYTES: usize = 40;
const ENTRY_BYTES: usize = 48;

#[derive(Clone)]
struct Entry {
    tier: u8,
    sequence: u64,
    root: [u8; 32],
}
impl Entry {
    fn name(&self, id: &[u8; 16]) -> String {
        Files::name(id, &format!("run-{}-{}", self.sequence, self.tier))
    }
}
#[derive(Clone)]
struct Head {
    budget: Option<u64>,
    id: [u8; 16],
    seq: u64,
    entries: Vec<Entry>,
}
impl Head {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES + ENTRY_BYTES * self.entries.len() + 32);
        bytes.extend(if self.budget.is_some() {
            BUDGET_MAGIC
        } else {
            MAGIC
        });
        bytes.extend((self.entries.len() as u64).to_le_bytes());
        bytes.extend(self.seq.to_le_bytes());
        bytes.extend(self.id);
        if let Some(budget) = self.budget {
            bytes.extend(budget.to_le_bytes());
        }
        for entry in &self.entries {
            bytes.extend(u64::from(entry.tier).to_le_bytes());
            bytes.extend(entry.sequence.to_le_bytes());
            bytes.extend(entry.root);
        }
        bytes.extend(Sha256::digest(&bytes));
        bytes
    }
    fn read(files: &Files) -> io::Result<Self> {
        let mut file = files.read(MANIFEST)?;
        let len = file.metadata()?.len();
        if !((HEADER_BYTES + 32) as u64..=(HEADER_BYTES + 8 + ENTRY_BYTES * MAX_LEVELS + 32) as u64)
            .contains(&len)
        {
            return Err(invalid("invalid live manifest length"));
        }
        let mut bytes = vec![0; len as usize];
        file.read_exact(&mut bytes)?;
        let split = bytes.len() - 32;
        let (body, digest) = bytes.split_at(split);
        if Sha256::digest(body)[..] != *digest {
            return Err(invalid("invalid live manifest"));
        }
        let (budget, header) = match &body[..8] {
            magic if magic == MAGIC => (None, HEADER_BYTES),
            magic if magic == BUDGET_MAGIC && body.len() >= HEADER_BYTES + 8 => {
                let n = u64::from_le_bytes(body[40..48].try_into().unwrap());
                if !valid_budget(n) {
                    return Err(invalid("invalid live write buffer budget"));
                }
                (Some(n), HEADER_BYTES + 8)
            }
            _ => return Err(invalid("invalid live manifest version")),
        };
        let count = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let seq = u64::from_le_bytes(body[16..24].try_into().unwrap());
        let id = body[24..40].try_into().unwrap();
        if count > MAX_LEVELS as u64
            || body.len() != header + ENTRY_BYTES * count as usize
            || (count == 0) != (seq == 0)
            || uuid::Uuid::from_bytes(id).get_version_num() != 4
        {
            return Err(invalid("invalid live manifest fields"));
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(count as usize);
        for record in body[header..].chunks_exact(ENTRY_BYTES) {
            let tier = u64::from_le_bytes(record[..8].try_into().unwrap());
            let sequence = u64::from_le_bytes(record[8..16].try_into().unwrap());
            if tier >= MAX_LEVELS as u64
                || sequence == 0
                || sequence > seq
                || entries.last().map_or(sequence != seq, |prev| {
                    u64::from(prev.tier) >= tier || prev.sequence <= sequence
                })
            {
                return Err(invalid("invalid live level order"));
            }
            entries.push(Entry {
                tier: tier as u8,
                sequence,
                root: record[16..].try_into().unwrap(),
            });
        }
        Ok(Self {
            budget,
            id,
            seq,
            entries,
        })
    }
    fn wal_name(&self) -> String {
        let tier = self.entries.first().map_or(0, |e| e.tier);
        Files::name(&self.id, &format!("wal-{}-{tier}", self.seq))
    }
    fn binding(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    fn keep(&self) -> BTreeSet<String> {
        let mut keep: BTreeSet<_> = self.entries.iter().map(|e| e.name(&self.id)).collect();
        keep.insert(self.wal_name());
        keep
    }
}

/// Counters for successful operations since this handle was created or opened.
/// WAL and pending byte counts describe the current checkpoint tail.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveStats {
    pub sequence: u64,
    pub base_sequence: u64,
    pub wal_bytes: u64,
    pub delta_entries: u64,
    pub pending_bytes: u64,
    pub checkpoints: u64,
    /// Immutable sorted levels currently selected by the manifest.
    pub levels: u64,
    /// Total completed immutable level file bytes written by this handle.
    pub level_bytes_written: u64,
    /// Largest single immutable level file published by this handle.
    pub largest_flush_bytes: u64,
    pub file_syncs: u64,
    pub directory_syncs: u64,
}

/// A single-writer binary KV backed by authenticated immutable levels plus a
/// bounded mutable delta. Automatic flushes carry through occupied age tiers.
/// Explicit checkpoint merges all tiers. Uncertain I/O requires reopening.
pub struct LiveDb {
    head: Head,
    levels: Vec<Level>,
    wal: Wal,
    delta: Delta,
    pending: u64,
    checkpoints: u64,
    level_bytes_written: u64,
    largest_flush_bytes: u64,
    file_syncs: u64,
    directory_syncs: u64,
    fenced: bool,
    // Release the directory lock after the WAL and all immutable readers close.
    files: Files,
}

const FRAME_CHARGE: u64 = 128;

fn op_charge(key: &[u8], value: Option<&[u8]>) -> u64 {
    256 + (key.len() + value.map_or(0, <[u8]>::len)) as u64
}

/// Apply one validated batch and return its conservative checkpoint charge.
fn apply(delta: &mut Delta, ops: &[WalOp<'_>]) -> u64 {
    // A positive frame charge also bounds recovery of empty batches. Repeated
    // writes are charged in full even when their map storage can be reused.
    let mut charge = FRAME_CHARGE;
    for &op in ops {
        let (key, value) = match op {
            WalOp::Put(key, value) => (key, Some(value)),
            WalOp::Delete(key) => (key, None),
        };
        charge += op_charge(key, value);
        if let Some(current) = delta.get_mut(key) {
            if let Some(bytes) = value {
                bytes.clone_into(current.get_or_insert_with(Vec::new));
            } else {
                *current = None;
            }
        } else {
            delta.insert(key.to_vec(), value.map(<[u8]>::to_vec));
        }
    }
    charge
}

impl LiveDb {
    /// Create in a new or empty directory, or resume a provable interrupted creation.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::create_with_buffer(path, LIVE_DEFAULT_BUFFER_BYTES)
    }

    /// Choose the inline checkpoint threshold (512 KiB through 16 MiB). A larger
    /// budget permits a longer WAL and more recovery work. The budget is persisted.
    pub fn create_with_buffer(path: impl AsRef<Path>, budget: u64) -> io::Result<Self> {
        if !valid_budget(budget) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "write buffer must be 512 KiB through 16 MiB",
            ));
        }
        let (files, dir_syncs) = Files::lock(path.as_ref(), true)?;
        match files.read(MANIFEST) {
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "live database already exists",
                ));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let (id, recorded) = files
            .creation_marker(Some(budget))?
            .ok_or_else(|| invalid("missing live creation marker"))?;
        if recorded.unwrap_or(LIVE_CHECKPOINT_BYTES) != budget {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "existing bootstrap has a different write buffer; use open to resume",
            ));
        }
        Self::initialize(files, id, recorded, dir_syncs)
    }

    fn initialize(
        files: Files,
        id: [u8; 16],
        budget: Option<u64>,
        mut dir_syncs: u64,
    ) -> io::Result<Self> {
        let head = Head {
            budget,
            id,
            seq: 0,
            entries: vec![],
        };
        files.sync(&mut dir_syncs)?;
        let wal_name = head.wal_name();
        let next = Files::name(&id, "head-next");
        let binding = head.binding();
        let encoded = head.encode();
        files.reset_bootstrap(
            &id,
            budget,
            &[(&wal_name, &wal_header(0, binding)), (&next, &encoded)],
        )?;
        let file = files.fresh(&wal_name)?;
        file.try_lock()?;
        let wal = Wal::initialize(file, 0, binding)?;
        files.publish(&id, &encoded, &mut dir_syncs)?;
        files.remove_marker(&id, budget)?;
        files.sync(&mut dir_syncs)?;
        Ok(Self {
            files,
            head,
            levels: vec![],
            wal,
            delta: Delta::new(),
            pending: 0,
            checkpoints: 0,
            level_bytes_written: 0,
            largest_flush_bytes: 0,
            file_syncs: 1,
            directory_syncs: dir_syncs,
            fenced: false,
        })
    }

    /// Acquire exclusive ownership, verify the selected levels' indexes, and
    /// replay checksum-verified complete WAL batches. A partial final frame
    /// is truncated before any new commit.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (files, mut dir_syncs) = Files::lock(path.as_ref(), false)?;
        let head = match Head::read(&files) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if let Some((id, budget)) = files.creation_marker(None)? {
                    return Self::initialize(files, id, budget, dir_syncs);
                }
                return Err(e);
            }
            other => other?,
        };
        let mut levels = Vec::with_capacity(head.entries.len());
        for e in &head.entries {
            let mut level = Level::open(files.read(&e.name(&head.id))?, e.root)?;
            if e.tier == BULK_TIER {
                level.enable_bulk_cache();
            }
            levels.push(level);
        }
        let mut delta = Delta::new();
        let mut pending = 0;
        let wal = Wal::open(
            files.writable(&head.wal_name())?,
            head.seq,
            head.binding(),
            |_, ops| {
                if pending >= head.budget.unwrap_or(LIVE_CHECKPOINT_BYTES) {
                    return Err(invalid("live WAL exceeds checkpoint interval"));
                }
                pending += apply(&mut delta, ops);
                Ok(())
            },
        )?;
        // A previous process may have renamed the selector and exited before
        // syncing the directory. Persist the observed winner before reclaiming.
        files.sync(&mut dir_syncs)?;
        let mut changed = files.reclaim(&head.id, &head.keep())?;
        changed |= files.remove_marker(&head.id, head.budget)?;
        if changed {
            files.sync(&mut dir_syncs)?;
        }
        Ok(Self {
            files,
            head,
            levels,
            wal,
            delta,
            pending,
            checkpoints: 0,
            level_bytes_written: 0,
            largest_flush_bytes: 0,
            file_syncs: 0,
            directory_syncs: dir_syncs,
            fenced: false,
        })
    }

    fn check(&self) -> io::Result<()> {
        if self.fenced || self.wal.is_fenced() {
            return Err(io::Error::other(
                "live writer requires reopen after an uncertain effect",
            ));
        }
        Ok(())
    }

    /// Last recovered or acknowledged batch sequence.
    pub fn sequence(&self) -> u64 {
        self.wal.sequence()
    }

    /// Current tail size, flushes and successful physical synchronization calls.
    pub fn stats(&self) -> LiveStats {
        LiveStats {
            sequence: self.sequence(),
            base_sequence: self.head.seq,
            wal_bytes: self.wal.len(),
            delta_entries: self.delta.len() as u64,
            pending_bytes: self.pending,
            checkpoints: self.checkpoints,
            levels: self.levels.len() as u64,
            level_bytes_written: self.level_bytes_written,
            largest_flush_bytes: self.largest_flush_bytes,
            file_syncs: self.file_syncs.saturating_add(self.wal.syncs()),
            directory_syncs: self.directory_syncs,
        }
    }

    /// Commit ordered mutations in one durable atomic batch. If an I/O
    /// failure follows publication, reopen to discover the winning sequence.
    pub fn commit(&mut self, ops: &[WalOp<'_>]) -> io::Result<u64> {
        self.check()?;
        if self.checkpoint_due() {
            validate_wal_batch(ops)?;
            self.flush(false)?;
        }
        let sequence = self.wal.append(ops)?;
        self.pending += apply(&mut self.delta, ops);
        if self.checkpoint_due() {
            self.flush(false)?;
        }
        Ok(sequence)
    }

    /// Persisted threshold shared by automatic flush and recovery admission.
    pub fn checkpoint_budget(&self) -> u64 {
        self.head.budget.unwrap_or(LIVE_CHECKPOINT_BYTES)
    }

    fn checkpoint_due(&self) -> bool {
        self.pending >= self.checkpoint_budget() || self.wal.len() >= self.checkpoint_budget()
    }

    /// Flush the tail and all occupied levels into one sorted run, reclaiming
    /// obsolete files after a synchronized manifest publication.
    pub fn checkpoint(&mut self) -> io::Result<()> {
        self.check()?;
        self.flush(true)
    }

    fn flush(&mut self, all: bool) -> io::Result<()> {
        if self.sequence() == self.head.seq && (!all || self.levels.len() <= 1) {
            return Ok(());
        }
        let (take, tier) = if all {
            (
                self.levels.len(),
                self.head.entries.last().map_or(0, |e| e.tier),
            )
        } else {
            // Binary carry. Files in preceding occupied tiers are newer than
            // every untouched level; tombstones must survive those deeper levels.
            let take = self
                .head
                .entries
                .iter()
                .enumerate()
                .take_while(|(i, e)| *i == usize::from(e.tier))
                .count();
            if take >= MAX_LEVELS {
                return Err(invalid("exhausted live sequence space"));
            }
            (take, take as u8)
        };
        self.fenced = true;
        let mut entry = Entry {
            tier,
            sequence: self.sequence(),
            root: [0; 32],
        };
        let mut file = self.files.fresh(&entry.name(&self.head.id))?;
        let includes_oldest = take == self.levels.len();
        let mut old: ArrayVec<_, MAX_LEVELS> = self.levels[..take].iter_mut().collect();
        entry.root = live_levels::write_level(&mut file, &self.delta, &mut old, includes_oldest)?;
        drop(old);
        self.publish_level(entry, file, take)
    }

    fn publish_level(&mut self, entry: Entry, file: std::fs::File, take: usize) -> io::Result<()> {
        let sequence = entry.sequence;
        sync_durable(&file)?;
        let output_bytes = file.metadata()?.len();
        let mut level = Level::open(file, entry.root)?;
        if entry.tier == BULK_TIER {
            level.enable_bulk_cache();
        }
        let mut entries = Vec::with_capacity(self.head.entries.len() - take + 1);
        entries.push(entry);
        entries.extend_from_slice(&self.head.entries[take..]);
        let head = Head {
            budget: self.head.budget,
            id: self.head.id,
            seq: sequence,
            entries,
        };
        let file = self.files.fresh(&head.wal_name())?;
        file.try_lock()?;
        let wal = Wal::initialize(file, head.seq, head.binding())?;
        self.files
            .publish(&head.id, &head.encode(), &mut self.directory_syncs)?;
        let retired_wal = self.head.wal_name();
        let retired: Vec<_> = self.head.entries[..take]
            .iter()
            .map(|e| e.name(&head.id))
            .collect();
        self.file_syncs = self
            .file_syncs
            .saturating_add(2)
            .saturating_add(self.wal.syncs());
        self.head = head;
        self.levels.splice(..take, [level]);
        self.wal = wal;
        self.delta.clear();
        self.pending = 0;
        self.files.remove(&retired_wal)?;
        for name in retired {
            self.files.remove(&name)?;
        }
        self.files.sync(&mut self.directory_syncs)?;
        self.checkpoints = self.checkpoints.saturating_add(1);
        self.level_bytes_written = self.level_bytes_written.saturating_add(output_bytes);
        self.largest_flush_bytes = self.largest_flush_bytes.max(output_bytes);
        self.fenced = false;
        Ok(())
    }

    /// Read the newest live value of a binary key.
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.check()?;
        let mut levels: ArrayVec<_, MAX_LEVELS> = self.levels.iter_mut().collect();
        live_levels::get(&mut levels, &self.delta, key)
    }

    /// Visit current rows in ascending order between the given bounds.
    pub fn visit_forward(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        self.visit(lower, upper, limit, false, emit)
    }

    /// Visit current rows in descending order, using the same ascending bounds.
    pub fn visit_reverse(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        self.visit(lower, upper, limit, true, emit)
    }

    fn visit(
        &mut self,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        limit: usize,
        reverse: bool,
        emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        self.check()?;
        let mut levels: ArrayVec<_, MAX_LEVELS> = self.levels.iter_mut().collect();
        live_levels::visit(&mut levels, &self.delta, lower, upper, limit, reverse, emit)
    }
}

#[cfg(test)]
#[path = "live_tests.rs"]
mod tests;
