//! Bounded online collection of encrypted document objects that no state names.
//!
//! An ordinary overwrite, a deletion and change-feed trimming each displace a
//! stored descriptor. The displaced manifest's digest becomes a candidate, a
//! hint only: an object is deleted when all of the following hold.
//!
//! * No document or retained change after-image of a frozen published state
//!   names it (a bounded resumable walk), and no after-image staged since that
//!   state names it (every staged after-image rescues its candidate).
//! * The selected durable snapshot is at or beyond that frozen state, so the
//!   durable application directory names it no longer either. A reopening
//!   replica therefore still holds every object its own snapshot names.
//! * A proof chunk additionally has no registered owner left. [`LINKS`] counts,
//!   per chunk, the manifests that name it; a manifest is counted exactly once,
//!   under its marker row. A restore clears the namespace and a census of the
//!   live manifests rebuilds it before any chunk is collected.
//!
//! Readers are unaffected: each generation reads through the native root it
//! selected, which keeps rows a later root deleted. Writers are fenced: an
//! apply decides whether an object is already published against the previous
//! generation's selection, which predates a deletion committed after it. Every
//! digest deleted since that selection therefore stays in the fence, and a
//! fenced object is written again instead of being found present. Publishing
//! a generation, whose selection is captured after the deletion, ends it.
//!
//! All storage work happens in bounded transactions of its own, outside the
//! committed apply's escrow and never inside an application publication. Every
//! transaction leaves the store consistent, so a crash needs no recovery: the
//! reopening restore reconciles both object namespaces with its snapshot and
//! replay displaces the later descriptors again.
use crate::{
    admission::{NodeAdmission, Reservation},
    document_encoding::{self, BodyManifest},
    document_store::{self, BLOBS, BODIES, Scope},
};
use anyhow::{Context, Result};
use kasumi_store::{PreparedTenantReadPoints, TenantStore, WriteOp};
use kasumi_types::{ChangeCommit, DocumentSlot, TenantState};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Bound,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Owner counts of proof chunks and the markers of the manifests counted.
/// `[COUNT] ‖ scope ‖ chunk digest` holds a big-endian `u64` of at least one;
/// `[MARKER] ‖ scope ‖ manifest digest` holds one byte.
pub(crate) const LINKS: &str = "engine.document.blob-links";
const LINK_KEY_BYTES: usize = 65;
const COUNT: u8 = 0;
const MARKER: u8 = 1;
const MARKED: &[u8] = &[1];
/// A manifest row is bounded by the document store's own object cap.
const MAX_MANIFEST_BYTES: usize = 32 << 20;
/// Bookkeeping below this many bytes is the engine's fixed floor.
const FLOOR_BYTES: u64 = 32 << 10;
const MAX_PENDING: usize = 1 << 18;
const CANDIDATE_BYTES: u64 = 72;
const MAX_REGISTRATION_SLOTS: usize = 1 << 18;
const MAX_FAILURES: u32 = 3;
/// Each selected disk slot requires authenticated native reads. A walk yields
/// after at most one page of those reads before the foreground apply returns.
const DISK_WALK_PAGE: usize = 32;

type Digest = [u8; 32];
type Documents = imbl::OrdMap<String, Arc<DocumentSlot>>;
type Feed = imbl::OrdMap<u64, Arc<ChangeCommit>>;

fn link_key(kind: u8, scope: Scope, digest: Digest) -> [u8; LINK_KEY_BYTES] {
    let mut key = [0; LINK_KEY_BYTES];
    key[0] = kind;
    key[1..].copy_from_slice(&scope.key(digest));
    key
}

/// Work one step may do. Each is a bound on one call, not on a cycle.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budgets {
    /// Document and change slots one step visits.
    pub walk_slots: usize,
    /// Manifests one census step reads.
    pub census_reads: usize,
    /// Manifests one transaction registers.
    pub register_bodies: usize,
    /// Queued chunk digests that make the next step register them.
    pub register_flush_digests: usize,
    /// Manifests one transaction deletes.
    pub delete_bodies: usize,
    /// Operations one deleting transaction carries.
    pub delete_operations: usize,
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            walk_slots: 4096,
            census_reads: 32,
            register_bodies: 256,
            register_flush_digests: 4096,
            delete_bodies: 256,
            delete_operations: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub cycles: u64,
    pub rescued: u64,
    pub deleted_bodies: u64,
    pub deleted_blobs: u64,
    pub registered: u64,
    pub transactions: u64,
    pub dropped: u64,
    pub failures: u64,
}

/// The exact authenticated feed prefix owned by the snapshot directory.
struct DiskFeed {
    selection: crate::application_sources::SelectedApplication,
    boundary: crate::application_sources::SnapshotBoundary<String>,
    first: u64,
    next: u64,
    end: u64,
}

impl DiskFeed {
    /// Close each native record reader before a census callback opens the
    /// manifest store. The page keeps its own admitted descriptor memory.
    fn advance(
        &mut self,
        budget: &mut usize,
        visit: &mut impl FnMut(&kasumi_types::StoredDocument) -> Result<bool>,
    ) -> Result<bool> {
        while self.next < self.end && *budget > 0 {
            let limit = DISK_WALK_PAGE.min(*budget);
            let (rows, _grant) = self
                .selection
                .with_base_snapshot_boundary(None, &self.boundary, |tree, memory, _, revision| {
                    let grant = crate::document_restore::ReadAdmissionFailure::reserve(
                        memory,
                        1024 + (limit as u64) * 1024,
                    )?;
                    let feed = crate::application_records::SnapshotFeed {
                        tree,
                        memory,
                        revision,
                        end_sequence: self.end,
                    };
                    let mut rows = Vec::with_capacity(limit);
                    feed.visit(self.first, self.next, |_, _, _, _, record| {
                        rows.push(record.document.clone());
                        Ok(rows.len() < limit)
                    })?;
                    anyhow::ensure!(!rows.is_empty(), "verified GC feed made no progress");
                    Ok((rows, grant))
                })?
                .context("GC snapshot feed directory disappeared")?;
            for row in rows {
                let proceed = match row.as_deref() {
                    Some(DocumentSlot::Stored(descriptor)) => visit(descriptor)?,
                    Some(DocumentSlot::Pending(_)) => {
                        anyhow::bail!("pending descriptor in persisted GC feed")
                    }
                    None => true,
                };
                self.next += 1;
                *budget -= 1;
                if !proceed {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// Walk only the live namespace of the exact primary directory. Each page
/// releases its native view before the visitor enters the manifest store.
struct DiskDocuments {
    selection: crate::application_sources::SelectedApplication,
    boundary: crate::application_sources::SnapshotBoundary<String>,
    collections: Vec<(String, usize)>,
    collection: usize,
    visited: usize,
    after: Option<String>,
}

impl DiskDocuments {
    fn advance(
        &mut self,
        budget: &mut usize,
        visit: &mut impl FnMut(&kasumi_types::StoredDocument) -> Result<bool>,
    ) -> Result<bool> {
        while *budget > 0 {
            let Some((collection, expected)) = self.collections.get(self.collection) else {
                return Ok(true);
            };
            let limit = (*budget).min(DISK_WALK_PAGE);
            let (rows, _grant) = self
                .selection
                .with_primary_boundary(None, &self.boundary, |tree, memory, _| {
                    let grant = crate::document_restore::ReadAdmissionFailure::reserve(
                        memory,
                        1024 + limit as u64 * 1024,
                    )?;
                    let mut ids = Vec::with_capacity(limit);
                    crate::application_records::visit_primary_ids(
                        tree,
                        collection,
                        3,
                        self.after.as_deref(),
                        |id| {
                            ids.push(id.to_owned());
                            Ok(ids.len() < limit)
                        },
                    )?;
                    let mut rows = Vec::with_capacity(ids.len());
                    for id in ids {
                        let (point, _decode, _) =
                            crate::application_records::admitted_snapshot_point(
                                tree,
                                memory,
                                collection,
                                &id,
                                self.boundary.revision,
                                || Ok(()),
                            )?;
                        let crate::application_records::PrimaryPoint::Live(slot) = point else {
                            anyhow::bail!("GC live primary key has no live descriptor")
                        };
                        rows.push(slot);
                    }
                    Ok((rows, grant))
                })?
                .context("GC selected primary directory disappeared")?;
            anyhow::ensure!(
                self.visited
                    .checked_add(rows.len())
                    .is_some_and(|n| n <= *expected),
                "GC primary exceeded the selected live count"
            );
            let exhausted = rows.len() < limit;
            for row in rows {
                let DocumentSlot::Stored(descriptor) = row.as_ref() else {
                    anyhow::bail!("pending descriptor in persisted GC primary");
                };
                let proceed = visit(descriptor)?;
                self.after = Some(descriptor.id.clone());
                self.visited += 1;
                *budget -= 1;
                if !proceed {
                    return Ok(false);
                }
            }
            if exhausted {
                anyhow::ensure!(self.visited == *expected, "GC primary live count differs");
                *budget = budget.saturating_sub(1);
                self.collection += 1;
                self.after = None;
                self.visited = 0;
            }
        }
        Ok(self.collection == self.collections.len())
    }
}

/// A resumable position in a frozen copy of the document and feed roots.
/// The persistent maps share their nodes with the published state.
struct Walk {
    documents: Vec<Documents>,
    disk_documents: Option<Box<DiskDocuments>>,
    _collection_roots: Option<Reservation>,
    feed: Feed,
    disk_feed: Option<Box<DiskFeed>>,
    collection: usize,
    after_document: Option<String>,
    after_commit: Option<u64>,
    next_record: usize,
    documents_done: bool,
    done: bool,
}
impl Walk {
    fn freeze(
        state: &TenantState,
        selection: &crate::application_sources::SelectedApplication,
        admission: &Arc<NodeAdmission>,
    ) -> Result<Option<Self>> {
        // A sparse log tail can share its original commit allocations. Bound the
        // number of freshly allocated map slots independently of the prefix.
        const MAX_TAIL: usize = 32;
        let retained = &state.change_feed;
        let end = retained.next_sequence;
        let first = end
            .checked_sub(u64::try_from(retained.event_count)?)
            .context("GC feed bounds overflow")?;
        let prefix = if retained.commits.is_empty() {
            None
        } else {
            selection
                .with_base_snapshot_records(None, state, |tree, memory, _, revision| {
                    Ok(crate::application_records::SnapshotFeed::open(
                        tree,
                        memory,
                        revision,
                        state.revision,
                        end,
                    )?
                    .map(|feed| feed.end_sequence))
                })?
                .flatten()
        };
        let disk_end = prefix.filter(|&after| {
            after > first && retained.commits.range(after..).take(MAX_TAIL + 1).count() <= MAX_TAIL
        });
        if let Some(after) = disk_end {
            anyhow::ensure!(
                retained.first_available_sequence() == first
                    && (after == end || retained.commits.contains_key(&after)),
                "GC retained feed and snapshot boundary differ"
            );
        }
        let use_primary = state.collections.values().any(|c| !c.documents.is_empty())
            && selection
                .with_serving_primary(None, state, |_, _, _| Ok(()))?
                .is_some();
        let roots_bytes = if use_primary {
            state.collections.keys().try_fold(1536usize, |bytes, name| {
                bytes.checked_add(std::mem::size_of::<(String, usize)>() + name.len())
            })
        } else {
            state
                .collections
                .len()
                .checked_mul(std::mem::size_of::<Documents>())
        }
        .context("GC collection root size overflow")?;
        let bytes = roots_bytes
            .checked_add(if disk_end.is_some() {
                4096 + MAX_TAIL * 256
            } else {
                0
            })
            .context("GC feed root size overflow")?;
        let grant = if bytes == 0 {
            None
        } else {
            let Ok(reserved) = admission.reserve_resident(u64::try_from(bytes)?) else {
                return Ok(None);
            };
            Some(reserved)
        };
        let mut documents = Vec::new();
        let disk_documents = if use_primary {
            let mut collections = Vec::new();
            if collections
                .try_reserve_exact(state.collections.len())
                .is_err()
            {
                return Ok(None);
            }
            collections.extend(
                state
                    .collections
                    .iter()
                    .map(|(name, c)| (name.clone(), c.documents.len())),
            );
            Some(Box::new(DiskDocuments {
                selection: selection.clone(),
                boundary: state.into(),
                collections,
                collection: 0,
                visited: 0,
                after: None,
            }))
        } else {
            if documents
                .try_reserve_exact(state.collections.len())
                .is_err()
            {
                return Ok(None);
            }
            documents.extend(state.collections.values().map(|c| c.documents.clone()));
            None
        };
        let (feed, disk_feed) = match disk_end {
            Some(after) => {
                let tail = retained
                    .commits
                    .range(after..)
                    .map(|(&sequence, commit)| (sequence, commit.clone()))
                    .collect();
                let disk = DiskFeed {
                    selection: selection.clone(),
                    boundary: state.into(),
                    first,
                    next: first,
                    end: after,
                };
                (tail, Some(Box::new(disk)))
            }
            None => (retained.commits.clone(), None),
        };
        Ok(Some(Self {
            documents,
            disk_documents,
            _collection_roots: grant,
            feed,
            disk_feed,
            collection: 0,
            after_document: None,
            after_commit: None,
            next_record: 0,
            documents_done: false,
            done: false,
        }))
    }

    /// Visit up to `budget` further stored slots. `visit` returns whether to
    /// continue; a stop leaves the walk resumable after the last slot visited.
    /// A failed visit leaves the cursor before the failing slot, so a retry
    /// resumes there without repeating successful owner registrations.
    fn advance(
        &mut self,
        mut budget: usize,
        mut visit: impl FnMut(&kasumi_types::StoredDocument) -> Result<bool>,
    ) -> Result<()> {
        if !self.documents_done
            && let Some(disk) = &mut self.disk_documents
        {
            budget = budget.min(DISK_WALK_PAGE);
            if !disk.advance(&mut budget, &mut visit)? {
                return Ok(());
            }
            self.documents_done = true;
            self.disk_documents = None;
        }
        while !self.documents_done && budget > 0 {
            let Some(documents) = self.documents.get(self.collection) else {
                self.documents_done = true;
                break;
            };
            let lower: Bound<&String> = match &self.after_document {
                Some(after) => Bound::Excluded(after),
                None => Bound::Unbounded,
            };
            let mut entries = documents
                .range::<(Bound<&String>, Bound<&String>), String>((lower, Bound::Unbounded));
            let mut last = None;
            let (exhausted, resume) = loop {
                let Some((id, slot)) = entries.next() else {
                    break (true, Ok(true));
                };
                if budget == 0 {
                    break (false, Ok(true));
                }
                budget -= 1;
                if let DocumentSlot::Stored(descriptor) = slot.as_ref() {
                    match visit(descriptor) {
                        Ok(true) => {}
                        Ok(false) => {
                            last = Some(id);
                            break (false, Ok(false));
                        }
                        Err(error) => break (false, Err(error)),
                    }
                }
                last = Some(id);
            };
            if exhausted {
                // Empty collections also consume a unit of scanning work.
                budget = budget.saturating_sub(1);
                self.collection += 1;
                self.after_document = None;
            } else if let Some(id) = last {
                self.after_document = Some(id.clone());
            }
            if !resume? {
                return Ok(());
            }
        }
        if let Some(disk) = &mut self.disk_feed {
            budget = budget.min(DISK_WALK_PAGE);
            if !disk.advance(&mut budget, &mut visit)? || disk.next < disk.end {
                return Ok(());
            }
            self.disk_feed = None;
        }
        while !self.done && budget > 0 {
            let after = self.after_commit;
            let lower: Bound<&u64> = match &after {
                Some(sequence) if self.next_record != 0 => Bound::Included(sequence),
                Some(sequence) => Bound::Excluded(sequence),
                None => Bound::Unbounded,
            };
            let Some((&sequence, commit)) = self
                .feed
                .range::<(Bound<&u64>, Bound<&u64>), u64>((lower, Bound::Unbounded))
                .next()
            else {
                self.done = true;
                break;
            };
            if commit.records.is_empty() {
                budget -= 1;
                self.after_commit = Some(sequence);
                continue;
            }
            while budget > 0 {
                let record = &commit.records[self.next_record];
                let proceed = match record.document.as_deref() {
                    Some(DocumentSlot::Stored(descriptor)) => visit(descriptor)?,
                    _ => true,
                };
                self.after_commit = Some(sequence);
                self.next_record += 1;
                budget -= 1;
                let complete = self.next_record == commit.records.len();
                if complete {
                    self.next_record = 0;
                }
                if !proceed {
                    return Ok(());
                }
                if complete {
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn check_snapshot_feed_walk(
    generation: &crate::Generation,
    admission: &Arc<NodeAdmission>,
    expect_log_tail: bool,
) -> Result<()> {
    let state = &generation.state;
    let selection = generation
        .application_selection
        .get()
        .context("no selected source")?;
    let mut walk = Walk::freeze(state, selection, admission)?.context("GC walk admission")?;
    anyhow::ensure!(
        walk.documents.is_empty() && walk.disk_documents.is_some(),
        "physical test requires a primary GC cursor"
    );
    let expected_documents: Vec<_> = state
        .collections
        .values()
        .flat_map(|c| c.documents.values())
        .map(|slot| match slot.as_ref() {
            DocumentSlot::Stored(stored) => (stored.id.clone(), stored.version, stored.body_object),
            DocumentSlot::Pending(_) => panic!("published GC test document is pending"),
        })
        .collect();
    assert!(!expected_documents.is_empty());
    let documents = walk.disk_documents.as_mut().unwrap();
    let mut budget = usize::MAX;
    let failure = documents
        .advance(&mut budget, &mut |_| {
            anyhow::bail!("first primary unavailable")
        })
        .unwrap_err();
    assert_eq!(failure.to_string(), "first primary unavailable");
    assert!(documents.after.is_none());
    let mut observed = Vec::new();
    while !documents.advance(&mut 1, &mut |row| {
        observed.push((row.id.clone(), row.version, row.body_object));
        Ok(false)
    })? {}
    assert_eq!(observed, expected_documents);
    let disk = walk
        .disk_feed
        .as_ref()
        .context("native snapshot must own this feed prefix")?;
    assert!(walk.feed.keys().all(|first| *first >= disk.end));
    assert_eq!(!walk.feed.is_empty(), expect_log_tail);
    let expected: Vec<_> = state
        .change_feed
        .commits
        .values()
        .flat_map(|commit| &commit.records)
        .filter_map(|record| match record.document.as_deref() {
            Some(DocumentSlot::Stored(stored)) => Some((stored.version, stored.body_object)),
            _ => None,
        })
        .collect();
    assert!(expected.len() >= 2);
    // Isolate the feed phase of the real cursor and interrupt its first object.
    walk.documents_done = true;
    let checkpoint = disk.next;
    let error = walk
        .advance(1, |_| anyhow::bail!("first manifest unavailable"))
        .unwrap_err();
    assert_eq!(error.to_string(), "first manifest unavailable");
    assert_eq!(walk.disk_feed.as_ref().unwrap().next, checkpoint);
    let mut seen = Vec::new();
    while !walk.done {
        walk.advance(1, |stored| {
            seen.push((stored.version, stored.body_object));
            Ok(false)
        })?;
    }
    assert_eq!(seen, expected);
    Ok(())
}

enum Phase {
    /// Dropping every candidate the frozen state still names.
    Walk(Walk),
    /// Verified against the frozen state; waiting for a durable snapshot at
    /// or beyond it while staged after-images keep rescuing.
    Await,
    /// Deleting the verified candidates in bounded transactions.
    Delete,
}
struct Cycle {
    revision: u64,
    /// Each candidate manifest, and whether its body is long enough to name
    /// a chunk: a shorter one is deleted without reading it or its owners.
    candidates: BTreeMap<Digest, bool>,
    phase: Phase,
}

/// A manifest staged or found by the census, and the chunks it names.
struct Registration {
    body: Digest,
    blobs: Vec<Digest>,
}

enum Census {
    Idle,
    Walking(Walk),
    Done,
}

struct State {
    budgets: Budgets,
    /// A restore is replacing the state, or collection stopped after failures.
    suspended: bool,
    consecutive_failures: u32,
    last_error: Option<&'static str>,
    /// Chunk ownership was lost: only manifests are collected until a restore.
    blobs_off: bool,
    // The same admitted tree moves into the cycle when its state is frozen.
    pending: BTreeMap<Digest, bool>,
    cycle: Option<Cycle>,
    /// `(manifest?, digest)` deleted since the current generation's selection.
    fence: BTreeSet<(bool, Digest)>,
    registrations: VecDeque<Registration>,
    registration_slots: usize,
    census: Census,
    grant: Option<Reservation>,
    granted: u64,
    stats: Stats,
}

/// What one step collects against. The caller holds the tenant apply lock and
/// is outside any committed apply's native escrow.
pub(crate) struct Step<'a> {
    pub state: &'a TenantState,
    pub selection: &'a crate::application_sources::SelectedApplication,
    /// Logical revision of the selected durable snapshot, when there is one.
    pub snapshot_revision: &'a dyn Fn() -> Result<Option<u64>>,
    pub store: &'a Arc<TenantStore>,
    pub scope: Scope,
}

pub(crate) struct ObjectGc {
    admission: OnceLock<Arc<NodeAdmission>>,
    /// Whether a step has work or a writer must consult the fence.
    armed: AtomicBool,
    state: Mutex<State>,
}
impl Default for ObjectGc {
    fn default() -> Self {
        Self {
            admission: OnceLock::new(),
            armed: AtomicBool::new(false),
            state: Mutex::new(State {
                budgets: Budgets::default(),
                suspended: false,
                consecutive_failures: 0,
                last_error: None,
                blobs_off: false,
                pending: BTreeMap::new(),
                cycle: None,
                fence: BTreeSet::new(),
                registrations: VecDeque::new(),
                registration_slots: 0,
                census: Census::Idle,
                grant: None,
                granted: 0,
                stats: Stats::default(),
            }),
        }
    }
}

impl State {
    fn footprint(&self) -> u64 {
        let candidates = self
            .cycle
            .as_ref()
            .map_or(0, |cycle| cycle.candidates.len());
        (self.pending.len().saturating_add(candidates) as u64)
            .saturating_mul(CANDIDATE_BYTES)
            .saturating_add((self.fence.len() as u64).saturating_mul(72))
            .saturating_add((self.registration_slots as u64).saturating_mul(32))
            .saturating_add(
                (self.registrations.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<Registration>() as u64),
            )
    }

    /// Admit `extra` further bytes of bookkeeping before allocating them.
    /// Above the fixed floor this is ordinary resident capacity, taken from
    /// the governor and never from a committed apply's escrow. A refusal only
    /// drops the bookkeeping it was for.
    fn admit(&mut self, admission: &Arc<NodeAdmission>, extra: u64) -> bool {
        let needed = self.footprint().saturating_add(extra);
        if needed <= FLOOR_BYTES || needed <= self.granted {
            return true;
        }
        let target = needed.checked_next_power_of_two().unwrap_or(needed);
        let admitted = match self.grant.as_mut() {
            Some(grant) => grant.reserve_additional(target - self.granted).is_ok(),
            None => match admission.reserve_resident(target) {
                Ok(grant) => {
                    self.grant = Some(grant);
                    true
                }
                Err(_) => false,
            },
        };
        if admitted {
            self.granted = target;
        }
        admitted
    }

    fn record_candidate(&mut self, admission: &Arc<NodeAdmission>, body: Digest, large: bool) {
        if let Some(already_large) = self.pending.get_mut(&body) {
            *already_large |= large;
            return;
        }
        if self.pending.len() >= MAX_PENDING || !self.admit(admission, CANDIDATE_BYTES) {
            self.stats.dropped += 1;
            return;
        }
        self.pending.insert(body, large);
    }

    /// Return capacity the bookkeeping no longer needs.
    fn settle(&mut self) {
        if self.registrations.is_empty() && self.registrations.capacity() > 512 {
            self.registrations = VecDeque::new();
        }
        let needed = self.footprint();
        if needed <= FLOOR_BYTES {
            self.grant = None;
            self.granted = 0;
        } else if needed < self.granted / 4 {
            let target = needed.checked_next_power_of_two().unwrap_or(needed);
            if let Some(grant) = self.grant.as_mut() {
                grant.retain(target);
                self.granted = target;
            }
        }
    }

    /// Whether a step would make progress. Owners queued below the flush
    /// bound wait, without waking a step, for a cycle that needs them.
    fn has_work(&self) -> bool {
        !self.suspended
            && (!self.pending.is_empty()
                || self.cycle.is_some()
                || (!self.registrations.is_empty()
                    && self.registration_slots >= self.budgets.register_flush_digests))
    }

    fn queue_registration(
        &mut self,
        admission: &Arc<NodeAdmission>,
        body: Digest,
        blobs: Vec<Digest>,
    ) -> bool {
        let grow = if self.registrations.len() == self.registrations.capacity() {
            self.registrations.len().max(8)
        } else {
            0
        };
        let extra = (blobs.capacity() as u64).saturating_mul(32).saturating_add(
            (grow as u64).saturating_mul(std::mem::size_of::<Registration>() as u64),
        );
        if self.registration_slots.saturating_add(blobs.capacity()) > MAX_REGISTRATION_SLOTS
            || !self.admit(admission, extra)
            || self.registrations.try_reserve_exact(grow).is_err()
        {
            self.drop_blobs();
            return false;
        }
        self.registration_slots += blobs.capacity();
        self.registrations.push_back(Registration { body, blobs });
        true
    }

    fn drop_blobs(&mut self) {
        self.blobs_off = true;
        self.registrations = VecDeque::new();
        self.registration_slots = 0;
        self.census = Census::Idle;
    }

    /// Forget every candidate and owner. The fence outlives this: only a
    /// published selection or a completed restore ends it.
    fn clear(&mut self) {
        self.pending = BTreeMap::new();
        self.cycle = None;
        self.registrations = VecDeque::new();
        self.registration_slots = 0;
        self.census = Census::Idle;
        self.blobs_off = false;
        self.consecutive_failures = 0;
        self.last_error = None;
        self.settle();
    }
}

impl ObjectGc {
    /// The node governor of the installed application sources. Without it no
    /// candidate is recorded and no step runs.
    pub(crate) fn install(&self, admission: Arc<NodeAdmission>) {
        let _ = self.admission.set(admission);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn rearm(&self, state: &State) {
        self.armed.store(
            state.has_work() || !state.fence.is_empty(),
            Ordering::Release,
        );
    }

    /// Whether a step would do anything. Checked without the apply lock.
    pub(crate) fn wants_step(&self) -> bool {
        self.armed.load(Ordering::Acquire) && self.admission.get().is_some()
    }

    /// Whether `digest` was deleted after the selection a writer checks object
    /// presence against. The writer then writes the object again.
    pub(crate) fn fenced(&self, body: bool, digest: &Digest) -> bool {
        self.armed.load(Ordering::Acquire) && self.lock().fence.contains(&(body, *digest))
    }

    /// An apply staged an after-image whose manifest is `body`, naming the
    /// distinct chunks `blobs`. The manifest is live again, and its chunks are
    /// counted before any chunk is collected.
    pub(crate) fn staged(&self, body: Digest, blobs: Vec<Digest>) {
        let Some(admission) = self.admission.get() else {
            return;
        };
        let mut state = self.lock();
        if state.suspended {
            return;
        }
        if let Some(cycle) = state.cycle.as_mut()
            && cycle.candidates.remove(&body).is_some()
        {
            state.stats.rescued += 1;
        }
        // Before the first census, its frozen state will include every
        // published live owner. Once frozen, newly staged owners must join
        // the registration queue even when the walk has passed their slot.
        if !blobs.is_empty() && !state.blobs_off && !matches!(state.census, Census::Idle) {
            state.queue_registration(admission, body, blobs);
        }
        self.rearm(&state);
    }

    /// Record the manifests `next` displaced from `previous`: replaced and
    /// deleted documents among `changed`, and trimmed change after-images.
    /// A missed displacement only keeps its object until the next restore.
    pub(crate) fn displaced(
        &self,
        previous: &TenantState,
        next: &TenantState,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) {
        let Some(admission) = self.admission.get() else {
            return;
        };
        let mut state = self.lock();
        if state.suspended {
            return;
        }
        let record = |state: &mut State, slot: &DocumentSlot| {
            let DocumentSlot::Stored(descriptor) = slot else {
                return;
            };
            state.record_candidate(
                admission,
                descriptor.body_object,
                descriptor.body_bytes >= document_encoding::STRING_THRESHOLD as u64,
            );
        };
        let still_named = |documents: Option<&Documents>, id: &str, before: &Arc<DocumentSlot>| {
            documents
                .and_then(|current| current.get(id))
                .is_some_and(|after| match (before.as_ref(), after.as_ref()) {
                    (DocumentSlot::Stored(before), DocumentSlot::Stored(after)) => {
                        before.body_object == after.body_object
                    }
                    _ => Arc::ptr_eq(before, after),
                })
        };
        for (name, ids) in changed {
            let Some(old) = previous.collections.get(name) else {
                continue;
            };
            let current = next.collections.get(name).map(|group| &group.documents);
            for id in ids {
                let Some(before) = old.documents.get(id) else {
                    continue;
                };
                if !still_named(current, id, before) {
                    record(&mut state, before);
                }
            }
        }
        let retained = next
            .change_feed
            .commits
            .get_min()
            .map(|(sequence, _)| *sequence);
        for (sequence, commit) in &previous.change_feed.commits {
            if retained.is_some_and(|retained| *sequence >= retained) {
                break;
            }
            for change in &commit.records {
                if let Some(slot) = &change.document {
                    let current = next
                        .collections
                        .get(&change.collection)
                        .map(|group| &group.documents);
                    if !still_named(current, &change.id, slot) {
                        record(&mut state, slot);
                    }
                }
            }
        }
        self.rearm(&state);
    }

    /// A generation was published. Its selection was captured, under the apply
    /// lock, after every deletion committed so far.
    pub(crate) fn selection_published(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.lock();
        if !state.fence.is_empty() {
            state.fence = BTreeSet::new();
            state.settle();
        }
        self.rearm(&state);
    }

    /// A restore is about to reconcile the object namespaces. Nothing is
    /// collected again until [`Self::reset`] follows its publication.
    pub(crate) fn suspend(&self) {
        let mut state = self.lock();
        state.clear();
        state.suspended = true;
        self.rearm(&state);
    }

    /// A restore published: both object namespaces hold exactly its
    /// snapshot's objects and no chunk owner is registered.
    pub(crate) fn reset(&self) {
        let mut state = self.lock();
        state.clear();
        state.fence = BTreeSet::new();
        state.settle();
        state.suspended = false;
        self.rearm(&state);
    }

    /// One bounded unit of work. A storage failure is retried by a later step
    /// and never reaches the caller; repeated failures stop collection until
    /// the next restore, keeping the fence.
    pub(crate) fn step(&self, step: &Step<'_>) {
        let Some(admission) = self.admission.get() else {
            return;
        };
        let mut state = self.lock();
        if state.suspended {
            return;
        }
        match state.advance(step, admission) {
            Ok(()) => state.consecutive_failures = 0,
            Err(error) => {
                state.stats.failures += 1;
                state.consecutive_failures += 1;
                state.last_error = Some("object collection failed");
                if state.consecutive_failures >= MAX_FAILURES {
                    tracing::warn!(
                        io_kind = ?error.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
                        "document object collection stopped until the next restore"
                    );
                    state.clear();
                    state.last_error = Some("object collection failed");
                    state.suspended = true;
                }
            }
        }
        state.settle();
        self.rearm(&state);
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> Stats {
        self.lock().stats
    }
    #[cfg(test)]
    pub(crate) fn set_budgets(&self, budgets: Budgets) {
        self.lock().budgets = budgets;
    }
    #[cfg(test)]
    pub(crate) fn idle(&self) -> bool {
        let state = self.lock();
        !state.has_work()
    }
    #[cfg(test)]
    pub(crate) fn last_error(&self) -> Option<&'static str> {
        self.lock().last_error
    }
    #[cfg(test)]
    pub(crate) fn fence_len(&self) -> usize {
        self.lock().fence.len()
    }
    #[cfg(test)]
    pub(crate) fn awaiting_snapshot(&self) -> Option<u64> {
        let state = self.lock();
        state
            .cycle
            .as_ref()
            .filter(|cycle| matches!(cycle.phase, Phase::Await))
            .map(|cycle| cycle.revision)
    }
}

impl State {
    fn advance(&mut self, step: &Step<'_>, admission: &Arc<NodeAdmission>) -> Result<()> {
        let deleting = self
            .cycle
            .as_ref()
            .is_some_and(|cycle| matches!(cycle.phase, Phase::Delete));
        // Owners are counted before any deletion decides a chunk is unowned.
        if !self.registrations.is_empty()
            && (deleting || self.registration_slots >= self.budgets.register_flush_digests)
        {
            self.register(step)?;
            // A stream of writes may enqueue a new manifest before every step.
            // Once all its owners are durable, the same step may also spend its
            // deletion budget. Remaining registrations still preclude deletion.
            if !deleting || !self.registrations.is_empty() {
                return Ok(());
            }
        }
        if self.cycle.is_none() {
            if self.pending.is_empty() {
                return Ok(());
            }
            self.begin(step, admission)?;
            if self.cycle.is_none() {
                return Ok(());
            }
        }
        // The census reads storage only while candidates wait for a snapshot.
        if !self.blobs_off && !matches!(self.census, Census::Done) {
            self.take_census(step, admission)?;
        }
        let walk_slots = self.budgets.walk_slots;
        let owners_known = self.blobs_off || matches!(self.census, Census::Done);
        let registered = self.registrations.is_empty();
        let cycle = self.cycle.as_mut().expect("collection cycle");
        let walked = match &mut cycle.phase {
            Phase::Walk(walk) => {
                let candidates = &mut cycle.candidates;
                walk.advance(walk_slots, |descriptor| {
                    candidates.remove(&descriptor.body_object);
                    Ok(!candidates.is_empty())
                })?;
                walk.done || candidates.is_empty()
            }
            Phase::Await | Phase::Delete => false,
        };
        if walked {
            cycle.phase = Phase::Await;
        }
        if cycle.candidates.is_empty() {
            self.cycle = None;
            return Ok(());
        }
        if matches!(cycle.phase, Phase::Await)
            && owners_known
            && (step.snapshot_revision)()?.is_some_and(|durable| durable >= cycle.revision)
        {
            cycle.phase = Phase::Delete;
            // Owners queued meanwhile are counted by the next step first.
            if !registered {
                return Ok(());
            }
        }
        if matches!(cycle.phase, Phase::Delete) {
            return self.delete(step, admission);
        }
        Ok(())
    }

    fn begin(&mut self, step: &Step<'_>, admission: &Arc<NodeAdmission>) -> Result<()> {
        let Some(walk) = Walk::freeze(step.state, step.selection, admission)? else {
            return Ok(());
        };
        let candidates = std::mem::take(&mut self.pending);
        self.cycle = Some(Cycle {
            revision: step.state.revision,
            candidates,
            phase: Phase::Walk(walk),
        });
        self.stats.cycles += 1;
        Ok(())
    }

    /// Queue the registration of every live manifest that can name a chunk.
    /// A body below the string threshold names none and costs no read. Every
    /// after-image staged after the census began is queued by its own apply.
    fn take_census(&mut self, step: &Step<'_>, admission: &Arc<NodeAdmission>) -> Result<()> {
        if matches!(self.census, Census::Idle) {
            let Some(walk) = Walk::freeze(step.state, step.selection, admission)? else {
                return Ok(());
            };
            self.census = Census::Walking(walk);
        }
        // A zero threshold flushes every queued owner. An empty queue must
        // still walk the next descriptor, including after the last flush.
        if !self.registrations.is_empty()
            && self.registration_slots >= self.budgets.register_flush_digests
        {
            return Ok(());
        }
        let Census::Walking(mut walk) = std::mem::replace(&mut self.census, Census::Idle) else {
            unreachable!("census is walking")
        };
        let mut reads = self.budgets.census_reads;
        let outcome = walk.advance(self.budgets.walk_slots, |descriptor| {
            if descriptor.body_bytes < document_encoding::STRING_THRESHOLD as u64 {
                return Ok(true);
            }
            let marker = link_key(MARKER, step.scope, descriptor.body_object);
            if step
                .store
                .get_bounded(LINKS, &marker, MARKED.len())?
                .is_none()
                && let Some(blobs) = manifest_blobs(step, descriptor.body_object)?
                && !blobs.is_empty()
            {
                // Queue each successful visit before moving the cursor. A
                // later storage error must not lose a discovered owner.
                if !self.queue_registration(admission, descriptor.body_object, blobs) {
                    return Ok(false);
                }
            }
            reads = reads.saturating_sub(1);
            Ok(reads > 0 && self.registration_slots < self.budgets.register_flush_digests)
        });
        if !self.blobs_off {
            self.census = if walk.done {
                Census::Done
            } else {
                Census::Walking(walk)
            };
        }
        outcome?;
        Ok(())
    }

    /// Count each queued manifest that has no marker yet, in one transaction.
    fn register(&mut self, step: &Step<'_>) -> Result<()> {
        let mut points =
            step.store
                .read_view()?
                .prepare_point_reads(LINKS.len(), LINK_KEY_BYTES, 8)?;
        let batch = self.registration_batch(step.scope, &mut points);
        let (operations, taken, registered) = points.finish(batch)?;
        if !operations.is_empty() {
            step.store.write_batch(&operations)?;
            self.stats.transactions += 1;
            self.stats.registered += registered;
        }
        for registration in self.registrations.drain(..taken) {
            self.registration_slots -= registration.blobs.capacity();
        }
        Ok(())
    }

    /// The tenant apply lock excludes another link writer. Plan all counts
    /// against one authenticated root and close it before committing the batch.
    fn registration_batch(
        &self,
        scope: Scope,
        points: &mut PreparedTenantReadPoints,
    ) -> Result<(Vec<WriteOp>, usize, u64)> {
        let mut operations = Vec::new();
        let mut counts = BTreeMap::<Digest, u64>::new();
        let mut marked = BTreeSet::new();
        let mut registered = 0u64;
        let mut taken = 0;
        for registration in self.registrations.iter().take(self.budgets.register_bodies) {
            taken += 1;
            let marker = link_key(MARKER, scope, registration.body);
            if !marked.insert(registration.body)
                || points.get(LINKS, &marker, MARKED.len())?.is_some()
            {
                continue;
            }
            operations.push(WriteOp::put(LINKS, marker, MARKED));
            registered += 1;
            for blob in &registration.blobs {
                let count = match counts.get(blob) {
                    Some(count) => *count,
                    None => points
                        .get(LINKS, &link_key(COUNT, scope, *blob), 8)?
                        .map(decode_count)
                        .transpose()?
                        .unwrap_or(0),
                };
                counts.insert(
                    *blob,
                    count.checked_add(1).context("chunk owner count overflow")?,
                );
            }
        }
        for (blob, count) in &counts {
            operations.push(WriteOp::put(
                LINKS,
                link_key(COUNT, scope, *blob),
                count.to_be_bytes(),
            ));
        }
        Ok((operations, taken, registered))
    }

    /// Delete a bounded batch of verified manifests, their markers, and each
    /// chunk no manifest owns any more, in one transaction.
    ///
    /// A counted manifest releases its count of each chunk it names. A manifest
    /// displaced before the census began was never counted: it releases
    /// nothing, and a chunk it names goes with it only when no owner at all is
    /// registered. Either way no live manifest names a chunk deleted here,
    /// because every live manifest that can name one is counted before the
    /// first deletion; and none the selected snapshot names does, because
    /// that snapshot is at or beyond the state the census began with.
    fn delete(&mut self, step: &Step<'_>, admission: &Arc<NodeAdmission>) -> Result<()> {
        step.store.check_access()?;
        let cycle = self.cycle.as_ref().expect("deleting cycle");
        let batch = cycle
            .candidates
            .iter()
            .take(self.budgets.delete_bodies)
            .map(|(body, large)| (*body, *large))
            .collect::<Vec<_>>();
        let mut operations = Vec::new();
        let mut bodies = Vec::new();
        let mut released = BTreeMap::<Digest, u64>::new();
        for (body, large) in batch {
            if operations.len() + released.len().saturating_mul(2) >= self.budgets.delete_operations
                && !bodies.is_empty()
            {
                break;
            }
            if large && !self.blobs_off {
                let marker = link_key(MARKER, step.scope, body);
                let counted = step
                    .store
                    .get_bounded(LINKS, &marker, MARKED.len())?
                    .is_some();
                // A marker whose manifest row is absent releases nothing.
                for blob in manifest_blobs(step, body)?.unwrap_or_default() {
                    *released.entry(blob).or_default() += u64::from(counted);
                }
                if counted {
                    operations.push(WriteOp::delete(LINKS, marker));
                }
            }
            operations.push(WriteOp::delete(BODIES, step.scope.key(body)));
            bodies.push(body);
        }
        let mut blobs = Vec::new();
        for (blob, released) in released {
            let key = link_key(COUNT, step.scope, blob);
            match read_count(step, blob)? {
                // No registered owner, and none released here: unowned.
                None if released == 0 => {}
                // A count below its released owners is never trusted to free.
                None => continue,
                Some(count) => match count.checked_sub(released) {
                    Some(0) => operations.push(WriteOp::delete(LINKS, key)),
                    Some(remaining) => {
                        if released != 0 {
                            operations.push(WriteOp::put(LINKS, key, remaining.to_be_bytes()));
                        }
                        continue;
                    }
                    None => continue,
                },
            }
            operations.push(WriteOp::delete(BLOBS, step.scope.key(blob)));
            blobs.push(blob);
        }
        if !bodies.is_empty() {
            // Fenced before the transaction: an uncertain commit stays fenced.
            if !self.admit(
                admission,
                ((bodies.len() + blobs.len()) as u64).saturating_mul(72),
            ) {
                anyhow::bail!("document collection fence admission refused");
            }
            for body in &bodies {
                self.fence.insert((true, *body));
            }
            for blob in &blobs {
                self.fence.insert((false, *blob));
            }
            step.store.write_batch(&operations)?;
            self.stats.transactions += 1;
            self.stats.deleted_bodies += bodies.len() as u64;
            self.stats.deleted_blobs += blobs.len() as u64;
        }
        let cycle = self.cycle.as_mut().expect("deleting cycle");
        for body in &bodies {
            cycle.candidates.remove(body);
        }
        if cycle.candidates.is_empty() {
            self.cycle = None;
        }
        Ok(())
    }
}

fn read_count(step: &Step<'_>, blob: Digest) -> Result<Option<u64>> {
    let key = link_key(COUNT, step.scope, blob);
    step.store
        .get_bounded(LINKS, &key, 8)?
        .map(|value| decode_count(value.as_bytes()))
        .transpose()
}

fn decode_count(value: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        value.try_into().context("chunk owner count is malformed")?,
    ))
}

/// The distinct chunks the published manifest `body` names, or `None` when the
/// store holds no such row (a bootstrap object still in its staging).
fn manifest_blobs(step: &Step<'_>, body: Digest) -> Result<Option<Vec<Digest>>> {
    use sha2::Digest as _;
    let Some(wire) = step
        .store
        .get_bounded(BODIES, &step.scope.key(body), MAX_MANIFEST_BYTES)?
    else {
        return Ok(None);
    };
    let wire = wire.as_bytes();
    anyhow::ensure!(
        <[u8; 32]>::from(sha2::Sha256::digest(wire)) == body,
        "published document manifest identity differs"
    );
    let work = crate::snapshot_codec::inspect_external_json_work(wire, &mut || Ok(()))?;
    let _decode = step
        .store
        .plaintext_memory_owner()
        .clone()
        .reserve_document_decode(work)?;
    let manifest = BodyManifest::from_bytes(wire, document_store::limits(MAX_MANIFEST_BYTES)?)?;
    let mut blobs = manifest
        .blob_references()
        .map(|reference| reference.sha256)
        .collect::<Vec<_>>();
    blobs.sort_unstable();
    blobs.dedup();
    Ok(Some(blobs))
}

/// Every chunk owner row, for a restore that replaces the object namespaces.
pub(crate) fn clear_links(
    store: &Arc<TenantStore>,
    mut delete: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let view = store.read_view()?;
    let outcome = view.visit(LINKS, 16, |key, _| delete(key));
    let close = view.close();
    outcome?;
    close
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::{ChangeRecord, StoredDocument};

    #[tokio::test]
    async fn repeated_displacements_leave_room_for_a_distinct_manifest() -> Result<()> {
        let admission = NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
        let gc = ObjectGc::default();
        let mut state = gc.lock();
        for _ in 0..=MAX_PENDING {
            state.record_candidate(&admission, [1; 32], false);
        }
        state.record_candidate(&admission, [1; 32], true);
        state.record_candidate(&admission, [2; 32], false);
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending.get(&[1; 32]), Some(&true));
        assert_eq!(state.pending.get(&[2; 32]), Some(&false));
        assert_eq!(state.stats.dropped, 0);
        assert_eq!(state.footprint(), 2 * CANDIDATE_BYTES);
        Ok(())
    }

    #[test]
    fn collect_feed_resumes_inside_a_commit_after_budget_stop_and_failed_visit() -> Result<()> {
        let mut feed = Feed::default();
        for start in [1u64, 12] {
            let records = (start..start + 11)
                .map(|version| {
                    let id = version.to_string();
                    ChangeRecord {
                        collection: "docs".into(),
                        id: id.clone(),
                        document: Some(Arc::new(DocumentSlot::Stored(StoredDocument {
                            id,
                            version,
                            body_bytes: 1,
                            document_bytes: 1,
                            body_sha256: [0; 32],
                            body_object: [0; 32],
                            body_object_bytes: 1,
                            body_decode_work: 1,
                            body_manifest_work: 1,
                        }))),
                    }
                })
                .collect();
            feed.insert(
                start,
                Arc::new(ChangeCommit {
                    revision: start,
                    first_sequence: start,
                    records,
                    record_bytes: 0,
                }),
            );
        }
        let documents = feed
            .get(&1)
            .unwrap()
            .records
            .iter()
            .take(5)
            .map(|record| (record.id.clone(), record.document.clone().unwrap()))
            .collect();
        let mut walk = Walk {
            disk_documents: None,
            documents: vec![documents],
            disk_feed: None,
            _collection_roots: None,
            feed,
            collection: 0,
            after_document: None,
            after_commit: None,
            next_record: 0,
            documents_done: false,
            done: false,
        };
        let mut registered = Vec::new();
        let failure = walk.advance(10, |doc| {
            anyhow::ensure!(doc.version != 3, "original document census read failed");
            registered.push(doc.version);
            Ok(true)
        });
        assert_eq!(
            failure.unwrap_err().to_string(),
            "original document census read failed"
        );
        assert_eq!(registered, [1, 2]);
        walk.advance(2, |doc| {
            registered.push(doc.version);
            Ok(true)
        })?;
        walk.advance(1, |doc| {
            registered.push(doc.version);
            Ok(false)
        })?;
        assert_eq!(registered, [1, 2, 3, 4, 5]);
        // Advancing past the exhausted collection consumes one unit.
        walk.advance(1, |_| panic!("already registered document"))?;
        let mut visited = Vec::new();
        walk.advance(3, |doc| {
            visited.push(doc.version);
            Ok(true)
        })?;
        assert_eq!(visited, [1, 2, 3]);
        walk.advance(20, |doc| {
            visited.push(doc.version);
            Ok(false)
        })?;
        assert_eq!(visited, [1, 2, 3, 4]);
        let fail = walk.advance(20, |doc| {
            anyhow::ensure!(doc.version != 7, "original census read failed");
            visited.push(doc.version);
            Ok(true)
        });
        assert_eq!(fail.unwrap_err().to_string(), "original census read failed");
        while !walk.done {
            let before = visited.len();
            walk.advance(2, |doc| {
                visited.push(doc.version);
                Ok(true)
            })?;
            assert!(visited.len() - before <= 2);
        }
        assert_eq!(visited, (1..23).collect::<Vec<_>>());
        Ok(())
    }
}
