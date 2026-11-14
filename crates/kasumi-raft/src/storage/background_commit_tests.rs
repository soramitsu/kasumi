//! A standalone group's snapshot build and journal purge yield to the other
//! tenants of their node database between commits, and store exactly what
//! back-to-back commits store.
use super::*;
use crate::control::tests::{fixture, id};
use openraft::storage::RaftLogStorageExt;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

const LIMIT: u64 = 64 << 20;
/// Every durable synchronization of the slow disk.
const SLOW_SYNC: Duration = Duration::from_millis(3);

fn scratch() -> (tempfile::TempDir, Arc<kasumi_store::ScratchDisk>) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
    (directory, disk)
}

fn paced() -> (BackgroundCommits, Arc<AtomicBool>) {
    let closing = Arc::new(AtomicBool::new(false));
    (BackgroundCommits::Paced(closing.clone()), closing)
}

/// Another tenant of the same node database, committing one small row after
/// another: the foreground a background build must leave room for.
struct Neighbour {
    stop: Arc<AtomicBool>,
    done: Arc<AtomicUsize>,
    commits: std::thread::JoinHandle<Vec<(Instant, Instant)>>,
}
impl Neighbour {
    async fn start(node: &kasumi_store::NodeStore) -> Result<Self> {
        let store = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "neighbour".into(),
            Arc::new(LocalKeyProvider::new([33; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicUsize::new(0));
        let (stopped, counted) = (stop.clone(), done.clone());
        let commits = std::thread::spawn(move || {
            let mut commits = Vec::new();
            while !stopped.load(Ordering::Acquire) {
                let started = Instant::now();
                let key = (commits.len() as u64).to_be_bytes();
                store
                    .write_batch(&[put("neighbour", &key, vec![7; 64])])
                    .unwrap();
                commits.push((started, Instant::now()));
                counted.store(commits.len(), Ordering::Release);
                std::thread::sleep(Duration::from_millis(1));
            }
            commits
        });
        let neighbour = Self {
            stop,
            done,
            commits,
        };
        // Serving before the background work starts.
        neighbour.wait_for(1).await;
        Ok(neighbour)
    }

    async fn wait_for(&self, commits: usize) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while self.done.load(Ordering::Acquire) < commits {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the neighbouring tenant commits");
    }

    fn finish(self) -> Vec<(Instant, Instant)> {
        self.stop.store(true, Ordering::Release);
        self.commits.join().unwrap()
    }
}

/// The neighbour's commits that began while the background work ran: how
/// many, and the longest.
fn during(commits: &[(Instant, Instant)], from: Instant, to: Instant) -> (usize, Duration) {
    let within = commits
        .iter()
        .filter(|(started, _)| *started >= from && *started <= to);
    (
        within.clone().count(),
        within
            .map(|(started, ended)| ended.duration_since(*started))
            .max()
            .unwrap_or_default(),
    )
}

/// Stage, publish and clean up one snapshot image as a build does.
fn build(
    domains: &TenantStorageSet,
    bytes: &[u8],
    snapshot: &SnapshotEnvelope,
    commits: &BackgroundCommits,
) -> Result<()> {
    let image = SnapshotImage::from_bytes(domains.application().scratch_disk(), bytes)?;
    let pending = stage_snapshot(domains, &image, LIMIT, snapshot, commits)?;
    publish_snapshot(domains, pending, snapshot, None)?;
    cleanup_snapshots(domains.application(), LIMIT, commits)
}

/// The published manifest and every stored chunk, in order.
fn stored(store: &TenantStore) -> Result<(SnapshotManifest, Vec<Vec<u8>>)> {
    assert!(load_manifest(store, b"pending", LIMIT)?.is_none());
    assert!(load_manifest(store, b"obsolete", LIMIT)?.is_none());
    let manifest = load_manifest(store, b"current", LIMIT)?.context("published snapshot")?;
    let chunks = (0..manifest.chunks)
        .map(|index| {
            Ok(store
                .get(SNAPSHOT, &chunk_key(&manifest, index))?
                .context("stored snapshot chunk")?
                .to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((manifest, chunks))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn a_paced_snapshot_build_stores_what_a_direct_one_does_while_another_tenant_commits()
-> FixtureResult<()> {
    let (_directory, fixture_scratch) = scratch();
    // Two snapshots of more than one chunk each; the second replaces the
    // first, so its build also cleans up the first one's chunks.
    let first = envelope(
        vec![42; SNAPSHOT_CHUNK_BYTES + 12_345],
        fixture_scratch.clone(),
    );
    let mut second = envelope(
        vec![43; 2 * SNAPSHOT_CHUNK_BYTES + 678],
        fixture_scratch.clone(),
    );
    second.meta.last_log_id.as_mut().unwrap().index += 1;
    let images = [
        first.encode(LIMIT)?.read_bounded(LIMIT as usize)?,
        second.encode(LIMIT)?.read_bounded(LIMIT as usize)?,
    ];
    let custody_provider = || Arc::new(LocalKeyProvider::new([241; 32]));

    // The reference: every commit back to back, on a disk nothing else uses.
    let direct_store = new_fault_store(FaultBackend::new(), fixture_scratch.clone()).await?;
    let direct = kasumi_store::test_utils::initialize_custody_fixture(
        direct_store.clone(),
        custody_provider(),
    )
    .await?;
    for (snapshot, bytes) in [&first, &second].into_iter().zip(&images) {
        build(&direct, bytes, snapshot, &BackgroundCommits::Direct)?;
    }
    // A direct build is no paced unit.
    assert_eq!(
        direct_store.node_store().background_write_status(),
        Default::default()
    );

    // The same builds, paced, on a slow disk another tenant commits to.
    let disk = FaultBackend::new();
    let paced_store = new_fault_store(disk.clone(), fixture_scratch.clone()).await?;
    let node = paced_store.node_store().clone();
    let paced_domains = kasumi_store::test_utils::initialize_custody_fixture(
        paced_store.clone(),
        custody_provider(),
    )
    .await?;
    let neighbour = Neighbour::start(&node).await?;
    disk.slow_syncs(SLOW_SYNC);
    let (commits, _closing) = paced();
    let started = Instant::now();
    for (snapshot, bytes) in [&first, &second].into_iter().zip(&images) {
        build(&paced_domains, bytes, snapshot, &commits)?;
    }
    let ended = Instant::now();
    let neighbour_commits = neighbour.finish();
    disk.slow_syncs(Duration::ZERO);

    // What is stored does not depend on the pacing: the same manifest but
    // for its random identity, and the same chunks byte for byte.
    let (direct_manifest, direct_chunks) = stored(&direct_store)?;
    let (paced_manifest, paced_chunks) = stored(&paced_store)?;
    assert_eq!(
        (
            paced_manifest.version,
            &paced_manifest.sha256,
            paced_manifest.bytes,
            paced_manifest.chunks
        ),
        (
            direct_manifest.version,
            &direct_manifest.sha256,
            direct_manifest.bytes,
            direct_manifest.chunks
        )
    );
    assert_eq!(paced_manifest.chunks, 3);
    assert!(paced_chunks == direct_chunks, "stored chunks differ");
    assert!(paced_chunks.concat() == images[1], "stored image differs");
    for store in [&direct_store, &paced_store] {
        let loaded = load_snapshot(store, LIMIT)?.context("stored snapshot")?;
        assert_eq!(loaded.meta, second.meta);
        assert_eq!(loaded.backend.sha256(), second.backend.sha256());
        validate_snapshot_coverage(
            if Arc::ptr_eq(store, &direct_store) {
                &direct
            } else {
                &paced_domains
            },
            &loaded,
            LIMIT,
        )?;
    }

    // Every bounded commit of the paced builds was one unit of the node's
    // shared background stream: a pending marker and the chunks of each
    // build, then one cleanup batch and its marker for the first snapshot.
    let status = node.background_write_status();
    assert_eq!(status.units, (1 + 2) + (1 + 3) + 2);
    assert!(
        status.database_time >= status.longest_database_time
            && status.longest_database_time > Duration::ZERO,
        "{status:?}"
    );
    // The neighbour committed while the builds ran, the builds paused for
    // it, and none of its commits waited for more than a unit or two, with
    // a second of slack for a loaded machine.
    let (count, longest) = during(&neighbour_commits, started, ended);
    eprintln!(
        "paced snapshot builds beside another tenant: wall={:?} units={} database_time={:?} \
         longest_unit={:?} paced_delay={:?} neighbour_commits={count} longest_neighbour_commit={longest:?}",
        ended.duration_since(started),
        status.units,
        status.database_time,
        status.longest_database_time,
        status.paced_delay,
    );
    assert!(count > 0, "{status:?}");
    assert!(status.paced_delay > Duration::ZERO, "{status:?}");
    assert!(
        longest <= status.longest_database_time * 2 + Duration::from_secs(1),
        "longest={longest:?} {status:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn a_closing_group_finishes_its_snapshot_build_back_to_back() -> FixtureResult<()> {
    let (_directory, fixture_scratch) = scratch();
    let snapshot = envelope(vec![9; SNAPSHOT_CHUNK_BYTES + 1], fixture_scratch.clone());
    let bytes = snapshot.encode(LIMIT)?.read_bounded(LIMIT as usize)?;
    let store = new_fault_store(FaultBackend::new(), fixture_scratch.clone()).await?;
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let neighbour = Neighbour::start(store.node_store()).await?;
    let (commits, closing) = paced();
    assert!(commits.paced().is_some());
    assert!(BackgroundCommits::Direct.paced().is_none());
    // Shutdown set the flag: whatever the neighbour does, no commit of the
    // build is a paced unit any more, so the shutdown waits for no pause.
    closing.store(true, Ordering::Release);
    assert!(commits.paced().is_none());
    build(&domains, &bytes, &snapshot, &commits)?;
    neighbour.finish();
    assert_eq!(
        store.node_store().background_write_status(),
        Default::default()
    );
    let (manifest, chunks) = stored(&store)?;
    assert_eq!(manifest.chunks, 2);
    assert!(chunks.concat() == bytes);
    Ok(())
}

fn blank(index: u64) -> Entry<TypeConfig> {
    Entry {
        initialization: None,
        log_id: id(index),
        payload: EntryPayload::Blank,
    }
}

/// What a purge leaves: the journal's state and its remaining entries.
async fn journal(log: &mut LogStore) -> Result<(LogState<TypeConfig>, Vec<LogId<u64>>)> {
    let state = log.get_log_state().await?;
    let entries = log
        .get_log_reader()
        .await
        .try_get_log_entries(..)
        .await?
        .into_iter()
        .map(|entry| entry.log_id)
        .collect();
    Ok((state, entries))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paced_journal_purge_leaves_what_a_direct_one_does_while_another_tenant_commits()
-> Result<()> {
    let (_directory, fixture_scratch) = scratch();
    // The reference: a direct purge in chunks of three entries.
    let (direct_stores, _, _, mut direct) =
        fixture(FaultBackend::new(), true, fixture_scratch.clone()).await?;
    direct.blocking_append((0..=9).map(blank)).await?;
    direct
        .purge_original(id(6), BackgroundCommits::Direct, 2)
        .await?;
    let direct_node = direct_stores.application().node_store().clone();
    assert_eq!(direct_node.background_write_status(), Default::default());

    // The same purge, paced, on a slow disk another tenant commits to.
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk.clone(), true, fixture_scratch.clone()).await?;
    log.blocking_append((0..=9).map(blank)).await?;
    let node = stores.application().node_store().clone();
    let neighbour = Neighbour::start(&node).await?;
    disk.slow_syncs(SLOW_SYNC);
    let (commits, closing) = paced();
    let started = Instant::now();
    log.purge_original(id(6), commits.clone(), 2).await?;
    let ended = Instant::now();
    // Three chunks, each one unit of the purge's own stream.
    let status = node.background_write_status();
    assert_eq!(status.units, 3);
    let (state, entries) = journal(&mut log).await?;
    assert_eq!(state.last_purged_log_id, Some(id(6)));
    assert_eq!(state.last_log_id, Some(id(9)));
    assert_eq!(entries, (7..=9).map(id).collect::<Vec<_>>());
    assert_eq!((state, entries), journal(&mut direct).await?);

    // A purge of one chunk, as after every periodic snapshot, never pauses.
    let before = node.background_write_status();
    assert!(log.purge_local(id(7), &closing).await?);
    let single = node.background_write_status();
    assert_eq!(single.units, before.units + 1);
    assert_eq!(single.paced_delay, before.paced_delay);
    // A closing group purges back to back: no chunk is a paced unit.
    closing.store(true, Ordering::Release);
    log.purge_original(id(9), commits, 0).await?;
    assert_eq!(node.background_write_status().units, single.units);
    let neighbour_commits = neighbour.finish();
    disk.slow_syncs(Duration::ZERO);
    let (state, entries) = journal(&mut log).await?;
    assert_eq!(state.last_purged_log_id, Some(id(9)));
    assert!(entries.is_empty());
    let (count, longest) = during(&neighbour_commits, started, ended);
    eprintln!(
        "paced journal purge beside another tenant: wall={:?} units={} database_time={:?} \
         longest_unit={:?} paced_delay={:?} neighbour_commits={count} longest_neighbour_commit={longest:?}",
        ended.duration_since(started),
        status.units,
        status.database_time,
        status.longest_database_time,
        status.paced_delay,
    );
    // It survives a reopen exactly as a direct purge does.
    drop((log, stores, direct, direct_stores));
    let (_stores, _, _, mut reopened) = fixture(disk.crash(), false, fixture_scratch).await?;
    let state = reopened.get_log_state().await?;
    assert_eq!(state.last_purged_log_id, Some(id(9)));
    assert_eq!(state.last_log_id, Some(id(9)));
    Ok(())
}
