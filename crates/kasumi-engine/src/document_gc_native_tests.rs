//! Online collection of document objects through the real state machine over
//! real encrypted native rows: each entry is applied, each snapshot built and
//! each reopen restored as openraft drives them in production.
use super::*;
use crate::document_gc::{Budgets, LINKS};
use kasumi_types::{Command, RequestAuthorization, RequestContext};
use openraft::storage::{RaftSnapshotBuilder as _, RaftStateMachine as _};

/// One replica whose entries, snapshots and reopen go through its machine.
struct Replica {
    fixture: OrdinaryFixture,
    machine: kasumi_raft::StateMachine,
    /// Every committed command, by log index, for the replay after a reopen.
    log: Vec<(u64, Vec<u8>)>,
}

fn entry(index: u64, command: &[u8]) -> kasumi_raft::Entry<kasumi_raft::TypeConfig> {
    kasumi_raft::Entry {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        payload: openraft::EntryPayload::Normal(kasumi_raft::RaftCommand::application(
            command.to_vec(),
        )),
        initialization: None,
    }
}

#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
impl Replica {
    async fn open(
        fixture: &OrdinaryFixture,
    ) -> crate::test_fixture_failure::FixtureResult<kasumi_raft::StateMachine> {
        Ok(kasumi_raft::StateMachine::open(
            fixture.fixture.stores.clone(),
            fixture.engine.clone(),
            fixture.fixture._buffers.clone(),
        )
        .await?)
    }

    async fn new() -> crate::test_fixture_failure::FixtureResult<Self> {
        let fixture = OrdinaryFixture::new().await?;
        let machine = Self::open(&fixture).await?;
        Ok(Self {
            fixture,
            machine,
            log: Vec::new(),
        })
    }

    fn gc(&self) -> &crate::document_gc::ObjectGc {
        &self.fixture.engine.object_gc
    }

    fn store(&self) -> &Arc<kasumi_store::TenantStore> {
        self.fixture.fixture.stores.application()
    }

    /// Commit `operation` as the next entry; it must succeed.
    async fn commit(
        &mut self,
        operation: Operation,
    ) -> crate::test_fixture_failure::FixtureResult<()> {
        let generation = self.fixture.engine.generation()?;
        let revision = generation.state.revision + 1;
        let index = revision - generation.state.revision_base;
        drop(generation);
        let command = serde_json::to_vec(&Command {
            context: RequestContext {
                authorization: RequestAuthorization::service_identity(),
                principal: "owner".into(),
                tenant: TENANT.into(),
                scopes: [Action::Read, Action::Write, Action::Admin]
                    .into_iter()
                    .collect(),
                request_id: format!("object-collection-{revision}"),
            },
            timestamp_ms: revision,
            operation,
        })
        .map_err(anyhow::Error::from)?;
        self.log.push((index, command.clone()));
        let responses = self
            .machine
            .apply([entry(index, &command)])
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&responses[0])
            .map_err(anyhow::Error::from)?
            .map_err(anyhow::Error::from)?;
        Ok(())
    }

    /// Build and publish this replica's own snapshot at its last entry. The
    /// next publication's selection is the first to carry it.
    async fn snapshot(&mut self) -> crate::test_fixture_failure::FixtureResult<()> {
        let mut builder = self.machine.get_snapshot_builder().await;
        builder
            .build_snapshot()
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(())
    }

    /// A snapshot, then one entry that names no new object: its publication
    /// selects the snapshot, so collection may delete what it verified.
    async fn checkpoint(&mut self) -> crate::test_fixture_failure::FixtureResult<()> {
        self.snapshot().await?;
        let key = format!("checkpoint-{}", self.log.len());
        self.commit(put(&key, "checkpoint", "x".into())).await
    }

    /// Checkpoints until collection has nothing left that a later snapshot
    /// could release: each one covers what the previous one verified.
    async fn settle(&mut self) -> crate::test_fixture_failure::FixtureResult<()> {
        for _ in 0..3 {
            self.checkpoint().await?;
            self.collect();
        }
        assert!(self.gc().idle());
        Ok(())
    }

    /// Run collection steps until nothing changes any more.
    fn collect(&self) {
        let mut quiet = 0;
        let mut before = self.gc().stats();
        for _ in 0..100_000 {
            self.fixture.engine.object_gc_step();
            let after = self.gc().stats();
            quiet = if after == before { quiet + 1 } else { 0 };
            before = after;
            if self.gc().idle() || quiet > 64 {
                break;
            }
        }
        assert_eq!(self.gc().last_error(), None);
    }

    /// What a restart does: reopen the machine, which restores the engine
    /// from the stored snapshot, then replay every entry after it.
    async fn reopen(self) -> crate::test_fixture_failure::FixtureResult<Self> {
        let Self {
            fixture,
            machine,
            log,
        } = self;
        drop(machine);
        let fixture = fixture.reopen().await?;
        let mut machine = Self::open(&fixture).await?;
        let (applied, _) = machine
            .applied_state()
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let applied = applied.map_or(0, |log| log.index);
        for (index, command) in log.iter().filter(|(index, _)| *index > applied) {
            machine
                .apply([entry(*index, command)])
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
        }
        Ok(Self {
            fixture,
            machine,
            log,
        })
    }

    /// The objects a new replica holds after installing this one's state:
    /// exactly what its documents and retained change after-images name.
    async fn named_objects(&self) -> crate::test_fixture_failure::FixtureResult<Published<usize>> {
        let (meta, image) = leader_snapshot(&self.fixture)?;
        let follower = OrdinaryFixture::replica(&self.fixture).await?;
        install(&follower, &meta, image).await?;
        let objects = published(follower.fixture.stores.application(), <[u8]>::len)?;
        follower.close().await?;
        Ok(objects)
    }

    async fn close(self) -> crate::test_fixture_failure::FixtureResult<()> {
        drop(self.machine);
        self.fixture.close().await
    }
}

/// Text that is neither hex nor base64: `shared` bytes every document of a
/// test has in common, then `own` bytes only `ordinal` has.
fn text(shared: usize, ordinal: u64, own: usize) -> String {
    let letters = |seed: u64, bytes: usize| {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..bytes)
            .map(move |_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"ghijklmnopqrstuvwxyz.,;:"[(state % 24) as usize] as char
            })
            .collect::<String>()
    };
    letters(u64::MAX, shared) + &letters(ordinal + 1, own)
}

fn delete(key: &str, id: &str) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Delete {
            collection: "docs".into(),
            id: id.into(),
            expected: Precondition::Any,
        }],
    })
}

fn rows(store: &Arc<kasumi_store::TenantStore>, namespace: &str) -> Result<Published<Vec<u8>>> {
    let mut rows = Published::new();
    let view = store.read_view()?;
    view.visit(namespace, 32 << 20, |key, row| {
        rows.insert((namespace_name(namespace), key.to_vec()), row.to_vec());
        Ok(())
    })?;
    view.close()?;
    Ok(rows)
}

fn namespace_name(namespace: &str) -> &'static str {
    match namespace {
        BODIES => BODIES,
        BLOBS => BLOBS,
        _ => LINKS,
    }
}

/// The chunk owner rows the published manifests call for: a marker for each
/// manifest that names a chunk, and for each such chunk the number of
/// manifests naming it. Every named chunk must be published.
fn expected_owners(store: &Arc<kasumi_store::TenantStore>) -> Result<Published<Vec<u8>>> {
    let bodies = rows(store, BODIES)?;
    let blobs = rows(store, BLOBS)?;
    let mut expected = Published::new();
    let mut counts = BTreeMap::<Vec<u8>, u64>::new();
    for ((_, key), wire) in &bodies {
        let manifest = crate::document_encoding::BodyManifest::from_bytes(
            wire,
            crate::document_store::limits(32 << 20)?,
        )?;
        let mut named = manifest
            .blob_references()
            .map(|reference| reference.sha256)
            .collect::<Vec<_>>();
        named.sort_unstable();
        named.dedup();
        if named.is_empty() {
            continue;
        }
        expected.insert((LINKS, [&[1u8][..], key.as_slice()].concat()), vec![1]);
        for digest in named {
            let chunk = [&key[..32], &digest[..]].concat();
            assert!(
                blobs.contains_key(&(BLOBS, chunk.clone())),
                "named chunk missing"
            );
            *counts
                .entry([&[0u8][..], chunk.as_slice()].concat())
                .or_default() += 1;
        }
    }
    for (key, count) in counts {
        expected.insert((LINKS, key), count.to_be_bytes().to_vec());
    }
    Ok(expected)
}

/// Every published manifest that names a chunk is counted exactly once.
fn assert_owners_exact(store: &Arc<kasumi_store::TenantStore>) -> Result<()> {
    assert_eq!(rows(store, LINKS)?, expected_owners(store)?);
    Ok(())
}

/// No owner row outlives its manifest, and no chunk is counted beyond the
/// manifests that name it: counting may lag, it never leads.
fn assert_no_stale_owner(store: &Arc<kasumi_store::TenantStore>) -> Result<()> {
    let expected = expected_owners(store)?;
    for (key, value) in rows(store, LINKS)? {
        assert!(
            expected
                .get(&key)
                .is_some_and(|expected| value <= *expected),
            "stale chunk owner row"
        );
    }
    Ok(())
}

fn tiny_budgets() -> Budgets {
    Budgets {
        walk_slots: 2,
        census_reads: 1,
        register_bodies: 1,
        register_flush_digests: 0,
        delete_bodies: 1,
        delete_operations: 4096,
    }
}

/// Owners are counted as soon as a step runs, so the rows can be compared.
fn eager_budgets() -> Budgets {
    Budgets {
        register_flush_digests: 0,
        ..Budgets::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_gc_native_keeps_shared_chunks_until_their_last_manifest_is_collected()
-> crate::test_fixture_failure::FixtureResult<()> {
    // Two full 48 KiB chunks in common, then each document's own tail.
    const SHARED: usize = 2 * 48 * 1024;
    let (first, second) = (text(SHARED, 1, 60_000), text(SHARED, 2, 60_000));
    let mut replica = Replica::new().await?;
    replica.gc().set_budgets(eager_budgets());
    replica.commit(Operation::SetLimits(feed_events(1))).await?;
    replica
        .commit(Operation::CreateCollection(definition()))
        .await?;
    replica.commit(put("x", "x", first.clone())).await?;
    replica.commit(put("y", "y", second.clone())).await?;
    let store = replica.store().clone();
    let both = published(&store, <[u8]>::len)?;
    // The feed trimmed x, but its live document still names the manifest.
    // Inserting and replaying this prefix needs no collection transaction.
    assert_eq!(replica.gc().stats().cycles, 0);
    assert_eq!(replica.gc().stats().transactions, 0);
    assert!(rows(&store, LINKS)?.is_empty());
    let chunks = |objects: &Published<usize>| {
        objects
            .keys()
            .filter(|(namespace, _)| *namespace == BLOBS)
            .count()
    };
    // Each manifest names four chunks, two of them the other's too.
    assert_eq!((both.len(), chunks(&both)), (8, 6));

    // A reader that selected its root before the deletion keeps every object.
    let reader = replica.fixture.engine.generation()?;
    replica.commit(delete("drop-x", "x")).await?;
    replica.collect();
    // Verified, but the selected snapshot still names the deleted document.
    assert_eq!(published(&store, <[u8]>::len)?, both);
    assert!(replica.gc().awaiting_snapshot().is_some());

    replica.checkpoint().await?;
    replica.collect();
    let stats = replica.gc().stats();
    assert_eq!((stats.deleted_bodies, stats.deleted_blobs), (1, 2));
    let remaining = published(&store, <[u8]>::len)?;
    assert_eq!(remaining, replica.named_objects().await?);
    assert_eq!(chunks(&remaining), 4);
    assert_owners_exact(&store)?;
    let current = replica.fixture.engine.generation()?;
    assert_eq!(served(&current, "y")?, second);
    assert_eq!(served(&reader, "x")?, first);
    assert_eq!(served(&reader, "y")?, second);
    drop(current);
    drop(reader);

    // The last manifest naming the shared chunks takes them with it.
    replica.commit(delete("drop-y", "y")).await?;
    replica.checkpoint().await?;
    replica.collect();
    let stats = replica.gc().stats();
    assert_eq!((stats.deleted_bodies, stats.deleted_blobs), (2, 6));
    assert_eq!(
        published(&store, <[u8]>::len)?,
        replica.named_objects().await?
    );
    assert!(rows(&store, LINKS)?.is_empty());

    // No generation was published since that deletion: the selection the
    // next apply reads still holds every row of `y`. The fence makes it write
    // them again instead of publishing a descriptor of deleted objects.
    assert!(replica.gc().fence_len() >= 5);
    replica.commit(put("again", "y", second.clone())).await?;
    assert_eq!(replica.gc().fence_len(), 0);
    let current = replica.fixture.engine.generation()?;
    assert_eq!(served(&current, "y")?, second);
    drop(current);
    replica.collect();
    assert_eq!(
        published(&store, <[u8]>::len)?,
        replica.named_objects().await?
    );
    replica.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_gc_native_churn_reaches_a_plateau_across_snapshots()
-> crate::test_fixture_failure::FixtureResult<()> {
    const DOCUMENTS: u64 = 6;
    const ROUNDS: u64 = 9;
    let mut replica = Replica::new().await?;
    // The feed keeps four after-images, so trimming displaces descriptors too.
    replica.commit(Operation::SetLimits(feed_events(4))).await?;
    replica
        .commit(Operation::CreateCollection(definition()))
        .await?;
    let store = replica.store().clone();
    let mut sizes = Vec::new();
    let mut written = std::collections::BTreeSet::new();
    for round in 0..ROUNDS {
        // Every round replaces each document's body and both of its chunks;
        // collection runs after each entry, as it does in production.
        for ordinal in 0..DOCUMENTS {
            let id = format!("churn-{ordinal}");
            let body = text(0, round * DOCUMENTS + ordinal, 60_000);
            replica
                .commit(put(&format!("{round}-{ordinal}"), &id, body))
                .await?;
            written.extend(published(&store, <[u8]>::len)?.into_keys());
        }
        replica.snapshot().await?;
        sizes.push(published(&store, <[u8]>::len)?.len());
    }
    // Three objects per body version: without collection 162 would remain.
    assert_eq!(written.len() as u64, 3 * DOCUMENTS * ROUNDS);
    let live = 3 * DOCUMENTS as usize;
    let plateau = sizes[3..].iter().copied().max().unwrap();
    assert!(
        plateau <= 3 * live && sizes[ROUNDS as usize - 1] <= sizes[3],
        "published objects kept growing: {sizes:?}"
    );
    assert!(replica.gc().stats().deleted_bodies >= DOCUMENTS * (ROUNDS - 4));

    // Once the last round is covered, only what the state names remains.
    replica.settle().await?;
    let remaining = published(&store, <[u8]>::len)?;
    assert_eq!(remaining, replica.named_objects().await?);
    assert_eq!(remaining.len(), live + 1);
    let current = replica.fixture.engine.generation()?;
    for ordinal in 0..DOCUMENTS {
        assert_eq!(
            served(&current, &format!("churn-{ordinal}"))?,
            text(0, (ROUNDS - 1) * DOCUMENTS + ordinal, 60_000)
        );
    }
    drop(current);
    replica.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_gc_native_interrupted_collection_resumes_after_a_reopen()
-> crate::test_fixture_failure::FixtureResult<()> {
    const DOCUMENTS: u64 = 6;
    const SHARED: usize = 48 * 1024;
    let body = |round: u64, ordinal: u64| text(SHARED, round * DOCUMENTS + ordinal, 60_000);
    let mut replica = Replica::new().await?;
    // One manifest, one owner and two slots per transaction or step.
    replica.gc().set_budgets(tiny_budgets());
    replica.commit(Operation::SetLimits(feed_events(1))).await?;
    replica
        .commit(Operation::CreateCollection(definition()))
        .await?;
    for round in 0..2 {
        for ordinal in 0..DOCUMENTS {
            let id = format!("resume-{ordinal}");
            replica
                .commit(put(
                    &format!("{round}-{ordinal}"),
                    &id,
                    body(round, ordinal),
                ))
                .await?;
        }
    }
    let store = replica.store().clone();
    let serves = |replica: &Replica, round: u64| -> Result<()> {
        let current = replica.fixture.engine.generation()?;
        for ordinal in 0..DOCUMENTS {
            assert_eq!(
                served(&current, &format!("resume-{ordinal}"))?,
                body(round, ordinal)
            );
        }
        Ok(())
    };
    // The first snapshot covers every overwrite: what was verified before it
    // is deleted, and the rest is verified and waits for the next snapshot.
    replica.checkpoint().await?;
    replica.collect();
    let waiting = replica.gc().stats();
    let garbage = published(&store, <[u8]>::len)?.len() - replica.named_objects().await?.len();
    // At least three superseded manifests, each with its two own chunks.
    assert!(garbage >= 9, "only {garbage} superseded objects remain");
    assert!(replica.gc().awaiting_snapshot().is_some());

    // The second snapshot releases them, one manifest per transaction. Stop
    // after the first of those transactions.
    replica.checkpoint().await?;
    let mut steps = 0;
    while replica.gc().stats().deleted_bodies == waiting.deleted_bodies {
        replica.fixture.engine.object_gc_step();
        steps += 1;
        assert!(steps < 10_000, "collection made no progress");
    }
    assert_eq!(replica.gc().last_error(), None);
    let interrupted = replica.gc().stats();
    assert_eq!(interrupted.deleted_bodies, waiting.deleted_bodies + 1);
    // That transaction left the store whole: every document is served, every
    // object the state names is present, and no owner row is stale. Other
    // superseded objects are still there.
    serves(&replica, 1)?;
    let partial = published(&store, <[u8]>::len)?;
    let named = replica.named_objects().await?;
    assert!(named.keys().all(|key| partial.contains_key(key)));
    assert!(partial.len() >= named.len() + 6);
    assert_no_stale_owner(&store)?;

    // The process dies here. Its restart restores the stored snapshot, which
    // reconciles both object namespaces, and replays the entry after it.
    drop(store);
    replica = replica.reopen().await?;
    replica.gc().set_budgets(tiny_budgets());
    let store = replica.store().clone();
    assert_eq!(published(&store, <[u8]>::len)?, named);
    assert_no_stale_owner(&store)?;
    serves(&replica, 1)?;

    // Collection resumes with the entries that follow the restart.
    for ordinal in 0..DOCUMENTS {
        let id = format!("resume-{ordinal}");
        replica
            .commit(put(&format!("2-{ordinal}"), &id, body(2, ordinal)))
            .await?;
    }
    replica.settle().await?;
    assert!(replica.gc().stats().deleted_bodies >= DOCUMENTS);
    assert_eq!(
        published(&store, <[u8]>::len)?,
        replica.named_objects().await?
    );
    assert_owners_exact(&store)?;
    serves(&replica, 2)?;

    // A restart forgets every chunk owner. The first entry after this one
    // displaces a manifest before any owner is counted again: its own chunks
    // still go with it, and the chunk the other documents share stays.
    replica.snapshot().await?;
    drop(store);
    replica = replica.reopen().await?;
    replica.gc().set_budgets(tiny_budgets());
    let store = replica.store().clone();
    assert!(rows(&store, LINKS)?.is_empty());
    let before = replica.gc().stats();
    replica
        .commit(delete("drop-after-restart", "resume-0"))
        .await?;
    replica.settle().await?;
    let after = replica.gc().stats();
    assert_eq!(after.deleted_bodies, before.deleted_bodies + 1);
    assert_eq!(after.deleted_blobs, before.deleted_blobs + 2);
    assert_eq!(
        published(&store, <[u8]>::len)?,
        replica.named_objects().await?
    );
    assert_owners_exact(&store)?;
    let current = replica.fixture.engine.generation()?;
    for ordinal in 1..DOCUMENTS {
        assert_eq!(
            served(&current, &format!("resume-{ordinal}"))?,
            body(2, ordinal)
        );
    }
    drop(current);
    replica.close().await
}
