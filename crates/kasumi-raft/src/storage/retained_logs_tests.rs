use super::*;
use crate::control::tests::{fixture, id};
use kasumi_store::test_utils::{FaultBackend, TestDiskMemory, private_tempdir};
use openraft::storage::RaftLogStorageExt;
use std::collections::{BTreeMap, BTreeSet};

fn entry(index: u64) -> Entry<TypeConfig> {
    Entry {
        initialization: None,
        log_id: id(index),
        payload: EntryPayload::Blank,
    }
}
fn header(index: u64) -> LogHeader {
    let entry = entry(index);
    LogHeader::build(&entry, &encode_entry(&entry).unwrap())
        .unwrap()
        .0
}
fn scratch() -> (tempfile::TempDir, Arc<kasumi_store::ScratchDisk>) {
    let directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
    (directory, disk)
}

#[test]
fn authenticated_unique_header_fold_is_order_independent_and_checks_extreme_holes() -> Result<()> {
    let mut fold = HeaderFold::default();
    for index in [u64::MAX, u64::MAX - 2, u64::MAX - 1] {
        fold.observe(index, header(index))?;
    }
    let span = fold.finish()?.unwrap();
    assert_eq!(span.first, id(u64::MAX - 2));
    assert_eq!(span.last, id(u64::MAX));
    assert_eq!(
        span.intersect((Bound::Excluded(u64::MAX), Bound::Unbounded)),
        None
    );
    assert_eq!(span.intersect((Bound::Unbounded, Bound::Excluded(0))), None);
    assert_eq!(
        span.intersect((Bound::Included(u64::MAX - 1), Bound::Unbounded)),
        Some(u64::MAX - 1..=u64::MAX)
    );
    let mut hole = HeaderFold::default();
    hole.observe(0, header(0))?;
    hole.observe(u64::MAX, header(u64::MAX))?;
    assert!(hole.finish().unwrap_err().to_string().contains("hole"));
    assert!(HeaderFold::default().finish()?.is_none());
    Ok(())
}

#[test]
fn append_chunk_schedule_preserves_every_durable_connected_prefix() -> Result<()> {
    for old_first in 0..=4 {
        for old_last in old_first..=5 {
            for first in 0..=6 {
                for last in first..=6 {
                    let previous = Some(RetainedSpan {
                        first: id(old_first),
                        last: id(old_last),
                    });
                    let entries = (first..=last).map(entry).collect::<Vec<_>>();
                    let connected = first <= old_last + 1 && last + 1 >= old_first;
                    for (bytes, operations) in [
                        (APPEND_BATCH_BYTES / 2 + 1, 1),
                        (1, APPEND_BATCH_OPERATIONS / 2 + 1),
                        (1, 1),
                    ] {
                        let cursor = EntryBatches::new(previous, &entries);
                        if !connected {
                            assert!(cursor.is_err());
                            continue;
                        }
                        let mut cursor = cursor?;
                        let mut actual = (old_first..=old_last)
                            .map(|index| (index, id(index)))
                            .collect::<BTreeMap<_, _>>();
                        let mut visited = BTreeSet::new();
                        let mut current = previous;
                        while let Some(range) = cursor.next_with(|_| Ok((bytes, operations)))? {
                            for offset in range.clone() {
                                assert!(
                                    visited.insert(offset),
                                    "an incoming entry may publish only once"
                                );
                                let id = entries[offset].log_id;
                                actual.insert(id.index, id);
                            }
                            // Independent map oracle: each already-durable chunk
                            // must be contiguous, including reverse prefix growth.
                            let indices = actual.keys().copied().collect::<Vec<_>>();
                            assert!(indices.windows(2).all(|pair| pair[1] == pair[0] + 1));
                            current = Some(RetainedSpan::including(current, &entries[range])?);
                            assert_eq!(
                                current.unwrap().first,
                                *actual.first_key_value().unwrap().1
                            );
                            assert_eq!(current.unwrap().last, *actual.last_key_value().unwrap().1);
                        }
                        assert_eq!(visited.len(), entries.len());
                        assert_eq!(
                            actual.len(),
                            (old_last.max(last) - old_first.min(first) + 1) as usize
                        );
                    }
                }
            }
        }
    }
    assert!(EntryBatches::new(None, &[entry(0), entry(2)]).is_err());
    assert!(EntryBatches::new(None, &[entry(1), entry(1)]).is_err());
    Ok(())
}

#[tokio::test]
async fn streamed_log_inventory_reopens_and_cloned_readers_follow_exact_range_changes() -> Result<()>
{
    let (_directory, scratch) = scratch();
    let disk = FaultBackend::new();
    let (stores, _, _, mut log) = fixture(disk.clone(), true, scratch.clone()).await?;
    log.blocking_append((3..=5).map(entry)).await?;
    // A real prepend plus suffix crosses the cursor's forward/backward phase.
    log.blocking_append((0..=8).map(entry)).await?;
    assert_eq!(log.get_log_state().await?.last_log_id, Some(id(8)));
    let mut reader = log.get_log_reader().await;
    assert_eq!(
        reader
            .try_get_log_entries(2..=6)
            .await?
            .into_iter()
            .map(|entry| entry.log_id)
            .collect::<Vec<_>>(),
        (2..=6).map(id).collect::<Vec<_>>()
    );
    assert!(log.blocking_append([entry(10)]).await.is_err());
    assert!(log.blocking_append([entry(9), entry(8)]).await.is_err());
    assert_eq!(log.get_log_state().await?.last_log_id, Some(id(8)));
    log.save_committed(Some(id(3))).await?;
    assert!(log.truncate(id(3)).await.is_err());
    log.truncate(id(6)).await?;
    log.purge(id(1)).await?;
    assert_eq!(
        reader
            .try_get_log_entries(..)
            .await?
            .into_iter()
            .map(|entry| entry.log_id)
            .collect::<Vec<_>>(),
        (2..=5).map(id).collect::<Vec<_>>()
    );
    assert!(reader.try_get_log_entries(..2).await?.is_empty());
    assert!(reader.try_get_log_entries(6..).await?.is_empty());
    drop((reader, log, stores));
    let (stores, _, _, mut reopened) = fixture(disk.crash(), false, scratch).await?;
    let state = reopened.get_log_state().await?;
    assert_eq!(state.last_purged_log_id, Some(id(1)));
    assert_eq!(state.last_log_id, Some(id(5)));
    assert_eq!(
        reopened
            .try_get_log_entries(..)
            .await?
            .into_iter()
            .map(|entry| entry.log_id)
            .collect::<Vec<_>>(),
        (2..=5).map(id).collect::<Vec<_>>()
    );
    drop(reopened);
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn streamed_open_rejects_holes_malformed_keys_and_noncanonical_headers() -> Result<()> {
    let (_directory, scratch) = scratch();
    let (stores, _, _, mut log) = fixture(FaultBackend::new(), true, scratch).await?;
    log.blocking_append((0..=4).map(entry)).await?;
    let store = stores.custody().store();
    let key = 2u64.to_be_bytes();
    let original = store.get(HEADERS, &key)?.unwrap();
    store.write_batch(&[delete(HEADERS, key.to_vec())])?;
    assert!(
        LogStore::open(stores.clone(), 1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("hole")
    );
    kasumi_store::test_utils::FixtureWriteBatch::prepare(
        store,
        &[
            kasumi_store::test_utils::FixtureWrite::Put(HEADERS, &key, original.as_bytes()),
            kasumi_store::test_utils::FixtureWrite::Put(HEADERS, &[8, 9], original.as_bytes()),
        ],
    )?
    .write(store)?;
    assert!(
        LogStore::open(stores.clone(), 1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("invalid raft index key")
    );
    store.write_batch(&[
        delete(HEADERS, vec![8, 9]),
        put(HEADERS, &key, serde_json::to_vec(&header(3))?),
    ])?;
    assert!(
        LogStore::open(stores.clone(), 1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("key/index mismatch")
    );
    let alternate = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
        store,
        original.as_bytes(),
        b" ",
    )?;
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        store,
        HEADERS,
        &key,
        alternate.as_bytes(),
    )?;
    assert!(LogStore::open(stores.clone(), 1).await.is_err());
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        store,
        HEADERS,
        &key,
        original.as_bytes(),
    )?;
    let reopened = LogStore::open(stores.clone(), 1).await?;
    drop((reopened, log));
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn point_log_reads_check_internal_metadata_commitment_and_current_custody_access()
-> Result<()> {
    let (_directory, scratch) = scratch();
    let (stores, _, custody_provider, mut log) =
        fixture(FaultBackend::new(), true, scratch).await?;
    log.blocking_append((0..=2).map(entry)).await?;
    let key = 1u64.to_be_bytes();
    let original = stores.custody().store().get(HEADERS, &key)?.unwrap();
    let mut changed = header(1);
    changed.log_id = LogId::new(openraft::CommittedLeaderId::new(4, 1), 1);
    stores
        .custody()
        .store()
        .write_batch(&[put(HEADERS, &key, serde_json::to_vec(&changed)?)])?;
    assert!(log.try_get_log_entries(1..=1).await.is_err());
    kasumi_store::test_utils::write_plaintext_copy_for_fixture(
        stores.custody().store(),
        HEADERS,
        &key,
        original.as_bytes(),
    )?;
    assert_eq!(log.try_get_log_entries(1..=1).await?[0].log_id, id(1));
    custody_provider.revoke();
    // Provider revocation is observed by a real refresh. It does not revoke
    // an already-issued, unexpired lease on this fixture's stationary clock.
    assert!(stores.custody().store().refresh_lease().await.is_err());
    assert!(log.try_get_log_entries(1..=1).await.is_err());
    custody_provider.allow();
    stores.custody().store().refresh_lease().await?;
    assert_eq!(log.try_get_log_entries(1..=1).await?[0].log_id, id(1));
    drop(log);
    stores.shutdown().await?;
    Ok(())
}

#[test]
fn limited_read_prefix_accounts_exact_bytes_and_never_rejects_the_first_entry() -> Result<()> {
    let mut batch = ReadBatch::default();
    assert!(batch.admit(READ_BATCH_BYTES + 1)?);
    assert!(batch.full());
    assert!(!batch.admit(1)?);
    let mut batch = ReadBatch::default();
    assert!(batch.admit(READ_BATCH_BYTES / 2)?);
    assert!(!batch.admit(READ_BATCH_BYTES / 2 + 1)?);
    assert_eq!(batch.bytes, READ_BATCH_BYTES / 2);
    assert_eq!(batch.entries, 1);
    assert!(batch.admit(READ_BATCH_BYTES / 2)?);
    assert!(batch.full());
    Ok(())
}

#[tokio::test]
async fn limited_read_returns_bounded_ordered_prefixes_while_exact_reads_remain_complete()
-> Result<()> {
    let (_directory, scratch) = scratch();
    let (stores, _, custody_provider, mut log) =
        fixture(FaultBackend::new(), true, scratch).await?;
    let end = (2 * READ_BATCH_ENTRIES + 3) as u64;
    log.blocking_append((0..end).map(entry)).await?;
    assert_eq!(log.try_get_log_entries(0..end).await?.len(), end as usize);
    let mut start = 0;
    let mut batches = 0;
    while start < end {
        let entries = log.limited_get_log_entries(start, end).await?;
        assert!(!entries.is_empty());
        assert!(entries.len() <= READ_BATCH_ENTRIES);
        assert_eq!(entries.first().unwrap().log_id, id(start));
        for (offset, entry) in entries.iter().enumerate() {
            assert_eq!(entry.log_id, id(start + offset as u64));
        }
        start += entries.len() as u64;
        batches += 1;
    }
    assert_eq!(batches, 3);
    assert!(log.limited_get_log_entries(end, end).await?.is_empty());
    assert!(log.limited_get_log_entries(end, end + 1).await.is_err());
    log.purge(id(0)).await?;
    assert!(log.limited_get_log_entries(0, end).await.is_err());
    custody_provider.revoke();
    assert!(stores.custody().store().refresh_lease().await.is_err());
    assert!(log.limited_get_log_entries(1, end).await.is_err());
    custody_provider.allow();
    stores.custody().store().refresh_lease().await?;
    drop(log);
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn limited_read_accepts_full_size_entries_and_checks_each_returned_body() -> Result<()> {
    let (_directory, scratch) = scratch();
    let (stores, _, _, mut log) = fixture(FaultBackend::new(), true, scratch).await?;
    // Each body is within the unchanged 32 MiB Store record ceiling. A single
    // one exceeds half of the 48 MiB batch window, so both must be separate.
    let large = |index| Entry {
        initialization: None,
        log_id: id(index),
        payload: EntryPayload::Normal(crate::RaftCommand::application(vec![7; (32 << 20) - 64])),
    };
    for index in 0..2 {
        log.blocking_append([large(index)]).await?;
    }
    for index in 0..2 {
        let entries = log.limited_get_log_entries(index, 2).await?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].log_id, id(index));
        let EntryPayload::Normal(command) = &entries[0].payload else {
            panic!("expected complete application body");
        };
        assert_eq!(command.bytes().len(), (32 << 20) - 64);
        assert!(command.bytes().iter().all(|&byte| byte == 7));
    }
    let changed = encode_entry(&Entry {
        initialization: None,
        log_id: id(1),
        payload: EntryPayload::Normal(crate::RaftCommand::application(vec![8; 1])),
    })?;
    stores
        .application()
        .write_batch(&[put(LOG, &1u64.to_be_bytes(), changed)])?;
    assert!(log.limited_get_log_entries(1, 2).await.is_err());
    drop(log);
    stores.shutdown().await?;
    Ok(())
}
