//! Invoked in separate writer and reader processes by benchmarks/indexer-kv/run.mjs.
use super::*;
use crate::test_utils::{TestDiskMemory, retry_disk_registry};
use kasumi_kv::{CacheConfig, Core, Operation, ReadSnapshot, ScanDirection};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, ops::Bound, time::Instant};

const TABLE: &str = "indexer";
const ID: Uuid = Uuid::from_u128(0xa40e02e4_75b4_42ca_89fe_dbd2f262b08e);
const GROUP: [u8; 16] = [0x62; 16];
const CACHE_BYTES: u64 = 8 << 20;
type Bytes = Vec<u8>;

#[derive(serde::Deserialize)]
struct Batch {
    ops: Vec<Vec<String>>,
}

fn read_trace() -> (Vec<Vec<Operation>>, BTreeMap<Bytes, Bytes>) {
    let text = fs::read_to_string(env::var_os("INDEXER_KV_TRACE").unwrap()).unwrap();
    let mut expected = BTreeMap::new();
    let mut batches = Vec::new();
    for line in text.lines() {
        let batch: Batch = serde_json::from_str(line).unwrap();
        let mut writes = Vec::new();
        for op in batch.ops {
            match op.as_slice() {
                [put, key, value] if put == "put" => {
                    let key = hex::decode(key).unwrap();
                    let value = hex::decode(value).unwrap();
                    expected.insert(key.clone(), value.clone());
                    writes.push(Operation::put(TABLE, key, value));
                }
                [del, key] if del == "del" => {
                    let key = hex::decode(key).unwrap();
                    expected.remove(&key);
                    writes.push(Operation::delete(TABLE, key));
                }
                _ => panic!("invalid trace operation"),
            }
        }
        assert!(!writes.is_empty());
        batches.push(writes);
    }
    assert!(!expected.is_empty());
    (batches, expected)
}

#[derive(Clone, Copy)]
enum RangeMode {
    Seek(ScanDirection),
    DescendingCursor,
}

fn measure_ranges(
    snapshot: &ReadSnapshot,
    rows: &[(&Bytes, &Bytes)],
    max_value: usize,
    mode: RangeMode,
) -> u128 {
    let width = rows.len().min(8);
    let started = Instant::now();
    for index in 0..64 {
        let first = (index * 197) % (rows.len() - width + 1);
        let window = &rows[first..first + width];
        let direction = match mode {
            RangeMode::Seek(direction) => direction,
            RangeMode::DescendingCursor => {
                let mut cursor = snapshot
                    .descending_cursor(
                        TABLE,
                        Bound::Included(window[0].0),
                        Bound::Included(window[width - 1].0),
                        max_value,
                    )
                    .unwrap();
                for (key, value) in window.iter().rev() {
                    let (found, actual) = cursor.next_row().unwrap().expect("range ended early");
                    assert_eq!(found.as_bytes(), key.as_slice());
                    assert_eq!(actual.as_bytes(), value.as_slice());
                }
                continue;
            }
        };
        let mut last = None;
        let ascending = matches!(direction, ScanDirection::Ascending);
        for offset in 0..width {
            let mut low = Bound::Included(window[0].0.as_slice());
            let mut high = Bound::Included(window[width - 1].0.as_slice());
            if let Some(ref key) = last {
                let exclusive = Bound::Excluded(kasumi_kv::AdmittedValue::as_bytes(key));
                if ascending {
                    low = exclusive;
                } else {
                    high = exclusive;
                }
            }
            let (key, value) = snapshot
                .seek_admitted(TABLE, low, high, direction, max_value)
                .unwrap()
                .expect("range ended early");
            let expected = window[if ascending {
                offset
            } else {
                width - 1 - offset
            }];
            assert_eq!(key.as_bytes(), expected.0);
            assert_eq!(value.as_bytes(), expected.1);
            last = Some(key);
        }
    }
    started.elapsed().as_nanos()
}

// One page from the actual networkSnapshots compound type/timestamp index followed
// by point lookups of the corresponding full documents. Other traces can omit it.
fn latest_block_page(
    core: &Core,
    snapshot: &ReadSnapshot,
    expected: &BTreeMap<Bytes, Bytes>,
    max: usize,
    streaming: bool,
) -> Option<serde_json::Value> {
    let prefix = b"x\0networkSnapshots\0y-t\0BLOCK\0".as_slice();
    let upper = b"x\0networkSnapshots\0y-t\0BLOCK\x01".as_slice();
    let rows: Vec<_> = expected
        .range(prefix.to_vec()..upper.to_vec())
        .rev()
        .take(24)
        .collect();
    if rows.is_empty() {
        return None;
    }
    let mut digest = Sha256::new();
    let mut samples = [0u128; 64];
    let started = Instant::now();
    for (round, sample) in samples.iter_mut().enumerate() {
        let page_start = Instant::now();
        let mut cursor = streaming.then(|| {
            snapshot
                .descending_cursor(TABLE, Bound::Included(prefix), Bound::Excluded(upper), max)
                .unwrap()
        });
        let mut last: Option<kasumi_kv::AdmittedValue> = None;
        for (want_index, want_marker) in &rows {
            let high = last.as_ref().map_or(upper, |k| k.as_bytes());
            let (index, marker) = match &mut cursor {
                Some(cursor) => cursor.next_row(),
                None => snapshot.seek_admitted(
                    TABLE,
                    Bound::Included(prefix),
                    Bound::Excluded(high),
                    ScanDirection::Descending,
                    max,
                ),
            }
            .unwrap()
            .unwrap();
            assert_eq!(index.as_bytes(), *want_index);
            assert_eq!(marker.as_bytes(), *want_marker);
            let id = index.as_bytes().rsplit(|&b| b == 0).next().unwrap();
            let key = [b"d\0networkSnapshots\0".as_slice(), id].concat();
            let value = core
                .get_admitted(snapshot, TABLE, &key, max)
                .unwrap()
                .unwrap();
            assert_eq!(value.as_bytes(), &expected[&key]);
            if round == 0 {
                digest.update((key.len() as u32).to_be_bytes());
                digest.update(&key);
                digest.update((value.as_bytes().len() as u32).to_be_bytes());
                digest.update(value.as_bytes());
            }
            last = Some(index);
        }
        *sample = page_start.elapsed().as_nanos();
    }
    let elapsed = started.elapsed().as_nanos();
    samples.sort_unstable();
    Some(serde_json::json!({
        "ns": elapsed, "pages": samples.len(), "p50_ns": samples[31],
        "p95_ns": samples[60], "documents_per_page": rows.len(),
        "page_sha256": hex::encode(digest.finalize()),
    }))
}

fn compact(core: &Core) -> serde_json::Value {
    let start = Instant::now();
    let before = core.maintenance_status().unwrap();
    core.request_compaction().unwrap();
    let mut steps = 0;
    let mut reclaimed = 0;
    let mut mutations = 0;
    let reason = loop {
        let progress = core
            .run_maintenance(kasumi_kv::MaintenanceBudget {
                units: 256,
                mutations: 16,
            })
            .unwrap();
        steps += 1;
        reclaimed += progress.reclaimed_bytes;
        mutations += progress.mutations;
        let status = core.maintenance_status().unwrap();
        if let Some(reason) = progress.deferred {
            break format!("deferred: {reason:?}");
        }
        if status.phase == kasumi_kv::StorageCompactionPhase::Idle && !status.requested {
            if status.cycles_completed > before.cycles_completed {
                break "cycle_completed".to_owned();
            }
            if progress.idle {
                break "nothing_eligible".to_owned();
            }
        }
        if start.elapsed().as_secs() >= 60 || steps >= 100_000 {
            break "budget".to_owned();
        }
    };
    serde_json::json!({"maintenance_ns":start.elapsed().as_nanos(), "reason":reason,
        "steps":steps, "mutations":mutations, "reclaimed_bytes":reclaimed,
        "phase":core.maintenance_status().unwrap().phase.as_str(),
        "initial_completed_cycles": before.cycles_completed,
        "final_completed_cycles": core.maintenance_status().unwrap().cycles_completed})
}

#[test]
#[ignore = "requires an isolated directory and external trace from the benchmark runner"]
fn paired_indexer_storage() {
    let (batches, expected) = read_trace();
    let path = std::path::PathBuf::from(env::var_os("INDEXER_KV_DB").unwrap());
    let memory = TestDiskMemory::new(512 << 20, 8192);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let group = NodeSegmentGroup::retained_prepared(&path, ID, disk.clone(), 16);
    let phase = env::var("INDEXER_KV_PHASE").unwrap();
    let cache = CacheConfig {
        byte_limit: CACHE_BYTES,
    };
    let started = Instant::now();
    let (core, mut report) = if phase == "write" {
        assert!(!path.exists(), "benchmark requires a fresh group");
        group.acquire_prepared(&NodeOpeningMode::Create).unwrap();
        let format_name =
            env::var("INDEXER_KV_DIRECTORY_FORMAT").unwrap_or_else(|_| "fixed".into());
        let format = match format_name.as_str() {
            "fixed" => kasumi_kv::DirectoryPageFormat::Fixed,
            "lz4" => kasumi_kv::DirectoryPageFormat::Lz4,
            other => panic!("unsupported benchmark directory format: {other}"),
        };
        let core = Core::create_with_backend_and_format(
            group.clone(),
            group.clone(),
            GROUP,
            cache,
            format,
        )
        .unwrap();
        group.publish_ready().unwrap();
        core.commit(&[Operation::create_table(TABLE)]).unwrap();
        let inline = env::var("INDEXER_KV_MAINTENANCE").as_deref() == Ok("inline");
        let policy = kasumi_kv::MaintenancePolicy::default();
        let budget = kasumi_kv::MaintenanceBudget {
            units: policy.inline_units,
            mutations: policy.inline_mutations,
        };
        let (mut mutations, mut deferrals, mut reclaimed_bytes) = (0, 0, 0);
        let before = disk.physical_synchronizations();
        let started = Instant::now();
        for batch in batches {
            if inline {
                let work = core.run_maintenance(budget).unwrap();
                mutations += work.mutations;
                deferrals += usize::from(work.deferred.is_some());
                reclaimed_bytes += work.reclaimed_bytes;
            }
            core.commit(&batch).unwrap();
        }
        let elapsed = started.elapsed().as_nanos();
        let after = disk.physical_synchronizations();
        (
            core,
            serde_json::json!({
                "ingest_ns": elapsed, "ordering_syncs": after.0 - before.0, "device_syncs": after.1 - before.1,
                "directory_page_format": format_name, "inline_maintenance": inline, "maintenance_publications": mutations,
                "maintenance_deferrals": deferrals, "maintenance_reclaimed_bytes": reclaimed_bytes,
            }),
        )
    } else {
        group.acquire_prepared(&NodeOpeningMode::Existing).unwrap();
        let core = Core::open_with_backend(group.clone(), group.clone(), GROUP, cache).unwrap();
        let open_ns = started.elapsed().as_nanos();
        if phase == "maintenance" {
            let progress = compact(&core);
            (core, progress)
        } else {
            let snapshot = core.snapshot().unwrap();
            let rows: Vec<_> = expected.iter().collect();
            let max_value = rows.iter().map(|(_, v)| v.len()).max().unwrap().max(1);
            let started = Instant::now();
            for i in 0..1024 {
                let (key, value) = rows[(i * 197) % rows.len()];
                let actual = core
                    .get_admitted(&snapshot, TABLE, key, max_value)
                    .unwrap()
                    .unwrap();
                assert_eq!(actual.as_bytes(), value);
            }
            let point_ns = started.elapsed().as_nanos();
            let forward_ns = measure_ranges(
                &snapshot,
                &rows,
                max_value,
                RangeMode::Seek(ScanDirection::Ascending),
            );
            let reverse_ns = measure_ranges(
                &snapshot,
                &rows,
                max_value,
                RangeMode::Seek(ScanDirection::Descending),
            );
            let reverse_cursor_ns =
                measure_ranges(&snapshot, &rows, max_value, RangeMode::DescendingCursor);
            let latest_seek = latest_block_page(&core, &snapshot, &expected, max_value, false);
            let latest = latest_block_page(&core, &snapshot, &expected, max_value, true);
            assert_eq!(
                latest_seek.as_ref().map(|v| &v["page_sha256"]),
                latest.as_ref().map(|v| &v["page_sha256"])
            );
            // Compare every row and ensure there are no unanticipated extra rows.
            let mut prior: Option<kasumi_kv::AdmittedValue> = None;
            for (key, value) in &rows {
                let (found, actual) = core
                    .next_admitted(
                        &snapshot,
                        TABLE,
                        b"",
                        prior.as_ref().map(|p| p.as_bytes()),
                        max_value,
                    )
                    .unwrap()
                    .expect("lost committed row");
                assert_eq!(found.as_bytes(), key.as_slice());
                assert_eq!(actual.as_bytes(), value.as_slice());
                prior = Some(found);
            }
            assert!(
                core.next_admitted(
                    &snapshot,
                    TABLE,
                    b"",
                    prior.as_ref().map(|p| p.as_bytes()),
                    max_value
                )
                .unwrap()
                .is_none()
            );
            (
                core,
                serde_json::json!({
                    "open_ns": open_ns, "point_ns": point_ns, "forward_ns": forward_ns,
                    "reverse_seek_ns": reverse_ns, "reverse_ns": reverse_cursor_ns, "latest_seek": latest_seek, "verified_rows": rows.len(), "latest_blocks": latest,
                }),
            )
        }
    };
    if phase == "write" {
        use std::os::unix::fs::MetadataExt;
        let bytes: u64 = crate::test_utils::node_group_files(&path)
            .iter()
            .map(|file| fs::metadata(file).unwrap().blocks() * 512)
            .sum();
        report["allocated_before_close"] = serde_json::json!(bytes);
    }
    let started = Instant::now();
    core.close().into_result().unwrap();
    assert!(core.into_disposal().dispose().complete());
    report["close_ns"] = serde_json::json!(started.elapsed().as_nanos());
    fs::write(
        env::var_os("INDEXER_KV_REPORT").unwrap(),
        report.to_string(),
    )
    .unwrap();
}
