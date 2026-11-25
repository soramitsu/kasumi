//! Measures how long one production-budget maintenance step keeps a real
//! node-disk database, and how many retained-descriptor verifications it
//! pays. The automatic node worker runs `run_maintenance` with exactly this
//! budget (`cache_warmer::MAINTENANCE_BUDGET`); while a step runs no tenant
//! write or read can proceed, so its duration is a foreground stall.
//!
//! `cargo test --release -p kasumi-store maintenance_step_benchmark -- \
//!   --ignored --nocapture`; `KASUMI_BENCH_ROWS` sets the table size.
use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use kasumi_kv::{CacheConfig, Core, MaintenanceBudget, Operation, StorageCompactionPhase};
use std::{collections::BTreeMap, env, time::Instant};

const ID: Uuid = Uuid::from_u128(0x5e1f_0a11_7a1c_4c3e_9d2b_b0c4_11e5_57e9);
const GROUP: [u8; 16] = [0x63; 16];
const TABLE: &str = "bench";
const BATCH: usize = 2_000;
/// `cache_warmer::MAINTENANCE_BUDGET`.
const WORKER_BUDGET: MaintenanceBudget = MaintenanceBudget {
    units: 512,
    mutations: 1,
};

fn key(index: usize) -> Vec<u8> {
    format!("account/{index:012}").into_bytes()
}

fn value(index: usize, round: u8) -> Vec<u8> {
    let mut bytes = vec![round; 48];
    bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
    bytes
}

#[derive(Default)]
struct Phase {
    steps: usize,
    units: usize,
    nanos: Vec<u128>,
    verifications: Vec<u64>,
}

#[test]
#[ignore = "benchmark: run explicitly with --ignored --nocapture"]
fn maintenance_step_benchmark() {
    let rows: usize = env::var("KASUMI_BENCH_ROWS")
        .ok()
        .and_then(|rows| rows.parse().ok())
        .unwrap_or(200_000);
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let memory = TestDiskMemory::new(1 << 30, 8192);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let group = NodeSegmentGroup::retained_prepared(&path, ID, disk.clone(), 16);
    group.acquire_prepared(&NodeOpeningMode::Create).unwrap();
    let core =
        Core::create_with_backend(group.clone(), group.clone(), GROUP, CacheConfig::default())
            .unwrap();
    group.publish_ready().unwrap();
    core.commit(&[Operation::create_table(TABLE)]).unwrap();

    // Two full rounds: the second supersedes every value and every directory
    // page of the first, so the forced cycle evacuates, walks and reclaims.
    let ingest = Instant::now();
    for round in 0..2u8 {
        for start in (0..rows).step_by(BATCH) {
            let batch: Vec<_> = (start..(start + BATCH).min(rows))
                .map(|index| Operation::put(TABLE, key(index), value(index, round)))
                .collect();
            core.commit(&batch).unwrap();
        }
    }
    let ingest_ns = ingest.elapsed().as_nanos();

    let before = core.maintenance_status().unwrap();
    core.request_compaction().unwrap();
    let mut phases: BTreeMap<&'static str, Phase> = BTreeMap::new();
    let cycle = Instant::now();
    let reason = loop {
        let phase = core.maintenance_status().unwrap().phase.as_str();
        let verified = NodeDiskFile::descriptor_verifications_for_test();
        let started = Instant::now();
        let progress = core.run_maintenance(WORKER_BUDGET).unwrap();
        let nanos = started.elapsed().as_nanos();
        let entry = phases.entry(phase).or_default();
        entry.steps += 1;
        entry.units += progress.units;
        entry.nanos.push(nanos);
        entry
            .verifications
            .push(NodeDiskFile::descriptor_verifications_for_test() - verified);
        if let Some(deferral) = progress.deferred {
            break format!("deferred: {deferral:?}");
        }
        let status = core.maintenance_status().unwrap();
        if status.phase == StorageCompactionPhase::Idle
            && !status.requested
            && status.cycles_completed > before.cycles_completed
        {
            break "cycle_completed".to_owned();
        }
        if cycle.elapsed().as_secs() >= 300 {
            break "time_limit".to_owned();
        }
    };
    let cycle_ns = cycle.elapsed().as_nanos();
    let status = core.maintenance_status().unwrap();

    let mut report = serde_json::Map::new();
    for (name, phase) in &mut phases {
        let mut sorted = phase.nanos.clone();
        sorted.sort_unstable();
        let at = |q: f64| sorted[((sorted.len() - 1) as f64 * q).round() as usize] as f64 / 1e6;
        report.insert(
            (*name).to_owned(),
            serde_json::json!({
                "steps": phase.steps,
                "units": phase.units,
                "total_ms": sorted.iter().sum::<u128>() as f64 / 1e6,
                "p50_ms": at(0.5),
                "p99_ms": at(0.99),
                "max_ms": at(1.0),
                "verifications_total": phase.verifications.iter().sum::<u64>(),
                "verifications_max_step": phase.verifications.iter().max().copied().unwrap_or(0),
            }),
        );
    }
    println!(
        "MAINTENANCE_STEP_BENCHMARK {}",
        serde_json::json!({
            "rows": rows,
            "ingest_ms": ingest_ns as f64 / 1e6,
            "cycle_ms": cycle_ns as f64 / 1e6,
            "reason": reason,
            "reclaimed_files_total": status.reclaimed_files_total,
            "reclaimed_bytes_total": status.reclaimed_bytes_total,
            "relocated_bytes_total": status.relocated_bytes_total,
            "phases_at_step_start": report,
        })
    );
    assert_eq!(reason, "cycle_completed");
    assert!(status.reclaimed_files_total > 0);
    let snapshot = core.snapshot().unwrap();
    for index in [0, rows / 2, rows - 1] {
        let actual = core
            .get_admitted(&snapshot, TABLE, &key(index), 64)
            .unwrap()
            .unwrap();
        assert_eq!(actual.as_bytes(), value(index, 1).as_slice());
    }
    drop(snapshot);
    assert!(core.close().into_result().is_ok());
    let mut disposal = core.into_disposal();
    assert!(disposal.dispose().complete());
}
