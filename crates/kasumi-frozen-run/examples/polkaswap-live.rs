//! Isolated mutable replay worker for benchmarks/indexer-kv/run.mjs.
#[cfg(unix)]
#[path = "polkaswap_live/reads.rs"]
mod reads;
#[cfg(unix)]
#[path = "polkaswap_live/trace.rs"]
mod trace;

#[cfg(unix)]
use kasumi_frozen_run::LiveDb;
#[cfg(unix)]
use serde_json::{Value, json};
#[cfg(unix)]
use std::{
    env,
    error::Error,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(unix)]
use trace::Trace;

#[cfg(unix)]
fn allocated(path: &Path) -> io::Result<u64> {
    let mut bytes = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            bytes += allocated(&entry.path())?;
        } else if meta.is_file() {
            bytes += meta.blocks() * 512;
        } else {
            return Err(io::Error::other("non-regular database entry"));
        }
    }
    Ok(bytes)
}

#[cfg(unix)]
fn ingest(db: &mut LiveDb, trace: &Trace) -> io::Result<Value> {
    let batches = trace.writes();
    let before = db.stats();
    assert_eq!(before.sequence, 0);
    let started = Instant::now();
    for (index, batch) in batches.iter().enumerate() {
        assert_eq!(db.commit(batch)?, index as u64 + 1);
    }
    let ns = started.elapsed().as_nanos();
    let after = db.stats();
    let file_syncs = after.file_syncs - before.file_syncs;
    assert!(file_syncs >= batches.len() as u64);
    Ok(json!({"ingest_ns":ns, "device_syncs":file_syncs,
        "directory_syncs":after.directory_syncs - before.directory_syncs,
        "committed_batches":batches.len(), "committed_operations":batches.iter().map(Vec::len).sum::<usize>(),
        "inline_maintenance":true, "checkpoint_threshold_bytes":db.checkpoint_budget(),
        "maintenance_publications":after.checkpoints - before.checkpoints,
        "levels_after_ingest":after.levels, "level_bytes_written":after.level_bytes_written,
        "largest_flush_bytes":after.largest_flush_bytes,
        "pending_batches":after.sequence - after.base_sequence, "pending_bytes":after.pending_bytes,
        "delta_entries":after.delta_entries, "wal_bytes":after.wal_bytes}))
}

#[cfg(unix)]
fn maintain(db: &mut LiveDb) -> io::Result<Value> {
    let before = db.stats();
    let started = Instant::now();
    db.checkpoint()?;
    let ns = started.elapsed().as_nanos();
    let after = db.stats();
    assert_eq!(after.sequence, before.sequence);
    assert_eq!(after.base_sequence, after.sequence);
    assert_eq!(after.delta_entries, 0);
    let publications = after.checkpoints - before.checkpoints;
    Ok(
        json!({"maintenance_ns":ns, "reason":if publications == 0 {"nothing_eligible"} else {"completed"},
        "steps":1, "mutations":publications, "levels_before":before.levels, "levels_after":after.levels,
        "level_bytes_written":after.level_bytes_written - before.level_bytes_written, "pending_batches_before":before.sequence - before.base_sequence,
        "pending_bytes_before":before.pending_bytes, "wal_bytes_before":before.wal_bytes,
        "pending_batches":after.sequence - after.base_sequence, "pending_bytes":after.pending_bytes,
        "wal_bytes":after.wal_bytes, "device_syncs":after.file_syncs - before.file_syncs,
        "directory_syncs":after.directory_syncs - before.directory_syncs}),
    )
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn Error>> {
    let phase = env::var("INDEXER_KV_PHASE")?;
    let directory = PathBuf::from(env::var_os("INDEXER_KV_DB").ok_or("missing database path")?);
    let fixture = PathBuf::from(env::var_os("INDEXER_KV_TRACE").ok_or("missing trace path")?);
    let output = env::var_os("INDEXER_KV_REPORT").ok_or("missing report path")?;
    let trace = Trace::load(&fixture)?;
    let start = Instant::now();
    let mut db = match phase.as_str() {
        "write" => {
            if directory.try_exists()? {
                return Err("benchmark requires a fresh database".into());
            }
            LiveDb::create(&directory)?
        }
        "read" | "maintenance" | "reopen" => LiveDb::open(&directory)?,
        _ => return Err("unknown benchmark phase".into()),
    };
    let open_ns = start.elapsed().as_nanos();
    let initial = db.stats();
    let mut report = match phase.as_str() {
        "write" => {
            let mut report = ingest(&mut db, &trace)?;
            report["allocated_before_close"] = json!(allocated(&directory)?);
            report
        }
        "maintenance" => maintain(&mut db)?,
        _ => reads::measure(&mut db, &trace.rows)?,
    };
    assert_eq!(db.sequence(), trace.batches.len() as u64);
    report["sequence"] = json!(db.sequence());
    report["open_ns"] = json!(open_ns);
    report["initial_file_syncs"] = json!(initial.file_syncs);
    report["initial_directory_syncs"] = json!(initial.directory_syncs);
    let start = Instant::now();
    drop(db);
    report["close_ns"] = json!(start.elapsed().as_nanos());
    fs::write(output, serde_json::to_vec(&report)?)?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("The compact live index benchmark requires a Unix filesystem.");
    std::process::exit(2);
}
