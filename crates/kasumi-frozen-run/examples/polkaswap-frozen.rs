//! Fixture harness for an already finalized, read-only data set. The live
//! writer comparison is separate (benchmarks/indexer-kv/run.mjs).
use kasumi_frozen_run::{FrozenRun, seal};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, BufRead, BufReader},
    ops::Bound::{Excluded, Included, Unbounded},
    time::Instant,
};

type Rows = BTreeMap<Vec<u8>, Vec<u8>>;
const INDEX: &[u8] = b"x\0networkSnapshots\0y-t\0BLOCK\0";
const INDEX_END: &[u8] = b"x\0networkSnapshots\0y-t\0BLOCK\x01";
const PRIMARY: &[u8] = b"d\0networkSnapshots\0";

fn replay(trace: &str) -> Result<Rows, Box<dyn std::error::Error>> {
    let mut rows = Rows::new();
    for line in BufReader::new(fs::File::open(trace)?).lines() {
        let row: serde_json::Value = serde_json::from_str(&line?)?;
        for op in row["ops"].as_array().ok_or("expected operations")? {
            let key = hex::decode(op[1].as_str().ok_or("missing key")?)?;
            match op[0].as_str() {
                Some("put") => {
                    rows.insert(key, hex::decode(op[2].as_str().ok_or("missing value")?)?);
                }
                Some("del") => {
                    rows.remove(&key);
                }
                _ => return Err("unknown operation".into()),
            }
        }
    }
    Ok(rows)
}

fn digest_row(hash: &mut Sha256, key: &[u8], value: &[u8]) {
    for bytes in [key, value] {
        hash.update(
            u32::try_from(bytes.len())
                .expect("bounded field")
                .to_be_bytes(),
        );
        hash.update(bytes);
    }
}

type Page = Vec<(Vec<u8>, Vec<u8>)>;

fn page(run: &mut FrozenRun, end: std::ops::Bound<&[u8]>) -> io::Result<Page> {
    let mut keys = Vec::with_capacity(24);
    run.visit_reverse(Included(INDEX), end, 24, |idx, _| {
        assert!(idx.starts_with(INDEX));
        let id = idx.rsplit(|&c| c == 0).next().unwrap();
        keys.push([PRIMARY, id].concat());
        Ok(())
    })?;
    let mut rows = Vec::with_capacity(keys.len());
    for key in keys {
        let value = run.get(&key)?.expect("missing primary document");
        rows.push((key, value));
    }
    Ok(rows)
}

fn quantiles(mut samples: Vec<u64>) -> serde_json::Value {
    samples.sort_unstable();
    let pick = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
    serde_json::json!({"count":samples.len(), "p50_ns":pick(50), "p95_ns":pick(95)})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 3 {
        return Err("usage: polkaswap-frozen write|read TRACE RUN [EXPECTED_ROOT]".into());
    }
    let rows = replay(&args[1])?;
    if rows.is_empty() {
        return Err("empty fixture".into());
    }
    let path = &args[2];
    if args[0] == "write" && args.len() == 3 {
        let started = Instant::now();
        let root = seal(path, rows.iter())?;
        println!(
            "{}",
            serde_json::json!({"root":hex::encode(root), "seal_ns":started.elapsed().as_nanos()})
        );
        return Ok(());
    }
    if args[0] != "read" || args.len() != 4 {
        return Err("expected read with root, or write without root".into());
    }
    let root: [u8; 32] = hex::decode(&args[3])?
        .try_into()
        .map_err(|_| "expected SHA-256")?;
    let started = Instant::now();
    let mut run = FrozenRun::open(path, root)?;
    let open_ns = started.elapsed().as_nanos();
    let mut reference = rows.iter().rev();
    let mut state = Sha256::new();
    let count = run.visit_reverse(
        Unbounded,
        Unbounded,
        rows.len().checked_add(1).unwrap(),
        |k, v| {
            let (key, value) = reference.next().expect("extra stored row");
            assert_eq!(k, key);
            assert_eq!(v, value);
            digest_row(&mut state, k, v);
            Ok(())
        },
    )?;
    assert!(reference.next().is_none());
    assert_eq!(count, rows.len());
    let ordered: Vec<_> = rows.iter().collect();
    let mut point = Vec::with_capacity(1024);
    for i in 0..1024 {
        let (k, v) = ordered[(i * 197) % rows.len()];
        let t = Instant::now();
        let actual = run.get(k)?;
        point.push(t.elapsed().as_nanos() as u64);
        assert_eq!(actual.as_ref(), Some(v));
    }
    let timestamps: Vec<_> = rows
        .range(INDEX.to_vec()..INDEX_END.to_vec())
        .rev()
        .map(|(idx, _)| idx)
        .collect();
    let documents = |cursor: usize| -> Page {
        timestamps
            .iter()
            .skip(cursor)
            .take(24)
            .map(|idx| {
                let key = [PRIMARY, idx.rsplit(|&c| c == 0).next().unwrap()].concat();
                let value = rows[&key].clone();
                (key, value)
            })
            .collect()
    };
    let wanted = documents(0);
    assert_eq!(wanted.len(), 24);
    let mut hash = Sha256::new();
    let warm = page(&mut run, Excluded(INDEX_END))?;
    assert_eq!(warm, wanted);
    for (k, v) in warm {
        digest_row(&mut hash, &k, &v);
    }
    let mut latest = Vec::with_capacity(64);
    for _ in 0..64 {
        let t = Instant::now();
        let found = page(&mut run, Excluded(INDEX_END))?;
        latest.push(t.elapsed().as_nanos() as u64);
        assert_eq!(found, wanted);
    }
    let mut historical = Vec::with_capacity(64);
    let mut history_hash = Sha256::new();
    for i in 0..64 {
        let cursor = i * (timestamps.len() - 24) / 63;
        let wanted = documents(cursor);
        let t = Instant::now();
        let found = page(&mut run, Included(timestamps[cursor]))?;
        historical.push(t.elapsed().as_nanos() as u64);
        assert_eq!(found, wanted);
        for (key, value) in found {
            digest_row(&mut history_hash, &key, &value);
        }
    }
    println!(
        "{}",
        serde_json::json!({"verified_rows":count, "open_ns":open_ns,
        "state_sha256":hex::encode(state.finalize()), "page_sha256":hex::encode(hash.finalize()),
        "point":quantiles(point), "latest_blocks":quantiles(latest),
        "historical_pages":quantiles(historical), "history_sha256":hex::encode(history_hash.finalize())})
    );
    Ok(())
}
