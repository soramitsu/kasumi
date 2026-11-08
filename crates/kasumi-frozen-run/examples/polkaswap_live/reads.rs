//! The point and range timings mirror the existing paired RocksDB worker.
use super::trace::Rows;
use kasumi_frozen_run::LiveDb;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io,
    ops::Bound::{Excluded, Included, Unbounded},
    time::Instant,
};

type Row<'a> = (&'a Vec<u8>, &'a Vec<u8>);
const LOWER: &[u8] = b"x\0networkSnapshots\0y-t\0BLOCK\0";
const UPPER: &[u8] = b"x\0networkSnapshots\0y-t\0BLOCK\x01";
const PRIMARY: &[u8] = b"d\0networkSnapshots\0";

fn digest_row(hash: &mut Sha256, key: &[u8], value: &[u8]) {
    for bytes in [key, value] {
        hash.update(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        hash.update(bytes);
    }
}

fn ranges(db: &mut LiveDb, rows: &[Row<'_>], reverse: bool) -> io::Result<u128> {
    let width = 8.min(rows.len());
    let started = Instant::now();
    for i in 0..64 {
        let first = (i * 197) % (rows.len() - width + 1);
        let window = &rows[first..first + width];
        let low = Included(window[0].0.as_slice());
        let high = Included(window[width - 1].0.as_slice());
        let mut offset = 0;
        let mut check = |key: &[u8], value: &[u8]| {
            let pos = if reverse { width - 1 - offset } else { offset };
            assert_eq!(
                (key, value),
                (window[pos].0.as_slice(), window[pos].1.as_slice())
            );
            offset += 1;
            Ok(())
        };
        let count = if reverse {
            db.visit_reverse(low, high, width, &mut check)?
        } else {
            db.visit_forward(low, high, width, &mut check)?
        };
        assert_eq!(count, width);
        assert_eq!(offset, width);
    }
    Ok(started.elapsed().as_nanos())
}

fn latest(db: &mut LiveDb, rows: &Rows) -> io::Result<Value> {
    let expected: Vec<_> = rows
        .range(LOWER.to_vec()..UPPER.to_vec())
        .rev()
        .take(24)
        .collect();
    if expected.is_empty() {
        return Ok(Value::Null);
    }
    let mut digest = Sha256::new();
    let mut samples = [0u128; 64];
    let started = Instant::now();
    for (round, sample) in samples.iter_mut().enumerate() {
        let page_start = Instant::now();
        let mut documents = Vec::with_capacity(24);
        let count = db.visit_reverse(Included(LOWER), Excluded(UPPER), 24, |index, marker| {
            let (key, value) = expected[documents.len()];
            assert_eq!((index, marker), (key.as_slice(), value.as_slice()));
            let id = index.rsplit(|&byte| byte == 0).next().unwrap();
            documents.push([PRIMARY, id].concat());
            Ok(())
        })?;
        assert_eq!(count, expected.len());
        assert_eq!(documents.len(), expected.len());
        for key in documents {
            let doc = db.get(&key)?.expect("missing indexed document");
            assert_eq!(doc, rows[&key]);
            if round == 0 {
                digest_row(&mut digest, &key, &doc);
            }
        }
        *sample = page_start.elapsed().as_nanos();
    }
    let ns = started.elapsed().as_nanos();
    samples.sort_unstable();
    Ok(
        json!({"ns":ns, "pages":64, "p50_ns":samples[31], "p95_ns":samples[60],
        "documents_per_page":expected.len(), "page_sha256":hex::encode(digest.finalize())}),
    )
}

pub(super) fn measure(db: &mut LiveDb, rows: &Rows) -> io::Result<Value> {
    let ordered: Vec<_> = rows.iter().collect();
    let start = Instant::now();
    for i in 0..1024 {
        let (key, expected) = ordered[(i * 197) % ordered.len()];
        assert_eq!(db.get(key)?.as_ref(), Some(expected));
    }
    let point = start.elapsed().as_nanos();
    let forward = ranges(db, &ordered, false)?;
    let reverse = ranges(db, &ordered, true)?;
    let latest = latest(db, rows)?;
    let mut reference = ordered.iter();
    let mut state = Sha256::new();
    let count = db.visit_forward(Unbounded, Unbounded, ordered.len() + 1, |key, value| {
        let (want_key, want_value) = reference.next().expect("unexpected extra row");
        assert_eq!((key, value), (want_key.as_slice(), want_value.as_slice()));
        digest_row(&mut state, key, value);
        Ok(())
    })?;
    assert_eq!(count, ordered.len());
    assert!(reference.next().is_none());
    Ok(
        json!({"point_ns":point, "forward_ns":forward, "reverse_ns":reverse,
        "latest_blocks":latest, "verified_rows":count, "state_sha256":hex::encode(state.finalize())}),
    )
}
