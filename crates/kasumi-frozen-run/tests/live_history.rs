//! Compare the ordered public API against an independent model after overwrites,
//! deletes, automatic maintenance, explicit compaction and process-style reopen.
#![cfg(unix)]

use kasumi_frozen_run::{LiveDb, WalOp};
use std::{collections::BTreeMap, ops::Bound};

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn verify(db: &mut LiveDb, expected: &Model, seq: u64) {
    assert_eq!(db.sequence(), seq);
    let mut next = expected.iter();
    db.visit_forward(
        Bound::Unbounded,
        Bound::Unbounded,
        usize::MAX,
        |key, value| {
            let (want_key, want_value) = next.next().expect("extra live row");
            assert_eq!((key, value), (want_key.as_slice(), want_value.as_slice()));
            Ok(())
        },
    )
    .unwrap();
    assert!(next.next().is_none());
    let lo = 280u32.to_be_bytes();
    let hi = 880u32.to_be_bytes();
    let bounds = (
        Bound::Excluded(lo.as_slice()),
        Bound::Included(hi.as_slice()),
    );
    let mut page = expected.range::<[u8], _>(bounds).rev().take(73);
    let count = db
        .visit_reverse(bounds.0, bounds.1, 73, |key, value| {
            let (want_key, want_value) = page.next().expect("extra range row");
            assert_eq!((key, value), (want_key.as_slice(), want_value.as_slice()));
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 73);
    assert!(page.next().is_none());
    for id in (0..2048u32).step_by(19) {
        let k = id.to_be_bytes();
        assert_eq!(db.get(&k).unwrap().as_ref(), expected.get(k.as_slice()));
    }
}

#[test]
fn history_survives_interleaved_writes_deletes_reopen_and_compaction() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("history");
    let mut db = LiveDb::create(&path).unwrap();
    let mut expected = Model::new();
    let mut sequence = 0;
    // Many entries per durable transaction keep this test short while producing
    // enough total written bytes for multiple on-disk flushes and merges.
    for epoch in 0..12u32 {
        for part in 0..8u32 {
            let mut data = Vec::new();
            for pos in 0..256u32 {
                let id = ((pos * 8 + part) * 919) % 2048;
                let key = id.to_be_bytes().to_vec();
                let value = if (id + epoch) % 7 == 0 {
                    None
                } else {
                    let mut value = vec![(id % 251) as u8; 400 + ((id + epoch) % 21) as usize];
                    value[..4].copy_from_slice(&epoch.to_be_bytes());
                    Some(value)
                };
                match &value {
                    Some(value) => {
                        expected.insert(key.clone(), value.clone());
                    }
                    None => {
                        expected.remove(&key);
                    }
                }
                data.push((key, value));
            }
            let ops: Vec<_> = data
                .iter()
                .map(|(key, value)| match value {
                    Some(value) => WalOp::Put(key, value),
                    None => WalOp::Delete(key),
                })
                .collect();
            sequence += 1;
            assert_eq!(db.commit(&ops).unwrap(), sequence);
        }
        verify(&mut db, &expected, sequence);
        if epoch % 3 == 1 {
            drop(db);
            db = LiveDb::open(&path).unwrap();
            verify(&mut db, &expected, sequence);
        }
    }
    db.checkpoint().unwrap();
    drop(db);
    verify(&mut LiveDb::open(&path).unwrap(), &expected, sequence);
}
