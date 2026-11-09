//! A failed export must never publish a partial base; a successful base may
//! immediately accept ordinary durable commits and survive later compaction.
#![cfg(unix)]
use kasumi_frozen_run::{LiveDb, WalOp};
use std::{io, ops::Bound};

fn key(i: u32) -> Vec<u8> {
    i.to_be_bytes().to_vec()
}

#[test]
fn failed_multipiece_import_reopens_empty_and_success_survives_ordinary_writes() {
    let root = tempfile::tempdir().unwrap();
    let mut db = LiveDb::create(root.path()).unwrap();
    let rows = (0..12_000).map(|i| Ok((key(i), vec![9; 400])));
    let input = rows.chain([Err(io::Error::other("source checkpoint disappeared"))]);
    assert!(db.load_sorted(input).is_err());
    assert!(db.get(&key(0)).is_err());
    drop(db);
    let mut db = LiveDb::open(root.path()).unwrap();
    assert_eq!(db.sequence(), 0);
    assert!(db.get(&key(0)).unwrap().is_none());
    let rows = (0..12_000u32).map(|i| Ok((key(i), vec![i as u8; 400])));
    assert_eq!(db.load_sorted(rows).unwrap(), 12_000);
    assert_eq!(db.sequence(), 1);
    assert!(db.load_sorted([]).is_err());
    drop(db);
    let mut db = LiveDb::open(root.path()).unwrap();
    for i in [0, 1234, 11_999] {
        assert_eq!(db.get(&key(i)).unwrap(), Some(vec![i as u8; 400]));
    }
    db.commit(&[WalOp::Delete(&key(400)), WalOp::Put(&key(401), b"changed")])
        .unwrap();
    db.checkpoint().unwrap();
    drop(db);
    let mut db = LiveDb::open(root.path()).unwrap();
    assert_eq!(db.sequence(), 2);
    assert!(db.get(&key(400)).unwrap().is_none());
    assert_eq!(db.get(&key(401)).unwrap().as_deref(), Some(&b"changed"[..]));
    let mut last = None;
    let n = db
        .visit_reverse(Bound::Unbounded, Bound::Unbounded, usize::MAX, |k, _| {
            assert!(last.as_ref().is_none_or(|old: &Vec<u8>| k < old.as_slice()));
            last = Some(k.to_vec());
            Ok(())
        })
        .unwrap();
    assert_eq!(n, 11_999);
}

#[test]
fn equal_or_decreasing_keys_at_a_piece_boundary_are_rejected() {
    for final_key in [b"b", b"a"] {
        let root = tempfile::tempdir().unwrap();
        let mut db = LiveDb::create(root.path()).unwrap();
        let rows = [
            Ok((b"a".to_vec(), vec![1; 4 << 20])),
            Ok((b"b".to_vec(), vec![2; 4 << 20])),
            Ok((final_key.to_vec(), vec![3; 2])),
        ];
        assert!(db.load_sorted(rows).is_err());
        drop(db);
        assert_eq!(LiveDb::open(root.path()).unwrap().sequence(), 0);
    }
}
