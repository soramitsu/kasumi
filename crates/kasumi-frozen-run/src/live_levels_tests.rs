use super::*;
use std::io::{Read, SeekFrom, Write};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::ops::RangeBounds;

fn level(delta: &Delta, older: &mut [&mut Level], final_run: bool, target: usize) -> Level {
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, delta, older, final_run, target).unwrap();
    Level::open(file, hash).unwrap()
}

#[test]
fn tiered_bounded_scans_and_point_reads_resolve_newest_puts_and_tombstones() {
    let mut old = Delta::new();
    let mut mid = Delta::new();
    let mut mem = Delta::new();
    old.insert(Vec::new(), Some(vec![1]));
    mid.insert(Vec::new(), Some(Vec::new()));
    let key = |i: u16| i.to_be_bytes().to_vec();
    for i in 0..96 {
        if i % 2 == 0 {
            old.insert(key(i), Some(vec![i as u8]));
        }
        if i % 3 == 0 {
            mid.insert(key(i), Some(vec![]));
        }
        if i % 4 == 0 {
            mid.insert(key(i), None);
        }
        if i % 5 == 0 {
            mem.insert(key(i), Some(vec![255]));
        }
        if i % 7 == 0 {
            mem.insert(key(i), None);
        }
    }
    let expected = old.iter().chain(&mid).chain(&mem).fold(
        std::collections::BTreeMap::new(),
        |mut rows, (k, v)| {
            if let Some(v) = v {
                rows.insert(k.clone(), v.clone());
            } else {
                rows.remove(k);
            }
            rows
        },
    );
    let mut base = level(&old, &mut [], true, 244);
    let mut changes = level(&mid, &mut [], false, 230);
    let mut merged = level(&mem, &mut [&mut changes, &mut base], true, 227);
    for (levels, delta) in [
        (&mut [&mut changes, &mut base][..], &mem),
        (&mut [&mut merged][..], &Delta::new()),
    ] {
        assert_eq!(get(levels, delta, b"").unwrap(), Some(vec![]));
        for i in 0..102 {
            assert_eq!(
                get(levels, delta, &key(i)).unwrap().as_ref(),
                expected.get(&key(i))
            );
        }
        let ks: Vec<_> = [0, 11, 22, 60, 95, 96].map(key).into();
        let bounds: Vec<_> = std::iter::once(Unbounded)
            .chain(
                ks.iter()
                    .flat_map(|k| [Included(k.as_slice()), Excluded(k.as_slice())]),
            )
            .collect();
        for &lo in &bounds {
            for &hi in &bounds {
                for rev in [false, true] {
                    let mut want: Vec<_> = expected
                        .iter()
                        .filter(|(k, _)| (lo, hi).contains(&k.as_slice()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if rev {
                        want.reverse();
                    }
                    for n in [0, 1, 9, usize::MAX] {
                        let mut actual = Vec::new();
                        let count = visit(levels, delta, lo, hi, n, rev, |k, v| {
                            actual.push((k.to_vec(), v.to_vec()));
                            Ok(())
                        })
                        .unwrap();
                        assert_eq!(
                            actual,
                            &want[..n.min(want.len())],
                            "{lo:?} {hi:?} reverse={rev}"
                        );
                        assert_eq!(count, actual.len());
                    }
                }
            }
        }
    }
}

#[test]
fn full_rollup_elides_tombstones_and_partial_rollup_preserves_them() {
    let mut old = level(
        &[(b"a".to_vec(), Some(vec![1]))].into(),
        &mut [],
        true,
        1000,
    );
    let mut next = level(
        &[(b"a".to_vec(), None), (b"b".to_vec(), Some(vec![]))].into(),
        &mut [],
        false,
        1000,
    );
    let mut retained = level(&Delta::new(), &mut [&mut next], false, 1000);
    let mut bottom = level(&Delta::new(), &mut [&mut retained, &mut old], true, 1000);
    assert_eq!(retained.lookup(b"a").unwrap(), Some(None));
    assert_eq!(bottom.lookup(b"a").unwrap(), None);
    assert_eq!(bottom.lookup(b"b").unwrap(), Some(Some(vec![])));
    assert!(bottom.loaded.as_ref().unwrap().deletes.is_none());
}

#[test]
fn sparse_index_and_empty_level_are_authenticated() {
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, &Delta::new(), &mut [], true, 64).unwrap();
    let mut db = Level::open(file.try_clone().unwrap(), hash).unwrap();
    assert_eq!(get(&mut [&mut db], &Delta::new(), b"").unwrap(), None);
    assert!(Level::open(file, [0; 32]).is_err());

    let delta = (0u8..5).map(|i| (vec![i], Some(vec![i]))).collect();
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, &delta, &mut [], false, 80).unwrap();
    let descriptor = index::open(&mut file, hash).unwrap().unwrap();
    assert!(matches!(
        index::read(&mut file, descriptor).unwrap(),
        Node::Branch { .. }
    ));
    let at = descriptor.at + 1;
    let mut byte = [0; 1];
    file.seek(SeekFrom::Start(at)).unwrap();
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    assert!(Level::open(file, hash).is_err());
}
