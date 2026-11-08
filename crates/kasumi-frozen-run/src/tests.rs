use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    ops::Bound::{Excluded, Included, Unbounded},
};

#[test]
fn binary_rows_reopen_and_seek_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history");
    let mut model = BTreeMap::from([
        (vec![], vec![]),
        (vec![0], vec![0, 255, 0]),
        (vec![255, 0], vec![0; BLOCK_TARGET + 1]),
    ]);
    for n in 0..600u16 {
        model.insert(n.to_be_bytes().to_vec(), vec![(n % 251) as u8; 333]);
    }
    let root = seal(&path, &model).unwrap();
    let mut run = FrozenRun::open(&path, root).unwrap();
    for (key, value) in &model {
        assert_eq!(&run.get(key).unwrap().unwrap(), value);
    }
    for missing in [&[0, 1, 0][..], &[255, 255], &[2, 88]] {
        assert_eq!(run.get(missing).unwrap(), None);
    }
    let bounds = [
        Unbounded,
        Included(&[][..]),
        Excluded(&[0][..]),
        Included(&[0, 98][..]),
        Excluded(&[1, 43][..]),
        Included(&[255][..]),
        Excluded(&[255, 0][..]),
    ];
    for lower in bounds {
        for upper in bounds {
            for limit in [0, 7, usize::MAX] {
                let expected: Vec<_> = model
                    .iter()
                    .filter(|(k, _)| {
                        let k = k.as_slice();
                        (match lower {
                            Included(v) => k >= v,
                            Excluded(v) => k > v,
                            Unbounded => true,
                        }) && (match upper {
                            Included(v) => k <= v,
                            Excluded(v) => k < v,
                            Unbounded => true,
                        })
                    })
                    .collect();
                for reverse in [false, true] {
                    let mut wanted = expected.clone();
                    if reverse {
                        wanted.reverse();
                    }
                    let mut wanted = wanted.into_iter().take(limit);
                    let visit = |key: &[u8], value: &[u8]| {
                        let next = wanted.next().unwrap();
                        assert_eq!((key, value), (next.0.as_slice(), next.1.as_slice()));
                        Ok(())
                    };
                    let count = if reverse {
                        run.visit_reverse(lower, upper, limit, visit)
                    } else {
                        run.visit_forward(lower, upper, limit, visit)
                    }
                    .unwrap();
                    assert_eq!(count, expected.len().min(limit));
                    assert!(wanted.next().is_none());
                }
            }
        }
    }
}

#[test]
fn failed_seals_leave_no_target_and_completed_names_are_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    for keys in [[1, 1], [2, 1]] {
        assert!(seal(&path, keys.map(|n| ([n], [n]))).is_err());
        assert!(!path.exists());
    }
    assert!(seal(&path, [(vec![0; MAX_KEY + 1], vec![])]).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    let empty = seal(&path, std::iter::empty::<(&[u8], &[u8])>()).unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        seal(&path, [([1], [2])]).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut run = FrozenRun::open(path, empty).unwrap();
    assert_eq!(run.get(&[]).unwrap(), None);
    assert_eq!(
        run.visit_reverse(Unbounded, Unbounded, usize::MAX, |_, _| unreachable!())
            .unwrap(),
        0
    );
}

#[test]
fn damaged_and_truncated_files_never_yield_unauthenticated_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let root = seal(&path, [([1], [17]), ([255], [0])]).unwrap();
    let original = fs::read(&path).unwrap();
    assert!(FrozenRun::open(&path, [0; 32]).is_err());
    for size in [0, 10, original.len() - 1] {
        fs::write(&path, &original[..size]).unwrap();
        assert!(FrozenRun::open(&path, root).is_err());
    }
    let mut changed = original.clone();
    let n = changed.len();
    changed[n - 17] ^= 1;
    fs::write(&path, &changed).unwrap();
    assert!(FrozenRun::open(&path, root).is_err());
    let mut changed = original.clone();
    changed[0] ^= 1;
    fs::write(&path, &changed).unwrap();
    let mut run = FrozenRun::open(&path, root).unwrap();
    assert!(
        run.visit_reverse(Unbounded, Unbounded, 1, |_, _| panic!(
            "damaged block exposed"
        ))
        .is_err()
    );
    fs::write(&path, &original).unwrap();
    let mut run = FrozenRun::open(&path, root).unwrap();
    fs::write(&path, []).unwrap();
    assert!(run.get(&[1]).is_err());
}

// Give deliberately malformed metadata/content a matching digest so the
// format and decompression checks run beyond the cryptographic rejection.
fn malformed(
    path: &std::path::Path,
    raw: &[u8],
    lengths: (u32, u32),
    first: u8,
    last: u8,
    copies: usize,
) -> [u8; 32] {
    let packed = lz4_flex::block::compress(raw);
    let mut directory = Vec::from(DIRECTORY_MAGIC.as_slice());
    directory.extend((copies as u32).to_le_bytes());
    for _ in 0..copies {
        directory.extend(lengths.0.to_le_bytes());
        directory.extend(lengths.1.to_le_bytes());
        directory.extend(Sha256::digest(&packed));
        directory.extend([1, 0, 1, 0, first, last]);
    }
    let root = Sha256::digest(&directory).into();
    let mut image = packed.repeat(copies);
    image.extend(&directory);
    image.extend((directory.len() as u64).to_le_bytes());
    image.extend(FOOTER_MAGIC);
    fs::write(path, image).unwrap();
    root
}

#[test]
fn authenticated_malformed_lengths_order_and_boundaries_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let row = |k| [1, 0, 0, 0, 0, 0, k];
    let raw = [row(2), row(1)].concat();
    let packed = lz4_flex::block::compress(&raw).len() as u32;
    for (raw_len, first, last, copies, open_ok) in [
        (raw.len() as u32, 1, 2, 1, true),
        (raw.len() as u32, 2, 2, 1, true),
        (raw.len() as u32, 3, 1, 1, false),
        (raw.len() as u32, 1, 2, 2, false),
        (raw.len() as u32 + 2, 1, 2, 1, true),
        (MAX_RAW as u32 + 1, 1, 2, 1, false),
    ] {
        let root = malformed(&path, &raw, (packed, raw_len), first, last, copies);
        let opened = FrozenRun::open(&path, root);
        assert_eq!(opened.is_ok(), open_ok);
        if let Ok(mut run) = opened {
            assert!(
                run.visit_forward(Unbounded, Unbounded, 1, |_, _| panic!(
                    "invalid row exposed"
                ))
                .is_err()
            );
        }
    }
}

#[test]
fn mid_block_seek_is_logarithmic_and_interior_blocks_only_probe_returned_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let root = seal(&path, (0..16000u32).map(|id| (id.to_be_bytes(), b""))).unwrap();
    let mut run = FrozenRun::open(&path, root).unwrap();

    // 3,276 ten-byte rows fit a block. This window ends near its midpoint.
    read::ROW_PROBES.with(|probes| probes.set(0));
    let mut visited = 0;
    let end = 1500u32.to_be_bytes();
    run.visit_reverse(Unbounded, Excluded(&end), 8, |key, _| {
        assert_eq!(key, (1499u32 - visited).to_be_bytes());
        visited += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, 8);
    assert!(read::ROW_PROBES.with(|probes| probes.get()) <= 8 + 13);

    read::ROW_PROBES.with(|probes| probes.set(0));
    let lo = 500u32.to_be_bytes();
    let hi = 14500u32.to_be_bytes();
    let count = run
        .visit_forward(Included(&lo), Excluded(&hi), usize::MAX, |_, _| Ok(()))
        .unwrap();
    assert_eq!(count, 14_000);
    assert!(read::ROW_PROBES.with(|probes| probes.get()) <= count + 2 * 13);

    read::ROW_PROBES.with(|probes| probes.set(0));
    let count = run
        .visit_reverse(Unbounded, Unbounded, usize::MAX, |_, _| Ok(()))
        .unwrap();
    assert_eq!(count, 16_000);
    assert_eq!(read::ROW_PROBES.with(|probes| probes.get()), count);
}
