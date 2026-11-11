use super::*;
use std::io::{Read, SeekFrom, Write};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::ops::RangeBounds;

std::thread_local! {
    /// The codec this test's levels are written with. Each test has its own
    /// thread, so one test can rerun the others' scenarios under Zstandard.
    static CODEC: std::cell::Cell<BlockCodec> = const { std::cell::Cell::new(BlockCodec::Lz4) };
}
fn codec() -> BlockCodec {
    CODEC.with(std::cell::Cell::get)
}

fn level(delta: &Delta, older: &mut [&mut Level], final_run: bool, target: usize) -> Level {
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, delta, older, final_run, target, codec()).unwrap();
    Level::open(file, hash, false).unwrap()
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
        assert_eq!(
            get(levels.iter_mut().map(|level| &mut **level), delta, b"").unwrap(),
            Some([].as_slice())
        );
        for i in 0..102 {
            assert_eq!(
                get(levels.iter_mut().map(|level| &mut **level), delta, &key(i)).unwrap(),
                expected.get(&key(i)).map(Vec::as_slice)
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
    assert_eq!(bottom.lookup(b"b").unwrap(), Some(Some([].as_slice())));
    assert!(bottom.loaded.as_ref().unwrap().deletes.is_none());
}

#[test]
fn sparse_index_and_empty_level_are_authenticated() {
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, &Delta::new(), &mut [], true, 64, codec()).unwrap();
    let mut db = Level::open(file.try_clone().unwrap(), hash, false).unwrap();
    assert_eq!(get([&mut db], &Delta::new(), b"").unwrap(), None);
    assert!(Level::open(file, [0; 32], false).is_err());

    let delta = (0u8..5).map(|i| (vec![i], Some(vec![i]))).collect();
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, &delta, &mut [], false, 80, codec()).unwrap();
    let descriptor = index::open(&file, hash).unwrap().unwrap();
    assert!(matches!(
        index::read(&file, descriptor).unwrap(),
        Node::Branch { .. }
    ));
    let at = descriptor.at + 1;
    let mut byte = [0; 1];
    file.seek(SeekFrom::Start(at)).unwrap();
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    assert!(Level::open(file, hash, false).is_err());
}

#[test]
fn ordinary_tiers_reuse_bounded_pieces_across_value_tombstone_and_gap_lookups() {
    let data: Delta = (0..10u8)
        .map(|i| (vec![2 * i], (i != 4).then(|| vec![i; 12])))
        .collect();
    let mut run = level(&data, &mut [], false, 80);
    assert_eq!(run.recent_limit, 2);
    for i in [0, 9, 4, 0, 4, 9, 5, 0, 8, 5] {
        assert_eq!(
            run.lookup(&[2 * i]).unwrap(),
            Some(data[&vec![2 * i]].as_deref())
        );
        assert_eq!(run.lookup(&[2 * i + 1]).unwrap(), None);
        assert!(run.recent.len() <= 2);
    }
    assert_eq!(run.recent.len(), 2);
}

#[test]
fn deep_tier_keeps_extra_indexes_without_retaining_decoded_blocks() {
    let data: Delta = (0..24u8)
        .map(|n| (vec![n * 2], (n % 3 != 0).then(|| vec![n; 64])))
        .collect();
    let mut run = level(&data, &mut [], false, 80);
    run.retain_deep_indexes();
    for n in (0..24u8).chain((0..24u8).rev()) {
        let key = [n * 2];
        assert_eq!(
            run.lookup(&key).unwrap(),
            Some(data[key.as_slice()].as_deref())
        );
        assert_eq!(run.lookup(&[n * 2 + 1]).unwrap(), None);
        assert!(run.recent.len() <= DEEP_RECENT);
        for piece in run.recent.iter().skip(ORDINARY_RECENT) {
            assert!(!piece.rows.has_decoded());
            assert!(!piece.deletes.as_ref().is_some_and(FrozenRun::has_decoded));
        }
    }
    assert_eq!(run.recent.len(), DEEP_RECENT);
}

#[test]
fn bulk_hot_piece_rotation_preserves_point_gaps_and_cursor_order() {
    let mut data = Delta::new();
    for n in 0..12u8 {
        data.insert(vec![n * 2], Some(vec![n; 12]));
    }
    let mut base = level(&data, &mut [], true, 80); // One key per piece.
    base.recent_limit = 3;
    for n in [2u8, 3, 2, 5, 11, 10, 9, 3, 2, 3] {
        assert_eq!(
            base.lookup(&[n * 2]).unwrap(),
            Some(Some([n; 12].as_slice()))
        );
        assert_eq!(base.lookup(&[n * 2 + 1]).unwrap(), None);
        assert!(base.recent.len() <= 3);
    }
    for reverse in [true, false] {
        let mut result = Vec::new();
        visit(
            &mut [&mut base],
            &Delta::new(),
            Excluded(&[6]),
            Included(&[16]),
            20,
            reverse,
            |key, value| {
                result.push((key[0], value[0]));
                Ok(())
            },
        )
        .unwrap();
        let mut expect = vec![(8, 4), (10, 5), (12, 6), (14, 7), (16, 8)];
        if reverse {
            expect.reverse();
        }
        assert_eq!(result, expect);
    }
}

#[test]
fn repeated_descents_follow_kept_branches_and_read_only_the_leaf() {
    let key = |i: u16| i.to_be_bytes().to_vec();
    let data: Delta = (0..300)
        .map(|i| (key(i), Some(vec![i as u8; 12])))
        .collect();
    let mut run = level(&data, &mut [], true, 80); // One key per piece.
    let node_reads = || index::NODE_READS.with(|reads| reads.replace(0));
    // Seven pieces apart: no lookup finds its piece among the three retained.
    let pass = |run: &mut Level| {
        let mut lookups = 0;
        for i in (0..300).step_by(7) {
            assert_eq!(
                run.lookup(&key(i)).unwrap(),
                Some(Some([i as u8; 12].as_slice()))
            );
            lookups += 1;
        }
        lookups
    };
    node_reads();
    let lookups = pass(&mut run);
    let first = node_reads();
    assert!(first > 2 * lookups, "the first pass reads its branches");
    assert_eq!(pass(&mut run), lookups);
    assert_eq!(node_reads(), lookups, "later descents read one leaf each");
    assert!(run.memo.branches.len() < 300);

    // A range scan starts from the same kept branches and stays exact.
    node_reads();
    let mut seen = Vec::new();
    visit(
        &mut [&mut run],
        &Delta::new(),
        Included(&key(140)),
        Excluded(&key(143)),
        9,
        false,
        |key, _| {
            seen.push(key.to_vec());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(seen, [key(140), key(141), key(142)]);
    assert_eq!(
        run.lookup(&key(299)).unwrap(),
        Some(Some([43; 12].as_slice()))
    );
    assert_eq!(run.lookup(&[1, 44, 0]).unwrap(), None);
}

#[test]
fn kept_branches_stay_within_their_count_and_key_bounds() {
    // More branches than the memo keeps: every lookup still resolves exactly.
    let key = |i: u16| i.to_be_bytes().to_vec();
    let data: Delta = (0..1400)
        .map(|i| (key(i), Some(vec![i as u8; 12])))
        .collect();
    let mut run = level(&data, &mut [], true, 80); // 1,400 pieces, 1,399 branches.
    for round in 0..2 {
        for i in 0..1400 {
            assert_eq!(
                run.lookup(&key(i)).unwrap(),
                Some(Some([i as u8; 12].as_slice())),
                "round {round}"
            );
        }
        assert_eq!(run.memo.branches.len(), MEMO_BRANCHES);
        assert_eq!(run.memo.key_bytes, 2 * MEMO_BRANCHES);
    }
    assert_eq!(run.lookup(&[5, 120, 0]).unwrap(), None);

    // Long split keys reach the byte bound first.
    let long = |i: u8| {
        let mut key = vec![i; 4000];
        key.push(i);
        key
    };
    let data: Delta = (0..48).map(|i| (long(i), Some(vec![i]))).collect();
    let mut run = level(&data, &mut [], true, 5000); // 48 pieces, 47 branches.
    for _ in 0..2 {
        for i in 0..48 {
            assert_eq!(run.lookup(&long(i)).unwrap(), Some(Some([i].as_slice())));
        }
    }
    assert!(run.memo.key_bytes <= MEMO_KEY_BYTES);
    assert_eq!(run.memo.branches.len(), MEMO_KEY_BYTES / 4001);
    assert_eq!(
        run.memo.key_bytes,
        run.memo
            .branches
            .iter()
            .map(|b| b.split.len())
            .sum::<usize>()
    );
}

#[test]
fn a_warm_memo_serves_every_scan_and_still_authenticates_what_it_reads() {
    use std::os::unix::fs::FileExt;
    let key = |i: u16| i.to_be_bytes().to_vec();
    let data: Delta = (0..64).map(|i| (key(i), Some(vec![i as u8; 12]))).collect();
    let mut file = tempfile::tempfile().unwrap();
    let hash = write_pieces(&mut file, &data, &mut [], true, 80, codec()).unwrap();
    let image = file.try_clone().unwrap();
    let mut run = Level::open(file, hash, false).unwrap();
    let flip = |at: u64| {
        let mut byte = [0];
        image.read_exact_at(&mut byte, at).unwrap();
        image.write_all_at(&[byte[0] ^ 1], at).unwrap();
    };

    // A first descent that fails its digest keeps nothing.
    let root = run.root.unwrap();
    flip(root.at);
    let refused = run.lookup(&key(40)).unwrap_err();
    assert_eq!(refused.to_string(), "live level node digest differs");
    assert!(run.memo.branches.is_empty());
    flip(root.at);

    // Every bound and direction agrees with the rows, cold and then warm.
    let bounds = [
        Unbounded,
        Included(&[0, 9][..]),
        Excluded(&[0, 9][..]),
        Included(&[0, 40][..]),
        Excluded(&[0, 40][..]),
    ];
    for _ in 0..2 {
        for &lo in &bounds {
            for &hi in &bounds {
                for rev in [false, true] {
                    let mut want: Vec<_> = data
                        .keys()
                        .filter(|k| (lo, hi).contains(&k.as_slice()))
                        .cloned()
                        .collect();
                    if rev {
                        want.reverse();
                    }
                    let mut seen = Vec::new();
                    visit(
                        &mut [&mut run],
                        &Delta::new(),
                        lo,
                        hi,
                        usize::MAX,
                        rev,
                        |key, _| {
                            seen.push(key.to_vec());
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert_eq!(seen, want, "{lo:?} {hi:?} reverse={rev}");
                }
            }
        }
        for i in 0..64 {
            assert_eq!(
                run.lookup(&key(i)).unwrap(),
                Some(Some([i as u8; 12].as_slice()))
            );
        }
    }
    assert_eq!(run.memo.branches.len(), 63);

    // Below the kept branches every read is still checked: damage the first
    // piece's leaf node, which is neither kept nor among the retained pieces.
    let mut branch = &run.memo.branches[0];
    while branch.kept[0] != NOT_KEPT {
        branch = &run.memo.branches[branch.kept[0] as usize];
    }
    let leaf = branch.left;
    flip(leaf.at);
    let refused = run.lookup(&key(0)).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    assert_eq!(refused.to_string(), "live level node digest differs");
    flip(leaf.at);
    assert_eq!(run.lookup(&key(0)).unwrap(), Some(Some([0; 12].as_slice())));
}

#[test]
fn filtered_root_authenticates_the_bits_before_accepting_a_negative_lookup() {
    let mut file = tempfile::tempfile().unwrap();
    let (hash, n) = write_sorted(
        &mut file,
        (0..128u16).map(|i| Ok((i.to_be_bytes().to_vec(), vec![]))),
        Some(128),
        codec(),
    )
    .unwrap();
    assert_eq!(n, 128);
    let root = index::open(&file, hash).unwrap().unwrap();
    let Node::BulkRoot { filter, .. } = index::read(&file, root).unwrap() else {
        panic!("missing filtered root")
    };
    assert!(
        matches!(Level::open(file.try_clone().unwrap(), hash, false),
        Err(e) if e.to_string() == "membership filter outside the bulk tier")
    );
    let mut bits = index::read_filter(&file, filter).unwrap();
    for i in 0..128u16 {
        assert!(bits.may_contain(&i.to_be_bytes()));
    }
    assert!((128..2000u16).any(|i| !bits.may_contain(&i.to_be_bytes())));
    bits.bytes_mut()[0] ^= 1;
    file.seek(SeekFrom::Start(filter.at)).unwrap();
    file.write_all(bits.bytes()).unwrap();
    assert!(
        matches!(Level::open(file, hash, true), Err(e) if e.to_string()=="bulk membership filter digest differs")
    );
}

#[test]
fn verified_scan_rejects_a_self_consistent_filter_that_hides_a_shadowed_key() {
    let mut file = tempfile::tempfile().unwrap();
    let mut index = index::Builder::default();
    let mut rows = vec![(b"old".to_vec(), Some(vec![]))];
    flush_piece(&mut file, &mut index, &mut rows, codec()).unwrap();
    let omitted = BulkFilter::for_rows(1).unwrap(); // Deliberately omit the key.
    let root = index.finish(&mut file, Some(&omitted)).unwrap();
    let mut level = Level::open(file, root, true).unwrap();
    let delta = Delta::from([(b"old".to_vec(), None)]);
    // The logical view is empty, but even this physically shadowed key must
    // be covered before the filtered database can pass qualification.
    let err = visit_verified(&mut [&mut level], &delta, |_, _| Ok(())).unwrap_err();
    assert_eq!(err.to_string(), "bulk filter omits a stored key");
}

#[test]
fn compacted_filter_size_tracks_surviving_rows_and_retained_tombstones() {
    let mut file = tempfile::tempfile().unwrap();
    let n = 16_384u16;
    let (hash, _) = write_sorted(
        &mut file,
        (0..n).map(|i| Ok((i.to_be_bytes().to_vec(), vec![9]))),
        Some(n.into()),
        codec(),
    )
    .unwrap();
    let mut base = Level::open(file, hash, true).unwrap();
    assert!(base.membership.as_ref().unwrap().bytes().len() > 16_000);
    let deletes: Delta = (1..n).map(|i| (i.to_be_bytes().to_vec(), None)).collect();
    for drop_tombstones in [true, false] {
        let mut compacted = tempfile::tempfile().unwrap();
        let root = write_pieces(
            &mut compacted,
            &deletes,
            &mut [&mut base],
            drop_tombstones,
            PIECE_TARGET,
            codec(),
        )
        .unwrap();
        let mut level = Level::open(compacted, root, true).unwrap();
        let bytes = level.membership.as_ref().unwrap().bytes().len();
        if drop_tombstones {
            assert_eq!(bytes, 64);
        } else {
            assert!(bytes > 16_000);
        }
        assert_eq!(
            level.lookup(&0u16.to_be_bytes()).unwrap(),
            Some(Some([9].as_slice()))
        );
        assert_eq!(
            level.lookup(&1u16.to_be_bytes()).unwrap(),
            if drop_tombstones { None } else { Some(None) }
        );
        let mut visible = 0;
        visit_verified(&mut [&mut level], &Delta::new(), |_, _| {
            visible += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(visible, 1);
    }
}

#[test]
fn filtered_input_stops_at_the_first_excess_row() {
    let mut file = tempfile::tempfile().unwrap();
    let rows = (0u8..3).map(|i| {
        assert!(i < 2, "import read past the first excess row");
        Ok((vec![i], vec![i]))
    });
    let err = write_sorted(&mut file, rows, Some(1), codec()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "filtered import exceeds expected row count"
    );
}

/// The scenarios above hold when the writer may also choose Zstandard. Their
/// rows are small enough that most blocks stay LZ4 inside the newer layout;
/// `live_tests` covers blocks that do become Zstandard.
#[test]
fn zstandard_levels_pass_the_same_scenarios() {
    CODEC.with(|codec| codec.set(BlockCodec::Zstd));
    tiered_bounded_scans_and_point_reads_resolve_newest_puts_and_tombstones();
    full_rollup_elides_tombstones_and_partial_rollup_preserves_them();
    sparse_index_and_empty_level_are_authenticated();
    ordinary_tiers_reuse_bounded_pieces_across_value_tombstone_and_gap_lookups();
    deep_tier_keeps_extra_indexes_without_retaining_decoded_blocks();
    bulk_hot_piece_rotation_preserves_point_gaps_and_cursor_order();
    repeated_descents_follow_kept_branches_and_read_only_the_leaf();
    kept_branches_stay_within_their_count_and_key_bounds();
    a_warm_memo_serves_every_scan_and_still_authenticates_what_it_reads();
    filtered_root_authenticates_the_bits_before_accepting_a_negative_lookup();
    verified_scan_rejects_a_self_consistent_filter_that_hides_a_shadowed_key();
    compacted_filter_size_tracks_surviving_rows_and_retained_tombstones();
    filtered_input_stops_at_the_first_excess_row();
}
