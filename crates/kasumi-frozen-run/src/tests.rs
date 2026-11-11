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

#[test]
fn valid_v1_rows_open_with_the_original_trusted_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy");
    // One V1 block. The directory has no representation flag or intermediate length.
    let raw = [1, 0, 1, 0, 0, 0, 1, 0xff, 1, 0, 0, 0, 0, 0, 2];
    let packed = lz4_flex::block::compress(&raw);
    malformed(
        &path,
        &raw,
        (packed.len() as u32, raw.len() as u32),
        1,
        2,
        1,
    );
    let mut image = fs::read(&path).unwrap();
    let at = packed.len();
    let end = image.len();
    image[at..at + 8].copy_from_slice(DIRECTORY_MAGIC_V1);
    image[end - 8..].copy_from_slice(FOOTER_MAGIC_V1);
    let root = Sha256::digest(&image[at..end - 16]).into();
    fs::write(&path, &image).unwrap();
    let mut run = FrozenRun::open(&path, root).unwrap();
    assert_eq!(run.get(&[1]).unwrap(), Some(vec![255]));
    assert_eq!(run.get(&[2]).unwrap(), Some(vec![]));
    let mut scanned = Vec::new();
    run.visit_reverse(Unbounded, Unbounded, usize::MAX, |k, v| {
        scanned.push((k.to_vec(), v.to_vec()));
        Ok(())
    })
    .unwrap();
    assert_eq!(scanned, vec![(vec![2], vec![]), (vec![1], vec![255])]);
    image[end - 8..].copy_from_slice(FOOTER_MAGIC);
    fs::write(&path, image).unwrap();
    assert!(FrozenRun::open(&path, root).is_err());
}

#[test]
fn authenticated_invalid_prefixes_cannot_reach_the_row_visitor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad");
    // Valid first key "a", followed by a purported backreference.
    let first = [0, 0, 1, 0, 0, 0, 0, 0, b'a'];
    for (encoded, raw) in [
        (vec![1, 0, 1, 0, 0, 0, 0, 0, b'a'], 7u32), // first row references a previous block
        (
            [first.as_slice(), &[2, 0, 1, 0, 0, 0, 0, 0, b'b']].concat(),
            16,
        ), // prior key too short
        (
            [first.as_slice(), &[1, 0, 1, 0, 0, 0, 0, 0, b'b']].concat(),
            13,
        ), // canonical extent too small
        (vec![0, 0, 1, 0, 3, 0, 0, 0, b'a'], 10),   // truncated value
        (first.to_vec(), u32::MAX),                 // reject before any size arithmetic
    ] {
        let packed = lz4_flex::block::compress(&encoded);
        let mut directory = Vec::from(DIRECTORY_MAGIC.as_slice());
        directory.extend(1u32.to_le_bytes());
        directory.extend((packed.len() as u32 | PREFIX_FLAG).to_le_bytes());
        directory.extend(raw.to_le_bytes());
        directory.extend((encoded.len() as u32).to_le_bytes());
        directory.extend(Sha256::digest(&packed));
        directory.extend([1, 0, 1, 0, b'a', b'b']);
        let root = Sha256::digest(&directory).into();
        let mut image = packed;
        image.extend(&directory);
        image.extend((directory.len() as u64).to_le_bytes());
        image.extend(FOOTER_MAGIC);
        fs::write(&path, image).unwrap();
        let result = FrozenRun::open(&path, root).and_then(|mut run| {
            run.visit_forward(Unbounded, Unbounded, usize::MAX, |_, _| {
                panic!("invalid prefix exposed")
            })
        });
        assert!(result.is_err());
    }
}

#[test]
fn writer_can_mix_prefixed_and_plain_blocks_in_one_authenticated_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed");
    let mut model = BTreeMap::new();
    for n in 0..1500 {
        let key = format!("x\0networkSnapshots\0y-t\0BLOCK\02:0010:{n:010}\0block-{n:08}");
        model.insert(key.into_bytes(), vec![1]);
    }
    model.insert(vec![255], vec![42; BLOCK_TARGET + 1]); // a standalone plain block
    let root = seal(&path, &model).unwrap();
    let image = fs::read(&path).unwrap();
    let tail = image.len() - 16;
    let meta_len = u64::from_le_bytes(image[tail..tail + 8].try_into().unwrap()) as usize;
    let mut metadata = &image[tail - meta_len + 8..tail];
    let blocks = u32_from(&mut metadata).unwrap();
    let mut prefixed = 0;
    for _ in 0..blocks {
        let tagged = u32_from(&mut metadata).unwrap() as u32;
        u32_from(&mut metadata).unwrap();
        if tagged & PREFIX_FLAG != 0 {
            prefixed += 1;
            u32_from(&mut metadata).unwrap();
        }
        take(&mut metadata, 32).unwrap();
        let first = u16_from(&mut metadata).unwrap();
        let last = u16_from(&mut metadata).unwrap();
        take(&mut metadata, first + last).unwrap();
    }
    assert!(prefixed > 0 && prefixed < blocks);
    let mut run = FrozenRun::open(&path, root).unwrap();
    let mut expected = model.iter().rev();
    let count = run
        .visit_reverse(Unbounded, Unbounded, usize::MAX, |key, value| {
            let row = expected.next().unwrap();
            assert_eq!((key, value), (row.0.as_slice(), row.1.as_slice()));
            Ok(())
        })
        .unwrap();
    assert_eq!(count, model.len());
}

/// Rows of hexadecimal text, as indexer documents carry: LZ4 has no entropy
/// coder and barely shortens them, Zstandard roughly halves them.
fn hex_rows(count: u32) -> BTreeMap<Vec<u8>, Vec<u8>> {
    (0..count)
        .map(|n| {
            let mut state = u64::from(n).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut value = String::new();
            for _ in 0..12 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                value.push_str(&format!("{state:016x}"));
            }
            (format!("account/{n:08}").into_bytes(), value.into_bytes())
        })
        .collect()
}

/// Every block's tagged length word, flags included, from a sealed image.
fn tagged_lengths(image: &[u8]) -> Vec<u32> {
    let tail = image.len() - 16;
    let meta_len = u64::from_le_bytes(image[tail..tail + 8].try_into().unwrap()) as usize;
    let mut metadata = &image[tail - meta_len + 8..tail];
    let blocks = u32_from(&mut metadata).unwrap();
    (0..blocks)
        .map(|_| {
            let tagged = u32_from(&mut metadata).unwrap() as u32;
            u32_from(&mut metadata).unwrap();
            if tagged & PREFIX_FLAG != 0 {
                u32_from(&mut metadata).unwrap();
            }
            take(&mut metadata, 32).unwrap();
            let first = u16_from(&mut metadata).unwrap();
            let last = u16_from(&mut metadata).unwrap();
            take(&mut metadata, first + last).unwrap();
            tagged
        })
        .collect()
}

#[test]
fn zstandard_runs_hold_the_same_rows_in_fewer_bytes_and_lz4_runs_are_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let mut model = hex_rows(2000);
    model.insert(vec![255], vec![42; BLOCK_TARGET + 1]); // one oversized row
    let [lz4, same, zstd] = ["lz4", "same", "zstd"].map(|name| dir.path().join(name));
    let lz4_root = seal(&lz4, &model).unwrap();
    // Naming the default codec writes the same bytes as not naming one.
    assert_eq!(
        seal_with_codec(&same, &model, BlockCodec::Lz4).unwrap(),
        lz4_root
    );
    let lz4_image = fs::read(&lz4).unwrap();
    assert_eq!(fs::read(&same).unwrap(), lz4_image);
    let zstd_root = seal_with_codec(&zstd, &model, BlockCodec::Zstd).unwrap();
    let zstd_image = fs::read(&zstd).unwrap();
    assert!(lz4_image.ends_with(FOOTER_MAGIC) && zstd_image.ends_with(FOOTER_MAGIC_ZSTD));
    assert!(
        zstd_image.len() * 3 < lz4_image.len() * 2,
        "{} against {}",
        zstd_image.len(),
        lz4_image.len()
    );
    // Only the Zstandard run marks blocks as Zstandard, and it marks most.
    let marked = |image: &[u8]| {
        let tagged = tagged_lengths(image);
        let marked = tagged.iter().filter(|word| *word & ZSTD_FLAG != 0).count();
        (marked, tagged.len())
    };
    assert_eq!(marked(&lz4_image).0, 0);
    let (zstd_blocks, blocks) = marked(&zstd_image);
    assert!(zstd_blocks * 2 > blocks && blocks > 8);
    for (path, root) in [(&lz4, lz4_root), (&zstd, zstd_root)] {
        let mut run = FrozenRun::open(path, root).unwrap();
        for (key, value) in &model {
            assert_eq!(&run.get(key).unwrap().unwrap(), value);
        }
        assert_eq!(run.get(b"account/0000000").unwrap(), None);
        let mut expected = model.iter().rev();
        let count = run
            .visit_reverse(Unbounded, Unbounded, usize::MAX, |key, value| {
                let row = expected.next().unwrap();
                assert_eq!((key, value), (row.0.as_slice(), row.1.as_slice()));
                Ok(())
            })
            .unwrap();
        assert_eq!(count, model.len());
    }
    // Each run answers only to its own root, and a flipped block byte in the
    // Zstandard run is caught before anything is expanded.
    assert!(FrozenRun::open(&zstd, lz4_root).is_err());
    let mut damaged = zstd_image.clone();
    damaged[0] ^= 1;
    fs::write(&zstd, &damaged).unwrap();
    let mut run = FrozenRun::open(&zstd, zstd_root).unwrap();
    assert!(run.get(b"account/00000000").is_err());
}

#[test]
fn authenticated_invalid_zstandard_blocks_cannot_reach_the_row_visitor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad");
    let row = |k| [1, 0, 0, 0, 0, 0, k];
    let raw = [row(1), row(2)].concat();
    let frame = codec::zstd_compress(&raw).unwrap();
    let lz4 = lz4_flex::block::compress(&raw);
    // Give each image a matching digest, so only the format checks refuse it.
    let image = |packed: &[u8], flags: u32, raw_len: u32, version_3: bool| {
        let (directory_magic, footer_magic) = if version_3 {
            (DIRECTORY_MAGIC_ZSTD, FOOTER_MAGIC_ZSTD)
        } else {
            (DIRECTORY_MAGIC, FOOTER_MAGIC)
        };
        let mut directory = Vec::from(directory_magic.as_slice());
        directory.extend(1u32.to_le_bytes());
        directory.extend((packed.len() as u32 | flags).to_le_bytes());
        directory.extend(raw_len.to_le_bytes());
        directory.extend(Sha256::digest(packed));
        directory.extend([1, 0, 1, 0, 1, 2]);
        let root: [u8; 32] = Sha256::digest(&directory).into();
        let mut image = packed.to_vec();
        image.extend(&directory);
        image.extend((directory.len() as u64).to_le_bytes());
        image.extend(footer_magic);
        fs::write(&path, image).unwrap();
        FrozenRun::open(&path, root)
            .and_then(|mut run| run.visit_forward(Unbounded, Unbounded, usize::MAX, |_, _| Ok(())))
    };
    let len = raw.len() as u32;
    // The well-formed image reads back, so the refusals below are about
    // their one difference from it.
    assert_eq!(image(&frame, ZSTD_FLAG, len, true).unwrap(), 2);
    assert_eq!(image(&lz4, 0, len, true).unwrap(), 2);
    for (packed, flags, raw_len, version_3) in [
        (b"not a Zstandard frame".as_slice(), ZSTD_FLAG, len, true),
        (lz4.as_slice(), ZSTD_FLAG, len, true), // an LZ4 block marked as Zstandard
        (frame.as_slice(), 0, len, true),       // a frame not marked as Zstandard
        (frame.as_slice(), ZSTD_FLAG, len + 7, true), // expands to less than declared
        (frame.as_slice(), ZSTD_FLAG, len - 7, true), // expands past its declared length
        (frame.as_slice(), ZSTD_FLAG, len, false), // version 2 has no such flag
    ] {
        assert!(image(packed, flags, raw_len, version_3).is_err());
    }
    // The library alone would expand each of these to the right rows: two
    // frames, a skippable frame before the block, and bytes after it.
    let halves = [
        codec::zstd_compress(&row(1)).unwrap(),
        codec::zstd_compress(&row(2)).unwrap(),
    ]
    .concat();
    let skippable = [&[0x50, 0x2A, 0x4D, 0x18, 1, 0, 0, 0, 9][..], &frame].concat();
    let trailing = [frame.as_slice(), &[0]].concat();
    for packed in [halves, skippable, trailing] {
        let refused = image(&packed, ZSTD_FLAG, len, true).unwrap_err();
        assert_eq!(refused.to_string(), "invalid Zstandard block");
    }
}
