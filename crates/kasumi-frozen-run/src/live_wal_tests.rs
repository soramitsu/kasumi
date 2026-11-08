use super::*;
use std::fs::OpenOptions;
use std::path::Path;

const BASE: u64 = 41;
const ROOT: [u8; 32] = [0x13; 32];

fn writable(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn create() -> (tempfile::NamedTempFile, Wal) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let wal = Wal::initialize(writable(file.path()), BASE, ROOT).unwrap();
    (file, wal)
}

#[test]
fn recovers_binary_puts_deletes_duplicates_and_empty_batches_in_order() {
    let (file, mut wal) = create();
    let value = vec![0xba; 4096];
    let first = [
        WalOp::Put(&[0xff, 0], &value),
        WalOp::Delete(b""),
        WalOp::Put(b"", b""),
        WalOp::Delete(&[0xff, 0]),
    ];
    assert_eq!(wal.syncs(), 1);
    assert_eq!(wal.append(&first).unwrap(), BASE + 1);
    assert!(wal.len() < 256);
    assert_eq!(wal.append(&[]).unwrap(), BASE + 2);
    assert_eq!(wal.syncs(), 3);
    drop(wal);
    let mut seqs = Vec::new();
    let mut wal = Wal::open(writable(file.path()), BASE, ROOT, |seq, ops| {
        seqs.push(seq);
        if seq == BASE + 1 {
            assert_eq!(ops, &first);
        } else {
            assert!(ops.is_empty());
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(seqs, [BASE + 1, BASE + 2]);
    assert_eq!(wal.syncs(), 1);
    assert_eq!(wal.append(&[WalOp::Delete(b"x")]).unwrap(), BASE + 3);
}

#[test]
fn every_truncated_batch_exposes_only_its_complete_predecessors() {
    let (source, mut wal) = create();
    let first = [WalOp::Put(b"alpha", b"\x01\x00\xff"), WalOp::Delete(b"x")];
    let second = [WalOp::Put(b"beta", &[7; 2048])];
    wal.append(&first).unwrap();
    let first_end = wal.len() as usize;
    wal.append(&second).unwrap();
    let image = std::fs::read(source.path()).unwrap();
    drop(wal);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    for cut in WAL_HEADER..=image.len() {
        std::fs::write(tmp.path(), &image[..cut]).unwrap();
        let mut observed = Vec::new();
        let (seq, end, _, _) = read_frames(&writable(tmp.path()), BASE, ROOT, |seq, ops| {
            observed.push(seq);
            if seq == BASE + 1 {
                assert_eq!(ops, &first);
            } else {
                assert_eq!(ops, &second);
            }
            Ok(())
        })
        .unwrap();
        let expected = usize::from(cut >= first_end) + usize::from(cut == image.len());
        assert_eq!(observed.len(), expected, "cut {cut}");
        assert_eq!(seq, BASE + expected as u64);
        assert_eq!(end as usize, [WAL_HEADER, first_end, image.len()][expected]);
    }
    std::fs::write(tmp.path(), &image[..image.len() - 1]).unwrap();
    let mut opened = Wal::open(writable(tmp.path()), BASE, ROOT, |_, _| Ok(())).unwrap();
    assert_eq!(opened.len() as usize, first_end);
    assert_eq!(opened.syncs(), 1);
    assert_eq!(std::fs::metadata(tmp.path()).unwrap().len(), opened.len());
    opened.append(&[WalOp::Put(b"replacement", b"")]).unwrap();
    Wal::open(writable(tmp.path()), BASE, ROOT, |sequence, ops| {
        if sequence == BASE + 2 {
            assert_eq!(ops, &[WalOp::Put(b"replacement", b"")]);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn every_single_byte_corruption_of_a_complete_file_fails_closed_without_truncating() {
    let (source, mut wal) = create();
    wal.append(&[WalOp::Delete(b"k")]).unwrap();
    wal.append(&[WalOp::Put(b"key", &[0x73; 1024])]).unwrap();
    let mut image = std::fs::read(source.path()).unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    for index in 0..image.len() {
        image[index] ^= 1;
        std::fs::write(tmp.path(), &image).unwrap();
        assert!(
            Wal::open(writable(tmp.path()), BASE, ROOT, |_, _| Ok(())).is_err(),
            "byte {index}"
        );
        assert_eq!(
            std::fs::metadata(tmp.path()).unwrap().len(),
            image.len() as u64
        );
        image[index] ^= 1;
    }
    assert!(Wal::open(writable(source.path()), BASE + 1, ROOT, |_, _| Ok(())).is_err());
    assert!(Wal::open(writable(source.path()), BASE, [7; 32], |_, _| Ok(())).is_err());
    assert!(Wal::initialize(writable(source.path()), BASE, ROOT).is_err());
}

#[test]
fn invalid_operations_are_refused_before_effect_and_sync_failure_fences_the_writer() {
    let (file, mut wal) = create();
    let end = wal.len();
    for ops in [
        vec![WalOp::Delete(&[0; MAX_KEY + 1])],
        vec![WalOp::Delete(b""); MAX_WAL_BATCH_OPS + 1],
    ] {
        assert_eq!(
            wal.append(&ops).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let largest = vec![0; MAX_VALUE];
    assert_eq!(
        wal.append(&[WalOp::Put(b"a", &largest), WalOp::Put(b"b", &largest)])
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!((wal.len(), wal.syncs(), wal.is_fenced()), (end, 1, false));
    let res = wal.append_with_sync(&[WalOp::Put(b"a", b"durability uncertain")], |_| {
        Err(io::Error::other("injected sync failure"))
    });
    assert!(res.is_err());
    assert!(wal.is_fenced());
    assert!(wal.append(&[WalOp::Delete(b"a")]).is_err());
    assert_eq!(wal.sequence(), BASE);
    assert_eq!(wal.syncs(), 1);
    drop(wal);
    let opened = Wal::open(writable(file.path()), BASE, ROOT, |_, ops| {
        assert_eq!(ops, &[WalOp::Put(b"a", b"durability uncertain")]);
        Ok(())
    })
    .unwrap();
    assert_eq!((opened.sequence(), opened.syncs()), (BASE + 1, 1));
}

#[test]
fn authenticated_invalid_encoding_is_rejected_before_callback_or_large_allocation() {
    let (file, _) = create();
    let cases: &[(&[u8], usize, usize, bool)] = &[
        (&[0x81, 0], 1, 2, false),    // noncanonical key length
        (&[2, 3, b'a'], 1, 3, false), // incomplete value
        (&[1, 1], 1, 2, false),       // trailing op
        (&[0], 1, 300, true),         // invalid LZ4 block
        (&[1], 1, MAX_WAL_BATCH_BYTES + 1, true),
        (&[1], MAX_WAL_BATCH_OPS + 1, 1, false),
    ];
    for &(stored, count, raw, compressed) in cases {
        let head = frame_header(
            &generation_digest(&wal_header(BASE, ROOT)),
            BASE + 1,
            count,
            raw,
            stored.len(),
            compressed,
        );
        let digest = frame_digest(&head, stored);
        let mut image = wal_header(BASE, ROOT).to_vec();
        image.extend_from_slice(&head);
        image.extend_from_slice(stored);
        image.extend_from_slice(&digest);
        std::fs::write(file.path(), &image).unwrap();
        assert!(
            Wal::open(writable(file.path()), BASE, ROOT, |_, _| panic!(
                "invalid batch reached visitor"
            ))
            .is_err()
        );
        assert_eq!(std::fs::read(file.path()).unwrap(), image);
    }
}

#[test]
fn transplanted_valid_frames_fail_for_a_different_generation_or_predecessor() {
    let (source, mut left) = create();
    left.append(&[WalOp::Delete(b"left")]).unwrap();
    let left_boundary = left.len() as usize;
    left.append(&[WalOp::Put(b"large", &[17; 2048])]).unwrap();
    let image = std::fs::read(source.path()).unwrap();
    for (root, first) in [
        (ROOT, b"right".as_slice()),
        ([0x37; 32], b"left".as_slice()),
    ] {
        let target = tempfile::NamedTempFile::new().unwrap();
        let mut other = Wal::initialize(writable(target.path()), BASE, root).unwrap();
        other.append(&[WalOp::Delete(first)]).unwrap();
        drop(other);
        let before = std::fs::read(target.path()).unwrap();
        let mut writer = OpenOptions::new().append(true).open(target.path()).unwrap();
        // A checksum-valid but misplaced frame header must also fail as a short tail.
        writer
            .write_all(&image[left_boundary..left_boundary + HEADER])
            .unwrap();
        assert!(Wal::open(writable(target.path()), BASE, root, |_, _| Ok(())).is_err());
        writer.write_all(&image[left_boundary + HEADER..]).unwrap();
        assert!(Wal::open(writable(target.path()), BASE, root, |_, _| Ok(())).is_err());
        assert_eq!(
            std::fs::metadata(target.path()).unwrap().len(),
            (before.len() + image.len() - left_boundary) as u64
        );
    }
}
