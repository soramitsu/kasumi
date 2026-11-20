use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir};
use std::os::unix::fs::FileExt;

fn fixture() -> (tempfile::TempDir, Arc<ScratchDisk>) {
    let directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    (directory, disk)
}

fn dispose(mut spool: EncryptedSpool) {
    let outcome = spool.close_once();
    assert_eq!(
        outcome.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Drained
    );
    outcome.into_result().unwrap();
}

#[test]
fn native_segment_appends_share_writes_and_authenticate_each_original_slot() {
    let (_directory, disk) = fixture();
    let data: Vec<u8> = (0..19 * NATIVE_BLOCK + 31)
        .map(|i| (i % 251) as u8)
        .collect();
    let mut regular = EncryptedSpool::new_native(&disk, data.len() as u64).unwrap();
    let mut grouped = EncryptedSpool::new_native(&disk, data.len() as u64).unwrap();
    for spool in [&mut regular, &mut grouped] {
        spool.write_all(&data[..27]).unwrap();
    }
    regular.write_all(&data[27..]).unwrap();
    grouped.write_native(&data[27..]).unwrap();
    regular.flush_extent().unwrap();
    grouped.flush_extent().unwrap();
    assert_eq!(regular.ciphertext_writes, 20);
    // One prefix, five groups of up to four complete slots, one partial tail.
    assert_eq!(grouped.ciphertext_writes, 7);
    assert_eq!(grouped.len(), regular.len());
    assert_eq!(grouped.physical_len, regular.physical_len);
    let mut actual = vec![0; data.len()];
    grouped.rewind().unwrap();
    grouped.read_exact(&mut actual).unwrap();
    assert_eq!(actual, data);
    assert_eq!(
        grouped.append_digest.clone().unwrap().finalize(),
        Sha256::digest(&data)
    );
    dispose(regular);

    // Swapping complete authenticated slots within the same native append
    // must fail at the first transplanted slot, under its original offset.
    let mut second = vec![0; NATIVE_SLOT as usize];
    grouped
        .file
        .read_exact_at(&mut second, 2 * NATIVE_SLOT)
        .unwrap();
    grouped.file.write_all_at(&second, NATIVE_SLOT).unwrap();
    grouped.seek(SeekFrom::Start(NATIVE_BLOCK as u64)).unwrap();
    assert_eq!(
        grouped.read_exact(&mut actual[..1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn native_directory_appends_group_four_slots_and_header_overwrites_preserve_pages() {
    let (_directory, disk) = fixture();
    let mut spool = EncryptedSpool::new_native(&disk, 9 * NATIVE_BLOCK as u64).unwrap();
    let header = vec![17; NATIVE_BLOCK];
    let first = vec![31; 4 * NATIVE_BLOCK];
    let second = vec![73; 4 * NATIVE_BLOCK];
    spool.write_native(&header).unwrap();
    spool.write_native(&first).unwrap();
    spool.write_native(&second).unwrap();
    spool.flush_extent().unwrap();
    // One header and one grouped ciphertext write per 16-KiB directory page.
    assert_eq!(spool.ciphertext_writes, 3);
    let replacement = vec![91; NATIVE_BLOCK];
    spool.rewind().unwrap();
    spool.write_native(&replacement).unwrap();
    spool.flush_extent().unwrap();
    spool.rewind().unwrap();
    let mut actual = Vec::new();
    spool.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, [replacement, first, second].concat());
    dispose(spool);
}

#[test]
fn native_layout_bounds_actual_crypto_reads_for_alternating_header_and_page() {
    fn read_workload(spool: &mut EncryptedSpool) -> u64 {
        spool.resize(2 * BLOCK as u64).unwrap();
        spool.flush_extent().unwrap();
        spool.cached_index = None;
        let before = spool.authenticated_bytes_read;
        let mut header = [0; NATIVE_BLOCK];
        let mut page = [0; 4 * NATIVE_BLOCK];
        for _ in 0..3 {
            spool.rewind().unwrap();
            spool.read_exact(&mut header).unwrap();
            spool
                .seek(SeekFrom::Start((BLOCK + NATIVE_BLOCK) as u64))
                .unwrap();
            spool.read_exact(&mut page).unwrap();
            assert_eq!(header, [0; NATIVE_BLOCK]);
            assert_eq!(page, [0; 4 * NATIVE_BLOCK]);
        }
        spool.authenticated_bytes_read - before
    }
    let (_directory, disk) = fixture();
    let mut native = EncryptedSpool::new_native(&disk, 2 * BLOCK as u64).unwrap();
    let mut sequential = EncryptedSpool::new(&disk, 2 * BLOCK as u64).unwrap();
    assert_eq!(native.cached.len(), NATIVE_BLOCK);
    assert_eq!(native.ciphertext.len(), NATIVE_SLOT as usize);
    assert_eq!(sequential.cached.len(), BLOCK);
    assert_eq!(sequential.ciphertext.len(), SLOT as usize);
    assert_eq!(read_workload(&mut native), 15 * NATIVE_SLOT);
    assert_eq!(read_workload(&mut sequential), 6 * SLOT);

    // Even a hit must check its exact owner before exposing plaintext.
    native.rewind().unwrap();
    let mut byte = [0];
    native.read_exact(&mut byte).unwrap();
    let before = native.authenticated_bytes_read;
    native.rewind().unwrap();
    native.read_exact(&mut byte).unwrap();
    assert_eq!(native.authenticated_bytes_read, before);
    dispose(sequential);
    native.owner_failed();
    assert!(native.rewind().is_err());
    assert!(native.read_exact(&mut byte).is_err());
}

#[test]
fn native_layout_overwrite_truncate_and_regrow_preserves_prefix_and_zeroes_suffix() {
    let (_directory, disk) = fixture();
    let mut spool = EncryptedSpool::new_native(&disk, 4 * NATIVE_BLOCK as u64).unwrap();
    let mut expected: Vec<_> = (0..3 * NATIVE_BLOCK + 31)
        .map(|i| (i % 251) as u8)
        .collect();
    spool.write_all(&expected).unwrap();
    spool
        .seek(SeekFrom::Start(NATIVE_BLOCK as u64 - 5))
        .unwrap();
    spool.write_all(&[252; 20]).unwrap();
    expected[NATIVE_BLOCK - 5..NATIVE_BLOCK + 15].fill(252);
    let retained = NATIVE_BLOCK + 7;
    spool.resize(retained as u64).unwrap();
    assert_eq!(spool.file.metadata().unwrap().len(), 2 * NATIVE_SLOT);
    expected[retained..].fill(0);
    spool.resize(expected.len() as u64).unwrap();
    spool.flush_extent().unwrap();
    assert_eq!(spool.file.metadata().unwrap().len(), 4 * NATIVE_SLOT);
    spool.cached_index = None;
    spool.rewind().unwrap();
    let mut actual = Vec::new();
    spool.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
    dispose(spool);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
}

#[test]
fn native_layout_authenticates_ciphertext_and_block_position() {
    for reorder in [false, true] {
        let (_directory, disk) = fixture();
        let mut spool = EncryptedSpool::new_native(&disk, 2 * NATIVE_BLOCK as u64).unwrap();
        spool.write_all(&vec![7; 2 * NATIVE_BLOCK]).unwrap();
        spool.flush_extent().unwrap();
        let mut first = vec![0; NATIVE_SLOT as usize];
        spool.file.read_exact_at(&mut first, 0).unwrap();
        if reorder {
            spool.file.write_all_at(&first, NATIVE_SLOT).unwrap();
        } else {
            first[24] ^= 1;
            spool.file.write_all_at(&first, 0).unwrap();
        }
        spool.cached_index = None;
        spool
            .seek(SeekFrom::Start(if reorder {
                NATIVE_BLOCK as u64
            } else {
                0
            }))
            .unwrap();
        let mut plaintext = [0; NATIVE_BLOCK];
        assert_eq!(
            spool.read_exact(&mut plaintext).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(plaintext, [0; NATIVE_BLOCK]);
        assert!(!disk.snapshot().filesystem_admission_ready);
    }
}

#[test]
fn prepared_native_layout_transfers_exact_buffers_and_claim_without_readmission() {
    let (_directory, disk) = fixture();
    let limit = 3 * NATIVE_BLOCK as u64 + 1;
    let physical = 4 * NATIVE_SLOT;
    assert_eq!(
        EncryptedSpool::transaction_ciphertext_len(limit).unwrap(),
        physical
    );
    let memory = disk
        .memory()
        .clone()
        .reserve_installed(
            (2 * NATIVE_BLOCK) as u64 + 40 + 3 * crate::disk_memory::ALLOCATION_ALLOWANCE + 32,
        )
        .unwrap();
    let mut prepared = claim::PreparedSpool::new(&disk, limit).unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    let rounded = disk.transaction_rounded(physical).unwrap();
    let mut space = disk.reserve_transaction_space(rounded, 1).unwrap();
    let promised = disk.snapshot().charged_bytes;
    let mut spool = prepared.acquire(&mut space).unwrap();
    assert_eq!(spool.cached.len(), NATIVE_BLOCK);
    assert_eq!(spool.ciphertext.len(), NATIVE_SLOT as usize);
    assert_eq!(spool.file.metadata().unwrap().len(), 0);
    spool.reserve_claimed_growth(&mut space, limit).unwrap();
    assert_eq!(spool.transaction_charged_bytes(), rounded);
    spool.resize(limit).unwrap();
    spool.flush_extent().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, promised);
    assert_eq!(spool.file.metadata().unwrap().len(), physical);
    space.finish().unwrap();
    dispose(spool);
    drop(memory);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
}
