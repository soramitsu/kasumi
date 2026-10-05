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
fn native_layout_bounds_actual_crypto_reads_for_alternating_header_and_page() {
    fn read_workload(spool: &mut EncryptedSpool) -> u64 {
        spool.resize(2 * BLOCK as u64).unwrap();
        spool.sync_all().unwrap();
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
    spool.sync_all().unwrap();
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
        spool.sync_all().unwrap();
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
    spool.sync_all().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, promised);
    assert_eq!(spool.file.metadata().unwrap().len(), physical);
    space.finish().unwrap();
    dispose(spool);
    drop(memory);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
}
