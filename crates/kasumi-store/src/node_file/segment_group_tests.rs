use super::*;
use crate::NodeDiskPhase;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ID: Uuid = Uuid::from_u128(0x2d3b_0c6e_5f41_4a8e_9b52_77a1_c0de_5e61);
const OTHER: Uuid = Uuid::from_u128(0x7f0e_1c2d_3b4a_4596_8877_6655_4433_2211);
const CACHE: usize = 8;

fn memory() -> Arc<dyn crate::NodeDiskMemoryAdmission> {
    TestDiskMemory::new(256 << 20, 4096)
}

fn fixture_disk(path: &Path, memory: &Arc<dyn crate::NodeDiskMemoryAdmission>) -> Arc<NodeDisk> {
    retry_disk_registry(|| NodeDisk::fixture_for_path(path, memory.clone())).unwrap()
}

fn acquire(
    path: &Path,
    disk: &Arc<NodeDisk>,
    mode: NodeOpeningMode,
    cache: usize,
) -> (Arc<NodeSegmentGroup>, Result<()>) {
    let group = NodeSegmentGroup::retained_prepared(path, ID, disk.clone(), cache);
    let result = group.acquire_prepared(&mode);
    (group, result)
}

/// A Ready group whose kv root published one slot.
fn ready_group(path: &Path, disk: &Arc<NodeDisk>, cache: usize) -> Arc<NodeSegmentGroup> {
    let (group, created) = acquire(path, disk, NodeOpeningMode::Create, cache);
    created.unwrap();
    group
        .write_root(RootSlot::A, &[0x5a; ROOT_SLOT_BYTES])
        .unwrap();
    group.sync_root().unwrap();
    group.publish_ready().unwrap();
    group
}

fn reopen(path: &Path, disk: &Arc<NodeDisk>, cache: usize) -> Arc<NodeSegmentGroup> {
    let (group, opened) = acquire(path, disk, NodeOpeningMode::Existing, cache);
    opened.unwrap();
    group
}

fn close(group: &NodeSegmentGroup) {
    let closed = group.close();
    assert_eq!(closed.entry(), BackendCloseEntry::Entered);
    assert_eq!(
        closed.native_disposition(),
        BackendNativeDisposition::Drained
    );
    closed.into_result().unwrap();
}

/// Drain a fenced group: its witnessed failed owners move into NodeDisk
/// custody, and only a fresh accepted census reopens the disk.
fn recover(group: &NodeSegmentGroup) {
    let closed = group.close();
    assert_eq!(
        closed.native_disposition(),
        BackendNativeDisposition::Drained
    );
    if closed.into_result().is_err() {
        let witness = group.failed_close_witness().unwrap();
        assert!(group.transfer_failed(&witness).unwrap());
        assert!(!group.failed_transfer_accepted());
    }
    group
        .disk()
        .reconcile(&CensusCancellation::default())
        .unwrap();
    assert_eq!(group.disk().snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(group.disk().snapshot().open_files, 0);
}

fn put(group: &NodeSegmentGroup, file: GroupFile, bytes: &[u8]) {
    group.create(file).unwrap();
    group.write(file, 0, bytes).unwrap();
    group.sync(file).unwrap();
}

fn read_all(group: &NodeSegmentGroup, file: GroupFile) -> Vec<u8> {
    let mut out = vec![0; group.len(file).unwrap() as usize];
    group.read(file, 0, &mut out).unwrap();
    out
}

fn raw_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

/// Every file and directory image below `path`, sorted by name.
fn tree(path: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut images = Vec::new();
    let mut pending = vec![path.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap().path();
            if std::fs::symlink_metadata(&entry).unwrap().is_dir() {
                images.push((entry.clone(), None));
                pending.push(entry);
            } else {
                images.push((entry.clone(), Some(std::fs::read(&entry).unwrap())));
            }
        }
    }
    images.sort();
    images
}

/// The NodeDisk charge of one file: its logical or allocated size, whichever
/// is larger, rounded to the filesystem allocation unit.
fn file_extent(path: &Path, unit: u64) -> u64 {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    metadata.len().max(metadata.blocks() * 512).div_ceil(unit) * unit
}

/// Recompute the installed census charge of a whole fixture root from the
/// filesystem alone: every directory's allowance or allocation, whichever is
/// larger, plus every file's extent.
fn expected_charge(root: &Path) -> u64 {
    let unit = crate::node_disk::filesystem(&File::open(root).unwrap())
        .unwrap()
        .1;
    let allowance = crate::DirectoryPolicy::fixture().extent_bytes;
    let directory =
        |path: &Path| allowance.max(std::fs::symlink_metadata(path).unwrap().blocks() * 512);
    let mut total = directory(root);
    for (path, image) in tree(root) {
        total += match image {
            Some(_) => file_extent(&path, unit),
            None => directory(&path),
        };
    }
    total
}

#[test]
fn names_have_exactly_the_kv_group_spelling() {
    let segment = GroupFile::segment(0x2a);
    assert_eq!(segment.file_name(), "000000000000002a.kvseg");
    assert_eq!(GroupFile::parse_name(&segment.file_name()), Some(segment));
    let checkpoint = GroupFile::checkpoint(7);
    assert_eq!(checkpoint.file_name(), "0000000000000007.kvckpt");
    assert_eq!(
        GroupFile::parse_name(&checkpoint.file_name()),
        Some(checkpoint)
    );
    for name in [
        "000000000000002A.kvseg",
        "00000000000002a.kvseg",
        "0000000000000000.kvseg",
        "000000000000002a.kvseg.tmp",
        "+00000000000002a.kvseg",
        "seg-000000000000002a.kvs",
        ROOT_FILE_NAME,
    ] {
        assert_eq!(GroupFile::parse_name(name), None, "{name}");
    }
}

#[test]
fn ready_publication_rewrites_only_the_first_sector() {
    let prepared = envelope(ID, ROOT_KIND, PREPARED, 0);
    let ready = envelope(ID, ROOT_KIND, READY, 0);
    assert_eq!(prepared[512..], ready[512..]);
    assert!(ready[CHECKSUM_END..].iter().all(|byte| *byte == 0));
    assert_eq!(
        validate_envelope(&prepared, ID, ROOT_KIND, 0).unwrap(),
        PREPARED
    );
    assert_eq!(validate_envelope(&ready, ID, ROOT_KIND, 0).unwrap(), READY);
    // A state change without its checksum matches neither image.
    let mut torn = prepared;
    torn[33] = READY;
    assert_eq!(
        validate_envelope(&torn, ID, ROOT_KIND, 0)
            .unwrap_err()
            .to_string(),
        "segment group envelope checksum differs"
    );
    let mut padded = ready;
    padded[HEADER_BYTES - 1] = 1;
    assert!(validate_envelope(&padded, ID, ROOT_KIND, 0).is_err());
    assert!(validate_envelope(&ready, ID, SEGMENT_KIND, 0).is_err());
    assert!(validate_envelope(&ready, OTHER, ROOT_KIND, 0).is_err());
}

#[test]
fn created_group_reopens_only_after_verifying_every_envelope() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), b"first segment");
    put(&group, GroupFile::segment(2), b"second");
    put(&group, GroupFile::checkpoint(1), b"checkpoint");
    // Create-only, and an identifier is never reused after its unlink.
    for file in [GroupFile::segment(2), GroupFile::segment(1)] {
        assert_eq!(
            group.create(file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
    group.unlink(GroupFile::segment(1)).unwrap();
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert_eq!(
        group.create(GroupFile::segment(1)).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    let image = std::fs::read(path.join("0000000000000002.kvseg")).unwrap();
    assert_eq!(&image[..16], MAGIC);
    assert_eq!(&image[16..32], ID.as_bytes());
    assert_eq!(&image[HEADER_BYTES..], b"second");
    let root = std::fs::read(path.join(ROOT_FILE_NAME)).unwrap();
    assert_eq!(root.len() as u64, ROOT_FILE_BYTES);
    assert_eq!(root[33], READY);
    close(&group);

    let group = reopen(&path, &disk, CACHE);
    let mut names = group.entries().unwrap();
    names.sort();
    assert_eq!(
        names,
        [
            OsString::from("0000000000000001.kvckpt"),
            OsString::from("0000000000000002.kvseg"),
            OsString::from(ROOT_FILE_NAME),
        ]
    );
    assert_eq!(read_all(&group, GroupFile::segment(2)), b"second");
    assert_eq!(read_all(&group, GroupFile::checkpoint(1)), b"checkpoint");
    let mut slot = [0; ROOT_SLOT_BYTES];
    group.read_root(RootSlot::A, &mut slot).unwrap();
    assert_eq!(slot, [0x5a; ROOT_SLOT_BYTES]);
    group.read_root(RootSlot::B, &mut slot).unwrap();
    assert_eq!(slot, [0; ROOT_SLOT_BYTES]);
    // The reopened owner refuses identifiers at or below the ones it saw.
    assert_eq!(
        group.create(GroupFile::segment(2)).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    group.create(GroupFile::segment(3)).unwrap();
    assert_eq!(group.len(GroupFile::segment(3)).unwrap(), 0);
    close(&group);

    // Another installed identity is refused without any mutation.
    let before = tree(directory.path());
    let other = NodeSegmentGroup::retained_prepared(&path, OTHER, disk.clone(), CACHE);
    let error = other
        .acquire_prepared(&NodeOpeningMode::Existing)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("identity differs"),
        "{error:#}"
    );
    close(&other);
    assert_eq!(tree(directory.path()), before);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    // Creating over an existing group directory is refused too.
    let (again, created) = acquire(&path, &disk, NodeOpeningMode::Create, CACHE);
    assert!(created.is_err());
    drop(again);
    assert_eq!(tree(directory.path()), before);
}

#[test]
fn offsets_follow_the_envelope_and_enforce_the_group_contract() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    let file = GroupFile::segment(1);
    group.create(file).unwrap();
    // A new file has no envelope and reads as empty until its first write.
    assert_eq!(group.len(file).unwrap(), 0);
    group.read(file, 0, &mut []).unwrap();
    assert_eq!(
        group.read(file, 0, &mut [0]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        group.write(file, 1, b"hole").unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    group.set_len(file, 0).unwrap();
    let physical = path.join(file.file_name());
    assert_eq!(std::fs::metadata(&physical).unwrap().len(), 0);

    group.write(file, 0, b"abcdef").unwrap();
    assert_eq!(group.len(file).unwrap(), 6);
    group.write(file, 2, b"XY").unwrap();
    group.write(file, 6, b"gh").unwrap();
    assert_eq!(read_all(&group, file), b"abXYefgh");
    assert_eq!(
        group.write(file, 9, b"hole").unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    // Range checks apply even to empty reads.
    group.read(file, 8, &mut []).unwrap();
    for (at, len) in [(9, 0), (8, 1), (7, 2)] {
        assert_eq!(
            group.read(file, at, &mut vec![0; len]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    group.set_len(file, 3).unwrap();
    assert_eq!(read_all(&group, file), b"abX");
    group.set_len(file, 5).unwrap();
    assert_eq!(read_all(&group, file), b"abX\0\0");
    group.sync(file).unwrap();
    let image = std::fs::read(&physical).unwrap();
    assert_eq!(image.len(), HEADER_BYTES + 5);
    assert_eq!(image[..HEADER_BYTES], envelope(ID, SEGMENT_KIND, READY, 1));

    // Unknown files are absent and never created implicitly.
    let absent = GroupFile::segment(9);
    assert!(!group.exists(absent).unwrap());
    for error in [
        group.len(absent).unwrap_err(),
        group.write(absent, 0, b"x").unwrap_err(),
        group.set_len(absent, 1).unwrap_err(),
        group.sync(absent).unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
    assert!(!path.join(absent.file_name()).exists());
    // Unlink of an absent name is complete once the directory is synchronized.
    group.unlink(absent).unwrap();
    group.sync_names().unwrap();
    assert_eq!(
        group.create(GroupFile::segment(0)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    close(&group);
    for error in [
        group.len(file).unwrap_err(),
        group.exists(file).unwrap_err(),
        group.sync_root().unwrap_err(),
        group.entries().unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
    // Close is idempotent once drained.
    close(&group);
    assert_eq!(disk.snapshot().open_files, 0);
}

#[test]
fn interrupted_create_reopens_as_an_empty_file_finished_by_the_next_mutation() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), b"sealed");
    let file = GroupFile::segment(2);
    // NodeDisk made the empty name durable, but the result was lost.
    group.inject(GroupFault::CreateAfterEffect);
    assert!(group.create(file).is_err());
    assert!(group.exists(file).is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    recover(&group);
    let mut group = reopen(&path, &disk, CACHE);
    assert!(group.exists(file).unwrap());
    assert_eq!(group.len(file).unwrap(), 0);
    assert_eq!(
        group.create(file).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );

    // The first mutation wrote only part of the envelope before failing.
    let expected = envelope(ID, SEGMENT_KIND, READY, 2);
    for torn in [0, 17, HEADER_BYTES - 1] {
        group.inject(GroupFault::TornEnvelope(torn));
        assert!(group.write(file, 0, b"payload").is_err());
        assert!(group.len(file).is_err());
        recover(&group);
        let image = std::fs::read(path.join(file.file_name())).unwrap();
        assert_eq!(image, expected[..torn]);
        group = reopen(&path, &disk, CACHE);
        assert_eq!(group.len(file).unwrap(), 0);
        assert_eq!(
            group.read(file, 0, &mut [0]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    // A prefix padded with zeros to one envelope is still unwritten.
    close(&group);
    raw_options()
        .open(path.join(file.file_name()))
        .unwrap()
        .set_len(HEADER_BYTES as u64)
        .unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(group.len(file).unwrap(), 0);
    group.write(file, 0, b"resumed").unwrap();
    group.sync(file).unwrap();
    close(&group);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, file), b"resumed");
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"sealed");
    // The complete envelope is durable even when the kv bytes are not.
    group.create(GroupFile::segment(3)).unwrap();
    group.inject(GroupFault::TornEnvelope(HEADER_BYTES));
    assert!(group.write(GroupFile::segment(3), 0, b"lost").is_err());
    recover(&group);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(group.len(GroupFile::segment(3)).unwrap(), 0);
    group.write(GroupFile::segment(3), 0, b"kept").unwrap();
    assert_eq!(read_all(&group, GroupFile::segment(3)), b"kept");
    close(&group);
}

#[test]
fn unlink_confirmed_before_the_garbage_update_is_idempotent_after_restart() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), &[1; 10_000]);
    put(&group, GroupFile::segment(2), &[2; 3_000]);
    put(&group, GroupFile::segment(3), &[3; 100]);
    let unit = crate::node_disk::filesystem(&File::open(directory.path()).unwrap())
        .unwrap()
        .1;
    let first = path.join(GroupFile::segment(1).file_name());
    let extent = file_extent(&first, unit);
    let before = disk.snapshot();
    group.unlink(GroupFile::segment(1)).unwrap();
    // Space is credited only after the confirmed unlink and parent sync.
    let after = disk.snapshot();
    assert_eq!(after.charged_bytes, before.charged_bytes - extent);
    assert_eq!(after.persistent_files, before.persistent_files - 1);
    assert!(!first.exists());
    // The process stops before the kv root forgets its garbage record.
    close(&group);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, after.charged_bytes);
    let group = reopen(&path, &disk, CACHE);
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    // The owed unlink completes as the parent synchronization of an absence.
    group.unlink(GroupFile::segment(1)).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, after.charged_bytes);

    // An unlink whose result was lost after the effect fences the group.
    let second = path.join(GroupFile::segment(2).file_name());
    let extent = file_extent(&second, unit);
    let before = disk.snapshot();
    group.inject(GroupFault::UnlinkAfterEffect);
    assert!(group.unlink(GroupFile::segment(2)).is_err());
    assert!(group.len(GroupFile::segment(3)).is_err());
    assert!(StorageAdmission::check_owner(&*group).is_err());
    assert!(!second.exists());
    recover(&group);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes - extent);
    let group = reopen(&path, &disk, CACHE);
    assert!(!group.exists(GroupFile::segment(2)).unwrap());
    group.unlink(GroupFile::segment(2)).unwrap();
    let mut names = group.entries().unwrap();
    names.sort();
    assert_eq!(
        names,
        [
            OsString::from(GroupFile::segment(3).file_name()),
            OsString::from(ROOT_FILE_NAME)
        ]
    );
    assert_eq!(read_all(&group, GroupFile::segment(3)), [3; 100]);
    close(&group);
    let running = disk.snapshot().charged_bytes;
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, running);
    assert_eq!(running, expected_charge(directory.path()));
}

#[test]
fn failed_parent_sync_and_unconfirmed_unlink_fence_and_keep_every_charge() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), b"one");
    put(&group, GroupFile::segment(2), b"two");
    // A failed directory synchronization leaves every name uncertain.
    group.inject(GroupFault::NamesBeforeEffect);
    assert!(group.sync_names().is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(group.create(GroupFile::segment(3)).is_err());
    assert!(!path.join(GroupFile::segment(3).file_name()).exists());
    recover(&group);
    // So does the directory synchronization of an absent-name unlink.
    let group = reopen(&path, &disk, CACHE);
    group.inject(GroupFault::NamesBeforeEffect);
    assert!(group.unlink(GroupFile::segment(9)).is_err());
    assert!(group.exists(GroupFile::segment(1)).is_err());
    recover(&group);

    // An unlink NodeDisk cannot confirm keeps the name and the charge.
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(group.len(GroupFile::segment(1)).unwrap(), 3);
    let before = disk.snapshot();
    let bytes = tree(directory.path());
    disk.fail();
    assert!(group.unlink(GroupFile::segment(1)).is_err());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
    assert_eq!(tree(directory.path()), bytes);
    assert!(group.exists(GroupFile::segment(1)).is_err());
    recover(&group);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"one");
    group.unlink(GroupFile::segment(1)).unwrap();
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    close(&group);
}

#[test]
fn failed_descriptor_close_keeps_the_exact_owner_and_blocks_the_census() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, 2);
    put(&group, GroupFile::segment(1), b"one");
    put(&group, GroupFile::segment(2), b"two");
    close(&group);
    // Clean descriptors close without settlement, so the next native close
    // is the eviction's own.
    let group = reopen(&path, &disk, 2);
    assert_eq!(group.cached_files(), 2);
    assert_eq!(read_all(&group, GroupFile::segment(2)), b"two");
    let before = disk.snapshot();
    let bytes = tree(directory.path());
    NodeDiskFile::fail_next_native_close(libc::EIO);
    // Reaching a third file must evict the least recently used descriptor.
    assert_eq!(
        group.len(GroupFile::segment(3)).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        group
            .create(GroupFile::segment(3))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(group.retained_failed_files(), 1);
    assert_eq!(group.cached_files(), 2);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().open_files, before.open_files);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(group.len(GroupFile::segment(2)).is_err());
    assert!(!path.join(GroupFile::segment(3).file_name()).exists());

    let closed = group.close();
    assert_eq!(
        closed.native_disposition(),
        BackendNativeDisposition::Retained
    );
    assert_eq!(
        closed.into_result().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    // Every owner is retained: the uncertain one and the two refused by the
    // failed disk. A repeat never enters native close again.
    assert_eq!(group.retained_failed_files(), 3);
    let attempts = NodeDiskFile::native_close_attempts();
    for _ in 0..2 {
        let repeated = group.close();
        assert_eq!(
            repeated.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            repeated.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(NodeDiskFile::native_close_attempts(), attempts);
        assert_eq!(group.retained_failed_files(), 3);
    }
    // An unattested native close cannot mint a transfer witness, and its
    // descriptor keeps the disk census closed.
    assert!(group.failed_close_witness().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(disk.snapshot().open_files, before.open_files);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(tree(directory.path()), bytes);
}

#[test]
fn registered_group_is_one_census_owner_until_its_failed_owners_are_accepted() {
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let provider: Arc<dyn crate::NodeDiskMemoryAdmission> = memory.clone();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &provider);
    let census = provider.storage_census();
    let baseline = memory.snapshot();

    let registration = NodeSegmentGroup::register(&path, ID, disk.clone(), CACHE).unwrap();
    assert_eq!(census.snapshot().segment_groups, 1);
    assert!(memory.snapshot().used_bytes > baseline.used_bytes);
    let group = registration.owner();
    group.acquire_prepared(&NodeOpeningMode::Create).unwrap();
    group
        .write_root(RootSlot::B, &[0x11; ROOT_SLOT_BYTES])
        .unwrap();
    group.sync_root().unwrap();
    group.publish_ready().unwrap();
    for id in 1..=20 {
        put(group, GroupFile::segment(id), &[id as u8; 64]);
    }
    // A clean close retires the owner, its entry table and its charge.
    assert_eq!(
        registration.retire(),
        crate::StorageCensusDisposition::Retired
    );
    assert_eq!(census.snapshot().segment_groups, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(disk.snapshot().open_files, 0);

    let registration = NodeSegmentGroup::register(&path, ID, disk.clone(), CACHE).unwrap();
    let id = registration.id();
    let group = registration.owner();
    group.acquire_prepared(&NodeOpeningMode::Existing).unwrap();
    assert_eq!(read_all(group, GroupFile::segment(20)), [20; 64]);
    StorageAdmission::owner_failed(group);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    // Drive closes every descriptor; the failed disk refuses to credit them,
    // so the census keeps the exact owner.
    assert_eq!(
        census.drain_owner(id),
        crate::StorageCensusDisposition::Retained
    );
    assert_eq!(census.snapshot().segment_groups, 1);
    let witness = group.failed_close_witness().unwrap();
    let mut originals = 0;
    group
        .with_failed_close_reports(&witness, |report| {
            report.visit_errors(|_| originals += 1);
        })
        .unwrap();
    assert_eq!(originals, CACHE + 1);
    assert!(group.transfer_failed(&witness).unwrap());
    assert!(group.transfer_failed(&witness).is_err());
    assert_eq!(group.retained_failed_files(), 0);
    assert_eq!(
        census.drain_owner(id),
        crate::StorageCensusDisposition::Retained
    );
    assert!(!group.failed_transfer_accepted());
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(group.failed_transfer_accepted());
    assert_eq!(
        registration.retire(),
        crate::StorageCensusDisposition::Retired
    );
    assert_eq!(census.snapshot().segment_groups, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, GroupFile::segment(1)), [1; 64]);
    close(&group);
}

#[test]
fn more_than_768_segments_reopen_and_evict_within_the_descriptor_budget() {
    const SEGMENTS: u64 = 800;
    // With the root, this cache is the fixture's whole 256-owner budget.
    const WHOLE_BUDGET: usize = 255;
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, WHOLE_BUDGET);
    for id in 1..=SEGMENTS {
        let file = GroupFile::segment(id);
        group.create(file).unwrap();
        group.write(file, 0, &id.to_le_bytes()).unwrap();
        assert!(disk.snapshot().open_files <= 256);
    }
    assert_eq!(disk.snapshot().open_files, 256);
    // The budget is exhausted: no other owner can open a descriptor now.
    assert_eq!(
        disk.create_file("fixture", Path::new("probe"), DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    close(&group);
    assert_eq!(disk.snapshot().open_files, 0);

    let group = reopen(&path, &disk, WHOLE_BUDGET);
    assert_eq!(group.cached_files(), WHOLE_BUDGET);
    assert_eq!(disk.snapshot().open_files, 256);
    for id in (1..=SEGMENTS).rev().chain(1..=SEGMENTS) {
        let mut bytes = [0; 8];
        group.read(GroupFile::segment(id), 0, &mut bytes).unwrap();
        assert_eq!(u64::from_le_bytes(bytes), id);
        assert!(disk.snapshot().open_files <= 256);
    }
    assert_eq!(group.entries().unwrap().len(), SEGMENTS as usize + 1);
    group.unlink(GroupFile::segment(400)).unwrap();
    group.create(GroupFile::segment(SEGMENTS + 1)).unwrap();
    close(&group);
    assert_eq!(disk.snapshot().open_files, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        expected_charge(directory.path())
    );
}

#[test]
fn previous_formats_and_foreign_files_are_rejected_before_any_mutation() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    // A single-file node store at the group path is not a group.
    let single = directory.path().join("single");
    let disk = fixture_disk(&single, &memory);
    let node = super::super::NodeFile::create_new(&single, ID, disk.clone()).unwrap();
    kasumi_kv::StorageBackend::close(&node.backend())
        .into_result()
        .unwrap();
    drop(node);
    let before = tree(directory.path());
    for mode in [NodeOpeningMode::Existing, NodeOpeningMode::Create] {
        let (group, opened) = acquire(&single, &disk, mode, CACHE);
        assert!(opened.is_err());
        close(&group);
        assert_eq!(tree(directory.path()), before);
    }
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);

    let path = directory.path().join("group");
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), b"payload");
    close(&group);
    let segment = path.join(GroupFile::segment(1).file_name());
    let root = path.join(ROOT_FILE_NAME);
    let original_segment = std::fs::read(&segment).unwrap();
    let original_root = std::fs::read(&root).unwrap();
    let old_root = {
        let mut image = super::super::header(ID, super::super::READY).to_vec();
        image.resize(ROOT_FILE_BYTES as usize, 0);
        image
    };
    let prepared_root = {
        let mut image = original_root.clone();
        image[..HEADER_BYTES].copy_from_slice(&envelope(ID, ROOT_KIND, PREPARED, 0));
        image
    };
    let legacy_kv = {
        let mut image = b"KASUMI-KV-000001".to_vec();
        image.resize(8192, 0);
        image
    };
    let foreign = {
        let mut image = envelope(OTHER, SEGMENT_KIND, READY, 1).to_vec();
        image.extend_from_slice(b"payload");
        image
    };
    let write = |path: &Path, bytes: &[u8]| {
        let file = raw_options()
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        std::os::unix::fs::FileExt::write_all_at(&file, bytes, 0).unwrap();
        file.sync_all().unwrap();
    };
    type Case<'a> = (&'a str, Box<dyn Fn() + 'a>, Box<dyn Fn() + 'a>);
    let cases: Vec<Case<'_>> = vec![
        (
            "unsupported segment group file format",
            Box::new(|| write(&root, &old_root)),
            Box::new(|| write(&root, &original_root)),
        ),
        (
            "initialization is incomplete",
            Box::new(|| write(&root, &prepared_root)),
            Box::new(|| write(&root, &original_root)),
        ),
        (
            "unsupported segment group file format",
            Box::new(|| write(&segment, &legacy_kv)),
            Box::new(|| write(&segment, &original_segment)),
        ),
        (
            "identity differs",
            Box::new(|| write(&segment, &foreign)),
            Box::new(|| write(&segment, &original_segment)),
        ),
        (
            "names another file",
            Box::new(|| {
                write(
                    &path.join(GroupFile::segment(2).file_name()),
                    &original_segment,
                )
            }),
            Box::new(|| {
                std::fs::remove_file(path.join(GroupFile::segment(2).file_name())).unwrap()
            }),
        ),
        (
            "names another file",
            Box::new(|| {
                write(
                    &path.join(GroupFile::checkpoint(1).file_name()),
                    &original_segment,
                )
            }),
            Box::new(|| {
                std::fs::remove_file(path.join(GroupFile::checkpoint(1).file_name())).unwrap()
            }),
        ),
        (
            "not a group file",
            Box::new(|| write(&path.join("0000000000000001.kvseg.tmp"), b"")),
            Box::new(|| std::fs::remove_file(path.join("0000000000000001.kvseg.tmp")).unwrap()),
        ),
        (
            "not a group file",
            Box::new(|| write(&path.join("seg-0000000000000002.kvs"), b"")),
            Box::new(|| std::fs::remove_file(path.join("seg-0000000000000002.kvs")).unwrap()),
        ),
        (
            // A torn single-file envelope is not a prefix of this one.
            "envelope is incomplete",
            Box::new(|| {
                write(
                    &path.join(GroupFile::segment(5).file_name()),
                    b"KASUMI-NODE-0002",
                )
            }),
            Box::new(|| {
                std::fs::remove_file(path.join(GroupFile::segment(5).file_name())).unwrap()
            }),
        ),
        (
            "subdirectory",
            Box::new(|| {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path.join(GroupFile::segment(3).file_name()))
                    .unwrap()
            }),
            Box::new(|| std::fs::remove_dir(path.join(GroupFile::segment(3).file_name())).unwrap()),
        ),
        (
            // Zeros beyond one envelope are not an interrupted create.
            "unsupported segment group file format",
            Box::new(|| write(&path.join(GroupFile::segment(4).file_name()), &[0; 5000])),
            Box::new(|| {
                std::fs::remove_file(path.join(GroupFile::segment(4).file_name())).unwrap()
            }),
        ),
    ];
    for (reason, damage, restore) in cases {
        damage();
        disk.reconcile(&CensusCancellation::default()).unwrap();
        let before = tree(directory.path());
        let (group, opened) = acquire(&path, &disk, NodeOpeningMode::Existing, CACHE);
        let error = opened.unwrap_err();
        assert!(format!("{error:#}").contains(reason), "{reason}: {error:#}");
        close(&group);
        assert_eq!(tree(directory.path()), before, "{reason}");
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        restore();
        disk.reconcile(&CensusCancellation::default()).unwrap();
    }
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"payload");
    close(&group);
}

#[test]
fn foreign_runtime_entry_fences_the_listing() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    put(&group, GroupFile::segment(1), b"one");
    let foreign = path.join(GroupFile::segment(2).file_name());
    let file = raw_options().create_new(true).open(&foreign).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&file, b"foreign", 0).unwrap();
    drop(file);
    assert!(group.entries().is_err());
    assert!(group.exists(GroupFile::segment(1)).is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    recover(&group);
    // The fresh census enrolled the foreign name; the strict reopen refuses
    // its image. (An empty file under a group name is an interrupted create,
    // which the kv root alone can classify.)
    let (group, opened) = acquire(&path, &disk, NodeOpeningMode::Existing, CACHE);
    let error = opened.unwrap_err();
    assert!(
        format!("{error:#}").contains("envelope is incomplete"),
        "{error:#}"
    );
    close(&group);
    assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
}

#[test]
fn admitted_growth_pins_the_newest_segment_and_capacity_denial_has_no_effect() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let mut config = NodeDisk::fixture_config(&path).unwrap();
    config.max_bytes = 8 << 20;
    config.maintenance_reserve_bytes = 0;
    let disk = retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    let group = ready_group(&path, &disk, 1);
    put(&group, GroupFile::segment(1), b"old");
    group.create(GroupFile::segment(2)).unwrap();
    let before = disk.snapshot().charged_bytes;
    StorageAdmission::reserve_growth(&*group, 0, 1 << 20).unwrap();
    assert!(disk.snapshot().charged_bytes >= before + (1 << 20));
    // The admitted descriptor is pinned: a full one-cell cache refuses
    // another file without any effect instead of evicting it.
    assert_eq!(
        group.len(GroupFile::segment(1)).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert!(group.exists(GroupFile::segment(2)).unwrap());
    group.write(GroupFile::segment(2), 0, &[7; 4096]).unwrap();
    StorageAdmission::settle_growth(&*group, 4096).unwrap();
    let unit = crate::node_disk::filesystem(&File::open(directory.path()).unwrap())
        .unwrap()
        .1;
    assert_eq!(
        disk.snapshot().charged_bytes,
        before + file_extent(&path.join(GroupFile::segment(2).file_name()), unit)
    );
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"old");

    // Growth beyond the installed budget is denied before any effect.
    let charged = disk.snapshot().charged_bytes;
    assert!(matches!(
        StorageAdmission::reserve_growth(&*group, 4096, 64 << 20),
        Err(AdmissionError::CapacityDenied)
    ));
    assert_eq!(
        group
            .write(GroupFile::segment(2), 4096, &vec![0; 16 << 20])
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(
        group
            .set_len(GroupFile::segment(2), 32 << 20)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(group.len(GroupFile::segment(2)).unwrap(), 4096);
    StorageAdmission::check_owner(&*group).unwrap();
    drop(StorageAdmission::reserve_workspace(&*group, 1024).unwrap());
    group.sync(GroupFile::segment(2)).unwrap();
    close(&group);
}

#[test]
fn journal_owned_empty_root_is_initialized_only_when_exact() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    // The journal durably created the directory and its empty root inode.
    let child = disk
        .open_directory("fixture", Path::new(""))
        .unwrap()
        .create_child(c"group", DiskWork::Foreground)
        .unwrap();
    let mut root = disk
        .create_file(
            "fixture",
            &Path::new("group").join(ROOT_FILE_NAME),
            DiskWork::Foreground,
        )
        .unwrap();
    let identity = root.identity().unwrap();
    root.close().unwrap();
    let mut unrelated = disk
        .create_file("fixture", Path::new("unrelated"), DiskWork::Foreground)
        .unwrap();
    let other = unrelated.identity().unwrap();
    unrelated.close().unwrap();
    drop(child);
    let (group, acquired) = acquire(&path, &disk, NodeOpeningMode::OwnedEmpty(other), CACHE);
    assert!(acquired.is_err());
    close(&group);
    assert_eq!(
        std::fs::metadata(path.join(ROOT_FILE_NAME)).unwrap().len(),
        0
    );
    let (group, acquired) = acquire(
        &path,
        &disk,
        NodeOpeningMode::OwnedEmpty(identity.clone()),
        CACHE,
    );
    acquired.unwrap();
    // Prepared is not reopenable until the kv root is published.
    assert!(group.publish_ready().is_err());
    group
        .write_root(RootSlot::A, &[1; ROOT_SLOT_BYTES])
        .unwrap();
    group.publish_ready().unwrap();
    put(&group, GroupFile::segment(1), b"owned");
    close(&group);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"owned");
    close(&group);
    // A populated directory is never re-initialized.
    let (group, acquired) = acquire(&path, &disk, NodeOpeningMode::OwnedEmpty(identity), CACHE);
    assert!(acquired.is_err());
    close(&group);
    let group = reopen(&path, &disk, CACHE);
    assert_eq!(read_all(&group, GroupFile::segment(1)), b"owned");
    close(&group);
}

#[test]
fn cleanup_claims_only_recognized_groups_and_resumes_after_an_interrupted_delete() {
    let memory = memory();
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, CACHE);
    for id in 1..=3 {
        put(&group, GroupFile::segment(id), &[id as u8; 100]);
    }
    put(&group, GroupFile::checkpoint(1), b"checkpoint");
    close(&group);
    // Another identity or a foreign entry is refused before any deletion.
    let before = tree(directory.path());
    assert!(NodeSegmentGroup::claim_cleanup(&path, OTHER, disk.clone(), CACHE).is_err());
    assert_eq!(tree(directory.path()), before);
    let stray = path.join("stray");
    raw_options().create_new(true).open(&stray).unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    let before = tree(directory.path());
    assert!(NodeSegmentGroup::claim_cleanup(&path, ID, disk.clone(), CACHE).is_err());
    assert_eq!(tree(directory.path()), before);
    assert_eq!(disk.snapshot().open_files, 0);
    std::fs::remove_file(&stray).unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();

    // An interrupted delete fences; the remaining names are claimed again.
    let cleanup = NodeSegmentGroup::claim_cleanup(&path, ID, disk.clone(), CACHE).unwrap();
    // The claim holds the exact root inode against a concurrent opening.
    let (opening, opened) = acquire(&path, &disk, NodeOpeningMode::Existing, CACHE);
    assert!(opened.is_err());
    close(&opening);
    cleanup.owner.inject(GroupFault::UnlinkAfterEffect);
    assert!(cleanup.delete().is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(!path.join(GroupFile::checkpoint(1).file_name()).exists());
    assert!(path.join(ROOT_FILE_NAME).exists());
    NodeSegmentGroup::claim_cleanup(&path, ID, disk.clone(), CACHE)
        .unwrap()
        .delete()
        .unwrap();
    assert!(!path.exists());

    // A Prepared group, never published, is recognized too.
    let (group, created) = acquire(&path, &disk, NodeOpeningMode::Create, CACHE);
    created.unwrap();
    put(&group, GroupFile::segment(1), b"unpublished");
    close(&group);
    assert!(
        acquire(&path, &disk, NodeOpeningMode::Existing, CACHE)
            .1
            .is_err()
    );
    NodeSegmentGroup::claim_cleanup(&path, ID, disk.clone(), CACHE)
        .unwrap()
        .delete()
        .unwrap();
    assert!(!path.exists());

    // The empty directory an interrupted cleanup leaves is removed alone.
    drop(
        disk.open_directory("fixture", Path::new(""))
            .unwrap()
            .create_child(c"group", DiskWork::Foreground)
            .unwrap(),
    );
    NodeSegmentGroup::claim_cleanup(&path, ID, disk.clone(), CACHE)
        .unwrap()
        .delete()
        .unwrap();
    assert!(!path.exists());
    assert_eq!(disk.snapshot().open_files, 0);
    let running = disk.snapshot().charged_bytes;
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, running);
    assert_eq!(running, expected_charge(directory.path()));
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_child(path: &Path, log_path: &Path) {
    let log = raw_options().create_new(true).open(log_path).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "node_file::segment_group::tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KASUMI_SEGMENT_GROUP_CHILD_PATH", path)
            // Child libtest lines must not interleave with the parent's test
            // result protocol. A regular file cannot deadlock on pipe capacity.
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let outcome = loop {
        match child.0.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "segment group crash child deadline elapsed",
                ));
            }
            Err(error) => break Err(error),
        }
    };
    if outcome
        .as_ref()
        .is_ok_and(|status| status.code() == Some(77))
    {
        return;
    }
    let kill = child.0.kill();
    let drain = child.0.wait();
    let mut diagnostic = Vec::new();
    let read =
        File::open(log_path).and_then(|file| file.take(16 << 10).read_to_end(&mut diagnostic));
    panic!(
        "segment group crash child failed: {outcome:?}; kill={kill:?}; drain={drain:?}; read={read:?}; first16KiB={}",
        String::from_utf8_lossy(&diagnostic)
    );
}

fn child_payload(id: u64) -> Vec<u8> {
    vec![id as u8; 3000 * id as usize]
}

#[test]
#[ignore = "subprocess helper; invoked with an owned temporary path"]
fn crash_child() {
    let memory = memory();
    let path = PathBuf::from(std::env::var_os("KASUMI_SEGMENT_GROUP_CHILD_PATH").unwrap());
    let disk = fixture_disk(&path, &memory);
    let group = ready_group(&path, &disk, 4);
    for id in 1..=12 {
        put(&group, GroupFile::segment(id), &child_payload(id));
    }
    put(&group, GroupFile::checkpoint(1), &[9; 5000]);
    for id in [2, 5] {
        group.unlink(GroupFile::segment(id)).unwrap();
    }
    // An interrupted roll and an unsynchronized append at the process exit.
    group.create(GroupFile::segment(13)).unwrap();
    group
        .write(GroupFile::segment(12), 3000 * 12, b"unsynchronized tail")
        .unwrap();
    std::process::exit(77);
}

#[test]
fn census_equals_extents_after_crash_child_restart() {
    let directory = private_tempdir().unwrap();
    let logs = private_tempdir().unwrap();
    let path = directory.path().join("group");
    run_child(&path, &logs.path().join("crash-child.log"));
    // This process has never registered the root: its census is fresh.
    let memory = memory();
    let disk = fixture_disk(&path, &memory);
    assert_eq!(
        disk.snapshot().charged_bytes,
        expected_charge(directory.path())
    );
    // Ten live segments, the checkpoint, the interrupted roll and the root.
    assert_eq!(disk.snapshot().persistent_files, 13);
    let group = reopen(&path, &disk, 4);
    for id in (1..=12).filter(|id| ![2, 5].contains(id)) {
        let mut expected = child_payload(id);
        if id == 12 {
            // A restart without power loss keeps the unsynchronized append.
            expected.extend_from_slice(b"unsynchronized tail");
        }
        assert_eq!(read_all(&group, GroupFile::segment(id)), expected);
    }
    for id in [2, 5] {
        assert!(!group.exists(GroupFile::segment(id)).unwrap());
    }
    assert_eq!(group.len(GroupFile::segment(13)).unwrap(), 0);
    assert_eq!(read_all(&group, GroupFile::checkpoint(1)), [9; 5000]);
    let unit = crate::node_disk::filesystem(&File::open(directory.path()).unwrap())
        .unwrap()
        .1;
    let charged = disk.snapshot().charged_bytes;
    let extent = file_extent(&path.join(GroupFile::segment(7).file_name()), unit);
    group.unlink(GroupFile::segment(7)).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, charged - extent);
    group
        .write(GroupFile::segment(13), 0, b"resumed roll")
        .unwrap();
    group.sync(GroupFile::segment(13)).unwrap();
    close(&group);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        expected_charge(directory.path())
    );
    assert_eq!(disk.snapshot().persistent_files, 12);
    let group = reopen(&path, &disk, 4);
    assert_eq!(read_all(&group, GroupFile::segment(13)), b"resumed roll");
    close(&group);
}
