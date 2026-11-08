use super::*;

fn open(
    group: &InMemoryGroup,
    roll: Arc<Roll>,
    admission: Arc<Admission>,
) -> DirectoryArenaBackend {
    let mut stage = ArenaOpening::default();
    stage
        .build_with_format(
            BackendRef::Original(crate::native_backend::OriginalBackend::component_fixture(
                Arc::new(group.clone()),
            )),
            roll,
            admission,
            GROUP,
            true,
        )
        .unwrap();
    let mut arena = stage.take_completed().unwrap();
    arena.max_pages = 2;
    arena
}

fn varied() -> Vec<u8> {
    let mut seed = 0x369d_ae95_u32;
    (0..DIRECTORY_PAGE_BYTES)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect()
}

#[test]
fn packed_and_raw_pages_share_one_arena_and_preserve_physical_reservations_and_floors() {
    let (group, roll, admission, _) = setup();
    let arena = open(&group, roll.clone(), admission.clone());
    assert_eq!(
        admission.last_workspace_bytes.load(Ordering::SeqCst),
        DirectoryArenaBackend::request_bytes::<Arc<Roll>>() + packed::SCRATCH_BYTES as u64
    );
    let charged = admission.workspace_calls.load(Ordering::SeqCst);
    admission.deny_workspace.store(true, Ordering::SeqCst);
    let compressible = [0x5a; DIRECTORY_PAGE_BYTES];
    let random = varied();
    let first = arena.append_page(&compressible).unwrap();
    let (start, size) = packed::extent(first.page_index).unwrap();
    assert_eq!(start, HEADER_BYTES as u64);
    assert!(size < 128, "stored {size} bytes for a constant 16 KiB page");
    let floor = arena.append_floor();
    assert!(floor.precedes(first));
    let (existing, fresh) = arena.transaction_space(2, 2).unwrap();
    let existing = existing.unwrap();
    assert_eq!(existing.initial_len, HEADER_BYTES as u64 + size as u64);
    assert_eq!(
        existing.maximum_len,
        existing.initial_len + DIRECTORY_PAGE_BYTES as u64
    );
    assert_eq!(fresh.count, 1);
    let second = arena.append_page(&random).unwrap();
    assert_eq!(first.arena_id, second.arena_id);
    assert!(!floor.precedes(second));
    assert_eq!(
        packed::extent(second.page_index).unwrap(),
        (existing.initial_len, DIRECTORY_PAGE_BYTES)
    );
    assert_eq!(group.len(existing.file).unwrap(), existing.maximum_len);
    let third = arena.append_page(&[0x7c; DIRECTORY_PAGE_BYTES]).unwrap();
    assert_eq!(third.arena_id, first.arena_id + 1);
    assert!(group.len(GroupFile::directory(third.arena_id)).unwrap() < fresh.last_len);
    arena.sync_pages().unwrap();
    let mut out = [0; DIRECTORY_PAGE_BYTES];
    for (reference, expected) in [
        (first, compressible.as_slice()),
        (second, random.as_slice()),
    ] {
        arena.read_page(reference, &mut out).unwrap();
        assert_eq!(out.as_slice(), expected);
    }
    assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), charged);
    admission.deny_workspace.store(false, Ordering::SeqCst);
    let crashed = group.crash();
    let restarted = open(
        &crashed,
        Arc::new(Roll {
            group: crashed.clone(),
            root: Mutex::new(roll.root.lock().unwrap().clone()),
        }),
        admission,
    );
    restarted.read_page(first, &mut out).unwrap();
    assert_eq!(out, compressible);
    restarted.read_page(second, &mut out).unwrap();
    assert_eq!(out.as_slice(), random);
    restarted.read_page(third, &mut out).unwrap();
    assert_eq!(out, [0x7c; DIRECTORY_PAGE_BYTES]);
    assert!(restarted.append_page(&random).unwrap().arena_id > third.arena_id);
}

#[test]
fn packed_reads_reject_invalid_extent_truncation_and_decoded_digest_mismatch() {
    let (group, roll, admission, _) = setup();
    let arena = open(&group, roll, admission);
    let reference = arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
    let file = GroupFile::directory(reference.arena_id);
    let (at, n) = packed::extent(reference.page_index).unwrap();
    let mut out = [0; DIRECTORY_PAGE_BYTES];
    for invalid in [
        DirectoryPageRef {
            page_index: u64::MAX,
            ..reference
        },
        DirectoryPageRef {
            sha256: [0; 32],
            ..reference
        },
        DirectoryPageRef {
            page_index: packed::reference(0, n + 1),
            ..reference
        },
    ] {
        assert!(matches!(
            arena
                .read_page(invalid, &mut out)
                .unwrap_err()
                .rejected_cause(),
            Some(crate::CoreErrorCause::Corrupt(_))
        ));
    }
    group.write(file, at, &vec![0xff; n]).unwrap();
    assert!(matches!(
        arena
            .read_page(reference, &mut out)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::Corrupt(_))
    ));
    group.set_len(file, at + n as u64 - 1).unwrap();
    assert!(matches!(
        arena
            .read_page(reference, &mut out)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::Corrupt(_))
    ));
}

#[test]
fn interrupted_packed_header_recovery_preserves_format_and_refuses_foreign_or_legacy_header() {
    let admission: Arc<dyn StorageAdmission> = Arc::new(Admission::default());
    let file = GroupFile::directory(1);
    let mut expected = [0; HEADER_BYTES];
    encode_header_into(GROUP, 1, true, &mut expected);
    for end in [0, 15, 16, 17, 127, HEADER_BYTES - 1, HEADER_BYTES] {
        let group = InMemoryGroup::new();
        group.create(file).unwrap();
        group.write(file, 0, &expected[..end]).unwrap();
        recover_directory_intent_with_format(&group, &admission, GROUP, 1, true).unwrap();
        let restarted = group.crash();
        let mut actual = [0; HEADER_BYTES];
        restarted.read(file, 0, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(validate_header(&actual, GROUP, 1, false).is_err());
    }
    let group = InMemoryGroup::new();
    group.create(file).unwrap();
    group.write(file, 0, &encode_header(GROUP, 1)).unwrap();
    assert!(recover_directory_intent_with_format(&group, &admission, GROUP, 1, true).is_err());
}

#[test]
fn torn_packed_append_never_changes_a_durable_page_or_reuses_its_offset_after_reopen() {
    for prefix_case in 0..5 {
        // The fault injector updates the old image's durable prefix. Start
        // each simulated power loss from the same independent durable state.
        let (group, roll, admission, _) = setup();
        let arena = open(&group, roll.clone(), admission.clone());
        let old = arena.append_page(&[0x16; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.sync_pages().unwrap();
        let next = arena.append_page(&[0x20; DIRECTORY_PAGE_BYTES]).unwrap();
        let (_, n) = packed::extent(next.page_index).unwrap();
        let keep = [0, 1, n / 2, n - 1, n][prefix_case];
        let damaged = group.crash_torn(GroupFile::directory(old.arena_id), keep);
        let restart = open(
            &damaged,
            Arc::new(Roll {
                group: damaged.clone(),
                root: Mutex::new(roll.root.lock().unwrap().clone()),
            }),
            admission.clone(),
        );
        let mut page = [0; DIRECTORY_PAGE_BYTES];
        restart.read_page(old, &mut page).unwrap();
        assert_eq!(page, [0x16; DIRECTORY_PAGE_BYTES]);
        if keep == n {
            restart.read_page(next, &mut page).unwrap();
            assert_eq!(page, [0x20; DIRECTORY_PAGE_BYTES]);
        } else {
            assert!(restart.read_page(next, &mut page).is_err());
        }
        let fresh = restart.append_page(&[0x30; DIRECTORY_PAGE_BYTES]).unwrap();
        assert!(fresh.arena_id > next.arena_id);
    }
}
