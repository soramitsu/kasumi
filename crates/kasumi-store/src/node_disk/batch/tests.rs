use super::*;
use crate::{
    CensusCancellation, NodeDiskConfig,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let directory = private_tempdir().unwrap();
    let config = NodeDisk::fixture_config(directory.path().join("unused")).unwrap();
    (directory, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn requests() -> [NamespacePart<'static>; 5] {
    [
        NamespacePart {
            root: "fixture",
            relative: Path::new("sessions"),
            kind: NamespacePartKind::Directory,
        },
        NamespacePart {
            root: "fixture",
            relative: Path::new("sessions/session"),
            kind: NamespacePartKind::Directory,
        },
        NamespacePart {
            root: "fixture",
            relative: Path::new("sessions/session/objects"),
            kind: NamespacePartKind::Directory,
        },
        NamespacePart {
            root: "fixture",
            relative: Path::new("sessions/session/intent.reserve"),
            kind: NamespacePartKind::File { length: 4096 },
        },
        NamespacePart {
            root: "fixture",
            relative: Path::new("sessions/session/outcome.reserve"),
            kind: NamespacePartKind::File { length: 4096 },
        },
    ]
}

#[test]
fn complete_plan_shortages_precede_every_namespace_effect() {
    for shortage in 0..6 {
        let (directory, mut config, memory) = fixture();
        match shortage {
            0 => config.max_persistent_files = 1,
            1 => config.max_persistent_subdirectories = 2,
            2 => config.max_open_files = 1,
            3 => config.max_open_directories = 3,
            4 => config.directory_policy.max_entries = 2,
            5 => {
                config.maintenance_reserve_bytes = 0;
                config.max_bytes = 2 * config.directory_policy.extent_bytes;
            }
            _ => unreachable!(),
        }
        let disk = open(&config, &memory);
        let root = disk.open_directory("fixture", Path::new("")).unwrap();
        let before = disk.snapshot();
        assert!(
            disk.admit_namespace(&requests(), DiskWork::Foreground)
                .is_err(),
            "shortage {shortage}"
        );
        assert!(!directory.path().join("sessions").exists());
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        assert!(disk.lock_state().namespace_batch.is_none());
        drop(root);
    }
}

#[test]
fn permits_transfer_exactly_once_without_charging_extent_twice() {
    let (directory, mut config, memory) = fixture();
    config.max_persistent_files = 2;
    config.max_persistent_subdirectories = 3;
    config.max_open_files = 2;
    config.max_open_directories = 4;
    let disk = open(&config, &memory);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    let mut admission = disk
        .admit_namespace(&requests(), DiskWork::Foreground)
        .unwrap();
    let promised = 3 * config.directory_policy.extent_bytes
        + 2 * super::super::file_ceiling(4096, disk.unit, config.file_allocation_policy).unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + promised
    );
    assert_eq!(
        disk.snapshot().pending_bytes,
        before.pending_bytes + promised
    );
    assert_eq!(
        disk.create_file("fixture", Path::new("unrelated"), DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    let sessions = root
        .create_admitted_child(c"sessions", &mut admission)
        .unwrap();
    let session = sessions
        .create_admitted_child(c"session", &mut admission)
        .unwrap();
    let objects = session
        .create_admitted_child(c"objects", &mut admission)
        .unwrap();
    for name in ["intent.reserve", "outcome.reserve"] {
        let relative = format!("sessions/session/{name}");
        let file = disk
            .create_admitted_file(&mut admission, "fixture", Path::new(&relative))
            .unwrap();
        assert_eq!(
            disk.snapshot().charged_bytes,
            before.charged_bytes + promised
        );
        file.reserve_growth(0, 4096, DiskWork::Foreground).unwrap();
        assert_eq!(
            disk.snapshot().charged_bytes,
            before.charged_bytes + promised
        );
        file.grow_reserved(4096).unwrap();
        file.sync_all_and_parent().unwrap();
        assert_eq!(
            directory.path().join(relative).metadata().unwrap().len(),
            4096
        );
    }
    admission.finish().unwrap();
    assert!(disk.lock_state().namespace_batch.is_none());
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert_eq!(
        disk.snapshot().persistent_directories,
        before.persistent_directories + 3
    );
    drop((objects, session, sessions, root));
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + promised
    );
}

/// Admission pays the byte ceiling and the free floor once. Free space taken
/// by another writer, or maintenance growth above the foreground ceiling,
/// must not refuse the admitted creates afterwards: any refusal there fenced
/// the whole disk.
#[test]
fn admitted_creates_spend_their_promise_after_the_floor_or_ceiling_moves() {
    for ceiling in [false, true] {
        let (directory, mut config, memory) = fixture();
        config.max_bytes = 64 << 20;
        config.maintenance_reserve_bytes = 16 << 20;
        let disk = open(&config, &memory);
        let root = disk.open_directory("fixture", Path::new("")).unwrap();
        let mut admission = disk
            .admit_namespace(&requests(), DiskWork::Foreground)
            .unwrap();
        let maintenance = if ceiling {
            *disk.available_override.lock().unwrap() = Some(1 << 40);
            let file = disk
                .create_file("fixture", Path::new("maintenance"), DiskWork::Maintenance)
                .unwrap();
            let foreground = config.max_bytes - config.maintenance_reserve_bytes;
            let requested = foreground - disk.snapshot().charged_bytes + 4096;
            file.reserve_growth(0, requested, DiskWork::Maintenance)
                .unwrap();
            assert!(disk.snapshot().charged_bytes > foreground);
            Some(file)
        } else {
            *disk.available_override.lock().unwrap() = Some(0);
            None
        };
        let sessions = root
            .create_admitted_child(c"sessions", &mut admission)
            .unwrap();
        let session = sessions
            .create_admitted_child(c"session", &mut admission)
            .unwrap();
        let objects = session
            .create_admitted_child(c"objects", &mut admission)
            .unwrap();
        for name in ["intent.reserve", "outcome.reserve"] {
            let relative = format!("sessions/session/{name}");
            let file = disk
                .create_admitted_file(&mut admission, "fixture", Path::new(&relative))
                .unwrap();
            file.grow_reserved(4096).unwrap();
            file.sync_all_and_parent().unwrap();
        }
        admission.finish().unwrap();
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        assert!(directory.path().join("sessions/session/objects").is_dir());
        // Unadmitted work still meets the moved floor or ceiling, unfenced.
        assert_eq!(
            disk.create_file("fixture", Path::new("unadmitted"), DiskWork::Foreground)
                .unwrap_err()
                .kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        *disk.available_override.lock().unwrap() = None;
        drop((maintenance, objects, session, sessions, root));
    }
}

/// Census charges an existing directory's whole observed extent, which can
/// exceed the policy, and such a parent refuses every new child. Admission
/// refuses it before any effect instead of the admitted create, whose
/// refusal fenced the whole disk.
#[test]
fn admission_refuses_a_parent_charged_beyond_its_extent_policy() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let sessions = root
        .create_child(c"sessions", DiskWork::Foreground)
        .unwrap();
    {
        let (device, inode) = sessions.verified_identity().unwrap();
        let mut state = disk.lock_state();
        disk.reserve(&mut state, 0, disk.unit, DiskWork::Foreground)
            .unwrap();
        let entry = state
            .accounted
            .get_mut(&super::super::Identity(device, inode))
            .and_then(AccountedInode::directory_mut)
            .unwrap();
        entry.bytes += disk.unit;
        entry.pending += disk.unit;
    }
    let before = disk.snapshot();
    assert_eq!(
        disk.admit_namespace(&requests()[1..], DiskWork::Foreground)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert!(disk.lock_state().namespace_batch.is_none());
    assert!(!directory.path().join("sessions/session").exists());
    assert_eq!(
        sessions
            .create_child(c"session", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[test]
fn pristine_cancel_retires_all_future_backing_and_returns_exact_credit() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let before = disk.snapshot();
    let admission = disk
        .admit_namespace(&requests(), DiskWork::Foreground)
        .unwrap();
    assert!(disk.snapshot().charged_bytes > before.charged_bytes);
    admission.cancel().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert!(disk.lock_state().namespace_batch.is_none());
}

#[test]
fn abandoned_or_partially_consumed_plan_stays_retained_until_complete_census() {
    for effect in [false, true] {
        let (_directory, config, memory) = fixture();
        let disk = open(&config, &memory);
        let root = disk.open_directory("fixture", Path::new("")).unwrap();
        let before = disk.snapshot();
        let mut admission = disk
            .admit_namespace(&requests(), DiskWork::Foreground)
            .unwrap();
        if effect {
            drop(
                root.create_admitted_child(c"sessions", &mut admission)
                    .unwrap(),
            );
        }
        let retained = disk.snapshot().charged_bytes;
        drop(admission);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, retained);
        assert!(disk.lock_state().namespace_batch.is_some());
        drop(root);
        let cancel = CensusCancellation::default();
        cancel.cancel();
        assert!(disk.reconcile(&cancel).is_err());
        assert!(disk.lock_state().namespace_batch.is_some());
        assert_eq!(disk.snapshot().charged_bytes, retained);
        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert!(disk.lock_state().namespace_batch.is_none());
        assert_eq!(
            disk.snapshot().charged_bytes,
            before.charged_bytes + u64::from(effect) * config.directory_policy.extent_bytes
        );
    }
}

#[test]
fn wrong_binding_duplicate_transfer_and_premature_finish_cannot_spend_permits() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let mut admission = disk
        .admit_namespace(&requests(), DiskWork::Foreground)
        .unwrap();
    {
        let mut state = disk.lock_state();
        let binding = state.namespace_batch.as_ref().unwrap().parts[3]
            .as_ref()
            .unwrap()
            .binding;
        assert!(
            admission
                .take_directory(&mut state, "fixture", binding)
                .is_err()
        );
        assert!(
            admission
                .take_file(&mut state, "wrong-root", binding)
                .is_err()
        );
        assert_eq!(reserved_files(&state), 2);
    }
    assert!(admission.finish().is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(disk.lock_state().namespace_batch.is_some());
}

#[test]
fn reserved_binding_and_parent_allowance_remain_unavailable_to_unrelated_creates() {
    let (_directory, mut config, memory) = fixture();
    config.directory_policy.max_entries = 1;
    let disk = open(&config, &memory);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let admission = disk
        .admit_namespace(
            &[NamespacePart {
                root: "fixture",
                relative: Path::new("held"),
                kind: NamespacePartKind::Directory,
            }],
            DiskWork::Foreground,
        )
        .unwrap();
    assert_eq!(
        root.create_child(c"held", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        root.create_child(c"other", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    admission.cancel().unwrap();
    drop(root.create_child(c"other", DiskWork::Foreground).unwrap());
}

#[test]
fn physical_owner_excludes_a_second_reservation_writer_until_actual_retirement() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let mut admission = disk
        .admit_namespace(
            &[NamespacePart {
                root: "fixture",
                relative: Path::new("outcome.reserve"),
                kind: NamespacePartKind::File { length: 4096 },
            }],
            DiskWork::Foreground,
        )
        .unwrap();
    let file = disk
        .create_admitted_file(&mut admission, "fixture", Path::new("outcome.reserve"))
        .unwrap();
    file.grow_reserved(4096).unwrap();
    file.sync_all_and_parent().unwrap();
    admission.finish().unwrap();
    let wrapper = disk.clone();
    assert_eq!(
        wrapper
            .open_file("fixture", Path::new("outcome.reserve"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    drop(file);
    let writer = wrapper
        .open_file("fixture", Path::new("outcome.reserve"))
        .unwrap();
    writer.write_all_at(b"outcome", 0).unwrap();
    writer.sync_all_and_parent().unwrap();
    let published = wrapper
        .publish_file(writer, "fixture", Path::new("outcome.kasumi"))
        .unwrap();
    assert_eq!(
        disk.open_file("fixture", Path::new("outcome.kasumi"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(published);
    assert!(
        disk.open_file("fixture", Path::new("outcome.kasumi"))
            .is_ok()
    );
    assert_eq!(disk.snapshot().persistent_files, 1);
}

#[test]
fn descendant_claim_uses_retained_prefix_and_exact_component_limits() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let nested = root.create_child(c"nested", DiskWork::Foreground).unwrap();
    let uuid = c"11111111-1111-1111-1111-111111111111";
    let names = [c"sessions", uuid];
    let base = NamespaceBinding::root(disk.roots["fixture"].identity);
    let root_claim = root.claim_descendants(&names).unwrap();
    assert_eq!(root_claim.binding, base.child(names[0]).child(names[1]));
    assert!(Arc::ptr_eq(&root_claim.disk, &disk));
    drop(root_claim);
    let nested_claim = nested.claim_descendants(&names).unwrap();
    assert_eq!(
        nested_claim.binding,
        base.child(c"nested").child(names[0]).child(names[1])
    );
    drop(nested_claim);
    for name in [c"", c".", c"..", c"bad/name"] {
        assert_eq!(
            root.claim_descendants(&[name]).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let boundary = CString::new(vec![b'x'; config.max_name_bytes as usize]).unwrap();
    drop(root.claim_descendants(&[&boundary]).unwrap());
    let overflow = CString::new(vec![b'x'; config.max_name_bytes as usize + 1]).unwrap();
    assert_eq!(
        root.claim_descendants(&[&overflow]).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    let names = vec![c"x"; config.max_depth as usize - 1];
    drop(root.claim_descendants(&names).unwrap());
    assert_eq!(
        nested.claim_descendants(&names).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    let names = vec![c"x"; config.max_depth as usize];
    assert_eq!(
        root.claim_descendants(&names).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}
