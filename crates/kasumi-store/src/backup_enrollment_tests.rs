//! Enrolled filesystem roots: creation, crash cuts, marker rejection and
//! substitution fences, through the public destination and a real NodeDisk.
use super::enrollment::{
    MARKER_NAME, test_after_effect,
    test_cut::{self, Step},
};
use super::*;
use crate::backup_marker::{MARKER_BYTES, Marker};
use crate::{FilesystemBackupDestination, NodeDiskPhase};
use kasumi_types::TrustVerifierIdentity;
use std::os::unix::fs::MetadataExt;

fn owner() -> TrustVerifierIdentity {
    TrustVerifierIdentity {
        installation_id: Uuid::from_u128(0x3f1c_9b20_7d44_4a6e_8c11_52e0_9ab7_c3d5),
        node_id: 7,
    }
}

fn marker_path(root: &Path) -> PathBuf {
    root.join(MARKER_NAME.to_str().unwrap())
}

fn entries(path: &Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn filesystem(
    owner: &TrustVerifierIdentity,
    namespace_id: Uuid,
    device: u64,
    inode: u64,
) -> BackupNamespaceBinding {
    BackupNamespaceBinding::Filesystem {
        installation_id: owner.installation_id,
        origin_node_id: owner.node_id,
        namespace_id,
        device,
        inode,
    }
}

/// A private accounting root installed over a fresh temporary directory; the
/// backup root itself is always a child that only enrollment may create.
fn installed() -> (
    tempfile::TempDir,
    Arc<crate::test_utils::TestDiskMemory>,
    Arc<crate::NodeDisk>,
    PathBuf,
) {
    let temporary = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(temporary.path().join("unused"), memory.clone())
    })
    .unwrap();
    let path = temporary.path().join("backups");
    (temporary, memory, disk, path)
}

// Every managed handle has retired; a fresh census models a process restart.
fn restart(disk: &crate::NodeDisk) {
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[tokio::test]
async fn enrolled_backup_root_binds_marker_owner_and_reopens_only_exactly() {
    let (temporary, _memory, disk, path) = installed();
    let namespace_id = Uuid::new_v4();
    // Invalid inputs are rejected before any namespace effect.
    for (identity, namespace, max_bytes) in [
        (
            TrustVerifierIdentity {
                installation_id: Uuid::nil(),
                node_id: 7,
            },
            namespace_id,
            1,
        ),
        (
            TrustVerifierIdentity {
                node_id: 0,
                ..owner()
            },
            namespace_id,
            1,
        ),
        (owner(), Uuid::nil(), 1),
        (owner(), Uuid::from_u128(1), 1),
        (owner(), namespace_id, 0),
    ] {
        assert!(
            FilesystemBackupDestination::enroll(
                &path,
                max_bytes,
                disk.clone(),
                &identity,
                namespace
            )
            .is_err()
        );
        assert!(!path.exists());
    }
    // An installed accounting root already exists; it can never be enrolled.
    assert!(
        FilesystemBackupDestination::enroll(
            temporary.path(),
            1,
            disk.clone(),
            &owner(),
            namespace_id
        )
        .is_err()
    );
    assert!(!marker_path(temporary.path()).exists());
    // Enrollment creates only the root itself, never a missing ancestor.
    assert!(
        FilesystemBackupDestination::enroll(
            temporary.path().join("absent/backups"),
            1,
            disk.clone(),
            &owner(),
            namespace_id
        )
        .is_err()
    );
    assert!(!temporary.path().join("absent").exists());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);

    let before = disk.snapshot();
    let destination =
        FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &owner(), namespace_id)
            .unwrap();
    let metadata = path.metadata().unwrap();
    let binding = destination.namespace_binding().unwrap();
    assert_eq!(
        binding,
        filesystem(&owner(), namespace_id, metadata.dev(), metadata.ino())
    );
    let marker = std::fs::read(marker_path(&path)).unwrap();
    assert_eq!(marker, Marker::from_binding(&binding).unwrap().encode());
    assert_eq!(
        std::fs::metadata(marker_path(&path)).unwrap().mode() & 0o777,
        0o600
    );
    let after = disk.snapshot();
    assert_eq!(
        after.persistent_directories,
        before.persistent_directories + 1
    );
    assert_eq!(after.persistent_files, before.persistent_files + 1);
    // No marker descriptor is retained, so further instances cannot contend.
    assert_eq!(after.open_files, before.open_files);
    let id = Uuid::new_v4();
    destination
        .put(id, BackupUpload::received(b"enrolled".to_vec()))
        .await
        .unwrap();

    // Completing the same enrollment and opening the exact binding both yield
    // further instances of the one root.
    let confirmed =
        FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &owner(), namespace_id)
            .unwrap();
    let reopened =
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &binding).unwrap();
    for other in [&confirmed, &reopened] {
        assert_eq!(other.namespace_binding().unwrap(), binding);
        assert_eq!(other.get(id, 1 << 20).await.unwrap(), b"enrolled");
    }
    // Another owner or namespace never adopts, re-marks or re-creates a root.
    for (identity, namespace) in [
        (
            TrustVerifierIdentity {
                node_id: 8,
                ..owner()
            },
            namespace_id,
        ),
        (owner(), Uuid::new_v4()),
    ] {
        assert!(
            FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &identity, namespace)
                .is_err()
        );
    }
    // Every bound field is exact, and S3 bindings never name a filesystem.
    let (device, inode) = (metadata.dev(), metadata.ino());
    for changed in [
        filesystem(
            &TrustVerifierIdentity {
                installation_id: Uuid::new_v4(),
                ..owner()
            },
            namespace_id,
            device,
            inode,
        ),
        filesystem(
            &TrustVerifierIdentity {
                node_id: 8,
                ..owner()
            },
            namespace_id,
            device,
            inode,
        ),
        filesystem(&owner(), Uuid::new_v4(), device, inode),
        filesystem(&owner(), namespace_id, device + 1, inode),
        filesystem(&owner(), namespace_id, device, inode + 1),
        BackupNamespaceBinding::S3 {
            https_origin: "https://s3.example/".into(),
            region: "ap-northeast-1".into(),
            bucket: "backups".into(),
            prefix: String::new(),
        },
    ] {
        assert!(
            FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &changed)
                .is_err(),
            "{changed:?}"
        );
    }
    assert!(FilesystemBackupDestination::open_enrolled(&path, 0, disk.clone(), &binding).is_err());
    assert_eq!(std::fs::read(marker_path(&path)).unwrap(), marker);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);

    drop((destination, confirmed, reopened));
    restart(&disk);
    let reopened =
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &binding).unwrap();
    assert_eq!(reopened.namespace_binding().unwrap(), binding);
    assert_eq!(reopened.get(id, 1 << 20).await.unwrap(), b"enrolled");
    // A named but absent backup is an error, not an empty success.
    assert!(reopened.get(Uuid::new_v4(), 1 << 20).await.is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[test]
fn backup_enrollment_crash_cuts_complete_or_fail_closed_without_repair() {
    for (step, lose_unsynced) in [
        (Step::RootCreated, false),
        (Step::MarkerCreated, false),
        (Step::MarkerWritten, false),
        // A real crash may lose written but unsynchronized marker bytes.
        (Step::MarkerWritten, true),
        (Step::MarkerSynced, false),
    ] {
        let (_temporary, _memory, disk, path) = installed();
        let namespace_id = Uuid::new_v4();
        let cut = test_cut::arm(&path, step);
        let error = FilesystemBackupDestination::enroll(
            &path,
            1 << 20,
            disk.clone(),
            &owner(),
            namespace_id,
        )
        .err()
        .expect("armed enrollment cut");
        assert!(format!("{error:#}").contains("injected crash"), "{error:#}");
        drop(cut);
        // An unfinished admission fences the owner exactly as a crash would.
        let finished = step == Step::MarkerSynced;
        assert_eq!(
            disk.snapshot().phase,
            if finished {
                NodeDiskPhase::Open
            } else {
                NodeDiskPhase::Failed
            },
            "{step:?}"
        );
        if lose_unsynced {
            std::fs::write(marker_path(&path), [0; 37]).unwrap();
        }
        restart(&disk);
        let metadata = path.metadata().unwrap();
        let expected = filesystem(&owner(), namespace_id, metadata.dev(), metadata.ino());
        let marker = std::fs::read(marker_path(&path)).ok();
        match step {
            Step::RootCreated => assert!(marker.is_none()),
            Step::MarkerCreated => assert_eq!(marker.as_deref(), Some(&[][..])),
            _ if lose_unsynced => assert_eq!(marker.as_deref(), Some(&[0; 37][..])),
            _ => assert_eq!(
                marker.as_deref(),
                Some(&Marker::from_binding(&expected).unwrap().encode()[..])
            ),
        }
        let listing = entries(&path);
        let resumed = FilesystemBackupDestination::enroll(
            &path,
            1 << 20,
            disk.clone(),
            &owner(),
            namespace_id,
        );
        if matches!(step, Step::RootCreated | Step::MarkerCreated) || lose_unsynced {
            assert!(resumed.is_err(), "{step:?}");
            assert!(
                FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &expected)
                    .is_err()
            );
            // Fail closed: nothing is marked, rewritten, repaired or removed.
            assert_eq!(std::fs::read(marker_path(&path)).ok(), marker);
            assert_eq!(entries(&path), listing);
            assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
            continue;
        }
        // A durable marker of this owner and namespace completes enrollment.
        let destination = resumed.unwrap();
        assert_eq!(destination.namespace_binding().unwrap(), expected);
        assert!(
            FilesystemBackupDestination::enroll(
                &path,
                1 << 20,
                disk.clone(),
                &owner(),
                Uuid::new_v4()
            )
            .is_err()
        );
        drop(destination);
        restart(&disk);
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &expected)
            .unwrap();
        assert_eq!(entries(&path), listing);
    }
}

#[derive(Clone, Copy, Debug)]
enum BadMarker {
    Unmarked,
    ForeignOwner,
    OtherNamespace,
    CorruptDigest,
    Short,
    Long,
    Legacy,
    OtherDirectory,
}

#[test]
fn unmarked_foreign_corrupt_and_copied_backup_markers_reject_without_recreation() {
    use BadMarker::*;
    for bad in [
        Unmarked,
        ForeignOwner,
        OtherNamespace,
        CorruptDigest,
        Short,
        Long,
        Legacy,
        OtherDirectory,
    ] {
        let (_temporary, _memory, disk, path) = installed();
        let namespace_id = Uuid::new_v4();
        // Produce the root out of band while stopped, then census it.
        crate::private_files::create_directory(&path).unwrap();
        let metadata = path.metadata().unwrap();
        let (device, inode) = (metadata.dev(), metadata.ino());
        let exact = Marker::new(owner(), namespace_id, device, inode).unwrap();
        let foreign = TrustVerifierIdentity {
            installation_id: Uuid::new_v4(),
            node_id: 7,
        };
        let bytes = match bad {
            Unmarked => None,
            ForeignOwner => Some(
                Marker::new(foreign, namespace_id, device, inode)
                    .unwrap()
                    .encode()
                    .to_vec(),
            ),
            OtherNamespace => Some(
                Marker::new(owner(), Uuid::new_v4(), device, inode)
                    .unwrap()
                    .encode()
                    .to_vec(),
            ),
            CorruptDigest => {
                let mut bytes = exact.encode();
                bytes[MARKER_BYTES - 1] ^= 1;
                Some(bytes.to_vec())
            }
            Short => Some(exact.encode()[..MARKER_BYTES - 1].to_vec()),
            Long => Some([exact.encode().as_slice(), &[0]].concat()),
            Legacy => Some(b"legacy backup marker".to_vec()),
            // This owner's exact namespace, recorded for another directory.
            OtherDirectory => Some(
                Marker::new(owner(), namespace_id, device, inode + 1)
                    .unwrap()
                    .encode()
                    .to_vec(),
            ),
        };
        if let Some(bytes) = &bytes {
            crate::private_files::create(&marker_path(&path), bytes).unwrap();
        }
        restart(&disk);
        let listing = entries(&path);
        assert!(
            FilesystemBackupDestination::open_enrolled(
                &path,
                1 << 20,
                disk.clone(),
                &exact.binding()
            )
            .is_err(),
            "{bad:?}"
        );
        assert!(
            FilesystemBackupDestination::enroll(
                &path,
                1 << 20,
                disk.clone(),
                &owner(),
                namespace_id
            )
            .is_err(),
            "{bad:?}"
        );
        // Even the marker's own recorded binding cannot open another directory.
        if let OtherDirectory = bad {
            let recorded = Marker::decode(bytes.as_deref().unwrap()).unwrap();
            assert!(
                FilesystemBackupDestination::open_enrolled(
                    &path,
                    1 << 20,
                    disk.clone(),
                    &recorded.binding()
                )
                .is_err()
            );
        }
        assert_eq!(std::fs::read(marker_path(&path)).ok(), bytes, "{bad:?}");
        assert_eq!(entries(&path), listing, "{bad:?}");
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open, "{bad:?}");
    }
}

#[test]
fn backup_root_binding_survives_device_renumbering_but_not_a_copied_directory() {
    let (temporary, _memory, disk, path) = installed();
    let namespace_id = Uuid::new_v4();
    let destination =
        FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &owner(), namespace_id)
            .unwrap();
    let enrolled = destination.namespace_binding().unwrap();
    drop(destination);
    let metadata = path.metadata().unwrap();
    // Model a remount that renumbered st_dev after enrollment: the recorded
    // device differs from every live observation, the directory inode does not.
    let remounted = Marker::new(
        owner(),
        namespace_id,
        metadata.dev() ^ 0x5a5a,
        metadata.ino(),
    )
    .unwrap();
    std::fs::write(marker_path(&path), remounted.encode()).unwrap();
    restart(&disk);
    let destination = FilesystemBackupDestination::open_enrolled(
        &path,
        1 << 20,
        disk.clone(),
        &remounted.binding(),
    )
    .unwrap();
    assert_eq!(
        destination.namespace_binding().unwrap(),
        remounted.binding()
    );
    // The marker, not the live st_dev, is the binding: the former exact value
    // no longer names this root.
    drop(destination);
    assert!(
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &enrolled)
            .is_err()
    );

    // A byte-exact copy of the marker in a new directory is not the root, even
    // when it is installed at the configured path while stopped.
    let moved = temporary.path().join("moved");
    std::fs::rename(&path, &moved).unwrap();
    crate::private_files::create_directory(&path).unwrap();
    crate::private_files::create(&marker_path(&path), &remounted.encode()).unwrap();
    restart(&disk);
    assert!(
        FilesystemBackupDestination::open_enrolled(
            &path,
            1 << 20,
            disk.clone(),
            &remounted.binding()
        )
        .is_err()
    );
    assert!(
        FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &owner(), namespace_id)
            .is_err()
    );
    // The binding names the directory, so the moved original still opens.
    FilesystemBackupDestination::open_enrolled(&moved, 1 << 20, disk.clone(), &remounted.binding())
        .unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[derive(Clone, Copy, Debug)]
enum Substitution {
    Rename,
    CopiedMarker,
    Symlink,
}

#[derive(Clone, Copy, Debug)]
enum Method {
    Binding,
    Put,
    Get,
    SessionPut,
    SessionGet,
    SessionObjects,
    SessionDelete,
}

struct SessionFixture {
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
    store: Arc<TenantStore>,
    keys: Arc<crate::test_utils::LocalKeyProvider>,
    disk: Arc<crate::NodeDisk>,
    path: PathBuf,
    destination: FilesystemBackupDestination,
}

impl SessionFixture {
    async fn new() -> Self {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = crate::test_utils::private_tempdir().unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let directory = crate::test_utils::private_tempdir().unwrap();
        let keys = Arc::new(crate::test_utils::LocalKeyProvider::new([73; 32]));
        let store = TenantStore::initialize_catalog_fixture(
            crate::NodeStore::create_new_fixture(
                directory.path().join("node"),
                crate::test_utils::NODE_STORE_ID,
                memory.clone(),
                scratch,
            )
            .unwrap(),
            "tenant".into(),
            keys.clone(),
        )
        .await
        .unwrap();
        let disk = store.persistent_disk().clone();
        let path = directory.path().join("backups");
        let destination = FilesystemBackupDestination::enroll(
            &path,
            crate::MAX_BACKUP_BUNDLE_BYTES,
            disk.clone(),
            &owner(),
            Uuid::new_v4(),
        )
        .unwrap();
        Self {
            _directory: directory,
            _scratch: scratch_directory,
            store,
            keys,
            disk,
            path,
            destination,
        }
    }
}

#[tokio::test]
async fn substituted_backup_root_fences_every_destination_method() {
    for substitution in [
        Substitution::Rename,
        Substitution::CopiedMarker,
        Substitution::Symlink,
    ] {
        for method in [
            Method::Binding,
            Method::Put,
            Method::Get,
            Method::SessionPut,
            Method::SessionGet,
            Method::SessionObjects,
            Method::SessionDelete,
        ] {
            let fixture = SessionFixture::new().await;
            let destination = &fixture.destination;
            let session =
                super::super::tests::begin(destination, &fixture.store, fixture.keys.clone()).await;
            let session_id = session.intent().session_id;
            let object = Uuid::new_v4();
            destination
                .session_put(
                    session_id,
                    BackupSessionSlot::Object(object),
                    BackupUpload::received(vec![1]),
                )
                .await
                .unwrap();
            let proof = super::super::tests::abort(
                destination,
                &fixture.store,
                fixture.keys.clone(),
                &session,
            )
            .await;
            let backup = Uuid::new_v4();
            destination
                .put(backup, BackupUpload::received(b"backup".to_vec()))
                .await
                .unwrap();
            let page = destination.session_objects(&proof, 1).await.unwrap();
            assert_eq!(page.objects, vec![BackupSessionObject::File { id: object }]);

            let marker = std::fs::read(marker_path(&fixture.path)).unwrap();
            let moved = fixture.path.with_file_name("moved");
            std::fs::rename(&fixture.path, &moved).unwrap();
            match substitution {
                Substitution::Rename => {
                    crate::private_files::create_directory(&fixture.path).unwrap()
                }
                Substitution::CopiedMarker => {
                    crate::private_files::create_directory(&fixture.path).unwrap();
                    crate::private_files::create(&marker_path(&fixture.path), &marker).unwrap();
                }
                Substitution::Symlink => std::os::unix::fs::symlink(&moved, &fixture.path).unwrap(),
            }
            let fresh = Uuid::new_v4();
            let result = match method {
                Method::Binding => destination.namespace_binding().map(drop),
                Method::Put => {
                    destination
                        .put(fresh, BackupUpload::received(vec![2]))
                        .await
                }
                Method::Get => destination.get(backup, 1 << 20).await.map(drop),
                Method::SessionPut => {
                    destination
                        .session_put(
                            session_id,
                            BackupSessionSlot::Object(fresh),
                            BackupUpload::received(vec![3]),
                        )
                        .await
                }
                Method::SessionGet => destination
                    .session_get(session_id, BackupSessionSlot::Intent, 1 << 20)
                    .await
                    .map(drop),
                Method::SessionObjects => destination.session_objects(&proof, 1).await.map(drop),
                Method::SessionDelete => destination.session_delete(&proof, &page.objects).await,
            };
            assert!(result.is_err(), "{substitution:?} {method:?}");
            assert_eq!(
                fixture.disk.snapshot().phase,
                NodeDiskPhase::Failed,
                "{substitution:?} {method:?}"
            );
            // The fenced call reached neither the original nor the substitute.
            assert_eq!(
                std::fs::read(moved.join(format!("sessions/{session_id}/objects/{object}.kasumi")))
                    .unwrap(),
                [1]
            );
            for root in [&moved, &fixture.path] {
                assert!(!root.join(format!("{fresh}.kasumi")).exists());
                assert!(
                    !root
                        .join(format!("sessions/{session_id}/objects/{fresh}.kasumi"))
                        .exists()
                );
            }
            let substitute = match substitution {
                Substitution::Rename => Some(BTreeSet::new()),
                Substitution::CopiedMarker => {
                    Some(BTreeSet::from([MARKER_NAME.to_str().unwrap().to_owned()]))
                }
                Substitution::Symlink => None,
            };
            if let Some(substitute) = substitute {
                assert_eq!(entries(&fixture.path), substitute);
            }
        }
    }
}

/// A sibling owner of the same physical device, such as the scratch disk on
/// the persistent filesystem, may be uncertain while this owner is healthy.
/// Its refusal is not a substitution: backup calls fail without fencing this
/// owner, and succeed again after the sibling's own census.
#[tokio::test]
async fn sibling_device_uncertainty_refuses_backup_calls_without_fencing_their_owner() {
    let temporary = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::installed_device_memory();
    let config = crate::NodeDisk::fixture_config(temporary.path().join("unused")).unwrap();
    // Installed selection registers the device by `st_dev`, exactly as the
    // persistent and scratch owners of one filesystem do in production.
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::open(
            &config,
            memory.clone(),
            &crate::CensusCancellation::default(),
        )
    })
    .unwrap();
    let path = temporary.path().join("backups");
    let destination =
        FilesystemBackupDestination::enroll(&path, 1 << 20, disk.clone(), &owner(), Uuid::new_v4())
            .unwrap();
    let binding = destination.namespace_binding().unwrap();
    let published = Uuid::new_v4();
    destination
        .put(published, BackupUpload::received(b"published".to_vec()))
        .await
        .unwrap();
    let sibling = crate::test_utils::retry_disk_registry(|| {
        crate::device_disk::DeviceDisk::open(
            temporary.path().metadata().unwrap().dev(),
            0,
            memory.clone(),
        )
    })
    .unwrap();
    sibling.lock().fail_owner();
    assert!(!disk.snapshot().filesystem_admission_ready);

    let listing = entries(&path);
    let fresh = Uuid::new_v4();
    let other = temporary.path().join("other");
    assert!(destination.namespace_binding().is_err());
    assert!(
        destination
            .put(fresh, BackupUpload::received(b"fresh".to_vec()))
            .await
            .is_err()
    );
    assert!(destination.get(published, 1 << 20).await.is_err());
    assert!(
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &binding).is_err()
    );
    assert!(
        FilesystemBackupDestination::enroll(
            &other,
            1 << 20,
            disk.clone(),
            &owner(),
            Uuid::new_v4()
        )
        .is_err()
    );
    // This owner stays open, and none of the refused calls created anything.
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(entries(&path), listing);
    assert!(!other.exists());

    // The sibling's census clears only its own uncertainty; the same calls
    // then succeed on the unchanged root.
    sibling.lock().reconcile_owner();
    assert_eq!(destination.namespace_binding().unwrap(), binding);
    destination
        .put(fresh, BackupUpload::received(b"fresh".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        destination.get(published, 1 << 20).await.unwrap(),
        b"published"
    );
    assert_eq!(destination.get(fresh, 1 << 20).await.unwrap(), b"fresh");
    let reopened =
        FilesystemBackupDestination::open_enrolled(&path, 1 << 20, disk.clone(), &binding).unwrap();
    assert_eq!(reopened.namespace_binding().unwrap(), binding);
    drop((reopened, destination, sibling));
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[derive(Clone, Copy, Debug)]
enum Effect {
    Put,
    SessionPut,
}

#[tokio::test]
async fn root_substituted_after_an_effect_leaves_it_unconfirmed_and_in_place() {
    for substitution in [
        Substitution::Rename,
        Substitution::CopiedMarker,
        Substitution::Symlink,
    ] {
        for effect in [Effect::Put, Effect::SessionPut] {
            let fixture = SessionFixture::new().await;
            let destination = &fixture.destination;
            let session =
                super::super::tests::begin(destination, &fixture.store, fixture.keys.clone()).await;
            let session_id = session.intent().session_id;
            let object = Uuid::new_v4();
            let marker = std::fs::read(marker_path(&fixture.path)).unwrap();
            let moved = fixture.path.with_file_name("moved");
            // Substitute the root after the effect has completed and before
            // the closing verification observes it.
            let (root, original) = (fixture.path.clone(), moved.clone());
            let _swap = test_after_effect::arm(&fixture.path, move || {
                std::fs::rename(&root, &original).unwrap();
                match substitution {
                    Substitution::Rename => crate::private_files::create_directory(&root).unwrap(),
                    Substitution::CopiedMarker => {
                        crate::private_files::create_directory(&root).unwrap();
                        crate::private_files::create(&marker_path(&root), &marker).unwrap();
                    }
                    Substitution::Symlink => std::os::unix::fs::symlink(&original, &root).unwrap(),
                }
            });
            let upload = BackupUpload::received(b"effect".to_vec());
            let (result, published) = match effect {
                Effect::Put => (
                    destination.put(object, upload).await,
                    format!("{object}.kasumi"),
                ),
                Effect::SessionPut => (
                    destination
                        .session_put(session_id, BackupSessionSlot::Object(object), upload)
                        .await,
                    format!("sessions/{session_id}/objects/{object}.kasumi"),
                ),
            };
            let error = result.expect_err("an unverified effect is never a success");
            assert!(
                format!("{error:#}").contains("the outcome is unconfirmed"),
                "{substitution:?} {effect:?}: {error:#}"
            );
            assert_eq!(
                fixture.disk.snapshot().phase,
                NodeDiskPhase::Failed,
                "{substitution:?} {effect:?}"
            );
            // The durable effect stays in the moved original: it is neither
            // removed nor reported as rolled back, and the substitute is
            // untouched.
            assert_eq!(std::fs::read(moved.join(&published)).unwrap(), b"effect");
            let substitute = match substitution {
                Substitution::Rename => Some(BTreeSet::new()),
                Substitution::CopiedMarker => {
                    Some(BTreeSet::from([MARKER_NAME.to_str().unwrap().to_owned()]))
                }
                Substitution::Symlink => None,
            };
            if let Some(substitute) = substitute {
                assert_eq!(entries(&fixture.path), substitute);
            }
        }
    }
}

#[tokio::test]
async fn enrollment_inside_an_enrolled_root_is_rejected_before_any_effect() {
    let fixture = SessionFixture::new().await;
    let destination = &fixture.destination;
    let session =
        super::super::tests::begin(destination, &fixture.store, fixture.keys.clone()).await;
    let session_id = session.intent().session_id;
    let object = Uuid::new_v4();
    destination
        .session_put(
            session_id,
            BackupSessionSlot::Object(object),
            BackupUpload::received(vec![1]),
        )
        .await
        .unwrap();
    let before = fixture.disk.snapshot();
    // The root itself, an enrolled directory below it, and the object
    // namespace that aborted-session reclamation lists.
    for nested in [
        fixture.path.join("nested"),
        fixture.path.join("sessions/nested"),
        fixture
            .path
            .join(format!("sessions/{session_id}/objects/nested")),
    ] {
        let parent = nested.parent().unwrap().to_owned();
        let listing = entries(&parent);
        assert!(
            FilesystemBackupDestination::enroll(
                &nested,
                1 << 20,
                fixture.disk.clone(),
                &owner(),
                Uuid::new_v4()
            )
            .is_err(),
            "{nested:?}"
        );
        assert_eq!(entries(&parent), listing, "{nested:?}");
    }
    let after = fixture.disk.snapshot();
    assert_eq!(after.phase, NodeDiskPhase::Open);
    assert_eq!(
        (after.persistent_files, after.persistent_directories),
        (before.persistent_files, before.persistent_directories)
    );
    // The outer namespace is intact: its aborted objects still list and
    // reclaim exactly.
    let proof =
        super::super::tests::abort(destination, &fixture.store, fixture.keys.clone(), &session)
            .await;
    let page = destination.session_objects(&proof, 1).await.unwrap();
    assert_eq!(page.objects, vec![BackupSessionObject::File { id: object }]);
    destination
        .session_delete(&proof, &page.objects)
        .await
        .unwrap();
    // A sibling of the enrolled root is not nested and enrolls normally.
    FilesystemBackupDestination::enroll(
        fixture.path.with_file_name("sibling"),
        1 << 20,
        fixture.disk.clone(),
        &owner(),
        Uuid::new_v4(),
    )
    .unwrap();
    assert_eq!(fixture.disk.snapshot().phase, NodeDiskPhase::Open);
}
