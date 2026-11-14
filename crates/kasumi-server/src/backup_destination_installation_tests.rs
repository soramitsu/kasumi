use super::*;
use kasumi_store::BackupUpload;

async fn installed() -> (
    tempfile::TempDir,
    RuntimeConfig,
    crate::runtime_memory::RuntimeStorage,
) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (installation, storage) = initialize_fixture(directory.path().join("installation"))
        .await
        .unwrap();
    crate::standalone::drain_operations().await.unwrap();
    let config = RuntimeConfig::load(installation.configuration).unwrap();
    (directory, config, storage)
}
type FixtureInstallation = (
    crate::standalone::InitializedInstallation,
    crate::runtime_memory::RuntimeStorage,
);
type FixtureInitialization =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<FixtureInstallation>> + Send>>;

// Keep the aggregate installer future's construction and poll storage outside
// the test's frame; use the normal test/runtime stack without increasing it.
#[inline(never)]
fn initialize_fixture(directory: PathBuf) -> FixtureInitialization {
    Box::pin(async move {
        crate::runtime_storage_fixtures::initialize_standalone(&directory, "tenant").await
    })
}
async fn enroll_fixture(
    config: RuntimeConfig,
    request: EnrollmentRequest,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<EnrollmentReceipt> {
    let outcome = enroll_with_storage(config, request, storage).await;
    // Join acknowledged result handoffs before this test's runtime may retire.
    crate::standalone::drain_operations().await.unwrap();
    outcome
}

fn request(config: &RuntimeConfig) -> EnrollmentRequest {
    EnrollmentRequest {
        format: 1,
        destination: "extra".into(),
        directory: config.persistent_disk.roots["backups"].join("extra"),
        max_bytes: 1 << 20,
        namespace_id: Uuid::new_v4(),
    }
}
fn original(config: &RuntimeConfig) -> (&Path, &BackupNamespaceBinding) {
    let DestinationConfig::Filesystem {
        directory,
        namespace_binding,
        ..
    } = &config.backup_destinations["local"]
    else {
        panic!("filesystem installer")
    };
    (directory, namespace_binding)
}

#[tokio::test]
async fn explicit_enrollment_captures_actual_owner_marker_and_reopens_after_owner_restart() {
    let (_temporary, mut config, storage) = installed().await;
    let input = request(&config);
    let receipt = enroll_fixture(config.clone(), input.clone(), storage.clone())
        .await
        .unwrap();
    assert_eq!(receipt.destination, "extra");
    let bytes = serde_json::to_vec(&receipt).unwrap();
    // Same stable request is an observation of the exact original enrollment.
    let repeated = enroll_fixture(config.clone(), input.clone(), storage.clone())
        .await
        .unwrap();
    assert_eq!(serde_json::to_vec(&repeated).unwrap(), bytes);
    config
        .backup_destinations
        .insert(receipt.destination.clone(), receipt.configuration);
    let persisted = serde_json::to_vec(&config).unwrap();
    config = serde_json::from_slice(&persisted).unwrap();
    let id = Uuid::new_v4();
    for round in 0..2 {
        let disk = storage.open_persistent(&config.persistent_disk).unwrap();
        let owner = crate::standalone::claim(&config, &disk).unwrap().unwrap();
        let destinations = open_destinations(
            &config.backup_destinations,
            disk.clone(),
            Some(&owner),
            None,
        )
        .unwrap();
        let binding = destinations["extra"].namespace_binding().unwrap();
        let identity = owner.identity_for(&disk).unwrap();
        assert!(
            matches!(binding, BackupNamespaceBinding::Filesystem { installation_id, origin_node_id, namespace_id, .. }
            if installation_id == identity.installation_id && origin_node_id == identity.node_id && namespace_id == input.namespace_id)
        );
        if round == 0 {
            destinations["extra"]
                .put(
                    id,
                    BackupUpload::received(b"retained ciphertext fixture".to_vec()),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            destinations["extra"].get(id, 1 << 20).await.unwrap(),
            b"retained ciphertext fixture"
        );
        drop((destinations, owner, disk));
    }
    assert!(
        enroll_fixture(config, input, storage).await.is_err(),
        "installed alias cannot be reassigned"
    );
}

#[test]
fn configuration_requires_explicit_valid_filesystem_binding_without_a_compatibility_default() {
    let mut raw =
        serde_json::json!({"kind":"filesystem","directory":"/unused/backups","max_bytes":1024});
    assert!(serde_json::from_value::<DestinationConfig>(raw.clone()).is_err());
    raw["namespace_binding"] = serde_json::json!({"kind":"filesystem", "installation_id":Uuid::nil(), "origin_node_id":0, "namespace_id":Uuid::nil(),"device":0,"inode":0});
    assert!(
        serde_json::from_value::<DestinationConfig>(raw.clone())
            .unwrap()
            .validate()
            .is_err()
    );
    raw["namespace_binding"] = serde_json::json!({"kind":"s3", "https_origin":"https://example.invalid/", "region":"r", "bucket":"b", "prefix":"p"});
    assert!(
        serde_json::from_value::<DestinationConfig>(raw.clone())
            .unwrap()
            .validate()
            .is_err()
    );
    raw["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<DestinationConfig>(raw).is_err());
}

#[tokio::test]
async fn runtime_requires_retained_owner_and_rejects_foreign_or_changed_binding_unchanged() {
    let (_temporary, config, storage) = installed().await;
    let disk = storage.open_persistent(&config.persistent_disk).unwrap();
    let owner = crate::standalone::claim(&config, &disk).unwrap().unwrap();
    let (directory, _) = original(&config);
    let marker = directory.join("kasumi-backup.marker");
    let before = std::fs::read(&marker).unwrap();
    assert!(open_destinations(&config.backup_destinations, disk.clone(), None, None).is_err());
    for field in 0..5 {
        let mut changed = config.backup_destinations.clone();
        let DestinationConfig::Filesystem {
            namespace_binding:
                BackupNamespaceBinding::Filesystem {
                    installation_id,
                    origin_node_id,
                    namespace_id,
                    device,
                    inode,
                },
            ..
        } = changed.get_mut("local").unwrap()
        else {
            unreachable!()
        };
        match field {
            0 => *installation_id = Uuid::new_v4(),
            1 => *origin_node_id += 1,
            2 => *namespace_id = Uuid::new_v4(),
            3 => *device += 1,
            _ => *inode += 1,
        }
        assert!(open_destinations(&changed, disk.clone(), Some(&owner), None).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), before);
    }
    let (_other_temporary, other_config, other_storage) = installed().await;
    let other_disk = other_storage
        .open_persistent(&other_config.persistent_disk)
        .unwrap();
    let other_owner = crate::standalone::claim(&other_config, &other_disk)
        .unwrap()
        .unwrap();
    assert!(
        open_destinations(
            &config.backup_destinations,
            disk.clone(),
            Some(&other_owner),
            None
        )
        .is_err()
    );
    assert_eq!(std::fs::read(marker).unwrap(), before);
}

#[tokio::test]
async fn startup_never_repairs_missing_malformed_or_copied_markers() {
    for variant in ["missing", "malformed", "copied"] {
        let (_temporary, config, storage) = installed().await;
        let (directory, binding) = original(&config);
        let directory = directory.to_owned();
        let marker = directory.join("kasumi-backup.marker");
        let original = std::fs::read(&marker).unwrap();
        match variant {
            "missing" => std::fs::remove_file(&marker).unwrap(),
            "malformed" => std::fs::write(&marker, b"malformed original").unwrap(),
            _ => {
                std::fs::rename(&directory, directory.with_file_name("retained-original")).unwrap();
                private_files::create_directory(&directory).unwrap();
                private_files::create(&marker, &original).unwrap();
            }
        }
        let before = std::fs::read(&marker).ok();
        let disk = storage.open_persistent(&config.persistent_disk).unwrap();
        disk.reconcile(&kasumi_store::CensusCancellation::default())
            .unwrap();
        let owner = crate::standalone::claim(&config, &disk).unwrap().unwrap();
        assert!(
            open_destinations(
                &config.backup_destinations,
                disk.clone(),
                Some(&owner),
                None
            )
            .is_err(),
            "{variant}"
        );
        assert_eq!(std::fs::read(&marker).ok(), before, "{variant}");
        assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
        assert!(binding.validate().is_ok());
    }
}

#[tokio::test]
async fn enrollment_refuses_unmarked_existing_root_missing_parent_and_invalid_request_without_effects()
 {
    let (_temporary, config, storage) = installed().await;
    let input = request(&config);
    for invalid in [
        EnrollmentRequest {
            namespace_id: Uuid::nil(),
            ..input.clone()
        },
        EnrollmentRequest {
            max_bytes: 0,
            ..input.clone()
        },
        EnrollmentRequest {
            directory: input.directory.join("absent/child"),
            ..input.clone()
        },
    ] {
        assert!(
            enroll_fixture(config.clone(), invalid, storage.clone())
                .await
                .is_err()
        );
        assert!(!input.directory.exists());
    }
    private_files::create_directory(&input.directory).unwrap();
    let disk = storage.open_persistent(&config.persistent_disk).unwrap();
    disk.reconcile(&kasumi_store::CensusCancellation::default())
        .unwrap();
    drop(disk);
    assert!(
        enroll_fixture(config, input.clone(), storage)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(&input.directory).unwrap().count(), 0);
}

#[tokio::test]
async fn enrollment_cannot_replace_original_owner_with_configuration_or_missing_installation() {
    let (_temporary, config, storage) = installed().await;
    let input = request(&config);
    let mut foreign = config.clone();
    let identity = Uuid::new_v4();
    for tenant in &mut foreign.tenants {
        tenant.serving = crate::serving_runtime::TenantServingConfig::Standalone {
            installation_id: identity,
        };
    }
    assert!(
        enroll_fixture(foreign, input.clone(), storage.clone())
            .await
            .is_err()
    );
    assert!(!input.directory.exists());
    let marker = config
        .database_path
        .parent()
        .unwrap()
        .join("installation.json");
    let retained = marker.with_extension("retained");
    std::fs::rename(&marker, &retained).unwrap();
    let bytes = std::fs::read(&retained).unwrap();
    let disk = storage.open_persistent(&config.persistent_disk).unwrap();
    disk.reconcile(&kasumi_store::CensusCancellation::default())
        .unwrap();
    drop(disk);
    assert!(
        enroll_fixture(config, input.clone(), storage)
            .await
            .is_err()
    );
    assert!(!input.directory.exists());
    assert!(!marker.exists());
    assert_eq!(std::fs::read(retained).unwrap(), bytes);
}

#[tokio::test]
async fn enrollment_cli_rejects_an_existing_receipt_before_opening_configuration() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let output = directory.path().join("original.json");
    private_files::create(&output, b"original receipt fixture").unwrap();
    assert!(
        command(
            &directory.path().join("absent-config"),
            &directory.path().join("absent-request"),
            &output
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(output).unwrap(), b"original receipt fixture");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
