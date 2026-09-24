use super::*;

#[test]
fn installed_markers_share_the_lock_owner_and_release_only_after_managed_delete() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let config = crate::persistent_disk::fixture_config(directory.path());
    let storage = crate::runtime_memory::RuntimeStorage::isolated_persistent_fixture(
        Default::default(),
        &config,
    )?;
    let disk = crate::persistent_disk::open(&config, &storage)?;
    let initial = disk.snapshot();
    let lock_path = directory.path().join("installation.lock");
    let lock = create_installed_file(&config, &disk, &lock_path, &[], 0)?;
    assert!(private_files::ExclusiveLock::acquire(&lock_path).is_err());
    let marker_path = directory.path().join("initialization.json");
    let marker = create_installed_file(&config, &disk, &marker_path, b"durable marker", 128)?;
    assert_eq!(
        disk.snapshot().persistent_files,
        initial.persistent_files + 2
    );
    assert!(disk.snapshot().charged_bytes > initial.charged_bytes);
    assert!(create_installed_file(&config, &disk, &marker_path, b"replacement", 128).is_err());
    assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(read_installed_file(&marker, 128)?, b"durable marker");
    drop(marker);
    assert!(disk.snapshot().charged_bytes > initial.charged_bytes);
    let marker = open_installed_file(&config, &disk, &marker_path)?;
    disk.delete_file(marker)?;
    assert!(!marker_path.exists());
    assert_eq!(disk.snapshot().charged_bytes, initial.charged_bytes);
    assert_eq!(
        disk.snapshot().persistent_files,
        initial.persistent_files + 1
    );
    drop(lock);
    let _exclusive = private_files::ExclusiveLock::acquire(&lock_path)?;
    Ok(())
}

#[test]
fn installed_marker_pair_cannot_recreate_a_missing_installation_lock() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let mut config = example_config();
    config.mode = DeploymentMode::Standalone;
    config.database_path = directory.path().join("node.redb");
    config.persistent_disk = crate::persistent_disk::fixture_config(directory.path());
    let installation = Installation {
        format: 3,
        installation_id: Uuid::new_v4(),
        control_incarnation: Uuid::new_v4(),
        database_id: config.database_id,
        database_path: config.database_path.clone(),
    };
    config.control.incarnation = Some(installation.control_incarnation.to_string());
    for tenant in &mut config.tenants {
        tenant.serving = TenantServingConfig::Standalone {
            installation_id: installation.installation_id,
        };
    }
    let storage = crate::runtime_memory::RuntimeStorage::isolated_persistent_fixture(
        Default::default(),
        &config.persistent_disk,
    )?;
    config.admission = storage.policy().clone();
    let disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
    for name in ["initialization.json", "installation.json"] {
        create_installed_file(
            &config.persistent_disk,
            &disk,
            &directory.path().join(name),
            &serde_json::to_vec(&installation)?,
            16 << 10,
        )?;
    }
    let files = disk.snapshot().persistent_files;
    assert!(claim(&config, &disk).is_err());
    assert!(!directory.path().join("installation.lock").exists());
    assert_eq!(disk.snapshot().persistent_files, files);
    Ok(())
}
