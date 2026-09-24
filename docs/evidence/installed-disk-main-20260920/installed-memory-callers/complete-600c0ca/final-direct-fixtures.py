from pathlib import Path
r=Path('target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server/src')
p=r/'configured_tenant_enrollment_tests.rs';s=p.read_text();s=s.replace('    let installation =\n        crate::standalone::initialize(', '    let (installation, storage) =\n        crate::runtime_storage_fixtures::initialize_standalone(');s=s.replace('    let installed =\n        crate::standalone::initialize(', '    let (installed, storage) =\n        crate::runtime_storage_fixtures::initialize_standalone(');s=s.replace('crate::runtime::NodeRuntime::open(config)','crate::runtime::NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage.clone())');s=s.replace('crate::standalone::stage_tenant(&installed.configuration, request.clone())','crate::standalone::stage_tenant_with_storage(&installed.configuration, request.clone(), storage.clone())');p.write_text(s)
p=r/'standalone_key_backup.rs';s=p.read_text().replace('let installed = crate::standalone::initialize(', 'let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(').replace('crate::standalone::backup_operator_keys(&installed.configuration, &output)','crate::standalone::backup_operator_keys_with_storage(&installed.configuration, &output, storage.clone())');p.write_text(s)
p=r/'local_auth.rs';s=p.read_text().replace('        assert!(reopened.create(specification, "initializer").is_err());','        assert!(reopened.create(specification, "initializer").is_err());\n        node.shutdown().await.unwrap();');p.write_text(s)
p=r/'local_recovery_tests.rs';s=p.read_text();a=s.index('async fn local_lost_file_binding_cleanup_requires_the_original_node_identity');b=s.index('\n#[tokio::test]',a);t=s[a:b]
t=t.replace('    let node = kasumi_store::NodeStore::create_new_fixture(','    let persistent = operator.store().persistent_disk().clone();\n    let scratch = operator.store().scratch_disk().clone();\n    let node = kasumi_store::NodeStore::create_new(')
t=t.replace('        operator.store().scratch_disk().clone(),','        persistent.clone(),\n        scratch.clone(),')
t=t.replace('    drop(node);','    node.shutdown().await.unwrap();\n    drop(node);')
t=t.replace('    let preserved = root.path().join("original-node.redb");\n    std::fs::rename(&path, &preserved).unwrap();\n    let other = kasumi_store::NodeStore::create_new_fixture(\n        &path,\n        Uuid::new_v4(),\n        kasumi_store::ScratchDisk::fixture(),\n    )\n    .unwrap();\n    drop(other);','''    let preserved = root.path().join("original-node.redb");
    let substitute = path.with_file_name("substitute.redb");
    let other = kasumi_store::NodeStore::create_new(
        &substitute,
        Uuid::new_v4(),
        persistent.clone(),
        scratch,
    ).unwrap();
    other.shutdown().await.unwrap();
    drop(other);
    // Model a stopped installation receiving an externally substituted file.
    // Re-census is legitimate only after every managed descriptor has closed.
    assert_eq!(persistent.snapshot().open_files, 0);
    persistent.pause().unwrap();
    std::fs::rename(&path, &preserved).unwrap();
    std::fs::rename(&substitute, &path).unwrap();
    persistent.reconcile(&kasumi_store::CensusCancellation::default()).unwrap();''')
t=t.replace('    std::fs::remove_file(&path).unwrap();\n    std::fs::rename(&preserved, &path).unwrap();','''    assert_eq!(persistent.snapshot().open_files, 0);
    persistent.pause().unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&preserved, &path).unwrap();
    persistent.reconcile(&kasumi_store::CensusCancellation::default()).unwrap();''')
s=s[:a]+t+s[b:];p.write_text(s)
