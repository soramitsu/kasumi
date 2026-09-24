from pathlib import Path
p=Path('target/installed-disk-validation/engine-fixture-callers/proposed/crates/kasumi-engine/src/snapshot_bundle.rs');s=p.read_text()
old='''        let node = NodeStore::create_new_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let store ='''
new='''        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
        kasumi_store::private_files::create_directory(&directory.path().join("persistent")).unwrap();
        let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
        let node = NodeStore::create_new_fixture(
            directory.path().join("persistent/node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            memory,
            disk,
        ).unwrap();
        fixture_on_node(directory, node, incarnation, tenant).await
    }
    type Fixture = (tempfile::TempDir, Arc<TenantEngine>, Arc<TenantStore>);
    async fn admitted_pair(incarnation: &str, config: crate::admission::AdmissionConfig) -> (Fixture, Fixture, Arc<crate::admission::NodeAdmission>, u64) {
        let left = kasumi_store::test_utils::private_tempdir().unwrap();
        let right = kasumi_store::test_utils::private_tempdir().unwrap();
        let (left_persistent, left_scratch) = crate::test_utils::fixture_disk_configs(left.path()).unwrap();
        let (right_persistent, right_scratch) = crate::test_utils::fixture_disk_configs(right.path()).unwrap();
        let metadata_bytes = crate::test_utils::isolated_disk_metadata_bytes(&left_persistent, &left_scratch).unwrap()
            .checked_add(crate::test_utils::isolated_disk_metadata_bytes(&right_persistent, &right_scratch).unwrap()).unwrap();
        // Both real installations share the original single operation allowance.
        let config = crate::test_utils::isolated_disk_config_with_metadata(config, &left_persistent, &left_scratch).unwrap();
        let config = crate::test_utils::isolated_disk_config_with_metadata(config, &right_persistent, &right_scratch).unwrap();
        let admission = crate::admission::NodeAdmission::new(config).unwrap();
        let left_storage = crate::test_utils::FixtureStorage::with_admission(&left_persistent, &left_scratch, admission.clone()).unwrap();
        let right_storage = crate::test_utils::FixtureStorage::with_admission(&right_persistent, &right_scratch, admission.clone()).unwrap();
        let left_node = left_storage.create_new(left.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
        let right_node = right_storage.create_new(right.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
        let left = fixture_on_node(left, left_node, incarnation, "tenant").await;
        let right = fixture_on_node(right, right_node, incarnation, "tenant").await;
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), metadata_bytes);
        (left, right, admission, metadata_bytes)
    }
    async fn fixture_on_node(directory: tempfile::TempDir, node: Arc<NodeStore>, incarnation: &str, tenant: &str) -> Fixture {
        let store ='''
assert old in s;s=s.replace(old,new)
s=s.replace('.logical_snapshot(&kasumi_store::ScratchDisk::fixture())','.logical_snapshot(source_store.scratch_disk())')
# Two public API fixtures need real same-core physical owners; raw codec cases retain explicit synthetic governor.
start=s.index('    async fn public_restore_admits');end=s.index('    #[tokio::test',start)
a=s[start:end]
a=a.replace('''        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;''','''        let maximum = 80 << 20;
        let config = crate::test_utils::admission_config_with_bookkeeping(crate::admission::AdmissionConfig { max_inflight_bytes: Some(maximum), ..Default::default() }).unwrap();
        let ((_source_dir, source, source_store), (_target_dir, target, target_store), admission, metadata_bytes) = admitted_pair(&incarnation, config).await;''')
begin=a.index('        // This is a fixture governor');finish=a.index('        let image =',begin)
a=a[:begin]+a[finish:]
begin=a.index('        let denied =');finish=a.index('        let live_files =',begin)
a=a[:begin]+'''        let available = layout.materialization_workspace().unwrap() - 1;
        let before = admission.snapshot();
        let held = admission.reserve(before.max_inflight_bytes - before.reserved_bytes - available, None).unwrap();
'''+a[finish:]
a=a.replace('denied.clone()', 'admission.clone()')
a=a.replace('''        assert_eq!(crate::test_utils::reserved_payload_bytes(&denied), 0);
        assert_eq!(denied.snapshot().inflight_operations, 0);''','''        drop(held);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), metadata_bytes);
        assert_eq!(admission.snapshot().inflight_operations, 0);''')
a=a.replace('reserved_payload_bytes(&admission), 0','reserved_payload_bytes(&admission), metadata_bytes')
s=s[:start]+a+s[end:]
start=s.index('    async fn public_capture_and_restore_preparation');a=s[start:]
a=a.replace('''        let (_source_dir, source, source_store) = fixture(&incarnation).await;
        let (_target_dir, target, target_store) = fixture(&incarnation).await;''','''        let ((_source_dir, source, source_store), (_target_dir, target, target_store), admission, metadata_bytes) = admitted_pair(&incarnation, Default::default()).await;''')
a=a.replace('        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();\n','')
a=a.replace('reserved_payload_bytes(&admission), 0','reserved_payload_bytes(&admission), metadata_bytes')
begin=a.index('        let denied =');finish=a.index('        source_store.shutdown()',begin)
a=a[:begin]+'''        let before = admission.snapshot();
        let held = admission.reserve(before.max_inflight_bytes - before.reserved_bytes - (1 << 20), None).unwrap();
        assert_eq!(source.snapshot(admission.clone(), 60_000).await.unwrap_err().code, kasumi_types::ErrorCode::ResourceExhausted);
        drop(held);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), metadata_bytes);
'''+a[finish:]
s=s[:start]+a;p.write_text(s)
