from pathlib import Path
root=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server/src')
def edit(name, changes):
 p=root/name;s=p.read_text()
 for old,new,count in changes:
  assert s.count(old)==count,(name,s.count(old),old[:80]);s=s.replace(old,new)
 p.write_text(s)
edit('runtime_storage_fixtures.rs',[(
'''    let persistent_root = directory.join("persistent");
    kasumi_store::private_files::create_directory(&persistent_root)?;
    let persistent = kasumi_store::NodeDisk::fixture_config(persistent_root.join("fixture-anchor"))?;
    let scratch = ScratchDiskConfig {
        directory: directory.join("scratch"),
        max_bytes: 256 << 30,
        min_free_bytes: 0,
    };''','''    let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(directory)?;''',1)])
edit('node_enrollment_tests.rs',[
 ('NodeStore, ScratchDisk, StorageAccess','NodeStore, StorageAccess',1),
 ('    let mut configuration = crate::runtime::example_config();','    let mut configuration = crate::runtime::example_config();\n    configuration.admission = Default::default();',1),
 ('''    let node = NodeStore::create_new_fixture(
        &configuration.database_path,
        configuration.database_id,
        ScratchDisk::fixture(),
    )?;''','''    let storage = crate::runtime_storage_fixtures::configure(&mut configuration)?;
    let _admission = storage.facade(storage.policy())?;
    let node = NodeStore::create_new(
        &configuration.database_path,
        configuration.database_id,
        storage.open_persistent(&configuration.persistent_disk)?,
        storage.open_scratch(&configuration.scratch_disk)?,
    )?;''',1),
])
edit('local_auth.rs',[
 ('''        let store = TenantStore::initialize_catalog(
            NodeStore::create_new_fixture(
                root.path().join("database"),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )''','''        let physical = crate::runtime_storage_fixtures::physical(root.path(), Default::default()).unwrap();
        let node = physical.create_new(root.path().join("persistent/database"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
        let store = TenantStore::initialize_catalog(
            Ok::<_, anyhow::Error>(node.clone())''',1),
])
# Replace the temporary expression with the already constructed physical owner.
p=root/'local_auth.rs';s=p.read_text().replace('''            Ok::<_, anyhow::Error>(node.clone())
            .unwrap(),''','''            node.clone(),''');p.write_text(s)
edit('audit_destination.rs',[
 ('''        let path = directory.path().join("node.redb");''','''        let physical = crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
        let path = directory.path().join("persistent/node.redb");''',1),
 ('''        let node = NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )''','''        let node = physical.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)''',1),
 ('FilesystemAuditArchive::open_fixture(directory.path().join("owned-cache"))','FilesystemAuditArchive::open(directory.path().join("persistent/owned-cache"), physical.persistent.clone())',1),
 ('directory.path().join("external-archive")','directory.path().join("persistent/external-archive")',1),
 ('        drop(store);\n        drop(node);','        drop(store);\n        node.shutdown().await.unwrap();\n        drop(node);',1),
 ('''        let node = NodeStore::open_existing_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )''','''        let node = physical.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)''',1),
 ('TenantStore::open_existing_fixture(node, "tenant".into(), provider)','TenantStore::open_existing_fixture(node.clone(), "tenant".into(), provider)',1),
 ('        reopened.shutdown().await.unwrap();','        reopened.shutdown().await.unwrap();\n        node.shutdown().await.unwrap();',1),
])
edit('tls.rs',[
 ('''        let path = directory.path().join("accept-error.redb");
        let node = NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )''','''        let physical = crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
        let path = directory.path().join("persistent/accept-error.redb");
        let node = physical.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)''',1),
 ('''        assert!(Arc::strong_count(&state.node) > 0);
        "completed before listener returned"''','''        assert!(Arc::strong_count(&state.node) > 0);
        state.node.shutdown().await.unwrap();
        "completed before listener returned"''',1),
 ('''        drop(
            NodeStore::open_existing_fixture(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
        );''','''        let reopened = physical.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap();
        reopened.shutdown().await.unwrap();''',1),
])
print('updated shared physical helper and four simple fixture modules')
