from pathlib import Path
root=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server/src')
def edit(name, changes):
 p=root/name;s=p.read_text()
 for old,new,count in changes:
  assert s.count(old)==count,(name,s.count(old),old[:70]);s=s.replace(old,new)
 p.write_text(s)
T='crate::runtime_memory::RuntimeStorage'
edit('authority_node_enrollment_tests.rs', [('initialize_owned(fixture.config.clone())','initialize_owned(fixture.config.clone(), fixture.storage.clone())',1)])
edit('standalone_provision_tests.rs',[
 ('    let result = initialize_owned(','    let storage = crate::runtime_storage_fixtures::standalone_storage(&directory, Default::default())?;\n    let result = initialize_owned(',1),
 ('            obstruct_profile_publication: true,\n        },','            obstruct_profile_publication: true,\n        },\n        storage.clone(),',1),
 ('    let _lock = private_files::ExclusiveLock::acquire(&directory.join("data/installation.lock"))?;','    let (persistent, scratch) = crate::runtime_storage_fixtures::standalone_disks(&directory)?;\n    let disk = storage.open_persistent(&persistent)?;\n    let lock = directory.join("data/installation.lock");\n    let (root, relative) = persistent.binding(&lock)?;\n    let _lock = disk.open_file(root, relative)?;',1),
 ('    let node = NodeStore::open_existing_fixture(\n        directory.join("data/node.redb"),\n        prepared.database_id,\n        kasumi_store::ScratchDisk::fixture(),\n    )?;\n    drop(node);','    let node = NodeStore::open_existing(\n        directory.join("data/node.redb"),\n        prepared.database_id,\n        disk,\n        storage.open_scratch(&scratch)?,\n    )?;\n    node.shutdown().await?;\n    drop(node);',1),
 ('initialize(&directory, "documents").await.is_err()','initialize_with_storage(&directory, "documents", storage).await.is_err()',1),
])
edit('node_provision.rs',[
 ('    use kasumi_store::ScratchDisk;\n','',1),
 ('        let admission = kasumi_engine::admission::NodeAdmission::new(Default::default())?;','        let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(Default::default(), &persistent, &scratch)?;\n        let admission = storage.facade(storage.policy())?;',1),
 ('            admission.clone(),\n        )','            admission.clone(),\n            &storage,\n        )',1),
 ('                admission.clone()\n            )','                admission.clone(),\n                &storage,\n            )',1),
 ('NodeStore::open_existing_fixture(','NodeStore::open_existing(',3),
 ('                ScratchDisk::open(scratch.clone())?','                storage.open_persistent(&persistent)?,\n                storage.open_scratch(&scratch)?',2),
 ('NodeStore::open_existing(&path, database_id, ScratchDisk::open(scratch)?)?','NodeStore::open_existing(&path, database_id, storage.open_persistent(&persistent)?, storage.open_scratch(&scratch)?)?',1),
 ('        let store = TenantStore::open_existing(\n            node,','        let store = TenantStore::open_existing(\n            node.clone(),',1),
 ('        audit.shutdown().await.unwrap();\n        Ok(())','        audit.shutdown().await.unwrap();\n        node.shutdown().await?;\n        Ok(())',1),
])
edit('control_genesis_tests.rs',[
 ('NodeStore, ScratchDisk, StorageAccess','NodeStore, StorageAccess',1),
 ('fn config(root: &Path) -> Result<RuntimeConfig>','fn config(root: &Path) -> Result<(RuntimeConfig, '+T+')>',1),
 ('    let mut config = crate::runtime::example_config();','    let mut config = crate::runtime::example_config();\n    config.admission = Default::default();',1),
 ('    config.validate()?;\n    Ok(config)','    config.validate()?;\n    let storage = crate::runtime_storage_fixtures::configure(&mut config)?;\n    Ok((config, storage))',1),
 ('async fn existing(config: &RuntimeConfig)','async fn existing(config: &RuntimeConfig, storage: &'+T+')',1),
 ('let config = config(directory.path())?','let (config, storage) = config(directory.path())?',2),
 ('let mut config = config(directory.path())?','let (mut config, storage) = config(directory.path())?',1),
 ('existing(&config)','existing(&config, &storage)',2),
 ('config.provision_node()','crate::data_node_enrollment::initialize_with_storage(config.clone(), storage.clone())',3),
 ('NodeStore::open_existing_fixture(','NodeStore::open_existing(',4),
 ('ScratchDisk::open(config.scratch_disk.clone())?','storage.open_persistent(&config.persistent_disk)?,\n        storage.open_scratch(&config.scratch_disk)?',4),
])
edit('rpc_control_signer_tests.rs',[
 ('    let initialization = InitializeSignerVerifier {','    let mut initialization = InitializeSignerVerifier {',1),
 ('    initialization.initialize().await.unwrap();\n    let scratch = kasumi_store::ScratchDisk::open(initialization.scratch_disk.clone()).unwrap();','    let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(initialization.admission.clone(), &initialization.persistent_disk, &initialization.scratch_disk).unwrap();\n    initialization.admission = storage.policy().clone();\n    initialization.initialize_with_storage(storage.clone()).await.unwrap();\n    let scratch = storage.open_scratch(&initialization.scratch_disk).unwrap();',1),
 ('crate::persistent_disk::open(&initialization.persistent_disk).unwrap()','storage.open_persistent(&initialization.persistent_disk).unwrap()',2),
 ('kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap()','storage.facade(storage.policy()).unwrap()',2),
])
# Clarify that the explicit extra sealed observer remains charged during the test.
p=root/'runtime_cluster_storage_tests.rs';s=p.read_text().replace('// Drop closed audit/store owners but deliberately retain the sealed facade.','// Drop closed audit/store owners but deliberately retain the sealed facade.\n    // Its base stays charged while a third facade overlaps; this checks ownership,\n    // not the full two-node payload maximum during that extra observer lifetime.');p.write_text(s)
print('updated five direct/configured fixture modules and regression scope comment')
