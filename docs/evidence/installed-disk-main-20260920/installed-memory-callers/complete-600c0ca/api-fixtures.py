from pathlib import Path
root=Path('target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server/src')
def edit(n,f):
 p=root/n;s=p.read_text();p.write_text(f(s))
def rep(s,a,b):
 assert a in s,a[:100];return s.replace(a,b)
def api(s):
 s=rep(s,'        _dir: tempfile::TempDir,','        _dir: tempfile::TempDir,\n        physical: kasumi_engine::test_utils::FixtureStorage,\n        node: Arc<NodeStore>,')
 s=rep(s,'            let node = NodeStore::create_new_fixture(\n                dir.path().join("node.redb"),\n                kasumi_store::test_utils::NODE_STORE_ID,\n                kasumi_store::ScratchDisk::fixture(),\n            )','            let physical = crate::runtime_storage_fixtures::physical(dir.path(), Default::default()).unwrap();\n            let node = physical.create_new(\n                dir.path().join("persistent/node.redb"),\n                kasumi_store::test_utils::NODE_STORE_ID,\n            )')
 s=rep(s,'            let node_admission =\n                kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();','            let node_admission = physical.admission.clone();')
 s=rep(s,'                node,\n                "tenant-a".into(),','                node.clone(),\n                "tenant-a".into(),')
 s=rep(s,'                _dir: dir,','                _dir: dir,\n                physical,\n                node,')
 s=rep(s,'            self.audit.shutdown().await.unwrap();','            self.audit.shutdown().await.unwrap();\n            self.node.shutdown().await.unwrap();')
 s=rep(s,'        let node = NodeStore::create_new_fixture(\n            fixture._dir.path().join("control.redb"),\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','        let node = fixture.physical.create_new(\n            fixture._dir.path().join("persistent/control.redb"),\n            kasumi_store::test_utils::NODE_STORE_ID,\n        )')
 s=rep(s,'            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','            fixture.audit.admission().clone(),')
 return s
edit('api.rs',api)
edit('api_backup_checkpoint_tests.rs',lambda s:rep(rep(s,'FilesystemBackupDestination::new_fixture(','FilesystemBackupDestination::new('),'            fixture._dir.path().join("backup"),\n            16 << 20,','            fixture._dir.path().join("persistent/backup"),\n            16 << 20,\n            fixture.physical.persistent.clone(),'))
edit('api_history_tests.rs',lambda s:rep(rep(s,'    let directory = kasumi_store::test_utils::private_tempdir().unwrap();\n',''),'FilesystemBackupDestination::new_fixture(directory.path(), 16 << 20)','FilesystemBackupDestination::new(fixture._dir.path().join("persistent/history-backup"), 16 << 20, fixture.physical.persistent.clone())'))
def lineage(s):
 s=rep(s,'    let backup_dir = kasumi_store::test_utils::private_tempdir().unwrap();\n','')
 s=rep(s,'FilesystemBackupDestination::new_fixture(backup_dir.path(), 16 << 20)','FilesystemBackupDestination::new(fixture._dir.path().join("persistent/lineage-backup"), 16 << 20, fixture.physical.persistent.clone())')
 s=rep(s,'    let mut dirs = Vec::new();','    let mut nodes = Vec::new();')
 s=rep(s,'        let dir = kasumi_store::test_utils::private_tempdir().unwrap();\n        let node = NodeStore::create_new_fixture(\n            dir.path().join("node.redb"),\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','        let path = fixture._dir.path().join(format!("persistent/lineage-{hop}.redb"));\n        let node = fixture.physical.create_new(\n            &path,\n            kasumi_store::test_utils::NODE_STORE_ID,\n        )')
 s=rep(s,'TenantStore::initialize_catalog_fixture(node, "tenant-a".into(), key.clone())','TenantStore::initialize_catalog_fixture(node.clone(), "tenant-a".into(), key.clone())')
 s=rep(s,'.fixture_snapshot()', '.fixture_snapshot(&fixture.physical.scratch)')
 s=rep(s,'encode_snapshot_candidate(&substituted, 64 << 20)','encode_snapshot_candidate(&fixture.physical.scratch, &substituted, 64 << 20)')
 s=rep(s,'        drop(stores);\n        let reopened_store','        drop(stores);\n        node.shutdown().await.unwrap();\n        let node = fixture.physical.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap();\n        let reopened_store')
 s=rep(s,'            NodeStore::open_existing_fixture(\n                dir.path().join("node.redb"),\n                kasumi_store::test_utils::NODE_STORE_ID,\n                kasumi_store::ScratchDisk::fixture(),\n            )\n            .unwrap(),','            node.clone(),')
 s=rep(s,'        dirs.push(dir);','        nodes.push(node);')
 s=rep(s,'    drop(dirs);','    for node in nodes { node.shutdown().await.unwrap(); }')
 return s
edit('api_resource_lineage_tests.rs',lineage)
def mcp(s):
 start=s.index('        let node = NodeStore::create_new_fixture(');end=s.index('        let mut config =',start)
 block=s[start:end]
 s=s[:start]+s[end:]
 block=rep(block,'let node = NodeStore::create_new_fixture(\n            private.join("node.redb"),\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','let node = physical.create_new(\n            private.join("persistent/node.redb"),\n            kasumi_store::test_utils::NODE_STORE_ID,\n        )')
 s=rep(s,'        let admission = kasumi_engine::admission::NodeAdmission::new(config).unwrap();','        let physical = crate::runtime_storage_fixtures::physical(&private, config).unwrap();\n        let admission = physical.admission.clone();\n'+block.rstrip())
 return s
edit('mcp_credential_tests.rs',mcp)
