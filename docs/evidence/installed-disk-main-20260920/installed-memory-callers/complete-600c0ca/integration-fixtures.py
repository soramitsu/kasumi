from pathlib import Path
r=Path('target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server')
p=r/'src/rpc_authority_tests.rs';s=p.read_text().replace('RuntimeStorage::isolated_fixture(&input.admission,','RuntimeStorage::isolated_fixture(input.admission.clone(),');p.write_text(s)
p=r/'tests/cluster_transport.rs';s=p.read_text()
a=s.index('async fn store(');b=s.index('\n#[tokio::test',a)
s=s[:a]+'''async fn store(node: Arc<NodeStore>) -> Result<Arc<TenantStore>> {
    TenantStore::initialize_catalog_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([13; 32])),
    ).await
}

fn physical(root: &std::path::Path) -> Result<kasumi_engine::test_utils::FixtureStorage> {
    let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(root)?;
    kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())
}
''' + s[b:]
s=s.replace('    let mut groups = Vec::new();','    let mut groups = Vec::new();\n    let mut physical_nodes = Vec::new();')
s=s.replace('        let group = RaftGroup::open(','        let replica_root = dir.path().join(format!("replica-{id}"));\n        let physical = physical(&replica_root)?;\n        let node = physical.create_new(replica_root.join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID)?;\n        physical_nodes.push(node.clone());\n        let group = RaftGroup::open(',1)
s=s.replace('store(&dir.path().join(format!("node-{id}.redb"))).await?','store(node).await?')
s=s.replace('    let group = RaftGroup::open(\n        1,','    let physical = physical(dir.path())?;\n    let node = physical.create_new(dir.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID)?;\n    let group = RaftGroup::open(\n        1,')
s=s.replace('store(&dir.path().join("node.redb")).await?','store(node.clone()).await?')
s=s.replace('kasumi_raft::SnapshotBufferOwner::fixture(),','physical.admission.snapshot_buffer_owner()?,')
s=s.replace('    stop.send(true)?;','    for node in physical_nodes { node.shutdown().await?; }\n    stop.send(true)?;',1)
pos=s.rfind('    group.shutdown().await?;');s=s[:pos]+s[pos:].replace('    group.shutdown().await?;','    group.shutdown().await?;\n    node.shutdown().await?;',1)
p.write_text(s)
for name in ['src/audit_destination.rs','src/local_auth.rs','src/mcp_credential_tests.rs']:
 p=r/name;s=p.read_text();s=s.replace('{NodeStore, TenantStore,','{TenantStore,').replace('{FileKeyProvider, NodeStore, StorageAccess}','{FileKeyProvider, StorageAccess}')
 p.write_text(s)
