from pathlib import Path
p=Path('target/installed-disk-validation/installed-memory-callers/complete-600c0ca/proposed/crates/kasumi-server/src/runtime.rs');s=p.read_text()
a=s.index('    async fn service_audit_survives_reopen');b=s.index('\n    #[',a)
t=s[a:b]
t=t.replace('let path = dir.path().join("node.redb");','let physical = crate::runtime_storage_fixtures::physical(dir.path(), Default::default()).unwrap();\n        let path = dir.path().join("persistent/node.redb");')
t=t.replace('NodeStore::create_new_fixture(\n            &path,\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','physical.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)')
t=t.replace('            node,\n            "acme".into(),','            node.clone(),\n            "acme".into(),')
t=t.replace('kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','physical.admission.clone(),')
t=t.replace('        drop(tenant);','        drop(tenant);\n        node.shutdown().await.unwrap();\n        let node = physical.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap();')
t=t.replace('            NodeStore::open_existing_fixture(\n                &path,\n                kasumi_store::test_utils::NODE_STORE_ID,\n                kasumi_store::ScratchDisk::fixture(),\n            )\n            .unwrap(),','            node.clone(),')
t=t.replace('        assert_eq!(service.scan("security.audit").unwrap().len(), 4);','        assert_eq!(service.scan("security.audit").unwrap().len(), 4);\n        audit.shutdown().await.unwrap();\n        node.shutdown().await.unwrap();')
s=s[:a]+t+s[b:]
a=s.index('    async fn startup_and_serving_drains_finish_live_tls_requests');b=s.index('\n    fn replica_diagnostics',a);t=s[a:b]
t=t.replace('            assert!(Arc::strong_count(&state.node) > 0);','            assert!(Arc::strong_count(&state.node) > 0);\n            state.node.shutdown().await.unwrap();')
t=t.replace('let path = directory.path().join("listener.redb");','let physical = crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();\n            let path = directory.path().join("persistent/listener.redb");')
t=t.replace('NodeStore::create_new_fixture(\n                &path,\n                kasumi_store::test_utils::NODE_STORE_ID,\n                kasumi_store::ScratchDisk::fixture(),\n            )','physical.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)')
t=t.replace('            drop(\n                NodeStore::open_existing_fixture(\n                    &path,\n                    kasumi_store::test_utils::NODE_STORE_ID,\n                    kasumi_store::ScratchDisk::fixture(),\n                )\n                .unwrap(),\n            );','            physical.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap().shutdown().await.unwrap();')
s=s[:a]+t+s[b:];p.write_text(s)
