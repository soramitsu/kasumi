from pathlib import Path
import subprocess,hashlib,json,difflib
root=Path.cwd(); stage=root/'target/installed-disk-validation/engine-fixture-helper'
p=stage/'proposed/crates/kasumi-engine/src/test_utils.rs'
s=p.read_text()
s+='''

#[cfg(test)]
mod physical_fixture_tests {
    use super::*;
    use crate::admission::{AdmissionConfig, NodeAdmission};
    use std::sync::Arc;

    #[tokio::test]
    async fn installed_metadata_preserves_the_exact_original_payload_allowance() -> anyhow::Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = fixture_disk_configs(directory.path())?;
        let payload = 64_u64 << 20;
        let config = AdmissionConfig { max_inflight_bytes: Some(payload), ..Default::default() };
        let config = isolated_disk_admission_config(config, &persistent, &scratch)?;
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let before = admission.snapshot();
        let metadata = isolated_disk_metadata_bytes(&persistent, &scratch)?;
        let storage = FixtureStorage::with_admission(&persistent, &scratch, admission.clone())?;
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes.checked_sub(before.reserved_bytes), Some(metadata));
        assert_eq!(after.live_reservations - before.live_reservations, 8);
        assert_eq!(after.inflight_operations, before.inflight_operations);
        assert_eq!(after.bookkeeping_bytes, before.bookkeeping_bytes);
        let payload_lease = admission.reserve(payload, None)?;
        assert!(admission.reserve(1, None).is_err());
        drop(payload_lease);
        let path = directory.path().join("persistent/node.redb");
        let first = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
        assert!(Arc::ptr_eq(first.persistent_disk(), &storage.persistent));
        assert!(Arc::ptr_eq(first.scratch_disk(), &storage.scratch));
        first.shutdown().await?;
        drop(first);
        let reopened = storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
        assert!(Arc::ptr_eq(reopened.persistent_disk(), &storage.persistent));
        assert_eq!(admission.snapshot().reserved_bytes, after.reserved_bytes);
        reopened.shutdown().await?;
        drop(reopened);
        admission.drain_snapshot_startups().await?;
        drop(storage);
        // Installed physical owners retain their actual metadata leases after
        // public callers disappear. It is not reusable operation capacity.
        assert_eq!(admission.snapshot().resident_reserved_bytes, metadata);
        Ok(())
    }

    #[test]
    fn configured_total_planning_preserves_existing_bookkeeping_and_limits() -> anyhow::Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = fixture_disk_configs(directory.path())?;
        let config = admission_config_with_bookkeeping(AdmissionConfig {
            max_inflight_bytes: Some(64 << 20),
            max_inflight_operations: 7,
            ..Default::default()
        })?;
        let old_total = config.max_inflight_bytes.unwrap();
        let planned = isolated_disk_config_with_metadata(config.clone(), &persistent, &scratch)?;
        assert_eq!(planned.max_inflight_bytes, Some(old_total + isolated_disk_metadata_bytes(&persistent, &scratch)?));
        let mut unchanged = planned;
        unchanged.max_inflight_bytes = config.max_inflight_bytes;
        assert_eq!(unchanged, config);
        Ok(())
    }
}
'''
r=subprocess.run(['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt','--edition','2024','--emit','stdout'],input=s,text=True,capture_output=True)
assert r.returncode==0,r.stderr
p.write_text(r.stdout)
base=root/'crates/kasumi-engine/src/test_utils.rs'; path=str(base.relative_to(root))
patch=''.join(difflib.unified_diff(base.read_text().splitlines(True),p.read_text().splitlines(True),fromfile='a/'+path,tofile='b/'+path))
(stage/'helper.patch').write_text(patch)
h=lambda data:hashlib.sha256(data).hexdigest()
(stage/'manifest.json').write_text(json.dumps({'status':'TARGET_ONLY_UNCOMPILED','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'requires':['node-disk-memory revision2','installed-disk-core-adapter90015017'],'patch_sha256':h(patch.encode()),'files':[{'path':path,'baseline_sha256':h(base.read_bytes()),'proposed_sha256':h(p.read_bytes())}]},indent=2)+'\n')
r=subprocess.run(['git','apply','--check',str(stage/'helper.patch')],capture_output=True,text=True)
assert r.returncode==0,r.stderr
print(h(patch.encode()))
