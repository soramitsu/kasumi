from pathlib import Path
import hashlib, json, difflib, subprocess
root=Path.cwd()
folder=root/'target/installed-disk-validation/journal-maintenance-memory-guards'
names=['crates/kasumi-engine/src/target_journal.rs','crates/kasumi-engine/src/target_journal_open_tests.rs','crates/kasumi-engine/src/tenant_audit.rs']
for name in names:
    dst=folder/'before'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((root/name).read_bytes())
    dst=folder/'proposed'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((root/name).read_bytes())
p=folder/'proposed'/names[0]
s=p.read_text();old='''        let gate = Self::owner_gate(&store)?;
''';assert s.count(old)==1
s=s.replace(old,'''        admission.memory().require_store_memory(&store)?;
        let gate = Self::owner_gate(&store)?;
''');p.write_text(s)
p=folder/'proposed'/names[1];s=p.read_text()
s=s.replace('    storage: crate::test_utils::FixtureStorage,\n','    storage: crate::test_utils::FixtureStorage,\n    config: crate::admission::AdmissionConfig,\n',1)
s=s.replace('NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?','NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?',1)
s=s.replace('            storage,\n            id,','            storage,\n            config,\n            id,',1)
s=s.replace('        storage,\n        id,','        storage,\n        config: _,\n        id,',1)
s+='''
#[tokio::test]
async fn journal_rejects_foreign_equal_policy_core_before_creating_or_reopening_head()
-> Result<()> {
    let f = Fixture::new().await?;
    f.node.drain_initializers().await?;
    let foreign = crate::admission::NodeAdmission::with_fixed_memory(
        f.config.clone(),
        2 << 30,
        0,
    )?;
    f.admission.memory().require_policy(&f.config)?;
    foreign.memory().require_policy(&f.config)?;
    assert!(!f.admission.shares_memory(&foreign));
    let limits = TargetJournalLimits { max_metadata_bytes: 4 << 20 };

    // No head exists yet. A foreign equal-policy core must not create one or
    // charge work to either governor before rejecting the owner mismatch.
    let before = f.admission.snapshot();
    let foreign_before = foreign.snapshot();
    let disk_before = f.storage.persistent.snapshot();
    let error = match TargetJournal::create_new(
        f.store.clone(), f.installed.clone(), limits.clone(), foreign.clone(),
    ) {
        Ok(_) => panic!("foreign core must not initialize a target journal"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "engine and physical storage memory owners differ");
    assert!(f.store.get(NS, b"metadata")?.is_none());
    for (admission, prior) in [(&f.admission, before), (&foreign, foreign_before)] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let disk_after = f.storage.persistent.snapshot();
    assert_eq!(disk_after.phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(disk_after.open_files, disk_before.open_files);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(disk_after.pending_bytes, disk_before.pending_bytes);

    let original = f.create()?;
    let head = f.store.get(NS, b"metadata")?.unwrap();
    // Remove the cached journal facade, leaving the store live. Without the
    // entry guard this reopen can publish a new facade on the foreign core.
    drop(original);
    let before = f.admission.snapshot();
    let foreign_before = foreign.snapshot();
    let error = match TargetJournal::open_existing(
        f.store.clone(), f.installed.clone(), limits, foreign.clone(),
    ) {
        Ok(_) => panic!("foreign core must not reopen an installed target journal"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "engine and physical storage memory owners differ");
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head.clone()));
    for (admission, prior) in [(&f.admission, before), (&foreign, foreign_before)] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let exact = f.reopen()?;
    assert_eq!(f.store.get(NS, b"metadata")?, Some(head));
    assert!(Arc::ptr_eq(&exact.admission, &f.admission));
    exact.shutdown().await?;
    f.admission.drain_snapshot_startups().await?;
    foreign.drain_snapshot_startups().await?;
    f.node.shutdown().await?;
    Ok(())
}
'''
p.write_text(s)
p=folder/'proposed'/names[2];s=p.read_text();old='''    ) -> Result<()> {
        let _apply = self.apply_lock.lock().map_err(|_| {
''';assert s.count(old)==1
s=s.replace(old,'''    ) -> Result<()> {
        let store = self.snapshot_store.get().ok_or_else(|| {
            Error::new(ErrorCode::Conflict, "install storage before audit maintenance")
        })?;
        admission.memory().require_store_memory(store).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "audit maintenance and physical storage memory owners differ",
            )
        })?;
        let _apply = self.apply_lock.lock().map_err(|_| {
''');s+='''
#[cfg(test)]
#[path = "tenant_audit_memory_tests.rs"]
mod memory_tests;
''';p.write_text(s)
new='crates/kasumi-engine/src/tenant_audit_memory_tests.rs';names.append(new)
p=folder/'proposed'/new
p.write_text('''use super::*;
use crate::admission::{AdmissionConfig, NodeAdmission};
use kasumi_store::{TenantStore, test_utils::{LocalKeyProvider, NODE_STORE_ID}};

#[test]
fn audit_maintenance_requires_installed_storage_before_reserving_a_pool() -> anyhow::Result<()> {
    let admission = NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
    let engine = TenantEngine::new(
        "maintenance".into(), "initial".into(), Policy::default(), Limits::default(),
    )?;
    let before = admission.snapshot();
    let error = engine.install_audit_maintenance(&admission).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "install storage before audit maintenance");
    assert!(engine.audit_maintenance.lock().unwrap().is_none());
    let after = admission.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, before.inflight_operations);
    Ok(())
}

#[tokio::test]
async fn audit_maintenance_rejects_foreign_equal_policy_core_and_keeps_exact_pool()
-> anyhow::Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
    let config = AdmissionConfig {
        max_inflight_bytes: Some((256_u64 << 20).checked_add(
            crate::test_utils::isolated_disk_metadata_bytes(&persistent, &scratch)?,
        ).ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?),
        ..Default::default()
    };
    let admission = NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?;
    let foreign = NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?;
    admission.memory().require_policy(&config)?;
    foreign.memory().require_policy(&config)?;
    assert!(!admission.shares_memory(&foreign));
    let physical = crate::test_utils::FixtureStorage::with_admission(
        &persistent, &scratch, admission.clone(),
    )?;
    let node = physical.create_new(directory.path().join("persistent/node.redb"), NODE_STORE_ID)?;
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(), "maintenance".into(), Arc::new(LocalKeyProvider::new([189; 32])),
    ).await?;
    node.drain_initializers().await?;
    let engine = TenantEngine::new(
        "maintenance".into(), "initial".into(), Policy::default(), Limits::default(),
    )?;
    engine.install_storage_access(&store)?;
    let before = admission.snapshot();
    let foreign_before = foreign.snapshot();
    let disk_before = physical.persistent.snapshot();
    let error = engine.install_audit_maintenance(&foreign).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "audit maintenance and physical storage memory owners differ");
    assert!(engine.audit_maintenance.lock().unwrap().is_none());
    for (owner, prior) in [(&admission, before.clone()), (&foreign, foreign_before)] {
        let after = owner.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let disk_after = physical.persistent.snapshot();
    assert_eq!(disk_after.phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(disk_after.open_files, disk_before.open_files);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(disk_after.pending_bytes, disk_before.pending_bytes);

    engine.install_audit_maintenance(&admission)?;
    let installed = engine.audit_maintenance.lock().unwrap().clone().unwrap();
    assert_eq!(admission.snapshot().reserved_bytes,
        before.reserved_bytes + crate::audit_maintenance::NodeAuditMaintenance::WORKSPACE_BYTES);
    engine.install_audit_maintenance(&admission)?;
    assert!(Arc::ptr_eq(&installed, engine.audit_maintenance.lock().unwrap().as_ref().unwrap()));
    assert_eq!(admission.snapshot().reserved_bytes,
        before.reserved_bytes + crate::audit_maintenance::NodeAuditMaintenance::WORKSPACE_BYTES);
    drop(installed);
    drop(engine);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    store.shutdown().await?;
    admission.drain_snapshot_startups().await?;
    foreign.drain_snapshot_startups().await?;
    node.shutdown().await?;
    Ok(())
}
''')
fmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
patch=[];manifest=[]
for name in names:
    p=folder/'proposed'/name
    formatted=subprocess.run([fmt,'--edition','2024','--emit','stdout','--config','skip_children=true'],input=p.read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
    p.write_bytes(formatted)
    old=(folder/'before'/name).read_bytes() if (folder/'before'/name).exists() else b''
    patch.extend(difflib.unified_diff(old.decode().splitlines(True),formatted.decode().splitlines(True),fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))
    manifest.append({'path':name,'before_sha256':hashlib.sha256(old).hexdigest() if old else None,'proposed_sha256':hashlib.sha256(formatted).hexdigest()})
(folder/'guards.patch').write_text(''.join(patch))
data={'status':'target_only_uncompiled','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'patch_sha256':hashlib.sha256((folder/'guards.patch').read_bytes()).hexdigest(),'files':manifest}
(folder/'manifest.json').write_text(json.dumps(data,indent=2)+'\n')
subprocess.run(['git','apply','--check',str(folder/'guards.patch')],check=True)
print(json.dumps(data,indent=2))
