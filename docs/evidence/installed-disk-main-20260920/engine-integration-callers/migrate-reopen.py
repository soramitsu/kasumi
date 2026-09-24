from pathlib import Path
import re
out=Path('target/installed-disk-validation/engine-integration-callers/proposed/crates/kasumi-engine/tests')
# Keep the original total/payload distinct from new actual disk metadata.
p=out/'common/mod.rs';s=p.read_text().replace('pub storage: kasumi_engine::test_utils::FixtureStorage,','pub storage: kasumi_engine::test_utils::FixtureStorage,\n    pub initial_disk_metadata_bytes: u64,')
s=s.replace('Self {\n            storage,','let initial_disk_metadata_bytes = storage.admission.snapshot().resident_reserved_bytes;\n        Self {\n            storage,\n            initial_disk_metadata_bytes,')
s=s.replace('/// engine and every retained generation drop before the enclosing private\n/// directory; these fixtures do not construct serving or Raft capabilities.','/// caller retains this scope until copied generations and images are dropped.\n/// These fixtures do not construct serving or Raft capabilities.')
p.write_text(s)
p=out/'staged_transactions.rs';s=p.read_text().replace('mod common;\n\nmod common;', 'mod common;');p.write_text(s)
p=out/'schema_activation.rs';s=p.read_text().replace('use kasumi_engine::{Database, SecurityAudit};','use kasumi_engine::{Database, SecurityAudit, TenantEngine};')
for function in ['request','creates','guard_assertions']:s=s.replace('fn '+function+'(db: &FixtureEngine', 'fn '+function+'(db: &TenantEngine')
p.write_text(s)
for name in ['history','guarded_staging','schema_activation','staged_transactions']:
    p=out/(name+'.rs');s=p.read_text()
    # The explicit lifetime belongs to the test scope, not a repeated opener.
    s=s.replace('async fn open(', 'async fn open(physical: &common::PhysicalFixture, ',1)
    s=s.replace('NodeStore::create_new_fixture(\n            path,\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','physical.storage.create_new(path, kasumi_store::test_utils::NODE_STORE_ID)')
    s=s.replace('NodeStore::open_existing_fixture(\n            path,\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','physical.storage.open_existing(path, kasumi_store::test_utils::NODE_STORE_ID)')
    s=s.replace('common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())')
    s=s.replace('common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), physical.storage.admission.clone())')
    # Calls are plain first-level async fixture open expressions. Work backwards
    # to preserve offsets; insert exactly one physical scope per test function.
    calls=list(re.finditer(r'(?P<indent>^[ \t]*)let \(db, (?P<audit>_?audit)\) = open\((?P<args>.*?)\)\s*\.await;',s,re.M|re.S))
    scopes={}; changes=[]
    for m in calls:
        preceding=s[:m.start()]
        headers=list(re.finditer(r'^(?:async )?fn [a-zA-Z_][a-zA-Z_0-9]*\(',preceding,re.M))
        assert headers,name
        scope=headers[-1].start();args=m['args'].strip();first=args.split(',',1)[0].strip()
        if scope not in scopes:
            scopes[scope]=first
            declaration=m['indent']+f'let physical = common::PhysicalFixture::new({first}, Default::default());\n'
        else:declaration=''
        replacement=declaration+m['indent']+f'let (db, {m["audit"]}) = open(&physical, {args}).await;'
        changes.append((m.start(),m.end(),replacement))
    for a,b,text in reversed(changes):s=s[:a]+text+s[b:]
    # Positive restore to another file in the SAME already-enrolled root uses
    # that same physical scope and actual scratch owner after prior close.
    s=re.sub(r'NodeStore::create_new_fixture\(\n        ([^\n]+),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture\(\),\n    \)',r'physical.storage.create_new(\1, kasumi_store::test_utils::NODE_STORE_ID)',s)
    s=s.replace('db.engine().fixture_snapshot()', 'db.engine().fixture_snapshot(&physical.storage.scratch)')
    if 'NodeStore::' not in s:s=s.replace('NodeStore, ', '')
    p.write_text(s)
    print(name,len(calls),'opens',len(scopes),'physical scopes')
# Admission's original 256MiB stays available in addition to disk metadata.
p=out/'admission.rs';s=p.read_text();a=s.index('    let node = NodeStore::create_new_fixture(');b=s.index('    let audit =',a)
s=s[:a]+'''    const MAX_BYTES: u64 = 256 << 20;
    let physical = common::PhysicalFixture::new(
        &directory.path().join("node.redb"),
        kasumi_engine::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            max_inflight_bytes: Some(MAX_BYTES), ..Default::default()
        }).unwrap(),
    );
    let node = physical.storage.create_new(directory.path().join("node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
    let admission = physical.storage.admission.clone();
'''+s[b:]
s=s.replace('common::security_audit_with_admission(', 'common::security_audit(')
s=s.replace('let occupied = kasumi_engine::test_utils::reserved_payload_bytes(&admission);','let occupied = kasumi_engine::test_utils::reserved_payload_bytes(&admission).checked_sub(physical.initial_disk_metadata_bytes).unwrap();')
s=s.replace('        MAX_BYTES\n    );','        MAX_BYTES + physical.initial_disk_metadata_bytes\n    );')
s=s.replace('    let node = NodeStore::create_new_fixture(\n        directory.path().join("local.redb"),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture(),\n    )','    let physical = common::PhysicalFixture::new(&directory.path().join("local.redb"), Default::default());\n    let node = physical.storage.create_new(directory.path().join("local.redb"), kasumi_store::test_utils::NODE_STORE_ID)')
s=s.replace('common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())')
s=s.replace('use kasumi_engine::admission::{AdmissionConfig, NodeAdmission};','use kasumi_engine::admission::AdmissionConfig;').replace('NodeStore, TenantStore','TenantStore');p.write_text(s)
