from pathlib import Path
import shutil, json, hashlib, sys, re
r=Path.cwd();pkg=r/'target/installed-disk-validation/directory-census-session';prior=r/'target/installed-disk-validation/directory-fixed-maps/native-03';frozen=r/'target/installed-disk-validation/directory-parent-transitions/native-05'
assert len(sys.argv)==2 and re.fullmatch(r'native-[0-9]{2}',sys.argv[1])
p=pkg/sys.argv[1];p.mkdir();records=[]
def digest(b):return hashlib.sha256(b).hexdigest()
def copy(src,dst):
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);records.append({'source':str(src),'destination':str(dst),'sha256':digest(src.read_bytes()),'exact':True})
for src in (pkg/'proposed').rglob('*'):
 if src.is_file():copy(src,p/'proposal-at-run'/src.relative_to(pkg/'proposed'))
store=pkg/'cumulative-proposed/crates/kasumi-store/src'
for source in [store/'node_disk.rs',*(store/'node_disk').rglob('*.rs')]:copy(source,p/source.relative_to(store))
for name in ('disk_memory.rs','device_disk.rs','private_files.rs','test_utils.rs','fixture-source-at-run.rs'):copy(prior/name,p/name)
for name in ('node_disk/tests.rs','disk_memory_tests.rs','node_disk/directory/tests.rs','node_disk/namespace/tests.rs'):
 dst=p/name;old=dst.read_bytes() if dst.exists() else b'';dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text('// Standalone scope: this external test module is omitted; production module bytes are unchanged.\n');records.append({'destination':str(dst),'omitted_unrelated_test_source_sha256':digest(old) if old else None})
copy(store/'allocation_tests.rs',p/'allocation_tests.rs')
(p/'driver.rs').write_text('''#![allow(dead_code, unused_imports)]
mod disk_memory;
mod device_disk;
mod node_disk;
mod private_files;
#[cfg(test)] mod test_utils;
#[cfg(test)] mod allocation_tests;
pub use disk_memory::{DiskOpenError, DiskMemoryLease, NodeDiskMemoryAdmission};
pub use node_disk::*;
fn main() {
    use std::{collections::BTreeMap,path::PathBuf};
    let config=NodeDiskConfig { roots:BTreeMap::from([("data".into(),PathBuf::from("/var/lib/kasumi/data"))]),max_bytes:64<<30,maintenance_reserve_bytes:8<<30,min_free_bytes:0,max_open_files:4096,max_open_directories:4096,directory_policy:DirectoryPolicy::new(1<<20,32768).unwrap(),max_persistent_files:1_000_000,max_persistent_subdirectories:1_000_000,census_work_per_step:1_000_000,max_depth:64,max_name_bytes:255};
    let needed=NodeDisk::memory_requirements(&config).unwrap();
    println!("production owner={} registry={} device={} registration={} uncommitted_two_GiB_headroom={} RSS_plus_other_reservations=UNQUALIFIED",needed.owner_bytes,needed.registry_bytes,needed.device_bytes,needed.registration_bytes,(2u64<<30)-needed.owner_bytes-needed.registry_bytes-needed.device_bytes-needed.registration_bytes);
}
''')
(p/'selection.json').write_text(json.dumps({'extern':json.loads((frozen/'selected.json').read_text()),'dependency_directory':str(frozen/'deps'),'scope':'Exact proposed production modules; exact census, fixed-map, cursor and ledger tests. Existing device tests compile but are filtered. External node_disk/tests.rs, disk_memory_tests.rs, directory/tests.rs and namespace/tests.rs omitted as recorded; their proposed source remains in proposal-at-run where present. Frozen real extracted TestDiskMemory and exact proposal allocator observer. Not integrated server serde, installed MemoryCore, RSS, native-memory or physical-directory-growth qualification.'},indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
runner=(prior/'run.py').read_text().replace("'directory_fixed_map_native'","'directory_census_session_native'")
runner=runner.replace("inputs += [f for f in (compiler.parent.parent/'lib')", "inputs += [f for base in (r/'crates',r/'vendor') for f in base.rglob('*') if f.is_file() and (f.suffix == '.rs' or f.name == 'Cargo.toml')] + [r/'Cargo.toml',r/'Cargo.lock']\ninputs += [f for f in (compiler.parent.parent/'lib')")
runner=runner.replace("before=inventory();", "(p/'owner.json').write_text(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'argv':sys.argv,'cwd':str(r),'TMPDIR':env['TMPDIR']},indent=2)+'\\n');before=inventory();")
(p/'run.py').write_text(runner)
print(p)
