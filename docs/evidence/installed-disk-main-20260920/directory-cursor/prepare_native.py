from pathlib import Path
import shutil,json,hashlib
r=Path.cwd();pkg=r/'target/installed-disk-validation/directory-cursor';parent=r/'target/installed-disk-validation/directory-parent-transitions';p=pkg/'native-06';p.mkdir()
records=[]
def digest(b):return hashlib.sha256(b).hexdigest()
def copy(src,dst):
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);records.append({'source':str(src),'destination':str(dst),'sha256':digest(src.read_bytes()),'exact':True})
for src in (pkg/'proposed').rglob('*'):
 if src.is_file():copy(src,p/'proposal-at-run'/src.relative_to(pkg/'proposed'))
store=parent/'proposed/crates/kasumi-store/src';override=pkg/'proposed/crates/kasumi-store/src'
for source in [store/'node_disk.rs',*(store/'node_disk').rglob('*.rs')]:
 rel=source.relative_to(store);new=override/rel;copy(new if new.exists() else source,p/rel)
for new in (override/'node_disk').rglob('*.rs'):
 rel=new.relative_to(override)
 if not (p/rel).exists():copy(new,p/rel)
for name in ('disk_memory.rs','device_disk.rs','private_files.rs'):copy(parent/'native-05'/name,p/name)
for name in ('node_disk/tests.rs','disk_memory_tests.rs','node_disk/directory/tests.rs','node_disk/namespace/tests.rs'):
 dst=p/name;old=dst.read_bytes() if dst.exists() else b'';dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text('// Standalone scope: unrelated test module omitted; production module bytes unchanged.\n');records.append({'destination':str(dst),'omitted_unrelated_test_source_sha256':digest(old) if old else None})
copy(r/'crates/kasumi-store/src/allocation_tests.rs',p/'allocation_tests.rs')
fixture=r/'crates/kasumi-store/src/test_utils.rs';raw=fixture.read_text();start=raw.index('/// A fixture installation');end=raw.index('\nimpl crate::NodeStore {',start);fragment=raw[start:end];(p/'test_utils.rs').write_text('use std::time::Duration;\n'+fragment);records.append({'source':str(fixture),'source_sha256':digest(raw.encode()),'destination':str(p/'test_utils.rs'),'extraction_start_byte':start,'extraction_end_byte':end,'fragment_sha256':digest(fragment.encode()),'prefix':'use std::time::Duration;\n'})
copy(fixture,p/'fixture-source-at-run.rs')
(p/'driver.rs').write_text('''#![allow(dead_code, unused_imports)]
mod disk_memory;
mod device_disk;
mod node_disk;
mod private_files;
#[cfg(test)] mod test_utils;
#[cfg(test)] mod allocation_tests;
pub use disk_memory::{DiskOpenError, DiskMemoryLease, NodeDiskMemoryAdmission};
pub use node_disk::*;
fn main() { println!("production cursor modules compile; native tests exercise exact cfg(test) modules"); }
''')
(p/'selection.json').write_text(json.dumps({'extern':json.loads((parent/'native-05/selected.json').read_text()),'dependency_directory':str(parent/'native-05/deps'),'scope':'Exact proposed production modules; exact cursor tests; inherited ledger and device tests compile but are filtered from execution. Root node_disk/tests.rs, disk_memory_tests.rs, directory/tests.rs and namespace/tests.rs omitted. Real TestDiskMemory subset and allocation_tests copied from actual source; not installed MemoryCore or RSS/physical-growth qualification.'},indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
print(p)
