from pathlib import Path
import hashlib,json,shutil,sys,re
r=Path.cwd();pkg=r/'target/installed-disk-validation/directory-managed-namespace';prior=r/'target/installed-disk-validation/directory-census-session/native-02'
assert len(sys.argv)==2 and re.fullmatch('native-[0-9]{2}',sys.argv[1]);p=pkg/sys.argv[1];p.mkdir()
records=[]
def copy(source,destination):
 destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination);records.append({'source':str(source),'destination':str(destination),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
for source in (pkg/'proposed').rglob('*'):
 if source.is_file():
  copy(source,p/'proposal-at-run'/source.relative_to(pkg/'proposed'))
  target=pkg/'cumulative-proposed'/source.relative_to(pkg/'proposed');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
store=pkg/'cumulative-proposed/crates/kasumi-store/src'
for source in [store/'node_disk.rs',*(store/'node_disk').rglob('*.rs')]:copy(source,p/source.relative_to(store))
for name in ('disk_memory.rs','device_disk.rs','private_files.rs','test_utils.rs','fixture-source-at-run.rs','disk_memory_tests.rs','driver.rs','selection.json'):copy(prior/name,p/name)
for name in ('node_disk/tests.rs','node_disk/directory/tests.rs','node_disk/namespace/tests.rs'):
 dst=p/name;old=dst.read_bytes();dst.write_text('// Same standalone exclusions as preceding census native-02.\n');records.append({'destination':str(dst),'omitted_unrelated_test_source_sha256':hashlib.sha256(old).hexdigest()})
copy(store/'allocation_tests.rs',p/'allocation_tests.rs')
selection=json.loads((p/'selection.json').read_text());selection['scope']='Exact proposed production modules; original census, fixed-map, cursor, ledger tests plus managed directory tests. Same external test exclusions and frozen real TestDiskMemory as census native-02; inherited device tests compile but filtered. No integrated server, whole-memory/RSS or physical-growth qualification.';(p/'selection.json').write_text(json.dumps(selection,indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
runner=(prior/'run.py').read_text().replace("'directory_census_session_native'","'directory_managed_namespace_native'")
(p/'run.py').write_text(runner)
print(p)
