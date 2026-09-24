from pathlib import Path
import hashlib,json,shutil,sys,re
r=Path.cwd();pkg=r/'target/installed-disk-validation/backup-namespace-admission-revision4';prior=r/'target/installed-disk-validation/directory-managed-namespace-generic/native-01'
assert len(sys.argv)==2 and re.fullmatch('native-[0-9]{2}',sys.argv[1]);p=pkg/sys.argv[1];p.mkdir()
records=[]
def copy(source,destination):
 destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination);records.append({'source':str(source),'destination':str(destination),'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'bytes':source.stat().st_size})
for source in (pkg/'proposed').rglob('*'):
 if source.is_file():copy(source,p/'proposal-at-run'/source.relative_to(pkg/'proposed'))
store=p/'proposal-at-run/crates/kasumi-store/src'
for source in [store/'node_disk.rs',*(store/'node_disk').rglob('*.rs')]:copy(source,p/source.relative_to(store))
for name in ('disk_memory.rs','device_disk.rs','private_files.rs','test_utils.rs','fixture-source-at-run.rs','disk_memory_tests.rs','driver.rs'):copy(prior/name,p/name)
for name in ('node_disk/tests.rs','node_disk/directory/tests.rs','node_disk/namespace/tests.rs'):
 dst=p/name;old=dst.read_bytes();dst.write_text('// Same standalone exclusions as preceding census native-02.\n');records.append({'destination':str(dst),'omitted_unrelated_test_source_sha256':hashlib.sha256(old).hexdigest()})
for name in ('allocation_tests.rs','backup_sessions_fs.rs','backup_session_terminal.rs','backup_session_admission_tests.rs'):copy(store/name,p/name)
# Extract only exact unchanged wire/container definitions. No authority proof
# or StorageAccess substitute is introduced. The three authenticated GC methods
# are explicitly omitted from this scoped filesystem compilation, as recorded.
source=r/'crates/kasumi-store/src/backup_sessions.rs';copy(source,p/'session-definitions-source-at-run.rs');s=source.read_text();start=s.index('pub const MAX_SESSION_RECORD_BYTES');end=s.index('/// One exact reclaimable object.')
(p/'backup_sessions_scoped.rs').write_text('use anyhow::{Context, Result, ensure};\nuse serde::{Serialize, Deserialize};\nuse std::sync::Arc;\nuse uuid::Uuid;\n'+s[start:end]+'\n#[path="backup_sessions_fs.rs"]\npub(crate) mod filesystem;\n')
fs=p/'backup_sessions_fs.rs';s=fs.read_text();start=s.index('    fn aborted_objects(');end=s.index('\n}\n\n#[cfg(test)]',start);omitted=s[start:end];fs.write_text(s[:start]+s[end:]);records.append({'destination':str(fs),'omitted_authenticated_gc_methods_sha256':hashlib.sha256(omitted.encode()).hexdigest(),'methods':['aborted_objects','list','delete'],'reason':'Scoped namespace/session publication validation; no fake proof/StorageAccess backend. Full authenticated GC compilation/integration remains open.'})
header=re.search(r'^pub\(crate\) const HEADER_LIMIT: usize = .*?;', (store/'backup.rs').read_text(),re.M).group(0)
driver=(p/'driver.rs').read_text();driver=driver.replace('fn main() {','mod backup { '+header+' }\n#[path="backup_sessions_scoped.rs"] mod backup_sessions;\nfn main() {',1);(p/'driver.rs').write_text(driver)
selection=json.loads((prior/'selection.json').read_text());selection['scope']='Actual proposed NodeDisk modules plus exact filesystem open/put/get and terminal modules. Original 49 node_disk tests plus eight batch regressions; actual existing two filesystem ownership regressions, six new filesystem/session regressions including subprocess restart and paused classification race, and two terminal codec regressions. Exact unchanged wire definitions are extracted from session-definitions-source-at-run.rs. Three authenticated GC methods (aborted_objects/list/delete) are explicitly omitted and hashed; there is no authority proof or StorageAccess stub. Full store/server compilation, backup/audit destination constructors, authenticated GC integration, whole RSS, inherited file-helper native close gaps, and supported-filesystem pre-effect directory bounds remain unqualified. Same three unrelated module test exclusions and disk_memory exclusions as prior native cohort. Five inherited device tests compile but are filtered.'
(p/'selection.json').write_text(json.dumps(selection,indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
runner=(prior/'run.py').read_text().replace("'directory_managed_namespace_native'","'backup_namespace_admission_native'")
runner=runner.replace("[str(p/'tests'),'node_disk::','--nocapture','--test-threads=1']","[str(p/'tests'),'node_disk::','backup_sessions::','--nocapture','--test-threads=1']")
(p/'run.py').write_text(runner)
print(p,'files',len(records),'bytes',sum(x.get('bytes',0) for x in records))
