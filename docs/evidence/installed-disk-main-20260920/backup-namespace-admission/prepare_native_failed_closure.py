from pathlib import Path
import hashlib,json,shutil,sys,re
r=Path.cwd();pkg=r/'target/installed-disk-validation/backup-namespace-admission';prior=r/'target/installed-disk-validation/directory-managed-namespace-generic/native-01'
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
# Exact unchanged definitions; the access capability itself comes from the
# frozen compiled real kasumi-store crate, never a permissive harness substitute.
source=r/'crates/kasumi-store/src/backup_sessions.rs';copy(source,p/'session-definitions-source-at-run.rs');s=source.read_text();start=s.index('pub const MAX_SESSION_RECORD_BYTES');end=s.index('pub struct VerifiedBackupSession')
(p/'backup_sessions_scoped.rs').write_text('use anyhow::{Context, Result, ensure};\nuse serde::{Serialize, Deserialize};\nuse sha2::{Digest, Sha256};\nuse std::sync::Arc;\nuse uuid::Uuid;\nuse kasumi_store::StorageAccess;\n'+s[start:end]+'\n#[path="backup_sessions_fs.rs"]\npub(crate) mod filesystem;\n')
header=re.search(r'^pub\(crate\) const HEADER_LIMIT: usize = .*?;', (store/'backup.rs').read_text(),re.M).group(0)
driver=(p/'driver.rs').read_text();driver=driver.replace('fn main() {','mod backup { '+header+' }\n#[path="backup_sessions_scoped.rs"] mod backup_sessions;\nfn main() {',1);(p/'driver.rs').write_text(driver)
# Cargo's dependency fingerprint is a little-endian u64 stored beside the JSON.
# Resolve only the selected crate's exact dependency closure, not every artifact
# in target/debug/deps and not a newest-filename heuristic per dependency.
fingerprints={}
for path in (r/'target/debug/.fingerprint').glob('*/lib-*'):
 if path.suffix or path.name.startswith('lib-lib'): # lib-libc is valid; suffix is the only exclusion
  if path.suffix: continue
 try:
  raw=path.read_text().strip()
  if re.fullmatch('[0-9a-f]{16}',raw):fingerprints[(path.name[4:],int.from_bytes(bytes.fromhex(raw),'little'))]=path
 except (UnicodeDecodeError,OSError):pass
selected=r/'target/debug/.fingerprint/kasumi-store-5be4970830ef58f8/lib-kasumi_store'
queue=[selected];seen=set();extern={};missing=[];resolution=[]
while queue:
 fp=queue.pop()
 if fp in seen:continue
 seen.add(fp);data=json.loads(fp.with_suffix('.json').read_text());name=fp.name[4:];extra=fp.parent.name.rsplit('-',1)[1];files=[]
 for suffix in ('.rlib','.rmeta','.dylib','.so'):
  artifact=r/'target/debug/deps'/('lib'+name+'-'+extra+suffix)
  if artifact.exists():copy(artifact,p/'deps'/artifact.name);files.append(artifact.name)
 if not files:missing.append({'fingerprint':str(fp),'reason':'no compiled artifact'})
 copy(fp,p/'fingerprints'/fp.parent.name/fp.name);copy(fp.with_suffix('.json'),p/'fingerprints'/fp.parent.name/(fp.name+'.json'))
 resolution.append({'crate':name,'fingerprint':str(fp),'artifacts':files})
 if name not in extern and any(f.endswith('.rlib') for f in files):extern[name]=str(p/'deps'/next(f for f in files if f.endswith('.rlib')))
 for dependency in data['deps']:
  key=(dependency[1],dependency[3]);found=fingerprints.get(key)
  if found is None:
   # Build-script fingerprints configure the already-built rlib. They are not
   # linkable Rust dependencies; every missing actual library rejects preparation.
   if dependency[1] not in ('build_script_build',):missing.append({'dependency':dependency,'owner':name})
  else:queue.append(found)
assert not missing,missing
required=('anyhow','serde','uuid','libc','sha2','parking_lot','zeroize','tempfile','hex','kasumi_store')
assert all(name in extern for name in required),(required,extern.keys())
selection={'extern':{name:extern[name] for name in required},'dependency_directory':str(p/'deps'),'dependency_resolution':resolution,'scope':'Actual proposed NodeDisk modules and complete backup_sessions_fs/terminal modules. Original 49 node_disk tests plus seven batch regressions; actual existing two filesystem ownership regressions, five new filesystem/session regressions including subprocess restart and paused classification race, and two terminal codec regressions. Exact unchanged wire/proof definitions are extracted from session-definitions-source-at-run.rs; real frozen kasumi-store StorageAccess and its Cargo-fingerprint-resolved dependency closure compile proof checks. This does not qualify full store/server integration, authenticated authority construction, whole RSS, native close gaps inherited by file helpers, or supported-filesystem pre-effect directory bounds. Same three unrelated module test exclusions and disk_memory exclusions as prior native cohort. Five inherited device tests compile but are filtered.'}
(p/'selection.json').write_text(json.dumps(selection,indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
runner=(prior/'run.py').read_text().replace("'directory_managed_namespace_native'","'backup_namespace_admission_native'")
runner=runner.replace("'zeroize','tempfile'","'zeroize','tempfile','hex','kasumi_store'")
runner=runner.replace("[str(p/'tests'),'node_disk::','--nocapture','--test-threads=1']","[str(p/'tests'),'node_disk::','backup_sessions::','--nocapture','--test-threads=1']")
(p/'run.py').write_text(runner)
print(p,'dependencies',len(resolution),'files',len(records),'bytes',sum(x.get('bytes',0) for x in records))
