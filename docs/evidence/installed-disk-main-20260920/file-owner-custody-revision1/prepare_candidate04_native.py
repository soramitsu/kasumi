from pathlib import Path
import hashlib,json,shutil,re
r=Path.cwd();pkg=r/'target/installed-disk-validation/file-owner-custody-revision1/candidate-04';prior=r/'target/installed-disk-validation/backup-namespace-admission-revision4/native-01';p=pkg/'native-01';p.mkdir()
sha=lambda b:hashlib.sha256(b).hexdigest();records=[]
def copy(source,destination):
 destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination);records.append({'source':str(source),'destination':str(destination),'sha256':sha(source.read_bytes()),'bytes':source.stat().st_size})
for source in (pkg/'proposed').rglob('*'):
 if source.is_file():copy(source,p/'proposal-at-run'/source.relative_to(pkg/'proposed'))
store=p/'proposal-at-run/crates/kasumi-store/src'
for source in [store/'node_disk.rs',*(store/'node_disk').rglob('*.rs')]:copy(source,p/source.relative_to(store))
for name in ('disk_memory.rs','device_disk.rs','private_files.rs','test_utils.rs','fixture-source-at-run.rs','disk_memory_tests.rs','driver.rs','backup_sessions_scoped.rs','session-definitions-source-at-run.rs'):
 copy(prior/name,p/name)
for name in ('node_disk/directory/tests.rs','node_disk/namespace/tests.rs'):
 dst=p/name;old=dst.read_bytes();dst.write_text('// Same standalone exclusions as preceding census native-02.\n');records.append({'destination':str(dst),'omitted_unrelated_test_source_sha256':sha(old)})
for name in ('allocation_tests.rs','backup_sessions_fs.rs','backup_session_terminal.rs','backup_session_admission_tests.rs'):copy(store/name,p/name)
fs=p/'backup_sessions_fs.rs';s=fs.read_text();start=s.index('    fn aborted_objects(');end=s.index('\n}\n\n#[cfg(test)]',start);omitted=s[start:end];fs.write_text(s[:start]+s[end:]);records.append({'destination':str(fs),'omitted_authenticated_gc_methods_sha256':sha(omitted.encode()),'methods':['aborted_objects','list','delete'],'reason':'Preserved filesystem publication scope; no substitute StorageAccess or authority proof.'})
# Include the exact file/custody cases previously outside the directory/session
# module cohort. Only tests requiring actual ScratchDisk or NodeStore integration
# remain outside this standalone linker selection; nothing is stubbed.
source=store/'node_disk/tests.rs';s=source.read_text()
exclude={
'persistent_and_scratch_cannot_spend_the_same_filesystem_promise',
'poisoned_shared_promises_cannot_be_reopened_by_either_owner',
'unknown_filesystem_observation_fences_scratch_until_a_drained_census',
'live_shrink_failure_retains_charges_through_drop_and_fences_shared_device',
'node_store_rejects_different_isolated_memory_before_touching_file',
}
selected=[];omitted=[];chunks=[s[:s.index('fn installation(')]]
for m in re.finditer(r'^fn (\w+)\(',s,re.M):
 end=s.index('\n}',m.end())+2;body=s[m.start():end];name=m.group(1)
 prefix=s[:m.start()].rstrip();test=prefix.endswith('#[test]')
 item={'name':name,'sha256':sha(body.encode()),'source_start_line':s[:m.start()].count('\n')+1,'test':test}
 if name in exclude:omitted.append(item);continue
 # Retain the existing platform-field helper's exact explicit lint annotation.
 attrs='#[test]\n' if test else ''
 if name=='retired_descriptor_no_longer_names':attrs='#[allow(clippy::unnecessary_cast)]\n'
 chunks.append(attrs+body+'\n\n');selected.append(item)
assert {i['name'] for i in omitted}==exclude
(p/'node_disk/tests.rs').write_text(''.join(chunks))
(p/'file-test-extraction.json').write_text(json.dumps({'source':str(source),'sha256':sha(source.read_bytes()),'selected':selected,'omitted':omitted,'reason':'Five existing integration cases require ScratchDisk/NodeStore and are not qualified by this module-only linker; all other exact tests and helpers retained.'},indent=2)+'\n')
selection=json.loads((prior/'selection.json').read_text())
selection['scope']='Preserves all 67 prior namespace/session module cases and five compiled device cases filtered by the original run selection. Adds every exact node_disk/tests.rs file/custody case except five explicit ScratchDisk/NodeStore integration cases. Includes five new custody regressions. Same exact wire/container extraction and three authenticated GC method exclusions; no fake StorageAccess or proof. Full workspace Clippy/runtime, the five omitted integration cases, generic DirectoryOwner Drop/configured-root native closure, whole opaque report/allocator/RSS envelope and supported-filesystem physical bounds remain outside qualification.'
selection['new_file_tests']=['node_disk::tests::'+i['name'] for i in selected if i['test']]
prior_receipt=json.loads((prior/'terminal-drain.json').read_text());prior_names=prior_receipt['test_names'];records.append({'prior_receipt':str(prior/'terminal-drain.json'),'sha256':sha((prior/'terminal-drain.json').read_bytes())})
selection['expected_names']=sorted(set(prior_names+selection['new_file_tests']))
assert len(prior_names)==67,(len(prior_names),prior_names)
assert len(selection['expected_names'])==67+len(selection['new_file_tests'])
(p/'selection.json').write_text(json.dumps(selection,indent=2)+'\n')
(p/'copies.json').write_text(json.dumps(records,indent=2)+'\n')
runner=(prior/'run.py').read_text().replace("'backup_namespace_admission_native'","'file_owner_custody_native'")
# Require the exact expanded inventory before accepting the one unfiltered-in-scope run.
runner=runner.replace("sys.exit(0 if all(","\nif len(results)==len(commands) and all(x['exit_code']==0 for x in results):\n import re\n actual=sorted(re.findall(r'^test (\\S+) \\.\\.\\.',(p/'run.stdout').read_text(),re.M))\n expected=selection['expected_names']\n acceptance={'expected':expected,'observed':actual,'exact':actual==expected}\n (p/'test-inventory-readback.json').write_text(json.dumps(acceptance,indent=2)+'\\n')\n assert actual==expected, acceptance\n assert re.search(r'test result: ok\\. '+str(len(expected))+r' passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;', (p/'run.stdout').read_text())\nsys.exit(0 if all(")
runner=runner.replace("('run-production',[str(p/'production')])", "('list',[str(p/'tests'),'--list']),('run-production',[str(p/'production')])")
marker=" if code or not drained or executable_before!=executable_after:break"
replacement=r""" if name=='list' and code==0:
  import re
  listed=sorted(re.findall(r'^(\S+): test$',(p/'list.stdout').read_text(),re.M))
  selected=sorted(name for name in listed if name.startswith(('node_disk::','backup_sessions::')))
  filtered=[name for name in listed if name not in selected]
  accepted=selected==selection['expected_names'] and len(filtered)==5 and all(name.startswith('device_disk::') for name in filtered)
  (p/'binary-inventory.json').write_text(json.dumps({'all':listed,'selected':selected,'filtered':filtered,'accepted':accepted},indent=2)+'\n')
  if not accepted:break
 if code or not drained or executable_before!=executable_after:break"""
runner=runner.replace(marker,replacement)
(p/'run.py').write_text(runner)
print(json.dumps({'native_root':str(p),'records':len(records),'expected_tests':len(selection['expected_names']),'added_file_tests':len(selection['new_file_tests']),'omitted':len(omitted),'runner_sha256':sha(runner.encode()),'selection_sha256':sha((p/'selection.json').read_bytes())}))
