from pathlib import Path
import json,hashlib,subprocess,difflib,re
D=Path('target/installed-disk-validation/77-engine-fixture-successor');rows=[];patch=[]
paths=['crates/kasumi-engine/src/service_retirement_tests.rs','crates/kasumi-engine/src/snapshot_codec.rs']
for rel in paths:
 before=Path(rel).read_text();s=before
 if rel.endswith('service_retirement_tests.rs'):
  old='''            fixture._directory.path().join(id),
            16 << 20,''';new='''            fixture._directory.path().join("persistent").join(id),
            16 << 20,
            fixture.storage.persistent.clone(),'''
  assert old in s;s=s.replace(old,new,1)
 else:
  start=s.index('#[cfg(test)]\nmod tests {');prefix=s[:start];t=s[start:]
  a=t.index('    fn read(');b=t.index('    pub(super) fn state()',a)
  t=t[:a]+'''    fn read(disk: &Arc<kasumi_store::ScratchDisk>, reader: &mut dyn Read) -> anyhow::Result<TenantState> {
        Ok(super::read(disk, reader)?.state)
    }
'''+t[b:]
  t=t.replace('read(&mut ', 'read(disk, &mut ')
  setup='''
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
        ).unwrap();
        let disk = &scratch.disk;'''
  # All four direct codec tests retain one owner for all valid/corrupt/truncated decodes.
  t,n=re.subn(r'(#\[test\]\n\s*fn [^(]+\(\) \{)',lambda m:m[0]+setup,t);assert n==4,n
  s=prefix+t
 run=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true','--emit','stdout'],input=s,capture_output=True,text=True);assert run.returncode==0,run.stderr;s=run.stdout
 for kind,content in [('before',before),('proposed',s)]:
  out=D/kind/rel;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(content)
 rows.append(dict(path=rel,before_sha256=hashlib.sha256(before.encode()).hexdigest(),proposed_sha256=hashlib.sha256(s.encode()).hexdigest()))
 patch.append('diff --git a/'+rel+' b/'+rel+'\n');patch.extend(difflib.unified_diff(before.splitlines(True),s.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
(D/'fix.patch').write_text(''.join(patch));patchsha=hashlib.sha256((D/'fix.patch').read_bytes()).hexdigest()
check=subprocess.run(['git','apply','--check',str(D/'fix.patch')],capture_output=True,text=True);assert check.returncode==0,check.stderr
(D/'manifest.json').write_text(json.dumps(dict(status='TARGET_ONLY_UNCOMPILED',patch_sha256=patchsha,files=rows,validation=dict(rustfmt_stdin=True,apply_check=True,no_build=True)),indent=2)+'\n')
print(patchsha)
