from pathlib import Path
import shutil,hashlib,json,difflib,subprocess
root=Path('/Users/mtakemiya/dev/kasumi');out=root/'target/installed-disk-validation/gate77-store-fixes';paths=['crates/kasumi-store/src/audit_archive.rs','crates/kasumi-store/src/scratch_disk.rs','crates/kasumi-store/src/node_disk/file.rs','crates/kasumi-store/src/device_disk.rs'];sha=lambda x:hashlib.sha256(x).hexdigest()
for rel in paths:
 for d in ['before','proposed']:
  p=out/d/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/rel,p)
p=out/'proposed'/paths[0];s=p.read_text();assert s.count('.store(true, Ordering::SeqCst, fixture_scratch.clone())')==1;assert s.count('.store(false, Ordering::SeqCst, fixture_scratch.clone())')==1;s=s.replace('.store(true, Ordering::SeqCst, fixture_scratch.clone())','.store(true, Ordering::SeqCst)').replace('.store(false, Ordering::SeqCst, fixture_scratch.clone())','.store(false, Ordering::SeqCst)');p.write_text(s)
p=out/'proposed'/paths[1];s=p.read_text();old='''        assert!(
            crate::test_utils::retry_disk_registry(|| ScratchDisk::open_fixture(
                &ScratchDiskConfig {
                    directory: link,
                    max_bytes: 1,
                    min_free_bytes: 0
                },
                crate::test_utils::TestDiskMemory::new(1 << 20, 32)
            ))
            .is_err()
        );''';new='''        let config = ScratchDiskConfig {
            directory: link,
            max_bytes: 1,
            min_free_bytes: 0,
        };
        let memory = crate::test_utils::TestDiskMemory::new(1 << 20, 32);
        assert!(
            crate::test_utils::retry_disk_registry(|| {
                ScratchDisk::open_fixture(&config, memory.clone())
            })
            .is_err()
        );''';assert s.count(old)==1;s=s.replace(old,new);p.write_text(s)
p=out/'proposed'/paths[2];s=p.read_text();old='''        let state = self.lock_state();
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        // Hold admission through physical path validation. On preparation
        // failure this local guard drops before the input descriptor owner.
        let mut state = self.lock_state();''';new='''        let mut state = self.lock_state();
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        // Hold this same admission guard through physical path validation. On
        // preparation failure it drops before the input descriptor owner.''';assert s.count(old)==1;s=s.replace(old,new);p.write_text(s)
p=out/'proposed'/paths[3];s=p.read_text();old='    pub(crate) fn memory(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {';assert s.count(old)==1;s=s.replace(old,'    #[cfg(test)]\n'+old);p.write_text(s)
parts=[];files=[]
for rel in paths:
 p=out/'proposed'/rel
 subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(p)],check=True)
 b=(out/'before'/rel).read_bytes();a=p.read_bytes();assert(root/rel).read_bytes()==b
 parts.extend(difflib.unified_diff(b.decode().splitlines(True),a.decode().splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
 files.append({'path':rel,'before_sha256':sha(b),'proposed_sha256':sha(a)})
patch=''.join(parts);(out/'store.patch').write_text(patch);(out/'manifest.json').write_text(json.dumps({'status':'target-only gate77 follow-up; uncompiled','patch_sha256':sha(patch.encode()),'files':files},indent=2)+'\n')
r=subprocess.run(['git','apply','--check',str(out/'store.patch')],cwd=root,text=True,capture_output=True);assert r.returncode==0,r.stderr;(out/'patch-check.json').write_text(json.dumps({'exit_code':r.returncode,'stderr':r.stderr,'stdout':r.stdout,'before_hashes_match':True},indent=2)+'\n');print(sha(patch.encode()))
