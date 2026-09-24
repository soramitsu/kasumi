from pathlib import Path
import difflib,json,hashlib,subprocess
r=Path.cwd();p=r/'target/installed-disk-validation/directory-parent-transitions';u=r/'target/installed-disk-validation/unified-inode-census';cb=p/'cumulative-base';cb.mkdir()
files=sorted(f.relative_to(p/'proposed') for f in (p/'proposed').rglob('*') if f.is_file())
for rel in files:
 if rel==Path('crates/kasumi-store/src/lib.rs'):source=r/rel
 elif (u/'proposed'/rel).exists():source=u/'base'/rel
 else:source=p/'base'/rel
 if source.exists():q=cb/rel;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(source.read_bytes())
def patch(base,output):
 chunks=[];changed=[]
 for rel in files:
  old=base/rel;new=p/'proposed'/rel;a=old.read_text().splitlines(keepends=True) if old.exists() else [];b=new.read_text().splitlines(keepends=True)
  if a==b:continue
  changed.append(str(rel));chunks.append(f'diff --git a/{rel} b/{rel}\n')
  if not old.exists():chunks.append('new file mode 100644\n')
  chunks.extend(difflib.unified_diff(a,b,fromfile=f'a/{rel}' if old.exists() else '/dev/null',tofile=f'b/{rel}'))
 output.write_text(''.join(chunks));return changed
successor=patch(p/'base',p/'parent-transitions.patch');cumulative=patch(cb,p/'cumulative.patch')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
manifest={'status':'frozen target-only; not merge-ready or production-qualified','root':str(r),'branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'dependency':{'patch':str(u/'unified-census.patch'),'sha256':sha(u/'unified-census.patch')},'upstream_context_preserved':'crates/kasumi-store/src/lib.rs RetainedSpool/SpoolClosePhase exports already present in root; successor base/proposed carry them, cumulative base is actual current lib.rs','patches':{n:{'sha256':sha(p/n),'files':v} for n,v in [('parent-transitions.patch',successor),('cumulative.patch',cumulative)]},'files':{str(rel):{'base_sha256':sha(p/'base'/rel) if (p/'base'/rel).exists() else None,'cumulative_base_sha256':sha(cb/rel) if (cb/rel).exists() else None,'proposed_sha256':sha(p/'proposed'/rel)} for rel in files}}
(p/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('files',len(files),'successor changed',len(successor),'cumulative changed',len(cumulative));print(json.dumps(manifest['patches'],indent=2))
