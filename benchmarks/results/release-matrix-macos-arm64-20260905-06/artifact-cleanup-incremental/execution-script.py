from pathlib import Path
import json, shutil, time, importlib.util, hashlib, subprocess
root=Path(__file__).resolve().parent.parent
out=root/'benchmarks/results/release-matrix-macos-arm64-20260905-06/artifact-cleanup-incremental'
out.mkdir(exist_ok=True)
assert not (out/'result.json').exists()
p=root/'target/incremental-capacity-candidates.json';d=json.loads(p.read_text())
s=importlib.util.spec_from_file_location('matrix',root/'scripts/run_benchmark_matrix.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
expected='a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2';assert m.source_identity()==expected
roots=[root/'target/debug/incremental',root/'target/linux-validation/debug/incremental']
paths=[Path(x['path'])for x in d['selected_units']]
assert len(paths)==len(set(paths))
for path in paths:
 assert path.parent in roots and path.is_dir() and not path.is_symlink()
 assert not any('working'in c.name for c in path.iterdir())
 for c in path.rglob('*'):assert not c.is_symlink()
# Retain every current compiled dependency and executable inode, without reading
# or changing the benchmark's data, process settings or source files.
retained={}
for lane in [root/'target/debug/deps',root/'target/linux-validation/debug/deps',root/'target/release']:
 for f in lane.iterdir():
  if f.is_file():
   st=f.stat();retained[str(f)]=(st.st_ino,st.st_size,st.st_mtime_ns)
proof={'status':'running','started_unix_seconds':time.time(),'source_sha256_before':expected,'free_disk_bytes_before':shutil.disk_usage(root).free,'selected_units':len(paths),'retained_compiled_files':len(retained),'cache_tradeoff':'Some future changed-source compilations lose incremental acceleration; current compiled artifacts and the existing warm target directories remain.'}
shutil.copyfile(p,out/p.name);shutil.copyfile(Path(__file__),out/'execution-script.py')
(out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
for path in paths:shutil.rmtree(path)
for f,identity in retained.items():
 st=Path(f).stat();assert (st.st_ino,st.st_size,st.st_mtime_ns)==identity,f
assert m.source_identity()==expected
proof.update(status='completed',finished_unix_seconds=time.time(),free_disk_bytes_after=shutil.disk_usage(root).free,source_sha256_after=expected,compiled_artifacts_unchanged=True)
proof['observed_free_disk_change_bytes']=proof['free_disk_bytes_after']-proof['free_disk_bytes_before']
(out/'result.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
