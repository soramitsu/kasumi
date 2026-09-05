#!/usr/bin/env python3
"""Remove only the individually inventoried obsolete Kasumi build artifacts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

root = Path(__file__).resolve().parent.parent
out = root / 'benchmarks/results/release-matrix-macos-arm64-20260905-06/artifact-cleanup'
out.mkdir(exist_ok=True)
assert not (out / 'result.json').exists(), 'preserve earlier cleanup evidence'
mac = json.loads((root / 'target/artifact-prune-candidates.json').read_text())
linux = json.loads((root / 'target/linux-obsolete-artifacts.json').read_text())
spec = importlib.util.spec_from_file_location('matrix', root / 'scripts/run_benchmark_matrix.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
expected = 'a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2'
assert driver.source_identity() == expected
for pid in (29330, 29334, 29404, 29406, 33218, 33219):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        continue
    raise RuntimeError(f'recorded validation/build process still exists: {pid}')
allowed = [root / suffix for suffix in ('target/debug/deps', 'target/debug/incremental', 'target/linux-validation/debug/deps', 'target/linux-validation/debug/incremental')]
protected = {Path(p) for p in mac['protected_executables']}
protected.update(Path(p['path']) for p in linux['protected_current_executables'])
protected_stats = {str(p): (p.stat().st_dev, p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns) for p in protected}
protected_inodes = {(v[0], v[1]) for v in protected_stats.values()}
paths = {Path(e['path']) for e in mac['superseded_executables'] + linux['candidates']}
for e in mac['obsolete_executable_debug_objects']:
    paths.update(Path(p) for p in e['files'])
for e in mac['obsolete_incremental_units'] + mac['older_incremental_sessions']:
    p = Path(e['path'])
    if 'keep_newest' in e:
        newest = Path(e['keep_newest'])
        assert newest.exists() and p.parent == newest.parent and p != newest
    paths.add(p)
for p in paths:
    assert p.is_absolute() and any(p.is_relative_to(a) and p != a for a in allowed), p
    assert not p.is_symlink(), p
    assert not any(q == p or q.is_relative_to(p) for q in protected), p
# A parent selection supersedes a nested selection; every parent has been
# individually identified in the review manifest, never a complete build lane.
selected = []
selected_set = set()
for p in sorted(paths, key=lambda p: len(p.parts)):
    if not any(parent in selected_set for parent in p.parents):
        selected.append(p)
        selected_set.add(p)
files = set()
for p in selected:
    files.update(q for q in p.rglob('*') if q.is_file() or q.is_symlink()) if p.is_dir() else files.add(p)
for p in files:
    st = p.lstat()
    assert stat.S_ISREG(st.st_mode), p
    assert (st.st_dev, st.st_ino) not in protected_inodes, p
before = shutil.disk_usage(root).free
for name in ('artifact-prune-candidates.json', 'linux-obsolete-artifacts.json'):
    shutil.copyfile(root / 'target' / name, out / name)
evidence = dict(status='running', source_sha256_before=expected, started_unix_seconds=time.time(), free_disk_bytes_before=before, selected_paths=len(selected), selected_regular_files=len(files), protected_executables=len(protected_stats), retained_release_lane=True, retained_current_incremental_sessions=True)
(out / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')
for p in selected:
    if p.is_dir():
        shutil.rmtree(p)
    else:
        p.unlink()
for p, identity in protected_stats.items():
    st = Path(p).stat()
    assert (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == identity, p
assert driver.source_identity() == expected
evidence.update(status='completed', finished_unix_seconds=time.time(), source_sha256_after=expected, protected_executables_unchanged=True, free_disk_bytes_after=shutil.disk_usage(root).free)
evidence['observed_free_disk_change_bytes'] = evidence['free_disk_bytes_after'] - before
evidence['scope'] = 'Only explicit superseded test executables, their obsolete object caches, and older finalized incremental sessions. Current binaries, newest warm sessions, dependencies, source, and all earlier evidence retained.'
(out / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(json.dumps(evidence, indent=2))
