"""Append reviewed guard/design inputs and later completed diagnostics."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git', 'branch', '--show-current'], cwd=root, text=True).strip() == 'master'
source = root / 'target/installed-disk-validation'
destination = root / 'docs/evidence/installed-disk-main-20260920'
manifest_path = destination / 'raw-sha256.json'
manifest = json.loads(manifest_path.read_text())
previous = len(manifest)
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name
files = {source / '83-core-guards-applied.json', source / 'archive-memory-successors.py'}
for name in ['snapshot-memory-guard', 'journal-maintenance-memory-guards',
             'server-startup-adapter', 'directory-successor-audit']:
    for path in (source / name).iterdir():
        if path.is_file() and path.suffix in {'.py', '.json', '.md', '.patch', '.txt'}:
            files.add(path)
attempts = []
for number in range(84, 100):
    receipt = source / f'{number}-result.json'
    if not receipt.exists():
        continue
    record = json.loads(receipt.read_text())
    assert record['drained'] and record['cwd'] == str(root), receipt
    attempts.append(number)
    files.add(source / f'run{number}.py')
    for path in source.glob(f'{number}-*'):
        if path.is_file():
            files.add(path)
for path in sorted(files):
    relative = path.relative_to(source)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    target = destination / relative
    if target.exists():
        assert target.read_bytes() == data, str(relative)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    name = str(relative)
    if name in manifest:
        assert manifest[name] == digest, name
    else:
        manifest[name] = digest
manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + '\n')
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name
print(json.dumps({'previous_entries_verified': previous, 'entries_verified': len(manifest),
                  'completed_attempts_archived': attempts, 'source_artifacts_copied': len(files)}))
