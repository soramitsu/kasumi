"""Append immutable installed-memory development inputs and completed attempts."""
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
old_count = len(manifest)
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name

files = set()
for name in [
    'installed-memory-combined.patch',
    'installed-memory-combined.manifest.json',
    'installed-memory-applied.json',
    '77-corrections-applied.json',
    'assemble-installed-memory-stack.py',
    'finalize-installed-memory-stack.py',
    'archive-installed-memory.py',
]:
    files.add(source / name)
combined = json.loads((source / 'installed-memory-combined.manifest.json').read_text())
directories = {Path(package['path']).parent for package in combined['packages']}
directories.update(Path(name) for name in [
    'gate77-store-fixes', '77-server-corrections',
    '77-engine-fixture-successor', 'gate77-root-fixes',
    'server-memory-independent-review',
    'installed-memory-combined-revisions/99430178',
    'engine-fixture-callers/revisions/b9b8ad4c',
])
for directory in directories:
    assert (source / directory).is_dir(), directory
    for path in (source / directory).iterdir():
        if path.is_file() and path.suffix in {'.py', '.json', '.md', '.patch', '.txt'}:
            files.add(path)

attempts = []
for number in range(77, 87):
    receipt = source / f'{number}-result.json'
    if not receipt.exists():
        continue
    record = json.loads(receipt.read_text())
    assert record['drained'], receipt
    assert record['cwd'] == str(root), receipt
    attempts.append(number)
    for path in source.glob(f'{number}-*'):
        if path.is_file():
            files.add(path)
    files.add(source / f'run{number}.py')

for path in sorted(files):
    assert path.is_file(), path
    relative = path.relative_to(source)
    name = str(relative)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    target = destination / relative
    if target.exists():
        assert target.read_bytes() == data, name
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if name in manifest:
        assert manifest[name] == digest, name
    else:
        manifest[name] = digest

manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + '\n')
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name
print(json.dumps({'previous_entries_verified': old_count, 'entries_verified': len(manifest),
                  'completed_attempts_archived': attempts, 'source_artifacts_copied': len(files)}))
