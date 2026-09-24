"""Append reviewed cache/disposal and recovery handoff evidence without rewriting history."""
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
for name, digest in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == digest, name

packages = [
    'retained-transaction-disposal-authority-review',
    'retained-transaction-disposal-revision2',
    'retained-transaction-disposal-revision2-root-review',
    '121-authority-diagnostic-cfg',
    '117-lifecycle-static-stack',
    '117-lifecycle-completion-handoff',
    '117-lifecycle-completion-handoff-root-review',
    'redb-fixed-cache-capacity',
    'redb-fixed-cache-capacity-revision2',
    'redb-fixed-cache-capacity-revision2-authority-review',
    'redb-fixed-cache-clean-close-followup',
    'redb-fixed-cache-metadata-components',
    '121-cache-root-review',
]
files = {Path(__file__).resolve()}
for name in packages:
    directory = source / name
    assert directory.is_dir(), directory
    files.update(p for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
for name in ['121-disposal-applied.json', '121-lifecycle-handoff-applied.json', '121-cache-applied.json']:
    path = source / name
    assert path.is_file(), path
    files.add(path)

attempts = []
for number in [118, 119, 121, 122, 123, 124]:
    receipt = source / f'{number}-result.json'
    if not receipt.exists():
        continue
    record = json.loads(receipt.read_text())
    assert record['drained'] and record['cwd'] == str(root), receipt
    attempts.append(number)
    files.add(source / f'run{number}.py')
    files.update(p for p in source.glob(f'{number}-*') if p.is_file())

for path in sorted(files):
    assert not path.is_symlink(), path
    relative = path.relative_to(source)
    data = path.read_bytes()
    # Native executables belong in target. All package files here are source,
    # disassembly, logs or receipts; unexpected binaries stop archival.
    assert data[:4] not in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x7fELF', b'\xca\xfe\xba\xbe'), path
    digest = hashlib.sha256(data).hexdigest()
    target = destination / relative
    if target.exists():
        assert target.read_bytes() == data, relative
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if str(relative) in manifest:
        assert manifest[str(relative)] == digest, relative
    else:
        manifest[str(relative)] = digest

manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + '\n')
for name, digest in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == digest, name
print(json.dumps({'previous_entries_verified': previous, 'entries_verified': len(manifest), 'completed_attempts_archived': attempts}))
