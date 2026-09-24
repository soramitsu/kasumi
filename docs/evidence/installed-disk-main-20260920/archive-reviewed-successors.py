"""Preserve immutable reviewed proposals, exact applications and scoped validation."""
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
files = {source / '96-corrections-applied.json', Path(__file__).resolve()}
for name in ['authority-unavailable-diagnostic', '91-target-authority-corrections',
             'reservation-cancellation-retirement', '88-contract-fixtures',
             '88-crash-private-installation', 'resident-snapshot-fixture-correction',
             '88-staged-crash-private-installation', 'repeatable-assembly-v2',
             'repeatable-assembly-v3', 'assembly-python-02',
             'snapshot-work-foundation-revision3', 'snapshot-work-independent-review',
             'snapshot-work-revision3-independent-review', 'redb-retained-terminal',
             'redb-retained-terminal-independent-review']:
    for path in (source / name).rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:
            assert not path.is_symlink(), path
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
                  'source_artifacts_copied': len(files)}))
