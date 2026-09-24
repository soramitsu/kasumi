"""Append reviewed proposals and completed development diagnostics, preserving failures."""
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
files = {Path(__file__).resolve(), source / 'observe98-schema.py',
         source / '102-corrections-applied.json', source / '102-reviewed-successors-applied.json'}
omitted = []
packages = [
    '88-engine-causal-fixtures', 'authority-unknown-diagnostic',
    '97-replication-close-fixture', '97-replication-close-fixture-authority-review',
    'disk-memory-lease-retirement', 'disk-memory-lease-retirement-authority-review',
    'snapshot-accounting-successor', 'snapshot-work-foundation-revision4',
    'snapshot-work-foundation-revision4-authority-review',
    'snapshot-work-foundation-revision5', 'snapshot-work-foundation-revision5-root-review',
]
for name in packages:
    for path in (source / name).rglob('*'):
        if not path.is_file() or '__pycache__' in path.parts:
            continue
        assert not path.is_symlink(), path
        data = path.read_bytes()
        if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x7fELF', b'\xca\xfe\xba\xbe'):
            omitted.append({'path': str(path.relative_to(source)), 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest(),
                            'reason': 'Native development probe executable retained under target; documentation archive retains sources, receipts and executable digest only.'})
        else:
            files.add(path)
omissions = source / 'terminal-successors-probe-binary-omissions.json'
data = (json.dumps(omitted, indent=2) + '\n').encode()
if omissions.exists():
    assert omissions.read_bytes() == data
else:
    omissions.write_bytes(data)
files.add(omissions)
attempts = []
for number in range(100, 107):
    receipt = source / f'{number}-result.json'
    if not receipt.exists():
        continue
    record = json.loads(receipt.read_text())
    assert record['drained'] and record['cwd'] == str(root), receipt
    attempts.append(number)
    files.add(source / f'run{number}.py')
    files.update(path for path in source.glob(f'{number}-*') if path.is_file())
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
                  'completed_attempts_archived': attempts, 'source_artifacts_copied': len(files),
                  'probe_binaries_retained_only_in_target': len(omitted)}))
