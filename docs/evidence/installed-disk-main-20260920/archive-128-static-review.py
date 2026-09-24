"""Append frozen run128 static evidence; preserve every old archive entry."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path('/Users/mtakemiya/dev/kasumi')
SOURCE = ROOT / 'target/installed-disk-validation'
DESTINATION = ROOT / 'docs/evidence/installed-disk-main-20260920'
MANIFEST = DESTINATION / 'raw-sha256.json'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def require(value, detail):
    if not value:
        raise RuntimeError(str(detail))


def verify(manifest):
    for name, expected in manifest.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, name)
        require(digest(DESTINATION / relative) == expected, name)


def main():
    require(subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT,
                                    text=True).strip() == 'master', 'master required')
    old_bytes = MANIFEST.read_bytes()
    old = json.loads(old_bytes)
    verify(old)
    package = SOURCE / '128-lifecycle-static-stack'
    require(digest(package / 'manifest.json') ==
            '28f63932b925f80d25dff779059007bea0c185bdce0000e563337ef124f63dbe', 'static manifest')
    frozen = json.loads((package / 'manifest.json').read_text())
    for name, expected in frozen['files'].items():
        require(digest(package / name) == expected, name)
    review = SOURCE / '128-lifecycle-static-root-review'
    require(digest(review / 'receipt.json') ==
            '2de4f180d0c4edd235bb50ce6ab26f17d7ae7b27e0ff3890723c50f9535bd7c7', 'frozen root receipt')
    receipt = json.loads((review / 'receipt.json').read_text())
    require(receipt['manifest_sha256'] == digest(package / 'manifest.json'), 'review target')
    require(receipt['review_sha256'] == digest(review / 'review.md'), 'review bytes')
    files = {Path(__file__).resolve()}
    for directory in [package, review]:
        files.update(p for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    planned = {}
    for path in sorted(files):
        require(not path.is_symlink(), path)
        data = path.read_bytes()
        require(data[:4] not in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x7fELF', b'\xca\xfe\xba\xbe'), path)
        require(path.suffix not in ('.rlib', '.rmeta', '.dylib', '.so', '.a', '.o'), path)
        name = str(path.relative_to(SOURCE))
        expected = hashlib.sha256(data).hexdigest()
        target = DESTINATION / name
        if name in old:
            require(old[name] == expected, f'History replacement refused: {name}')
        if target.exists():
            require(not target.is_symlink() and target.read_bytes() == data, target)
        planned[name] = (data, expected)
    additions = {name: expected for name, (_, expected) in planned.items() if name not in old}
    if additions:
        evidence = {
            'previous_entries_verified': len(old), 'entries_after': len(old) + len(additions) + 1,
            'previous_raw_manifest_sha256': hashlib.sha256(old_bytes).hexdigest(),
            'new_source_files': additions, 'native_binaries_copied': 0,
            'lifecycle_binary_inventory_only_sha256': frozen['before']['target/debug/deps/lifecycle-377b80b89ca111b0'],
            'old_failure_bytes_preserved': True, 'actual_source_or_release_docs_edited': False,
            'cargo_or_native_program_invoked': False,
        }
        data = (json.dumps(evidence, indent=2, sort_keys=True) + '\n').encode()
        planned['128-static-archive-receipt.json'] = (data, hashlib.sha256(data).hexdigest())
    for name, (data, expected) in planned.items():
        target = DESTINATION / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            require(not target.is_symlink() and target.read_bytes() == data, target)
        require(digest(target) == expected, target)
    verify(old)
    require(MANIFEST.read_bytes() == old_bytes, 'Concurrent archive update')
    updated = {**old, **{name: expected for name, (_, expected) in planned.items()}}
    require(all(updated[name] == expected for name, expected in old.items()), 'Old entry changed')
    if additions:
        MANIFEST.write_text(json.dumps(updated, indent=2, sort_keys=True) + '\n')
    verify(updated)
    print(json.dumps({'previous_entries_verified': len(old), 'entries_verified': len(updated),
                      'new_entries': len(updated) - len(old), 'binary_bytes_copied': 0,
                      'manifest_sha256': digest(MANIFEST)}, sort_keys=True))


if __name__ == '__main__':
    main()
