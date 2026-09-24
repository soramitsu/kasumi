"""Freeze completed storage composition and file-custody packages for append-only evidence."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path('/Users/mtakemiya/dev/kasumi')
SOURCE = ROOT / 'target/installed-disk-validation'
OUTPUT = SOURCE / 'storage-composition-archive'
PACKAGE_ROOTS = [
    'storage-and-namespace-integration',
    *[f'storage-and-namespace-integration-revision{n}' for n in range(2, 7)],
    'storage-and-namespace-overlap-independent-review',
    'file-owner-custody-revision1',
    'file-owner-custody-independent-review',
    'redb-page-number-freeze05-managed-review',
]
SKIP_DIRS = {'assembly', 'cargo-target'}
CONTROLS = [
    'storage-and-namespace-integration-revision6/qualification-receipt.json',
    'storage-and-namespace-integration-revision6/native-full-store/conservative-terminal-acceptance.json',
    'file-owner-custody-revision1/candidate-04/qualification-receipt.json',
    'file-owner-custody-revision1/candidate-04/native-01/terminal-drain.json',
    'file-owner-custody-independent-review/candidate04-fixture-native-review.json',
    'redb-page-number-freeze05-managed-review/receipt.json',
]


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def main():
    assert subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip() == 'master'
    files = set()
    for name in PACKAGE_ROOTS:
        package = SOURCE / name
        assert package.is_dir() and not package.is_symlink(), package
        for path in package.rglob('*'):
            relative = path.relative_to(package)
            if SKIP_DIRS.intersection(relative.parts):
                continue
            if path.is_symlink():
                raise RuntimeError(f'Symlink in selected package: {path}')
            if path.is_file():
                files.add(path)
    files.add(Path(__file__).resolve())
    assert all(path.resolve().is_relative_to(SOURCE) for path in files)
    controls = {name: digest(SOURCE / name) for name in CONTROLS}
    selected = {str(path.relative_to(SOURCE)): {'sha256': digest(path), 'bytes': path.stat().st_size}
                for path in sorted(files)}
    output = {'package_roots': PACKAGE_ROOTS, 'controls': controls, 'terminal_runs': {},
              'candidate_terminal_runs': {}, 'files': selected,
              'selection_policy': 'Frozen package source, readback, receipt and original native transcript files. Cargo assembly and target caches excluded. Native executable bytes hashed but not copied. No release qualification inferred.'}
    OUTPUT.mkdir(exist_ok=False)
    path = OUTPUT / 'inputs.json'
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'files': len(files), 'input_sha256': digest(path),
                      'input_bytes': path.stat().st_size, 'controls': controls}, sort_keys=True))


if __name__ == '__main__':
    main()
