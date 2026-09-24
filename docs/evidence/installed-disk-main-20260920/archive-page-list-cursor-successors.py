"""Append frozen prerequisites and only terminal 125--134 evidence, without rewriting history.

Native executables/dependencies remain in target or their original toolchain.
Their exact hashes and inventories are preserved. No Rust program is invoked.
Rerunning appends newly terminal attempts; live logs/inventories are never selected.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess


ROOT = Path('/Users/mtakemiya/dev/kasumi')
SOURCE = ROOT / 'target/installed-disk-validation'
DESTINATION = ROOT / 'docs/evidence/installed-disk-main-20260920'
MANIFEST = DESTINATION / 'raw-sha256.json'
PINS = {
    '116-stopped-epoch-exact-drain-diagnostics/manifest.json': '0e30b8a5982afe30c7f63313ae22c9da7a78285f1fb87e8225744c39f8a5d2c4',
    '116-stopped-epoch-exact-drain-root-review/receipt.json': 'be8da8b0a7da640ead838ea52d3fcba2ab8594e317ca05049d76ae99ea92b449',
    'redb-page-list-prerequisites/manifest.json': 'e429fcbf0d1dfec0980bbfaafa2b537a3f58ba57e584ff309b485db8228acc95',
    'redb-page-list-key-copy-followup/manifest.json': 'c38e85f78c447e6e1dbb507bb263d18f22818ea340030d332d883f6479b2bf7c',
    '126-page-list-compile-corrections/manifest.json': 'e325d9e2b7d92c9df38cd86de243ae42d45ce4069e399afa8e47926418e06c77',
    'redb-page-list-prerequisites-root-review/review.md': '68ee42ae1fbaf7c537cc39b28fceae66e5098caef29f79d36fe2b417d3adfb03',
    'redb-page-list-prerequisites-authority-review/receipt.json': '798af5730dd6295b61bdf2b264a36fbbcbc82c99459dd96762c720b8316b2291',
    '124-bootstrap-vote-diagnostics/manifest.json': 'ac78fd1f0407c9f9da67b30407f377b924269cdd9701796c4dafb07ddaf6bc86',
    '124-bootstrap-vote-root-review/receipt.json': 'fa3be7b87faf07777d66b4ec36751f71dfd2d38b7998a912da4f8b7b39cdc257',
    '124-recovery-observation-current-leader/manifest.json': 'b0ee34b84f87f2a14c45344cccc77552c8e29cdc38f9754ca411ac16b2ecce8e',
    '124-recovery-observation-independent-review/receipt.json': '45a5037b9e9c9d780e9aa60f82c5715c07e7932fe4c090e6390bbe4a31e09751',
    '125-stopped-epoch-bounded-resolution/manifest.json': '5f5e58b7662368c52581fdf251d016e8d7ceaa374e2ec221b1e658411aa08a33',
    '125-stopped-epoch-root-review/review.md': '7db97e16c996b44ca43518e83e6ce992697ccbccd7680d488cb3f4549f786d88',
    'directory-cursor/manifest.json': 'ac89bc7f26311438bca9ef018533f9fdc1a3cfb92cc904ebef543905666075d0',
    'directory-cursor-independent-review/receipt.json': '3c97fe7f03b0949c005e86987e7715e4f90f5af4197c2e6a89ff2066a9a553ca',
}
BINARY_SUFFIXES = {'.rlib', '.rmeta', '.dylib', '.so', '.a', '.o', '.dll', '.exe'}
NATIVE_MAGIC = {
    b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce',
    b'\x7fELF', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf',
}


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def safe_relative(name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, name)
    return path


def verify_archive(manifest):
    for name, expected in manifest.items():
        path = DESTINATION / safe_relative(name)
        require(not path.is_symlink(), path)
        require(digest(path) == expected, f'Archive hash differs: {name}')


def create_only(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(data)
    except FileExistsError:
        require(not path.is_symlink() and path.read_bytes() == data,
                f'Existing evidence differs: {path}')


def main():
    require(subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT,
                                    text=True).strip() == 'master', 'master required')
    old_bytes = MANIFEST.read_bytes()
    old = json.loads(old_bytes)
    verify_archive(old)
    files = {Path(__file__).resolve()}
    for relative, expected in PINS.items():
        control = SOURCE / relative
        require(digest(control) == expected, f'Frozen package differs: {relative}')
        files.update(p for p in control.parent.rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts)

    # Verify every cursor raw entry, including binary bytes that will be omitted.
    cursor = SOURCE / 'directory-cursor'
    require(digest(cursor / 'raw-sha256.json') ==
            'a7eea6a02bdeb775b23ef96a0bcfeff0c77071bea36259b80110447cc22e39c5',
            'Frozen cursor inventory differs')
    cursor_raw = json.loads((cursor / 'raw-sha256.json').read_text())
    for name, record in cursor_raw.items():
        path = cursor / safe_relative(name)
        require(not path.is_symlink() and path.stat().st_size == record['bytes']
                and digest(path) == record['sha256'], f'Cursor input differs: {name}')
    require(digest(cursor / 'native-06/results.json') ==
            '4c93e85f83b01db03ab8531f72ce48d95be5e349560c43ae10ca014ec37136b2',
            'Frozen native06 result differs')

    for name in ['125-exact-drain-applied.json', '126-prerequisites-applied.json',
                 '132-compile-corrections-applied.json', '133-stopped-epoch-resolution-applied.json']:
        path = SOURCE / name
        require(path.is_file(), f'Missing frozen applied receipt: {name}')
        files.add(path)

    attempts = []
    pending = []
    for number in range(125, 135):
        receipt = SOURCE / f'{number}-result.json'
        if not receipt.exists():
            pending.append(number)
            continue
        result = json.loads(receipt.read_text())
        require(result['cwd'] == str(ROOT) and result['drained'] is True
                and isinstance(result['exit_code'], int), f'Nonterminal attempt: {number}')
        attempts.append(number)
        runner = SOURCE / f'run{number}.py'
        require(runner.is_file(), runner)
        files.add(runner)
        files.update(p for p in SOURCE.glob(f'{number}-*') if p.is_file())

    planned = {}
    omissions = []
    source_hashes = {}
    for path in sorted(files):
        require(not path.is_symlink(), path)
        relative = str(path.relative_to(SOURCE))
        safe_relative(relative)
        actual = digest(path)
        source_hashes[relative] = actual
        with path.open('rb') as stream:
            magic = stream.read(8)
        native = magic[:4] in NATIVE_MAGIC
        dependency = path.suffix in BINARY_SUFFIXES or magic == b'!<arch>\n'
        if native or dependency:
            omissions.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': actual,
                              'reason': 'Native executable/dependency bytes retained under target; exact digest archived.'})
        else:
            planned[relative] = {'source': path, 'sha256': actual}

    # These dependency/toolchain files are outside the selected frozen package.
    # Preserve their supplied inventory, without reading or copying outside it.
    native_before = json.loads((cursor / 'native-06/before.json').read_text())
    native_after = json.loads((cursor / 'native-06/after.json').read_text())
    require(native_before == native_after, 'native06 input inventories differ')
    inventory_only = []
    for name, record in sorted(native_before.items()):
        path = Path(name)
        if path.suffix in BINARY_SUFFIXES or path.name in {'rustc', 'rustfmt'}:
            inventory_only.append({'path': name, **record,
                                   'provenance': 'directory-cursor/native-06/before.json and after.json',
                                   'verification': 'Supplied immutable inventory only; external bytes not reread by archiver.'})
    omission_bytes = encoded({'selected_binary_omissions': omissions,
                              'external_inventory_only': inventory_only,
                              'policy': 'No native/dependency bytes copied; original source, failures, inventories and receipts retained.'})
    omission_id = hashlib.sha256(omission_bytes).hexdigest()[:20]
    omission_name = f'page-list-cursor-native-binary-omissions/{omission_id}.json'
    planned[omission_name] = {'data': omission_bytes,
                             'sha256': hashlib.sha256(omission_bytes).hexdigest()}

    # Preflight the entire destination before any writes; old entries are immutable.
    for name, item in planned.items():
        if name in old:
            require(old[name] == item['sha256'], f'History replacement refused: {name}')
        target = DESTINATION / safe_relative(name)
        if target.exists():
            require(not target.is_symlink() and digest(target) == item['sha256'],
                    f'Existing destination differs: {name}')
    additions = {name: item['sha256'] for name, item in planned.items() if name not in old}
    summary = {'previous_entries_verified': len(old), 'entries_verified': len(old),
               'new_entries': 0, 'completed_attempts_archived': attempts,
               'attempts_without_terminal_receipts_excluded': pending,
               'selected_native_binaries_omitted': len(omissions),
               'external_binary_inventory_only_entries': len(inventory_only)}
    if not additions:
        verify_archive(old)
        require(MANIFEST.read_bytes() == old_bytes, 'Concurrent archive change')
        print(json.dumps(summary, sort_keys=True))
        return

    batch_id = hashlib.sha256(encoded(additions)).hexdigest()[:20]
    receipt_name = f'page-list-cursor-append-receipts/{batch_id}.json'
    require(receipt_name not in old, 'Append receipt already indexed unexpectedly')
    summary.update({'entries_verified': len(old) + len(additions) + 1,
                    'new_entries': len(additions) + 1, 'append_receipt': receipt_name})
    receipt = {**summary, 'previous_raw_manifest_sha256': hashlib.sha256(old_bytes).hexdigest(),
               'preserved_old_entry_count': len(old), 'new_files': additions,
               'frozen_package_controls': PINS, 'cursor_raw_entries_verified': len(cursor_raw),
               'failure_bytes_preserved': True, 'actual_source_or_release_docs_edited': False,
               'rust_build_or_test_invoked': False}
    receipt_bytes = encoded(receipt)
    planned[receipt_name] = {'data': receipt_bytes,
                             'sha256': hashlib.sha256(receipt_bytes).hexdigest()}

    for name, item in planned.items():
        target = DESTINATION / safe_relative(name)
        if 'source' in item:
            require(digest(item['source']) == item['sha256'], f'Source changed: {name}')
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with target.open('xb') as output, item['source'].open('rb') as source:
                    shutil.copyfileobj(source, output)
            except FileExistsError:
                require(not target.is_symlink() and digest(target) == item['sha256'], target)
        else:
            create_only(target, item['data'])
        require(digest(target) == item['sha256'], f'Copy verification failed: {name}')
    require(all(digest(SOURCE / name) == expected for name, expected in source_hashes.items()),
            'Selected terminal/frozen source changed during archive')
    verify_archive(old)
    require(MANIFEST.read_bytes() == old_bytes, 'Concurrent archive change; no manifest replaced')
    updated = {**old, **{name: item['sha256'] for name, item in planned.items()}}
    require(all(updated[name] == expected for name, expected in old.items()), 'Old mapping changed')
    temporary = DESTINATION / f'.raw-sha256-{batch_id}.tmp'
    with temporary.open('xb') as stream:
        stream.write(encoded(updated))
    os.replace(temporary, MANIFEST)
    verify_archive(updated)
    require(len(updated) == summary['entries_verified'], 'Final archive count differs')
    summary['raw_manifest_sha256'] = digest(MANIFEST)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
