from pathlib import Path
import difflib, hashlib, json, ast
root=Path.cwd();folder=root/'target/installed-disk-validation/assembly-metadata-custody'
names=['scripts/gate_process.py','scripts/release_gate.py','scripts/test_release_gate.py','scripts/package_release.py']
for name in names:
    for layer in ('before','proposed'):
        dst=folder/layer/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((root/name).read_bytes())
p=folder/'proposed/scripts/gate_process.py';s=p.read_text()
s=s.replace('def run(command, source, environment, stream, timeout_seconds, observe):','def run(command, source, environment, stream, timeout_seconds, observe, *, stderr):')
s=s.replace('stdout=stream, stderr=subprocess.STDOUT,','stdout=stream, stderr=stderr,')
s=s.replace('''            os.fsync(stream.fileno())
            observe(record)
''','''            os.fsync(stream.fileno())
            if stderr != subprocess.STDOUT:
                stderr.flush()
                os.fsync(stderr.fileno())
            observe(record)
''')
p.write_text(s)
p=folder/'proposed/scripts/release_gate.py';s=p.read_text();old='''                                       lambda value: write_json(process_path, value))''';assert old in s;s=s.replace(old,'''                                       lambda value: write_json(process_path, value),
                                       stderr=subprocess.STDOUT)''');p.write_text(s)
p=folder/'proposed/scripts/test_release_gate.py';s=p.read_text();old='''lambda value: observations.append(dict(value)))'''
# Preserve the existing test's exact observer; this argument is the sole direct call.
start=s.index('result = release_gate.gate_process.run(');end=s.index('\n',s.index('observ',start)) if False else start
print(s[start:start+420])
p.write_text(s)
p=folder/'proposed/scripts/package_release.py';s=p.read_text()
s=s.replace('import subprocess\n', '').replace('import tomllib\n','import tomllib\n\nimport gate_process\n')
old='''def build_inventory(source, output, record, production, target, epoch):
    """Map Cargo-reported compiled packages to exact locked crate sources."""
    command = ["cargo", "+" + TOOLCHAIN, "metadata", "--locked", "--format-version", "1",
               "--no-default-features", "--filter-platform", target]
    metadata = json.loads(subprocess.check_output(command, cwd=source))
'''
new='''def build_inventory(source, output, record, production, target, epoch):
    """Map Cargo-reported compiled packages to exact locked crate sources."""
    metadata = capture_metadata(source, output.parent / "metadata-custody", target,
                                json.loads((source.parent / "source-files.json").read_text()))
'''
assert old in s;s=s.replace(old,new)
# Add trusted process helper before build_inventory, keeping all readers in one source module.
marker='def build_inventory(source, output, record, production, target, epoch):'
s=s.replace(marker,(folder/'metadata-code.txt').read_text()+'\n\n'+marker) if (folder/'metadata-code.txt').exists() else s
p.write_text(s)
# Migrate the actual direct caller and record the observed working directory.
p=folder/'proposed/scripts/test_release_gate.py';s=p.read_text().replace('import sys\n', 'import sys\nimport subprocess\n');old='os.environ.copy(), stream, .05, observe)';assert old in s;s=s.replace(old,'os.environ.copy(), stream, .05, observe,\n                                                       stderr=subprocess.STDOUT)');p.write_text(s)
p=folder/'proposed/scripts/gate_process.py';s=p.read_text();s=s.replace('''    received = []
''','''    if stderr != subprocess.STDOUT and (not hasattr(stderr, "fileno") or not hasattr(stderr, "flush")):
        raise ValueError("gate stderr requires an explicit owned file or STDOUT")
    received = []
''',1)
s=s.replace('''    record = {"status": "running", "command": command, "timeout_seconds": timeout_seconds,
''','''    record = {"status": "running", "command": command, "timeout_seconds": timeout_seconds,
              "working_directory": str(Path(source).resolve(strict=True)),
''');p.write_text(s)
# Python syntax inspection only. No imports, tests, subprocesses or workloads.
for name in names:
    ast.parse((folder/'proposed'/name).read_text(),filename=name)
print('Prepared Python sources parse; no tests executed.')
new='scripts/test_package_metadata.py';names.append(new)
p=folder/'proposed'/new;p.write_text((folder/'test-code.txt').read_text());ast.parse(p.read_text(),filename=new)
patch=[];manifest=[]
for name in names:
    old=(folder/'before'/name).read_bytes() if (folder/'before'/name).exists() else b''
    new=(folder/'proposed'/name).read_bytes()
    patch.extend(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))
    manifest.append({'path':name,'before_sha256':hashlib.sha256(old).hexdigest() if old else None,'proposed_sha256':hashlib.sha256(new).hexdigest()})
(folder/'metadata.patch').write_text(''.join(patch))
receipt={'status':'target_only_static_syntax_inspected_unexecuted_tests','patch_sha256':hashlib.sha256((folder/'metadata.patch').read_bytes()).hexdigest(),'files':manifest}
(folder/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
