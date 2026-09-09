"""Read-only allowlisted extraction inside the VM; never emits private blobs."""
import hashlib
import json
from pathlib import Path
import re
import stat

ROOT = Path('/opt/kasumi-acceptance/3a8d512-small-standalone-001')
BUILD = Path('/opt/kasumi-acceptance/3a8d512-functional-arm64/run/evidence.json')
SOURCE = '3a8d5121e1ddee14ae8a6d938d12152eaa04e417'
IMAGE = 'sha256:abf802c3daf7460f7498869910288b63bf5e138efc28e3c0704bf931b99e1ed4'
RUNNER = 'd3d87af9491932a86faae1b8855c6a6c46a30caaad404fe6244f729b15488966'
DISPATCH = 'c4a1f230bdc8a83418675aa58283627b80a78bc5537480bd620a11b96987de0a'
BUILD_HASH = '41c9a17334c861ad20c560d6dd3cdd802b67bd307a1806fa1d83f9e6e5980545'


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid digest evidence')
    return value


def load(path):
    need(stat.S_ISREG(path.lstat().st_mode), 'selected evidence must be a regular file')
    with path.open('rb') as source:
        value = source.read((128 << 20) + 1)
    need(len(value) <= 128 << 20, 'selected JSON exceeds limit')
    return json.loads(value)


def owned(base, name):
    path = base / name
    need(not Path(name).is_absolute() and path.resolve().is_relative_to(base.resolve()),
         'selected evidence escaped its owned directory')
    need(not path.is_symlink(), 'selected evidence is a symlink')
    return path


def terminal(state):
    need(state.get('Status') == 'exited' and state.get('ExitCode') == 0 and state.get('Pid') == 0
         and state.get('Running') is False and state.get('Paused') is False
         and state.get('Restarting') is False and state.get('OOMKilled') is False,
         'terminal container is not successfully drained')
    return {key: state[key] for key in ('Status', 'ExitCode', 'Pid', 'Running', 'Paused', 'Restarting',
                                        'OOMKilled', 'StartedAt', 'FinishedAt')}


need(stat.S_IMODE(ROOT.stat().st_mode) == 0o700 and ROOT.stat().st_uid == 0,
     'private evidence parent permissions differ')
d = load(ROOT / 'dispatch.json')
n = load(ROOT / 'run/evidence.json')
need(d['status'] == 'passed' and d['dispatch_sha256'] == DISPATCH and d['signals'] == [],
     'dispatch identity or outcome differs')
need(d['cleanup'] == {'forced': False, 'verified': True}, 'dispatch cleanup was forced or uncertain')
need(d['create_certain'] is True and d['native_exit_code'] == 0 and d['native_oom_killed'] is False,
     'container creation or native completion differs')
need(d['plan']['image'] == IMAGE and d['plan']['commit'] == SOURCE
     and d['plan']['runner_sha256'] == RUNNER and d['plan']['build_evidence_sha256'] == BUILD_HASH,
     'dispatch plan inputs differ')
commands = d['commands']
need(all(c['process_group_drained'] is True and c.get('forced_process_stop') is False
         and c.get('drain_errors') == [] and c['exit_code'] == 0 for c in commands),
     'a dispatch subprocess was not successful and drained')
for entry in commands:
    for stream in ('stdout', 'stderr'):
        need(sha(owned(ROOT, entry[stream])) == entry[stream + '_sha256'], 'dispatch log hash differs')
need(len([c for c in commands if c['label'] == 'container-create']) == 1
     and len([c for c in commands if c['label'] == 'container-start']) == 1,
     'container mutation was retried')
inspections = {}
for label in ('container-create-inspect', 'container-terminal-inspect'):
    selected = [c for c in commands if c['label'] == label]
    need(len(selected) == 1, 'container inspection is absent or ambiguous')
    c = selected[0]
    values = load(owned(ROOT, c['stdout']))
    need(len(values) == 1, 'container inspection is ambiguous')
    value = values[0]
    need(value['Id'] == d['container_id'] and value['Image'] == IMAGE
         and value['Name'] == '/' + d['container_name']
         and value['Config']['Labels']['org.kasumi.acceptance.dispatch-owner'] == d['owner_label'],
         'archived inspection ownership differs')
    inspections[label] = value
create = inspections['container-create-inspect']
end = inspections['container-terminal-inspect']
need(create['State']['Status'] == 'created' and create['State']['Pid'] == 0,
     'container ran before its recorded creation inspection')
need(terminal(end['State']) == terminal(d['terminal_state']), 'terminal receipt differs from inspection')
host = create['HostConfig']
need(host['Init'] is True and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none'
     and host['NanoCpus'] == 2_000_000_000 and host['Memory'] == 4 << 30
     and host['MemorySwap'] == 4 << 30 and host['PidsLimit'] == 512
     and host['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,size=268435456,mode=1777'},
     'actual container isolation differs')
expected_mounts = {(str(ROOT), '/results', True),
                  ('/opt/kasumi-acceptance/3a8d512-git', '/source', False),
                  ('/opt/kasumi-acceptance/3a8d512-functional-arm64/run', '/build', False),
                  ('/opt/kasumi-acceptance/small-native-tools-84379a4/small_native_smoke.py',
                   '/tools/small_native_smoke.py', False)}
need({(m['Source'], m['Destination'], m['RW']) for m in create['Mounts'] if m['Type'] == 'bind'}
     == expected_mounts, 'actual writable input mount differs')
expected_env = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'safe.directory',
                'GIT_CONFIG_VALUE_0': '/source', 'PYTHONDONTWRITEBYTECODE': '1'}
for key, value in expected_env.items():
    need([s.split('=', 1)[1] for s in create['Config']['Env'] if s.split('=', 1)[0] == key] == [value],
         'actual container environment differs')
need(n['status'] == 'passed' and n['runner_sha256'] == RUNNER and n['source_commit'] == SOURCE
     and n['build_evidence_sha256'] == BUILD_HASH and n['build_overall_status'] == 'failed'
     and n['cleanup_errors'] == [] and d['native_evidence_sha256'] == sha(ROOT / 'run/evidence.json'),
     'native diagnostic identity or cleanup differs')
need(n['documents'] == 129 and n['canonical_bytes'] == 129 * 1024, 'native corpus size differs')
need(n['source_tree'] == d['source_tree'], 'native source tree differs')
need(n['renewal']['before_file_sha256'] != n['renewal']['after_file_sha256'], 'credential was not renewed')
need(n['recovery']['phase'] == 'finished'
     and n['recovery']['fencing_scope'] == 'exclusive_local_installation', 'local recovery scope differs')
steps = {}
safe_steps = []
for entry in n['steps']:
    name = entry['name']
    need(name not in steps, 'native step duplicated')
    steps[name] = entry
    need(entry['process_group_drained'] is True and entry['forced_stop'] is False,
         'native child failed to drain')
    if name == 'old-resource-refused':
        need(entry['status'] == 'passed_expected_authorization_rejection' and entry['exit_code'] > 0,
             'old-resource denial did not complete explicitly')
    else:
        need(entry['status'] == 'passed' and entry['exit_code'] == 0, 'native step did not pass')
    for stream in ('stdout', 'stderr'):
        need(sha(owned(ROOT / 'run', entry[stream])) == entry[stream + '_sha256'], 'native step hash differs')
    safe_steps.append({key: entry[key] for key in ('name', 'status', 'exit_code', 'process_group_drained',
                                                  'forced_stop', 'seconds', 'stdout_sha256', 'stderr_sha256')})
required = {'init', 'check-config', 'create-collection', 'load', 'renew', 'backup-create', 'backup-verify',
            'daemon-initial', 'daemon-restarted', 'daemon-restored', 'verify-renewed', 'verify-restarted',
            'restore', 'restore-status', 'verify-restored', 'old-resource-refused', 'verify-after-rejection'}
need(required <= steps.keys(), 'required native lifecycle check is absent')
safe_readiness = {}
for name in ('daemon-initial', 'daemon-restarted', 'daemon-restored'):
    observations = steps[name]['readiness']
    successful = [v for v in observations if v.get('status') == 200]
    need(len(successful) == 1 and observations[-1] == successful[0]
         and successful[0]['tls'] == 'TLSv1.3', 'protected readiness was not reached over pinned TLS')
    safe_readiness[name] = {key: successful[0][key] for key in
                           ('status', 'tls', 'certificate_sha256', 'body_sha256')}
    safe_readiness[name]['observation_count'] = len(observations)
load_path = ROOT / 'run/load/events.jsonl'
load_events = []
with load_path.open('rb') as stream:
    for line in stream:
        need(len(line) <= 2 << 20 and len(load_events) < 4096, 'load journal exceeds small diagnostic bound')
        load_events.append(json.loads(line))
need(len(load_events) >= 2 and load_events[0]['event'] == 'started'
     and load_events[0]['executable_sha256'] == n['binaries']['kasumi-bench-capacity']['sha256']
     and load_events[-1]['event'] == 'passed' and load_events[-1]['documents'] == 129
     and load_events[-1]['canonical_bytes'] == 129 * 1024
     and load_events[-1]['expected_sha256'] == load_events[-1]['observed_sha256'] == n['corpus_sha256']
     and sha(load_path) == n['artifact_inventory']['load/events.jsonl']['sha256'],
     'initial load journal or corpus binding differs')
checkpoint = load(ROOT / 'run/checkpoint.json')
need(checkpoint == load(owned(ROOT / 'run', steps['backup-verify']['stdout'])), 'backup verification changed checkpoint')
restore = load(owned(ROOT / 'run', steps['restore']['stdout']))
status = load(owned(ROOT / 'run', steps['restore-status']['stdout']))
request = load(ROOT / 'run/restore.json')
for result in (restore, status):
    need(result['phase'] == 'finished' and result['fencing_scope'] == 'exclusive_local_installation'
         and result['request'] == request and result['last_failure'] is None, 'exact local restore did not finish')
need(restore['client_profile'] == status['client_profile'], 'local restore profile publication differs')
safe_corpus = {}
for name in ('verify-renewed', 'verify-restarted', 'verify-restored', 'verify-after-rejection'):
    result = n['corpus_checks'][name]
    need(result['event'] == 'passed' and result['documents'] == 129 and result['canonical_bytes'] == 129 * 1024
         and result['expected_sha256'] == result['observed_sha256'] == n['corpus_sha256'],
         'corpus changed across lifecycle')
    safe_corpus[name] = {key: result[key] for key in ('event', 'documents', 'canonical_bytes',
                                                    'expected_sha256', 'observed_sha256')}
denial = n['corpus_checks']['old-resource-refused']
need(denial['event'] == 'failed' and denial['transport_code'] in ('Unauthenticated', 'PermissionDenied'),
     'old resource failed without explicit authorization denial')
need(len(n['mcp_checks']) == 4, 'expected original and restored MCP discovery/read checks')
safe_mcp = []
for entry in n['mcp_checks']:
    need(entry['tls'] == 'TLSv1.3' and sha(owned(ROOT / 'run', entry['file'])) == entry['sha256'],
         'MCP TLS or response binding differs')
    safe_mcp.append({key: entry[key] for key in ('file', 'sha256', 'tls', 'certificate_sha256')})
need(sha(BUILD) == BUILD_HASH, 'frozen build report changed')
b = load(BUILD)
need(b['status'] == 'failed' and b['source_commit'] == SOURCE and b['source_tree'] == n['source_tree']
     and b['lockfile_sha256'] == n['lockfile_sha256'] and b['toolchain'] == '1.97.1',
     'native build provenance differs')
safe_binaries = {}
safe_gates = {}
for name, gate_name in (('kasumid', 'production'), ('kasumictl', 'production'),
                        ('kasumi-bench-capacity', 'network-driver')):
    gates = [g for g in b['gates'] if g['name'] == gate_name]
    need(len(gates) == 1 and gates[0]['exit_code'] == 0, 'required build gate did not pass')
    gate = gates[0]
    packages = gate['compiled_packages']
    need(packages and all(not set(p['features']) & {'test-utils', 'embedded-fixture', 'loopback-fixture'}
                          for p in packages.values()), 'compiled fixture feature detected')
    artifact = [a for a in gate['executables'].values() if a['target'] == name]
    need(len(artifact) == 1 and artifact[0]['test'] is False, 'build executable is ambiguous or a fixture')
    expected = digest(artifact[0]['sha256'])
    need(n['binaries'][name]['sha256'] == d['input_binaries'][name] == expected
         and sha(ROOT / 'run/binaries' / name) == expected, 'actual copied executable differs from build')
    safe_binaries[name] = {'build_gate': gate_name, 'sha256': expected,
                           'bytes': (ROOT / 'run/binaries' / name).stat().st_size, 'test': False}
    inventory = {key: p['features'] for key, p in sorted(packages.items())}
    safe_gates[gate_name] = {'exit_code': 0, 'compiled_package_count': len(packages),
                            'fixture_features_absent': True,
                            'feature_inventory_sha256': hashlib.sha256(json.dumps(inventory,
                                sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
safe_commands = [{key: c[key] for key in ('label', 'exit_code', 'process_group_drained',
                                         'forced_process_stop', 'stdout_sha256', 'stderr_sha256')}
                 for c in commands]
result = {
    'schema': 1, 'release_acceptance': False, 'original_functional_status': 'failed',
    'scope': '129 documents of 1024 canonical bytes; offline standalone diagnostic of frozen 3a8d512',
    'privacy': 'Allowlisted metadata and hashes only. No keys, tokens, configs, raw logs or inspections exported.',
    'source': {'commit': SOURCE, 'tree': n['source_tree'], 'lockfile_sha256': digest(n['lockfile_sha256']),
               'toolchain': '1.97.1', 'build_evidence_sha256': BUILD_HASH},
    'runners': {'dispatch_sha256': DISPATCH, 'native_sha256': RUNNER},
    'private_evidence_hashes': {'dispatch_json': sha(ROOT / 'dispatch.json'),
                               'native_evidence_json': sha(ROOT / 'run/evidence.json'),
                               'checkpoint_json': sha(ROOT / 'run/checkpoint.json')},
    'dispatch': {'status': d['status'], 'started_at': d['started_at'], 'finished_at': d['finished_at'],
                 'elapsed_seconds': d['elapsed_seconds'], 'cleanup_verified': True, 'forced_stop': False,
                 'container_id': d['container_id'], 'image': IMAGE, 'terminal_state': terminal(end['State']),
                 'preserved_container_ids': d['preserved_container_ids'], 'create_count': 1, 'start_count': 1,
                 'commands': safe_commands},
    'isolation': {'network': 'none', 'init': True, 'read_only_root': True, 'cpus': 2,
                  'memory_bytes': 4 << 30, 'memory_swap_bytes': 4 << 30, 'tmpfs_tmp_bytes': 256 << 20,
                  'pids_limit': 512, 'only_host_writable_mount': '/results',
                  'readonly_mounts': ['/source', '/build', '/tools/small_native_smoke.py'],
                  'verified_environment': expected_env, 'private_parent_mode': '0700', 'private_parent_uid': 0},
    'build_gates': safe_gates, 'executables': safe_binaries,
    'native': {'status': n['status'], 'started_at': n['started_at'], 'finished_at': n['finished_at'],
               'timeouts_seconds': n['timeouts_seconds'], 'documents': n['documents'],
               'canonical_bytes': n['canonical_bytes'], 'corpus_sha256': digest(n['corpus_sha256']),
               'steps': safe_steps, 'corpus_checks': safe_corpus, 'mcp_checks': safe_mcp,
               'protected_readiness': safe_readiness,
               'initial_load_journal_sha256': sha(load_path), 'initial_load_full_corpus_verified': True,
               'renewed_credential_file_changed': True, 'backup_exact_checkpoint_verified': True,
               'local_recovery_exact_request_and_profile_verified': True,
               'local_recovery_phase': 'finished', 'fencing_scope': 'exclusive_local_installation',
               'old_resource_explicit_denial': denial['transport_code'], 'cleanup_error_count': 0},
}
print(json.dumps(result, indent=2, sort_keys=True))
