#!/usr/bin/env python3
"""Owned Linux/Docker verification. Requires root, systemd delegation, and ext4.

No existing daemon, container, mount, target, or image store is reused. This
runner never deletes its loop image; it preserves successes and failures alike.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import uuid

from gate_process import drain, group_members, run
from outer_guards import (DEADLINES, DISK, LABEL, MEMORY, atomic_json, check_container,
                          check_loop, check_owner, digest, extract_archive, identity,
                          need, private_directory)
from prepare import LOCKS, source_inventory

ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
SIGNALS = []


def query(arguments, timeout=15):
    return subprocess.check_output(arguments, text=True, env=ENV, timeout=timeout).strip()


def call(arguments, timeout=30):
    subprocess.run(arguments, env=ENV, timeout=timeout, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def properties(unit):
    names = ['LoadState', 'Id', 'MainPID', 'ControlGroup', 'MemoryMax', 'MemorySwapMax', 'Delegate',
             'InvocationID', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus']
    inspected = subprocess.run(['systemctl', 'show', unit, '--property=' + ','.join(names)],
                               text=True, env=ENV, timeout=15, capture_output=True)
    text = inspected.stdout
    result = {}
    for line in text.splitlines():
        key, value = line.split('=', 1)
        need(key not in result, 'duplicate unit property')
        result[key] = value
    need(inspected.returncode == 0 or (inspected.returncode == 1
         and result.get('LoadState') == 'not-found' and result.get('Id') == unit),
         'systemd unit inspection failed: ' + inspected.stderr)
    return result


def cgroup_members(root):
    if not root.exists():
        return []
    result = set()
    for current, _, files in os.walk(root, onerror=lambda error: (_ for _ in ()).throw(error)):
        if 'cgroup.procs' in files:
            result.update(int(pid) for pid in (Path(current) / 'cgroup.procs').read_text().split())
    return sorted(result)


def memory_sample(root):
    return {name: (root / name).read_text() for name in
            ('memory.current', 'memory.peak', 'memory.events', 'memory.stat', 'pids.current')}


def process_identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': int(fields[19]), 'group': int(fields[2])}


class Owner:
    def __init__(self, directory):
        self.directory = private_directory(directory)
        self.owner = json.loads((self.directory / 'owner.json').read_text())
        check_owner(self.owner, self.directory)
        self.state = {'schema': 1, 'owner': self.owner, 'status': 'running', 'phase': 'initial',
                      'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'started_utc_epoch': time.time(), 'started_monotonic': time.monotonic(),
                      'gates': {}, 'cleanup': {}, 'errors': []}
        self.mount = self.directory / 'filesystem'
        self.image = self.directory / 'disk.ext4'
        self.cg = None
        self.daemon = None
        self.daemon_log = None
        self.current = None
        need(not (self.directory / 'status.json').exists(), 'run already attempted; use recover for cleanup only')
        self.saved()

    def saved(self):
        atomic_json(self.directory / 'status.json', self.state)

    def intent(self, phase):
        self.state['phase'] = phase
        self.saved()
        need(not SIGNALS, 'verification interrupted')

    def docker(self, *arguments):
        return ['docker', '--host', 'unix://' + str(self.mount / 'run/docker.sock'),
                '--config', str(self.mount / 'client'), *arguments]

    def inspect_container(self, name):
        values = json.loads(query(self.docker('inspect', name)))
        need(len(values) == 1, 'container inspection ambiguous')
        check_container(values[0], self.owner, name, self.state['prepared_image'],
                        self.mounts(), '/' + str(self.cg.relative_to('/sys/fs/cgroup') / 'containers'))
        return values[0]

    def mounts(self):
        return [(str(self.mount / source), target) for source, target in
                [('work', '/work'), ('target', '/target'), ('target-fuzz', '/target-fuzz'),
                 ('corpus', '/workspace/fuzz/corpus'), ('artifacts', '/workspace/fuzz/artifacts'),
                 ('tmp', '/tmp'), ('work/db.lock', '/opt/verification/advisory-db/db.lock')]]

    def arm_deadline(self, seconds):
        # RuntimeMaxSec is relative to the original service start. The kernel/
        # systemd boundary covers hashing, blocking preparation, and cleanup even
        # if the Python observer cannot regain control.
        elapsed = time.monotonic() - self.state['started_monotonic']
        total = max(1, int(elapsed + seconds))
        call(['systemctl', 'set-property', '--runtime', self.owner['unit'],
              'RuntimeMaxSec=' + str(total)], timeout=10)

    def initialize_cgroup(self):
        unit = properties(self.owner['unit'])
        need(unit['Id'] == self.owner['unit'] and int(unit['MainPID']) == os.getpid(),
             'runner is not the declared systemd owner')
        need(unit['Delegate'] == 'yes' and int(unit['MemoryMax']) == MEMORY
             and unit['MemorySwapMax'] == '0', 'delegated memory boundary differs')
        location = query(['cat', '/proc/self/cgroup'])
        need(location == '0::' + unit['ControlGroup'], 'unexpected current cgroup')
        self.cg = Path('/sys/fs/cgroup') / unit['ControlGroup'].lstrip('/')
        need(self.cg.is_dir() and self.cg.name == self.owner['unit'], 'unit cgroup identity differs')
        self.state['unit'] = unit
        self.state['cgroup'] = str(self.cg)
        self.saved()
        controller = self.cg / 'supervisor'
        controller.mkdir()
        (controller / 'cgroup.procs').write_text(str(os.getpid()))
        need(not (self.cg / 'cgroup.procs').read_text().strip(), 'undeclared unit root process')
        available = set((self.cg / 'cgroup.controllers').read_text().split())
        need({'memory', 'pids', 'cpu'} <= available, 'required cgroup controllers unavailable')
        (self.cg / 'cgroup.subtree_control').write_text('+memory +pids +cpu')
        (self.cg / 'daemon').mkdir()
        (self.cg / 'containers').mkdir()
        import shutil
        host_tools = {}
        for name in ('docker', 'dockerd', 'systemctl', 'systemd-run', 'losetup', 'mkfs.ext4',
                     'mount', 'umount', 'findmnt', 'git', 'sync'):
            path = shutil.which(name, path=ENV['PATH'])
            need(path is not None, 'required host tool absent: ' + name)
            host_tools[name] = {'path': str(Path(path).resolve()), 'sha256': digest(path)}
        host_tools['python'] = {'path': sys.executable, 'sha256': digest(sys.executable)}
        self.state['host_tools'] = host_tools
        self.state['host_uname'] = list(os.uname())
        self.state['host_os_release'] = Path('/etc/os-release').read_text()
        self.state['initial_memory'] = memory_sample(self.cg)
        self.saved()

    def loop(self):
        listing = json.loads(query(['losetup', '--json', '--list', '--output',
                                    'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,SIZELIMIT,OFFSET',
                                    self.state['loop_device']]))['loopdevices']
        need(len(listing) == 1, 'loop inspection ambiguous')
        check_loop(listing[0], self.image, self.state['image_identity'])
        need(listing[0]['name'] == self.state['loop_device'], 'loop device changed')
        return listing[0]

    def mounted(self):
        self.loop()
        values = json.loads(query(['findmnt', '--json', '--mountpoint', str(self.mount),
                                   '--output', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS']))['filesystems']
        need(len(values) == 1, 'mount inspection ambiguous')
        value = values[0]
        need(value['target'] == str(self.mount) and value['source'] == self.state['loop_device']
             and value['fstype'] == 'ext4' and value['uuid'] == self.owner['run_id'],
             'mount identity differs')
        options = set(value['options'].split(','))
        need({'nodev', 'nosuid', 'rw'} <= options, 'mount protection differs')
        return value

    def storage(self):
        self.intent('allocate-private-disk')
        fd = os.open(self.image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.posix_fallocate(fd, 0, DISK)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.state['image_identity'] = identity(self.image)
        self.intent('attach-private-loop')
        device = query(['losetup', '--find', '--show', '--nooverlap', str(self.image)])
        self.state['loop_device'] = device
        self.saved()
        self.loop()
        self.intent('format-private-loop')
        call(['mkfs.ext4', '-F', '-m', '0', '-U', self.owner['run_id'], device], timeout=180)
        self.loop()
        self.mount.mkdir(mode=0o700)
        self.intent('mount-private-loop')
        call(['mount', '--types', 'ext4', '--options', 'nodev,nosuid', device, str(self.mount)])
        self.state['mount'] = self.mounted()
        for name in ('run', 'client', 'work', 'target', 'target-fuzz', 'corpus', 'artifacts', 'tmp', 'logs'):
            (self.mount / name).mkdir(mode=0o700)
        (self.mount / 'work/tmp').mkdir(mode=0o700)
        ENV['TMPDIR'] = str(self.mount / 'tmp')
        self.saved()

    def command(self, name, command, deadline, environment=None):
        self.intent(name)
        log = self.mount / 'logs' / (name + '.log')
        started = time.time()
        samples = self.mount / 'logs' / (name + '.resources.jsonl')
        last = [0.0]

        def observe(record):
            self.state['gates'][name] = record
            self.saved()
            now = time.monotonic()
            if self.cg and now - last[0] > 1:
                last[0] = now
                metrics = {'utc_epoch': time.time(), 'monotonic': now,
                           'memory': memory_sample(self.cg),
                           'filesystem': dict(zip(('block_size', 'blocks', 'free_blocks'),
                               (os.statvfs(self.mount).f_frsize, os.statvfs(self.mount).f_blocks,
                                os.statvfs(self.mount).f_bfree)))}
                with samples.open('a') as output:
                    output.write(json.dumps(metrics) + '\n')
        with log.open('x') as stream:
            result = run(command, self.directory, environment or ENV, stream, deadline, observe)
        result.update(raw_log_sha256=digest(log), started_utc_epoch=started, finished_utc_epoch=time.time())
        self.state['gates'][name] = result
        self.saved()
        return result

    def source(self):
        source = self.owner['source']
        need(query(['git', '-C', source, 'rev-parse', 'HEAD']) == self.owner['commit'],
             'source checkout differs from exact commit')
        need(not query(['git', '-C', source, 'status', '--porcelain', '--untracked-files=all']),
             'source checkout has uncommitted state')
        archive = self.mount / 'source.tar'
        call(['git', '-C', source, 'archive', '--format=tar', '--output', str(archive),
              self.owner['commit']], timeout=60)
        need(digest(archive) == self.owner['archive_sha256'], 'source archive digest differs')
        context = self.mount / 'context'
        extract_archive(archive, context)
        before = source_inventory(context, LOCKS)
        (self.mount / 'work/source-inputs.expected.json').write_text(json.dumps(before) + '\n')
        self.state['source_tree'] = query(['git', '-C', source, 'rev-parse', 'HEAD^{tree}'])
        self.state['locks'] = LOCKS
        self.state['harness_sha256'] = digest(__file__)
        self.saved()

    def start_daemon(self):
        self.intent('start-private-daemon')
        config = {
            'data-root': str(self.mount / 'docker'), 'exec-root': str(self.mount / 'run/docker'),
            'pidfile': str(self.mount / 'run/docker.pid'),
            'hosts': ['unix://' + str(self.mount / 'run/docker.sock')],
            'storage-driver': 'overlay2', 'features': {'containerd-snapshotter': False},
            'bridge': 'none', 'iptables': False, 'ip6tables': False, 'ip-forward': False,
            'ip-masq': False, 'userland-proxy': False, 'live-restore': False,
            'exec-opts': ['native.cgroupdriver=cgroupfs'],
            'cgroup-parent': str(self.cg.relative_to('/sys/fs/cgroup') / 'containers'),
            'log-driver': 'local', 'log-opts': {'max-size': '8m', 'max-file': '2'},
            'max-concurrent-downloads': 1, 'max-concurrent-uploads': 1,
        }
        config['cgroup-parent'] = '/' + config['cgroup-parent']
        path = self.mount / 'daemon.json'
        atomic_json(path, config)
        self.daemon_log = (self.mount / 'logs/daemon.log').open('x')
        environment = dict(ENV, DOCKER_TMPDIR=str(self.mount / 'tmp'), TMPDIR=str(self.mount / 'tmp'))
        self.daemon = subprocess.Popen(['dockerd', '--config-file', str(path)], env=environment,
                                       cwd=self.directory, stdout=self.daemon_log,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=lambda: (self.cg / 'daemon/cgroup.procs').write_text(str(os.getpid())))
        self.state['daemon_process'] = process_identity(self.daemon.pid)
        self.saved()
        until = time.monotonic() + 60
        while time.monotonic() < until:
            need(not SIGNALS and self.daemon.poll() is None, 'private daemon stopped or interrupted')
            try:
                info = json.loads(query(self.docker('info', '--format', '{{json .}}'), timeout=2))
                need(info['DockerRootDir'] == str(self.mount / 'docker') and info['CgroupDriver'] == 'cgroupfs',
                     'private daemon configuration differs')
                self.state['docker_info'] = info
                self.saved()
                return
            except subprocess.CalledProcessError:
                time.sleep(.2)
        raise RuntimeError('private daemon readiness deadline exceeded')

    def prepare(self):
        started = time.monotonic()
        self.storage()
        self.source()
        self.start_daemon()
        remaining = DEADLINES['prepare'] - (time.monotonic() - started)
        need(remaining > 0, 'preparation deadline exceeded before build')
        iid = self.mount / 'prepared-image-id'
        result = self.command('prepare', self.docker('build', '--network=host', '--no-cache',
                              '--cgroup-parent', '/' + str(self.cg.relative_to('/sys/fs/cgroup') / 'containers'),
                              '--iidfile', str(iid), '-f', str(self.mount / 'context/verification/Containerfile'),
                              str(self.mount / 'context')), remaining,
                              dict(ENV, DOCKER_BUILDKIT='1'))
        need(result['status'] == 'passed', 'preparation failed')
        image = iid.read_text().strip()
        need(len(image) == 71 and image.startswith('sha256:'), 'immutable image ID absent')
        manifest = json.loads(query(self.docker('image', 'inspect', image)))
        need(len(manifest) == 1 and manifest[0]['Id'] == image, 'prepared image identity differs')
        need(cgroup_members(self.cg / 'containers') == [], 'preparation descendants remain')
        self.state['prepared_image'] = image
        self.state['prepared_image_inspect'] = manifest[0]
        self.saved()

    def stop_container(self, name):
        info = self.inspect_container(name)
        cid = info['Id']
        if info['State']['Running']:
            call(self.docker('stop', '--time', '10', cid), timeout=20)
        info = self.inspect_container(name)
        need(info['Id'] == cid and not info['State']['Running'] and not info['State']['Paused'],
             'owned container did not stop')
        need(info['State']['Pid'] == 0, 'container still owns a live process')
        # Container cgroups may disappear; the entire delegated container parent
        # must also be empty, independent of Docker's reported terminal state.
        need(cgroup_members(self.cg / 'containers') == [], 'container descendants remain')
        return info

    def gate(self, phase):
        started = time.monotonic()
        self.arm_deadline(DEADLINES[phase])
        self.intent('create-' + phase)
        name = 'redb-' + self.owner['run_id'] + '-' + phase
        lock = self.mount / 'work/db.lock'
        if not lock.exists():
            lock.touch(mode=0o600, exist_ok=False)
        self.state['current_container_intent'] = name
        self.saved()
        args = self.docker('create', '--name', name, '--label', LABEL + '=' + self.owner['run_id'],
                           '--network=none', '--read-only', '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--memory', str(MEMORY),
                           '--memory-swap', str(MEMORY), '--pids-limit=1024', '--init',
                           '--cgroup-parent', '/' + str(self.cg.relative_to('/sys/fs/cgroup') / 'containers'))
        for source, target in self.mounts():
            args += ['--mount', f'type=bind,src={source},dst={target}']
        args += [self.state['prepared_image'], 'python3', 'verification/execute_inside.py', phase]
        query(args, timeout=30)
        info = self.inspect_container(name)
        self.current = name
        self.state['current_container'] = {'name': name, 'id': info['Id']}
        self.saved()
        remaining = DEADLINES[phase] - (time.monotonic() - started)
        need(remaining > 0, 'gate deadline exceeded before start')
        result = self.command(phase, self.docker('start', '--attach', info['Id']), remaining)
        terminal = self.stop_container(name)
        result['container_terminal'] = terminal
        self.state['gates'][phase] = result
        self.current = None
        self.saved()
        need(result['status'] == 'passed' and terminal['State']['ExitCode'] == 0
             and not terminal['State']['OOMKilled'], 'container gate failed')
        inner = self.mount / 'work/evidence' / (phase + '.json')
        outcome = json.loads(inner.read_text())
        need(outcome['status'] == 'passed', 'inner gate did not prove success')
        result['inner_sha256'] = digest(inner)
        self.saved()

    def cleanup(self):
        errors = []
        try:
            # Resolve an uncertain create by its original unique name and label;
            # never create a substitute container or infer absence from timeout.
            name = self.state.get('current_container_intent')
            if name and 'prepared_image' in self.state:
                ids = query(self.docker('ps', '-aq', '--no-trunc', '--filter',
                                       'label=' + LABEL + '=' + self.owner['run_id'])).splitlines()
                for cid in ids:
                    info = json.loads(query(self.docker('inspect', cid)))[0]
                    owned_name = info['Name'].removeprefix('/')
                    need(owned_name.startswith('redb-' + self.owner['run_id'] + '-'),
                         'unexpected container under owned daemon')
                    self.stop_container(owned_name)
        except BaseException as error:
            errors.append('container drain: ' + repr(error))
        if self.daemon is not None:
            try:
                self.state['cleanup']['daemon_process_group'] = drain(self.daemon)
                # A managed containerd/shim can leave the daemon's process group.
                # The private delegated subtree owns those descendants too.
                for name in ('containers', 'daemon'):
                    root = self.cg / name
                    if cgroup_members(root):
                        (root / 'cgroup.kill').write_text('1')
                    until = time.monotonic() + 10
                    while cgroup_members(root) and time.monotonic() < until:
                        time.sleep(.05)
                    need(cgroup_members(root) == [], 'owned descendant cgroup did not drain')
                need(group_members(self.daemon.pid) == [], 'daemon process group did not drain')
                self.state['cleanup']['descendants_drained'] = True
            except BaseException as error:
                errors.append('daemon drain: ' + repr(error))
        if self.daemon_log is not None:
            self.daemon_log.flush()
            os.fsync(self.daemon_log.fileno())
            self.daemon_log.close()
        if self.cg:
            self.state['final_memory'] = memory_sample(self.cg)
        if not errors and self.image.exists():
            try:
                self.detach_storage()
            except BaseException as error:
                errors.append('filesystem detach: ' + repr(error))
        self.state['cleanup']['errors'] = errors
        self.state['cleanup']['drained'] = not errors
        self.saved()

    def detach_storage(self):
        need('image_identity' in self.state, 'allocation outcome uncertain; retain image')
        need(identity(self.image) == self.state['image_identity'], 'owned image changed')
        devices = json.loads(query(['losetup', '--json', '--list', '--associated', str(self.image),
                                    '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,SIZELIMIT,OFFSET']))['loopdevices']
        need(len(devices) <= 1, 'multiple loop bindings to owner image')
        if devices:
            check_loop(devices[0], self.image, self.state['image_identity'])
            self.state['loop_device'] = devices[0]['name']
            self.saved()
            # findmnt exit 1 alone is not sufficient to infer an absent mount.
            # Enumerate kernel mountinfo, reject mismatched targets and aliases.
            found = []
            major_minor = str(os.major(os.stat(self.state['loop_device']).st_rdev)) + ':' + str(os.minor(os.stat(self.state['loop_device']).st_rdev))
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                if fields[2] == major_minor or fields[4] == str(self.mount):
                    found.append(fields)
            if found:
                need(len(found) == 1 and found[0][4] == str(self.mount), 'loop mount alias or target differs')
                self.mounted()
                call(['sync', '-f', str(self.mount)])
                usage = os.statvfs(self.mount)
                self.state['cleanup']['filesystem_usage'] = {
                    'total': usage.f_blocks * usage.f_frsize, 'free': usage.f_bfree * usage.f_frsize}
                self.saved()
                call(['umount', str(self.mount)])
                need(not any(line.split()[2] == major_minor for line in
                             Path('/proc/self/mountinfo').read_text().splitlines()), 'loop mount remains')
            self.loop()
            call(['losetup', '--detach', self.state['loop_device']])
            need(not json.loads(query(['losetup', '--json', '--list', '--associated', str(self.image),
                                       '--output', 'NAME']))['loopdevices'], 'loop binding remains')
        else:
            need(not any(line.split()[4] == str(self.mount) for line in
                         Path('/proc/self/mountinfo').read_text().splitlines()), 'unexpected owner mount remains')
        self.state['cleanup']['filesystem_detached'] = True
        self.saved()

    def execute(self):
        try:
            self.initialize_cgroup()
            self.prepare()
            for phase in ('test', 'fuzz-build', 'fuzz-smoke'):
                self.gate(phase)
            source = self.owner['source']
            need(query(['git', '-C', source, 'rev-parse', 'HEAD']) == self.owner['commit']
                 and not query(['git', '-C', source, 'status', '--porcelain', '--untracked-files=all']),
                 'host source checkout changed')
            self.state['status'] = 'passed'
        except BaseException as error:
            self.state['status'] = 'failed'
            self.state['errors'].append(repr(error))
        finally:
            self.cleanup()
            if not self.state['cleanup']['drained']:
                self.state['status'] = 'failed'
            self.state['finished_utc_epoch'] = time.time()
            self.state['finished_monotonic'] = time.monotonic()
            self.saved()
        return 0 if self.state['status'] == 'passed' else 1


def launch(arguments):
    need(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root execution required')
    parent = private_directory(arguments.parent)
    need(query(['findmnt', '--noheadings', '--target', str(parent), '--output', 'FSTYPE']) == 'ext4',
         'reference runner requires an ext4 backing filesystem')
    run_id = str(uuid.uuid4())
    directory = parent / run_id
    directory.mkdir(mode=0o700)
    owner = {'schema': 1, 'run_id': run_id, 'unit': f'redb-verify-{run_id}.service',
             'source': str(Path(arguments.source).resolve()), 'commit': arguments.commit,
             'archive_sha256': arguments.archive_sha256}
    check_owner(owner, directory)
    atomic_json(directory / 'owner.json', owner)
    command = ['systemd-run', '--unit', owner['unit'], '--wait', '--pipe',
               '--property=Slice=system.slice', '--property=Delegate=yes', '--property=MemoryMax=' + str(MEMORY),
               '--property=MemorySwapMax=0', '--property=TasksMax=2048',
               '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=15',
               '--property=KillMode=control-group',
               sys.executable, str(Path(__file__).resolve()), 'execute', str(directory)]
    print(str(directory), flush=True)
    outcome = None
    try:
        with (directory / 'launcher.log').open('x') as stream:
            outcome = run(command, parent, ENV, stream, 7300,
                          lambda record: atomic_json(directory / 'launcher.json', record))
    finally:
        # Stopping the client is insufficient. Inspect and stop the exact unit.
        unit = properties(owner['unit'])
        need(unit['Id'] == owner['unit'], 'systemd ownership differs')
        if unit['ActiveState'] not in ('inactive', 'failed'):
            call(['systemctl', 'stop', owner['unit']], timeout=40)
            unit = properties(owner['unit'])
        need(unit['ActiveState'] in ('inactive', 'failed'), 'systemd owner did not stop')
        expected_cgroup = Path('/sys/fs/cgroup/system.slice') / owner['unit']
        need(not unit['ControlGroup'] or Path('/sys/fs/cgroup') / unit['ControlGroup'].lstrip('/') == expected_cgroup,
             'systemd cgroup differs')
        need(cgroup_members(expected_cgroup) == [], 'systemd descendants remain')
        atomic_json(directory / 'unit-terminal.json', unit)
    return 0 if outcome and outcome['status'] == 'passed' else 1


def recover(directory):
    need(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root recovery required')
    root = private_directory(directory)
    owner = json.loads((root / 'owner.json').read_text())
    check_owner(owner, root)
    state = json.loads((root / 'status.json').read_text())
    need(state.get('owner') == owner and state.get('schema') == 1, 'owner status differs')
    need(state.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'boot identity changed; inspect preserved device state manually')
    unit = properties(owner['unit'])
    need(unit['Id'] == owner['unit'], 'recovery unit differs')
    if unit['ActiveState'] not in ('inactive', 'failed'):
        need(unit.get('InvocationID') == state.get('unit', {}).get('InvocationID'),
             'recovery invocation identity differs')
        call(['systemctl', 'stop', owner['unit']], timeout=40)
        unit = properties(owner['unit'])
    need(unit['ActiveState'] in ('inactive', 'failed'), 'recovery owner still active')
    recorded_cgroup = Path(state.get('cgroup', '/nonexistent'))
    need(str(recorded_cgroup).startswith('/sys/fs/cgroup/')
         and recorded_cgroup.name == owner['unit'], 'recovery cgroup identity differs')
    need(cgroup_members(recorded_cgroup) == [], 'recovery descendants remain')
    instance = Owner.__new__(Owner)
    instance.directory, instance.owner, instance.state = root, owner, state
    instance.mount, instance.image = root / 'filesystem', root / 'disk.ext4'
    state['recovery_unit_terminal'] = unit
    state['status'] = 'failed'
    state.setdefault('errors', []).append('stopped-owner physical cleanup; execution not resumed')
    instance.saved()
    if instance.image.exists():
        instance.detach_storage()
    state['cleanup']['recovered_after_unit_drain'] = True
    state['cleanup']['drained'] = True
    instance.saved()
    return 0


def main():
    need(sys.version_info >= (3, 11), 'Python 3.11 or newer is required')
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    start = sub.add_parser('launch')
    start.add_argument('--parent', required=True, help='existing root-owned mode-0700 directory')
    start.add_argument('--source', required=True)
    start.add_argument('--commit', required=True)
    start.add_argument('--archive-sha256', required=True)
    execute = sub.add_parser('execute')
    execute.add_argument('directory')
    recovery = sub.add_parser('recover')
    recovery.add_argument('directory')
    args = parser.parse_args()
    if args.action == 'launch':
        return launch(args)
    if args.action == 'recover':
        return recover(args.directory)
    need(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root execution required')
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda received, _: SIGNALS.append(received))
    return Owner(args.directory).execute()


if __name__ == '__main__':
    sys.exit(main())
