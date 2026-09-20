#!/usr/bin/env python3
"""Extract selected crash frames and exact binary prologues without running Kasumi."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1 << 20):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    expected = '26d58319400fb6ee4fddcfe8b0b1aa2cb116d8f084c72f843c4027eb1e42fd88'
    if sha(args.binary) != expected:
        raise SystemExit('binary hash differs from the failed gate')
    report = json.loads(args.report.read_text().split('\n', 1)[1])
    if report['termination']['byPid'] != 65795:
        raise SystemExit('crash PID differs from the failed gate')
    images = report['usedImages']
    uuid_output = subprocess.check_output(['/usr/bin/dwarfdump', '--uuid', str(args.binary)], text=True)
    if images[0]['uuid'].lower() not in uuid_output.lower():
        raise SystemExit('crash image UUID differs from the retained executable')
    frames = report['threads'][report['faultingThread']]['frames']
    # Omit thread registers, memory maps, host/OS inventory, usernames and paths.
    selected = [{key: frame[key] for key in ('symbol', 'symbolLocation', 'sourceFile', 'sourceLine', 'imageOffset') if key in frame}
                for frame in frames if frame.get('imageIndex') == 0]
    names = {
        'exercise_completed_recovery0': ('completed recovery poll', 0x14d000 + 0x650 + 0x20),
        'exercise_route_publication0': ('route publication poll', 0x5a000 + 0xd10 + 0x20),
        'ControlPlane10initialize0': ('Control initialize poll', 0x7000 + 0x650 + 0x20),
        'Database11collections0': ('collections poll', 0x3000 + 0x360 + 0x20),
        'Database17collections_inner0': ('collections inner poll', 0x7000 + 0xc80 + 0x20),
        'Database7barrier0': ('database barrier poll', 0x2000 + 0x140 + 0x20),
    }
    nm = subprocess.check_output(['/usr/bin/nm', '-n', str(args.binary)], text=True)
    symbols = {fields[2]: int(fields[0], 16) for row in nm.splitlines()
               if len(fields := row.split()) == 3 and fields[0] != 'U'}
    objdump = subprocess.check_output(['/usr/bin/xcrun', '--find', 'llvm-objdump'], text=True).strip()
    disassembly, sizes, seen = [], [], set()
    for frame in selected:
        symbol = frame.get('symbol', '')
        for name, (label, size) in names.items():
            if name not in symbol or name in seen:
                continue
            seen.add(name)
            address = symbols['_' + symbol]
            argv = [objdump, '--disassemble', '--start-address=' + hex(address), '--stop-address=' + hex(address + 96), str(args.binary)]
            output = subprocess.check_output(argv, text=True).replace(str(args.binary), '<retained-binary>')
            disassembly.append(output)
            sizes.append({'label': label, 'symbol': symbol, 'start_address': hex(address), 'reserved_stack_bytes': size,
                          'measurement': 'manual sum of fixed ARM64 prologue allocation, including register save; disassembly retained'})
    if len(seen) != len(names):
        raise SystemExit('required frame missing')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'prologues.txt').write_text('\n'.join(disassembly))
    output = {
        'source': 'f4a472ffa510cead0a5383a5a199a7e5f47560ef',
        'test': 'recovery_control::recovery_uncertain_activation_resolves_original_winner_and_confirms_every_voter_forward',
        'status': 'observed failure; proposed source fix has not been compiled or executed',
        'report_sha256': sha(args.report), 'binary_sha256': expected, 'binary_uuid': images[0]['uuid'],
        'capture_time': report['captureTime'], 'pid': 65795, 'exception_type': report['exception']['type'],
        'termination': {'namespace': 'SIGNAL', 'code': 6}, 'total_triggered_frames': len(frames),
        'selected_frames': selected, 'prologue_reservations': sizes,
        'prologues_sha256': sha(args.output / 'prologues.txt'),
        'extractor_sha256': sha(Path(__file__)),
        'tools': {'objdump_version': subprocess.check_output([objdump, '--version'], text=True).strip()},
        'limitation': 'Static prologue inspection is not a measurement of complete dynamic stack usage. No new Kasumi process or compiler ran.'
    }
    (args.output / 'analysis.json').write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    main()
