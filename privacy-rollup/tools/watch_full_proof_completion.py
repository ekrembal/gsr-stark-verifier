#!/usr/bin/env python3
"""Run the fixed-statement Script check only after a frozen full run completes.

This is an auxiliary watcher: it never restarts proving or changes checkpoints,
limits, inputs or receipts. It exits on a stopped/paused/stale runner.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (55, 60))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    p.add_argument('--config-sha256', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    root = a.run.resolve()
    config_path = root / 'config.json'
    if digest(config_path) != a.config_sha256:
        raise ValueError('run configuration hash mismatch')
    config = json.loads(config_path.read_text())
    script = ROOT / 'privacy-rollup/tools/check_padded_script.py'
    profile = ROOT / 'privacy-rollup/fixtures/apply-batch/receipt-template.json'
    frozen = {str(path): digest(path) for path in (script, profile)}
    while True:
        if digest(config_path) != a.config_sha256:
            raise ValueError('run configuration changed while waiting')
        status = json.loads((root / 'status.json').read_text())
        if status['config_sha256'] != a.config_sha256:
            raise ValueError('status belongs to another run')
        if status['state'] == 'complete':
            break
        if status['state'] != 'running' or time.time() - status['updated_at'] > 120:
            raise RuntimeError('runner stopped, paused or stale; watcher does not resume it')
        if time.time() >= config['deadline_at']:
            raise RuntimeError('run deadline reached before completion')
        time.sleep(15)
    if not status['full_receipt_verified'] or any(
        status[key] != config['expected_segments']
        for key in ('completed_verified_segments', 'lifted_segments', 'joined_prefix_segments')
    ):
        raise ValueError('incomplete receipt chain')
    for path, expected in frozen.items():
        if digest(path) != expected:
            raise ValueError('Script checker or trusted profile changed')
    for name in ('full-unpadded', 'full-padded'):
        checkpoint = json.loads((root / 'checks' / (name + '.json')).read_text())
        if checkpoint['config_sha256'] != a.config_sha256 or digest(checkpoint['artifact']) != checkpoint['sha256']:
            raise ValueError('final receipt checkpoint changed')
        result = checkpoint['verification']['result']['result']
        for check in ('complete_guest_verified', 'assumptions_empty', 'successful_exit',
                      'wrong_journal_rejected', 'wrong_image_rejected', 'corrupt_seal_rejected'):
            if result.get(check) is not True:
                raise ValueError('missing final acceptance check: ' + check)
    final = root / 'final'
    command = [sys.executable, str(script), '--receipt', str(final / 'receipt.json'),
               '--seal', str(final / 'seal.bin'), '--journal', str(final / 'journal.bin'),
               '--image', config['image_id'], '--profile', str(profile), '--out', str(a.out)]
    start = time.monotonic()
    process = subprocess.run(command, capture_output=True, text=True, timeout=60, preexec_fn=limits)
    # The checker creates the output directory itself and refuses overwrites.
    report = {'command': command, 'exit_code': process.returncode,
              'seconds': time.monotonic() - start,
              'max_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
              'config_sha256': a.config_sha256, 'frozen_checker_profile': frozen,
              'stdout': process.stdout, 'stderr': process.stderr}
    evidence = a.out.with_name(a.out.name + '-watcher.json')
    with evidence.open('x') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps(report), flush=True)
    if process.returncode:
        raise RuntimeError('Script check failed; see watcher evidence')


if __name__ == '__main__':
    main()
