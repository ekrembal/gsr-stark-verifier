#!/usr/bin/env python3
"""Run a local benchmark with wall-time, aggregate RSS and free-disk guards.

Writes stdout, stderr and machine-readable resource evidence beside --output.
The guards are sampled, not a substitute for the environment's hard cgroup limit.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


def group_rss_kib(group):
    total = 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.getpgid(int(entry.name)) != group:
                continue
            for line in (entry / 'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    total += int(line.split()[1])
        except (OSError, ProcessLookupError):
            pass
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=900)
    parser.add_argument('--rss-mib', type=int, default=12288)
    parser.add_argument('--free-mib', type=int, default=1024)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or min(args.seconds, args.rss_mib, args.free_mib) <= 0:
        parser.error('supply a command and positive resource limits')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(args.output.parent).free < args.free_mib * 1024**2:
        parser.error('insufficient free disk before launch')
    for suffix in ('.stdout', '.stderr', '.resources.json'):
        if args.output.with_suffix(suffix).exists():
            parser.error(f'refusing to overwrite evidence: {args.output.with_suffix(suffix)}')
    start = time.monotonic()
    peak = 0
    minimum_free = shutil.disk_usage(args.output.parent).free
    reason = None
    with args.output.with_suffix('.stdout').open('x') as stdout, args.output.with_suffix('.stderr').open('x') as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        while process.poll() is None:
            peak = max(peak, group_rss_kib(process.pid))
            minimum_free = min(minimum_free, shutil.disk_usage(args.output.parent).free)
            elapsed = time.monotonic() - start
            if elapsed > args.seconds:
                reason = 'wall_time_limit'
            elif peak > args.rss_mib * 1024:
                reason = 'rss_limit'
            elif minimum_free < args.free_mib * 1024**2:
                reason = 'free_disk_limit'
            if reason:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.25)
        code = process.wait()
    result = dict(command=command, exit_code=code, stopped_by=reason,
                  seconds=time.monotonic()-start, sampled_peak_group_rss_kib=peak,
                  minimum_free_disk_bytes=minimum_free, sampling_seconds=0.25,
                  limits=dict(seconds=args.seconds, rss_mib=args.rss_mib, free_mib=args.free_mib))
    args.output.with_suffix('.resources.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result), flush=True)
    raise SystemExit(1 if reason else code)


if __name__ == '__main__':
    main()
