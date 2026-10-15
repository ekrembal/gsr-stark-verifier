#!/usr/bin/env python3
"""Summarize optional host CPU operation wall timers from a bounded proof run."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', type=Path, help='bounded_command.py output prefix')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    resources = json.loads(args.prefix.with_suffix('.resources.json').read_text())
    if resources['exit_code'] or resources['stopped_by']:
        parser.error('the bounded proof run did not complete successfully')
    samples = defaultdict(list)
    for name, nanos in re.findall(r'^gsr_cpu_op (\w+) (\d+)$',
                                  args.prefix.with_suffix('.stderr').read_text(), re.M):
        samples[name].append(int(nanos))
    if not samples:
        parser.error('no CPU timers found; build the supplemental patch and set GSR_PROFILE_CPU=1')
    results = [json.loads(line) for line in args.prefix.with_suffix('.stdout').read_text().splitlines()
               if line.startswith('{')]
    proof = next(item for item in results if item.get('real_local_proof'))
    duration = proof['seconds']
    phases = [dict(name=name, calls=len(times), seconds=sum(times)/1e9,
                   largest_call_seconds=max(times)/1e9,
                   fraction_of_prover_time=sum(times)/1e9/duration)
              for name, times in samples.items()]
    phases.sort(key=lambda item: item['seconds'], reverse=True)
    report = dict(scope='Host CPU operation wall times, including Rayon workers; not CPU-time samples',
                  timer_env='GSR_PROFILE_CPU=1', proof_result=proof, resources=resources,
                  phases=phases, profiled_call_seconds=sum(p['seconds'] for p in phases),
                  hal_call_seconds=sum(p['seconds'] for p in phases
                                       if not p['name'].startswith('circuit_')))
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    for phase in phases:
        print(f"{phase['name']}: {phase['seconds']:.6f}s ({phase['fraction_of_prover_time']:.1%}), "
              f"{phase['calls']} calls")


if __name__ == '__main__':
    main()
