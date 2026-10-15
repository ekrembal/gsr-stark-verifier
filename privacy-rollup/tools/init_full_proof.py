#!/usr/bin/env python3
"""Create an immutable configuration for a captured, resumable proof run.

First use full_proof_check capture to populate DIRECTORY/capture. Files in
DIRECTORY/inputs are included in the frozen hash manifest. The prover and
checker must already be built and preserved outside regenerable build caches.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    p.add_argument('--native',required=True,type=Path)
    p.add_argument('--checker',required=True,type=Path)
    p.add_argument('--image',required=True)
    p.add_argument('--segments',required=True,type=int)
    p.add_argument('--hours',type=float,default=18)
    p.add_argument('--threads',type=int,default=4,help='Rayon threads per prover stage')
    p.add_argument('--address-space-gib',type=int,default=14,help='RLIMIT_AS per stage')
    p.add_argument('--stage-rss-gib',type=int,default=12,help='sampled RSS guard per stage')
    p.add_argument('--total-rss-gib',type=int,help='sampled RSS guard over concurrent stages')
    p.add_argument('--seconds-per-segment',type=float,default=184.25,help='initial ETA estimate')
    p.add_argument('--prove-seconds',type=int,default=480,help='wall-time guard per leaf proof')
    p.add_argument('--hash-lanes',type=int,choices=(8,16),default=16,help='Poseidon2 rows per batch')
    p.add_argument('--fast-ntt',action='store_true',help='use the tabulated BabyBear NTT/zk_shift')
    a = p.parse_args()
    root=a.directory.resolve()
    assert not (root/'config.json').exists(), 'configuration already exists'
    capture=root/'capture'
    metadata=json.loads((capture/'capture.json').read_text())
    assert metadata['complete'] and metadata['segments']==a.segments
    assert metadata['image_id']==a.image
    assert 0<a.hours<=24
    assert 1<=a.threads<=64 and 1<=a.address_space_gib<=64 and 1<=a.stage_rss_gib<=64
    assert shutil.disk_usage(root).free >= 2*1024**3, 'reserve at least 2 GiB before initialization'
    runner=root/'runner.py'
    shutil.copy2(Path(__file__).with_name('full_proof_runner.py'),runner)
    files=[a.native.resolve(),a.checker.resolve(),runner,
           capture/'capture.json',capture/'journal.bin',capture/'segments.spool']
    if (root/'inputs').exists():
        files.extend(p for p in (root/'inputs').rglob('*') if p.is_file())
    now=time.time()
    config=dict(native=str(a.native.resolve()),checker=str(a.checker.resolve()),
        capture=str(capture/'capture.json'),journal=str(capture/'journal.bin'),
        spool=str(capture/'segments.spool'),image_id=a.image,expected_segments=a.segments,
        frozen_sha256={str(f):sha(f) for f in files},started_at=now,deadline_at=now+a.hours*3600,
        minimum_free_bytes=1536*1024**2,maximum_group_rss_kib=a.stage_rss_gib*1024**2,
        maximum_total_rss_kib=(a.total_rss_gib or a.stage_rss_gib)*1024**2,
        address_space_bytes=a.address_space_gib*1024**3,cpu_seconds_per_wall_second=a.threads,
        estimated_seconds_per_segment=a.seconds_per_segment,
        stage_seconds=dict(prove=a.prove_seconds,lift=120,join=120,padded=180,verify=60),
        prover_environment=dict(RAYON_NUM_THREADS=str(a.threads),GSR_BATCH_CPU='1',GSR_PERIODIC_CPU='1',
                                GSR_BATCH_EVAL_CPU='1',GSR_PROFILE_CPU='1',
                                GSR_HASH_LANES=str(a.hash_lanes),GSR_FAST_NTT='1' if a.fast_ntt else '0'))
    with (root/'config.json').open('x') as f:
        json.dump(config,f,indent=2);f.write('\n')
    print(json.dumps({'directory':str(root),'image':a.image,'segments':a.segments,
                      'frozen_files':len(files),'config_sha256':sha(root/'config.json')}))


if __name__=='__main__':
    main()
