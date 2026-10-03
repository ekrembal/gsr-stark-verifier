#!/usr/bin/env python3
"""Durable, resumable orchestration of the frozen real prover.

The default schedule is sequential (leaf, lift, prefix join). `--jobs N` proves
up to N independent leaves concurrently and joins lifts in a deterministic
balanced tree over segment ranges; each range [lo, hi) splits at
lo + (hi - lo + 1) // 2, so a resumed run reproduces the same tree.

No guest/AIR/prover code is rebuilt here. Configuration hashes bind the saved
executables and single-execution spool. Every completed receipt is independently
verified and fsynced before its checkpoint becomes visible. A detached process
can continue across tool calls; an executor interruption can resume from disk.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def sync_file(path):
    with Path(path).open('rb') as f:
        os.fsync(f.fileno())
    fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix('.tmp')
    with temp.open('w') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)
    sync_file(path)


def group_memory(group):
    rss, vsize = 0, 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.getpgid(int(entry.name)) != group:
                continue
            for line in (entry / 'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    rss += int(line.split()[1])
                elif line.startswith('VmSize:'):
                    vsize += int(line.split()[1])
        except (OSError, ProcessLookupError):
            pass
    return rss, vsize


def tree_ranges(lo, hi):
    """Post-order (lo, mid, hi) join nodes of the balanced tree over [lo, hi)."""
    if hi - lo < 2:
        return []
    mid = lo + (hi - lo + 1) // 2
    return tree_ranges(lo, mid) + tree_ranges(mid, hi) + [(lo, mid, hi)]


def linked_copy(source, target):
    source, target = Path(source), Path(target)
    if target.exists():
        if digest(source) != digest(target):
            raise RuntimeError('existing checkpoint differs: ' + str(target))
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    os.link(source, target)
    sync_file(target)


class Runner:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        self.config = json.loads((self.root / 'config.json').read_text())
        self.config_hash = digest(self.root / 'config.json')
        self.lock = (self.root / 'runner.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (self.root / 'active').mkdir(exist_ok=True)
        for active in [self.root / 'active-process.json', *(self.root / 'active').glob('*.json')]:
            if not active.exists():
                continue
            previous = json.loads(active.read_text())
            try:
                stat = Path(f"/proc/{previous['pid']}/stat").read_text().rsplit(') ',1)[1].split()
                if stat[0] != 'Z' and stat[19] == previous.get('start_ticks'):
                    raise RuntimeError('previous stage still running; do not start a second prover')
            except FileNotFoundError:
                pass
            active.unlink()
        if os.environ.get('RISC0_DEV_MODE') is not None:
            raise RuntimeError('RISC0_DEV_MODE must be absent')
        for path, expected in self.config['frozen_sha256'].items():
            if digest(path) != expected:
                raise RuntimeError('frozen file changed: ' + path)
        for name in ['leaves', 'joins', 'checks', 'logs', 'final']:
            (self.root / name).mkdir(exist_ok=True)
        self.capture = json.loads(Path(self.config['capture']).read_text())
        self.total = self.capture['segments']
        assert self.capture['complete'] and self.total == len(self.capture['selected'])
        assert self.capture['image_id'] == self.config['image_id']
        assert self.total == self.config['expected_segments']
        self.started = self.config['started_at']
        self.env = dict(os.environ)
        self.env.update(self.config['prover_environment'])
        self.native = self.config['native']
        self.checker = self.config['checker']
        self.completed, self.lifted, self.prefix = 0, 0, 0
        self.jobs = 1
        self.running = {}
        self.guard = threading.RLock()
        self.abort = threading.Event()
        previous_status = self.root / 'status.json'
        self.peak = (json.loads(previous_status.read_text()).get('sampled_peak_group_rss_kib',0)
                     if previous_status.exists() else 0)
        self.sample_times = []
        self.last_status = 0

    def event(self, event, **details):
        item = dict(time=time.time(), event=event, **details)
        with self.guard, (self.root / 'events.jsonl').open('a') as f:
            f.write(json.dumps(item) + '\n')
            f.flush()
            os.fsync(f.fileno())

    def status(self, state='running', force=False, error=None):
        with self.guard:
            self.write_status(state, force, error)

    def write_status(self, state, force, error):
        now = time.time()
        if not force and now - self.last_status < 5:
            return
        self.last_status = now
        estimate = (sum(self.sample_times) / len(self.sample_times)
                    if self.sample_times else self.config['estimated_seconds_per_segment'])
        result = dict(state=state, pid=os.getpid(), updated_at=now,
                      elapsed_seconds=now-self.started, completed_verified_segments=self.completed,
                      lifted_segments=self.lifted, joined_prefix_segments=self.prefix,
                      total_segments=self.total, jobs=self.jobs,
                      current_stage=(sorted(self.running) or [None])[0], running_stages=sorted(self.running),
                      current_group_rss_kib=sum(self.running.values()), sampled_peak_group_rss_kib=self.peak,
                      free_disk_bytes=shutil.disk_usage(self.root).free,
                      remaining_eta_seconds=(0 if state == 'complete' else
                                             max(0,self.total-self.prefix)*estimate/self.jobs+60),
                      full_receipt_verified=state == 'complete', config_sha256=self.config_hash,
                      error=error)
        atomic_json(self.root / 'status.json', result)
        if force:
            print(json.dumps(result), flush=True)

    def limits(self, seconds):
        parent_pid = os.getpid()
        def apply():
            # Stop a native stage if its supervisor is killed. Otherwise a
            # resumed supervisor could compete with an orphaned 9-GiB prover.
            if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM) != 0:
                raise OSError(ctypes.get_errno(), 'PR_SET_PDEATHSIG failed')
            if os.getppid() != parent_pid:
                os._exit(125)
            space = self.config.get('address_space_bytes', 14*1024**3)
            cpus = self.config.get('cpu_seconds_per_wall_second', 4)
            resource.setrlimit(resource.RLIMIT_AS, (space,space))
            resource.setrlimit(resource.RLIMIT_CPU, (seconds*cpus+30,seconds*cpus+35))
            resource.setrlimit(resource.RLIMIT_FSIZE, (512*1024**2,512*1024**2))
            resource.setrlimit(resource.RLIMIT_CORE, (0,0))
        return apply

    def run_command(self, name, command, seconds):
        logs = self.root / 'logs' / name
        logs.mkdir(exist_ok=True)
        attempt = len(list(logs.glob('*.resources.json'))) + 1
        # Crashes before writing resource evidence must not overwrite old output.
        while (logs / f'{attempt:04}.stdout').exists():
            attempt += 1
        prefix = logs / f'{attempt:04}'
        if shutil.disk_usage(self.root).free < self.config['minimum_free_bytes']:
            raise RuntimeError('free disk guard before ' + name)
        if time.time() >= self.config['deadline_at']:
            raise RuntimeError('overall wall-time guard; checkpoints retained')
        active_file = self.root / 'active' / (name+'.json')
        with self.guard:
            self.running[name] = 0
        self.status(force=True)
        start = time.monotonic()
        peak, max_vsize, reason = 0, 0, None
        with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=self.env, start_new_session=True, close_fds=True, preexec_fn=self.limits(seconds))
            atomic_json(active_file, {'pid':process.pid,'stage':name,
                'command':command,'started_at':time.time(),'config_sha256':self.config_hash,
                'start_ticks':Path(f'/proc/{process.pid}/stat').read_text().rsplit(') ',1)[1].split()[19]})
            try:
                while process.poll() is None:
                    rss, vsize = group_memory(process.pid)
                    peak, max_vsize = max(peak,rss), max(max_vsize,vsize)
                    with self.guard:
                        self.running[name] = rss
                        total_rss = sum(self.running.values())
                        self.peak = max(self.peak,total_rss)
                    if time.monotonic()-start > seconds:
                        reason = 'stage wall-time guard'
                    elif time.time() >= self.config['deadline_at']:
                        reason = 'overall wall-time guard'
                    elif rss > self.config['maximum_group_rss_kib']:
                        reason = 'sampled RSS guard'
                    elif total_rss > self.config.get('maximum_total_rss_kib',
                                                     self.config['maximum_group_rss_kib']):
                        reason = 'sampled total RSS guard'
                    elif shutil.disk_usage(self.root).free < self.config['minimum_free_bytes']:
                        reason = 'free disk guard'
                    elif (self.root / 'STOP').exists():
                        reason = 'requested stop'
                    elif self.abort.is_set():
                        reason = 'sibling stage failed'
                    if reason:
                        os.killpg(process.pid,signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid,signal.SIGKILL)
                        break
                    self.status()
                    time.sleep(0.5)
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid,signal.SIGKILL)
                raise
            code = process.wait()
        elapsed = time.monotonic()-start
        record = dict(command=command,exit_code=code,reason=reason,seconds=elapsed,
            peak_group_rss_kib=peak,peak_group_vsize_kib=max_vsize,
            free_disk_bytes=shutil.disk_usage(self.root).free,stage_wall_limit=seconds,
            address_space_hard_limit_bytes=self.config.get('address_space_bytes', 14*1024**3))
        atomic_json(prefix.with_suffix('.resources.json'),record)
        active_file.unlink(missing_ok=True)
        with self.guard:
            self.running.pop(name, None)
        if code != 0 or reason:
            raise RuntimeError(f'{name}: exit={code}, reason={reason}; see {prefix}')
        results = [json.loads(line) for line in prefix.with_suffix('.stdout').read_text().splitlines()
                   if line.startswith('{')]
        if not results:
            raise RuntimeError('no result from ' + name)
        return dict(resources=record,result=results[-1],log_prefix=str(prefix))

    def checkpoint(self, name, artifact, command, check, kind, expected_claim=None, index=None,
                   expected_fields=None):
        artifact = Path(artifact)
        meta = self.root / 'checks' / (name+'.json')
        if meta.exists():
            value = json.loads(meta.read_text())
            if value['config_sha256'] != self.config_hash or digest(artifact) != value['sha256']:
                raise RuntimeError('checkpoint changed: ' + name)
            return value
        proof = None
        adopted = artifact.exists()
        if not adopted:
            proof = self.run_command(name,command,self.config['stage_seconds'][kind])
        verified = self.run_command(name+'-verify',check,self.config['stage_seconds']['verify'])
        result = verified['result']['result']
        if not (result.get('integrity_verified') or result.get('complete_guest_verified')):
            raise RuntimeError('independent verification did not pass')
        if index is not None and result.get('index') != index:
            raise RuntimeError('receipt index mismatch')
        if expected_claim is not None and result['claim']['digest'] != expected_claim:
            raise RuntimeError('lifted claim differs from segment')
        if expected_fields is not None and any(result['claim'][k] != v for k,v in expected_fields.items()):
            raise RuntimeError('joined claim boundaries/output differ from its two children')
        sync_file(artifact)
        value = dict(config_sha256=self.config_hash,artifact=str(artifact),sha256=digest(artifact),
                     bytes=artifact.stat().st_size,adopted_after_interruption=adopted,
                     proof=proof,verification=verified,completed_at=time.time())
        atomic_json(meta,value)
        self.event('checkpoint',name=name,sha256=value['sha256'],bytes=value['bytes'])
        return value

    def prefix_path(self, index):
        return (self.root/'leaves'/'lift-0.pc' if index == 0
                else self.root/'joins'/f'{index:04}'/'joined.pc')

    def run(self, stop_after=None):
        self.event('runner_started',pid=os.getpid(),config_sha256=self.config_hash)
        try:
            for index, item in enumerate(self.capture['selected']):
                if (self.root/'PAUSE').exists():
                    self.status('paused',force=True)
                    return
                iteration = time.monotonic()
                leaf_dir = self.root / 'leaves'
                leaf = leaf_dir / f'receipt-{index}.pc'
                trace = leaf_dir / f'segment-{index}.pc'
                if not leaf.exists():
                    with Path(self.config['spool']).open('rb') as stream:
                        stream.seek(item['offset'])
                        data = stream.read(item['bytes'])
                    if len(data) != item['bytes']:
                        raise RuntimeError('truncated execution spool')
                    trace.write_bytes(data)
                    sync_file(trace)
                leaf_meta = self.checkpoint(f'leaf-{index:04}',leaf,
                    [self.native,'prove',str(leaf_dir),str(index)],
                    [self.checker,'segment',str(leaf)],'prove',index=index)
                self.completed = index+1
                trace.unlink(missing_ok=True)
                lift = leaf_dir / f'lift-{index}.pc'
                lift_meta = self.checkpoint(f'lift-{index:04}',lift,
                    [self.native,'lift',str(leaf_dir),str(index)],
                    [self.checker,'succinct',str(lift)],'lift',
                    expected_claim=leaf_meta['verification']['result']['result']['claim']['digest'])
                self.lifted = index+1
                if index:
                    previous_name = 'lift-0000' if index == 1 else f'join-{index-1:04}'
                    previous_meta = json.loads((self.root/'checks'/(previous_name+'.json')).read_text())
                    left = previous_meta['verification']['result']['result']['claim']
                    right = lift_meta['verification']['result']['result']['claim']
                    if left['post'] != right['pre']:
                        raise RuntimeError('noncontiguous execution checkpoints')
                    expected = dict(pre=left['pre'], input=left['input'],
                                    **{k:right[k] for k in ['post','output','sys_exit','user_exit']})
                    dest = self.prefix_path(index).parent
                    dest.mkdir(exist_ok=True)
                    linked_copy(self.prefix_path(index-1),dest/'lift-0.pc')
                    linked_copy(lift,dest/'lift-1.pc')
                    self.checkpoint(f'join-{index:04}',dest/'joined.pc',
                        [self.native,'join',str(dest),'0','1'],
                        [self.checker,'succinct',str(dest/'joined.pc')],'join',expected_fields=expected)
                    (dest/'lift-0.pc').unlink()
                    (dest/'lift-1.pc').unlink()
                self.prefix = index+1
                # Cached iterations are excluded from ETA samples on resume.
                duration = time.monotonic()-iteration
                if duration > 10:
                    self.sample_times.append(duration)
                self.status(force=True)
                if stop_after and self.prefix >= stop_after:
                    self.status('paused',force=True)
                    return
            self.finish(self.prefix_path(self.total-1))
        except BaseException as error:
            self.status('stopped',force=True,error=str(error))
            self.event('stopped',error=str(error))
            raise

    def finish(self, root_receipt):
            final = self.root/'final'
            linked_copy(root_receipt,final/'joined.pc')
            linked_copy(Path(self.config['journal']),final/'journal.bin')
            linked_copy(Path(self.config['capture']),final/'capture.json')
            self.checkpoint('full-unpadded',final/'joined.pc',[],
                [self.checker,'full',str(final/'joined.pc'),str(final/'journal.bin'),self.config['image_id']],
                'verify')
            self.checkpoint('full-padded',final/'padded.pc',
                [self.native,'padded',str(final),'joined'],
                [self.checker,'full',str(final/'padded.pc'),str(final/'journal.bin'),self.config['image_id'],
                    str(final/'padded-parameters.pc')],'padded')
            self.status('complete',force=True)
            self.event('complete',segments=self.total)

    def leaf(self, index):
        """Prove, verify, lift and verify segment `index`; return its lifted claim."""
        item = self.capture['selected'][index]
        leaf_dir = self.root / 'leaves'
        leaf = leaf_dir / f'receipt-{index}.pc'
        trace = leaf_dir / f'segment-{index}.pc'
        if not leaf.exists():
            with Path(self.config['spool']).open('rb') as stream:
                stream.seek(item['offset'])
                data = stream.read(item['bytes'])
            if len(data) != item['bytes']:
                raise RuntimeError('truncated execution spool')
            trace.write_bytes(data)
            sync_file(trace)
        leaf_meta = self.checkpoint(f'leaf-{index:04}',leaf,
            [self.native,'prove',str(leaf_dir),str(index)],
            [self.checker,'segment',str(leaf)],'prove',index=index)
        trace.unlink(missing_ok=True)
        lift = leaf_dir / f'lift-{index}.pc'
        lift_meta = self.checkpoint(f'lift-{index:04}',lift,
            [self.native,'lift',str(leaf_dir),str(index)],
            [self.checker,'succinct',str(lift)],'lift',
            expected_claim=leaf_meta['verification']['result']['result']['claim']['digest'])
        with self.guard:
            self.completed += 1
            self.lifted += 1
        return lift, lift_meta['verification']['result']['result']['claim']

    def join(self, lo, mid, hi, left, right):
        """Join the receipts for [lo, mid) and [mid, hi); return the joined receipt and claim."""
        (left_path, left_claim), (right_path, right_claim) = left, right
        if left_claim['post'] != right_claim['pre']:
            raise RuntimeError('noncontiguous execution checkpoints')
        expected = dict(pre=left_claim['pre'], input=left_claim['input'],
                        **{k:right_claim[k] for k in ['post','output','sys_exit','user_exit']})
        dest = self.root/'joins'/f'tree-{lo:04}-{hi:04}'
        dest.mkdir(exist_ok=True)
        if not (self.root/'checks'/f'tree-{lo:04}-{hi:04}.json').exists():
            linked_copy(left_path,dest/'lift-0.pc')
            linked_copy(right_path,dest/'lift-1.pc')
        meta = self.checkpoint(f'tree-{lo:04}-{hi:04}',dest/'joined.pc',
            [self.native,'join',str(dest),'0','1'],
            [self.checker,'succinct',str(dest/'joined.pc')],'join',expected_fields=expected)
        (dest/'lift-0.pc').unlink(missing_ok=True)
        (dest/'lift-1.pc').unlink(missing_ok=True)
        return dest/'joined.pc', meta['verification']['result']['result']['claim']

    def run_tree(self, jobs, leaf_jobs=None):
        """Bounded concurrent leaves; joins become ready as soon as both children verify."""
        self.jobs = jobs
        leaf_jobs = leaf_jobs or jobs
        self.event('runner_started',pid=os.getpid(),config_sha256=self.config_hash,jobs=jobs,
                   leaf_jobs=leaf_jobs)
        joins = tree_ranges(0, self.total)
        done = {}
        pending_leaves = list(range(self.total))
        running = {}
        try:
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                while len(done) < self.total + len(joins):
                    stopping = (self.root/'PAUSE').exists()
                    while len(running) < jobs:
                        # Joins first: they are short and free disk/memory sooner.
                        ready = next(((lo,mid,hi) for lo,mid,hi in joins
                                      if (lo,hi) not in done and (lo,hi) not in running.values()
                                      and (lo,mid) in done and (mid,hi) in done), None)
                        if ready:
                            lo, mid, hi = ready
                            future = pool.submit(self.join, lo, mid, hi, done[(lo,mid)], done[(mid,hi)])
                            running[future] = (lo, hi)
                        elif (pending_leaves and not stopping and
                              sum(hi-lo == 1 for lo,hi in running.values()) < leaf_jobs):
                            index = pending_leaves.pop(0)
                            running[pool.submit(self.leaf, index)] = (index, index+1)
                        else:
                            break
                    if not running:
                        self.status('paused',force=True)
                        return
                    try:
                        finished, _ = wait(running, timeout=5, return_when=FIRST_COMPLETED)
                        for future in finished:
                            key = running.pop(future)
                            done[key] = future.result()
                    except BaseException:
                        # Terminate sibling stages before the pool waits for them.
                        self.abort.set()
                        raise
                    with self.guard:
                        self.prefix = len({i for (lo,hi) in done if hi-lo > 1 for i in range(lo,hi)})
                    self.status()
            self.finish(done[(0, self.total)][0])
        except BaseException as error:
            self.status('stopped',force=True,error=str(error))
            self.event('stopped',error=str(error))
            raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    p.add_argument('--stop-after',type=int)
    p.add_argument('--status',action='store_true')
    p.add_argument('--jobs',type=int,
                   help='concurrent stages with a balanced join tree (default: sequential prefix)')
    p.add_argument('--leaf-jobs',type=int,
                   help='maximum concurrent leaf proofs within --jobs (default: --jobs)')
    a = p.parse_args()
    if a.status:
        print((a.directory/'status.json').read_text())
    elif a.jobs:
        if not 1 <= a.jobs <= 8 or a.stop_after:
            p.error('--jobs must be 1..8 and cannot be combined with --stop-after')
        if a.leaf_jobs is not None and not 1 <= a.leaf_jobs <= a.jobs:
            p.error('--leaf-jobs must be 1..--jobs')
        Runner(a.directory).run_tree(a.jobs, a.leaf_jobs)
    else:
        Runner(a.directory).run(a.stop_after)


if __name__ == '__main__':
    main()
