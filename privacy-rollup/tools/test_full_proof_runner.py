#!/usr/bin/env python3
"""Scheduler tests for full_proof_runner.py with a fake prover and checker.

The fake receipts carry only [pre, post) segment ranges, so contiguity, tree
shape, checkpoint reuse and failure handling are exercised without proving.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import full_proof_runner as runner  # noqa: E402

NATIVE = r'''
import json, os, sys, time
from pathlib import Path
op, d = sys.argv[1], Path(sys.argv[2])
with open(os.environ['FAKE_CALLS'], 'a') as f:
    f.write(' '.join([op, *sys.argv[3:]]) + '\n')
fail = os.environ.get('FAKE_FAIL')
def read(p): return json.loads(Path(p).read_text())
if op == 'prove':
    i = int(sys.argv[3])
    assert (d / f'segment-{i}.pc').read_bytes() == b'trace-%d' % i
    if 'FAKE_ONE_LEAF' in os.environ:
        marker = Path(os.environ['FAKE_ONE_LEAF'])
        os.close(os.open(marker, os.O_CREAT | os.O_EXCL))
        time.sleep(0.3)
        marker.unlink()
    out, value = d / f'receipt-{i}.pc', dict(index=i, pre=i, post=i + 1)
elif op == 'lift':
    i = int(sys.argv[3])
    out, value = d / f'lift-{i}.pc', read(d / f'receipt-{i}.pc')
elif op == 'join':
    left, right = read(d / 'lift-0.pc'), read(d / 'lift-1.pc')
    out, value = d / 'joined.pc', dict(index=None, pre=left['pre'], post=right['post'])
    if fail == d.name:
        sys.exit(3)
else:
    out, value = d / 'padded.pc', read(d / 'joined.pc')
out.write_text(json.dumps(value))
print(json.dumps({'result': {}}))
'''

CHECKER = r'''
import json, sys
from pathlib import Path
op, value = sys.argv[1], json.loads(Path(sys.argv[2]).read_text())
claim = dict(digest='c%d-%d' % (value['pre'], value['post']), pre=str(value['pre']),
             post=str(value['post']), input='in', output='out', sys_exit=0, user_exit=0)
key = 'complete_guest_verified' if op == 'full' else 'integrity_verified'
print(json.dumps({'result': {key: True, 'index': value['index'], 'claim': claim}}))
'''


def setup(root, segments):
    for name, body in [('native', NATIVE), ('checker', CHECKER)]:
        path = root / name
        path.write_text('#!' + sys.executable + '\n' + textwrap.dedent(body))
        path.chmod(0o755)
    spool = b''.join(b'trace-%d' % i for i in range(segments))
    (root / 'segments.spool').write_bytes(spool)
    (root / 'journal.bin').write_bytes(b'journal')
    selected, offset = [], 0
    for i in range(segments):
        size = len(b'trace-%d' % i)
        selected.append(dict(index=i, offset=offset, bytes=size))
        offset += size
    (root / 'capture.json').write_text(json.dumps(
        dict(complete=True, segments=segments, selected=selected, image_id='image')))
    (root / 'config.json').write_text(json.dumps(dict(
        native=str(root / 'native'), checker=str(root / 'checker'),
        capture=str(root / 'capture.json'), journal=str(root / 'journal.bin'),
        spool=str(root / 'segments.spool'), image_id='image', expected_segments=segments,
        frozen_sha256={}, started_at=0, deadline_at=4e9, minimum_free_bytes=0,
        maximum_group_rss_kib=4 * 1024**2, estimated_seconds_per_segment=1,
        stage_seconds=dict(prove=60, lift=60, join=60, padded=60, verify=60),
        prover_environment={})))


class TreeRangesTest(unittest.TestCase):
    def test_balanced_post_order(self):
        for n in range(1, 40):
            nodes = runner.tree_ranges(0, n)
            self.assertEqual(len(nodes), n - 1)
            built = {(i, i + 1) for i in range(n)}
            for lo, mid, hi in nodes:
                self.assertIn((lo, mid), built)
                self.assertIn((mid, hi), built)
                self.assertLessEqual(abs((mid - lo) - (hi - mid)), 1)
                built.add((lo, hi))
            if n > 1:
                self.assertEqual(nodes[-1][::2], (0, n))
        self.assertEqual(runner.tree_ranges(0, 5), [(0, 1, 2), (0, 2, 3), (3, 4, 5), (0, 3, 5)])


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.environ['FAKE_CALLS'] = str(self.root / 'calls.log')
        os.environ.pop('FAKE_FAIL', None)

    def tearDown(self):
        os.environ.pop('FAKE_FAIL', None)
        self.temp.cleanup()

    def calls(self):
        return (self.root / 'calls.log').read_text().splitlines()

    def finish(self, value):
        status = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(status['state'], 'complete')
        self.assertEqual(json.loads((self.root / 'final' / 'padded.pc').read_text())['post'], value)

    def open_runner(self):
        run = runner.Runner(self.root)
        self.addCleanup(run.lock.close)
        return run

    def test_sequential_prefix_unchanged(self):
        setup(self.root, 5)
        self.open_runner().run()
        self.finish(5)
        self.assertEqual(sum(c.startswith('join') for c in self.calls()), 4)

    def test_tree_completes_and_resumes_without_reproving(self):
        setup(self.root, 7)
        os.environ['FAKE_FAIL'] = 'tree-0004-0007'
        first = self.open_runner()
        with self.assertRaises(RuntimeError):
            first.run_tree(3)
        first.lock.close()
        self.assertEqual(sorted(p.name for p in (self.root / 'active').iterdir()), [])
        proved = sum(c.startswith('prove') for c in self.calls())
        os.environ.pop('FAKE_FAIL')
        self.open_runner().run_tree(3)
        self.finish(7)
        calls = self.calls()
        self.assertEqual(sum(c.startswith('prove') for c in calls), 7)
        self.assertGreaterEqual(proved, 4)
        joins = sorted(p.stem for p in (self.root / 'checks').glob('tree-*.json'))
        self.assertEqual(joins, ['tree-%04d-%04d' % (lo, hi) for lo, _, hi in
                                 sorted(runner.tree_ranges(0, 7))])

    def test_leaf_jobs_bounds_concurrent_leaves(self):
        setup(self.root, 6)
        os.environ['FAKE_ONE_LEAF'] = str(self.root / 'leaf-active')
        self.addCleanup(os.environ.pop, 'FAKE_ONE_LEAF', None)
        self.open_runner().run_tree(3, 1)
        self.finish(6)
        self.assertEqual(sum(c.startswith('prove') for c in self.calls()), 6)

    def test_noncontiguous_children_are_rejected(self):
        setup(self.root, 2)
        run = self.open_runner()
        left = (self.root / 'a.pc', dict(pre='0', post='1', input='in'))
        right = (self.root / 'b.pc', dict(pre='2', post='3', output='out', sys_exit=0, user_exit=0))
        with self.assertRaisesRegex(RuntimeError, 'noncontiguous'):
            run.join(0, 1, 2, left, right)


if __name__ == '__main__':
    unittest.main()
