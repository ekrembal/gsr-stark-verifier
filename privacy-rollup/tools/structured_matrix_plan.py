#!/usr/bin/env python3
"""Derive a fixed-VK linear evaluator plan and check every replaced matrix row.

S-box outputs are independent witness columns. No nonlinear Poseidon operation
is recomputed, assumed satisfied, or removed. This script reconstructs only
the compiler's linear forms and checks exact finite-field coefficient equality.
"""
import argparse
import hashlib
import json
from pathlib import Path

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
VK_SHA = 'bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183'
EXT = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]]
# Exact t=4 diagonal from pinned ProveKit r1cs-compiler/poseidon2/constants.rs.
DIAG = [int(s, 16) for s in [
    '10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7',
    '0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b',
    '00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15',
    '222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b']]


def combine(terms):
    out = {}
    for coefficient, form in terms:
        for column, value in form.items():
            out[column] = (out.get(column, 0) + coefficient*value) % P
    return {column: value for column, value in out.items() if value}


def external(forms):
    return [combine(zip(row, forms)) for row in EXT]


def internal(forms):
    return [combine([(1, f) for f in forms] + [(d, f)]) for d, f in zip(DIAG, forms)]


def derive(data):
    assert data['vk_sha256'] == VK_SHA
    assert (data['rows'], data['columns'], data['w1_size']) == (38819, 51805, 5530)
    matrices = data['matrices']
    coefficients = [int(s or '0') for s in data['coefficients']]
    one = coefficients.index(1)

    def single(row):
        return len(row) == 1 and row[0][1] == one

    def triple(row):
        a, b, c = matrices
        return (a[row] == b[row] and len(a[row]) > 1 and single(c[row])
                and a[row+1] == b[row+1] == c[row] and single(c[row+1])
                and a[row+2] == c[row+1] and b[row+2] == a[row] and single(c[row+2]))

    def form(matrix, row):
        entries = matrices[matrix][row]
        assert len(set(c for c, _ in entries)) == len(entries)
        return {c: coefficients[k] for c, k in entries if coefficients[k]}

    blocks = []
    row = 0
    common_rc = None
    while row + 268 <= data['rows']:
        if not all(triple(row+3*j) for j in range(88)):
            row += 1
            continue
        y2 = [matrices[2][row+3*j][0][0] for j in range(88)]
        y4 = [matrices[2][row+3*j+1][0][0] for j in range(88)]
        y5 = [matrices[2][row+3*j+2][0][0] for j in range(88)]
        initial = [form(0, row+3*i) for i in range(4)]
        state = initial
        cursor = 0
        rc = []

        def sbox(expected):
            nonlocal cursor
            actual = form(0, row+3*cursor)
            difference = combine([(1, actual), (-1, expected)])
            assert set(difference) <= {0}, (row, cursor, difference)
            constant = difference.get(0, 0)
            assert combine([(1, expected), (constant, {0: 1})]) == actual
            rc.append(constant)
            out = {y5[cursor]: 1}
            cursor += 1
            return out

        for _ in range(4):
            state = external([sbox(f) for f in state])
        for _ in range(56):
            state = internal([sbox(state[0]), *state[1:]])
        for _ in range(4):
            state = external([sbox(f) for f in state])
        assert cursor == 88 and rc[:4] == [0]*4
        outputs = []
        for lane in range(4):
            r = row+264+lane
            assert form(0, r) == state[lane], (row, lane, 'final A')
            assert form(1, r) == {0: 1}, (row, lane, 'final B')
            assert single(matrices[2][r]), (row, lane, 'final C')
            outputs.append(matrices[2][r][0][0])
        if common_rc is None:
            common_rc = rc
        assert rc == common_rc, (row, 'round constants differ')
        blocks.append(dict(row=row, y2=y2, y4=y4, y5=y5, outputs=outputs,
                           initial=[sorted(f.items()) for f in initial]))
        row += 268
    assert len(blocks) == 142
    return dict(vk_sha256=VK_SHA, rows=data['rows'], columns=data['columns'],
                w1_size=data['w1_size'], diagonal=DIAG, round_constants=common_rc,
                blocks=blocks, checked_rows=len(blocks)*268,
                checked_matrix_rows=len(blocks)*268*3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix_dump', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--rust-output', type=Path)
    args = parser.parse_args()
    data = json.loads(args.matrix_dump.read_text())
    result = derive(data)
    encoded = (json.dumps(result, separators=(',', ':'))+'\n').encode()
    args.output.write_bytes(encoded)
    if args.rust_output:
        fe = lambda n: f'ark_ff::MontFp!("{n}")'
        lines = ['// Generated by structured_matrix_plan.py after exact symbolic row checks.',
                 f'// VK SHA-256: {VK_SHA}',
                 'const DIAGONAL: [FieldElement; 4] = [' + ','.join(map(fe, DIAG)) + '];',
                 'const ROUND_CONSTANTS: [FieldElement; 88] = [' + ','.join(map(fe, result['round_constants'])) + '];',
                 'static BLOCKS: [Block; 142] = [']
        for block in result['blocks']:
            lines.append('Block { row: '+str(block['row'])+',')
            for key in ['y2', 'y4', 'y5', 'outputs']:
                lines.append(key+': ['+','.join(map(str, block[key]))+'],')
            lines.append('initial: [')
            for form in block['initial']:
                lines.append('&['+','.join(f'({c},{fe(v)})' for c,v in form)+'],')
            lines.append(']},')
        lines.append('];')
        args.rust_output.write_text('\n'.join(lines)+'\n')
    print(json.dumps({k: result[k] for k in ['vk_sha256', 'checked_rows', 'checked_matrix_rows']} | {
        'blocks':len(result['blocks']), 'bytes':len(encoded),
        'plan_sha256':hashlib.sha256(encoded).hexdigest()}))


if __name__ == '__main__':
    main()
