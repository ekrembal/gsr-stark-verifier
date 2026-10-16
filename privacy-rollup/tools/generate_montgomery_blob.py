#!/usr/bin/env python3
"""Generate the fixed BN254 Fr Montgomery BigInt2 experiment, without an AIR change.

The verifier enforces a*b + p*R = q*p + r*R over integers represented by byte
polynomials; Rust additionally enforces r < p. R=2**256 and gcd(R,p)=1.
Witness generation is not trusted. Only the verifier program plus canonicality
establishes the output. Layout follows pinned RISC Zero 3.0.6 BIBC and BigInt2.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
R = 1 << 256
BABY_BEAR = 2013265921


def build(terms=1):
    assert terms in (1, 4, 32)
    # Machine register arenas: a1=x11, a2=x12, result=a3=x13;
    # temporary stack=x2 (48 bytes), constants=t3=x28 (176 bytes).
    consts = P.to_bytes(32, 'little') + pow(R, -1, P).to_bytes(32, 'little')
    consts += (P*R).to_bytes(64, 'little') + R.to_bytes(48, 'little')
    types = [(32, 255, 0, 0), (48, 255, 0, 0),
             (63, 32*255**2, 0, 0), (64 if terms == 1 else 66, terms*32*255**2+255, 255, 0),
             (64, 255, 0, 0)]
    ops = []

    def op(code, typ, a, b=0):
        assert 0 <= a < 2**24 and 0 <= b < 2**24
        ops.append(code | typ << 4 | a << 16 | b << 40)
        return len(ops)-1

    def load(typ, reg, offset):
        return op(3, typ, reg << 16 | offset)

    a, b = load(0, 11, 0), load(0, 12, 0)
    p, rinv, pr, radix = load(0, 28, 0), load(0, 28, 2), load(4, 28, 4), load(1, 28, 8)
    ab = op(10, 2, a, b)
    for index in range(1, terms):
        a, b = load(0, 11, 2*index), load(0, 12, 2*index)
        ab = op(8, 3, ab, op(10, 2, a, b))
    t = op(11, 0, ab, p)
    r = op(11, 0, op(10, 2, t, rinv), p)
    numerator = op(9, 3, op(8, 3, ab, pr), op(10, 4, r, radix))
    q = op(12, 1, numerator, p)
    op(4, 1, 2 << 16, q)
    op(4, 0, 13 << 16, r)
    nondet = b'bibc' + struct.pack('<5I', 1, 0, len(types), 0, len(ops))
    nondet += b''.join(struct.pack('<4Q', *t) for t in types)
    nondet += struct.pack('<'+'Q'*len(ops), *ops)
    verify = []

    def atom(reg, offset, chunks, final, coefficient, write=False):
        for i in reversed(range(chunks)):
            poly_op = (3 if final else 2) if i == 0 else 1
            verify.append(int(write) << 28 | poly_op << 24 | (coefficient+4) << 21 | reg << 16 | offset+i)

    # Inputs are read before writing output, including when a and r alias.
    for index in range(terms):
        atom(11, 2*index, 2, False, 1)
        atom(12, 2*index, 2, True, 1)
    atom(2, 0, 3, False, -1, True)
    atom(28, 0, 2, True, -1)
    atom(13, 0, 2, False, -1, True)
    atom(28, 8, 3, True, -1)
    atom(28, 4, 4, True, 1)
    # q has 48 bytes; q*p therefore has 79 coefficients. Pad to 80.
    for chunk in reversed(range(5)):
        for poly_op in (4, 5, 1 if chunk else 6):
            verify.append(2 << 28 | poly_op << 24 | chunk)
    verify.append(2 << 28)  # Return only after EqZero.
    # Absolute coefficient bound, including adversarial byte-range q witnesses.
    # Inputs/output/q are byte constrained by the unchanged BigInt2 memory circuit.
    magnitude = (terms+1)*32*255**2 + 2*255
    carry_bound = (magnitude+254)//255
    # Honest carry generation uses a 22-bit encoding centered at 2**21.
    assert carry_bound < 2**21
    # No BabyBear coefficient wraparound can disguise a nonzero integer residue.
    # Include even the largest representable signed carry, not just honest carries.
    # The pinned v2 circuit byte-constrains Carry2's byte, not just six bits.
    # Therefore use its full 0..255 range for an untrusted carry witness.
    adversarial_carry_bound = 127*16384 + 255*256 + 255
    assert magnitude + 257*adversarial_carry_bound < BABY_BEAR
    header = struct.pack('<4I', len(nondet)//4, len(verify), len(consts)//4, 12)
    blob = header + nondet + struct.pack('<'+'I'*len(verify), *verify) + consts
    return blob, dict(terms=terms, verifier_instructions=len(verify), syscall_cycles=len(verify)+1,
                      temporary_bytes=48, constant_bytes=len(consts),
                      polynomial_coefficients=80, coefficient_magnitude_bound=magnitude,
                      honest_carry_magnitude_bound=carry_bound,
                      circuit_carry_magnitude_bound=adversarial_carry_bound)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--terms', type=int, choices=[1, 4, 32], default=1)
    args = parser.parse_args()
    blob, facts = build(args.terms)
    # Independent integer identity checks; these are tests, not a circuit proof.
    rng = random.Random(0x424e323534)
    boundaries = [0, 1, 2, P-2, P-1, R-1]
    pairs = [(a, b) for a in boundaries for b in boundaries]
    pairs += [(rng.randrange(R), rng.randrange(R)) for _ in range(10000)]
    for index, (a, b) in enumerate(pairs):
        dot = a*b
        if args.terms > 1:
            dot = args.terms*a*b if index < len(boundaries)**2 else dot + sum(rng.randrange(R)*rng.randrange(R) for _ in range(args.terms-1))
        r = (dot*pow(R, -1, P)) % P
        numerator = dot+P*R-r*R
        assert numerator >= 0 and numerator % P == 0
        q = numerator//P
        assert q < 2**384 and dot+P*R-q*P-r*R == 0 and 0 <= r < P
    words = struct.unpack('<'+'I'*(len(blob)//4), blob)
    # A u32 array supplies the required alignment without a new dependency.
    code = '// Generated by privacy-rollup/tools/generate_montgomery_blob.py.\n'
    code += '// Experimental BN254 Fr kernel; see reports/fused-bigint2-feasibility.md.\n'
    symbol = 'BN254_MONT_BLOB' if args.terms == 1 else f'BN254_MONT_DOT{args.terms}_BLOB'
    code += f'static {symbol}: [u32; {len(words)}] = [\n'
    for i in range(0, len(words), 8):
        code += '    ' + ', '.join(f'0x{x:08x}' for x in words[i:i+8]) + ',\n'
    code += '];\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(code)
    print(json.dumps(dict(facts, bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                         integer_cases=len(pairs)), indent=2))


if __name__ == '__main__':
    main()
