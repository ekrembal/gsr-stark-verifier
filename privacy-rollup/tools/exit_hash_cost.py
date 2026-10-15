#!/usr/bin/env python3
"""What it costs a Tapleaf 0xC2 Script to check that a note is in the commitment tree.

A Script exit has to recompute the commitment root from a note commitment and its 32 siblings. This tool
generates that check for both note-tree hashes and runs it with `bitcoin-util evalscript`:

poseidon2  the BN254 Poseidon2 node `h3(NODE, left, right, 0)` (t = 4, R_F = 8, R_P = 56) in big-number
           arithmetic; the permutation is one macro, called once per level;
sha256     the tagged SHA-256 node `from_digest(SHA256(T || T || left || right))`, with T the tag hash and the
           top three bits cleared so the node stays a canonical field element.

Both scripts must accept a valid path and reject a path with one flipped sibling; the SHA-256 level must
also keep a node whose first byte masks to zero. Writes
`build/exit-hash-cost.json`.

    python3 tools/exit_hash_cost.py
"""
import hashlib
import json
import random
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "risc0-succinct/tools"))
from gsr import Asm, Script, V, evalscript  # noqa: E402

DEPTH = 32
P = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
NODE_TAG = 6
CONSTANTS = (REPO / "privacy-rollup/tools/poseidon2_constants.rs").read_text()


def parse(name: str) -> list[int]:
    body = CONSTANTS[CONSTANTS.index(f"const {name}"):]
    body = body[:body.index("];\n")]
    return [int(h, 16) for h in re.findall(r'"([0-9a-fA-F]{64})"', body)]


DIAG = parse("INTERNAL_DIAGONAL")
RC = [parse("ROUND_CONSTANTS")[4 * r:4 * r + 4] for r in range(64)]


# ---- references ----

def external(s: list[int]) -> list[int]:
    t0, t1 = s[0] + s[1], s[2] + s[3]
    t2, t3 = 2 * s[1] + t1, 2 * s[3] + t0
    t4, t5 = 4 * t1 + t3, 4 * t0 + t2
    return [(t3 + t5) % P, t5 % P, (t2 + t4) % P, t4 % P]


def permutation(s: list[int]) -> list[int]:
    s = external(s)
    for r in range(64):
        if r < 4 or r >= 60:
            s = external([pow((x + c) % P, 5, P) for x, c in zip(s, RC[r])])
        else:
            s[0] = pow((s[0] + RC[r][0]) % P, 5, P)
            total = sum(s)
            s = [(x * d + total) % P for x, d in zip(s, DIAG)]
    return s


def poseidon2_node(left: int, right: int) -> int:
    return permutation([left, right, 0, NODE_TAG])[0]


# The Noir blackbox vectors of the former `pr_crypto` test.
assert permutation([0, 0, 0, 0])[0] == 0x18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E
assert permutation([0, 1, 2, 3])[2] == 0x04CBB44C61D928ED06808456BF758CBF0C18D1E15A7B6DBC8245FA7515D5E3CB


TAG = hashlib.sha256(b"gsr-privacy-rollup/note-node").digest()


def sha256_node(left: bytes, right: bytes) -> bytes:
    d = bytearray(hashlib.sha256(TAG + TAG + left + right).digest())
    d[0] &= 0x1F
    return bytes(d)


# ---- scripts ----

def le(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "little")


def poseidon2_permutation_body() -> bytes:
    """Macro body: (s0 s1 s2 s3 -- node), all values reduced mod P; only output 0 is kept."""
    a = Asm([V("s0"), V("s1"), V("s2"), V("s3")])
    s = list(a.st)

    def red(v: V) -> V:
        a.roll(v)
        a.push(le(P))
        return a.op("MOD", 2, V("r")).top()

    def matrix(s: list[V]) -> list[V]:
        a.pick(s[0]); a.pick(s[1]); t0 = a.op("ADD", 2, V("t0")).top()          # noqa: E702
        a.pick(s[2]); a.pick(s[3]); t1 = a.op("ADD", 2, V("t1")).top()          # noqa: E702
        a.pick(s[1]); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x"))            # noqa: E702
        a.pick(t1); t2 = a.op("ADD", 2, V("t2")).top()                          # noqa: E702
        a.roll(s[3]); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x"))            # noqa: E702
        a.pick(t0); t3 = a.op("ADD", 2, V("t3")).top()                          # noqa: E702
        a.roll(t1); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x")); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x"))  # noqa: E702,E501
        a.pick(t3); t4 = a.op("ADD", 2, V("t4")).top()                          # noqa: E702
        a.roll(t0); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x")); a.op("DUP", 0, V("x")); a.op("ADD", 2, V("x"))  # noqa: E702,E501
        a.pick(t2); t5 = a.op("ADD", 2, V("t5")).top()                          # noqa: E702
        a.roll(t3); a.pick(t5); n0 = a.op("ADD", 2, V("n0")).top()              # noqa: E702
        a.roll(t2); a.pick(t4); n2 = a.op("ADD", 2, V("n2")).top()              # noqa: E702
        for v in (s[0], s[1], s[2]):
            a.drop(v)
        return [red(n0), red(t5), red(n2), red(t4)]

    def sbox(v: V) -> V:
        a.roll(v)
        a.op("DUP", 0, V("x")); a.op("DUP", 0, V("x")); a.op("MUL", 2, V("x2"))  # noqa: E702
        a.push(le(P)); a.op("MOD", 2, V("x2"))                                  # noqa: E702
        a.op("DUP", 0, V("x")); a.op("MUL", 2, V("x4"))                         # noqa: E702
        a.push(le(P)); a.op("MOD", 2, V("x4"))                                  # noqa: E702
        a.op("MUL", 2, V("x5")); a.push(le(P))                                  # noqa: E702
        return a.op("MOD", 2, V("y")).top()

    def add_constant(v: V, c: int) -> V:
        a.roll(v)
        a.push(le(c))
        a.op("ADD", 2, V("x"))
        a.push(le(P))
        return a.op("MOD", 2, V("x")).top()

    s = matrix(s)
    for r in range(64):
        if r < 4 or r >= 60:
            s = [sbox(add_constant(v, c)) for v, c in zip(s, RC[r])]
            s = matrix(s)
        else:
            s[0] = sbox(add_constant(s[0], RC[r][0]))
            a.pick(s[0]); a.pick(s[1]); a.op("ADD", 2, V("x"))                  # noqa: E702
            a.pick(s[2]); a.op("ADD", 2, V("x")); a.pick(s[3])                  # noqa: E702
            total = a.op("ADD", 2, V("sum")).top()
            out = []
            for v, d in zip(s, DIAG):
                a.roll(v); a.push(le(d)); a.op("MUL", 2, V("x"))                 # noqa: E702
                a.pick(total); a.op("ADD", 2, V("x")); a.push(le(P))             # noqa: E702
                out.append(a.op("MOD", 2, V("s")).top())
            a.drop(total)
            s = out
    for v in s[1:]:
        a.drop(v)
    assert len(a.st) == 1
    return bytes(a.s.code)


# Each level takes (bit sibling node) with the node on top and leaves the parent: `ROT NOTIF SWAP ENDIF`
# orders the pair as (left right), the node being the right child when the bit is set.
ORDER = Script().op("ROT").op("NOTIF").op("SWAP").op("ENDIF")


def path_script(macros: list[bytes], level: int, root: bytes) -> Script:
    """Macro declarations, the level macro called 32 times, then `<root> EQUAL`."""
    s = Script()
    for body in macros:
        s.macro(body)
    for _ in range(DEPTH):
        s.callmacro(level)
    return s.data(root).op("EQUAL")


def poseidon2_script(root: int) -> Script:
    level = Script().extend(ORDER).int(0).int(NODE_TAG).callmacro(0)
    return path_script([poseidon2_permutation_body(), bytes(level.code)], 1, le(root))


def sha256_level() -> Script:
    level = Script().extend(ORDER).op("CAT").data(TAG + TAG).op("SWAP").op("CAT").op("SHA256")
    # Clear the top three bits of the first byte. Numbers are little-endian, so `(d[0] & 0x1f) + 0x100`
    # keeps a second byte and its first byte survives `1 LEFT` even when it is zero.
    level.op("DUP").int(1).op("LEFT").data(b"\x1f").op("AND").data(b"\x00\x01").op("ADD").int(1).op("LEFT")
    return level.op("SWAP").int(1).int(31).op("SUBSTR").op("CAT")


def sha256_script(root: bytes) -> Script:
    return path_script([bytes(sha256_level().code)], 0, root)


def witness(leaf: bytes, siblings: list[bytes], index: int) -> list[bytes]:
    """Bottom to top: level 31's (bit, sibling) ... level 0's, then the leaf on top."""
    items = []
    for i in reversed(range(DEPTH)):
        items += [b"\x01" if (index >> i) & 1 else b"", siblings[i]]
    return items + [leaf]


def run(name: str, script: Script, items: list[bytes]) -> dict:
    bad = list(items)
    bad[-2] = bytes([bad[-2][0] ^ 1]) + bad[-2][1:]  # level 0's sibling
    ok, rejected = evalscript(script, items), evalscript(script, bad)
    assert ok["success"], (name, ok["error"])
    assert not rejected["success"], name
    return {"script_bytes": len(script.code), "witness_bytes": sum(len(x) for x in items),
            "varops": ok["varops"], "rejects_bad_sibling": True}


def main() -> None:
    rng = random.Random(7)
    index = rng.randrange(1 << DEPTH)
    report = {}

    leaf = rng.randrange(P)
    sib = [rng.randrange(P) for _ in range(DEPTH)]
    node = leaf
    for i in range(DEPTH):
        node = poseidon2_node(sib[i], node) if (index >> i) & 1 else poseidon2_node(node, sib[i])
    items = witness(le(leaf), [le(x) for x in sib], index)
    report["poseidon2"] = {**run("poseidon2", poseidon2_script(node), items),
                           "permutation_macro_bytes": len(poseidon2_permutation_body())}

    leaf_b = bytes([rng.randrange(32)]) + bytes(rng.randrange(256) for _ in range(31))
    sib_b = [bytes([rng.randrange(32)]) + bytes(rng.randrange(256) for _ in range(31)) for _ in range(DEPTH)]
    node_b = leaf_b
    for i in range(DEPTH):
        node_b = sha256_node(sib_b[i], node_b) if (index >> i) & 1 else sha256_node(node_b, sib_b[i])
    items = witness(leaf_b, sib_b, index)
    report["sha256"] = {**run("sha256", sha256_script(node_b), items),
                        "level_macro_bytes": len(sha256_level().code)}
    # A node whose first byte masks to zero (1 in 32) must stay 32 bytes.
    right = next(x.to_bytes(32, "little") for x in range(1 << 16)
                 if sha256_node(bytes(32), x.to_bytes(32, "little"))[0] == 0)
    one = Script().extend(sha256_level()).data(sha256_node(bytes(32), right)).op("EQUAL")
    assert evalscript(one, [b"\x01", bytes(32), right])["success"]
    out = REPO / "build/exit-hash-cost.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
