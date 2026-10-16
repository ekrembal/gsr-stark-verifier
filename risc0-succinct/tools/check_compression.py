#!/usr/bin/env python3
"""Check that macro compression does not change how the verifier operates.

The reusable-macros BIP states that a well-formed committed script and its unrolled script give the same result,
final stack and opcode positions for any initial stack and transaction context, except for (1) anything that commits
to the script bytes (Tapleaf hash, signature messages, OP_TX CURRENT_TAPSCRIPT), (2) the weight-funded varops budget
and (3) the unrolling charge. This tool checks the premises and the conclusion for the RISC Zero verifier:

static   with a decoder written from the BIP (not compress.unroll): the compressed scripts are well formed
         (declarations first, canonical CompactSize, references only to earlier declarations), every declaration is
         reachable, the unrolled script equals the uncompressed one byte for byte, and neither contains OP_SUCCESSx,
         OP_CODESEPARATOR, a signature opcode or an OP_TX read of a field that depends on the script bytes, so
         exception (1) cannot apply (fixed-statement and covenant verifiers);
rollup   the settlement leaf reads its own script (exception 1) and compensates with the declarations' length: the
         unrolled plain and compressed leaves differ only in the two splice offsets, by exactly that length;
dynamic  with the node's own unroller and interpreter (bitcoin-util evalscript, and gsr-meter for the position):
         the fully inline, the plain and the compressed fixed-statement verifiers give the same success, error,
         final stack and position of the last executed instruction in the unrolled script on the valid witness and
         on mutated witnesses, and each one's varops exceed the inline script's by exactly its unrolling charge (a
         failing script pays only its unrolling: execution charges are deducted when the script ends);
regtest  plain and compressed covenant spends with the committed receipt, valid and mutated, get the same
         testmempoolaccept verdict and reject reason under standard policy.

    python3 check_compression.py [--cases N]     writes build/compression-check.json
"""
import argparse
import hashlib
import json
import random
import subprocess
import sys

import compress
import covenant as cv
import generate as g
import gsr
import measure
import reference as ref
from gsr import OPS, Script

ROOT = g.ROOT
OP_MACRO, OP_CALLMACRO = OPS["MACRO"], OPS["CALLMACRO"]
BASE, WRITE_FIXED, WRITE_PER_BYTE = 300, 800, 7  # BIP 440
FORBIDDEN = {0xAB: "OP_CODESEPARATOR", 0xAC: "OP_CHECKSIG", 0xAD: "OP_CHECKSIGVERIFY", 0xBA: "OP_CHECKSIGADD",
             0xCC: "OP_CHECKSIGFROMSTACK"}


# ---- static: an independent decoder ----

def read_compact(b: bytes, i: int) -> tuple[int, int]:
    p = b[i]
    if p < 0xFD:
        return p, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[p]
    v = int.from_bytes(b[i + 1:i + 1 + w], "little")
    assert v >= {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[p], "non-canonical CompactSize"
    return v, i + 1 + w


def instructions(b: bytes, start: int, end: int):
    """(opcode, begin, end, reference index or None) for one body or the main script."""
    i = start
    while i < end:
        op, begin = b[i], i
        i += 1
        idx = None
        if op == OP_CALLMACRO:
            idx, i = read_compact(b, i)
        elif 1 <= op <= 0x4B:
            i += op
        elif op in (0x4C, 0x4D, 0x4E):
            w = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            i += w + int.from_bytes(b[i:i + w], "little")
        assert i <= end, "instruction crosses its body"
        yield op, begin, i, idx


def decode(b: bytes) -> tuple[list[tuple[int, int]], tuple[int, int]]:
    bodies, i = [], 0
    while i < len(b) and b[i] == OP_MACRO:
        n, j = read_compact(b, i + 1)
        assert j + n <= len(b)
        for op, _, _, idx in instructions(b, j, j + n):
            assert op != OP_MACRO, "OP_MACRO inside a body"
            assert idx is None or idx < len(bodies), "reference to a later declaration"
        bodies.append((j, j + n))
        i = j + n
    for op, _, _, idx in instructions(b, i, len(b)):
        assert op != OP_MACRO, "OP_MACRO after the declarations"
        assert idx is None or idx < len(bodies), "reference to an undeclared body"
    return bodies, (i, len(b))


def unroll(b: bytes) -> tuple[bytes, dict]:
    """The unrolled script and the BIP's totals: substituted instructions, references visited, reachable bodies."""
    bodies, main = decode(b)
    out, tot, seen = bytearray(), {"substituted": 0, "references": 0}, set()

    def emit(rng: tuple[int, int], depth: int) -> None:
        for op, begin, end, idx in instructions(b, *rng):
            if idx is not None:
                tot["references"] += 1
                seen.add(idx)
                emit(bodies[idx], depth + 1)
            else:
                out.extend(b[begin:end])
                if depth:
                    tot["substituted"] += 1
    emit(main, 0)
    tot["declarations"], tot["reachable"] = len(bodies), len(seen)
    return bytes(out), tot


def unrolling_charge(b: bytes) -> int:
    u, t = unroll(b)
    if not t["declarations"]:
        return 0
    return BASE * (t["substituted"] + t["references"]) + WRITE_FIXED + WRITE_PER_BYTE * ((len(u) + 7) // 8 * 8)


# OP_TX fields whose value depends on the committed script bytes: TX_WEIGHT; CURRENT_TAPSCRIPT, CURRENT_TAPLEAF_HASH,
# CURRENT_CONTROL_BLOCK (its parity bit), CURRENT_TAPTREE_ROOT; INPUT_PREVOUT_SCRIPTPUBKEY, INPUT_WITNESS_ITEMS.
SCRIPT_DEPENDENT = {1: 0x08, 2: 0x04 | 0x08 | 0x10 | 0x40, 4: 0x08 | 0x80}


def op_tx_selectors(code: bytes) -> list[bytes | None]:
    """The selector of every OP_TX, or None when it is not a constant pushed right before it."""
    out, prev = [], None
    for op, s, e, _ in instructions(code, 0, len(code)):
        if op == OPS["TX"]:
            out.append(code[s - 6:s] if prev == (s - 7, 6) else None)
        prev = (s, op)
    return out


def static_checks(plain: bytes, comp: bytes) -> dict:
    up, tp = unroll(plain)
    uc, tc = unroll(comp)
    found = {}
    for op, _, _, _ in instructions(up, 0, len(up)):
        if op in FORBIDDEN or gsr.is_op_success(op):
            found[FORBIDDEN.get(op, hex(op))] = found.get(FORBIDDEN.get(op, hex(op)), 0) + 1
    sels = op_tx_selectors(up)
    dependent = [None if x is None else x.hex() for x in sels
                 if x is None or any(x[b] & m for b, m in SCRIPT_DEPENDENT.items())]
    return {"plain_bytes": len(plain), "compressed_bytes": len(comp), "unrolled_bytes": len(up),
            "unrolled_identical": up == uc,
            "declarations": {"plain": tp["declarations"], "compressed": tc["declarations"]},
            "all_declarations_reachable": tc["reachable"] == tc["declarations"],
            "forbidden_or_success_opcodes": found, "op_tx_selectors": sorted({x.hex() for x in sels if x}),
            "script_dependent_op_tx": dependent,
            "unrolling_charge": {"plain": unrolling_charge(plain), "compressed": unrolling_charge(comp)}}


def rollup_checks() -> dict:
    sys.path.insert(0, str(ROOT.parent / "privacy-rollup/tools"))
    import rollup_covenant as rc
    template = json.loads((ROOT.parent / "privacy-rollup/fixtures/apply-batch/receipt-template.json").read_text())
    rollup_id, root = hashlib.sha256(b"rollup id").digest(), hashlib.sha256(b"root").digest()
    leaves = {k: rc.Covenant(template, rollup_id, root, compressed=c)
              for k, c in (("plain", False), ("compressed", True))}
    ins = {}
    for k, leaf in leaves.items():
        u = unroll(leaf.script)[0]
        ins[k] = [u[s:e] for _, s, e, _ in instructions(u, 0, len(u))]
    diff = [(a, c) for a, c in zip(ins["plain"], ins["compressed"]) if a != c]
    expected = [tuple(bytes(Script().int(off + leaf.decl_len).code) for leaf in leaves.values())
                for off in (rc.CS_PREFIX, rc.ROOT_END)]
    return {"bytes": {k: len(v.script) for k, v in leaves.items()},
            "decl_len": {k: v.decl_len for k, v in leaves.items()},
            "instructions": {k: len(v) for k, v in ins.items()}, "differences": [(a.hex(), c.hex()) for a, c in diff],
            "only_splice_offsets_differ": len(ins["plain"]) == len(ins["compressed"]) and diff == expected}


# ---- dynamic: the node interpreter ----

def mutate(stack: list[bytes], rng: random.Random) -> tuple[str, list[bytes]]:
    s = list(stack)
    k = rng.randrange(len(s))
    kind = rng.choice(["flip", "flip", "flip", "truncate", "extend", "empty", "swap", "zero", "drop_top", "extra"])
    if kind == "flip" and s[k]:
        p = rng.randrange(len(s[k]))
        s[k] = s[k][:p] + bytes([s[k][p] ^ (1 << rng.randrange(8))]) + s[k][p + 1:]
    elif kind == "truncate" and s[k]:
        s[k] = s[k][:-1]
    elif kind == "extend":
        s[k] = s[k] + b"\x00"
    elif kind == "empty":
        s[k] = b""
    elif kind == "swap" and k + 1 < len(s):
        s[k], s[k + 1] = s[k + 1], s[k]
    elif kind == "zero":
        s[k] = bytes(len(s[k]))
    elif kind == "drop_top":
        s = s[:-1]
    elif kind == "extra":
        s = s + [b"\x01"]
    return f"{kind}@{k}", s


def run(code: bytes, stack: list[bytes]) -> dict:
    sc = Script()
    sc.code = bytearray(code)
    r = gsr.evalscript(sc, stack)
    e = measure.meter({"script": code.hex(), "witness": [x.hex() for x in stack]})
    return {"success": r["success"], "error": r["error"], "stack": r["stack-after"], "varops": r["varops"],
            "pc": e["pc"], "meter_agrees": (e["ok"], e["varops"]) == (r["success"], r["varops"])}


def dynamic_checks(plain: bytes, comp: bytes, witness: list[bytes], cases: int) -> dict:
    inline = unroll(plain)[0]
    charge = {"plain": unrolling_charge(plain), "compressed": unrolling_charge(comp)}
    rng = random.Random(0x6773722D)
    inputs = [("valid", witness)] + [mutate(witness, rng) for _ in range(cases)]
    mismatches, outcomes, positions = [], {}, set()
    for name, stack in inputs:
        r = {k: run(c, stack) for k, c in (("inline", inline), ("plain", plain), ("compressed", comp))}
        keys = ("success", "error", "stack", "pc")
        same = all([r[k][x] for x in keys] == [r["inline"][x] for x in keys] and r[k]["meter_agrees"] for k in r)
        exact = all(r[k]["varops"] - r["inline"]["varops"] == charge[k] for k in ("plain", "compressed"))
        if not (same and exact):
            mismatches.append({"case": name, **{k: {x: r[k][x] for x in ("success", "error", "varops", "pc")}
                                                for k in r}})
        key = "valid" if r["inline"]["success"] else str(r["inline"]["error"])
        outcomes[key] = outcomes.get(key, 0) + 1
        positions.add(r["inline"]["pc"])
    return {"cases": len(inputs), "outcomes": outcomes, "distinct_positions": len(positions), "mismatches": mismatches,
            "valid_varops": {k: run(c, witness)["varops"] for k, c in
                             (("inline", inline), ("plain", plain), ("compressed", comp))}}


# ---- regtest: consensus and standard policy ----

def regtest_checks(covs: dict, receipt: dict, seal: bytes, cases: int) -> dict:
    datadir = ROOT / "build/regtest-compression-check"
    subprocess.run(["rm", "-rf", str(datadir)], check=True)
    datadir.mkdir(parents=True)
    subprocess.run([str(cv.BITCOIN_BUILD / "bin/bitcoind"), "-regtest", f"-datadir={datadir}", "-daemonwait",
                    "-server", "-listen=0", "-rpcport=19482", "-port=19483", "-vbparams=tapleaf_0xc2:0:3999999999"],
                   check=True)

    def rpc(method, *args):
        cmd = [str(cv.BITCOIN_BUILD / "bin/bitcoin-cli"), "-regtest", f"-datadir={datadir}", "-rpcport=19482",
               method, *[a if isinstance(a, str) else json.dumps(a) for a in args]]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out.strip()

    try:
        funding = {}
        for k, c in covs.items():
            addr = cv.output_key_to_p2tr(c.taproot.output_pubkey)
            block = rpc("generatetoaddress", 1, addr)[0]
            cb = rpc("getblock", block, 2)["tx"][0]
            funding[k] = (cb["txid"], next(i for i, o in enumerate(cb["vout"])
                                           if o["scriptPubKey"]["hex"] == c.taproot.scriptPubKey.hex()))
        rpc("generatetoaddress", 101, cv.output_key_to_p2tr(covs["plain"].taproot.output_pubkey))
        while rpc("getdeploymentinfo")["deployments"]["tapleaf_0xc2"]["bip9"]["status"] != "active":
            rpc("generatetoaddress", 144, cv.output_key_to_p2tr(covs["plain"].taproot.output_pubkey))

        rng = random.Random(0x72656774)
        n_items = len(cv.g.build_witness(covs["plain"].gen, receipt, seal, covs["plain"].hints))
        variants = [("valid", None), ("output_value_minus_1", "value"), ("extra_output", "extra"),
                    ("sequence_0xfffffffe", "sequence"), ("locktime_1", "locktime")]
        variants += [(f"flip_item_{rng.randrange(n_items)}", "flip") for _ in range(cases)]
        rows = {}
        for name, kind in variants:
            row = {}
            for k, c in covs.items():
                tx = c.tx(*funding[k])
                if kind == "value":
                    tx.vout[0].nValue -= 1
                elif kind == "extra":
                    tx.vout.append(cv.CTxOut(0, cv.CScript(bytes([0x6A, 1, 0]))))
                elif kind == "sequence":
                    tx.vin[0].nSequence = 0xFFFFFFFE
                elif kind == "locktime":
                    tx.nLockTime = 1
                c.spend(tx)
                if kind == "flip":
                    i = int(name.rsplit("_", 1)[1])
                    st = tx.wit.vtxinwit[0].scriptWitness.stack
                    st[i] = st[i][:-1] + bytes([st[i][-1] ^ 1]) if st[i] else b"\x01"
                a = rpc("testmempoolaccept", [tx.serialize().hex()])[0]
                row[k] = {"allowed": a["allowed"], "reason": a.get("reject-reason"), "weight": tx.get_weight()}
            row["same_verdict"] = (row["plain"]["allowed"], row["plain"]["reason"]) == \
                                  (row["compressed"]["allowed"], row["compressed"]["reason"])
            rows[name] = row
        return {"spends": rows, "all_same": all(r["same_verdict"] for r in rows.values()),
                "valid_accepted": rows["valid"]["plain"]["allowed"] and rows["valid"]["compressed"]["allowed"]}
    finally:
        rpc("stop")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=200, help="mutated witnesses for the interpreter check")
    ap.add_argument("--regtest-cases", type=int, default=12, help="mutated witness items for the regtest check")
    args = ap.parse_args()
    receipt = json.loads((ROOT / "fixtures/receipt.json").read_text())
    seal = (ROOT / "fixtures/seal.bin").read_bytes()
    gen = g.Gen(g.Statement(receipt), ref.load_circuit())
    first = gen.generate()[1]
    plain = bytes(gen.generate(first["accesses"], first["pool"])[0].code)
    comp, stats = compress.compress(plain)
    witness = g.build_witness(gen, receipt, seal)

    cr = json.loads((ROOT / "fixtures/covenant-receipt.json").read_text())
    cs = (ROOT / "fixtures/covenant-seal.bin").read_bytes()
    covs = {"plain": cv.Covenant(cr, cs), "compressed": cv.Covenant(cr, cs, compressed=True)}

    report = {"compression": stats, "static": {"fixed": static_checks(plain, comp),
                                               "covenant": static_checks(covs["plain"].script,
                                                                         covs["compressed"].script)}}
    print(json.dumps(report["static"]), flush=True)
    report["rollup"] = rollup_checks()
    print(json.dumps(report["rollup"]), flush=True)
    report["dynamic"] = dynamic_checks(plain, comp, witness, args.cases)
    print(json.dumps({k: v for k, v in report["dynamic"].items() if k != "mismatches"}),
          "mismatches:", len(report["dynamic"]["mismatches"]), flush=True)
    report["regtest"] = regtest_checks(covs, cr, cs, args.regtest_cases)
    d, r = report["dynamic"], report["regtest"]
    report["ok"] = (all(s["unrolled_identical"] and s["all_declarations_reachable"]
                        and not s["forbidden_or_success_opcodes"] and not s["script_dependent_op_tx"]
                        for s in report["static"].values())
                    and report["rollup"]["only_splice_offsets_differ"]
                    and not d["mismatches"] and r["all_same"] and r["valid_accepted"])
    out = ROOT / "build/compression-check.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1))
    print(json.dumps({"regtest_all_same": r["all_same"], "valid_accepted": r["valid_accepted"], "ok": report["ok"]}))


if __name__ == "__main__":
    main()
