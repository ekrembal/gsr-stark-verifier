#!/usr/bin/env python3
"""Differential tests: RISC Zero's native verifier vs. the Python reference vs. the generated Script.

The valid padded-SHA fixture must be accepted by all three -- the Script inside a complete Taproot spend metered by
the pinned Core interpreter -- and must produce the same intermediate values natively and in the reference. Every
negative case must be rejected by all three.

    python3 differential.py [--quick]     # --quick: standalone evalscript instead of the full transaction meter
"""
import argparse
import copy
import functools
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable

import babybear as bb
import generate as g
import measure
import reference as ref
import run
from babybear import P

ROOT = Path(__file__).resolve().parents[1]
RISC0 = Path(os.environ.get("RISC0_DIR", Path.home() / "risc0"))
BUILD = ROOT / "build/test"


@functools.cache
def native_binary() -> Path:
    """The risc0-zkvm lib test binary (built once by `cargo test --no-run`) that holds `gsr_verify_file`."""
    proc = subprocess.run(["cargo", "test", "--release", "-p", "risc0-zkvm", "--features", "prove", "--lib",
                           "--no-run", "--message-format=json"], cwd=RISC0, capture_output=True, text=True, check=True)
    for line in proc.stdout.splitlines():
        msg = json.loads(line)
        if msg.get("reason") == "compiler-artifact" and msg["target"]["name"] == "risc0_zkvm" and msg.get("executable"):
            return Path(msg["executable"])
    raise RuntimeError("risc0-zkvm test binary not found")


def native(receipt: dict, seal: bytes, trace: bool = False) -> tuple[bool, str, list[str]]:
    BUILD.mkdir(parents=True, exist_ok=True)
    rp, sp = BUILD / "receipt.json", BUILD / "seal.bin"
    rp.write_text(json.dumps(receipt))
    sp.write_bytes(seal)
    env = dict(os.environ, R0_GSR_RECEIPT=str(rp), R0_GSR_SEAL=str(sp))
    if trace:
        env["R0_GSR_TRACE"] = "1"
    proc = subprocess.run([str(native_binary()), "gsr_verify_file", "--ignored", "--nocapture"],
                          cwd=RISC0, env=env, capture_output=True, text=True)
    line = next((x for x in proc.stdout.splitlines() if x.startswith("NATIVE_")), None)
    if line is None:
        raise RuntimeError(proc.stdout + proc.stderr)
    return line == "NATIVE_OK", line, [x for x in proc.stderr.splitlines() if x.startswith("GSR_TRACE ")]


def reference(receipt: dict, seal: bytes) -> tuple[bool, str]:
    try:
        ref.verify_receipt(receipt, seal)
        return True, "REFERENCE_OK"
    except ref.VerifyError as err:
        return False, f"REFERENCE_ERR {err}"


def script(bundle: dict, quick: bool) -> tuple[bool, str]:
    if quick:
        r = run.run(bundle)
        return bool(r["success"]), str(r["error"])
    e = measure.meter(bundle)
    ok = all(measure.limits(bundle, e).values())
    return ok, f"{e['error']} varops={e['varops']} weight={e['transaction_weight']}"


def mont(ext) -> list[int]:
    return [bb.to_mont(c) for c in ext]


def compare_traces(lines: list[str], t: dict) -> list[str]:
    """Native Montgomery-word intermediates vs. the reference trace; returns mismatching keys."""
    native_vals: dict[str, list] = {}
    for line in lines:
        _, key, words = line.split(" ", 2) if line.count(" ") == 2 else (*line.split(" "), "")
        native_vals.setdefault(key, []).append([int(w, 16) for w in words.split(",") if w])
    root = lambda h: list(struct.unpack("<8I", bytes.fromhex(h)))  # noqa: E731
    names = {ref.GROUP_ACCUM: "accum", ref.GROUP_CODE: "code", ref.GROUP_DATA: "data"}
    want = {
        "out": [[bb.to_mont(o) for o in t["out"]] + [t["po2"]]],
        "mix": [[bb.to_mont(m) for m in t["mix"]]],
        "poly_mix": [mont(t["poly_mix"])], "z": [mont(t["z"])], "result": [mont(t["result"])],
        "check_poly": [mont(t["check"])], "check": [root(t["check_root"])], "fri_mix": [mont(t["fri_mix"])],
        "round_mix": [mont(m) for m in t["fri_round_mix"]],
        "pos": [[q["pos"]] for q in t["queries"]],
        "goal": [mont(goal) for q in t["queries"] for goal in q["goals"]],
    }
    for gid, name in names.items():
        want[name] = [root(t["roots"][gid])]
    bad = [k for k in want if native_vals.get(k) != want[k]]
    bad += [k for k in native_vals if k not in want]
    return bad


def bundle_for(receipt: dict, witness: list[bytes], cache: dict) -> dict:
    """Script specialized to `receipt`'s statement (cached per statement) paired with `witness`."""
    st = g.Statement(receipt)
    key = (st.control_id, st.control_root, st.inner_control_root, st.claim_digest)
    if key not in cache:
        gen = g.Gen(st, ref.load_circuit())
        first = gen.generate()[1]
        cache[key] = (gen.generate(first["accesses"], first["pool"])[0].code.hex(), first["functions"])
    code, functions = cache[key]
    return {"script": code, "witness": [w.hex() for w in witness], "info": {"functions": functions}}


def flip(seal: bytes, word: int, value: Callable[[int], int] | None = None) -> bytes:
    b = bytearray(seal)
    old = struct.unpack_from("<I", b, 4 * word)[0]
    struct.pack_into("<I", b, 4 * word, old ^ 1 if value is None else value(old))
    return bytes(b)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    receipt = json.loads((ROOT / "fixtures/receipt.json").read_text())
    seal = (ROOT / "fixtures/seal.bin").read_bytes()
    gen = g.Gen(g.Statement(receipt), ref.load_circuit())
    hints = g.prover_hints(gen, receipt, seal)
    cache: dict = {}
    failures = []

    # Positive case, with native/reference intermediate differential.
    ok_n, msg_n, lines = native(receipt, seal, trace=True)
    t: dict = {}
    ref.verify_receipt(receipt, seal, t)
    bad = compare_traces(lines, t)
    ok_s, msg_s = script(bundle_for(receipt, g.build_witness(gen, receipt, seal, hints), cache), args.quick)
    print(f"valid: native={msg_n} reference=REFERENCE_OK script={ok_s} ({msg_s}) "
          f"trace_values={len(lines)} trace_mismatches={bad}")
    if not (ok_n and ok_s) or bad:
        failures.append("valid")

    # Seal offsets of the canonical layout.
    lay = gen.layout
    w_code_top = 33
    w_coeff = 33 + 4 * 8 * g.TRACE_TOP
    w_fri_top = w_coeff + lay.coeff_words
    w_final = w_fri_top + 3 * 8 * 32
    w_q0 = w_final + 4 * 64
    q_words = sum(lay.rows.values()) + 4 * 8 * g.TRACE_LEVELS + 3 * 64 + 8 * sum(g.FRI_LEVELS)
    w_q49_last = w_q0 + 50 * q_words - 1
    row0 = w_q0 + lay.rows["accum"] // 2
    fits = lambda w: struct.unpack_from("<I", seal, 4 * w)[0] < (1 << 32) - P  # noqa: E731
    nc_row = next(w for w in range(w_q0, w_q0 + lay.rows["accum"]) if fits(w))
    nc_coeff = next(w for w in range(w_coeff, w_coeff + 64) if fits(w))

    seal_cases = {
        "tampered_out": flip(seal, 5),
        "tampered_po2": flip(seal, 32),
        "tampered_code_top": flip(seal, w_code_top + 3),
        "tampered_coeff": flip(seal, w_coeff + 100),
        "tampered_fri_top": flip(seal, w_fri_top + 7),
        "tampered_final_poly": flip(seal, w_final + 11),
        "tampered_query0_trace_row": flip(seal, row0),
        "tampered_query0_trace_path": flip(seal, w_q0 + sum(lay.rows.values())),
        "tampered_query49_fri_path": flip(seal, w_q49_last),
        "noncanonical_query_row": flip(seal, nc_row, lambda x: x + P),
        "noncanonical_coeff": flip(seal, nc_coeff, lambda x: x + P),
        "malformed_field_ffffffff": flip(seal, row0, lambda x: 0xFFFFFFFF),
    }
    for name, s in seal_cases.items():
        cases_s = bundle_for(receipt, g.build_witness(gen, receipt, s, hints), cache)
        check(failures, name, native(receipt, s), reference(receipt, s), script(cases_s, args.quick))

    base_witness = g.build_witness(gen, receipt, seal, hints)
    for name, s, mutate in [
        ("truncated_seal", seal[:-4], lambda w: [w[0][:-4]] + w[1:]),
        ("surplus_seal_word", seal + bytes(4), lambda w: [bytes(4)] + w),
        ("surplus_bytes_in_item", seal + bytes(4), lambda w: [w[0] + bytes(4)] + w[1:]),
        ("unaligned_seal", seal + b"\0", lambda w: [w[0] + b"\0"] + w[1:]),
    ]:
        check(failures, name, native(receipt, s), reference(receipt, s),
              script(bundle_for(receipt, mutate(list(base_witness)), cache), args.quick))

    def with_claim(**changes) -> dict:
        r = copy.deepcopy(receipt)
        r["claim"].update(changes)
        r["claim_digest"] = ref.claim_digest(r["claim"]).hex()
        return r

    other_journal = hashlib.sha256(b"not the journal").digest()
    receipt_cases = {
        "control_id_mismatch": dict(control_id="11" * 32),
        "control_root_mismatch": dict(control_root="22" * 32),
        "inner_control_root_mismatch": dict(inner_control_root="33" * 32),
        "claim_digest_mismatch": dict(claim_digest="44" * 32),
    }
    metadata = [(k, {**receipt, **v}) for k, v in receipt_cases.items()]
    r = copy.deepcopy(receipt)
    r["control_inclusion_proof"]["index"] = 1
    metadata.append(("control_inclusion_index_mismatch", r))
    r = copy.deepcopy(receipt)
    r["control_inclusion_proof"]["digests"][3] = "55" * 32
    metadata.append(("control_inclusion_path_mismatch", r))
    metadata.append(("journal_mismatch", with_claim(
        output=ref.output_digest(other_journal, bytes(32)).hex(), journal_digest=other_journal.hex())))
    metadata.append(("termination_sys_exit_paused", with_claim(sys_exit=1)))
    metadata.append(("termination_user_exit_nonzero", with_claim(user_exit=1)))
    metadata.append(("assumptions_nonempty", with_claim(output=ref.output_digest(
        bytes.fromhex(receipt["claim"]["journal_digest"]), b"\x66" * 32).hex())))
    for name, r in metadata:
        # The Script is specialized to the expected statement: the verifier for `r` runs on the honest witness
        # (with `r`'s control inclusion proof).
        sb = bundle_for(r, g.build_witness(gen, r, seal, hints), cache)
        check(failures, name, native(r, seal), reference(r, seal), script(sb, args.quick))
    for name, field, value in [("circuit_info_mismatch", "circuit_info", "RECURSION:rev1v2"),
                               ("proof_system_info_mismatch", "proof_system_info", "RISC0_STARK:v2__"),
                               ("hash_suite_mismatch", "hashfn", "sha-256")]:
        r = {**receipt, field: value}
        try:
            g.Statement(r)
            spec = (True, "specialized")
        except ValueError as err:
            spec = (False, f"no Script for statement: {err}")
        if field == "proof_system_info":
            spec = (False, "proof system info is a Script constant (fixed transcript seed)")
        check(failures, name, native(r, seal), reference(r, seal), spec)

    # Witness-level mutations the Script must reject (the native seal equivalents are covered above).
    w = [x.hex() for x in base_witness]
    wcases: dict[str, list[str] | None] = {
        "surplus_witness_element": ["00"] + w,
        "missing_witness_element": w[1:],
        "empty_witness": [],
        "hint_flipped": None,
        "hint_noncanonical": None,
    }
    hi = g.QUERY_ITEMS.index("hints")
    idx = len(w) - len(g.SETUP_ITEMS) - 1 - hi  # query 0's hints item
    for name in ("hint_flipped", "hint_noncanonical"):
        h = bytearray.fromhex(w[idx])
        v = struct.unpack_from("<I", h, 0)[0]
        struct.pack_into("<I", h, 0, v ^ 1 if name == "hint_flipped" else (v + P if v < (1 << 32) - P else v))
        wcases[name] = w[:idx] + [h.hex()] + w[idx + 1:]
    for name, ws in wcases.items():
        assert ws is not None
        b = bundle_for(receipt, [bytes.fromhex(x) for x in ws], cache)
        ok, msg = script(b, args.quick)
        print(f"{name}: script={ok} ({msg})")
        if ok:
            failures.append(name)

    print("FAILURES:", failures) if failures else print("ALL_OK")
    sys.exit(1 if failures else 0)


def check(failures: list, name: str, n: tuple, r: tuple, s: tuple) -> None:
    print(f"{name}: native={n[1]} reference={r[1]} script={s[0]} ({s[1]})")
    if n[0] or r[0] or s[0]:
        failures.append(name)


if __name__ == "__main__":
    main()
