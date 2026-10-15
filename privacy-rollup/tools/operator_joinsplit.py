#!/usr/bin/env python3
"""Operator path for a batch carrying a real ProveKit join-split (executed, not proven).

1. `joinsplit-batch` builds and proves a deposit join-split and writes the reference witness;
2. `pr-operator init/genesis/submit` admits it only after native ProveKit verification, and rejects
   a resubmission (reserved funding), a forged statement and a corrupted proof;
3. `pr-operator build` assembles the batch from the pool; its witness must equal the reference;
4. `settle exec` runs the `apply_batch` guest on the operator's frames (ProveKit verified inside the
   guest), and the guest journal must equal the native journal;
5. `accept` advances the tip and empties the pool, `rollback` restores the previous state.

Writes `build/privacy-rollup-operator.json`.
"""
import json
import subprocess
import time
from pathlib import Path

PR = Path(__file__).resolve().parents[1]
BUILD = PR.parent / "build"
WORK = BUILD / "privacy-rollup-operator"
OPERATOR = PR / "target/release/pr-operator"
JOINSPLIT = PR / "target/release/joinsplit-batch"
SETTLE = PR / "prover/target/release/settle"
PKP, PKV = PR / "fixtures/joinsplit/joinsplit.pkp", PR / "fixtures/joinsplit/joinsplit.pkv"
# pr_tests::descriptor(), its genesis outpoint and ROLLUP_SPK.
DESCRIPTOR = {"protocol_version": 1, "genesis_nonce": {"txid": [7] * 32, "vout": 0}, "image_id": [9] * 32,
              "internal_key": [2] * 32, "seed_sats": 10_000}
GENESIS = ("01" * 32, 0)
ROLLUP_SPK = "5120" + "aa" * 32


def run(*args, ok=True) -> subprocess.CompletedProcess:
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if ok and p.returncode:
        raise RuntimeError(f"{args[0]} failed: {p.stderr.strip()}")
    return p


def rejected(*args) -> str:
    p = run(*args, ok=False)
    assert p.returncode, f"accepted: {args}"
    return p.stderr.strip().splitlines()[-1]


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    js, state, out = WORK / "joinsplit", WORK / "state", WORK / "batch1"
    for d in (state, out):
        if d.exists():
            subprocess.run(["rm", "-r", str(d)], check=True)
    report = {}
    run(JOINSPLIT, PKP, PKV, js)
    (WORK / "descriptor.json").write_text(json.dumps(DESCRIPTOR))
    run(OPERATOR, "init", state, WORK / "descriptor.json", PKV)
    run(OPERATOR, "genesis", state, *GENESIS)

    tx = json.loads((js / "tx.json").read_text())
    forged = dict(tx, public=dict(tx["public"], fee_sats=tx["public"]["fee_sats"] + 1))
    (WORK / "forged.json").write_text(json.dumps(forged))
    hints = list(tx["proof_hints"])
    hints[len(hints) // 2] ^= 1
    (WORK / "corrupt.json").write_text(json.dumps(dict(tx, proof_hints=hints)))
    report["reject_forged_statement"] = rejected(OPERATOR, "submit", state, WORK / "forged.json", js / "funding.json")
    report["reject_corrupt_proof"] = rejected(OPERATOR, "submit", state, WORK / "corrupt.json", js / "funding.json")
    t = time.time()
    assert run(OPERATOR, "submit", state, js / "tx.json", js / "funding.json").stdout.strip() == "1"
    report["submit_seconds"] = round(time.time() - t, 2)
    report["reject_resubmission"] = rejected(OPERATOR, "submit", state, js / "tx.json", js / "funding.json")
    report["reject_missing_funding"] = rejected(OPERATOR, "submit", state, js / "tx.json")

    req = WORK / "request.json"
    req.write_text(json.dumps({"rollup_script_pubkey": ROLLUP_SPK, "successor_script_pubkey": ROLLUP_SPK}))
    run(OPERATOR, "build", state, req, out)
    batch = json.loads((out / "batch.json").read_text())
    assert batch["transactions"] == 1 and batch["guest_frames"] == ["proof0.pc"]
    assert json.loads((out / "witness.json").read_text()) == json.loads((js / "witness.json").read_text())
    assert not (out / "vk.pc").exists()
    assert (out / "proof0.pc").read_bytes() == (js / "proof0.pc").read_bytes()
    report["witness_equals_reference"] = True

    t = time.time()
    log = run(SETTLE, "exec", out / "witness.json", out / "exec", out / "proof0.pc").stdout
    report["guest_exec_seconds"] = round(time.time() - t, 1)
    report["guest_log"] = log.strip().splitlines()
    assert (out / "exec/journal.bin").read_bytes().hex() == batch["journal"]
    report["guest_journal_equals_native"] = True

    before = json.loads(run(OPERATOR, "status", state).stdout)
    after = json.loads(run(OPERATOR, "accept", state, batch["annex"], batch["backing_sats"], "02" * 32, 0).stdout)
    assert after["batch_number"] == 1 and after["pending"] == 0 and after["state_root"] == batch["new_state_root"]
    report["reject_after_settlement"] = rejected(OPERATOR, "submit", state, js / "tx.json", js / "funding.json")
    restored = json.loads(run(OPERATOR, "rollback", state).stdout)
    assert {k: v for k, v in restored.items() if k != "pending"} == {k: v for k, v in before.items() if k != "pending"}
    report["accept_and_rollback"] = {"before": before, "after": after, "restored": restored}

    (BUILD / "privacy-rollup-operator.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print("OK")


if __name__ == "__main__":
    main()
