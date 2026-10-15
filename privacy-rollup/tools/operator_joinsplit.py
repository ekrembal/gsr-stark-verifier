#!/usr/bin/env python3
"""Operator path for a batch carrying a user's zero-knowledge join-split receipt (executed, not proven).

    operator_joinsplit.py [--reuse]

1. `pr-wallet deposit` builds a deposit join-split at the operator's tip; `joinsplit prove` proves it
   on the user side (segments, lift, join, then the zero-knowledge `identity_zk` step) and
   `pr-wallet tx` wraps the receipt into the `RollupTransaction`;
2. `pr-operator init/genesis/submit` admits it only after verifying the zero-knowledge seal and its
   claim, and rejects a forged statement, a corrupted receipt, another statement's receipt, a
   resubmission (reserved funding) and missing funding;
3. `pr-operator build` assembles the batch from the pool and hands the receipt on unchanged;
4. `settle exec` runs the `apply_batch` guest with the receipt's claim as an assumption
   (`env::verify(JOINSPLIT_ID, statement)`); the guest journal must equal the native journal;
5. `accept` advances the tip and empties the pool, `rollback` restores the previous state.

`--reuse` keeps the previous run's wallet output and receipts instead of proving again.
Writes `build/privacy-rollup-operator.json`.
"""
import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

PR = Path(__file__).resolve().parents[1]
BUILD = PR.parent / "build"
WORK = BUILD / "privacy-rollup-operator"
OPERATOR = PR / "target/release/pr-operator"
WALLET = PR / "target/release/pr-wallet"
JOINSPLIT = PR / "prover/target/release/joinsplit"
SETTLE = PR / "prover/target/release/settle"
# pr_tests::descriptor(), its genesis outpoint and ROLLUP_SPK.
DESCRIPTOR = {"protocol_version": 1, "genesis_nonce": {"txid": [7] * 32, "vout": 0}, "image_id": [9] * 32,
              "internal_key": [2] * 32, "seed_sats": 10_000}
GENESIS = ("01" * 32, 0)
ROLLUP_SPK = "5120" + "aa" * 32
FUNDING_SPK = "0020" + "bb" * 32
# Host prover switches of patches/risc0-cpu-*.patch: they change proving speed, not the proofs.
PROVER_ENV = {"GSR_BATCH_CPU": "1", "GSR_PERIODIC_CPU": "1", "GSR_BATCH_EVAL_CPU": "1", "GSR_HASH_LANES": "16",
              "GSR_FAST_NTT": "1"}
for _k, _v in PROVER_ENV.items():
    os.environ.setdefault(_k, _v)


def run(*args, ok=True) -> subprocess.CompletedProcess:
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if ok and p.returncode:
        raise RuntimeError(f"{args[0]} failed: {p.stderr.strip()}")
    return p


def rejected(*args) -> str:
    p = run(*args, ok=False)
    assert p.returncode, f"accepted: {args}"
    return p.stderr.strip().splitlines()[-1]


def user(status: Path, out: Path, txid: str, seed: int) -> dict:
    """The wallet side: build the witness, prove it, assemble the transaction."""
    run(WALLET, "deposit", status, txid, 1, 20_000, FUNDING_SPK, 700, seed, out)
    t = time.time()
    stats = json.loads(run(JOINSPLIT, "prove", out / "witness.json", out / "receipt.bin").stdout)
    stats["wall_seconds"] = round(time.time() - t, 1)
    run(WALLET, "tx", out)
    (out / "prove.json").write_text(json.dumps(stats, indent=2) + "\n")
    return stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reuse", action="store_true")
    args = ap.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    js, other, state, out = WORK / "joinsplit", WORK / "other", WORK / "state", WORK / "batch1"
    for d in (state, out) if args.reuse else (state, out, js, other):
        shutil.rmtree(d, ignore_errors=True)
    report = {}
    (WORK / "descriptor.json").write_text(json.dumps(DESCRIPTOR))
    run(OPERATOR, "init", state, WORK / "descriptor.json")
    run(OPERATOR, "genesis", state, *GENESIS)
    status = WORK / "status.json"
    status.write_text(run(OPERATOR, "status", state).stdout)
    if not args.reuse:
        user(status, js, "41" * 32, 1)
        user(status, other, "42" * 32, 2)
    report["user_proving"] = json.loads((js / "prove.json").read_text())
    report["verify_standalone"] = run(JOINSPLIT, "verify", js / "tx.json").stdout.strip()

    tx = json.loads((js / "tx.json").read_text())
    forged = dict(tx, public=dict(tx["public"], fee_sats=tx["public"]["fee_sats"] + 1))
    (WORK / "forged.json").write_text(json.dumps(forged))
    corrupt = list(tx["receipt"])
    corrupt[len(corrupt) // 2] ^= 1
    (WORK / "corrupt.json").write_text(json.dumps(dict(tx, receipt=corrupt)))
    swapped = dict(tx, receipt=json.loads((other / "tx.json").read_text())["receipt"])
    (WORK / "swapped.json").write_text(json.dumps(swapped))
    funding = js / "funding.json"
    report["reject_forged_statement"] = rejected(OPERATOR, "submit", state, WORK / "forged.json", funding)
    report["reject_corrupt_receipt"] = rejected(OPERATOR, "submit", state, WORK / "corrupt.json", funding)
    report["reject_other_statement_receipt"] = rejected(OPERATOR, "submit", state, WORK / "swapped.json", funding)
    t = time.time()
    assert run(OPERATOR, "submit", state, js / "tx.json", funding).stdout.strip() == "1"
    report["submit_seconds"] = round(time.time() - t, 2)
    report["reject_resubmission"] = rejected(OPERATOR, "submit", state, js / "tx.json", funding)
    report["reject_missing_funding"] = rejected(OPERATOR, "submit", state, js / "tx.json")

    req = WORK / "request.json"
    req.write_text(json.dumps({"rollup_script_pubkey": ROLLUP_SPK, "successor_script_pubkey": ROLLUP_SPK}))
    run(OPERATOR, "build", state, req, out)
    batch = json.loads((out / "batch.json").read_text())
    assert batch["transactions"] == 1 and batch["assumption_receipts"] == ["receipt0.bin"]
    assert (out / "receipt0.bin").read_bytes() == (js / "receipt.bin").read_bytes()
    report["receipt_forwarded_unchanged"] = True

    t = time.time()
    log = run(SETTLE, "exec", out / "witness.json", out / "exec", out / "receipt0.bin").stdout
    report["guest_exec_seconds"] = round(time.time() - t, 1)
    report["guest_log"] = log.strip().splitlines()
    assert (out / "exec/journal.bin").read_bytes().hex() == batch["journal"]
    report["guest_journal_equals_native"] = True
    report["reject_settle_with_other_receipt"] = rejected(
        SETTLE, "exec", out / "witness.json", out / "exec-bad", other / "receipt.bin")

    before = json.loads(run(OPERATOR, "status", state).stdout)
    after = json.loads(run(OPERATOR, "accept", state, batch["annex"], batch["backing_sats"], "02" * 32, 0).stdout)
    assert after["batch_number"] == 1 and after["pending"] == 0 and after["state_root"] == batch["new_state_root"]
    report["reject_after_settlement"] = rejected(OPERATOR, "submit", state, js / "tx.json", funding)
    restored = json.loads(run(OPERATOR, "rollback", state).stdout)
    assert {k: v for k, v in restored.items() if k != "pending"} == {k: v for k, v in before.items() if k != "pending"}
    report["accept_and_rollback"] = {"before": before, "after": after, "restored": restored}

    (BUILD / "privacy-rollup-operator.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print("OK")


if __name__ == "__main__":
    main()
