#!/usr/bin/env python3
"""Recursive lineage and the fixed rollup address with real settlement proofs on a gsr regtest node (patched with bitcoin/bitcoin#36466):

  * genesis, then escrow deposit a: batch 1 spends the genesis state (no predecessor receipt), mined;
  * escrow deposit b: batch 2 proves batch 1's journal by its poseidon2 receipt (an assumption discharged
    with `resolve`), mined; both depositors scan their notes;
  * batch 2's witness executed with batch 1's on-chain padded-SHA receipt verified inside the guest
    (`settle exec --seal`): same journal;
  * `settle exec` of batch 2 without a predecessor proof, with the wrong predecessor receipt, or with a
    fabricated old state (attacker-chosen `parent`) fails;
  * every settlement pays the genesis output's address in output 0 and `OP_RETURN <new root>` in output 1, and
    `settle exec` fails with a flipped or missing predecessor root output, a wrong or non-OP_RETURN new root
    output, or output 0 at another address.

Writes build/lineage-e2e.json. Build the binaries as in batcher_e2e.py.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

import batcher_e2e as be
import relay_e2e as r
import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.address import script_to_p2wsh
from test_framework.key import compute_xonly_pubkey, generate_privkey

r.WORK = rc.REPO / "build/lineage-e2e"
r.NODES = {"a": (r.WORK / "node", 19822)}
r.HTTP = {"a": 18820}
SETTLE = be.TARGET / "settle"
if os.environ.get("BATCHER_WRAPPER"):
    be.BATCHER = os.environ["BATCHER_WRAPPER"]


def settle_exec(*args: str) -> tuple[bool, str]:
    p = subprocess.run([str(SETTLE), "exec", *args], capture_output=True, text=True)
    return p.returncode == 0, (p.stdout + p.stderr).strip().splitlines()[-1][:300] if (p.stdout + p.stderr).strip() else ""


def seed(name: str) -> str:
    return hashlib.sha256(f"lineage-e2e {name}".encode()).hexdigest()


def checks(state, report: dict) -> None:
    """Scans both depositors, then executes batch 2 in seal mode and with missing, wrong and fabricated
    predecessors."""
    scans = {n: be.wallet("scan", r.url("a"), seed(n)) for n in ["a", "b"]}
    report["scans"] = scans
    assert all([x["value"] for x in s] == [r.VALUE] for s in scans.values()), scans

    b1, b2 = state / "batches/1", state / "batches/2"
    w2 = b2 / "witness.json"
    journal2 = json.loads((b2 / "receipt.json").read_text())["journal"]
    cases = {}
    t = time.time()
    p = subprocess.run([str(SETTLE), "exec", str(w2), str(r.WORK / "exec-seal"), "--seal",
                        str(b1 / "receipt.json"), str(b1 / "seal.bin")], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    m = re.search(r"executed: (\d+) cycles, (\d+) segments", p.stdout)
    cases["seal_mode"] = {"ok": True, "cycles": int(m[1]), "segments": int(m[2]),
                          "seconds": round(time.time() - t, 1),
                          "same_journal": (r.WORK / "exec-seal/journal.bin").read_bytes().hex() == journal2}
    assert cases["seal_mode"]["same_journal"]
    p = subprocess.run([str(SETTLE), "exec", str(w2), str(r.WORK / "exec-receipt"), "--receipt",
                        str(b1 / "unconditional.bin")], capture_output=True, text=True)
    m = re.search(r"executed: (\d+) cycles, (\d+) segments", p.stdout)
    cases["receipt_mode"] = {"ok": p.returncode == 0, "cycles": int(m[1]), "segments": int(m[2])}
    cases["no_predecessor"] = settle_exec(str(w2), str(r.WORK / "x"))
    cases["wrong_predecessor_seal"] = settle_exec(str(w2), str(r.WORK / "x"), "--seal",
                                                  str(b2 / "receipt.json"), str(b2 / "seal.bin"))
    forged = json.loads(w2.read_text())
    forged["old_state"]["parent"] = {"txid": [0xAA] * 32, "vout": 0}
    (r.WORK / "forged.json").write_text(json.dumps(forged))
    cases["fabricated_parent"] = settle_exec(str(r.WORK / "forged.json"), str(r.WORK / "x"), "--receipt",
                                             str(b1 / "unconditional.bin"))
    for name, edit in [("predecessor_root_output_flipped", lambda w: w["predecessor_tx"]["outputs"][1]["script_pubkey"]
                        .__setitem__(2, w["predecessor_tx"]["outputs"][1]["script_pubkey"][2] ^ 1)),
                       ("predecessor_root_output_missing", lambda w: w["predecessor_tx"]["outputs"].pop(1)),
                       ("new_root_output_wrong", lambda w: w["settlement"]["outputs"][1]["script_pubkey"]
                        .__setitem__(2, w["settlement"]["outputs"][1]["script_pubkey"][2] ^ 1)),
                       ("root_output_not_op_return", lambda w: w["settlement"]["outputs"][1]["script_pubkey"]
                        .__setitem__(0, 0x51)),
                       ("output0_other_address", lambda w: w["settlement"]["outputs"][0]["script_pubkey"]
                        .__setitem__(5, w["settlement"]["outputs"][0]["script_pubkey"][5] ^ 1))]:
        w = json.loads(w2.read_text())
        edit(w)
        (r.WORK / f"{name}.json").write_text(json.dumps(w))
        cases[name] = settle_exec(str(r.WORK / f"{name}.json"), str(r.WORK / "x"), "--receipt",
                                  str(b1 / "unconditional.bin"))
    report["exec"] = cases
    for k in ["no_predecessor", "wrong_predecessor_seal", "fabricated_parent", "predecessor_root_output_flipped",
              "predecessor_root_output_missing", "new_root_output_wrong", "root_output_not_op_return",
              "output0_other_address"]:
        assert not cases[k][0], (k, cases[k])


def resume() -> None:
    """Re-runs `checks` against the state of a run whose batcher is still serving."""
    state, report = r.WORK / "batcher", {"node": str(r.BIN), "resumed": True}
    blocks = {}
    for h in range(r.rpc("a", "getblockcount") + 1):
        bh = r.rpc("a", "getblockhash", h)
        blocks.update({t: bh for t in r.rpc("a", "getblock", bh)["tx"]})
    for b in r.http("a", "GET", "/v1/batches")[1]:
        n = b["batch_number"]
        mined = r.rpc("a", "getrawtransaction", b["txid"], 1, blocks[b["txid"]])
        report[f"batch_{n}"] = {**b, "confirmations": mined.get("confirmations"), "weight": mined["weight"],
                                "inputs": len(mined["vin"]), "outputs": len(mined["vout"]),
                                "stats": json.loads((state / f"batches/{n}/stats.json").read_text())}
    try:
        checks(state, report)
    finally:
        (rc.REPO / "build/lineage-e2e.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


def main() -> None:
    shutil.rmtree(r.WORK, ignore_errors=True)
    r.WORK.mkdir(parents=True)
    r.start_node("a")
    report: dict = {"node": str(r.BIN)}
    batcher = None
    try:
        miner = script_to_p2wsh(be.OP_TRUE)
        first = r.rpc("a", "generatetoaddress", 1, miner)[0]
        r.rpc("a", "generatetoaddress", 100, miner)
        while r.rpc("a", "getdeploymentinfo")["deployments"]["tapleaf_0xc2"]["bip9"]["status"] != "active":
            r.rpc("a", "generatetoaddress", 144, miner)
        coinbase = r.rpc("a", "getblock", first, 2)["tx"][0]
        template = json.loads(be.TEMPLATE.read_text())
        descriptor = {"protocol_version": 1,
                      "genesis_nonce": {"txid": list(bytes.fromhex(be.internal(coinbase["txid"]))), "vout": 0},
                      "image_id": list(bytes.fromhex(template["claim"]["pre"])),
                      "internal_key": list(rc.NUMS), "seed_sats": r.SEED_SATS}
        (r.WORK / "descriptor.json").write_text(json.dumps(descriptor))
        state = r.WORK / "batcher"
        ids = json.loads(subprocess.run([str(be.BATCHER), "init", str(state), str(r.WORK / "descriptor.json")],
                                        check=True, capture_output=True, text=True).stdout)
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        fund = 2 * (r.VALUE + r.FEE)
        gtx.vout = [CTxOut(r.SEED_SATS, CScript(bytes.fromhex(ids["script_pubkey"]))),
                    CTxOut(value - r.SEED_SATS - 2 * fund - 10_000, CScript(be.OP_TRUE_SPK)),
                    CTxOut(fund, CScript(be.OP_TRUE_SPK)), CTxOut(fund, CScript(be.OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = r.rpc("a", "sendrawtransaction", gtx.serialize().hex())
        r.rpc("a", "generateblock", miner, [gtxid])
        subprocess.run([str(be.BATCHER), "genesis", str(state), gtx.serialize().hex()], check=True)
        batcher = r.serve("a", state)

        users = {}
        for k, name in enumerate(["a", "b"]):
            out = r.WORK / f"{name}-deposit.json"
            be.wallet("deposit-address", r.url("a"), seed(name), r.VALUE, r.FEE,
                      compute_xonly_pubkey(generate_privkey())[0].hex(), r.DELAY, out)
            d = json.loads(out.read_text())
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(int(gtxid, 16), 2 + k), b"", 0xFFFFFFFF)]
            tx.vout = [CTxOut(d["amount_sats"], CScript(bytes.fromhex(d["script_pubkey"])))]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
            users[name] = {"file": out, "raw": tx.serialize().hex()}

        for n, name in [(1, "a"), (2, "b")]:
            users[name]["txid"] = r.rpc("a", "sendrawtransaction", users[name]["raw"])
            r.rpc("a", "generatetoaddress", r.CONFIRMATIONS, miner)
            be.wallet("register", r.url("a"), users[name]["file"], users[name]["txid"], 0)
            p, b = r.settle_until_broadcast("a")
            e = r.entry("a", b["txid"])
            block = r.rpc("a", "generatetoaddress", 1, miner)[0]
            mined = r.rpc("a", "getrawtransaction", b["txid"], 1, block)
            r.rpc("a", "generatetoaddress", r.CONFIRMATIONS, miner)
            out, err = p.communicate(timeout=900)
            assert p.returncode == 0, err
            stats = json.loads((state / f"batches/{n}/stats.json").read_text())
            report[f"batch_{n}"] = {**b, "mempool": e, "confirmations": mined.get("confirmations"),
                                    "weight": mined["weight"], "inputs": len(mined["vin"]),
                                    "outputs": len(mined["vout"]), "stats": stats}
            assert stats["lineage"] == ("genesis" if n == 1 else "receipt"), stats
            new_root = json.loads((state / f"batches/{n}/receipt.json").read_text())["journal"][136:200]
            report[f"batch_{n}"]["static_address"] = mined["vout"][0]["scriptPubKey"]["hex"] == ids["script_pubkey"]
            report[f"batch_{n}"]["root_output"] = mined["vout"][1]["scriptPubKey"]["hex"]
            assert report[f"batch_{n}"]["static_address"], mined["vout"][0]
            assert mined["vout"][1]["scriptPubKey"]["hex"] == "6a20" + new_root and mined["vout"][1]["value"] == 0
            print(f"batch {n} mined: {report[f'batch_{n}']['weight']} WU, lineage {stats['lineage']}", flush=True)

        checks(state, report)
    finally:
        if batcher:
            be.stop(batcher)
        try:
            r.rpc("a", "stop")
        except RuntimeError:
            pass
        (rc.REPO / "build/lineage-e2e.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    resume() if sys.argv[1:] == ["--resume"] else main()
