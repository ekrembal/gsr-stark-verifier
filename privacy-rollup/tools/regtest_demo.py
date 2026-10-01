#!/usr/bin/env python3
"""Regtest demonstration of the privacy rollup on the pinned GSR node, driven through the operator CLI.

    regtest_demo.py [--batches N]

1. authenticated genesis: a transaction spends the descriptor's `genesis_nonce` and creates the rollup output
   (seed sats) at the covenant leaf of the genesis state root;
2. N consecutive anchor-only settlements, each proven by the `apply_batch` guest (padded-SHA succinct
   receipt), metered against every GSR limit and mined;
3. negative spends of settlement 1: metered (redirected/extra/altered outputs, altered annex, new root,
   input sequence, locktime and version, another batch's receipt, another guest's receipt, tampered seal,
   truncated witness), each rejected by the interpreter; and submitted to the node in a block
   (rollup input not at index 0, an extra funding input, altered control block), each rejected by
   consensus;
4. policy versus consensus: standard policy rejects the annex-bearing spend, `generateblock` mines it;
5. cadence: two consecutive settlements cannot share a block (the leaf's `1 CSV`);
6. reorg: invalidating the last settlement block and rolling the operator back, then restoring it;
7. restart: a fresh operator replays the annexes read back from the chain to the same state.

Writes `build/privacy-rollup-regtest.json`.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut

sys.path.insert(0, str(rc.BITCOIN_SOURCE / "test/functional"))
from test_framework.address import script_to_p2wsh  # noqa: E402

PR = Path(__file__).resolve().parents[1]
BUILD = rc.REPO / "build"
BITCOIN = rc.REPO / "build/bitcoin/bin"
OPERATOR = PR / "target/release/pr-operator"
SETTLE = PR / "prover/target/release/settle"
TEMPLATE = PR / "fixtures/apply-batch/receipt-template.json"
PKV = PR / "fixtures/joinsplit/joinsplit.pkv"
OTHER_GUEST = rc.REPO / "risc0-succinct/fixtures"
WORK = BUILD / "privacy-rollup-regtest"
DATADIR = WORK / "node"
PORT = 19482
OP_TRUE = b"\x51"
OP_TRUE_SPK = b"\x00\x20" + hashlib.sha256(OP_TRUE).digest()
SEED_SATS = 100_000


def rpc(method: str, *args):
    cmd = [str(BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={DATADIR}", f"-rpcport={PORT}", "-stdin", method]
    proc = subprocess.run(cmd, input="".join((a if isinstance(a, str) else json.dumps(a)) + "\n" for a in args),
                          text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip())
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout.strip()


def operator(*args) -> str:
    return subprocess.run([str(OPERATOR), *map(str, args)], check=True, capture_output=True, text=True).stdout


def internal(txid: str) -> str:
    return bytes.fromhex(txid)[::-1].hex()


def mine(address: str, txs: list[str]) -> str:
    return rpc("generateblock", address, txs)["hash"]


class Batch:
    def __init__(self, cov: rc.Covenant, out: Path) -> None:
        self.cov, self.out = cov, out
        self.batch = json.loads((out / "batch.json").read_text())
        self.receipt = json.loads((out / "proof/receipt.json").read_text())
        self.seal = (out / "proof/seal.bin").read_bytes()
        self.new_root = bytes.fromhex(self.batch["new_state_root"])
        self.annex = bytes.fromhex(self.batch["annex"])
        assert self.receipt["journal"] == self.batch["journal"]

    def tx(self, receipt=None, seal=None, new_root=None, annex=None, edit=None, hints=None) -> CTransaction:
        tx = rc.settlement_tx(self.batch)
        if edit:
            edit(tx)
        tx.wit.vtxinwit[0].scriptWitness.stack = self.cov.witness(
            receipt or self.receipt, seal or self.seal, new_root or self.new_root, annex or self.annex, hints)
        return tx

    def meter(self, tx: CTransaction, name: str, batch=None) -> dict:
        return rc.meter(self.cov, tx, batch or self.batch, self.out / f"meter-{name}.json")


def build_batch(state: Path, cov: rc.Covenant, out: Path) -> Batch:
    req = {"rollup_script_pubkey": cov.script_pubkey.hex(), "transactions": []}
    (out.parent / f"{out.name}-req.json").write_text(json.dumps(req))
    new_root = bytes.fromhex(json.loads(operator("build", state, out.parent / f"{out.name}-req.json", out)))
    req["successor_script_pubkey"] = cov.for_root(new_root).script_pubkey.hex()
    (out.parent / f"{out.name}-req.json").write_text(json.dumps(req))
    operator("build", state, out.parent / f"{out.name}-req.json", out)
    t = time.time()
    log = subprocess.run([str(SETTLE), "prove", str(out / "witness.json"), str(out / "proof")], check=True,
                         capture_output=True, text=True).stdout
    (out / "prove.log").write_text(log)
    print(f"  proved {out.name} in {time.time() - t:.0f}s", flush=True)
    return Batch(cov, out)


def negative_cases(b: Batch, other: Batch) -> dict:
    other_root = hashlib.sha256(b"other root").digest()

    def set_out0(spk):
        return lambda tx: setattr(tx.vout[0], "scriptPubKey", CScript(spk))

    def bump(i, d):
        return lambda tx: setattr(tx.vout[i], "nValue", tx.vout[i].nValue + d)

    flipped = bytearray(b.annex)
    flipped[-1] ^= 1
    cases = {
        "redirected_successor": b.tx(edit=set_out0(b.cov.for_root(other_root).script_pubkey)),
        "successor_for_witness_root": b.tx(new_root=other_root,
                                          edit=set_out0(b.cov.for_root(other_root).script_pubkey)),
        "successor_value_minus_one": b.tx(edit=bump(0, -1)),
        "extra_output": b.tx(edit=lambda tx: tx.vout.append(CTxOut(1000, CScript(OP_TRUE_SPK)))),
        "altered_annex": b.tx(annex=bytes(flipped)),
        "input_sequence_2": b.tx(edit=lambda tx: setattr(tx.vin[0], "nSequence", 2)),
        "locktime_1": b.tx(edit=lambda tx: setattr(tx, "nLockTime", 1)),
        "version_3": b.tx(edit=lambda tx: setattr(tx, "version", 3)),
        "other_batch_receipt": b.tx(receipt=other.receipt, seal=other.seal),
        "tampered_seal": b.tx(seal=b.seal[:40] + bytes([b.seal[40] ^ 1]) + b.seal[41:],
                              hints=rc.g.prover_hints(b.cov.gen, b.receipt, b.seal)),
        "other_guest_receipt": b.tx(receipt=json.loads((OTHER_GUEST / "covenant-receipt.json").read_text()),
                                    seal=(OTHER_GUEST / "covenant-seal.bin").read_bytes()),
        "truncated_witness": b.tx(),
    }
    stack = cases["truncated_witness"].wit.vtxinwit[0].scriptWitness.stack
    cases["truncated_witness"].wit.vtxinwit[0].scriptWitness.stack = stack[1:]
    result = {}
    for name, tx in cases.items():
        e = b.meter(tx, name)
        result[name] = {"rejected": not e["ok"], "error": e["error"]}
        print(f"  negative {name}: {e['error']}", flush=True)
    return result


def consensus_negatives(b: Batch, miner: str, coin: COutPoint) -> dict:
    """Spends of settlement 1 that only the node can judge (other inputs, Taproot commitment), each
    submitted in a block before settlement 1 itself is mined."""
    def with_coin(at: int) -> CTransaction:
        tx = b.tx()
        tx.vin.insert(at, CTxIn(coin, b"", 0xFFFFFFFF))
        w = CTxInWitness()
        w.scriptWitness.stack = [OP_TRUE]
        tx.wit.vtxinwit.insert(at, w)
        return tx

    def control(edit) -> CTransaction:
        tx = b.tx()
        stack = tx.wit.vtxinwit[0].scriptWitness.stack
        stack[-2] = edit(bytearray(stack[-2]))
        return tx

    def other_key(c: bytearray) -> bytes:
        c[1:33] = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        return bytes(c)

    def flip_parity(c: bytearray) -> bytes:
        c[0] ^= 1
        return bytes(c)

    cases = {"rollup_input_at_index_1": with_coin(0), "extra_funding_input": with_coin(1),
             "control_block_internal_key": control(other_key), "control_block_parity": control(flip_parity)}
    result = {}
    for name, tx in cases.items():
        try:
            mine(miner, [tx.serialize().hex()])
            result[name] = {"rejected": False, "error": ""}
        except RuntimeError as err:
            result[name] = {"rejected": True, "error": str(err)}
        print(f"  consensus negative {name}: {result[name]['error']}", flush=True)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batches", type=int, default=2)
    args = ap.parse_args()
    assert args.batches >= 2
    shutil.rmtree(WORK, ignore_errors=True)
    DATADIR.mkdir(parents=True)
    subprocess.run([str(BITCOIN / "bitcoind"), "-regtest", f"-datadir={DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={PORT}", f"-port={PORT + 1}", "-vbparams=script_restoration:0:3999999999"],
                   check=True)
    report: dict = {}
    try:
        miner = script_to_p2wsh(OP_TRUE)
        first = rpc("generatetoaddress", 1, miner)[0]
        rpc("generatetoaddress", 100, miner)
        while rpc("getdeploymentinfo")["deployments"]["script_restoration"]["bip9"]["status"] != "active":
            rpc("generatetoaddress", 144, miner)
        coinbase = rpc("getblock", first, 2)["tx"][0]
        nonce = {"txid": list(bytes.fromhex(internal(coinbase["txid"]))), "vout": 0}

        # Genesis: descriptor -> root -> covenant leaf; the genesis tx spends the nonce.
        template = json.loads(TEMPLATE.read_text())
        descriptor = {"protocol_version": 1, "genesis_nonce": nonce,
                      "image_id": list(bytes.fromhex(template["claim"]["pre"])),
                      "internal_key": list(rc.NUMS), "seed_sats": SEED_SATS}
        (WORK / "descriptor.json").write_text(json.dumps(descriptor))
        state = WORK / "operator"
        ids = json.loads(operator("init", state, WORK / "descriptor.json", PKV))
        rollup_id, root = bytes.fromhex(ids["rollup_id"]), bytes.fromhex(ids["state_root"])
        t = time.time()
        cov = rc.Covenant(template, rollup_id, root)
        print(f"covenant generated in {time.time() - t:.0f}s: {len(cov.script)} bytes", flush=True)
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        gtx.vout = [CTxOut(SEED_SATS, CScript(cov.script_pubkey)), CTxOut(value - SEED_SATS - 10_000, CScript(OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [OP_TRUE]
        gtxid = rpc("sendrawtransaction", gtx.serialize().hex())
        mine(miner, [gtxid])
        operator("genesis", state, internal(gtxid), 0)
        report["genesis"] = {"txid": gtxid, "rollup_id": rollup_id.hex(), "state_root": root.hex(),
                             "covenant_script_bytes": len(cov.script), "nonce_spent": coinbase["txid"]}

        # Settlements.
        settlements, blocks = [], []
        current = cov
        for k in range(1, args.batches + 1):
            b = build_batch(state, current, WORK / f"batch{k}")
            tx = b.tx()
            e = b.meter(tx, "accept")
            limits = rc.limits(current, e)
            assert all(limits.values()), (e, limits)
            raw = tx.serialize().hex()
            entry = {"batch_number": b.batch["batch_number"], "txid": tx.txid_hex, "weight": tx.get_weight(),
                     "annex_bytes": len(b.annex), "varops": e["varops"], "budget": e["budget"],
                     "invoked_body_bytes": e["invoked_body_bytes"], "peak_entries": e["peak_entries"],
                     "limits": limits, "standard_policy": rpc("testmempoolaccept", [raw])[0]}
            if k == 2:
                # Cadence: settlement 2 cannot be mined in the block that confirms settlement 1.
                try:
                    mine(miner, [settlements[0]["raw"], raw])
                    report["same_block_settlements"] = "accepted"
                except RuntimeError as err:
                    report["same_block_settlements"] = f"rejected: {err}"
                blocks.append(mine(miner, [settlements[0]["raw"]]))
            if k >= 2:
                blocks.append(mine(miner, [raw]))
            entry["raw"] = raw
            settlements.append(entry)
            operator("accept", state, b.batch["annex"], b.batch["outputs"][0]["value"], internal(entry["txid"]), 0)
            if k == 1:
                first_batch = b
                report["consensus_negatives_of_settlement_1"] = consensus_negatives(
                    b, miner, COutPoint(int(gtxid, 16), 1))
            current = current.for_root(b.new_root)
            print(f"settlement {k}: {entry['weight']} WU, {entry['varops']} varops", flush=True)
        report["negative_spends_of_settlement_1"] = negative_cases(first_batch, b)

        status = json.loads(operator("status", state))
        utxo = rpc("gettxout", internal(status["utxo"][0]), status["utxo"][1])
        report["final_status"] = status
        report["rollup_utxo_on_chain"] = {"value": utxo["value"], "script_pubkey": utxo["scriptPubKey"]["hex"],
                                          "matches_covenant": utxo["scriptPubKey"]["hex"] == current.script_pubkey.hex()}

        # Reorg: drop the last settlement block, roll back, then restore.
        rpc("invalidateblock", blocks[-1])
        rolled = json.loads(operator("rollback", state))
        rpc("reconsiderblock", blocks[-1])
        last = settlements[-1]
        operator("accept", state, b.batch["annex"], b.batch["outputs"][0]["value"], internal(last["txid"]), 0)
        report["reorg"] = {"rolled_back_to": rolled["batch_number"],
                           "restored_to": json.loads(operator("status", state))["batch_number"]}

        # Restart from chain data only: read every annex back from the mined settlements.
        fresh = WORK / "replay"
        operator("init", fresh, WORK / "descriptor.json", PKV)
        operator("genesis", fresh, internal(gtxid), 0)
        for s, block in zip(settlements, blocks):
            mined = rpc("getrawtransaction", s["txid"], True, block)
            annex = mined["vin"][0]["txinwitness"][-1]
            operator("accept", fresh, annex, round(mined["vout"][0]["value"] * 100_000_000), internal(s["txid"]), 0)
        report["replay_matches"] = json.loads(operator("status", fresh)) == json.loads(operator("status", state))
        for s in settlements:
            s.pop("raw")
        report["settlements"] = settlements
    finally:
        rpc("stop")
    out = BUILD / "privacy-rollup-regtest.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    failures = [n for n, c in {**report["negative_spends_of_settlement_1"],
                               **report["consensus_negatives_of_settlement_1"]}.items() if not c["rejected"]]
    ok = (not failures and report["replay_matches"] and report["rollup_utxo_on_chain"]["matches_covenant"]
          and report["same_block_settlements"].startswith("rejected")
          and report["reorg"] == {"rolled_back_to": args.batches - 1, "restored_to": args.batches})
    print("OK" if ok else f"FAILED {failures}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    os.chdir(Path(__file__).parent)
    main()
