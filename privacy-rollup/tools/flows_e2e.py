#!/usr/bin/env python3
"""Every user flow through SDK -> batcher -> gsr regtest node, each batch proven and mined:

  batch 1  empty settlement (no transactions)
  batch 2  two deposits from two wallets (batch deposit)
  batch 3  a shielded transfer A -> B and a withdrawal by B to a public script (mixed batch)

then checks the withdrawal output on chain, both wallets' scans, nullifier replay rejection and a
batcher restart. Writes build/flows-e2e.json. Build the binaries as in batcher_e2e.py first.
Funding coins are regtest P2WSH(OP_TRUE) outputs, as in batcher_e2e.py: not safe on a public network.
"""
import hashlib
import json
import os
import shutil
import subprocess
import time

import batcher_e2e as be
import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.address import script_to_p2wsh

be.WORK = rc.REPO / "build/flows-e2e"
be.DATADIR = be.WORK / "node"
be.PORT, be.HTTP = 19682, 18680
be.URL = f"http://127.0.0.1:{be.HTTP}"
URL = be.URL
SEED_SATS = 100_000
DEPOSITS = {"a": 20_000, "b": 15_000}
DEPOSIT_FEE, TRANSFER_SATS, TRANSFER_FEE, WITHDRAW_SATS, WITHDRAW_FEE = 700, 8_000, 500, 5_000, 600
WITHDRAW_SPK = b"\x00\x20" + hashlib.sha256(b"flows-e2e withdrawal").digest()


def serve(state, miner, log):
    env = {**os.environ, **be.PROVER_ENV, "BITCOIN_RPC_URL": f"http://127.0.0.1:{be.PORT}",
           "BITCOIN_RPC_COOKIE": str(be.DATADIR / "regtest/.cookie")}
    p = subprocess.Popen([str(be.BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{be.HTTP}", "--mine-to", miner,
                          "--min-transactions", "0"], env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)
    for _ in range(600):
        try:
            if be.http("GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("batcher did not start")


def settle(report: dict, name: str) -> dict:
    t = time.time()
    r = be.wallet("settle", URL)
    r["wall_seconds"] = round(time.time() - t, 1)
    tx = be.rpc("getrawtransaction", r["txid"], 1, r["block_hash"])
    r["onchain"] = {"confirmations": tx.get("confirmations"), "weight": tx["weight"], "vsize": tx["vsize"],
                    "annex_bytes": len(tx["vin"][0]["txinwitness"][-1]) // 2,
                    "leaf_bytes": len(tx["vin"][0]["txinwitness"][-3]) // 2,
                    "inputs": len(tx["vin"]), "outputs": [(o["value"], o["scriptPubKey"]["hex"]) for o in tx["vout"]]}
    assert r["onchain"]["confirmations"] >= 1
    report[name] = r
    print(f"{name}: {r['wall_seconds']}s, {tx['weight']} WU", flush=True)
    return r


def main() -> None:
    shutil.rmtree(be.WORK, ignore_errors=True)
    be.DATADIR.mkdir(parents=True)
    subprocess.run([str(be.BITCOIN / "bitcoind"), "-regtest", f"-datadir={be.DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={be.PORT}", f"-port={be.PORT + 1}", "-vbparams=tapleaf_0xc2:0:3999999999"],
                   check=True)
    report: dict = {}
    batcher = None
    try:
        miner = script_to_p2wsh(be.OP_TRUE)
        first = be.rpc("generatetoaddress", 1, miner)[0]
        be.rpc("generatetoaddress", 100, miner)
        while be.rpc("getdeploymentinfo")["deployments"]["tapleaf_0xc2"]["bip9"]["status"] != "active":
            be.rpc("generatetoaddress", 144, miner)
        coinbase = be.rpc("getblock", first, 2)["tx"][0]
        template = json.loads(be.TEMPLATE.read_text())
        descriptor = {"protocol_version": 1,
                      "genesis_nonce": {"txid": list(bytes.fromhex(be.internal(coinbase["txid"]))), "vout": 0},
                      "image_id": list(bytes.fromhex(template["claim"]["pre"])),
                      "internal_key": list(rc.NUMS), "seed_sats": SEED_SATS}
        (be.WORK / "descriptor.json").write_text(json.dumps(descriptor))
        state = be.WORK / "batcher"
        ids = json.loads(subprocess.run([str(be.BATCHER), "init", str(state), str(be.WORK / "descriptor.json")],
                                        check=True, capture_output=True, text=True).stdout)
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        gtx.vout = [CTxOut(SEED_SATS, CScript(bytes.fromhex(ids["script_pubkey"]))),
                    CTxOut(value - SEED_SATS - sum(DEPOSITS.values()) - 10_000, CScript(be.OP_TRUE_SPK))]
        gtx.vout += [CTxOut(v, CScript(be.OP_TRUE_SPK)) for v in DEPOSITS.values()]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = be.rpc("sendrawtransaction", gtx.serialize().hex())
        be.rpc("generateblock", miner, [gtxid])
        subprocess.run([str(be.BATCHER), "genesis", str(state), gtxid, "0"], check=True)
        log = be.WORK / "batcher.log"
        batcher = serve(state, miner, log)

        settle(report, "batch1_empty")

        users = {}
        for k, (name, amount) in enumerate(DEPOSITS.items()):
            d = be.WORK / name
            d.mkdir()
            seed = hashlib.sha256(f"flows-e2e {name}".encode()).hexdigest()
            users[name] = {"seed": seed, "address": be.wallet("address", seed)["address"]}
            coin = {"outpoint": {"txid": list(bytes.fromhex(be.internal(gtxid))), "vout": 2 + k}, "amount": amount,
                    "script_pubkey": list(be.OP_TRUE_SPK)}
            (d / "funding.json").write_text(json.dumps([{"coin": coin, "witness": [be.OP_TRUE.hex()]}]))
            t = time.time()
            r = be.wallet("deposit", URL, seed, d / "funding.json", DEPOSIT_FEE, d / "submission.json")
            r["wall_seconds"] = round(time.time() - t, 1)
            report[f"deposit_{name}"] = r
            print(f"deposit {name}: {r['wall_seconds']}s", flush=True)
        assert be.http("GET", "/v1/status")[1]["pending"] == 2
        settle(report, "batch2_two_deposits")

        scans = {n: be.wallet("scan", URL, u["seed"]) for n, u in users.items()}
        report["scan_after_deposits"] = scans
        for n, amount in DEPOSITS.items():
            assert sorted(x["value"] for x in scans[n]) == [0, amount - DEPOSIT_FEE], scans[n]
        note_a = next(x for x in scans["a"] if x["value"])
        note_b = next(x for x in scans["b"] if x["value"])

        t = time.time()
        r = be.wallet("send", URL, users["a"]["seed"], note_a["leaf"], users["b"]["address"], TRANSFER_SATS,
                      TRANSFER_FEE)
        r["wall_seconds"] = round(time.time() - t, 1)
        report["transfer_a_to_b"] = r
        t = time.time()
        r = be.wallet("withdraw", URL, users["b"]["seed"], note_b["leaf"], WITHDRAW_SPK.hex(), WITHDRAW_SATS,
                      WITHDRAW_FEE)
        r["wall_seconds"] = round(time.time() - t, 1)
        report["withdrawal_b"] = r
        assert be.http("GET", "/v1/status")[1]["pending"] == 2
        s3 = settle(report, "batch3_transfer_and_withdrawal")
        assert [WITHDRAW_SATS, WITHDRAW_SPK.hex()] in [[round(v * 100_000_000), h] for v, h in s3["onchain"]["outputs"]]
        backing = be.http("GET", "/v1/status")[1]
        report["status_final"] = backing

        scans = {n: be.wallet("scan", URL, u["seed"]) for n, u in users.items()}
        report["scan_final"] = scans
        a_left = DEPOSITS["a"] - DEPOSIT_FEE - TRANSFER_SATS - TRANSFER_FEE
        b_left = DEPOSITS["b"] - DEPOSIT_FEE - WITHDRAW_SATS - WITHDRAW_FEE
        assert sorted(x["value"] for x in scans["a"] if x["leaf"] != note_a["leaf"]) == [0, 0, a_left], scans["a"]
        assert TRANSFER_SATS in [x["value"] for x in scans["b"]], scans["b"]
        assert b_left in [x["value"] for x in scans["b"]], scans["b"]

        sub = json.loads((be.WORK / "a/submission.json").read_text())
        report["replayed_deposit"] = be.http("POST", "/v1/transactions", json.dumps(sub).encode())
        assert report["replayed_deposit"][0] in (400, 409)

        be.stop(batcher)
        batcher = serve(state, miner, log)
        restarted = be.http("GET", "/v1/status")[1]
        assert {k: v for k, v in restarted.items() if k != "settling"} == \
            {k: v for k, v in backing.items() if k != "settling"}
        report["restart_ok"] = True
    finally:
        if batcher:
            be.stop(batcher)
        subprocess.run([str(be.BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={be.DATADIR}", f"-rpcport={be.PORT}",
                        "stop"], capture_output=True)
        (rc.REPO / "build/flows-e2e.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps({k: (v.get("onchain", {}).get("weight"), v.get("wall_seconds")) for k, v in report.items()
                      if isinstance(v, dict) and "wall_seconds" in v}, indent=2))


if __name__ == "__main__":
    main()
