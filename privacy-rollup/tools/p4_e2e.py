#!/usr/bin/env python3
"""P4 fee policy through SDK -> batcher -> gsr regtest node:

  * fee quote, and a deposit paying less than its own weight rejected at admission
  * two deposits priced for a three-transaction batch: the batcher refuses to prove (shortfall)
  * four deposits; while the batch proves, one depositor double-spends their funding coin in the
    mempool (the pinning vector): the batcher abandons before broadcast and drops that deposit
  * the remaining three are reproved with a reward output and sent directly to the "miner" node,
    then fee-bumped by CPFP through the reward output (submitpackage) and mined
  * a second batcher holding the pre-settlement state adopts that settlement as another operator's

Writes build/p4-e2e.json. Build the binaries as in batcher_e2e.py first. Funding coins are regtest
P2WSH(OP_TRUE) outputs, as in batcher_e2e.py: not safe on a public network.
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

be.WORK = rc.REPO / "build/p4-e2e"
be.DATADIR = be.WORK / "node"
be.PORT, be.HTTP = 19692, 18690
be.URL = f"http://127.0.0.1:{be.HTTP}"
URL = be.URL
SEED_SATS, DEPOSIT_SATS, SAT_PER_VB, TARGET = 100_000, 50_000, 0.1, 3
NAMES = ["a", "b", "c", "d"]


def serve(state, port, log, *extra):
    env = {**os.environ, **be.PROVER_ENV, "BITCOIN_RPC_URL": f"http://127.0.0.1:{be.PORT}",
           "BITCOIN_RPC_COOKIE": str(be.DATADIR / "regtest/.cookie"),
           "PR_BATCHER_REWARD_KEY": hashlib.sha256(b"p4-e2e operator reward key").hexdigest()}
    p = subprocess.Popen([str(be.BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{port}",
                          "--min-transactions", "0", "--fee-rate", str(SAT_PER_VB),
                          "--target-transactions", str(TARGET), *extra],
                         env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)
    for _ in range(600):
        try:
            be.URL = f"http://127.0.0.1:{port}"
            if be.http("GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        finally:
            be.URL = URL
        time.sleep(0.5)
    raise RuntimeError("batcher did not start")


def batch(n: int) -> dict:
    return be.http("GET", f"/v1/batches/{n}")[1]


def wait_stage(n: int, stages: set, timeout: float = 7200) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r = batch(n)
        if isinstance(r, dict) and r.get("stage") in stages:
            return r
        time.sleep(5)
    raise RuntimeError(f"batch {n} did not reach {stages}")


def main() -> None:
    shutil.rmtree(be.WORK, ignore_errors=True)
    be.DATADIR.mkdir(parents=True)
    subprocess.run([str(be.BITCOIN / "bitcoind"), "-regtest", f"-datadir={be.DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={be.PORT}", f"-port={be.PORT + 1}", "-vbparams=tapleaf_0xc2:0:3999999999",
                    "-acceptnonstdtxn=1", "-minrelaytxfee=0.00000100", "-blockmintxfee=0.00000100",
                    "-incrementalrelayfee=0.00000100"], check=True)
    report: dict = {}
    procs = []
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
                    CTxOut(value - SEED_SATS - len(NAMES) * DEPOSIT_SATS - 10_000, CScript(be.OP_TRUE_SPK))]
        gtx.vout += [CTxOut(DEPOSIT_SATS, CScript(be.OP_TRUE_SPK)) for _ in NAMES]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = be.rpc("sendrawtransaction", gtx.serialize().hex())
        be.rpc("generateblock", miner, [gtxid])
        subprocess.run([str(be.BATCHER), "genesis", str(state), gtx.serialize().hex()], check=True)
        log = be.WORK / "batcher.log"
        miner_url = f"http://127.0.0.1:{be.PORT}"
        procs.append(serve(state, be.HTTP, log, "--submit-url", miner_url))

        fees = be.http("GET", "/v1/fees")[1]
        report["quote"] = fees["quote"]
        reward_spk = fees["reward_script"]
        assert reward_spk and reward_spk.startswith("5120"), fees
        fee = fees["quote"]["deposit_sats"] + 400
        report["deposit_fee"] = fee
        print(f"quote {fees['quote']}; paying {fee} per deposit", flush=True)

        users, funding = {}, {}
        for k, name in enumerate(NAMES):
            d = be.WORK / name
            d.mkdir()
            seed = hashlib.sha256(f"p4-e2e {name}".encode()).hexdigest()
            users[name] = seed
            coin = {"outpoint": {"txid": list(bytes.fromhex(be.internal(gtxid))), "vout": 2 + k},
                    "amount": DEPOSIT_SATS, "script_pubkey": list(be.OP_TRUE_SPK)}
            funding[name] = (gtxid, 2 + k)
            (d / "funding.json").write_text(json.dumps([{"coin": coin, "witness": [be.OP_TRUE.hex()]}]))

        try:
            be.wallet("deposit", URL, users["d"], be.WORK / "d/funding.json", 1, be.WORK / "d/low.json")
            raise AssertionError("a 1-sat deposit was admitted")
        except RuntimeError as e:
            assert "below the floor" in str(e), e
            report["low_fee_rejected"] = str(e)[-400:]
        print("low-fee deposit rejected", flush=True)

        def deposit(name):
            t = time.time()
            r = be.wallet("deposit", URL, users[name], be.WORK / name / "funding.json", fee,
                          be.WORK / name / "submission.json")
            r["wall_seconds"] = round(time.time() - t, 1)
            report[f"deposit_{name}"] = r
            print(f"deposit {name}: {r['wall_seconds']}s", flush=True)

        for n in NAMES[:2]:
            deposit(n)
        report["fees_two"] = be.http("GET", "/v1/fees")[1]
        assert not report["fees_two"]["pool"]["ready"], report["fees_two"]
        report["shortfall"] = be.http("POST", "/v1/batches", b"")
        assert report["shortfall"][0] == 409 and "do not cover" in str(report["shortfall"][1]), report["shortfall"]
        print(f"shortfall: {report['shortfall']}", flush=True)
        for n in NAMES[2:]:
            deposit(n)
        report["fees_four"] = be.http("GET", "/v1/fees")[1]
        assert report["fees_four"]["pool"]["ready"], report["fees_four"]

        t = time.time()
        code, started = be.http("POST", "/v1/batches", b"")
        assert code in (200, 202), (code, started)
        n = started["batch_number"]
        time.sleep(30)
        pin = CTransaction()
        pin.version = 2
        pin.vin = [CTxIn(COutPoint(int(funding["d"][0], 16), funding["d"][1]), b"", 0xFFFFFFFD)]
        pin.vout = [CTxOut(DEPOSIT_SATS - 200, CScript(be.OP_TRUE_SPK))]
        pin.wit.vtxinwit = [CTxInWitness()]
        pin.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        report["pin_txid"] = be.rpc("sendrawtransaction", pin.serialize().hex())
        failed = wait_stage(n, {"failed", "confirmed", "broadcast"})
        report["abandoned"] = {**failed, "wall_seconds": round(time.time() - t, 1)}
        assert failed["stage"] == "failed" and "spent elsewhere" in failed["error"], failed
        assert be.http("GET", "/v1/status")[1]["pending"] == 3
        print(f"batch {n} abandoned after {report['abandoned']['wall_seconds']}s: {failed['error']}", flush=True)

        state2 = be.WORK / "batcher2"
        shutil.copytree(state, state2)

        t = time.time()
        code, started = be.http("POST", "/v1/batches", b"")
        assert code in (200, 202), (code, started)
        n = started["batch_number"]
        sent = wait_stage(n, {"broadcast", "failed", "confirmed"})
        assert sent["stage"] == "broadcast", sent
        report["prove_wall_seconds"] = round(time.time() - t, 1)
        inflight = json.loads((state / "inflight.json").read_text())
        report["inflight"] = {k: inflight[k] for k in ("txid", "miner_fee", "weight", "reward")}
        parent = be.rpc("getmempoolentry", inflight["txid"])
        report["parent_mempool"] = parent
        _, reward_value, _ = inflight["reward"]
        parent_vsize = -(-inflight["weight"] // 4)
        bump_rate = (inflight["miner_fee"] + (reward_value - 330) // 2) / (parent_vsize + 111)
        report["bump_sat_per_vb"] = bump_rate
        report["bump"] = be.http("POST", "/v1/bump", json.dumps({"sat_per_vb": bump_rate}).encode())
        assert report["bump"][0] == 200, report["bump"]
        child = report["bump"][1]["child_txid"]
        report["parent_after_bump"] = be.rpc("getmempoolentry", inflight["txid"])
        assert report["bump"][1]["package_sat_per_vb"] > inflight["miner_fee"] / parent_vsize, report["bump"]
        print(f"bumped: {report['bump'][1]}", flush=True)
        block = be.rpc("generatetoaddress", 1, miner)[0]
        txids = [x["txid"] for x in be.rpc("getblock", block, 2)["tx"]]
        assert inflight["txid"] in txids and child in txids and report["pin_txid"] in txids, txids
        done = wait_stage(n, {"confirmed", "failed"}, 600)
        assert done["stage"] == "confirmed", done
        tx = be.rpc("getrawtransaction", inflight["txid"], 1, block)
        report["settlement"] = {**done, "weight": tx["weight"], "vsize": tx["vsize"], "inputs": len(tx["vin"]),
                                "outputs": [(o["value"], o["scriptPubKey"]["hex"]) for o in tx["vout"]]}
        assert any(o["scriptPubKey"]["hex"] == reward_spk for o in tx["vout"])
        status = be.http("GET", "/v1/status")[1]
        report["status"] = status

        log2 = be.WORK / "batcher2.log"
        procs.append(serve(state2, be.HTTP + 1, log2, "--auto", "1", "--mine-to", miner))
        be.URL = f"http://127.0.0.1:{be.HTTP + 1}"
        for _ in range(120):
            s2 = be.http("GET", "/v1/status")[1]
            if s2.get("batch_number") == status.get("batch_number"):
                break
            time.sleep(1)
        be.URL = URL
        report["status_adopted"] = s2
        assert {k: v for k, v in s2.items() if k not in ("settling", "pending")} == \
            {k: v for k, v in status.items() if k not in ("settling", "pending")}, (s2, status)
        assert "adopted settlement" in log2.read_text()
        print("second batcher adopted the settlement", flush=True)
    finally:
        for p in procs:
            be.stop(p)
        subprocess.run([str(be.BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={be.DATADIR}", f"-rpcport={be.PORT}",
                        "stop"], capture_output=True)
        (rc.REPO / "build/p4-e2e.json").write_text(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
