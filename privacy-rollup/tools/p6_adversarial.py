#!/usr/bin/env python3
"""P6 adversarial run on a gsr regtest node, with a real settlement receipt:

  * one SDK deposit, proven and broadcast by the batcher; the batcher is killed right after broadcast;
  * the broadcast settlement is tampered with and each variant is offered to the node in a block
    (`generateblock` with an explicit transaction list, which runs full consensus validation):
    changed / added / dropped outputs and inputs, annex byte flip, annex padded by 100 kB, corrupted seal,
    and the genuine witness moved onto a covenant copy (same script, different coin);
  * the batcher restarts, resumes the in-flight settlement and records it once mined;
  * the mined settlement is replayed.

Writes build/p6-adversarial.json. Build the binaries as in batcher_e2e.py first. Funding coins are regtest
P2WSH(OP_TRUE) outputs, as in batcher_e2e.py: not safe on a public network.
"""
import copy
import hashlib
import json
import shutil
import signal
import subprocess
import time
from io import BytesIO

import batcher_e2e as be
import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.address import script_to_p2wsh

be.WORK = rc.REPO / "build/p6-adversarial"
be.DATADIR = be.WORK / "node"
be.PORT, be.HTTP = 19702, 18700
be.URL = f"http://127.0.0.1:{be.HTTP}"
SEED_SATS, DEPOSIT_SATS, DEPOSIT_FEE = 100_000, 50_000, 9_000


def serve(state, log):
    env = {**be.os.environ, **be.PROVER_ENV, "BITCOIN_RPC_URL": f"http://127.0.0.1:{be.PORT}",
           "BITCOIN_RPC_COOKIE": str(be.DATADIR / "regtest/.cookie"),
           "PR_BATCHER_REWARD_KEY": hashlib.sha256(b"p6 operator reward key").hexdigest()}
    p = subprocess.Popen([str(be.BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{be.HTTP}",
                          "--min-transactions", "0", "--fee-rate", "0.1", "--target-transactions", "1",
                          "--submit-url", f"http://127.0.0.1:{be.PORT}"],
                         env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)
    for _ in range(600):
        try:
            if be.http("GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("batcher did not start")


def wait_stage(n: int, stages: set, timeout: float = 7200) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r = be.http("GET", f"/v1/batches/{n}")[1]
        if isinstance(r, dict) and r.get("stage") in stages:
            return r
        time.sleep(2)
    raise RuntimeError(f"batch {n} did not reach {stages}")


def decode(raw: str) -> CTransaction:
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw)))
    return tx


def in_block(miner: str, tx: CTransaction) -> str:
    """Mines `tx` alone; returns "accepted" or the node's rejection."""
    try:
        be.rpc("generateblock", miner, [tx.serialize().hex()])
        return "accepted"
    except RuntimeError as e:
        return str(e)


def main() -> None:
    shutil.rmtree(be.WORK, ignore_errors=True)
    be.DATADIR.mkdir(parents=True)
    subprocess.run([str(be.BITCOIN / "bitcoind"), "-regtest", f"-datadir={be.DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={be.PORT}", f"-port={be.PORT + 1}", "-vbparams=tapleaf_0xc2:0:3999999999",
                    "-acceptnonstdtxn=1", "-minrelaytxfee=0.00000100", "-blockmintxfee=0.00000100",
                    "-incrementalrelayfee=0.00000100"], check=True)
    report: dict = {}
    procs: list = []
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
        rollup_spk = bytes.fromhex(ids["script_pubkey"])
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        gtx.vout = [CTxOut(SEED_SATS, CScript(rollup_spk)),
                    CTxOut(value - SEED_SATS - DEPOSIT_SATS - 10_000, CScript(be.OP_TRUE_SPK)),
                    CTxOut(DEPOSIT_SATS, CScript(be.OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = be.rpc("sendrawtransaction", gtx.serialize().hex())
        be.rpc("generateblock", miner, [gtxid])
        subprocess.run([str(be.BATCHER), "genesis", str(state), gtx.serialize().hex()], check=True)
        log = be.WORK / "batcher.log"
        procs.append(serve(state, log))

        d = be.WORK / "a"
        d.mkdir()
        coin = {"outpoint": {"txid": list(bytes.fromhex(be.internal(gtxid))), "vout": 2},
                "amount": DEPOSIT_SATS, "script_pubkey": list(be.OP_TRUE_SPK)}
        (d / "funding.json").write_text(json.dumps([{"coin": coin, "witness": [be.OP_TRUE.hex()]}]))
        seed = hashlib.sha256(b"p6 a").hexdigest()
        t = time.time()
        be.wallet("deposit", be.URL, seed, d / "funding.json", DEPOSIT_FEE, d / "submission.json")
        report["deposit_seconds"] = round(time.time() - t, 1)
        print(f"deposit proven in {report['deposit_seconds']} s", flush=True)

        code, started = be.http("POST", "/v1/batches", b"")
        assert code in (200, 202), (code, started)
        n = started["batch_number"]
        t = time.time()
        r = wait_stage(n, {"broadcast", "failed", "confirmed"})
        assert r["stage"] == "broadcast", r
        report["settlement_seconds"] = round(time.time() - t, 1)
        procs[0].send_signal(signal.SIGKILL)
        procs[0].wait()
        inflight = json.loads((state / "inflight.json").read_text())
        assert inflight["txid"] in be.rpc("getrawmempool"), "settlement not in the mempool"
        report["killed_after_broadcast"] = {"txid": inflight["txid"], "weight": inflight["weight"]}
        print(f"settlement {inflight['txid']} broadcast after {report['settlement_seconds']} s; batcher killed",
              flush=True)

        good = decode(inflight["raw"])
        stack = good.wit.vtxinwit[0].scriptWitness.stack
        assert stack[-1][:1] == b"\x50", "last witness item is not an annex"

        # A covenant copy: the same script, funded by a different transaction.
        ctx = CTransaction()
        ctx.version = 2
        ctx.vin = [CTxIn(COutPoint(int(gtxid, 16), 1), b"", 0xFFFFFFFF)]
        ctx.vout = [CTxOut(SEED_SATS, CScript(rollup_spk)),
                    CTxOut(gtx.vout[1].nValue - SEED_SATS - 5_000, CScript(be.OP_TRUE_SPK))]
        ctx.wit.vtxinwit = [CTxInWitness()]
        ctx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        assert in_block(miner, ctx) == "accepted"
        assert inflight["txid"] in be.rpc("getrawmempool"), "settlement mined before the tamper cases"

        def variant(f):
            tx = copy.deepcopy(good)
            f(tx)
            return tx

        def flip_last(b: bytes) -> bytes:
            return b[:-1] + bytes([b[-1] ^ 1])

        def set_item(tx, i, v):
            tx.wit.vtxinwit[0].scriptWitness.stack[i] = v

        def successor_value(tx):
            tx.vout[0].nValue -= 1

        def last_value(tx):
            tx.vout[-1].nValue -= 1

        def last_redirected(tx):
            tx.vout[-1].scriptPubKey = CScript(be.OP_TRUE_SPK)

        def extra_output(tx):
            tx.vout.append(CTxOut(1_000, CScript(be.OP_TRUE_SPK)))

        def funding_dropped(tx):
            tx.vin.pop()
            tx.wit.vtxinwit.pop()

        def copy_input(tx):
            tx.vin[0].prevout = COutPoint(ctx.txid_int, 0)

        cases = {
            "successor_value_minus_1": successor_value,
            "last_output_value_minus_1": last_value,
            "last_output_redirected": last_redirected,
            "extra_output": extra_output,
            "funding_input_dropped": funding_dropped,
            "annex_byte_flipped": lambda tx: set_item(tx, -1, flip_last(stack[-1])),
            "annex_padded_100kB": lambda tx: set_item(tx, -1, stack[-1] + bytes(100_000)),
            "seal_byte_flipped": lambda tx: set_item(tx, 0, flip_last(stack[0])),
            "covenant_copy_input": copy_input,
        }
        report["tampered"] = {}
        for name, f in cases.items():
            res = in_block(miner, variant(f))
            assert inflight["txid"] in be.rpc("getrawmempool"), name
            report["tampered"][name] = res[-300:]
            print(f"{name}: {res[-160:]}", flush=True)
            assert res != "accepted", name

        procs[0] = serve(state, log)
        be.rpc("generatetoaddress", 1, miner)
        r = wait_stage(n, {"confirmed", "failed"}, 600)
        assert r["stage"] == "confirmed", r
        status = be.http("GET", "/v1/status")[1]
        assert status["batch_number"] == n and status["pending"] == 0 and not status["settling"], status
        assert not (state / "inflight.json").exists()
        report["resumed"] = {"batch": r, "status": status}
        print(f"restarted batcher recorded batch {n} as confirmed", flush=True)

        try:
            be.rpc("sendrawtransaction", inflight["raw"])
            report["replay"] = "accepted"
        except RuntimeError as e:
            report["replay"] = str(e)[-300:]
        report["replay_in_block"] = in_block(miner, good)[-300:]
        assert report["replay"] != "accepted" and report["replay_in_block"] != "accepted"
        print(f"replay: {report['replay']} / {report['replay_in_block'][-120:]}", flush=True)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                p.wait()
        subprocess.run([str(be.BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={be.DATADIR}", f"-rpcport={be.PORT}",
                        "stop"], capture_output=True)
        (rc.REPO / "build/p6-adversarial.json").write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
