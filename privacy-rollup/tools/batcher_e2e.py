#!/usr/bin/env python3
"""End to end over the Rust SDK and batcher on a GSR regtest node:

1. genesis: `pr-batcher init` prints the covenant output, a transaction funds it, `pr-batcher genesis`;
2. `pr-batcher serve` (Bitcoin Core RPC from the environment, `--mine-to` for regtest);
3. the SDK wallet example builds a deposit witness locally, proves it and POSTs the submission;
4. HTTP rejections: duplicate, corrupted transaction, oversized body, unknown batch;
5. `POST /v1/batches`: the batcher proves the settlement (resolve_zk), builds and mines the
   covenant spend, and records it after confirmation;
6. checks on chain, the wallet scans its note, the batcher restarts to the same status.

Writes `build/batcher-e2e.json`. Build first (from `prover/`):

    GSR_BUILD_CPU_BATCH=1 GSR_CPU_BATCH_LANES=16 cargo build --release -p pr-batcher
    GSR_BUILD_CPU_BATCH=1 GSR_CPU_BATCH_LANES=16 cargo build --release -p pr-sdk --examples
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
import sys

sys.path.insert(0, str(rc.BITCOIN_SOURCE / "test/functional"))
from test_framework.address import script_to_p2wsh  # noqa: E402

PR = Path(__file__).resolve().parents[1]
BITCOIN = rc.REPO / "build/bitcoin/bin"
TARGET = PR / "prover/target/release"
BATCHER, WALLET = TARGET / "pr-batcher", TARGET / "examples/wallet"
TEMPLATE = PR / "fixtures/apply-batch/receipt-template.json"
WORK = rc.REPO / "build/batcher-e2e"
DATADIR = WORK / "node"
PORT, HTTP = 19582, 18580
URL = f"http://127.0.0.1:{HTTP}"
OP_TRUE = b"\x51"
OP_TRUE_SPK = b"\x00\x20" + hashlib.sha256(OP_TRUE).digest()
SEED_SATS, DEPOSIT_SATS, DEPOSIT_FEE = 100_000, 20_000, 700
PROVER_ENV = {"GSR_BATCH_CPU": "1", "GSR_PERIODIC_CPU": "1", "GSR_BATCH_EVAL_CPU": "1", "GSR_HASH_LANES": "16",
              "GSR_FAST_NTT": "1"}


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


def http(method: str, path: str, body: bytes | None = None) -> tuple[int, object]:
    req = urllib.request.Request(URL + path, data=body, method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            text = r.read()
            return r.status, json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except json.JSONDecodeError:
            return e.code, text.decode(errors="replace")


def internal(txid: str) -> str:
    return bytes.fromhex(txid)[::-1].hex()


def serve(state: Path, miner: str, log: Path) -> subprocess.Popen:
    env = {**os.environ, **PROVER_ENV, "BITCOIN_RPC_URL": f"http://127.0.0.1:{PORT}",
           "BITCOIN_RPC_COOKIE": str(DATADIR / "regtest/.cookie")}
    p = subprocess.Popen([str(BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{HTTP}", "--mine-to", miner,
                          "--web", str(PR / "prover/web")], env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            if http("GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError("batcher did not start")


def stop(p: subprocess.Popen) -> None:
    p.send_signal(signal.SIGINT)
    p.wait(timeout=30)


def wallet(*args) -> dict:
    p = subprocess.run([str(WALLET), *map(str, args)], capture_output=True, text=True, env={**os.environ, **PROVER_ENV})
    if p.returncode:
        raise RuntimeError(f"wallet {args[0]}: exit {p.returncode}: {p.stderr[-4000:]}")
    return json.loads(p.stdout)


def main() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    DATADIR.mkdir(parents=True)
    subprocess.run([str(BITCOIN / "bitcoind"), "-regtest", f"-datadir={DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={PORT}", f"-port={PORT + 1}", "-vbparams=script_restoration:0:3999999999"],
                   check=True)
    report: dict = {}
    batcher = None
    try:
        miner = script_to_p2wsh(OP_TRUE)
        first = rpc("generatetoaddress", 1, miner)[0]
        rpc("generatetoaddress", 100, miner)
        while rpc("getdeploymentinfo")["deployments"]["script_restoration"]["bip9"]["status"] != "active":
            rpc("generatetoaddress", 144, miner)
        coinbase = rpc("getblock", first, 2)["tx"][0]
        template = json.loads(TEMPLATE.read_text())
        descriptor = {"protocol_version": 1,
                      "genesis_nonce": {"txid": list(bytes.fromhex(internal(coinbase["txid"]))), "vout": 0},
                      "image_id": list(bytes.fromhex(template["claim"]["pre"])),
                      "internal_key": list(rc.NUMS), "seed_sats": SEED_SATS}
        (WORK / "descriptor.json").write_text(json.dumps(descriptor))
        state = WORK / "batcher"
        t = time.time()
        ids = json.loads(subprocess.run([str(BATCHER), "init", str(state), str(WORK / "descriptor.json")],
                                        check=True, capture_output=True, text=True).stdout)
        report["init_seconds"] = round(time.time() - t, 1)
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        gtx.vout = [CTxOut(SEED_SATS, CScript(bytes.fromhex(ids["script_pubkey"]))),
                    CTxOut(value - SEED_SATS - DEPOSIT_SATS - 10_000, CScript(OP_TRUE_SPK)),
                    CTxOut(DEPOSIT_SATS, CScript(OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [OP_TRUE]
        gtxid = rpc("sendrawtransaction", gtx.serialize().hex())
        rpc("generateblock", miner, [gtxid])
        subprocess.run([str(BATCHER), "genesis", str(state), gtxid, "0"], check=True)
        report["genesis"] = {"txid": gtxid, **ids}

        log = WORK / "batcher.log"
        batcher = serve(state, miner, log)
        report["status_genesis"] = http("GET", "/v1/status")[1]

        user = WORK / "user"
        user.mkdir()
        seed = hashlib.sha256(b"batcher-e2e user").hexdigest()
        coin = {"outpoint": {"txid": list(bytes.fromhex(internal(gtxid))), "vout": 2}, "amount": DEPOSIT_SATS,
                "script_pubkey": list(OP_TRUE_SPK)}
        (user / "funding.json").write_text(json.dumps([{"coin": coin, "witness": [OP_TRUE.hex()]}]))
        t = time.time()
        report["deposit"] = wallet("deposit", URL, seed, user / "funding.json", DEPOSIT_FEE, user / "submission.json")
        report["deposit"]["wall_seconds"] = round(time.time() - t, 1)
        print(f"deposit proved and submitted in {report['deposit']['wall_seconds']}s", flush=True)
        assert report["deposit"]["pending"] == 1

        sub = json.loads((user / "submission.json").read_text())
        corrupt = dict(sub, transaction=sub["transaction"][:-8] + ("00000000" if sub["transaction"][-8:] != "00000000"
                                                                 else "11111111"))
        report["rejections"] = {
            "duplicate": http("POST", "/v1/transactions", json.dumps(sub).encode()),
            "corrupted_receipt": http("POST", "/v1/transactions", json.dumps(corrupt).encode()),
            "not_hex": http("POST", "/v1/transactions", json.dumps(dict(sub, transaction="zz")).encode()),
            "oversized_body": http("POST", "/v1/transactions", b"{" + b" " * (9 << 20) + b"}")[0],
            "unknown_batch": http("GET", "/v1/batches/99"),
        }
        assert report["rejections"]["duplicate"][0] == 409, report["rejections"]["duplicate"]
        assert report["rejections"]["corrupted_receipt"][0] == 400
        assert report["rejections"]["not_hex"][0] == 400
        assert report["rejections"]["oversized_body"] == 413
        assert report["rejections"]["unknown_batch"][0] == 404

        t = time.time()
        report["settlement"] = wallet("settle", URL)
        report["settlement"]["wall_seconds"] = round(time.time() - t, 1)
        print(f"settled in {report['settlement']['wall_seconds']}s", flush=True)
        txid = report["settlement"]["txid"]
        onchain = rpc("getrawtransaction", txid, 1, report["settlement"]["block_hash"])
        report["onchain"] = {"confirmations": onchain.get("confirmations"), "weight": onchain["weight"],
                             "annex_bytes": len(onchain["vin"][0]["txinwitness"][-1]) // 2,
                             "inputs": len(onchain["vin"]), "outputs": len(onchain["vout"])}
        assert onchain["confirmations"] >= 1
        status = http("GET", "/v1/status")[1]
        report["status_after"] = status
        assert status["batch_number"] == 1 and status["pending"] == 0
        assert status["utxo"] == [internal(txid), 0]
        report["scan"] = wallet("scan", URL, seed)
        assert sorted(n["value"] for n in report["scan"]) == [0, DEPOSIT_SATS - DEPOSIT_FEE]  # deposit change + zero note
        report["resubmit_after_settlement"] = http("POST", "/v1/transactions", json.dumps(sub).encode())
        assert report["resubmit_after_settlement"][0] in (400, 409)

        stop(batcher)
        batcher = serve(state, miner, log)
        restarted = http("GET", "/v1/status")[1]
        report["restart_status_matches"] = {k: v for k, v in restarted.items() if k != "settling"} == \
            {k: v for k, v in status.items() if k != "settling"}
        assert report["restart_status_matches"]
        report["batches"] = http("GET", "/v1/batches")[1]
    finally:
        if batcher:
            stop(batcher)
        subprocess.run([str(BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={DATADIR}", f"-rpcport={PORT}", "stop"],
                       capture_output=True)
        (rc.REPO / "build/batcher-e2e.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps({k: report.get(k) for k in ("deposit", "settlement", "onchain")}, indent=2, default=str))


if __name__ == "__main__":
    main()
