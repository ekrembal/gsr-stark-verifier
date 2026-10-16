#!/usr/bin/env python3
"""Non-interactive Taproot escrow deposits through SDK -> batcher -> gsr regtest node:

  * wallet A gets a deposit address from the SDK, an ordinary transaction pays it, and A registers it;
    registrations with a wrong refund leaf, a wrong outpoint or a replay are rejected;
  * the batcher waits for confirmations, sweeps the escrow with a genuine settlement (proven and mined)
    and A's scan finds the minted note;
  * wallet B's escrow is never registered: its refund leaf is rejected before the delay and accepted after.

Writes build/escrow-e2e.json. Build the binaries as in batcher_e2e.py first (with the wallet example).
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
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.script import TaprootSignatureHash, taproot_construct
from transaction import NUMS

be.WORK = rc.REPO / "build/escrow-e2e"
be.DATADIR = be.WORK / "node"
be.PORT, be.HTTP = 19692, 18690
be.URL = URL = f"http://127.0.0.1:{be.HTTP}"
SEED_SATS, FUND_SATS = 100_000, 50_000
VALUE, FEE, DELAY, CONFIRMATIONS = 20_000, 700, 10, 2
ESCROW_INPUT_SEQUENCE = 0xfffffffd
REFUND_LEAF = 0xc0


def serve(state, miner, log):
    env = {**os.environ, **be.PROVER_ENV, "BITCOIN_RPC_URL": f"http://127.0.0.1:{be.PORT}",
           "BITCOIN_RPC_COOKIE": str(be.DATADIR / "regtest/.cookie")}
    p = subprocess.Popen([str(be.BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{be.HTTP}", "--mine-to", miner,
                          "--min-transactions", "0", "--confirmations", str(CONFIRMATIONS),
                          "--min-refund-delay", str(DELAY)], env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)
    for _ in range(600):
        try:
            if be.http("GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("batcher did not start")


def settle_mining(miner: str) -> dict:
    """`wallet settle`, mining a block whenever the settlement waits for confirmations."""
    p = subprocess.Popen([str(be.WALLET), "settle", URL], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while p.poll() is None:
        time.sleep(5)
        batches = be.http("GET", "/v1/batches")[1]
        if batches and batches[-1]["stage"] == "broadcast" and batches[-1]["block_hash"]:
            be.rpc("generatetoaddress", 1, miner)
    out, err = p.communicate()
    if p.returncode:
        raise RuntimeError(f"wallet settle: exit {p.returncode}: {err}")
    return json.loads(out)


def pay(fund_txid: str, vout: int, spk: bytes, amount: int, miner: str) -> str:
    """An ordinary payment to the escrow address (here from a regtest P2WSH(OP_TRUE) coin)."""
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), vout), b"", 0xFFFFFFFF)]
    tx.vout = [CTxOut(amount, CScript(spk))]
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
    txid = be.rpc("sendrawtransaction", tx.serialize().hex())
    be.rpc("generateblock", miner, [txid])
    return txid


def refund_tx(d: dict, txid: str, key: bytes, seq: int) -> CTransaction:
    """Spends the escrow through its refund leaf, signed with the payer's key."""
    leaf = bytes.fromhex(d["refund_leaf"])
    control = bytes.fromhex(d["control"])
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(COutPoint(int(txid, 16), 0), b"", seq)]
    tx.vout = [CTxOut(d["amount_sats"] - 1_000, CScript(be.OP_TRUE_SPK))]
    spent = [CTxOut(d["amount_sats"], CScript(bytes.fromhex(d["script_pubkey"])))]
    h = TaprootSignatureHash(tx, spent, 0, 0, scriptpath=True, leaf_script=CScript(leaf), leaf_ver=REFUND_LEAF,
                             codeseparator_pos=0xffffffff)
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = [sign_schnorr(key, h), leaf, control]
    return tx


def refund_control(d: dict) -> bytes:
    """The refund leaf's control block: parity | NUMS | sweep leaf hash (the refund leaf's sibling)."""
    tr = taproot_construct(NUMS, [("sweep", CScript(bytes(d["opening"]["sweep_leaf"])), 0xc2),
                                  ("refund", CScript(bytes.fromhex(d["refund_leaf"])), REFUND_LEAF)])
    assert bytes(tr.scriptPubKey).hex() == d["script_pubkey"], "SDK escrow address differs from BIP341 construction"
    return bytes([REFUND_LEAF | tr.negflag]) + NUMS + tr.leaves["refund"].merklebranch


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
                    CTxOut(value - SEED_SATS - 2 * FUND_SATS - 10_000, CScript(be.OP_TRUE_SPK)),
                    CTxOut(FUND_SATS, CScript(be.OP_TRUE_SPK)), CTxOut(FUND_SATS, CScript(be.OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = be.rpc("sendrawtransaction", gtx.serialize().hex())
        be.rpc("generateblock", miner, [gtxid])
        subprocess.run([str(be.BATCHER), "genesis", str(state), gtx.serialize().hex()], check=True)
        log = be.WORK / "batcher.log"
        batcher = serve(state, miner, log)
        report["terms"] = be.http("GET", "/v1/escrow")[1]

        users = {}
        for k, name in enumerate(["a", "b"]):
            seed = hashlib.sha256(f"escrow-e2e {name}".encode()).hexdigest()
            key = generate_privkey()
            out = be.WORK / f"{name}-deposit.json"
            r = be.wallet("deposit-address", URL, seed, VALUE, FEE, compute_xonly_pubkey(key)[0].hex(), DELAY, out)
            d = json.loads(out.read_text())
            assert r["amount_sats"] == VALUE + FEE == d["amount_sats"]
            d["control"] = refund_control(d).hex()
            txid = pay(gtxid, 2 + k, bytes.fromhex(d["script_pubkey"]), d["amount_sats"], miner)
            users[name] = {"seed": seed, "key": key, "deposit": d, "file": out, "txid": txid}
        report["escrow_script_pubkey_a"] = users["a"]["deposit"]["script_pubkey"]

        a = users["a"]
        bad = json.loads(a["file"].read_text())
        bad["refund_leaf"] = users["b"]["deposit"]["refund_leaf"]
        reg = {"outpoint": [a["txid"], 0], "opening": bad["opening"], "refund_leaf": bad["refund_leaf"]}
        report["register_wrong_refund_leaf"] = be.http("POST", "/v1/escrows", json.dumps(reg).encode())
        assert report["register_wrong_refund_leaf"][0] == 400, report["register_wrong_refund_leaf"]
        reg = {"outpoint": [users["b"]["txid"], 0], "opening": a["deposit"]["opening"],
               "refund_leaf": a["deposit"]["refund_leaf"]}
        report["register_other_output"] = be.http("POST", "/v1/escrows", json.dumps(reg).encode())
        assert report["register_other_output"][0] == 400, report["register_other_output"]
        reg = {"outpoint": [a["txid"], 1], "opening": a["deposit"]["opening"], "refund_leaf": a["deposit"]["refund_leaf"]}
        report["register_missing_output"] = be.http("POST", "/v1/escrows", json.dumps(reg).encode())
        assert report["register_missing_output"][0] == 404, report["register_missing_output"]

        report["register_a"] = be.wallet("register", URL, a["file"], a["txid"], 0)
        try:
            be.wallet("register", URL, a["file"], a["txid"], 0)
            raise AssertionError("replayed registration was accepted")
        except RuntimeError as e:
            report["register_replay"] = str(e)[-200:]
        report["escrows_before_confirmations"] = be.http("GET", "/v1/escrows")[1]
        be.rpc("generatetoaddress", CONFIRMATIONS, miner)

        t = time.time()
        r = settle_mining(miner)
        r["wall_seconds"] = round(time.time() - t, 1)
        tx = be.rpc("getrawtransaction", r["txid"], 1, r["block_hash"])
        sweep = tx["vin"][1]
        r["onchain"] = {"confirmations": tx.get("confirmations"), "weight": tx["weight"], "vsize": tx["vsize"],
                        "annex_bytes": len(tx["vin"][0]["txinwitness"][-1]) // 2,
                        "inputs": [(i["txid"], i["vout"], i["sequence"]) for i in tx["vin"]],
                        "escrow_witness_bytes": [len(w) // 2 for w in sweep["txinwitness"]],
                        "outputs": [(o["value"], o["scriptPubKey"]["hex"]) for o in tx["vout"]]}
        report["batch1_escrow_sweep"] = r
        assert len(tx["vin"]) == 2 and (sweep["txid"], sweep["vout"]) == (a["txid"], 0)
        assert sweep["sequence"] == ESCROW_INPUT_SEQUENCE
        assert sweep["txinwitness"][0] == bytes(a["deposit"]["opening"]["sweep_leaf"]).hex()
        assert round(tx["vout"][0]["value"] * 100_000_000) == SEED_SATS + VALUE
        print(f"escrow sweep: {r['wall_seconds']}s, {tx['weight']} WU", flush=True)

        scan = be.wallet("scan", URL, a["seed"])
        report["scan_a"] = scan
        assert [x["value"] for x in scan] == [VALUE], scan
        report["escrows_after_sweep"] = be.http("GET", "/v1/escrows")[1]
        assert report["escrows_after_sweep"] == []

        b = users["b"]
        on_time = refund_tx(b["deposit"], b["txid"], b["key"], DELAY)
        report["refund_before_delay"] = be.rpc("testmempoolaccept", [on_time.serialize().hex()])[0]
        assert not report["refund_before_delay"]["allowed"]
        be.rpc("generatetoaddress", DELAY, miner)
        short = refund_tx(b["deposit"], b["txid"], b["key"], DELAY - 1)
        report["refund_sequence_below_delay"] = be.rpc("testmempoolaccept", [short.serialize().hex()])[0]
        assert not report["refund_sequence_below_delay"]["allowed"]
        wrong = refund_tx(b["deposit"], b["txid"], users["a"]["key"], DELAY)
        report["refund_wrong_key"] = be.rpc("testmempoolaccept", [wrong.serialize().hex()])[0]
        assert not report["refund_wrong_key"]["allowed"]
        report["refund_after_delay"] = be.rpc("testmempoolaccept", [on_time.serialize().hex()])[0]
        assert report["refund_after_delay"]["allowed"], report["refund_after_delay"]
        be.rpc("generateblock", miner, [be.rpc("sendrawtransaction", on_time.serialize().hex())])
        assert not be.rpc("gettxout", b["txid"], 0)
        report["refund_mined"] = True
    finally:
        if batcher:
            be.stop(batcher)
        subprocess.run([str(be.BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={be.DATADIR}", f"-rpcport={be.PORT}",
                        "stop"], capture_output=True)
        (rc.REPO / "build/escrow-e2e.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps({k: v.get("onchain", {}).get("weight") for k, v in report.items()
                      if isinstance(v, dict) and "onchain" in v}))


if __name__ == "__main__":
    main()
