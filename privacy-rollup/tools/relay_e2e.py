#!/usr/bin/env python3
"""Public-mempool relay and RBF of real settlements between two gsr nodes patched with bitcoin/bitcoin#36466:

  * escrow deposits a and b are paid and confirmed on both nodes (no P2WSH funding input: under #36466 an
    annex on the rollup input requires an annex on every other non-P2A input, so only escrows can join);
  * with the nodes disconnected, batcher A settles {a} through `sendrawtransaction` on node A and batcher B
    (its own state, same genesis) settles {a, b} on node B, both under default mempool policy;
  * the nodes reconnect and node B re-announces its settlement: node A must take it over P2P as an ordinary
    RBF replacement (different txid, since output 1 publishes the new state root);
  * variants of the replacement with the escrow input's annex missing or inflated fail consensus
    (`generateblock` with `submit=false`), and the replacement is mined and recorded by batcher B.

Writes build/relay-e2e.json. Build the binaries as in batcher_e2e.py, with the node from
`BITCOIN_BIN` (default build/bitcoin-annex/bin: the gsr node with the #36466 commits).
"""
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from io import BytesIO
from pathlib import Path

import batcher_e2e as be
import rollup_covenant as rc
from rollup_covenant import CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.address import script_to_p2wsh
from test_framework.key import compute_xonly_pubkey, generate_privkey

WORK = rc.REPO / "build/relay-e2e"
BIN = Path(os.environ.get("BITCOIN_BIN", rc.REPO / "build/bitcoin-annex/bin"))
NODES = {"a": (WORK / "node-a", 19802), "b": (WORK / "node-b", 19812)}
HTTP = {"a": 18800, "b": 18810}
SEED_SATS, VALUE, FEE, DELAY, CONFIRMATIONS = 100_000, 20_000, 10_000, 10, 2
ESCROW_INPUT_SEQUENCE = 2
# Fixed regtest credentials, so a node restart does not invalidate the batchers' RPC login.
RPC_AUTH = ["-rpcuser=gsrpp", "-rpcpassword=gsrpp-regtest"]


def rpc(node: str, method: str, *args):
    datadir, port = NODES[node]
    cmd = [str(BIN / "bitcoin-cli"), "-regtest", f"-datadir={datadir}", f"-rpcport={port}", *RPC_AUTH, "-stdin", method]
    p = subprocess.run(cmd, input="".join((a if isinstance(a, str) else json.dumps(a)) + "\n" for a in args),
                       text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.strip())
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return p.stdout.strip()


def url(node: str) -> str:
    return f"http://127.0.0.1:{HTTP[node]}"


def http(node: str, method: str, path: str, body: bytes | None = None):
    req = urllib.request.Request(url(node) + path, data=body, method=method,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            t = r.read()
            return r.status, json.loads(t) if t else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def start_node(node: str, *extra: str) -> None:
    datadir, port = NODES[node]
    datadir.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(BIN / "bitcoind"), "-regtest", f"-datadir={datadir}", "-daemonwait", "-server", "-listen=1",
                    f"-rpcport={port}", f"-port={port + 1}", "-acceptnonstdtxn=0", *RPC_AUTH,
                    "-vbparams=tapleaf_0xc2:0:3999999999", "-debug=net", "-debug=mempool", "-debug=mempoolrej", *extra], check=True)


def restart_empty(node: str) -> None:
    """Restarts `node` offline with an empty mempool."""
    rpc(node, "setnetworkactive", False)
    rpc(node, "stop")
    time.sleep(3)
    (NODES[node][0] / "regtest/mempool.dat").unlink(missing_ok=True)
    start_node(node, "-persistmempool=0", "-networkactive=0")


def connect() -> None:
    rpc("b", "setnetworkactive", True)
    rpc("a", "setnetworkactive", True)
    rpc("b", "addnode", f"127.0.0.1:{NODES['a'][1] + 1}", "onetry")
    for _ in range(100):
        # A peer is only offered transactions once its version handshake has completed.
        if all(any("verack" in q["bytesrecv_per_msg"] and q["relaytxes"] for q in rpc(n, "getpeerinfo"))
               for n in NODES):
            return
        time.sleep(0.2)
    raise RuntimeError("nodes did not connect")


def sync_blocks() -> None:
    for _ in range(300):
        if rpc("a", "getbestblockhash") == rpc("b", "getbestblockhash"):
            return
        time.sleep(0.2)
    raise RuntimeError("blocks did not sync")


def serve(node: str, state: Path) -> subprocess.Popen:
    datadir, port = NODES[node]
    env = {**{k: v for k, v in os.environ.items() if k != "BITCOIN_RPC_COOKIE"}, **be.PROVER_ENV,
           "BITCOIN_RPC_URL": f"http://127.0.0.1:{port}", "BITCOIN_RPC_USER": "gsrpp",
           "BITCOIN_RPC_PASSWORD": "gsrpp-regtest"}
    p = subprocess.Popen([str(be.BATCHER), "serve", str(state), "--listen", f"127.0.0.1:{HTTP[node]}",
                          "--min-transactions", "0", "--confirmations", str(CONFIRMATIONS),
                          "--min-refund-delay", str(DELAY), "--fee-rate", "0.1"],
                         env=env, stdout=(WORK / f"batcher-{node}.log").open("ab"), stderr=subprocess.STDOUT)
    for _ in range(600):
        try:
            if http(node, "GET", "/v1/status")[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"batcher {node} did not start")


def settle_until_broadcast(node: str) -> tuple[subprocess.Popen, dict]:
    """`wallet settle` against batcher `node`; returns once its settlement is broadcast (or fails)."""
    p = subprocess.Popen([str(be.WALLET), "settle", url(node)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env={**os.environ, **be.PROVER_ENV})
    t = time.time()
    while True:
        time.sleep(3)
        batches = http(node, "GET", "/v1/batches")[1] or []
        if batches and batches[-1]["stage"] == "failed":
            raise RuntimeError(f"batcher {node}: {batches[-1]}")
        if batches and batches[-1]["stage"] == "broadcast" and batches[-1].get("txid"):
            b = batches[-1]
            b["wall_seconds"] = round(time.time() - t, 1)
            return p, b
        if p.poll() is not None:
            raise RuntimeError(f"wallet settle {node}: {p.communicate()}")


def entry(node: str, txid: str) -> dict:
    e = rpc(node, "getmempoolentry", txid)
    return {"vsize": e["vsize"], "weight": e["weight"], "fee_sats": round(e["fees"]["base"] * 1e8),
            "wtxid": e["wtxid"], "bip125_replaceable": e.get("bip125-replaceable")}


def block_check(node: str, miner: str, raw: str) -> list:
    try:
        rpc(node, "generateblock", miner, [raw], False)
        return [True, ""]
    except RuntimeError as e:
        return [False, str(e).splitlines()[-1][:200]]


def main() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    for n in NODES:
        start_node(n)
    report: dict = {"node": str(BIN)}
    batchers = {}
    settles = []
    try:
        connect()
        miner = script_to_p2wsh(be.OP_TRUE)
        first = rpc("a", "generatetoaddress", 1, miner)[0]
        rpc("a", "generatetoaddress", 100, miner)
        while rpc("a", "getdeploymentinfo")["deployments"]["tapleaf_0xc2"]["bip9"]["status"] != "active":
            rpc("a", "generatetoaddress", 144, miner)
        coinbase = rpc("a", "getblock", first, 2)["tx"][0]
        template = json.loads(be.TEMPLATE.read_text())
        descriptor = {"protocol_version": 1,
                      "genesis_nonce": {"txid": list(bytes.fromhex(be.internal(coinbase["txid"]))), "vout": 0},
                      "image_id": list(bytes.fromhex(template["claim"]["pre"])),
                      "internal_key": list(rc.NUMS), "seed_sats": SEED_SATS}
        (WORK / "descriptor.json").write_text(json.dumps(descriptor))
        states = {n: WORK / f"batcher-{n}" for n in NODES}
        ids = {n: json.loads(subprocess.run([str(be.BATCHER), "init", str(s), str(WORK / "descriptor.json")],
                                            check=True, capture_output=True, text=True).stdout)
               for n, s in states.items()}
        assert ids["a"]["script_pubkey"] == ids["b"]["script_pubkey"]
        gtx = CTransaction()
        gtx.version = 2
        gtx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), b"", 0xFFFFFFFF)]
        value = round(coinbase["vout"][0]["value"] * 100_000_000)
        fund = 2 * (VALUE + FEE)
        gtx.vout = [CTxOut(SEED_SATS, CScript(bytes.fromhex(ids["a"]["script_pubkey"]))),
                    CTxOut(value - SEED_SATS - 2 * fund - 10_000, CScript(be.OP_TRUE_SPK)),
                    CTxOut(fund, CScript(be.OP_TRUE_SPK)), CTxOut(fund, CScript(be.OP_TRUE_SPK))]
        gtx.wit.vtxinwit = [CTxInWitness()]
        gtx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
        gtxid = rpc("a", "sendrawtransaction", gtx.serialize().hex())
        rpc("a", "generateblock", miner, [gtxid])
        for s in states.values():
            subprocess.run([str(be.BATCHER), "genesis", str(s), gtx.serialize().hex()], check=True)
        batchers = {n: serve(n, s) for n, s in states.items()}

        users = {}
        for k, name in enumerate(["a", "b"]):
            seed = hashlib.sha256(f"relay-e2e {name}".encode()).hexdigest()
            out = WORK / f"{name}-deposit.json"
            be.wallet("deposit-address", url("a"), seed, VALUE, FEE,
                      compute_xonly_pubkey(generate_privkey())[0].hex(), DELAY, out)
            d = json.loads(out.read_text())
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(int(gtxid, 16), 2 + k), b"", 0xFFFFFFFF)]
            tx.vout = [CTxOut(d["amount_sats"], CScript(bytes.fromhex(d["script_pubkey"])))]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [be.OP_TRUE]
            txid = rpc("a", "sendrawtransaction", tx.serialize().hex())
            users[name] = {"seed": seed, "file": out, "txid": txid}
        rpc("a", "generatetoaddress", CONFIRMATIONS, miner)
        sync_blocks()
        be.wallet("register", url("a"), users["a"]["file"], users["a"]["txid"], 0)
        for name in users:
            be.wallet("register", url("b"), users[name]["file"], users[name]["txid"], 0)

        # Settle {a} on node A while connected: does an annexed settlement relay under default policy?
        p, b1 = settle_until_broadcast("a")
        settles.append(p)
        tx1 = b1["txid"]
        t0 = time.time()
        while time.time() - t0 < 180 and tx1 not in rpc("b", "getrawmempool"):
            time.sleep(0.2)
        report["batch_a"] = {**b1, "node_a": entry("a", tx1),
                             "relayed_to_node_b": tx1 in rpc("b", "getrawmempool")}
        assert report["batch_a"]["relayed_to_node_b"], "settlement did not relay"
        raw1 = rpc("a", "getrawtransaction", tx1)
        print(f"batch a relayed: {report['batch_a']['node_a']}", flush=True)

        # Node B forgets it (disconnect, then evict by restarting with an empty mempool) so batcher B builds
        # a competing {a, b} settlement of the same rollup coin.
        restart_empty("b")
        assert tx1 not in rpc("b", "getrawmempool")
        p, b2 = settle_until_broadcast("b")
        settles.append(p)
        tx2 = b2["txid"]
        raw2 = rpc("b", "getrawtransaction", tx2)
        e2 = entry("b", tx2)
        report["batch_b"] = {**b2, "node_b": e2}
        assert tx1 != tx2

        report["batch_b"]["outputs"] = len(rpc("b", "getrawtransaction", tx2, 1)["vout"])
        assert report["batch_b"]["outputs"] == 2, "a deposit-only settlement pays only the rollup and its root"

        # Node B announces a transaction only when it enters its mempool, so empty it, reconnect, resubmit:
        # node A must replace tx1 with tx2 through P2P relay.
        restart_empty("b")
        connect()
        rpc("b", "sendrawtransaction", raw2)
        t0 = time.time()
        while time.time() - t0 < 180 and tx2 not in rpc("a", "getrawmempool"):
            time.sleep(0.2)
        mp = rpc("a", "getrawmempool")
        e1 = report["batch_a"]["node_a"]
        report["replacement"] = {
            "tx2_relayed_to_node_a": tx2 in mp, "tx1_evicted_from_node_a": tx1 not in mp,
            "delta_fee_sats": e2["fee_sats"] - e1["fee_sats"],
            "incremental_relay_floor_sats": -(-e2["vsize"] * 100 // 1000),
            "feerate_old_sat_vb": round(e1["fee_sats"] / e1["vsize"], 4),
            "feerate_new_sat_vb": round(e2["fee_sats"] / e2["vsize"], 4),
            "resend_old_to_node_a": None}
        try:
            rpc("a", "sendrawtransaction", raw1)
            report["replacement"]["resend_old_to_node_a"] = [True, ""]
        except RuntimeError as e:
            report["replacement"]["resend_old_to_node_a"] = [False, str(e).splitlines()[-1][:200]]
        assert report["replacement"]["tx2_relayed_to_node_a"] and report["replacement"]["tx1_evicted_from_node_a"]
        print(f"replacement: {report['replacement']}", flush=True)

        # Escrow-input annex variants of the replacement, checked for consensus validity only.
        t2 = CTransaction()
        t2.deserialize(BytesIO(bytes.fromhex(raw2)))
        k = next(i for i, v in enumerate(t2.vin) if v.nSequence == ESCROW_INPUT_SEQUENCE)
        stack = t2.wit.vtxinwit[k].scriptWitness.stack
        report["escrow_witness_items"] = [len(x) for x in stack]
        assert stack[-1] == b"\x50"
        checks = {"honest": stack}
        checks["escrow_annex_missing"] = stack[:-1]
        checks["escrow_annex_inflated_20kB"] = stack[:-1] + [b"\x50\x00" + bytes(20_000)]
        report["consensus"] = {}
        for name, s in checks.items():
            v = CTransaction()
            v.deserialize(BytesIO(bytes.fromhex(raw2)))
            v.wit.vtxinwit[k].scriptWitness.stack = s
            report["consensus"][name] = block_check("a", miner, v.serialize().hex())
        assert report["consensus"]["honest"][0]
        assert not report["consensus"]["escrow_annex_missing"][0]
        assert not report["consensus"]["escrow_annex_inflated_20kB"][0]

        block = rpc("a", "generatetoaddress", 1, miner)[0]
        sync_blocks()
        mined = rpc("a", "getrawtransaction", tx2, 1, block)
        report["mined"] = {"txid": tx2, "confirmations": mined.get("confirmations"), "weight": mined["weight"],
                           "annex_bytes": len(mined["vin"][0]["txinwitness"][-1]) // 2,
                           "annex_prefix": mined["vin"][0]["txinwitness"][-1][:12],
                           "inputs": len(mined["vin"]), "outputs": len(mined["vout"])}
        rpc("a", "generatetoaddress", CONFIRMATIONS, miner)
        sync_blocks()
        out, err = settles[1].communicate(timeout=600)
        assert settles[1].returncode == 0, err
        report["batch_b_final"] = json.loads(out)
        scans = {n: be.wallet("scan", url("b"), users[n]["seed"]) for n in users}
        report["scans_via_b"] = scans
        assert all([x["value"] for x in s] == [VALUE] for s in scans.values()), scans
    finally:
        for p in settles:
            if p.poll() is None:
                p.kill()
        for p in batchers.values():
            be.stop(p)
        for n in NODES:
            try:
                rpc(n, "stop")
            except RuntimeError:
                pass
        (rc.REPO / "build/relay-e2e.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
